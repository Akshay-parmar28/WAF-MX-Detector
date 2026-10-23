"""Global hotkey via RegisterHotKey (no low-level hook, no admin rights needed)."""

from __future__ import annotations

import logging
import sys
import threading
from typing import Callable

log = logging.getLogger(__name__)

MOD_ALT, MOD_CONTROL, MOD_SHIFT, MOD_WIN, MOD_NOREPEAT = 0x1, 0x2, 0x4, 0x8, 0x4000
WM_HOTKEY, WM_QUIT = 0x0312, 0x0012

_MODS = {"alt": MOD_ALT, "ctrl": MOD_CONTROL, "control": MOD_CONTROL, "shift": MOD_SHIFT, "win": MOD_WIN, "super": MOD_WIN}
_NAMED = {
    "space": 0x20, "enter": 0x0D, "return": 0x0D, "tab": 0x09, "esc": 0x1B, "escape": 0x1B,
    "backspace": 0x08, "insert": 0x2D, "delete": 0x2E, "home": 0x24, "end": 0x23,
    "pageup": 0x21, "pagedown": 0x22, "left": 0x25, "up": 0x26, "right": 0x27, "down": 0x28,
}


def parse_hotkey(spec: str) -> tuple[int, int]:
    """'ctrl+alt+m' -> (modifier_mask, virtual_key). Raises ValueError on bad input."""
    parts = [p.strip().lower() for p in (spec or "").split("+") if p.strip()]
    if len(parts) < 2:
        raise ValueError("use at least one modifier and one key, e.g. ctrl+alt+m")
    *mods, key = parts
    mask = 0
    for m in mods:
        if m not in _MODS:
            raise ValueError(f"unknown modifier {m!r} (use ctrl, alt, shift, win)")
        mask |= _MODS[m]
    if not mask:
        raise ValueError("at least one modifier is required")
    if key in _NAMED:
        vk = _NAMED[key]
    elif len(key) == 1 and key.isalnum() and key.isascii():
        vk = ord(key.upper())
    elif key.startswith("f") and key[1:].isdigit() and 1 <= int(key[1:]) <= 24:
        vk = 0x70 + int(key[1:]) - 1
    else:
        raise ValueError(f"unknown key {key!r}")
    return mask, vk


class HotkeyListener:
    """Owns a thread that registers the hotkey and pumps its message loop."""

    def __init__(self, spec: str, callback: Callable[[], None], on_error: Callable[[str], None] | None = None):
        self.spec = spec
        self.callback = callback
        self.on_error = on_error or (lambda m: log.error(m))
        self._thread: threading.Thread | None = None
        self._tid = 0
        self._ready = threading.Event()
        self.registered = False

    def start(self) -> bool:
        if sys.platform != "win32":
            self.on_error("Global hotkeys are only available on Windows")
            return False
        mods, vk = parse_hotkey(self.spec)
        self._thread = threading.Thread(target=self._run, args=(mods, vk), name="wafmx-hotkey", daemon=True)
        self._thread.start()
        self._ready.wait(3)
        return self.registered

    def _run(self, mods: int, vk: int) -> None:
        import ctypes
        from ctypes import wintypes

        user32, kernel32 = ctypes.windll.user32, ctypes.windll.kernel32
        self._tid = kernel32.GetCurrentThreadId()
        hid = 0x5741
        if not user32.RegisterHotKey(None, hid, mods | MOD_NOREPEAT, vk):
            self.on_error(f"Could not register {self.spec}; another program may already use it")
            self._ready.set()
            return
        self.registered = True
        self._ready.set()
        msg = wintypes.MSG()
        try:
            while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
                if msg.message == WM_HOTKEY and msg.wParam == hid:
                    try:
                        self.callback()
                    except Exception:
                        log.exception("Hotkey callback failed")
        finally:
            user32.UnregisterHotKey(None, hid)
            self.registered = False

    def stop(self) -> None:
        if sys.platform == "win32" and self._tid:
            import ctypes

            ctypes.windll.user32.PostThreadMessageW(self._tid, WM_QUIT, 0, 0)
        if self._thread:
            self._thread.join(timeout=2)
        self._thread, self._tid = None, 0
