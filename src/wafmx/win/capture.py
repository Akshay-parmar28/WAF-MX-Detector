"""Collect candidate text for detection from the current selection, the element
under the pointer, or the clipboard, in that order."""

from __future__ import annotations

import logging
import time

from ..config import Settings
from . import winapi
from .uia import UiaWorker

log = logging.getLogger(__name__)


class Capturer:
    def __init__(self, settings: Settings, uia: UiaWorker):
        self.s = settings
        self.uia = uia

    # -- strategies ------------------------------------------------------------
    def _copy_selection(self) -> str | None:
        """Ctrl+C the current selection, read it, put the old clipboard back.

        Skipped for console programs (Ctrl+C would interrupt a running job) and
        when the clipboard holds non-text data we could not faithfully restore.
        """
        s = self.s
        if not s.use_clipboard_fallback:
            return None
        exe = winapi.foreground_exe()
        if exe in {x.lower() for x in s.clipboard_blocklist}:
            log.debug("Selection copy skipped for %s", exe)
            return None
        if s.restore_clipboard and not winapi.clipboard_is_text_only():
            log.debug("Clipboard holds non-text data; selection copy skipped")
            return None
        prev = winapi.get_clipboard_text()
        seq0 = winapi.clipboard_sequence()
        winapi.wait_modifiers_released(1.0)
        winapi.send_ctrl_c()
        deadline = time.monotonic() + 0.5
        while time.monotonic() < deadline and winapi.clipboard_sequence() == seq0:
            time.sleep(0.02)
        if winapi.clipboard_sequence() == seq0:
            return None  # nothing was selected / the app ignored the copy
        time.sleep(0.03)
        text = winapi.get_clipboard_text()
        if s.restore_clipboard:
            winapi.set_clipboard_text(prev)
        return text

    # -- public ------------------------------------------------------------------
    def for_hotkey(self) -> list[tuple[str, str]]:
        """Candidates in priority order: selection, UI Automation at pointer, clipboard."""
        out: list[tuple[str, str]] = []
        existing = winapi.get_clipboard_text()
        try:
            sel = self._copy_selection()
        except Exception:
            log.exception("Selection capture failed")
            sel = None
        if sel:
            out.append(("selection", sel))
        try:
            x, y = winapi.cursor_pos()
            for t in self.uia.read(x, y):
                out.append(("pointer", t))
        except Exception:
            log.exception("Pointer capture failed")
        if existing and self.s.use_clipboard_fallback:
            out.append(("clipboard", existing))
        return out

    def for_hover(self, x: int, y: int) -> list[tuple[str, str]]:
        return [("pointer", t) for t in self.uia.read(x, y)]
