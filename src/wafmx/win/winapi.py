"""Thin, typed ctypes wrappers for the handful of Win32 calls this app needs.

Importing this module on a non-Windows host is safe; calling into it is not.
"""

from __future__ import annotations

import sys
import time

IS_WIN = sys.platform == "win32"

if IS_WIN:
    import ctypes
    from ctypes import wintypes

    user32 = ctypes.WinDLL("user32", use_last_error=True)
    kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    CF_UNICODETEXT = 13
    CF_TEXT = 1
    CF_OEMTEXT = 7
    GMEM_MOVEABLE = 0x0002

    user32.OpenClipboard.argtypes = [wintypes.HWND]
    user32.OpenClipboard.restype = wintypes.BOOL
    user32.CloseClipboard.restype = wintypes.BOOL
    user32.EmptyClipboard.restype = wintypes.BOOL
    user32.GetClipboardData.argtypes = [wintypes.UINT]
    user32.GetClipboardData.restype = wintypes.HANDLE
    user32.SetClipboardData.argtypes = [wintypes.UINT, wintypes.HANDLE]
    user32.SetClipboardData.restype = wintypes.HANDLE
    user32.EnumClipboardFormats.argtypes = [wintypes.UINT]
    user32.EnumClipboardFormats.restype = wintypes.UINT
    user32.GetClipboardSequenceNumber.restype = wintypes.DWORD
    kernel32.GlobalAlloc.argtypes = [wintypes.UINT, ctypes.c_size_t]
    kernel32.GlobalAlloc.restype = wintypes.HGLOBAL
    kernel32.GlobalLock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalFree.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalSize.argtypes = [wintypes.HGLOBAL]
    kernel32.GlobalSize.restype = ctypes.c_size_t

    ULONG_PTR = ctypes.c_size_t

    class MOUSEINPUT(ctypes.Structure):
        _fields_ = [("dx", wintypes.LONG), ("dy", wintypes.LONG), ("mouseData", wintypes.DWORD),
                    ("dwFlags", wintypes.DWORD), ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]

    class KEYBDINPUT(ctypes.Structure):
        _fields_ = [("wVk", wintypes.WORD), ("wScan", wintypes.WORD), ("dwFlags", wintypes.DWORD),
                    ("time", wintypes.DWORD), ("dwExtraInfo", ULONG_PTR)]

    class HARDWAREINPUT(ctypes.Structure):
        _fields_ = [("uMsg", wintypes.DWORD), ("wParamL", wintypes.WORD), ("wParamH", wintypes.WORD)]

    class _INPUTUNION(ctypes.Union):
        _fields_ = [("mi", MOUSEINPUT), ("ki", KEYBDINPUT), ("hi", HARDWAREINPUT)]

    class INPUT(ctypes.Structure):
        _fields_ = [("type", wintypes.DWORD), ("u", _INPUTUNION)]

    user32.SendInput.argtypes = [wintypes.UINT, ctypes.POINTER(INPUT), ctypes.c_int]
    user32.SendInput.restype = wintypes.UINT

INPUT_KEYBOARD = 1
KEYEVENTF_KEYUP = 0x0002
VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN, VK_LBUTTON, VK_RBUTTON = 0x10, 0x11, 0x12, 0x5B, 0x5C, 0x01, 0x02
VK_C = 0x43


def _require_win() -> None:
    if not IS_WIN:
        raise RuntimeError("Windows only")


# --- process-level helpers ----------------------------------------------------
def enable_dpi_awareness() -> None:
    if not IS_WIN:
        return
    try:
        user32.SetProcessDpiAwarenessContext(ctypes.c_void_p(-4))  # per-monitor v2
        return
    except (AttributeError, OSError):
        pass
    try:
        ctypes.WinDLL("shcore").SetProcessDpiAwareness(2)
    except (AttributeError, OSError):
        try:
            user32.SetProcessDPIAware()
        except (AttributeError, OSError):
            pass


_mutex_handle = None


def acquire_single_instance(name: str = "Local\\WAFMXDetector.SingleInstance") -> bool:
    """True if we are the only running instance."""
    global _mutex_handle
    if not IS_WIN:
        return True
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    _mutex_handle = kernel32.CreateMutexW(None, False, name)
    return ctypes.get_last_error() != 183  # ERROR_ALREADY_EXISTS


# --- cursor / keyboard state ---------------------------------------------------
def cursor_pos() -> tuple[int, int]:
    _require_win()
    pt = wintypes.POINT()
    user32.GetCursorPos(ctypes.byref(pt))
    return pt.x, pt.y


def key_down(vk: int) -> bool:
    _require_win()
    return bool(user32.GetAsyncKeyState(vk) & 0x8000)


def mouse_buttons_down() -> bool:
    return key_down(VK_LBUTTON) or key_down(VK_RBUTTON)


def modifiers_down() -> bool:
    return any(key_down(v) for v in (VK_SHIFT, VK_CONTROL, VK_MENU, VK_LWIN, VK_RWIN))


def wait_modifiers_released(timeout: float = 1.0) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if not modifiers_down():
            return True
        time.sleep(0.01)
    return not modifiers_down()


def send_ctrl_c() -> None:
    _require_win()

    def ki(vk: int, up: bool) -> INPUT:
        i = INPUT(type=INPUT_KEYBOARD)
        i.u.ki = KEYBDINPUT(wVk=vk, wScan=0, dwFlags=KEYEVENTF_KEYUP if up else 0, time=0, dwExtraInfo=0)
        return i

    seq = (INPUT * 4)(ki(VK_CONTROL, False), ki(VK_C, False), ki(VK_C, True), ki(VK_CONTROL, True))
    user32.SendInput(4, seq, ctypes.sizeof(INPUT))


def foreground_pid() -> int:
    _require_win()
    hwnd = user32.GetForegroundWindow()
    pid = wintypes.DWORD()
    user32.GetWindowThreadProcessId(hwnd, ctypes.byref(pid))
    return pid.value


def foreground_exe() -> str:
    """Lower-case executable name of the foreground window's process ('' if unknown)."""
    _require_win()
    pid = foreground_pid()
    if not pid:
        return ""
    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE
    kernel32.QueryFullProcessImageNameW.argtypes = [wintypes.HANDLE, wintypes.DWORD, wintypes.LPWSTR, ctypes.POINTER(wintypes.DWORD)]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    h = kernel32.OpenProcess(0x1000, False, pid)  # PROCESS_QUERY_LIMITED_INFORMATION
    if not h:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(1024)
        size = wintypes.DWORD(1024)
        if not kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(size)):
            return ""
        return buf.value.replace("/", "\\").rsplit("\\", 1)[-1].lower()
    finally:
        kernel32.CloseHandle(h)


# --- clipboard -----------------------------------------------------------------
def clipboard_sequence() -> int:
    _require_win()
    return int(user32.GetClipboardSequenceNumber())


def _open_clipboard(retries: int = 10) -> bool:
    for _ in range(retries):
        if user32.OpenClipboard(None):
            return True
        time.sleep(0.02)
    return False


def clipboard_formats() -> list[int]:
    _require_win()
    if not _open_clipboard():
        return []
    try:
        out, fmt = [], 0
        while True:
            fmt = user32.EnumClipboardFormats(fmt)
            if not fmt:
                break
            out.append(int(fmt))
        return out
    finally:
        user32.CloseClipboard()


def clipboard_is_text_only() -> bool:
    """True if the clipboard is empty or holds only text formats (safe to restore)."""
    fmts = clipboard_formats()
    text_like = {CF_TEXT, CF_OEMTEXT, CF_UNICODETEXT, 16}  # 16 = CF_LOCALE
    return all(f in text_like for f in fmts)


def get_clipboard_text() -> str | None:
    _require_win()
    if not _open_clipboard():
        return None
    try:
        h = user32.GetClipboardData(CF_UNICODETEXT)
        if not h:
            return None
        p = kernel32.GlobalLock(h)
        if not p:
            return None
        try:
            size = kernel32.GlobalSize(h)
            if size > 2_000_000:
                return None
            return ctypes.wstring_at(p)
        finally:
            kernel32.GlobalUnlock(h)
    finally:
        user32.CloseClipboard()


def set_clipboard_text(text: str | None) -> bool:
    """Replace the clipboard with ``text`` (or empty it when None)."""
    _require_win()
    if not _open_clipboard():
        return False
    try:
        user32.EmptyClipboard()
        if text is None:
            return True
        data = ctypes.create_unicode_buffer(text)
        nbytes = ctypes.sizeof(data)
        h = kernel32.GlobalAlloc(GMEM_MOVEABLE, nbytes)
        if not h:
            return False
        p = kernel32.GlobalLock(h)
        if not p:
            kernel32.GlobalFree(h)
            return False
        ctypes.memmove(p, data, nbytes)
        kernel32.GlobalUnlock(h)
        if not user32.SetClipboardData(CF_UNICODETEXT, h):
            kernel32.GlobalFree(h)
            return False
        return True
    finally:
        user32.CloseClipboard()
