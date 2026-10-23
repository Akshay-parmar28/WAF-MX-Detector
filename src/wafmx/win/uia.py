"""UI Automation reader: text under the mouse pointer (links, cells, chat text).

COM must be initialised on the thread that makes UIA calls, so all requests are
funnelled through one dedicated worker thread. The ``uiautomation`` package is
optional: if it is missing or fails, hover/hotkey still work via clipboard text.
"""

from __future__ import annotations

import logging
import queue
import sys
import threading
from concurrent.futures import Future

log = logging.getLogger(__name__)

# Climbing past these would return the *page* URL for any hovered text, which is misleading.
_STOP_TYPES = {"DocumentControl", "WindowControl", "PaneControl", "TitleBarControl", "TabControl"}
_MAX_TEXT = 2048
_MAX_CLIMB = 4


def _clip(s: object) -> str:
    return s.strip()[:_MAX_TEXT] if isinstance(s, str) else ""


def _texts_for(ctrl) -> list[str]:
    out: list[str] = []
    for getter in ("GetValuePattern", "GetLegacyIAccessiblePattern"):
        try:
            pat = getattr(ctrl, getter)()
            if pat:
                for attr in ("Value", "Name"):
                    t = _clip(getattr(pat, attr, ""))
                    if t:
                        out.append(t)
        except Exception:
            continue
    try:
        t = _clip(ctrl.Name)
        if t:
            out.append(t)
    except Exception:
        pass
    return out


def read_point(x: int, y: int) -> list[str]:
    """Collect candidate strings at screen point (call from the UIA worker thread)."""
    import uiautomation as auto

    ctrl = auto.ControlFromPoint(x, y)
    texts: list[str] = []
    depth = 0
    while ctrl is not None and depth <= _MAX_CLIMB:
        try:
            ctype = ctrl.ControlTypeName
        except Exception:
            break
        if ctype in _STOP_TYPES:
            break
        texts.extend(_texts_for(ctrl))
        try:
            ctrl = ctrl.GetParentControl()
        except Exception:
            break
        depth += 1
    seen, uniq = set(), []
    for t in texts:
        if t not in seen:
            seen.add(t)
            uniq.append(t)
    return uniq


class UiaWorker:
    def __init__(self) -> None:
        self._q: queue.Queue[tuple[int, int, Future] | None] = queue.Queue()
        self._thread: threading.Thread | None = None
        self.available = False

    def start(self) -> None:
        if sys.platform != "win32":
            return
        try:
            import importlib

            importlib.import_module("uiautomation")
        except Exception as e:
            log.warning("UI Automation unavailable (%s); using clipboard capture only", e)
            return
        self.available = True
        self._thread = threading.Thread(target=self._run, name="wafmx-uia", daemon=True)
        self._thread.start()

    def _run(self) -> None:
        import uiautomation as auto

        with auto.UIAutomationInitializerInThread():
            while True:
                item = self._q.get()
                if item is None:
                    return
                x, y, fut = item
                if not fut.set_running_or_notify_cancel():
                    continue
                try:
                    fut.set_result(read_point(x, y))
                except Exception as e:
                    fut.set_exception(e)

    def read(self, x: int, y: int, timeout: float = 1.5) -> list[str]:
        if not self.available:
            return []
        fut: Future = Future()
        self._q.put((x, y, fut))
        try:
            return fut.result(timeout=timeout)
        except Exception as e:
            log.debug("UIA read failed: %s", e)
            return []

    def stop(self) -> None:
        if self._thread:
            self._q.put(None)
            self._thread.join(timeout=2)
            self._thread = None
