"""Dwell-based hover trigger.

Polls the cursor position at ~20 Hz (no global mouse hook, so no input-latency
risk and nothing for security software to flag). Fires once per dwell.
"""

from __future__ import annotations

import logging
import threading
import time
from typing import Callable

from . import winapi

log = logging.getLogger(__name__)

_MOD_VK = {"ctrl": winapi.VK_CONTROL, "shift": winapi.VK_SHIFT, "alt": winapi.VK_MENU}


class HoverMonitor:
    def __init__(
        self,
        dwell_ms: int,
        modifier: str,
        on_dwell: Callable[[int, int], None],
        is_own_window_at: Callable[[int, int], bool] | None = None,
    ):
        self.dwell = dwell_ms / 1000.0
        self.modifier = modifier
        self.on_dwell = on_dwell
        self.is_own = is_own_window_at or (lambda x, y: False)
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None

    def start(self) -> None:
        self._stop.clear()
        self._thread = threading.Thread(target=self._run, name="wafmx-hover", daemon=True)
        self._thread.start()

    def stop(self) -> None:
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=1)
            self._thread = None

    def _run(self) -> None:
        anchor = winapi.cursor_pos()
        since = time.monotonic()
        fired = False
        while not self._stop.wait(0.05):
            try:
                pos = winapi.cursor_pos()
                if abs(pos[0] - anchor[0]) > 3 or abs(pos[1] - anchor[1]) > 3:
                    anchor, since, fired = pos, time.monotonic(), False
                    continue
                if fired or time.monotonic() - since < self.dwell:
                    continue
                if winapi.mouse_buttons_down():
                    continue
                if self.modifier and not winapi.key_down(_MOD_VK[self.modifier]):
                    continue
                if self.is_own(*pos):
                    fired = True
                    continue
                fired = True
                self.on_dwell(*pos)
            except Exception:
                log.exception("Hover loop error")
                time.sleep(0.5)
