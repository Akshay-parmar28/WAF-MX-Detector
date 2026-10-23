"""System-tray icon (pystray). Runs detached so Tk keeps the main thread."""

from __future__ import annotations

import logging
from typing import Callable

from .icon import make_icon

log = logging.getLogger(__name__)


class Tray:
    def __init__(
        self,
        *,
        post: Callable[[Callable[[], None]], None],
        is_enabled: Callable[[], bool],
        on_toggle: Callable[[], None],
        on_settings: Callable[[], None],
        on_clipboard: Callable[[], None],
        on_folder: Callable[[], None],
        on_quit: Callable[[], None],
        title: str,
    ):
        import pystray

        self._pystray = pystray
        self.post = post
        menu = pystray.Menu(
            pystray.MenuItem("Detect URL on clipboard", lambda *_: post(on_clipboard)),
            pystray.MenuItem("Enabled", lambda *_: post(on_toggle), checked=lambda _i: is_enabled()),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Settings…", lambda *_: post(on_settings), default=True),
            pystray.MenuItem("Open settings folder", lambda *_: post(on_folder)),
            pystray.Menu.SEPARATOR,
            pystray.MenuItem("Quit", lambda *_: post(on_quit)),
        )
        self.icon = pystray.Icon("wafmx", make_icon(64, "idle"), title, menu)

    def start(self) -> None:
        self.icon.run_detached()

    def set_state(self, state: str) -> None:
        try:
            self.icon.icon = make_icon(64, state)
        except Exception:
            log.debug("tray icon update failed", exc_info=True)

    def notify(self, message: str, title: str = "WAF MX Detector") -> None:
        try:
            self.icon.notify(message, title)
        except Exception:
            log.debug("tray notify failed", exc_info=True)

    def update_menu(self) -> None:
        try:
            self.icon.update_menu()
        except Exception:
            pass

    def stop(self) -> None:
        try:
            self.icon.stop()
        except Exception:
            pass
