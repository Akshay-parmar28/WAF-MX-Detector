"""Application wiring: Tk main thread + worker threads + tray + triggers."""

from __future__ import annotations

import logging
import logging.handlers
import os
import queue
import sys
import threading
import tkinter as tk
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from tkinter import messagebox

from . import APP_NAME, __version__
from .config import ConfigStore, Settings, app_dir
from .service import DetectionService, Outcome, Status
from .store import History
from .urlutil import extract_urls
from .win import autostart, winapi
from .win.capture import Capturer
from .win.hotkey import HotkeyListener
from .win.hover import HoverMonitor
from .win.uia import UiaWorker

log = logging.getLogger("wafmx")


def setup_logging(level: str) -> None:
    root = logging.getLogger()
    root.setLevel(getattr(logging, level.upper(), logging.INFO))
    if not any(isinstance(h, logging.handlers.RotatingFileHandler) for h in root.handlers):
        h = logging.handlers.RotatingFileHandler(app_dir() / "wafmx.log", maxBytes=256_000, backupCount=2, encoding="utf-8")
        h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s: %(message)s"))
        root.addHandler(h)
    # urllib3 debug logs contain request lines; keep them out of the log file.
    logging.getLogger("urllib3").setLevel(logging.WARNING)


class App:
    def __init__(self, start_minimized: bool = True, config_path: Path | None = None):
        winapi.enable_dpi_awareness()
        self.store = ConfigStore(config_path)
        self.settings: Settings = self.store.load()
        setup_logging(self.settings.log_level)
        log.info("%s %s starting", APP_NAME, __version__)

        self.root = tk.Tk()
        self.root.withdraw()
        self.root.title(APP_NAME)
        self._ui_q: queue.Queue = queue.Queue()
        self._pool = ThreadPoolExecutor(max_workers=3, thread_name_prefix="wafmx-work")
        self._gen = 0
        self._gen_lock = threading.Lock()
        self.enabled = True
        self._settings_win = None

        self.history = History(app_dir() / "history.db", self.settings.history_max_entries)
        self.service = DetectionService(self.settings, self.history)
        self.uia = UiaWorker()
        self.uia.start()
        self.capture = Capturer(self.settings, self.uia)

        from .ui.tooltip import Tooltip
        from .ui.tray import Tray

        self.tooltip = Tooltip(self.root, self.settings.tooltip_font_size)
        self.tray = Tray(
            post=self.post,
            is_enabled=lambda: self.enabled,
            on_toggle=self.toggle_enabled,
            on_settings=self.open_settings,
            on_clipboard=self.detect_clipboard,
            on_folder=self.open_folder,
            on_quit=self.quit,
            title=APP_NAME,
        )
        self.hotkey: HotkeyListener | None = None
        self.hover: HoverMonitor | None = None

        self.tray.start()
        self._apply_triggers()
        self.root.after(40, self._pump)
        self.root.protocol("WM_DELETE_WINDOW", self.quit)
        if not self.settings.allowed_domains or not start_minimized:
            self.root.after(300, self.open_settings)  # first run: guide the user to the allowlist

    # ----------------------------------------------------------------- threading
    def post(self, fn) -> None:
        """Run ``fn`` on the Tk thread."""
        self._ui_q.put(fn)

    def _pump(self) -> None:
        try:
            while True:
                fn = self._ui_q.get_nowait()
                try:
                    fn()
                except Exception:
                    log.exception("UI callback failed")
        except queue.Empty:
            pass
        self.root.after(40, self._pump)

    def _next_gen(self) -> int:
        with self._gen_lock:
            self._gen += 1
            return self._gen

    def _is_current(self, gen: int) -> bool:
        return gen == self._gen

    # ----------------------------------------------------------------- triggers
    def _apply_triggers(self) -> None:
        for t in (self.hotkey, self.hover):
            if t:
                t.stop()
        self.hotkey = self.hover = None
        s = self.settings
        if not self.enabled:
            self.tray.set_state("off")
            return
        self.tray.set_state("idle")
        if s.hotkey_enabled:
            hk = HotkeyListener(s.hotkey, lambda: self._pool.submit(self._run_hotkey), on_error=lambda m: self.post(lambda: self.tray.notify(m)))
            try:
                if not hk.start() and sys.platform == "win32":
                    log.warning("Hotkey %s not registered", s.hotkey)
                self.hotkey = hk
            except ValueError as e:
                self.tray.notify(f"Hotkey invalid: {e}")
        if s.hover_enabled and sys.platform == "win32":
            self.hover = HoverMonitor(s.hover_dwell_ms, s.hover_modifier, lambda x, y: self._pool.submit(self._run_hover, x, y), self._is_own_window_at)
            self.hover.start()

    def _is_own_window_at(self, x: int, y: int) -> bool:
        try:
            return self.tooltip.contains_point(x, y) or winapi.foreground_pid() == os.getpid()
        except Exception:
            return False

    def toggle_enabled(self) -> None:
        self.enabled = not self.enabled
        self._apply_triggers()
        self.tray.update_menu()
        self.tray.notify("Detection enabled" if self.enabled else "Detection paused")

    # ----------------------------------------------------------------- detection flows
    def _has_candidate_url(self, cands: list[tuple[str, str]]) -> bool:
        return any(extract_urls(t, self.settings.allowed_domains) for _s, t in cands)

    def _run_hotkey(self) -> None:
        gen = self._next_gen()
        x, y = winapi.cursor_pos()
        cands = self.capture.for_hotkey()
        self._detect_and_show(gen, cands, x, y, quiet_misses=False)

    def _run_hover(self, x: int, y: int) -> None:
        gen = self._next_gen()
        cands = self.capture.for_hover(x, y)
        if not self._has_candidate_url(cands):
            return
        self._detect_and_show(gen, cands, x, y, quiet_misses=True)

    def detect_clipboard(self) -> None:
        def work() -> None:
            gen = self._next_gen()
            x, y = winapi.cursor_pos() if sys.platform == "win32" else (100, 100)
            text = winapi.get_clipboard_text() if sys.platform == "win32" else ""
            self._detect_and_show(gen, [("clipboard", text or "")], x, y, quiet_misses=False)

        self._pool.submit(work)

    def _detect_and_show(self, gen: int, cands, x: int, y: int, quiet_misses: bool) -> None:
        if self._has_candidate_url(cands):
            self.post(lambda: self._is_current(gen) and self.tooltip.show_checking(x, y))
        out = self.service.detect_from_candidates(cands)
        if quiet_misses and out.status in (Status.NO_URL, Status.NOT_ALLOWED):
            self.post(lambda: self._is_current(gen) and self.tooltip.hide())
            return
        self.post(lambda: self._is_current(gen) and self.tooltip.show_outcome(out, x, y, self.settings.tooltip_seconds))
        log.info("detect status=%s host=%s http=%s cached=%s", out.status.value, out.host, out.http_status, out.cached)

    # ----------------------------------------------------------------- settings
    def open_settings(self) -> None:
        from .ui.settings_ui import SettingsWindow

        if self._settings_win is not None:
            try:
                if self._settings_win.winfo_exists():
                    self._settings_win.deiconify()
                    self._settings_win.lift()
                    self._settings_win.focus_force()
                    return
            except tk.TclError:
                pass
        self._settings_win = SettingsWindow(
            self.root,
            self.settings,
            on_save=self.apply_settings,
            probe=self._probe,
            history_rows=lambda: self.history.recent(200),
            clear_history=self.history.clear,
            export_cfg=self.store.export_to,
            import_cfg=self.store.import_from,
        )

    def _probe(self, settings: Settings, url: str) -> Outcome:
        """Settings-window test: uses the unsaved settings, no cache, no history."""
        probe_settings = Settings.from_dict(settings.to_dict())
        probe_settings.cache_enabled = False
        probe_settings.history_enabled = False
        return DetectionService(probe_settings).detect_from_text(url) if url else Outcome(Status.NO_URL, "Enter a URL to test")

    def apply_settings(self, new: Settings) -> None:
        self.store.save(new)
        self.settings = new
        setup_logging(new.log_level)
        self.history.max_entries = new.history_max_entries
        self.service = DetectionService(new, self.history)
        self.capture = Capturer(new, self.uia)
        self.tooltip.font_size = new.tooltip_font_size
        try:
            autostart.set_enabled(new.start_with_windows)
        except OSError:
            log.exception("Could not update autostart")
            self.tray.notify("Could not change the Start with Windows setting")
        self._apply_triggers()
        log.info("Settings saved")

    def open_folder(self) -> None:
        if sys.platform == "win32":
            os.startfile(str(app_dir()))  # noqa: S606 - opens a folder we own

    # ----------------------------------------------------------------- lifecycle
    def quit(self) -> None:
        log.info("Shutting down")
        for t in (self.hotkey, self.hover):
            if t:
                t.stop()
        self.uia.stop()
        self.tray.stop()
        self._pool.shutdown(wait=False, cancel_futures=True)
        try:
            self.root.quit()
            self.root.destroy()
        except tk.TclError:
            pass

    def run(self) -> None:
        self.root.mainloop()


def fatal_dialog(message: str) -> None:
    r = tk.Tk()
    r.withdraw()
    messagebox.showerror(APP_NAME, message)
    r.destroy()
