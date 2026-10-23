"""Entry point: GUI by default, ``--detect URL`` for a one-shot console check."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from . import APP_NAME, __version__


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="wafmx", description=f"{APP_NAME} {__version__}")
    ap.add_argument("--minimized", action="store_true", help="start in the tray without opening settings")
    ap.add_argument("--config", type=Path, help="use this config file instead of the default")
    ap.add_argument("--detect", metavar="URL", help="run one detection with the saved settings, print the result and exit")
    ap.add_argument("--version", action="version", version=__version__)
    args = ap.parse_args(argv)

    if args.detect:
        from .config import ConfigStore
        from .service import DetectionService

        out = DetectionService(ConfigStore(args.config).load()).detect_from_text(args.detect)
        print(f"{out.status.value}: {out.mx or out.message}")
        return 0 if out.ok else 2

    from .win import winapi

    if not winapi.acquire_single_instance():
        from .app import fatal_dialog

        fatal_dialog(f"{APP_NAME} is already running (look for the tray icon).")
        return 1

    from .app import App

    App(start_minimized=args.minimized, config_path=args.config).run()
    return 0


if __name__ == "__main__":
    sys.exit(main())
