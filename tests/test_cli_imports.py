import importlib
import json
import sys

import pytest

from wafmx.__main__ import main


@pytest.mark.parametrize("mod", ["wafmx.win.winapi", "wafmx.win.autostart", "wafmx.win.hotkey", "wafmx.win.hover", "wafmx.win.uia", "wafmx.win.capture", "wafmx.service", "wafmx.fetcher"])
def test_modules_import_without_windows(mod):
    importlib.import_module(mod)


def test_cli_detect_reports_not_allowed_for_empty_allowlist(tmp_path, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({}))
    rc = main(["--config", str(cfg), "--detect", "https://anything.example.test/"])
    assert rc == 2
    assert capsys.readouterr().out.strip() != ""


def test_cli_detect_blocks_non_allowlisted(tmp_path, capsys):
    cfg = tmp_path / "c.json"
    cfg.write_text(json.dumps({"allowed_domains": ["example.test"]}))
    rc = main(["--config", str(cfg), "--detect", "https://other.invalid/"])
    out = capsys.readouterr().out
    assert rc == 2 and out.startswith(("not_allowed", "no_url"))


def test_hotkey_listener_degrades_off_windows():
    from wafmx.win.hotkey import HotkeyListener

    errors = []
    hk = HotkeyListener("ctrl+alt+m", lambda: None, errors.append)
    if sys.platform != "win32":
        assert hk.start() is False and errors
