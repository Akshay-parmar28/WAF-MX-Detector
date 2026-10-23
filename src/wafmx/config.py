"""Persistent, validated configuration.

Settings live in a JSON file under %APPDATA%\\WAFMXDetector (or ~/.config on
non-Windows hosts, used only for tests). Nothing organisation-specific ships
as a default: the allowlist starts empty and the user fills it in via the UI.
"""

from __future__ import annotations

import json
import os
import re
import sys
import tempfile
from dataclasses import asdict, dataclass, field, fields
from pathlib import Path
from typing import Any

SCHEMA_VERSION = 1


def app_dir() -> Path:
    """Directory for config, cache and history."""
    if sys.platform == "win32":
        base = os.environ.get("APPDATA") or str(Path.home() / "AppData" / "Roaming")
    else:
        base = os.environ.get("XDG_CONFIG_HOME") or str(Path.home() / ".config")
    p = Path(base) / "WAFMXDetector"
    p.mkdir(parents=True, exist_ok=True)
    return p


@dataclass
class ExtractionRule:
    """One way of pulling an MX identifier out of an HTML page.

    kind:
      regex    - ``pattern`` is a regular expression; group ``group`` is the MX id.
      between  - text between ``pattern`` (prefix) and ``suffix`` literals.
      meta     - value of <meta name="``pattern``" content="..."> tag.
      header   - value of HTTP response header named ``pattern``.
    """

    name: str = "rule"
    kind: str = "regex"
    pattern: str = ""
    suffix: str = ""
    group: int = 1
    enabled: bool = True

    VALID_KINDS = ("regex", "between", "meta", "header")


def default_rules() -> list[ExtractionRule]:
    # Generic, non-sensitive examples. The user is expected to tune these.
    return [
        ExtractionRule(
            name="Labelled identifier",
            kind="regex",
            pattern=r"(?i)\b(?:mx|gateway|server)[\s_-]*(?:id|name)?\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]{1,63})",
            group=1,
        ),
    ]


@dataclass
class Settings:
    schema_version: int = SCHEMA_VERSION

    # Targets
    allowed_domains: list[str] = field(default_factory=list)  # "example.com", "*.example.com"
    allow_http: bool = False  # plain http probing is off unless explicitly enabled
    allow_private_ips: bool = False  # block RFC1918/loopback/link-local by default
    allowed_ports: list[int] = field(default_factory=lambda: [80, 443])
    probe_path: str = "/__waf_probe__"
    probe_method: str = "GET"

    # Extraction
    rules: list[ExtractionRule] = field(default_factory=default_rules)
    mx_value_pattern: str = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"  # sanity check on any result
    match_status_codes: list[int] = field(default_factory=list)  # empty = any status

    # Network limits
    connect_timeout: float = 5.0
    read_timeout: float = 8.0
    total_timeout: float = 12.0
    max_response_bytes: int = 262144  # 256 KiB
    max_redirects: int = 3
    follow_redirects: bool = True
    verify_tls: bool = True
    ca_bundle_path: str = ""  # optional PEM file for private CAs
    use_system_trust_store: bool = True
    user_agent: str = "WAFMXDetector/1.0"
    extra_headers: dict[str, str] = field(default_factory=dict)

    # Triggers
    hotkey_enabled: bool = True
    hotkey: str = "ctrl+alt+m"
    hover_enabled: bool = False
    hover_dwell_ms: int = 700
    hover_modifier: str = ""  # "", "ctrl", "shift" or "alt" required while hovering
    use_clipboard_fallback: bool = True
    restore_clipboard: bool = True
    # Never send Ctrl+C to these programs (it would interrupt a running console job).
    clipboard_blocklist: list[str] = field(
        default_factory=lambda: ["cmd.exe", "powershell.exe", "pwsh.exe", "windowsterminal.exe", "conhost.exe", "wt.exe", "putty.exe", "mintty.exe"]
    )

    # Tooltip
    tooltip_seconds: float = 6.0
    tooltip_follow_cursor: bool = True
    tooltip_font_size: int = 10

    # Cache and history
    cache_enabled: bool = True
    cache_ttl_seconds: int = 300
    history_enabled: bool = False
    history_max_entries: int = 200

    # App
    start_with_windows: bool = False
    start_minimized: bool = True
    log_level: str = "INFO"

    # ------------------------------------------------------------------
    def validate(self) -> list[str]:
        """Return a list of human-readable problems (empty list = valid)."""
        problems: list[str] = []
        from .urlutil import normalize_domain_pattern  # local import avoids cycle

        for d in self.allowed_domains:
            if normalize_domain_pattern(d) is None:
                problems.append(f"Invalid domain pattern: {d!r}")
        if not self.probe_path.startswith("/"):
            problems.append("Probe path must start with '/'")
        if any(c in self.probe_path for c in "\r\n \t"):
            problems.append("Probe path must not contain whitespace")
        if self.probe_method.upper() not in ("GET", "HEAD", "POST"):
            problems.append("Probe method must be GET, HEAD or POST")
        for r in self.rules:
            if r.kind not in ExtractionRule.VALID_KINDS:
                problems.append(f"Rule {r.name!r}: unknown kind {r.kind!r}")
                continue
            if not r.pattern:
                problems.append(f"Rule {r.name!r}: pattern is empty")
            if r.kind == "regex":
                try:
                    re.compile(r.pattern)
                except re.error as e:
                    problems.append(f"Rule {r.name!r}: bad regex ({e})")
            if r.kind == "between" and not r.suffix:
                problems.append(f"Rule {r.name!r}: 'between' needs a suffix")
        try:
            re.compile(self.mx_value_pattern)
        except re.error as e:
            problems.append(f"MX value pattern invalid ({e})")
        for name, val, lo, hi in (
            ("Connect timeout", self.connect_timeout, 0.5, 60),
            ("Read timeout", self.read_timeout, 0.5, 120),
            ("Total timeout", self.total_timeout, 1, 180),
        ):
            if not (lo <= val <= hi):
                problems.append(f"{name} must be between {lo} and {hi} seconds")
        if not (1024 <= self.max_response_bytes <= 8 * 1024 * 1024):
            problems.append("Max response size must be between 1 KiB and 8 MiB")
        if not (0 <= self.max_redirects <= 10):
            problems.append("Max redirects must be between 0 and 10")
        if not (100 <= self.hover_dwell_ms <= 5000):
            problems.append("Hover dwell must be between 100 and 5000 ms")
        if self.hover_modifier not in ("", "ctrl", "shift", "alt"):
            problems.append("Hover modifier must be empty, ctrl, shift or alt")
        if self.hotkey_enabled:
            from .win.hotkey import parse_hotkey  # pure parser, safe off-Windows

            try:
                parse_hotkey(self.hotkey)
            except ValueError as e:
                problems.append(f"Hotkey: {e}")
        return problems

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> "Settings":
        known = {f.name for f in fields(cls)}
        clean: dict[str, Any] = {}
        for k, v in (data or {}).items():
            if k not in known:
                continue
            if k == "rules" and isinstance(v, list):
                rules = []
                rule_fields = {f.name for f in fields(ExtractionRule)}
                for item in v:
                    if isinstance(item, dict):
                        rules.append(ExtractionRule(**{a: b for a, b in item.items() if a in rule_fields}))
                clean[k] = rules
            else:
                clean[k] = v
        return cls(**clean)


class ConfigStore:
    """Load/save Settings atomically."""

    def __init__(self, path: Path | None = None):
        self.path = path or (app_dir() / "config.json")

    def load(self) -> Settings:
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if not isinstance(raw, dict):
                raise ValueError("config root must be an object")
            return Settings.from_dict(raw)
        except FileNotFoundError:
            return Settings()
        except (ValueError, TypeError, OSError):
            # Keep the broken file for inspection, start from defaults.
            try:
                self.path.replace(self.path.with_suffix(".json.bad"))
            except OSError:
                pass
            return Settings()

    def save(self, settings: Settings) -> None:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix="config.", suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as fh:
                json.dump(settings.to_dict(), fh, indent=2, sort_keys=True)
                fh.flush()
                os.fsync(fh.fileno())
            os.replace(tmp, self.path)
        except BaseException:
            try:
                os.unlink(tmp)
            except OSError:
                pass
            raise

    def export_to(self, settings: Settings, dest: Path) -> None:
        dest.write_text(json.dumps(settings.to_dict(), indent=2, sort_keys=True), encoding="utf-8")

    def import_from(self, src: Path) -> Settings:
        raw = json.loads(src.read_text(encoding="utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Config file must contain a JSON object")
        return Settings.from_dict(raw)
