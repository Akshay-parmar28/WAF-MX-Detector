"""Apply user-configured extraction rules to an HTTP response."""

from __future__ import annotations

import html
import re
from dataclasses import dataclass
from html.parser import HTMLParser
from typing import Mapping

from .config import ExtractionRule


@dataclass(frozen=True)
class Extraction:
    mx: str
    rule_name: str


class _TextAndMeta(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.parts: list[str] = []
        self.meta: dict[str, str] = {}
        self._skip = 0

    def handle_starttag(self, tag, attrs):
        if tag in ("script", "style"):
            self._skip += 1
        elif tag == "meta":
            d = {k.lower(): (v or "") for k, v in attrs}
            name = d.get("name") or d.get("property") or d.get("http-equiv")
            if name and "content" in d:
                self.meta.setdefault(name.lower(), d["content"])

    def handle_endtag(self, tag):
        if tag in ("script", "style") and self._skip:
            self._skip -= 1

    def handle_data(self, data):
        if not self._skip:
            self.parts.append(data)


def html_to_text(markup: str) -> tuple[str, dict[str, str]]:
    p = _TextAndMeta()
    try:
        p.feed(markup)
        p.close()
    except Exception:  # malformed markup must never crash detection
        pass
    text = re.sub(r"[ \t\r\f\v]+", " ", " ".join(p.parts))
    text = re.sub(r"\s*\n\s*", "\n", text)
    return text, p.meta


def _clean(value: str) -> str:
    return html.unescape(value).strip().strip("\"'")


def _apply(rule: ExtractionRule, raw: str, text: str, meta: dict[str, str], headers: Mapping[str, str]) -> list[str]:
    out: list[str] = []
    if rule.kind == "regex":
        rx = re.compile(rule.pattern)
        for haystack in (raw, text):
            for m in rx.finditer(haystack):
                try:
                    out.append(m.group(rule.group))
                except IndexError:
                    out.append(m.group(0))
                if len(out) >= 5:
                    return out
    elif rule.kind == "between":
        for haystack in (raw, text):
            start = haystack.find(rule.pattern)
            if start >= 0:
                start += len(rule.pattern)
                end = haystack.find(rule.suffix, start)
                if end >= 0 and end - start <= 256:
                    out.append(haystack[start:end])
    elif rule.kind == "meta":
        v = meta.get(rule.pattern.lower())
        if v:
            out.append(v)
    elif rule.kind == "header":
        v = {k.lower(): val for k, val in headers.items()}.get(rule.pattern.lower())
        if v:
            out.append(v)
    return [x for x in out if x]


def extract_mx(
    body: str,
    headers: Mapping[str, str],
    rules: list[ExtractionRule],
    value_pattern: str,
) -> Extraction | None:
    """Return the first extraction that passes the sanity pattern, else None."""
    check = re.compile(value_pattern)
    text, meta = html_to_text(body)
    for rule in rules:
        if not rule.enabled:
            continue
        try:
            for cand in _apply(rule, body, text, meta, headers):
                cand = _clean(cand)
                if cand and check.fullmatch(cand):
                    return Extraction(mx=cand, rule_name=rule.name)
        except re.error:
            continue
    return None


def explain(
    body: str,
    headers: Mapping[str, str],
    rules: list[ExtractionRule],
    value_pattern: str,
) -> list[str]:
    """Per-rule diagnostics for the Settings 'Test rules' pane."""
    check = re.compile(value_pattern)
    text, meta = html_to_text(body)
    lines: list[str] = []
    for rule in rules:
        if not rule.enabled:
            lines.append(f"[off]   {rule.name}")
            continue
        try:
            cands = [_clean(c) for c in _apply(rule, body, text, meta, headers)]
        except re.error as e:
            lines.append(f"[error] {rule.name}: invalid regex ({e})")
            continue
        if not cands:
            lines.append(f"[miss]  {rule.name}: no match")
            continue
        good = [c for c in cands if check.fullmatch(c)]
        if good:
            lines.append(f"[HIT]   {rule.name}: {good[0]}")
        else:
            lines.append(f"[reject] {rule.name}: matched {cands[0]!r} but it fails the MX value pattern")
    return lines
