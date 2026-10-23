"""URL extraction and allowlist validation. Pure functions, no network."""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from urllib.parse import urlsplit, urlunsplit

_LABEL_RE = re.compile(r"^(?!-)[a-z0-9-]{1,63}(?<!-)$")
_URL_RE = re.compile(r"""(?i)\bhttps?://[^\s<>"'`\x00-\x1f]+""")
_BARE_RE = re.compile(
    r"""(?i)(?<![@\w./-])((?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}(?::\d{1,5})?(?:[/?#][^\s<>"'`\x00-\x1f]*)?)"""
)
_TRAILING = ".,;:!?'\"”’»>"
_PAIRS = {")": "(", "]": "[", "}": "{"}

MAX_URL_LEN = 2048


class UrlError(ValueError):
    """The URL is unusable or not permitted; message is safe to show the user."""


def normalize_domain_pattern(pattern: str) -> str | None:
    """Return a canonical pattern ('example.com' or '*.example.com') or None if invalid."""
    p = (pattern or "").strip().lower().rstrip(".")
    if not p:
        return None
    wildcard = False
    if p.startswith("*."):
        wildcard, p = True, p[2:]
    if "*" in p or "/" in p or ":" in p or " " in p:
        return None
    try:
        p = p.encode("idna").decode("ascii")
    except UnicodeError:
        return None
    labels = p.split(".")
    if len(labels) < 2 or not all(_LABEL_RE.match(x) for x in labels):
        return None
    try:
        ipaddress.ip_address(p)
        return None  # IP literals are never valid allowlist entries
    except ValueError:
        pass
    return ("*." if wildcard else "") + p


def host_matches(host: str, patterns: list[str]) -> bool:
    host = host.lower().rstrip(".")
    for raw in patterns:
        pat = normalize_domain_pattern(raw)
        if pat is None:
            continue
        if pat.startswith("*."):
            if host.endswith(pat[1:]) and len(host) > len(pat) - 1:
                return True
        elif host == pat:
            return True
    return False


@dataclass(frozen=True)
class Target:
    scheme: str
    host: str
    port: int | None
    path_query: str

    @property
    def origin(self) -> str:
        default = 443 if self.scheme == "https" else 80
        netloc = self.host if self.port in (None, default) else f"{self.host}:{self.port}"
        return f"{self.scheme}://{netloc}"

    def probe_url(self, probe_path: str) -> str:
        return self.origin + probe_path


def _trim(url: str) -> str:
    changed = True
    while url and changed:
        changed = False
        if url[-1] in _TRAILING:
            url, changed = url[:-1], True
        elif url[-1] in _PAIRS and url.count(url[-1]) > url.count(_PAIRS[url[-1]]):
            url, changed = url[:-1], True
    return url


def extract_urls(text: str, allowed_domains: list[str] | None = None) -> list[str]:
    """Pull URL-like strings from free text, in order of appearance.

    Bare ``host.tld/path`` strings are only returned if their host is allowlisted,
    which keeps file names like ``report.pdf`` from being treated as hosts.
    """
    if not text:
        return []
    text = text[:20000]
    found: list[tuple[int, str]] = []
    covered: list[tuple[int, int]] = []
    for m in _URL_RE.finditer(text):
        found.append((m.start(), _trim(m.group(0))))
        covered.append((m.start(), m.end()))
    if allowed_domains:
        for m in _BARE_RE.finditer(text):
            if any(a <= m.start() < b for a, b in covered):
                continue
            cand = _trim(m.group(1))
            host = urlsplit("//" + cand).hostname or ""
            if host_matches(host, allowed_domains):
                found.append((m.start(), cand))
    found.sort(key=lambda t: t[0])
    seen: set[str] = set()
    out: list[str] = []
    for _, u in found:
        if u and u not in seen:
            seen.add(u)
            out.append(u)
    return out


def parse_target(
    raw: str,
    allowed_domains: list[str],
    *,
    allow_http: bool = False,
    allowed_ports: tuple[int, ...] = (80, 443),
) -> Target:
    """Validate ``raw`` and return a Target, or raise UrlError."""
    raw = (raw or "").strip()
    if not raw:
        raise UrlError("No URL found")
    if len(raw) > MAX_URL_LEN:
        raise UrlError("URL is too long")
    if any(ord(c) < 0x20 or ord(c) == 0x7F for c in raw):
        raise UrlError("URL contains control characters")
    if "://" not in raw:
        raw = "https://" + raw.lstrip("/")
    try:
        parts = urlsplit(raw)
        port = parts.port
    except ValueError:
        raise UrlError("Malformed URL") from None
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        raise UrlError(f"Scheme {scheme!r} is not supported")
    if scheme == "http" and not allow_http:
        raise UrlError("Plain http is disabled in settings")
    if parts.username is not None or parts.password is not None or "@" in (parts.netloc or ""):
        raise UrlError("URLs with embedded credentials are rejected")
    host = (parts.hostname or "").lower().rstrip(".")
    if not host:
        raise UrlError("URL has no host")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        raise UrlError("Host name is not valid") from None
    try:
        ipaddress.ip_address(host)
        raise UrlError("IP-address hosts are not permitted")
    except ValueError as e:
        if isinstance(e, UrlError):
            raise
    if not allowed_domains:
        raise UrlError("No allowed domains are configured yet")
    if not host_matches(host, allowed_domains):
        raise UrlError("Host is not in the allowed domain list")
    if port is not None and port not in allowed_ports:
        raise UrlError(f"Port {port} is not permitted")
    pq = urlunsplit(("", "", parts.path or "/", parts.query, ""))
    return Target(scheme=scheme, host=host, port=port, path_query=pq)
