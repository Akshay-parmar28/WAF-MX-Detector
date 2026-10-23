"""Detection service: text/URL in, structured Outcome out. UI-agnostic."""

from __future__ import annotations

import logging
from dataclasses import dataclass
from enum import Enum

from .config import Settings
from .extractor import extract_mx
from .fetcher import FetchError, GuardedFetcher
from .store import History, TTLCache
from .urlutil import UrlError, extract_urls, parse_target

log = logging.getLogger(__name__)


class Status(str, Enum):
    MX_FOUND = "mx_found"          # an MX identifier was extracted
    NO_MX = "no_mx"                # server answered, but no MX identifier in it
    FAILED = "failed"              # network / TLS / DNS / timeout / redirect problem
    NOT_ALLOWED = "not_allowed"    # URL rejected by validation or allowlist
    NO_URL = "no_url"              # nothing URL-like was found in the input


@dataclass
class Outcome:
    status: Status
    message: str
    host: str = ""
    mx: str = ""
    http_status: int = 0
    rule: str = ""
    cached: bool = False
    elapsed_ms: int = 0
    truncated: bool = False

    @property
    def ok(self) -> bool:
        return self.status is Status.MX_FOUND


class DetectionService:
    def __init__(self, settings: Settings, history: History | None = None, fetcher: GuardedFetcher | None = None):
        self.settings = settings
        self.history = history
        self._fetcher = fetcher or GuardedFetcher(settings)
        self._cache = TTLCache(settings.cache_ttl_seconds)

    def clear_cache(self) -> None:
        self._cache.clear()

    # ------------------------------------------------------------------
    def detect_from_text(self, text: str) -> Outcome:
        s = self.settings
        urls = extract_urls(text, s.allowed_domains)
        if not urls:
            return Outcome(Status.NO_URL, "No URL found in the selection")
        last: Outcome | None = None
        for u in urls[:5]:
            out = self.detect(u)
            if out.status not in (Status.NOT_ALLOWED,):
                return out
            last = out
        assert last is not None
        return last

    def detect_from_candidates(self, candidates: list[tuple[str, str]]) -> Outcome:
        """Try each (source, text) in order; keep going while nothing usable was found."""
        best: Outcome | None = None
        for _source, text in candidates:
            out = self.detect_from_text(text)
            if out.status not in (Status.NO_URL, Status.NOT_ALLOWED):
                return out
            if best is None or (best.status is Status.NO_URL and out.status is Status.NOT_ALLOWED):
                best = out
        return best or Outcome(Status.NO_URL, "No URL found under the pointer or in the selection")

    def detect(self, url: str) -> Outcome:
        s = self.settings
        try:
            target = parse_target(
                url,
                s.allowed_domains,
                allow_http=s.allow_http,
                allowed_ports=tuple(s.allowed_ports),
            )
        except UrlError as e:
            return Outcome(Status.NOT_ALLOWED, str(e))

        key = (target.origin, s.probe_path, s.probe_method)
        if s.cache_enabled:
            hit = self._cache.get(key)
            if hit is not None:
                hit.cached = True
                return hit

        try:
            res = self._fetcher.fetch(target)
        except FetchError as e:
            out = Outcome(Status.FAILED, e.message, host=target.host)
            self._record(out)
            return out
        except Exception as e:  # defensive: never let a worker thread die silently
            log.exception("Unexpected fetch failure")
            out = Outcome(Status.FAILED, f"Unexpected error: {type(e).__name__}", host=target.host)
            self._record(out)
            return out

        wanted = s.match_status_codes
        if wanted and res.status not in wanted:
            out = Outcome(
                Status.NO_MX,
                f"HTTP {res.status} (not a configured MX status)",
                host=target.host,
                http_status=res.status,
                elapsed_ms=res.elapsed_ms,
                truncated=res.truncated,
            )
        else:
            ex = extract_mx(res.body, res.headers, s.rules, s.mx_value_pattern)
            if ex:
                out = Outcome(
                    Status.MX_FOUND,
                    ex.mx,
                    host=target.host,
                    mx=ex.mx,
                    http_status=res.status,
                    rule=ex.rule_name,
                    elapsed_ms=res.elapsed_ms,
                    truncated=res.truncated,
                )
            else:
                out = Outcome(
                    Status.NO_MX,
                    f"HTTP {res.status}: no MX identifier in response",
                    host=target.host,
                    http_status=res.status,
                    elapsed_ms=res.elapsed_ms,
                    truncated=res.truncated,
                )
        if s.cache_enabled:
            self._cache.put(key, out)
        self._record(out)
        return out

    def _record(self, out: Outcome) -> None:
        if self.history and self.settings.history_enabled and out.host:
            try:
                self.history.add(out.host, out.status.value, out.mx, out.http_status)
            except Exception:
                log.exception("History write failed")
