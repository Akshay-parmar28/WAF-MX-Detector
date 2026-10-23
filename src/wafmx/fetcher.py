"""Guarded HTTP fetcher.

Safety properties enforced here (not left to callers):
  * every hop (including redirects) is re-validated against the allowlist
  * DNS is resolved once, the resolved IPs are checked, and the connection is
    pinned to a vetted IP (no DNS-rebinding window between check and connect)
  * TLS verification stays on; SNI and certificate hostname use the real host
  * hard caps on redirects, wall-clock time and response size
  * no cookies, no credentials, no proxies picked up from the environment
"""

from __future__ import annotations

import ipaddress
import socket
import ssl
import time
from dataclasses import dataclass, field
from typing import Callable

import urllib3
from urllib3.exceptions import (
    ConnectTimeoutError,
    MaxRetryError,
    NewConnectionError,
    ProtocolError,
    ReadTimeoutError,
    SSLError,
)

from .config import Settings
from .urlutil import Target, UrlError, parse_target

REDIRECT_CODES = {301, 302, 303, 307, 308}


class FetchError(Exception):
    """Request failed. ``kind`` is a stable machine-readable category."""

    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind
        self.message = message


@dataclass
class FetchResult:
    status: int
    headers: dict[str, str]
    body: str
    final_url: str
    truncated: bool = False
    redirects: list[str] = field(default_factory=list)
    elapsed_ms: int = 0


def _ip_is_forbidden(ip: ipaddress._BaseAddress) -> bool:
    return (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
        or (isinstance(ip, ipaddress.IPv6Address) and bool(ip.ipv4_mapped) and _ip_is_forbidden(ip.ipv4_mapped))
    )


def default_resolver(host: str, port: int) -> list[str]:
    infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    seen: list[str] = []
    for fam, _, _, _, sockaddr in infos:
        if fam in (socket.AF_INET, socket.AF_INET6) and sockaddr[0] not in seen:
            seen.append(sockaddr[0])
    return seen


def _build_ssl_context(settings: Settings) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    if settings.use_system_trust_store:
        try:
            import truststore  # uses the Windows certificate store

            ctx = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        except Exception:
            pass
    if settings.ca_bundle_path:
        ctx.load_verify_locations(cafile=settings.ca_bundle_path)
    if not settings.verify_tls:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


class GuardedFetcher:
    def __init__(self, settings: Settings, resolver: Callable[[str, int], list[str]] | None = None):
        self.s = settings
        self._resolve = resolver or default_resolver
        self._ssl = _build_ssl_context(settings)

    # ------------------------------------------------------------------
    def _pick_ip(self, host: str, port: int) -> str:
        try:
            ips = self._resolve(host, port)
        except socket.gaierror:
            raise FetchError("dns", f"Could not resolve {host}") from None
        if not ips:
            raise FetchError("dns", f"No address found for {host}")
        for ip in ips:
            addr = ipaddress.ip_address(ip)
            if self.s.allow_private_ips or not _ip_is_forbidden(addr):
                return ip
        raise FetchError("blocked", "Host resolves only to private or reserved addresses")

    def _one_hop(self, target: Target, path: str, method: str, deadline: float):
        scheme, host = target.scheme, target.host
        port = target.port or (443 if scheme == "https" else 80)
        ip = self._pick_ip(host, port)

        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise FetchError("timeout", "Total time limit reached")
        timeout = urllib3.Timeout(
            connect=min(self.s.connect_timeout, remaining),
            read=min(self.s.read_timeout, remaining),
        )
        # Connect to the vetted IP but keep Host/SNI/cert-name as the real host.
        if scheme == "https":
            pool = urllib3.HTTPSConnectionPool(
                ip,
                port=port,
                timeout=timeout,
                retries=False,
                ssl_context=self._ssl,
                server_hostname=host,
                assert_hostname=host if self.s.verify_tls else False,
                cert_reqs="CERT_REQUIRED" if self.s.verify_tls else "CERT_NONE",
            )
        else:
            pool = urllib3.HTTPConnectionPool(ip, port=port, timeout=timeout, retries=False)

        headers = {
            "Host": host if port in (80, 443) else f"{host}:{port}",
            "User-Agent": self.s.user_agent,
            "Accept": "text/html,application/xhtml+xml,*/*;q=0.8",
            "Accept-Encoding": "identity",
            "Connection": "close",
        }
        for k, v in self.s.extra_headers.items():
            if k.lower() not in ("host", "cookie", "authorization", "proxy-authorization"):
                headers[k] = v
        resp = None
        try:
            resp = pool.request(
                method,
                path,
                headers=headers,
                redirect=False,
                preload_content=False,
                decode_content=False,
            )
            limit = self.s.max_response_bytes
            chunks: list[bytes] = []
            got, truncated = 0, False
            if method != "HEAD":
                for chunk in resp.stream(8192, decode_content=False):
                    got += len(chunk)
                    if got > limit:
                        chunks.append(chunk[: len(chunk) - (got - limit)])
                        truncated = True
                        break
                    chunks.append(chunk)
                    if time.monotonic() > deadline:
                        raise FetchError("timeout", "Total time limit reached")
            return resp.status, dict(resp.headers), b"".join(chunks), truncated
        finally:
            if resp is not None:
                try:
                    resp.release_conn()
                    resp.close()
                except Exception:
                    pass
            pool.close()

    # ------------------------------------------------------------------
    def fetch(self, target: Target) -> FetchResult:
        started = time.monotonic()
        deadline = started + self.s.total_timeout
        method = self.s.probe_method.upper()
        current = target
        path = self.s.probe_path
        hops: list[str] = []
        ports = tuple(self.s.allowed_ports)

        for _ in range(self.s.max_redirects + 1):
            try:
                status, headers, raw, truncated = self._one_hop(current, path, method, deadline)
            except FetchError:
                raise
            except (ConnectTimeoutError,):
                raise FetchError("timeout", "Connection timed out") from None
            except ReadTimeoutError:
                raise FetchError("timeout", "Server took too long to respond") from None
            except SSLError as e:
                raise FetchError("tls", f"TLS verification failed: {_short(e)}") from None
            except MaxRetryError as e:
                reason = e.reason
                if isinstance(reason, SSLError):
                    raise FetchError("tls", f"TLS verification failed: {_short(reason)}") from None
                if isinstance(reason, (ConnectTimeoutError, ReadTimeoutError)):
                    raise FetchError("timeout", "Connection timed out") from None
                raise FetchError("connect", f"Could not connect: {_short(reason)}") from None
            except (NewConnectionError, ProtocolError, OSError) as e:
                raise FetchError("connect", f"Could not connect: {_short(e)}") from None

            if status in REDIRECT_CODES and self.s.follow_redirects:
                loc = {k.lower(): v for k, v in headers.items()}.get("location", "")
                if not loc:
                    pass  # treat as final response
                else:
                    if len(hops) >= self.s.max_redirects:
                        raise FetchError("redirect", "Too many redirects")
                    nxt = _resolve_location(current, loc)
                    try:
                        current = parse_target(
                            nxt,
                            self.s.allowed_domains,
                            allow_http=self.s.allow_http,
                            allowed_ports=ports,
                        )
                    except UrlError as e:
                        raise FetchError("redirect", f"Redirect refused: {e}") from None
                    path = current.path_query
                    hops.append(nxt)
                    if status == 303:
                        method = "GET"
                    continue

            return FetchResult(
                status=status,
                headers=headers,
                body=_decode(raw, headers),
                final_url=current.origin + path,
                truncated=truncated,
                redirects=hops,
                elapsed_ms=int((time.monotonic() - started) * 1000),
            )
        raise FetchError("redirect", "Too many redirects")


def _resolve_location(base: Target, loc: str) -> str:
    from urllib.parse import urljoin

    return urljoin(base.origin + "/", loc.strip())


def _short(exc: object) -> str:
    s = str(exc).replace("\n", " ")
    return s if len(s) <= 160 else s[:157] + "..."


def _decode(raw: bytes, headers: dict[str, str]) -> str:
    ctype = {k.lower(): v for k, v in headers.items()}.get("content-type", "")
    enc = "utf-8"
    if "charset=" in ctype.lower():
        enc = ctype.lower().split("charset=", 1)[1].split(";")[0].strip().strip("\"'") or "utf-8"
    try:
        return raw.decode(enc, errors="replace")
    except LookupError:
        return raw.decode("utf-8", errors="replace")
