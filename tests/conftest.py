"""Shared fixtures: tiny local HTTP(S) servers with synthetic WAF-style pages.

All hostnames are reserved ``.test`` names mapped to 127.0.0.1 by an injected
resolver, so no real network, DNS or organisation-specific data is involved.
"""

from __future__ import annotations

import socket
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
import trustme

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from wafmx.config import ExtractionRule, Settings  # noqa: E402
from wafmx.fetcher import GuardedFetcher  # noqa: E402

SYNTHETIC_PAGE = "<html><head><title>Blocked</title></head><body><h1>Request blocked</h1><p>Gateway: mx-test-07</p></body></html>"


class Behaviour:
    """Mutable per-test server behaviour."""

    def __init__(self) -> None:
        self.status = 403
        self.body = SYNTHETIC_PAGE.encode()
        self.headers: dict[str, str] = {"Content-Type": "text/html; charset=utf-8"}
        self.delay = 0.0
        self.routes: dict[str, tuple[int, dict[str, str], bytes]] = {}
        self.seen_paths: list[str] = []
        self.seen_hosts: list[str] = []
        self.seen_headers: list[dict[str, str]] = []


def _make_handler(beh: Behaviour):
    class H(BaseHTTPRequestHandler):
        protocol_version = "HTTP/1.1"

        def log_message(self, *a):  # silence
            pass

        def _serve(self):
            beh.seen_paths.append(self.path)
            beh.seen_hosts.append(self.headers.get("Host", ""))
            beh.seen_headers.append({k.lower(): v for k, v in self.headers.items()})
            if beh.delay:
                time.sleep(beh.delay)
            status, headers, body = beh.routes.get(self.path, (beh.status, beh.headers, beh.body))
            try:
                self.send_response(status)
                for k, v in headers.items():
                    self.send_header(k, v)
                self.send_header("Content-Length", str(len(body)))
                self.send_header("Connection", "close")
                self.end_headers()
                if self.command != "HEAD":
                    self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                pass

        do_GET = do_POST = do_HEAD = _serve

    return H


class _QuietServer(ThreadingHTTPServer):
    def handle_error(self, request, client_address):  # clients abort on purpose in timeout/TLS tests
        pass


class Server:
    def __init__(self, ctx: ssl.SSLContext | None):
        self.beh = Behaviour()
        self.httpd = _QuietServer(("127.0.0.1", 0), _make_handler(self.beh))
        if ctx:
            self.httpd.socket = ctx.wrap_socket(self.httpd.socket, server_side=True)
        self.port = self.httpd.server_address[1]
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.thread.start()

    def close(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.fixture(scope="session")
def ca(tmp_path_factory):
    return trustme.CA()


@pytest.fixture(scope="session")
def ca_pem(ca, tmp_path_factory):
    p = tmp_path_factory.mktemp("ca") / "ca.pem"
    ca.cert_pem.write_to_path(str(p))
    return str(p)


def _tls_ctx(ca: trustme.CA, *names: str) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ca.issue_cert(*names).configure_cert(ctx)
    return ctx


@pytest.fixture()
def https_server(ca):
    s = Server(_tls_ctx(ca, "waf.example.test", "other.example.test"))
    yield s
    s.close()


@pytest.fixture()
def wrongname_server(ca):
    s = Server(_tls_ctx(ca, "unrelated.invalid"))
    yield s
    s.close()


@pytest.fixture()
def http_server():
    s = Server(None)
    yield s
    s.close()


HOSTS = {"waf.example.test": "127.0.0.1", "other.example.test": "127.0.0.1", "evil.test": "127.0.0.1"}


def resolver(host: str, port: int) -> list[str]:
    if host in HOSTS:
        return [HOSTS[host]]
    raise socket.gaierror("no such host")


@pytest.fixture()
def make_settings(ca_pem):
    def _make(server: Server, **over) -> Settings:
        s = Settings(
            allowed_domains=["*.example.test"],
            allowed_ports=[server.port],
            allow_private_ips=True,  # loopback test servers
            use_system_trust_store=False,
            ca_bundle_path=ca_pem,
            probe_path="/probe",
            rules=[ExtractionRule(name="gw", kind="regex", pattern=r"Gateway:\s*([A-Za-z0-9._-]+)", group=1)],
            connect_timeout=2,
            read_timeout=2,
            total_timeout=4,
        )
        for k, v in over.items():
            setattr(s, k, v)
        return s

    return _make


@pytest.fixture()
def make_fetcher():
    def _make(settings: Settings) -> GuardedFetcher:
        return GuardedFetcher(settings, resolver=resolver)

    return _make
