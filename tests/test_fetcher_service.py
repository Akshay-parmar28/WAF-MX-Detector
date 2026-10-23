
from wafmx.fetcher import GuardedFetcher
from wafmx.service import DetectionService, Status
from wafmx.store import History
from wafmx.urlutil import parse_target

from conftest import resolver


def url(server, host="waf.example.test", path="/orig?token=SECRET"):
    return f"https://{host}:{server.port}{path}"


def svc(settings, **kw):
    return DetectionService(settings, fetcher=GuardedFetcher(settings, resolver=resolver), **kw)


# ---------------------------------------------------------------- outcome classification
def test_mx_found_on_blocked_page_and_probe_path_replaces_original(https_server, make_settings):
    s = make_settings(https_server)
    out = svc(s).detect(url(https_server))
    assert out.status is Status.MX_FOUND and out.mx == "mx-test-07" and out.http_status == 403 and out.rule == "gw"
    assert https_server.beh.seen_paths == ["/probe"]  # original path/query (and its token) never sent
    assert https_server.beh.seen_hosts == [f"waf.example.test:{https_server.port}"]


def test_generic_error_page_is_not_reported_as_mx(https_server, make_settings):
    https_server.beh.body = b"<html><body><h1>403 Forbidden</h1></body></html>"
    out = svc(make_settings(https_server)).detect(url(https_server))
    assert out.status is Status.NO_MX and out.http_status == 403 and out.mx == ""


def test_200_without_mx_is_no_mx(https_server, make_settings):
    https_server.beh.status, https_server.beh.body = 200, b"<html>hello</html>"
    assert svc(make_settings(https_server)).detect(url(https_server)).status is Status.NO_MX


def test_status_filter(https_server, make_settings):
    s = make_settings(https_server, match_status_codes=[403])
    https_server.beh.status = 500
    out = svc(s).detect(url(https_server))
    assert out.status is Status.NO_MX and "not a configured MX status" in out.message


def test_not_allowed_host_never_connects(https_server, make_settings):
    s = make_settings(https_server)
    out = svc(s).detect(url(https_server, host="evil.test"))
    assert out.status is Status.NOT_ALLOWED and https_server.beh.seen_paths == []


def test_detect_from_text_picks_first_usable_url(https_server, make_settings):
    s = make_settings(https_server)
    text = f"junk https://evil.test/x then {url(https_server)}"
    assert svc(s).detect_from_text(text).mx == "mx-test-07"
    assert svc(s).detect_from_text("no links here").status is Status.NO_URL


# ---------------------------------------------------------------- TLS
def test_untrusted_ca_fails_closed(https_server, make_settings):
    s = make_settings(https_server, ca_bundle_path="")
    out = svc(s).detect(url(https_server))
    assert out.status is Status.FAILED and "TLS" in out.message and https_server.beh.seen_paths == []


def test_hostname_mismatch_fails_closed(wrongname_server, make_settings):
    out = svc(make_settings(wrongname_server)).detect(url(wrongname_server))
    assert out.status is Status.FAILED and "TLS" in out.message


def test_tls_verification_can_be_disabled_explicitly(wrongname_server, make_settings):
    s = make_settings(wrongname_server, verify_tls=False)
    assert svc(s).detect(url(wrongname_server)).status is Status.MX_FOUND  # only with the explicit opt-out


def test_plain_http_requires_opt_in(http_server, make_settings):
    s = make_settings(http_server)
    out = svc(s).detect(f"http://waf.example.test:{http_server.port}/x")
    assert out.status is Status.NOT_ALLOWED
    s.allow_http = True
    assert svc(s).detect(f"http://waf.example.test:{http_server.port}/x").mx == "mx-test-07"


# ---------------------------------------------------------------- redirects
def test_redirect_to_allowed_host_is_followed_and_revalidated(https_server, make_settings):
    port = https_server.port
    https_server.beh.routes["/probe"] = (302, {"Location": f"https://other.example.test:{port}/landed"}, b"")
    out = svc(make_settings(https_server)).detect(url(https_server))
    assert out.mx == "mx-test-07"
    assert https_server.beh.seen_paths == ["/probe", "/landed"]


def test_redirect_to_disallowed_host_is_refused(https_server, make_settings):
    https_server.beh.routes["/probe"] = (302, {"Location": f"https://evil.test:{https_server.port}/x"}, b"")
    out = svc(make_settings(https_server)).detect(url(https_server))
    assert out.status is Status.FAILED and "Redirect refused" in out.message
    assert https_server.beh.seen_paths == ["/probe"]


def test_redirect_downgrade_to_http_is_refused(https_server, make_settings):
    https_server.beh.routes["/probe"] = (301, {"Location": f"http://other.example.test:{https_server.port}/x"}, b"")
    out = svc(make_settings(https_server)).detect(url(https_server))
    assert out.status is Status.FAILED and "http" in out.message.lower()


def test_redirect_loop_is_capped(https_server, make_settings):
    https_server.beh.routes["/probe"] = (302, {"Location": "/probe"}, b"")
    out = svc(make_settings(https_server, max_redirects=2)).detect(url(https_server))
    assert out.status is Status.FAILED and "redirect" in out.message.lower()
    assert len(https_server.beh.seen_paths) == 3


def test_redirects_can_be_disabled(https_server, make_settings):
    https_server.beh.routes["/probe"] = (302, {"Location": f"https://other.example.test:{https_server.port}/x"}, b"redirect body")
    out = svc(make_settings(https_server, follow_redirects=False)).detect(url(https_server))
    assert out.status is Status.NO_MX and out.http_status == 302


# ---------------------------------------------------------------- limits and address guard
def test_response_is_truncated_at_limit(https_server, make_settings):
    https_server.beh.body = b"A" * 200_000 + b" Gateway: mx-late-99"
    s = make_settings(https_server, max_response_bytes=4096)
    out = svc(s).detect(url(https_server))
    assert out.status is Status.NO_MX and out.truncated  # MX sat beyond the cap, so it is not read


def test_slow_server_times_out(https_server, make_settings):
    https_server.beh.delay = 3
    s = make_settings(https_server, read_timeout=0.5, total_timeout=1)
    out = svc(s).detect(url(https_server))
    assert out.status is Status.FAILED and "long" in out.message.lower() or "timed out" in out.message.lower() or "limit" in out.message.lower()
    assert out.status is Status.FAILED


def test_unresolvable_host_is_a_clean_failure(make_settings, https_server):
    s = make_settings(https_server, allowed_domains=["*.example.test"])
    out = svc(s).detect(f"https://nohost.example.test:{https_server.port}/")
    assert out.status is Status.FAILED and "resolve" in out.message.lower()


def test_private_addresses_blocked_by_default(https_server, make_settings):
    s = make_settings(https_server, allow_private_ips=False)
    out = svc(s).detect(url(https_server))
    assert out.status is Status.FAILED and "private" in out.message.lower() and https_server.beh.seen_paths == []


def test_connection_refused_is_a_clean_failure(make_settings, https_server):
    s = make_settings(https_server, allowed_ports=[1])
    out = svc(s).detect("https://waf.example.test:1/")
    assert out.status is Status.FAILED


def test_cookie_and_auth_headers_cannot_be_injected(https_server, make_settings):
    s = make_settings(https_server, extra_headers={"Cookie": "a=b", "Authorization": "x", "Host": "evil.test", "X-Test": "1"})
    GuardedFetcher(s, resolver=resolver).fetch(parse_target(url(https_server), s.allowed_domains, allowed_ports=(https_server.port,)))
    sent = https_server.beh.seen_headers[0]
    assert sent.get("x-test") == "1"
    assert "cookie" not in sent and "authorization" not in sent
    assert sent["host"] == f"waf.example.test:{https_server.port}"


# ---------------------------------------------------------------- cache + history
def test_cache_prevents_second_request_and_history_is_host_only(https_server, make_settings, tmp_path):
    s = make_settings(https_server, history_enabled=True)
    hist = History(tmp_path / "h.db", 10)
    sv = svc(s, history=hist)
    a = sv.detect(url(https_server, path="/a?secret=1"))
    b = sv.detect(url(https_server, path="/b?secret=2"))
    assert a.mx == b.mx and b.cached and len(https_server.beh.seen_paths) == 1
    rows = hist.recent()
    assert len(rows) == 1 and rows[0].host == "waf.example.test" and rows[0].mx == "mx-test-07"
    assert "secret" not in repr(rows)


def test_history_is_trimmed(tmp_path):
    h = History(tmp_path / "h.db", 3)
    for i in range(10):
        h.add(f"h{i}.example.test", "mx_found", "mx", 403)
    assert [r.host for r in h.recent()] == ["h9.example.test", "h8.example.test", "h7.example.test"]
    h.clear()
    assert h.recent() == []
