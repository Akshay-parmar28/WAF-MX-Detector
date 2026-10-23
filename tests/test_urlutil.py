import pytest

from wafmx.urlutil import UrlError, extract_urls, host_matches, normalize_domain_pattern, parse_target

ALLOW = ["example.test", "*.corp.example.test"]


@pytest.mark.parametrize(
    "raw,expected",
    [
        ("Example.TEST", "example.test"),
        ("*.Corp.Example.test.", "*.corp.example.test"),
        ("  a.b.c  ", "a.b.c"),
        ("", None),
        ("localhost", None),
        ("10.0.0.1", None),
        ("exa*mple.com", None),
        ("http://example.com", None),
        ("example.com:443", None),
        ("-bad.example.com", None),
        ("*.", None),
    ],
)
def test_normalize(raw, expected):
    assert normalize_domain_pattern(raw) == expected


def test_host_matching_is_exact_or_wildcard_subdomain_only():
    assert host_matches("example.test", ALLOW)
    assert not host_matches("www.example.test", ALLOW)  # exact entry does not cover subdomains
    assert host_matches("a.corp.example.test", ALLOW)
    assert host_matches("a.b.corp.example.test", ALLOW)
    assert not host_matches("corp.example.test", ALLOW)  # wildcard needs a subdomain
    assert not host_matches("example.test.evil.test", ALLOW)
    assert not host_matches("evilexample.test", ALLOW)
    assert not host_matches("xcorp.example.test", ALLOW)


def test_extract_urls_trims_punctuation_and_dedupes():
    text = "See (https://a.corp.example.test/x?y=1), and https://a.corp.example.test/x?y=1. Also <https://example.test/p>!"
    assert extract_urls(text) == ["https://a.corp.example.test/x?y=1", "https://example.test/p"]


def test_extract_bare_hosts_only_when_allowlisted():
    text = "report.pdf notes.txt a.corp.example.test/login other.org/x"
    assert extract_urls(text, ALLOW) == ["a.corp.example.test/login"]
    assert extract_urls(text) == []


def test_extract_ignores_email_addresses():
    assert extract_urls("mail me: bob@a.corp.example.test", ALLOW) == []


@pytest.mark.parametrize(
    "url,msg",
    [
        ("https://other.org/x", "not in the allowed"),
        ("https://user:pw@example.test/", "credentials"),
        ("https://example.test@evil.test/", "credentials"),
        ("ftp://example.test/", "not supported"),
        ("javascript:alert(1)", "Malformed|not supported"),
        ("http://example.test/", "http is disabled"),
        ("https://10.1.2.3/", "IP-address"),
        ("https://[::1]/", "IP-address"),
        ("https://example.test:8443/", "Port 8443"),
        ("https://example.test.evil.test/", "not in the allowed"),
        ("https://example.test/\r\nX: y", "control characters"),
        ("https:///path", "no host"),
        ("", "No URL"),
    ],
)
def test_parse_target_rejects(url, msg):
    with pytest.raises(UrlError, match=msg):
        parse_target(url, ALLOW)


def test_parse_target_accepts_and_normalises():
    t = parse_target("HTTPS://A.Corp.Example.TEST:443/p/q?z=1#frag", ALLOW)
    assert (t.scheme, t.host, t.port, t.path_query) == ("https", "a.corp.example.test", 443, "/p/q?z=1")
    assert t.origin == "https://a.corp.example.test"
    assert parse_target("example.test/x", ALLOW).origin == "https://example.test"


def test_empty_allowlist_rejects_everything():
    with pytest.raises(UrlError, match="No allowed domains"):
        parse_target("https://example.test/", [])


def test_http_allowed_only_when_enabled():
    t = parse_target("http://example.test/", ALLOW, allow_http=True)
    assert t.scheme == "http"
