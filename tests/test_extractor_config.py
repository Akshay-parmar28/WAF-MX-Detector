import json

from wafmx.config import ConfigStore, ExtractionRule, Settings
from wafmx.extractor import explain, extract_mx
from wafmx.store import TTLCache
from wafmx.win.hotkey import MOD_ALT, MOD_CONTROL, parse_hotkey

import pytest

VAL = r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$"
PAGE = '<html><head><meta name="x-gw" content="mx-meta-1"><script>var gateway="no-script"</script></head><body><p>Gateway:&nbsp;mx-body-2</p><!-- id=mx-comment-3 --></body></html>'


def rule(**kw):
    return ExtractionRule(**{"name": "r", **kw})


def test_regex_between_meta_header():
    assert extract_mx(PAGE, {}, [rule(kind="regex", pattern=r"id=(mx-[a-z]+-\d)")], VAL).mx == "mx-comment-3"
    assert extract_mx(PAGE, {}, [rule(kind="between", pattern="id=", suffix=" -->")], VAL).mx == "mx-comment-3"
    assert extract_mx(PAGE, {}, [rule(kind="meta", pattern="X-GW")], VAL).mx == "mx-meta-1"
    assert extract_mx("", {"X-Gateway": "mx-hdr-9"}, [rule(kind="header", pattern="x-gateway")], VAL).mx == "mx-hdr-9"


def test_text_rule_sees_decoded_visible_text_not_scripts():
    r = rule(kind="regex", pattern=r"Gateway:\s*(mx-[a-z]+-\d)")
    assert extract_mx(PAGE, {}, [r], VAL).mx == "mx-body-2"  # visible text has the entity decoded
    assert extract_mx(PAGE, {}, [rule(kind="regex", pattern=r"gateway=\"([a-z-]+)\"")], VAL).mx == "no-script"  # raw match still possible when asked
    from wafmx.extractor import html_to_text

    assert "no-script" not in html_to_text(PAGE)[0]


def test_value_pattern_rejects_garbage_and_first_valid_rule_wins():
    junk = rule(name="junk", kind="regex", pattern=r"<h1>(.*?)</h1>")
    page = "<h1>Request blocked!</h1> Gateway: mx-ok-1"
    good = rule(name="good", kind="regex", pattern=r"Gateway:\s*(\S+)")
    res = extract_mx(page, {}, [junk, good], VAL)
    assert (res.mx, res.rule_name) == ("mx-ok-1", "good")
    assert extract_mx("<h1>Request blocked!</h1>", {}, [junk], VAL) is None


def test_disabled_and_broken_rules_are_skipped():
    rules = [rule(kind="regex", pattern="(", enabled=True), rule(kind="regex", pattern=r"(mx-\d)", enabled=False), rule(kind="regex", pattern=r"(mx-\d)")]
    assert extract_mx("mx-5", {}, rules, VAL).mx == "mx-5"


def test_explain_reports_hit_miss_reject():
    rules = [rule(name="a", kind="regex", pattern=r"nomatch(\d)"), rule(name="b", kind="regex", pattern=r"<h1>(.*)</h1>"), rule(name="c", kind="regex", pattern=r"(mx-\d)")]
    lines = explain("<h1>bad value!</h1> mx-3", {}, rules, VAL)
    assert lines[0].startswith("[miss]") and lines[1].startswith("[reject]") and lines[2].startswith("[HIT]")


def test_settings_roundtrip_and_validation(tmp_path):
    store = ConfigStore(tmp_path / "c.json")
    assert store.load().allowed_domains == []  # nothing org-specific by default
    s = Settings(allowed_domains=["example.test"], hotkey="ctrl+shift+f9")
    assert s.validate() == []
    store.save(s)
    again = store.load()
    assert again.allowed_domains == ["example.test"] and again.hotkey == "ctrl+shift+f9" and isinstance(again.rules[0], ExtractionRule)


def test_validation_catches_problems():
    s = Settings(allowed_domains=["bad host"], probe_path="nope", hotkey="m", connect_timeout=0, max_response_bytes=5, rules=[ExtractionRule(pattern="(", kind="regex")])
    msgs = " | ".join(s.validate())
    for needle in ("Invalid domain", "Probe path", "Hotkey", "Connect timeout", "Max response", "bad regex"):
        assert needle in msgs


def test_corrupt_config_is_set_aside(tmp_path):
    p = tmp_path / "c.json"
    p.write_text("{not json")
    assert ConfigStore(p).load().allowed_domains == []
    assert (tmp_path / "c.json.bad").exists()


def test_unknown_keys_ignored_and_import_export(tmp_path):
    p = tmp_path / "c.json"
    p.write_text(json.dumps({"allowed_domains": ["example.test"], "future_option": 1}))
    s = ConfigStore(p).load()
    assert s.allowed_domains == ["example.test"]
    out = tmp_path / "exp.json"
    ConfigStore(p).export_to(s, out)
    assert ConfigStore(p).import_from(out).allowed_domains == ["example.test"]


def test_hotkey_parser():
    assert parse_hotkey("Ctrl+Alt+M") == (MOD_CONTROL | MOD_ALT, ord("M"))
    assert parse_hotkey("ctrl+f9")[1] == 0x78
    for bad in ("m", "ctrl", "ctrl+", "foo+m", "ctrl+??", "ctrl+f99"):
        with pytest.raises(ValueError):
            parse_hotkey(bad)


def test_ttl_cache_expiry_and_eviction():
    import time

    c = TTLCache(ttl=0.05, max_items=2)
    c.put("a", 1)
    assert c.get("a") == 1
    time.sleep(0.07)
    assert c.get("a") is None
    c.put("x", 1), c.put("y", 2), c.put("z", 3)
    assert c.get("x") is None and c.get("z") == 3
