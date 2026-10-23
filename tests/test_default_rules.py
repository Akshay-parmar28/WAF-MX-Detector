"""The shipped rules must work without any user configuration.

Sample pages are synthetic: made-up numbers, same wording structure as the block page.
"""

import json

import pytest

from wafmx.config import ConfigStore, ExtractionRule, Settings, default_rules
from wafmx.extractor import extract_mx

S = Settings()


def mx(page: str):
    r = extract_mx(page, {}, S.rules, S.mx_value_pattern)
    return r.mx if r else None


@pytest.mark.parametrize(
    "page,expected",
    [
        ("<html><body><h3>Error</h3><p>This request could not be processed due to an error.<br>Please contact customer support.</p><p>The incident ID is N/A / 1111111111111111111 - 44.20.</p></body></html>", "44.20"),
        ("<p>The incident ID is N/A / 2222222222222222222 - 08.136.</p>", "08.136"),
        ("<p>The incident ID is 4521 / 3333333333333333333 - 12.7.</p>", "12.7"),
        ("<p>The incident&nbsp;ID is N/A / 4444444444444444444 - 08.136.</p>", "08.136"),
        ("<p>The incident ID is N/A /\n 5555555555555555555 -\n 44.20.</p>", "44.20"),
        ("<p>the Incident Id is N/A / 6666666666666666666 - 9.1</p>", "9.1"),
        ("<p>MX ID is 08.136.</p>", "08.136"),
        ("<p>MX ID: mx-42</p>", "mx-42"),
    ],
)
def test_builtin_rules_extract_mx(page, expected):
    assert mx(page) == expected


@pytest.mark.parametrize(
    "page",
    [
        "<h1>403 Forbidden</h1>",
        "<p>The incident ID is 7777777777777777777.</p>",  # incident number only, no MX: must not be mistaken for one
        "<p>Server: nginx</p>",
        "",
    ],
)
def test_builtin_rules_do_not_invent_an_mx(page):
    assert mx(page) is None


def test_v1_placeholder_config_is_upgraded(tmp_path):
    v1 = Settings(schema_version=1, allowed_domains=["example.test"])
    old = ExtractionRule(
        name="Labelled identifier",
        kind="regex",
        pattern=r"(?i)\b(?:mx|gateway|server)[\s_-]*(?:id|name)?\s*[:=]\s*([A-Za-z0-9][A-Za-z0-9._-]{1,63})",
    )
    d = v1.to_dict()
    d["rules"] = [old.__dict__ | {}]
    p = tmp_path / "c.json"
    p.write_text(json.dumps(d))
    s = ConfigStore(p).load()
    assert [r.name for r in s.rules] == [r.name for r in default_rules()]
    assert s.schema_version == 2 and s.allowed_domains == ["example.test"]


def test_customised_rules_survive_upgrade(tmp_path):
    custom = ExtractionRule(name="mine", kind="regex", pattern=r"x(\d)")
    d = Settings(schema_version=1, rules=[custom]).to_dict()
    p = tmp_path / "c.json"
    p.write_text(json.dumps(d))
    assert [r.name for r in ConfigStore(p).load().rules] == ["mine"]


def test_default_settings_validate_cleanly():
    assert Settings(allowed_domains=["example.test"]).validate() == []
