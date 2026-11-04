import json
import re

import pytest

from wscan.scanners import SCANNERS
import wscan.check_catalog as catalog


FIELDS = (
    "title", "short_description", "what_is_tested", "risk_if_vulnerable",
    "verification_overview", "remediation_overview", "limitations",
)


def test_catalog_matches_registry_and_has_plain_text_in_both_languages():
    data = json.loads(catalog._CATALOG_PATH.read_text(encoding="utf-8"))
    assert data["schema_version"] == "1.0.0"
    assert set(data["checks"]) == set(SCANNERS)
    assert sum(bool(item["references"]) for item in data["checks"].values()) == 35
    assert {check_id for check_id, item in data["checks"].items() if not item["references"]} == {
        "security_headers", "graphql", "jwt", "websocket", "mass_assignment", "http_methods",
    }
    for check_id, item in data["checks"].items():
        assert set(item) == {"ja", "en", "references"}
        for lang in ("ja", "en"):
            assert set(item[lang]) == set(FIELDS)
            for field in FIELDS:
                value = item[lang][field]
                assert isinstance(value, str) and value.strip(), (check_id, lang, field)
                assert not re.search(r"<(?:[A-Za-z/])", value), (check_id, lang, field)
        assert isinstance(item["references"], list)
        for ref in item["references"]:
            assert isinstance(ref, dict)
            assert ref["kind"] in {"CWE", "OWASP"}
            assert isinstance(ref["id"], str) and ref["id"].strip()
            if "url" in ref:
                assert isinstance(ref["url"], str) and ref["url"].startswith("https://")


def test_getters_normalize_locale_and_fall_back_to_japanese(monkeypatch):
    catalog._loaded = False
    assert catalog.catalog_version() == "1.0.0"
    ja = catalog.get_check_description("sqli")
    assert ja is not None
    assert catalog.get_check_description("sqli", "EN_us") != ja
    assert catalog.get_check_description("sqli", "fr") == ja
    assert catalog.get_check_description("missing") is None
    assert len(catalog.list_checks("en")) == len(SCANNERS)
    assert catalog.list_checks("en-US") == catalog.list_checks("en")


def test_missing_english_entry_falls_back_to_japanese(monkeypatch):
    item = {"ja": {key: "ja text" for key in FIELDS}, "references": []}
    payload = json.dumps({"schema_version": "1.0.0", "checks": {"sample": item}})

    class Source:
        def read_text(self, encoding):
            return payload

    monkeypatch.setattr(catalog, "_CATALOG_PATH", Source())
    monkeypatch.setattr(catalog, "_loaded", False)
    assert catalog.get_check_description("sample", "en") == catalog.get_check_description("sample", "ja")


@pytest.mark.parametrize("contents", [None, "{broken", '{"schema_version":"2.0.0","checks":{}}'])
def test_missing_or_malformed_catalog_is_empty_without_exception(monkeypatch, contents):
    class Source:
        def read_text(self, encoding):
            if contents is None:
                raise FileNotFoundError("missing catalog")
            return contents

    monkeypatch.setattr(catalog, "_CATALOG_PATH", Source())
    monkeypatch.setattr(catalog, "_loaded", False)
    assert catalog.catalog_version() is None
    assert catalog.list_checks() == ()
    assert catalog.get_check_description("sqli") is None
