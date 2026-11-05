from wscan import check_catalog
from wscan import sarif
from wscan.i18n import translate_or
from wscan.sarif import _RULE_DESCS, SarifExporter


FINDING = {
    "check_type": "sqli", "url": "http://fixture.test/", "field_name": "q",
    "payload": "'", "severity": "high", "verified": True,
    "verification_state": "reproduced",
}


def _rule(doc, check="sqli"):
    return next(rule for rule in doc["runs"][0]["tool"]["driver"]["rules"]
                if rule["id"] == check)


def test_catalog_rule_text_is_localized_and_help_contains_risk_and_mitigation(monkeypatch):
    monkeypatch.setattr(check_catalog, "_loaded", False)
    for lang in ("ja", "en"):
        rule = _rule(SarifExporter(lang).export([FINDING]))
        desc = check_catalog.get_check_description("sqli", lang)
        assert rule["shortDescription"]["text"] == desc.short_description
        assert rule["fullDescription"]["text"] == desc.short_description
        assert desc.risk_if_vulnerable in rule["help"]["text"]
        assert desc.remediation_overview in rule["help"]["text"]
        assert rule["help"]["markdown"] == rule["help"]["text"]


def test_unknown_check_preserves_legacy_text_and_catalog_does_not_change_results(monkeypatch):
    real_lookup = sarif.get_check_description
    monkeypatch.setattr(sarif, "get_check_description", lambda *_: None)
    unknown = {**FINDING, "check_type": "legacy_unknown"}
    rule = _rule(SarifExporter().export([unknown]), "legacy_unknown")
    assert rule["shortDescription"]["text"] == "legacy_unknown"
    assert rule["fullDescription"]["text"] == "legacy_unknown"

    monkeypatch.setattr(sarif, "get_check_description", lambda *_: None)
    without_catalog = SarifExporter().export([FINDING])
    monkeypatch.setattr(sarif, "get_check_description",
                        lambda check, lang: real_lookup(check, lang))
    with_catalog = SarifExporter().export([FINDING])
    assert with_catalog["runs"][0]["results"] == without_catalog["runs"][0]["results"]
    assert [r["id"] for r in with_catalog["runs"][0]["tool"]["driver"]["rules"]] == [
        r["id"] for r in without_catalog["runs"][0]["tool"]["driver"]["rules"]
    ]


def test_known_check_references_only_emit_http_help_uri(monkeypatch):
    monkeypatch.setattr(check_catalog, "_loaded", False)
    refs = check_catalog.get_check_references("sqli")
    monkeypatch.setattr(sarif, "get_check_references", lambda _: (
        type(refs[0])("CWE", "1", "javascript:alert(1)"),
        type(refs[0])("CWE", "2", "http://example.test/ref"),
    ))
    rule = _rule(SarifExporter().export([FINDING]))
    assert rule["helpUri"] == "http://example.test/ref"
    assert "$schema" in SarifExporter().export([FINDING])
    assert SarifExporter().export([FINDING])["version"] == "2.1.0"
    assert set(rule) >= {"id", "name", "shortDescription", "fullDescription", "help",
                         "defaultConfiguration", "properties"}


def test_known_check_legacy_fallback_matches_translation(monkeypatch):
    monkeypatch.setattr(sarif, "get_check_description", lambda *_: None)
    rule = _rule(SarifExporter().export([FINDING]))
    assert rule["shortDescription"]["text"] == translate_or(
        "sarif.rule.sqli", "ja", _RULE_DESCS["sqli"]
    )
