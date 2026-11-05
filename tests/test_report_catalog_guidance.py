from types import SimpleNamespace

import pytest

from wscan import check_catalog, report
from wscan.check_catalog import CatalogReference, get_check_description
from wscan.report import ReportGenerator
from wscan.scanners.base import Finding


@pytest.mark.parametrize("lang", ["ja", "en"])
def test_known_check_guidance_is_localized(tmp_path, monkeypatch, lang):
    monkeypatch.setattr(check_catalog, "_loaded", False)
    finding = Finding.from_dict({"check_type": "sqli", "severity": "high",
                                 "url": "http://fixture.test/", "field_name": "q",
                                 "payload": "'", "evidence": "legacy evidence"})
    html = ReportGenerator(tmp_path, lang=lang).generate(
        "fixture", [finding], [finding.url], ["sqli"]
    ).read_text()
    description = get_check_description("sqli", lang)
    assert description.short_description in html
    assert description.risk_if_vulnerable in html
    assert description.remediation_overview in html
    assert 'href="https://cwe.mitre.org/data/definitions/89.html"' in html
    assert "CWE 89.html" in html
    assert "一般的なチェックガイダンス" in html if lang == "ja" else "General check guidance" in html
    assert "legacy evidence" in html


def test_unknown_check_uses_neutral_fallback(tmp_path):
    finding = Finding.from_dict({"check_type": "unknown_check", "severity": "low",
                                 "url": "http://fixture.test/", "field_name": "q",
                                 "payload": "", "evidence": "e"})
    html = ReportGenerator(tmp_path).generate("fixture", [finding], [], []).read_text()
    assert "一般的なチェックガイダンスは利用できません。" in html


def test_catalog_content_is_escaped_and_unsafe_reference_is_plain_text(tmp_path, monkeypatch):
    description = SimpleNamespace(short_description="<script>alert(1)</script>",
                                  risk_if_vulnerable="<b>risk</b>",
                                  remediation_overview="<img src=x>")
    monkeypatch.setattr(report, "get_check_description", lambda check, lang: description)
    monkeypatch.setattr(report, "get_check_references", lambda check: (
        CatalogReference("CWE", "<script>", "javascript:alert(1)"),
    ))
    finding = Finding.from_dict({"check_type": "sqli", "severity": "high",
                                 "url": "http://fixture.test/", "field_name": "q",
                                 "payload": "'", "evidence": "e"})
    html = ReportGenerator(tmp_path).generate("fixture", [finding], [], []).read_text()
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "&lt;b&gt;risk&lt;/b&gt;" in html
    assert "&lt;img src=x&gt;" in html
    assert 'href="javascript:' not in html
    assert "CWE &lt;script&gt;" in html


def test_catalog_guidance_does_not_change_severity_or_finding_counts(tmp_path, monkeypatch):
    findings = [Finding.from_dict({"check_type": "sqli", "severity": "high",
                                   "url": "http://fixture.test/", "field_name": "q",
                                   "payload": "'", "evidence": "e", "verified": True})]
    rendered = ReportGenerator(tmp_path).generate("fixture", findings, [], []).read_text()
    monkeypatch.setattr(report, "get_check_description", lambda check, lang: None)
    monkeypatch.setattr(report, "get_check_references", lambda check: ())
    without_catalog = ReportGenerator(tmp_path).generate("fixture", findings, [], []).read_text()
    markers = ('class="count total-count"', 'class="count high-count"', 'class="finding-card')
    assert tuple(rendered.count(marker) for marker in markers) == tuple(
        without_catalog.count(marker) for marker in markers
    )
    assert "一般的なチェックガイダンス" in rendered
    assert "一般的なチェックガイダンスは利用できません。" in without_catalog
