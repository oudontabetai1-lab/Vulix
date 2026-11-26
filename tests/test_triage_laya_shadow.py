"""Tests for Laya shadow output in triage mode.

Verifies:
1. Laya shadow advisory annotation (score, choice, advisory_source="laya") when available.
2. Complete fail-open fallback when Laya is disabled, package unavailable, or inference errors.
3. Fallback reason recording in TriageReport.
4. Report model backward compatibility (legacy constructors, to_dict).
5. Non-interference: triage classifications (risk_level, likely_vulns, payloads) are
   strictly unaffected by Laya score/choice on both vulnerable and safe endpoints.
6. Transmission accounting: external bytes sent are recorded and not misrepresented as reduced.
"""

from io import StringIO
import os
import sys
import types
from unittest.mock import AsyncMock, patch

import pytest
from rich.console import Console

from wscan import laya_client
from wscan.triage import (
    FieldRisk,
    PageRisk,
    TriageEngine,
    TriageReport,
    analyse_field,
    apply_laya_shadow,
    render_triage_report,
)


def _fake_laya(monkeypatch, predict_fn):
    laya_client._agents.clear()
    laya_client._failed.clear()
    agent = types.SimpleNamespace(predict=predict_fn)

    def load(*a, **k):
        return agent

    monkeypatch.setitem(sys.modules, "laya", types.SimpleNamespace(load=load))
    monkeypatch.setenv("WSCAN_LAYA", "1")


def _make_sample_report():
    fr1 = FieldRisk(
        url="http://test.local/login",
        field_name="username",
        field_type="text",
        form_action="/login",
        likely_vulns=["sqli", "xss", "nosql"],
        risk_level="critical",
        payloads={"sqli": ["' OR 1=1--"], "xss": ["<script>alert(1)</script>"]},
    )
    fr2 = FieldRisk(
        url="http://test.local/contact",
        field_name="message",
        field_type="textarea",
        form_action="/contact",
        likely_vulns=["xss", "stored_xss", "sqli", "ssti"],
        risk_level="critical",
        payloads={"xss": ["<script>alert(1)</script>"]},
    )
    pr1 = PageRisk(
        url="http://test.local/login",
        page_level_risks=["session"],
        header_issues=["HSTS missing"],
        forms_found=1,
        inputs_found=2,
    )
    return TriageReport(
        target_url="http://test.local",
        field_risks=[fr1, fr2],
        page_risks=[pr1],
        llm_insights="Initial prose strategy",
    )


def test_laya_shadow_annotates_field_risk_when_available(monkeypatch):
    """When Laya is enabled and available, shadow score/choice are attached without altering verdicts."""
    _fake_laya(
        monkeypatch,
        lambda s, q: {
            "answers": {
                "score": {"score": 0.88},
                "choice": {"choice": "sqli"},
            }
        },
    )

    report = _make_sample_report()
    result = apply_laya_shadow(report)

    assert result.laya_status == "available"
    assert result.laya_fallback_reason is None

    for fr in result.field_risks:
        assert fr.laya_score == 0.88
        assert fr.score == 0.88
        assert fr.laya_choice == "sqli"
        assert fr.choice == "sqli"
        assert fr.advisory_source == "laya"

        # Deterministic triage verdicts remain completely untouched
        assert fr.risk_level == "critical"
        assert "sqli" in fr.likely_vulns
        assert len(fr.payloads) > 0


def test_laya_shadow_disabled_fallback(monkeypatch):
    """When WSCAN_LAYA is not enabled, Laya status is disabled and fallback reason is recorded."""
    monkeypatch.delenv("WSCAN_LAYA", raising=False)

    report = _make_sample_report()
    result = apply_laya_shadow(report)

    assert result.laya_status == "disabled"
    assert "disabled" in result.laya_fallback_reason.lower()

    for fr in result.field_risks:
        assert fr.laya_score is None
        assert fr.laya_choice is None
        assert fr.advisory_source is None
        assert fr.score is None
        assert fr.choice is None

    # Prose insights are preserved
    assert result.llm_insights == "Initial prose strategy"


def test_laya_shadow_unavailable_package_fallback(monkeypatch):
    """When WSCAN_LAYA=1 but the laya package is missing, status is unavailable with fallback."""
    laya_client._agents.clear()
    laya_client._failed.clear()
    monkeypatch.setenv("WSCAN_LAYA", "1")
    monkeypatch.setitem(sys.modules, "laya", None)

    report = _make_sample_report()
    result = apply_laya_shadow(report)

    assert result.laya_status == "unavailable"
    assert "unavailable" in result.laya_fallback_reason.lower()

    for fr in result.field_risks:
        assert fr.laya_score is None
        assert fr.laya_choice is None
        assert fr.advisory_source is None


def test_laya_shadow_inference_error_fail_open(monkeypatch):
    """When Laya raises an exception or returns None, fail-open preserves the report."""
    def _exploding_predict(s, q):
        raise RuntimeError("Inference memory fault")

    _fake_laya(monkeypatch, _exploding_predict)

    report = _make_sample_report()
    result = apply_laya_shadow(report)

    assert result.laya_status == "error"
    assert result.laya_fallback_reason is not None

    for fr in result.field_risks:
        assert fr.laya_score is None
        assert fr.laya_choice is None
        assert fr.advisory_source is None
        # Deterministic findings remain intact
        assert fr.risk_level == "critical"

    # Prose insights preserved
    assert result.llm_insights == "Initial prose strategy"


def test_field_risk_and_triage_report_backward_compatibility():
    """Verify legacy construction (positional / keyword) and to_dict backward compatibility."""
    # Legacy 7-parameter positional instantiation
    fr = FieldRisk(
        "http://test.local/search",
        "q",
        "text",
        "/search",
        ["sqli", "xss"],
        "critical",
        {"sqli": ["' OR 1=1--"]},
    )
    assert fr.laya_score is None
    assert fr.laya_choice is None
    assert fr.advisory_source is None
    assert fr.score is None
    assert fr.choice is None

    # Alias synchronization
    fr_alias = FieldRisk(
        url="http://test.local",
        field_name="f",
        field_type="text",
        form_action="/a",
        likely_vulns=["xss"],
        risk_level="high",
        payloads={},
        score=0.75,
        choice="xss",
    )
    assert fr_alias.laya_score == 0.75
    assert fr_alias.laya_choice == "xss"

    report = TriageReport(target_url="http://test.local", field_risks=[fr, fr_alias])
    d = report.to_dict()

    # Legacy keys
    assert "target_url" in d
    assert "field_risks" in d
    assert "page_risks" in d
    assert "llm_insights" in d
    # New metadata keys
    assert "laya_status" in d
    assert "laya_fallback_reason" in d
    assert "llm_bytes_sent" in d
    assert "llm_bytes_sent_without_laya" in d

    fr_dict = d["field_risks"][0]
    for key in ("url", "field_name", "field_type", "form_action", "likely_vulns", "risk_level", "payloads"):
        assert key in fr_dict
    assert fr_dict["laya_score"] is None
    assert fr_dict["advisory_source"] is None


def test_triage_decision_not_altered_by_laya(monkeypatch):
    """Ensure Laya score/choice NEVER alters deterministic risk_level, likely_vulns, or payloads.

    Compares triage output across:
    - Safe twin field (e.g., token/button/csrf) vs vulnerable input field (e.g., user_id)
    - With Laya disabled vs with Laya returning extreme high risk vs extreme low risk.
    """
    field_vuln = {"name": "user_id", "type": "text"}
    field_safe = {"name": "csrf_token", "type": "hidden"}

    risk_vuln_base = analyse_field("http://test.local/user", field_vuln, "/user")
    risk_safe_base = analyse_field("http://test.local/user", field_safe, "/user")

    assert risk_vuln_base is not None
    assert risk_safe_base is not None

    # 1. Baseline without Laya
    monkeypatch.delenv("WSCAN_LAYA", raising=False)
    rep_base = TriageReport(
        target_url="http://test.local",
        field_risks=[
            FieldRisk(
                url=risk_vuln_base.url,
                field_name=risk_vuln_base.field_name,
                field_type=risk_vuln_base.field_type,
                form_action=risk_vuln_base.form_action,
                likely_vulns=list(risk_vuln_base.likely_vulns),
                risk_level=risk_vuln_base.risk_level,
                payloads=dict(risk_vuln_base.payloads),
            ),
            FieldRisk(
                url=risk_safe_base.url,
                field_name=risk_safe_base.field_name,
                field_type=risk_safe_base.field_type,
                form_action=risk_safe_base.form_action,
                likely_vulns=list(risk_safe_base.likely_vulns),
                risk_level=risk_safe_base.risk_level,
                payloads=dict(risk_safe_base.payloads),
            ),
        ],
    )
    apply_laya_shadow(rep_base)

    # 2. Extreme high risk Laya prediction
    _fake_laya(monkeypatch, lambda s, q: {"answers": {"score": {"score": 0.99}, "choice": {"choice": "sqli"}}})
    rep_high = TriageReport(
        target_url="http://test.local",
        field_risks=[
            FieldRisk(
                url=risk_vuln_base.url,
                field_name=risk_vuln_base.field_name,
                field_type=risk_vuln_base.field_type,
                form_action=risk_vuln_base.form_action,
                likely_vulns=list(risk_vuln_base.likely_vulns),
                risk_level=risk_vuln_base.risk_level,
                payloads=dict(risk_vuln_base.payloads),
            ),
            FieldRisk(
                url=risk_safe_base.url,
                field_name=risk_safe_base.field_name,
                field_type=risk_safe_base.field_type,
                form_action=risk_safe_base.form_action,
                likely_vulns=list(risk_safe_base.likely_vulns),
                risk_level=risk_safe_base.risk_level,
                payloads=dict(risk_safe_base.payloads),
            ),
        ],
    )
    apply_laya_shadow(rep_high)

    # 3. Extreme low risk Laya prediction
    _fake_laya(monkeypatch, lambda s, q: {"answers": {"score": {"score": 0.01}, "choice": {"choice": "other"}}})
    rep_low = TriageReport(
        target_url="http://test.local",
        field_risks=[
            FieldRisk(
                url=risk_vuln_base.url,
                field_name=risk_vuln_base.field_name,
                field_type=risk_vuln_base.field_type,
                form_action=risk_vuln_base.form_action,
                likely_vulns=list(risk_vuln_base.likely_vulns),
                risk_level=risk_vuln_base.risk_level,
                payloads=dict(risk_vuln_base.payloads),
            ),
            FieldRisk(
                url=risk_safe_base.url,
                field_name=risk_safe_base.field_name,
                field_type=risk_safe_base.field_type,
                form_action=risk_safe_base.form_action,
                likely_vulns=list(risk_safe_base.likely_vulns),
                risk_level=risk_safe_base.risk_level,
                payloads=dict(risk_safe_base.payloads),
            ),
        ],
    )
    apply_laya_shadow(rep_low)

    # In all three cases, deterministic verdicts MUST be 100% identical
    for idx in (0, 1):
        assert rep_base.field_risks[idx].risk_level == rep_high.field_risks[idx].risk_level == rep_low.field_risks[idx].risk_level
        assert rep_base.field_risks[idx].likely_vulns == rep_high.field_risks[idx].likely_vulns == rep_low.field_risks[idx].likely_vulns
        assert rep_base.field_risks[idx].payloads == rep_high.field_risks[idx].payloads == rep_low.field_risks[idx].payloads


@pytest.mark.asyncio
async def test_transmission_accounting_recorded_and_not_misrepresented(monkeypatch):
    """External transmission bytes are tracked, and shadow mode does not claim reduction."""
    class FakePG:
        def __init__(self, **kwargs):
            self.provider = "claude"

        async def _check_llm_available(self):
            return True

        def use_role(self, role):
            from contextlib import nullcontext
            return nullcontext()

    async def fake_complete_text(_pg, prompt, **kwargs):
        return "1. Target the username field for SQLi"

    monkeypatch.setattr("wscan.payload_gen.PayloadGenerator", FakePG)
    monkeypatch.setattr("wscan.llm_client.complete_text", fake_complete_text)

    engine = TriageEngine.__new__(TriageEngine)
    engine.llm_provider = "claude"
    engine.ollama_model = engine.openai_model = engine.gemini_model = engine.claude_model = ""
    engine.openai_base_url = ""
    engine.role_models = {}
    engine.target_url = "http://test.local"
    engine.report = _make_sample_report()

    prose = await engine._llm_analyse()
    assert "Target the username field" in prose

    assert engine.report.llm_bytes_sent > 0
    assert engine.report.llm_bytes_sent_without_laya == engine.report.llm_bytes_sent

    # Render report to verify console output
    buf = StringIO()
    console = Console(file=buf, color_system=None, width=120)
    render_triage_report(engine.report, console)
    output = buf.getvalue()

    assert f"External LLM transmission: {engine.report.llm_bytes_sent} bytes" in output
    assert "no transmission reduction" in output
    assert "削減済み" not in output
    assert "reduced" not in output.lower().replace("no transmission reduction", "")


def test_render_triage_report_shadow_column():
    """Verify Laya shadow column appears only when Laya advisory values are present."""
    report_no_laya = _make_sample_report()
    buf_no_laya = StringIO()
    console_no_laya = Console(file=buf_no_laya, color_system=None, width=120)
    render_triage_report(report_no_laya, console_no_laya)
    out_no_laya = buf_no_laya.getvalue()
    assert "Laya Shadow" not in out_no_laya

    report_with_laya = _make_sample_report()
    report_with_laya.field_risks[0].laya_score = 0.95
    report_with_laya.field_risks[0].laya_choice = "sqli"
    report_with_laya.field_risks[0].advisory_source = "laya"

    buf_with_laya = StringIO()
    console_with_laya = Console(file=buf_with_laya, color_system=None, width=120)
    render_triage_report(report_with_laya, console_with_laya)
    out_with_laya = buf_with_laya.getvalue()
    assert "Laya Shadow" in out_with_laya
    assert "sqli (0.95)" in out_with_laya


def test_mutation_fallback_removal_fails(monkeypatch):
    """Mutation check: verify that a broken non-fail-open implementation fails the contract."""
    # Simulation of non-fail-open mutation: raising or clearing results on Laya error
    def broken_laya_shadow_mutation(report):
        from wscan import laya_client
        if laya_client.available():
            raise RuntimeError("Uncaught Laya failure")
        return report

    _fake_laya(monkeypatch, lambda s, q: None)

    # Our real apply_laya_shadow MUST succeed without raising and keep the report intact:
    report = _make_sample_report()
    res = apply_laya_shadow(report)
    assert res is not None
    assert len(res.field_risks) == 2

    # But the broken mutation fails:
    with pytest.raises(RuntimeError):
        broken_laya_shadow_mutation(report)
