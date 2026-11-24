"""Security regression tests for target-derived text passed into LLM prompts."""
from __future__ import annotations

import types

import pytest

from wscan.remediation import generate_fix


@pytest.mark.asyncio
async def test_remediation_prompt_redacts_finding_payload_without_losing_fix_context(
    monkeypatch,
):
    from wscan import url_scope

    captured = {}

    async def fake_call(_payload_gen, prompt):
        captured["prompt"] = prompt
        return "エスケープと入力検証を行ってください。" * 3

    monkeypatch.setattr("wscan.remediation._call_llm_raw", fake_call)
    monkeypatch.setitem(
        url_scope._SECRET_VALUES,
        "configured-remediation-secret",
        "configured_auth_value",
    )
    finding = types.SimpleNamespace(
        check_type="xss",
        url="https://alice:password@target.test/search?token=url-token-secret",
        field_name="search_term",
        payload=(
            '<svg onload=alert(7)> Bearer configured-remediation-secret '
            "?api_key=payload-key-secret"
        ),
        evidence=(
            "reflected in double_quoted_attr; Authorization: Bearer evidence-token-secret; "
            "Cookie: sessionid=cookie-token-secret"
        ),
    )

    _text, is_ai = await generate_fix(finding, types.SimpleNamespace(provider="ollama"))

    prompt = captured["prompt"]
    assert is_ai
    for secret in (
        "configured-remediation-secret",
        "url-token-secret",
        "payload-key-secret",
        "evidence-token-secret",
        "cookie-token-secret",
        "password@",
        "alice:",
    ):
        assert secret not in prompt
    assert "xss" in prompt
    assert "search_term" in prompt
    assert "/search" in prompt
    assert "double_quoted_attr" in prompt
    assert "<svg onload=alert(7)>" in prompt


@pytest.mark.asyncio
async def test_triage_prompt_redacts_urls_fields_and_header_observations(monkeypatch):
    from wscan import url_scope
    from wscan.triage import FieldRisk, PageRisk, TriageEngine, TriageReport

    captured = {}

    class FakePG:
        def __init__(self, **_kwargs):
            self.provider = "ollama"

        async def _check_llm_available(self):
            return True

        def use_role(self, _role):
            from contextlib import nullcontext
            return nullcontext()

    async def fake_complete_text(_pg, prompt, **_kwargs):
        captured["prompt"] = prompt
        return "Prioritize the search field."

    monkeypatch.setattr("wscan.payload_gen.PayloadGenerator", FakePG)
    monkeypatch.setattr("wscan.llm_client.complete_text", fake_complete_text)
    monkeypatch.setitem(url_scope._SECRET_VALUES, "triage-config-secret", "test_auth")
    engine = TriageEngine.__new__(TriageEngine)
    engine.llm_provider = "ollama"
    engine.ollama_model = engine.openai_model = engine.gemini_model = engine.claude_model = ""
    engine.openai_base_url = ""
    engine.role_models = {}
    engine.report = TriageReport(
        target_url="https://user:password@target.test/home?token=triage-url-secret",
        field_risks=[FieldRisk(
            url="https://target.test/search?api_key=triage-field-secret",
            field_name="search_term",
            field_type="text",
            form_action="/search",
            likely_vulns=["xss"],
            risk_level="high",
            payloads={"xss": ["Bearer triage-config-secret"]},
        )],
        page_risks=[PageRisk(
            url="https://target.test/home?token=triage-page-secret",
            page_level_risks=["security_headers"],
            header_issues=["Set-Cookie: sessionid=triage-cookie-secret"],
            forms_found=1,
            inputs_found=1,
        )],
    )

    output = await engine._llm_analyse()
    prompt = captured["prompt"]
    assert output == "Prioritize the search field."
    for secret in (
        "password@", "triage-url-secret", "triage-field-secret",
        "triage-page-secret", "triage-cookie-secret", "triage-config-secret",
    ):
        assert secret not in prompt
    assert "search_term" in prompt and "xss" in prompt and "Set-Cookie" in prompt


@pytest.mark.asyncio
async def test_attack_planner_prompt_wraps_page_inputs_url_and_fingerprint(monkeypatch):
    from wscan.attack_planner import AttackPlanner
    from wscan.payload_gen import PayloadGenerator

    captured = {}
    planner = AttackPlanner(PayloadGenerator(provider="ollama"), ["xss"])

    async def fake_stream(prompt):
        captured["prompt"] = prompt
        return '{"page_purpose":"search","fields":[{"name":"q","priority_checks":["xss"]}]}'

    planner._call_ollama = fake_stream
    await planner._llm_plan(
        "https://user:password@target.test/search?token=planner-url-secret",
        "<html><title>Bearer planner-title-secret</title><body>Syntax error</body></html>",
        [{"inputs": [{"name": "q", "type": "text"}]}],
        ["q"],
        site_map="/search?api_key=planner-map-secret",
        fingerprint="Response header Authorization: Bearer planner-header-secret",
    )

    prompt = captured["prompt"]
    for secret in (
        "password@", "planner-url-secret", "planner-title-secret",
        "planner-map-secret", "planner-header-secret",
    ):
        assert secret not in prompt
    assert "field 'q'" in prompt and "xss" in prompt


@pytest.mark.asyncio
async def test_web_intelligence_redacts_context_before_search_and_prompt(monkeypatch):
    from wscan.llm_web_tools import research_vulnerability

    sent_queries = []

    async def fake_search(query, max_results=5):
        sent_queries.append(query)
        return "<untrusted_target_data>Bearer web-result-secret</untrusted_target_data>"

    monkeypatch.setattr("wscan.llm_web_tools.search_web", fake_search)
    result = await research_vulnerability(
        "xss", "https://user:password@target.test/?token=web-context-secret"
    )

    assert len(sent_queries) == 1
    for text in (sent_queries[0], result):
        assert "password@" not in text
        assert "web-context-secret" not in text
        assert "web-result-secret" not in text
    assert "XSS bypass payload" in sent_queries[0]
    assert "target.test" not in sent_queries[0]
    assert "Web Intelligence" in result


def test_agent_verifier_prompt_redacts_finding_payload_and_evidence(monkeypatch):
    from wscan import url_scope
    from wscan.agent_harness import AgentRole, AgentWorkItem
    from wscan.llm_agent_browser import AgentBrowserScanner

    monkeypatch.setitem(url_scope._SECRET_VALUES, "agent-config-secret", "test_credential")
    scanner = AgentBrowserScanner("https://target.test", checks=["xss"])
    scanner._candidate_for_work = lambda _work: {
        "check_type": "xss",
        "url": "https://user:password@target.test/search?token=agent-url-secret",
        "field_name": "search_term",
        "payload": "<svg onload=alert(3)> Bearer agent-config-secret ?api_key=agent-payload-secret",
        "evidence": "reflected in double_quoted_attr; Cookie: sessionid=agent-cookie-secret",
    }
    work = AgentWorkItem("verifier-redaction", AgentRole.VERIFIER, "candidate")
    prompt = scanner._build_work_task(work, [])

    for secret in (
        "password@", "agent-url-secret", "agent-config-secret",
        "agent-payload-secret", "agent-cookie-secret",
    ):
        assert secret not in prompt
    assert "search_term" in prompt and "double_quoted_attr" in prompt
    assert "<svg onload=alert(3)>" in prompt


def test_agent_task_and_scope_prompts_redact_target_url_values():
    from wscan.agent_harness import AgentRole, AgentWorkItem
    from wscan.llm_agent_browser import AgentBrowserScanner

    scanner = AgentBrowserScanner(
        "https://user:password@target.test/search?token=agent-target-secret",
        checks=["xss"],
        login_url="https://authuser:authpass@target.test/login?api_key=agent-login-secret",
        auth_user="configured-user",
        auth_pass="configured-password",
    )
    tasks = [scanner._build_task(), scanner._build_recon_task()]
    auth_work = AgentWorkItem("auth-redaction", AgentRole.AUTHENTICATOR, scanner.login_url)
    tasks.append(scanner._build_work_task(auth_work, []))
    tasks.append(scanner._build_security_scope_policy())

    for prompt in tasks:
        assert "password@" not in prompt
        assert "authpass@" not in prompt
        assert "agent-target-secret" not in prompt
        assert "agent-login-secret" not in prompt
    assert all("target.test" in prompt for prompt in tasks)


def test_agent_reviewer_prompt_wraps_gaps_and_work_ledger():
    from wscan.agent_harness import AgentRole, AgentWorkItem
    from wscan.llm_agent_browser import AgentBrowserScanner

    scanner = AgentBrowserScanner("https://target.test", checks=["xss"])
    scanner._harness = types.SimpleNamespace(state=types.SimpleNamespace(
        reviewer_gaps=["Bearer reviewer-gap-secret; reflected in double_quoted_attr"],
        work_queue=[types.SimpleNamespace(
            role=AgentRole.PROBE_SPECIALIST,
            target="https://user:password@target.test/search?token=reviewer-ledger-secret",
            check_type="xss",
            status=types.SimpleNamespace(value="queued"),
        )],
    ))
    work = AgentWorkItem("reviewer-ledger", AgentRole.ADVERSARIAL_REVIEWER, "https://target.test")
    prompt = scanner._build_work_task(work, [])

    for secret in ("reviewer-gap-secret", "password@", "reviewer-ledger-secret"):
        assert secret not in prompt
    assert "double_quoted_attr" in prompt and "xss" in prompt
    assert "<untrusted_target_data" in prompt


@pytest.mark.asyncio
async def test_web_tool_error_context_is_redacted(monkeypatch):
    from wscan.llm_web_tools import fetch_url, search_web

    class FailingClient:
        def __init__(self, **_kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return False

        async def post(self, *_args, **_kwargs):
            raise RuntimeError("request failed Bearer web-error-secret")

        async def get(self, *_args, **_kwargs):
            raise RuntimeError("request failed Bearer web-error-secret")

    monkeypatch.setattr("wscan.llm_web_tools.httpx.AsyncClient", FailingClient)
    search_error = await search_web("generic xss")
    fetch_error = await fetch_url("https://user:password@target.test/?token=web-error-secret")

    for result in (search_error, fetch_error):
        assert "web-error-secret" not in result
        assert "password@" not in result
        assert "Bearer <redacted>" in result
        assert "<untrusted_target_data" in result


@pytest.mark.asyncio
async def test_scan_report_ai_prompts_redact_target_and_finding_data(monkeypatch, tmp_path):
    from wscan import url_scope
    from wscan.engine import ScanEngine

    class FakePayloadGenerator:
        async def _check_llm_available(self):
            return True

    monkeypatch.setitem(url_scope._SECRET_VALUES, "report-config-secret", "test_credential")
    engine = ScanEngine.__new__(ScanEngine)
    engine.payload_gen = FakePayloadGenerator()
    engine.target_url = "https://user:password@target.test/?token=report-target-secret"
    engine.output_dir = tmp_path
    finding = types.SimpleNamespace(
        check_type="xss",
        severity="high",
        url="https://target.test/search?api_key=report-finding-secret",
        field_name="search_term",
        payload="<svg onload=alert(4)> Bearer report-config-secret",
        evidence="reflected in double_quoted_attr; Cookie: sessionid=report-cookie-secret",
    )
    engine.all_findings = [finding]
    prompts = []

    async def fake_llm_text(prompt):
        prompts.append(prompt)
        return "修正方針を示します。" * 4

    engine._call_llm_text = fake_llm_text
    await ScanEngine._ai_analysis_report(engine)

    assert len(prompts) == 2
    for prompt in prompts:
        for secret in (
            "password@", "report-target-secret", "report-finding-secret",
            "report-config-secret", "report-cookie-secret",
        ):
            assert secret not in prompt
    assert "xss" in prompts[0]
    assert "search_term" in prompts[1]
    assert "double_quoted_attr" in prompts[0] or "double_quoted_attr" in prompts[1]
