"""Tests for Agent mode auth claim ground-truth verification labeling.

CLAUDE.md rule:
Agent layer = originality: NEVER drop or downgrade Agent findings via deterministic
re-verification; label provenance/certainty instead.

Covers:
  - Unit tests for pure function verify_agent_auth_claim
  - Integration tests with fake/stub agent and browser (no real LLM)
  - Verification that unverified auth claims record "auth:login_not_verified"
  - Verification that findings and severities are never dropped or altered
"""
from __future__ import annotations

import json
import re
import sys
import types
from unittest.mock import patch

import pytest

from wscan.auth_detect import (
    AGENT_AUTH_COVERAGE_GAP,
    AGENT_AUTH_UNVERIFIED,
    AGENT_AUTH_VERIFIED,
    AgentAuthVerification,
    _detect_token_diff,
    verify_agent_auth_claim,
)
from wscan.llm_agent_browser import AgentBrowserScanner, AgentRole


# =============================================================================
# 1. Pure Helper Unit Tests
# =============================================================================

class TestVerifyAgentAuthClaimPure:
    """Test pure function verify_agent_auth_claim without any browser or network I/O."""

    def test_verified_when_cookies_departure_and_no_form(self):
        before = []
        after = [{"name": "session_id", "value": "secret123", "domain": "target.test", "path": "/"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=before,
            after_cookies=after,
            current_url="http://target.test/dashboard",
            login_url="http://target.test/login",
            body="<html><body><h1>Dashboard</h1><p>Welcome back!</p></body></html>",
        )
        assert result.status == AGENT_AUTH_VERIFIED
        assert result.is_verified is True
        assert result.reasons == []
        assert result.coverage_gap == ""
        assert result.cookie_or_token_gained is True
        assert result.left_login_page is True
        assert result.login_form_absent is True

    def test_verified_when_token_in_local_storage(self):
        before_tokens = []
        after_tokens = [{"storage": "local", "key": "access_token", "value": "eyJhbGciOiJIUzI1NiJ9.test"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=[],
            before_tokens=before_tokens,
            after_tokens=after_tokens,
            current_url="http://target.test/app/home",
            login_url="http://target.test/login",
            body="<html><body><div id='app'>App view</div></body></html>",
        )
        assert result.status == AGENT_AUTH_VERIFIED
        assert result.is_verified is True
        assert result.reasons == []
        assert result.coverage_gap == ""
        assert result.cookie_or_token_gained is True

    def test_regression_stale_unchanged_token_left_page_no_form_is_unverified(self):
        # Regression test for Gate 2(a):
        # Pre-existing/stale token unchanged during login must NOT be treated as gained.
        # Even if page navigated away and no login form remains, status must be unverified_auth_claim.
        stale = [{"storage": "local", "key": "access_token", "value": "stale_unchanged_jwt_value_123"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=[],
            before_tokens=stale,
            after_tokens=stale,
            current_url="http://target.test/app/home",
            login_url="http://target.test/login",
            body="<html><body><div id='app'>App view</div></body></html>",
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert result.is_verified is False
        assert "missing_session_artifact" in result.reasons
        assert result.coverage_gap == AGENT_AUTH_COVERAGE_GAP
        assert result.cookie_or_token_gained is False
        assert result.left_login_page is True
        assert result.login_form_absent is True

    def test_unverified_when_no_before_token_snapshot_exists(self):
        # When no 'before' snapshot exists (before_tokens=None), treat as not gained (unverified)
        # rather than guessing that everything after is new.
        tokens = [{"storage": "local", "key": "session_token", "value": "some_valid_looking_token_123"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=[],
            before_tokens=None,
            after_tokens=tokens,
            current_url="http://target.test/app/home",
            login_url="http://target.test/login",
            body="<html><body><div id='app'>App view</div></body></html>",
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert result.is_verified is False
        assert "missing_session_artifact" in result.reasons
        assert result.cookie_or_token_gained is False

    def test_verified_when_token_value_modified(self):
        before = [{"storage": "local", "key": "auth_token", "value": "guest_anon_token_123"}]
        after = [{"storage": "local", "key": "auth_token", "value": "logged_in_member_token_456"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=[],
            before_tokens=before,
            after_tokens=after,
            current_url="http://target.test/app/home",
            login_url="http://target.test/login",
            body="<html><body><div id='app'>App view</div></body></html>",
        )
        assert result.status == AGENT_AUTH_VERIFIED
        assert result.is_verified is True
        assert result.reasons == []
        assert result.cookie_or_token_gained is True

    def test_detect_token_diff_pure_unit(self):
        stale = [{"storage": "local", "key": "auth_token", "value": "stale_token_123"}]
        # No before snapshot -> False
        assert _detect_token_diff(None, stale) is False
        # Stale unchanged -> False
        assert _detect_token_diff(stale, stale) is False
        # New key -> True
        assert _detect_token_diff([], stale) is True
        # Changed value -> True
        modified = [{"storage": "local", "key": "auth_token", "value": "new_token_456"}]
        assert _detect_token_diff(stale, modified) is True
        # Empty after -> False
        assert _detect_token_diff(stale, []) is False

    def test_unverified_when_no_session_artifact_gained(self):
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=[],
            before_tokens=[],
            after_tokens=[],
            current_url="http://target.test/dashboard",
            login_url="http://target.test/login",
            body="<html><body><h1>Dashboard</h1></body></html>",
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert result.is_verified is False
        assert "missing_session_artifact" in result.reasons
        assert result.coverage_gap == AGENT_AUTH_COVERAGE_GAP

    def test_unverified_when_still_on_login_page(self):
        cookies = [{"name": "session", "value": "s123", "domain": "target.test", "path": "/"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=cookies,
            current_url="http://target.test/login",
            login_url="http://target.test/login",
            body="<html><body><p>Still here</p></body></html>",
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert "still_on_login_page" in result.reasons
        assert result.coverage_gap == AGENT_AUTH_COVERAGE_GAP

    def test_unverified_when_login_form_still_present(self):
        cookies = [{"name": "session", "value": "s123", "domain": "target.test", "path": "/"}]
        body = """
        <html><body>
          <form action="/login" method="POST">
            <input name="username" type="text" />
            <input name="password" type="password" />
          </form>
        </body></html>
        """
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=cookies,
            current_url="http://target.test/dashboard",
            login_url="http://target.test/login",
            body=body,
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert "login_form_still_present" in result.reasons
        assert result.coverage_gap == AGENT_AUTH_COVERAGE_GAP

    def test_unverified_when_failure_text_detected(self):
        cookies = [{"name": "temp_session", "value": "t123", "domain": "target.test", "path": "/"}]
        result = verify_agent_auth_claim(
            claimed_success=True,
            before_cookies=[],
            after_cookies=cookies,
            current_url="http://target.test/portal",
            login_url="http://target.test/login",
            body="<html><body><div class='error'>Invalid credentials, please retry</div></body></html>",
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert "auth_failure_text_detected" in result.reasons
        assert result.coverage_gap == AGENT_AUTH_COVERAGE_GAP

    def test_unverified_when_auth_not_claimed(self):
        result = verify_agent_auth_claim(
            claimed_success=False,
            current_url="http://target.test/dashboard",
            login_url="http://target.test/login",
        )
        assert result.status == AGENT_AUTH_UNVERIFIED
        assert result.reasons == ["auth_not_claimed"]
        assert result.coverage_gap == AGENT_AUTH_COVERAGE_GAP

    def test_direct_boolean_flags(self):
        res_ok = verify_agent_auth_claim(
            claimed_success=True,
            has_cookie_diff=True,
            left_login_page=True,
            login_form_present=False,
        )
        assert res_ok.status == AGENT_AUTH_VERIFIED
        assert res_ok.is_verified is True

        res_fail = verify_agent_auth_claim(
            claimed_success=True,
            has_cookie_diff=False,
            has_token_diff=False,
            left_login_page=True,
            login_form_present=False,
        )
        assert res_fail.status == AGENT_AUTH_UNVERIFIED
        assert "missing_session_artifact" in res_fail.reasons


# =============================================================================
# 2. Integration Tests with Fake/Stub Agent and Browser (No Real LLM)
# =============================================================================

class _History:
    def __init__(self, text: str, is_success: bool = True):
        self._text = text
        self._is_success = is_success

    def final_result(self) -> str:
        return self._text

    def extracted_content(self) -> list[str]:
        return []

    def is_successful(self) -> bool:
        return self._is_success

    def errors(self) -> list:
        return []


@pytest.mark.asyncio
async def test_agent_mode_labels_unverified_login_claim(tmp_path):
    """When LLM self-asserts 'AUTH COMPLETE' but deterministic ground-truth fails:

    - auth_verification_status is 'unverified_auth_claim'
    - coverage note 'auth:login_not_verified' is recorded in coverage_gaps
    - Findings produced by explorer/probe are NEVER dropped
    - Severities are NOT changed
    - Run status is marked partial/incomplete
    """
    class _FakeBrowser:
        def __init__(self, **_kwargs):
            self.cookies = []
            self.url = "http://fixture.test/login"
            self.body = "<form><input name='username'><input type='password'></form>"

        async def stop(self):
            pass

    tasks = []

    class _FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs
            tasks.append(kwargs["task"])

        async def run(self, **_kwargs):
            task = self.kwargs["task"]
            if "authenticate at" in task.lower():
                return _History("AUTH COMPLETE")
            if "Act only as the Explorer" in task:
                return _History("PAGE_FOUND: http://fixture.test/items\nEXPLORATION COMPLETE")
            if "probe specialist" in task:
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/items\n"
                    "Field: q\nPayload: <script>alert(1)</script>\n"
                    "Evidence: xss executed\nPROBE COMPLETE"
                )
            if "independent verifier" in task:
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/items\n"
                    "Field: q\nPayload: <script>alert(1)</script>\n"
                    "Evidence: xss confirmed\nVERIFICATION COMPLETE"
                )
            return _History("REVIEW COMPLETE")

    fake_browser_use = types.ModuleType("browser_use")
    fake_browser_use.Agent = _FakeAgent
    fake_browser_use.Browser = _FakeBrowser
    fake_browser_use.BrowserSession = lambda **_kw: _FakeBrowser()
    fake_profile = types.ModuleType("browser_use.browser.profile")
    fake_profile.BrowserProfile = lambda **kw: kw

    scanner = AgentBrowserScanner(
        target_url="http://fixture.test",
        login_url="http://fixture.test/login",
        auth_user="admin",
        auth_pass="secret",
        checks=["xss"],
        max_steps=30,
        harness_output_dir=tmp_path,
    )

    with patch("wscan.llm_agent_browser._build_llm", return_value=object()), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, "")
    ), patch.dict(sys.modules, {
        "browser_use": fake_browser_use,
        "browser_use.browser": types.ModuleType("browser_use.browser"),
        "browser_use.browser.profile": fake_profile,
    }):
        result = await scanner.run()

    # 1. Auth claim is truthfully labeled unverified
    assert result.auth_verification_status == AGENT_AUTH_UNVERIFIED
    assert AGENT_AUTH_COVERAGE_GAP in result.coverage_gaps
    assert any("still_on_login_page" in r for r in result.auth_verification_reasons)
    assert result.harness_status == "partial"
    assert result.success is False

    # 2. Originality preserved: findings and severities are NOT dropped or downgraded
    assert len(result.findings) == 1
    assert result.findings[0].check_type == "xss"
    assert result.findings[0].severity == "high"


@pytest.mark.asyncio
async def test_agent_mode_labels_verified_login_claim(tmp_path):
    """When LLM self-asserts 'AUTH COMPLETE' and deterministic ground-truth succeeds:

    - auth_verification_status is 'verified'
    - 'auth:login_not_verified' is NOT in coverage_gaps
    - Findings produced by explorer/probe are retained
    - Run status is complete
    """
    class _FakeBrowser:
        def __init__(self, **_kwargs):
            self.cookies = []
            self.url = "http://fixture.test/login"
            self.body = "<form><input name='username'><input type='password'></form>"

        async def stop(self):
            pass

    browser_inst = _FakeBrowser()

    class _FakeAgent:
        def __init__(self, **kwargs):
            self.kwargs = kwargs

        async def run(self, **_kwargs):
            task = self.kwargs["task"]
            if "authenticate at" in task.lower():
                # Simulate successful login side-effects in browser
                browser_inst.cookies = [
                    {"name": "session_id", "value": "val123", "domain": "fixture.test", "path": "/"}
                ]
                browser_inst.url = "http://fixture.test/dashboard"
                browser_inst.body = "<h1>Dashboard</h1><p>Welcome admin</p>"
                return _History("AUTH COMPLETE")
            if "Act only as the Explorer" in task:
                return _History("PAGE_FOUND: http://fixture.test/items\nEXPLORATION COMPLETE")
            if "probe specialist" in task:
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/items\n"
                    "Field: q\nPayload: <script>alert(1)</script>\n"
                    "Evidence: xss executed\nPROBE COMPLETE"
                )
            if "independent verifier" in task:
                nonce = re.search(r"WSCAN-NONCE:([^\s]+)", self.kwargs["extend_system_message"]).group(1)
                return _History(
                    f"WSCAN-NONCE:{nonce}\nVULNERABILITY FOUND:\n"
                    "Type: xss\nSeverity: high\nURL: http://fixture.test/items\n"
                    "Field: q\nPayload: <script>alert(1)</script>\n"
                    "Evidence: xss confirmed\nVERIFICATION COMPLETE"
                )
            return _History("REVIEW COMPLETE")

    fake_browser_use = types.ModuleType("browser_use")
    fake_browser_use.Agent = _FakeAgent
    fake_browser_use.Browser = lambda **_kw: browser_inst
    fake_browser_use.BrowserSession = lambda **_kw: browser_inst
    fake_profile = types.ModuleType("browser_use.browser.profile")
    fake_profile.BrowserProfile = lambda **kw: kw

    scanner = AgentBrowserScanner(
        target_url="http://fixture.test",
        login_url="http://fixture.test/login",
        auth_user="admin",
        auth_pass="secret",
        checks=["xss"],
        max_steps=30,
        harness_output_dir=tmp_path,
    )

    with patch("wscan.llm_agent_browser._build_llm", return_value=object()), patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, "")
    ), patch.dict(sys.modules, {
        "browser_use": fake_browser_use,
        "browser_use.browser": types.ModuleType("browser_use.browser"),
        "browser_use.browser.profile": fake_profile,
    }):
        result = await scanner.run()

    # 1. Auth claim is verified
    assert result.auth_verification_status == AGENT_AUTH_VERIFIED
    assert AGENT_AUTH_COVERAGE_GAP not in result.coverage_gaps
    assert result.auth_verification_reasons == []
    assert result.harness_status == "complete"
    assert result.success is True

    # 2. Findings retained
    assert len(result.findings) == 1
    assert result.findings[0].check_type == "xss"
    assert result.findings[0].severity == "high"


@pytest.mark.asyncio
async def test_agent_engine_records_auth_verification_in_evidence_and_report(tmp_path):
    """Test that AgentEngine preserves auth verification status in evidence.json and calls report."""
    from wscan.agent_engine import AgentEngine
    from wscan.llm_agent_browser import AgentFinding, AgentScanResult

    engine = AgentEngine(
        url="http://fixture.test",
        auth_user="user",
        auth_pass="pass",
        output_dir=tmp_path,
        llm_provider="ollama",
    )

    mock_result = AgentScanResult(
        target_url="http://fixture.test",
        findings=[
            AgentFinding(
                check_type="xss",
                severity="medium",
                url="http://fixture.test/search",
                field_name="q",
                payload="'><script>1</script>",
                evidence="found xss",
                agent_verified=False,
            )
        ],
        steps_taken=5,
        final_summary="Finished scan",
        success=False,
        harness_status="partial",
        coverage_gaps=["auth:login_not_verified"],
        auth_verification_status=AGENT_AUTH_UNVERIFIED,
        auth_verification_reasons=["missing_session_artifact"],
    )

    with patch("wscan.llm_agent_browser.AgentBrowserScanner.run", return_value=mock_result):
        res = await engine.run()

    evidence_file = tmp_path / "evidence.json"
    assert evidence_file.exists()
    evidence_data = json.loads(evidence_file.read_text(encoding="utf-8"))
    assert evidence_data["auth_verification_status"] == AGENT_AUTH_UNVERIFIED
    assert evidence_data["auth_verification_reasons"] == ["missing_session_artifact"]
    assert "auth:login_not_verified" in evidence_data["coverage_gaps"]

    report_file = tmp_path / "report.html"
    assert report_file.exists()
    report_content = report_file.read_text(encoding="utf-8")
    assert "unverified_auth_claim" in report_content
    assert "auth:login_not_verified" in report_content
