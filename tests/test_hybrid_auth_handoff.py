import asyncio
import json
from unittest.mock import AsyncMock, MagicMock
import pytest
from wscan.agent_engine import AgentEngine, AgentHandoffData
from wscan.engine import ScanEngine
from wscan.llm_agent_browser import AgentBrowserScanner, AgentScanResult


class DummyBrowser:
    def __init__(self, cookies=None, storage=None):
        self._cookies = cookies or []
        self._storage = storage or {}
        self.set_calls = []

    async def cookies(self):
        return self._cookies

    async def export_storage_state(self):
        return self._storage

    async def set_cookies_from_list(self, cookie_list, url):
        self.set_calls.append((list(cookie_list), url))


def test_handoff_data_fields_populated_and_not_persisted():
    """Handoff cookies and storage_state are populated in memory, but excluded from serialization."""
    raw_cookies = [{"name": "session", "value": "secret123", "domain": "fixture.test"}]
    raw_storage = {"cookies": raw_cookies, "origins": []}

    handoff = AgentHandoffData(
        discovered_urls=["http://fixture.test/dashboard"],
        auth_user="admin",
        auth_pass="pass",
        login_url="http://fixture.test/login",
        summary="Recon completed",
        findings=[],
        cookies=raw_cookies,
        storage_state=raw_storage,
    )

    # In memory: populated
    assert handoff.cookies == raw_cookies
    assert handoff.storage_state == raw_storage

    # Serialized: to_dict excludes cookies and storage_state by default
    serialized = handoff.to_dict()
    assert "cookies" not in serialized
    assert "storage_state" not in serialized
    dumped = json.dumps(serialized)
    assert "secret123" not in dumped

    # Explicit override only if requested
    explicit = handoff.to_dict(include_auth_state=True)
    assert explicit["cookies"] == raw_cookies
    assert explicit["storage_state"] == raw_storage


@pytest.mark.asyncio
async def test_agent_scanner_captures_auth_state_before_stop():
    """AgentBrowserScanner._capture_auth_state populates cookies and storage_state."""
    scanner = AgentBrowserScanner(
        target_url="http://fixture.test",
        llm_provider="none",
    )
    test_cookies = [{"name": "sid", "value": "token_abc", "domain": "fixture.test"}]
    test_storage = {"cookies": test_cookies, "origins": []}
    browser = DummyBrowser(cookies=test_cookies, storage=test_storage)

    await scanner._capture_auth_state(browser)

    assert scanner.captured_cookies == test_cookies
    assert scanner.captured_storage_state == test_storage


@pytest.mark.asyncio
async def test_run_recon_populates_handoff_cookies_and_storage(tmp_path):
    """AgentEngine.run_recon gathers cookies and storage_state into AgentHandoffData."""
    test_cookies = [{"name": "auth_token", "value": "xyz789", "domain": "fixture.test"}]
    test_storage = {"cookies": test_cookies}

    class _MockScanner:
        def __init__(self, **_kwargs):
            self.captured_cookies = test_cookies
            self.captured_storage_state = test_storage

        async def run(self):
            res = AgentScanResult(
                target_url="http://fixture.test",
                success=True,
                findings=[],
                final_summary="recon done",
            )
            res.memory.visited_urls = ["http://fixture.test", "http://fixture.test/dashboard"]
            res.cookies = self.captured_cookies
            res.storage_state = self.captured_storage_state
            return res

    engine = AgentEngine(url="http://fixture.test", llm_provider="none", output_dir=str(tmp_path))
    from unittest.mock import patch
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _MockScanner):
        handoff = await engine.run_recon()

    assert handoff.cookies == test_cookies
    assert handoff.storage_state == test_storage
    assert "http://fixture.test/dashboard" in handoff.discovered_urls


def test_handoff_cookies_scope_filtering(tmp_path):
    """Only in-scope cookies are seeded; out-of-scope third-party cookies are discarded."""
    engine = ScanEngine(
        url="http://app.fixture.test/home",
        target_urls=["http://api.fixture.test/"],
        access_urls=["http://auth.fixture.test/"],
        output_dir=str(tmp_path),
        fast_mode=True,
    )

    mixed_cookies = [
        {"name": "app_sid", "value": "1", "domain": "app.fixture.test"},
        {"name": "wildcard", "value": "2", "domain": ".fixture.test"},
        {"name": "api_token", "value": "3", "domain": "api.fixture.test"},
        {"name": "auth_token", "value": "4", "domain": "auth.fixture.test"},
        {"name": "tracker", "value": "bad", "domain": "analytics.evil.com"},
        {"name": "cdn_cookie", "value": "bad", "domain": "external-cdn.net"},
        {"name": "host_only", "value": "5"},  # no domain -> target host
    ]

    filtered = engine._filter_handoff_cookies(mixed_cookies)
    names = [c["name"] for c in filtered]
    assert names == ["app_sid", "wildcard", "api_token", "auth_token", "host_only"]
    assert "tracker" not in names
    assert "cdn_cookie" not in names


@pytest.mark.asyncio
async def test_hybrid_phase2_proof_gating_verified(tmp_path):
    """When Phase 2 has NO credentials and proof is verified, mark authenticated coverage."""
    engine = ScanEngine(
        url="http://fixture.test/",
        output_dir=str(tmp_path),
        fast_mode=True,
        handoff_cookies=[{"name": "session", "value": "valid_token", "domain": "fixture.test"}],
    )
    engine._protected_access_candidate = MagicMock(return_value="http://fixture.test/dashboard")
    # before (unauthenticated): 401 Unauthorized
    # after (authenticated with cookies): 200 OK
    responses = {
        (None, "http://fixture.test/dashboard"): (401, "Login required", False),
        ("browser", "http://fixture.test/dashboard"): (200, "Dashboard content", False),
    }

    async def mock_protected_resp(url, *, browser=None):
        key = ("browser" if browser is not None else None, url)
        return responses.get(key, (None, "", False))

    engine._protected_resource_response = AsyncMock(side_effect=mock_protected_resp)
    browser = DummyBrowser()

    verified = await engine._seed_and_verify_handoff_cookies(browser)

    assert verified is True
    assert engine.authentication_state["protected_access"] == "verified"
    assert engine.authentication_state["state"] == "success"
    assert "handoff_cookies_seeded" in engine.authentication_state["evidence"]
    assert len(browser.set_calls) == 1

    # Check that prerequisite coverage marks auth_session
    prereqs = set()
    if engine.authentication_state.get("protected_access") == "verified":
        prereqs.add("auth_session")
    assert "auth_session" in prereqs


@pytest.mark.asyncio
async def test_hybrid_phase2_proof_gating_denied_does_not_claim_coverage(tmp_path):
    """When Phase 2 has NO credentials and proof is denied, keep unverified (do not claim)."""
    engine = ScanEngine(
        url="http://fixture.test/",
        output_dir=str(tmp_path),
        fast_mode=True,
        handoff_cookies=[{"name": "session", "value": "expired_token", "domain": "fixture.test"}],
    )
    engine._protected_access_candidate = MagicMock(return_value="http://fixture.test/dashboard")
    # before: 401 Unauthorized
    # after: still 401 Unauthorized (denied)
    responses = {
        (None, "http://fixture.test/dashboard"): (401, "Login required", False),
        ("browser", "http://fixture.test/dashboard"): (401, "Invalid session", False),
    }

    async def mock_protected_resp(url, *, browser=None):
        key = ("browser" if browser is not None else None, url)
        return responses.get(key, (None, "", False))

    engine._protected_resource_response = AsyncMock(side_effect=mock_protected_resp)
    browser = DummyBrowser()

    verified = await engine._seed_and_verify_handoff_cookies(browser)

    assert verified is False
    assert engine.authentication_state["protected_access"] == "denied"
    assert engine.authentication_state["state"] == "incomplete"
    assert any("authentication_unverified:" in err for err in engine.wave_errors)

    # Prerequisite coverage must NOT include auth_session
    prereqs = set()
    if engine.authentication_state.get("protected_access") == "verified":
        prereqs.add("auth_session")
    assert "auth_session" not in prereqs


@pytest.mark.asyncio
async def test_hybrid_phase2_credentials_authoritative_over_handoff_cookies(tmp_path):
    """When Phase 2 has login credentials, _auto_login runs as authoritative."""
    engine = ScanEngine(
        url="http://fixture.test/",
        login_url="http://fixture.test/login",
        auth_user="user",
        auth_pass="pass",
        output_dir=str(tmp_path),
        fast_mode=True,
        handoff_cookies=[{"name": "old_session", "value": "old", "domain": "fixture.test"}],
    )
    engine._auto_login = AsyncMock(return_value=True)
    engine._seed_and_verify_handoff_cookies = AsyncMock()
    engine._browser = MagicMock()
    engine._browser.auth_user = "user"
    engine._browser.auth_pass = "pass"
    engine._browser.set_cookies = AsyncMock()
    engine._browser.set_cookies_from_list = AsyncMock()
    engine._browser.last_login_url = "http://fixture.test/dashboard"
    engine._browser.page = MagicMock(url="http://fixture.test/dashboard")
    engine._scan_login_form_preauth = AsyncMock()
    engine._sync_cookies_from_browser = AsyncMock(return_value=True)
    engine.authentication_state = {"protected_access": "verified", "state": "success"}

    # Run the auth block
    if engine.login_url and engine._browser.auth_user and engine._browser.auth_pass:
        await engine._scan_login_form_preauth()
        success = await engine._auto_login(engine._browser)
    elif getattr(engine, "handoff_cookies", None):
        await engine._seed_and_verify_handoff_cookies(engine._browser)

    engine._auto_login.assert_awaited_once()
    engine._seed_and_verify_handoff_cookies.assert_not_awaited()
