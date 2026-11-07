"""Protected access evidence, with real Chromium checks explicitly opt-in."""
import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan import login_surface as ls
from wscan.engine import ScanEngine


@pytest.mark.parametrize("before,after,body,expected", [
    (401, 200, "<h1>Private resource</h1>", "verified"),
    (403, 200, "<h1>Private resource</h1>", "verified"),
    (200, 200, '<h1>Public</h1><a href="/logout">Log out</a>', "unknown"),
    (401, 401, "Authentication required", "denied"),
    (401, 403, "Forbidden", "denied"),
    (401, 429, "Unavailable", "unknown"),
    (401, 503, "Unavailable", "unknown"),
    (401, None, "", "unknown"),
    (401, 200, '<div class="g-recaptcha"></div>', "unknown"),
    (401, 200, '<form><input type="password"><button>Log in</button></form>', "denied"),
])
def test_same_resource_proof(before, after, body, expected):
    proof, _ = ls.assess_protected_access(before_status=before, after_status=after, after_body=body)
    assert proof == expected


def test_public_baseline_challenge_and_redirect_proof():
    assert ls.assess_protected_access(before_status=302, before_login_redirect=True,
                                     after_status=200, after_body="Private resource")[0] == "verified"
    assert ls.assess_protected_access(before_status=401, after_status=302,
                                     after_login_redirect=True)[0] == "denied"
    assert ls.assess_protected_access(before_status=401, after_status=302)[0] == "unknown"
    assert ls.assess_protected_access(before_status=403, before_body='<div class="g-recaptcha"></div>',
                                     after_status=200, after_body="Public resource")[0] == "unknown"


def test_denied_dominates_configured_indicator_and_unknown_rejects_ui_signals():
    for proof, expected in (("denied", ls.FAILURE), ("verified", ls.SUCCESS), ("unknown", ls.SUCCESS)):
        obs = ls.LoginObservation(post_url="http://fixture.test/home", body='<a href="/logout">Log out</a>',
                                  success_indicator="/home", protected_access=proof)
        result = ls.assess_login_state(obs)
        assert result.state == expected
        if proof == "unknown":
            assert "configured_indicator" in result.evidence
            assert "protected_access_verified" not in result.evidence
        obs.success_indicator = ""
        assert ls.assess_login_state(obs).state == (ls.INCOMPLETE if proof == "unknown" else expected)


def engine_for(url, output, **kwargs):
    engine = ScanEngine(url + "/proof-resource", login_url=url + "/proof-login/plain",
                        auth_user="fixture-user@example.test", auth_pass="fixture-password",
                        checks=["sqli"], llm_provider="none", output_dir=str(output),
                        open_report=False, enable_ai_analysis=False, enable_waf_detection=False,
                        enable_payload_learning=False, enable_adaptive_payloads=False,
                        enable_community_payloads=False, enable_component_intel=False,
                        enable_sitemap_crawl=False, headless=True, fast_mode=True, **kwargs)
    return engine


def test_candidate_scope_exclusions_and_no_guessed_resource(tmp_path):
    engine = engine_for("http://fixture.test", tmp_path)
    assert engine._protected_access_candidate() == "http://fixture.test/proof-resource"
    engine.exclude_urls = [engine.target_url]
    assert engine._protected_access_candidate() == ""
    engine.exclude_urls = []
    for target in (engine.login_url, "http://fixture.test/logout", "http://fixture.test/%6cogout",
                   "http://fixture.test/%256cogout", "http://fixture.test/api?action=%6cogout",
                   "file:///private", "http://u:p@fixture.test/x"):
        engine.target_url = target
        engine.target_urls = [target]
        assert engine._protected_access_candidate() == ""


@pytest.mark.parametrize("location,excluded,is_login", [
    ("http://outside.test/private", False, False),
    ("/proof-login/plain", False, True),
    ("/proof-login/plain", True, False),
])
def test_httpx_exact_destination_anonymous_headers_and_no_redirect_hop(tmp_path, location, excluded, is_login):
    engine = engine_for("http://fixture.test", tmp_path)
    seen = []

    def handle(request):
        seen.append((str(request.url), dict(request.headers)))
        return httpx.Response(302, headers={"location": location})

    engine.httpx_client_kwargs = lambda **kw: {**kw, "transport": httpx.MockTransport(handle), "trust_env": False}
    engine.auth_headers = lambda **kw: {"Authorization": "test-only", "Cookie": "test-only"}
    engine._sync_cookies_from_browser = AsyncMock(return_value=True)
    if excluded:
        engine.exclude_urls = [engine.login_url]

    async def check():
        assert (await engine._protected_resource_response(engine.target_url))[2] is is_login
        await engine._protected_resource_response(engine.target_url, browser=object())
    asyncio.run(check())
    assert len(seen) == 2
    assert "authorization" not in seen[0][1] and "cookie" not in seen[0][1]
    assert "authorization" in seen[1][1] and "cookie" in seen[1][1]
    assert all(url == engine.target_url for url, _ in seen)
    engine._sync_cookies_from_browser.assert_awaited_once_with(engine._sync_cookies_from_browser.call_args.args[0],
                                                            for_url=engine.target_url)


def test_browser_token_without_supported_httpx_identity_stays_unknown(tmp_path):
    engine = engine_for("http://fixture.test", tmp_path)
    engine._protected_resource_response = AsyncMock(return_value=(401, "", False))
    engine.auth_headers = lambda **kw: {}

    class Browser:
        async def auto_login(self, *args, protected_access_check, **kwargs):
            proof, reason = await protected_access_check(api_token_issued=True)
            self.last_login_assessment = ls.assess_login_state(ls.LoginObservation(
                post_url="http://fixture.test/home", api_token_issued=True,
                protected_access=proof, protected_access_reason=reason))
            return self.last_login_assessment.authenticated

    assert not asyncio.run(engine._auto_login(Browser()))
    assert engine.authentication_state["protected_access"] == "unknown"
    assert engine.authentication_state["reasons"] == ["browser_token_context_unsupported"]


@pytest.mark.skipif(os.getenv("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 for real Chromium")
def test_failed_initial_login_keeps_preauth_order_and_incomplete_completion(tmp_path):
    from tests.fixtures import login_surface_app as fx
    from tests.test_totp_login_e2e import serving
    from wscan.monitor import MonitorServer

    with serving(fx.create_app()) as url:
        async def check():
            monitor = MonitorServer(port=0)
            engine = engine_for(url, tmp_path, monitor=monitor)
            engine._browser.auth_pass = "invalid-local-password"
            phases = []

            async def preauth():
                phases.append("preauth")

            async def crawl():
                phases.append("crawl")
                return []

            async def plan(pages):
                phases.append("plan")
                return {}

            async def attack(pages, plans):
                phases.append("attack")

            engine._scan_login_form_preauth = preauth
            engine._phase_crawl, engine._phase_plan, engine._phase_attack = crawl, plan, attack
            for name in ("_run_api_template_checks", "_run_json_injection_checks", "_run_xml_injection_checks",
                         "_run_tls_seed_scans", "_phase_verify", "_phase_report_async", "_drain_notifications"):
                setattr(engine, name, AsyncMock())
            engine._init_checkpoint = lambda: None
            engine._save_checkpoint = lambda: None
            await engine.run()
            assert phases == ["preauth", "crawl", "plan", "attack"]
            assert monitor.api_scan_status == "incomplete"
            assert monitor._scan_complete_data["authentication"]["state"] == ls.FAILURE
            assert monitor._scan_complete_data["evidence_completion"]["status"] == "EVIDENCE_INCOMPLETE"
            assert engine.coverage_summary()["authentication"]["protected_access"] == "unknown"
        asyncio.run(check())


def test_evidence_serialization_terminal_truth_and_abort_precedence(tmp_path):
    import json

    # 1. Unverified / failed auth produces "incomplete" terminal truth in saved evidence
    eng_failed = engine_for("http://127.0.0.1:9", tmp_path / "failed")
    eng_failed.authentication_state = {"state": "failure", "protected_access": "unknown", "configured": True}
    eng_failed.wave_errors.append("authentication_unverified:protected_access_denied")
    eng_failed._save_evidence()
    saved = json.loads((tmp_path / "failed" / "evidence.json").read_text(encoding="utf-8"))
    assert saved["status"] == "incomplete"
    assert saved["coverage"]["evidence_completion"]["status"] == "EVIDENCE_INCOMPLETE"
    assert saved["aborted"] is False

    # 2. Aborted scan dominates and produces "aborted", even with failed auth
    eng_aborted = engine_for("http://127.0.0.1:9", tmp_path / "aborted")
    eng_aborted.scan_aborted = True
    eng_aborted.authentication_state = {"state": "failure", "protected_access": "unknown", "configured": True}
    eng_aborted.wave_errors.append("authentication_unverified:protected_access_denied")
    eng_aborted._save_evidence()
    saved = json.loads((tmp_path / "aborted" / "evidence.json").read_text(encoding="utf-8"))
    assert saved["status"] == "aborted"
    assert saved["aborted"] is True

    # 3. Normal scan without authentication produces "done"
    eng_noauth = ScanEngine("http://127.0.0.1:9/target", output_dir=str(tmp_path / "noauth"),
                            checks=["sqli"], llm_provider="none", open_report=False)
    eng_noauth._save_evidence()
    saved = json.loads((tmp_path / "noauth" / "evidence.json").read_text(encoding="utf-8"))
    assert saved["status"] == "done"
    assert saved["aborted"] is False


def test_loopback_encoded_logout_handler_not_reached(tmp_path):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    from tests.test_totp_login_e2e import serving

    app = FastAPI()
    app.state.calls = 0

    @app.get("/logout")
    async def logout():
        app.state.calls += 1
        return HTMLResponse("Session ended")

    with serving(app) as url:
        engine = engine_for(url, tmp_path)
        engine.target_url = url + "/%6cogout"
        candidate = engine._protected_access_candidate()
        assert candidate == ""
        result = asyncio.run(engine._protected_resource_response(candidate))
        assert result == (None, "", False)
        # Direct call with encoded destructive URL is also refused without HTTP request
        direct_result = asyncio.run(engine._protected_resource_response(url + "/%6cogout"))
        assert direct_result == (None, "", False)
        assert app.state.calls == 0


def test_script_only_indicator_not_matched_as_body_content():
    obs = ls.LoginObservation(
        post_url="http://127.0.0.1/home",
        login_url="http://127.0.0.1/login",
        body='<h1>Public</h1><script>const message="Welcome private user";</script>',
        success_indicator="Welcome private user",
        protected_access="unknown",
    )
    result = ls.assess_login_state(obs)
    assert not result.authenticated
    assert result.state == ls.INCOMPLETE
    assert "success_indicator" not in result.evidence


@pytest.mark.skipif(os.getenv("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 for real Chromium")
def test_chromium_cookie_proof_deception_expiry_and_no_candidate(tmp_path):
    from tests.fixtures import login_surface_app as fx
    from tests.test_totp_login_e2e import serving

    app = fx.create_app()
    with serving(app) as url:
        async def check():
            for mode in ("plain", "public", "guest", "invalid", "challenge", "limited", "unavailable", "no-candidate"):
                engine = engine_for(url, tmp_path / mode)
                engine.login_url = url + "/proof-login/" + ("plain" if mode in {"invalid", "no-candidate"} else mode)
                browser = engine._browser
                browser.sleep_factor = 0
                if mode == "invalid":
                    browser.auth_pass = "invalid-local-password"
                if mode == "no-candidate":
                    engine.target_url = engine.login_url
                    engine.target_urls = [engine.login_url]
                    engine.login_success_indicator = "Private resource"
                await browser.init()
                try:
                    # Every browser request is confined to this disposable server.
                    async def scoped(route):
                        if route.request.url.startswith(url + "/"):
                            await route.continue_()
                        else:
                            await route.abort()
                    await browser.page.context.route("**/*", scoped)
                    ok = await engine._auto_login(browser)
                    state = engine.authentication_state
                    assert ok == (mode in {"plain", "no-candidate"}), (mode, state)
                    assert state["protected_access"] == ("verified" if mode == "plain" else
                                                        "denied" if mode in {"public", "guest"} else "unknown"), (mode, state)
                    if mode in {"challenge", "limited", "unavailable", "invalid"}:
                        expected = {"challenge": (ls.CHALLENGE, "mfa"), "limited": (ls.INCOMPLETE, "http_429"),
                                    "unavailable": (ls.INCOMPLETE, "http_503"), "invalid": (ls.FAILURE, "http_401")}
                        assert (state["state"], state["reasons"][0]) == expected[mode], (mode, state)
                    if mode == "plain":
                        assert "logout_control" not in state["evidence"]
                        assert app.state.proof_requests[0] == {"allowed": False, "cookie_present": False}
                        assert app.state.proof_requests[-1] == {"allowed": True, "cookie_present": True}
                        app.state.proof_session_valid = False
                        assert await engine._api_session_looks_expired(engine.target_url)
                        app.state.proof_session_valid = True
                        assert await engine._relogin_if_needed(browser, status=401, for_url=engine.target_url)
                        assert await engine._force_relogin(for_url=engine.target_url)
                        assert engine.authentication_state["protected_access"] == "verified"
                    if mode == "no-candidate":
                        assert state["state"] == "configured"
                        assert any(e.startswith("authentication_unverified:") for e in engine.wave_errors)
                        assert "configured_indicator" in state["evidence"]
                finally:
                    await browser.close()
        asyncio.run(check())


@pytest.mark.skipif(os.getenv("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 for real Chromium")
def test_chromium_unsubmitted_form_with_script_marker_fails_auto_login(tmp_path):
    from fastapi import FastAPI, Request
    from fastapi.responses import HTMLResponse
    from tests.test_totp_login_e2e import serving

    app = FastAPI()
    app.state.submissions = 0

    @app.get("/login")
    async def login():
        return HTMLResponse(
            '<h1>Public</h1><form onsubmit="event.preventDefault();this.remove()">'
            '<input name="username"><input type="password" name="password"><button>Log in</button></form>'
            '<script>const unusedSuccessText="Welcome private user";</script>'
        )

    @app.post("/login")
    async def submit(request: Request):
        app.state.submissions += 1
        return HTMLResponse("Not authenticated", status_code=401)

    with serving(app) as url:
        async def exercise():
            engine = engine_for(url, tmp_path)
            engine.target_url = engine.login_url = url + "/login"
            engine.login_success_indicator = "Welcome private user"
            browser = engine._browser
            await browser.init()
            try:
                await browser.page.context.route(
                    "**/*",
                    lambda route: route.continue_() if route.request.url.startswith(url + "/") else route.abort(),
                )
                ok = await engine._auto_login(browser)
                assert app.state.submissions == 0
                assert not ok, "Script-only configured marker returned successful auto_login with no submitted request"
                assert engine.authentication_state.get("state") != "configured"
            finally:
                await browser.close()

        asyncio.run(exercise())
