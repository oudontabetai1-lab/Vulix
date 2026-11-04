"""Browser-free tests for fresh tokens on harvested SPA API replay."""
from __future__ import annotations

import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from tests.fixtures.large_vuln_app import create_app
from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
from wscan.injection_point import InjectionPoint
from wscan.token_lifecycle import TokenCarrier, TokenTransport, build_token_capability_matrix


def make_scanner(app, url, enabled=True, *, allowed=True):
    engine = _TestEngine(app, base_url="http://large-fixture.test")
    engine.token_lifecycle_manager = enabled
    engine.cookies = {"session_id": "spa-session"}
    engine._is_access_allowed_url = lambda _url: allowed
    engine.injection_templates = {
        "spa": {
            "url": url,
            "method": "POST",
            "json_body": {"email": "old", "csrf_token": "stale-token"},
            "headers": {"X-CSRF-Token": "stale-token"},
        }
    }
    scanner = _TestFormScanner(engine)
    point = InjectionPoint.for_json_body("POST", url, "/email", template_id="spa")
    return scanner, engine, point


async def replay(app, path="/token-json", enabled=True, *, allowed=True):
    url = f"http://large-fixture.test{path}"
    scanner, engine, point = make_scanner(app, url, enabled, allowed=allowed)
    result = await scanner._apply_json_payload(point, "probe\\r\\nCc: injected@example.test")
    return scanner, engine, result


class SpaApiTokenLifecycleTests(IsolatedAsyncioTestCase):
    async def test_json_replay_refreshes_live_rotating_token_without_note_leak(self):
        app = create_app()
        scanner, engine, (body, pair) = await replay(app)
        received_body, received_header = app.state.json_csrf_received[-1]
        fresh = json.loads(received_body)["csrf_token"]
        self.assertEqual(pair["response"]["status"], 200)
        self.assertNotEqual(fresh, "stale-token")
        self.assertEqual(received_header, fresh)
        self.assertNotIn(fresh, repr(engine.wave_errors))
        self.assertNotIn(fresh, repr(pair["request"]))
        self.assertNotIn("stale-token", repr(pair["request"]))
        self.assertIn("token_lifecycle:refreshed:mail_header:", repr(engine.wave_errors))
        self.assertNotIn(fresh, repr(engine.wave_errors))
        self.assertIn("Cc: injected@example.test", body)
        self.assertGreaterEqual(app.state.json_csrf_requests, 1)
        self.assertEqual(scanner._token_manager_enabled(TokenCarrier.JSON, TokenTransport.SPA_API), True)

    async def test_echoed_fresh_token_is_redacted_from_response_evidence_only(self):
        app = create_app()
        app.state.json_csrf_echo = True
        _, engine, (body, pair) = await replay(app)
        fresh = json.loads(app.state.json_csrf_received[-1][0])["csrf_token"]
        stored = repr(pair) + repr(engine.wave_errors)
        self.assertIn("Cc: injected@example.test", body)
        self.assertNotIn(fresh, stored)
        self.assertIn("tok_ref_", pair["response"]["body"])

    async def test_x_xsrf_header_is_refreshed_on_managed_spa_send(self):
        app = FastAPI()
        app.state.expected = ""
        app.state.received = ""

        @app.get("/api", response_class=HTMLResponse)
        async def refresh_page():
            app.state.expected = "rotated-header-token"
            response = HTMLResponse("ready")
            response.headers["X-XSRF-TOKEN"] = app.state.expected
            return response

        @app.post("/api", response_class=PlainTextResponse)
        async def submit(request: Request):
            app.state.received = request.headers.get("x-xsrf-token", "")
            return PlainTextResponse("accepted" if app.state.received == app.state.expected else "CSRF token mismatch", status_code=200 if app.state.received == app.state.expected else 419)

        scanner, engine, point = make_scanner(app, "http://large-fixture.test/api", True)
        headers = {"X-XSRF-TOKEN": "stale-token"}
        with patch.object(scanner, "_token_manager_enabled", wraps=scanner._token_manager_enabled) as gate:
            async with httpx.AsyncClient(**engine.httpx_client_kwargs()) as client:
                response, _, sent_headers = await scanner._send_httpx_token_managed(
                    client, "POST", point.url,
                    {"email": "probe", "csrf_token": "stale-token"}, headers, "json",
                )
        gate.assert_any_call(TokenCarrier.HTTP_HEADER, TokenTransport.SPA_API)
        fresh = app.state.received
        self.assertEqual(response.status_code, 200)
        self.assertNotEqual(fresh, "stale-token")
        self.assertEqual(sent_headers["X-XSRF-TOKEN"], fresh)
        self.assertEqual(len(engine.wave_errors), 1)
        self.assertTrue(engine.wave_errors[0].startswith("token_lifecycle:refreshed:mail_header:tok_ref_"))

    async def test_stale_after_single_retry_is_note_only_inconclusive(self):
        app = create_app()
        app.state.json_csrf_force_stale = True
        _, engine, (_, pair) = await replay(app)
        self.assertEqual(pair["response"]["status"], 419)
        self.assertEqual(app.state.json_csrf_requests, 2)
        self.assertEqual(len(engine.wave_errors), 2)
        self.assertTrue(engine.wave_errors[0].startswith("token_lifecycle:refreshed:mail_header:tok_ref_"))
        self.assertEqual(engine.wave_errors[1], "token_lifecycle:probe_inconclusive:mail_header")

    async def test_flag_off_sends_legacy_bytes_and_issues_no_refresh_get(self):
        app = create_app()
        _, engine, (_, pair) = await replay(app, enabled=False)
        self.assertEqual(pair["response"]["status"], 419)
        self.assertEqual(app.state.json_csrf_requests, 1)
        self.assertEqual(app.state.json_csrf_received[0], (
            json.dumps({"email": "probe\\r\\nCc: injected@example.test", "csrf_token": "stale-token"}),
            "stale-token",
        ))
        self.assertFalse(engine.wave_errors)
        self.assertEqual(app.state.json_csrf_refresh_gets, 0)

    async def test_refresh_exception_falls_back_to_unmodified_request(self):
        app = create_app()
        scanner, engine, point = make_scanner(app, "http://large-fixture.test/token-json")
        with patch.object(scanner, "_refresh_httpx_token", side_effect=RuntimeError("refresh unavailable")):
            async with httpx.AsyncClient(**engine.httpx_client_kwargs()) as client:
                response, sent_body, sent_headers = await scanner._send_httpx_token_managed(
                    client, "POST", point.url,
                    {"email": "unchanged", "csrf_token": "stale-token"},
                    {"X-CSRF-Token": "stale-token"}, "json",
                )
        self.assertEqual(response.status_code, 419)
        self.assertEqual(sent_body["csrf_token"], "stale-token")
        self.assertEqual(sent_headers["X-CSRF-Token"], "stale-token")
        self.assertEqual(app.state.json_csrf_requests, 1)

    async def test_out_of_scope_refresh_url_is_not_fetched(self):
        app = create_app()
        _, engine, (_, pair) = await replay(app, allowed=False)
        self.assertEqual(pair["response"]["status"], 419)
        self.assertEqual(app.state.json_csrf_requests, 1)
        self.assertEqual(len(engine.wave_errors), 1)
        self.assertEqual(engine.wave_errors[0], "token_lifecycle:probe_inconclusive:mail_header")
        self.assertEqual(app.state.json_csrf_refresh_gets, 0)

    def test_spa_matrix_supports_only_json_and_recognized_headers(self):
        matrix = build_token_capability_matrix()
        self.assertTrue(matrix.is_supported(TokenCarrier.JSON, TokenTransport.SPA_API))
        self.assertTrue(matrix.is_supported(TokenCarrier.HTTP_HEADER, TokenTransport.SPA_API))
