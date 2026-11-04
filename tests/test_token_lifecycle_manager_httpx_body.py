from __future__ import annotations

import json
from unittest import IsolatedAsyncioTestCase
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, PlainTextResponse

from tests.fixtures.large_vuln_app import create_app
from tests.test_token_lifecycle_fixtures import _DummyBrowser, _TestEngine, _TestFormScanner
from wscan.injection_point import InjectionPoint
from wscan.token_lifecycle import DeclaredStatus, TokenCarrier, TokenTransport, build_token_capability_matrix


class Engine:
    def __init__(self, app, url, flag):
        self.app = app
        self.browser = _DummyBrowser()
        self.monitor = None
        self.payload_gen = None
        self.state_profile = "unrestricted"
        self.attempt_ledger = None
        self.request_logger = None
        self.base_url = "http://large-fixture.test"
        self.timeout = 5
        self.token_lifecycle_manager = flag
        self.cookies = {"session_id": "session-json"}
        self.wave_errors = []
        self.injection_templates = {"json": {
            "url": url, "method": "POST",
            "json_body": {"email": "old", "csrf_token": "old-token"},
            "headers": {"X-CSRF-Token": "old-token"},
        }}
        app.state.json_csrf_expected["session-json"] = "old-token"

    def httpx_client_kwargs(self, **kwargs):
        kwargs.update(transport=httpx.ASGITransport(app=self.app), base_url=self.base_url, cookies=self.cookies)
        return kwargs

    def _is_access_allowed_url(self, _url):
        return True

    def _is_url_excluded(self, _url):
        return False


def scanner(app, url, flag):
    engine = Engine(app, url, flag)
    return _TestFormScanner(engine), engine


def point(url):
    return InjectionPoint.for_json_body("POST", url, "/email", template_id="json")


async def apply(app, path, flag, payload="probe\r\nCc: injected@example.test"):
    url = f"http://large-fixture.test{path}"
    sc, engine = scanner(app, url, flag)
    source, pair = await sc._apply_json_payload(point(url), payload)
    return source, pair, engine


class HttpxBodyManagerTests(IsolatedAsyncioTestCase):
    async def test_manager_refreshes_rotating_json_and_header_and_safe_twin_stays_safe(self):
        app = create_app()
        vulnerable, pair, _ = await apply(app, "/token-json", True)
        safe, safe_pair, _ = await apply(app, "/token-json-safe", True)
        self.assertIn("Cc: injected@example.test", vulnerable)
        self.assertNotIn("probe\r\nCc: injected@example.test", safe)
        self.assertEqual(pair["response"]["status"], safe_pair["response"]["status"], 200)
        self.assertNotIn("old-token", repr(pair["request"]))
        self.assertNotIn("old-token", repr(safe_pair["request"]))
        self.assertNotIn(app.state.json_csrf_last_value, repr(pair["request"]))
        self.assertNotEqual(json.loads(app.state.json_csrf_received[0][0])["csrf_token"], "old-token")
        self.assertNotEqual(app.state.json_csrf_received[0][1], "old-token")

    async def test_flag_off_keeps_legacy_body_and_both_modes_reach_vulnerable_signal(self):
        outcomes = []
        for flag in (False, True):
            app = create_app()
            source, pair, _ = await apply(app, "/token-json", flag)
            outcomes.append(("Cc: injected@example.test" in source, pair["response"]["status"]))
            if flag is False:
                self.assertEqual(app.state.json_csrf_received[0], (
                    json.dumps({"email": "probe\r\nCc: injected@example.test", "csrf_token": "old-token"}),
                    "old-token",
                ))
        self.assertEqual(outcomes, [(True, 200), (True, 200)])

    async def test_retry_is_bounded_and_final_stale_is_inconclusive(self):
        app = create_app()
        app.state.json_csrf_force_stale = True
        _, pair, engine = await apply(app, "/token-json", True)
        self.assertEqual(pair["response"]["status"], 419)
        self.assertEqual(app.state.json_csrf_requests, 2)
        self.assertEqual(len(engine.wave_errors), 2)
        self.assertTrue(engine.wave_errors[0].startswith("token_lifecycle:refreshed:mail_header:tok_ref_"))
        self.assertEqual(engine.wave_errors[1], "token_lifecycle:probe_inconclusive:mail_header")

    async def test_retry_rediscovers_nonce_rotated_after_first_request(self):
        app = FastAPI()
        app.state.json_csrf_expected = {}
        app.state.expected = "old-token"
        app.state.page_reads = 0
        app.state.received = []

        @app.get("/{path}", response_class=HTMLResponse)
        async def page(path: str):
            app.state.page_reads += 1
            token = f"rotated-{app.state.page_reads}"
            app.state.expected = token
            return HTMLResponse(f'<meta name="csrf-token" content="{token}">')

        async def post(request: Request, safe: bool):
            data = await request.json()
            token = request.headers.get("x-csrf-token")
            app.state.received.append((data["csrf_token"], token))
            # Rotate after the initially valid token is submitted but before the
            # retry; only its fresh GET can discover the replacement.
            if app.state.page_reads and len(app.state.received) == 1 and token == app.state.expected and data["csrf_token"] == app.state.expected:
                app.state.expected = "rotated-after-first-post"
                return PlainTextResponse("CSRF token mismatch", status_code=419)
            if data["csrf_token"] != app.state.expected or token != app.state.expected:
                return PlainTextResponse("CSRF token mismatch", status_code=419)
            value = str(data["email"])
            if safe:
                value = value.replace("\r", "").replace("\n", "")
            return PlainTextResponse(f"accepted:{value}")

        @app.post("/rotating-json", response_class=PlainTextResponse)
        async def vulnerable(request: Request):
            return await post(request, False)

        @app.post("/rotating-json-safe", response_class=PlainTextResponse)
        async def safe(request: Request):
            return await post(request, True)

        source, pair, engine = await apply(app, "/rotating-json", True)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("Cc: injected@example.test", source)
        self.assertEqual(app.state.received, [("rotated-1", "rotated-1"), ("rotated-2", "rotated-2")])
        self.assertEqual(len(engine.wave_errors), 1)
        self.assertTrue(engine.wave_errors[0].startswith("token_lifecycle:refreshed:mail_header:tok_ref_"))

        safe_source, safe_pair, _ = await apply(app, "/rotating-json-safe", True)
        self.assertEqual(safe_pair["response"]["status"], 200)
        self.assertNotIn("probe\r\nCc: injected@example.test", safe_source)

        # Flag off retains the legacy request and does not perform page discovery.
        app.state.expected = "old-token"
        app.state.page_reads = 0
        app.state.received.clear()
        _, legacy_pair, legacy_engine = await apply(app, "/rotating-json", False)
        self.assertEqual(legacy_pair["response"]["status"], 200)
        self.assertEqual(app.state.page_reads, 0)
        self.assertEqual(app.state.received, [("old-token", "old-token")])
        self.assertEqual(legacy_engine.wave_errors, [])

    async def test_discovery_failure_and_exception_fall_back_without_raising(self):
        app = create_app()
        app.state.json_csrf_page_error = True
        source, pair, _ = await apply(app, "/token-json", True)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("Cc: injected@example.test", source)

        app = create_app()
        url = "http://large-fixture.test/token-json"
        sc, _ = scanner(app, url, True)
        with patch.object(sc, "_refresh_httpx_token", side_effect=RuntimeError("refresh failure")):
            source, pair = await sc._apply_json_payload(point(url), "probe")
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("probe", source)

    def test_only_httpx_json_xml_and_header_are_supported(self):
        matrix = build_token_capability_matrix()
        for carrier in (TokenCarrier.JSON, TokenCarrier.XML, TokenCarrier.HTTP_HEADER):
            self.assertEqual(matrix.get_status(carrier, TokenTransport.HTTPX), DeclaredStatus.SUPPORTED)
        self.assertEqual(matrix.get_status(TokenCarrier.JSON, TokenTransport.PLAYWRIGHT), DeclaredStatus.PLANNED)

    async def test_xml_carrier_refreshes_matching_element_and_header(self):
        app = FastAPI()

        @app.get("/xml")
        async def xml_page():
            return HTMLResponse('<meta name="csrf-token" content="xml_fresh_secret">')

        @app.post("/xml")
        async def xml_post(request: Request):
            body = (await request.body()).decode()
            if "<csrf_token>xml_fresh_secret</csrf_token>" not in body or request.headers.get("x-csrf-token") != "xml_fresh_secret":
                return PlainTextResponse("CSRF token mismatch", status_code=419)
            return PlainTextResponse("accepted")

        url = "http://large-fixture.test/xml"
        engine = _TestEngine(app, base_url="http://large-fixture.test")
        engine.token_lifecycle_manager = True
        engine.injection_templates = {"xml": {
            "url": url, "method": "POST",
            "xml_body": "<root><email>old</email><csrf_token>old</csrf_token></root>",
            "headers": {"X-CSRF-Token": "old"},
        }}
        scanner = _TestFormScanner(engine)
        ip = InjectionPoint.for_xml_body("POST", url, "/root/email", template_id="xml")
        source, pair = await scanner._apply_xml_payload(ip, "probe")
        self.assertEqual(pair["response"]["status"], 200)
        self.assertEqual(source, "accepted")
        self.assertNotIn("xml_fresh_secret", repr(pair["request"]))
