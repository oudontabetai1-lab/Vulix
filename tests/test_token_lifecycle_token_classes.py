"""Browser-free behavioral twins for supported form token lifecycles."""
from __future__ import annotations

import unittest
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse

from tests.fixtures.large_vuln_app import create_app
from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
from tests.test_token_lifecycle_manager_httpx_form import PAYLOAD, _ip
from wscan.injection_point import InjectionPoint


BASE = "http://large-fixture.test"


class TokenClassTests(unittest.IsolatedAsyncioTestCase):
    def scanner(self, app, enabled=True, cookies=None):
        engine = _TestEngine(app, base_url=BASE)
        engine.token_lifecycle_manager = enabled
        engine.cookies = cookies or {}
        return _TestFormScanner(engine), engine

    async def test_static_has_safe_twin_under_both_modes(self):
        for path, vulnerable in (("/csrf-static", True), ("/csrf-static-safe", False)):
            for enabled in (False, True):
                app = create_app()
                sc, engine = self.scanner(app, enabled)
                source, pair = await sc._apply_ip(_ip(BASE, path), PAYLOAD)
                self.assertEqual(pair["response"]["status"], 200)
                self.assertEqual("\nCc: attacker@evil.example.com" in source, vulnerable)
                self.assertEqual(engine.wave_errors, [])

    async def test_rotating_fixture_is_independent_existing_one_time_endpoint(self):
        for path, vulnerable in (("/csrf-contact", True), ("/csrf-contact-safe", False)):
            outcomes = []
            for enabled in (False, True):
                app = create_app()
                sc, _ = self.scanner(app, enabled)
                source, pair = await sc._apply_ip(_ip(BASE, path), PAYLOAD)
                outcomes.append((pair["response"]["status"], "\nCc: attacker@evil.example.com" in source))
                if path == "/csrf-contact":
                    self.assertTrue(all(value is None for value in app.state.csrf_nonces.values()))
            self.assertEqual(outcomes[0], outcomes[1])
            self.assertEqual(outcomes[0], (200, vulnerable))

    async def test_one_time_consumes_token_once_and_safe_twin_sanitizes(self):
        for path, vulnerable in (("/csrf-onetime", True), ("/csrf-onetime-safe", False)):
            app = create_app()
            sc, engine = self.scanner(app, True)
            source, pair = await sc._apply_ip(_ip(BASE, path), PAYLOAD)
            self.assertEqual(pair["response"]["status"], 200)
            self.assertEqual("\nCc: attacker@evil.example.com" in source, vulnerable)

        app = create_app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
            form = await client.get("/csrf-onetime")
            token = form.text.split('name="csrf_token" value="')[1].split('"')[0]
            self.assertEqual((await client.post("/csrf-onetime", data={"email": "first", "csrf_token": token})).status_code, 200)
            self.assertEqual((await client.post("/csrf-onetime", data={"email": "second", "csrf_token": token})).status_code, 419)

        for enabled in (False, True):
            app = create_app()
            sc, _ = self.scanner(app, enabled)
            source, pair = await sc._apply_ip(_ip(BASE, "/csrf-onetime-safe"), PAYLOAD)
            self.assertEqual(pair["response"]["status"], 200)
            self.assertNotIn("\nCc: attacker@evil.example.com", source)

    async def test_session_bound_token_isolated_and_refresh_uses_correct_session(self):
        app = create_app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as a, httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as b:
            page_a = await a.get("/csrf-session")
            token_a = page_a.text.split('name="csrf_token" value="')[1].split('"')[0]
            page_b = await b.get("/csrf-session")
            token_b = page_b.text.split('name="csrf_token" value="')[1].split('"')[0]
            self.assertNotEqual(a.cookies["session_id"], b.cookies["session_id"])
            rejected = await b.post("/csrf-session", data={"email": "probe", "csrf_token": token_a})
            self.assertEqual(rejected.status_code, 419)
            self.assertEqual((await b.post("/csrf-session", data={"email": "probe", "csrf_token": token_b})).status_code, 200)
        sc, engine = self.scanner(app, True, {"session_id": b.cookies["session_id"]})
        source, pair = await sc._apply_ip(_ip(BASE, "/csrf-session"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("\nCc: attacker@evil.example.com", source)

    async def test_session_bound_safe_twin_has_no_finding_in_both_modes(self):
        for enabled in (False, True):
            app = create_app()
            sc, _ = self.scanner(app, enabled)
            source, pair = await sc._apply_ip(_ip(BASE, "/csrf-session-safe"), PAYLOAD)
            self.assertEqual(pair["response"]["status"], 200)
            self.assertNotIn("\nCc: attacker@evil.example.com", source)

    async def test_no_token_pair_skips_refresh_get_and_keeps_flag_parity(self):
        app = FastAPI()
        reads = 0

        @app.get("/no-token", response_class=HTMLResponse)
        async def page():
            nonlocal reads
            reads += 1
            return HTMLResponse('<form method="post" action="/no-token"><input name="email" value="user@example.com"></form>')

        @app.post("/no-token", response_class=PlainTextResponse)
        async def vulnerable(email: str = Form("")):
            return PlainTextResponse(f"Sent: {email}")

        @app.get("/no-token-safe", response_class=HTMLResponse)
        async def safe_page():
            nonlocal reads
            reads += 1
            return HTMLResponse('<form method="post" action="/no-token-safe"><input name="email" value="user@example.com"></form>')

        @app.post("/no-token-safe", response_class=PlainTextResponse)
        async def safe(email: str = Form("")):
            clean = email.replace("\r", "").replace("\n", "")
            return PlainTextResponse(f"Sent: {clean}")

        for path, expected in (("/no-token", True), ("/no-token-safe", False)):
            outcomes = []
            for enabled in (False, True):
                sc, engine = self.scanner(app, enabled)
                with patch.object(sc, "_apply_form_with_token_refresh", wraps=sc._apply_form_with_token_refresh) as refresh:
                    ip = InjectionPoint.for_form(f"{BASE}{path}", "email", form_index=0, form_tokens=())
                    result = await sc._apply_ip(ip, PAYLOAD)
                    refresh.assert_not_awaited()
                source, pair = result
                outcomes.append((pair["response"]["status"], "\nCc: attacker@evil.example.com" in source, engine.wave_errors))
            self.assertEqual(outcomes[0], outcomes[1])
            self.assertEqual(outcomes[0][0], 200)
            self.assertEqual(outcomes[0][1], expected)
        self.assertEqual(reads, 0)

    async def test_refresh_failure_is_inconclusive_not_finding_or_negative(self):
        app = create_app()
        sc, engine = self.scanner(app, True)
        source, pair = await sc._apply_ip(_ip(BASE, "/csrf-contact-oneshot-stuck"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 419)
        self.assertNotIn("\nCc: attacker@evil.example.com", source)
        self.assertEqual(engine.wave_errors[-1], "token_lifecycle:probe_inconclusive:mail_header")
        self.assertEqual(getattr(engine, "_probe_inconclusive", False), False)
        self.assertEqual(sc.findings, [])


if __name__ == "__main__":
    unittest.main()
