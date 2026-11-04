"""Browser-free behavioral twins for supported form token lifecycles."""
from __future__ import annotations

import unittest
from html.parser import HTMLParser
from unittest.mock import patch

import httpx
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse

from tests.fixtures.large_vuln_app import create_app
from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
from tests.test_token_lifecycle_manager_httpx_form import PAYLOAD, _ip
from wscan.injection_point import InjectionPoint
from wscan.scanners.mail_header import MailHeaderInjectionScanner


BASE = "http://large-fixture.test"


class _FormParser(HTMLParser):
    def __init__(self):
        super().__init__()
        self.form = None
        self.forms = []

    def handle_starttag(self, tag, attrs):
        attrs = dict(attrs)
        if tag == "form":
            self.form = {"action": attrs.get("action", ""), "method": attrs.get("method", "get").upper(), "fields": {}}
        elif tag == "input" and self.form is not None and attrs.get("name"):
            self.form["fields"][attrs["name"]] = attrs.get("value", "")

    def handle_endtag(self, tag):
        if tag == "form" and self.form is not None:
            self.forms.append(self.form)
            self.form = None


class _HttpxFormBrowser:
    def __init__(self, engine):
        self.engine = engine
        self.page = self
        self.context = self
        self.html = ""
        self.cookie_list = []

    async def cookies(self):
        return self.cookie_list

    async def navigate(self, url):
        async with httpx.AsyncClient(**self.engine.httpx_client_kwargs()) as client:
            response = await client.get(url, cookies=self.engine.cookies)
            self.engine.cookies.update(response.cookies)
            self.cookie_list = [{"name": k, "value": v, "domain": "large-fixture.test", "path": "/"} for k, v in self.engine.cookies.items()]
            self.html = response.text

    async def evaluate(self, _script, _args):
        parser = _FormParser()
        parser.feed(self.html)
        form = next((form for form in parser.forms if "email" in form["fields"]), None)
        if form and form["action"]:
            form["action"] = str(httpx.URL(BASE).join(form["action"]))
        return form

    async def screenshot_b64(self, label=""):
        return ""


class TokenClassTests(unittest.IsolatedAsyncioTestCase):
    def scanner(self, app, enabled=True, cookies=None):
        engine = _TestEngine(app, base_url=BASE)
        engine.token_lifecycle_manager = enabled
        engine.cookies = cookies or {}
        engine._finding_dedup = set()
        engine.all_findings = []
        engine.probe_statuses = []
        engine.record_probe_status = lambda status, url=None: engine.probe_statuses.append((status, str(url or "")))
        return _TestFormScanner(engine), engine

    async def scan_real(self, app, path, enabled=True):
        scanner, engine = self.scanner(app, enabled)
        scanner = MailHeaderInjectionScanner(engine)
        engine.browser = _HttpxFormBrowser(engine)
        scanner.browser = engine.browser
        ip = InjectionPoint.for_form(f"{BASE}{path}", "email", form_tokens=("csrf_token",))
        findings = await scanner.scan_injection_point(ip, {"name": "email", "value": ""})
        return findings, scanner, engine

    async def test_static_has_safe_twin_under_both_modes(self):
        for path, vulnerable in (("/csrf-static", True), ("/csrf-static-safe", False)):
            for enabled in (False, True):
                app = create_app()
                sc, engine = self.scanner(app, enabled)
                source, pair = await sc._apply_ip(_ip(BASE, path), PAYLOAD)
                self.assertEqual(pair["response"]["status"], 200)
                self.assertEqual("\nCc: attacker@evil.example.com" in source, vulnerable)
                self.assertEqual(engine.wave_errors, [])
                findings, _, _ = await self.scan_real(app, path, enabled)
                self.assertEqual(bool(findings), vulnerable)

    async def test_rotating_fixture_is_independent_existing_one_time_endpoint(self):
        for path, vulnerable in (("/csrf-contact", True), ("/csrf-contact-safe", False)):
            outcomes = []
            for enabled in (False, True):
                app = create_app()
                sc, _ = self.scanner(app, enabled)
                source, pair = await sc._apply_ip(_ip(BASE, path), PAYLOAD)
                outcomes.append((pair["response"]["status"], "\nCc: attacker@evil.example.com" in source))
                findings, _, _ = await self.scan_real(app, path, enabled)
                self.assertEqual(bool(findings), vulnerable)
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
            for enabled in (False, True):
                findings, _, _ = await self.scan_real(create_app(), path, enabled)
                self.assertEqual(bool(findings), vulnerable)

        app = create_app()
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
            form = await client.get("/csrf-onetime")
            token = form.text.split('name="csrf_token" value="')[1].split('"')[0]
            reloaded = await client.get("/csrf-onetime")
            reloaded_token = reloaded.text.split('name="csrf_token" value="')[1].split('"')[0]
            self.assertEqual(reloaded_token, token)
            self.assertEqual((await client.post("/csrf-onetime", data={"email": "first", "csrf_token": token})).status_code, 200)
            self.assertNotEqual((await client.get("/csrf-onetime")).text.split('name="csrf_token" value="')[1].split('"')[0], token)
            self.assertEqual((await client.post("/csrf-onetime", data={"email": "second", "csrf_token": token})).status_code, 419)

        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url=BASE) as client:
            first = await client.get("/csrf-contact")
            old_token = first.text.split('name="csrf_token" value="')[1].split('"')[0]
            new_token = (await client.get("/csrf-contact")).text.split('name="csrf_token" value="')[1].split('"')[0]
            self.assertNotEqual(old_token, new_token)
            self.assertEqual((await client.post("/csrf-contact", data={"email": "x", "csrf_token": old_token})).status_code, 403)

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
        for enabled in (False, True):
            findings, _, _ = await self.scan_real(create_app(), "/csrf-session", enabled)
            self.assertTrue(findings)

    async def test_session_bound_safe_twin_has_no_finding_in_both_modes(self):
        for enabled in (False, True):
            app = create_app()
            sc, _ = self.scanner(app, enabled)
            source, pair = await sc._apply_ip(_ip(BASE, "/csrf-session-safe"), PAYLOAD)
            self.assertEqual(pair["response"]["status"], 200)
            self.assertNotIn("\nCc: attacker@evil.example.com", source)
            findings, _, _ = await self.scan_real(create_app(), "/csrf-session-safe", enabled)
            self.assertEqual(findings, [])

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
        scanner, engine = self.scanner(app, True)
        scanner = MailHeaderInjectionScanner(engine)
        engine.browser = _HttpxFormBrowser(engine)
        scanner.browser = engine.browser
        with patch.object(scanner, "_apply_payload_raw", return_value=None):
            ip = InjectionPoint.for_form(f"{BASE}/csrf-contact-oneshot-stuck", "email", form_tokens=("csrf_token",))
            findings = await scanner.scan_injection_point(ip, {"name": "email", "value": ""})
        self.assertEqual(findings, [])
        self.assertIn("token_lifecycle:probe_inconclusive:mail_header", engine.wave_errors)
        self.assertIn((419, f"{BASE}/csrf-contact-oneshot-stuck"), engine.probe_statuses)
        self.assertNotIn((200, f"{BASE}/csrf-contact-oneshot-stuck"), engine.probe_statuses)
        self.assertEqual(scanner.findings, [])


if __name__ == "__main__":
    unittest.main()
