"""httpx FORM トークンマネージャ（flag 既定 OFF）の parity / inconclusive テスト。"""
from __future__ import annotations

import unittest

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, PlainTextResponse

from tests.fixtures.large_vuln_app import create_app
from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
from wscan.injection_point import InjectionPoint
from wscan.token_lifecycle import (
    DeclaredStatus, TokenCarrier, TokenTransport, build_token_capability_matrix,
    refresh_form_tokens,
)

PAYLOAD = "user@example.com\r\nCc: attacker@evil.example.com"


def _ip(base, path):
    return InjectionPoint.for_form(f"{base}{path}", "email", form_index=0, form_tokens=("csrf_token",))


class ManagerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = create_app(page_count=4)

    def _scanner(self, flag, app=None, base="http://large-fixture.test"):
        engine = _TestEngine(app or self.app, base_url=base)
        if flag is not None:
            engine.token_lifecycle_manager = flag
        engine.wave_errors = []
        return _TestFormScanner(engine), engine

    def _inconclusive(self, engine):
        return [n for n in engine.wave_errors if "probe_inconclusive" in n]

    async def test_default_flag_off_has_no_attribute_effect(self):
        sc, eng = self._scanner(None)
        self.assertFalse(sc._token_manager_enabled())
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact-oneshot-stuck"), PAYLOAD)
        self.assertEqual(self._inconclusive(eng), [])

    async def test_vulnerable_rotating_parity_on_off(self):
        out = {}
        for flag in (False, True):
            sc, eng = self._scanner(flag)
            src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact"), PAYLOAD)
            out[flag] = (pair["response"]["status"], "\nCc: attacker@evil.example.com" in src, eng.wave_errors)
        self.assertEqual(out[False][0], 200)
        self.assertEqual(out[False], out[True])
        self.assertTrue(out[True][1])

    async def test_stuck_vulnerable_on_is_inconclusive_not_finding(self):
        sc, eng = self._scanner(True)
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact-oneshot-stuck"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 419)
        self.assertNotIn("\nCc: attacker@evil.example.com", src)
        self.assertEqual(self._inconclusive(eng), ["token_lifecycle:probe_inconclusive:mail_header"])

    async def test_stuck_off_is_legacy_silent(self):
        sc, eng = self._scanner(False)
        await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact-oneshot-stuck"), PAYLOAD)
        self.assertEqual(self._inconclusive(eng), [])

    async def test_stuck_safe_twin_is_accepted_without_inconclusive(self):
        sc, eng = self._scanner(True)
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact-oneshot-stuck-safe"), PAYLOAD)
        self.assertNotIn("\nCc: attacker@evil.example.com", src)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertEqual(self._inconclusive(eng), [])

    async def test_safe_twin_on_no_inconclusive(self):
        sc, eng = self._scanner(True)
        src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact-safe"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertEqual(self._inconclusive(eng), [])

    async def test_static_token_request_bytes_identical(self):
        res = {}
        for flag in (False, True):
            sc, eng = self._scanner(flag)
            _, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-static"), PAYLOAD)
            res[flag] = (pair["request"]["post_data"], pair["response"]["status"], eng.wave_errors)
        self.assertEqual(res[False], res[True])

    async def test_waf_403_is_blocked_not_inconclusive(self):
        app = FastAPI()

        @app.get("/f", response_class=HTMLResponse)
        async def f():
            return HTMLResponse('<form method="post" action="/f"><input type="hidden" name="csrf_token" value="abc123tok"><input name="email"></form>')

        @app.post("/f", response_class=PlainTextResponse)
        async def p(email: str = Form(""), csrf_token: str = Form("")):
            return PlainTextResponse("Access Denied by WAF", status_code=403)

        sc, eng = self._scanner(True, app, "http://waf.test")
        await sc._apply_ip(_ip("http://waf.test", "/f"), PAYLOAD)
        self.assertEqual(self._inconclusive(eng), [])

    async def test_raw_nonce_absent_from_notes_and_snapshots(self):
        sc, eng = self._scanner(True)
        await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact-oneshot-stuck"), PAYLOAD)
        self.assertNotIn("token_secretvalue123", " ".join(eng.wave_errors))
        r = refresh_form_tokens({"csrf_token": "token_secretvalue123"}, provenance="u", status_code=200)
        self.assertNotIn("token_secretvalue123", repr(r))

    async def test_manager_exception_falls_back_to_legacy(self):
        from unittest.mock import patch
        sc, eng = self._scanner(True)
        with patch("wscan.token_lifecycle.refresh_form_tokens", side_effect=RuntimeError("boom")):
            src, pair = await sc._apply_ip(_ip("http://large-fixture.test", "/csrf-contact"), PAYLOAD)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertEqual(self._inconclusive(eng), [])

    def test_matrix_declares_only_implemented_httpx_carriers_supported(self):
        m = build_token_capability_matrix()
        self.assertTrue(m.is_supported(TokenCarrier.FORM_URLENCODED, TokenTransport.HTTPX))
        supported = [(c, t) for c in TokenCarrier for t in TokenTransport if m.is_supported(c, t)]
        # PLAYWRIGHT と FLOW が SUPPORTED に追加されたため、6 エントリになる
        expected = sorted(supported, key=lambda x: (x[0].value, x[1].value))
        self.assertEqual(sorted(supported, key=lambda x: (x[0].value, x[1].value)), sorted([
            (TokenCarrier.FORM_URLENCODED, TokenTransport.HTTPX),
            (TokenCarrier.JSON, TokenTransport.HTTPX),
            (TokenCarrier.XML, TokenTransport.HTTPX),
            (TokenCarrier.HTTP_HEADER, TokenTransport.HTTPX),
            (TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT),
            (TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW),
        ], key=lambda x: (x[0].value, x[1].value)))
