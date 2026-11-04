"""Anti-CSRF / Nonce トークンライフサイクル HTTPX フォーム共有パスの統合テスト。

CI 環境で Chromium 等のブラウザバイナリを起動せず（browser-free）、
httpx.ASGITransport を用いて以下の仕様を満たすことを検証する:
(a) fresh-token リフレッシュにより、ローテーションフォームへのプローブがインジェクションへ到達すること
(b) 安全ツイン（safe twin）ではインジェクションが成立せず所見が生じないこと
(c) 静的トークン（static-token）フォームが従来どおり正常に動作すること
(d) リフレッシュ不可時（500 エラー等）に token_lifecycle:refresh_unavailable:<check> ノートを記録し元のリクエストを送信すること
(e) 生トークン値がノート・ログ・証拠・ペア情報に一切漏洩せず derive_token_ref_id で秘匿されること
(f) mail_header テストが非回帰かつ正常に通過すること
"""
from __future__ import annotations

import unittest
import tempfile
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from tests.fixtures.large_vuln_app import create_app
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.scanners.mail_header import MailHeaderInjectionScanner
from wscan.request_logger import RequestLogger
from wscan.token_lifecycle import derive_token_ref_id, extract_form_tokens


class _DummyBrowserContext:
    def __init__(self, cookies: list[dict] | None = None):
        self._cookies = cookies or []

    async def cookies(self):
        return self._cookies


class _DummyPage:
    def __init__(self, context: _DummyBrowserContext):
        self.context = context


class _DummyBrowser:
    def __init__(self, cookies: list[dict] | None = None):
        self.context = _DummyBrowserContext(cookies)
        self.page = _DummyPage(self.context)
        self.last_probe_delivered = True

    async def fill_and_submit_form(self, form_index, field_name, payload):
        return "", {}


class _TestEngine:
    def __init__(self, app, base_url: str = "http://large-fixture.test"):
        self.app = app
        self.base_url = base_url
        self.browser = _DummyBrowser()
        self.wave_errors: list[str] = []
        self.monitor = None
        self.payload_gen = None
        self.state_profile = "unrestricted"
        self.attempt_ledger = None
        self.request_logger = None
        self.timeout = 10
        self.cookies: dict[str, str] = {}

    def httpx_client_kwargs(self, **kwargs):
        kwargs["transport"] = httpx.ASGITransport(app=self.app)
        kwargs["base_url"] = self.base_url
        return kwargs

    def _is_access_allowed_url(self, url: str) -> bool:
        return True

    def _is_url_excluded(self, url: str) -> bool:
        return False


class _TestFormScanner(BaseScanner):
    CHECK_TYPE = "mail_header"

    async def scan_field(self, *args, **kwargs):
        return []

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        # トークン再取得を行わない素の送信（フォールバック時の挙動検証用）
        client_kwargs = {}
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs()
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.post(
                url,
                data={field_name: payload, "csrf_token": "stale_raw_token_value_xyz"},
            )
            pair = {
                "request": {
                    "url": url,
                    "method": "POST",
                    "post_data": f"{field_name}={payload}&csrf_token=stale_raw_token_value_xyz",
                },
                "response": {
                    "url": str(resp.url),
                    "status": resp.status_code,
                    "body": resp.text,
                    "headers": dict(resp.headers),
                },
            }
            return resp.text, pair


class TokenLifecycleFixturesTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = create_app(page_count=4)
        self.engine = _TestEngine(self.app)
        self.scanner = _TestFormScanner(self.engine)

    async def test_a_vulnerable_rotating_token_form_refreshes_and_reaches_injection(self):
        """(a) fresh-token リフレッシュにより、ローテーションフォームでインジェクションが成立すること。"""
        # 単体 POST では古い/未設定トークンのため 403 CSRF token mismatch となることを確認
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://large-fixture.test",
        ) as raw_client:
            stale_post = await raw_client.post(
                "/csrf-contact",
                data={"email": "attacker@evil.test", "csrf_token": "invalid_old_token"},
            )
            self.assertEqual(stale_post.status_code, 403)
            self.assertIn("CSRF token mismatch", stale_post.text)

        # 共有 HTTPX フォーム経路で InjectionPoint を介してプローブ送信
        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-contact",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        payload = "user@example.com\r\nCc: attacker@evil.example.com"
        source, pair = await self.scanner._apply_ip(ip, payload)

        # トークンが送信直前に再取得されたため 200 で受理され、CRLF 注入ヘッダが反射する
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("\nCc: attacker@evil.example.com", source)
        self.assertIn("Sending confirmation...", source)

    async def test_b_safe_twin_produces_no_finding_with_fresh_token(self):
        """(b) 安全ツインではトークン更新を経て 200 受理されるが、CRLF 除去により注入が成立しないこと。"""
        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-contact-safe",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        payload = "user@example.com\r\nCc: attacker@evil.example.com"
        scanner = MailHeaderInjectionScanner(self.engine)
        self.engine.sleep_factor = 0
        findings = await scanner.scan_injection_point(ip, {"name": "email", "value": ""})
        source, pair = await self.scanner._apply_ip(ip, payload)

        # トークン検証は 200 で正常通過するが、CRLF がサニタイズされインジェクション行は存在しない
        self.assertEqual(pair["response"]["status"], 200)
        self.assertNotIn("\nCc: attacker@evil.example.com", source)
        self.assertIn("Sending confirmation...", source)
        self.assertEqual(findings, [])

    async def test_refresh_preserves_original_request_and_only_changes_token(self):
        from fastapi import FastAPI, Form
        from fastapi.responses import HTMLResponse, PlainTextResponse

        app = FastAPI()
        received = {}

        @app.get("/page")
        async def page():
            return HTMLResponse('<form method="get" action="/new"><input name="email" value="fresh"><input name="other" value="changed"><input name="csrf_token" value="fresh-token"></form>')

        @app.post("/original")
        async def original(email: str = Form(""), other: str = Form(""), csrf_token: str = Form("")):
            received.update(email=email, other=other, csrf_token=csrf_token)
            return PlainTextResponse("accepted")

        engine = _TestEngine(app, base_url="http://request-test")
        scanner = _TestFormScanner(engine)
        ip = InjectionPoint.for_form("http://request-test/page", "email", method="POST", action="/original",
            form_tokens=("csrf_token",), form_fields=(("email", "original"), ("other", "kept"), ("csrf_token", "stale-token")))
        refreshed = await scanner._apply_form_with_token_refresh(ip, "payload")
        self.assertIsNotNone(refreshed)
        source, pair = refreshed
        self.assertEqual(received, {"email": "payload", "other": "kept", "csrf_token": "fresh-token"}, pair)
        self.assertEqual(pair["request"]["url"], "http://request-test/original")
        self.assertEqual(pair["request"]["method"], "POST")

    async def test_stale_retry_refresh_failure_records_note(self):
        from fastapi import FastAPI, Form
        from fastapi.responses import HTMLResponse, PlainTextResponse

        app = FastAPI()
        gets = 0

        @app.get("/form", response_class=HTMLResponse)
        async def get_form():
            nonlocal gets
            gets += 1
            token = '<input name="csrf_token" value="fresh">' if gets == 1 else '<input name="other" value="missing">'
            return HTMLResponse(f'<form method="post">{token}<input name="email" value="x"></form>')

        @app.post("/form")
        async def post_form(email: str = Form(""), csrf_token: str = Form("")):
            return PlainTextResponse("CSRF token mismatch", status_code=403)

        engine = _TestEngine(app, base_url="http://retry-fail")
        scanner = _TestFormScanner(engine)
        ip = InjectionPoint.for_form("http://retry-fail/form", "email", form_tokens=("csrf_token",),
            form_fields=(("email", "original"), ("csrf_token", "old")))
        await scanner._apply_ip(ip, "payload")
        self.assertIn("token_lifecycle:refresh_unavailable:mail_header", engine.wave_errors)

    async def test_probe_send_exception_propagates(self):
        ip = InjectionPoint.for_form("http://large-fixture.test/csrf-contact", "email", form_tokens=("csrf_token",))
        with patch.object(self.scanner, "_record_probe_status", side_effect=RuntimeError("send failed")):
            with self.assertRaisesRegex(RuntimeError, "send failed"):
                await self.scanner._apply_ip(ip, "payload")

    async def test_raw_tokens_absent_from_request_logger_files(self):
        from fastapi import FastAPI, Form
        from fastapi.responses import HTMLResponse, PlainTextResponse
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            app = FastAPI()
            @app.get("/form", response_class=HTMLResponse)
            async def form():
                return HTMLResponse('<form method="post"><input name="csrf_token" value="fresh-token-raw-secret"><input name="email" value="original"></form>')
            @app.post("/form")
            async def submit(email: str = Form(""), csrf_token: str = Form("")):
                return PlainTextResponse("accepted")
            self.engine = _TestEngine(app, base_url="http://logger-test")
            self.scanner = _TestFormScanner(self.engine)
            logger = RequestLogger(directory)
            self.engine.request_logger = logger
            ip = InjectionPoint.for_form("http://logger-test/form", "email", form_tokens=("csrf_token",),
                form_fields=(("email", "original"), ("csrf_token", "stale-token-raw-secret")))
            source, pair = await self.scanner._apply_ip(ip, "logged payload")
            raw_fresh = "fresh-token-raw-secret"
            logger.log_payload("email", "logged payload", "mail_header", ip.url)
            logger.log_probe(role="attack", pair=pair, check="mail_header", field="email", payload="logged payload", url=ip.url, sent=True)
            files = [path for path in Path(directory).rglob("*") if path.is_file()]
            contents = "".join(path.read_text(errors="replace") for path in files)
            for secret in (raw_fresh, "stale-token-raw-secret"):
                self.assertNotIn(secret, contents)
                self.assertNotIn(secret, str(self.engine.wave_errors))
                self.assertNotIn(secret, str(self.scanner.findings))

    async def test_c_static_token_form_works_unchanged(self):
        """(c) 固定トークンフォーム（static-token）でも正常に動作すること。"""
        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-static",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        payload = "user@example.com\r\nCc: attacker@evil.example.com"
        source, pair = await self.scanner._apply_ip(ip, payload)

        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("\nCc: attacker@evil.example.com", source)

    async def test_d_refresh_unavailable_records_scan_note_and_falls_back(self):
        """(d) フォーム再取得が 500 等で失敗した場合、観測ノートを記録し元の送信へフォールバックすること。"""
        # 500 を返すエンドポイント
        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-failing-form",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        source, pair = await self.scanner._apply_ip(ip, "probe_payload")

        # refresh_unavailable ノートが記録されること
        self.assertIn("token_lifecycle:refresh_unavailable:mail_header", self.engine.wave_errors)
        # 既存の _apply_payload 経路へフォールバックして元の送信が行われること
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("Sent: probe_payload", source)

    async def test_refresh_redirect_does_not_leave_scope_and_falls_back_unchanged(self):
        from fastapi import FastAPI, Form, Request
        from fastapi.responses import HTMLResponse, PlainTextResponse, RedirectResponse

        app = FastAPI()
        requests = []

        @app.get("/form")
        async def form():
            return RedirectResponse("http://out-of-scope.test/landing", status_code=302)

        @app.get("/{path:path}")
        async def observe(path: str, request: Request):
            requests.append((request.url.hostname, request.method, await request.body()))
            return HTMLResponse('<form><input name="csrf_token" value="unexpected"></form>')

        @app.post("/form")
        async def submit(email: str = Form(""), csrf_token: str = Form("")):
            requests.append(("request-test", "POST", f"email={email}&csrf_token={csrf_token}".encode()))
            return PlainTextResponse(f"Sent: {email}")

        engine = _TestEngine(app, base_url="http://request-test")
        scanner = _TestFormScanner(engine)
        ip = InjectionPoint.for_form(
            "http://request-test/form", "email", form_tokens=("csrf_token",),
            form_fields=(("email", "original"), ("csrf_token", "stale_raw_token_value_xyz")),
        )
        source, pair = await scanner._apply_ip(ip, "probe_payload")

        self.assertNotIn("out-of-scope.test", [host for host, _, _ in requests])
        self.assertIn(("request-test", "POST", b"email=probe_payload&csrf_token=stale_raw_token_value_xyz"), requests)
        self.assertIn("token_lifecycle:refresh_unavailable:mail_header", engine.wave_errors)
        self.assertIn("Sent: probe_payload", source)
        self.assertEqual(pair["request"]["post_data"], "email=probe_payload&csrf_token=stale_raw_token_value_xyz")

    async def test_d2_refresh_unavailable_on_budget_exhaustion(self):
        """(d2) リクエスト予算（budget gate）超過時にも refresh_unavailable を記録しフォールバックすること。"""
        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-contact",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        # 本プローブは許可しつつ、トークン再取得時の追加 GET 予算が超過（_field_budget_gate -> True）する状態を模擬
        with patch.object(self.scanner, "_field_budget_gate", side_effect=[False, True]):
            source, pair = await self.scanner._apply_ip(ip, "budget_payload")

        self.assertIn("token_lifecycle:refresh_unavailable:mail_header", self.engine.wave_errors)
        # フォールバックで _apply_payload が呼ばれたこと（無効トークンにより 403）
        self.assertEqual(pair["response"]["status"], 403)

    async def test_e_raw_token_value_never_appears_in_notes_or_evidence(self):
        """(e) 生トークン値がノート・ログ・証拠・pair の post_data に現れず不可逆参照ID化されること。"""
        # アプリから実際の生トークン値を 1 つ取得
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app),
            base_url="http://large-fixture.test",
        ) as client:
            resp = await client.get("/csrf-contact")
            tokens = extract_form_tokens(resp.text)
            real_raw_token = tokens["csrf_token"]
            self.assertTrue(real_raw_token.startswith("token_"))

        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-contact",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        source, pair = await self.scanner._apply_ip(ip, "user@test.org")

        # 生トークン値が wave_errors（ノート）に含まれないこと
        for note in self.engine.wave_errors:
            self.assertNotIn(real_raw_token, note)

        # pair["request"]["post_data"] に生トークン値が含まれず、tok_ref_ が含まれること
        post_data = pair["request"]["post_data"]
        self.assertNotIn(real_raw_token, post_data)
        self.assertIn("csrf_token=tok_ref_", post_data)

    async def test_f_tested_token_field_is_never_overwritten_by_refresh(self):
        """検査対象フィールド自体がトークンの場合は再取得による上書きを行わないこと。"""
        ip = InjectionPoint.for_form(
            "http://large-fixture.test/csrf-contact",
            "csrf_token",
            form_index=0,
            form_tokens=("csrf_token",),
        )
        attack_token_payload = "' OR '1'='1"
        source, pair = await self.scanner._apply_ip(ip, attack_token_payload)

        # 検査対象フィールド自体はリフレッシュ対象外であり、フォールバックの _apply_payload を通る
        self.assertIn(attack_token_payload, pair["request"]["post_data"])

    async def test_g_bounded_retry_on_stale_response_resends_at_most_once(self):
        """(g) レスポンスが STALE（失効）と判定された場合、最大1回だけ再取得して再送すること（有界リトライ）。"""
        from fastapi import FastAPI, Form
        from fastapi.responses import HTMLResponse, PlainTextResponse

        retry_app = FastAPI()
        post_count = 0
        get_count = 0

        @retry_app.get("/stale-form", response_class=HTMLResponse)
        async def stale_form_get():
            nonlocal get_count
            get_count += 1
            return HTMLResponse(
                f'<form method="post" action="/stale-form">'
                f'<input type="hidden" name="csrf_token" value="tok_{get_count}">'
                f'<input name="email" value="user@test">'
                f'</form>'
            )

        @retry_app.post("/stale-form", response_class=PlainTextResponse)
        async def stale_form_post(email: str = Form(""), csrf_token: str = Form("")):
            nonlocal post_count
            post_count += 1
            if post_count == 1:
                # 初回は STALE エラーを返す
                return PlainTextResponse("CSRF token mismatch error occurred", status_code=403)
            # 2回目（リトライ）は成功
            return PlainTextResponse(f"Success on retry: {email}", status_code=200)

        engine = _TestEngine(retry_app, base_url="http://retry-test")
        scanner = _TestFormScanner(engine)
        ip = InjectionPoint.for_form(
            "http://retry-test/stale-form",
            "email",
            form_index=0,
            form_tokens=("csrf_token",),
        )

        source, pair = await scanner._apply_ip(ip, "retry_payload")
        # 1回目の STALE 後、1回だけリトライが行われて 200 成功応答を取得したこと
        self.assertEqual(post_count, 2)
        self.assertEqual(get_count, 2)
        self.assertEqual(pair["response"]["status"], 200)
        self.assertIn("Success on retry: retry_payload", source)
