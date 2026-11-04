"""Anti-CSRF / Nonce トークンライフサイクル観測層の単体テスト（加算的・非ブロッキング）。

本テストスイートは以下を検証する:
1. トークンフィールドに対するトークン失効応答（STALE / INCONCLUSIVE / BLOCKED）が観測ノートを記録すること
2. 通常の非トークンフィールド（q, username 等）では一切ノートが記録されないこと（誤分類防止）
3. トークンフィールドであっても正常 200 応答ではノートが記録されないこと
4. 生トークン値がノートに含まれず不可逆な参照IDのみ記録されること
5. 脆弱性判定・チェックポイント完了挙動が従来と一切変わらないこと（非回帰）
"""
from __future__ import annotations

import unittest
from unittest.mock import AsyncMock

import pytest

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.token_lifecycle import (
    is_token_field_name,
)


class _DummyBrowser:
    def __init__(self, status: int = 200, body: str = "OK", headers: dict | None = None):
        self.status = status
        self.body = body
        self.headers = headers or {}
        self.last_probe_delivered = True

    async def fill_and_submit_form(self, form_index, field_name, payload):
        pair = {
            "request": {
                "url": "https://example.com/form",
                "method": "POST",
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "post_data": f"{field_name}={payload}",
            },
            "response": {
                "status": self.status,
                "headers": dict(self.headers),
                "body": self.body,
            },
        }
        return self.body, pair


class _DummyEngine:
    def __init__(self, browser: _DummyBrowser | None = None):
        self.browser = browser or _DummyBrowser()
        self.wave_errors: list[str] = []
        self.monitor = None
        self.payload_gen = None
        self.state_profile = "unrestricted"
        self.attempt_ledger = None
        self.request_logger = None

    def observability_summary(self) -> dict:
        by_category: dict[str, int] = {}
        for raw_note in self.wave_errors:
            note = str(raw_note)
            category = note.split(":", 1)[0].strip() if ":" in note else "other"
            category = category or "other"
            by_category[category] = by_category.get(category, 0) + 1
        return {
            "total": len(self.wave_errors),
            "by_category": by_category,
            "llm_calls": 0,
        }


class _TestScanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, *args, **kwargs):
        return []

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        return await self.browser.fill_and_submit_form(form_index, field_name, payload)


# ── 1. 純粋関数テスト（フィールド名判定） ─────────────────────────────────────

def test_is_token_field_name_pure():
    """トークンフィールド名判定の純粋関数を検証（通常フィールドを誤分類しない）。"""
    # トークンフィールドとして正しく認識されるべき名称
    assert is_token_field_name("csrf") is True
    assert is_token_field_name("_csrf") is True
    assert is_token_field_name("csrf_token") is True
    assert is_token_field_name("CSRF-TOKEN") is True
    assert is_token_field_name("csrfmiddlewaretoken") is True
    assert is_token_field_name("authenticity_token") is True
    assert is_token_field_name("__RequestVerificationToken") is True
    assert is_token_field_name("_token") is True
    assert is_token_field_name("token") is True
    assert is_token_field_name("nonce") is True
    assert is_token_field_name("_nonce") is True
    assert is_token_field_name("_wpnonce") is True
    assert is_token_field_name("xsrf") is True
    assert is_token_field_name("xsrf_token") is True

    # ユーザー入力フィールドとして誤認識されてはならない名称
    assert is_token_field_name("q") is False
    assert is_token_field_name("search") is False
    assert is_token_field_name("username") is False
    assert is_token_field_name("email") is False
    assert is_token_field_name("password") is False
    assert is_token_field_name("stockton") is False
    assert is_token_field_name("token_amount") is False
    assert is_token_field_name("user_token") is False
    assert is_token_field_name("access_token") is False
    assert is_token_field_name("reset_token") is False
    assert is_token_field_name("") is False
    assert is_token_field_name(None) is False


# ── 2. 観測層テスト（非同期） ───────────────────────────────────────────────

class TokenLifecycleObservabilityTests(unittest.IsolatedAsyncioTestCase):
    """BaseScanner のトークンライフサイクル観測層を検証する。"""

    async def test_token_field_expiry_response_records_observability_note(self):
        """トークンフィールドに対する失効レスポンスが観測ノートを記録しサマリへ反映されること。"""
        # 403 CSRF トークン不一致応答
        browser = _DummyBrowser(
            status=403,
            body="CSRF token mismatch error occurred",
        )
        engine = _DummyEngine(browser)
        scanner = _TestScanner(engine)
        raw_secret_payload = "super_secret_attack_payload_12345678"

        ip = InjectionPoint.for_form("https://example.com/post", "csrf_token", form_index=0)
        source, pair = await scanner._apply_ip(ip, raw_secret_payload)

        # 応答とペアは従来通りそのまま返る
        self.assertEqual(source, "CSRF token mismatch error occurred")
        self.assertEqual(pair["response"]["status"], 403)

        # 観測ノートが記録されていること
        self.assertEqual(len(engine.wave_errors), 1)
        note = engine.wave_errors[0]
        self.assertTrue(note.startswith("token_lifecycle:stale:xss:csrf_token:stale_token_mismatch"))

        # 生シークレットがノートに含まれていないこと
        self.assertNotIn(raw_secret_payload, note)
        # 不可逆参照IDが含まれていること
        self.assertIn("tok_ref_", note)

        # observability_summary のカテゴリ集計に token_lifecycle が反映されること
        summary = engine.observability_summary()
        self.assertEqual(summary["total"], 1)
        self.assertEqual(summary["by_category"].get("token_lifecycle"), 1)

    async def test_safe_twin_normal_non_token_field_records_no_note(self):
        """通常の非トークン入力フィールド（username 等）では失効風エラーでもノートを記録しない。"""
        # 同じ 403 CSRF トークン不一致応答だが、対象フィールドは通常の "username"
        browser = _DummyBrowser(
            status=403,
            body="CSRF token mismatch error occurred",
        )
        engine = _DummyEngine(browser)
        scanner = _TestScanner(engine)

        ip = InjectionPoint.for_form("https://example.com/login", "username", form_index=0)
        source, pair = await scanner._apply_ip(ip, "alice")

        # 挙動不変（通常通り返る）
        self.assertEqual(source, "CSRF token mismatch error occurred")
        self.assertEqual(pair["response"]["status"], 403)

        # 観測ノートは一切記録されないこと（誤分類防止）
        self.assertEqual(engine.wave_errors, [])
        summary = engine.observability_summary()
        self.assertEqual(summary["total"], 0)
        self.assertNotIn("token_lifecycle", summary["by_category"])

    async def test_safe_twin_fresh_200_response_records_no_note(self):
        """トークンフィールドであっても 200 正常受理レスポンスではノートを記録しない。"""
        # 200 正常受理応答
        browser = _DummyBrowser(
            status=200,
            body="<html>Success</html>",
        )
        engine = _DummyEngine(browser)
        scanner = _TestScanner(engine)

        ip = InjectionPoint.for_form("https://example.com/login", "csrf_token", form_index=0)
        source, pair = await scanner._apply_ip(ip, "fresh_token_value")

        self.assertEqual(source, "<html>Success</html>")
        self.assertEqual(pair["response"]["status"], 200)

        # 観測ノートは記録されないこと
        self.assertEqual(engine.wave_errors, [])
        summary = engine.observability_summary()
        self.assertEqual(summary["total"], 0)

    async def test_laravel_419_page_expired_records_stale_note(self):
        """Laravel 419 Page Expired 応答が STALE 観測ノートとして記録されること。"""
        browser = _DummyBrowser(
            status=419,
            body="419 | Page Expired",
        )
        engine = _DummyEngine(browser)
        scanner = _TestScanner(engine)

        ip = InjectionPoint.for_form("https://example.com/login", "_token", form_index=0)
        await scanner._apply_ip(ip, "expired_token")

        self.assertEqual(len(engine.wave_errors), 1)
        note = engine.wave_errors[0]
        self.assertTrue(note.startswith("token_lifecycle:stale:xss:_token:stale_token_mismatch"))

    async def test_status_403_hint_only_records_inconclusive_note(self):
        """ステータス 403 単体（明示的本文シグナルなし）が INCONCLUSIVE ノートとして記録されること。"""
        browser = _DummyBrowser(
            status=403,
            body="Forbidden",
        )
        engine = _DummyEngine(browser)
        scanner = _TestScanner(engine)

        ip = InjectionPoint.for_form("https://example.com/login", "authenticity_token", form_index=0)
        await scanner._apply_ip(ip, "some_token")

        self.assertEqual(len(engine.wave_errors), 1)
        note = engine.wave_errors[0]
        self.assertTrue(note.startswith("token_lifecycle:inconclusive:xss:authenticity_token:status_hint_only"))

    async def test_non_regression_findings_and_checkpoint_keys_unaffected(self):
        """観測層が脆弱性判定およびチェックポイントキーに影響を与えない非回帰性を検証。"""
        from wscan.checkpoint import unit_key

        browser = _DummyBrowser(
            status=403,
            body="CSRF token mismatch",
        )
        engine = _DummyEngine(browser)
        scanner = _TestScanner(engine)

        ip = InjectionPoint.for_form("https://example.com/form", "csrf_token", form_index=1)
        url, field_name, form_index, location_token, pointer = ip.stable_key_parts()
        key = unit_key(url, field_name, int(form_index), scanner.CHECK_TYPE, location_token=location_token, pointer=pointer)

        # 観測ノート記録の有無に関わらず unit_key は一意かつ不変
        self.assertIn("https://example.com/form", key)
        self.assertIn("csrf_token", key)
        self.assertIn("xss", key)

        # プローブ送信後も scanner の findings リストは一切変更されない
        self.assertEqual(scanner.findings, [])
        await scanner._apply_ip(ip, "payload")
        self.assertEqual(scanner.findings, [])
