"""ログイン形態マトリクス（7形態）のループバック E2E テスト。

Normal-mode auto-login が各ログイン形態で期待される状態（success / challenge / failure）
に到達すること、および検証済み（verified）のときのみ認証カバレッジが報告されることを実ブラウザで保証する。
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import os
import socket
import tempfile
import threading
import time
from typing import Generator

import httpx
import pytest
import uvicorn

from tests.fixtures import login_matrix_app as fx
from wscan import login_surface as ls
from wscan.engine import ScanEngine


def _e2e_enabled() -> bool:
    return os.environ.get("WSCAN_E2E", "").strip().lower() in {"1", "true", "yes", "on"}


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


_CHROMIUM_OK = _chromium_available()


@contextmanager
def serving(app) -> Generator[str, None, None]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10.0
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("login matrix fixture server did not start")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        sock.close()


@pytest.fixture(scope="module")
def base_url():
    """モジュール単位でループバックサーバーを一度だけ起動する。"""
    app = fx.create_app()
    with serving(app) as url:
        yield url


# =============================================================================
# 1. 高速ユニットテスト（WSCAN_E2E 未設定時でも CI/通常 pytest で実行）
# =============================================================================

@pytest.mark.parametrize("variant", fx.VARIANTS, ids=[v.name for v in fx.VARIANTS])
def test_fixture_anonymous_access_denied(variant: fx.LoginVariantSpec):
    """全形態の保護リソースが未認証アクセスに対して 401 を返すことを保証。"""
    async def check():
        transport = httpx.ASGITransport(app=fx.create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            resp = await client.get(variant.protected_path)
            assert resp.status_code == 401
    asyncio.run(check())


def test_variant_specs_completeness():
    """全7形態の定義が一意かつ完全であることを保証。"""
    assert len(fx.VARIANTS) == 7
    ids = [v.variant_id for v in fx.VARIANTS]
    assert sorted(ids) == list(range(1, 8))
    names = [v.name for v in fx.VARIANTS]
    assert len(set(names)) == 7


# =============================================================================
# 2. 実ブラウザ E2E マトリクステスト（WSCAN_E2E=1 のみ実行）
# =============================================================================

async def _run_matrix_scan(base: str, variant: fx.LoginVariantSpec, password: str) -> ScanEngine:
    """指定ログイン形態に対して短時間の実ブラウザスキャン（checks=[xss], no-LLM）を実行する。"""
    with tempfile.TemporaryDirectory() as tmp_dir:
        engine = ScanEngine(
            f"{base}{variant.protected_path}",
            login_url=f"{base}{variant.login_path}",
            auth_user=fx.USERNAME,
            auth_pass=password,
            checks=["xss"],
            llm_provider="none",
            headless=True,
            output_dir=tmp_dir,
            open_report=False,
            enable_waf_detection=False,
            enable_ai_analysis=False,
            enable_payload_learning=False,
            enable_adaptive_payloads=False,
            enable_sitemap_crawl=False,
            depth=1,
            fast_mode=True,
            max_payloads=2,
            request_delay=0,
            use_planner=False,
            sarif=False,
            timeout=8,
            navigation_retries=0,
        )
        await asyncio.wait_for(engine.run(), timeout=45)
        return engine


@pytest.mark.skipif(not _e2e_enabled(), reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.skipif(not _CHROMIUM_OK, reason="Chromium 利用不可")
@pytest.mark.parametrize("variant", fx.VARIANTS, ids=[v.name for v in fx.VARIANTS])
def test_login_matrix_valid_credentials(base_url: str, variant: fx.LoginVariantSpec):
    """正しい認証情報でのログイン到達状態・証拠・カバレッジ検証。"""
    engine = asyncio.run(_run_matrix_scan(base_url, variant, fx.PASSWORD))
    browser = engine._browser
    assessment = getattr(browser, "last_login_assessment", None)

    # 1. BrowserManager.auto_login 結果
    assert browser.last_login_success is variant.expected_valid_auto_login

    # 2. last_login_assessment 状態 + 理由コード
    assert assessment is not None
    assert assessment.state == variant.expected_valid_state
    assert assessment.authenticated is variant.expected_valid_auto_login
    for reason in variant.expected_valid_reasons:
        assert reason in assessment.reasons

    # 3. engine authentication_state.protected_access
    auth_state = getattr(engine, "authentication_state", {})
    assert auth_state.get("protected_access") == variant.expected_valid_proof

    # 4. 短時間スキャンの認証カバレッジ報告（verified のときのみ計上）
    coverage = engine.coverage_summary()
    auth_cov = coverage.get("authentication", {})

    if variant.expected_valid_authenticated_coverage:
        assert auth_cov.get("protected_access") == "verified"
        assert auth_cov.get("state") == "success"
    else:
        assert auth_cov.get("protected_access") != "verified"
        assert auth_cov.get("state") != "success"


@pytest.mark.skipif(not _e2e_enabled(), reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.skipif(not _CHROMIUM_OK, reason="Chromium 利用不可")
@pytest.mark.parametrize("variant", fx.VARIANTS, ids=[v.name for v in fx.VARIANTS])
def test_login_matrix_wrong_credentials(base_url: str, variant: fx.LoginVariantSpec):
    """誤った認証情報での拒絶状態・非成功・認証カバレッジ非計上検証。"""
    engine = asyncio.run(_run_matrix_scan(base_url, variant, fx.WRONG_PASSWORD))
    browser = engine._browser
    assessment = getattr(browser, "last_login_assessment", None)

    # 1. auto_login は絶対に失敗すること
    assert browser.last_login_success is False

    # 2. 状態は SUCCESS でなく FAILURE / CHALLENGE / INCOMPLETE
    assert assessment is not None
    assert assessment.authenticated is False
    assert assessment.state in {ls.FAILURE, ls.CHALLENGE, ls.INCOMPLETE}

    # 3. engine authentication_state.protected_access は verified でないこと
    auth_state = getattr(engine, "authentication_state", {})
    assert auth_state.get("protected_access") != "verified"

    # 4. 認証カバレッジに計上されないこと
    coverage = engine.coverage_summary()
    auth_cov = coverage.get("authentication", {})

    assert auth_cov.get("protected_access") != "verified"
    assert auth_cov.get("state") != "success"


@pytest.mark.skipif(not _e2e_enabled(), reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.skipif(not _CHROMIUM_OK, reason="Chromium 利用不可")
def test_hidden_submit_button_in_modal_submits_via_request_submit(base_url: str):
    """閉じたモーダル内の非可視 submit ボタンを持つフォームでも requestSubmit で送達されることを実ブラウザで検証。"""
    async def _test():
        from wscan.browser import BrowserManager
        mgr = BrowserManager(headless=True, timeout=10)
        try:
            await mgr.init()
            login_url = f"{base_url}/v3/login"
            await mgr.navigate(login_url)
            # /v3/login では modal は display:none (非可視)
            # fill_and_submit_form を実行し、requestSubmit 経由でフォームが送信され delivered となることを検証
            source, pair = await mgr.fill_and_submit_form(0, "username", "probe_user")
            assert mgr.last_probe_delivered is True
            assert mgr.last_probe_delivery_reason == "delivered"
        finally:
            await mgr.close()

    asyncio.run(_test())
