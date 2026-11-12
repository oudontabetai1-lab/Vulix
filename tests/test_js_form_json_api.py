"""JS 制御フォーム（fetch JSON 送信）の検出・JSON 注入点登録のテスト。

SPA ログイン等で submit が ``preventDefault`` され、ページ内 JS が同一オリジンの
JSON API へ fetch するフォームではネイティブ送達相関が常に失敗する。このテストは:

1. 純粋関数 :mod:`wscan.js_form_detect` の判定・値無害化（ユニット）
2. ループバックフィクスチャ（v8 脆弱＋安全ツイン）での実ブラウザ E2E
   - ``transport_error:...:probe_not_delivered`` ノイズが 1 form×check 1 件の
     ``js_handled_form`` note に置き換わること
   - フォームの呼び出し先 JSON エンドポイントが注入点として登録され、SQLi が
     検出されること（安全ツインは非検出）
   - 観測 template / 監査ログに実認証情報が残らないこと

E2E は ``WSCAN_E2E=1`` かつ Chromium が利用できるときだけ実行する。
"""
from __future__ import annotations

import asyncio
from contextlib import contextmanager
import json
import os
import socket
import tempfile
import threading
import time
from typing import Generator

import pytest
import uvicorn

from tests.fixtures import login_matrix_app as fx
from wscan import js_form_detect
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


# =============================================================================
# 1. 純粋関数のユニットテスト（WSCAN_E2E 未設定でも実行）
# =============================================================================

def _fetch_request(body: dict, *, url: str = "https://app.test/v4/api/login",
                   resource_type: str = "fetch") -> dict:
    """v4 形態と同じ fetch 送信の観測 request dict を作る。"""
    return {
        "url": url,
        "method": "POST",
        "resource_type": resource_type,
        "headers": {"Content-Type": "application/json"},
        "post_data": json.dumps(body),
    }


def test_detector_matches_fetch_json_body():
    """fetch/xhr＋同origin＋フィールド名を運ぶ JSON body でテンプレートを返す。"""
    req = _fetch_request({"username": "probe", "password": "safe"})
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is not None
    assert target["method"] == "POST"
    assert target["url"] == "https://app.test/v4/api/login"
    assert target["endpoint"] == "https://app.test/v4/api/login"
    assert target["json_body"] == {"username": "probe", "password": "safe"}
    assert target["content_type"] == "application/json"
    assert set(target["field_names"]) == {"username", "password"}


def test_detector_accepts_inflight_pending_request():
    """probe 返却時に応答未着の pending request も根拠になる。"""
    req = _fetch_request({"username": "probe", "password": "safe"})
    # pending は pairs に載らないため完了フィールド無しで渡す呼び出し形を想定
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is not None


def test_detector_rejects_document_navigation():
    """window 内に document（ナビゲーション）があれば submit は遷移済み＝非 JS 制御。"""
    req = _fetch_request({"username": "probe", "password": "safe"})
    nav = {"url": "https://app.test/v4/login", "method": "GET",
           "resource_type": "document", "headers": {}, "post_data": None}
    target = js_form_detect.js_form_json_target(
        [req, nav], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is None


def test_detector_rejects_redacted_post_data():
    """認証フロー由来の赤字化済み request（post_data="[REDACTED]"）は除外する。

    赤字化済みログイン POST を実認証情報のまま再生しないための境界。
    """
    req = {"url": "https://app.test/v4/api/login", "method": "POST",
           "resource_type": "fetch", "headers": {},
           "post_data": "[REDACTED]"}
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is None


def test_detector_rejects_cross_origin():
    """同一オリジンでない fetch はフォームの送信先として扱わない。"""
    req = _fetch_request({"username": "probe", "password": "safe"},
                         url="https://evil.example/api/login")
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is None


def test_detector_rejects_missing_field_names():
    """フォームのフィールド名を運ばない JSON body はフォーム送信と判定しない。"""
    req = _fetch_request({"other": "x"})
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is None


def test_detector_rejects_target_field_missing():
    """注入対象フィールド自身が body に無い request は採用しない。"""
    req = _fetch_request({"password": "safe"})
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is None


def test_detector_rejects_get_navigation_shape():
    """GET（送信でない）request は対象外。"""
    req = {"url": "https://app.test/v4/api/login", "method": "GET",
           "resource_type": "fetch", "headers": {}, "post_data": None}
    target = js_form_detect.js_form_json_target(
        [req], "https://app.test/v4/login", ["username", "password"], "username")
    assert target is None


def test_sanitize_replaces_exact_credential_and_payload_values():
    """認証情報・現在 payload と完全一致する文字列値のみ空文字へ置換する。"""
    secrets = ("fixture-user@example.test", "fixture-password", "' OR 1=1--")
    body = {
        "username": "' OR 1=1--",
        "password": "fixture-password",
        "email": "fixture-user@example.test",
        "note": "contains fixture-password inside",
        "nested": {"deep": ["fixture-password", "keep"]},
        "count": 3,
    }
    cleaned = js_form_detect.sanitize_credential_values(body, secrets)
    assert cleaned == {
        "username": "",
        "password": "",
        "email": "",
        "note": "contains fixture-password inside",  # 部分一致は置換しない
        "nested": {"deep": ["", "keep"]},
        "count": 3,
    }
    # 元オブジェクトを壊さない（純粋関数）
    assert body["username"] == "' OR 1=1--"


# =============================================================================
# 2. 実ブラウザ E2E（WSCAN_E2E=1 のみ実行）
# =============================================================================

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
                raise RuntimeError("js-form fixture server did not start")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        sock.close()


async def _run_v8_scan(base: str, login_path: str, tmp_dir: str) -> ScanEngine:
    """JS 制御ログインフォームをターゲットにした短時間スキャン（no-LLM）。

    target_url をログインページ自身にする（origin scope で login_url が攻撃対象に
    なり pre-auth ログインフォーム検査が走る）。
    """
    engine = ScanEngine(
        f"{base}{login_path}",
        login_url=f"{base}{login_path}",
        auth_user=fx.USERNAME,
        auth_pass=fx.PASSWORD,
        checks=["sqli", "xss"],
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
        max_payloads=4,
        request_delay=0,
        use_planner=False,
        sarif=False,
        timeout=8,
        navigation_retries=0,
    )
    await asyncio.wait_for(engine.run(), timeout=150)
    return engine


def _jsonl_text(tmp_dir: str) -> str:
    """出力ディレクトリ配下の監査 JSONL（http_requests/payloads/probe_attempts）を連結する。"""
    parts = []
    for root, _dirs, files in os.walk(tmp_dir):
        for name in files:
            if name.endswith(".jsonl"):
                with open(os.path.join(root, name), "r", encoding="utf-8", errors="replace") as fh:
                    parts.append(fh.read())
    return "\n".join(parts)


def _template_body_of(engine: ScanEngine, needle: str) -> dict:
    """needle（endpoint 部分一致）のテンプレート body を返す（無ければ AssertionError）。"""
    for template in (engine.injection_templates or {}).values():
        if needle in str(template.get("endpoint", "")):
            return template.get("json_body") or {}
    raise AssertionError(f"template for {needle} not registered")


_V8_CASES = [
    ("vulnerable", "/v8/login"),
    ("safe", "/v8/safe/login"),
]


@pytest.mark.skipif(not _e2e_enabled(), reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.skipif(not _CHROMIUM_OK, reason="Chromium 利用不可")
@pytest.mark.parametrize("case,login_path", _V8_CASES)
def test_v8_js_form_scan(case: str, login_path: str):
    """JS 制御フォームのノイズ抑止・JSON 注入点登録・脆弱/安全判定を検証。"""
    app = fx.create_app()
    with serving(app) as base, tempfile.TemporaryDirectory() as tmp_dir:
        engine = asyncio.run(_run_v8_scan(base, login_path, tmp_dir))
        is_vulnerable = case == "vulnerable"
        endpoint = f"/v8/api/login" if is_vulnerable else "/v8/api/safe-login"
        page_path = login_path

        # 1. ノイズ抑止: transport_error:...:probe_not_delivered は 0 件。
        notes = list(getattr(engine, "wave_errors", []) or [])
        assert not [n for n in notes if "probe_not_delivered" in n], notes

        # 2. 1 form×check 1 件の js_handled_form note（sqli+xss の 2 件）。
        js_notes = [n for n in notes if n.startswith("js_handled_form:")]
        assert sorted(n.split(":")[1] for n in js_notes) == ["sqli", "xss"], notes
        for note in js_notes:
            assert note.endswith(f":{page_path}"), (note, page_path)

        # 3. フォームの呼び出し先 JSON エンドポイントが注入点登録されている。
        endpoints = {getattr(ip, "url", "") for ip in engine.json_injection_points}
        assert any(e.endswith(endpoint) for e in endpoints), endpoints
        pointers = sorted(
            getattr(ip, "parameter_id", "") for ip in engine.json_injection_points
            if getattr(ip, "url", "").endswith(endpoint))
        assert pointers == ["/password", "/username"], pointers

        # 4. 観測 template に実認証情報・投入値を残さない。
        body = _template_body_of(engine, endpoint)
        serialized = json.dumps(body)
        assert fx.USERNAME not in serialized
        assert fx.PASSWORD not in serialized
        assert "baseline_test" not in serialized

        # 5. 脆弱側は SQLi 検出、安全側は非検出。
        findings = list(getattr(engine, "all_findings", []) or [])
        on_endpoint = [f for f in findings if endpoint in str(getattr(f, "url", ""))]
        if is_vulnerable:
            sqli_hits = [f for f in on_endpoint if getattr(f, "check_type", "") == "sqli"]
            assert sqli_hits, [str(f.url) for f in findings]
            # username ポインタの検出（兄弟 password ポインタへの payload 由来誤検知でない）
            ptrs = {str(getattr(f, "injection_pointer", "") or "") for f in sqli_hits}
            assert "/username" in ptrs, ptrs
            assert "/password" not in ptrs, ptrs
            # JSON 応答は HTML でないため XSS 検出はしない
            assert not [f for f in on_endpoint if getattr(f, "check_type", "") == "xss"], \
                [str(f.url) for f in on_endpoint]
        else:
            assert not on_endpoint, [str(f.url) for f in on_endpoint]

        # 6. 監査ログ（http_requests.jsonl / payloads.jsonl 等）に実認証情報を残さない。
        logs = _jsonl_text(tmp_dir)
        assert fx.PASSWORD not in logs
        assert fx.USERNAME not in logs
