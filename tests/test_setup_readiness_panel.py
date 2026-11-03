"""Tests for on-demand scan-readiness ("preflight") panel and API.

Verifies:
1. API test: POST /api/v1/preflight with minimal config returns 200 with verdict and checks;
   missing or empty url returns HTTP 400.
2. Pure-function mapping test for preflightStatusLabel and preflightVerdictLabel:
   - pass -> green ✓ "OK"
   - warning -> amber "警告"
   - fail -> red ✗ "失敗"
   - not_checked -> neutral "未確認"
   - not_applicable -> neutral "非該当"
   - unknown -> neutral "不明"
   Hard correctness invariant: ONLY 'pass' yields the pass/green styling.
3. UI harness test (Playwright, browser-gated):
   - Drive Setup readiness panel with stubbed response containing not_checked, fail, and verdict warning.
   - Assert rendered DOM shows NO pass/green styling or OK label for not_checked and fail rows.
   - Assert verdict is amber/warning (never pass).
   - Assert unavailable/error response displays explicit unavailable text without pass/green styling.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

from fastapi.testclient import TestClient
import pytest

from tests.ui_harness import ui_harness
from wscan.monitor import MonitorServer

ROOT = Path(__file__).resolve().parents[1]
SETUP_MODULE_JS = ROOT / "templates" / "ui" / "setup-module.js"


def _run_node(script: str) -> dict:
    """Run JS script passed via stdin to Node.js and return parsed JSON."""
    proc = subprocess.run(
        ["node", "-"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    return json.loads(proc.stdout)


# ─── 1. API Test ─────────────────────────────────────────────────────────────

def test_preflight_api_minimal_and_missing_url(tmp_path):
    """POST /api/v1/preflight returns 200 with verdict/checks; missing url returns 400."""
    server = MonitorServer()
    client = TestClient(server.app)

    # Missing url in body -> 400
    res_empty = client.post("/api/v1/preflight", json={})
    assert res_empty.status_code == 400
    assert "url" in res_empty.json().get("error", "").lower()

    # Empty string url -> 400
    res_blank = client.post("/api/v1/preflight", json={"url": "   "})
    assert res_blank.status_code == 400
    assert "url" in res_blank.json().get("error", "").lower()

    # Empty url inside config dict -> 400
    res_nested = client.post("/api/v1/preflight", json={"config": {"url": ""}})
    assert res_nested.status_code == 400
    assert "url" in res_nested.json().get("error", "").lower()

    # Non-object body -> 400
    res_list = client.post("/api/v1/preflight", json=["invalid"])
    assert res_list.status_code == 400

    # Minimal valid url -> 200 with verdict and checks shape
    res_valid = client.post("/api/v1/preflight", json={"url": "http://127.0.0.1:9"})
    assert res_valid.status_code == 200
    data = res_valid.json()
    assert "verdict" in data
    assert "checks" in data
    assert isinstance(data["checks"], list)
    assert isinstance(data["verdict"], str)
    assert data["verdict"] in ("pass", "warning", "fail")


def test_preflight_api_auth_and_live_channel_checks(monkeypatch):
    """POST /api/v1/preflight verifies authentication and live channel readiness without leaking secrets."""
    server = MonitorServer()
    client = TestClient(server.app)

    # 1. No auth configured -> authentication is not_applicable, websocket is pass
    res_no_auth = client.post("/api/v1/preflight", json={"url": "http://127.0.0.1:9"})
    assert res_no_auth.status_code == 200
    checks_no_auth = {c["id"]: c for c in res_no_auth.json()["checks"]}
    assert checks_no_auth["authentication"]["status"] == "not_applicable"
    assert checks_no_auth["authentication"]["reason_code"] == "auth_not_configured"
    assert checks_no_auth["websocket"]["status"] == "pass"
    assert checks_no_auth["websocket"]["reason_code"] == "available"

    # 2. Disabled live channel via no_monitor -> websocket is not_applicable
    res_no_mon = client.post("/api/v1/preflight", json={"url": "http://127.0.0.1:9", "no_monitor": True})
    assert res_no_mon.status_code == 200
    checks_no_mon = {c["id"]: c for c in res_no_mon.json()["checks"]}
    assert checks_no_mon["websocket"]["status"] == "not_applicable"
    assert checks_no_mon["websocket"]["reason_code"] == "monitor_disabled"

    # 3. Valid auth configuration with reachability probe mock and secret sentinel
    sentinel = "TOP_SECRET_AUTH_PASSWORD_SENTINEL_654"
    monkeypatch.setattr(
        "wscan.preflight._probe_login_page",
        lambda url, proxy, verify: (200, "<html><form><input name='username'/></form></html>", None)
    )

    res_auth = client.post("/api/v1/preflight", json={
        "url": "http://127.0.0.1:9",
        "login_url": "http://127.0.0.1:9/login",
        "auth_user": "admin",
        "auth_pass": sentinel,
        "accounts": [{"username": "admin", "password": sentinel}],
    })
    assert res_auth.status_code == 200
    data_auth = res_auth.json()
    checks_auth = {c["id"]: c for c in data_auth["checks"]}
    assert checks_auth["authentication"]["status"] == "pass"
    assert checks_auth["authentication"]["reason_code"] == "configured"
    assert "Preflight does not verify credentials or login success" in checks_auth["authentication"]["detail"]
    # Secret sentinel must not leak
    assert sentinel not in json.dumps(data_auth)

    # 4. Out-of-scope login_url -> fails preflight
    res_out_of_scope = client.post("/api/v1/preflight", json={
        "url": "http://127.0.0.1:9",
        "login_url": "https://attacker-controlled.example/login",
        "auth_user": "admin",
        "auth_pass": "pass",
    })
    assert res_out_of_scope.status_code == 200
    data_out = res_out_of_scope.json()
    checks_out = {c["id"]: c for c in data_out["checks"]}
    assert checks_out["authentication"]["status"] == "fail"
    assert checks_out["authentication"]["reason_code"] == "login_url_out_of_scope"
    assert data_out["verdict"] == "fail"


# ─── 2. Pure-Function Status & Verdict Label Mapping Test ────────────────────

def test_preflight_status_label_pure_mapping():
    """Verify preflightStatusLabel and preflightVerdictLabel mappings and hard green invariant."""
    script = f"""
    const {{ preflightStatusLabel, preflightVerdictLabel }} = require('{SETUP_MODULE_JS}');

    const statuses = [
      'pass',
      'warning',
      'fail',
      'not_checked',
      'not_applicable',
      'unknown',
      'other_random_value',
      null,
      undefined
    ];

    const mappedStatuses = {{}};
    for (const s of statuses) {{
      mappedStatuses[String(s)] = preflightStatusLabel(s);
    }}

    const verdicts = ['pass', 'warning', 'fail', 'unknown', 'custom'];
    const mappedVerdicts = {{}};
    for (const v of verdicts) {{
      mappedVerdicts[v] = preflightVerdictLabel(v);
    }}

    console.log(JSON.stringify({{
      mappedStatuses,
      mappedVerdicts,
    }}));
    """
    res = _run_node(script)
    statuses = res["mappedStatuses"]
    verdicts = res["mappedVerdicts"]

    # 1. Check exact expected labels
    assert "OK" in statuses["pass"]["label"]
    assert statuses["pass"]["label"] == "✓ OK"
    assert statuses["warning"]["label"] == "警告"
    assert "失敗" in statuses["fail"]["label"]
    assert statuses["fail"]["label"] == "✗ 失敗"
    assert statuses["not_checked"]["label"] == "未確認"
    assert statuses["not_applicable"]["label"] == "非該当"
    assert statuses["unknown"]["label"] == "不明"
    assert statuses["other_random_value"]["label"] == "不明"

    # 2. Check CSS classes
    pass_class = statuses["pass"]["cssClass"]
    assert pass_class == "setup-status-pass"
    assert statuses["warning"]["cssClass"] == "setup-status-warning"
    assert statuses["fail"]["cssClass"] == "setup-status-fail"
    assert statuses["not_checked"]["cssClass"] == "setup-status-not-checked"
    assert statuses["not_applicable"]["cssClass"] == "setup-status-not-applicable"
    assert statuses["unknown"]["cssClass"] == "setup-status-unknown"

    # 3. Hard invariant: ONLY 'pass' yields the pass/green class or OK label
    non_passing_keys = [
        "warning", "fail", "not_checked", "not_applicable",
        "unknown", "other_random_value", "null", "undefined"
    ]
    for key in non_passing_keys:
        st = statuses[key]
        assert st["cssClass"] != pass_class, f"{key} must not share pass class"
        assert "pass" not in st["cssClass"], f"{key} cssClass must not contain 'pass'"
        assert "OK" not in st["label"], f"{key} label must not contain 'OK'"
        assert "準備OK" not in st["label"], f"{key} label must not contain '準備OK'"

    # 4. Check verdicts
    assert verdicts["pass"]["label"] == "準備OK"
    assert verdicts["pass"]["cssClass"] == "setup-verdict-pass"
    assert verdicts["warning"]["label"] == "注意 (一部未確認/警告)"
    assert verdicts["warning"]["cssClass"] == "setup-verdict-warning"
    assert verdicts["fail"]["label"] == "失敗"
    assert verdicts["fail"]["cssClass"] == "setup-verdict-fail"

    # Amber warning verdict must be distinct from green pass verdict
    assert verdicts["warning"]["cssClass"] != verdicts["pass"]["cssClass"]
    assert "pass" not in verdicts["warning"]["cssClass"]
    assert verdicts["warning"]["label"] != verdicts["pass"]["label"]


# ─── 3. UI Harness Test (Playwright) ─────────────────────────────────────────

def test_setup_readiness_panel_ui(ui_harness):
    """Drive Setup readiness panel with stubbed non-pass response and verify DOM rendering."""
    pytest.importorskip("playwright")
    from tests.ui_harness import require_browser, STANDARD_VIEWPORTS

    require_browser()
    vp = STANDARD_VIEWPORTS[1440]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    stubbed_response = {
        "schema_version": "1.0.0",
        "verdict": "warning",
        "checks": [
            {
                "id": "authentication",
                "status": "not_checked",
                "reason_code": "not_implemented",
                "detail": "Authentication readiness is not checked in this increment.",
            },
            {
                "id": "playwright",
                "status": "fail",
                "reason_code": "dependency_missing",
                "detail": "Playwright Chromium is unavailable.",
            },
            {
                "id": "reachability_direct",
                "status": "pass",
                "reason_code": "reachable",
                "detail": "HTTP GET returned status 200.",
            },
        ],
    }

    # Intercept /api/v1/preflight to return deterministic payload
    def handle_preflight(route):
        route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(stubbed_response),
        )

    page.route("**/api/v1/preflight", handle_preflight)

    page.goto(f"{ui_harness.server_url}/app#/setup")
    page.wait_for_selector("#setupSurface:not([hidden])")
    page.wait_for_selector("#setupReadinessSection")

    # 1. Fill URL
    url_input = page.locator("#cfgInputUrl")
    url_input.fill("https://example.com/target")

    # 2. Click run readiness button
    page.click("#setupRunPreflightBtn")

    # 3. Wait for verdict bar and check rows
    page.wait_for_selector("#setupReadinessVerdictBadge")
    page.wait_for_selector(".setup-readiness-check-item")

    verdict_badge = page.locator("#setupReadinessVerdictBadge")
    verdict_text = verdict_badge.inner_text()
    verdict_classes = verdict_badge.get_attribute("class") or ""

    # Verdict must be warning (amber/partial state), NEVER pass or 準備OK
    assert "注意 (一部未確認/警告)" in verdict_text
    assert "準備OK" not in verdict_text
    assert "setup-verdict-warning" in verdict_classes
    assert "setup-verdict-pass" not in verdict_classes

    # 4. Check rows: not_checked row
    auth_row = page.locator('.setup-readiness-check-item[data-check-id="authentication"]')
    auth_chip = auth_row.locator(".setup-readiness-status-chip")
    auth_chip_text = auth_chip.inner_text()
    auth_chip_classes = auth_chip.get_attribute("class") or ""

    assert "未確認" in auth_chip_text
    assert "OK" not in auth_chip_text
    assert "setup-status-not-checked" in auth_chip_classes
    assert "setup-status-pass" not in auth_chip_classes

    # 5. Check rows: fail row
    playwright_row = page.locator('.setup-readiness-check-item[data-check-id="playwright"]')
    pw_chip = playwright_row.locator(".setup-readiness-status-chip")
    pw_chip_text = pw_chip.inner_text()
    pw_chip_classes = pw_chip.get_attribute("class") or ""

    assert "失敗" in pw_chip_text
    assert "OK" not in pw_chip_text
    assert "setup-status-fail" in pw_chip_classes
    assert "setup-status-pass" not in pw_chip_classes

    # 6. Check rows: pass row
    reach_row = page.locator('.setup-readiness-check-item[data-check-id="reachability_direct"]')
    reach_chip = reach_row.locator(".setup-readiness-status-chip")
    reach_chip_text = reach_chip.inner_text()
    reach_chip_classes = reach_chip.get_attribute("class") or ""

    assert "OK" in reach_chip_text
    assert "setup-status-pass" in reach_chip_classes

    # Verify no console or uncaught exceptions during happy path
    ui_harness.assert_no_errors(page)

    # 7. Test unavailable / error state fallback
    def handle_preflight_error(route):
        route.fulfill(
            status=500,
            content_type="application/json",
            body=json.dumps({"error": "Preflight check failed: internal error"}),
        )

    page.unroute("**/api/v1/preflight")
    page.route("**/api/v1/preflight", handle_preflight_error)

    # Click run preflight again
    page.click("#setupRunPreflightBtn")
    page.wait_for_selector("#setupReadinessUnavailable")

    unavail = page.locator("#setupReadinessUnavailable")
    unavail_text = unavail.inner_text()
    assert "readiness を取得できませんでした (利用不可)" in unavail_text

    # Under unavailable/error response, NO pass/green or OK label may appear
    content_html = page.locator("#setupReadinessContent").inner_html()
    assert "setup-status-pass" not in content_html
    assert "setup-verdict-pass" not in content_html
    assert "準備OK" not in content_html

    # Ensure only the expected HTTP 500 network error was logged, no uncaught JS pageerror
    errors = ui_harness.get_errors(page)
    assert all("Failed to load resource" in err or "500" in err for err in errors)
    assert not any("pageerror" in err for err in errors)
