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
        lambda url, proxy, verify, **kwargs: (200, "<html><form><input name='username'/></form></html>", None)
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
    assert checks_auth["authentication"]["status"] == "warning"
    assert checks_auth["authentication"]["reason_code"] == "login_not_verified"
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

    # 5. Session-only auth -> returns warning with session_not_verified (not pass)
    res_session = client.post("/api/v1/preflight", json={
        "url": "http://127.0.0.1:9",
        "cookie": "sid=xyz123",
    })
    assert res_session.status_code == 200
    checks_session = {c["id"]: c for c in res_session.json()["checks"]}
    assert checks_session["authentication"]["status"] == "warning"
    assert checks_session["authentication"]["reason_code"] == "session_not_verified"
    assert "not verified" in checks_session["authentication"]["detail"]


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


def test_prelaunch_summary_filter_and_sort_pure_mapping():
    """Verify filterAndSortNonPassChecks priority sorting and removal of pass checks."""
    script = f"""
    const {{ filterAndSortNonPassChecks }} = require('{SETUP_MODULE_JS}');

    const inputChecks = [
      {{ id: 'reachability', status: 'pass', detail: 'OK' }},
      {{ id: 'unknown_check', status: 'unknown', detail: '?' }},
      {{ id: 'playwright', status: 'fail', detail: 'PW missing' }},
      {{ id: 'authentication', status: 'warning', detail: 'session_not_verified' }},
      {{ id: 'websocket', status: 'not_checked', detail: 'live channel unverified' }},
      {{ id: 'oob', status: 'warning', detail: 'OOB not configured' }},
      {{ id: 'db_leak', status: 'fail', detail: 'Critical fail' }},
      {{ id: 'proxy_na', status: 'not_applicable', detail: 'N/A' }},
      {{ id: 'dns_pass', status: 'pass', detail: 'DNS resolved' }},
    ];

    const sorted = filterAndSortNonPassChecks(inputChecks);
    const emptyResult = filterAndSortNonPassChecks([]);
    const nullResult = filterAndSortNonPassChecks(null);
    const allPassResult = filterAndSortNonPassChecks([
      {{ id: 'c1', status: 'pass' }},
      {{ id: 'c2', status: 'pass' }},
    ]);

    console.log(JSON.stringify({{
      sorted,
      emptyResult,
      nullResult,
      allPassResult,
    }}));
    """
    res = _run_node(script)
    sorted_checks = res["sorted"]
    assert res["emptyResult"] == []
    assert res["nullResult"] == []
    assert res["allPassResult"] == []

    # 1. No 'pass' status is in sorted list
    assert not any(c["status"] == "pass" for c in sorted_checks)
    assert len(sorted_checks) == 7

    # 2. fail checks must come first, then warnings (including authentication), then others (including websocket)
    statuses = [c["status"] for c in sorted_checks]
    assert statuses[0] == "fail"
    assert statuses[1] == "fail"
    assert statuses[2] == "warning"
    assert statuses[3] == "warning"
    for s in statuses[4:]:
        assert s in ("unknown", "not_checked", "not_applicable", "unavailable")


def test_prelaunch_summary_state_transitions_and_invariants():
    """Verify computePrelaunchSummaryState across all states and the hard green invariant."""
    script = f"""
    const {{ computePrelaunchSummaryState }} = require('{SETUP_MODULE_JS}');

    const checksSample = [
      {{ id: 'playwright', status: 'fail', detail: 'PW missing' }},
      {{ id: 'reachability', status: 'pass', detail: 'OK' }},
    ];

    const states = {{
      never_run: computePrelaunchSummaryState({{ status: 'never_run' }}),
      running: computePrelaunchSummaryState({{ status: 'running', checks: checksSample }}),
      unavailable: computePrelaunchSummaryState({{ status: 'unavailable', errorMessage: 'connection refused' }}),
      completed_pass: computePrelaunchSummaryState({{
        status: 'completed',
        verdict: 'pass',
        checks: [{{ id: 'reachability', status: 'pass' }}],
        isStale: false,
      }}),
      completed_pass_stale: computePrelaunchSummaryState({{
        status: 'completed',
        verdict: 'pass',
        checks: [{{ id: 'reachability', status: 'pass' }}],
        isStale: true,
      }}),
      completed_warning: computePrelaunchSummaryState({{
        status: 'completed',
        verdict: 'warning',
        checks: [{{ id: 'auth', status: 'not_checked' }}],
        isStale: false,
      }}),
      completed_warning_stale: computePrelaunchSummaryState({{
        status: 'completed',
        verdict: 'warning',
        checks: [{{ id: 'auth', status: 'not_checked' }}],
        isStale: true,
      }}),
      completed_fail: computePrelaunchSummaryState({{
        status: 'completed',
        verdict: 'fail',
        checks: checksSample,
        isStale: false,
      }}),
      completed_unknown: computePrelaunchSummaryState({{
        status: 'completed',
        verdict: 'unexpected',
        checks: [],
        isStale: false,
      }}),
    }};

    console.log(JSON.stringify(states));
    """
    res = _run_node(script)

    # 1. Check never_run
    assert res["never_run"]["state"] == "never_run"
    assert res["never_run"]["isPass"] is False
    assert res["never_run"]["badgeLabel"] == "未確認"
    assert res["never_run"]["badgeClass"] == "setup-status-not-checked"
    assert "OK" not in res["never_run"]["badgeLabel"]

    # 2. Check running
    assert res["running"]["state"] == "running"
    assert res["running"]["isPass"] is False
    assert "確認中" in res["running"]["badgeLabel"]
    assert "pass" not in res["running"]["badgeClass"]

    # 3. Check unavailable
    assert res["unavailable"]["state"] == "unavailable"
    assert res["unavailable"]["isPass"] is False
    assert res["unavailable"]["badgeLabel"] == "利用不可"
    assert "connection refused" in res["unavailable"]["message"]
    assert "pass" not in res["unavailable"]["badgeClass"]

    # 4. Check completed pass (fresh)
    assert res["completed_pass"]["state"] == "pass"
    assert res["completed_pass"]["isPass"] is True
    assert res["completed_pass"]["badgeLabel"] == "準備OK"
    assert res["completed_pass"]["badgeClass"] == "setup-verdict-pass"
    assert len(res["completed_pass"]["nonPassChecks"]) == 0

    # 5. Check completed pass but STALE
    stale_pass = res["completed_pass_stale"]
    assert stale_pass["state"] == "stale"
    assert stale_pass["isPass"] is False
    assert stale_pass["isStale"] is True
    assert "設定変更あり" in stale_pass["badgeLabel"]
    assert "pass" not in stale_pass["badgeClass"]
    assert "OK" not in stale_pass["badgeLabel"]

    # 6. Check completed warning
    assert res["completed_warning"]["state"] == "warning"
    assert res["completed_warning"]["isPass"] is False
    assert res["completed_warning"]["badgeClass"] == "setup-verdict-warning"
    assert "pass" not in res["completed_warning"]["badgeClass"]
    assert len(res["completed_warning"]["nonPassChecks"]) == 1

    # 7. Check completed fail
    assert res["completed_fail"]["state"] == "fail"
    assert res["completed_fail"]["isPass"] is False
    assert res["completed_fail"]["badgeClass"] == "setup-verdict-fail"
    assert "pass" not in res["completed_fail"]["badgeClass"]
    assert len(res["completed_fail"]["nonPassChecks"]) == 1
    assert res["completed_fail"]["nonPassChecks"][0]["id"] == "playwright"

    # 8. Hard Invariant: ONLY completed_pass yields isPass === True and setup-verdict-pass
    non_passing_state_keys = [
        "never_run", "running", "unavailable",
        "completed_pass_stale", "completed_warning",
        "completed_warning_stale", "completed_fail", "completed_unknown"
    ]
    for key in non_passing_state_keys:
        st = res[key]
        assert st["isPass"] is False, f"{key} must have isPass === False"
        assert st["badgeClass"] != "setup-verdict-pass", f"{key} must not have setup-verdict-pass"
        assert "pass" not in st["badgeClass"] or "compass" in st["badgeClass"], f"{key} badgeClass must not contain 'pass'"
        assert st["badgeLabel"] != "準備OK", f"{key} badgeLabel must not be '準備OK'"


def test_prelaunch_summary_unrecognised_status_maps_to_unknown_state():
    """Verify an unrecognised status value maps to non-pass 'unknown' state and never passes."""
    script = f"""
    const {{ computePrelaunchSummaryState }} = require('{SETUP_MODULE_JS}');

    const unrecognisedStatuses = [
        'invalid_status',
        'foo_bar',
        'custom_status',
        'done',
        'succeeded',
        'aborted',
    ];

    const results = {{}};
    for (const st of unrecognisedStatuses) {{
      results[st] = computePrelaunchSummaryState({{
        status: st,
        verdict: 'pass', // even if verdict is pass, unrecognized status must not pass
        checks: [{{ id: 'test_check', status: 'pass' }}],
        isStale: false,
      }});
    }}

    console.log(JSON.stringify(results));
    """
    res = _run_node(script)
    for st, descriptor in res.items():
        assert descriptor["state"] == "unknown", f"{st} should map to state 'unknown'"
        assert descriptor["isPass"] is False, f"{st} isPass must be False"
        assert descriptor["isStale"] is False
        assert descriptor["badgeLabel"] == "不明"
        assert descriptor["badgeClass"] == "setup-verdict-unknown"
        assert "pass" not in descriptor["badgeClass"]
        assert "準備OK" not in descriptor["badgeLabel"]
        assert "OK" not in descriptor["badgeLabel"]


def test_is_config_stale_pure_function():
    """Verify isConfigStale compares payloads deterministically."""
    script = f"""
    const {{ isConfigStale }} = require('{SETUP_MODULE_JS}');

    const base = {{ url: 'https://example.com', depth: 2, checks: ['sqli', 'xss'] }};
    const identical = {{ url: 'https://example.com', depth: 2, checks: ['sqli', 'xss'] }};
    const changedUrl = {{ url: 'https://example.org', depth: 2, checks: ['sqli', 'xss'] }};
    const changedDepth = {{ url: 'https://example.com', depth: 3, checks: ['sqli', 'xss'] }};
    const changedChecks = {{ url: 'https://example.com', depth: 2, checks: ['sqli'] }};

    console.log(JSON.stringify({{
      identicalStale: isConfigStale(base, identical),
      changedUrlStale: isConfigStale(base, changedUrl),
      changedDepthStale: isConfigStale(base, changedDepth),
      changedChecksStale: isConfigStale(base, changedChecks),
      nullLastStale: isConfigStale(null, base),
      nullCurrentStale: isConfigStale(base, null),
    }}));
    """
    res = _run_node(script)
    assert res["identicalStale"] is False
    assert res["changedUrlStale"] is True
    assert res["changedDepthStale"] is True
    assert res["changedChecksStale"] is True
    assert res["nullLastStale"] is False
    assert res["nullCurrentStale"] is False


def test_render_setup_view_recomputes_staleness_on_preflight_success():
    """Verify that when runPreflight succeeds, staleness is recomputed against current config.

    If config changed while the check was running, the result must be marked stale (non-pass).
    """
    script = f"""
    const {{ renderSetupView }} = require('{SETUP_MODULE_JS}');

    const elementRegistry = {{}};
    function makeElement(tag) {{
      const children = [];
      const attrs = {{}};
      const listeners = {{}};
      let _id = '';
      const el = {{
        tagName: tag,
        children: children,
        hidden: false,
        className: '',
        value: '',
        dataset: {{}},
        style: {{}},
        get id() {{ return _id; }},
        set id(v) {{
          _id = String(v);
          elementRegistry[_id] = el;
        }},
        setAttribute(k, v) {{
          attrs[k] = String(v);
          if (k === 'id') {{
            _id = String(v);
            elementRegistry[v] = el;
          }}
        }},
        getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
        removeAttribute(k) {{ delete attrs[k]; }},
        appendChild(c) {{ children.push(c); }},
        removeChild(c) {{
          const idx = children.indexOf(c);
          if (idx !== -1) children.splice(idx, 1);
        }},
        replaceChildren(...c) {{ children.length = 0; children.push(...c); }},
        addEventListener(evt, fn) {{
          listeners[evt] = listeners[evt] || [];
          listeners[evt].push(fn);
        }},
        dispatch(evt, data) {{
          (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
        }},
        focus() {{ this._focused = true; }},
        classList: {{
          _classes: new Set(),
          add(c) {{ this._classes.add(c); }},
          remove(c) {{ this._classes.delete(c); }},
          toggle(c, force) {{
            if (force === undefined) force = !this._classes.has(c);
            if (force) this._classes.add(c);
            else this._classes.delete(c);
          }},
          contains(c) {{ return this._classes.has(c); }},
        }},
        querySelector() {{ return null; }},
        querySelectorAll() {{ return []; }},
      }};
      return el;
    }}

    const mockDoc = {{
      createElement: makeElement,
      getElementById: (id) => elementRegistry[id] || null,
      querySelector: () => null,
      querySelectorAll: () => [],
    }};

    const container = makeElement('div');
    const schema = {{
      defaults: {{ url: 'https://example.com', depth: 2, checks: ['sqli'] }},
      schema: {{
        type: 'object',
        properties: {{
          url: {{ type: 'string', title: 'Target URL' }},
          depth: {{ type: 'integer', title: 'Crawl Depth' }},
        }},
      }},
    }};

    let resolveFetch;
    const fetchPromise = new Promise((resolve) => {{
      resolveFetch = resolve;
    }});

    const instance = renderSetupView(container, schema, {{
      document: mockDoc,
      fetchPreflight: async (payload) => {{
        return fetchPromise;
      }},
    }});

    // Set initial URL
    const urlInput = elementRegistry['cfgInputUrl'];
    urlInput.value = 'https://example.com';

    // Trigger preflight run
    const runPromise = instance.runPreflight();

    // While preflight is running, user changes the URL input in the form
    urlInput.value = 'https://changed-during-run.com';

    // Preflight check finishes successfully
    resolveFetch({{
      schema_version: '1.0.0',
      verdict: 'pass',
      checks: [{{ id: 'reachability_direct', status: 'pass' }}],
    }});

    runPromise.then(() => {{
      const state = instance.getPrelaunchState();
      console.log(JSON.stringify(state));
    }});
    """
    res = _run_node(script)
    assert res["state"] == "stale"
    assert res["isStale"] is True
    assert res["isPass"] is False
    assert "設定変更あり" in res["badgeLabel"]
    assert "setup-status-warning" in res["badgeClass"]
    assert "setup-verdict-pass" not in res["badgeClass"]
    assert "準備OK" not in res["badgeLabel"]


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


def test_setup_prelaunch_summary_ui(ui_harness):
    """Verify Setup pre-launch summary consumes readiness preflight, staleness, and advisory launch."""
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
                "status": "warning",
                "reason_code": "session_not_verified",
                "detail": "Session cookie specified but not verified.",
            },
            {
                "id": "websocket",
                "status": "not_checked",
                "reason_code": "unverified",
                "detail": "Live channel readiness unverified.",
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

    page.route(
        "**/api/v1/preflight",
        lambda route: route.fulfill(
            status=200,
            content_type="application/json",
            body=json.dumps(stubbed_response),
        ),
    )

    page.goto(f"{ui_harness.server_url}/app#/setup")
    page.wait_for_selector("#setupSurface:not([hidden])")
    page.wait_for_selector("#setupPrelaunchSummary")

    # 1. Initial State: never run -> not_checked
    verdict_badge = page.locator("#setupPrelaunchVerdictBadge")
    assert verdict_badge.inner_text() == "未確認"
    badge_classes = verdict_badge.get_attribute("class") or ""
    assert "setup-status-not-checked" in badge_classes
    assert "setup-verdict-pass" not in badge_classes
    assert "OK" not in verdict_badge.inner_text()

    rerun_btn = page.locator("#setupPrelaunchRerunBtn")
    assert "準備チェック実行" in rerun_btn.inner_text()

    checks_list = page.locator("#setupPrelaunchChecksList")
    assert "まだ実行されていません" in checks_list.inner_text()

    # 2. Run readiness via pre-launch summary button
    url_input = page.locator("#cfgInputUrl")
    url_input.fill("https://example.com/target")

    rerun_btn.click()
    page.wait_for_selector(".setup-prelaunch-check-item")

    # Verdict badge updates to warning (amber / non-pass)
    verdict_text = verdict_badge.inner_text()
    verdict_cls = verdict_badge.get_attribute("class") or ""
    assert "注意 (一部未確認/警告)" in verdict_text
    assert "準備OK" not in verdict_text
    assert "setup-verdict-warning" in verdict_cls
    assert "setup-verdict-pass" not in verdict_cls

    # Compact list of non-pass checks: fail first, then warning, then not_checked; pass is excluded
    items = page.locator(".setup-prelaunch-check-item")
    assert items.count() == 3

    # First check: playwright (fail)
    item0 = items.nth(0)
    assert item0.get_attribute("data-check-id") == "playwright"
    chip0 = item0.locator(".setup-prelaunch-check-chip")
    assert "失敗" in chip0.inner_text()
    assert "setup-status-fail" in (chip0.get_attribute("class") or "")
    assert "setup-status-pass" not in (chip0.get_attribute("class") or "")

    # Second check: authentication (warning - must stay non-pass)
    item1 = items.nth(1)
    assert item1.get_attribute("data-check-id") == "authentication"
    chip1 = item1.locator(".setup-prelaunch-check-chip")
    assert "警告" in chip1.inner_text()
    assert "setup-status-warning" in (chip1.get_attribute("class") or "")
    assert "setup-status-pass" not in (chip1.get_attribute("class") or "")
    assert "OK" not in chip1.inner_text()

    # Third check: websocket (not_checked)
    item2 = items.nth(2)
    assert item2.get_attribute("data-check-id") == "websocket"
    chip2 = item2.locator(".setup-prelaunch-check-chip")
    assert "未確認" in chip2.inner_text()
    assert "setup-status-not-checked" in (chip2.get_attribute("class") or "")
    assert "setup-status-pass" not in (chip2.get_attribute("class") or "")
    assert "OK" not in chip2.inner_text()

    # Pass check 'reachability_direct' must NOT appear in non-pass checks
    summary_html = page.locator("#setupPrelaunchSummary").inner_html()
    assert "reachability_direct" not in summary_html

    # 3. Staleness: modifying setup config marks summary as stale (non-pass)
    depth_input = page.locator("#cfgDepth")
    depth_input.fill("5")

    page.wait_for_function(
        "() => document.getElementById('setupPrelaunchVerdictBadge').textContent.includes('設定変更あり')"
    )
    stale_text = verdict_badge.inner_text()
    stale_cls = verdict_badge.get_attribute("class") or ""
    assert "設定変更あり" in stale_text
    assert "準備OK" not in stale_text
    assert "setup-status-warning" in stale_cls
    assert "setup-verdict-pass" not in stale_cls

    assert "最新設定で再チェック" in rerun_btn.inner_text()

    # 4. Advisory launch: clicking scan start is NOT blocked by non-pass readiness
    start_btn = page.locator("#setupStartScanBtn")
    start_btn.click()
    page.wait_for_function("() => window.location.hash === '#/monitor'")
    assert page.url.endswith("#/monitor")

    # 5. Unavailable state fallback
    page.goto(f"{ui_harness.server_url}/app#/setup")
    page.wait_for_selector("#setupPrelaunchSummary")

    page.unroute("**/api/v1/preflight")
    page.route(
        "**/api/v1/preflight",
        lambda route: route.fulfill(
            status=500,
            content_type="application/json",
            body=json.dumps({"error": "Preflight endpoint unavailable"}),
        ),
    )

    page.locator("#cfgInputUrl").fill("https://example.com/target")
    page.locator("#setupPrelaunchRerunBtn").click()

    page.wait_for_function(
        "() => document.getElementById('setupPrelaunchVerdictBadge').textContent.includes('利用不可')"
    )
    unavail_badge = page.locator("#setupPrelaunchVerdictBadge")
    assert "利用不可" in unavail_badge.inner_text()
    assert "setup-status-fail" in (unavail_badge.get_attribute("class") or "")
    assert "setup-verdict-pass" not in (unavail_badge.get_attribute("class") or "")
    assert "準備OK" not in unavail_badge.inner_text()
