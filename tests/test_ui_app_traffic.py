"""Tests for /app Traffic view, pure JS helpers, action capability gating,
and browser UI interactions via ui_harness.

Verifies:
1. Pure function tests (via Node):
   - Action resolution gates replay, mutation, and proxy as disabled with 'not available in this version'.
   - Action resolution enables open_in_browser when URL is valid and declared available.
   - Cross-link building to Crawl and Findings.
   - Display redaction helpers mask secrets and userinfo.
   - Traffic filtering and count summary calculations.
2. Browser UI interaction tests (via ui_harness; skips cleanly without Chromium):
   - Traffic view mounts and sets active rail button.
   - Entries from http_requests.jsonl are listed in the table.
   - Selecting a row opens detail panel with redacted metadata and parsed input points.
   - Action buttons for replay, mutate, proxy are visibly disabled with 'not available in this version'.
   - Open-in-browser is enabled with valid URL.
   - Honest status: absent log displays explicit unavailable state with reason (never fake empty success).
   - Sentinel secret non-leak: dummy secret in log does NOT appear in rendered DOM text, URL hash, or storage.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import pytest

from tests.ui_harness import (
    UIHarness,
    require_browser,
    STANDARD_VIEWPORTS,
    ui_harness,
)

ROOT = Path(__file__).resolve().parents[1]
TRAFFIC_MODULE_JS = ROOT / "templates" / "ui" / "traffic-module.js"

SENTINEL_TRAFFIC_TOKEN = "SENTINEL_DUMMY_TOKEN_TRAFFIC_VIEW_77777"
SENTINEL_TRAFFIC_SECRET = "SENTINEL_DUMMY_SECRET_TRAFFIC_VIEW_88888"


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


def test_traffic_module_pure_action_resolution():
    """Verify action entry points gate replay/mutation/proxy as unavailable."""
    script = f"""
    const trafficMod = require('{TRAFFIC_MODULE_JS}');

    const entryValid = {{
      id: 'req_01',
      url: 'https://example.com/api/test?q=1',
      method: 'GET',
    }};

    // Backend manifest without replay/mutation/proxy capabilities
    const mockManifest = {{
      schema_version: '1.0.0',
      capabilities: {{
        traffic: true,
        open_browser: true,
      }},
    }};

    const actions = trafficMod.resolveTrafficActions(entryValid, {{ manifest: mockManifest }});

    console.log(JSON.stringify({{ actions }}));
    """
    res = _run_node(script)
    actions = {a["id"]: a for a in res["actions"]}

    assert actions["open_in_browser"]["enabled"] is True
    assert actions["open_in_browser"]["url"] == "https://example.com/api/test?q=1"

    # Replay is disabled with explicit reason
    assert actions["replay"]["enabled"] is False
    assert "not available in this version" in actions["replay"]["reason"]

    # Mutate is disabled with explicit reason
    assert actions["mutate"]["enabled"] is False
    assert "not available in this version" in actions["mutate"]["reason"]

    # Send-to-proxy is disabled with explicit reason
    assert actions["send_to_proxy"]["enabled"] is False
    assert "not available in this version" in actions["send_to_proxy"]["reason"]


def test_traffic_module_pure_redaction_and_links():
    """Verify display redaction masks secrets and cross-links build valid hashes."""
    script = f"""
    const trafficMod = require('{TRAFFIC_MODULE_JS}');

    const secretUrl = 'https://admin:{SENTINEL_TRAFFIC_SECRET}@example.com/api?token={SENTINEL_TRAFFIC_TOKEN}&safe=ok';
    const redactedUrl = trafficMod.redactDisplayUrl(secretUrl);

    const crawlLink = trafficMod.buildCrawlLink('scan_01', 'https://example.com/page');
    const findingsLink = trafficMod.buildFindingsLink('scan_01', 'https://example.com/page');
    const hash = trafficMod.buildTrafficHash('scan_01', 'req_05', {{ method: 'post', status: '2xx', search: 'login' }});

    console.log(JSON.stringify({{
      redactedUrl,
      crawlLink,
      findingsLink,
      hash,
    }}));
    """
    res = _run_node(script)

    assert SENTINEL_TRAFFIC_TOKEN not in res["redactedUrl"]
    assert SENTINEL_TRAFFIC_SECRET not in res["redactedUrl"]
    assert "<redacted>" in res["redactedUrl"]
    assert "safe=ok" in res["redactedUrl"]

    assert res["crawlLink"] == "#/crawl?scan=scan_01&url=https%3A%2F%2Fexample.com%2Fpage"
    assert res["findingsLink"] == "#/findings?scan=scan_01&url=https%3A%2F%2Fexample.com%2Fpage"
    assert "scan=scan_01" in res["hash"]
    assert "entry=req_05" in res["hash"]
    assert "method=post" in res["hash"]
    assert "status=2xx" in res["hash"]


def test_traffic_module_pure_filtering():
    """Verify in-memory filtering by method, status, source, and search."""
    script = f"""
    const trafficMod = require('{TRAFFIC_MODULE_JS}');

    const entries = [
      {{ id: '1', method: 'GET', status: 200, source: 'browser', url: 'https://example.com/home', input_point_kinds: {{ query: false }} }},
      {{ id: '2', method: 'POST', status: 302, source: 'scanner', url: 'https://example.com/login', post_data_preview: 'user=admin', input_point_kinds: {{ form: true }} }},
      {{ id: '3', method: 'GET', status: 404, source: 'browser', url: 'https://example.com/missing', input_point_kinds: {{ query: true }} }},
      {{ id: '4', method: 'POST', status: 500, source: 'scanner', url: 'https://example.com/api', post_data_preview: '{{"action": "test"}}', input_point_kinds: {{ json: true }} }},
    ];

    const fMethod = trafficMod.filterTraffic(entries, {{ method: 'post' }});
    const fStatus = trafficMod.filterTraffic(entries, {{ status: '2xx' }});
    const fSource = trafficMod.filterTraffic(entries, {{ source: 'scanner' }});
    const fType = trafficMod.filterTraffic(entries, {{ type: 'json' }});
    const fSearch = trafficMod.filterTraffic(entries, {{ search: 'missing' }});

    console.log(JSON.stringify({{
      fMethodIds: fMethod.map(e => e.id),
      fStatusIds: fStatus.map(e => e.id),
      fSourceIds: fSource.map(e => e.id),
      fTypeIds: fType.map(e => e.id),
      fSearchIds: fSearch.map(e => e.id),
    }}));
    """
    res = _run_node(script)

    assert res["fMethodIds"] == ["2", "4"]
    assert res["fStatusIds"] == ["1"]
    assert res["fSourceIds"] == ["2", "4"]
    assert res["fTypeIds"] == ["4"]
    assert res["fSearchIds"] == ["3"]


def test_browser_traffic_view_mount_list_and_gating(ui_harness: UIHarness):
    """Browser test: Traffic view mounts, lists entries, gates replay, and shows unavailable state."""
    require_browser()

    # 1. Seed two scans: one with valid traffic audit log, one without
    scan_with_traffic = "scan_traffic_ok"
    d_ok = ui_harness.output_dir / scan_with_traffic
    d_ok.mkdir(parents=True, exist_ok=True)
    (d_ok / "report.html").write_text("<html><body>Scan with traffic</body></html>", encoding="utf-8")
    (d_ok / "scan_config.json").write_text(json.dumps({"config": {"url": "http://example.local"}}), encoding="utf-8")
    (d_ok / "evidence.json").write_text(json.dumps({"status": "done", "target": "http://example.local", "findings": []}), encoding="utf-8")

    traffic_entries = [
        {
            "id": "req_101",
            "method": "GET",
            "url": f"http://admin:{SENTINEL_TRAFFIC_SECRET}@example.local/items?token={SENTINEL_TRAFFIC_TOKEN}&cat=electronics",
            "request_headers": {
                "Authorization": f"Bearer {SENTINEL_TRAFFIC_SECRET}",
                "User-Agent": "Vulix-Audit",
            },
            "status": 200,
            "ts": 1700000010.0,
        },
        {
            "id": "req_102",
            "method": "POST",
            "url": "http://example.local/login",
            "request_headers": {
                "Content-Type": "application/x-www-form-urlencoded",
            },
            "post_data": f"user=alice&password={SENTINEL_TRAFFIC_SECRET}",
            "status": 302,
            "ts": 1700000020.0,
        },
    ]
    (d_ok / "http_requests.jsonl").write_text(
        "\n".join(json.dumps(e) for e in traffic_entries), encoding="utf-8"
    )

    # Second scan: absent log (http_requests.jsonl missing)
    scan_no_traffic = "scan_traffic_missing"
    d_missing = ui_harness.output_dir / scan_no_traffic
    d_missing.mkdir(parents=True, exist_ok=True)
    (d_missing / "report.html").write_text("<html><body>Scan without traffic</body></html>", encoding="utf-8")
    (d_missing / "scan_config.json").write_text(json.dumps({"config": {"url": "http://example2.local"}}), encoding="utf-8")
    (d_missing / "evidence.json").write_text(json.dumps({"status": "done", "target": "http://example2.local", "findings": []}), encoding="utf-8")

    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1440])

    # Navigate to /app#/traffic?scan=scan_traffic_ok
    page.goto(f"{ui_harness.server_url}/app#/traffic?scan={scan_with_traffic}", wait_until="domcontentloaded")
    page.wait_for_function("() => location.hash.includes('/traffic')")
    page.locator("#trafficSurface").wait_for(state="visible")

    # Assert active rail button and header title
    assert page.locator('[data-route="traffic"]').get_attribute("aria-current") == "page"
    assert page.locator("#viewTitle").inner_text() == "Traffic"

    # Wait for traffic rows to render
    page.locator(".traffic-row").first.wait_for(state="visible")
    rows = page.locator(".traffic-row")
    assert rows.count() == 2

    # Check first row displays GET and redacted URL
    first_row = rows.first
    assert "GET" in first_row.inner_text()
    assert "200" in first_row.inner_text()
    assert "<redacted>" in first_row.inner_text()
    assert "cat=electronics" in first_row.inner_text()

    # Detail panel: action buttons check
    page.locator(".traffic-actions-card").wait_for(state="visible")

    # Replay, mutate, and send-to-proxy must be visibly disabled with 'not available in this version'
    replay_btn = page.locator('.traffic-action-btn:has-text("リプレイ")')
    assert replay_btn.is_disabled()
    assert "not available in this version" in replay_btn.inner_text()

    mutate_btn = page.locator('.traffic-action-btn:has-text("改変送信")')
    assert mutate_btn.is_disabled()
    assert "not available in this version" in mutate_btn.inner_text()

    proxy_btn = page.locator('.traffic-action-btn:has-text("プロキシへ送信")')
    assert proxy_btn.is_disabled()
    assert "not available in this version" in proxy_btn.inner_text()

    # Open-in-browser is enabled
    browser_btn = page.locator('.traffic-action-btn:has-text("ブラウザで開く")')
    assert not browser_btn.is_disabled()
    assert browser_btn.get_attribute("href") is not None

    # Cross-links check
    crawl_cross_link = page.locator('.traffic-cross-link:has-text("Crawl Graph")')
    assert crawl_cross_link.is_visible()
    assert "crawl" in crawl_cross_link.get_attribute("href")

    findings_cross_link = page.locator('.traffic-cross-link:has-text("Findings")')
    assert findings_cross_link.is_visible()
    assert "findings" in findings_cross_link.get_attribute("href")

    # Input-point kinds chips check
    query_chip = page.locator('.traffic-ip-chip:has-text("QUERY")')
    assert query_chip.is_visible()
    assert "(2)" in query_chip.inner_text()

    # Sentinel test: dummy secret must NOT appear in any rendered DOM text, URL, or localStorage
    page_content = page.content()
    assert SENTINEL_TRAFFIC_TOKEN not in page_content
    assert SENTINEL_TRAFFIC_SECRET not in page_content
    assert SENTINEL_TRAFFIC_TOKEN not in page.url
    assert SENTINEL_TRAFFIC_SECRET not in page.url

    storage_data = page.evaluate("() => JSON.stringify(window.localStorage)")
    assert SENTINEL_TRAFFIC_TOKEN not in storage_data
    assert SENTINEL_TRAFFIC_SECRET not in storage_data

    # Now switch to the scan without traffic audit log (test explicit unavailable state)
    page.locator(".traffic-scan-select").select_option(scan_no_traffic)
    page.locator(".traffic-unavailable-box").wait_for(state="visible")

    unavail_box = page.locator(".traffic-unavailable-box")
    assert "unavailable" in unavail_box.inner_text().lower() or "利用できません" in unavail_box.inner_text()
    assert "http_requests.jsonl" in unavail_box.inner_text()
