"""
Tests for the Scan History Screen in templates/dashboard.html.

Verifies:
1. Navigation rail has 'スキャン履歴' and 'ライブモニター' buttons.
2. View switching toggles between #viewLiveMonitor and #viewScanHistory without destroying DOM.
3. Loading / empty / error / table states render properly.
4. Scan table rows correctly format targets, dates, severity badges, report links, and zip download links.
5. Search filtering by target or scan ID, and status filtering.
6. XSS protection: target URLs and scan IDs are properly escaped via safe DOM nodes and encodeURIComponent.
7. Playwright / headless Chromium integration with a running test server.
"""

import json
import socket
import threading
import time
from pathlib import Path

import pytest
import uvicorn
from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright

from wscan.monitor import MonitorServer


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UvicornServerThread:
    def __init__(self, srv: MonitorServer, port: int):
        self.srv = srv
        self.port = port
        self.config = uvicorn.Config(srv.app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        time.sleep(0.5)

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=2)


def test_dashboard_scan_history_static_structure():
    """Verify HTML template structure contains all required components."""
    html = Path("templates/dashboard.html").read_text(encoding="utf-8")
    assert 'id="navScanHistory"' in html
    assert 'id="navLiveMonitor"' in html
    assert 'id="viewScanHistory"' in html
    assert 'id="viewLiveMonitor"' in html
    assert 'id="historyTable"' in html
    assert 'id="historyTableBody"' in html
    assert 'id="btnRefreshHistory"' in html
    assert 'id="historySearchInput"' in html
    assert 'id="historyStatusFilter"' in html
    assert 'id="historyLoadingState"' in html
    assert 'id="historyEmptyState"' in html
    assert 'id="historyErrorState"' in html
    assert "switchMainView" in html
    assert "loadScanHistory" in html


def test_dashboard_scan_history_api_integration(tmp_path, monkeypatch):
    """Test MonitorServer with mock scan output directories."""
    # Create mock scans in tmp_path
    scan1 = tmp_path / "20261026_100000"
    scan1.mkdir()
    (scan1 / "report.html").write_text("<h1>Report</h1>", encoding="utf-8")
    (scan1 / "evidence.json").write_text(json.dumps({
        "target": "http://test-app.local",
        "scan_date": "2026-10-26T10:00:00",
        "status": "done",
        "findings": [
            {"id": "f1", "check_type": "xss", "severity": "critical", "url": "http://target.com/a"},
            {"id": "f2", "check_type": "sqli", "severity": "high", "url": "http://target.com/b"}
        ]
    }), encoding="utf-8")

    scan2 = tmp_path / "20261026_110000"
    scan2.mkdir()
    (scan2 / "evidence.json").write_text(json.dumps({
        "target": "http://another-target.org/path",
        "scan_date": "2026-10-26T11:00:00",
        "status": "aborted",
        "findings": []
    }), encoding="utf-8")

    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)

    srv = MonitorServer()
    client = TestClient(srv.app)

    res = client.get("/api/v1/scans")
    assert res.status_code == 200
    data = res.json()
    assert "scans" in data
    scans = {s["id"]: s for s in data["scans"]}
    assert "20261026_100000" in scans
    assert "20261026_110000" in scans

    s1 = scans["20261026_100000"]
    assert s1["target"] == "http://test-app.local"
    assert s1["status"] == "done"
    assert s1["findings_count"] == 2
    assert s1["severity"]["critical"] == 1
    assert s1["severity"]["high"] == 1
    assert s1["report_available"] is True


def test_dashboard_scan_history_playwright_e2e(tmp_path, monkeypatch):
    """E2E browser test using Playwright against live dashboard."""
    # Setup test scan directory
    scan_done = tmp_path / "20261026_120000"
    scan_done.mkdir()
    (scan_done / "report.html").write_text("<html><body>Safe Report</body></html>", encoding="utf-8")
    (scan_done / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/app",
        "scan_date": "2026-10-26T12:00:00",
        "status": "done",
        "findings": [
            {"id": "f1", "check_type": "xss", "severity": "critical", "url": "http://example.com/login"},
            {"id": "f2", "check_type": "sqli", "severity": "medium", "url": "http://example.com/items"}
        ]
    }), encoding="utf-8")

    # Add scan with special characters for XSS check
    scan_xss = tmp_path / "20261026_130000"
    scan_xss.mkdir()
    (scan_xss / "evidence.json").write_text(json.dumps({
        "target": "https://malicious.site/<script>alert(1)</script>",
        "scan_date": "2026-10-26T13:00:00",
        "status": "error",
        "findings": []
    }), encoding="utf-8")

    # Add scan with secret canaries to verify URL privacy redaction
    scan_secrets = tmp_path / "20261026_140000"
    scan_secrets.mkdir()
    (scan_secrets / "evidence.json").write_text(json.dumps({
        "target": "https://admin:CANARY_SECRET_PASS@portal.corp/app?token=CANARY_QUERY_SECRET&safe=ok#access_token=CANARY_FRAG_SECRET",
        "scan_date": "2026-10-26T14:00:00",
        "status": "done",
        "findings": []
    }), encoding="utf-8")

    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)

    srv = MonitorServer()
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.wait_for_selector("#navLiveMonitor")

            # 1. Initial State: Live Monitor visible, Scan History hidden
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")
            assert "active" in page.get_attribute("#navLiveMonitor", "class")
            assert "active" not in (page.get_attribute("#navScanHistory", "class") or "")

            # 2. Click 'スキャン履歴' in navigation rail
            page.click("#navScanHistory")
            page.wait_for_selector("#historyTable tbody tr")

            # 3. View Switch Verified
            assert not page.is_visible("#viewLiveMonitor")
            assert page.is_visible("#viewScanHistory")
            assert "active" in page.get_attribute("#navScanHistory", "class")
            assert "active" not in (page.get_attribute("#navLiveMonitor", "class") or "")
            assert "スキャン履歴" in page.inner_text("#headerTitle")

            # 4. Table Rows Populated
            rows = page.query_selector_all("#historyTable tbody tr")
            assert len(rows) == 3

            # Check done scan row
            row_html = page.inner_html("#historyTable tbody")
            assert "20261026_120000" in row_html
            assert "https://example.com/app" in row_html
            assert "完了" in row_html
            assert "C:1" in row_html
            assert "M:1" in row_html
            assert "📄 レポート" in row_html
            assert "⬇ ZIP" in row_html

            # Verify XSS safety: <script> was rendered as text, not HTML tag
            script_tags = page.query_selector_all("#historyTable tbody script")
            assert len(script_tags) == 0
            assert "&lt;script&gt;" in row_html or "<script>" in page.inner_text("#historyTable tbody")

            # Verify URL privacy redaction: credential and sensitive query/fragment canaries are ABSENT
            assert "CANARY_SECRET_PASS" not in row_html
            assert "CANARY_QUERY_SECRET" not in row_html
            assert "CANARY_FRAG_SECRET" not in row_html
            # Verify redacted form appears in displayed text and title
            assert "&lt;redacted&gt;@portal.corp" in row_html or "<redacted>@portal.corp" in page.inner_text("#historyTable tbody")
            assert "token=&lt;redacted&gt;" in row_html or "token=<redacted>" in page.inner_text("#historyTable tbody")

            # 5. Search filtering
            page.fill("#historySearchInput", "malicious")
            filtered_rows = page.query_selector_all("#historyTable tbody tr")
            assert len(filtered_rows) == 1
            assert "20261026_130000" in page.inner_text("#historyTable tbody")

            # Clear search
            page.fill("#historySearchInput", "")
            all_rows = page.query_selector_all("#historyTable tbody tr")
            assert len(all_rows) == 3

            # Status filter
            page.select_option("#historyStatusFilter", "done")
            done_rows = page.query_selector_all("#historyTable tbody tr")
            assert len(done_rows) == 2
            assert "20261026_120000" in page.inner_text("#historyTable tbody")

            page.select_option("#historyStatusFilter", "all")

            # 6. Switch back to Live Monitor
            page.click("#navLiveMonitor")
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")
            assert "ライブモニター" in page.inner_text("#headerTitle")

            # 7. Keyboard Navigation (Tab & Enter)
            page.focus("#navScanHistory")
            page.keyboard.press("Enter")
            assert page.is_visible("#viewScanHistory")
            assert not page.is_visible("#viewLiveMonitor")

            page.focus("#navLiveMonitor")
            page.keyboard.press("Space")
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_scan_history_empty_state(tmp_path, monkeypatch):
    """Test empty state when no scans exist in output directory."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)

    srv = MonitorServer()
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.click("#navScanHistory")
            page.wait_for_selector("#historyEmptyState")

            assert page.is_visible("#historyEmptyState")
            assert not page.is_visible("#historyTableScroll")
            assert "スキャン履歴はありません" in page.inner_text("#historyEmptyState")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_scan_history_fetch_error_and_401(tmp_path, monkeypatch):
    """Test network error and 401 Unauthorized error state handling."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)

    srv = MonitorServer()
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            # 1. Simulate 401 Unauthorized on /api/v1/scans
            page.route("**/api/v1/scans", lambda route: route.fulfill(
                status=401,
                body=json.dumps({"detail": "Unauthorized"}),
                headers={"Content-Type": "application/json"}
            ))

            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.click("#navScanHistory")
            page.wait_for_selector("#historyErrorState")

            assert page.is_visible("#historyErrorState")
            assert not page.is_visible("#historyTableScroll")
            err_text = page.inner_text("#historyErrorMessage")
            assert "401" in err_text or "認証" in err_text

            # 2. Simulate network / fetch failure
            page.unroute("**/api/v1/scans")
            page.route("**/api/v1/scans", lambda route: route.abort())

            # Click retry button
            page.click("#historyErrorState button")
            page.wait_for_selector("#historyErrorState")
            assert page.is_visible("#historyErrorState")

            # 3. Simulate recovery after network restored
            page.unroute("**/api/v1/scans")
            page.route("**/api/v1/scans", lambda route: route.fulfill(
                status=200,
                body=json.dumps({"scans": [], "storage": {}}),
                headers={"Content-Type": "application/json"}
            ))
            page.click("#historyErrorState button")
            page.wait_for_selector("#historyEmptyState")
            assert page.is_visible("#historyEmptyState")
            assert not page.is_visible("#historyErrorState")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_scan_history_background_ws_liveness(tmp_path, monkeypatch):
    """Test that background WebSocket updates continue while scan history is open."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)

    srv = MonitorServer()

    async def emit_test_page():
        await srv.emit("page_start", {"url": "https://example.com/live-test-page"})
        return {"ok": True}

    srv.app.add_api_route("/__test__/emit-page", emit_test_page, methods=["POST"])

    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.wait_for_selector("#navLiveMonitor")

            # Switch to Scan History
            page.click("#navScanHistory")
            assert page.is_visible("#viewScanHistory")
            assert not page.is_visible("#viewLiveMonitor")

            # Post to test endpoint inside uvicorn's event loop to trigger WS emit
            res = page.request.post(f"http://127.0.0.1:{port}/__test__/emit-page")
            assert res.status == 200

            # Wait for client to process WebSocket message
            page.wait_for_function("document.getElementById('statPages') && document.getElementById('statPages').textContent.trim() === '1'")

            # Switch back to live monitor and verify state was preserved and updated
            page.click("#navLiveMonitor")
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")

            stat_pages = page.inner_text("#statPages")
            assert "1" in stat_pages

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_scan_history_unknown_evidence_counts(tmp_path, monkeypatch):
    """Missing/malformed evidence must surface as unknown counts, not done/0."""
    # Valid complete evidence with an explicit zero: the only case that may be 0/done.
    d_valid = tmp_path / "scan_valid_zero"
    d_valid.mkdir()
    (d_valid / "report.html").write_text("<html>ok</html>", encoding="utf-8")
    (d_valid / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/ok",
        "scan_date": "2026-10-26T10:00:00",
        "status": "done",
        "findings": [],
    }), encoding="utf-8")

    # Legacy evidence without status but with a findings array remains complete.
    d_legacy = tmp_path / "scan_legacy_zero"
    d_legacy.mkdir()
    (d_legacy / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/legacy",
        "scan_date": "2026-10-26T10:01:00",
        "findings": [],
    }), encoding="utf-8")

    # Evidence missing entirely (report exists): unknown count, not done.
    d_missing = tmp_path / "scan_missing_evidence"
    d_missing.mkdir()
    (d_missing / "report.html").write_text("<html>legacy report</html>", encoding="utf-8")

    # Malformed JSON evidence.
    d_malformed = tmp_path / "scan_malformed"
    d_malformed.mkdir()
    (d_malformed / "evidence.json").write_text("{not json", encoding="utf-8")

    # Read failure (invalid UTF-8) must be treated like malformed evidence.
    d_unreadable = tmp_path / "scan_unreadable"
    d_unreadable.mkdir()
    (d_unreadable / "evidence.json").write_bytes(b"\xff\xfe\x00\x00")

    # Valid evidence that explicitly says done but has no findings array.
    d_nofindings = tmp_path / "scan_done_no_findings"
    d_nofindings.mkdir()
    (d_nofindings / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/nofindings",
        "scan_date": "2026-10-26T10:02:00",
        "status": "done",
    }), encoding="utf-8")

    # Explicit non-complete statuses with a valid zero count.
    d_error = tmp_path / "scan_error_zero"
    d_error.mkdir()
    (d_error / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/error",
        "scan_date": "2026-10-26T10:03:00",
        "status": "error",
        "findings": [],
    }), encoding="utf-8")

    d_aborted = tmp_path / "scan_aborted_zero"
    d_aborted.mkdir()
    (d_aborted / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/aborted",
        "scan_date": "2026-10-26T10:04:00",
        "status": "aborted",
        "findings": [],
    }), encoding="utf-8")

    d_incomplete = tmp_path / "scan_incomplete_zero"
    d_incomplete.mkdir()
    (d_incomplete / "evidence.json").write_text(json.dumps({
        "target": "https://example.com/incomplete",
        "scan_date": "2026-10-26T10:05:00",
        "status": "incomplete",
        "findings": [],
    }), encoding="utf-8")

    # Running scan without evidence yet.
    d_running = tmp_path / "scan_running"
    d_running.mkdir()

    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()
    srv.scan_in_progress = True
    srv.current_scan_id = "scan_running"
    client = TestClient(srv.app)
    scans = {s["id"]: s for s in client.get("/api/v1/scans").json()["scans"]}

    assert scans["scan_valid_zero"]["findings_count"] == 0
    assert scans["scan_valid_zero"]["status"] == "done"
    assert scans["scan_legacy_zero"]["findings_count"] == 0
    assert scans["scan_legacy_zero"]["status"] == "done"

    for sid in ("scan_missing_evidence", "scan_malformed", "scan_unreadable",
                "scan_done_no_findings"):
        assert scans[sid]["findings_count"] is None, sid

    assert scans["scan_missing_evidence"]["status"] == "incomplete"
    assert scans["scan_malformed"]["status"] == "error"
    assert scans["scan_unreadable"]["status"] == "error"
    assert scans["scan_done_no_findings"]["status"] == "incomplete"

    assert scans["scan_error_zero"]["findings_count"] == 0
    assert scans["scan_error_zero"]["status"] == "error"
    assert scans["scan_aborted_zero"]["findings_count"] == 0
    assert scans["scan_aborted_zero"]["status"] == "aborted"
    assert scans["scan_incomplete_zero"]["findings_count"] == 0
    assert scans["scan_incomplete_zero"]["status"] == "incomplete"
    assert scans["scan_running"]["findings_count"] is None
    assert scans["scan_running"]["status"] == "scanning"


def test_dashboard_scan_history_privacy_playwright(tmp_path, monkeypatch):
    """Known credential canaries must not appear in cell, title, attrs, or localStorage."""
    canaries = [
        "CANARY_USER_PASS", "CANARY_QUERY", "CANARY_FRAG", "CANARY_NOSCHEME",
        "CANARY_MATRIX", "CANARY_JSESSION", "CANARY_ASP", "CANARY_JS",
        "CANARY_MALFORMED", "CANARY_ENCODED", "CANARY_LDAP",
    ]
    targets = {
        "p-valid": (
            "https://user:CANARY_USER_PASS@example.com/app"
            "?token=CANARY_QUERY&safe=ok#access_token=CANARY_FRAG"
        ),
        "p-noscheme": "user:CANARY_NOSCHEME@example.com/path",
        "p-matrix-token": "http://example.com/path;token=CANARY_MATRIX",
        "p-jsession": "http://example.com/path;jsessionid=CANARY_JSESSION",
        "p-asp": "https://example.com/path/(S(CANARY_ASP))/view",
        "p-js": "javascript:alert('CANARY_JS')",
        "p-malformed": "http://user:CANARY_MALFORMED@[bad-host/path",
        "p-encoded-key": "https://example.com/app?%74oken=CANARY_ENCODED",
        "p-ldap": "ldap://user:CANARY_LDAP@ldap.example.com/ou=users",
        "p-safe": "https://example.com/safe/path?q=ok",
    }
    for sid, target in targets.items():
        d = tmp_path / sid
        d.mkdir()
        (d / "evidence.json").write_text(json.dumps({
            "target": target,
            "scan_date": "2026-10-26T12:00:00",
            "status": "done",
            "findings": [],
        }), encoding="utf-8")

    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.click("#navScanHistory")
            page.wait_for_selector("#historyTableBody tr")

            body_text = page.inner_text("#historyTableBody")
            body_html = page.locator("#historyTableBody").evaluate("el => el.outerHTML")
            all_attrs = page.evaluate(
                "() => Array.from(document.querySelectorAll('#historyTableBody *'))"
                ".flatMap(el => Array.from(el.attributes).map(a => a.name + '=' + a.value))"
            )
            local_storage = page.evaluate("() => JSON.stringify(localStorage)")

            for canary in canaries:
                assert canary not in body_text, canary
                assert canary not in body_html, canary
                assert all(canary not in attr for attr in all_attrs), canary
                assert canary not in local_storage, canary

            # Valid HTTP(S) URLs keep a meaningful, masked display.
            assert "<redacted>@example.com" in body_text
            assert "token=<redacted>" in body_text
            assert "access_token=<redacted>" in body_text
            assert ";token=<redacted>" in body_text
            assert ";jsessionid=<redacted>" in body_text
            assert "(<redacted>)" in body_text
            assert "%74oken=<redacted>" in body_text
            assert "https://example.com/safe/path?q=ok" in body_text

            # Invalid/unsupported values use the neutral placeholder.
            assert "（URL非表示）" in body_text

            # Cell text and title come from the same sanitized value.
            valid_cell = page.locator("#historyTableBody tr").filter(
                has_text="p-valid"
            ).locator(".history-target-cell")
            assert valid_cell.inner_text() == valid_cell.get_attribute("title")
            assert "<redacted>@example.com" in valid_cell.inner_text()

            # Still no executable markup injection from target text.
            assert page.query_selector_all("#historyTableBody script") == []

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_scan_history_unknown_counts_playwright(tmp_path, monkeypatch):
    """Unknown counts render as 未取得; only complete zero evidence says 検出なし."""
    def make_scan(sid, evidence=None, raw_bytes=None):
        d = tmp_path / sid
        d.mkdir()
        if raw_bytes is not None:
            (d / "evidence.json").write_bytes(raw_bytes)
        elif evidence is not None:
            (d / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")

    make_scan("c-empty-done", {
        "target": "https://example.com/done",
        "scan_date": "2026-10-26T13:00:00", "status": "done", "findings": [],
    })
    make_scan("c-missing")
    make_scan("c-malformed", raw_bytes=b"{broken")
    make_scan("c-error-zero", {
        "target": "https://example.com/error",
        "scan_date": "2026-10-26T13:02:00", "status": "error", "findings": [],
    })
    make_scan("c-incomplete-zero", {
        "target": "https://example.com/incomplete",
        "scan_date": "2026-10-26T13:03:00", "status": "incomplete", "findings": [],
    })
    make_scan("c-running")

    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()
    srv.scan_in_progress = True
    srv.current_scan_id = "c-running"
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    def findings_cell(page, sid):
        return page.locator("#historyTableBody tr").filter(
            has_text=sid
        ).locator("td").nth(3).inner_text()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.click("#navScanHistory")
            page.wait_for_selector("#historyTableBody tr")

            done_cell = findings_cell(page, "c-empty-done")
            assert "0" in done_cell
            assert "検出なし" in done_cell

            for sid in ("c-missing", "c-malformed", "c-running"):
                cell = findings_cell(page, sid)
                assert "未取得" in cell, sid
                assert "検出なし" not in cell, sid

            for sid in ("c-error-zero", "c-incomplete-zero"):
                cell = findings_cell(page, sid)
                assert "0" in cell, sid
                assert "検出なし" not in cell, sid

            browser.close()
    finally:
        server_thread.stop()
