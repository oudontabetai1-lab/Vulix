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
            assert len(rows) == 2

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

            # 5. Search filtering
            page.fill("#historySearchInput", "malicious")
            filtered_rows = page.query_selector_all("#historyTable tbody tr")
            assert len(filtered_rows) == 1
            assert "20261026_130000" in page.inner_text("#historyTable tbody")

            # Clear search
            page.fill("#historySearchInput", "")
            all_rows = page.query_selector_all("#historyTable tbody tr")
            assert len(all_rows) == 2

            # Status filter
            page.select_option("#historyStatusFilter", "done")
            done_rows = page.query_selector_all("#historyTable tbody tr")
            assert len(done_rows) == 1
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
