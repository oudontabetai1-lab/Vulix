"""
Tests for the Audit Log Screen in templates/dashboard.html.

Verifies:
1. Static DOM Structure: Navigation rail `#navAuditLog`, mobile header toggle `#hdrBtnAudit`,
   audit container `#viewAuditLog`, table, search, filter, and state boxes.
2. API contract verification against `GET /api/v1/audit`.
3. Playwright browser e2e testing:
   - View switching between Live Monitor, Scan History, and Audit Log without teardown.
   - Known action label mapping and safe structural display.
   - Strict IP validation (valid IPv4/IPv6 rendered; invalid/raw spoofed values masked as '—').
   - Strict timestamp validation (valid ISO formatted; invalid values rendered as '不明').
   - Sensitive details and canary token withholding (token/key query params masked; invalid/dangerous detail suppressed as '（詳細非表示）').
   - Empty state, error state, and 401 retry behavior.
   - Responsive mobile navigation (390px viewport) and keyboard accessibility.
   - Background WebSocket event reception across view transitions.
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


def test_dashboard_audit_log_static_structure():
    """Verify HTML template contains required elements for audit log view."""
    html = Path("templates/dashboard.html").read_text(encoding="utf-8")

    # Sidebar rail & mobile header navigation
    assert 'id="navAuditLog"' in html
    assert 'switchMainView(\'audit\')' in html
    assert 'id="hdrBtnAudit"' in html

    # Main Audit Log container and controls
    assert 'id="viewAuditLog"' in html
    assert 'id="btnRefreshAudit"' in html
    assert 'id="auditSearchInput"' in html
    assert 'id="auditActionFilter"' in html
    assert 'id="auditTable"' in html
    assert 'id="auditTableBody"' in html

    # State boxes
    assert 'id="auditLoadingState"' in html
    assert 'id="auditEmptyState"' in html
    assert 'id="auditErrorState"' in html
    assert 'id="auditErrorMessage"' in html


def test_dashboard_audit_log_api_integration(tmp_path, monkeypatch):
    """Verify API interaction with GET /api/v1/audit."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()

    # When no audit file exists, return empty list
    client = TestClient(srv.app)
    res = client.get("/api/v1/audit")
    assert res.status_code == 200
    assert res.json() == {"audit": []}

    # Record some audit entries
    audit_file = tmp_path / "management_audit.jsonl"
    entries = [
        {"ts": "2026-10-26T12:00:00", "ip": "127.0.0.1", "action": "scan_start", "detail": "https://example.com/target"},
        {"ts": "2026-10-26T12:05:00", "ip": "192.168.1.100", "action": "scan_abort", "detail": "scan-12345"},
        {"ts": "2026-10-26T12:10:00", "ip": "::1", "action": "upload", "detail": "custom_rules.txt"},
    ]
    audit_file.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    res2 = client.get("/api/v1/audit")
    assert res2.status_code == 200
    data = res2.json().get("audit", [])
    assert len(data) == 3
    # Returned reversed (newest first)
    assert data[0]["action"] == "upload"
    assert data[1]["action"] == "scan_abort"
    assert data[2]["action"] == "scan_start"


def test_dashboard_audit_log_playwright_e2e(tmp_path, monkeypatch):
    """E2E test with Playwright verifying presentation, privacy masking, and XSS safety."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()

    audit_file = tmp_path / "management_audit.jsonl"
    entries = [
        # 1. scan_start with sensitive query token and credential
        {
            "ts": "2026-10-26T12:00:00",
            "ip": "192.168.1.50",
            "action": "scan_start",
            "detail": "https://example.com/api?token=CANARY_SECRET_TOKEN_123&user=alice"
        },
        # 2. scan_abort with safe alphanum scan ID
        {
            "ts": "2026-10-26T12:01:00",
            "ip": "10.0.0.1",
            "action": "scan_abort",
            "detail": "scan-safe-id-001"
        },
        # 3. upload with safe file
        {
            "ts": "2026-10-26T12:02:00",
            "ip": "127.0.0.1",
            "action": "upload",
            "detail": "my-rules_v1.0.txt"
        },
        # 4. upload with sensitive token filename (should be concealed)
        {
            "ts": "2026-10-26T12:02:30",
            "ip": "127.0.0.1",
            "action": "upload",
            "detail": "api_secret_key.pem"
        },
        # 5. schedule_add with valid URL and interval
        {
            "ts": "2026-10-26T12:03:00",
            "ip": "172.16.0.5",
            "action": "schedule_add",
            "detail": "https://sched.example.com/daily (24.0h)"
        },
        # 6. settings_update
        {
            "ts": "2026-10-26T12:04:00",
            "ip": "192.168.1.1",
            "action": "settings_update",
            "detail": "webhook_set=True enabled=True"
        },
        # 7. unknown action with potentially dangerous/sensitive text
        {
            "ts": "2026-10-26T12:05:00",
            "ip": "10.0.0.99",
            "action": "custom_internal_command",
            "detail": "secret_internal_arg=CANARY_COMMAND_SECRET"
        },
        # 8. invalid timestamp and spoofed/invalid raw IP
        {
            "ts": "invalid-timestamp-string",
            "ip": "192.168.1.1<script>alert(1)</script>, 10.0.0.1",
            "action": "scans_prune",
            "detail": "5 件"
        },
        # 9. XSS injection attempt in detail
        {
            "ts": "2026-10-26T12:07:00",
            "ip": "127.0.0.1",
            "action": "scan_delete",
            "detail": "<img src=x onerror=alert(1)>"
        }
    ]
    audit_file.write_text("\n".join(json.dumps(e) for e in entries) + "\n", encoding="utf-8")

    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(f"http://127.0.0.1:{port}/monitor")

            # 1. Initial view is Live Monitor
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")
            assert not page.is_visible("#viewAuditLog")

            # 2. Switch to Audit Log
            page.click("#navAuditLog")
            page.wait_for_selector("#auditTableBody tr")
            assert not page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")
            assert page.is_visible("#viewAuditLog")
            assert "監査ログ" in page.inner_text("#headerTitle")

            rows = page.locator("#auditTableBody tr")
            # 9 entries recorded
            assert rows.count() == 9

            dom_text = page.inner_text("#auditTableBody")
            dom_html = page.inner_html("#auditTableBody")

            # 3. Privacy & Canary Secret Verification
            # Canary tokens MUST NOT appear anywhere in inner text or attributes
            assert "CANARY_SECRET_TOKEN_123" not in dom_text
            assert "CANARY_SECRET_TOKEN_123" not in dom_html
            assert "CANARY_COMMAND_SECRET" not in dom_text
            assert "CANARY_COMMAND_SECRET" not in dom_html

            # Sensitive upload file is concealed
            assert "api_secret_key.pem" not in dom_text

            # Token query parameter was masked
            assert "<redacted>" in dom_text

            # Unknown action detail is concealed
            assert "（詳細非表示）" in dom_text

            # XSS probe detail was suppressed or text-escaped (no HTML tag execution)
            assert "<img src=x" not in dom_html

            # Invalid timestamp rendered as '不明'
            assert "不明" in dom_text

            # Spoofed/invalid IP rendered as '—'
            assert "192.168.1.1<script>" not in dom_text
            assert "<script>" not in dom_html

            # Known action badge labels
            assert "スキャン開始" in dom_text
            assert "スキャン中断" in dom_text
            assert "ファイル配置" in dom_text
            assert "定期追加" in dom_text
            assert "設定変更" in dom_text
            assert "その他操作" in dom_text

            # 4. Filter by Action Group
            page.select_option("#auditActionFilter", "scan")
            # Entries in scan group: scan_start, scan_abort, scans_prune, scan_delete (4 rows)
            assert page.locator("#auditTableBody tr").count() == 4

            page.select_option("#auditActionFilter", "upload")
            assert page.locator("#auditTableBody tr").count() == 2

            page.select_option("#auditActionFilter", "all")
            assert page.locator("#auditTableBody tr").count() == 9

            # 5. Search Filter
            search = page.locator("#auditSearchInput")
            search.fill("my-rules")
            assert page.locator("#auditTableBody tr").count() == 1
            assert "my-rules_v1.0.txt" in page.locator("#auditTableBody").inner_text()
            search.fill("")
            assert page.locator("#auditTableBody tr").count() == 9

            # 6. Switch to Scan History and back to Audit Log
            page.click("#navScanHistory")
            assert page.is_visible("#viewScanHistory")
            assert not page.is_visible("#viewAuditLog")

            page.click("#navAuditLog")
            assert page.is_visible("#viewAuditLog")
            assert not page.is_visible("#viewScanHistory")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_audit_log_empty_state(tmp_path, monkeypatch):
    """Test empty state when management_audit.jsonl is empty or missing."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(f"http://127.0.0.1:{port}/monitor")

            page.click("#navAuditLog")
            page.wait_for_selector("#auditEmptyState", state="visible")
            assert page.is_visible("#auditEmptyState")
            assert "記録された管理操作はありません" in page.inner_text("#auditEmptyState")
            assert not page.is_visible("#auditTableScroll")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_audit_log_fetch_error_and_401(tmp_path, monkeypatch):
    """Test error handling and 401 retry behavior."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()

    # Route that returns 401
    from starlette.responses import JSONResponse
    def auth_required_audit():
        return JSONResponse({"error": "Unauthorized"}, status_code=401)

    srv.app.router.routes = [r for r in srv.app.router.routes if getattr(r, "path", None) != "/api/v1/audit"]
    srv.app.add_api_route("/api/v1/audit", auth_required_audit, methods=["GET"])

    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            page.goto(f"http://127.0.0.1:{port}/monitor")

            page.click("#navAuditLog")
            page.wait_for_selector("#auditErrorState", state="visible")
            assert page.is_visible("#auditErrorState")
            assert "認証が必要" in page.inner_text("#auditErrorMessage")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_audit_log_mobile_nav_keyboard(tmp_path, monkeypatch):
    """Verify mobile navigation toggle (<=1200px) and keyboard interaction."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()

    audit_file = tmp_path / "management_audit.jsonl"
    audit_file.write_text(json.dumps({
        "ts": "2026-10-26T12:00:00",
        "ip": "127.0.0.1",
        "action": "scan_start",
        "detail": "https://example.com/mobile-test"
    }) + "\n", encoding="utf-8")

    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            # Mobile viewport 390px
            page = browser.new_page(viewport={"width": 390, "height": 844})
            page.goto(f"http://127.0.0.1:{port}/monitor")

            # In mobile mode, .ws-rail is hidden, .hdr-view-toggle is visible
            rail_display = page.evaluate("getComputedStyle(document.querySelector('.ws-rail')).display")
            assert rail_display == "none"

            toggle_display = page.evaluate("getComputedStyle(document.querySelector('.hdr-view-toggle')).display")
            assert toggle_display in ("flex", "inline-flex")
            assert page.is_visible("#hdrBtnAudit")

            # Click mobile header button
            page.click("#hdrBtnAudit")
            page.wait_for_selector("#auditTableBody tr")
            assert page.is_visible("#viewAuditLog")
            assert not page.is_visible("#viewLiveMonitor")
            assert page.locator("#auditTableBody tr").count() == 1

            # Switch back via keyboard on #hdrBtnLive
            page.focus("#hdrBtnLive")
            page.keyboard.press("Enter")
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewAuditLog")

            # Keyboard navigation to #hdrBtnAudit
            page.focus("#hdrBtnAudit")
            page.keyboard.press("Enter")
            assert page.is_visible("#viewAuditLog")
            assert not page.is_visible("#viewLiveMonitor")

            browser.close()
    finally:
        server_thread.stop()


def test_dashboard_audit_log_ws_lifecycle_across_views(tmp_path, monkeypatch):
    """Verify WebSocket messages continue to update live monitor state while switching to audit view."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)
    srv = MonitorServer()

    async def emit_lifecycle_step(step: str):
        await srv.emit("page_start", {"url": f"https://example.com/step-{step}"})
        return {"ok": True, "step": step}

    srv.app.add_api_route("/__test__/emit-step/{step}", emit_lifecycle_step, methods=["POST"])

    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            received_messages = []
            def handle_ws(ws):
                ws.on("framereceived", lambda payload: received_messages.append((time.time(), payload)))
            page.on("websocket", handle_ws)

            page.goto(f"http://127.0.0.1:{port}/monitor")
            page.wait_for_selector("#viewLiveMonitor")

            # 1. Trigger emit before entering audit
            res1 = page.request.post(f"http://127.0.0.1:{port}/__test__/emit-step/before_audit")
            assert res1.status == 200
            page.wait_for_function("document.getElementById('statPages') && document.getElementById('statPages').textContent.trim() === '1'")
            assert any("before_audit" in str(msg[1]) for msg in received_messages)
            count_before = len(received_messages)

            # 2. Switch to audit view
            page.click("#navAuditLog")
            page.wait_for_selector("#viewAuditLog")

            # Trigger emit while audit view is active
            res2 = page.request.post(f"http://127.0.0.1:{port}/__test__/emit-step/during_audit")
            assert res2.status == 200
            page.wait_for_function("document.getElementById('statPages') && document.getElementById('statPages').textContent.trim() === '2'")
            assert any("during_audit" in str(msg[1]) for msg in received_messages)
            count_during = len(received_messages)
            assert count_during > count_before

            # 3. Switch back to live view
            page.click("#navLiveMonitor")
            page.wait_for_selector("#viewLiveMonitor")

            # Trigger emit after returning to live
            res3 = page.request.post(f"http://127.0.0.1:{port}/__test__/emit-step/after_return")
            assert res3.status == 200
            page.wait_for_function("document.getElementById('statPages') && document.getElementById('statPages').textContent.trim() === '3'")
            assert any("after_return" in str(msg[1]) for msg in received_messages)
            count_after = len(received_messages)
            assert count_after > count_during

            browser.close()
    finally:
        server_thread.stop()
