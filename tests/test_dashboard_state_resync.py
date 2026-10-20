"""Regression coverage for dashboard state reconstruction after WebSocket reconnects."""
import os
import socket
import threading
import time
import unittest

from fastapi import Request
from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer


class ScanSnapshotTests(unittest.TestCase):
    def test_long_history_returns_full_snapshot_instead_of_truncated_event_tail(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "fixture-scan"
        monitor._begin_scan_snapshot()
        monitor.api_scan_status = "scanning"
        monitor.api_target = "http://127.0.0.1:9/fixture"
        monitor.api_phase = "attack"

        async def seed():
            await monitor.emit_scan_started({"url": monitor.api_target})
            await monitor.emit_scan_config(monitor.api_target, ["xss"], 1, 1, 5)
            await monitor.emit_phase("attack")
            await monitor.emit_intervention_state(True)
            for i in range(202):
                await monitor.emit("status", {"message": f"event {i}"})
            await monitor.emit_page_start("http://127.0.0.1:9/fixture")
            await monitor.emit_payload_test("q", "fixture", "xss", monitor.api_target)
            await monitor.emit_finding({
                "url": monitor.api_target, "field_name": "q", "check_type": "xss",
                "payload": "fixture", "evidence_type": "reflected", "verified": False,
            })

        import asyncio
        asyncio.run(seed())
        self.assertGreater(len(monitor.event_history), 200)
        client = TestClient(monitor.app)
        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()

        self.assertEqual(snapshot["type"], "scan_snapshot")
        self.assertEqual(snapshot["sequence"], monitor._scan_sequence)
        self.assertEqual(snapshot["data"]["status"], "scanning")
        self.assertEqual(snapshot["data"]["phase"], "attack")
        self.assertTrue(snapshot["data"]["paused"])
        self.assertEqual(snapshot["data"]["page_count"], 1)
        self.assertEqual(snapshot["data"]["check_counts"], {"xss": 1})
        self.assertEqual(len(snapshot["data"]["findings"]), 1)

    def test_short_history_snapshot_keeps_pending_modal_and_new_scan_resets_counts(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "first"
        monitor._begin_scan_snapshot()
        monitor.api_scan_status = "scanning"
        monitor.pending_interactive = {
            "type": "crawl_review", "timestamp": time.time(), "data": {"pages": []}
        }

        async def seed():
            await monitor.emit_scan_started({"url": "http://127.0.0.1:9/fixture"})
            await monitor.emit_page_start("http://127.0.0.1:9/fixture")
            await monitor.emit_payload_test("q", "fixture", "xss")

        import asyncio
        asyncio.run(seed())
        first_run = monitor._scan_run_id
        self.assertLess(len(monitor.event_history), 200)
        client = TestClient(monitor.app)
        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["pending_interactive"]["type"], "crawl_review")
        self.assertEqual(snapshot["data"]["page_count"], 1)
        self.assertEqual(snapshot["data"]["check_counts"], {"xss": 1})

        monitor.api_scan_id = "second"
        monitor._begin_scan_snapshot()
        self.assertNotEqual(monitor._scan_run_id, first_run)
        self.assertEqual(monitor._scan_page_count, 0)
        self.assertEqual(monitor._scan_check_counts, {})
        self.assertFalse(monitor._scan_paused)
        self.assertEqual(len(monitor.event_history), 0)

    def test_completed_snapshot_keeps_terminal_status_and_report_reference(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "completed-run"
        monitor._begin_scan_snapshot()
        monitor.api_findings = [{"check_type": "xss", "verified": True}]

        import asyncio
        asyncio.run(monitor.emit("scan_complete", {
            "total_findings": 1, "report_path": "output/completed/report.html",
            "scan_id": "completed", "findings": monitor.api_findings,
        }))
        client = TestClient(monitor.app)
        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["status"], "done")
        self.assertEqual(snapshot["data"]["complete"], {
            "total_findings": 1, "report_path": "output/completed/report.html",
            "scan_id": "completed",
        })
        self.assertEqual(snapshot["data"]["findings"], monitor.api_findings)

    def test_operator_aborted_scan_zero_findings_contract(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "aborted-zero"
        monitor._begin_scan_snapshot()
        monitor.api_findings = []

        import asyncio
        asyncio.run(monitor.emit("scan_complete", {
            "total_findings": 0, "report_path": "output/aborted/report.html",
            "scan_id": "aborted-zero", "findings": [],
            "status": "aborted", "aborted": True,
        }))
        client = TestClient(monitor.app)
        status_resp = client.get("/api/v1/scan/status").json()
        self.assertEqual(status_resp["status"], "aborted")
        self.assertTrue(status_resp["aborted"])
        self.assertEqual(status_resp["findings_count"], 0)

        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["status"], "aborted")
        self.assertEqual(snapshot["data"]["complete"]["status"], "aborted")
        self.assertTrue(snapshot["data"]["complete"]["aborted"])
        self.assertEqual(snapshot["data"]["findings"], [])

    def test_operator_aborted_scan_positive_findings_contract(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "aborted-pos"
        monitor._begin_scan_snapshot()
        monitor.api_findings = [{"check_type": "xss", "verified": True}]

        import asyncio
        asyncio.run(monitor.emit("scan_complete", {
            "total_findings": 1, "report_path": "output/aborted/report.html",
            "scan_id": "aborted-pos", "findings": monitor.api_findings,
            "status": "aborted", "aborted": True,
        }))
        client = TestClient(monitor.app)
        status_resp = client.get("/api/v1/scan/status").json()
        self.assertEqual(status_resp["status"], "aborted")
        self.assertTrue(status_resp["aborted"])
        self.assertEqual(status_resp["findings_count"], 1)

        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["status"], "aborted")
        self.assertEqual(snapshot["data"]["complete"]["status"], "aborted")
        self.assertTrue(snapshot["data"]["complete"]["aborted"])
        self.assertEqual(len(snapshot["data"]["findings"]), 1)

    def test_normal_unaborted_scan_zero_findings_safe_twin(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "normal-zero"
        monitor._begin_scan_snapshot()
        monitor.api_findings = []

        import asyncio
        asyncio.run(monitor.emit("scan_complete", {
            "total_findings": 0, "report_path": "output/normal/report.html",
            "scan_id": "normal-zero", "findings": [],
            "status": "done", "aborted": False,
        }))
        client = TestClient(monitor.app)
        status_resp = client.get("/api/v1/scan/status").json()
        self.assertEqual(status_resp["status"], "done")
        self.assertFalse(status_resp["aborted"])
        self.assertEqual(status_resp["findings_count"], 0)

        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["status"], "done")
        self.assertEqual(snapshot["data"]["complete"]["status"], "done")
        self.assertFalse(snapshot["data"]["complete"]["aborted"])
        self.assertEqual(snapshot["data"]["findings"], [])

    def test_normal_unaborted_scan_positive_findings_safe_twin(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "normal-pos"
        monitor._begin_scan_snapshot()
        monitor.api_findings = [{"check_type": "sqli", "verified": True}]

        import asyncio
        asyncio.run(monitor.emit("scan_complete", {
            "total_findings": 1, "report_path": "output/normal/report.html",
            "scan_id": "normal-pos", "findings": monitor.api_findings,
            "status": "done", "aborted": False,
        }))
        client = TestClient(monitor.app)
        status_resp = client.get("/api/v1/scan/status").json()
        self.assertEqual(status_resp["status"], "done")
        self.assertFalse(status_resp["aborted"])
        self.assertEqual(status_resp["findings_count"], 1)

        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["status"], "done")
        self.assertEqual(snapshot["data"]["complete"]["status"], "done")
        self.assertFalse(snapshot["data"]["complete"]["aborted"])
        self.assertEqual(len(snapshot["data"]["findings"]), 1)

    def test_scan_engine_aborted_sets_truthful_terminal_status_and_payload(self):
        from unittest.mock import AsyncMock, patch
        from wscan.engine import ScanEngine
        from wscan.intervention import AbortScan

        monitor = MonitorServer(port=0)
        engine = ScanEngine("http://127.0.0.1:9/target", monitor=monitor)

        async def run_aborted():
            with patch.object(engine, "_phase_crawl", AsyncMock(return_value=[])), \
                 patch.object(engine, "_phase_plan", AsyncMock(return_value={})), \
                 patch.object(engine, "_phase_attack", AsyncMock(side_effect=AbortScan("operator abort"))), \
                 patch.object(engine, "_phase_verify", AsyncMock()), \
                 patch.object(engine, "_phase_report_async", AsyncMock()), \
                 patch.object(engine, "_drain_notifications", AsyncMock()), \
                 patch.object(engine._browser, "init", AsyncMock()), \
                 patch.object(engine._browser, "close", AsyncMock()):
                await engine.run()

        import asyncio
        asyncio.run(run_aborted())
        self.assertTrue(engine.scan_aborted)
        self.assertEqual(monitor.api_scan_status, "aborted")
        self.assertEqual(monitor._scan_complete_data.get("status"), "aborted")
        self.assertTrue(monitor._scan_complete_data.get("aborted"))

    def test_scan_engine_normal_completion_sets_done_terminal_status(self):
        from unittest.mock import AsyncMock, patch
        from wscan.engine import ScanEngine

        monitor = MonitorServer(port=0)
        engine = ScanEngine("http://127.0.0.1:9/target", monitor=monitor)

        async def run_normal():
            with patch.object(engine, "_phase_crawl", AsyncMock(return_value=[])), \
                 patch.object(engine, "_phase_plan", AsyncMock(return_value={})), \
                 patch.object(engine, "_phase_attack", AsyncMock()), \
                 patch.object(engine, "_run_api_template_checks", AsyncMock()), \
                 patch.object(engine, "_run_json_injection_checks", AsyncMock()), \
                 patch.object(engine, "_run_tls_seed_scans", AsyncMock()), \
                 patch.object(engine, "_phase_verify", AsyncMock()), \
                 patch.object(engine, "_phase_report_async", AsyncMock()), \
                 patch.object(engine, "_drain_notifications", AsyncMock()), \
                 patch.object(engine._browser, "init", AsyncMock()), \
                 patch.object(engine._browser, "close", AsyncMock()):
                await engine.run()

        import asyncio
        asyncio.run(run_normal())
        self.assertFalse(engine.scan_aborted)
        self.assertEqual(monitor.api_scan_status, "done")
        self.assertEqual(monitor._scan_complete_data.get("status"), "done")
        self.assertFalse(monitor._scan_complete_data.get("aborted"))

    def test_scan_engine_preserves_browser_startup_error(self):
        from unittest.mock import AsyncMock, patch
        from wscan.engine import ScanEngine

        monitor = MonitorServer(port=0)
        engine = ScanEngine("http://127.0.0.1:9/target", monitor=monitor)
        startup_error = RuntimeError("browser startup failed")

        async def run_with_startup_failure():
            with patch.object(engine._browser, "init", AsyncMock(side_effect=startup_error)), \
                 patch.object(engine._browser, "close", AsyncMock()), \
                 patch.object(engine.header_manager, "stop_background_refresh", AsyncMock()), \
                 patch.object(engine, "_phase_verify", AsyncMock()), \
                 patch.object(engine, "_phase_report_async", AsyncMock()), \
                 patch.object(engine, "_drain_notifications", AsyncMock()):
                await engine.run()

        import asyncio
        with self.assertRaisesRegex(RuntimeError, "browser startup failed") as caught:
            asyncio.run(run_with_startup_failure())
        self.assertIs(caught.exception, startup_error)

    def test_short_history_snapshot_preserves_url_order_statuses_and_new_run_reset(self):
        monitor = MonitorServer(port=0)
        monitor.api_scan_id = "url-run"
        monitor._begin_scan_snapshot()

        async def seed():
            await monitor.emit_url_start("http://127.0.0.1:9/first")
            await monitor.emit_url_complete("http://127.0.0.1:9/first")
            await monitor.emit_scan_gap("http://127.0.0.1:9/blocked")
            await monitor.emit_url_start("http://127.0.0.1:9/second")

        import asyncio
        asyncio.run(seed())
        self.assertLess(len(monitor.event_history), 200)
        client = TestClient(monitor.app)
        with client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["url_order"], [
            "http://127.0.0.1:9/first",
            "http://127.0.0.1:9/blocked",
            "http://127.0.0.1:9/second",
        ])
        self.assertEqual(snapshot["data"]["url_statuses"], {
            "http://127.0.0.1:9/first": "done",
            "http://127.0.0.1:9/blocked": "error",
            "http://127.0.0.1:9/second": "scanning",
        })

        old_run = monitor._scan_run_id
        monitor.api_scan_id = "next-url-run"
        monitor._begin_scan_snapshot()
        self.assertNotEqual(monitor._scan_run_id, old_run)
        self.assertEqual(monitor._scan_url_order, [])
        self.assertEqual(monitor._scan_url_statuses, {})

    def test_finding_promotes_an_existing_url_status_to_vulnerable(self):
        monitor = MonitorServer(port=0)
        monitor._begin_scan_snapshot()
        url = "http://127.0.0.1:9/finding-page"

        async def seed():
            await monitor.emit_url_start(url)
            await monitor.emit_finding({
                "url": url, "field_name": "q", "check_type": "xss",
                "payload": "fixture", "evidence_type": "reflected", "verified": False,
            })

        import asyncio
        asyncio.run(seed())
        self.assertEqual(monitor._scan_snapshot_event()["data"]["url_statuses"][url], "vuln")


class DashboardResyncChromiumTests(unittest.TestCase):
    """Exercise the production dashboard and WebSocket against a loopback fixture only."""

    @classmethod
    def setUpClass(cls):
        import uvicorn

        cls.monitor = MonitorServer(port=0)

        async def seed(request: Request):
            cls.monitor.api_scan_id = "fixture-run-1"
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "scanning"
            cls.monitor.api_target = "http://127.0.0.1:9/fixture"
            cls.monitor.api_phase = ""
            cls.monitor.api_progress = {"current": 7, "total": 12, "percent": 58}
            cls.monitor.api_findings = []
            await cls.monitor.emit_scan_started({"url": cls.monitor.api_target})
            await cls.monitor.emit_scan_config(cls.monitor.api_target, ["xss"], 1, 1, 5)
            await cls.monitor.emit_phase("attack")
            await cls.monitor.emit_intervention_state(True)
            await cls.monitor.emit_url_start("http://127.0.0.1:9/probe-page", 1)
            for i in range(198):
                await cls.monitor.emit("status", {"message": f"fixture event {i}"})
            for _ in range(2):
                await cls.monitor.emit_page_start(cls.monitor.api_target)
                await cls.monitor.emit_payload_test("q", "fixture", "xss", cls.monitor.api_target)
            await cls.monitor.emit_finding({
                "url": "http://127.0.0.1:9/finding-page", "field_name": "q", "check_type": "xss",
                "severity": "high", "confidence": "tentative", "payload": "fixture",
                "evidence": "fixture finding", "evidence_type": "reflected", "verified": False,
                "verification_state": "assumed",
            })
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def add_page(request: Request):
            await cls.monitor.emit_page_start(cls.monitor.api_target)
            return {"sequence": cls.monitor._scan_sequence}

        async def finish_url(request: Request):
            await cls.monitor.emit_url_complete("http://127.0.0.1:9/probe-page")
            await cls.monitor.emit("scan_complete", {
                "total_findings": len(cls.monitor.api_findings),
                "report_path": "output/fixture/report.html",
                "scan_id": cls.monitor.api_scan_id,
            })
            return {"sequence": cls.monitor._scan_sequence}

        async def new_scan(request: Request):
            cls.monitor.api_scan_id = "fixture-run-2"
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "scanning"
            cls.monitor.api_target = "http://127.0.0.1:9/fixture-two"
            cls.monitor.api_phase = ""
            cls.monitor.api_progress = {"current": 0, "total": 0, "percent": 0}
            cls.monitor.api_findings = []
            await cls.monitor.emit_scan_started({"url": cls.monitor.api_target})
            await cls.monitor.emit_page_start(cls.monitor.api_target)
            await cls.monitor.emit_url_start(cls.monitor.api_target, 1)
            await cls.monitor.emit_payload_test("id", "fixture", "sqli", cls.monitor.api_target)
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def finish_abort_zero(request: Request):
            cls.monitor.api_scan_id = "fixture-abort-zero"
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "scanning"
            cls.monitor.api_target = "http://127.0.0.1:9/abort-zero"
            cls.monitor.api_findings = []
            await cls.monitor.emit_scan_started({"url": cls.monitor.api_target})
            await cls.monitor.emit("scan_complete", {
                "total_findings": 0,
                "report_path": "output/abort-zero/report.html",
                "scan_id": cls.monitor.api_scan_id,
                "findings": [],
                "status": "aborted",
                "aborted": True,
            })
            await cls.monitor.emit_awaiting_config()
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def finish_abort_pos(request: Request):
            cls.monitor.api_scan_id = "fixture-abort-pos"
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "scanning"
            cls.monitor.api_target = "http://127.0.0.1:9/abort-pos"
            finding = {
                "url": "http://127.0.0.1:9/abort-pos", "field_name": "q", "check_type": "xss",
                "severity": "high", "confidence": "tentative", "payload": "<script>",
                "evidence": "reflected", "evidence_type": "reflected", "verified": False,
            }
            cls.monitor.api_findings = []
            await cls.monitor.emit_scan_started({"url": cls.monitor.api_target})
            await cls.monitor.emit_finding(finding)
            await cls.monitor.emit("scan_complete", {
                "total_findings": 1,
                "report_path": "output/abort-pos/report.html",
                "scan_id": cls.monitor.api_scan_id,
                "findings": cls.monitor.api_findings,
                "status": "aborted",
                "aborted": True,
            })
            await cls.monitor.emit_awaiting_config()
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def finish_normal_zero(request: Request):
            cls.monitor.api_scan_id = "fixture-normal-zero"
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "scanning"
            cls.monitor.api_target = "http://127.0.0.1:9/normal-zero"
            cls.monitor.api_findings = []
            await cls.monitor.emit_scan_started({"url": cls.monitor.api_target})
            await cls.monitor.emit("scan_complete", {
                "total_findings": 0,
                "report_path": "output/normal-zero/report.html",
                "scan_id": cls.monitor.api_scan_id,
                "findings": [],
                "status": "done",
                "aborted": False,
            })
            await cls.monitor.emit_awaiting_config()
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def finish_normal_pos(request: Request):
            cls.monitor.api_scan_id = "fixture-normal-pos"
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "scanning"
            cls.monitor.api_target = "http://127.0.0.1:9/normal-pos"
            finding = {
                "url": "http://127.0.0.1:9/normal-pos", "field_name": "id", "check_type": "sqli",
                "severity": "critical", "confidence": "certain", "payload": "1' OR '1'='1",
                "evidence": "syntax error", "evidence_type": "error", "verified": True,
            }
            cls.monitor.api_findings = []
            await cls.monitor.emit_scan_started({"url": cls.monitor.api_target})
            await cls.monitor.emit_finding(finding)
            await cls.monitor.emit("scan_complete", {
                "total_findings": 1,
                "report_path": "output/normal-pos/report.html",
                "scan_id": cls.monitor.api_scan_id,
                "findings": cls.monitor.api_findings,
                "status": "done",
                "aborted": False,
            })
            await cls.monitor.emit_awaiting_config()
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def idle(request: Request):
            cls.monitor.api_scan_id = None
            cls.monitor._begin_scan_snapshot()
            cls.monitor.api_scan_status = "idle"
            cls.monitor.api_findings = []
            await cls.monitor.emit_awaiting_config()
            return {}

        cls.monitor.app.add_api_route("/__test__/idle", idle, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/seed", seed, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/page", add_page, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/finish-url", finish_url, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/new-scan", new_scan, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/abort-zero", finish_abort_zero, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/abort-pos", finish_abort_pos, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/normal-zero", finish_normal_zero, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/normal-pos", finish_normal_pos, methods=["POST"])
        cls.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.listen(128)
        cls.port = cls.sock.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(
            cls.monitor.app, log_level="error", access_log=False, lifespan="off"
        ))
        cls.thread = threading.Thread(
            target=cls.server.run, kwargs={"sockets": [cls.sock]}, daemon=True
        )
        cls.thread.start()
        deadline = time.time() + 10
        while not cls.server.started and time.time() < deadline:
            time.sleep(0.02)
        if not cls.server.started:
            raise RuntimeError("loopback dashboard server did not start")
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        cls.sock.close()

    def test_reconnect_reload_duplicate_order_and_new_scan_state(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            def local_only(route):
                if route.request.url.startswith(self.base_url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", local_only)
            seed = page.request.post(f"{self.base_url}/__test__/seed").json()
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            page.wait_for_function(
                """() => state.scanRunId && state.lastEventSequence > 200 &&
                    state.pageCount === 2 && state.checkCounts.xss === 2 &&
                    state.findingCount === 1 && state.paused === true""",
                timeout=10000,
            )
            self.assertEqual(page.locator("#statPages").inner_text(), "2")
            self.assertIn("xss", page.locator("#checkCounters").inner_text())
            self.assertIn("fixture finding", page.locator("#findingsPanel").inner_text())
            self.assertIn("スキャン中", page.locator("#statusText").inner_text())
            self.assertIn("visible", page.locator("#ibPauseState").get_attribute("class"))
            probe_url = "http://127.0.0.1:9/probe-page"
            self.assertEqual(page.evaluate("url => state.urlStatuses[url]", probe_url), "scanning")
            self.assertEqual(page.locator("#urlList .url-text").all_text_contents(), [probe_url])

            page.evaluate("() => { window.__oldSocket = state.ws; state.ws.close(); }")
            completed = page.request.post(f"{self.base_url}/__test__/finish-url").json()
            page.wait_for_function(
                """expected => state.ws !== window.__oldSocket && state.ws.readyState === WebSocket.OPEN &&
                    state.lastEventSequence === expected && state.scanDone &&
                    state.urlStatuses['http://127.0.0.1:9/probe-page'] === 'done'""",
                arg=completed["sequence"], timeout=10000,
            )
            self.assertEqual(page.locator("#statPages").inner_text(), "2")
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)
            self.assertEqual(page.locator("#urlList .url-text").all_text_contents(), [probe_url])
            self.assertEqual(page.locator("#urlList .url-badge").all_inner_texts(), ["完了"])
            screenshot_path = os.environ.get("WSCAN_DASHBOARD_RESYNC_SCREENSHOT")
            if screenshot_path:
                page.screenshot(path=screenshot_path, full_page=True)

            old_run_id = page.evaluate("state.scanRunId")
            old_sequence = page.evaluate("state.lastEventSequence")
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function(
                """expected => state.scanRunId && state.lastEventSequence === expected &&
                    state.pageCount === 2 && state.checkCounts.xss === 2 && state.findingCount === 1 &&
                    state.paused === true && state.scanDone &&
                    state.urlStatuses['http://127.0.0.1:9/probe-page'] === 'done'""",
                arg=completed["sequence"], timeout=10000,
            )
            self.assertEqual(page.locator("#statPages").inner_text(), "2")
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)
            self.assertEqual(page.locator("#urlList .url-text").all_text_contents(), [probe_url])
            self.assertEqual(page.locator("#urlList .url-badge").all_inner_texts(), ["完了"])

            page.request.post(f"{self.base_url}/__test__/page")
            page.wait_for_function(
                "expected => state.lastEventSequence === expected && state.pageCount === 3",
                arg=old_sequence + 1,
            )
            page.evaluate("""() => {
                handleEvent({type:'page_start', server_id:state.serverInstanceId,
                    run_id:state.scanRunId, scan_id:state.scanId,
                    sequence:state.lastEventSequence, data:{url:'duplicate'}});
                handleEvent({type:'page_start', server_id:state.serverInstanceId,
                    run_id:state.scanRunId, scan_id:state.scanId,
                    sequence:state.lastEventSequence + 2, data:{url:'out-of-order'}});
            }""")
            self.assertEqual(page.locator("#statPages").inner_text(), "3")
            self.assertEqual(page.locator("#urlList .url-badge").all_inner_texts(), ["完了"])
            page.wait_for_function(
                """expected => state.ws.readyState === WebSocket.OPEN && state.lastEventSequence === expected &&
                    state.pageCount === 3""", arg=old_sequence + 1, timeout=10000,
            )

            new_scan = page.request.post(f"{self.base_url}/__test__/new-scan").json()
            page.wait_for_function(
                """({expectedRun, expectedSeq}) => state.scanRunId === expectedRun && state.lastEventSequence === expectedSeq &&
                    state.pageCount === 1 && state.checkCounts.sqli === 1 && state.findingCount === 0""",
                arg={"expectedRun": new_scan["run_id"], "expectedSeq": new_scan["sequence"]},
                timeout=10000,
            )
            page.evaluate("""oldRun => handleEvent({type:'page_start',
                server_id:state.serverInstanceId, run_id:oldRun, scan_id:'fixture-run-1',
                sequence:9999, data:{url:'stale-old-scan'}})""", old_run_id)
            self.assertEqual(page.locator("#statPages").inner_text(), "1")
            self.assertEqual(page.locator("#checkCounters").inner_text().strip(), "sqli 1")
            self.assertEqual(page.locator("#urlList .url-text").all_text_contents(), ["http://127.0.0.1:9/fixture-two"])
            self.assertEqual(page.locator("#urlList .url-badge").all_inner_texts(), ["検査中"])
            browser.close()

    def test_chromium_initial_idle_and_explicit_new_scan_after_completion(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.route("**/*", lambda route: route.continue_()
                       if route.request.url.startswith(self.base_url) else route.abort())
            page.request.post(f"{self.base_url}/__test__/idle")
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            page.wait_for_function("document.getElementById('scanConfigOverlay').classList.contains('active')")
            self.assertTrue(page.locator("#scanConfigOverlay").is_visible())
            self.assertIn("設定フォーム", page.locator("#statusText").inner_text())

            completed = page.request.post(f"{self.base_url}/__test__/normal-pos").json()
            page.wait_for_function("seq => state.lastEventSequence === seq && state.scanDone",
                                   arg=completed["sequence"])
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            page.locator("button.ws-newscan").click()
            self.assertTrue(page.locator("#scanConfigOverlay").is_visible())
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)

            started = page.request.post(f"{self.base_url}/__test__/new-scan").json()
            page.wait_for_function("run => state.scanRunId === run && !state.scanDone",
                                   arg=started["run_id"])
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            self.assertFalse(page.locator("#postScanActions").is_visible())
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 0)
            self.assertEqual(page.locator("#statPages").inner_text(), "1")
            self.assertIn("スキャン開始", page.locator("#statusText").inner_text())
            browser.close()

    def test_chromium_operator_aborted_zero_findings_renders_aborted(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            def local_only(route):
                if route.request.url.startswith(self.base_url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", local_only)
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            res = page.request.post(f"{self.base_url}/__test__/abort-zero").json()

            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            self.assertTrue(page.locator("#postScanActions").is_visible())
            status_text = page.locator("#statusText").inner_text()
            self.assertIn("Scan aborted", status_text)
            self.assertIn("0 finding(s)", status_text)
            self.assertNotIn("Scan complete", status_text)
            self.assertNotIn("スキャン完了", status_text)
            self.assertEqual(page.locator("#statRemain").inner_text(), "中断")
            self.assertIn("aborted", page.locator("#statusDot").get_attribute("class"))
            self.assertNotIn("done", page.locator("#statusDot").get_attribute("class"))

            # Test reload / reconnect snapshot rendering
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            status_text_after = page.locator("#statusText").inner_text()
            self.assertIn("Scan aborted", status_text_after)
            self.assertIn("0 finding(s)", status_text_after)
            self.assertNotIn("Scan complete", status_text_after)
            self.assertNotIn("スキャン完了", status_text_after)
            self.assertEqual(page.locator("#statRemain").inner_text(), "中断")
            self.assertIn("aborted", page.locator("#statusDot").get_attribute("class"))
            self.assertNotIn("done", page.locator("#statusDot").get_attribute("class"))
            browser.close()

    def test_chromium_operator_aborted_positive_findings_renders_aborted(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            def local_only(route):
                if route.request.url.startswith(self.base_url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", local_only)
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            res = page.request.post(f"{self.base_url}/__test__/abort-pos").json()

            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone &&
                    state.findingCount === 1""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            self.assertTrue(page.locator("#postScanActions").is_visible())
            status_text = page.locator("#statusText").inner_text()
            self.assertIn("Scan aborted", status_text)
            self.assertIn("1 finding(s)", status_text)
            self.assertNotIn("Scan complete", status_text)
            self.assertNotIn("スキャン完了", status_text)
            self.assertEqual(page.locator("#statRemain").inner_text(), "中断")
            self.assertIn("aborted", page.locator("#statusDot").get_attribute("class"))
            self.assertNotIn("done", page.locator("#statusDot").get_attribute("class"))
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)

            # Test reload / reconnect snapshot rendering
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone &&
                    state.findingCount === 1""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            status_text_after = page.locator("#statusText").inner_text()
            self.assertIn("Scan aborted", status_text_after)
            self.assertIn("1 finding(s)", status_text_after)
            self.assertNotIn("Scan complete", status_text_after)
            self.assertNotIn("スキャン完了", status_text_after)
            self.assertEqual(page.locator("#statRemain").inner_text(), "中断")
            self.assertIn("aborted", page.locator("#statusDot").get_attribute("class"))
            self.assertNotIn("done", page.locator("#statusDot").get_attribute("class"))
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)
            browser.close()

    def test_chromium_normal_unaborted_zero_findings_safe_twin(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            def local_only(route):
                if route.request.url.startswith(self.base_url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", local_only)
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            res = page.request.post(f"{self.base_url}/__test__/normal-zero").json()

            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            self.assertTrue(page.locator("#postScanActions").is_visible())
            status_text = page.locator("#statusText").inner_text()
            self.assertIn("Scan complete", status_text)
            self.assertIn("0 finding(s)", status_text)
            self.assertEqual(page.locator("#statRemain").inner_text(), "完了")
            self.assertIn("done", page.locator("#statusDot").get_attribute("class"))

            # Test reload / reconnect snapshot rendering
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            status_text_after = page.locator("#statusText").inner_text()
            self.assertIn("Scan complete", status_text_after)
            self.assertIn("0 finding(s)", status_text_after)
            self.assertEqual(page.locator("#statRemain").inner_text(), "完了")
            self.assertIn("done", page.locator("#statusDot").get_attribute("class"))
            browser.close()

    def test_chromium_normal_unaborted_positive_findings_safe_twin(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()

            def local_only(route):
                if route.request.url.startswith(self.base_url):
                    route.continue_()
                else:
                    route.abort()

            page.route("**/*", local_only)
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            res = page.request.post(f"{self.base_url}/__test__/normal-pos").json()

            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone &&
                    state.findingCount === 1""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            self.assertTrue(page.locator("#postScanActions").is_visible())
            status_text = page.locator("#statusText").inner_text()
            self.assertIn("Scan complete", status_text)
            self.assertIn("1 finding(s)", status_text)
            self.assertEqual(page.locator("#statRemain").inner_text(), "完了")
            self.assertIn("done", page.locator("#statusDot").get_attribute("class"))
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)

            # Test reload / reconnect snapshot rendering
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function(
                """expected => state.scanRunId === expected.run_id &&
                    state.lastEventSequence === expected.sequence && state.scanDone &&
                    state.findingCount === 1""",
                arg={"run_id": res["run_id"], "sequence": res["sequence"]},
                timeout=10000,
            )
            self.assertFalse(page.locator("#scanConfigOverlay").is_visible())
            status_text_after = page.locator("#statusText").inner_text()
            self.assertIn("Scan complete", status_text_after)
            self.assertIn("1 finding(s)", status_text_after)
            self.assertEqual(page.locator("#statRemain").inner_text(), "完了")
            self.assertIn("done", page.locator("#statusDot").get_attribute("class"))
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)
            browser.close()

    def test_chromium_history_list_renders_aborted_and_done_badges(self):
        import json
        import shutil
        import tempfile
        from pathlib import Path
        from playwright.sync_api import sync_playwright
        import wscan.monitor as monitor_mod

        tmp_out = Path(tempfile.mkdtemp(prefix="wscan_history_ui_test_"))
        orig_base = monitor_mod.OUTPUT_BASE
        try:
            monitor_mod.OUTPUT_BASE = tmp_out

            # 1. Aborted scan folder
            d_aborted = tmp_out / "20261019_010000"
            d_aborted.mkdir(parents=True)
            (d_aborted / "report.html").write_text("<html>aborted</html>", encoding="utf-8")
            (d_aborted / "evidence.json").write_text(json.dumps({
                "target": "http://127.0.0.1:9/target-aborted",
                "scan_date": "2026-10-19T01:00:00",
                "status": "aborted",
                "aborted": True,
                "findings": [],
            }), encoding="utf-8")

            # 2. Done scan folder (normal safe twin)
            d_done = tmp_out / "20261019_020000"
            d_done.mkdir(parents=True)
            (d_done / "report.html").write_text("<html>done</html>", encoding="utf-8")
            (d_done / "evidence.json").write_text(json.dumps({
                "target": "http://127.0.0.1:9/target-done",
                "scan_date": "2026-10-19T02:00:00",
                "status": "done",
                "aborted": False,
                "findings": [],
            }), encoding="utf-8")

            # 3. Legacy scan folder without status/aborted
            d_legacy = tmp_out / "20261019_030000"
            d_legacy.mkdir(parents=True)
            (d_legacy / "report.html").write_text("<html>legacy</html>", encoding="utf-8")
            (d_legacy / "evidence.json").write_text(json.dumps({
                "target": "http://127.0.0.1:9/target-legacy",
                "scan_date": "2026-10-19T03:00:00",
                "findings": [],
            }), encoding="utf-8")

            with sync_playwright() as playwright:
                browser = playwright.chromium.launch(headless=True)
                page = browser.new_page()

                def local_only(route):
                    if route.request.url.startswith(self.base_url):
                        route.continue_()
                    else:
                        route.abort()

                page.route("**/*", local_only)
                page.goto(f"{self.base_url}/", wait_until="domcontentloaded")
                page.wait_for_selector("#scanRows tr td span.st")

                rows = page.locator("#scanRows tr")
                self.assertEqual(rows.count(), 3)

                badges = page.locator("#scanRows tr td span.st").all_inner_texts()
                classes = [
                    page.locator("#scanRows tr td span.st").nth(i).get_attribute("class")
                    for i in range(rows.count())
                ]

                # Verify presence of 'aborted' and 'done' statuses and styling
                self.assertIn("aborted", badges)
                self.assertIn("done", badges)
                self.assertTrue(any("st aborted" in c for c in classes))
                self.assertTrue(any("st done" in c for c in classes))

                browser.close()
        finally:
            monitor_mod.OUTPUT_BASE = orig_base
            shutil.rmtree(tmp_out, ignore_errors=True)


class ScanHistoryStatusPersistenceTests(unittest.TestCase):
    def test_save_evidence_writes_status_and_aborted_for_aborted_and_normal(self):
        import json
        import shutil
        import tempfile
        from pathlib import Path
        from wscan.engine import ScanEngine

        tmp_dir = Path(tempfile.mkdtemp(prefix="wscan_evidence_test_"))
        try:
            # Aborted twin
            eng_aborted = ScanEngine("http://127.0.0.1:9/target", output_dir=str(tmp_dir / "aborted"))
            eng_aborted.scan_aborted = True
            eng_aborted._save_evidence()

            ev_aborted = json.loads((tmp_dir / "aborted" / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(ev_aborted.get("status"), "aborted")
            self.assertIs(ev_aborted.get("aborted"), True)

            # Normal completion safe twin
            eng_normal = ScanEngine("http://127.0.0.1:9/target", output_dir=str(tmp_dir / "normal"))
            eng_normal.scan_aborted = False
            eng_normal._save_evidence()

            ev_normal = json.loads((tmp_dir / "normal" / "evidence.json").read_text(encoding="utf-8"))
            self.assertEqual(ev_normal.get("status"), "done")
            self.assertIs(ev_normal.get("aborted"), False)
        finally:
            shutil.rmtree(tmp_dir, ignore_errors=True)

    def test_list_scans_returns_truthful_status_for_aborted_done_and_legacy(self):
        import json
        import shutil
        import tempfile
        from pathlib import Path
        import wscan.monitor as monitor_mod

        tmp_base = Path(tempfile.mkdtemp(prefix="wscan_scans_test_"))
        orig_base = monitor_mod.OUTPUT_BASE
        try:
            monitor_mod.OUTPUT_BASE = tmp_base
            monitor = monitor_mod.MonitorServer(port=0)

            # Aborted persisted evidence
            d_aborted = tmp_base / "scan_aborted"
            d_aborted.mkdir(parents=True)
            (d_aborted / "report.html").write_text("<html>rpt</html>", encoding="utf-8")
            (d_aborted / "evidence.json").write_text(json.dumps({
                "target": "http://127.0.0.1:9/target",
                "scan_date": "2026-10-19T01:00:00",
                "status": "aborted",
                "aborted": True,
                "findings": [],
            }), encoding="utf-8")

            # Normal completed persisted evidence
            d_done = tmp_base / "scan_done"
            d_done.mkdir(parents=True)
            (d_done / "report.html").write_text("<html>rpt</html>", encoding="utf-8")
            (d_done / "evidence.json").write_text(json.dumps({
                "target": "http://127.0.0.1:9/target",
                "scan_date": "2026-10-19T02:00:00",
                "status": "done",
                "aborted": False,
                "findings": [],
            }), encoding="utf-8")

            # Legacy persisted evidence without status/aborted
            d_legacy = tmp_base / "scan_legacy"
            d_legacy.mkdir(parents=True)
            (d_legacy / "report.html").write_text("<html>rpt</html>", encoding="utf-8")
            (d_legacy / "evidence.json").write_text(json.dumps({
                "target": "http://127.0.0.1:9/target",
                "scan_date": "2026-10-19T03:00:00",
                "findings": [],
            }), encoding="utf-8")

            client = TestClient(monitor.app)
            resp = client.get("/api/v1/scans")
            self.assertEqual(resp.status_code, 200)
            scans_by_id = {s["id"]: s for s in resp.json().get("scans", [])}

            self.assertEqual(scans_by_id["scan_aborted"]["status"], "aborted")
            self.assertEqual(scans_by_id["scan_done"]["status"], "done")
            self.assertEqual(scans_by_id["scan_legacy"]["status"], "done")
        finally:
            monitor_mod.OUTPUT_BASE = orig_base
            shutil.rmtree(tmp_base, ignore_errors=True)


class ScanFindingMetricsContractTests(unittest.TestCase):
    def setUp(self):
        self.monitor = MonitorServer(port=0)
        self.client = TestClient(self.monitor.app)
        self.monitor.api_scan_id = "metrics-test-scan"
        self.monitor.api_scan_status = "scanning"

    def test_empty_findings_contract(self):
        self.monitor.api_findings = []

        status_res = self.client.get("/api/v1/scan/status").json()
        findings_res = self.client.get("/api/v1/scan/findings").json()
        results_res = self.client.get("/api/v1/scan/results").json()

        for res in (status_res, findings_res, results_res):
            self.assertEqual(res["total_findings_count"], 0)
            self.assertEqual(res["confirmed_findings_count"], 0)
            self.assertEqual(res["hypothesis_count"], 0)

        # Legacy behavior
        self.assertEqual(status_res["findings_count"], 0)
        self.assertEqual(findings_res["findings_count"], 0)
        self.assertEqual(results_res["findings_count"], 0)
        self.assertEqual(results_res["findings"], [])

    def test_hypothetical_assumed_finding_contract_1_0_1(self):
        # 1 assumed finding: total=1, confirmed=0, hypothesis=1
        self.monitor.api_findings = [
            {
                "id": "f_assumed",
                "check_type": "xss",
                "severity": "high",
                "verified": False,
                "verification_state": "assumed",
            }
        ]

        status_res = self.client.get("/api/v1/scan/status").json()
        findings_res = self.client.get("/api/v1/scan/findings").json()
        results_res = self.client.get("/api/v1/scan/results").json()

        # Explicit parallel metrics match across all 3 endpoints
        for res in (status_res, findings_res, results_res):
            self.assertEqual(res["total_findings_count"], 1)
            self.assertEqual(res["confirmed_findings_count"], 0)
            self.assertEqual(res["hypothesis_count"], 1)

        # Legacy findings_count semantics preserved
        self.assertEqual(status_res["findings_count"], 1)
        self.assertEqual(findings_res["findings_count"], 1)
        self.assertEqual(results_res["findings_count"], 0)  # results only counts confirmed for CI/CD

        # Findings lists remain unpruned
        self.assertEqual(len(findings_res["findings"]), 1)
        self.assertEqual(len(results_res["findings"]), 1)

    def test_confirmed_reproduced_finding_contract_1_1_0(self):
        # 1 reproduced finding: total=1, confirmed=1, hypothesis=0
        self.monitor.api_findings = [
            {
                "id": "f_reproduced",
                "check_type": "sqli",
                "severity": "critical",
                "verified": True,
                "verification_state": "reproduced",
            }
        ]

        status_res = self.client.get("/api/v1/scan/status").json()
        findings_res = self.client.get("/api/v1/scan/findings").json()
        results_res = self.client.get("/api/v1/scan/results").json()

        for res in (status_res, findings_res, results_res):
            self.assertEqual(res["total_findings_count"], 1)
            self.assertEqual(res["confirmed_findings_count"], 1)
            self.assertEqual(res["hypothesis_count"], 0)

        # Legacy findings_count matches confirmed in this case
        self.assertEqual(status_res["findings_count"], 1)
        self.assertEqual(findings_res["findings_count"], 1)
        self.assertEqual(results_res["findings_count"], 1)
        self.assertEqual(results_res["critical_count"], 1)

    def test_mixed_findings_and_legacy_fallback(self):
        # 1 reproduced + 2 assumed + 1 legacy dict without state (defaults to confirmed)
        self.monitor.api_findings = [
            {
                "id": "f1",
                "check_type": "sqli",
                "severity": "critical",
                "verified": True,
                "verification_state": "reproduced",
            },
            {
                "id": "f2",
                "check_type": "xss",
                "severity": "high",
                "verified": False,
                "verification_state": "assumed",
            },
            {
                "id": "f3",
                "check_type": "rce",
                "severity": "critical",
                "source": "agent",
                "verified": False,
                "verification_state": "assumed",
            },
            {
                "id": "f4_legacy",
                "check_type": "header",
                "severity": "low",
                # No verification_state or verified bool -> legacy confirmed fallback
            },
        ]

        status_res = self.client.get("/api/v1/scan/status").json()
        findings_res = self.client.get("/api/v1/scan/findings").json()
        results_res = self.client.get("/api/v1/scan/results").json()

        # Total = 4, confirmed = 2 (f1, f4_legacy), hypothesis = 2 (f2, f3)
        for res in (status_res, findings_res, results_res):
            self.assertEqual(res["total_findings_count"], 4)
            self.assertEqual(res["confirmed_findings_count"], 2)
            self.assertEqual(res["hypothesis_count"], 2)

        # Legacy findings_count semantics
        self.assertEqual(status_res["findings_count"], 4)
        self.assertEqual(findings_res["findings_count"], 4)
        self.assertEqual(results_res["findings_count"], 2)


class DashboardConsistencyContractTests(unittest.TestCase):
    def setUp(self):
        self.monitor = MonitorServer(port=0)
        self.monitor.api_scan_id = "test-consistency"
        self.monitor._begin_scan_snapshot()
        self.client = TestClient(self.monitor.app)

    def test_websocket_snapshot_exposes_explicit_finding_counts_and_aborted(self):
        self.monitor.api_findings = [
            {
                "id": "f_reproduced",
                "check_type": "sqli",
                "severity": "critical",
                "verified": True,
                "verification_state": "reproduced",
            },
            {
                "id": "f_assumed",
                "check_type": "xss",
                "severity": "high",
                "verified": False,
                "verification_state": "assumed",
            },
        ]
        self.monitor.api_scan_status = "aborted"

        with self.client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()

        data = snapshot["data"]
        self.assertEqual(data["total_findings_count"], 2)
        self.assertEqual(data["confirmed_findings_count"], 1)
        self.assertEqual(data["hypothesis_count"], 1)
        self.assertEqual(data["findings_count"], 2)
        self.assertTrue(data["aborted"])
        self.assertEqual(data["status"], "aborted")

    def test_scan_gap_and_observability_coverage_consistency(self):
        import asyncio
        asyncio.run(
            self.monitor.emit_scan_gap(
                url="http://127.0.0.1:9/unreachable",
                field_name="(page)",
                check="access",
                location="navigation",
                note="Connection refused",
            )
        )

        status_res = self.client.get("/api/v1/scan/status").json()
        results_res = self.client.get("/api/v1/scan/results").json()

        self.assertEqual(status_res["scan_gap_count"], 1)
        self.assertEqual(len(status_res["scan_gaps"]), 1)
        self.assertEqual(status_res["scan_gaps"][0]["url"], "http://127.0.0.1:9/unreachable")
        self.assertEqual(results_res["scan_gap_count"], 1)

        with self.client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["scan_gap_count"], 1)
        self.assertEqual(len(snapshot["data"]["scan_gaps"]), 1)
        self.assertEqual(snapshot["data"]["url_statuses"]["http://127.0.0.1:9/unreachable"], "error")

    def test_scan_complete_preserves_field_progress_and_completion_percentage(self):
        import asyncio
        asyncio.run(self.monitor.emit_progress(current=42, total=42, message="Done testing"))
        asyncio.run(
            self.monitor.emit("scan_complete", {
                "total_findings": 0,
                "total_findings_count": 0,
                "confirmed_findings_count": 0,
                "hypothesis_count": 0,
                "status": "done",
            })
        )

        status_res = self.client.get("/api/v1/scan/status").json()
        self.assertEqual(status_res["status"], "done")
        self.assertEqual(status_res["progress"]["current"], 42)
        self.assertEqual(status_res["progress"]["total"], 42)
        self.assertEqual(status_res["progress"]["percent"], 100)

    def test_abort_endpoint_sets_status_aborting_and_marks_aborted_liveness(self):
        self.monitor.scan_in_progress = True
        self.monitor.api_scan_status = "scanning"

        r = self.client.post("/api/v1/scan/abort")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.json(), {"status": "aborting"})

        status_res = self.client.get("/api/v1/scan/status").json()
        self.assertEqual(status_res["status"], "aborting")
        self.assertTrue(status_res["aborted"])

        with self.client.websocket_connect("/ws") as ws:
            snapshot = ws.receive_json()
        self.assertEqual(snapshot["data"]["status"], "aborting")
        self.assertTrue(snapshot["data"]["aborted"])

    def test_phase_verify_does_not_clobber_attack_fields_progress(self):
        from unittest.mock import AsyncMock, patch
        from wscan.engine import ScanEngine
        from wscan.scanners.base import Finding, VerificationState

        engine = ScanEngine("http://127.0.0.1:9/target", monitor=self.monitor)
        engine.completed_fields = 50
        engine.total_fields = 50

        f = Finding.from_dict({
            "url": "http://127.0.0.1:9/target",
            "field_name": "q",
            "check_type": "xss",
            "payload": "<script>1</script>",
            "evidence": "alert",
            "evidence_type": "reflected",
            "severity": "high",
            "confidence": "firm",
            "verified": False,
            "verification_state": "assumed",
        })
        engine.all_findings = [f]

        import asyncio
        asyncio.run(self.monitor.emit_progress(current=50, total=50, message="attack complete"))
        with patch.object(engine, "_verify_one", AsyncMock(return_value="reproduced")), \
             patch.object(engine._browser, "init", AsyncMock()), \
             patch.object(engine._browser, "close", AsyncMock()):
            asyncio.run(engine._phase_verify())

        status_res = self.client.get("/api/v1/scan/status").json()
        self.assertEqual(status_res["progress"]["current"], 50)
        self.assertEqual(status_res["progress"]["total"], 50)
        self.assertEqual(status_res["progress"]["percent"], 100)
        self.assertEqual(status_res["total_findings_count"], 1)
        self.assertEqual(status_res["confirmed_findings_count"], 1)
        self.assertEqual(status_res["hypothesis_count"], 0)


if __name__ == "__main__":
    unittest.main()


