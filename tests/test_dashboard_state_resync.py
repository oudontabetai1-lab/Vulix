"""Regression coverage for dashboard state reconstruction after WebSocket reconnects."""
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
            for i in range(198):
                await cls.monitor.emit("status", {"message": f"fixture event {i}"})
            for _ in range(2):
                await cls.monitor.emit_page_start(cls.monitor.api_target)
                await cls.monitor.emit_payload_test("q", "fixture", "xss", cls.monitor.api_target)
            await cls.monitor.emit_finding({
                "url": cls.monitor.api_target, "field_name": "q", "check_type": "xss",
                "severity": "high", "confidence": "tentative", "payload": "fixture",
                "evidence": "fixture finding", "evidence_type": "reflected", "verified": False,
                "verification_state": "assumed",
            })
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        async def add_page(request: Request):
            await cls.monitor.emit_page_start(cls.monitor.api_target)
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
            await cls.monitor.emit_payload_test("id", "fixture", "sqli", cls.monitor.api_target)
            return {"run_id": cls.monitor._scan_run_id, "sequence": cls.monitor._scan_sequence}

        cls.monitor.app.add_api_route("/__test__/seed", seed, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/page", add_page, methods=["POST"])
        cls.monitor.app.add_api_route("/__test__/new-scan", new_scan, methods=["POST"])
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

            page.evaluate("() => { window.__oldSocket = state.ws; state.ws.close(); }")
            page.wait_for_function(
                """expected => state.ws !== window.__oldSocket && state.ws.readyState === WebSocket.OPEN &&
                    state.lastEventSequence === expected""",
                arg=seed["sequence"], timeout=10000,
            )
            self.assertEqual(page.locator("#statPages").inner_text(), "2")
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)

            old_run_id = page.evaluate("state.scanRunId")
            old_sequence = page.evaluate("state.lastEventSequence")
            page.reload(wait_until="domcontentloaded")
            page.wait_for_function(
                """expected => state.scanRunId && state.lastEventSequence === expected &&
                    state.pageCount === 2 && state.checkCounts.xss === 2 && state.findingCount === 1 &&
                    state.paused === true""",
                arg=seed["sequence"], timeout=10000,
            )
            self.assertEqual(page.locator("#statPages").inner_text(), "2")
            self.assertEqual(page.locator("#findingsPanel .finding-card").count(), 1)

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
            browser.close()


if __name__ == "__main__":
    unittest.main()
