"""スキャン終端で status_message に進行中フェーズの文言を残さないことを検証する。"""
import asyncio
import unittest

from wscan.monitor import MonitorServer, _completion_status_message


class CompletionStatusMessageTests(unittest.TestCase):
    def test_terminal_message_per_status(self):
        self.assertEqual(_completion_status_message("done"), "Scan complete")
        self.assertEqual(
            _completion_status_message("aborted"),
            "Scan aborted (partial report)",
        )
        self.assertEqual(_completion_status_message("incomplete"), "Scan incomplete")
        self.assertEqual(_completion_status_message("error"), "Scan failed")
        self.assertEqual(_completion_status_message("unknown"), "Scan finished")

    def test_scan_complete_clears_stale_phase_message(self):
        monitor = MonitorServer(port=0)
        monitor._begin_scan_snapshot()

        async def run():
            await monitor.emit_status(
                "OS injection testing: q on http://127.0.0.1:1/search?q=hello",
                "running",
            )
            await monitor.emit("scan_complete", {"status": "done", "total_findings": 0})

        asyncio.run(run())
        snapshot = monitor._scan_snapshot_event()["data"]
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(snapshot["status_message"], "Scan complete")

    def test_aborted_scan_clears_stale_phase_message(self):
        monitor = MonitorServer(port=0)
        monitor._begin_scan_snapshot()

        async def run():
            await monitor.emit_status("XSS testing: q", "running")
            await monitor.emit(
                "scan_complete", {"status": "aborted", "aborted": True, "total_findings": 0}
            )

        asyncio.run(run())
        snapshot = monitor._scan_snapshot_event()["data"]
        self.assertEqual(snapshot["status"], "aborted")
        self.assertEqual(
            snapshot["status_message"], "Scan aborted (partial report)"
        )

    def test_error_completion_keeps_specific_failure_reason(self):
        monitor = MonitorServer(port=0)
        monitor._begin_scan_snapshot()

        async def run():
            await monitor.emit_status("スキャン中にエラーが発生しました: fixture", "error")
            await monitor.emit("scan_complete", {"status": "error", "total_findings": 0})

        asyncio.run(run())
        snapshot = monitor._scan_snapshot_event()["data"]
        self.assertEqual(snapshot["status"], "error")
        self.assertEqual(
            snapshot["status_message"], "スキャン中にエラーが発生しました: fixture"
        )

    def test_agent_completion_message_is_kept(self):
        monitor = MonitorServer(port=0)
        monitor._begin_scan_snapshot()

        asyncio.run(
            monitor.emit_status("Agent scan complete — 0 finding(s)", "done")
        )
        snapshot = monitor._scan_snapshot_event()["data"]
        self.assertEqual(snapshot["status"], "done")
        self.assertEqual(
            snapshot["status_message"], "Agent scan complete — 0 finding(s)"
        )
