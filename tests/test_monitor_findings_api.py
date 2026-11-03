"""Unit tests for the scan findings read API (/api/v1/scans/{scan_id}/findings)."""
import json
import tempfile
from pathlib import Path
import unittest

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer


class ScanFindingsApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = tempfile.TemporaryDirectory()
        self.output_base = Path(self.tmp_dir.name)

        # Patch OUTPUT_BASE on monitor module
        import wscan.monitor as m
        self._orig_output_base = m.OUTPUT_BASE
        m.OUTPUT_BASE = self.output_base

        self.server = MonitorServer()
        self.client = TestClient(self.server.app)

    def tearDown(self):
        import wscan.monitor as m
        m.OUTPUT_BASE = self._orig_output_base
        self.tmp_dir.cleanup()

    def test_scan_not_found_returns_404(self):
        res = self.client.get("/api/v1/scans/nonexistent-scan-id/findings")
        self.assertEqual(res.status_code, 404)
        data = res.json()
        self.assertEqual(data.get("error"), "not found")

    def test_scan_without_evidence_json_returns_unavailable(self):
        scan_dir = self.output_base / "scan-incomplete"
        scan_dir.mkdir(parents=True)
        # scan directory exists but evidence.json does not

        res = self.client.get("/api/v1/scans/scan-incomplete/findings")
        self.assertEqual(res.status_code, 404)
        data = res.json()
        self.assertFalse(data.get("findings_available"))
        self.assertEqual(data.get("status"), "incomplete")

    def test_history_scan_findings_from_evidence_json(self):
        scan_dir = self.output_base / "20261103-100000"
        scan_dir.mkdir(parents=True)
        evidence_file = scan_dir / "evidence.json"

        findings = [
            {
                "check_type": "xss",
                "severity": "high",
                "url": "http://example.com/search",
                "field_name": "q",
                "payload": "<script>alert(1)</script>",
                "evidence": "reflected",
                "verification_state": "reproduced",
                "verified": True,
                "source": "scanner",
            },
            {
                "check_type": "sqli",
                "severity": "critical",
                "url": "http://example.com/login",
                "field_name": "user",
                "payload": "' OR 1=1--",
                "evidence": "syntax error",
                "verification_state": "assumed",
                "verified": False,
                "source": "agent",
                "agent_verified": False,
            },
        ]

        evidence_content = {
            "target": "http://example.com",
            "status": "done",
            "findings": findings,
        }
        evidence_file.write_text(json.dumps(evidence_content), encoding="utf-8")

        res = self.client.get("/api/v1/scans/20261103-100000/findings")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertTrue(data.get("findings_available"))
        self.assertEqual(data.get("scan_id"), "20261103-100000")
        self.assertEqual(data.get("status"), "done")
        self.assertEqual(data.get("total_findings_count"), 2)
        self.assertEqual(data.get("findings_count"), 2)
        self.assertEqual(data.get("confirmed_findings_count"), 1)
        self.assertEqual(data.get("hypothesis_count"), 1)

        returned_findings = data.get("findings")
        self.assertEqual(len(returned_findings), 2)
        self.assertEqual(returned_findings[0]["check_type"], "xss")
        self.assertEqual(returned_findings[1]["check_type"], "sqli")
        self.assertEqual(returned_findings[1]["source"], "agent")
        self.assertFalse(returned_findings[1]["agent_verified"])

    def test_preflight_result_read_api(self):
        scan_dir = self.output_base / "scan-preflight"
        scan_dir.mkdir(parents=True)
        expected = {"schema_version": "1.0.0", "verdict": "warning", "checks": []}
        (scan_dir / "preflight.json").write_text(json.dumps(expected), encoding="utf-8")

        response = self.client.get("/api/v1/scans/scan-preflight/preflight")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), expected)

        missing = self.client.get("/api/v1/scans/scan-preflight/missing/preflight")
        self.assertEqual(missing.status_code, 404)

    def test_live_scan_findings_returned_when_in_progress(self):
        self.server.scan_in_progress = True
        self.server.current_scan_id = "live-scan-001"
        self.server.api_scan_status = "scanning"
        self.server.api_findings = [
            {
                "check_type": "os",
                "severity": "high",
                "url": "http://example.com/cmd",
                "field_name": "c",
                "payload": "; id",
                "evidence": "uid=0",
                "verification_state": "reproduced",
                "verified": True,
                "source": "scanner",
            }
        ]

        # Scan dir also exists
        scan_dir = self.output_base / "live-scan-001"
        scan_dir.mkdir(parents=True)

        res = self.client.get("/api/v1/scans/live-scan-001/findings")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data.get("scan_id"), "live-scan-001")
        self.assertEqual(data.get("status"), "scanning")
        self.assertEqual(len(data.get("findings")), 1)
        self.assertEqual(data.get("findings")[0]["check_type"], "os")

    def test_directory_traversal_rejected(self):
        res = self.client.get("/api/v1/scans/..%2Fetc/findings")
        self.assertIn(res.status_code, (400, 404))


if __name__ == "__main__":
    unittest.main()
