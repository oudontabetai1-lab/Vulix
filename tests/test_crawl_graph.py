"""Tests for the crawl graph snapshot API and pure projection function."""
from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from typing import Any

from fastapi.testclient import TestClient

import wscan.monitor as monitor_mod
from wscan.crawl_graph import (
    SCHEMA_VERSION,
    determine_completeness,
    generate_node_id,
    normalize_node_kind,
    project_crawl_graph,
)
from wscan.monitor import MonitorServer


class CrawlGraphProjectionTests(unittest.TestCase):
    """Unit tests for the pure projection function (no I/O)."""

    def test_deterministic_ids(self):
        """Test that node IDs are derived deterministically and stably."""
        url_a = "http://example.com/items?category=books"
        url_b = "http://example.com/login"

        id1 = generate_node_id("page", url_a)
        id2 = generate_node_id("page", url_a)
        self.assertEqual(id1, id2)
        self.assertTrue(id1.startswith("page_"))

        # Form and param IDs are also deterministic
        form_id1 = generate_node_id("form", url_b, "0")
        form_id2 = generate_node_id("form", url_b, "0")
        self.assertEqual(form_id1, form_id2)
        self.assertTrue(form_id1.startswith("form_"))

        param_id1 = generate_node_id("param", url_a, "query:category")
        param_id2 = generate_node_id("param", url_a, "query:category")
        self.assertEqual(param_id1, param_id2)
        self.assertTrue(param_id1.startswith("param_"))

        # Reordering inputs produces identical node IDs in the projected graph
        data1 = {
            "page_graph": {
                url_a: {"depth": 0, "forms": 0, "params": 1},
                url_b: {"depth": 1, "parent": url_a, "forms": 1, "params": 0},
            }
        }
        data2 = {
            "page_graph": {
                url_b: {"depth": 1, "parent": url_a, "forms": 1, "params": 0},
                url_a: {"depth": 0, "forms": 0, "params": 1},
            }
        }
        proj1 = project_crawl_graph(data1)
        proj2 = project_crawl_graph(data2)
        self.assertEqual(
            [n["id"] for n in proj1["nodes"]],
            [n["id"] for n in proj2["nodes"]],
        )
        self.assertEqual(proj1["edges"], proj2["edges"])

    def test_redaction_userinfo_and_query_secrets(self):
        """Test that user credentials, secret query params, and tokens are redacted."""
        raw_url = "http://admin:super_secret_pw@example.com/dashboard?token=tok_123456&client_secret=s3cr3t#access_token=frag_token_789"
        data = {
            "target_url": raw_url,
            "page_graph": {
                raw_url: {
                    "depth": 0,
                    "forms": 1,
                    "params": 2,
                }
            },
            "pages": [
                {
                    "url": raw_url,
                    "depth": 0,
                    "forms": 1,
                    "params": 2,
                    "param_names": ["token", "client_secret"],
                    "form_details": [
                        {
                            "action": raw_url,
                            "method": "post",
                            "fields": [{"name": "password", "type": "password"}],
                        }
                    ],
                }
            ],
            "findings": [
                {
                    "id": "f-1",
                    "url": raw_url,
                    "field_name": "token",
                    "check_type": "xss",
                    "severity": "high",
                }
            ],
        }
        proj = project_crawl_graph(data)

        # Target URL redacted
        self.assertNotIn("super_secret_pw", proj["target_url"])
        self.assertNotIn("tok_123456", proj["target_url"])
        self.assertNotIn("s3cr3t", proj["target_url"])
        self.assertNotIn("frag_token_789", proj["target_url"])
        self.assertIn("<redacted>@", proj["target_url"])
        self.assertIn("token=<redacted>", proj["target_url"])

        # Nodes redaction
        for node in proj["nodes"]:
            url_str = node.get("url", "")
            self.assertNotIn("super_secret_pw", url_str)
            self.assertNotIn("tok_123456", url_str)
            self.assertNotIn("s3cr3t", url_str)
            self.assertNotIn("frag_token_789", url_str)

            for act in node.get("actions", []):
                self.assertNotIn("super_secret_pw", act.get("action", ""))
                self.assertNotIn("tok_123456", act.get("action", ""))

            for f_ref in node.get("findings", []):
                self.assertNotIn("super_secret_pw", f_ref.get("url", ""))
                self.assertNotIn("tok_123456", f_ref.get("url", ""))

    def test_completeness_states(self):
        """Test completeness transitions: partial, unknown, and complete."""
        # 1. In-progress -> partial
        proj_prog = project_crawl_graph({
            "status": "scanning",
            "phase": "crawl",
            "nodes": [{"kind": "page", "url": "http://example.com"}],
        })
        self.assertEqual(proj_prog["completeness"], "partial")
        self.assertIn("scan_in_progress", proj_prog["completeness_reasons"])

        # 2. Aborted -> partial
        proj_abort = project_crawl_graph({
            "status": "aborted",
            "aborted": True,
            "nodes": [{"kind": "page", "url": "http://example.com"}],
        })
        self.assertEqual(proj_abort["completeness"], "partial")
        self.assertIn("scan_aborted", proj_abort["completeness_reasons"])

        # 3. Gaps present -> partial
        proj_gaps = project_crawl_graph({
            "status": "done",
            "scan_gaps": [{"url": "http://example.com/err"}],
            "nodes": [{"kind": "page", "url": "http://example.com"}],
        })
        self.assertEqual(proj_gaps["completeness"], "partial")
        self.assertIn("scan_gaps_present", proj_gaps["completeness_reasons"])

        # 4. Truncation detected -> partial
        proj_trunc = project_crawl_graph({
            "status": "done",
            "truncation_counts": {"unit_key_1": 2},
            "nodes": [{"kind": "page", "url": "http://example.com"}],
        })
        self.assertEqual(proj_trunc["completeness"], "partial")
        self.assertIn("truncation_detected", proj_trunc["completeness_reasons"])

        # 5. Idle -> unknown
        proj_idle = project_crawl_graph({
            "status": "idle",
            "nodes": [{"kind": "page", "url": "http://example.com"}],
        })
        self.assertEqual(proj_idle["completeness"], "unknown")
        self.assertIn("scan_idle", proj_idle["completeness_reasons"])

        # 6. Complete -> complete
        proj_done = project_crawl_graph({
            "status": "done",
            "nodes": [{"kind": "page", "url": "http://example.com"}],
        })
        self.assertEqual(proj_done["completeness"], "complete")
        self.assertIn("scan_completed", proj_done["completeness_reasons"])

    def test_unknown_node_kinds_preserved_as_unknown(self):
        """Test that arbitrary or unclassified node kinds are preserved as 'unknown'."""
        self.assertEqual(normalize_node_kind("websocket"), "unknown")
        self.assertEqual(normalize_node_kind("custom_service"), "unknown")
        self.assertEqual(normalize_node_kind("PAGE"), "page")
        self.assertEqual(normalize_node_kind("FORM"), "form")
        self.assertEqual(normalize_node_kind("PARAM"), "param")

        data = {
            "status": "done",
            "nodes": [
                {
                    "id": "ws-1",
                    "kind": "websocket_endpoint",
                    "url": "ws://example.com/socket",
                    "label": "Live Socket",
                    "metadata": {"protocol": "json"},
                },
                {
                    "id": "page-1",
                    "kind": "page",
                    "url": "http://example.com/home",
                },
            ],
            "edges": [
                {"source": "page-1", "target": "ws-1", "kind": "connects_to"},
            ],
        }
        proj = project_crawl_graph(data)
        kinds = {n["kind"] for n in proj["nodes"]}
        self.assertIn("unknown", kinds)
        self.assertIn("page", kinds)
        self.assertEqual(proj["summary"]["unknown_count"], 1)

        # Unknown node attributes are retained and ID is in the unknown_ namespace
        unk_node = next(n for n in proj["nodes"] if n["kind"] == "unknown")
        self.assertTrue(unk_node["id"].startswith("unknown_"))
        self.assertEqual(unk_node["metadata"].get("original_kind"), "websocket_endpoint")
        self.assertEqual(unk_node["metadata"].get("protocol"), "json")

    def test_empty_scan(self):
        """Test that an empty scan produces a well-formed projection schema."""
        proj = project_crawl_graph({})
        self.assertEqual(proj["version"], SCHEMA_VERSION)
        self.assertEqual(proj["scan_id"], "")
        self.assertEqual(proj["target_url"], "")
        self.assertEqual(proj["completeness"], "unknown")
        self.assertIn("empty_scan", proj["completeness_reasons"])
        self.assertEqual(proj["nodes"], [])
        self.assertEqual(proj["edges"], [])
        self.assertEqual(proj["summary"]["total_nodes"], 0)
        self.assertEqual(proj["summary"]["pages_count"], 0)
        self.assertEqual(proj["summary"]["forms_count"], 0)
        self.assertEqual(proj["summary"]["params_count"], 0)
        self.assertEqual(proj["summary"]["unknown_count"], 0)
        self.assertEqual(proj["summary"]["total_edges"], 0)
        self.assertEqual(proj["summary"]["findings_count"], 0)


class CrawlGraphApiTests(unittest.TestCase):
    """Integration tests for the HTTP crawl graph endpoints and authentication."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self._orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp
        self.token = "auth_token_for_tests"
        self.srv = MonitorServer(port=0, auth_token=self.token)
        self.client = TestClient(self.srv.app)
        self.auth_headers = {"Authorization": f"Bearer {self.token}"}

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig_base

    def test_auth_enforced_on_endpoints(self):
        """Verify that requests without token receive 401."""
        res1 = self.client.get("/api/v1/scan/crawl-graph")
        self.assertEqual(res1.status_code, 401)

        res2 = self.client.get("/api/v1/scans/test_scan_id/crawl-graph")
        self.assertEqual(res2.status_code, 401)

    def test_active_scan_crawl_graph_endpoint(self):
        """Verify /api/v1/scan/crawl-graph returns live scan projection."""
        self.srv.api_scan_id = "live_scan_001"
        self.srv.api_target = "http://example.com/test"
        self.srv.api_scan_status = "scanning"
        self.srv.api_phase = "crawl"
        self.srv._scan_page_graph["http://example.com/test"] = {
            "depth": 0,
            "forms": 1,
            "inputs": 1,
            "params": 0,
        }

        res = self.client.get("/api/v1/scan/crawl-graph", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scan_id"], "live_scan_001")
        self.assertEqual(data["completeness"], "partial")
        self.assertIn("scan_in_progress", data["completeness_reasons"])
        self.assertEqual(len(data["nodes"]), 1)
        self.assertEqual(data["nodes"][0]["url"], "http://example.com/test")

    def test_historical_scan_crawl_graph_endpoint(self):
        """Verify /api/v1/scans/{scan_id}/crawl-graph loads and projects saved scan data."""
        import json

        scan_dir = self.tmp / "scan_hist_001"
        scan_dir.mkdir(parents=True, exist_ok=True)

        evidence = {
            "target": "http://history.example.com",
            "status": "done",
            "visited_urls": [
                "http://history.example.com/",
                "http://history.example.com/about",
            ],
            "findings": [
                {
                    "id": "f_1",
                    "url": "http://history.example.com/about",
                    "field_name": "q",
                    "check_type": "xss",
                    "severity": "medium",
                }
            ],
            "attack_plans": [
                {
                    "url": "http://history.example.com/about",
                    "page_purpose": "About company",
                    "fields": [{"name": "q"}],
                }
            ],
        }
        (scan_dir / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")

        res = self.client.get("/api/v1/scans/scan_hist_001/crawl-graph", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scan_id"], "scan_hist_001")
        self.assertEqual(data["completeness"], "complete")
        self.assertEqual(data["summary"]["pages_count"], 2)

        about_node = next(n for n in data["nodes"] if n["url"] == "http://history.example.com/about")
        self.assertEqual(len(about_node["findings"]), 1)
        self.assertEqual(about_node["findings"][0]["check_type"], "xss")

    def test_nonexistent_scan_id_returns_404(self):
        """Verify that requesting a missing scan returns 404."""
        res = self.client.get("/api/v1/scans/nonexistent_scan_xyz/crawl-graph", headers=self.auth_headers)
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json(), {"error": "not found"})

    def test_historical_scan_crawl_graph_findings_absent_backward_compatibility(self):
        """Verify data['findings'] defaults to [] and findings_available is preserved when absent."""
        import json

        scan_dir = self.tmp / "scan_findings_absent"
        scan_dir.mkdir(parents=True, exist_ok=True)

        evidence = {
            "target": "http://history.example.com",
            "status": "done",
            "findings_available": False,
            "visited_urls": ["http://history.example.com/"],
        }
        (scan_dir / "evidence.json").write_text(json.dumps(evidence), encoding="utf-8")

        loaded = self.srv._load_crawl_graph_data_from_dir(scan_dir, "scan_findings_absent")
        self.assertEqual(loaded["findings"], [])
        self.assertIs(loaded["findings_available"], False)

        res = self.client.get("/api/v1/scans/scan_findings_absent/crawl-graph", headers=self.auth_headers)
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertEqual(data["scan_id"], "scan_findings_absent")
        for node in data["nodes"]:
            self.assertFalse(node.get("findings_available", True))


if __name__ == "__main__":
    unittest.main()
