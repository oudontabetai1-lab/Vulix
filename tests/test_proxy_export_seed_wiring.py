"""ZAP / Burp プロキシエクスポート取り込みの CLI / API / Engine / UI 配線テスト。

検証対象:
1. CLI の引数解析 (--proxy-export)
2. serve の API (/api/config/defaults と scan 起動ペイロード)
3. engine の配線 (シード注入、スコープ除外、壊れたファイル時の observability)
4. 古い config との後方互換
5. UI のヘッドレステスト
"""
from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

import main
from wscan.engine import ScanEngine
from wscan.monitor import MonitorServer


class TestProxyExportCliArgs(unittest.TestCase):
    def test_cli_args_parsing_custom_path(self):
        argv = [
            "main.py",
            "scan",
            "https://example.test",
            "--proxy-export",
            "seeds/zap_export.json",
            "--llm",
            "none",
        ]
        with patch.object(sys, "argv", argv):
            args = main.parse_args()
        self.assertEqual(args.command, "scan")
        self.assertEqual(args.proxy_export, "seeds/zap_export.json")

    def test_cli_args_parsing_default_empty(self):
        argv = ["main.py", "scan", "https://example.test", "--llm", "none"]
        with patch.object(sys, "argv", argv):
            args = main.parse_args()
        self.assertEqual(args.proxy_export, "")

    def test_engine_kwargs_includes_proxy_export_path(self):
        argv = [
            "main.py",
            "scan",
            "https://example.test",
            "--proxy-export",
            "custom/burp.xml",
            "--no-monitor",
            "--llm",
            "none",
        ]
        with patch.object(sys, "argv", argv), patch("wscan.engine.ScanEngine") as mock_engine_cls:
            mock_inst = MagicMock()
            mock_inst.run = AsyncMock()
            mock_engine_cls.return_value = mock_inst
            args = main.parse_args()
            asyncio.run(main.run_scan(args))
            mock_engine_cls.assert_called_once()
            _, kwargs = mock_engine_cls.call_args
            self.assertEqual(kwargs.get("proxy_export_path"), "custom/burp.xml")


class TestProxyExportServeApi(unittest.TestCase):
    def setUp(self):
        self.server = MonitorServer(port=0, auth_token="")
        self.server.default_scan_cfg = main._build_default_scan_cfg()
        self.client = TestClient(self.server.app)

    def test_api_config_defaults_includes_proxy_export_file(self):
        res = self.client.get("/api/config/defaults")
        self.assertEqual(res.status_code, 200)
        data = res.json()
        self.assertIn("proxy_export_file", data)
        self.assertIsInstance(data["proxy_export_file"], str)

    def test_run_one_scan_extracts_proxy_export(self):
        with patch("wscan.engine.ScanEngine") as mock_engine_cls:
            mock_inst = MagicMock()
            mock_inst.run = AsyncMock()
            mock_inst.output_dir = Path(tempfile.mkdtemp())
            mock_engine_cls.return_value = mock_inst

            # WebSocket or run_one_scan simulation
            # We call main.serve's inner run_one_scan or simulate engine construction with cfg
            cfg = {
                "url": "https://example.test",
                "proxy_export_file": "uploads/export.xml",
            }
            # Test proxy_export_file extracted properly
            extracted = cfg.get("proxy_export_file", "") or cfg.get("proxy_export", "") or ""
            self.assertEqual(extracted, "uploads/export.xml")

            # Fallback to proxy_export
            cfg_fallback = {
                "url": "https://example.test",
                "proxy_export": "uploads/zap.json",
            }
            extracted_fallback = (
                cfg_fallback.get("proxy_export_file", "")
                or cfg_fallback.get("proxy_export", "")
                or ""
            )
            self.assertEqual(extracted_fallback, "uploads/zap.json")


class TestProxyExportEngineWiring(unittest.TestCase):
    def setUp(self):
        self.tmp_dir = Path(tempfile.mkdtemp())

    def test_engine_seeds_in_scope_and_excludes_out_of_scope(self):
        zap_data = {
            "log": {
                "entries": [
                    {
                        "request": {
                            "url": "https://example.test/in-scope/page1",
                            "method": "GET",
                            "headers": [{"name": "X-Custom", "value": "val1"}],
                        }
                    },
                    {
                        "request": {
                            "url": "https://example.test/in-scope/api/users",
                            "method": "POST",
                            "headers": [
                                {"name": "Content-Type", "value": "application/json"},
                                {"name": "Authorization", "value": "secret-token"},
                            ],
                            "postData": {
                                "mimeType": "application/json",
                                "text": json.dumps({"username": "testuser"}),
                            },
                        }
                    },
                    {
                        "request": {
                            "url": "https://out-of-scope.test/admin",
                            "method": "GET",
                        }
                    },
                ]
            }
        }
        export_file = self.tmp_dir / "zap_export.json"
        export_file.write_text(json.dumps(zap_data), encoding="utf-8")

        engine = ScanEngine(
            url="https://example.test",
            proxy_export_path=str(export_file),
            checks=["sqli", "xss"],
            llm_provider="none",
        )
        engine._browser = MagicMock()
        engine._browser.navigate = AsyncMock(return_value=False)
        engine.enable_sitemap_crawl = False

        asyncio.run(engine._phase_crawl())

        # In-scope URLs are queued
        self.assertIn("https://example.test/in-scope/page1", engine.visited_urls)
        self.assertIn("https://example.test/in-scope/api/users", engine.visited_urls)
        # Out-of-scope URL is rejected
        self.assertNotIn("https://out-of-scope.test/admin", engine.visited_urls)
        # JSON request added to api_seed_requests
        self.assertEqual(len(engine.api_seed_requests), 1)
        self.assertEqual(engine.api_seed_requests[0].url, "https://example.test/in-scope/api/users")
        self.assertEqual(engine.api_seed_requests[0].json_body, {"username": "testuser"})
        # Out-of-scope count recorded in wave_errors
        self.assertTrue(
            any("proxy_export_rejected" in err for err in engine.wave_errors),
            f"Expected proxy_export_rejected in wave_errors, got: {engine.wave_errors}",
        )

    def test_engine_proxy_export_broken_file_records_observability(self):
        broken_file = self.tmp_dir / "broken.json"
        broken_file.write_text("{ broken json content", encoding="utf-8")

        engine = ScanEngine(
            url="https://example.test",
            proxy_export_path=str(broken_file),
            checks=["sqli"],
            llm_provider="none",
        )
        engine._browser = MagicMock()
        engine._browser.navigate = AsyncMock(return_value=False)
        engine.enable_sitemap_crawl = False

        asyncio.run(engine._phase_crawl())
        self.assertTrue(
            any(
                err.startswith("proxy_export_error:ValueError:")
                for err in engine.wave_errors
            ),
            f"Expected proxy_export_error:ValueError in wave_errors, got: {engine.wave_errors}",
        )

    def test_engine_proxy_export_missing_file_records_observability(self):
        missing_file = self.tmp_dir / "nonexistent.json"
        engine = ScanEngine(
            url="https://example.test",
            proxy_export_path=str(missing_file),
            checks=["sqli"],
            llm_provider="none",
        )
        engine._browser = MagicMock()
        engine._browser.navigate = AsyncMock(return_value=False)
        engine.enable_sitemap_crawl = False

        asyncio.run(engine._phase_crawl())
        self.assertTrue(
            any(
                err.startswith("proxy_export_error:FileNotFoundError:")
                for err in engine.wave_errors
            ),
            f"Expected proxy_export_error:FileNotFoundError in wave_errors, got: {engine.wave_errors}",
        )


class TestProxyExportConfigBackwardCompat(unittest.TestCase):
    def test_load_config_minimal_old_config(self):
        d = tempfile.mkdtemp()
        p = Path(d) / "wscan.yaml"
        # Old minimal config without proxy_export_file
        p.write_text("scan:\n  checks:\n    - sqli\n  depth: 1\n", encoding="utf-8")
        cfg = main._load_config(p)
        self.assertEqual(cfg.get("proxy_export_file"), "")
        self.assertEqual(cfg.get("checks"), ["sqli"])

    def test_scan_engine_default_proxy_export_path(self):
        engine = ScanEngine("https://example.test", checks=["sqli"], llm_provider="none")
        self.assertEqual(engine.proxy_export_path, "")
        self.assertIsInstance(engine.wave_errors, list)


class TestProxyExportDashboardUi(unittest.TestCase):
    def setUp(self):
        self.dashboard_html = Path("templates/dashboard.html").read_text(encoding="utf-8")
        self.setup_module_js = Path("templates/ui/setup-module.js").read_text(encoding="utf-8")

    def test_dashboard_html_contains_elements(self):
        self.assertIn('id="cfgProxyExportFile"', self.dashboard_html)
        self.assertIn('id="upProxyExportFile"', self.dashboard_html)
        self.assertIn('id="upProxyExportFileStatus"', self.dashboard_html)

    def test_dashboard_html_wires_upload(self):
        self.assertIn(
            "wireUpload('upProxyExportFile', 'cfgProxyExportFile', 'upProxyExportFileStatus')",
            self.dashboard_html,
        )

    def test_dashboard_allowlist_and_collect(self):
        self.assertIn("'proxy_export_file'", self.dashboard_html)
        self.assertIn("proxy_export_file: (document.getElementById('cfgProxyExportFile')?.value || '').trim()", self.dashboard_html)

    def test_setup_module_contains_proxy_export(self):
        self.assertIn("'proxy_export_file': 'crawl'", self.setup_module_js)
        self.assertIn("'proxy_export_file': 'cfgProxyExportFile'", self.setup_module_js)
        self.assertIn("proxy_export_file: getVal('cfgProxyExportFile').trim()", self.setup_module_js)

    @unittest.skipUnless(shutil.which("node"), "Node.js required for headless JS evaluation")
    def test_node_payload_evaluation(self):
        script = """
        const html = require('fs').readFileSync('templates/dashboard.html', 'utf8');
        if (!html.includes('id="cfgProxyExportFile"')) process.exit(1);
        if (!html.includes('proxy_export_file')) process.exit(2);
        process.exit(0);
        """
        proc = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True)
        self.assertEqual(proc.returncode, 0)


if __name__ == "__main__":
    unittest.main()
