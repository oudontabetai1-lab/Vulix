"""Tests for the /app default shell integration:
1. Route compatibility (/, /monitor, /reports/*, key APIs unchanged).
2. Serve command output points to /app.
3. Legacy pages link clearly to /app.
4. Navigation entries in /app resolve to registered views or an explicit unavailable state.
5. No traffic view is registered or linked in /app.
"""
from __future__ import annotations

import ast
import asyncio
from argparse import Namespace
import io
import json
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

import pytest
from fastapi.testclient import TestClient

import main
import wscan.monitor as monitor_mod
from wscan.monitor import MonitorServer

ROOT = Path(__file__).resolve().parents[1]
APP_HTML = ROOT / "templates" / "app.html"
APP_ENTRY_JS = ROOT / "templates" / "ui" / "app-entry.js"
PORTAL_HTML = ROOT / "templates" / "portal.html"
DASHBOARD_HTML = ROOT / "templates" / "dashboard.html"


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


class TestRoutesCompatibility:
    """Verify legacy entry points, reports, and key APIs keep their exact routes and responses."""

    @pytest.fixture(autouse=True)
    def setup_server_with_fixture_scan(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wscan_routes_compat_test_"))
        self._orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp

        # Seed sample scan fixture
        self.scan_id = "20261104_100000"
        scan_dir = self.tmp / self.scan_id
        scan_dir.mkdir(parents=True)
        (scan_dir / "report.html").write_text(
            "<!DOCTYPE html><html><body><h1>Scan Report 20261104_100000</h1></body></html>",
            encoding="utf-8",
        )
        (scan_dir / "evidence.json").write_text(
            json.dumps({
                "target": "https://example.test",
                "scan_date": "2026-11-04T10:00:00",
                "findings": [{"id": "f_1", "severity": "high", "check_type": "xss"}],
            }),
            encoding="utf-8",
        )

        self.server = MonitorServer(port=0, auth_token="")
        self.client = TestClient(self.server.app)

        yield

        monitor_mod.OUTPUT_BASE = self._orig_base
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_legacy_pages_return_200_and_expected_markup(self):
        # / (portal)
        resp_portal = self.client.get("/")
        assert resp_portal.status_code == 200
        assert "Server Portal" in resp_portal.text
        assert "text/html" in resp_portal.headers.get("content-type", "")

        # /monitor (dashboard)
        resp_monitor = self.client.get("/monitor")
        assert resp_monitor.status_code == 200
        assert "ライブモニター" in resp_monitor.text
        assert "scanConfigOverlay" in resp_monitor.text

        # /app (unified shell)
        resp_app = self.client.get("/app")
        assert resp_app.status_code == 200
        assert "Vulix" in resp_app.text
        assert "app-entry.js" in resp_app.text

    def test_reports_endpoint_backward_compatibility(self):
        # /reports/{scan_id}/report.html
        resp_report = self.client.get(f"/reports/{self.scan_id}/report.html")
        assert resp_report.status_code == 200
        assert "Scan Report 20261104_100000" in resp_report.text

        # /reports/{scan_id}/ (trailing slash defaults to report.html)
        resp_report_slash = self.client.get(f"/reports/{self.scan_id}/")
        assert resp_report_slash.status_code == 200
        assert "Scan Report 20261104_100000" in resp_report_slash.text

        # /reports/{scan_id}/evidence.json
        resp_evidence = self.client.get(f"/reports/{self.scan_id}/evidence.json")
        assert resp_evidence.status_code == 200
        data = resp_evidence.json()
        assert data["target"] == "https://example.test"
        assert len(data["findings"]) == 1

        # Unknown scan returns 404
        assert self.client.get("/reports/nonexistent/report.html").status_code == 404

    def test_key_apis_backward_compatibility(self):
        # GET /api/v1/scans
        resp_scans = self.client.get("/api/v1/scans")
        assert resp_scans.status_code == 200
        scans_data = resp_scans.json()
        assert "scans" in scans_data
        assert any(s["id"] == self.scan_id for s in scans_data["scans"])

        # GET /api/v1/scan/status
        resp_status = self.client.get("/api/v1/scan/status")
        assert resp_status.status_code == 200
        status_data = resp_status.json()
        assert "status" in status_data
        assert "scan_id" in status_data

        # GET /api/config/defaults
        self.server.default_scan_cfg = {"checks": ["sqli", "xss"], "depth": 2, "timeout": 30}
        resp_defaults = self.client.get("/api/config/defaults")
        assert resp_defaults.status_code == 200
        defaults_data = resp_defaults.json()
        assert "checks" in defaults_data
        assert "depth" in defaults_data
        assert "timeout" in defaults_data

        # GET /api/v1/capability-manifest
        resp_manifest = self.client.get("/api/v1/capability-manifest")
        assert resp_manifest.status_code == 200
        manifest_data = resp_manifest.json()
        assert "scanners" in manifest_data or "categories" in manifest_data

        # GET /api/v1/settings
        resp_settings = self.client.get("/api/v1/settings")
        assert resp_settings.status_code == 200
        settings_data = resp_settings.json()
        assert "notifications" in settings_data

        # GET /api/v1/schedules
        resp_schedules = self.client.get("/api/v1/schedules")
        assert resp_schedules.status_code == 200
        schedules_data = resp_schedules.json()
        assert "schedules" in schedules_data

        # GET /api/v1/audit
        resp_audit = self.client.get("/api/v1/audit")
        assert resp_audit.status_code == 200
        audit_data = resp_audit.json()
        assert "audit" in audit_data


class TestServeOutputAndDefaults:
    """Verify serve command outputs and opens the /app URL."""

    def test_serve_source_code_points_to_app(self):
        source = Path("main.py").read_text(encoding="utf-8")
        parsed = ast.parse(source)

        run_serve_node = None
        for node in ast.walk(parsed):
            if isinstance(node, ast.AsyncFunctionDef) and node.name == "run_serve":
                run_serve_node = node
                break

        assert run_serve_node is not None, "run_serve async function not found in main.py"

        # Check that /app is present in the printed panel string
        run_serve_source = ast.get_source_segment(source, run_serve_node)
        assert ":{port}/app" in run_serve_source
        assert "{lan_ip}:{port}/app" in run_serve_source
        assert "webbrowser.open(f\"http://localhost:{port}/app\")" in run_serve_source

    def test_serve_banner_output_contains_app(self, monkeypatch):
        captured_panels = []

        class DummyConsole:
            def print(self, *args, **kwargs):
                for arg in args:
                    if hasattr(arg, "renderable"):
                        captured_panels.append(str(arg.renderable))
                    else:
                        captured_panels.append(str(arg))

        class ServerExit(Exception):
            pass

        def dummy_config(*, app, **kwargs):
            raise ServerExit

        monkeypatch.setattr("uvicorn.Config", dummy_config)
        monkeypatch.setattr("rich.console.Console", DummyConsole)

        with pytest.raises(ServerExit):
            asyncio.run(main.run_serve(Namespace(port=8765, host="127.0.0.1", auth_token="")))

        panel_text = "\n".join(captured_panels)
        assert "http://127.0.0.1:8765/app" in panel_text
        assert "http://localhost:8765/app" in panel_text


class TestLegacyPagesLinkToApp:
    """Verify legacy portal and monitor pages contain clear links to /app."""

    def test_portal_html_contains_clear_link_to_app(self):
        html = PORTAL_HTML.read_text(encoding="utf-8")
        assert 'href="/app"' in html
        assert "新ダッシュボード" in html
        # Both header and main section offer access
        assert 'id="appDashboardLink"' in html
        assert 'id="bannerAppDashboardLink"' in html

    def test_dashboard_html_contains_clear_link_to_app(self):
        html = DASHBOARD_HTML.read_text(encoding="utf-8")
        assert 'href="/app"' in html
        assert "新ダッシュボード" in html
        # Header and rail links exist with target="_top" so clicking inside iframe opens full view
        assert 'id="hdrAppDashboardLink"' in html
        assert 'id="railAppDashboardLink"' in html
        assert 'target="_top"' in html


class TestAppNavigationResolutionAndTrafficAbsence:
    """Verify every /app navigation item resolves properly and traffic is absent."""

    def test_all_navigation_buttons_have_matching_routes(self):
        html = APP_HTML.read_text(encoding="utf-8")
        matches = re.findall(r'data-route="([^"]+)"', html)
        assert len(matches) >= 8, f"Expected at least 8 navigation items in app.html, found: {matches}"

        expected_routes = {
            "portal",
            "history",
            "audit",
            "setup",
            "monitor",
            "findings",
            "crawl",
            "agent-skills",
            "settings",
        }
        actual_routes = set(matches)
        assert actual_routes == expected_routes

    def test_route_resolution_pure_function(self):
        script = f"""
        const fs = require('fs');
        const code = fs.readFileSync('{APP_ENTRY_JS}', 'utf8');

        // Extract parseRoute implementation from app-entry.js
        const fnMatch = code.match(/function parseRoute\\(hash\\) \\{{([\\s\\S]*?)\\n  \\}}/);
        if (!fnMatch) {{
          console.error('parseRoute not found');
          process.exit(1);
        }}
        const parseRoute = new Function('hash', fnMatch[1]);

        const validRoutes = [
          '#/portal',
          '#/history',
          '#/audit',
          '#/setup',
          '#/monitor',
          '#/monitor?scan=20261104_100000',
          '#/findings',
          '#/findings?scan=20261104_100000&severity=high',
          '#/crawl',
          '#/crawl?scan=20261104_100000&mode=graph',
          '#/agent-skills',
          '#/settings'
        ];

        const validResults = validRoutes.map(r => ({{
          hash: r,
          parsed: parseRoute(r)
        }}));

        // Invalid or unregistered routes
        const invalidRoutes = [
          '#/traffic',
          '#/traffic?mode=live',
          '#/unknown-view',
          '#/admin',
          '#/portal?unexpected_param=1',
          '#//evil//route',
          '#/monitor?scan=bad!id',
        ];

        const invalidResults = invalidRoutes.map(r => ({{
          hash: r,
          parsed: parseRoute(r)
        }}));

        console.log(JSON.stringify({{ validResults, invalidResults }}));
        """
        res = _run_node(script)

        for item in res["validResults"]:
            assert item["parsed"] is not None, f"Expected {item['hash']} to resolve, got null"
            assert "id" in item["parsed"]
            assert len(item["parsed"]["id"]) > 0

        for item in res["invalidResults"]:
            assert item["parsed"] is None, (
                f"Expected invalid route {item['hash']} to return null (cleanly leading to explicit unavailable state), "
                f"got {item['parsed']}"
            )

    def test_no_traffic_view_linked_in_app_shell(self):
        app_html = APP_HTML.read_text(encoding="utf-8")
        assert "traffic" not in app_html.lower()

        app_entry_js = APP_ENTRY_JS.read_text(encoding="utf-8")
        assert "traffic" not in app_entry_js.lower()

    def test_obsolete_portal_frame_markup_removed_from_app_shell(self):
        app_html = APP_HTML.read_text(encoding="utf-8")
        assert "portalFrame" not in app_html, "Obsolete iframe#portalFrame must be removed from app.html"

        app_entry_js = APP_ENTRY_JS.read_text(encoding="utf-8")
        assert "portalFrame" not in app_entry_js, "Obsolete portalFrame DOM binding must be removed from app-entry.js"
