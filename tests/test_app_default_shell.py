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

from tests.ui_harness import UIHarness, ui_harness, require_browser

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
    """Verify serve, scan, and agent commands output and open the correct /app URL."""

    def test_dashboard_url_helper(self):
        assert main.get_dashboard_url(8765) == "http://localhost:8765/app"
        assert (
            main.get_dashboard_url(8765, "20261104_100000")
            == "http://localhost:8765/app#/monitor?scan=20261104_100000"
        )
        assert (
            main.get_dashboard_url(8765, "agent_20261104_100000")
            == "http://localhost:8765/app#/monitor?scan=agent_20261104_100000"
        )
        assert main.get_dashboard_url(8765, view="monitor") == "http://localhost:8765/app#/monitor"
        assert main.get_dashboard_url(8765, "", view="monitor") == "http://localhost:8765/app#/monitor"

        dummy_monitor_with_id = Namespace(current_scan_id="20261104_100000", api_scan_id="20261104_100000")
        assert (
            main.get_dashboard_url(8765, monitor=dummy_monitor_with_id, view="monitor")
            == "http://localhost:8765/app#/monitor?scan=20261104_100000"
        )

        dummy_monitor_without_id = Namespace(current_scan_id="", api_scan_id="")
        assert (
            main.get_dashboard_url(8765, monitor=dummy_monitor_without_id, view="monitor")
            == "http://localhost:8765/app#/monitor"
        )

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

    def test_scan_printed_url_and_browser_open_default_and_custom(self, monkeypatch, tmp_path):
        captured_prints = []
        opened_urls = []

        class DummyConsole:
            def print(self, *args, **kwargs):
                for arg in args:
                    if hasattr(arg, "renderable"):
                        captured_prints.append(str(arg.renderable))
                    else:
                        captured_prints.append(str(arg))

        monkeypatch.setattr("rich.console.Console", DummyConsole)
        monkeypatch.setattr("webbrowser.open", lambda url: opened_urls.append(url))

        async def fast_sleep(*args, **kwargs):
            return

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        async def dummy_serve(self):
            return

        monkeypatch.setattr("uvicorn.Server.serve", dummy_serve)

        from wscan.engine import ScanEngine

        async def dummy_engine_run(self):
            return

        monkeypatch.setattr(ScanEngine, "run", dummy_engine_run)

        # 1. Default output: URL carries scan ID from live monitor and deep links
        args_default = main.parse_args(["scan", "https://example.test", "--port", "8765"])
        asyncio.run(main.run_scan(args_default))
        all_prints_default = "\n".join(captured_prints)
        assert "http://localhost:8765/app#/monitor?scan=" in all_prints_default
        assert len(opened_urls) == 1
        assert opened_urls[0].startswith("http://localhost:8765/app#/monitor?scan=")
        default_scan_id = opened_urls[0].split("scan=")[1]
        assert len(default_scan_id) > 0

        # 2. Custom output directory: opens live Monitor view without scan ID;
        # never puts the custom directory name in the URL
        captured_prints.clear()
        opened_urls.clear()
        custom_dir = tmp_path / "custom_sensitive_scan_out"
        args_custom = main.parse_args(["scan", "https://example.test", "--port", "8765", "--output", str(custom_dir)])
        asyncio.run(main.run_scan(args_custom))
        all_prints_custom = "\n".join(captured_prints)
        expected_url = "http://localhost:8765/app#/monitor"
        assert expected_url in all_prints_custom
        assert opened_urls == [expected_url]
        assert "custom_sensitive_scan_out" not in opened_urls[0]
        assert "custom_sensitive_scan_out" not in all_prints_custom.split("Monitoring dashboard:")[1].splitlines()[0]

    def test_agent_printed_url_and_browser_open_default_and_custom(self, monkeypatch, tmp_path):
        captured_prints = []
        opened_urls = []

        class DummyConsole:
            def print(self, *args, **kwargs):
                for arg in args:
                    if hasattr(arg, "renderable"):
                        captured_prints.append(str(arg.renderable))
                    else:
                        captured_prints.append(str(arg))

        monkeypatch.setattr("rich.console.Console", DummyConsole)
        monkeypatch.setattr("webbrowser.open", lambda url: opened_urls.append(url))

        async def fast_sleep(*args, **kwargs):
            return

        monkeypatch.setattr(asyncio, "sleep", fast_sleep)

        async def dummy_serve(self):
            return

        monkeypatch.setattr("uvicorn.Server.serve", dummy_serve)

        from wscan.agent_engine import AgentEngine
        from wscan.llm_agent_browser import AgentScanResult

        async def dummy_agent_run(self):
            return AgentScanResult(target_url="https://example.test", success=True, findings=[])

        monkeypatch.setattr(AgentEngine, "run", dummy_agent_run)

        # 1. Default output: URL carries agent scan ID from live monitor
        args_default = main.parse_args(["agent", "https://example.test", "--port", "8765", "--llm", "ollama"])
        asyncio.run(main.run_agent(args_default))
        all_prints_default = "\n".join(captured_prints)
        assert "http://localhost:8765/app#/monitor?scan=agent_" in all_prints_default
        assert len(opened_urls) == 1
        assert opened_urls[0].startswith("http://localhost:8765/app#/monitor?scan=agent_")

        # 2. Custom output directory: opens live Monitor view without scan ID;
        # never puts the custom directory name in the URL
        captured_prints.clear()
        opened_urls.clear()
        custom_dir = tmp_path / "custom_sensitive_agent_out"
        args_custom = main.parse_args(["agent", "https://example.test", "--port", "8765", "--llm", "ollama", "--output", str(custom_dir)])
        asyncio.run(main.run_agent(args_custom))
        all_prints_custom = "\n".join(captured_prints)
        expected_url = "http://localhost:8765/app#/monitor"
        assert expected_url in all_prints_custom
        assert opened_urls == [expected_url]
        assert "custom_sensitive_agent_out" not in opened_urls[0]
        assert "custom_sensitive_agent_out" not in all_prints_custom.split("Monitoring dashboard:")[1].splitlines()[0]

    def test_no_monitor_and_batch_modes_do_not_open_browser(self, monkeypatch, tmp_path):
        captured_prints = []
        opened_urls = []

        class DummyConsole:
            def print(self, *args, **kwargs):
                for arg in args:
                    if hasattr(arg, "renderable"):
                        captured_prints.append(str(arg.renderable))
                    else:
                        captured_prints.append(str(arg))

        monkeypatch.setattr("rich.console.Console", DummyConsole)
        monkeypatch.setattr("webbrowser.open", lambda url: opened_urls.append(url))

        from wscan.engine import ScanEngine
        from wscan.agent_engine import AgentEngine
        from wscan.llm_agent_browser import AgentScanResult
        from wscan.batch_runner import BatchResult

        async def dummy_engine_run(self):
            return

        async def dummy_agent_run(self):
            return AgentScanResult(target_url="https://example.test", success=True, findings=[])

        monkeypatch.setattr(ScanEngine, "run", dummy_engine_run)
        monkeypatch.setattr(AgentEngine, "run", dummy_agent_run)

        # 1. scan with --no-monitor
        args_scan = main.parse_args(["scan", "https://example.test", "--no-monitor"])
        asyncio.run(main.run_scan(args_scan))
        assert len(opened_urls) == 0, f"webbrowser.open should not be called in --no-monitor mode: {opened_urls}"
        assert "Monitoring dashboard:" not in "\n".join(captured_prints)

        # 2. agent with --no-monitor
        captured_prints.clear()
        args_agent = main.parse_args(["agent", "https://example.test", "--no-monitor", "--llm", "ollama"])
        asyncio.run(main.run_agent(args_agent))
        assert len(opened_urls) == 0, f"webbrowser.open should not be called in agent --no-monitor mode: {opened_urls}"
        assert "Monitoring dashboard:" not in "\n".join(captured_prints)

        # 3. batch mode
        captured_prints.clear()
        dummy_targets = tmp_path / "targets.yaml"
        dummy_targets.write_text("targets:\n  - url: https://example.test\n", encoding="utf-8")
        args_batch = main.parse_args(["batch", str(dummy_targets)])

        async def dummy_batch_run(self):
            self.results = []
            self.output_base.mkdir(parents=True, exist_ok=True)
            return self.results

        monkeypatch.setattr("wscan.batch_runner.BatchRunner.run", dummy_batch_run)
        asyncio.run(main.run_batch(args_batch))
        assert len(opened_urls) == 0, f"webbrowser.open should not be called in batch mode: {opened_urls}"
        assert "Monitoring dashboard:" not in "\n".join(captured_prints)

    def test_app_browser_monitor_mounts_default_and_custom_output_urls(self, ui_harness: UIHarness):
        """Browser test verifying that default output URL (with scan ID) and custom
        output URL (without scan ID) both properly mount the live Monitor view,
        and that custom output never leaks the directory name into the URL."""
        ui_harness.seed_representative_scans()
        page = ui_harness.new_page()

        # 1. Custom output directory URL without scan ID:
        # mounts and follows the live Monitor view directly, no directory name in URL
        custom_output_url = f"{ui_harness.server_url}/app#/monitor"
        page.goto(custom_output_url, wait_until="domcontentloaded")
        page.wait_for_function("""() => {
            const host = document.querySelector('#monitorModule');
            return host && !host.hidden && host.shadowRoot?.querySelector('#viewLiveMonitor');
        }""")
        assert page.url.endswith("#/monitor")
        assert "scan=" not in page.url
        assert not page.locator("#message").is_visible()

        # 2. Default output with scan ID:
        # when the live scan context matches the scan ID, the live Monitor view mounts
        default_scan_id = "20261026_100000"
        default_url = f"{ui_harness.server_url}/app#/monitor?scan={default_scan_id}"
        page.goto(default_url, wait_until="domcontentloaded")
        # Ensure frame WS/state is ready before delivering matching active scan event
        page.wait_for_function("""() => {
            const w = document.querySelector('#monitorFrame')?.contentWindow;
            return w?._eventStream?.connected
              && w.eval("typeof state.serverInstanceId === 'string' && state.serverInstanceId.length > 0");
        }""")
        event_js = (
            "const ev={type:'scan_started',server_id:state.serverInstanceId,"
            f"run_id:'run-default',scan_id:'{default_scan_id}',sequence:1,"
            "backend_version:_eventStream.backendVersion(),"
            "data:{url:'https://safe.example.test',checks:['xss']}};"
            "state.ws.onmessage({data:JSON.stringify(ev)})"
        )
        page.evaluate(f"() => document.querySelector('#monitorFrame').contentWindow.eval({event_js!r})")
        page.wait_for_function("""() => {
            const host = document.querySelector('#monitorModule');
            return host && !host.hidden && host.shadowRoot?.querySelector('#viewLiveMonitor');
        }""")
        assert page.url.endswith(f"#/monitor?scan={default_scan_id}")
        assert not page.locator("#message").is_visible()

        # 3. Confirm that an arbitrary custom directory name in the URL would be rejected
        page.goto(f"{ui_harness.server_url}/app#/monitor?scan=custom_sensitive_dir", wait_until="domcontentloaded")
        page.wait_for_selector("#message", state="visible")
        assert page.locator("#message").is_visible()
        assert "見つかりません" in page.locator("#message").inner_text()
        ui_harness.assert_no_errors(page)


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

    def test_app_browser_navigation_all_entries_mount_or_explicit_unavailable(self, ui_harness: UIHarness):
        """Real browser test verifying that every /app navigation entry resolves to either
        a mounted registered view with visible view-specific element or an explicit unavailable
        state with a reason (never a blank or broken view). Also asserts no navigation entry or link
        targets a Traffic view."""
        ui_harness.seed_representative_scans()
        page = ui_harness.new_page()
        page.goto(f"{ui_harness.server_url}/app", wait_until="domcontentloaded")
        page.wait_for_selector("nav[aria-label='Application']", state="visible")

        # 1. Assert no navigation entry or link anywhere targets a Traffic view
        nav_texts = page.eval_on_selector_all(
            "nav button, nav a",
            "els => els.map(el => (el.textContent || '').trim().toLowerCase())",
        )
        all_routes = page.eval_on_selector_all(
            "[data-route]",
            "els => els.map(el => (el.getAttribute('data-route') || '').toLowerCase())",
        )
        all_hrefs = page.eval_on_selector_all(
            "a[href]",
            "els => els.map(el => (el.getAttribute('href') || '').toLowerCase())",
        )
        for text in nav_texts:
            assert "traffic" not in text, f"Navigation text contains traffic: {text}"
        for route in all_routes:
            assert "traffic" not in route, f"Navigation route contains traffic: {route}"
        for href in all_hrefs:
            assert "traffic" not in href, f"Link href targets traffic: {href}"

        # 2. Get all navigation entries from the DOM
        nav_buttons = page.locator("nav [data-route]")
        count = nav_buttons.count()
        assert count >= 8, f"Expected at least 8 navigation items in nav, found {count}"

        routes = []
        for i in range(count):
            btn = nav_buttons.nth(i)
            route_id = btn.get_attribute("data-route")
            assert route_id, "Navigation button missing data-route attribute"
            routes.append(route_id)

        # Specific elements indicating that each registered view has mounted
        view_specific_selectors = {
            "portal": "#summarySurface",
            "history": "#summarySurface",
            "audit": "#summarySurface",
            "setup": "#setupSurface",
            "monitor": "#monitorFrame",
            "findings": "#findingsSurface",
            "crawl": "#crawlSurface",
            "agent-skills": "#agentSkillsSurface",
            "settings": "#settingsSurface",
        }

        for route_id in routes:
            # Navigate to the entry by clicking its nav button
            btn = page.locator(f'nav [data-route="{route_id}"]')
            btn.click()
            page.wait_for_timeout(60)

            # Confirm aria-current="page" was applied
            assert btn.get_attribute("aria-current") == "page", f"Route {route_id} button not marked aria-current"

            # Check view-specific selector or unavailable message
            expected_selector = view_specific_selectors.get(route_id)
            surface = page.locator(expected_selector) if expected_selector else None
            message = page.locator("#message")

            # Either registered view mounted or explicit unavailable state shown
            is_mounted = surface is not None and surface.is_visible()
            is_unavailable = message.is_visible()

            assert is_mounted or is_unavailable, (
                f"Route {route_id} is neither mounted (expected selector {expected_selector}) "
                f"nor showing an explicit unavailable state (#message)."
            )

            if is_unavailable:
                reason = message.inner_text().strip()
                assert len(reason) > 0, f"Route {route_id} unavailable message has no reason text"
                assert any(k in reason for k in ("利用不可", "不正", "一致しません", "見つかりません", "unavailable")), (
                    f"Route {route_id} unavailable message does not contain expected reason keyword: {reason}"
                )
            else:
                # View mounted: assert it is not blank and contains view-specific elements
                if route_id in ("portal", "history", "audit"):
                    assert page.locator("#summarySurface").is_visible()
                    assert len(page.locator("#summarySurface").inner_text().strip()) > 0
                elif route_id == "setup":
                    assert page.locator("#setupSurface").is_visible()
                    page.wait_for_selector("#cfgInputUrl", state="visible")
                elif route_id == "monitor":
                    assert page.locator("#monitorFrame").is_visible() or page.locator("#monitorModule").is_visible()
                elif route_id == "findings":
                    assert page.locator("#findingsSurface").is_visible()
                    page.wait_for_selector(".findings-split-view, .findings-container", state="visible")
                elif route_id == "crawl":
                    assert page.locator("#crawlSurface").is_visible()
                    page.wait_for_selector("#crawlModeSelect, .crawl-toolbar, #crawlSvg", state="visible")
                elif route_id == "agent-skills":
                    assert page.locator("#agentSkillsSurface").is_visible()
                    assert len(page.locator("#agentSkillsSurface").inner_text().strip()) > 0
                elif route_id == "settings":
                    assert page.locator("#settingsSurface").is_visible()
                    page.wait_for_selector(".ui-settings-container, #notificationCard, #saveSettingsBtn", state="visible")

            # Never a blank or broken view
            surface_section = page.locator("#surface")
            assert surface_section.is_visible()
            ui_harness.assert_no_errors(page)
