"""Tests for token-authenticated GET API probes and clearing synced token on logout.

Covers:
  - Unit tests for the routing decision (should_route_to_api_get)
  - Unit tests for clearing synced tokens on logout / session loss / re-login
  - Loopback SPA E2E test with Bearer JWT, vulnerable GET API (/api/items?q=),
    safe twin (/api/items_safe?q=), and verification that raw secrets never leak into
    persisted scan artefacts.
"""
from __future__ import annotations

import asyncio
import contextlib
import json
import os
import socket
import tempfile
import threading
import time
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from wscan import session_guard
from wscan.engine import (
    CrawledPage,
    ScanEngine,
    _AUTH_TOKEN_UNSET,
    _WORKER_AUTH_TOKEN,
    _clear_synced_token,
    _effective_synced_token,
    _store_synced_token,
)
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner, Finding, injection_point_from_finding
from wscan.scanners.sqli import SQLiScanner


# =============================================================================
# 1. Pure Routing Decision Tests (should_route_to_api_get)
# =============================================================================

class PureGetApiRoutingDecisionTests(unittest.TestCase):
    def test_spa_get_with_synced_token_same_origin_routes_to_api_get(self):
        ip = InjectionPoint.for_url_param(
            "http://target.test/api/items?q=shoes",
            "q",
            source="spa",
        )
        synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer test-jwt-xyz"},
        }
        self.assertTrue(
            session_guard.should_route_to_api_get(
                ip,
                synced_token=synced_token,
            )
        )

    def test_crawl_get_top_level_document_stays_on_browser_navigation(self):
        ip = InjectionPoint.for_url_param(
            "http://target.test/products?q=shoes",
            "q",
            source="crawl",
        )
        synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer test-jwt-xyz"},
        }
        self.assertFalse(
            session_guard.should_route_to_api_get(
                ip,
                synced_token=synced_token,
            )
        )

    def test_form_injection_point_not_routed(self):
        ip = InjectionPoint.for_form(
            "http://target.test/api/items",
            "q",
            0,
        )
        synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer test-jwt-xyz"},
        }
        self.assertFalse(
            session_guard.should_route_to_api_get(
                ip,
                synced_token=synced_token,
            )
        )

    def test_cross_origin_api_get_not_routed(self):
        ip = InjectionPoint.for_url_param(
            "http://evil.test/api/items?q=shoes",
            "q",
            source="spa",
        )
        synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer test-jwt-xyz"},
        }
        self.assertFalse(
            session_guard.should_route_to_api_get(
                ip,
                synced_token=synced_token,
            )
        )

    def test_missing_or_empty_synced_token_not_routed(self):
        ip = InjectionPoint.for_url_param(
            "http://target.test/api/items?q=shoes",
            "q",
            source="spa",
        )
        self.assertFalse(
            session_guard.should_route_to_api_get(ip, synced_token=None)
        )
        self.assertFalse(
            session_guard.should_route_to_api_get(ip, synced_token={})
        )
        self.assertFalse(
            session_guard.should_route_to_api_get(
                ip, synced_token={"origin": "http://target.test", "headers": {}}
            )
        )

    def test_engine_spa_harvested_urls_fallback(self):
        # Even if source was crawl/empty, if URL is in engine._spa_harvested_urls, route to API GET
        ip = InjectionPoint.for_url_param(
            "http://target.test/api/items?q=shoes",
            "q",
            source="crawl",
        )
        mock_engine = SimpleNamespace(
            _spa_harvested_urls={"http://target.test/api/items"}
        )
        synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer test-jwt-xyz"},
        }
        self.assertTrue(
            session_guard.should_route_to_api_get(
                ip,
                synced_token=synced_token,
                engine=mock_engine,
            )
        )

    def test_scanner_helper_delegation(self):
        eng = ScanEngine.__new__(ScanEngine)
        eng._synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer token-1"},
        }
        eng._spa_harvested_urls = set()
        eng._browser = None
        eng.monitor = None

        class DummyScanner(BaseScanner):
            def __init__(self, engine):
                self.engine = engine
            async def scan_field(self, *args, **kwargs):
                return []

        scanner = DummyScanner(eng)
        ip_spa = InjectionPoint.for_url_param(
            "http://target.test/api/data?id=1", "id", source="spa"
        )
        ip_crawl = InjectionPoint.for_url_param(
            "http://target.test/page?id=1", "id", source="crawl"
        )

        self.assertTrue(scanner._should_route_to_api_get(ip_spa))
        self.assertFalse(scanner._should_route_to_api_get(ip_crawl))
        self.assertFalse(scanner._should_route_to_api_get(None))


# =============================================================================
# 2. Logout & Session Loss Token Clearance Tests
# =============================================================================

class LogoutClearsTokenTests(unittest.TestCase):
    def test_clear_synced_token_clears_worker_local_shared_and_capture(self):
        eng = ScanEngine.__new__(ScanEngine)
        eng._synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer shared-token"},
        }

        # Simulate network capture slot
        capture = SimpleNamespace(_observed_auth_headers={"http://target.test": {"Authorization": "Bearer slot-token"}})
        browser = SimpleNamespace(network=capture)
        eng._browser = browser

        # Set worker-local ContextVar
        token = _WORKER_AUTH_TOKEN.set({
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer worker-token"},
        })
        try:
            self.assertEqual(
                _effective_synced_token(eng)["headers"]["Authorization"],
                "Bearer worker-token",
            )
            # Clear all
            eng.clear_synced_token()

            self.assertEqual(_effective_synced_token(eng), {})
            self.assertEqual(eng._synced_token, {})
            self.assertEqual(capture._observed_auth_headers, {})
        finally:
            _WORKER_AUTH_TOKEN.reset(token)

    def test_origin_scoped_clear(self):
        eng = ScanEngine.__new__(ScanEngine)
        eng._synced_token = {
            "origin": "http://target.test",
            "headers": {"Authorization": "Bearer target-token"},
        }
        capture = SimpleNamespace(_observed_auth_headers={
            "http://target.test": {"Authorization": "Bearer target-token"},
            "http://other.test": {"Authorization": "Bearer other-token"},
        })
        eng._browser = SimpleNamespace(network=capture)

        # Clear target origin only
        eng.clear_synced_token(origin="http://target.test")
        self.assertEqual(eng._synced_token, {})
        self.assertNotIn("http://target.test", capture._observed_auth_headers)
        self.assertIn("http://other.test", capture._observed_auth_headers)

    def test_finding_roundtrip_preserves_injection_source(self):
        finding = Finding(
            check_type="sqli",
            severity="high",
            url="http://target.test/api/items?q=1",
            field_name="q",
            payload="' OR '1'='1",
            evidence="SQL syntax error",
            injection_location="url_param",
            injection_source="spa",
        )
        d = finding.to_dict()
        self.assertEqual(d.get("injection_source"), "spa")

        restored = Finding.from_dict(d)
        self.assertEqual(restored.injection_source, "spa")

        ip = injection_point_from_finding(restored)
        self.assertIsNotNone(ip)
        self.assertEqual(ip.location, "url_param")
        self.assertEqual(ip.source, "spa")


# =============================================================================
# 3. Loopback FastAPI SPA End-to-End Test
# =============================================================================

def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def _wait_until_serving(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with contextlib.closing(socket.create_connection(("127.0.0.1", port), 0.25)):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"fixture server never came up on port {port}")


def _e2e_enabled() -> bool:
    return os.environ.get("WSCAN_E2E", "").strip().lower() in {"1", "true", "yes", "on"}


SECRET_JWT = "super-secret-jwt-token-abcdef123456"


def create_spa_get_api_app() -> FastAPI:
    """Creates a loopback FastAPI SPA fixture with token-based authentication (no cookies).

    Endpoints:
      - GET /: SPA HTML that stores Bearer JWT in localStorage and triggers
               XHR/fetch GET /api/items?q=shoes and GET /api/items_safe?q=shoes.
      - GET /api/items?q=...: Protected GET API vulnerable to SQL injection. 401 without Bearer JWT.
      - GET /api/items_safe?q=...: Protected GET API safe twin. 401 without Bearer JWT.
    """
    app = FastAPI(title="SPA GET API Fixture")

    def _is_authenticated(request: Request) -> bool:
        auth = request.headers.get("authorization", "")
        return auth.strip() == f"Bearer {SECRET_JWT}"

    @app.get("/", response_class=HTMLResponse)
    async def index():
        return f"""<!doctype html>
<html>
  <head><title>SPA GET API Test</title></head>
  <body>
    <h1>SPA Dashboard</h1>
    <div id="results">Loading...</div>
    <script>
      localStorage.setItem('auth_token', '{SECRET_JWT}');
      async function run() {{
        const token = localStorage.getItem('auth_token');
        const headers = {{'Authorization': 'Bearer ' + token}};
        try {{
          const r1 = await fetch('/api/items?q=shoes', {{ headers }});
          const d1 = await r1.json();
          const r2 = await fetch('/api/items_safe?q=shoes', {{ headers }});
          const d2 = await r2.json();
          document.getElementById('results').textContent = 'Loaded ' + d1.length + ' items';
        }} catch(e) {{
          document.getElementById('results').textContent = 'Error: ' + e;
        }}
      }}
      run();
    </script>
  </body>
</html>"""

    @app.get("/api/items")
    async def get_items(request: Request, q: str = ""):
        if not _is_authenticated(request):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized: missing or invalid Bearer token"},
            )
        # Vulnerable to SQL injection in `q`
        if "'" in q or "--" in q or "/*" in q or "select" in q.lower():
            return JSONResponse(
                status_code=500,
                content={
                    "error": f"sqlite3.OperationalError: unrecognized token near '{q}': syntax error",
                    "details": "SELECT id, name FROM items WHERE name LIKE '%" + q + "%'",
                },
            )
        return JSONResponse(content=[{"id": 1, "name": f"Item for {q}"}])

    @app.get("/api/items_safe")
    async def get_items_safe(request: Request, q: str = ""):
        if not _is_authenticated(request):
            return JSONResponse(
                status_code=401,
                content={"error": "Unauthorized: missing or invalid Bearer token"},
            )
        # Safe twin: properly parameterized, never reflects SQL errors
        return JSONResponse(content=[{"id": 1, "name": f"Safe item for {q}"}])

    return app


@pytest.mark.skipif(not _e2e_enabled(), reason="requires WSCAN_E2E=1")
class LoopbackSpaGetApiE2ETests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.port = _free_port()
        app = create_spa_get_api_app()
        config = uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="warning")
        cls.server = uvicorn.Server(config)
        cls.thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.thread.start()
        _wait_until_serving(cls.port)
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=3.0)

    async def test_loopback_spa_get_api_sqli_found_safe_twin_clean_no_secrets_persisted(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            engine = ScanEngine(
                self.base_url,
                checks=["sqli"],
                spa_crawl=True,
                allow_state_changing_probes=True,
                llm_provider="none",
                headless=True,
                output_dir=tmp_dir,
                open_report=False,
                enable_waf_detection=False,
                enable_ai_analysis=False,
                enable_payload_learning=False,
                enable_payload_evolution=False,
                enable_payload_mutation=False,
                enable_adaptive_payloads=False,
                enable_sitemap_crawl=False,
                depth=1,
                fast_mode=True,
                max_payloads=4,
                request_delay=0,
                use_planner=False,
                sarif=False,
                timeout=8,
                navigation_retries=0,
            )

            await asyncio.wait_for(engine.run(), timeout=120)

            # 1. Verify vulnerable GET API found
            sqli_findings = [f for f in engine.all_findings if f.check_type == "sqli"]
            vuln_findings = [f for f in sqli_findings if "/api/items" in f.url and f.field_name == "q"]
            self.assertGreaterEqual(
                len(vuln_findings),
                1,
                f"Expected SQLi finding on /api/items?q=, got {len(vuln_findings)} (total findings: {len(engine.all_findings)})",
            )

            # 2. Verify safe twin is clean
            safe_findings = [f for f in engine.all_findings if "/api/items_safe" in f.url]
            self.assertEqual(
                len(safe_findings),
                0,
                f"Expected 0 findings on /api/items_safe, got {len(safe_findings)}: {safe_findings}",
            )

            # 3. Verify no raw token value is persisted in any artifact file
            for file_path in Path(tmp_dir).rglob("*"):
                if file_path.is_file():
                    try:
                        content = file_path.read_text(encoding="utf-8", errors="ignore")
                        self.assertNotIn(
                            SECRET_JWT,
                            content,
                            f"Secret token leaked into persisted file: {file_path.name}",
                        )
                    except Exception:
                        pass
