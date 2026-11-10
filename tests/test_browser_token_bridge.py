"""Tests for browser token bridge: carry browser Authorization header into httpx auth headers.

Covers:
  - Pure helper unit tests (in-scope pick, cross-origin ignored, latest wins, user header precedence)
  - Engine-level auth_headers() integration and per-worker ContextVar isolation
  - Loopback FastAPI SPA end-to-end test (JWT in localStorage, fetch with Bearer, API 401 without it,
    SQLi in query + safe twin in category): protected_access verified, no false expiry/relogin,
    SQLi finding confirmed, safe twin clean.
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
from unittest.mock import AsyncMock

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse

from wscan import session_guard
from wscan.engine import (
    ScanEngine,
    _AUTH_TOKEN_UNSET,
    _WORKER_AUTH_TOKEN,
    _effective_synced_token,
    _store_synced_token,
)


# =============================================================================
# 1. Pure Helper Unit Tests
# =============================================================================

class PureTokenBridgeHelperTests(unittest.TestCase):
    def test_in_scope_pick(self):
        pairs = [
            {
                "request": {
                    "url": "http://target.test/api/items",
                    "headers": {"Authorization": "Bearer token-123", "Accept": "application/json"},
                }
            }
        ]
        result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
        self.assertEqual(result, {"Authorization": "Bearer token-123"})

    def test_cross_origin_ignored(self):
        pairs = [
            {
                "request": {
                    "url": "http://evil.test/api/items",
                    "headers": {"Authorization": "Bearer evil-token"},
                }
            },
            {
                "request": {
                    "url": "https://target.test/api/items",  # different scheme (https vs http)
                    "headers": {"Authorization": "Bearer https-token"},
                }
            },
            {
                "request": {
                    "url": "http://target.test:8080/api/items",  # different port
                    "headers": {"Authorization": "Bearer port-token"},
                }
            },
        ]
        result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
        self.assertEqual(result, {})

    def test_latest_wins(self):
        pairs = [
            {
                "request": {
                    "url": "http://target.test/api/v1",
                    "headers": {"Authorization": "Bearer old-token"},
                }
            },
            {
                "request": {
                    "url": "http://target.test/api/v2",
                    "headers": {"Authorization": "Bearer new-rotated-token"},
                }
            },
        ]
        result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
        self.assertEqual(result, {"Authorization": "Bearer new-rotated-token"})

    def test_user_header_precedence(self):
        pairs = [
            {
                "request": {
                    "url": "http://target.test/api/items",
                    "headers": {"Authorization": "Bearer browser-token"},
                }
            }
        ]
        # When user already configured Authorization, browser header is ignored
        result = session_guard.extract_latest_auth_header(
            pairs, "http://target.test/", user_headers={"Authorization": "Bearer user-token"}
        )
        self.assertEqual(result, {})

        # Case-insensitive user header match
        result_lower = session_guard.extract_latest_auth_header(
            pairs, "http://target.test/", user_headers={"authorization": "Bearer user-token"}
        )
        self.assertEqual(result_lower, {})

    def test_non_bearer_authorization_ignored(self):
        pairs = [
            {
                "request": {
                    "url": "http://target.test/api/items",
                    "headers": {"Authorization": "Basic dXNlcjpwYXNz"},
                }
            }
        ]
        result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
        self.assertEqual(result, {})

    def test_token_scheme_accepted(self):
        pairs = [
            {
                "request": {
                    "url": "http://target.test/api/items",
                    "headers": {"Authorization": "Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"},
                }
            }
        ]
        result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
        self.assertEqual(
            result, {"Authorization": "Token 9944b09199c62bcf9418ad846dd0e4bbdfc6ee4b"}
        )

    def test_empty_token_ignored(self):
        pairs = [
            {
                "request": {
                    "url": "http://target.test/api/items",
                    "headers": {"Authorization": "Bearer "},
                }
            }
        ]
        result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
        self.assertEqual(result, {})

    def test_api_key_headers_supported(self):
        for header_name, canonical_name in [
            ("x-api-key", "X-API-Key"),
            ("x-auth-token", "X-Auth-Token"),
            ("x-access-token", "X-Access-Token"),
        ]:
            pairs = [
                {
                    "request": {
                        "url": "http://target.test/api/data",
                        "headers": {header_name: "secret-key-val"},
                    }
                }
            ]
            result = session_guard.extract_latest_auth_header(pairs, "http://target.test/")
            self.assertEqual(result, {canonical_name: "secret-key-val"})

    def test_empty_pairs_and_none_handled_gracefully(self):
        self.assertEqual(session_guard.extract_latest_auth_header([], "http://target.test/"), {})
        self.assertEqual(session_guard.extract_latest_auth_header(None, "http://target.test/"), {})
        self.assertEqual(session_guard.extract_latest_auth_header([{}], ""), {})

    def test_capture_slot_user_header_precedence(self):
        capture = _bare_capture()
        capture.authentication_active = True
        _send(capture, _request("http://target.test/api/mfa",
                                headers={"Authorization": "Bearer slot-token"}))
        self.assertEqual(
            session_guard.extract_latest_auth_header(capture, "http://target.test/"),
            {"Authorization": "Bearer slot-token"},
        )
        self.assertEqual(
            session_guard.extract_latest_auth_header(
                capture, "http://target.test/", {"Authorization": "Bearer user-token"}
            ),
            {},
        )
        # Cross-origin targets never receive the slot value.
        self.assertEqual(
            session_guard.extract_latest_auth_header(capture, "http://other.test/"), {}
        )

    def test_slot_wins_over_older_pairs(self):
        capture = _bare_capture()
        # Normal (post-login) SPA fetch: captured in pairs with headers.
        _send(capture, _request("http://target.test/api/search",
                                headers={"Authorization": "Bearer older-pair-token"}))
        # Login-flow submission later: redacted from pairs, kept in the slot.
        capture.authentication_active = True
        _send(capture, _request("http://target.test/api/mfa", method="POST",
                                headers={"Authorization": "Bearer newer-slot-token"},
                                post_data='{"otp":"123456"}'))
        self.assertEqual(
            session_guard.extract_latest_auth_header(capture, "http://target.test/"),
            {"Authorization": "Bearer newer-slot-token"},
        )
        # Page clears keep the in-memory slot (bridge survives page transitions).
        capture.clear()
        self.assertEqual(
            session_guard.extract_latest_auth_header(capture, "http://target.test/"),
            {"Authorization": "Bearer newer-slot-token"},
        )


# =============================================================================
# 1b. Secret-protection boundary: login-flow redaction is preserved
# =============================================================================

LOGIN_TOKEN = "jwt-login-flow-secret-7f3c9a2b"
LOGIN_PASSWORD = "hunter2-login-password"
MFA_CODE = "123456"


def _bare_capture():
    from wscan.browser import NetworkCapture

    return NetworkCapture()


def _request(url, method="GET", headers=None, post_data=None):
    return SimpleNamespace(
        url=url,
        method=method,
        headers=dict(headers or {}),
        post_data=post_data,
        resource_type="fetch",
        redirected_from=None,
    )


def _response(request, status=200, headers=None, body=""):
    return SimpleNamespace(
        request=request,
        url=request.url,
        status=status,
        headers=dict(headers or {}),
        text=AsyncMock(return_value=body),
    )


def _send(capture, request, status=200, headers=None, body=""):
    capture.on_request(request)
    capture.on_response(_response(request, status=status, headers=headers, body=body))


def _persisted_text(output_dir) -> str:
    chunks = []
    for path in sorted(Path(output_dir).rglob("*")):
        if path.is_file():
            chunks.append(path.read_text(encoding="utf-8", errors="replace"))
    return "\n".join(chunks)


class LoginFlowRedactionBoundaryTests(unittest.TestCase):
    """While authentication_active, every captured request stays fully redacted.

    The login token may still be bridged to httpx ``auth_headers`` through the
    private, in-memory slot, and must never reach any persisted artefact.
    """

    def test_token_response_then_mfa_post_stays_redacted_and_bridges(self):
        from wscan.request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmp_dir:
            capture = _bare_capture()
            capture.logger = RequestLogger(tmp_dir)
            capture.authentication_active = True

            login = _request(
                "http://target.test/api/login",
                method="POST",
                headers={"Content-Type": "application/json"},
                post_data=json.dumps({"username": "admin", "password": LOGIN_PASSWORD}),
            )
            _send(capture, login, body=json.dumps({"token": LOGIN_TOKEN}))

            # A token in the login response does NOT end the redaction window:
            # the following MFA submission is still the login flow.
            mfa = _request(
                "http://target.test/api/mfa",
                method="POST",
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {LOGIN_TOKEN}",
                },
                post_data=json.dumps({"otp": MFA_CODE}),
            )
            _send(capture, mfa)

            self.assertEqual(len(capture.pairs), 2)
            for pair in capture.pairs:
                self.assertEqual(pair["request"]["url"], "[authentication]")
                self.assertEqual(pair["request"]["headers"], {})
                self.assertEqual(pair["request"]["post_data"], "[REDACTED]")
                self.assertEqual(pair["response"]["url"], "[authentication]")
                self.assertEqual(pair["response"]["headers"], {})

            # Token is still bridged for same-origin httpx probes.
            self.assertEqual(
                session_guard.extract_latest_auth_header(capture, "http://target.test/"),
                {"Authorization": f"Bearer {LOGIN_TOKEN}"},
            )
            # ...but only in memory: captured pairs carry none of the secrets.
            self.assertNotIn(LOGIN_TOKEN, json.dumps(capture.pairs))
            self.assertNotIn(LOGIN_PASSWORD, json.dumps(capture.pairs))
            self.assertNotIn(MFA_CODE, json.dumps(capture.pairs))

            # Force the payload artefact to exist as well, then scan every file
            # the logger/evidence writer produced for the secret value.
            capture.logger.log_payload(
                field="otp", payload=MFA_CODE, check_type="sqli",
                url="http://target.test/api/mfa",
            )
            persisted = _persisted_text(tmp_dir)
            self.assertTrue((Path(tmp_dir) / "http_requests.jsonl").is_file())
            self.assertTrue((Path(tmp_dir) / "payloads.jsonl").is_file())
            self.assertNotIn(LOGIN_TOKEN, persisted)
            self.assertNotIn(LOGIN_PASSWORD, persisted)

    def test_normal_spa_fetch_is_captured_and_logger_redacts_authorization(self):
        from wscan.request_logger import RequestLogger

        with tempfile.TemporaryDirectory() as tmp_dir:
            capture = _bare_capture()
            capture.logger = RequestLogger(tmp_dir)
            # Outside the login flow: headers are captured as before.
            _send(capture, _request(
                "http://target.test/api/search",
                method="POST",
                headers={"Authorization": f"Bearer {LOGIN_TOKEN}",
                         "Content-Type": "application/json"},
                post_data=json.dumps({"query": "apple"}),
            ))

            pair = capture.pairs[0]
            self.assertEqual(pair["request"]["url"], "http://target.test/api/search")
            self.assertEqual(
                pair["request"]["headers"]["Authorization"], f"Bearer {LOGIN_TOKEN}"
            )
            self.assertEqual(
                session_guard.extract_latest_auth_header(capture, "http://target.test/"),
                {"Authorization": f"Bearer {LOGIN_TOKEN}"},
            )
            # Request logger still masks Authorization, and the raw token is absent.
            logged = (Path(tmp_dir) / "http_requests.jsonl").read_text(encoding="utf-8")
            self.assertIn('"Authorization": "<redacted>"', logged)
            self.assertNotIn(LOGIN_TOKEN, logged)

    def test_slot_holds_only_recognized_normalized_headers(self):
        capture = _bare_capture()
        capture.authentication_active = True
        _send(capture, _request(
            "http://target.test/api/items",
            headers={
                "Authorization": "Basic dXNlcjpwYXNz",   # not a recognized scheme
                "X-Custom-Secret": "raw-custom-value",    # unknown header name
            },
        ))
        self.assertEqual(capture._observed_auth_headers, {})
        self.assertEqual(
            session_guard.extract_latest_auth_header(capture, "http://target.test/"), {}
        )


# =============================================================================
# 2. Engine-level Auth Headers & Worker ContextVar Tests
# =============================================================================

class EngineTokenBridgeTests(unittest.TestCase):
    def test_auth_headers_includes_synced_token_for_same_origin(self):
        eng = ScanEngine.__new__(ScanEngine)
        eng._cookies = ""
        eng.header_manager = type("HM", (), {"current": lambda self: {}})()
        eng.headers_for_url = lambda url: {}
        eng._synced_token = {
            "origin": "http://fixture.test",
            "headers": {"Authorization": "Bearer test-jwt"},
        }

        # Same origin: token is added
        headers = eng.auth_headers(url="http://fixture.test/api/protected")
        self.assertEqual(headers.get("Authorization"), "Bearer test-jwt")

        # Cross origin: token is omitted
        cross_headers = eng.auth_headers(url="http://other.test/api/protected")
        self.assertNotIn("Authorization", cross_headers)

        # Empty url: token is omitted (never send token to unknown destinations)
        empty_headers = eng.auth_headers(url="")
        self.assertNotIn("Authorization", empty_headers)

    def test_auth_headers_user_configured_header_wins(self):
        eng = ScanEngine.__new__(ScanEngine)
        eng._cookies = ""
        eng.header_manager = type(
            "HM", (), {"current": lambda self: {"Authorization": "Bearer user-cli-token"}}
        )()
        eng.headers_for_url = lambda url: {"Authorization": "Bearer user-cli-token"}
        eng._synced_token = {
            "origin": "http://fixture.test",
            "headers": {"Authorization": "Bearer browser-token"},
        }

        headers = eng.auth_headers(url="http://fixture.test/api/protected")
        # User header MUST win
        self.assertEqual(headers["Authorization"], "Bearer user-cli-token")

    def test_per_worker_contextvar_isolation(self):
        eng = ScanEngine.__new__(ScanEngine)
        eng._cookies = ""
        eng._synced_token = {
            "origin": "http://fixture.test",
            "headers": {"Authorization": "Bearer global-token"},
        }

        async def worker_task(task_token_val):
            # Seed worker context
            token = _WORKER_AUTH_TOKEN.set(
                {
                    "origin": "http://fixture.test",
                    "headers": {"Authorization": f"Bearer {task_token_val}"},
                }
            )
            try:
                await asyncio.sleep(0.01)
                eff = _effective_synced_token(eng)
                return eff["headers"]["Authorization"]
            finally:
                _WORKER_AUTH_TOKEN.reset(token)

        async def run_workers():
            res1, res2 = await asyncio.gather(worker_task("worker-1"), worker_task("worker-2"))
            return res1, res2

        r1, r2 = asyncio.run(run_workers())
        self.assertEqual(r1, "Bearer worker-1")
        self.assertEqual(r2, "Bearer worker-2")
        # Global engine token is untouched
        self.assertEqual(eng._synced_token["headers"]["Authorization"], "Bearer global-token")


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


def create_token_spa_app() -> FastAPI:
    """Creates a loopback FastAPI SPA fixture with token-based authentication (no cookies)."""
    app = FastAPI(title="Token SPA Test Fixture")
    VALID_TOKEN = "jwt-secret-session-token-42"

    def _is_authenticated(request: Request) -> bool:
        auth = request.headers.get("authorization", "")
        return auth.strip() == f"Bearer {VALID_TOKEN}"

    @app.get("/", response_class=HTMLResponse)
    async def index(request: Request):
        if _is_authenticated(request):
            return HTMLResponse("<h1>Welcome admin</h1><p>Protected Dashboard Content</p>")
        return HTMLResponse(
            "<p>Redirecting to login</p>",
            status_code=302,
            headers={"Location": "/login"},
        )

    @app.get("/login", response_class=HTMLResponse)
    async def login_page():
        return """<!doctype html>
<html>
  <head><title>Login</title></head>
  <body>
    <div id="login-container">
      <div id="status-msg">Please sign in</div>
      <form id="login-form">
        <label for="username">Username</label>
        <input id="username" name="username" type="text" />
        <label for="password">Password</label>
        <input id="password" name="password" type="password" />
        <button id="login-submit" type="submit">Sign In</button>
      </form>
    </div>
    <div id="app-view"></div>
    <script>
      document.getElementById('login-form').addEventListener('submit', async function(e) {
        e.preventDefault();
        const u = document.getElementById('username').value;
        const p = document.getElementById('password').value;
        const res = await fetch('/api/login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username: u, password: p})
        });
        if (res.ok) {
          const data = await res.json();
          localStorage.setItem('jwt_token', data.token);
          // SPA transitions: remove login form from DOM so form is not still present
          document.getElementById('login-container').remove();
          document.getElementById('app-view').innerHTML = '<h2>Welcome admin</h2>';
          // Authenticated API request triggered by SPA
          await fetch('/api/search', {
            method: 'POST',
            headers: {
              'Authorization': 'Bearer ' + data.token,
              'Content-Type': 'application/json'
            },
            body: JSON.stringify({query: 'apple', category: 'fruit'})
          });
        }
      });
    </script>
  </body>
</html>"""

    @app.post("/api/login")
    async def login_api(request: Request):
        data = await request.json()
        if data.get("username") == "admin" and data.get("password") == "password123":
            # Pure token authentication — NO Set-Cookie header!
            return JSONResponse({"token": VALID_TOKEN, "access_token": VALID_TOKEN})
        return JSONResponse({"error": "invalid credentials"}, status_code=401)

    @app.get("/dashboard")
    async def dashboard(request: Request):
        if _is_authenticated(request):
            return HTMLResponse("<h1>Welcome admin</h1><p>Protected Dashboard Content</p>")
        # Browser navigation (Accept text/html with browser User-Agent): serve SPA dashboard
        accept = request.headers.get("accept", "")
        ua = request.headers.get("user-agent", "").lower()
        if "text/html" in accept and ("mozilla" in ua or "chrome" in ua):
            return HTMLResponse("""<!doctype html>
<html>
  <body>
    <h1>Dashboard</h1>
    <div id="content">Loading...</div>
    <script>
      const token = localStorage.getItem('jwt_token');
      if (token) {
        document.getElementById('content').innerHTML = '<h2>Welcome admin</h2>';
        fetch('/api/search', {
          method: 'POST',
          headers: {
            'Authorization': 'Bearer ' + token,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({query: 'apple', category: 'fruit'})
        });
      }
    </script>
  </body>
</html>""")
        # Unauthenticated probe (direct httpx without token): 401 Unauthorized
        return HTMLResponse("<h1>401 Unauthorized</h1>", status_code=401)

    @app.post("/api/search")
    async def search_api(request: Request):
        if not _is_authenticated(request):
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        body = await request.json()
        query = str(body.get("query", ""))
        # SQL Injection flaw on query (safe twin on category)
        if "'" in query:
            return JSONResponse(
                status_code=500,
                content={
                    "error": "You have an error in your SQL syntax; check the manual near ''' at line 1"
                },
            )
        return JSONResponse({"results": [{"query": query, "category": body.get("category", "")}]})

    return app


@pytest.mark.skipif(not _e2e_enabled(), reason="set WSCAN_E2E=1 to run the loopback SPA test")
class LoopbackTokenBridgeE2ETests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn

        cls.port = _free_port()
        app = create_token_spa_app()
        cls.server = uvicorn.Server(
            uvicorn.Config(app, host="127.0.0.1", port=cls.port, log_level="error")
        )
        cls.server_thread = threading.Thread(target=cls.server.run, daemon=True)
        cls.server_thread.start()
        _wait_until_serving(cls.port)

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.server_thread.join(timeout=3.0)

    async def test_token_bridge_e2e_scan(self):
        with tempfile.TemporaryDirectory() as tmp_dir:
            engine = ScanEngine(
                f"http://127.0.0.1:{self.port}/dashboard",
                login_url=f"http://127.0.0.1:{self.port}/login",
                auth_user="admin",
                auth_pass="password123",
                login_success_indicator="Welcome admin",
                logged_in_marker="Welcome admin",
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

            # 1. Protected access becomes verified (no browser_token_context_unsupported)
            self.assertEqual(engine.authentication_state.get("protected_access"), "verified")
            self.assertNotIn(
                "authentication_unverified:browser_token_context_unsupported",
                getattr(engine, "wave_errors", []),
            )

            # 2. No false expiry / relogin thrashing loop
            self.assertEqual(getattr(engine, "_relogin_count", 0), 0)

            # 3. Findings include SQL injection on query
            sqli_findings = [f for f in engine.all_findings if f.check_type == "sqli"]
            self.assertTrue(
                len(sqli_findings) >= 1, f"Expected SQLi finding, got: {engine.all_findings}"
            )
            sqli_target_params = [
                getattr(f, "param", "") or getattr(f, "injection_pointer", "")
                for f in sqli_findings
            ]
            self.assertTrue(
                any("/query" in str(p) or "query" in str(p) for p in sqli_target_params),
                f"SQLi must be on query, got params: {sqli_target_params}",
            )

            # 4. Safe twin clean (no SQLi on category)
            self.assertFalse(
                any("/category" in str(p) or "category" in str(p) for p in sqli_target_params),
                f"Safe twin 'category' should have no findings, got: {sqli_target_params}",
            )



if __name__ == "__main__":
    unittest.main()
