"""Per-worker BrowserContext and cookie jar isolation tests.

Verifies that concurrent workers (concurrency > 1) hold independent
BrowserContext instances and isolated cookie jars, preventing identity
cross-contamination when receiving response Set-Cookie headers or
performing automatic logins.
"""
import asyncio
import http.server
import json
import threading
import unittest
from unittest.mock import AsyncMock, MagicMock

from wscan.browser import (
    BrowserManager,
    WorkerBrowser,
    build_browser_context_options,
    prepare_cloned_cookies,
    prepare_cloned_storage_state,
)


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright

        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


class _FixtureServer(http.server.ThreadingHTTPServer):
    daemon_threads = True


class TestPureContextIsolation(unittest.TestCase):
    """Test pure functions that build context options and clone cookies."""

    def test_build_browser_context_options_defaults(self):
        opts = build_browser_context_options()
        self.assertEqual(opts["viewport"], {"width": 1280, "height": 800})
        self.assertIn("user_agent", opts)
        self.assertNotIn("proxy", opts)
        self.assertNotIn("extra_http_headers", opts)
        self.assertNotIn("service_workers", opts)

    def test_build_browser_context_options_with_headers_and_proxy(self):
        opts = build_browser_context_options(
            proxy="http://127.0.0.1:8080",
            extra_headers={"X-Custom": "val", "x-custom": "dup"},
        )
        self.assertEqual(opts["proxy"], {"server": "http://127.0.0.1:8080"})
        self.assertIn("extra_http_headers", opts)
        # Case collision deduplicated
        self.assertEqual(opts["extra_http_headers"]["x-custom"], "dup")

    def test_build_browser_context_options_scoped_headers_blocks_service_workers(self):
        opts = build_browser_context_options(
            extra_headers={"Authorization": "Bearer tok"},
            header_scope_origins=["https://api.example.com"],
            header_scope_enforce=True,
        )
        self.assertEqual(opts.get("service_workers"), "block")
        # Scoped headers are handled via CDP / route, not context extra_http_headers
        self.assertNotIn("extra_http_headers", opts)

    def test_prepare_cloned_cookies_normalizes_and_filters(self):
        raw = [
            {
                "name": "sess",
                "value": "abc",
                "domain": "example.com",
                "path": "/",
                "secure": True,
                "httpOnly": True,
                "sameSite": "Lax",
                "expires": 1234567890,
            },
            {"name": "", "value": "empty_name"},
            {"name": "no_val", "value": None},
            {"name": "url_cookie", "value": "xyz", "url": "https://example.com/api"},
            "invalid_type",
        ]
        cloned = prepare_cloned_cookies(raw)
        self.assertEqual(len(cloned), 2)
        self.assertEqual(cloned[0]["name"], "sess")
        self.assertEqual(cloned[0]["value"], "abc")
        self.assertEqual(cloned[0]["domain"], "example.com")
        self.assertEqual(cloned[0]["path"], "/")
        self.assertTrue(cloned[0]["secure"])
        self.assertTrue(cloned[0]["httpOnly"])
        self.assertEqual(cloned[0]["sameSite"], "Lax")
        self.assertEqual(cloned[0]["expires"], 1234567890)

        self.assertEqual(cloned[1]["name"], "url_cookie")
        self.assertEqual(cloned[1]["url"], "https://example.com/api")

    def test_prepare_cloned_cookies_empty_or_none(self):
        self.assertEqual(prepare_cloned_cookies(None), [])
        self.assertEqual(prepare_cloned_cookies([]), [])

    def test_prepare_cloned_storage_state_keeps_local_storage_and_filters_cookies(self):
        raw = {
            "cookies": [
                {
                    "name": "sess",
                    "value": "abc",
                    "domain": "example.com",
                    "path": "/",
                },
                {"name": "", "value": "drop_me"},
                {"name": "bad", "value": None},
            ],
            "origins": [
                {
                    "origin": "https://app.example.com",
                    "localStorage": [
                        {"name": "jwt", "value": "token-1"},
                        {"name": "", "value": "drop"},
                        "invalid",
                        {"name": "theme", "value": "dark"},
                    ],
                },
                {"origin": "", "localStorage": [{"name": "x", "value": "y"}]},
                "not-a-dict",
            ],
        }
        cloned = prepare_cloned_storage_state(raw)
        self.assertIsNotNone(cloned)
        self.assertEqual(len(cloned["cookies"]), 1)
        self.assertEqual(cloned["cookies"][0]["name"], "sess")
        self.assertEqual(len(cloned["origins"]), 1)
        self.assertEqual(cloned["origins"][0]["origin"], "https://app.example.com")
        ls = cloned["origins"][0]["localStorage"]
        self.assertEqual(ls, [
            {"name": "jwt", "value": "token-1"},
            {"name": "theme", "value": "dark"},
        ])

    def test_prepare_cloned_storage_state_rejects_non_dict(self):
        self.assertIsNone(prepare_cloned_storage_state(None))
        self.assertIsNone(prepare_cloned_storage_state([]))  # type: ignore[arg-type]
        empty = prepare_cloned_storage_state({})
        self.assertEqual(empty, {"cookies": [], "origins": []})


class TestWorkerBrowserContextIsolation(unittest.IsolatedAsyncioTestCase):
    """Test WorkerBrowser context creation, isolation, and lifecycle."""

    async def test_create_worker_fallback_when_no_browser(self):
        """When BrowserManager._browser is None, fallback uses shared context without failing."""
        real = BrowserManager()
        mock_ctx = AsyncMock()
        mock_page = MagicMock()
        mock_page.close = AsyncMock()
        mock_ctx.new_page.return_value = mock_page
        real._context = mock_ctx
        real._browser = None

        worker = await real.create_worker()
        self.assertIs(worker._context, mock_ctx)
        self.assertFalse(worker._owns_context)
        self.assertIs(worker.page, mock_page)

        await worker.close()
        mock_page.close.assert_awaited_once()
        # Shared context is NOT closed
        mock_ctx.close.assert_not_called()

    @unittest.skipUnless(_chromium_available(), "Chromium is not available")
    async def test_create_worker_isolated_context_when_browser_available(self):
        """When browser is running, each worker gets an independent BrowserContext."""
        real = BrowserManager(headless=True)
        await real.init()
        try:
            target_url = "http://127.0.0.1:9999"
            real.target_url = target_url
            await real.set_cookies("base_token=initial_shared", target_url)

            worker1 = await real.create_worker()
            worker2 = await real.create_worker()

            self.assertIsNot(worker1._context, worker2._context)
            self.assertIsNot(worker1._context, real._context)
            self.assertIsNot(worker2._context, real._context)
            self.assertTrue(worker1._owns_context)
            self.assertTrue(worker2._owns_context)

            # Baseline cookies are cloned into both workers
            c1_init = await worker1._context.cookies()
            c2_init = await worker2._context.cookies()
            self.assertTrue(any(c["name"] == "base_token" and c["value"] == "initial_shared" for c in c1_init))
            self.assertTrue(any(c["name"] == "base_token" and c["value"] == "initial_shared" for c in c2_init))

            # Mutate worker1's cookie jar
            await worker1.set_cookies("worker_id=worker1_identity", target_url)

            # Mutate worker2's cookie jar
            await worker2.set_cookies("worker_id=worker2_identity", target_url)

            c1 = await worker1._context.cookies()
            c2 = await worker2._context.cookies()
            c_main = await real._context.cookies()

            c1_ids = [c["value"] for c in c1 if c["name"] == "worker_id"]
            c2_ids = [c["value"] for c in c2 if c["name"] == "worker_id"]
            main_ids = [c["value"] for c in c_main if c["name"] == "worker_id"]

            self.assertEqual(c1_ids, ["worker1_identity"])
            self.assertEqual(c2_ids, ["worker2_identity"])
            self.assertEqual(main_ids, [])  # Main browser unaffected

            # Closing worker closes dedicated context
            await worker1.close()
            await worker2.close()
            self.assertEqual(real._active_workers, [])
        finally:
            await real.close()

    @unittest.skipUnless(_chromium_available(), "Chromium is not available")
    async def test_create_worker_clones_local_storage_auth_token(self):
        """B1 false-negative guard: SPA JWT in localStorage must reach workers."""
        real = BrowserManager(headless=True)
        await real.init()
        server = None
        server_thread = None
        try:
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = b"<html><body>ok</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):
                    pass

            server = _FixtureServer(("127.0.0.1", 0), Handler)
            port = server.server_port
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            origin = f"http://127.0.0.1:{port}"

            await real.navigate(origin + "/")
            await real.page.evaluate("localStorage.setItem('jwt', 'auth-token-xyz')")
            await real.set_cookies("sess=cookie-baseline", origin)

            worker = await real.create_worker()
            try:
                await worker.navigate(origin + "/")
                jwt = await worker.page.evaluate("localStorage.getItem('jwt')")
                self.assertEqual(jwt, "auth-token-xyz")
                cookies = await worker._context.cookies()
                self.assertTrue(
                    any(c["name"] == "sess" and c["value"] == "cookie-baseline" for c in cookies)
                )
            finally:
                await worker.close()
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if server_thread is not None:
                server_thread.join(timeout=2)
            await real.close()

    @unittest.skipUnless(_chromium_available(), "Chromium is not available")
    async def test_worker_local_storage_stays_isolated(self):
        """B1 safe twin: worker-local localStorage mutations must not leak across workers."""
        real = BrowserManager(headless=True)
        await real.init()
        server = None
        server_thread = None
        try:
            class Handler(http.server.BaseHTTPRequestHandler):
                def do_GET(self):
                    body = b"<html><body>ok</body></html>"
                    self.send_response(200)
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *args):
                    pass

            server = _FixtureServer(("127.0.0.1", 0), Handler)
            port = server.server_port
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            origin = f"http://127.0.0.1:{port}"

            worker1 = await real.create_worker()
            worker2 = await real.create_worker()
            try:
                await worker1.navigate(origin + "/")
                await worker2.navigate(origin + "/")
                await worker1.page.evaluate("localStorage.setItem('role', 'alice')")
                await worker2.page.evaluate("localStorage.setItem('role', 'bob')")
                self.assertEqual(
                    await worker1.page.evaluate("localStorage.getItem('role')"),
                    "alice",
                )
                self.assertEqual(
                    await worker2.page.evaluate("localStorage.getItem('role')"),
                    "bob",
                )
            finally:
                await worker1.close()
                await worker2.close()
        finally:
            if server is not None:
                server.shutdown()
                server.server_close()
            if server_thread is not None:
                server_thread.join(timeout=2)
            await real.close()

    @unittest.skipUnless(_chromium_available(), "Chromium is not available")
    async def test_main_cookie_refresh_propagates_to_all_workers(self):
        """B2 false-negative guard: rotated Cookie on main must reach every worker jar."""
        real = BrowserManager(headless=True)
        await real.init()
        try:
            target_url = "http://127.0.0.1:9999"
            real.target_url = target_url
            worker1 = await real.create_worker()
            worker2 = await real.create_worker()
            try:
                await real.set_cookies("auth=rotated-v2", target_url)

                for worker in (worker1, worker2):
                    cookies = await worker._context.cookies()
                    self.assertTrue(
                        any(c["name"] == "auth" and c["value"] == "rotated-v2" for c in cookies),
                        msg=f"worker missing refreshed cookie: {cookies}",
                    )

                # Safe twin: worker-local cookie writes still must not cross-contaminate.
                await worker1.set_cookies("worker_only=w1", target_url)
                c2 = await worker2._context.cookies()
                self.assertFalse(any(c["name"] == "worker_only" for c in c2))
            finally:
                await worker1.close()
                await worker2.close()
        finally:
            await real.close()

    @unittest.skipUnless(_chromium_available(), "Chromium is not available")
    async def test_main_header_refresh_updates_worker_extra_headers_and_context(self):
        """B2: context-wide header refresh must update worker.extra_headers and context."""
        real = BrowserManager(headless=True, extra_headers={"Authorization": "Bearer old"})
        await real.init()
        try:
            worker1 = await real.create_worker()
            worker2 = await real.create_worker()
            try:
                self.assertEqual(real._header_intercept_mode, "context")
                await real.update_extra_headers({"Authorization": "Bearer rotated"})
                self.assertEqual(worker1.extra_headers.get("Authorization"), "Bearer rotated")
                self.assertEqual(worker2.extra_headers.get("Authorization"), "Bearer rotated")
            finally:
                await worker1.close()
                await worker2.close()
        finally:
            await real.close()


@unittest.skipUnless(_chromium_available(), "Chromium is not available")
class TestSharedSessionRaceConcurrentWorkers(unittest.IsolatedAsyncioTestCase):
    """Verify that concurrent workers do not cross-contaminate cookies under race conditions."""

    async def asyncSetUp(self):
        self.request_records = []

        records = self.request_records

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                cookie_hdr = self.headers.get("Cookie", "")
                records.append((self.path, cookie_hdr))

                if self.path == "/session/alice":
                    body = b"<html><body>Alice logged in</body></html>"
                    self.send_response(200)
                    self.send_header("Set-Cookie", "auth_sess=alice_token; Path=/; HttpOnly")
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path == "/session/bob":
                    body = b"<html><body>Bob logged in</body></html>"
                    self.send_response(200)
                    self.send_header("Set-Cookie", "auth_sess=bob_token; Path=/; HttpOnly")
                    self.send_header("Content-Type", "text/html")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                elif self.path.startswith("/protected/whoami"):
                    body = json.dumps({"cookie": cookie_hdr}).encode("utf-8")
                    self.send_response(200)
                    self.send_header("Content-Type", "application/json")
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)
                else:
                    body = b"OK"
                    self.send_response(200)
                    self.send_header("Content-Length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

            def log_message(self, *args):
                pass

        self.server = _FixtureServer(("127.0.0.1", 0), Handler)
        self.port = self.server.server_port
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        self.base_url = f"http://127.0.0.1:{self.port}"

    async def asyncTearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.server_thread.join(timeout=2)

    async def test_concurrent_workers_prevent_identity_cross_contamination(self):
        """Worker 1 (Alice) and Worker 2 (Bob) navigate concurrently; cookie jars must remain strictly isolated."""
        bm = BrowserManager(headless=True)
        await bm.init()
        try:
            worker1 = await bm.create_worker()
            worker2 = await bm.create_worker()

            async def run_worker1():
                # Worker 1 logs in as Alice
                await worker1.navigate(f"{self.base_url}/session/alice")
                await asyncio.sleep(0.05)
                # Verify whoami
                await worker1.navigate(f"{self.base_url}/protected/whoami?worker=1")
                content = await worker1.get_page_source()
                return content

            async def run_worker2():
                # Worker 2 logs in as Bob
                await worker2.navigate(f"{self.base_url}/session/bob")
                await asyncio.sleep(0.05)
                # Verify whoami
                await worker2.navigate(f"{self.base_url}/protected/whoami?worker=2")
                content = await worker2.get_page_source()
                return content

            res1, res2 = await asyncio.gather(run_worker1(), run_worker2())

            # Worker 1 received only alice_token
            self.assertIn("alice_token", res1)
            self.assertNotIn("bob_token", res1)

            # Worker 2 received only bob_token
            self.assertIn("bob_token", res2)
            self.assertNotIn("alice_token", res2)

            # Inspect server-side recorded headers for /protected/whoami
            whoami_requests = [r for r in self.request_records if "/protected/whoami" in r[0]]
            for path, cookie in whoami_requests:
                if "worker=1" in path:
                    self.assertIn("auth_sess=alice_token", cookie)
                    self.assertNotIn("bob_token", cookie)
                elif "worker=2" in path:
                    self.assertIn("auth_sess=bob_token", cookie)
                    self.assertNotIn("alice_token", cookie)

            await worker1.close()
            await worker2.close()
        finally:
            await bm.close()

    async def test_engine_phase_attack_concurrent_isolates_cookie_jars(self):
        """ScanEngine._phase_attack_concurrent maintains isolated cookie jars across concurrent tasks."""
        from wscan.engine import CrawledPage, ScanEngine

        bm = BrowserManager(headless=True)
        await bm.init()
        try:
            eng = ScanEngine(self.base_url, checks=["xss"], concurrency=2)
            eng._browser = bm

            page_alice = CrawledPage(url=f"{self.base_url}/session/alice", html="", forms=[], url_params=[], depth=0)
            page_bob = CrawledPage(url=f"{self.base_url}/session/bob", html="", forms=[], url_params=[], depth=0)

            observed_identities = {}

            async def fake_attack_one_page(page, plans):
                # Navigate to the session page to receive Set-Cookie
                await eng.browser.navigate(page.url)
                # Introduce a tiny pause to allow concurrent interleaved requests
                await asyncio.sleep(0.05)
                # Query whoami endpoint
                tag = "alice" if "alice" in page.url else "bob"
                await eng.browser.navigate(f"{self.base_url}/protected/whoami?tag={tag}")
                body = await eng.browser.get_page_source()
                observed_identities[tag] = body

            eng._attack_one_page = fake_attack_one_page

            await eng._phase_attack_concurrent([page_alice, page_bob], {})

            # Verify neither worker received the other worker's session cookie
            self.assertIn("alice_token", observed_identities["alice"])
            self.assertNotIn("bob_token", observed_identities["alice"])

            self.assertIn("bob_token", observed_identities["bob"])
            self.assertNotIn("alice_token", observed_identities["bob"])
        finally:
            await bm.close()


if __name__ == "__main__":
    unittest.main()
