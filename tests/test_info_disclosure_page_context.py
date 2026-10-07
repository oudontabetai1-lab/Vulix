"""別ページの DOM ではなく対象 URL の詳細エラーを監査する回帰。"""
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch
import unittest

import httpx

from tests.fixtures.realistic_api import create_app
from wscan.scanners.base import BaseScanner, PageDocumentUnavailable
from wscan.scanners.info_disclosure import InfoDisclosureScanner


class ErrorPageContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_target_body_and_safe_twin_ignore_stale_dom(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app()), base_url="http://fixture.test"
        ) as client:
            for target, stale, expected in [
                ("/console/debug-error", "/console/safe-error", True),
                ("/console/safe-error", "/console/debug-error", False),
            ]:
                with self.subTest(target=target):
                    stale_body = (await client.get(stale)).text
                    engine = SimpleNamespace(
                        browser=SimpleNamespace(page=SimpleNamespace(content=AsyncMock(return_value=stale_body))),
                        monitor=None, payload_gen=None, wave_errors=[],
                    )
                    scanner = InfoDisclosureScanner(engine)
                    scanner._get = AsyncMock(side_effect=client.get)
                    scanner.current_page_pair = lambda url: {"response": {"body": stale_body}}
                    scanner.record_finding = AsyncMock(return_value=object())
                    url = f"http://fixture.test{target}"
                    findings = await scanner._check_error_page(url)
                    self.assertEqual(bool(findings), expected)
                    scanner._get.assert_awaited_once_with(url)
                    engine.browser.page.content.assert_not_awaited()
                    if expected:
                        details = scanner.record_finding.call_args.kwargs
                        self.assertEqual(details["url"], url)
                        self.assertEqual(details["evidence_details"]["matched_label"], "Python traceback")
                        self.assertIn("Traceback", details["pair"]["response"]["body"])

    async def test_unavailable_document_is_not_successful_empty_scan(self):
        engine = SimpleNamespace(browser=None, monitor=None, payload_gen=None, wave_errors=[])
        scanner = InfoDisclosureScanner(engine)
        scanner._get = AsyncMock(side_effect=httpx.ConnectError("offline"))
        scanner.current_page_pair = lambda url: {}
        with self.assertRaises(PageDocumentUnavailable):
            await scanner._check_error_page("http://fixture.test/console/debug-error")
        self.assertTrue(engine.wave_errors)


def test_realistic_api_error_page_engine_recall():
    """実エンジンで詳細エラー＋.env の Positive と安全ツインを確認。"""
    import os
    from urllib.parse import urlparse
    import pytest
    from wscan.benchmark_fixtures import UvicornFixtureLauncher
    from wscan.benchmark_scan import ScanEngineScanRunner

    if os.environ.get("WSCAN_E2E", "").lower() not in {"1", "true", "yes", "on"}:
        pytest.skip("WSCAN_E2E opt-in required")
    with UvicornFixtureLauncher().launch("realistic_api") as base:
        outcome = ScanEngineScanRunner(timeout=300)(base, ["info_disclosure"])
    paths = {urlparse(f.url).path for f in outcome.findings if f.check_type == "info_disclosure"}
    assert {"/.env", "/console/debug-error"} <= paths
    assert not {"/safe/.env", "/console/safe-error"} & paths
    assert ("info_disclosure", "/console/debug-error", "(page)", "page-level") in outcome.exercised


class PartialDisclosureTests(unittest.IsolatedAsyncioTestCase):
    async def test_document_failure_retains_already_detected_resource(self):
        scanner = InfoDisclosureScanner(SimpleNamespace(browser=None, monitor=None, payload_gen=None))
        resource = object()
        scanner._check_sensitive_files = AsyncMock(return_value=[resource])
        scanner._check_directory_listing = AsyncMock(return_value=[])
        scanner._check_tech_headers = AsyncMock(return_value=[])
        scanner._check_error_page = AsyncMock(side_effect=PageDocumentUnavailable("offline"))
        with self.assertRaises(PageDocumentUnavailable) as raised:
            await scanner.scan_page("http://fixture.test/console/debug-error")
        self.assertEqual(raised.exception.findings, [resource])


class DocumentVerificationTests(unittest.IsolatedAsyncioTestCase):
    async def test_verify_keeps_shared_protected_redirect_semantics(self):
        for kind in ("info_error_pattern", "info_tech_headers"):
            for target, allowed in [("http://outside.test/debug", False),
                                    ("http://fixture.test/debug", False),
                                    ("https://fixture.test/final", True)]:
                with self.subTest(kind=kind, target=target):
                    url = "https://fixture.test/debug"
                    redirect = SimpleNamespace(status=302, url=url, headers={"location": target},
                        text=AsyncMock(return_value="Traceback (most recent call last)"), dispose=AsyncMock())
                    final = SimpleNamespace(status=500, url=target, headers={"server": "fixture"},
                        text=AsyncMock(return_value="Traceback (most recent call last)"), dispose=AsyncMock())
                    get = AsyncMock(side_effect=[redirect, final])
                    sync = AsyncMock()
                    engine = SimpleNamespace(browser=SimpleNamespace(_context=SimpleNamespace(
                        request=SimpleNamespace(get=get))), monitor=None, payload_gen=None,
                        _sync_cookies_from_browser=sync)
                    scanner = InfoDisclosureScanner(engine)
                    assert await scanner.verify_finding(SimpleNamespace(url=url, evidence_type=kind)) is (
                        True if allowed else None)
                    assert get.await_count == (2 if allowed else 1)
                    assert all(call.kwargs["max_redirects"] == 0 for call in get.call_args_list)
                    sync.assert_awaited_once()

    async def test_verify_uses_uncached_shared_get_and_reports_unavailable(self):
        url = "http://fixture.test/debug"
        for kind in ("info_error_pattern", "info_tech_headers"):
            for response, expected in [
                (SimpleNamespace(status_code=500, text="Traceback (most recent call last)",
                                 headers={"server": "fixture"}), True),
                (SimpleNamespace(status_code=200, text="safe", headers={}), False),
                (SimpleNamespace(status_code=302, text="Traceback (most recent call last)",
                                 headers={"server": "fixture"}), None),
            ]:
                with self.subTest(kind=kind, status=response.status_code):
                    engine = SimpleNamespace(browser=None, monitor=None, payload_gen=None,
                                             _page_obs_raw_cache={url: {"body": "stale"}})
                    scanner = InfoDisclosureScanner(engine)
                    finding = SimpleNamespace(url=url, evidence_type=kind)
                    with patch.object(BaseScanner, "_get", AsyncMock(return_value=response)) as get:
                        self.assertIs(await scanner.verify_finding(finding), expected)
                        get.assert_awaited_once_with(url)
                    self.assertEqual(engine._page_obs_raw_cache[url]["body"], "stale")
        scanner = InfoDisclosureScanner(SimpleNamespace(browser=None, monitor=None, payload_gen=None))
        finding = SimpleNamespace(url=url, evidence_type="info_error_pattern")
        with patch.object(BaseScanner, "_get", AsyncMock(return_value=SimpleNamespace(
                status_code=200, text="", body_unavailable=True))):
            self.assertIsNone(await scanner.verify_finding(finding))
        with patch.object(BaseScanner, "_get", AsyncMock(side_effect=RuntimeError("offline"))):
            self.assertIsNone(await scanner.verify_finding(finding))

    async def test_resource_and_directory_verification_remain_no_follow(self):
        for kind in ("info_sensitive_resource", "info_directory_listing"):
            scanner = InfoDisclosureScanner(SimpleNamespace(browser=None, monitor=None, payload_gen=None))
            scanner._get = AsyncMock(return_value=SimpleNamespace(status_code=302))
            finding = SimpleNamespace(url="http://fixture.test/resource", evidence_type=kind)
            self.assertFalse(await scanner.verify_finding(finding))
            scanner._get.assert_awaited_once_with(finding.url, follow_redirects=False)


def test_rotating_cookie_document_verification_chromium():
    """再検証の Set-Cookie を native jar に反映し、後続ブラウザ要求の認証を保つ。"""
    import asyncio
    import os
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    import pytest
    from playwright.async_api import async_playwright

    if os.environ.get("WSCAN_E2E", "").lower() not in {"1", "true", "yes", "on"}:
        pytest.skip("WSCAN_E2E opt-in required")

    class Handler(BaseHTTPRequestHandler):
        session = "s1"
        calls = []

        def do_GET(self):
            cookie = self.headers.get("Cookie", "")
            Handler.calls.append((self.path, cookie))
            if self.path == "/hop":
                self.send_response(302)
                self.send_header("Location", "/protected")
                self.end_headers()
                return
            authorized = cookie == f"sid={Handler.session}"
            self.send_response(500 if self.path == "/debug" and authorized else 200 if authorized else 401)
            if self.path == "/debug" and authorized:
                Handler.session = f"s{int(Handler.session[1:]) + 1}"
                self.send_header("Set-Cookie", f"sid={Handler.session}; Path=/; HttpOnly")
            self.send_header("Server", "fixture")
            self.end_headers()
            self.wfile.write(b"Traceback (most recent call last)" if self.path == "/debug" else b"ok")

        def log_message(self, *args):
            pass

    async def run(base):
        async with async_playwright() as p:
            browser = await p.chromium.launch(headless=True)
            try:
                context = await browser.new_context()
                await context.add_cookies([{"name": "sid", "value": "s1", "url": base, "httpOnly": True}])
                engine = SimpleNamespace(browser=SimpleNamespace(_context=context), monitor=None,
                                         payload_gen=None, timeout=3, cookies="sid=s1")
                engine.auth_headers = lambda extra=None, include_cookie=True: (
                    {"Cookie": engine.cookies} if include_cookie else {})

                async def sync(browser, url):
                    engine.cookies = "; ".join(f"{c['name']}={c['value']}" for c in await context.cookies(base))

                engine._sync_cookies_from_browser = sync
                scanner = InfoDisclosureScanner(engine)
                scanner.record_finding = AsyncMock(return_value=object())
                assert await scanner._check_error_page(base + "/debug")
                assert engine.cookies == "sid=s2"
                for kind, value in [("info_error_pattern", "s3"), ("info_tech_headers", "s4")]:
                    assert await scanner.verify_finding(SimpleNamespace(
                        url=base + "/debug", evidence_type=kind)) is True
                    assert Handler.session == value
                    cookies = await context.cookies(base)
                    assert cookies[0]["value"] == value and cookies[0]["httpOnly"]
                    assert engine.cookies == f"sid={value}"
                page = await context.new_page()
                from wscan.browser import NetworkCapture
                network = NetworkCapture()
                page.on("request", network.on_request)
                page.on("response", network.on_response)
                response = await page.goto(base + "/protected")
                assert response.status == 200
                await network.enrich_response(response)
                engine.browser.network = network
                with patch.object(scanner, "_get", AsyncMock(side_effect=RuntimeError("offline"))):
                    raw = await scanner._compute_raw_document(base + "/protected")
                assert raw["body"] == "ok" and raw["status"] == 200
                assert network.pairs[0]["request"]["resource_type"] == "document"
                assert network.pairs[0]["request"]["_req_id"] == network.pairs[0]["response"]["_req_id"]
                # native redirect 連鎖: Chromium の 302 hop と redirected_from で最終 document を証明する。
                network.clear()
                response = await page.goto(base + "/hop")
                await network.enrich_response(response)
                assert [p["response"]["status"] for p in network.pairs] == [302, 200]
                assert (network.pairs[1]["request"]["_redirected_from_req_id"]
                        == network.pairs[0]["request"]["_req_id"])
                scanner.engine._page_obs_raw_cache = {}
                with patch.object(scanner, "_get", AsyncMock(side_effect=RuntimeError("offline"))):
                    raw = await scanner._compute_raw_document(base + "/hop")
                assert raw["body"] == "ok" and raw["url"] == base + "/protected"
                assert Handler.calls == [("/debug", "sid=s1"), ("/debug", "sid=s2"),
                                         ("/debug", "sid=s3"), ("/protected", "sid=s4"),
                                         ("/hop", "sid=s4"), ("/protected", "sid=s4")]
            finally:
                await browser.close()

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        asyncio.run(run(f"http://127.0.0.1:{server.server_port}"))
    finally:
        server.shutdown()
        server.server_close()
        thread.join()
