"""別ページの DOM ではなく対象 URL の詳細エラーを監査する回帰。"""
from types import SimpleNamespace
from unittest.mock import AsyncMock
import unittest

import httpx

from tests.fixtures.realistic_api import create_app
from wscan.scanners.base import PageDocumentUnavailable
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
