"""
Unit and regression tests for SQLi scanner authentication bypass oracle
and HTTP status / probe delivery truth.
"""
from types import SimpleNamespace
import unittest
from unittest.mock import AsyncMock

from wscan.injection_point import InjectionPoint
from wscan.scanners.sqli import SQLiScanner


class MockBrowser:
    def __init__(self, current_url="http://example.com/dashboard", delivered=True, pair=None):
        self.page = SimpleNamespace(url=current_url)
        self.last_probe_delivered = delivered
        self.last_pair = pair
        self.network = SimpleNamespace(latest=lambda: self.last_pair)


class SQLiAuthBypassOracleTests(unittest.TestCase):
    def setUp(self):
        self.scanner = object.__new__(SQLiScanner)
        self.scanner.engine = SimpleNamespace(login_success_indicator="")
        self.original_url = "http://example.com/login"

    def test_http_status_errors_rejected_as_auth_bypass(self):
        """HTTP 401, 403, 404, 429, 500 on /dashboard -> (False, ...)"""
        for code in (401, 403, 404, 429, 500):
            with self.subTest(status_code=code):
                pair = {"response": {"status": code}}
                self.scanner.browser = MockBrowser(
                    current_url="http://example.com/dashboard",
                    delivered=True,
                    pair=pair,
                )
                source = "Welcome to your private dashboard! Here is your secret account data and settings."
                bypassed, post_url = self.scanner._detect_auth_bypass(
                    self.original_url, source, pair=pair
                )
                self.assertFalse(bypassed)
                self.assertEqual(post_url, "http://example.com/dashboard")

                # Also test when pair is inspected via browser.last_pair
                bypassed_no_pair, post_url_no_pair = self.scanner._detect_auth_bypass(
                    self.original_url, source
                )
                self.assertFalse(bypassed_no_pair)
                self.assertEqual(post_url_no_pair, "http://example.com/dashboard")

    def test_unauthenticated_public_redirect_rejected(self):
        """Redirect to unauthenticated /public page with 200 OK -> (False, ...)"""
        pair = {"response": {"status": 200}}
        self.scanner.browser = MockBrowser(
            current_url="http://example.com/public",
            delivered=True,
            pair=pair,
        )
        source = "Welcome to our public page! Nothing secret here, just general information for all visitors."
        bypassed, post_url = self.scanner._detect_auth_bypass(
            self.original_url, source, pair=pair
        )
        self.assertFalse(bypassed)
        self.assertEqual(post_url, "http://example.com/public")

    def test_undelivered_probe_rejected(self):
        """Undelivered probe (browser.last_probe_delivered = False) -> (False, ...)"""
        pair = {"response": {"status": 200}}
        self.scanner.browser = MockBrowser(
            current_url="http://example.com/dashboard",
            delivered=False,
            pair=pair,
        )
        source = "Welcome to your private dashboard! Here is your secret account data and settings."
        bypassed, post_url = self.scanner._detect_auth_bypass(
            self.original_url, source, pair=pair
        )
        self.assertFalse(bypassed)
        self.assertEqual(post_url, "http://example.com/dashboard")

    def test_valid_bypass_still_detected(self):
        """Valid authenticated bypass on /dashboard / /admin with HTTP 200 and authenticated content -> (True, ...)"""
        pair = {"response": {"status": 200}}
        self.scanner.browser = MockBrowser(
            current_url="http://example.com/dashboard",
            delivered=True,
            pair=pair,
        )
        source = "Welcome to your private dashboard! Here is your secret account data and settings."
        bypassed, post_url = self.scanner._detect_auth_bypass(
            self.original_url, source, pair=pair
        )
        self.assertTrue(bypassed)
        self.assertEqual(post_url, "http://example.com/dashboard")

        # Test with /admin and logout link
        self.scanner.browser = MockBrowser(
            current_url="http://example.com/admin",
            delivered=True,
            pair=pair,
        )
        source_admin = "<html><body><h1>Admin Console</h1><a href='/logout'>Sign out</a></body></html>"
        bypassed_admin, post_url_admin = self.scanner._detect_auth_bypass(
            self.original_url, source_admin, pair=pair
        )
        self.assertTrue(bypassed_admin)
        self.assertEqual(post_url_admin, "http://example.com/admin")


class SQLiScanInjectionPointNegativeTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_injection_point_negative_on_403_or_public_redirect(self):
        """End-to-end scan_injection_point negative test confirming no sqli_auth_bypass finding is emitted when /dashboard returns HTTP 403 or redirects to /public."""
        scanner = object.__new__(SQLiScanner)
        scanner.engine = SimpleNamespace(
            login_success_indicator="",
            max_payloads=10,
            custom_payloads={},
            _finding_dedup=set(),
            all_findings=[],
        )
        scanner.monitor = None
        scanner._field_budget_gate = lambda: False
        scanner.may_scan_injection_point = lambda ip: True
        scanner.get_payloads = AsyncMock(return_value=["' OR '1'='1"])
        scanner.log_payload_test = AsyncMock()
        scanner.check_response_for_patterns = lambda source, patterns: False
        scanner.response_time_exceeded = lambda pair, threshold: False

        # Test Case 1: /dashboard returns HTTP 403
        browser_403 = MockBrowser(
            current_url="http://example.com/dashboard",
            delivered=True,
            pair={"response": {"status": 403, "body": "Forbidden"}},
        )
        scanner.browser = browser_403

        async def fake_baseline(ip):
            return "<html><body><form action='/login'><input name='username'></form></body></html>", {"response": {"status": 200}}

        async def fake_apply_403(ip, payload, **kwargs):
            return "Forbidden access to dashboard", {"response": {"status": 403}}

        scanner._get_baseline = fake_baseline
        scanner._apply_ip = fake_apply_403
        scanner._probe_decision = lambda *args, **kwargs: None
        scanner.record_finding = AsyncMock()

        ip = InjectionPoint.for_form("http://example.com/login", "username", 0)
        findings = await scanner.scan_injection_point(ip, {"name": "username"})
        auth_bypass_findings = [f for f in (findings or []) if getattr(f, "evidence_type", "") == "sqli_auth_bypass"]
        self.assertEqual(len(auth_bypass_findings), 0)
        scanner.record_finding.assert_not_called()

        # Test Case 2: redirects to /public
        browser_public = MockBrowser(
            current_url="http://example.com/public",
            delivered=True,
            pair={"response": {"status": 200, "body": "Public page"}},
        )
        scanner.browser = browser_public

        async def fake_apply_public(ip, payload, **kwargs):
            return "Welcome to our public page! Nothing secret here, just general information for all visitors.", {"response": {"status": 200}}

        scanner._apply_ip = fake_apply_public
        findings = await scanner.scan_injection_point(ip, {"name": "username"})
        auth_bypass_findings = [f for f in (findings or []) if getattr(f, "evidence_type", "") == "sqli_auth_bypass"]
        self.assertEqual(len(auth_bypass_findings), 0)
        scanner.record_finding.assert_not_called()


if __name__ == "__main__":
    unittest.main()
