"""
Tests for SQLi attack status truth: classifying auth-lost and blocked responses
as unexecuted/indeterminate, preventing silent false negatives, and ensuring
checkpoint units remain incomplete for retry.
"""
from __future__ import annotations

import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from wscan.checkpoint import CheckpointState
from wscan.injection_point import InjectionPoint
from wscan.scanners.sqli import SQLiScanner, classify_sqli_response


class ClassifySqliResponseTests(unittest.TestCase):
    """Pure unit tests for classify_sqli_response distinguishing session_lost vs blocked."""

    def test_unauthorized_status_401(self):
        """HTTP 401 returns ('session_lost', '401')."""
        result = classify_sqli_response(
            status=401,
            final_url="http://example.com/profile",
            body="<html><body>Unauthorized</body></html>",
            target_url="http://example.com/profile",
        )
        self.assertEqual(result, ("session_lost", "401"))

    def test_forbidden_status_403(self):
        """HTTP 403 returns ('blocked', '403')."""
        result = classify_sqli_response(
            status=403,
            final_url="http://example.com/search",
            body="<html><body>Forbidden</body></html>",
            target_url="http://example.com/search",
        )
        self.assertEqual(result, ("blocked", "403"))

    def test_rate_limited_status_429(self):
        """HTTP 429 returns ('blocked', '429')."""
        result = classify_sqli_response(
            status=429,
            final_url="http://example.com/items",
            body="<html><body>Too Many Requests</body></html>",
            target_url="http://example.com/items",
        )
        self.assertEqual(result, ("blocked", "429"))

    def test_server_error_500_without_sql_error(self):
        """HTTP 500 without SQL error returns ('blocked', '500')."""
        result = classify_sqli_response(
            status=500,
            final_url="http://example.com/search",
            body="<html><body>Internal Server Error</body></html>",
            target_url="http://example.com/search",
            has_sql_error=False,
        )
        self.assertEqual(result, ("blocked", "500"))

    def test_server_error_500_with_sql_error_preserves_finding(self):
        """HTTP 500 with a real SQL error is not suppressed (returns None)."""
        result = classify_sqli_response(
            status=500,
            final_url="http://example.com/search",
            body="<html><body>sqlite3.OperationalError: near syntax error</body></html>",
            target_url="http://example.com/search",
            has_sql_error=True,
        )
        self.assertIsNone(result)

    def test_gateway_errors_502_503_504(self):
        """502, 503, 504 return ('blocked', '<code>')."""
        for code in (502, 503, 504):
            with self.subTest(code=code):
                result = classify_sqli_response(
                    status=code,
                    final_url="http://example.com/search",
                    body="<html><body>Bad Gateway</body></html>",
                    target_url="http://example.com/search",
                )
                self.assertEqual(result, ("blocked", str(code)))

    def test_redirect_to_login_page_detected(self):
        """Redirect from authenticated target_url to login page returns ('session_lost', 'login_redirect')."""
        result = classify_sqli_response(
            status=200,
            final_url="http://example.com/login",
            body="<html><body><form action='/login'><input type='password' name='password'></form></body></html>",
            target_url="http://example.com/dashboard",
            login_url="http://example.com/login",
        )
        self.assertEqual(result, ("session_lost", "login_redirect"))

    def test_preauth_login_form_target_not_classified_as_auth_lost(self):
        """Scanning a login page itself (target_url == /login) must not be classified as auth lost."""
        result = classify_sqli_response(
            status=200,
            final_url="http://example.com/login",
            body="<html><body><form action='/login'><input name='username'><input type='password' name='password'></form></body></html>",
            target_url="http://example.com/login",
            login_url="http://example.com/login",
        )
        self.assertIsNone(result)

    def test_preauth_login_form_401_credential_rejection_not_classified(self):
        """On a pre-auth login page, 401 invalid credentials is normal response, not session loss."""
        result = classify_sqli_response(
            status=401,
            final_url="http://example.com/login",
            body="<html><body>Invalid username or password</body></html>",
            target_url="http://example.com/login",
            login_url="http://example.com/login",
        )
        self.assertIsNone(result)

    def test_preauth_login_form_403_is_classified_as_blocked(self):
        """On a login page, WAF 403 is still classified as blocked."""
        result = classify_sqli_response(
            status=403,
            final_url="http://example.com/login",
            body="<html><body>Access Denied</body></html>",
            target_url="http://example.com/login",
            login_url="http://example.com/login",
        )
        self.assertEqual(result, ("blocked", "403"))

    def test_normal_authenticated_response_returns_none(self):
        """Normal HTTP 200 response on authenticated page returns None."""
        result = classify_sqli_response(
            status=200,
            final_url="http://example.com/dashboard",
            body="<html><body><h1>Dashboard</h1><p>Search results for query</p></body></html>",
            target_url="http://example.com/dashboard",
            login_url="http://example.com/login",
        )
        self.assertIsNone(result)


class MockTestBrowser:
    def __init__(self, current_url="http://example.com/dashboard", delivered=True, pair=None):
        self.page = SimpleNamespace(url=current_url)
        self.last_probe_delivered = delivered
        self.last_pair = pair
        self.network = SimpleNamespace(latest=lambda: self.last_pair)


class SQLiScannerAttackStatusTests(unittest.IsolatedAsyncioTestCase):
    """Scanner-level tests for vulnerable and safe twin form / URL-param fields."""

    def _make_scanner(self, browser, login_url="http://example.com/login"):
        scanner = object.__new__(SQLiScanner)
        scanner.engine = SimpleNamespace(
            login_url=login_url,
            logged_in_marker="",
            login_success_indicator="",
            max_payloads=10,
            sleep_factor=0.0,
            custom_payloads={},
            _finding_dedup=set(),
            all_findings=[],
            wave_errors=[],
            _api_auth_failed=False,
            _json_probe_failed=False,
        )
        scanner.browser = browser
        scanner.monitor = None
        scanner.CHECK_TYPE = "sqli"
        scanner._field_budget_gate = lambda: False
        scanner.may_scan_injection_point = lambda ip: True
        scanner.get_payloads = AsyncMock(return_value=["payload_500", "payload_403", "' OR 1=1 --"])
        scanner._prioritize_login_payloads = lambda fn, pls: pls
        scanner.log_payload_test = AsyncMock()
        scanner._probe_id = lambda p: "probe_1"
        scanner.response_time_exceeded = lambda pair, threshold: False
        scanner._probe_decision = lambda *args, **kwargs: None
        scanner._body_similarity = lambda a, b: 0.95
        return scanner

    async def test_vulnerable_endpoint_blocked_first_payloads_later_payload_detects_sqli(self):
        """Vulnerable endpoint where initial payloads get generic 500 / 403, and later payload proves SQLi."""
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        scanner = self._make_scanner(browser)

        async def fake_get_baseline(ip):
            return "<html><body>Authenticated dashboard content</body></html>", {
                "response": {"status": 200, "url": "http://example.com/dashboard"}
            }

        async def fake_apply_ip(ip, payload, **kwargs):
            if payload == "payload_500":
                # Generic 500 without DB error
                return "<html><body>Internal Server Error</body></html>", {
                    "response": {"status": 500, "url": "http://example.com/dashboard"}
                }
            elif payload == "payload_403":
                # WAF 403 block
                return "<html><body>Forbidden by WAF</body></html>", {
                    "response": {"status": 403, "url": "http://example.com/dashboard"}
                }
            elif "' OR 1=1" in payload:
                # Real SQL error finding
                return "<html><body>SQL error: syntax error near '...</body></html>", {
                    "response": {"status": 200, "url": "http://example.com/dashboard"}
                }
            return "<html><body>Dashboard</body></html>", {
                "response": {"status": 200, "url": "http://example.com/dashboard"}
            }

        scanner._get_baseline = fake_get_baseline
        scanner._apply_ip = fake_apply_ip
        ip_url = "http://example.com/dashboard"
        scanner.record_finding = AsyncMock(return_value=SimpleNamespace(
            url=ip_url,
            field_name="search_q",
            check_type="sqli",
            evidence_type="sqli_error",
        ))

        ip = InjectionPoint.for_form("http://example.com/dashboard", "search_q", 0)
        findings = await scanner.scan_injection_point(ip, {"name": "search_q"})

        # Finding MUST still be produced!
        self.assertEqual(len(findings), 1)
        # Blocked notes recorded
        self.assertTrue(any("response_blocked:sqli:500" in n for n in scanner.engine.wave_errors))
        self.assertTrue(any("response_blocked:sqli:403" in n for n in scanner.engine.wave_errors))
        # auth_lost was NOT set!
        self.assertFalse(scanner.engine._api_auth_failed)

    async def test_safe_twin_all_403_records_all_blocked_and_incomplete(self):
        """Safe twin where every probe returns 403 records all_probes_blocked note without findings."""
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        scanner = self._make_scanner(browser)

        async def fake_get_baseline(ip):
            return "<html><body>Forbidden</body></html>", {
                "response": {"status": 403, "url": "http://example.com/dashboard"}
            }

        async def fake_apply_ip(ip, payload, **kwargs):
            return "<html><body>Forbidden</body></html>", {
                "response": {"status": 403, "url": "http://example.com/dashboard"}
            }

        scanner._get_baseline = fake_get_baseline
        scanner._apply_ip = fake_apply_ip

        ip = InjectionPoint.for_form("http://example.com/dashboard", "safe_q", 0)
        findings = await scanner.scan_injection_point(ip, {"name": "safe_q"})

        self.assertEqual(len(findings), 0)
        self.assertTrue(any("response_blocked:sqli:403" in n for n in scanner.engine.wave_errors))
        self.assertTrue(any("all_probes_blocked:sqli" in n for n in scanner.engine.wave_errors))
        # Not auth lost (no 401 or redirect)
        self.assertFalse(scanner.engine._api_auth_failed)

    async def test_vulnerable_form_session_expired_mid_attack_records_note_and_stops_field(self):
        """When an authenticated vulnerable form loses session (redirect to /login), scan note is recorded."""
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        scanner = self._make_scanner(browser)

        call_count = [0]

        async def fake_get_baseline(ip):
            return "<html><body>Authenticated dashboard content</body></html>", {
                "response": {"status": 200, "url": "http://example.com/dashboard"}
            }

        async def fake_apply_ip(ip, payload, **kwargs):
            call_count[0] += 1
            # Mid-attack, session expires: redirects to /login
            browser.page.url = "http://example.com/login"
            return (
                "<html><body><h2>Login</h2><form action='/login'><input type='password'></form></body></html>",
                {"response": {"status": 302, "url": "http://example.com/login"}},
            )

        scanner._get_baseline = fake_get_baseline
        scanner._apply_ip = fake_apply_ip

        ip = InjectionPoint.for_form("http://example.com/dashboard", "search_q", 0)
        findings = await scanner.scan_injection_point(ip, {"name": "search_q"})

        # No findings recorded on dead session
        self.assertEqual(len(findings), 0)
        # Scan note recorded
        self.assertTrue(any(n.startswith("auth_lost:sqli:login_redirect") for n in scanner.engine.wave_errors))
        self.assertTrue(scanner.engine._api_auth_failed)

    async def test_safe_twin_session_expired_mid_attack_stays_clean(self):
        """Safe twin field whose session expires stays clean (no false positives) and records auth_lost."""
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        scanner = self._make_scanner(browser)

        async def fake_get_baseline(ip):
            return "<html><body>Safe authenticated results</body></html>", {
                "response": {"status": 200, "url": "http://example.com/dashboard"}
            }

        async def fake_apply_ip(ip, payload, **kwargs):
            # Session expired returning 401
            browser.page.url = "http://example.com/dashboard"
            return "Unauthorized", {"response": {"status": 401, "url": "http://example.com/dashboard"}}

        scanner._get_baseline = fake_get_baseline
        scanner._apply_ip = fake_apply_ip

        ip = InjectionPoint.for_form("http://example.com/dashboard", "safe_q", 1)
        findings = await scanner.scan_injection_point(ip, {"name": "safe_q"})

        # Must not add false positives
        self.assertEqual(len(findings), 0)
        # Records auth_lost
        self.assertTrue(any(n.startswith("auth_lost:sqli:401") for n in scanner.engine.wave_errors))
        self.assertTrue(scanner.engine._api_auth_failed)

    async def test_baseline_auth_lost_returns_immediately(self):
        """If baseline itself is auth-lost (401 or login redirect), scanner aborts before payload test."""
        browser = MockTestBrowser(current_url="http://example.com/login")
        scanner = self._make_scanner(browser)

        apply_called = [False]

        async def fake_get_baseline(ip):
            return "<html><body><form action='/login'></form></body></html>", {
                "response": {"status": 302, "url": "http://example.com/login"}
            }

        async def fake_apply_ip(ip, payload, **kwargs):
            apply_called[0] = True
            return "", {}

        scanner._get_baseline = fake_get_baseline
        scanner._apply_ip = fake_apply_ip

        ip = InjectionPoint.for_form("http://example.com/dashboard", "search_q", 0)
        findings = await scanner.scan_injection_point(ip, {"name": "search_q"})

        self.assertEqual(len(findings), 0)
        self.assertFalse(apply_called[0])
        self.assertTrue(any(n.startswith("auth_lost:sqli:login_redirect") for n in scanner.engine.wave_errors))

    async def test_verify_finding_indeterminate_on_auth_lost(self):
        """During verify_finding, an auth-lost response returns None (indeterminate) to avoid false downgrade."""
        browser = MockTestBrowser(current_url="http://example.com/login")
        scanner = self._make_scanner(browser)

        async def fake_apply_ip(ip, payload, **kwargs):
            return "<html><body>Login</body></html>", {"response": {"status": 302, "url": "http://example.com/login"}}

        scanner._apply_ip = fake_apply_ip

        finding = SimpleNamespace(
            url="http://example.com/dashboard",
            field_name="search_q",
            payload="'",
            evidence_type="sqli_error",
        )
        result = await scanner.verify_finding(finding)
        self.assertIsNone(result)
        self.assertTrue(scanner.engine._api_auth_failed)

    async def test_verify_finding_indeterminate_on_blocked_403(self):
        """During verify_finding, a 403 blocked response returns None (indeterminate) without auth_failed."""
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        scanner = self._make_scanner(browser)

        async def fake_apply_ip(ip, payload, **kwargs):
            return "<html><body>Forbidden</body></html>", {"response": {"status": 403, "url": "http://example.com/dashboard"}}

        scanner._apply_ip = fake_apply_ip

        finding = SimpleNamespace(
            url="http://example.com/dashboard",
            field_name="search_q",
            payload="'",
            evidence_type="sqli_error",
        )
        result = await scanner.verify_finding(finding)
        self.assertIsNone(result)
        self.assertTrue(any("response_blocked:sqli:403" in n for n in scanner.engine.wave_errors))
        self.assertFalse(scanner.engine._api_auth_failed)


class EngineCheckpointIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Engine-level tests asserting checkpoint state is not marked complete on auth-lost or all-blocked."""

    async def test_scan_field_with_auth_lost_leaves_checkpoint_incomplete(self):
        """When SQLi scanner records auth_lost note, _scan_field sets status='error' and does not mark checkpoint done."""
        from wscan.engine import ScanEngine

        engine = ScanEngine(
            "http://example.com/dashboard",
            checks=["sqli"],
            llm_provider="none",
            headless=True,
            login_url="http://example.com/login",
        )
        engine.checkpoint = CheckpointState(target_url="http://example.com/dashboard")
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        engine._browser = browser

        scanner = object.__new__(SQLiScanner)
        scanner.engine = engine
        scanner.browser = browser
        scanner.monitor = None
        engine.sleep_factor = 0.0
        scanner.CHECK_TYPE = "sqli"
        scanner.may_scan_injection_point = lambda ip: True

        async def fake_scan_ip(ip, field):
            scanner._record_scan_note("auth_lost:sqli:login_redirect")
            engine._api_auth_failed = True
            return []

        scanner.scan_injection_point = fake_scan_ip
        engine.scanners["sqli"] = scanner

        ip = InjectionPoint.for_form("http://example.com/dashboard", "vuln_q", 0)

        await engine._scan_field(
            url="http://example.com/dashboard",
            form_index=0,
            field={"name": "vuln_q"},
            is_url_param=False,
        )

        # Assert checkpoint is NOT marked done!
        self.assertFalse(engine._checkpoint_is_done_ip(ip, "sqli"))

        # Assert scan matrix recorded error status
        matrix_rows = [r for r in engine.scan_matrix if r["field_name"] == "vuln_q"]
        self.assertEqual(len(matrix_rows), 1)
        self.assertEqual(matrix_rows[0]["status"], "error")
        self.assertIn("session lost", matrix_rows[0]["note"])

    async def test_scan_field_with_all_probes_blocked_leaves_checkpoint_incomplete(self):
        """When all probes are blocked, _scan_field sets status='error' and leaves checkpoint incomplete."""
        from wscan.engine import ScanEngine

        engine = ScanEngine(
            "http://example.com/dashboard",
            checks=["sqli"],
            llm_provider="none",
            headless=True,
            login_url="http://example.com/login",
        )
        engine.checkpoint = CheckpointState(target_url="http://example.com/dashboard")
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        engine._browser = browser

        scanner = object.__new__(SQLiScanner)
        scanner.engine = engine
        scanner.browser = browser
        scanner.monitor = None
        engine.sleep_factor = 0.0
        scanner.CHECK_TYPE = "sqli"
        scanner.may_scan_injection_point = lambda ip: True

        async def fake_scan_ip(ip, field):
            scanner._record_scan_note("response_blocked:sqli:403")
            scanner._record_scan_note("all_probes_blocked:sqli")
            return []

        scanner.scan_injection_point = fake_scan_ip
        engine.scanners["sqli"] = scanner

        ip = InjectionPoint.for_form("http://example.com/dashboard", "blocked_q", 0)

        await engine._scan_field(
            url="http://example.com/dashboard",
            form_index=0,
            field={"name": "blocked_q"},
            is_url_param=False,
        )

        # Assert checkpoint is NOT marked done!
        self.assertFalse(engine._checkpoint_is_done_ip(ip, "sqli"))

        # Assert scan matrix recorded error status
        matrix_rows = [r for r in engine.scan_matrix if r["field_name"] == "blocked_q"]
        self.assertEqual(len(matrix_rows), 1)
        self.assertEqual(matrix_rows[0]["status"], "error")
        self.assertIn("all probes blocked", matrix_rows[0]["note"])

    async def test_scan_field_successful_safe_twin_marks_checkpoint_done(self):
        """When safe twin completes scan with evaluable responses and no findings, status is 'tested' and checkpoint is done."""
        from wscan.engine import ScanEngine

        engine = ScanEngine(
            "http://example.com/dashboard",
            checks=["sqli"],
            llm_provider="none",
            headless=True,
            login_url="http://example.com/login",
        )
        engine.checkpoint = CheckpointState(target_url="http://example.com/dashboard")
        browser = MockTestBrowser(current_url="http://example.com/dashboard")
        engine._browser = browser

        scanner = object.__new__(SQLiScanner)
        scanner.engine = engine
        scanner.browser = browser
        scanner.monitor = None
        engine.sleep_factor = 0.0
        scanner.CHECK_TYPE = "sqli"
        scanner.may_scan_injection_point = lambda ip: True

        async def fake_scan_ip(ip, field):
            # Normal clean scan with no findings
            return []

        scanner.scan_injection_point = fake_scan_ip
        engine.scanners["sqli"] = scanner

        ip = InjectionPoint.for_form("http://example.com/dashboard", "safe_q", 1)

        await engine._scan_field(
            url="http://example.com/dashboard",
            form_index=1,
            field={"name": "safe_q"},
            is_url_param=False,
        )

        # Assert checkpoint IS marked done for clean safe field
        self.assertTrue(engine._checkpoint_is_done_ip(ip, "sqli"))

        # Assert scan matrix recorded 'tested'
        matrix_rows = [r for r in engine.scan_matrix if r["field_name"] == "safe_q"]
        self.assertEqual(len(matrix_rows), 1)
        self.assertEqual(matrix_rows[0]["status"], "tested")
        self.assertEqual(matrix_rows[0]["finding_count"], 0)

    async def test_fallback_verify_non_json_not_assumed_on_stale_flag(self):
        """Fallback verify on non-JSON locations resets stale auth/transport flags so real finding is reproduced."""
        from wscan.engine import ScanEngine
        from wscan.scanners.base import Finding

        engine = ScanEngine(
            "http://example.com/items",
            checks=["xss"],
            llm_provider="none",
            headless=True,
        )
        browser = MockTestBrowser(current_url="http://example.com/items")
        browser.dialog_fired = True
        browser.navigate = AsyncMock()
        browser.reset_dialog = lambda: None
        engine._browser = browser

        # Set stale flags left from an earlier check
        engine._api_auth_failed = True
        engine._json_probe_failed = True

        scanner = SimpleNamespace(
            _apply_ip=AsyncMock(return_value=("<html>alert(1)</html>", {"response": {"status": 200}})),
            _check_reflected=lambda src, pl: True,
        )
        engine.scanners["xss"] = scanner

        finding = Finding(
            url="http://example.com/items?q=test",
            field_name="q",
            check_type="xss",
            payload="<script>alert(1)</script>",
            evidence="alert(1)",
            severity="high",
            confidence="confirmed",
        )
        finding.injection_location = "url_param"

        status = await engine._verify_one(finding)
        self.assertEqual(status, "reproduced")
        # Stale flags were reset
        self.assertFalse(engine._api_auth_failed)
        self.assertFalse(engine._json_probe_failed)
