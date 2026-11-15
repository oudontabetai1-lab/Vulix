"""Tests for safe token stale detection, refresh, and bounded retry recovery.

Verifies response classification (auth_expired vs csrf_stale vs rate_limited),
non-idempotent state-changing probe retry safety, bounded retry budget,
and redaction invariants.
"""
from __future__ import annotations

import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.token_lifecycle import (
    ConsumptionCondition,
    RefreshKind,
    RefreshStrategy,
    TokenBinding,
    TokenCarrier,
    TokenLifecycleEvent,
    TokenOutcome,
    TokenOutcomeKind,
    TokenTransport,
    classify_token_response,
    decide_token_retry,
    derive_token_ref_id,
    is_probe_conclusive,
    redact_token_value,
)


class MockEngine:
    def __init__(self, enabled: bool = True):
        self.token_lifecycle_manager = enabled
        self._probe_inconclusive = False
        self._api_auth_failed = False
        self._json_probe_failed = False
        self.wave_errors: list[str] = []
        self.events: list[TokenLifecycleEvent] = []
        self.monitor = None
        self.payload_gen = None
        self.browser = None
        self.all_findings: list = []

    def record_token_lifecycle_event(self, event: TokenLifecycleEvent) -> None:
        self.events.append(event)


class DummyScanner(BaseScanner):
    CHECK_TYPE = "xss"

    def __init__(self, engine: MockEngine | None = None):
        super().__init__(engine or MockEngine())
        self._probe_failures: list[str] = []

    def _probe_failure(self, reason: str = "") -> None:
        self._probe_failures.append(reason)

    def _token_manager_enabled(self, carrier=None, transport=None) -> bool:
        return bool(getattr(self.engine, "token_lifecycle_manager", False))

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ):
        return []


class ResponseClassificationTests(unittest.TestCase):
    """Classification tests distinguishing auth_expired, rate_limited, and stale CSRF."""

    def test_auth_expired_401(self):
        outcome = classify_token_response(status_code=401, body="Unauthorized")
        self.assertEqual(outcome.outcome, TokenOutcomeKind.AUTH_EXPIRED)
        self.assertEqual(outcome.reason_code, "auth_expired")
        self.assertFalse(outcome.is_retryable)
        self.assertFalse(is_probe_conclusive(outcome))

    def test_auth_expired_login_redirect(self):
        outcome = classify_token_response(
            status_code=302,
            headers={"Location": "/auth/login?next=/profile"},
            body="",
        )
        self.assertEqual(outcome.outcome, TokenOutcomeKind.AUTH_EXPIRED)
        self.assertEqual(outcome.reason_code, "auth_expired")
        self.assertFalse(outcome.is_retryable)

    def test_auth_expired_explicit_body_signal(self):
        for phrase in ("Session has expired", "Authentication required", "Please log in"):
            outcome = classify_token_response(status_code=403, body=f"<html>{phrase}</html>")
            self.assertEqual(outcome.outcome, TokenOutcomeKind.AUTH_EXPIRED)
            self.assertEqual(outcome.reason_code, "auth_expired")

    def test_rate_limited_429(self):
        outcome = classify_token_response(status_code=429, body="Too Many Requests")
        self.assertEqual(outcome.outcome, TokenOutcomeKind.RATE_LIMITED)
        self.assertEqual(outcome.reason_code, "rate_limited")
        self.assertFalse(outcome.is_retryable)
        self.assertFalse(is_probe_conclusive(outcome))

    def test_rate_limited_retry_after_header(self):
        outcome = classify_token_response(
            status_code=503,
            headers={"Retry-After": "60"},
            body="Temporarily unavailable",
        )
        self.assertEqual(outcome.outcome, TokenOutcomeKind.RATE_LIMITED)
        self.assertEqual(outcome.reason_code, "rate_limited")

    def test_csrf_stale_mismatch(self):
        outcome = classify_token_response(
            status_code=403,
            body="CSRF token mismatch",
        )
        self.assertEqual(outcome.outcome, TokenOutcomeKind.STALE)
        self.assertEqual(outcome.reason_code, "stale_token_mismatch")
        self.assertTrue(outcome.is_retryable)

    def test_forbidden_policy_distinction(self):
        outcome = classify_token_response(
            status_code=403,
            body="Forbidden by administrative rules: access denied",
        )
        self.assertEqual(outcome.outcome, TokenOutcomeKind.FORBIDDEN_POLICY)
        self.assertEqual(outcome.reason_code, "forbidden_policy")
        self.assertFalse(is_probe_conclusive(outcome))

    def test_app_validation_error_distinction(self):
        outcome = classify_token_response(
            status_code=422,
            body='{"error": "validation failed: invalid parameter"}',
        )
        self.assertEqual(outcome.outcome, TokenOutcomeKind.APP_VALIDATION_ERROR)
        self.assertEqual(outcome.reason_code, "app_validation_error")


class StateChangingRetrySafetyTests(unittest.TestCase):
    """Tests for non-idempotent probe retry safety and bounded retry limits."""

    def setUp(self):
        self.reload_strategy = RefreshStrategy(strategy=RefreshKind.PAGE_RELOAD, max_retries=2)
        self.api_strategy = RefreshStrategy(strategy=RefreshKind.API_CALL, max_retries=2)

    def test_state_changing_replays_only_on_explicit_rejection_status(self):
        # 403, 419, 422 prove the server rejected the request before mutation
        for status in (403, 419, 422):
            stale_outcome = TokenOutcome(
                outcome=TokenOutcomeKind.STALE,
                reason_code="stale_token_mismatch",
                http_status_hint=status,
                is_retryable=True,
            )
            decision = decide_token_retry(
                outcome=stale_outcome,
                attempt_count=1,
                max_retries=2,
                method="POST",
                refresh_strategy=self.reload_strategy,
            )
            self.assertTrue(decision.should_retry, f"Expected retry for status {status}")
            self.assertTrue(decision.requires_refresh)

    def test_state_changing_aborts_on_ambiguous_200_status(self):
        # 200 OK means operation may have been applied; must not replay
        ambiguous_outcome = TokenOutcome(
            outcome=TokenOutcomeKind.STALE,
            reason_code="stale_token_mismatch",
            http_status_hint=200,
            is_retryable=True,
        )
        decision = decide_token_retry(
            outcome=ambiguous_outcome,
            attempt_count=1,
            max_retries=2,
            method="POST",
            refresh_strategy=self.reload_strategy,
        )
        self.assertFalse(decision.should_retry)
        self.assertIn("ambiguous response status", decision.reason)

    def test_state_changing_aborts_on_ambiguous_500_or_timeout(self):
        # 500 or timeout (None) cannot guarantee server did not apply mutation
        for status in (500, None):
            ambiguous_outcome = TokenOutcome(
                outcome=TokenOutcomeKind.STALE,
                reason_code="stale_token_mismatch",
                http_status_hint=status,
                is_retryable=True,
            )
            decision = decide_token_retry(
                outcome=ambiguous_outcome,
                attempt_count=1,
                max_retries=2,
                method="POST",
                refresh_strategy=self.reload_strategy,
            )
            self.assertFalse(decision.should_retry)

    def test_idempotent_get_allows_retry_on_stale(self):
        stale_outcome = TokenOutcome(
            outcome=TokenOutcomeKind.STALE,
            reason_code="stale_token_mismatch",
            http_status_hint=403,
            is_retryable=True,
        )
        decision = decide_token_retry(
            outcome=stale_outcome,
            attempt_count=1,
            max_retries=2,
            method="GET",
            refresh_strategy=self.reload_strategy,
        )
        self.assertTrue(decision.should_retry)

    def test_auth_expired_never_retried_as_csrf_refresh(self):
        auth_outcome = TokenOutcome(
            outcome=TokenOutcomeKind.AUTH_EXPIRED,
            reason_code="auth_expired",
            http_status_hint=401,
            is_retryable=False,
        )
        decision = decide_token_retry(
            outcome=auth_outcome,
            attempt_count=1,
            max_retries=2,
            method="POST",
            refresh_strategy=self.reload_strategy,
        )
        self.assertFalse(decision.should_retry)
        self.assertIn("Authentication session expired", decision.reason)

    def test_rate_limited_never_blindly_retried(self):
        rate_outcome = TokenOutcome(
            outcome=TokenOutcomeKind.RATE_LIMITED,
            reason_code="rate_limited",
            http_status_hint=429,
            is_retryable=False,
        )
        decision = decide_token_retry(
            outcome=rate_outcome,
            attempt_count=1,
            max_retries=2,
            method="POST",
            refresh_strategy=self.reload_strategy,
        )
        self.assertFalse(decision.should_retry)
        self.assertIn("Rate limited", decision.reason)

    def test_bounded_retry_limit_strictly_enforced(self):
        stale_outcome = TokenOutcome(
            outcome=TokenOutcomeKind.STALE,
            reason_code="stale_token_mismatch",
            http_status_hint=403,
            is_retryable=True,
        )
        # 1 retry budget (attempt_count 2 >= max_retries 2)
        decision = decide_token_retry(
            outcome=stale_outcome,
            attempt_count=2,
            max_retries=2,
            method="POST",
            refresh_strategy=self.reload_strategy,
        )
        self.assertFalse(decision.should_retry)
        self.assertIn("Max retry limit reached", decision.reason)


class ScannerTokenLifecycleIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """Integration checks for BaseScanner token refresh handling."""

    async def test_send_httpx_token_managed_handles_auth_expired(self):
        eng = MockEngine(enabled=True)
        scanner = DummyScanner(eng)

        mock_resp = SimpleNamespace(
            status_code=401,
            headers={"Content-Type": "application/json"},
            text='{"error": "unauthorized"}',
            request=SimpleNamespace(headers={}, extensions={}),
            extensions={},
        )
        mock_client = SimpleNamespace(
            request=AsyncMock(return_value=mock_resp),
            get=AsyncMock(return_value=mock_resp),
        )

        resp, _, _ = await scanner._send_httpx_token_managed(
            mock_client, "POST", "http://example.com/api",
            {"csrf_token": "tok1"}, {"X-CSRF-Token": "tok1"}, "json"
        )
        self.assertEqual(resp.status_code, 401)
        self.assertTrue(eng._probe_inconclusive)
        self.assertTrue(eng._api_auth_failed)
        self.assertTrue(any("auth_expired" in note for note in eng.wave_errors))
        self.assertTrue(any("probe_inconclusive" in note for note in eng.wave_errors))
        self.assertEqual(mock_client.request.await_count, 1)

    async def test_send_httpx_token_managed_handles_rate_limited(self):
        eng = MockEngine(enabled=True)
        scanner = DummyScanner(eng)

        mock_resp = SimpleNamespace(
            status_code=429,
            headers={"Retry-After": "30"},
            text="Too Many Requests",
            request=SimpleNamespace(headers={}, extensions={}),
            extensions={},
        )
        mock_client = SimpleNamespace(
            request=AsyncMock(return_value=mock_resp),
            get=AsyncMock(return_value=mock_resp),
        )

        resp, _, _ = await scanner._send_httpx_token_managed(
            mock_client, "POST", "http://example.com/api",
            {"csrf_token": "tok1"}, {"X-CSRF-Token": "tok1"}, "json"
        )
        self.assertEqual(resp.status_code, 429)
        self.assertTrue(eng._probe_inconclusive)
        self.assertTrue(any("rate_limited" in note for note in eng.wave_errors))
        self.assertTrue(any("probe_inconclusive" in note for note in eng.wave_errors))
        self.assertEqual(mock_client.request.await_count, 1)

    async def test_send_httpx_alias_and_inconclusive_helper(self):
        eng = MockEngine(enabled=True)
        scanner = DummyScanner(eng)
        self.assertTrue(hasattr(scanner, "_send_httpx_request_with_token_refresh"))
        self.assertFalse(scanner.is_probe_inconclusive())
        eng._probe_inconclusive = True
        self.assertTrue(scanner.is_probe_inconclusive())


class RedactionInvariantTests(unittest.TestCase):
    """Ensures raw token values are never leaked into notes, events, or evidence."""

    def test_raw_token_value_redaction(self):
        raw_secret = "secret_csrf_token_value_9876543210"
        redacted = redact_token_value(raw_secret)
        self.assertNotIn(raw_secret, redacted)
        self.assertIn("***", redacted)
        self.assertIn("len=34", redacted)

    def test_derive_token_ref_id_irreversible(self):
        raw_secret = "secret_csrf_token_value_9876543210"
        ref_id = derive_token_ref_id(raw_secret)
        self.assertTrue(ref_id.startswith("tok_ref_"))
        self.assertNotIn(raw_secret, ref_id)
        self.assertEqual(ref_id, derive_token_ref_id(raw_secret))

    def test_token_lifecycle_event_has_no_raw_secret_field(self):
        event = TokenLifecycleEvent(
            probe_attempt_id="att_1",
            evidence_id=None,
            check="xss",
            carrier=TokenCarrier.JSON,
            transport=TokenTransport.HTTPX,
            attempt_count=1,
            refresh_reason="stale",
            final_status=419,
            final_lifecycle_status="stale",
        )
        d = event.to_dict()
        serialized = json.dumps(d)
        for sensitive in ("token", "value", "secret", "cookie"):
            self.assertNotIn(sensitive, d.keys())
        self.assertIn("stale", serialized)
