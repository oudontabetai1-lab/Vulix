"""Browser managed form lifecycle telemetry checks without Chromium."""
import ast
import asyncio
import inspect
import re
import textwrap

from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.scanners.xss import XSSScanner
from wscan.token_lifecycle import _TOKEN_TELEMETRY_REASONS


class Engine:
    def __init__(self, enabled=True, raising=False):
        self.token_lifecycle_manager = enabled
        self._probe_inconclusive = False
        self.events = []
        self.raising = raising

    def record_token_lifecycle_event(self, event):
        if self.raising:
            raise RuntimeError("recorder")
        self.events.append(event)


def make_scanner(responses, enabled=True, gate=True, raising=False):
    scanner = XSSScanner.__new__(XSSScanner)
    scanner.engine = Engine(enabled, raising)
    notes = []
    attempts = []
    class Page:
        async def evaluate(self, *_args):
            return {"csrf_token": "fresh"}

    scanner.browser = type("Browser", (), {
        "last_probe_delivered": True, "page": Page(),
    })()
    scanner.CHECK_TYPE = "xss"
    scanner.may_scan_injection_point = lambda _ip: True
    scanner._field_budget_gate = lambda: False
    scanner._apply_form_with_token_refresh = lambda *_args: _async_none()
    scanner._record_scan_note = notes.append
    scanner._probe_failure = lambda *_args: None
    scanner._observe_token_lifecycle = lambda *_args: None
    scanner._record_attempt = lambda *args: attempts.append(args)
    scanner._token_manager_enabled = lambda *_args: gate
    calls = iter(responses)

    async def apply_payload(*_args):
        return "PLAYWRIGHT", {"response": next(calls)}

    scanner._apply_payload = apply_payload
    return scanner, notes, attempts


async def _async_none():
    return None


def run(responses, **kwargs):
    scanner, notes, attempts = make_scanner(responses, **kwargs)
    ip = InjectionPoint.for_form("https://example.test/", "email", form_tokens=())
    result = asyncio.run(scanner._apply_ip_unrecorded(ip, "payload"))
    return scanner, notes, attempts, result


def stale():
    return {"status": 419, "headers": {}, "body": "CSRF token mismatch"}


def test_retry_emits_one_event_with_final_attempt_details():
    scanner, _notes, _attempts, (source, pair) = run(
        [stale(), {"status": 200, "headers": {}, "body": "ok"}])
    assert len(scanner.engine.events) == 1
    event = scanner.engine.events[0]
    assert (event.attempt_count, event.refresh_reason, event.final_status,
            event.transport.value) == (2, "stale", 200, "playwright")
    assert source == "PLAYWRIGHT" and pair["response"]["status"] == 200


def test_stale_retry_note_and_verdict_do_not_depend_on_recorder():
    observed = run([stale(), stale()], enabled=True)
    noop = run([stale(), stale()], enabled=True)
    scanner, notes, _attempts, result = observed
    _noop_scanner, noop_notes, _noop_attempts, noop_result = noop
    assert len(scanner.engine.events) == 1
    assert scanner.engine.events[0].final_lifecycle_status == "stale"
    assert "token_lifecycle:probe_inconclusive:xss" in notes
    assert (notes, result) == (noop_notes, noop_result)


def test_flag_off_skips_browser_lifecycle_event():
    scanner, _notes, _attempts, _result = run([stale()], enabled=False, gate=False)
    assert scanner.engine.events == []


def test_engine_flag_off_suppresses_event_even_when_scanner_gate_is_true():
    scanner, _notes, _attempts, _result = run([stale()], enabled=False, gate=True)
    assert scanner.engine.events == []


def test_recorder_error_is_a_note_and_does_not_escape():
    scanner, notes, _attempts, result = run([stale(), {"status": 200, "headers": {}, "body": "ok"}], raising=True)
    assert result[1]["response"]["status"] == 200
    assert "token_lifecycle_event_error:RuntimeError" in notes


def test_browser_refresh_reason_literals_match_event_schema():
    source = textwrap.dedent(inspect.getsource(BaseScanner._apply_ip_unrecorded))
    literals = set(re.findall(r'refresh_reason\s*=\s*["\']([^"\']+)["\']', source))
    assert literals <= _TOKEN_TELEMETRY_REASONS
