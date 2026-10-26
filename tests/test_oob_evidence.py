"""Strict, private Out-Of-Band (OOB) mail header probe evidence verification."""
from __future__ import annotations

import asyncio
import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wscan.injection_point import InjectionPoint
from wscan.oob_email import ReceivedEmail
from wscan.oob_evidence import (
    CHECK_TYPE,
    DECISION_RULE,
    DECISION_VERSION,
    RECORD_KIND,
    accepted_decisions,
    correlate_finding,
    decision_subject,
    valid_shape,
)
from wscan.probe_ledger import ProbeOutcome, ProbeRole, Transport, sha256_hex
from wscan.probe_recorder import ProbeLedger, completion_identity
from wscan.request_logger import RequestLogger
from wscan.scanners import mail_header as mail_header_mod
from wscan.scanners.base import Finding
from wscan.scanners.mail_header import MailHeaderInjectionScanner


def persisted(logger: RequestLogger) -> list[dict]:
    if not logger.probe_ledger.path or not logger.probe_ledger.path.exists():
        return []
    return [json.loads(line) for line in logger.probe_ledger.path.read_text().splitlines()]


class _StubBrowser:
    def __init__(self, response_body: str = ""):
        self._body = response_body
        self.navigate = AsyncMock(return_value=True)
        self.test_url_param = AsyncMock(
            return_value=(response_body, {"request": {}, "response": {"status": 200, "body": response_body}})
        )
        self.fill_and_submit_form = AsyncMock(
            return_value=(response_body, {"request": {}, "response": {"status": 200, "body": response_body}})
        )

    async def screenshot_b64(self, label=""):
        return ""


class _StubEngine:
    def __init__(self, tmp_path: Path, browser: _StubBrowser, received: ReceivedEmail | None = None,
                 winning_index: int = 0, sink_error: Exception | None = None):
        self.target_url = "http://target.test"
        self.request_logger = RequestLogger(tmp_path)
        self.browser = browser
        self.monitor = None
        self.payload_gen = None
        self._finding_dedup = set()
        self.all_findings = []
        self.checks = ["mail_header"]
        self.sleep_factor = 0.0
        self.wave_errors = []
        self._counter = 0
        self._winning_index = winning_index

        if sink_error is not None:
            class _ErrorSink:
                def fetch_recent(self, limit=50):
                    raise sink_error
            self.oob_sink = _ErrorSink()
        elif received is not None or winning_index >= 0:
            class _Sink:
                def fetch_recent(self, limit=50):
                    return [received] if received is not None else []
            self.oob_sink = _Sink()
        else:
            self.oob_sink = None

    def new_oob_address(self):
        token = f"wscan-oob-tok{self._counter}"
        self._counter += 1
        return (token, f"{token}@collab.test")


# =====================================================================
# 1. Validator Unit Tests: valid_shape
# =====================================================================

def test_valid_shape_accepts_valid_decisions():
    valid_record = {
        "record_kind": RECORD_KIND,
        "check": CHECK_TYPE,
        "actor": "oob_oracle",
        "decision_rule": DECISION_RULE,
        "decision_version": DECISION_VERSION,
        "role": "attack",
        "outcome": "matched",
        "decision_subject": "a" * 64,
        "response": {"oob": True, "body_hash": "b" * 64, "body_length": 128},
        "rationale": "token_matched",
    }
    assert valid_shape(valid_record) is True


def test_valid_shape_strictly_rejects_no_match():
    # Empty mailbox is inconclusive; no_match is strictly forbidden for OOB email
    record = {
        "record_kind": RECORD_KIND,
        "check": CHECK_TYPE,
        "actor": "oob_oracle",
        "decision_rule": DECISION_RULE,
        "decision_version": DECISION_VERSION,
        "role": "attack",
        "outcome": "no_match",
        "decision_subject": "a" * 64,
        "rationale": "polling_deadline_expired",
    }
    assert valid_shape(record) is False


def test_valid_shape_rejects_invalid_subjects():
    base = {
        "record_kind": RECORD_KIND,
        "check": CHECK_TYPE,
        "actor": "oob_oracle",
        "decision_rule": DECISION_RULE,
        "decision_version": DECISION_VERSION,
        "role": "attack",
        "outcome": "timeout",
        "rationale": "polling_deadline_expired",
    }
    # Subject too short
    assert valid_shape({**base, "decision_subject": "a" * 63}) is False
    # Subject contains non-hex chars
    assert valid_shape({**base, "decision_subject": "z" * 64}) is False
    # Subject contains uppercase
    assert valid_shape({**base, "decision_subject": "A" * 64}) is False


def test_valid_shape_rejects_payload_in_matched_without_oob():
    record = {
        "record_kind": RECORD_KIND,
        "check": CHECK_TYPE,
        "actor": "oob_oracle",
        "decision_rule": DECISION_RULE,
        "decision_version": DECISION_VERSION,
        "role": "attack",
        "outcome": "matched",
        "decision_subject": "a" * 64,
        "response": {"oob": False},
        "rationale": "inconsistent",
    }
    assert valid_shape(record) is False


# =====================================================================
# 2. Causal Rebuilder Unit Tests: accepted_decisions
# =====================================================================

def test_accepted_decisions_valid_causal_chain():
    req_id = "scan:u1:0001"
    obs_id = "scan:u1:0002"
    dec_id = "scan:u1:0003"
    unit = "unit_key_1"

    events = {
        req_id: {
            "attempt_id": req_id,
            "record_kind": "request",
            "check": CHECK_TYPE,
            "role": "attack",
            "scan_id": "scan",
            "completion_unit": unit,
            "injection_key": unit,
            "request": {"transport": "httpx", "method": "POST", "url": "http://target.test/contact"},
        },
        obs_id: {
            "attempt_id": obs_id,
            "record_kind": "observation",
            "check": CHECK_TYPE,
            "role": "attack",
            "scan_id": "scan",
            "completion_unit": unit,
            "injection_key": unit,
            "parent_id": req_id,
            "request_attempt_id": req_id,
            "request": {"transport": "httpx", "method": "POST", "url": "http://target.test/contact", "sent": True},
            "response": {"status": 200, "body_hash": "c" * 64, "body_length": 50},
        },
        dec_id: {
            "attempt_id": dec_id,
            "record_kind": RECORD_KIND,
            "check": CHECK_TYPE,
            "actor": "oob_oracle",
            "decision_rule": DECISION_RULE,
            "decision_version": DECISION_VERSION,
            "role": "attack",
            "scan_id": "scan",
            "completion_unit": unit,
            "injection_key": unit,
            "parent_id": obs_id,
            "request_attempt_id": req_id,
            "outcome": "matched",
            "decision_subject": "d" * 64,
            "response": {"oob": True, "body_hash": "e" * 64, "body_length": 100},
            "rationale": "token_matched",
        },
    }

    result = accepted_decisions(events)
    assert unit in result
    assert len(result[unit]) == 1
    assert result[unit][0]["attempt_id"] == dec_id


def test_accepted_decisions_inversion_poisons_unit():
    # Sequence order inverted: observation sequence is earlier than request
    req_id = "scan:u1:0002"
    obs_id = "scan:u1:0001"
    dec_id = "scan:u1:0003"
    unit = "unit_key_1"

    events = {
        req_id: {
            "attempt_id": req_id,
            "record_kind": "request",
            "check": CHECK_TYPE,
            "role": "attack",
            "scan_id": "scan",
            "completion_unit": unit,
            "injection_key": unit,
            "request": {"transport": "httpx", "method": "POST", "url": "http://target.test/contact"},
        },
        obs_id: {
            "attempt_id": obs_id,
            "record_kind": "observation",
            "check": CHECK_TYPE,
            "role": "attack",
            "scan_id": "scan",
            "completion_unit": unit,
            "injection_key": unit,
            "parent_id": req_id,
            "request_attempt_id": req_id,
            "request": {"transport": "httpx", "method": "POST", "url": "http://target.test/contact", "sent": True},
            "response": {"status": 200, "body_hash": "c" * 64, "body_length": 50},
        },
        dec_id: {
            "attempt_id": dec_id,
            "record_kind": RECORD_KIND,
            "check": CHECK_TYPE,
            "actor": "oob_oracle",
            "decision_rule": DECISION_RULE,
            "decision_version": DECISION_VERSION,
            "role": "attack",
            "scan_id": "scan",
            "completion_unit": unit,
            "injection_key": unit,
            "parent_id": obs_id,
            "request_attempt_id": req_id,
            "outcome": "matched",
            "decision_subject": "d" * 64,
            "response": {"oob": True, "body_hash": "e" * 64, "body_length": 100},
            "rationale": "token_matched",
        },
    }

    result = accepted_decisions(events)
    # Poisoned unit returns empty list
    assert result.get(unit) == []


from wscan.checkpoint import unit_key


def _ip_unit(ip: InjectionPoint) -> str:
    url, field_name, form_index, location_token, pointer = ip.stable_key_parts()
    return unit_key(
        url, field_name, int(form_index), "mail_header",
        location_token=location_token, pointer=pointer,
    )


# =====================================================================
# 3. Finding Correlation Unit Tests: correlate_finding
# =====================================================================

def test_correlate_finding_success():
    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)
    token = "tok123"
    desc = "CRLF"
    unit = _ip_unit(ip)
    subj = decision_subject(unit, token, desc)
    dec_id = "scan:u1:0003"

    finding = Finding(
        url=ip.url,
        field_name="email",
        check_type=CHECK_TYPE,
        evidence_type="mail_header_oob",
        severity="high",
        payload="test@example.com\r\nCc: tok123@collab.test",
        evidence="Mail header injection CONFIRMED via OOB",
        confidence="confirmed",
        evidence_details={
            "oob_token": token,
            "newline_variant": desc,
            "attempt_ids": [dec_id],
        },
    )

    accepted = [{
        "attempt_id": dec_id,
        "outcome": "matched",
        "decision_subject": subj,
        "completion_unit": unit,
    }]

    assert correlate_finding(finding, accepted, {}) is True


def test_correlate_finding_rejects_missing_attempt():
    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)
    finding = Finding(
        url=ip.url,
        field_name="email",
        check_type=CHECK_TYPE,
        evidence_type="mail_header_oob",
        severity="high",
        payload="test@example.com\r\nCc: tok123@collab.test",
        evidence="Mail header injection CONFIRMED via OOB",
        confidence="confirmed",
        evidence_details={
            "oob_token": "tok123",
            "newline_variant": "CRLF",
            "attempt_ids": ["scan:u1:9999"],
        },
    )
    assert correlate_finding(finding, [], {}) is False


# =====================================================================
# 4. Integrated Scanner & Ledger Lifecycle Tests
# =====================================================================

@pytest.mark.asyncio
async def test_vulnerable_twin_produces_confirmed_finding_and_complete_ledger(tmp_path, monkeypatch):
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    winning_index = 1
    winning_token = f"wscan-oob-tok{winning_index}"
    received = ReceivedEmail(
        uid="1",
        to_addrs=[f"{winning_token}@collab.test"],
        subject="Contact Form Delivery",
        body="Message received.",
    )

    browser = _StubBrowser("Thank you for contacting us.")
    engine = _StubEngine(tmp_path, browser, received=received, winning_index=winning_index)
    scanner = MailHeaderInjectionScanner(engine)

    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)
    unit = engine.request_logger.probe_ledger.expect(
        _ip_unit(ip), "mail_header", rules=["mail_header_oob"]
    )

    with engine.request_logger.probe_ledger.unit_scope(unit):
        findings = await scanner.scan_injection_point(ip, {"name": "email"})

    oob_findings = [f for f in findings if f.evidence_type == "mail_header_oob"]
    assert len(oob_findings) == 1
    f = oob_findings[0]
    assert f.confidence == "confirmed"
    assert f.evidence_details["oob_token"] == winning_token
    assert "attempt_ids" in f.evidence_details

    # Persist and check ledger
    engine.request_logger.probe_ledger.write_manifest()
    rows = persisted(engine.request_logger)
    assert len(rows) > 0

    decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
    assert len(decisions) >= 1
    matched = [d for d in decisions if d.get("outcome") == "matched"]
    assert len(matched) == 1
    assert matched[0]["attempt_id"] in f.evidence_details["attempt_ids"]

    # Manifest and completion summary check
    summary = engine.request_logger.probe_ledger.completion_summary(["mail_header"])
    assert summary["checks"]["mail_header"]["units"][unit]["status"] == "COMPLETE"
    assert summary["status"] == "COMPLETE"

    # Restored ledger check
    restored = ProbeLedger(tmp_path, tmp_path.name)
    assert restored.completion_summary(["mail_header"])["status"] == "COMPLETE"


@pytest.mark.asyncio
async def test_safe_twin_produces_zero_findings_timeout_and_incomplete_completion(tmp_path, monkeypatch):
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    # Empty mailbox: received is None
    browser = _StubBrowser("Safe response with input sanitized.")
    engine = _StubEngine(tmp_path, browser, received=None)
    scanner = MailHeaderInjectionScanner(engine)

    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)
    unit = engine.request_logger.probe_ledger.expect(
        _ip_unit(ip), "mail_header", rules=["mail_header_oob"]
    )

    with engine.request_logger.probe_ledger.unit_scope(unit):
        findings = await scanner.scan_injection_point(ip, {"name": "email"})

    oob_findings = [f for f in findings if f.evidence_type == "mail_header_oob"]
    assert len(oob_findings) == 0

    engine.request_logger.probe_ledger.write_manifest()
    rows = persisted(engine.request_logger)
    decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
    assert len(decisions) > 0

    # Every decision must be TIMEOUT, strictly no "no_match"
    for d in decisions:
        assert d["outcome"] == "timeout"
        assert d["outcome"] != "no_match"

    summary = engine.request_logger.probe_ledger.completion_summary(["mail_header"])
    # Empty mailbox is inconclusive; unit status is PARTIAL / EVIDENCE_INCOMPLETE, never COMPLETE
    assert summary["checks"]["mail_header"]["units"][unit]["status"] != "COMPLETE"
    assert summary["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_error_twin_transport_failure(tmp_path, monkeypatch):
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    browser = _StubBrowser("Thank you.")
    engine = _StubEngine(tmp_path, browser, sink_error=ConnectionResetError("IMAP dropped connection"))
    scanner = MailHeaderInjectionScanner(engine)

    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)
    unit = engine.request_logger.probe_ledger.expect(
        _ip_unit(ip), "mail_header", rules=["mail_header_oob"]
    )

    with engine.request_logger.probe_ledger.unit_scope(unit):
        findings = await scanner.scan_injection_point(ip, {"name": "email"})

    assert [f for f in findings if f.evidence_type == "mail_header_oob"] == []

    engine.request_logger.probe_ledger.write_manifest()
    rows = persisted(engine.request_logger)
    decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
    assert len(decisions) > 0
    for d in decisions:
        assert d["outcome"] == "transport_error"

    summary = engine.request_logger.probe_ledger.completion_summary(["mail_header"])
    assert summary["checks"]["mail_header"]["units"][unit]["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_privacy_invariants_no_cleartext_credentials_or_raw_rfc822(tmp_path, monkeypatch):
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    raw_password = "super_secret_oob_pass_98765"
    raw_rfc822_body = "From: admin@target.test\r\nSubject: Secret Corporate Letter\r\n\r\nTOP SECRET DATA DO NOT LEAK"
    winning_token = "wscan-oob-tok0"

    received = ReceivedEmail(
        uid="100",
        to_addrs=[f"{winning_token}@collab.test"],
        subject="Confidential Report",
        body=raw_rfc822_body,
    )

    browser = _StubBrowser("Form submitted.")
    engine = _StubEngine(tmp_path, browser, received=received, winning_index=0)
    engine.oob_config = SimpleNamespace(password=raw_password, username="oob_user")
    scanner = MailHeaderInjectionScanner(engine)

    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)
    unit = engine.request_logger.probe_ledger.expect(_ip_unit(ip), "mail_header", rules=["mail_header_oob"])

    with engine.request_logger.probe_ledger.unit_scope(unit):
        await scanner.scan_injection_point(ip, {"name": "email"})

    engine.request_logger.probe_ledger.write_manifest()

    # Read all files in logger directory
    ledger_content = ""
    for file_path in tmp_path.glob("**/*"):
        if file_path.is_file():
            ledger_content += file_path.read_text(errors="ignore") + "\n"

    # Invariants:
    # 1. Cleartext password must never appear in any ledger or log file
    assert raw_password not in ledger_content
    # 2. Raw confidential email body must not be persisted in full
    assert "TOP SECRET DATA DO NOT LEAK" not in ledger_content
    assert "Secret Corporate Letter" not in ledger_content


# =====================================================================
# 6. Physical HTTP Wire Fixture Tests: 4 Scanner States
# =====================================================================

import socket
import threading
from contextlib import contextmanager
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
import uvicorn
from wscan.checkpoint import CheckpointState, save_checkpoint, load_checkpoint
from wscan.report import ReportGenerator


@contextmanager
def _local_http_wire_fixture():
    app = FastAPI()
    recorded_wire_requests: list[dict] = []

    @app.post("/contact")
    async def contact_post(req: Request):
        form = await req.form()
        recorded_wire_requests.append(dict(form))
        return HTMLResponse("<html><body>Contact received</body></html>")

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    import time
    deadline = time.monotonic() + 5
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{port}", recorded_wire_requests
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


@pytest.mark.asyncio
async def test_wire_state_vulnerable_confirmed_and_correlated(tmp_path, monkeypatch):
    """State 1: Vulnerable with real wire HTTP submission and successful ledger correlation."""
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    with _local_http_wire_fixture() as (base_url, recorded):
        winning_index = 1
        winning_token = f"wscan-oob-tok{winning_index}"
        received = ReceivedEmail(
            uid="1",
            to_addrs=[f"{winning_token}@collab.test"],
            subject="Contact form delivery",
            body="Message body",
        )
        page = SimpleNamespace(
            evaluate=AsyncMock(return_value={"action": f"{base_url}/contact", "method": "POST", "fields": {"email": ""}})
        )
        browser = SimpleNamespace(
            navigate=AsyncMock(return_value=True),
            page=page,
            screenshot_b64=AsyncMock(return_value=""),
        )
        engine = _StubEngine(tmp_path, browser, received=received, winning_index=winning_index)
        scanner = MailHeaderInjectionScanner(engine)
        ip = InjectionPoint.for_form(f"{base_url}/contact", "email", 0)
        unit = engine.request_logger.probe_ledger.expect(_ip_unit(ip), "mail_header", rules=["mail_header_oob"])

        with engine.request_logger.probe_ledger.unit_scope(unit):
            findings = await scanner.scan_injection_point(ip, {"name": "email"})

        # (1) Real wire verification
        assert len(recorded) > 0
        assert any(winning_token in str(r.get("email", "")) for r in recorded)

        # (2) Finding state verification: confirmed and reproduced
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == "confirmed"
        assert f.verification_state == "reproduced"
        assert f.verified is True
        assert "attempt_ids" in f.evidence_details
        assert "CONFIRMED" in f.evidence

        # (3) Ledger write and re-read verification
        engine.request_logger.probe_ledger.write_manifest()
        rows = persisted(engine.request_logger)
        decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
        assert len(decisions) >= 1
        matched = [d for d in decisions if d.get("outcome") == "matched"]
        assert len(matched) == 1
        assert matched[0]["attempt_id"] in f.evidence_details["attempt_ids"]

        # (4) Checkpoint verification
        state = CheckpointState(findings=[f.to_dict()])
        save_checkpoint(tmp_path, state)
        loaded = load_checkpoint(tmp_path)
        assert len(loaded.findings) == 1
        restored_f = Finding.from_dict(loaded.findings[0])
        assert restored_f.confidence == "confirmed"
        assert restored_f.verification_state == "reproduced"
        assert restored_f.verified is True


@pytest.mark.asyncio
async def test_wire_state_safe_twin_timeout(tmp_path, monkeypatch):
    """State 2: Safe twin with real wire HTTP submission, zero findings, timeout ledger."""
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    with _local_http_wire_fixture() as (base_url, recorded):
        page = SimpleNamespace(
            evaluate=AsyncMock(return_value={"action": f"{base_url}/contact", "method": "POST", "fields": {"email": ""}})
        )
        browser = SimpleNamespace(
            navigate=AsyncMock(return_value=True),
            page=page,
            screenshot_b64=AsyncMock(return_value=""),
        )
        engine = _StubEngine(tmp_path, browser, received=None)
        scanner = MailHeaderInjectionScanner(engine)
        ip = InjectionPoint.for_form(f"{base_url}/contact", "email", 0)
        unit = engine.request_logger.probe_ledger.expect(_ip_unit(ip), "mail_header", rules=["mail_header_oob"])

        with engine.request_logger.probe_ledger.unit_scope(unit):
            findings = await scanner.scan_injection_point(ip, {"name": "email"})

        # (1) Real wire requests sent
        assert len(recorded) > 0

        # (2) Zero findings produced
        oob_findings = [f for f in findings if f.evidence_type == "mail_header_oob"]
        assert len(oob_findings) == 0

        # (3) Ledger decisions are timeout, strictly not no_match
        engine.request_logger.probe_ledger.write_manifest()
        rows = persisted(engine.request_logger)
        decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
        assert len(decisions) > 0
        for d in decisions:
            assert d["outcome"] == "timeout"
            assert d["outcome"] != "no_match"

        # (4) Manifest reflects incomplete
        summary = engine.request_logger.probe_ledger.completion_summary(["mail_header"])
        assert summary["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_wire_state_transport_error(tmp_path, monkeypatch):
    """State 3: Transport error with real wire HTTP submission, transport_error ledger."""
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    with _local_http_wire_fixture() as (base_url, recorded):
        page = SimpleNamespace(
            evaluate=AsyncMock(return_value={"action": f"{base_url}/contact", "method": "POST", "fields": {"email": ""}})
        )
        browser = SimpleNamespace(
            navigate=AsyncMock(return_value=True),
            page=page,
            screenshot_b64=AsyncMock(return_value=""),
        )
        engine = _StubEngine(tmp_path, browser, sink_error=ConnectionResetError("IMAP connection reset"))
        scanner = MailHeaderInjectionScanner(engine)
        ip = InjectionPoint.for_form(f"{base_url}/contact", "email", 0)
        unit = engine.request_logger.probe_ledger.expect(_ip_unit(ip), "mail_header", rules=["mail_header_oob"])

        with engine.request_logger.probe_ledger.unit_scope(unit):
            findings = await scanner.scan_injection_point(ip, {"name": "email"})

        # (1) Real wire requests sent
        assert len(recorded) > 0

        # (2) Zero findings produced
        assert [f for f in findings if f.evidence_type == "mail_header_oob"] == []

        # (3) Ledger decisions are transport_error
        engine.request_logger.probe_ledger.write_manifest()
        rows = persisted(engine.request_logger)
        decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
        assert len(decisions) > 0
        for d in decisions:
            assert d["outcome"] == "transport_error"

        summary = engine.request_logger.probe_ledger.completion_summary(["mail_header"])
        assert summary["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_wire_state_logger_failure_unconfirmed_finding(tmp_path, monkeypatch):
    """State 4: Logger write failure / quarantined ledger produces unconfirmed Finding without CONFIRMED claims."""
    monkeypatch.setattr(mail_header_mod, "OOB_WAIT_SECONDS", 0.0)
    monkeypatch.setattr(mail_header_mod, "OOB_POLL_INTERVAL", 0.0)

    with _local_http_wire_fixture() as (base_url, recorded):
        winning_token = "wscan-oob-tok0"
        received = ReceivedEmail(
            uid="1",
            to_addrs=[f"{winning_token}@collab.test"],
            subject="Contact form delivery",
            body="Message body",
        )
        page = SimpleNamespace(
            evaluate=AsyncMock(return_value={"action": f"{base_url}/contact", "method": "POST", "fields": {"email": ""}})
        )
        browser = SimpleNamespace(
            navigate=AsyncMock(return_value=True),
            page=page,
            screenshot_b64=AsyncMock(return_value=""),
        )
        engine = _StubEngine(tmp_path, browser, received=received, winning_index=0)
        # Force quarantine to simulate logger failure / quarantined ledger
        engine.request_logger.probe_ledger._quarantined = True

        scanner = MailHeaderInjectionScanner(engine)
        ip = InjectionPoint.for_form(f"{base_url}/contact", "email", 0)
        unit = engine.request_logger.probe_ledger.expect(_ip_unit(ip), "mail_header", rules=["mail_header_oob"])

        with engine.request_logger.probe_ledger.unit_scope(unit):
            findings = await scanner.scan_injection_point(ip, {"name": "email"})

        # (1) Real wire requests sent
        assert len(recorded) > 0

        # (2) Finding generated but unconfirmed
        assert len(findings) == 1
        f = findings[0]
        assert f.confidence == "likely"
        assert f.verification_state == "assumed"
        assert f.verified is False
        assert "attempt_ids" not in f.evidence_details
        assert "CONFIRMED" not in f.evidence

        # (3) Ledger manifest marks write failure / incomplete
        engine.request_logger.probe_ledger.write_manifest()
        summary = engine.request_logger.probe_ledger.completion_summary(["mail_header"])
        assert summary["status"] != "COMPLETE"

        # (4) Checkpoint persistence preserves unconfirmed state
        state = CheckpointState(findings=[f.to_dict()])
        save_checkpoint(tmp_path, state)
        loaded = load_checkpoint(tmp_path)
        assert len(loaded.findings) == 1
        restored_f = Finding.from_dict(loaded.findings[0])
        assert restored_f.confidence == "likely"
        assert restored_f.verification_state == "assumed"
        assert restored_f.verified is False

        # (5) Report generation does not label finding as CONFIRMED
        rg = ReportGenerator(output_dir=tmp_path)
        report_file = rg.generate(
            target=base_url,
            findings=[f],
            visited_urls=[base_url],
            checks=["mail_header"],
        )
        report_content = report_file.read_text(encoding="utf-8")
        assert "[CONFIRMED]" not in report_content
        assert "CONFIRMED via OOB" not in report_content


@pytest.mark.asyncio
async def test_no_logger_unconfirmed_finding():
    """No-logger environment: scanner preserves finding as likely/assumed without attempt_ids."""
    winning_token = "wscan-oob-tok0"
    received = ReceivedEmail(
        uid="1",
        to_addrs=[f"{winning_token}@collab.test"],
        subject="Contact form delivery",
        body="Message body",
    )
    page = SimpleNamespace(
        evaluate=AsyncMock(return_value={"action": "http://target.test/contact", "method": "POST", "fields": {"email": ""}})
    )
    browser = SimpleNamespace(
        navigate=AsyncMock(return_value=True),
        page=page,
        screenshot_b64=AsyncMock(return_value=""),
    )

    class _NoLoggingEngine:
        def __init__(self, b, r):
            self.target_url = "http://target.test"
            self.request_logger = None
            self.browser = b
            self.monitor = None
            self.payload_gen = None
            self._finding_dedup = set()
            self.all_findings = []
            self.checks = ["mail_header"]
            self.sleep_factor = 0.0
            self.wave_errors = []
            self._counter = 0

            class _Sink:
                def fetch_recent(self, limit=50):
                    return [r]
            self.oob_sink = _Sink()

        def new_oob_address(self):
            tok = f"wscan-oob-tok{self._counter}"
            self._counter += 1
            return (tok, f"{tok}@collab.test")

    engine = _NoLoggingEngine(browser, received)
    scanner = MailHeaderInjectionScanner(engine)
    ip = InjectionPoint.for_form("http://target.test/contact", "email", 0)

    findings = await scanner.scan_injection_point(ip, {"name": "email"})
    assert len(findings) == 1
    f = findings[0]
    assert f.confidence == "likely"
    assert f.verification_state == "assumed"
    assert f.verified is False
    assert "attempt_ids" not in f.evidence_details
    assert "CONFIRMED" not in f.evidence

