"""Probe evidence ledger tests for SQLi standard sweep with Playwright transport.

Tests cover:
1. Vulnerable and safe twin endpoints: recorded count matches executed transmission count.
2. payload_fingerprint consistency across payload, request, observation, and decision records.
3. Write failure on recorder: marks wave incomplete in observability without breaking scan, findings, or checkpoint.
4. Count mismatch between planned/executed/manifest: marks wave incomplete in observability.
5. Privacy / Secret redaction: Cookies, Authorization headers, and credentials are never persisted in plaintext.
6. JSONL compatibility: payloads.jsonl and http_requests.jsonl retain their exact format and counts.
7. Resume stability: attempt IDs and causality (request -> observation -> decision) are preserved on resume.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from tests.test_shared_probe_evidence import make_engine, probe_server, rows
from wscan.attempt_ledger import payload_fingerprint
from wscan.checkpoint import CheckpointState
from wscan.injection_point import InjectionPoint
from wscan.probe_ledger import sha256_hex
from wscan.probe_recorder import ProbeLedger, completion_identity
from wscan.request_logger import RequestLogger
from wscan.scanners.sqli import SQLiScanner


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_sqli_probe_ledger_vulnerable_twin(tmp_path, probe_server, carrier):
    """Vulnerable endpoint: records match transmissions, payload_fingerprint consistent, no incomplete."""
    output = tmp_path / f"sqli-vuln-{carrier}"
    url = f"{probe_server}/sqli/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "sqli", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    # 1. Finding must be confirmed
    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "sqli"

    # 2. Check probe records in probe_attempts.jsonl
    recorded = rows(engine.request_logger)
    assert len(recorded) > 0

    sqli_records = [r for r in recorded if r.get("check") == "sqli" and r.get("wave") == "standard"]
    assert len(sqli_records) > 0

    # Verify payload_fingerprint is present and identical across the causal chain for the finding payload
    requests = [r for r in sqli_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in sqli_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in sqli_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched_decision = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched_decision is not None, "At least one decision must be matched on vulnerable target"
    assert matched_decision.get("payload_fingerprint"), "Decision must have payload_fingerprint"

    # Correlated request
    correlated_req = next(r for r in requests if r["attempt_id"] == matched_decision["request_attempt_id"])
    assert correlated_req["payload_fingerprint"] == matched_decision["payload_fingerprint"]

    # No incomplete notes in wave_errors
    assert not any(n.startswith("probe_ledger_incomplete:") for n in engine.wave_errors)
    obs = engine.observability_summary()
    assert "probe_ledger_incomplete" not in obs["by_category"]


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_sqli_probe_ledger_safe_twin(tmp_path, probe_server, carrier):
    """Safe endpoint: all non-matching decisions, counts reconcile, no incomplete note."""
    output = tmp_path / f"sqli-safe-{carrier}"
    url = f"{probe_server}/sqli/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "sqli", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    # 1. 0 findings
    assert len(engine.all_findings) == 0

    # 2. Decisions are no_match
    recorded = rows(engine.request_logger)
    decisions = [
        r for r in recorded
        if r.get("check") == "sqli" and r.get("wave") == "standard" and r.get("record_kind") == "decision"
    ]
    assert len(decisions) >= 1
    assert all(d.get("outcome") == "no_match" for d in decisions)
    assert all(d.get("payload_fingerprint") for d in decisions)

    # 3. No incomplete notes
    assert not any(n.startswith("probe_ledger_incomplete:") for n in engine.wave_errors)
    obs = engine.observability_summary()
    assert "probe_ledger_incomplete" not in obs["by_category"]


@pytest.mark.asyncio
async def test_sqli_probe_ledger_write_failure_marks_incomplete_without_breaking_scan(tmp_path, probe_server):
    """When probe_ledger write fails, scan finishes, findings remain, but wave_errors logs write_failed."""
    output = tmp_path / "sqli-write-fail"
    engine = make_engine(f"{probe_server}/sqli/vulnerable/form", "sqli", output, timeout=2)

    # Quarantining the probe_ledger simulates durable write failure
    engine.request_logger.probe_ledger._quarantined = True

    await asyncio.wait_for(engine.run(), timeout=60)

    # Scan and findings must NOT be broken by ledger write failure
    assert len(engine.all_findings) >= 1

    # Observability MUST record probe_ledger_incomplete:sqli:standard:write_failed
    assert "probe_ledger_incomplete:sqli:standard:write_failed" in engine.wave_errors
    obs = engine.observability_summary()
    assert obs["by_category"].get("probe_ledger_incomplete", 0) >= 1

    # Checkpoint must NOT fail due to ledger failure (checkpoint remains functional)
    assert engine.checkpoint is not None


@pytest.mark.asyncio
async def test_sqli_probe_ledger_count_mismatch_marks_incomplete(tmp_path):
    """When executed != planned count (without findings or auth lost), count_mismatch is recorded."""
    output = tmp_path / "sqli-mismatch"
    logger = RequestLogger(output)

    scanner = object.__new__(SQLiScanner)
    scanner.engine = SimpleNamespace(
        login_url="",
        logged_in_marker="",
        max_payloads=10,
        sleep_factor=0.0,
        wave_errors=[],
        request_logger=logger,
        checkpoint=None,
    )
    scanner.browser = SimpleNamespace(
        page=SimpleNamespace(url="http://example.com/test"),
        last_probe_delivered=True,
    )
    scanner.monitor = None
    scanner.CHECK_TYPE = "sqli"
    scanner.SUPPORTS_JSON_BODY = False
    scanner.SUPPORTS_XML_BODY = False
    scanner._should_route_to_api_get = lambda ip: False
    scanner._field_budget_gate = lambda: False
    scanner.may_scan_injection_point = lambda ip: True

    # 3 payloads planned, but simulate only 1 executed due to premature break without finding
    scanner.get_payloads = AsyncMock(return_value=["p1", "p2", "p3"])
    scanner._prioritize_login_payloads = lambda fn, pls: pls
    scanner._get_baseline = AsyncMock(return_value=("baseline_content", {"response": {"status": 200}}))
    scanner._current_page_url = lambda url, pair=None: url
    scanner.check_response_for_patterns = lambda src, pats: None
    scanner._probe_id = lambda p: "p_id"
    scanner._record_scan_note = lambda note: scanner.engine.wave_errors.append(note)
    scanner.log_payload_test = AsyncMock()

    # Stub _apply_ip to return safe non-matching response
    scanner._apply_ip = AsyncMock(return_value=("safe_content", {"response": {"status": 200}}))
    scanner._probe_decision = lambda *args, **kwargs: None

    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)

    # Force early break in the loop by patching payloads during iteration or simulating loop break
    # For instance, if an unexpected exception or short circuit caused executed < planned
    scanner.get_payloads = AsyncMock(return_value=["p1", "p2", "p3"])

    # Let's run scan_injection_point directly where _test_payload only runs once by setting auth_lost after 1st
    # Wait, if auth_lost is set, it's not count_mismatch. To trigger count_mismatch without auth_lost and without findings:
    # We can mock get_payloads returning 3, but executed_standard_count ending up != planned
    # Or manifest_requests count != executed_standard_count (e.g. 2 executed, but 0 in manifest)
    with patch.object(scanner, "evolved_payloads", AsyncMock(return_value=[])):
        with patch.object(scanner, "mutated_payloads", AsyncMock(return_value=[])):
            # Here logger has probe_ledger enabled, but since _apply_ip is mocked, 0 requests are logged to ledger
            # So manifest_count (0) != executed_count (3) -> count_mismatch!
            findings = await scanner.scan_injection_point(ip, {})

    assert "probe_ledger_incomplete:sqli:standard:count_mismatch" in scanner.engine.wave_errors


def test_sqli_probe_ledger_redaction_secrets_not_persisted(tmp_path):
    """Sensitive headers (Cookie, Authorization) and credentials are redacted in probe_attempts.jsonl."""
    logger = RequestLogger(tmp_path)
    secret_cookie = "session_token_xyz_secret_999"
    secret_auth = "Bearer super_secret_jwt_token_888"

    # Log probe through request logger
    logger.log_probe(
        role="attack",
        check="sqli",
        wave="standard",
        transport="playwright",
        field="username",
        sent=True,
        pair={
            "request": {
                "method": "POST",
                "url": "http://example.com/login?token=sensitive_query_111",
                "headers": {
                    "Cookie": f"session={secret_cookie}",
                    "Authorization": secret_auth,
                    "User-Agent": "WscanAgent",
                },
                "post_data": "username=admin&password=secret_password_222",
            },
            "response": {
                "status": 200,
                "url": "http://example.com/login",
                "headers": {
                    "Set-Cookie": f"session={secret_cookie}; HttpOnly",
                },
                "body": "Welcome admin",
            },
        },
        payload="' OR '1'='1",
        payload_fingerprint="abc123fingerprint",
        record_kind="request",
    )

    ledger_path = tmp_path / "probe_attempts.jsonl"
    assert ledger_path.exists()
    content = ledger_path.read_text(encoding="utf-8")

    # Sensitive values must NOT appear in plaintext
    assert secret_cookie not in content
    assert secret_auth not in content
    assert "secret_password_222" not in content
    assert "sensitive_query_111" not in content

    # Fingerprint and headers_excerpt redacted
    assert "abc123fingerprint" in content
    assert "<redacted>" in content


def test_sqli_probe_ledger_existing_jsonl_compatibility(tmp_path):
    """payloads.jsonl and http_requests.jsonl retain their format and are unaffected by ledger."""
    logger = RequestLogger(tmp_path)

    # Log HTTP request
    logger.log_http({
        "request": {
            "method": "GET",
            "url": "http://example.com/products?id=1",
            "headers": {"Host": "example.com"},
            "timestamp": 1700000000.0,
        },
        "response": {
            "status": 200,
            "headers": {"Content-Type": "text/html"},
        },
    })

    # Log payload test
    logger.log_payload("id", "' OR '1'='1", "sqli", "http://example.com/products", payload_fingerprint="fp123")

    http_jsonl = tmp_path / "http_requests.jsonl"
    payload_jsonl = tmp_path / "payloads.jsonl"

    assert http_jsonl.exists()
    assert payload_jsonl.exists()

    http_row = json.loads(http_jsonl.read_text(encoding="utf-8").strip())
    assert set(http_row.keys()) == {
        "ts", "method", "url", "transport_route", "request_headers",
        "post_data", "status", "response_headers",
    }

    payload_row = json.loads(payload_jsonl.read_text(encoding="utf-8").strip())
    # probe_attempt_id is included when logged, payload content is redacted if secret
    assert set(payload_row.keys()).issubset({
        "ts", "url", "field", "check_type", "payload", "probe_attempt_id",
    })
    assert payload_row["field"] == "id"
    assert payload_row["check_type"] == "sqli"


def test_sqli_probe_ledger_resume_causality(tmp_path):
    """On resume, attempt IDs, sequential ordering, and causal relationships are preserved."""
    # First run: create records
    logger1 = RequestLogger(tmp_path)
    aid1 = logger1.log_probe(
        role="attack", check="sqli", wave="standard", record_kind="request",
        payload_fingerprint="fp_resume_test",
    )
    aid2 = logger1.log_probe(
        role="attack", check="sqli", wave="standard", record_kind="observation",
        parent_id=aid1, request_attempt_id=aid1, sent=True,
        payload_fingerprint="fp_resume_test",
    )
    aid3 = logger1.log_probe(
        role="attack", check="sqli", wave="standard", record_kind="decision",
        parent_id=aid2, request_attempt_id=aid1, outcome="no_match",
        payload_fingerprint="fp_resume_test",
    )
    logger1.probe_ledger.write_manifest()

    # Second run: restore from same directory (resume)
    logger2 = RequestLogger(tmp_path)
    assert not logger2.probe_ledger.quarantined
    assert not logger2.probe_ledger.evidence_incomplete

    # Subsequent attempt ID must follow strictly monotonically
    seq1 = int(aid3.rpartition(":")[2])
    aid4 = logger2.probe_ledger.next_attempt_id()
    seq4 = int(aid4.rpartition(":")[2])
    assert seq4 == seq1 + 1

    # Causality intact
    rows2 = rows(logger2)
    by_id = {r["attempt_id"]: r for r in rows2}
    assert by_id[aid2]["request_attempt_id"] == aid1
    assert by_id[aid3]["request_attempt_id"] == aid1
    assert by_id[aid3]["parent_id"] == aid2
    assert by_id[aid1]["payload_fingerprint"] == "fp_resume_test"
    assert by_id[aid2]["payload_fingerprint"] == "fp_resume_test"
    assert by_id[aid3]["payload_fingerprint"] == "fp_resume_test"
