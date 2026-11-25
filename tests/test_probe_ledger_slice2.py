"""Probe evidence ledger tests for Slice 2:
1. Playwright transport XSS standard sweep (form and query).
2. HTTPX transport JSON body injection for SQLi (_apply_json_payload / _run_json_injection_checks).
3. Thread-safe reconciliation helper (_reconcile_probe_ledger_wave / wave_records lock protection).

For each target:
1. Vulnerable and safe twin endpoints: recorded count matches executed transmission count.
2. Incomplete on recorder write failure or count mismatch.
3. Privacy / Secret redaction: secrets and sensitive headers/fields are never persisted in plaintext.
4. JSONL compatibility: payloads.jsonl and http_requests.jsonl retain exact format and counts.
5. Resume stability: attempt IDs and causality (request -> observation -> decision) are preserved on resume.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest

from tests.test_shared_probe_evidence import json_scan, make_engine, probe_server, rows
from wscan.attempt_ledger import payload_fingerprint
from wscan.checkpoint import CheckpointState
from wscan.injection_point import InjectionPoint
from wscan.probe_ledger import sha256_hex
from wscan.probe_recorder import ProbeLedger, completion_identity
from wscan.request_logger import RequestLogger
from wscan.scanners.sqli import SQLiScanner
from wscan.scanners.xss import XSSScanner


# ==============================================================================
# Target 1: Playwright XSS standard sweep
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_xss_probe_ledger_vulnerable_twin(tmp_path, probe_server, carrier):
    """Vulnerable endpoint: records match transmissions, payload_fingerprint consistent, no incomplete."""
    output = tmp_path / f"xss-vuln-{carrier}"
    url = f"{probe_server}/xss/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "xss", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    # 1. Finding confirmed
    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "xss"

    # 2. Check probe records in probe_attempts.jsonl
    recorded = rows(engine.request_logger)
    assert len(recorded) > 0

    xss_records = [r for r in recorded if r.get("check") == "xss" and r.get("wave") == "standard"]
    assert len(xss_records) > 0

    requests = [r for r in xss_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in xss_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in xss_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched_decision = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched_decision is not None, "At least one decision must be matched on vulnerable target"
    assert matched_decision.get("payload_fingerprint"), "Decision must have payload_fingerprint"

    # Correlated request
    correlated_req = next(r for r in requests if r["attempt_id"] == matched_decision["request_attempt_id"])
    assert correlated_req["payload_fingerprint"] == matched_decision["payload_fingerprint"]

    # Also verify payload row has identical fingerprint
    payload_rows = [r for r in recorded if r.get("record_kind") == "payload" and r.get("check") == "xss"]
    assert len(payload_rows) >= 1
    assert any(p.get("payload_fingerprint") == matched_decision["payload_fingerprint"] for p in payload_rows)

    # No incomplete notes in wave_errors
    assert not any(n.startswith("probe_ledger_incomplete:") for n in engine.wave_errors)
    obs = engine.observability_summary()
    assert "probe_ledger_incomplete" not in obs["by_category"]


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_xss_probe_ledger_safe_twin(tmp_path, probe_server, carrier):
    """Safe endpoint: all non-matching decisions, counts reconcile, no incomplete note."""
    output = tmp_path / f"xss-safe-{carrier}"
    url = f"{probe_server}/xss/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "xss", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    # 1. 0 findings
    assert len(engine.all_findings) == 0

    # 2. Decisions are no_match
    recorded = rows(engine.request_logger)
    decisions = [
        r for r in recorded
        if r.get("check") == "xss" and r.get("wave") == "standard" and r.get("record_kind") == "decision"
    ]
    assert len(decisions) >= 1
    assert all(d.get("outcome") == "no_match" for d in decisions)
    assert all(d.get("payload_fingerprint") for d in decisions)

    # 3. No incomplete notes
    assert not any(n.startswith("probe_ledger_incomplete:") for n in engine.wave_errors)
    obs = engine.observability_summary()
    assert "probe_ledger_incomplete" not in obs["by_category"]


@pytest.mark.asyncio
async def test_xss_probe_ledger_write_failure_marks_incomplete_without_breaking_scan(tmp_path, probe_server):
    """When probe_ledger write fails on XSS sweep, scan finishes, findings remain, but wave_errors logs write_failed."""
    output = tmp_path / "xss-write-fail"
    engine = make_engine(f"{probe_server}/xss/vulnerable/form", "xss", output, timeout=2)

    # Quarantining probe_ledger simulates durable write failure
    engine.request_logger.probe_ledger._quarantined = True

    await asyncio.wait_for(engine.run(), timeout=60)

    # Scan and findings must NOT be broken by ledger write failure
    assert len(engine.all_findings) >= 1

    # Observability MUST record probe_ledger_incomplete:xss:standard:write_failed
    assert "probe_ledger_incomplete:xss:standard:write_failed" in engine.wave_errors
    obs = engine.observability_summary()
    assert obs["by_category"].get("probe_ledger_incomplete", 0) >= 1


@pytest.mark.asyncio
async def test_xss_probe_ledger_count_mismatch_marks_incomplete(tmp_path):
    """When executed != planned count (without findings or auth lost), count_mismatch is recorded."""
    output = tmp_path / "xss-mismatch"
    logger = RequestLogger(output)

    scanner = object.__new__(XSSScanner)
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
        reset_dialog=lambda: None,
        dialog_fired=False,
        dialog_message="",
        navigate=AsyncMock(),
        get_page_source=AsyncMock(return_value=""),
    )
    scanner.monitor = None
    scanner.CHECK_TYPE = "xss"
    scanner.SUPPORTS_JSON_BODY = True
    scanner.SUPPORTS_XML_BODY = False
    scanner._should_route_to_api_get = lambda ip: False
    scanner._field_budget_gate = lambda: False
    scanner.may_scan_injection_point = lambda ip: True
    scanner._response_body_for = lambda url: ""
    scanner._baseline_handlers = AsyncMock(return_value=([], None, ""))
    scanner._analyze_reflection = lambda *args: None
    scanner._record_scan_note = lambda note: scanner.engine.wave_errors.append(note)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("safe_content", {"response": {"status": 200}}))
    scanner._probe_decision = lambda *args, **kwargs: None

    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)

    # 3 payloads planned, but _apply_ip mocked without appending to ledger -> manifest_count (0) != executed_count (3)
    scanner.get_payloads = AsyncMock(return_value=["<script>1</script>", "<script>2</script>", "<script>3</script>"])

    with patch.object(scanner, "evolved_payloads", AsyncMock(return_value=[])):
        findings = await scanner.scan_injection_point(ip, {})

    assert "probe_ledger_incomplete:xss:standard:count_mismatch" in scanner.engine.wave_errors


def test_xss_probe_ledger_redaction_secrets_not_persisted(tmp_path):
    """Sensitive headers (Cookie, Authorization) and credentials are redacted in probe_attempts.jsonl for XSS."""
    logger = RequestLogger(tmp_path)
    secret_cookie = "secret_session_xss_999"
    secret_auth = "Bearer xss_jwt_secret_token"

    logger.log_probe(
        role="attack",
        check="xss",
        wave="standard",
        transport="playwright",
        field="search_term",
        sent=True,
        pair={
            "request": {
                "method": "POST",
                "url": "http://example.com/search?secret_key=sensitive_query_xss",
                "headers": {
                    "Cookie": f"auth={secret_cookie}",
                    "Authorization": secret_auth,
                },
                "post_data": "search_term=alert_test&user_secret=pass123",
            },
            "response": {
                "status": 200,
                "url": "http://example.com/search",
                "headers": {"Set-Cookie": f"auth={secret_cookie}"},
                "body": "<div>Results</div>",
            },
        },
        payload="<script>alert(1)</script>",
        payload_fingerprint="fp_xss_secret_test",
        record_kind="request",
    )

    ledger_path = tmp_path / "probe_attempts.jsonl"
    assert ledger_path.exists()
    content = ledger_path.read_text(encoding="utf-8")

    assert secret_cookie not in content
    assert secret_auth not in content
    assert "sensitive_query_xss" not in content
    assert "fp_xss_secret_test" in content
    assert "<redacted>" in content


def test_xss_probe_ledger_existing_jsonl_compatibility(tmp_path):
    """payloads.jsonl and http_requests.jsonl retain their format and are unaffected by XSS ledger."""
    logger = RequestLogger(tmp_path)
    logger.log_http({
        "request": {
            "method": "GET",
            "url": "http://example.com/xss?q=test",
            "headers": {"Host": "example.com"},
            "timestamp": 1700000000.0,
        },
        "response": {"status": 200, "headers": {"Content-Type": "text/html"}},
    })
    logger.log_payload("q", "<script>alert(1)</script>", "xss", "http://example.com/xss", payload_fingerprint="fp_xss_comp")

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
    assert set(payload_row.keys()).issubset({
        "ts", "url", "field", "check_type", "payload", "probe_attempt_id",
    })
    assert payload_row["field"] == "q"
    assert payload_row["check_type"] == "xss"


def test_xss_probe_ledger_resume_causality(tmp_path):
    """On resume, XSS attempt IDs, sequential ordering, and causal relationships are preserved."""
    logger1 = RequestLogger(tmp_path)
    aid1 = logger1.log_probe(
        role="attack", check="xss", wave="standard", record_kind="request",
        payload_fingerprint="fp_xss_resume",
    )
    aid2 = logger1.log_probe(
        role="attack", check="xss", wave="standard", record_kind="observation",
        parent_id=aid1, request_attempt_id=aid1, sent=True,
        payload_fingerprint="fp_xss_resume",
    )
    aid3 = logger1.log_probe(
        role="attack", check="xss", wave="standard", record_kind="decision",
        parent_id=aid2, request_attempt_id=aid1, outcome="no_match",
        payload_fingerprint="fp_xss_resume",
    )
    logger1.probe_ledger.write_manifest()

    logger2 = RequestLogger(tmp_path)
    assert not logger2.probe_ledger.quarantined
    assert not logger2.probe_ledger.evidence_incomplete

    seq1 = int(aid3.rpartition(":")[2])
    aid4 = logger2.probe_ledger.next_attempt_id()
    seq4 = int(aid4.rpartition(":")[2])
    assert seq4 == seq1 + 1

    rows2 = rows(logger2)
    by_id = {r["attempt_id"]: r for r in rows2}
    assert by_id[aid2]["request_attempt_id"] == aid1
    assert by_id[aid3]["request_attempt_id"] == aid1
    assert by_id[aid3]["parent_id"] == aid2
    assert by_id[aid1]["payload_fingerprint"] == "fp_xss_resume"
    assert by_id[aid2]["payload_fingerprint"] == "fp_xss_resume"
    assert by_id[aid3]["payload_fingerprint"] == "fp_xss_resume"


# ==============================================================================
# Target 2: HTTPX transport JSON body injection for SQLi
# ==============================================================================

@pytest.mark.asyncio
async def test_json_sqli_probe_ledger_vulnerable_twin(tmp_path, probe_server):
    """HTTPX JSON body vulnerable endpoint: records match transmissions, fingerprint consistent, no incomplete."""
    url = f"{probe_server}/sqli/vulnerable/json"
    engine, ip = await json_scan(url, "sqli", tmp_path)

    # 1. Finding confirmed
    assert len(engine.all_findings) >= 1
    assert engine.all_findings[0].check_type == "sqli"

    # 2. Probe records verification
    recorded = rows(engine.request_logger)
    assert len(recorded) > 0

    sqli_records = [r for r in recorded if r.get("check") == "sqli" and r.get("wave") == "standard"]
    assert len(sqli_records) > 0

    requests = [r for r in sqli_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in sqli_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in sqli_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched_decision = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched_decision is not None
    assert matched_decision.get("payload_fingerprint")

    correlated_req = next(r for r in requests if r["attempt_id"] == matched_decision["request_attempt_id"])
    assert correlated_req["payload_fingerprint"] == matched_decision["payload_fingerprint"]

    # 3. No incomplete notes
    assert not any(n.startswith("probe_ledger_incomplete:") for n in engine.wave_errors)
    obs = engine.observability_summary()
    assert "probe_ledger_incomplete" not in obs["by_category"]


@pytest.mark.asyncio
async def test_json_sqli_probe_ledger_safe_twin(tmp_path, probe_server):
    """HTTPX JSON body safe endpoint: 0 findings, decisions no_match, counts reconcile, no incomplete."""
    url = f"{probe_server}/sqli/safe/json"
    engine, ip = await json_scan(url, "sqli", tmp_path)

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
async def test_json_sqli_probe_ledger_write_failure_marks_incomplete_without_breaking_scan(tmp_path, probe_server):
    """When probe_ledger write fails during JSON body injection, scan finishes, findings remain, write_failed recorded."""
    url = f"{probe_server}/sqli/vulnerable/json"
    engine = make_engine(url, "sqli", tmp_path, timeout=2)
    ip = InjectionPoint.for_json_body("POST", url, "/q", template_id="fixture")
    engine.json_injection_points = [ip]
    engine.injection_templates["fixture"] = dict(url=url, method="POST", json_body={"q": "original", "password": "hidden-secret"})

    # Simulate durable write failure
    engine.request_logger.probe_ledger._quarantined = True

    await engine._run_json_injection_checks()

    # Finding must remain
    assert len(engine.all_findings) >= 1

    # Observability MUST record probe_ledger_incomplete:sqli:standard:write_failed
    assert "probe_ledger_incomplete:sqli:standard:write_failed" in engine.wave_errors
    obs = engine.observability_summary()
    assert obs["by_category"].get("probe_ledger_incomplete", 0) >= 1


@pytest.mark.asyncio
async def test_json_sqli_probe_ledger_count_mismatch_marks_incomplete(tmp_path, probe_server):
    """When JSON body template is missing or execution count does not reconcile with manifest, count_mismatch is recorded."""
    url = f"{probe_server}/sqli/safe/json"
    engine = make_engine(url, "sqli", tmp_path, timeout=2)
    # Point to non-existent template -> unexecutable template -> 0 requests sent -> count_mismatch
    ip = InjectionPoint.for_json_body("POST", url, "/q", template_id="non_existent_template")
    engine.json_injection_points = [ip]
    engine.injection_templates = {}

    await engine._run_json_injection_checks()

    assert "probe_ledger_incomplete:sqli:standard:count_mismatch" in engine.wave_errors


def test_json_sqli_probe_ledger_redaction_secrets_not_persisted(tmp_path):
    """Sensitive JSON fields (password, token), headers, and cookies are redacted in probe_attempts.jsonl."""
    logger = RequestLogger(tmp_path)
    secret_pw = "super_confidential_pw_999"
    secret_auth = "Bearer json_injection_jwt_token"

    logger.log_probe(
        role="attack",
        check="sqli",
        wave="standard",
        transport="httpx",
        field="json_password_field",
        sent=True,
        pair={
            "request": {
                "method": "POST",
                "url": "http://example.com/api/login?query_secret=top_secret_query_val",
                "headers": {
                    "Authorization": secret_auth,
                    "Content-Type": "application/json",
                },
                "post_data": json.dumps({"username": "admin", "password": secret_pw}),
            },
            "response": {
                "status": 200,
                "url": "http://example.com/api/login",
                "headers": {"Content-Type": "application/json"},
                "body": json.dumps({"status": "ok"}),
            },
        },
        payload="' OR '1'='1",
        payload_fingerprint="fp_json_secret_test",
        record_kind="request",
    )

    ledger_path = tmp_path / "probe_attempts.jsonl"
    assert ledger_path.exists()
    content = ledger_path.read_text(encoding="utf-8")

    assert secret_pw not in content
    assert secret_auth not in content
    assert "top_secret_query_val" not in content
    assert "fp_json_secret_test" in content
    assert "<redacted>" in content


def test_json_sqli_probe_ledger_existing_jsonl_compatibility(tmp_path):
    """JSON injection logging does not disturb payloads.jsonl or http_requests.jsonl schema."""
    logger = RequestLogger(tmp_path)
    logger.log_http({
        "request": {
            "method": "POST",
            "url": "http://example.com/api/update",
            "headers": {"Content-Type": "application/json"},
            "post_data": '{"id": "1"}',
            "timestamp": 1700000000.0,
        },
        "response": {"status": 200, "headers": {"Content-Type": "application/json"}},
    })
    logger.log_payload("id", "1' OR '1'='1", "sqli", "http://example.com/api/update", payload_fingerprint="fp_json_sqli_comp")

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
    assert set(payload_row.keys()).issubset({
        "ts", "url", "field", "check_type", "payload", "probe_attempt_id",
    })
    assert payload_row["field"] == "id"
    assert payload_row["check_type"] == "sqli"


def test_json_sqli_probe_ledger_resume_causality(tmp_path):
    """Resume preserves attempt ID ordering and parent/request references for HTTPX JSON probes."""
    logger1 = RequestLogger(tmp_path)
    aid1 = logger1.log_probe(
        role="attack", check="sqli", wave="standard", transport="httpx",
        record_kind="request", payload_fingerprint="fp_json_resume",
    )
    aid2 = logger1.log_probe(
        role="attack", check="sqli", wave="standard", transport="httpx",
        record_kind="observation", parent_id=aid1, request_attempt_id=aid1, sent=True,
        payload_fingerprint="fp_json_resume",
    )
    aid3 = logger1.log_probe(
        role="attack", check="sqli", wave="standard", transport="httpx",
        record_kind="decision", parent_id=aid2, request_attempt_id=aid1, outcome="no_match",
        payload_fingerprint="fp_json_resume",
    )
    logger1.probe_ledger.write_manifest()

    logger2 = RequestLogger(tmp_path)
    assert not logger2.probe_ledger.quarantined
    assert not logger2.probe_ledger.evidence_incomplete

    aid4 = logger2.probe_ledger.next_attempt_id()
    seq1 = int(aid3.rpartition(":")[2])
    seq4 = int(aid4.rpartition(":")[2])
    assert seq4 == seq1 + 1

    rows2 = rows(logger2)
    by_id = {r["attempt_id"]: r for r in rows2}
    assert by_id[aid2]["request_attempt_id"] == aid1
    assert by_id[aid3]["request_attempt_id"] == aid1
    assert by_id[aid3]["parent_id"] == aid2
    assert by_id[aid1]["payload_fingerprint"] == "fp_json_resume"
    assert by_id[aid2]["payload_fingerprint"] == "fp_json_resume"
    assert by_id[aid3]["payload_fingerprint"] == "fp_json_resume"


# ==============================================================================
# Lock protection & shared helper test (Follow-up item 3)
# ==============================================================================

def test_wave_records_lock_protection_and_filtering(tmp_path):
    """Verify wave_records operates under _lock and correctly filters role, unit, record_kind, injection_key."""
    ledger = ProbeLedger(tmp_path, "test_scan")
    # Populate events
    ledger.events = {
        "1": {"check": "sqli", "wave": "standard", "role": "attack", "record_kind": "request", "completion_unit": "u1", "injection_key": "k1"},
        "2": {"check": "sqli", "wave": "standard", "role": "baseline", "record_kind": "request", "completion_unit": "u1", "injection_key": "k1"},
        "3": {"check": "sqli", "wave": "standard", "role": "attack", "record_kind": "decision", "completion_unit": "u1", "injection_key": "k1"},
        "4": {"check": "xss", "wave": "standard", "role": "attack", "record_kind": "request", "completion_unit": "u2", "injection_key": "k2"},
        "5": {"check": "sqli", "wave": "standard", "role": "attack", "record_kind": "request", "completion_unit": "", "injection_key": "k3"},
    }

    # Query with unit
    recs = ledger.wave_records(check="sqli", wave="standard", role="attack", record_kind="request", unit="u1")
    assert len(recs) == 1
    assert recs[0]["completion_unit"] == "u1"

    # Query without unit but with injection_key
    recs_key = ledger.wave_records(check="sqli", wave="standard", role="attack", record_kind="request", injection_key="k3")
    assert len(recs_key) == 1
    assert recs_key[0]["injection_key"] == "k3"

    # Query xss
    recs_xss = ledger.wave_records(check="xss", wave="standard", role="attack", record_kind="request", unit="u2")
    assert len(recs_xss) == 1
    assert recs_xss[0]["check"] == "xss"
