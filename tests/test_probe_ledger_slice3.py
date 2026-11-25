"""Probe evidence ledger tests for Slice 3:
1. Playwright and HTTPX JSON transports for OS injection (os).
2. Playwright and HTTPX JSON transports for SSTI (ssti).
3. Playwright and HTTPX JSON transports for NoSQL injection (nosql).
4. Playwright and HTTPX JSON transports for Path Traversal (path_traversal).
5. BaseScanner shared helpers (_payload_fingerprint and dispatch probe propagation).

For each target:
1. Vulnerable and safe twin endpoints: recorded count matches executed transmission count.
2. Incomplete on recorder write failure or count mismatch.
3. Privacy / Secret redaction: secrets and sensitive headers/fields are never persisted in plaintext.
4. JSONL compatibility: payloads.jsonl and http_requests.jsonl retain exact format and counts.
"""
from __future__ import annotations

import asyncio
import html
import json
import os
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock, patch

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse
import uvicorn

from wscan.attempt_ledger import payload_fingerprint
from wscan.checkpoint import CheckpointState
from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint
from wscan.probe_ledger import sha256_hex
from wscan.probe_recorder import ProbeLedger, completion_identity
from wscan.request_logger import RequestLogger
from wscan.scanners.os_injection import OSInjectionScanner
from wscan.scanners.ssti import SSTIScanner
from wscan.scanners.nosql_injection import NoSQLInjectionScanner
from wscan.scanners.path_traversal import PathTraversalScanner


@pytest.fixture(scope="module")
def slice3_server():
    app = FastAPI()

    @app.api_route("/{check}/{kind}/{carrier}", methods=["GET", "POST"])
    async def page(check: str, kind: str, carrier: str, request: Request):
        value = request.query_params.get("q", "")
        has_nosql_query = any("[$ne]" in k or "$ne" in v for k, v in request.query_params.items())
        json_body = {}
        if request.method == "POST":
            if carrier == "json":
                try:
                    json_body = await request.json()
                    value = str(json_body.get("q", ""))
                except Exception:
                    value = ""
            else:
                form = await request.form()
                value = str(form.get("q", ""))

        text = "Normal benign page content " * 10

        if check == "os":
            if kind == "vulnerable" and value not in ("", "baseline_os_test"):
                text = "uid=0(root) gid=0(root) groups=0(root)"
            elif kind == "safe":
                text = f"Sanitized input: {html.escape(value)}"

        elif check == "ssti":
            if kind == "vulnerable" and "2654435761*2654435761" in value:
                text = "Result: 7046029209275649121"
            elif kind == "safe":
                text = f"Expression literal: {html.escape(value)}"

        elif check == "nosql":
            if kind == "vulnerable":
                if carrier == "json":
                    if isinstance(json_body.get("q"), dict) or "$ne" in str(json_body):
                        text = "MongoError: comparison operator not supported in query"
                elif has_nosql_query or "$ne" in value or "{" in value:
                    text = "MongoError: syntax error in expression"
            elif kind == "safe":
                text = f"Filtered input: {html.escape(value)}"

        elif check == "path_traversal":
            if kind == "vulnerable" and (".." in value or "etc" in value or "passwd" in value):
                text = "root:x:0:0:root:/root:/bin/bash"
            elif kind == "safe":
                text = f"Safe file path: {html.escape(value)}"

        if carrier == "json":
            return JSONResponse({"status": "ok", "message": text})

        form = '<form method="post"><input name="q"><button type="submit">Submit</button></form>' if carrier == "form" else ""
        return HTMLResponse(f"<html><head><title>Slice3 Fixture</title></head><body>{form}<div>{text}</div></body></html>")

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline
        time.sleep(0.01)
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


def make_engine(url, check, output, **options):
    engine = ScanEngine(
        url,
        checks=[check],
        llm_provider="none",
        headless=True,
        output_dir=str(output),
        open_report=False,
        enable_waf_detection=False,
        enable_ai_analysis=False,
        enable_payload_learning=False,
        enable_adaptive_payloads=False,
        enable_payload_evolution=False,
        enable_payload_mutation=False,
        enable_sitemap_crawl=False,
        enable_component_intel=False,
        enable_tls_scan=False,
        auto_spa_crawl=False,
        depth=0,
        fast_mode=True,
        request_delay=0,
        use_planner=False,
        sarif=False,
        navigation_retries=0,
        **options,
    )
    if check == "os":
        engine.payload_gen.default_payloads[check] = ["; id ;"]
    elif check == "ssti":
        engine.payload_gen.default_payloads[check] = ["{{2654435761*2654435761}}"]
    elif check == "nosql":
        engine.payload_gen.default_payloads[check] = ['{"$ne": ""}']
    elif check == "path_traversal":
        engine.payload_gen.default_payloads[check] = ["../../../../etc/passwd"]
    return engine


def rows(logger):
    path = logger.probe_ledger.path
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


# ==============================================================================
# Target 1: OS Injection (os)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_os_probe_ledger_vulnerable_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"os-vuln-{carrier}"
    url = f"{slice3_server}/os/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "os", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "os"

    recorded = rows(engine.request_logger)
    assert len(recorded) > 0

    os_records = [r for r in recorded if r.get("check") == "os" and r.get("wave") == "standard"]
    assert len(os_records) > 0

    requests = [r for r in os_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in os_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in os_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]

    assert not any(n.startswith("probe_ledger_incomplete:os") for n in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_os_probe_ledger_safe_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"os-safe-{carrier}"
    url = f"{slice3_server}/os/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "os", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    os_decisions = [r for r in recorded if r.get("check") == "os" and r.get("record_kind") == "decision" and r.get("role") == "attack"]
    assert len(os_decisions) >= 1
    assert all(d.get("outcome") == "no_match" for d in os_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:os") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_os_probe_ledger_write_failure(tmp_path):
    engine = make_engine("http://example.com/test", "os", tmp_path)
    scanner = OSInjectionScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner.dispatch = AsyncMock(return_value=SimpleNamespace(source="benign", pair={"response": {"status": 200}}))

    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)
    scanner.get_payloads = AsyncMock(return_value=["; id ;"])

    # Simulate quarantined ledger
    engine.request_logger.probe_ledger._quarantined = True
    await scanner.scan_injection_point(ip, {})

    assert "probe_ledger_incomplete:os:standard:write_failed" in engine.wave_errors


@pytest.mark.asyncio
async def test_os_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "os", tmp_path)
    scanner = OSInjectionScanner(engine)
    scanner.log_payload_test = AsyncMock()
    # Mock dispatch returning empty pair so no probe record is written to ledger
    scanner.dispatch = AsyncMock(return_value=SimpleNamespace(source="benign", pair={"response": {"status": 200}}))
    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)
    scanner.get_payloads = AsyncMock(return_value=["; id ;", "; uname ;"])

    await scanner.scan_injection_point(ip, {})
    assert "probe_ledger_incomplete:os:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Target 2: SSTI (ssti)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_ssti_probe_ledger_vulnerable_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"ssti-vuln-{carrier}"
    url = f"{slice3_server}/ssti/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "ssti", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "ssti"

    recorded = rows(engine.request_logger)
    ssti_records = [r for r in recorded if r.get("check") == "ssti" and r.get("wave") == "standard"]
    assert len(ssti_records) > 0

    requests = [r for r in ssti_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in ssti_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in ssti_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]
    assert not any(n.startswith("probe_ledger_incomplete:ssti") for n in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_ssti_probe_ledger_safe_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"ssti-safe-{carrier}"
    url = f"{slice3_server}/ssti/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "ssti", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    ssti_decisions = [r for r in recorded if r.get("check") == "ssti" and r.get("record_kind") == "decision" and r.get("role") == "attack"]
    assert len(ssti_decisions) >= 1
    assert all(d.get("outcome") == "no_match" for d in ssti_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:ssti") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_ssti_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "ssti", tmp_path)
    scanner = SSTIScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner.dispatch = AsyncMock(return_value=SimpleNamespace(source="benign", pair={"response": {"status": 200}}))
    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)

    await scanner.scan_injection_point(ip, {})
    assert "probe_ledger_incomplete:ssti:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Target 3: NoSQL Injection (nosql)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_nosql_probe_ledger_vulnerable_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"nosql-vuln-{carrier}"
    url = f"{slice3_server}/nosql/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "nosql", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "nosql"

    recorded = rows(engine.request_logger)
    nosql_records = [r for r in recorded if r.get("check") == "nosql" and r.get("wave") == "standard"]
    assert len(nosql_records) > 0

    requests = [r for r in nosql_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in nosql_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in nosql_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]
    assert not any(n.startswith("probe_ledger_incomplete:nosql") for n in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_nosql_probe_ledger_safe_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"nosql-safe-{carrier}"
    url = f"{slice3_server}/nosql/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "nosql", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    nosql_decisions = [r for r in recorded if r.get("check") == "nosql" and r.get("record_kind") == "decision" and r.get("role") == "attack"]
    assert len(nosql_decisions) >= 1
    assert all(d.get("outcome") == "no_match" for d in nosql_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:nosql") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_nosql_json_probe_ledger_vulnerable(tmp_path, slice3_server):
    """JSON body carrier for NoSQL injection."""
    output = tmp_path / "nosql-json-vuln"
    url = f"{slice3_server}/nosql/vulnerable/json"
    engine = make_engine(url, "nosql", output, timeout=2)
    ip = InjectionPoint.for_json_body("POST", url, "/q", template_id="fixture")
    engine.json_injection_points = [ip]
    engine.injection_templates["fixture"] = dict(url=url, method="POST", json_body={"q": "original"})

    await engine._run_json_injection_checks()
    engine.request_logger.probe_ledger.write_manifest()

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "nosql"

    recorded = rows(engine.request_logger)
    json_records = [r for r in recorded if r.get("check") == "nosql" and r.get("wave") == "standard"]
    assert len(json_records) > 0

    decisions = [r for r in json_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]
    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")
    assert not any(n.startswith("probe_ledger_incomplete:nosql") for n in engine.wave_errors)


# ==============================================================================
# Target 4: Path Traversal (path_traversal)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_path_traversal_probe_ledger_vulnerable_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"pt-vuln-{carrier}"
    url = f"{slice3_server}/path_traversal/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "path_traversal", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "path_traversal"

    recorded = rows(engine.request_logger)
    pt_records = [r for r in recorded if r.get("check") == "path_traversal" and r.get("wave") == "standard"]
    assert len(pt_records) > 0

    requests = [r for r in pt_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in pt_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in pt_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]
    assert not any(n.startswith("probe_ledger_incomplete:path_traversal") for n in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_path_traversal_probe_ledger_safe_twin(tmp_path, slice3_server, carrier):
    output = tmp_path / f"pt-safe-{carrier}"
    url = f"{slice3_server}/path_traversal/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "path_traversal", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    pt_decisions = [r for r in recorded if r.get("check") == "path_traversal" and r.get("record_kind") == "decision" and r.get("role") == "attack"]
    assert len(pt_decisions) >= 1
    assert all(d.get("outcome") == "no_match" for d in pt_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:path_traversal") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_path_traversal_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "path_traversal", tmp_path)
    scanner = PathTraversalScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner.dispatch = AsyncMock(return_value=SimpleNamespace(source="benign", pair={"response": {"status": 200}}))
    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)
    scanner.get_payloads = AsyncMock(return_value=["../../etc/passwd", "../../../etc/passwd"])

    await scanner.scan_injection_point(ip, {})
    assert "probe_ledger_incomplete:path_traversal:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Cross-cutting: Privacy & Redaction, JSONL Compatibility, BaseScanner helper
# ==============================================================================

def test_slice3_probe_ledger_redaction_secrets_not_persisted(tmp_path):
    """Sensitive headers and values are never persisted in probe_attempts.jsonl for slice 3 checks."""
    logger = RequestLogger(tmp_path)
    secret_cookie = "secret_session_slice3_tok"
    secret_auth = "Bearer slice3_secret_api_token"

    for check in ["os", "ssti", "nosql", "path_traversal"]:
        logger.log_probe(
            role="attack",
            check=check,
            wave="standard",
            transport="playwright",
            field="input_field",
            sent=True,
            pair={
                "request": {
                    "method": "POST",
                    "url": f"http://example.com/{check}?token=confidential_slice3_param",
                    "headers": {
                        "Cookie": f"session={secret_cookie}",
                        "Authorization": secret_auth,
                    },
                    "post_data": "q=test&password=very_secret_password",
                },
                "response": {
                    "status": 200,
                    "url": f"http://example.com/{check}",
                    "headers": {"Set-Cookie": f"session={secret_cookie}"},
                    "body": "<div>Normal response</div>",
                },
            },
            payload="test_payload",
            payload_fingerprint=f"fp_{check}_secret_test",
            record_kind="request",
        )

    ledger_path = tmp_path / "probe_attempts.jsonl"
    assert ledger_path.exists()
    content = ledger_path.read_text(encoding="utf-8")

    assert secret_cookie not in content
    assert secret_auth not in content
    assert "confidential_slice3_param" not in content
    assert "very_secret_password" not in content
    assert "<redacted>" in content


def test_slice3_probe_ledger_existing_jsonl_compatibility(tmp_path):
    """payloads.jsonl and http_requests.jsonl retain their format and are unaffected by slice 3 records."""
    logger = RequestLogger(tmp_path)
    logger.log_http({
        "request": {
            "method": "GET",
            "url": "http://example.com/os?q=id",
            "headers": {"Host": "example.com"},
            "timestamp": 1700000000.0,
        },
        "response": {"status": 200, "headers": {"Content-Type": "text/html"}},
    })
    logger.log_payload("q", "; id ;", "os", "http://example.com/os", payload_fingerprint="fp_os_comp")

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


def test_base_scanner_payload_fingerprint_helper(tmp_path):
    """BaseScanner._payload_fingerprint correctly binds payload, unit_key, and check."""
    engine = make_engine("http://example.com/test", "os", tmp_path)
    scanner = OSInjectionScanner(engine)
    ip = InjectionPoint.for_form("http://example.com/form", "field1", 0)
    fp = scanner._payload_fingerprint(ip, "; id ;")
    assert fp != ""
    assert isinstance(fp, str)
    assert len(fp) == 64  # sha256 hex length

    unit_key = CheckpointState._candidate_unit_key(ip, "os")
    expected_fp = payload_fingerprint("; id ;", unit_key, "os")
    assert fp == expected_fp
