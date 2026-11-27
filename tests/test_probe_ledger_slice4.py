"""Probe evidence ledger tests for Slice 4:
1. Playwright and HTTPX JSON transports for LDAP injection (ldap).
2. Playwright and HTTPX JSON transports for SSRF (ssrf).
3. Playwright and HTTPX JSON transports for Header Injection (header_injection).
4. Playwright transport for Open Redirect (open_redirect).

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
from pathlib import Path
import socket
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock
from urllib.parse import unquote

import pytest
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
import uvicorn

from wscan.attempt_ledger import payload_fingerprint
from wscan.checkpoint import CheckpointState
from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint
from wscan.request_logger import RequestLogger
from wscan.scanners.ldap_injection import LDAPScanner
from wscan.scanners.ssrf import SSRFScanner
from wscan.scanners.header_injection import HeaderInjectionScanner
from wscan.scanners.open_redirect import OpenRedirectScanner


@pytest.fixture(scope="module")
def slice4_server():
    app = FastAPI()

    @app.api_route("/{check}/{kind}/{carrier}", methods=["GET", "POST"])
    async def page(check: str, kind: str, carrier: str, request: Request):
        value = request.query_params.get("url", request.query_params.get("q", ""))
        json_body = {}
        if request.method == "POST":
            if carrier == "json":
                try:
                    json_body = await request.json()
                    value = str(json_body.get("url", json_body.get("q", "")))
                except Exception:
                    value = ""
            else:
                form = await request.form()
                value = str(form.get("url", form.get("q", "")))

        text = "Normal benign page content " * 10
        extra_headers: dict[str, str] = {}

        if check == "ldap":
            if kind == "vulnerable" and value not in ("", "normaluser"):
                text = "javax.naming.directory.InvalidSearchFilterException: bad search filter"
            elif kind == "safe":
                text = f"Filtered LDAP query: {html.escape(value)}"

        elif check == "ssrf":
            if kind == "vulnerable" and ("169.254.169.254" in value or "file://" in value):
                text = "ami-id: ami-0abcdef1234567890\ninstance-id: i-1234567890abcdef0"
            elif kind == "safe":
                text = f"Validated URL target: {html.escape(value)}"

        elif check == "header_injection":
            decoded = unquote(unquote(value))
            if kind == "vulnerable":
                if "X-WscanHdrInject" in decoded:
                    extra_headers["X-WscanHdrInject"] = "1"
                if "wscan_session=injected" in decoded:
                    extra_headers["Set-Cookie"] = "wscan_session=injected; Path=/"
                text = f"Header processed: {html.escape(value)}"
            elif kind == "safe":
                text = f"Sanitized header value: {html.escape(value)}"

        elif check == "open_redirect":
            if kind == "vulnerable" and "evil.wscan-test.example.com" in value:
                return RedirectResponse(url=value, status_code=302)
            elif kind == "safe":
                text = f"Safe local redirect: {html.escape(value)}"

        if carrier == "json":
            return JSONResponse({"status": "ok", "message": text}, headers=extra_headers)

        field_name = "url" if check in ("ssrf", "open_redirect") else "q"
        form = f'<form method="post"><input name="{field_name}"><button type="submit">Submit</button></form>' if carrier == "form" else ""
        return HTMLResponse(
            f"<html><head><title>Slice4 Fixture</title></head><body>{form}<div>{text}</div></body></html>",
            headers=extra_headers,
        )

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
    return engine


def rows(logger):
    path = logger.probe_ledger.path
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


# ==============================================================================
# Target 1: LDAP Injection (ldap)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_ldap_probe_ledger_vulnerable_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"ldap-vuln-{carrier}"
    url = f"{slice4_server}/ldap/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "ldap", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "ldap"

    recorded = rows(engine.request_logger)
    assert len(recorded) > 0

    ldap_records = [r for r in recorded if r.get("check") == "ldap" and r.get("wave") == "standard"]
    assert len(ldap_records) > 0

    requests = [r for r in ldap_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in ldap_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in ldap_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")
    assert matched.get("decision_rule") == "ldap_payload_oracle"

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]

    assert not any(n.startswith("probe_ledger_incomplete:ldap") for n in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_ldap_probe_ledger_safe_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"ldap-safe-{carrier}"
    url = f"{slice4_server}/ldap/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "ldap", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    ldap_requests = [
        r for r in recorded
        if r.get("check") == "ldap" and r.get("wave") == "standard" and r.get("record_kind") == "request" and r.get("role") == "attack"
    ]
    ldap_decisions = [
        r for r in recorded
        if r.get("check") == "ldap" and r.get("wave") == "standard" and r.get("record_kind") == "decision" and r.get("role") == "attack"
    ]
    assert len(ldap_decisions) >= 1
    assert len(ldap_requests) == len(ldap_decisions)
    assert all(d.get("outcome") == "no_match" for d in ldap_decisions)
    assert all(d.get("payload_fingerprint") for d in ldap_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:ldap") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_ldap_probe_ledger_write_failure(tmp_path):
    engine = make_engine("http://example.com/test", "ldap", tmp_path)
    scanner = LDAPScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner.dispatch = AsyncMock(return_value=SimpleNamespace(source="benign", pair={"response": {"status": 200}}))

    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)
    engine.request_logger.probe_ledger._quarantined = True
    await scanner.scan_injection_point(ip, {"name": "q"})

    assert "probe_ledger_incomplete:ldap:standard:write_failed" in engine.wave_errors


@pytest.mark.asyncio
async def test_ldap_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "ldap", tmp_path)
    scanner = LDAPScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner.dispatch = AsyncMock(return_value=SimpleNamespace(source="benign", pair={"response": {"status": 200}}))
    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)

    await scanner.scan_injection_point(ip, {"name": "q"})
    assert "probe_ledger_incomplete:ldap:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Target 2: SSRF (ssrf)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_ssrf_probe_ledger_vulnerable_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"ssrf-vuln-{carrier}"
    url = f"{slice4_server}/ssrf/vulnerable/{carrier}" + ("?url=initial" if carrier == "query" else "")
    engine = make_engine(url, "ssrf", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "ssrf"

    recorded = rows(engine.request_logger)
    ssrf_records = [r for r in recorded if r.get("check") == "ssrf" and r.get("wave") == "standard"]
    assert len(ssrf_records) > 0

    requests = [r for r in ssrf_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in ssrf_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in ssrf_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")
    assert matched.get("decision_rule") == "ssrf_payload_oracle"

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]
    assert not any(n.startswith("probe_ledger_incomplete:ssrf") for n in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_ssrf_probe_ledger_safe_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"ssrf-safe-{carrier}"
    url = f"{slice4_server}/ssrf/safe/{carrier}" + ("?url=initial" if carrier == "query" else "")
    engine = make_engine(url, "ssrf", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    ssrf_requests = [
        r for r in recorded
        if r.get("check") == "ssrf" and r.get("wave") == "standard" and r.get("record_kind") == "request" and r.get("role") == "attack"
    ]
    ssrf_decisions = [
        r for r in recorded
        if r.get("check") == "ssrf" and r.get("wave") == "standard" and r.get("record_kind") == "decision" and r.get("role") == "attack"
    ]
    assert len(ssrf_decisions) >= 1
    assert len(ssrf_requests) == len(ssrf_decisions)
    assert all(d.get("outcome") == "no_match" for d in ssrf_decisions)
    assert all(d.get("payload_fingerprint") for d in ssrf_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:ssrf") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_ssrf_probe_ledger_write_failure(tmp_path):
    engine = make_engine("http://example.com/test", "ssrf", tmp_path)
    scanner = SSRFScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("benign", {"response": {"status": 200}}))
    ip = InjectionPoint.for_form("http://example.com/test", "url", 0)

    engine.request_logger.probe_ledger._quarantined = True
    await scanner.scan_injection_point(ip, {"name": "url"})
    assert "probe_ledger_incomplete:ssrf:standard:write_failed" in engine.wave_errors


@pytest.mark.asyncio
async def test_ssrf_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "ssrf", tmp_path)
    scanner = SSRFScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("benign", {"response": {"status": 200}}))
    ip = InjectionPoint.for_form("http://example.com/test", "url", 0)

    await scanner.scan_injection_point(ip, {"name": "url"})
    assert "probe_ledger_incomplete:ssrf:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Target 3: Header Injection (header_injection)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_header_injection_probe_ledger_vulnerable_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"hi-vuln-{carrier}"
    url = f"{slice4_server}/header_injection/vulnerable/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "header_injection", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "header_injection"

    recorded = rows(engine.request_logger)
    hi_records = [r for r in recorded if r.get("check") == "header_injection" and r.get("wave") == "standard"]
    assert len(hi_records) > 0

    requests = [r for r in hi_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in hi_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in hi_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")
    assert matched.get("decision_rule") == "header_injection_oracle"

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]
    if carrier == "query":
        assert not any(n.startswith("probe_ledger_incomplete:header_injection") for n in engine.wave_errors)
    else:
        assert any(d.get("outcome") == "unexecutable" for d in decisions)
        assert "probe_ledger_incomplete:header_injection:standard:count_mismatch" in engine.wave_errors


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_header_injection_probe_ledger_safe_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"hi-safe-{carrier}"
    url = f"{slice4_server}/header_injection/safe/{carrier}" + ("?q=initial" if carrier == "query" else "")
    engine = make_engine(url, "header_injection", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    hi_requests = [
        r for r in recorded
        if r.get("check") == "header_injection" and r.get("wave") == "standard" and r.get("record_kind") == "request" and r.get("role") == "attack"
    ]
    hi_decisions = [
        r for r in recorded
        if r.get("check") == "header_injection" and r.get("wave") == "standard" and r.get("record_kind") == "decision" and r.get("role") == "attack"
    ]
    assert len(hi_decisions) >= 1
    assert all(d.get("payload_fingerprint") for d in hi_decisions)
    if carrier == "query":
        assert len(hi_requests) == len(hi_decisions)
        assert all(d.get("outcome") == "no_match" for d in hi_decisions)
        assert not any(n.startswith("probe_ledger_incomplete:header_injection") for n in engine.wave_errors)
    else:
        no_match_decisions = [d for d in hi_decisions if d.get("outcome") == "no_match"]
        unexec_decisions = [d for d in hi_decisions if d.get("outcome") == "unexecutable"]
        assert len(no_match_decisions) == len(hi_requests) == 3
        assert len(unexec_decisions) == 3
        assert "probe_ledger_incomplete:header_injection:standard:count_mismatch" in engine.wave_errors


@pytest.mark.asyncio
async def test_header_injection_json_probe_ledger_vulnerable_and_safe(tmp_path, slice4_server):
    for kind in ("vulnerable", "safe"):
        output = tmp_path / f"hi-json-{kind}"
        url = f"{slice4_server}/header_injection/{kind}/json"
        engine = make_engine(url, "header_injection", output, timeout=2)
        scanner = HeaderInjectionScanner(engine)
        ip = InjectionPoint.for_json_body("POST", url, "/q", template_id="fixture")
        engine.injection_templates["fixture"] = dict(url=url, method="POST", json_body={"q": "original"})
        findings = await scanner.scan_injection_point(ip, {"name": "/q"})

        recorded = rows(engine.request_logger)
        hi_requests = [
            r for r in recorded
            if r.get("check") == "header_injection" and r.get("wave") == "standard" and r.get("record_kind") == "request" and r.get("role") == "attack"
        ]
        hi_decisions = [
            r for r in recorded
            if r.get("check") == "header_injection" and r.get("wave") == "standard" and r.get("record_kind") == "decision" and r.get("role") == "attack"
        ]
        assert len(hi_requests) == len(hi_decisions) >= 1
        assert not any(n.startswith("probe_ledger_incomplete:header_injection") for n in engine.wave_errors)
        if kind == "vulnerable":
            assert len(findings) == 1
            assert any(d.get("outcome") == "matched" for d in hi_decisions)
        else:
            assert len(findings) == 0
            assert all(d.get("outcome") == "no_match" for d in hi_decisions)


@pytest.mark.asyncio
async def test_header_injection_probe_ledger_write_failure(tmp_path):
    engine = make_engine("http://example.com/test", "header_injection", tmp_path)
    scanner = HeaderInjectionScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("benign", {"response": {"status": 200, "headers": {}}}))
    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)

    engine.request_logger.probe_ledger._quarantined = True
    await scanner.scan_injection_point(ip, {"name": "q"})
    assert "probe_ledger_incomplete:header_injection:standard:write_failed" in engine.wave_errors


@pytest.mark.asyncio
async def test_header_injection_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "header_injection", tmp_path)
    scanner = HeaderInjectionScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("benign", {"response": {"status": 200, "headers": {}}}))
    ip = InjectionPoint.for_form("http://example.com/test", "q", 0)

    await scanner.scan_injection_point(ip, {"name": "q"})
    assert "probe_ledger_incomplete:header_injection:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Target 4: Open Redirect (open_redirect)
# ==============================================================================

@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_open_redirect_probe_ledger_vulnerable_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"or-vuln-{carrier}"
    url = f"{slice4_server}/open_redirect/vulnerable/{carrier}" + ("?url=initial" if carrier == "query" else "")
    engine = make_engine(url, "open_redirect", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) >= 1
    finding = engine.all_findings[0]
    assert finding.check_type == "open_redirect"

    recorded = rows(engine.request_logger)
    or_records = [r for r in recorded if r.get("check") == "open_redirect" and r.get("wave") == "standard"]
    assert len(or_records) > 0

    requests = [r for r in or_records if r.get("record_kind") == "request" and r.get("role") == "attack"]
    observations = [r for r in or_records if r.get("record_kind") == "observation" and r.get("role") == "attack"]
    decisions = [r for r in or_records if r.get("record_kind") == "decision" and r.get("role") == "attack"]

    assert len(requests) >= 1
    assert len(observations) >= 1
    assert len(decisions) >= 1

    matched = next((d for d in decisions if d.get("outcome") == "matched"), None)
    assert matched is not None
    assert matched.get("payload_fingerprint")
    assert matched.get("decision_rule") == "open_redirect_oracle"

    correlated = next(r for r in requests if r["attempt_id"] == matched["request_attempt_id"])
    assert correlated["payload_fingerprint"] == matched["payload_fingerprint"]
    if carrier == "form":
        assert not any(n.startswith("probe_ledger_incomplete:open_redirect") for n in engine.wave_errors)
    else:
        assert "probe_ledger_incomplete:open_redirect:standard:count_mismatch" in engine.wave_errors


@pytest.mark.asyncio
@pytest.mark.parametrize("carrier", ["form", "query"])
async def test_open_redirect_probe_ledger_safe_twin(tmp_path, slice4_server, carrier):
    output = tmp_path / f"or-safe-{carrier}"
    url = f"{slice4_server}/open_redirect/safe/{carrier}" + ("?url=initial" if carrier == "query" else "")
    engine = make_engine(url, "open_redirect", output, timeout=2)
    await asyncio.wait_for(engine.run(), timeout=60)

    assert len(engine.all_findings) == 0
    recorded = rows(engine.request_logger)
    or_requests = [
        r for r in recorded
        if r.get("check") == "open_redirect" and r.get("wave") == "standard" and r.get("record_kind") == "request" and r.get("role") == "attack"
    ]
    or_decisions = [
        r for r in recorded
        if r.get("check") == "open_redirect" and r.get("wave") == "standard" and r.get("record_kind") == "decision" and r.get("role") == "attack"
    ]
    assert len(or_decisions) >= 1
    assert len(or_requests) == len(or_decisions)
    assert all(d.get("outcome") == "no_match" for d in or_decisions)
    assert all(d.get("payload_fingerprint") for d in or_decisions)
    assert not any(n.startswith("probe_ledger_incomplete:open_redirect") for n in engine.wave_errors)


@pytest.mark.asyncio
async def test_open_redirect_probe_ledger_write_failure(tmp_path):
    engine = make_engine("http://example.com/test", "open_redirect", tmp_path)
    engine._browser = SimpleNamespace(page=SimpleNamespace(url="http://example.com/test"))
    scanner = OpenRedirectScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("benign", {"response": {"status": 200, "headers": {}}}))
    ip = InjectionPoint.for_form("http://example.com/test", "url", 0)

    engine.request_logger.probe_ledger._quarantined = True
    await scanner.scan_injection_point(ip, {"name": "url"})
    assert "probe_ledger_incomplete:open_redirect:standard:write_failed" in engine.wave_errors


@pytest.mark.asyncio
async def test_open_redirect_probe_ledger_count_mismatch(tmp_path):
    engine = make_engine("http://example.com/test", "open_redirect", tmp_path)
    engine._browser = SimpleNamespace(page=SimpleNamespace(url="http://example.com/test"))
    scanner = OpenRedirectScanner(engine)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("benign", {"response": {"status": 200, "headers": {}}}))
    ip = InjectionPoint.for_form("http://example.com/test", "url", 0)

    await scanner.scan_injection_point(ip, {"name": "url"})
    assert "probe_ledger_incomplete:open_redirect:standard:count_mismatch" in engine.wave_errors


# ==============================================================================
# Cross-cutting: Privacy & Redaction, JSONL Compatibility
# ==============================================================================

def test_slice4_probe_ledger_redaction_secrets_not_persisted(tmp_path):
    """Sensitive headers and values are never persisted in probe_attempts.jsonl for slice 4 checks."""
    logger = RequestLogger(tmp_path)
    secret_cookie = "secret_session_slice4_tok"
    secret_auth = "Bearer slice4_secret_api_token"

    for check in ["ldap", "ssrf", "header_injection", "open_redirect"]:
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
                    "url": f"http://example.com/{check}?token=confidential_slice4_param",
                    "headers": {
                        "Cookie": f"session={secret_cookie}",
                        "Authorization": secret_auth,
                    },
                    "post_data": "url=test&password=very_secret_slice4_password",
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
    assert "confidential_slice4_param" not in content
    assert "very_secret_slice4_password" not in content
    assert "<redacted>" in content


def test_slice4_probe_ledger_existing_jsonl_compatibility(tmp_path):
    """payloads.jsonl and http_requests.jsonl retain their format and are unaffected by slice 4 records."""
    logger = RequestLogger(tmp_path)
    logger.log_http({
        "request": {
            "method": "GET",
            "url": "http://example.com/ldap?q=admin",
            "headers": {"Host": "example.com"},
            "timestamp": 1700000000.0,
        },
        "response": {"status": 200, "headers": {"Content-Type": "text/html"}},
    })
    logger.log_payload("q", "*)(cn=*))(|(cn=*", "ldap", "http://example.com/ldap", payload_fingerprint="fp_ldap_comp")

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
