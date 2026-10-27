"""Tests for probe evidence wiring in CachePoisoningScanner."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan.probe_recorder import MANIFEST_FILENAME
from wscan.request_logger import RequestLogger
from wscan.scanners.cache_poisoning import CachePoisoningScanner, UNKEYED_HEADERS

URL = "http://target.test/app/profile?tab=info"
CHECK = "cache_poisoning"


class FakeEndpoint:
    def __init__(self, handler):
        self.handler = handler
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        return self.handler(request)


def setup_scanner(tmp_path, monkeypatch, endpoint_handler, *, logging=True):
    logger = None if logging is None else RequestLogger(tmp_path, enabled=logging)
    engine = SimpleNamespace(
        request_logger=logger,
        browser=SimpleNamespace(screenshot_b64=AsyncMock(return_value="")),
        monitor=None,
        payload_gen=None,
        timeout=5,
        proxy=None,
        wave_errors=[],
        all_findings=[],
        _finding_dedup=set(),
        auth_headers=lambda extra=None, **kw: {"Authorization": "Bearer secret-token", **(extra or {})},
    )
    scanner = CachePoisoningScanner(engine)
    options = []
    original_client = httpx.AsyncClient

    def client_factory(**kwargs):
        options.append(dict(kwargs))
        return original_client(**kwargs, transport=httpx.MockTransport(endpoint_handler))

    monkeypatch.setattr("wscan.scanners.cache_poisoning.httpx.AsyncClient", client_factory)
    return scanner, logger, options


def load_ledger_rows(logger, tmp_path):
    assert logger.probe_ledger.write_manifest()
    path = logger.probe_ledger.path
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    restored = RequestLogger(tmp_path).probe_ledger
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    return rows, restored, manifest


def sends(rows):
    return [r for r in rows if r["record_kind"] == "request"]


def observations(rows):
    return [r for r in rows if r["record_kind"] == "observation"]


def decisions(rows):
    return [r for r in rows if r["record_kind"] == "decision"]


@pytest.mark.asyncio
async def test_poisoning_attack_and_verify_evidence(tmp_path, monkeypatch):
    """(a) request hook wires submission, (b) 1:1 sends/observations, (c) attack->verify roles and decisions."""
    marker_used = None

    def handler(request):
        nonlocal marker_used
        header = UNKEYED_HEADERS[0]
        val = request.headers.get(header.lower())
        if val:
            marker_used = val
            return httpx.Response(
                200,
                text=f"Hello from {val}",
                headers={"Cache-Control": "public, max-age=300", "Content-Type": "text/html"},
            )
        else:
            return httpx.Response(
                200,
                text=f"Hello from {marker_used}",  # clean verify observes persisted marker
                headers={"CF-Cache-Status": "HIT", "Content-Type": "text/html"},
            )

    endpoint = FakeEndpoint(handler)
    scanner, logger, options = setup_scanner(tmp_path, monkeypatch, endpoint)

    findings = await scanner._scan_poisoning(URL)
    assert len(findings) == 1
    assert findings[0].confidence == "confirmed"

    # Options must have request hook
    assert any("event_hooks" in opt and "request" in opt["event_hooks"] for opt in options)

    rows, restored, manifest = load_ledger_rows(logger, tmp_path)
    req_rows = sends(rows)
    obs_rows = observations(rows)
    dec_rows = decisions(rows)

    # 1:1 sends to observations - NO double observation
    assert len(req_rows) == 2
    assert len(obs_rows) == 2
    assert len(dec_rows) == 2

    attack_req, verify_req = req_rows
    attack_obs, verify_obs = obs_rows
    attack_dec, verify_dec = dec_rows

    assert attack_req["role"] == "attack"
    assert verify_req["role"] == "verify"
    assert verify_req["baseline_attempt_ids"] == [attack_req["attempt_id"]]

    assert attack_obs["parent_id"] == attack_req["attempt_id"]
    assert verify_obs["parent_id"] == verify_req["attempt_id"]

    assert attack_dec["outcome"] == "matched"
    assert attack_dec["decision_rule"] == "cache_poisoning_reflection"
    assert attack_dec["parent_id"] == attack_obs["attempt_id"]

    assert verify_dec["outcome"] == "matched"
    assert verify_dec["decision_rule"] == "cache_poisoning_persistence"
    assert verify_dec["parent_id"] == verify_obs["attempt_id"]


@pytest.mark.asyncio
async def test_poisoning_no_match_records_evidence(tmp_path, monkeypatch):
    """When header does not reflect or response is uncacheable, attack records no_match."""
    def handler(request):
        return httpx.Response(200, text="clean body", headers={"Cache-Control": "no-store"})

    endpoint = FakeEndpoint(handler)
    scanner, logger, _ = setup_scanner(tmp_path, monkeypatch, endpoint)

    findings = await scanner._scan_poisoning(URL)
    assert len(findings) == 0

    rows, restored, manifest = load_ledger_rows(logger, tmp_path)
    req_rows = sends(rows)
    obs_rows = observations(rows)
    dec_rows = decisions(rows)

    assert len(req_rows) == len(obs_rows) == len(dec_rows)
    for dec in dec_rows:
        assert dec["outcome"] == "no_match"
        assert dec["decision_rule"] == "cache_poisoning_reflection"


@pytest.mark.asyncio
async def test_deception_baseline_and_attack_evidence(tmp_path, monkeypatch):
    """Cache deception records baseline (without detector decision) followed by attack."""
    dynamic_content = "secret dynamic dashboard content " * 10

    def handler(request):
        url_str = str(request.url)
        if url_str.endswith(".css") or ".css?" in url_str:
            return httpx.Response(
                200,
                text=dynamic_content,
                headers={"Cache-Control": "public, max-age=600", "Content-Type": "text/css"},
            )
        return httpx.Response(
            200,
            text=dynamic_content,
            headers={"Cache-Control": "no-store", "Content-Type": "text/html"},
        )

    endpoint = FakeEndpoint(handler)
    scanner, logger, _ = setup_scanner(tmp_path, monkeypatch, endpoint)

    findings = await scanner._scan_deception(URL)
    assert len(findings) == 1
    assert findings[0].evidence_type == "cache_deception"

    rows, restored, manifest = load_ledger_rows(logger, tmp_path)
    req_rows = sends(rows)
    obs_rows = observations(rows)
    dec_rows = decisions(rows)

    # 1 baseline request/obs, 1 attack request/obs/decision
    assert len(req_rows) == 2
    assert len(obs_rows) == 2
    assert len(dec_rows) == 1  # baseline terminates at observation

    base_req, attack_req = req_rows
    base_obs, attack_obs = obs_rows
    attack_dec = dec_rows[0]

    assert base_req["role"] == "baseline"
    assert attack_req["role"] == "attack"
    assert attack_req["baseline_attempt_ids"] == [base_req["attempt_id"]]

    assert base_obs["outcome"] is None
    assert base_obs["decision_rule"] == "cache_deception_baseline"
    assert "comparison measurement only" in base_obs["rationale"]

    assert attack_dec["outcome"] == "matched"
    assert attack_dec["decision_rule"] == "cache_deception_match"
    assert attack_dec["parent_id"] == attack_obs["attempt_id"]


@pytest.mark.asyncio
async def test_evidence_gap_on_transport_failure(tmp_path, monkeypatch):
    """(d) Transport/timeout failure in _evidence_scope records note_gap and does not leak exception."""
    def handler(request):
        raise httpx.ConnectError("Connection refused", request=request)

    endpoint = FakeEndpoint(handler)
    scanner, logger, _ = setup_scanner(tmp_path, monkeypatch, endpoint)

    # Neither poisoning nor deception should leak exception outside
    findings_p = await scanner._scan_poisoning(URL)
    assert findings_p == []

    findings_d = await scanner._scan_deception(URL)
    assert findings_d == []

    rows, restored, manifest = load_ledger_rows(logger, tmp_path)
    dec_rows = decisions(rows)
    assert any("transport_error" in dec["outcome"] for dec in dec_rows)


@pytest.mark.asyncio
async def test_evidence_gap_on_extension_mismatch(tmp_path, monkeypatch):
    """(d) Response extension mismatch triggers note_gap cleanly."""
    def handler(request):
        # Strip extension to simulate an untracked request or middleware drop
        request.extensions.clear()
        return httpx.Response(200, text="body")

    endpoint = FakeEndpoint(handler)
    scanner, logger, _ = setup_scanner(tmp_path, monkeypatch, endpoint)

    await scanner._scan_poisoning(URL)
    assert logger.probe_ledger.write_manifest()
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    write_errors = manifest.get("write_errors", [])
    assert any(err.get("error") == "cache_poisoning_request_missing" for err in write_errors)
    assert "cache_poisoning_request_missing" in scanner.engine.wave_errors


@pytest.mark.asyncio
async def test_disabled_logger_operates_without_error(tmp_path, monkeypatch):
    """(e) logger disabled/None operates normally without exception."""
    def handler(request):
        return httpx.Response(200, text="clean body", headers={"Cache-Control": "no-store"})

    endpoint = FakeEndpoint(handler)
    scanner, logger, options = setup_scanner(tmp_path, monkeypatch, endpoint, logging=False)

    findings = await scanner.scan_page(URL)
    assert findings == []
    # No event_hooks in options when logger is disabled
    assert all("event_hooks" not in opt for opt in options)
