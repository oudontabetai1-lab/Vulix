import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan.request_logger import RequestLogger
from wscan.scanners.file_upload import FileUploadScanner, _PROBE_FILES


URL = "http://user:pass@target.test/upload?access_token=query-secret"


def setup(tmp_path, monkeypatch, endpoint, *, logging=True):
    logger = None if logging is None else RequestLogger(tmp_path, enabled=logging)
    engine = SimpleNamespace(request_logger=logger, browser=SimpleNamespace(screenshot_b64=AsyncMock(return_value="")), monitor=None, payload_gen=None,
        timeout=2, proxy="", wave_errors=[], all_findings=[], _finding_dedup=set(),
        auth_headers=lambda *a, **kw: {"Authorization": "Bearer auth-secret", "Cookie": "sid=cookie-secret"},
        httpx_client_kwargs=lambda **kw: kw)
    scanner = FileUploadScanner(engine)
    monkeypatch.setattr(scanner, "_form_action_url", AsyncMock(return_value=URL))
    monkeypatch.setattr(scanner, "log_payload_test", AsyncMock())
    original = httpx.AsyncClient
    physical = []

    def client(**kwargs):
        async def send(request):
            physical.append(request)
            return endpoint(request)
        return original(**kwargs, transport=httpx.MockTransport(send))

    monkeypatch.setattr("wscan.scanners.file_upload.httpx.AsyncClient", client)
    return scanner, logger, physical


def rows(logger):
    path = logger.probe_ledger.path
    return [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []


@pytest.mark.asyncio
async def test_dangerous_upload_records_causal_evidence_and_preserves_wire(tmp_path, monkeypatch):
    scanner, logger, physical = setup(tmp_path, monkeypatch,
        lambda req: httpx.Response(200, content=b"upload success wscan-probe-1.0", headers={"set-cookie": "sid=response-secret"}, request=req))
    findings = await scanner.scan_field(URL, 0, {"name": "attachment", "type": "file"})
    assert len(findings) == 1
    finding = findings[0]
    request, = physical
    probe = _PROBE_FILES[0]
    assert request.content and probe.content in request.content and probe.filename.encode() in request.content
    assert request.headers["Authorization"] == "Basic dXNlcjpwYXNz"
    assert request.headers["Cookie"] == "sid=cookie-secret"
    assert request.url.params["access_token"] == "query-secret"
    records = rows(logger)
    sent = next(r for r in records if r["record_kind"] == "request")
    observed = next(r for r in records if r["record_kind"] == "observation")
    decision = next(r for r in records if r["record_kind"] == "decision")
    assert sent["request"]["transport"] == observed["request"]["transport"] == "httpx"
    assert observed["parent_id"] == observed["request_attempt_id"] == sent["attempt_id"]
    assert decision["parent_id"] == observed["attempt_id"] and decision["request_attempt_id"] == sent["attempt_id"]
    assert decision["outcome"] == "matched" and decision["decision_rule"] == "file_upload_executable"
    assert (finding.evidence_type, finding.severity, finding.confidence) == ("file_upload_executable", "critical", "likely")
    serialized = json.dumps(finding.to_dict()) + logger.probe_ledger.path.read_text()
    for secret in ("query-secret", "user:pass", "auth-secret", "cookie-secret", "response-secret"):
        assert secret not in serialized


@pytest.mark.asyncio
async def test_safe_response_is_observation_then_no_match(tmp_path, monkeypatch):
    scanner, logger, physical = setup(tmp_path, monkeypatch,
        lambda req: httpx.Response(200, content=b"nothing", request=req))
    assert await scanner.scan_field(URL, 0, {"name": "file", "type": "file"}) == []
    assert len(physical) == len(_PROBE_FILES)
    records = rows(logger)
    assert len([r for r in records if r["record_kind"] == "observation"]) == len(_PROBE_FILES)
    decisions = [r for r in records if r["record_kind"] == "decision"]
    assert len(decisions) == len(_PROBE_FILES) and all(r["outcome"] == "no_match" for r in decisions)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,outcome", [(httpx.ReadTimeout, "timeout"), (httpx.ConnectError, "transport_error"), (httpx.WriteError, "transport_error")])
async def test_transport_failures_continue_without_fabricated_response(tmp_path, monkeypatch, failure, outcome):
    calls = []
    def endpoint(req):
        calls.append(req)
        if len(calls) == 1:
            raise failure("private failure", request=req)
        return httpx.Response(200, content=b"safe", request=req)
    scanner, logger, physical = setup(tmp_path, monkeypatch, endpoint)
    assert await scanner.scan_field(URL, 0, {"name": "file", "type": "file"}) == []
    assert len(physical) == len(_PROBE_FILES)
    decisions = [r for r in rows(logger) if r["record_kind"] == "decision"]
    assert decisions[0]["outcome"] == outcome and decisions[0]["response"] is None
    assert not any((r.get("response") or {}).get("status") == 0 for r in rows(logger))


@pytest.mark.asyncio
@pytest.mark.parametrize("logging", [None, False])
async def test_unavailable_logger_keeps_detector_behavior(tmp_path, monkeypatch, logging):
    scanner, logger, physical = setup(tmp_path, monkeypatch,
        lambda req: httpx.Response(200, content=b"upload success wscan-probe-1.0", request=req), logging=logging)
    findings = await scanner.scan_field(URL, 0, {"name": "file", "type": "file"})
    assert len(findings) == 1 and findings[0].evidence_type == "file_upload_executable"
    assert len(physical) == 1
    if logger:
        assert logger.probe_ledger.evidence_incomplete


@pytest.mark.asyncio
async def test_verification_transport_failure_still_returns_none(tmp_path, monkeypatch):
    scanner, logger, physical = setup(tmp_path, monkeypatch,
        lambda req: (_ for _ in ()).throw(httpx.ConnectError("failure", request=req)))
    finding = SimpleNamespace(payload=_PROBE_FILES[0].filename, url=URL, field_name="file",
                              evidence_type="file_upload_executable")
    assert await scanner.verify_finding(finding) is None
    assert len(physical) == 1
    assert not rows(logger)
