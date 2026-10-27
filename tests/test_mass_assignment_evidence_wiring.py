import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan.request_logger import RequestLogger
from wscan.scanners.mass_assignment import MassAssignmentScanner


URL = "http://user:pass@target.test/api?access_token=query-secret"


def setup(tmp_path, monkeypatch, handler, *, logging=True):
    tmp_path.mkdir(parents=True, exist_ok=True)
    logger = None if logging is None else RequestLogger(tmp_path, enabled=logging)
    engine = SimpleNamespace(request_logger=logger, browser=SimpleNamespace(screenshot_b64=AsyncMock(return_value="")),
        monitor=None, payload_gen=None, timeout=2, proxy="", wave_errors=[], all_findings=[],
        _finding_dedup=set(), login_url="", logged_in_marker="",
        auth_headers=lambda *_args, **_kwargs: {"Authorization": "Bearer auth-secret", "Cookie": "sid=cookie-secret"},
        httpx_client_kwargs=lambda **kw: kw)
    scanner = MassAssignmentScanner(engine)
    scanner.log_payload_test = _noop
    physical = []
    original = httpx.AsyncClient

    def client(**kwargs):
        async def send(request):
            physical.append(request)
            return handler(request, len(physical))
        return original(**kwargs, transport=httpx.MockTransport(send))

    monkeypatch.setattr("wscan.scanners.mass_assignment.httpx.AsyncClient", client)
    template = SimpleNamespace(url=URL, method="POST", json_body={"name": "new"},
                               content_type="application/json", headers={"X-Tenant": "tenant"})
    return scanner, engine, logger, physical, template


async def _noop(*args, **kwargs):
    return None


def rows(logger):
    path = logger.probe_ledger._path
    return [json.loads(line) for line in path.read_text().splitlines()] if path and path.exists() else []


@pytest.mark.asyncio
async def test_vulnerable_pair_records_baseline_attack_and_decision(tmp_path, monkeypatch):
    def handler(request, index):
        body = request.content.decode()
        payload = json.loads(body)
        assert request.method == "POST" and str(request.url) == URL
        assert request.headers["X-Tenant"] == "tenant"
        return httpx.Response(200, json=payload if index == 1 else {**payload, "role": payload["role"]}, request=request)

    scanner, _, logger, physical, template = setup(tmp_path, monkeypatch, handler)
    finding = await scanner._test_template(template)
    assert len(physical) == 2 and finding is not None
    assert json.loads(physical[0].content) == {"name": "new"}
    assert "role" not in json.loads(physical[0].content)
    assert "role" in json.loads(physical[1].content)
    records = rows(logger)
    requests = [r for r in records if r["record_kind"] == "request" and r.get("check") == "mass_assignment"]
    observations = [r for r in records if r["record_kind"] == "observation" and r.get("check") == "mass_assignment"]
    decisions = [r for r in records if r["record_kind"] == "decision" and r.get("check") == "mass_assignment"]
    assert len(requests) == 2 and len(observations) == 2 and len(decisions) == 1
    assert requests[0]["role"] == "baseline" and requests[1]["role"] == "attack"
    assert observations[0]["request_attempt_id"] == requests[0]["attempt_id"]
    assert observations[1]["request_attempt_id"] == requests[1]["attempt_id"]
    assert requests[1]["baseline_attempt_ids"] == [requests[0]["attempt_id"]]
    assert decisions[-1]["parent_id"] == observations[1]["attempt_id"]
    assert decisions[-1]["request_attempt_id"] == requests[1]["attempt_id"]
    assert decisions[-1]["outcome"] == "matched"


@pytest.mark.asyncio
async def test_safe_and_non_2xx_are_no_match(tmp_path, monkeypatch):
    for case_index, (status, body) in enumerate(((200, {"ok": True}), (422, {"role": "echoed"}))):
        scanner, _, logger, _, template = setup(tmp_path / str(status), monkeypatch,
            lambda req, _i: httpx.Response(status, json=body, request=req))
        assert await scanner._test_template(template) is None
        decision = [r for r in rows(logger) if r["record_kind"] == "decision"]
        if case_index == 0:
            assert decision and decision[-1]["outcome"] == "no_match"
        else:
            assert not decision


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,outcome", [(httpx.ReadTimeout, "timeout"), (httpx.ConnectError, "transport_error")])
@pytest.mark.parametrize("failed_index", [1, 2])
async def test_transport_failure_has_no_fabricated_response(tmp_path, monkeypatch, failure, outcome, failed_index):
    def handler(request, index):
        if index == failed_index:
            raise failure("failed", request=request)
        return httpx.Response(200, json={"ok": True}, request=request)
    scanner, _, logger, _, template = setup(tmp_path, monkeypatch, handler)
    assert await scanner._test_template(template) is None
    records = rows(logger)
    decisions = [r for r in records if r["record_kind"] == "decision"]
    assert decisions[-1]["outcome"] == outcome and decisions[-1].get("response") is None
    assert not any((r.get("response") or {}).get("status") == 0 for r in records)


@pytest.mark.asyncio
@pytest.mark.parametrize("logging", [None, False])
async def test_logger_absent_or_disabled_preserves_finding(tmp_path, monkeypatch, logging):
    def handler(request, index):
        body = json.loads(request.content)
        return httpx.Response(200, json=body if index == 1 else {**body, "role": body["role"]}, request=request)
    scanner, engine, logger, physical, template = setup(tmp_path, monkeypatch, handler, logging=logging)
    finding = await scanner._test_template(template)
    assert finding is not None and len(physical) == 2
    if logger:
        assert logger.probe_ledger.evidence_incomplete


@pytest.mark.asyncio
async def test_wire_keeps_secrets_but_finding_and_probe_records_redact(tmp_path, monkeypatch):
    def handler(request, index):
        body = json.loads(request.content)
        if index == 2:
            body["role"] = body["role"]
        return httpx.Response(200, json=body, headers={"X-Note": "email=private@example.test", "Set-Cookie": "sid=response-secret"}, request=request)
    scanner, _, logger, physical, template = setup(tmp_path, monkeypatch, handler)
    finding = await scanner._test_template(template)
    assert finding is not None
    wire = physical[1]
    assert wire.headers["Authorization"] == "Basic dXNlcjpwYXNz"
    assert wire.headers["Cookie"] == "sid=cookie-secret"
    assert wire.url.params["access_token"] == "query-secret"
    serialized = json.dumps(finding.to_dict()) + logger.probe_ledger._path.read_text()
    for secret in ("user:pass", "query-secret", "cookie-secret", "response-secret"):
        assert secret not in serialized
