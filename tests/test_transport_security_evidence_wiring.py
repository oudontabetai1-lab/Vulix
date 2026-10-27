"""Persisted HTTPX method evidence for the page-level transport scanner."""
import json
from types import SimpleNamespace

import httpx
import pytest

from wscan.probe_recorder import MANIFEST_FILENAME
from wscan.request_logger import RequestLogger
from wscan.scanners.base import PageDocumentUnavailable
from wscan.scanners.transport_security import TransportSecurityScanner


URL = "http://user:pass@target.test/private?access_token=query-secret"


class MethodFixture:
    def __init__(self, *, vulnerable=False, failure=None):
        self.vulnerable, self.failure, self.requests = vulnerable, failure, []

    def __call__(self, request):
        self.requests.append(request)
        if self.failure and request.method == self.failure[0]:
            raise self.failure[1]("private-exception-secret", request=request)
        missing = request.url.path.startswith("/wscan-missing-")
        if missing:
            return httpx.Response(404, request=request)
        if request.method == "GET":
            if any(request.headers.get(name, "") == "OPTIONS" for name in (
                    "x-http-method-override", "x-method-override", "x-http-method")):
                return (httpx.Response(204, headers={"allow": "GET, OPTIONS"}, request=request)
                        if self.vulnerable else httpx.Response(200, content=b"page", request=request))
            return httpx.Response(200, content=b"page", request=request)
        if request.method == "OPTIONS":
            return httpx.Response(204, headers={"allow": "GET, OPTIONS"}, request=request)
        if request.method == "TRACE" and self.vulnerable:
            token = request.headers["x-xst-probe"]
            return httpx.Response(200, content=token.encode(), headers={"set-cookie": "sid=response-secret"}, request=request)
        if request.method == "TRACE":
            return httpx.Response(405, request=request)
        return httpx.Response(405, request=request)


def setup(tmp_path, monkeypatch, fixture, *, logging=True, hook=None):
    logger = None if logging is None else RequestLogger(tmp_path, enabled=logging)

    def client_kwargs(**kwargs):
        # Mirror ScanEngine.httpx_client_kwargs: both submission and response hooks.
        hooks = {"request": [hook]} if hook else {}
        if logger is not None:
            hooks["request"] = [*hooks.get("request", []), logger.log_httpx_submission]
            hooks["response"] = [logger.log_httpx_response]
        return {**kwargs, "event_hooks": hooks}

    engine = SimpleNamespace(
        request_logger=logger, browser=SimpleNamespace(network=SimpleNamespace(pairs=[])), monitor=None,
        payload_gen=None, timeout=1, proxy="", wave_errors=[], all_findings=[], _finding_dedup=set(),
        _is_access_allowed_url=lambda url: httpx.URL(url).host == "target.test",
        _is_url_excluded=lambda url: False,
        httpx_client_kwargs=client_kwargs,
    )
    scanner = TransportSecurityScanner(engine)
    original = httpx.AsyncClient
    options = []

    def client(**kwargs):
        options.append(dict(kwargs))
        return original(**kwargs, transport=httpx.MockTransport(fixture))

    monkeypatch.setattr("wscan.scanners.transport_security.httpx.AsyncClient", client)
    return engine, scanner, logger, options


def ledger_rows(logger):
    path = logger.probe_ledger.path
    return [json.loads(line) for line in path.read_text().splitlines()]


@pytest.mark.asyncio
async def test_vulnerable_methods_record_one_causal_chain_per_send_and_reload(tmp_path, monkeypatch):
    fixture, hook_calls = MethodFixture(vulnerable=True), []

    async def existing_hook(request):
        hook_calls.append(request.method)

    _, scanner, logger, options = setup(tmp_path, monkeypatch, fixture, hook=existing_hook)
    findings = await scanner.scan_page(URL)
    assert [finding.evidence_type for finding in findings] == ["http_without_https_upgrade", "http_trace_xst", "http_method_override",
        "http_method_override", "http_method_override"]
    assert len(fixture.requests) == len(hook_calls) == logger.payload_count
    assert all(options_row["event_hooks"]["request"][0] is existing_hook for options_row in options)
    assert all(len(options_row["event_hooks"]["request"]) == 2 for options_row in options)
    assert [i for i, request in enumerate(fixture.requests) if "cookie" in request.headers] == list(range(5, 16))

    logger.probe_ledger.write_manifest()
    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]
    decisions = [row for row in records if row["record_kind"] == "decision"]
    assert len(requests) == len(observations) == len(fixture.requests)
    assert len(decisions) == 6
    assert [row["request"]["method"] for row in requests] == [request.method for request in fixture.requests]
    assert {row["role"] for row in requests} == {"baseline", "control", "attack"}
    assert {row["outcome"] for row in decisions} == {"matched", "no_match"}
    assert all(row["decision_rule"] in {"http_trace_xst", "http_connect_capability",
                                        "http_webdav_enabled", "http_method_override"} for row in decisions)
    by_attempt = {row["attempt_id"]: row for row in requests}
    by_observation = {row["request_attempt_id"]: row for row in observations}
    for request, physical in zip(requests, fixture.requests):
        observation = by_observation[request["attempt_id"]]
        assert observation["parent_id"] == request["attempt_id"]
        expected_status = (404 if physical.url.path.startswith("/wscan-missing-") else
                           204 if fixture.vulnerable and physical.method == "GET" and any(physical.headers.get(name) == "OPTIONS" for name in (
                               "x-http-method-override", "x-method-override", "x-http-method")) else
                           200 if physical.method == "GET" else
                           204 if physical.method == "OPTIONS" else
                           200 if physical.method == "TRACE" and fixture.vulnerable else 405)
        assert observation["response"]["status"] == expected_status
        assert request["request"]["transport"] == "httpx"
        assert not physical.url.username and not physical.url.password
        assert physical.url.params["access_token"] == "query-secret"
        assert "authorization" not in physical.headers
    for decision in decisions:
        assert decision["parent_id"] in {row["attempt_id"] for row in observations}
        assert decision["request_attempt_id"] in by_attempt
        assert decision["baseline_attempt_ids"] and decision["control_attempt_ids"]
        assert all(ref in by_attempt for ref in (*decision["baseline_attempt_ids"], *decision["control_attempt_ids"]))
    assert all(row["outcome"] is None for row in observations if by_attempt[row["request_attempt_id"]]["role"] in {"baseline", "control"})

    restored = RequestLogger(tmp_path)
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert set(restored.probe_ledger.events) == {row["attempt_id"] for row in records}
    assert manifest["logical_requests"] == len(requests)
    assert manifest["evidence_incomplete"] is False
    persisted = logger.probe_ledger.path.read_text() + (tmp_path / MANIFEST_FILENAME).read_text()
    for path in (logger.http_path, logger.payload_path):
        if path.exists():
            persisted += path.read_text()
    for secret in ("user:pass", "query-secret", "response-secret", "private-exception-secret"):
        assert secret not in persisted
    for finding in findings:
        serialized = json.dumps(finding.to_dict())
        assert all(secret not in serialized for secret in ("user:pass", "query-secret", "response-secret"))


@pytest.mark.asyncio
async def test_safe_method_fixture_only_records_classifier_no_matches(tmp_path, monkeypatch):
    fixture = MethodFixture(vulnerable=False)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)
    findings = await scanner.scan_page(URL)
    assert [finding.evidence_type for finding in findings] == ["http_without_https_upgrade"]
    decisions = [row for row in ledger_rows(logger) if row["record_kind"] == "decision"]
    assert len(decisions) == 6
    assert all(row["outcome"] == "no_match" for row in decisions)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,outcome", [(httpx.ReadTimeout, "timeout"),
                                               (httpx.ConnectError, "transport_error")])
async def test_method_transport_failures_have_typed_decisions_without_response(tmp_path, monkeypatch, failure, outcome):
    fixture = MethodFixture(failure=("TRACE", failure))
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)
    with pytest.raises(PageDocumentUnavailable):
        await scanner.scan_page(URL)
    records = ledger_rows(logger)
    failed = next(row for row in records if row["record_kind"] == "request" and row["request"]["method"] == "TRACE")
    decision = next(row for row in records if row["record_kind"] == "decision" and row["request_attempt_id"] == failed["attempt_id"])
    assert decision["outcome"] == outcome
    assert decision["response"] is None
    assert not any((row.get("response") or {}).get("status") == 0 for row in records)
    assert "private-exception-secret" not in logger.probe_ledger.path.read_text()


@pytest.mark.asyncio
@pytest.mark.parametrize("logging", [None, False])
async def test_unavailable_logger_does_not_change_detection(tmp_path, monkeypatch, logging):
    fixture = MethodFixture(vulnerable=True)
    engine, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture, logging=logging)
    findings = await scanner.scan_page(URL)
    assert [finding.evidence_type for finding in findings] == ["http_without_https_upgrade", "http_trace_xst", "http_method_override",
        "http_method_override", "http_method_override"]
    assert len(fixture.requests) == 16
    assert "transport_security_evidence_unavailable" in engine.wave_errors
    if logger:
        assert logger.probe_ledger.evidence_incomplete


@pytest.mark.asyncio
async def test_ledger_write_failure_preserves_findings_and_marks_manifest_incomplete(tmp_path, monkeypatch):
    fixture = MethodFixture(vulnerable=True)
    engine, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)
    logger.probe_ledger.append = lambda record: (_ for _ in ()).throw(RuntimeError("logger-private-secret"))
    findings = await scanner.scan_page(URL)
    assert [finding.evidence_type for finding in findings] == ["http_without_https_upgrade", "http_trace_xst",
        "http_method_override", "http_method_override", "http_method_override"]
    assert len(fixture.requests) == 16
    assert logger.probe_ledger.evidence_incomplete
    assert "logger-private-secret" not in str(logger.probe_ledger.manifest.to_dict())
    logger.probe_ledger.write_manifest()
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert manifest["evidence_incomplete"] is True
    assert any("probe_observation_error:RuntimeError" == row["error"] for row in manifest["write_errors"])
