"""Real HTTPX sends and persisted scanner evidence, including failure and replay."""
import builtins
import hashlib
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan.probe_recorder import MANIFEST_FILENAME
from wscan.request_logger import RequestLogger
from wscan.scanners.request_smuggling import RequestSmugglingScanner, _PROBE_DEFINITIONS, _probe_body

URL = "http://target.test/private?access_token=query-secret"
CHECK = "request_smuggling"


class Endpoint:
    def __init__(self, status=200, body=b"normal", failure=None, fail_method="POST"):
        self.status, self.body = status, body
        self.failure, self.fail_method = failure, fail_method
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        if self.failure and request.method == self.fail_method:
            raise self.failure("private-exception-secret", request=request)
        return httpx.Response(self.status if request.method == "POST" else 200,
            content=self.body, headers={"set-cookie": "sid=response-secret", "x-observed": "yes"})


def setup(tmp_path, monkeypatch, endpoint, *, logging=True):
    logger = None if logging is None else RequestLogger(tmp_path, enabled=logging)
    engine = SimpleNamespace(request_logger=logger,
        browser=SimpleNamespace(screenshot_b64=AsyncMock(return_value="")), monitor=None, payload_gen=None,
        timeout=2, proxy=None, wave_errors=[], all_findings=[], _finding_dedup=set(),
        auth_headers=lambda extra=None, **kw: {"Authorization": "Bearer header-secret", "Cookie": "sid=cookie-secret", **(extra or {})},
        tls_config=SimpleNamespace(httpx_options=lambda: pytest.fail("changed TLS options")))
    scanner = RequestSmugglingScanner(engine)
    original = httpx.AsyncClient
    options = []

    def client(**kwargs):
        options.append(dict(kwargs))
        return original(**kwargs, transport=httpx.MockTransport(endpoint))

    monkeypatch.setattr("wscan.scanners.request_smuggling.httpx.AsyncClient", client)
    return scanner, logger, options


async def run(scanner, logger, *, rule="request_smuggling_oracle"):
    if logger is None:
        return await scanner._probe_cl_te(URL)
    ledger = logger.probe_ledger
    unit = ledger.expect("private-page", CHECK, rules=(rule,))
    with ledger.unit_scope(unit):
        return await scanner._probe_cl_te(URL)


def reopened(logger, tmp_path):
    assert logger.probe_ledger.write_manifest()
    path = logger.probe_ledger.path
    rows = [json.loads(line) for line in path.read_text().splitlines()] if path.exists() else []
    restored = RequestLogger(tmp_path).probe_ledger
    assert list(restored.events.values()) == rows
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert manifest["logical_requests"] == len([r for r in rows if r["record_kind"] == "request"])
    return rows, restored, manifest


def sends(rows):
    return [r for r in rows if r["record_kind"] == "request"]


def observations(rows):
    return [r for r in rows if r["record_kind"] == "observation"]


@pytest.mark.asyncio
@pytest.mark.parametrize("status,body,positive", [(200, b"normal", False), (200, b"", False),
    (400, b"400 Bad Request: invalid chunk", True), (302, b"redirect body", False)])
async def test_baseline_attack_and_reopen(tmp_path, monkeypatch, status, body, positive):
    endpoint = Endpoint(status, body)
    scanner, logger, options = setup(tmp_path, monkeypatch, endpoint)
    findings = await run(scanner, logger,
        rule="request_smuggling_parser_error" if positive else "request_smuggling_oracle")
    assert bool(findings) == positive
    rows, restored, manifest = reopened(logger, tmp_path)
    assert len(rows) == 5  # baseline request/observation, attack request/observation/decision
    baseline, attack = sends(rows)
    base_obs, attack_obs = observations(rows)
    decision = rows[-1]
    assert [r.method for r in endpoint.requests] == ["GET", "POST"]
    assert [r["role"] for r in sends(rows)] == ["baseline", "attack"]
    assert baseline["attempt_id"] != attack["attempt_id"]
    assert attack["baseline_attempt_ids"] == decision["baseline_attempt_ids"] == [baseline["attempt_id"]]
    assert base_obs["outcome"] == "no_match"
    assert base_obs["decision_rule"] == "request_smuggling_baseline"
    assert decision["outcome"] == ("matched" if positive else "no_match")
    assert decision["parent_id"] == attack_obs["attempt_id"]
    assert decision["request_attempt_id"] == attack["attempt_id"]
    assert decision["decision_version"] == "1" and decision["rationale"]
    for request, observation, physical in zip(sends(rows), observations(rows), endpoint.requests):
        assert request["request"]["method"] == physical.method
        assert request["request"]["transport"] == "httpx"
        assert request["request"]["sent"] is False
        assert observation["request"]["sent"] is True
        assert observation["request_attempt_id"] == observation["parent_id"] == request["attempt_id"]
        assert request["request"]["body_hash"] == hashlib.sha256(physical.content).hexdigest()
        assert request["request"]["body_length"] == len(physical.content)
        assert observation["response"]["body_hash"] == hashlib.sha256(body).hexdigest()
        assert observation["response"]["body_length"] == len(body)
        assert observation["response"]["elapsed_ms"] >= 0
        assert observation["response"]["headers_hash"]
        assert "x-observed: yes" in observation["response"]["headers_excerpt"]
        assert physical.headers["Authorization"] == "Bearer header-secret"
        assert physical.headers["Cookie"] == "sid=cookie-secret"
        assert physical.url.params["access_token"] == "query-secret"
        assert "query-secret" not in observation["response"]["final_url"]
        assert physical.extensions["timeout"] == dict(connect=2, read=2, write=2, pool=2)
    assert endpoint.requests[1].content == _probe_body("CL.TE")
    assert endpoint.requests[1].headers["content-length"] == "6"
    assert endpoint.requests[1].headers["transfer-encoding"] == "chunked"
    assert all(set(opt) == {"timeout", "follow_redirects", "event_hooks"} for opt in options)
    assert all(opt["follow_redirects"] is False and set(opt["event_hooks"]) == {"request"} for opt in options)
    assert restored.completion_summary([CHECK])["status"] == "COMPLETE"
    assert manifest["evidence_incomplete"] is False
    persisted = logger.probe_ledger.path.read_text() + (tmp_path / MANIFEST_FILENAME).read_text()
    for secret in ("header-secret", "cookie-secret", "response-secret", "query-secret"):
        assert secret not in persisted
    if positive:
        assert findings[0].confidence == "tentative"
        assert findings[0].evidence_details["probe_attempt_id"] == attack["attempt_id"]
        assert findings[0].evidence_details["attempt_ids"] == [r["attempt_id"] for r in sends(rows)]


@pytest.mark.asyncio
@pytest.mark.parametrize("replay", ["matched", "no_match", "timeout", "transport_error"])
async def test_verification_relates_real_original_attempt(tmp_path, monkeypatch, replay):
    endpoint = Endpoint(400, b"400 Bad Request: invalid chunk")
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint)
    finding, = await run(scanner, logger, rule="request_smuggling_parser_error")
    original = finding.evidence_details["probe_attempt_id"]
    original_ids = list(finding.evidence_details["attempt_ids"])
    if replay == "no_match":
        endpoint.status, endpoint.body = 200, b"normal"
    elif replay in {"timeout", "transport_error"}:
        endpoint.failure = httpx.ReadTimeout if replay == "timeout" else httpx.ReadError
    unit = logger.probe_ledger.expect("verify-page", CHECK, role="verify", rules=(finding.evidence_type,))
    with logger.probe_ledger.unit_scope(unit):
        result = await scanner.verify_finding(finding)
    assert result is ({"matched": True, "no_match": False, "timeout": False, "transport_error": None}[replay])
    rows, restored, _ = reopened(logger, tmp_path)
    verify_rows = [r for r in rows if r["completion_unit"] == unit]
    base, verify = sends(verify_rows)
    assert base["role"] == "baseline" and verify["role"] == "verify"
    assert base["parent_id"] == verify["parent_id"] == original
    assert verify["baseline_attempt_ids"] == [base["attempt_id"]]
    assert verify_rows[-1]["outcome"] == replay
    assert verify_rows[-1]["request_attempt_id"] == verify["attempt_id"]
    assert finding.evidence_details["attempt_ids"] == original_ids
    assert [r.method for r in endpoint.requests] == ["GET", "POST", "GET", "POST"]
    assert len(observations(verify_rows)) == (1 if endpoint.failure else 2)
    if endpoint.failure:
        assert verify_rows[-1]["response"] is None
        assert restored.completion_summary([CHECK])["status"] != "COMPLETE"
    else:
        assert restored.completion_summary([CHECK])["status"] == "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["GET", "POST"])
@pytest.mark.parametrize("exception,outcome", [(httpx.ReadTimeout, "timeout"), (httpx.ConnectTimeout, "timeout"),
    (httpx.ConnectError, "transport_error"), (httpx.WriteError, "transport_error")])
async def test_transport_outcomes_without_fabricated_response(tmp_path, monkeypatch, method, exception, outcome):
    endpoint = Endpoint(failure=exception, fail_method=method)
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint)
    findings = await run(scanner, logger)
    intentional = method == "POST" and exception is httpx.ReadTimeout
    assert bool(findings) == intentional
    if intentional:
        assert findings[0].evidence_type == "request_smuggling_timing"
        assert findings[0].confidence == "tentative"
    rows, restored, _ = reopened(logger, tmp_path)
    assert len(endpoint.requests) == (1 if method == "GET" else 2)
    assert len(sends(rows)) == len(endpoint.requests)
    assert len(observations(rows)) == (0 if method == "GET" else 1)
    terminal = rows[-1]
    assert terminal["record_kind"] == "decision"
    assert terminal["outcome"] == outcome
    assert terminal["request_attempt_id"] == terminal["parent_id"] == sends(rows)[-1]["attempt_id"]
    assert terminal["response"] is None
    assert "private-exception-secret" not in logger.probe_ledger.path.read_text()
    assert restored.completion_summary([CHECK])["status"] != "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("logging", [None, False])
@pytest.mark.parametrize("timeout", [False, True])
async def test_unavailable_logger_preserves_detector(tmp_path, monkeypatch, logging, timeout):
    endpoint = Endpoint(failure=httpx.ReadTimeout if timeout else None)
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint, logging=logging)
    findings = await run(scanner, logger)
    assert bool(findings) == timeout
    assert len(endpoint.requests) == 2
    assert "request_smuggling_evidence_unavailable" in scanner.engine.wave_errors
    assert not (tmp_path / "probe_attempts.jsonl").exists()
    if logger:
        assert logger.probe_ledger.completion_summary([CHECK])["status"] == "EVIDENCE_INCOMPLETE"
    if timeout:
        assert "probe_attempt_id" not in findings[0].evidence_details


@pytest.mark.asyncio
@pytest.mark.parametrize("failed_write", ["request", "observation", "decision", "manifest"])
async def test_disk_failures_remain_incomplete_after_reopen(tmp_path, monkeypatch, failed_write):
    endpoint = Endpoint(400, b"400 Bad Request: invalid chunk")
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint)
    ledger = logger.probe_ledger
    real_open = builtins.open
    real_replace = __import__("os").replace
    writes = 0

    def failing_open(path, mode="r", *args, **kwargs):
        nonlocal writes
        if str(path) == str(ledger.path) and mode == "a":
            writes += 1
            if writes == {"request": 1, "observation": 4, "decision": 5}[failed_write]:
                raise OSError("disk full")
        return real_open(path, mode, *args, **kwargs)

    def failing_replace(src, dst):
        if str(dst).endswith(MANIFEST_FILENAME):
            raise OSError("manifest denied")
        return real_replace(src, dst)

    with monkeypatch.context() as failure:
        if failed_write != "manifest":
            failure.setattr(builtins, "open", failing_open)
        else:
            failure.setattr("wscan.probe_recorder.os.replace", failing_replace)
        finding, = await run(scanner, logger)
        assert ledger.evidence_incomplete
        assert ledger.completion_summary([CHECK])["status"] == "EVIDENCE_INCOMPLETE"
        assert ledger.quarantined == (failed_write != "manifest")
    assert len(endpoint.requests) == 2
    rows, restored, manifest = reopened(logger, tmp_path)
    assert manifest["evidence_incomplete"]
    assert manifest["write_errors"]
    assert restored.evidence_incomplete
    assert restored.completion_summary([CHECK])["status"] == "EVIDENCE_INCOMPLETE"
    if failed_write == "request":
        assert not rows
        assert "probe_attempt_id" not in finding.evidence_details


@pytest.mark.asyncio
async def test_timeout_finding_replay_stays_timeout_evidence(tmp_path, monkeypatch):
    endpoint = Endpoint(failure=httpx.ReadTimeout)
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint)
    finding, = await run(scanner, logger)
    assert await scanner.verify_finding(finding) is True
    rows, restored, _ = reopened(logger, tmp_path)
    assert [r["outcome"] for r in rows if r["record_kind"] == "decision"] == ["timeout", "timeout"]
    assert len(sends(rows)) == 4 and len(observations(rows)) == 2
    assert restored.completion_summary([CHECK])["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_received_response_delay_heuristic_keeps_original_threshold(tmp_path, monkeypatch):
    import time
    endpoint = Endpoint()
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint)
    ticks = iter([0, 0.1, 0.1, 6.2])
    monkeypatch.setattr("wscan.scanners.request_smuggling.time",
        SimpleNamespace(monotonic=lambda: next(ticks), time=time.time))
    finding, = await run(scanner, logger, rule="request_smuggling_timing")
    assert finding.evidence_type == "request_smuggling_timing"
    assert finding.evidence_details["delta"] == 6.0
    rows, restored, _ = reopened(logger, tmp_path)
    assert rows[-1]["outcome"] == "matched"
    assert len(observations(rows)) == 2
    assert restored.completion_summary([CHECK])["status"] == "COMPLETE"


@pytest.mark.asyncio
async def test_scan_page_preserves_order_host_dedup_and_probe_shapes(tmp_path, monkeypatch):
    endpoint = Endpoint()
    scanner, logger, _ = setup(tmp_path, monkeypatch, endpoint)
    assert await scanner.scan_page(URL) == []
    assert await scanner.scan_page(URL + "&next=1") == []
    rows, _, _ = reopened(logger, tmp_path)
    assert [r.method for r in endpoint.requests] == ["GET", "POST"] * 3
    assert len(sends(rows)) == 6 and len(observations(rows)) == 6
    for request, name in zip(endpoint.requests[1::2], _PROBE_DEFINITIONS):
        assert request.content == _probe_body(name)
        for key, value in _PROBE_DEFINITIONS[name]["headers"].items():
            assert request.headers[key] == value


def test_client_options_preserve_proxy_and_existing_tls_defaults(monkeypatch):
    options = []
    monkeypatch.setattr("wscan.scanners.request_smuggling.httpx.AsyncClient", lambda **kw: options.append(kw))
    scanner = RequestSmugglingScanner(SimpleNamespace(browser=None, monitor=None, payload_gen=None,
        request_logger=None, tls_config=SimpleNamespace(httpx_options=lambda: pytest.fail("TLS changed"))))
    scanner._client(3.5, "http://proxy.test")
    assert options == [dict(timeout=3.5, follow_redirects=False, proxy="http://proxy.test")]
