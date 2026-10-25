"""Exercise the real scanner, HTTPX hooks and persisted evidence, including replay."""
import copy
import json
from types import SimpleNamespace

import httpx
import pytest

from wscan.engine import ScanEngine
from wscan.graphql_evidence import RULES
from wscan.probe_recorder import ProbeLedger
from wscan.request_logger import RequestLogger
from wscan.scanners.graphql import GraphQLScanner, _INJECTION_PAYLOADS


URL = "http://fixture.test/graphql?token=url-secret"


def persisted(logger):
    return [json.loads(line) for line in logger.probe_ledger.path.read_text().splitlines()]


class Endpoint:
    def __init__(self, vulnerable=True, injection="xss", failure="", get_only=False):
        self.vulnerable, self.injection, self.failure, self.get_only = vulnerable, injection, failure, get_only
        self.requests = []

    def __call__(self, request):
        self.requests.append(request)
        payload = (json.loads(request.content) if request.method == "POST"
                   else {"query": request.url.params.get("query")})
        if self.get_only and request.method == "POST" and payload == {"query": "{ __typename }"}:
            return httpx.Response(405, json={"data": None})
        if isinstance(payload, list):
            return httpx.Response(200, json=[{"data": {"__typename": "Query"}}] if self.vulnerable else {"data": None})
        query = payload["query"]
        if query == "{ __typename }":
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        if self.failure:
            if self.failure == "timeout":
                raise httpx.ReadTimeout("body-secret", request=request)
            if self.failure == "reset":
                raise httpx.ReadError("body-secret", request=request)
            if self.failure == "malformed":
                return httpx.Response(200, text="not JSON body-secret")
            if self.failure == "ambiguous":
                return httpx.Response(200, json={"errors": [{"message": "resolver unavailable"}]})
            if self.failure == "auth":
                return httpx.Response(403, json={"errors": [{"message": "forbidden"}]})
        if "a99:" in query:
            return httpx.Response(200, json={"data": {"a99": "Query"}} if self.vulnerable else {"data": {}})
        if "ofType { name ofType" in query:
            return httpx.Response(200, json={"data": {"__schema": {}}} if self.vulnerable else {"data": {}})
        if "__schema" in query:
            return httpx.Response(200, json={"data": {"__schema": {"types": [{
                "name": "Query", "fields": [{"name": "password" if self.vulnerable else "search",
                "args": [{"name": "query", "type": {"name": "String"}}]}]}]}}})
        for payload_string, kind in _INJECTION_PAYLOADS:
            if payload_string in query and kind == self.injection and self.vulnerable:
                if kind == "sqli":
                    return httpx.Response(200, json={"errors": [{"message": "sqlite syntax error"}]})
                return httpx.Response(200, json={"data": {"result": "49" if kind == "ssti" else payload_string}})
        return httpx.Response(200, json={"data": {"result": "clean"}})


def setup(tmp_path, endpoint):
    logger = RequestLogger(tmp_path)
    engine = SimpleNamespace(browser=None, monitor=None, payload_gen=None, request_logger=logger,
        timeout=1, cookies="sid=cookie-secret", proxy="", wave_errors=[],
        tls_config=SimpleNamespace(httpx_options=lambda: {"transport": httpx.MockTransport(endpoint)}))
    engine.httpx_client_kwargs = lambda: ScanEngine.httpx_client_kwargs(engine)
    scanner = GraphQLScanner(engine)
    return scanner, logger


async def run_endpoint(scanner, logger):
    ledger = logger.probe_ledger
    unit = ledger.expect("page", "graphql", rules=RULES)
    with ledger.unit_scope(unit):
        assert await scanner._is_graphql(URL, {"Authorization": "Bearer header-secret"}, 1)
        findings = await scanner._test_endpoint(URL, {"Cookie": "sid=cookie-secret"}, 1)
    return findings, unit


@pytest.mark.asyncio
@pytest.mark.parametrize("vulnerable,injection", [(True, "xss"), (True, "sqli"), (True, "ssti"), (False, "xss")])
async def test_production_persistence_oracles_and_replay(tmp_path, vulnerable, injection):
    endpoint = Endpoint(vulnerable, injection)
    scanner, logger = setup(tmp_path, endpoint)
    findings, unit = await run_endpoint(scanner, logger)
    rows = persisted(logger)
    accepted = logger.probe_ledger._correlated_decisions()[unit]
    assert accepted
    assert {r["decision_rule"] for r in accepted} == {"graphql_discovery", *RULES}
    assert len([r for r in rows if r["record_kind"] == "request"]) == len(endpoint.requests)
    assert len(endpoint.requests) == 5 + ({"xss": 1, "sqli": 2, "ssti": 3}[injection] if vulnerable else 6)
    assert logger.http_count == len(endpoint.requests)
    assert len(logger.http_path.read_text().splitlines()) == len(endpoint.requests)
    assert logger.probe_ledger.completion_summary(["graphql"])["status"] == "COMPLETE"
    assert bool([f for f in findings if f.check_type == "graphql_dos"]) == vulnerable
    assert bool([f for f in findings if f.check_type == "graphql_batch"]) == vulnerable
    assert bool([f for f in findings if f.check_type == "graphql_sensitive"]) == vulnerable
    assert bool([f for f in findings if f.check_type == "graphql_injection"]) == vulnerable
    assert all(f.evidence_details.get("attempt_ids") for f in findings)
    for finding in findings:
        if finding.check_type == "graphql_dos":
            assert finding.check_type not in ScanEngine._VERIFIABLE_CHECKS
            continue
        verify_unit = logger.probe_ledger.expect("verify:" + finding.check_type, "graphql",
                                               rules=(finding.check_type,), role="verify")
        with logger.probe_ledger.unit_scope(verify_unit):
            assert await scanner.verify_finding(finding) is True
        decisions = logger.probe_ledger._correlated_decisions()[verify_unit]
        assert len(decisions) == 1
        assert decisions[0]["related_attempt_ids"] == finding.evidence_details["attempt_ids"]
    assert logger.probe_ledger.write_manifest()
    restored = ProbeLedger(tmp_path, tmp_path.name)
    assert restored._correlated_decisions() == logger.probe_ledger._correlated_decisions()
    assert not restored.evidence_incomplete
    text = "\n".join(p.read_text() for p in tmp_path.glob("*.json*"))
    for secret in ("url-secret", "header-secret", "cookie-secret", "{{7*7}}", "UNION SELECT", "wscan-graphql-xss"):
        assert secret not in text
    manifest = json.loads((tmp_path / "probe_attempts_manifest.json").read_text())
    assert manifest["logical_requests"] == len(endpoint.requests)


@pytest.mark.asyncio
@pytest.mark.parametrize("failure,outcome", [("timeout", "timeout"), ("reset", "transport_error"),
    ("malformed", "unexecutable"), ("ambiguous", "unexecutable"), ("auth", "blocked")])
async def test_failures_never_become_safe_negatives(tmp_path, failure, outcome):
    scanner, logger = setup(tmp_path, Endpoint(failure=failure))
    _, unit = await run_endpoint(scanner, logger)
    decisions = [r for r in persisted(logger) if r["record_kind"] == "graphql_decision" and r["role"] == "attack"]
    assert decisions and outcome in {r["outcome"] for r in decisions}
    assert not any(r["outcome"] == "no_match" for r in decisions)
    assert logger.probe_ledger.completion_summary(["graphql"])["status"] != "COMPLETE"
    assert "body-secret" not in logger.probe_ledger.path.read_text()
    assert logger.probe_ledger._correlated_decisions()[unit]


@pytest.mark.asyncio
async def test_discovery_get_and_origin_duplicate_suppression(tmp_path):
    endpoint = Endpoint(get_only=True)
    scanner, logger = setup(tmp_path, endpoint)
    findings, unit = await run_endpoint(scanner, logger)
    roots = [r for r in persisted(logger) if r["record_kind"] == "graphql_decision" and r["role"] == "baseline"]
    assert len(roots) == 2 and roots[-1]["outcome"] == "matched"
    assert "query=%3Credacted%3E" in logger.probe_ledger.path.read_text()
    assert logger.probe_ledger._correlated_decisions()[unit]
    scanner._tested_endpoints.add("http://fixture.test")
    first = await scanner.scan_page(URL)
    count = len(endpoint.requests)
    assert first
    assert await scanner.scan_page(URL) == []
    assert len(endpoint.requests) == count


@pytest.mark.asyncio
@pytest.mark.parametrize("damage", ["missing", "hash", "foreign", "late", "wrong_unit", "fake_baseline", "duplicate", "header_only", "substitution", "baseline_endpoint"])
async def test_two_cause_and_source_links_fail_closed(tmp_path, damage):
    scanner, logger = setup(tmp_path, Endpoint())
    findings, unit = await run_endpoint(scanner, logger)
    records = persisted(logger)
    events = {r["attempt_id"]: r for r in records}
    aggregate = next(r for r in events.values() if r.get("decision_rule") == "graphql_dos")
    other_id = aggregate["related_attempt_ids"][0]
    original = copy.deepcopy(events)
    if damage == "missing":
        records.remove(events[other_id])
    elif damage == "hash":
        events[other_id]["response"]["body_hash"] = "a" * 64
    elif damage == "foreign":
        events[other_id]["scan_id"] = "foreign"
    elif damage == "late":
        events[other_id]["attempt_id"] = logger.probe_ledger.scan_id + ":999999"
    elif damage == "wrong_unit":
        events[other_id]["completion_unit"] = "a" * 64
    elif damage == "fake_baseline":
        aggregate["baseline_attempt_ids"] = [events[other_id]["request_attempt_id"]]
    elif damage == "duplicate":
        aggregate["related_attempt_ids"] *= 2
    elif damage == "header_only":
        aggregate["parent_id"] = next(r["attempt_id"] for r in records if r["record_kind"] == "observation"
            and r["request_attempt_id"] == aggregate["request_attempt_id"] and not r["response"]["body_hash"])
    elif damage == "substitution":
        aggregate["parent_id"] = other_id
    else:
        baseline = aggregate["baseline_attempt_ids"][0]
        for row in records:
            if row["attempt_id"] == baseline or row.get("request_attempt_id") == baseline:
                if row.get("request"):
                    row["request"]["url"] = row["request"]["url"].replace("/graphql", "/other")
    logger.probe_ledger.path.write_text("".join(json.dumps(r) + "\n" for r in records))
    reopened = ProbeLedger(tmp_path, tmp_path.name)
    assert reopened._correlated_decisions()[unit] == []
    logger.probe_ledger.path.write_text("".join(json.dumps(r) + "\n" for r in original.values()))
    finding = next(f for f in findings if f.check_type == "graphql_batch")
    finding.evidence_details["attempt_ids"] = ["foreign:000001"]
    verify_unit = logger.probe_ledger.expect("foreign-replay", "graphql", rules=("graphql_batch",), role="verify")
    with logger.probe_ledger.unit_scope(verify_unit):
        assert await scanner.verify_finding(finding)
    assert logger.probe_ledger._correlated_decisions()[verify_unit] == []


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["field", "subtype", "operation", "endpoint"])
async def test_replay_cannot_borrow_another_finding_identity(tmp_path, mutation):
    scanner, logger = setup(tmp_path, Endpoint())
    findings, _ = await run_endpoint(scanner, logger)
    finding = next(f for f in findings if f.check_type == "graphql_injection")
    if mutation == "field":
        finding.field_name = "Query.other(query)"
    elif mutation == "subtype":
        finding.evidence_type = "graphql_injection_ssti"
    elif mutation == "operation":
        finding.request["body"] = finding.request["body"].replace("password(", "other(")
    else:
        finding.url = finding.url.replace("/graphql", "/api/graphql")
    unit = logger.probe_ledger.expect("verify-different", "graphql", rules=("graphql_injection",), role="verify")
    with logger.probe_ledger.unit_scope(unit):
        await scanner.verify_finding(finding)
    assert logger.probe_ledger.write_manifest()
    restored = ProbeLedger(tmp_path, tmp_path.name)
    assert restored._correlated_decisions()[unit] == []
    assert restored.completion_summary(["graphql"])["status"] != "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["blocked", "timeout", "malformed"])
async def test_dos_second_leg_failure_keeps_both_actual_causes(tmp_path, failure):
    endpoint = Endpoint()
    def handler(request):
        if b"ofType { name ofType" in request.content:
            endpoint.requests.append(request)
            if failure == "timeout":
                raise httpx.ReadTimeout("private-error", request=request)
            if failure == "malformed":
                return httpx.Response(200, text="bad JSON private-error")
            return httpx.Response(200, json={"errors": [{"message": "query too deep"}]})
        return endpoint(request)
    scanner, logger = setup(tmp_path, handler)
    findings, unit = await run_endpoint(scanner, logger)
    assert not any(f.check_type == "graphql_dos" for f in findings)
    rows = persisted(logger)
    dos = [r for r in rows if r["decision_rule"].startswith("graphql_dos")]
    assert {r["decision_rule"] for r in dos} >= {"graphql_dos_alias", "graphql_dos_depth"}
    aggregate = next((r for r in dos if r["decision_rule"] == "graphql_dos"), None)
    if failure != "timeout":
        assert aggregate and len(aggregate["related_attempt_ids"]) == 1
        assert aggregate["outcome"] == ("blocked" if failure == "blocked" else "unexecutable")
    else:
        assert aggregate is None
    assert logger.probe_ledger._correlated_decisions()[unit]
    assert logger.probe_ledger.completion_summary(["graphql"])["status"] != "COMPLETE"
    assert len([r for r in rows if r["record_kind"] == "request"]) == len(endpoint.requests)


@pytest.mark.asyncio
async def test_safe_introspection_retains_fallback_injection_requests(tmp_path):
    endpoint = Endpoint(False)
    def handler(request):
        if b"__schema" in request.content and b"ofType { name ofType" not in request.content:
            endpoint.requests.append(request)
            return httpx.Response(200, json={"data": {"__typename": "Query"}})
        return endpoint(request)
    scanner, logger = setup(tmp_path, handler)
    findings, unit = await run_endpoint(scanner, logger)
    assert findings == []
    decisions = [r for r in persisted(logger) if r["record_kind"] == "graphql_decision"]
    assert next(r for r in decisions if r["decision_rule"] == "graphql_introspection")["outcome"] == "no_match"
    assert len([r for r in decisions if r["decision_rule"] == "graphql_injection"]) == 18
    assert len(endpoint.requests) == 23
    assert logger.probe_ledger._correlated_decisions()[unit]


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["ledger", "manifest"])
async def test_logger_failure_preserves_detection_but_quarantines_completion(tmp_path, monkeypatch, failure):
    scanner, logger = setup(tmp_path, Endpoint())
    if failure == "ledger":
        logger.probe_ledger._path = tmp_path / "missing" / "probe_attempts.jsonl"
    else:
        import wscan.probe_recorder
        monkeypatch.setattr(wscan.probe_recorder.os, "replace", lambda *a: (_ for _ in ()).throw(OSError("full")))
    findings, _ = await run_endpoint(scanner, logger)
    assert findings
    assert logger.probe_ledger.evidence_incomplete
    assert logger.probe_ledger.completion_summary(["graphql"])["status"] == "EVIDENCE_INCOMPLETE"
    if failure == "ledger":
        assert logger.probe_ledger.quarantined


@pytest.mark.asyncio
async def test_legacy_and_interrupted_resume_do_not_supply_causal_completion(tmp_path):
    scanner, logger = setup(tmp_path, Endpoint())
    findings, unit = await run_endpoint(scanner, logger)
    before = persisted(logger)
    assert logger.probe_ledger.write_manifest()
    logger = RequestLogger(tmp_path)
    with logger.probe_ledger.unit_scope(unit):
        logger.log_probe(role="attack", check="graphql", outcome="matched",
                         decision_rule="graphql_batch", decision_version="1")
        with logger.probe_scope(None, "graphql", transport="graphql") as context:
            logger.begin_request(context, {"method": "POST", "url": URL}, "graphql")
    logger.probe_ledger.write_manifest()
    restored = ProbeLedger(tmp_path, tmp_path.name)
    rows = persisted(logger)
    assert len({r["attempt_id"] for r in rows}) == len(rows)
    assert rows[:len(before)] == before
    assert restored._correlated_decisions()[unit] == []
    assert restored.completion_summary(["graphql"])["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_missing_replay_payload_is_explicit_no_send(tmp_path):
    scanner, logger = setup(tmp_path, Endpoint())
    findings, _ = await run_endpoint(scanner, logger)
    finding = next(f for f in findings if f.check_type == "graphql_injection")
    finding.request = {}
    unit = logger.probe_ledger.expect("no-send", "graphql", rules=("graphql_injection",), role="verify")
    with logger.probe_ledger.unit_scope(unit):
        assert await scanner.verify_finding(finding) is None
    rows = logger.probe_ledger._correlated_decisions()[unit]
    assert len(rows) == 1 and rows[0]["outcome"] == "unexecutable"
    assert rows[0]["request"] is rows[0]["response"] is None
    assert logger.probe_ledger.completion_summary(["graphql"])["status"] == "PARTIAL"


@pytest.mark.asyncio
async def test_production_engine_requires_current_grounded_replay(tmp_path):
    scanner, logger = setup(tmp_path, Endpoint())
    scanner.engine.scanners = {"graphql": scanner}
    findings, _ = await run_endpoint(scanner, logger)
    finding = next(f for f in findings if f.check_type == "graphql_batch")
    assert await ScanEngine._verify_one(scanner.engine, finding) == "reproduced"
    from unittest.mock import AsyncMock
    scanner.verify_finding = AsyncMock(return_value=True)
    assert await ScanEngine._verify_one(scanner.engine, finding) == "assumed"


@pytest.mark.asyncio
async def test_production_engine_policy_skip_is_partial_without_sending(tmp_path):
    endpoint = Endpoint()
    scanner, logger = setup(tmp_path, endpoint)
    scanner.engine.scanners = {"graphql": scanner}
    findings, _ = await run_endpoint(scanner, logger)
    finding = next(f for f in findings if f.check_type == "graphql_batch")
    scanner.engine.state_profile = "read-only"
    before = len(endpoint.requests)
    assert await ScanEngine._verify_one(scanner.engine, finding) == "assumed"
    assert len(endpoint.requests) == before
    rows = [r for r in persisted(logger) if r["role"] == "verify"]
    assert len(rows) == 1 and rows[0]["outcome"] == "skipped"
    assert logger.probe_ledger.completion_summary(["graphql"])["status"] == "PARTIAL"


@pytest.mark.asyncio
@pytest.mark.parametrize("profile", ["unrestricted", "read-only"])
async def test_actual_engine_api_planning_runtime_and_verify_keys(tmp_path, profile):
    from unittest.mock import AsyncMock
    from tests.test_shared_probe_evidence import make_engine
    from wscan.checkpoint import unit_key
    from wscan.probe_recorder import completion_identity
    endpoint = Endpoint()
    engine = make_engine(URL, "graphql", tmp_path, state_profile=profile)
    engine.tls_config = SimpleNamespace(httpx_options=lambda: {"transport": httpx.MockTransport(endpoint)})
    engine.api_seed_requests = [SimpleNamespace(url=URL, method="POST", json_body={"query": "{}"})]
    engine._maybe_relogin_for_page = AsyncMock()
    engine._sync_cookies_from_browser = AsyncMock()
    engine._api_session_looks_expired = AsyncMock(return_value=False)
    engine.scanners["graphql"]._tested_endpoints.add("http://fixture.test")
    engine._plan_evidence([])
    key = completion_identity(unit_key(URL, "(api)", 0, "graphql"))
    assert set(engine.request_logger.probe_ledger.planned[key]["rules"]) == set(RULES)
    await engine._run_api_template_checks()
    plan = engine.request_logger.probe_ledger.planned[key]
    assert plan["executed"] and not plan["reason"]
    summary = engine.evidence_completion()
    assert summary["checks"]["graphql"]["units"][key]["status"] == ("COMPLETE" if profile == "unrestricted" else "PARTIAL")
    assert summary["status"] == "EVIDENCE_INCOMPLETE"  # unknown auxiliary paths stay explicit
    if profile == "read-only":
        assert not endpoint.requests
    else:
        finding = next(f for f in engine.all_findings if f.check_type == "graphql_batch")
        assert await engine._verify_one(finding) == "reproduced"
        verify_key = completion_identity(unit_key(finding.url, finding.field_name, 0, "graphql") + "\x1everify:" + finding.evidence_type)
        assert engine.request_logger.probe_ledger.planned[verify_key]["rules"] == ["graphql_batch"]


@pytest.mark.parametrize("vulnerable", [True, False])
@pytest.mark.asyncio
async def test_real_loopback_http_twins(tmp_path, monkeypatch, vulnerable):
    import asyncio
    import os
    import sys
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
    from pathlib import Path
    endpoint = Endpoint(vulnerable)
    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            content = self.rfile.read(int(self.headers.get("Content-Length", "0")))
            response = endpoint(httpx.Request("POST", "http://loopback" + self.path, content=content))
            self.send_response(response.status_code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response.content)))
            self.end_headers()
            self.wfile.write(response.content)
        def log_message(self, *args):
            pass
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    output = tmp_path
    if os.environ.get("WSCAN_GRAPHQL_ACCEPTANCE_DIR"):
        output = Path(os.environ["WSCAN_GRAPHQL_ACCEPTANCE_DIR"]) / ("vulnerable" if vulnerable else "safe")
        output.mkdir(parents=True, exist_ok=False)
    scanner, logger = setup(output, endpoint)
    scanner.engine.tls_config = SimpleNamespace(httpx_options=lambda: {"verify": False})
    monkeypatch.setattr(sys.modules[__name__], "URL", f"http://127.0.0.1:{server.server_port}/graphql")
    try:
        findings, unit = await run_endpoint(scanner, logger)
        logger.probe_ledger.write_manifest()
        restored = ProbeLedger(output, output.name)
        assert restored.completion_summary(["graphql"])["status"] == "COMPLETE"
        assert restored._correlated_decisions()[unit]
        assert len([r for r in persisted(logger) if r["record_kind"] == "request"]) == len(endpoint.requests)
        assert bool([f for f in findings if f.check_type == "graphql_dos"]) == vulnerable
    finally:
        await asyncio.to_thread(server.shutdown)
        server.server_close()
        thread.join(timeout=3)
        assert not thread.is_alive()
