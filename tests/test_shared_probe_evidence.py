"""Common probe wiring uses real loopback HTTP, with persisted causal assertions."""
import asyncio
import html
import json
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

import httpx
import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from wscan.checkpoint import CheckpointState
from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint
from wscan.request_logger import RequestLogger, current_probe
from wscan.probe_recorder import completion_identity
from wscan.scanners.base import finding_dict_confirmed


@pytest.fixture(scope="module")
def probe_server():
    app = FastAPI()

    @app.api_route("/{check}/{kind}/{carrier}", methods=["GET", "POST"])
    async def page(check: str, kind: str, carrier: str, request: Request):
        value = request.query_params.get("q", "")
        if request.method == "POST":
            value = ((await request.json()).get("q", "") if carrier == "json"
                     else (await request.form()).get("q", ""))
        if kind == "timeout" and value not in ("", "baseline_test", "baseline_value_wscan"):
            await asyncio.sleep(0.4)
        text = "Normal content " * 40
        if check == "sqli" and kind == "vulnerable" and "'" in value:
            text = "You have an error in your SQL syntax"
        if check == "sqli" and kind == "boolean":
            text = "Normal content " * 40 if "1=2" not in value else "No results"
        if check == "xss":
            text = value if kind == "vulnerable" else html.escape(value)
        form = '<form method="post"><input name="q"><button type="submit">Submit</button></form>' if carrier == "form" else ""
        if carrier == "noise":
            form = '<iframe src="/background-frame"></iframe><img src="/background-image">'
        return HTMLResponse(f"<html><head><title>Probe fixture</title></head><body>{form}<div>{text}</div></body></html>")

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
    engine = ScanEngine(url, checks=[check], llm_provider="none", headless=True,
                        output_dir=str(output), open_report=False, enable_waf_detection=False,
                        enable_ai_analysis=False, enable_payload_learning=False,
                        enable_adaptive_payloads=False, enable_payload_evolution=False,
                        enable_payload_mutation=False, enable_sitemap_crawl=False,
                        enable_component_intel=False, enable_tls_scan=False,
                        auto_spa_crawl=False, depth=0, fast_mode=True, request_delay=0,
                        use_planner=False, sarif=False, navigation_retries=0, **options)
    engine.payload_gen.default_payloads[check] = ["'" if check == "sqli" else "<script>alert(1)</script>"]
    return engine


def rows(logger):
    path = logger.probe_ledger.path
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


async def json_scan(url, check, output, *, timeout=2, logger_failure=False, boolean=False):
    engine = make_engine(url, check, output, timeout=timeout)
    ip = InjectionPoint.for_json_body("POST", url, "/q", template_id="fixture")
    engine.json_injection_points = [ip]
    engine.injection_templates["fixture"] = dict(url=url, method="POST", json_body={"q": "original", "password": "hidden-secret"})
    if boolean:
        engine.payload_gen.default_payloads[check] = ["1 AND 1=1"]
    if logger_failure:
        blocked = Path(output) / "blocked-ledger"
        blocked.mkdir()
        engine.request_logger.probe_ledger._path = blocked
    # Production API caller, actual HTTPX client and scanner; browser is unused by JSON requests.
    await engine._run_json_injection_checks()
    engine.request_logger.probe_ledger.write_manifest()
    return engine, ip


@pytest.mark.asyncio
@pytest.mark.parametrize("check", ["sqli", "xss"])
@pytest.mark.parametrize("kind", ["vulnerable", "safe"])
async def test_real_json_caller_twins_persist_oracles(tmp_path, probe_server, check, kind):
    engine, ip = await json_scan(f"{probe_server}/{check}/{kind}/json", check, tmp_path)
    ledger = engine.request_logger.probe_ledger
    unit = completion_identity(CheckpointState._candidate_unit_key(ip, check))
    recorded = rows(engine.request_logger)
    requests = [r for r in recorded if r["record_kind"] == "request"]
    decisions = [r for r in recorded if r["record_kind"] == "decision"]
    assert requests and decisions
    assert {r["role"] for r in requests} == {"baseline", "attack"}
    assert decisions[-1]["outcome"] == ("matched" if kind == "vulnerable" else "no_match")
    assert decisions[-1]["baseline_attempt_ids"]
    assert ledger.completion_summary([check])["checks"][check]["units"][unit]["status"] == "COMPLETE"
    assert len(engine.all_findings) == int(kind == "vulnerable")
    assert current_probe(engine.request_logger) is None
    assert "hidden-secret" not in ledger.path.read_text()
    manifest = json.loads((tmp_path / "probe_attempts_manifest.json").read_text())
    assert manifest["logical_requests"] == len(requests)
    assert len({r["attempt_id"] for r in recorded}) == len(recorded)
    metrics = {"candidate": len(engine.all_findings),
               "confirmed": sum(finding_dict_confirmed(f.to_dict()) for f in engine.all_findings),
               "logical_requests": len(requests), "decisions": len(decisions)}
    (tmp_path / "metrics.json").write_text(json.dumps(metrics))


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["timeout", "transport_error", "logger"])
async def test_real_json_failures_never_complete(tmp_path, probe_server, failure):
    kind = "timeout" if failure == "timeout" else "vulnerable" if failure == "logger" else "safe"
    url = f"{probe_server}/sqli/{kind}/json"
    if failure == "transport_error":
        with socket.socket() as sock:
            sock.bind(("127.0.0.1", 0))
            url = f"http://127.0.0.1:{sock.getsockname()[1]}/sqli/safe/json"
    engine, _ = await json_scan(url, "sqli", tmp_path, timeout=0.1, logger_failure=failure == "logger")
    ledger = engine.request_logger.probe_ledger
    assert ledger.completion_summary(["sqli"])["status"] == "EVIDENCE_INCOMPLETE"
    assert len(engine.all_findings) == int(failure == "logger")
    if failure == "logger":
        assert ledger.quarantined and ledger.evidence_incomplete
    else:
        assert any(r["outcome"] == failure for r in rows(engine.request_logger))


@pytest.mark.asyncio
async def test_duplicate_httpx_hooks_one_logical_request_and_mixed_resume(tmp_path, probe_server):
    logger = RequestLogger(tmp_path)
    ip = InjectionPoint.for_json_body("POST", f"{probe_server}/sqli/safe/json", "/q")
    legacy = logger.log_probe(role="discover")
    with logger.probe_scope(ip, "sqli", role="baseline"):
        async with httpx.AsyncClient(event_hooks={"request": [logger.log_httpx_submission] * 2,
                                                "response": [logger.log_httpx_response] * 2}) as client:
            await client.post(ip.url, json={"q": "safe"})
    assert sum(r["record_kind"] == "request" for r in rows(logger)) == 1
    assert sum(r["record_kind"] == "observation" for r in rows(logger)) == 1
    assert logger.probe_ledger.write_manifest()
    restored = RequestLogger(tmp_path)
    assert not restored.probe_ledger.evidence_incomplete
    assert rows(restored)[0]["attempt_id"] == legacy
    assert restored.probe_ledger.write_manifest()
    assert json.loads((tmp_path / "probe_attempts_manifest.json").read_text())["logical_requests"] == 1


@pytest.mark.asyncio
async def test_real_boolean_control_links_exact_attack_and_two_baselines(tmp_path, probe_server):
    engine, _ = await json_scan(f"{probe_server}/sqli/boolean/json", "sqli", tmp_path, boolean=True)
    recorded = rows(engine.request_logger)
    decision = next(r for r in recorded if r["record_kind"] == "decision")
    control = next(r for r in recorded if r["record_kind"] == "request" and r["role"] == "control")
    assert decision["outcome"] == "matched"
    assert decision["control_attempt_ids"] == [control["attempt_id"]]
    assert len(set(decision["baseline_attempt_ids"])) == 2
    assert control["parent_id"] == decision["request_attempt_id"]
    assert engine.request_logger.probe_ledger.completion_summary(["sqli"])["status"] == "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["missing_control", "wrong_parent", "omitted_reference"])
async def test_boolean_control_cannot_be_missing_or_borrowed(tmp_path, probe_server, corruption):
    engine, _ = await json_scan(f"{probe_server}/sqli/boolean/json", "sqli", tmp_path, boolean=True)
    recorded = rows(engine.request_logger)
    control = next(r for r in recorded if r["record_kind"] == "request" and r["role"] == "control")
    if corruption == "missing_control":
        control["record_kind"] = "payload"
    elif corruption == "wrong_parent":
        control["parent_id"] = "foreign:000001"
    else:
        for row in recorded:
            if row["record_kind"] == "decision":
                row["control_attempt_ids"] = []
    engine.request_logger.probe_ledger.path.write_text("".join(json.dumps(r) + "\n" for r in recorded))
    assert RequestLogger(tmp_path).probe_ledger.completion_summary(["sqli"])["status"] == "EVIDENCE_INCOMPLETE"


@pytest.mark.asyncio
async def test_reused_httpx_request_counts_each_send_without_duplicate_hooks(tmp_path, probe_server):
    logger = RequestLogger(tmp_path)
    ip = InjectionPoint.for_json_body("POST", f"{probe_server}/sqli/safe/json", "/q")
    async with httpx.AsyncClient(event_hooks={"request": [logger.log_httpx_submission] * 2,
                                            "response": [logger.log_httpx_response] * 2}) as client:
        request = client.build_request("POST", ip.url, json={"q": "safe"})
        with logger.probe_scope(ip, "sqli"):
            await client.send(request)
            await client.send(request)
        await client.send(request)  # an unscoped reuse must not retain the old attack context
    recorded = rows(logger)
    scoped = [r for r in recorded if r["record_kind"] == "request"]
    assert len(scoped) == 2 and len({r["attempt_id"] for r in scoped}) == 2
    assert recorded[-1]["record_kind"] == "legacy" and recorded[-1]["check"] == ""


@pytest.mark.asyncio
@pytest.mark.parametrize("corruption", ["missing_request", "missing_body", "wrong_unit", "wrong_check",
                                        "wrong_field", "wrong_role", "foreign_baseline", "missing_baseline",
                                        "unrelated_legacy", "late_undecided_request"])
async def test_persisted_wrong_missing_and_late_evidence_fail_closed(tmp_path, probe_server, corruption):
    engine, _ = await json_scan(f"{probe_server}/sqli/safe/json", "sqli", tmp_path)
    logger = engine.request_logger
    recorded = rows(logger)
    decision = next(r for r in recorded if r["record_kind"] == "decision")
    request = next(r for r in recorded if r["attempt_id"] == decision["request_attempt_id"])
    observation = next(r for r in recorded if r["attempt_id"] == decision["parent_id"])
    if corruption == "missing_request":
        request["record_kind"] = "payload"
    elif corruption == "missing_body":
        for row in recorded:
            if row["record_kind"] == "observation":
                row["response"]["body_hash"] = ""
    elif corruption == "wrong_unit":
        request["completion_unit"] = "a" * 64
    elif corruption == "wrong_check":
        request["check"] = "xss"
    elif corruption == "wrong_field":
        request["injection_key"] = "other-location"
    elif corruption == "wrong_role":
        observation["role"] = "verify"
    elif corruption == "foreign_baseline":
        decision["baseline_attempt_ids"][0] = "foreign:000001"
    elif corruption == "missing_baseline":
        decision["baseline_attempt_ids"].pop()
    elif corruption == "unrelated_legacy":
        decision["record_kind"] = "legacy"
    else:
        late = dict(request, attempt_id=logger.probe_ledger.next_attempt_id())
        recorded.append(late)
    logger.probe_ledger.path.write_text("".join(json.dumps(r) + "\n" for r in recorded))
    restored = RequestLogger(tmp_path)
    assert restored.probe_ledger.completion_summary(["sqli"])["status"] == "EVIDENCE_INCOMPLETE"


@pytest.mark.asyncio
async def test_parallel_equal_names_keep_explicit_locations_and_late_hook_context(tmp_path, probe_server):
    logger = RequestLogger(tmp_path)
    ips = [InjectionPoint.for_json_body("POST", f"{probe_server}/sqli/safe/json", "/q"),
           InjectionPoint.for_url_param(f"{probe_server}/sqli/safe/json", "q")]
    responses = []

    async def send(ip):
        unit = logger.probe_ledger.expect(CheckpointState._candidate_unit_key(ip, "sqli"), "sqli", rules=["sqli_payload_oracle"])
        with logger.probe_ledger.unit_scope(unit), logger.probe_scope(ip, "sqli", role="baseline"):
            async with httpx.AsyncClient(event_hooks={"request": [logger.log_httpx_submission]}) as client:
                responses.append(await client.post(ip.url, json={"q": "safe"}))
            await asyncio.sleep(0)
    await asyncio.gather(*(send(ip) for ip in ips))
    assert current_probe(logger) is None
    # Deliberately dispatch callbacks after both task-local scopes have ended.
    for response in reversed(responses):
        await logger.log_httpx_response(response)
    recorded = rows(logger)
    requests = {r["attempt_id"]: r for r in recorded if r["record_kind"] == "request"}
    assert len(requests) == 2 and len({r["completion_unit"] for r in requests.values()}) == 2
    assert len({r["injection_key"] for r in requests.values()}) == 2
    for row in recorded:
        if row["record_kind"] == "observation":
            assert row["completion_unit"] == requests[row["request_attempt_id"]]["completion_unit"]
    assert logger.probe_ledger.completion_summary(["sqli"])["status"] == "EVIDENCE_INCOMPLETE"


def test_real_http_json_process_restart_preserves_rows_ids_and_mixed_legacy(tmp_path, probe_server):
    script = "import asyncio,sys; from tests.test_shared_probe_evidence import json_scan; asyncio.run(json_scan(sys.argv[1],'sqli',sys.argv[2]))"
    for iteration in range(2):
        result = subprocess.run([sys.executable, "-c", script, f"{probe_server}/sqli/safe/json", str(tmp_path)],
                                capture_output=True, text=True, timeout=30)
        assert result.returncode == 0, result.stdout + result.stderr
        logger = RequestLogger(tmp_path)
        assert logger.probe_ledger.completion_summary(["sqli"])["status"] == "COMPLETE"
        if iteration == 0:
            logger.log_probe(role="discover")
            logger.probe_ledger.write_manifest()
            # Genuine pre-event-format row mixed with current format records.
            recorded = rows(logger)
            recorded[-1].pop("record_kind")
            recorded[-1].pop("request_attempt_id")
            logger.probe_ledger.path.write_text("".join(json.dumps(r) + "\n" for r in recorded))
            before = logger.probe_ledger.path.read_bytes()
        else:
            assert logger.probe_ledger.path.read_bytes().startswith(before)
    recorded = rows(logger)
    assert len({r["attempt_id"] for r in recorded}) == len(recorded)


@pytest.mark.asyncio
@pytest.mark.parametrize("outcome", ["blocked", "skipped", "unexecutable"])
async def test_authoritative_dispatcher_gates_persist_nonnegative_outcomes(tmp_path, probe_server, outcome):
    engine = make_engine(f"{probe_server}/sqli/safe/json", "sqli", tmp_path)
    scanner = engine.scanners["sqli"]
    ip = InjectionPoint.for_url_param(engine.target_url, "q")
    if outcome == "blocked":
        engine.state_profile = "read-only"
        ip = InjectionPoint.for_form(engine.target_url, "q", method="POST", action="/delete", labels="delete")
        await scanner.dispatch(ip, "value")
    elif outcome == "skipped":
        scanner._field_budget_gate = lambda: True
        await scanner._apply_ip(ip, "value")
    else:
        scanner._dispatch_driver_available = lambda _: False
        await scanner.dispatch(ip, "value")
    recorded = rows(engine.request_logger)
    assert recorded[-1]["outcome"] == outcome
    assert not any(r["record_kind"] == "request" for r in recorded)
    assert engine.evidence_completion()["status"] == "EVIDENCE_INCOMPLETE"


@pytest.mark.asyncio
async def test_oracle_execution_error_and_logger_error_do_not_change_exception_or_findings(tmp_path, probe_server):
    engine = make_engine(f"{probe_server}/sqli/safe/json", "sqli", tmp_path)
    scanner = engine.scanners["sqli"]
    ip = InjectionPoint.for_json_body("POST", engine.target_url, "/q")

    async def fail():
        raise ValueError("hidden-secret")
    with pytest.raises(ValueError, match="hidden-secret"):
        await scanner._send_probe(ip, fail)
    assert rows(engine.request_logger)[-1]["outcome"] == "verification_error"
    assert "hidden-secret" not in engine.request_logger.probe_ledger.path.read_text()
    assert current_probe(engine.request_logger) is None

    logger = engine.request_logger
    original = logger.log_probe
    def fail_observation(**kwargs):
        if kwargs.get("record_kind") == "observation":
            raise OSError("hidden-secret")
        return original(**kwargs)
    logger.log_probe = fail_observation
    engine.json_injection_points = [ip]
    engine.injection_templates[""] = dict(url=ip.url, method="POST", json_body={"q": "original"})
    await engine._run_json_injection_checks()
    assert not engine.all_findings
    assert logger.probe_ledger.evidence_incomplete
    assert current_probe(logger) is None
