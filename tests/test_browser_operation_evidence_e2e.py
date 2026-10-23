"""Real ScanEngine Chromium page/flow/DOM twins and fresh-interpreter resume."""
import asyncio
import html
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import threading
import time

import pytest
import uvicorn
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse

from tests.test_shared_probe_evidence import make_engine, rows
from wscan.scanners.base import finding_dict_confirmed

pytestmark = pytest.mark.skipif(os.environ.get("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 required")


@pytest.fixture(scope="module")
def browser_server():
    app = FastAPI()
    visits = {"setup": 0}
    @app.get("/setup")
    async def setup():
        visits["setup"] += 1
        return HTMLResponse('<input name="password" type="password"><main>setup</main>')
    @app.api_route("/{kind}/{carrier}", methods=["GET", "POST"])
    async def target(kind: str, carrier: str, request: Request):
        value = request.query_params.get("q", "initial")
        if request.method == "POST":
            value = (await request.form()).get("q", "")
        form = '<form method="post"><input name="q"><button type="submit">send</button></form>' if carrier == "form" else ""
        sink = "innerHTML" if kind in {"vulnerable", "flood"} else "textContent"
        script = f'document.getElementById("out").{sink} = {json.dumps(value)};'
        if kind == "flood" and "__WSCAN_DOMXSS__" in value:
            script += "for(let i=0;i<4;i++)alert('recovery-trigger');"
        return HTMLResponse(f'<html><head><title>DOM fixture</title></head><body>{form}<div id="out"></div><script>{script}</script></body></html>')
    sock = socket.socket(); sock.bind(("127.0.0.1", 0))
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True); thread.start()
    deadline = time.monotonic() + 5
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline
        time.sleep(.01)
    try:
        yield f"http://127.0.0.1:{sock.getsockname()[1]}", visits
    finally:
        server.should_exit = True; thread.join(timeout=5); sock.close()
        assert not thread.is_alive()


async def scan(url, output, mode="normal", resume=False):
    from urllib.parse import urlsplit
    origin = urlsplit(url); base = f"{origin.scheme}://{origin.netloc}"
    steps = [{"action":"navigate", "url":base + "/setup"},
             {"action":"fill", "field":"ghost" if mode == "failure" else "password", "value":"browser-secret-sentinel"},
             {"action":"navigate", "url":url}]
    engine = make_engine(url, "dom_xss", output, flows=[{"name":"prerequisite", "steps":steps}],
                         timeout=2, resume_dir=str(output) if resume else "")
    # Use registered production scanners and the actual scheduler, not scan_field in isolation.
    from wscan.scanners.js_static import JsStaticScanner
    engine.scanners["js_static"] = JsStaticScanner(engine)
    engine.checks.append("js_static")
    if mode == "resume-page":
        engine.scanners.pop("dom_xss"); engine.checks.remove("dom_xss")
    await asyncio.wait_for(engine.run(), timeout=90)
    if mode == "verify-errors":
        import copy
        from wscan.engine import ScanEngine
        finding = next(f for f in engine.all_findings if f.check_type == "dom_xss")
        unavailable = copy.deepcopy(finding)
        unavailable.payload, unavailable.evidence_details = "", {}
        # The real engine has closed Chromium: replay must record inability, never a negative.
        for label, candidate in (("missing-marker", unavailable), ("closed-page", finding)):
            with ScanEngine._evidence_scope(engine, label, "dom_xss", rules=("dom_xss_verify",), role="verify"):
                assert await engine.scanners["dom_xss"].verify_finding(candidate) is None
    records = rows(engine.request_logger)
    metrics = {"candidate":len(engine.all_findings),
               "dom_candidate":sum(f.check_type == "dom_xss" for f in engine.all_findings),
               "confirmed":sum(finding_dict_confirmed(f.to_dict()) for f in engine.all_findings),
               "dom_confirmed":sum(f.check_type == "dom_xss" and finding_dict_confirmed(f.to_dict()) for f in engine.all_findings),
               "completion":engine.evidence_completion(),
               "logical_requests":sum(r["record_kind"] == "request" for r in records),
               "http_count":engine.request_logger.http_count}
    Path(output, "browser-metrics.json").write_text(json.dumps(metrics, indent=2))


def launch(url, output, mode="normal", resume=False):
    output.mkdir(parents=True, exist_ok=resume)
    script = "import asyncio,sys;from tests.test_browser_operation_evidence_e2e import scan;asyncio.run(scan(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]=='1'))"
    result = subprocess.run([sys.executable,"-c",script,url,str(output),mode,str(int(resume))],capture_output=True,text=True,timeout=120)
    name = "resume" if resume else "scan"
    (output / f"{name}.stdout").write_text(result.stdout); (output / f"{name}.stderr").write_text(result.stderr)
    (output / f"{name}.exit").write_text(str(result.returncode))
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((output / "browser-metrics.json").read_text())


@pytest.mark.parametrize("carrier", ["query", "form"])
@pytest.mark.parametrize("kind", ["vulnerable", "safe"])
def test_engine_page_flow_dom_twins(tmp_path, browser_server, kind, carrier):
    base, _ = browser_server
    output = Path(os.environ.get("WSCAN_BROWSER_ACCEPTANCE_DIR", tmp_path)) / f"{kind}-{carrier}"
    url = f"{base}/{kind}/{carrier}" + ("?q=initial" if carrier == "query" else "")
    metrics = launch(url, output)
    assert metrics["dom_candidate"] == int(kind == "vulnerable"), metrics
    if os.environ.get("WSCAN_BROWSER_BASELINE") == "1":
        return
    records = [json.loads(line) for line in (output / "probe_attempts.jsonl").read_text().splitlines()]
    by_id = {r["attempt_id"]:r for r in records}
    decisions = [r for r in records if (r.get("browser") or {}).get("kind") == "decision"]
    assert any(r["decision_rule"] == "js_static_snapshot" for r in decisions)
    dom = [r for r in decisions if r["decision_rule"] == "dom_xss_payload_oracle"]
    assert dom and dom[-1]["outcome"] == ("matched" if kind == "vulnerable" else "no_match"), decisions
    assert any(u["status"] == "COMPLETE" for u in metrics["completion"]["checks"]["dom_xss"]["units"].values()), metrics
    if kind == "vulnerable":
        assert metrics["dom_confirmed"] == 1
        assert any(r["decision_rule"] == "dom_xss_verify" and r["outcome"] == "matched" for r in decisions)
    for row in dom:
        op = by_id[row["browser"]["operation_id"]]
        snap = by_id[op["browser"]["snapshot_id"]]
        flow_end = by_id[snap["parent_id"]]
        assert flow_end["browser"]["kind"] == "flow_end"
        assert flow_end["outcome"] == "no_match"
        assert op["parent_id"] == snap["attempt_id"]
    assert len(by_id) == len(records)
    assert "browser-secret-sentinel" not in (output / "probe_attempts.jsonl").read_text()
    assert metrics["completion"]["status"] == "EVIDENCE_INCOMPLETE"


def test_engine_intermediate_flow_failure_blocks_dispatch(tmp_path, browser_server):
    base, _ = browser_server
    output = Path(os.environ.get("WSCAN_BROWSER_ACCEPTANCE_DIR", tmp_path)) / "failed-flow"
    metrics = launch(f"{base}/vulnerable/query?q=initial", output, "failure")
    assert metrics["dom_candidate"] == 0 and metrics["completion"]["status"] == "EVIDENCE_INCOMPLETE"
    records = [json.loads(line) for line in (output / "probe_attempts.jsonl").read_text().splitlines()]
    steps = [r for r in records if (r.get("browser") or {}).get("kind") == "flow_step"]
    assert [(r["browser"]["index"],r["outcome"]) for r in steps] == [(1,"no_match"),(2,"unexecutable")]
    assert not any((r.get("browser") or {}).get("kind") == "operation" for r in records)


def test_process_resume_reuses_proof_without_repeating_completed_flow(tmp_path, browser_server):
    base, visits = browser_server
    output = Path(os.environ.get("WSCAN_BROWSER_ACCEPTANCE_DIR", tmp_path)) / "resume"
    url = f"{base}/safe/page"
    before = visits["setup"]
    first = launch(url, output, "resume-page")
    original = (output / "probe_attempts.jsonl").read_bytes()
    assert visits["setup"] == before + 1
    resumed = launch(url, output, "resume-page", resume=True)
    assert visits["setup"] == before + 1
    assert (output / "probe_attempts.jsonl").read_bytes().startswith(original)
    assert first["candidate"] == resumed["candidate"]
    assert any(u["status"] == "COMPLETE" for u in resumed["completion"]["checks"]["js_static"]["units"].values())
    # An old execution marker cannot manufacture evidence, or justify repeating state changes.
    (output / "probe_attempts.jsonl").rename(output / "saved-proof.jsonl")
    without_proof = launch(url, output, "resume-page", resume=True)
    assert visits["setup"] == before + 1
    assert without_proof["completion"]["status"] == "EVIDENCE_INCOMPLETE"


def test_engine_actual_dialog_flood_recovery_is_causal(tmp_path, browser_server):
    base, _ = browser_server
    output = Path(os.environ.get("WSCAN_BROWSER_ACCEPTANCE_DIR", tmp_path)) / "recovery"
    metrics = launch(f"{base}/flood/query?q=initial", output)
    assert metrics["dom_candidate"] == 1
    records = [json.loads(line) for line in (output / "probe_attempts.jsonl").read_text().splitlines()]
    by_id = {r["attempt_id"]:r for r in records}
    recoveries = [r for r in records if (r.get("browser") or {}).get("kind") == "recovery"]
    assert recoveries, records
    for recovery in recoveries:
        dialog = by_id[recovery["parent_id"]]
        assert dialog["browser"]["kind"] == "dialog"
        operation = by_id[dialog["parent_id"]]
        assert operation["browser"]["kind"] == "operation" and operation["check"] == "dom_xss"
        assert dialog["browser"]["page_id"] == operation["browser"]["page_id"]
    restores = [r for r in records if (r.get("browser") or {}).get("kind") == "restore"]
    assert restores
    for restore in restores:
        lifecycle = by_id[restore["parent_id"]]
        assert lifecycle["browser"]["kind"] == "lifecycle"
        assert by_id[lifecycle["parent_id"]]["browser"]["kind"] == "recovery"
        request = by_id[restore["request_attempt_id"]]
        assert request["record_kind"] == "request" and request["role"] == "cleanup"
        assert request["parent_id"] == lifecycle["attempt_id"]
    # Replacing the page cannot transfer an old-page snapshot into fresh verification proof.
    assert metrics["completion"]["status"] == "EVIDENCE_INCOMPLETE"


def test_real_verifier_missing_marker_and_closed_page_are_indeterminate(tmp_path, browser_server):
    base, _ = browser_server
    output = Path(os.environ.get("WSCAN_BROWSER_ACCEPTANCE_DIR", tmp_path)) / "verify-errors"
    metrics = launch(f"{base}/vulnerable/query?q=initial", output, "verify-errors")
    records = [json.loads(line) for line in (output / "probe_attempts.jsonl").read_text().splitlines()]
    decisions = [r for r in records if (r.get("browser") or {}).get("kind") == "decision" and r["role"] == "verify"]
    assert {"unexecutable", "verification_error"}.issubset({r["outcome"] for r in decisions})
    assert not any(r["outcome"] == "no_match" for r in decisions)
    assert metrics["completion"]["status"] == "EVIDENCE_INCOMPLETE"
