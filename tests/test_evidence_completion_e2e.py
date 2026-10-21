"""Opt-in Chromium acceptance through the production crawl/attack/verify/report path."""
import asyncio
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

from wscan.engine import ScanEngine
from wscan.scanners.base import finding_dict_confirmed

pytestmark = pytest.mark.skipif(os.environ.get("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 opt-in required")


async def run_scan(url, output, resume=False):
    engine = ScanEngine(
        url, checks=["cors"], llm_provider="none", headless=True, output_dir=output,
        resume_dir=output if resume else "", open_report=False, enable_waf_detection=False,
        enable_ai_analysis=False, enable_payload_learning=False, enable_adaptive_payloads=False,
        enable_sitemap_crawl=False, enable_component_intel=False, enable_tls_scan=False,
        auto_spa_crawl=False, depth=0, fast_mode=True, request_delay=0, use_planner=False,
        sarif=False, timeout=1, navigation_retries=0,
    )
    if url.endswith("/logger-failure"):
        # Exercise an actual filesystem append failure while the real detector still runs.
        blocked = Path(output, "blocked-ledger")
        blocked.mkdir(exist_ok=True)
        engine.request_logger.probe_ledger._path = blocked
    await asyncio.wait_for(engine.run(), timeout=60)
    findings = [f.to_dict() for f in engine.all_findings]
    metrics = {"candidate": len(findings), "confirmed": sum(finding_dict_confirmed(f) for f in findings),
               "completion": engine.evidence_completion(), "scan_matrix": engine.scan_matrix}
    Path(output, "acceptance-metrics.json").write_text(json.dumps(metrics, indent=2))


@pytest.fixture(scope="module")
def fixture_url():
    app = FastAPI()

    @app.get("/{kind}")
    async def page(kind: str, request: Request):
        origin = request.headers.get("origin")
        if kind == "timeout" and origin:
            await asyncio.sleep(2)
        headers = {"Access-Control-Allow-Origin": origin, "Access-Control-Allow-Credentials": "true"} \
            if kind == "vulnerable" and origin else {}
        return HTMLResponse("<html><head><title>CORS fixture</title></head><body>Fixture</body></html>", headers=headers)

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while not server.started:
        assert thread.is_alive() and time.monotonic() < deadline, "fixture startup failed"
        time.sleep(0.02)
    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive(), "fixture cleanup failed"


def launch_scan(url, output, resume=False):
    # A fresh interpreter proves that no in-memory completion index survives resume.
    script = "import asyncio,sys; from tests.test_evidence_completion_e2e import run_scan; asyncio.run(run_scan(sys.argv[1],sys.argv[2],sys.argv[3]=='1'))"
    result = subprocess.run([sys.executable, "-c", script, url, str(output), str(int(resume))],
                            capture_output=True, text=True, timeout=90)
    output.mkdir(parents=True, exist_ok=True)
    (output / ("resume.log" if resume else "scan.log")).write_text(result.stdout + result.stderr)
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((output / "acceptance-metrics.json").read_text())


@pytest.mark.parametrize("kind,candidate,confirmed,status", [
    ("vulnerable", 1, 1, "COMPLETE"), ("safe", 0, 0, "COMPLETE"), ("timeout", 0, 0, "PARTIAL"),
    ("logger-failure", 0, 0, "EVIDENCE_INCOMPLETE"),
])
def test_chromium_twins_failure_and_process_resume(tmp_path, fixture_url, kind, candidate, confirmed, status):
    from playwright.sync_api import sync_playwright
    with sync_playwright() as pw:
        if not Path(pw.chromium.executable_path).is_file():
            pytest.skip("Chromium is not installed")
    base = Path(os.environ.get("WSCAN_EVIDENCE_ACCEPTANCE_DIR", tmp_path))
    output = base / kind
    metrics = launch_scan(f"{fixture_url}/{kind}", output)
    assert (metrics["candidate"], metrics["confirmed"]) == (candidate, confirmed), metrics
    assert metrics["completion"]["status"] == status, metrics
    evidence = json.loads((output / "evidence.json").read_text())
    manifest = json.loads((output / "probe_attempts_manifest.json").read_text())
    assert evidence["coverage"]["evidence_completion"]["status"] == status
    assert manifest["completion"]["status"] == status
    assert "Evidence completion" in (output / "report.html").read_text()
    if kind in {"vulnerable", "safe"}:
        before = (output / "probe_attempts.jsonl").read_text().splitlines()
        resumed = launch_scan(f"{fixture_url}/{kind}", output, resume=True)
        assert resumed["completion"]["status"] == "COMPLETE", resumed
        assert (resumed["candidate"], resumed["confirmed"]) == (candidate, confirmed)
        after = (output / "probe_attempts.jsonl").read_text().splitlines()
        assert after[:len(before)] == before
        assert len({json.loads(line)["attempt_id"] for line in after}) == len(after)


def test_dashboard_chromium_shows_evidence_completion_after_reconnect(tmp_path):
    from playwright.sync_api import sync_playwright
    from wscan.monitor import MonitorServer

    monitor = MonitorServer(port=0)
    completion = {"status": "EVIDENCE_INCOMPLETE", "checks": {"cors": {"status": "PARTIAL"}}}
    asyncio.run(monitor.emit("scan_complete", {"total_findings": 0, "status": "done",
                                              "findings": [], "evidence_completion": completion}))
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(monitor.app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()
    try:
        with sync_playwright() as pw:
            if not Path(pw.chromium.executable_path).is_file():
                pytest.skip("Chromium is not installed")
            browser = pw.chromium.launch(headless=True)
            try:
                page = browser.new_page(viewport={"width": 1440, "height": 1000})
                page.goto(f"http://127.0.0.1:{port}/monitor")
                page.wait_for_function("document.getElementById('statusText').textContent.includes('EVIDENCE_INCOMPLETE')")
                page.reload()
                page.wait_for_function("document.getElementById('statusText').textContent.includes('EVIDENCE_INCOMPLETE')")
                output = Path(os.environ.get("WSCAN_EVIDENCE_ACCEPTANCE_DIR", tmp_path))
                output.mkdir(parents=True, exist_ok=True)
                page.screenshot(path=str(output / "dashboard-evidence-completion.png"), full_page=True)
            finally:
                browser.close()
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        assert not thread.is_alive()


def test_old_checkpoint_without_evidence_stays_incomplete_in_production_resume(tmp_path, fixture_url):
    output = Path(os.environ.get("WSCAN_EVIDENCE_ACCEPTANCE_DIR", tmp_path)) / "old-checkpoint"
    assert launch_scan(f"{fixture_url}/safe", output)["completion"]["status"] == "COMPLETE"
    (output / "probe_attempts.jsonl").unlink()
    (output / "probe_attempts_manifest.json").unlink()
    checkpoint = json.loads((output / "checkpoint.json").read_text())
    checkpoint["version"] = 1
    (output / "checkpoint.json").write_text(json.dumps(checkpoint))
    resumed = launch_scan(f"{fixture_url}/safe", output, resume=True)
    assert resumed["completion"]["status"] == "EVIDENCE_INCOMPLETE"
    assert resumed["candidate"] == resumed["confirmed"] == 0
    rows = [json.loads(line) for line in (output / "probe_attempts.jsonl").read_text().splitlines()]
    assert not any(row["outcome"] for row in rows), "resume must not fabricate historical decisions"
