"""Opt-in production Chromium query/form scans and fresh-interpreter resume."""
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tests.test_shared_probe_evidence import make_engine, probe_server, rows
from wscan.scanners.base import finding_dict_confirmed
from wscan.injection_point import InjectionPoint
from wscan.request_logger import current_probe

pytestmark = pytest.mark.skipif(os.environ.get("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 opt-in required")


async def run_scan(url, check, output, resume=False):
    engine = make_engine(url, check, output, timeout=2, resume_dir=str(output) if resume else "")
    await asyncio.wait_for(engine.run(), timeout=90)
    ledger = engine.request_logger.probe_ledger
    metrics = {"candidate": len(engine.all_findings),
               "confirmed": sum(finding_dict_confirmed(f.to_dict()) for f in engine.all_findings),
               "completion": engine.evidence_completion(),
               "logical_requests": sum(r["record_kind"] == "request" for r in rows(engine.request_logger)),
               "decisions": [r for r in rows(engine.request_logger) if r["record_kind"] == "decision"]}
    Path(output, "shared-metrics.json").write_text(json.dumps(metrics, indent=2))


def launch(url, check, output, resume=False):
    script = "import asyncio,sys; from tests.test_shared_probe_evidence_e2e import run_scan; asyncio.run(run_scan(sys.argv[1],sys.argv[2],sys.argv[3],sys.argv[4]=='1'))"
    result = subprocess.run([sys.executable, "-c", script, url, check, str(output), str(int(resume))],
                            text=True, capture_output=True, timeout=120)
    output.mkdir(parents=True, exist_ok=True)
    name = "resume" if resume else "scan"
    (output / f"{name}.stdout").write_text(result.stdout)
    (output / f"{name}.stderr").write_text(result.stderr)
    (output / f"{name}.exit").write_text(str(result.returncode))
    assert result.returncode == 0, result.stdout + result.stderr
    return json.loads((output / "shared-metrics.json").read_text())


@pytest.mark.parametrize("carrier", ["query", "form"])
@pytest.mark.parametrize("check", ["sqli", "xss"])
@pytest.mark.parametrize("kind", ["vulnerable", "safe"])
def test_engine_chromium_twins_and_process_resume(tmp_path, probe_server, carrier, check, kind):
    output = Path(os.environ.get("WSCAN_SHARED_ACCEPTANCE_DIR", tmp_path)) / f"{check}-{carrier}-{kind}"
    url = f"{probe_server}/{check}/{kind}/{carrier}" + ("?q=initial" if carrier == "query" else "")
    metrics = launch(url, check, output)
    assert metrics["candidate"] == int(kind == "vulnerable"), metrics
    assert metrics["logical_requests"] > 0 and metrics["decisions"], metrics
    assert any(u["status"] == "COMPLETE" for c in metrics["completion"]["checks"].values()
               for u in c["units"].values()), metrics
    assert any(r["outcome"] == ("matched" if kind == "vulnerable" else "no_match")
               and r["decision_rule"] == f"{check}_payload_oracle" for r in metrics["decisions"]), metrics
    # Unknown auxiliary and verification paths must keep whole-check completion conservative.
    assert metrics["completion"]["status"] == "EVIDENCE_INCOMPLETE"
    before = (output / "probe_attempts.jsonl").read_bytes()
    resumed = launch(url, check, output, resume=True)
    assert (resumed["candidate"], resumed["confirmed"]) == (metrics["candidate"], metrics["confirmed"])
    assert (output / "probe_attempts.jsonl").read_bytes().startswith(before)
    records = [json.loads(line) for line in (output / "probe_attempts.jsonl").read_text().splitlines()]
    assert len({r["attempt_id"] for r in records}) == len(records)
    by_id = {r["attempt_id"]: r for r in records}
    for row in records:
        if row["record_kind"] == "decision" and row["decision_rule"]:
            request = by_id[row["request_attempt_id"]]
            assert request["record_kind"] == "request"
            assert request["completion_unit"] == row["completion_unit"]
            assert all(by_id[ref]["role"] == "baseline" for ref in row["baseline_attempt_ids"])


@pytest.mark.asyncio
async def test_chromium_setup_assets_and_iframe_do_not_claim_attack_context(tmp_path, probe_server):
    engine = make_engine(f"{probe_server}/sqli/safe/noise?q=initial", "sqli", tmp_path, timeout=2)
    browser = engine.browser
    await browser.init()
    try:
        ip = InjectionPoint.for_url_param(f"{probe_server}/sqli/safe/noise?q=initial", "q")
        logger = engine.request_logger
        with logger.probe_scope(ip, "sqli"):
            await browser.navigate(ip.url)  # setup navigation has no shared-send binding
        assert not any(r["record_kind"] == "request" for r in rows(logger))
        await engine.scanners["sqli"]._apply_ip(ip, "test")
        requests = [r for r in rows(logger) if r["record_kind"] == "request"]
        assert len(requests) == 1
        assert "background" not in requests[0]["request"]["url"]
        assert current_probe(logger) is None and browser.network.probe_context is None
    finally:
        await browser.close()
