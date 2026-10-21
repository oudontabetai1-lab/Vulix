"""Completion requires persisted decisions for the exact planned unit."""
import asyncio
import json
import subprocess
import sys
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wscan.check_coverage import reconcile_evidence
from wscan.checkpoint import CheckpointState, unit_key
from wscan.engine import CrawledPage, ScanEngine
from wscan.probe_ledger import ProbeOutcome, ProbeRole
from wscan.probe_recorder import ProbeLedger, completion_identity
from wscan.request_logger import RequestLogger


def decision(logger, rule="rule", outcome=ProbeOutcome.NO_MATCH, check="cors"):
    return logger.log_probe(role=ProbeRole.ATTACK, check=check, outcome=outcome,
                            decision_rule=rule, decision_version="1")


def test_pure_reconciliation_requires_each_rule_and_exact_unit():
    plans = {"a": {"check": "cors", "rules": ["one", "two"], "role": "attack", "executed": True}}
    row = {"check": "cors", "role": "attack", "decision_rule": "one",
           "decision_version": "1", "outcome": "no_match"}
    assert reconcile_evidence(plans, {"other": [row]}, ["cors"])["status"] == "EVIDENCE_INCOMPLETE"
    partial = reconcile_evidence(plans, {"a": [row]}, ["cors"])
    assert partial["checks"]["cors"]["units"]["a"]["missing_rules"] == ["two"]
    rows = [row, dict(row, decision_rule="two")]
    assert reconcile_evidence(plans, {"a": rows}, ["cors"])["status"] == "COMPLETE"
    assert reconcile_evidence(plans, {"a": rows}, ["cors"], execution_success=False)["status"] == "PARTIAL"
    assert reconcile_evidence(plans, {"a": rows}, ["cors"], logging_failed=True)["status"] == "EVIDENCE_INCOMPLETE"
    for bad in (dict(row, check="xss"), dict(row, role="verify"), dict(row, decision_version="0")):
        assert reconcile_evidence(plans, {"a": [bad, rows[1]]}, ["cors"])["status"] == "EVIDENCE_INCOMPLETE"


@pytest.mark.parametrize("outcome", [ProbeOutcome.TIMEOUT, ProbeOutcome.BLOCKED, ProbeOutcome.SKIPPED,
                                    ProbeOutcome.UNEXECUTABLE, ProbeOutcome.TRANSPORT_ERROR])
def test_recorded_failure_is_evidence_but_never_successful_negative(tmp_path, outcome):
    logger = RequestLogger(tmp_path)
    unit = logger.probe_ledger.expect("unit", "cors", rules=["rule"])
    with logger.probe_ledger.unit_scope(unit):
        decision(logger, outcome=outcome)
    summary = logger.probe_ledger.completion_summary(["cors"])
    assert summary["status"] == "PARTIAL"
    assert summary["checks"]["cors"]["units"][unit]["missing_rules"] == []


def test_empty_unknown_and_unreached_plans_do_not_complete(tmp_path):
    ledger = ProbeLedger(tmp_path, "scan")
    assert ledger.completion_summary([])["status"] == "EVIDENCE_INCOMPLETE"
    assert ledger.completion_summary(["cors"])["status"] == "EVIDENCE_INCOMPLETE"
    ledger.expect("unknown", "cors", reason="uninstrumented_detector_contract")
    unit = ledger.expect("never-reached", "cors", rules=["rule"])
    summary = ledger.completion_summary(["cors"])
    assert summary["checks"]["cors"]["units"][unit]["missing_rules"] == ["rule"]
    assert summary["status"] == "EVIDENCE_INCOMPLETE"


def test_logger_failure_preserves_gate_and_does_not_return_evidence_id(tmp_path):
    logger = RequestLogger(tmp_path)
    unit = logger.probe_ledger.expect("unit", "cors", rules=["rule"])
    logger.probe_ledger._path = tmp_path  # opening a directory for append fails
    with logger.probe_ledger.unit_scope(unit):
        assert decision(logger) is None
    assert logger.probe_ledger.completion_summary(["cors"])["status"] == "EVIDENCE_INCOMPLETE"


def test_failed_pre_attempt_plan_persistence_stays_visible_after_io_recovers(tmp_path):
    logger = RequestLogger(tmp_path)
    unit = logger.probe_ledger.expect("unit", "cors", rules=["rule"])
    manifest = tmp_path / "probe_attempts_manifest.json"
    manifest.mkdir()
    with logger.probe_ledger.unit_scope(unit):
        decision(logger)
    manifest.rmdir()
    assert logger.probe_ledger.write_manifest()
    assert logger.probe_ledger.completion_summary(["cors"])["status"] == "EVIDENCE_INCOMPLETE"
    assert RequestLogger(tmp_path).probe_ledger.completion_summary(["cors"])["status"] == "EVIDENCE_INCOMPLETE"


@pytest.mark.asyncio
async def test_parallel_fields_keep_exact_hashed_identity_and_parent_ids(tmp_path):
    logger = RequestLogger(tmp_path)
    ledger = logger.probe_ledger
    keys = [unit_key("https://t.test/?token=private", name, 0, "cors", True)
            for name in ("first-private-field", "second-private-field")]
    units = [ledger.expect(key, "cors", rules=["rule"]) for key in keys]
    ledger.write_manifest()

    async def run(unit):
        with ledger.unit_scope(unit):
            parent = logger.log_probe(role=ProbeRole.ATTACK, check="cors")
            await asyncio.sleep(0)
            logger.log_probe(role=ProbeRole.ATTACK, check="cors", parent_id=parent,
                             outcome=ProbeOutcome.NO_MATCH, decision_rule="rule", decision_version="1")
    await asyncio.gather(*(run(unit) for unit in units))
    rows = [json.loads(line) for line in ledger.path.read_text().splitlines()]
    by_id = {r["attempt_id"]: r for r in rows}
    for row in rows:
        if row["parent_id"]:
            assert row["completion_unit"] == by_id[row["parent_id"]]["completion_unit"]
    assert {r["completion_unit"] for r in rows} == set(units)
    assert ledger.current_unit() == ""
    assert ledger.completion_summary(["cors"])["status"] == "COMPLETE"
    text = ledger.path.read_text() + (tmp_path / "probe_attempts_manifest.json").read_text()
    assert "private" not in text and "https://" not in text


def test_process_restart_restores_real_evidence_and_leaves_interrupted_unit_partial(tmp_path):
    script = '''
import os, sys
from wscan.request_logger import RequestLogger
from wscan.probe_ledger import ProbeRole, ProbeOutcome
l = RequestLogger(sys.argv[1])
u = l.probe_ledger.expect("finished", "cors", rules=["rule"])
with l.probe_ledger.unit_scope(u):
    l.log_probe(role=ProbeRole.ATTACK, check="cors", outcome=ProbeOutcome.NO_MATCH,
                decision_rule="rule", decision_version="1")
v = l.probe_ledger.expect("interrupted", "cors", rules=["rule"])
with l.probe_ledger.unit_scope(v):
    l.log_probe(role=ProbeRole.ATTACK, check="cors", outcome=ProbeOutcome.NO_MATCH,
                decision_rule="rule", decision_version="1")
    os._exit(0)
'''
    result = subprocess.run([sys.executable, "-c", script, str(tmp_path)], capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    logger = RequestLogger(tmp_path)
    original = logger.probe_ledger.path.read_bytes()
    summary = logger.probe_ledger.completion_summary(["cors"])
    assert summary["checks"]["cors"]["units"][completion_identity("finished")]["status"] == "COMPLETE"
    assert summary["checks"]["cors"]["units"][completion_identity("interrupted")]["status"] == "PARTIAL"
    assert logger.probe_ledger.path.read_bytes() == original
    with logger.probe_ledger.unit_scope(completion_identity("interrupted")):
        decision(logger)
    assert logger.probe_ledger.completion_summary(["cors"])["status"] == "COMPLETE"
    rows = [json.loads(line) for line in logger.probe_ledger.path.read_text().splitlines()]
    assert len({r["attempt_id"] for r in rows}) == len(rows) == 3


def test_old_checkpoint_completed_bit_does_not_invent_evidence(tmp_path):
    state = CheckpointState.from_dict({"version": 1, "checks": ["cors"],
        "completed_units": [unit_key("https://t.test/", "(page)", 0, "cors")]})
    assert state.is_done("https://t.test/", "(page)", 0, "cors")
    logger = RequestLogger(tmp_path)
    logger.probe_ledger.expect(next(iter(state.completed_units)), "cors", rules=["rule"])
    assert logger.probe_ledger.completion_summary(["cors"])["status"] == "EVIDENCE_INCOMPLETE"
    assert not logger.probe_ledger.path.exists()


@pytest.mark.parametrize("missing", ["probe_attempts.jsonl", "probe_attempts_manifest.json"])
def test_final_reconciliation_catches_deleted_persisted_source(tmp_path, missing):
    logger = RequestLogger(tmp_path)
    unit = logger.probe_ledger.expect("unit", "cors", rules=["rule"])
    with logger.probe_ledger.unit_scope(unit):
        decision(logger)
    assert logger.probe_ledger.completion_summary(["cors"])["status"] == "COMPLETE"
    (tmp_path / missing).unlink()
    logger.probe_ledger.reconcile_persisted()
    assert logger.probe_ledger.completion_summary(["cors"])["status"] == "EVIDENCE_INCOMPLETE"


@pytest.mark.asyncio
async def test_engine_registers_the_whole_queue_before_dispatch_and_preserves_skips(tmp_path):
    engine = ScanEngine.__new__(ScanEngine)
    engine.request_logger = RequestLogger(tmp_path)
    engine.checks = ["cors", "xss"]
    engine.scanners = {"cors": SimpleNamespace(HAS_PAGE_LEVEL=True), "xss": SimpleNamespace(HAS_PAGE_LEVEL=False)}
    engine.max_forms = 5
    engine.concurrency = 1
    engine.visited_urls = {"https://t.test/unreachable"}
    engine.chain_scanner = SimpleNamespace(run=AsyncMock(return_value=[]))
    pages = [CrawledPage(url="https://t.test/a", forms=[], url_params=["q"], html="", depth=0),
             CrawledPage(url="https://t.test/b", forms=[], url_params=[], html="", depth=0)]

    async def skip_everything(*_args):
        persisted = json.loads((tmp_path / "probe_attempts_manifest.json").read_text())
        assert len(persisted["planned_units"]) == 7
    engine._phase_attack_serial = skip_everything
    await engine._phase_attack(pages, {})
    summary = engine.evidence_completion()
    assert summary["status"] == "EVIDENCE_INCOMPLETE"
    assert len(summary["checks"]["cors"]["units"]) == 4


@pytest.mark.asyncio
async def test_engine_parallel_field_callers_attribute_same_name_different_locations(tmp_path):
    engine = ScanEngine("https://t.test/", checks=["cors"], output_dir=str(tmp_path),
                        llm_provider="none", enable_adaptive_payloads=False,
                        enable_checkpoint=False, enable_component_intel=False,
                        enable_tls_scan=False, enable_payload_learning=False)

    async def scan(ip, _field):
        await asyncio.sleep(0)
        decision(engine.request_logger)
        return []
    engine.scanners = {"cors": SimpleNamespace(scan_injection_point=scan)}
    await asyncio.gather(engine._scan_field("https://t.test/", 0, {"name": "q"}, False),
                         engine._scan_field("https://t.test/", 0, {"name": "q"}, True))
    rows = [json.loads(line) for line in engine.request_logger.probe_ledger.path.read_text().splitlines()]
    assert {r["completion_unit"] for r in rows} == {
        completion_identity(unit_key("https://t.test/", "q", 0, "cors", is_url))
        for is_url in (False, True)
    }
    assert engine.evidence_completion()["status"] == "EVIDENCE_INCOMPLETE"  # field detector contract unknown
    assert len(engine.scan_matrix) == 2


def test_report_and_dashboard_reconnect_surface_completion_without_changing_findings(tmp_path):
    from wscan.monitor import MonitorServer
    from wscan.report import ReportGenerator

    completion = {"status": "EVIDENCE_INCOMPLETE", "checks": {"cors": {"status": "PARTIAL"}}}
    html = ReportGenerator(tmp_path)._build_coverage_html({"evidence_completion": completion})
    assert "Evidence completion" in html and "EVIDENCE_INCOMPLETE" in html
    monitor = MonitorServer(port=0)
    asyncio.run(monitor.emit("scan_complete", {"total_findings": 0, "status": "done",
                                              "evidence_completion": completion}))
    assert monitor.api_scan_status == "done"
    assert monitor._scan_snapshot_event()["data"]["complete"]["evidence_completion"] == completion
    dashboard = Path("templates/dashboard.html").read_text()
    assert "data.evidence_completion" in dashboard and "evidenceCompletion.status" in dashboard
