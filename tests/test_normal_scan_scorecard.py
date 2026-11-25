"""通常スキャンの検出非回帰ゲートのユニットテスト。

テスト対象:
1. baseline スコアカードの正常 PASS（自己照合および閾値判定）。
2. 違反注入 1: Recall の低下（見逃し・偽陰性）。
3. 違反注入 2: Safe twin の誤検知（偽陽性 FP）。
4. 違反注入 3: Attempt 数の黙った減少（silent payload reduction＝偽陰性）。
5. 違反注入 4: Probe ledger の不整合（write_error / count_mismatch / quarantine）。
6. 未計測・空虚合格の拒絶（None は合格扱いしない）。
7. スコアカード構築（build_normal_scan_scorecard）の純粋性・直列化ラウンドトリップ。
8. 永続化（load_normal_scorecard_file / save_normal_scorecard_file）。
"""
from __future__ import annotations

import json
from pathlib import Path
import pytest

from tests.fixtures.realistic_site import EXPECTED_FINDINGS, SAFE_ENDPOINTS
from wscan.normal_scan_scorecard import (
    NormalScanGateVerdict,
    NormalScanScorecard,
    build_normal_scan_scorecard,
    evaluate_normal_scan_gate,
    load_normal_scorecard_file,
    save_normal_scorecard_file,
)
from wscan.probe_ledger import ProbeAttemptRecord, ProbeOutcome, ProbeRole

_BASELINE_PATH = Path(__file__).resolve().parents[1] / "benchmarks" / "baselines" / "normal_scan_realistic_site.json"


def _make_dummy_finding(check: str, path: str, field: str, verified: bool = True):
    return {
        "check": check,
        "path": path,
        "field": field,
        "verified": verified,
    }


def _make_dummy_records(check: str, count: int, outcome: str = "no_match", role: str = "attack"):
    records = []
    for i in range(count):
        records.append({
            "check": check,
            "role": role,
            "outcome": outcome,
            "record_kind": "request",
        })
        records.append({
            "check": check,
            "role": role,
            "outcome": outcome,
            "record_kind": "decision",
        })
    return records


# ── 1. Baseline 正常検証 ───────────────────────────────────────────────────

def test_checked_in_baseline_file_exists_and_loads():
    assert _BASELINE_PATH.is_file(), f"Baseline file missing at {_BASELINE_PATH}"
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    assert isinstance(scorecard, NormalScanScorecard)
    assert scorecard.mode == "normal"
    assert scorecard.fixture_id == "realistic_site"
    assert scorecard.overall_status == "COMPLETE"
    assert scorecard.ground_truth_recall["expected_total"] == 11
    assert scorecard.ground_truth_recall["matched_total"] == 11
    assert scorecard.ground_truth_recall["recall"] == 1.0
    assert scorecard.safe_twin_precision["safe_total"] == 15
    assert scorecard.safe_twin_precision["fp_total"] == 0
    assert scorecard.safe_twin_precision["fpr"] == 0.0
    assert scorecard.total_attempts == 222
    assert scorecard.ledger_integrity["valid"] is True


def test_baseline_passes_detection_gate():
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    verdict = evaluate_normal_scan_gate(scorecard)
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0
    assert verdict.total_attempts == 222
    assert "PASSED" in verdict.describe()


def test_baseline_self_comparison_passes():
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    verdict = evaluate_normal_scan_gate(scorecard, baseline=scorecard)
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.regressed_checks == ()
    assert verdict.dropped_attempt_checks == ()


# ── 2. 違反注入 1: Recall の低下（見逃し・偽陰性） ──────────────────────────

def test_gate_rejects_recall_drop_against_ground_truth():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    # sqli の 1 件を見逃し扱いにする
    data["ground_truth_recall"]["matched_total"] = 10
    data["ground_truth_recall"]["recall"] = 10 / 11
    data["ground_truth_recall"]["missed"] = [{"check": "sqli", "path": "/products", "field": "category", "note": "error-based"}]
    data["ground_truth_recall"]["by_check"]["sqli"]["matched"] = 1
    data["ground_truth_recall"]["by_check"]["sqli"]["recall"] = 0.5
    data["overall_status"] = "FAILED"

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("False negative regression" in r or "Recall dropped" in r for r in verdict.reasons)
    assert "sqli" in verdict.regressed_checks
    assert "FAILED" in verdict.describe()


def test_gate_rejects_check_level_recall_drop_even_if_total_holds():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    # 特定 check（ssti）の recall が低下
    data["ground_truth_recall"]["by_check"]["ssti"]["matched"] = 0
    data["ground_truth_recall"]["by_check"]["ssti"]["recall"] = 0.0
    data["ground_truth_recall"]["missed"] = [{"check": "ssti", "path": "/greeting", "field": "name", "note": "template"}]

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("Recall dropped for check 'ssti'" in r for r in verdict.reasons)
    assert "ssti" in verdict.regressed_checks


# ── 3. 違反注入 2: Safe twin の誤検知（偽陽性 FP） ─────────────────────────

def test_gate_rejects_safe_twin_false_positive():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    # /help の安全入力で誤検知が発生
    data["safe_twin_precision"]["fp_total"] = 1
    data["safe_twin_precision"]["tn_total"] = 14
    data["safe_twin_precision"]["fpr"] = 1 / 15
    data["safe_twin_precision"]["false_positives"] = [{
        "path": "/help",
        "field": "query",
        "note": "search term HTML-escaped",
        "findings": [{"check": "xss", "path": "/help", "field": "query"}],
    }]
    data["overall_status"] = "FAILED"

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("False positive on safe twin" in r for r in verdict.reasons)
    assert len(verdict.false_positives) == 1
    assert verdict.false_positives[0]["path"] == "/help"


def test_gate_rejects_safe_twin_fp_increase_over_baseline():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["safe_twin_precision"]["fp_total"] = 2
    data["safe_twin_precision"]["fpr"] = 2 / 15

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("False positive on safe twin" in r for r in verdict.reasons)


# ── 4. 違反注入 3: Attempt 数の黙った減少（silent payload reduction） ───────

def test_gate_rejects_check_attempt_drop_silent_reduction():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    # sqli の attempt 数が 54 から 30 に黙って減少（recall 1.0 を維持していても失格）
    data["attempt_counts"]["sqli"] = 30
    data["total_attempts"] = base.total_attempts - 24

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert "sqli" in verdict.dropped_attempt_checks
    assert any("Attempt count dropped for check 'sqli'" in r for r in verdict.reasons)
    assert any("silent payload reduction = false negative" in r for r in verdict.reasons)


def test_gate_rejects_total_attempt_drop_even_if_individual_unflagged():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["total_attempts"] = base.total_attempts - 10

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("Total probe attempt count dropped vs baseline" in r for r in verdict.reasons)


# ── 5. 違反注入 4: Probe ledger の不整合 ────────────────────────────────────

def test_gate_rejects_ledger_write_error_or_quarantine():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["ledger_integrity"]["had_write_error"] = True
    data["ledger_integrity"]["valid"] = False
    data["overall_status"] = "INCOMPLETE"

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("write error or quarantine" in r for r in verdict.reasons)
    assert "ledger_write_error_or_quarantined" in verdict.ledger_violations


def test_gate_rejects_ledger_count_mismatch():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    mismatch_note = "probe_ledger_incomplete:sqli:standard:count_mismatch"
    data["ledger_integrity"]["count_mismatches"] = [mismatch_note]
    data["ledger_integrity"]["valid"] = False
    data["overall_status"] = "INCOMPLETE"

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("Probe ledger count mismatch" in r for r in verdict.reasons)
    assert mismatch_note in verdict.ledger_violations


def test_gate_rejects_ledger_gap():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    gap_note = "completion_plan_not_persisted"
    data["ledger_integrity"]["gaps"] = [gap_note]
    data["ledger_integrity"]["valid"] = False

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any(gap_note in r for r in verdict.reasons)


# ── 6. 未計測・空虚合格の拒絶（None は合格扱いしない） ───────────────────────

def test_gate_rejects_empty_ground_truth_vacuous_pass():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["ground_truth_recall"]["expected_total"] = 0
    data["ground_truth_recall"]["recall"] = None

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, allow_vacuous=False)
    assert verdict.passed is False
    assert any("Empty expected ground truth: recall is None" in r for r in verdict.reasons)


def test_gate_rejects_empty_safe_twin_unmeasured():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["safe_twin_precision"]["safe_total"] = 0
    data["safe_twin_precision"]["fpr"] = None

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur)
    assert verdict.passed is False
    assert any("Empty safe twin ground truth: fpr is None" in r for r in verdict.reasons)


def test_gate_rejects_zero_attempts():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["total_attempts"] = 0

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur)
    assert verdict.passed is False
    assert any("Zero probe attempts executed" in r for r in verdict.reasons)


def test_gate_rejects_unmeasured_checks():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["unmeasured_checks"] = ["open_redirect"]

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur)
    assert verdict.passed is False
    assert any("Unmeasured target checks present: open_redirect" in r for r in verdict.reasons)


# ── 7. build_normal_scan_scorecard の検証 ───────────────────────────────────

def test_build_normal_scan_scorecard_nominal_match():
    # EXPECTED_FINDINGS の全11件を模した Findings
    findings = [
        _make_dummy_finding(spec["check"], spec["path"], spec["field"])
        for spec in EXPECTED_FINDINGS
    ]
    # 各 check のダミー ledger レコード
    ledger_records = []
    checks = ["header_injection", "open_redirect", "path_traversal", "sqli", "ssti", "xss"]
    for ch in checks:
        ledger_records.extend(_make_dummy_records(ch, 10))

    scorecard = build_normal_scan_scorecard(
        findings=findings,
        expected_findings=EXPECTED_FINDINGS,
        safe_endpoints=SAFE_ENDPOINTS,
        target_checks=checks,
        ledger_records=ledger_records,
    )

    assert scorecard.overall_status == "COMPLETE"
    assert scorecard.ground_truth_recall["recall"] == 1.0
    assert scorecard.ground_truth_recall["matched_total"] == 11
    assert scorecard.ground_truth_recall["expected_total"] == 11
    assert scorecard.safe_twin_precision["fp_total"] == 0
    assert scorecard.safe_twin_precision["fpr"] == 0.0
    assert scorecard.safe_twin_precision["safe_total"] == 15
    assert scorecard.total_attempts == 60
    assert scorecard.ledger_integrity["valid"] is True


def test_build_normal_scan_scorecard_detects_wave_errors_and_mismatches():
    findings = [_make_dummy_finding(spec["check"], spec["path"], spec["field"]) for spec in EXPECTED_FINDINGS]
    wave_errors = ["probe_ledger_incomplete:sqli:standard:count_mismatch"]

    scorecard = build_normal_scan_scorecard(
        findings=findings,
        expected_findings=EXPECTED_FINDINGS,
        safe_endpoints=SAFE_ENDPOINTS,
        target_checks=["sqli"],
        wave_errors=wave_errors,
    )

    assert scorecard.overall_status == "INCOMPLETE"
    assert scorecard.ledger_integrity["valid"] is False
    assert len(scorecard.ledger_integrity["count_mismatches"]) == 1


# ── 8. 永続化とラウンドトリップ ──────────────────────────────────────────────

def test_scorecard_save_and_load_round_trip(tmp_path):
    orig = load_normal_scorecard_file(_BASELINE_PATH)
    out_file = tmp_path / "saved_scorecard.json"
    save_normal_scorecard_file(orig, out_file)

    loaded = load_normal_scorecard_file(out_file)
    assert loaded == orig
    assert loaded.to_dict() == orig.to_dict()
