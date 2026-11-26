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
    assert scorecard.total_attempts == 4056
    assert scorecard.ledger_integrity["valid"] is True


def test_baseline_passes_detection_gate():
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    # 基準スコアカード単体の整合性検証（require_baseline=False）
    verdict = evaluate_normal_scan_gate(scorecard, require_baseline=False)
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0
    assert "PASSED" in verdict.describe()


def test_baseline_self_comparison_passes():
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    # 自己照合非回帰ゲート（require_baseline=True デフォルト）
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


def test_gate_rejects_manifest_gaps_mapping_through_builder():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    findings = [_make_dummy_finding(spec["check"], spec["path"], spec["field"]) for spec in EXPECTED_FINDINGS]
    checks = ["header_injection", "open_redirect", "path_traversal", "sqli", "ssti", "xss"]
    ledger_records = []
    for ch in checks:
        ledger_records.extend(_make_dummy_records(ch, 10))

    manifest = {
        "had_write_error": False,
        "quarantined": False,
        "write_errors": [{"error": "manifest_gap_detected", "role": "", "outcome": "gap"}],
    }
    scorecard = build_normal_scan_scorecard(
        findings=findings,
        expected_findings=EXPECTED_FINDINGS,
        safe_endpoints=SAFE_ENDPOINTS,
        target_checks=checks,
        ledger_records=ledger_records,
        ledger_manifest=manifest,
    )
    assert scorecard.ledger_integrity["valid"] is False
    assert "manifest_gap_detected" in scorecard.ledger_integrity["gaps"]

    verdict = evaluate_normal_scan_gate(scorecard, baseline=base)
    assert verdict.passed is False
    assert any("manifest_gap_detected" in r for r in verdict.reasons)


def test_gate_rejects_manifest_gaps_object_through_builder():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    findings = [_make_dummy_finding(spec["check"], spec["path"], spec["field"]) for spec in EXPECTED_FINDINGS]
    checks = ["header_injection", "open_redirect", "path_traversal", "sqli", "ssti", "xss"]
    ledger_records = []
    for ch in checks:
        ledger_records.extend(_make_dummy_records(ch, 10))

    class FakeManifestObj:
        had_write_error = False
        quarantined = False
        gaps = ["obj_gap_marker"]

    scorecard = build_normal_scan_scorecard(
        findings=findings,
        expected_findings=EXPECTED_FINDINGS,
        safe_endpoints=SAFE_ENDPOINTS,
        target_checks=checks,
        ledger_records=ledger_records,
        ledger_manifest=FakeManifestObj(),
    )
    assert scorecard.ledger_integrity["valid"] is False
    assert "obj_gap_marker" in scorecard.ledger_integrity["gaps"]

    verdict = evaluate_normal_scan_gate(scorecard, baseline=base)
    assert verdict.passed is False
    assert any("obj_gap_marker" in r for r in verdict.reasons)


def test_gate_rejects_planned_probes_deficit():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    findings = [_make_dummy_finding(spec["check"], spec["path"], spec["field"]) for spec in EXPECTED_FINDINGS]
    checks = ["header_injection", "open_redirect", "path_traversal", "sqli", "ssti", "xss"]
    ledger_records = []
    for ch in checks:
        ledger_records.extend(_make_dummy_records(ch, 10))

    # planned が 50 なのに 10 試行しか実行されていない
    scorecard = build_normal_scan_scorecard(
        findings=findings,
        expected_findings=EXPECTED_FINDINGS,
        safe_endpoints=SAFE_ENDPOINTS,
        target_checks=checks,
        ledger_records=ledger_records,
        planned_probes={"sqli": 50},
    )
    assert scorecard.ledger_integrity["valid"] is False
    assert len(scorecard.ledger_integrity["planned_deficits"]) > 0

    verdict = evaluate_normal_scan_gate(scorecard, baseline=base)
    assert verdict.passed is False
    assert any("Planned probes exceeded executed" in r or "planned probes deficit" in r.lower() for r in verdict.reasons)


def test_gate_rejects_tampered_valid_true_when_write_error_exists():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["ledger_integrity"]["had_write_error"] = True
    data["ledger_integrity"]["valid"] = True  # 改ざんされたフラグ

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("corruption" in r.lower() or "write error" in r.lower() for r in verdict.reasons)


def test_gate_rejects_tampered_valid_true_when_gaps_exist():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["ledger_integrity"]["gaps"] = ["hidden_gap"]
    data["ledger_integrity"]["valid"] = True  # 改ざんされたフラグ

    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False
    assert any("hidden_gap" in r or "corruption" in r.lower() for r in verdict.reasons)


# ── 6. 未計測・空虚合格の拒絶（None は合格扱いしない） ───────────────────────

def test_gate_rejects_missing_baseline_by_default():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    verdict = evaluate_normal_scan_gate(base)
    assert verdict.passed is False
    assert any("Missing baseline scorecard" in r for r in verdict.reasons)


def test_gate_allows_standalone_when_baseline_not_required():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    verdict = evaluate_normal_scan_gate(base, require_baseline=False)
    assert verdict.passed is True


def test_unmeasured_check_when_expected_gt_zero_and_attempts_zero():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    findings = [_make_dummy_finding(spec["check"], spec["path"], spec["field"]) for spec in EXPECTED_FINDINGS]
    checks = ["header_injection", "open_redirect", "path_traversal", "sqli", "ssti", "xss"]
    ledger_records = []
    # xss 以外の 5 check だけ試行を実行（xss は 0 attempt）
    for ch in checks:
        if ch != "xss":
            ledger_records.extend(_make_dummy_records(ch, 10))

    card = build_normal_scan_scorecard(
        findings=findings,
        expected_findings=EXPECTED_FINDINGS,
        safe_endpoints=SAFE_ENDPOINTS,
        target_checks=checks,
        ledger_records=ledger_records,
    )
    assert "xss" in card.unmeasured_checks
    assert card.ground_truth_recall["by_check"]["xss"]["recall"] is None
    assert card.overall_status == "INCOMPLETE"

    verdict = evaluate_normal_scan_gate(card, baseline=base)
    assert verdict.passed is False
    assert any("Unmeasured target checks present: xss" in r for r in verdict.reasons)


def test_gate_rejects_unmeasured_check_even_with_allow_vacuous():
    base = load_normal_scorecard_file(_BASELINE_PATH)
    data = base.to_dict()
    data["unmeasured_checks"] = ["sqli"]
    cur = NormalScanScorecard.from_dict(data)
    verdict = evaluate_normal_scan_gate(cur, baseline=base, allow_vacuous=True)
    assert verdict.passed is False
    assert any("Unmeasured target checks present: sqli" in r for r in verdict.reasons)

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


# ── 9. Redirect ホップ除外と本当の二重送信（二重送信検知）の照合 ─────────────

from wscan.scanners.base import BaseScanner
from wscan.injection_point import InjectionPoint


class _ReconcileTestScanner(BaseScanner):
    CHECK_TYPE = "test_check"

    def __init__(self, engine):
        super().__init__(engine)

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []


class _MockLedger:
    def __init__(self, records, events=None):
        self._records = records
        self.events = events or {}
        self.enabled = True
        self.quarantined = False
        self.manifest = type("Manifest", (), {"had_write_error": False})()

    def current_unit(self):
        return "unit_test"

    def wave_records(self, **kwargs):
        return list(self._records)


class _MockEngine:
    def __init__(self, records, events=None):
        self.wave_errors = []
        self.monitor = None
        self.payload_gen = None
        mock_ledger = _MockLedger(records, events)
        self.request_logger = type("Logger", (), {"probe_ledger": mock_ledger})()


def test_reconcile_excludes_redirect_hop_no_mismatch():
    """HTTP 3xx 追従による二次ホップは initial カウントから除外され、count_mismatch にならない。"""
    records = [
        {
            "attempt_id": "att_001",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_x",
            "request": {"url": "http://example.com/redirect?url=/target"},
        },
        {
            "attempt_id": "att_002",
            "parent_id": "att_001",
            "rationale": "redirect_hop_from:att_001",
            "payload_fingerprint": "fp_x",
            "request": {"url": "http://example.com/target"},
        },
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/redirect", "url")

    # 1 回の probe 実行で 3xx リダイレクト追従（計 2 リクエスト）
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=1,
        executed_count=1,
        findings_count=0,
    )

    # redirect ホップが除外され manifest_count == 1 == executed_count となり mismatch は出ない
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" not in engine.wave_errors


def test_reconcile_detects_genuine_duplicate_probe_send_same_payload():
    """同一 payload であっても本当の二重送信（複数回 dispatch）は除外されず count_mismatch が記録される。"""
    records = [
        {
            "attempt_id": "att_001",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_same",
            "request": {"url": "http://example.com/search?q=test"},
        },
        {
            "attempt_id": "att_002",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_same",
            "request": {"url": "http://example.com/search?q=test"},
        },
    ]
    # 先行リクエスト att_001 の観測応答は 200 OK（3xx ではない）
    events = {
        "obs_001": {
            "record_kind": "observation",
            "request_attempt_id": "att_001",
            "response": {"status": 200},
        },
        "obs_002": {
            "record_kind": "observation",
            "request_attempt_id": "att_002",
            "response": {"status": 200},
        },
    }
    engine = _MockEngine(records, events)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/search", "q")

    # executed_count=1 なのに 2 回送信されている
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=1,
        executed_count=1,
        findings_count=0,
    )

    # payload_fingerprint が同じでも、redirect ホップではないため 2 件とも initial として残る
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" in engine.wave_errors


def test_reconcile_detects_genuine_duplicate_probe_send_on_redirect_endpoint():
    """リダイレクトするエンドポイントであっても、probe が二重送信された場合は count_mismatch が記録される。"""
    records = [
        # 1 回目 dispatch (att_001 -> att_002 redirect hop)
        {"attempt_id": "att_001", "parent_id": "", "rationale": "initial"},
        {"attempt_id": "att_002", "parent_id": "att_001", "rationale": "redirect_hop_from:att_001"},
        # 2 回目 dispatch（二重送信: att_003 -> att_004 redirect hop）
        {"attempt_id": "att_003", "parent_id": "", "rationale": "initial"},
        {"attempt_id": "att_004", "parent_id": "att_003", "rationale": "redirect_hop_from:att_003"},
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/redirect", "url")

    # executed_count=1 なのに 2 回 dispatch された（initial が att_001 と att_003 の 2 件）
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=1,
        executed_count=1,
        findings_count=0,
    )

    # 4 リクエスト中 2 リクエストが redirect ホップ、initial は 2 件 != executed_count(1)
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" in engine.wave_errors


@pytest.mark.asyncio
async def test_httpx_redirect_hops_tagged_in_request_logger(tmp_path):
    """HTTPX が 3xx リダイレクトを追従した際、二次リクエストに redirect_hop が正しくタグ付けされることの実証。"""
    import httpx
    from wscan.request_logger import RequestLogger
    from wscan.injection_point import InjectionPoint

    def mock_handler(request):
        if request.url.path == "/redir":
            return httpx.Response(302, headers={"Location": "http://testserver/final"})
        return httpx.Response(200, text="reached target")

    transport = httpx.MockTransport(mock_handler)
    logger = RequestLogger(tmp_path)
    logger.enabled = True
    ip = InjectionPoint.for_url_param("GET", "http://testserver/redir", "q")

    with logger.probe_scope(ip, "test_check", role="attack", wave="standard") as ctx:
        async with httpx.AsyncClient(
            transport=transport,
            event_hooks={
                "request": [logger.log_httpx_submission],
                "response": [logger.log_httpx_response],
            },
            follow_redirects=True,
        ) as client:
            resp = await client.get("http://testserver/redir?q=payload")
            assert resp.status_code == 200

    # probe_ledger に記録された request イベントの確認
    events = list(logger.probe_ledger.events.values())
    req_events = [e for e in events if e.get("record_kind") == "request"]
    assert len(req_events) == 2

    first_req, second_req = req_events[0], req_events[1]
    # 1 回目: initial request
    assert first_req.get("parent_id") == ""
    assert not str(first_req.get("rationale") or "").startswith("redirect_hop")

    # 2 回目: redirect hop (1 回目を親とし、rationale に redirect_hop が刻まれる)
    assert second_req.get("parent_id") == first_req.get("attempt_id")
    assert str(second_req.get("rationale") or "").startswith("redirect_hop_from:")

    # BaseScanner の判定ロジックで初回のみが抽出されることを確認
    initial_reqs = [
        r for r in req_events
        if not BaseScanner._is_redirect_hop_request(r, req_events, logger.probe_ledger)
    ]
    assert len(initial_reqs) == 1
    assert initial_reqs[0] is first_req

