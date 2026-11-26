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
    assert scorecard.ground_truth_recall["expected_total"] == 11
    assert scorecard.ground_truth_recall["matched_total"] == 11
    assert scorecard.ground_truth_recall["recall"] == 1.0
    assert scorecard.safe_twin_precision["safe_total"] == 15
    assert scorecard.safe_twin_precision["fp_total"] == 0
    assert scorecard.safe_twin_precision["fpr"] == 0.0
    assert scorecard.total_attempts == sum(scorecard.attempt_counts.values()) > 0
    # 既知の不整合（navigate 再試行による同一 probe の再送）は理由付きで記録し、valid は偽のまま。
    known = scorecard.known_inconsistencies
    assert known, "known inconsistencies must be declared explicitly"
    for kind in known.values():
        for entry in kind.values():
            assert entry["count"] > 0 and entry["reason"].strip()
    assert scorecard.ledger_integrity["valid"] is False
    assert scorecard.overall_status == "INCOMPLETE"


def test_baseline_alone_is_not_silently_green():
    """baseline の承認が無い単体照合では、既知の不整合も FAIL として表に出る。"""
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    verdict = evaluate_normal_scan_gate(scorecard, require_baseline=False)
    assert verdict.passed is False
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0


def test_baseline_self_comparison_passes_with_warnings():
    scorecard = load_normal_scorecard_file(_BASELINE_PATH)
    # 自己照合非回帰ゲート（require_baseline=True デフォルト）。既知分は WARN として見える。
    verdict = evaluate_normal_scan_gate(scorecard, baseline=scorecard)
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.regressed_checks == ()
    assert verdict.dropped_attempt_checks == ()
    assert verdict.warnings
    assert "WARN" in verdict.describe()


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
    base = _card_with_integrity()  # 不整合なしの scorecard
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
    """HTTP 3xx 追従による二次ホップは initial カウントから除外され、count_mismatch にならない（ケース 1: 追従する 3xx）。"""
    records = [
        {
            "request_attempt_id": "prb_001",
            "attempt_id": "att_001",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_x",
            "request": {"url": "http://example.com/redirect?url=/target"},
        },
        {
            "request_attempt_id": "prb_001",
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

    # 1 回の probe 実行で 3xx リダイレクト追従（計 2 リクエスト、initial は 1 件）
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=1,
        executed_count=1,
        findings_count=0,
    )

    # redirect ホップが除外され initial_count == 1 == executed_count となり mismatch は出ない
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" not in engine.wave_errors


def test_reconcile_non_followed_3xx_no_mismatch():
    """リダイレクトを追従しない 3xx 応答エンドポイントへの複数プローブ（ケース 2: 追従しない 3xx）。

    各プローブは独立した probe_attempt_id を持ち、リダイレクトホップは発生しない。
    先行応答が 3xx であっても後続プローブがホップと誤判定されず、全件が initial として正しく計上される。
    """
    records = [
        {
            "request_attempt_id": "prb_001",
            "attempt_id": "att_001",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_1",
            "request": {"url": "http://example.com/redirect?url=/p1"},
        },
        {
            "request_attempt_id": "prb_002",
            "attempt_id": "att_002",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_2",
            "request": {"url": "http://example.com/redirect?url=/p2"},
        },
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/redirect", "url")

    # 2 回の probe 送信（追従なし、各 302 応答）
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=2,
        executed_count=2,
        findings_count=0,
    )

    # 2 件とも initial として計上され initial_count == 2 == executed_count
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" not in engine.wave_errors


def test_reconcile_detects_genuine_duplicate_send_within_same_attempt():
    """同一 probe attempt 内で 2 回の initial 送信が行われた場合（ケース 3a: 本当の二重送信）。

    同一 attempt_id / request_attempt_id でホップではないリクエストが複数ある場合、
    仮に executed_count が 2 であっても duplicate として count_mismatch が記録される。
    """
    records = [
        {
            "request_attempt_id": "prb_001",
            "attempt_id": "att_001",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_1",
            "request": {"url": "http://example.com/login"},
        },
        {
            "request_attempt_id": "prb_001",
            "attempt_id": "att_002",
            "parent_id": "",
            "rationale": "",  # ホップではなく同一 attempt 内での二重送信
            "payload_fingerprint": "fp_1",
            "request": {"url": "http://example.com/login"},
        },
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("POST", "http://example.com/login", "user")

    # executed_count=2, planned_count=2 であっても、同一 attempt 内に複数の initial があるため duplicate 検知
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=2,
        executed_count=2,
        findings_count=0,
    )

    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" in engine.wave_errors


def test_reconcile_detects_genuine_duplicate_probe_send_on_redirect_endpoint():
    """リダイレクトするエンドポイントであっても、probe が複数回 dispatch された場合は count_mismatch（ケース 3b: 本当の二重送信）。"""
    records = [
        # 1 回目 dispatch (att_001 -> att_002 redirect hop)
        {"request_attempt_id": "prb_001", "attempt_id": "att_001", "parent_id": "", "rationale": "initial"},
        {"request_attempt_id": "prb_001", "attempt_id": "att_002", "parent_id": "att_001", "rationale": "redirect_hop_from:att_001"},
        # 2 回目 dispatch（二重送信: att_003 -> att_004 redirect hop）
        {"request_attempt_id": "prb_002", "attempt_id": "att_003", "parent_id": "", "rationale": "initial"},
        {"request_attempt_id": "prb_002", "attempt_id": "att_004", "parent_id": "att_003", "rationale": "redirect_hop_from:att_003"},
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


def test_reconcile_distinct_payloads_in_sequence_on_3xx_endpoint():
    """先行リクエストが 3xx を返すエンドポイントで、異なる payload が連続送信された場合（ケース 4: 異なる payload の並び）。

    以前のヒューリスティック 3 では、先行 3xx 応答の直後のリクエストが誤って redirect hop と判定されていたが、
    probe identity 相関により各プローブが正しく個別の initial として認識される。
    """
    records = [
        # payload 1: 302 を返す
        {
            "request_attempt_id": "prb_001",
            "attempt_id": "att_001",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_payload_1",
            "request": {"url": "http://example.com/redirect?url=/a"},
        },
        # payload 2: 302 を返す
        {
            "request_attempt_id": "prb_002",
            "attempt_id": "att_002",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_payload_2",
            "request": {"url": "http://example.com/redirect?url=/b"},
        },
        # payload 3: 200 を返す
        {
            "request_attempt_id": "prb_003",
            "attempt_id": "att_003",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_payload_3",
            "request": {"url": "http://example.com/redirect?url=/c"},
        },
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/redirect", "url")

    # executed_count = 3
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=3,
        executed_count=3,
        findings_count=0,
    )

    # 3 件とも initial として正しく判定され、count_mismatch は発生しない
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" not in engine.wave_errors


def test_reconcile_redirect_chain_multiple_hops_no_mismatch():
    """リダイレクトチェーン（301 -> 302 -> 200）の複数ホップ除外（ケース 5: リダイレクトチェーン）。

    1 つの probe attempt から複数段のリダイレクトが発生しても、初期送信のみが 1 件として計上される。
    """
    records = [
        # initial request -> 301
        {
            "request_attempt_id": "prb_chain_01",
            "attempt_id": "att_hop_0",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_chain",
            "request": {"url": "http://example.com/step1"},
        },
        # 1st hop -> 302
        {
            "request_attempt_id": "prb_chain_01",
            "attempt_id": "att_hop_1",
            "parent_id": "att_hop_0",
            "rationale": "redirect_hop_from:att_hop_0",
            "payload_fingerprint": "fp_chain",
            "request": {"url": "http://example.com/step2"},
        },
        # 2nd hop -> 200
        {
            "request_attempt_id": "prb_chain_01",
            "attempt_id": "att_hop_2",
            "parent_id": "att_hop_1",
            "rationale": "redirect_hop_from:att_hop_1",
            "payload_fingerprint": "fp_chain",
            "request": {"url": "http://example.com/step3"},
        },
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/step1", "q")

    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=1,
        executed_count=1,
        findings_count=0,
    )

    # 3 リクエスト中 2 件がホップ、initial は 1 件 == executed_count(1)
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" not in engine.wave_errors


def test_xss_early_break_with_finding_deduplication_no_mismatch():
    """XSS スキャナで record_finding が重複により None を返しても、found_vuln により count_mismatch 判定されない。"""
    records = [
        {
            "request_attempt_id": "prb_xss_01",
            "attempt_id": "att_xss_01",
            "parent_id": "",
            "rationale": "",
            "payload_fingerprint": "fp_xss_1",
            "request": {"url": "http://example.com/search?q=payload1"},
        },
    ]
    engine = _MockEngine(records)
    scanner = _ReconcileTestScanner(engine)
    ip = InjectionPoint.for_url_param("GET", "http://example.com/search", "q")

    # planned=5, executed=1 で早期 break。findings リストは空だが found_vuln=True により findings_count=1 を渡す
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=5,
        executed_count=1,
        findings_count=1,
    )
    assert "probe_ledger_incomplete:test_check:standard:count_mismatch" not in engine.wave_errors

    # 逆に findings_count=0（found_vuln=False）の場合は未完了不一致（count_mismatch）が検知される
    engine.wave_errors.clear()
    scanner._reconcile_probe_ledger_wave(
        ip,
        "standard",
        planned_count=5,
        executed_count=1,
        findings_count=0,
    )
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

    # BaseScanner の相関判定で initial は 1 件、duplicate なし
    initial_count, has_dup = BaseScanner._reconcile_manifest_requests(req_events)
    assert initial_count == 1
    assert has_dup is False


@pytest.mark.asyncio
async def test_httpx_non_followed_redirect_probes_not_tagged_as_hops(tmp_path):
    """HTTPX で follow_redirects=False の場合、連続するプローブが誤って hop 扱いされない実証。"""
    import httpx
    from wscan.request_logger import RequestLogger
    from wscan.injection_point import InjectionPoint

    def mock_handler(request):
        return httpx.Response(302, headers={"Location": "http://testserver/other"})

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
            follow_redirects=False,
        ) as client:
            resp1 = await client.get("http://testserver/redir?q=p1")
            assert resp1.status_code == 302

    with logger.probe_scope(ip, "test_check", role="attack", wave="standard") as ctx:
        async with httpx.AsyncClient(
            transport=transport,
            event_hooks={
                "request": [logger.log_httpx_submission],
                "response": [logger.log_httpx_response],
            },
            follow_redirects=False,
        ) as client:
            resp2 = await client.get("http://testserver/redir?q=p2")
            assert resp2.status_code == 302

    events = list(logger.probe_ledger.events.values())
    req_events = [e for e in events if e.get("record_kind") == "request"]
    assert len(req_events) == 2

    # 各プローブは独立しており parent_id も hop タグもなし
    assert req_events[0].get("parent_id") == ""
    assert not str(req_events[0].get("rationale") or "").startswith("redirect_hop")
    assert req_events[1].get("parent_id") == ""
    assert not str(req_events[1].get("rationale") or "").startswith("redirect_hop")

    # 相関判定で 2 件とも initial、duplicate なし
    initial_count, has_dup = BaseScanner._reconcile_manifest_requests(req_events)
    assert initial_count == 2
    assert has_dup is False



# ── 既知の不整合（baseline 承認）と再送の計上 ─────────────────────────────

def _card_with_integrity(count_mismatches=(), duplicate_sends=None, known=None):
    base = load_normal_scorecard_file(_BASELINE_PATH).to_dict()
    base["ledger_integrity"]["count_mismatches"] = list(count_mismatches)
    base["ledger_integrity"]["duplicate_sends"] = dict(duplicate_sends or {})
    base["ledger_integrity"]["valid"] = not (count_mismatches or duplicate_sends)
    base["known_inconsistencies"] = known or {}
    return NormalScanScorecard.from_dict(base)


_NOTE = "probe_ledger_incomplete:ssti:standard:count_mismatch"
_KNOWN = {
    "count_mismatches": {_NOTE: {"count": 1, "reason": "navigate retry"}},
    "duplicate_sends": {"ssti": {"count": 2, "reason": "navigate retry"}},
}


def test_gate_warns_on_known_inconsistencies_at_baseline_level():
    base = _card_with_integrity([_NOTE], {"ssti": 2}, _KNOWN)
    cur = _card_with_integrity([_NOTE], {"ssti": 2})
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is True, verdict.describe()
    assert len(verdict.warnings) == 2


@pytest.mark.parametrize("mismatches,dups", [
    ([_NOTE, _NOTE], {"ssti": 2}),                     # 既知 mismatch の増加
    ([_NOTE], {"ssti": 3}),                            # 既知の再送の増加
    ([_NOTE, "probe_ledger_incomplete:sqli:standard:count_mismatch"], {"ssti": 2}),  # 新規 mismatch
    ([_NOTE], {"ssti": 2, "xss": 1}),                  # 新規 check の再送
])
def test_gate_fails_on_increase_or_new_inconsistency(mismatches, dups):
    base = _card_with_integrity([_NOTE], {"ssti": 2}, _KNOWN)
    cur = _card_with_integrity(mismatches, dups)
    verdict = evaluate_normal_scan_gate(cur, baseline=base)
    assert verdict.passed is False


def test_gate_ignores_known_entry_without_reason():
    known = {"count_mismatches": {_NOTE: {"count": 1, "reason": ""}}}
    base = _card_with_integrity([_NOTE], None, known)
    verdict = evaluate_normal_scan_gate(_card_with_integrity([_NOTE]), baseline=base)
    assert verdict.passed is False


def test_gate_uses_baseline_known_list_not_current_one():
    """現在の scorecard が自分で既知を宣言しても承認にはならない。"""
    base = _card_with_integrity()
    cur = _card_with_integrity([_NOTE], {"ssti": 2}, _KNOWN)
    assert evaluate_normal_scan_gate(cur, baseline=base).passed is False


def test_scorecard_counts_one_attempt_per_probe_identity():
    """試行数は probe identity ごとに 1 件。hop は除外、同じ probe の再送は duplicate_sends へ。"""
    def req(att, probe, rationale=""):
        return {"check": "ssti", "role": "attack", "record_kind": "request",
                "attempt_id": att, "request_attempt_id": probe, "rationale": rationale}
    records = [
        req("a1", "a1"), req("a2", "a1", "redirect_hop_from:a1"),   # 追従 hop
        req("b1", "b1"), req("b2", "b1"), req("b3", "b1"),          # navigate 再試行で 3 送信
        req("c1", ""),                                              # 旧形式（request_attempt_id 無し）
    ]
    card = build_normal_scan_scorecard(
        findings=[], expected_findings=EXPECTED_FINDINGS, safe_endpoints=SAFE_ENDPOINTS,
        target_checks=["ssti"], ledger_records=records,
    )
    assert card.attempt_counts["ssti"] == 3
    assert card.ledger_integrity["duplicate_sends"] == {"ssti": 2}
    assert card.ledger_integrity["valid"] is False
    assert NormalScanScorecard.from_dict(card.to_dict()).ledger_integrity["duplicate_sends"] == {"ssti": 2}


def test_measure_script_only_approves_documented_inconsistencies():
    from scripts.measure_normal_scan_baseline import _attach_known_inconsistencies
    card = _card_with_integrity(
        [_NOTE, "probe_ledger_incomplete:sqli:standard:count_mismatch"], {"ssti": 4, "xss": 1})
    known = _attach_known_inconsistencies(card).known_inconsistencies
    assert set(known["count_mismatches"]) == {_NOTE}
    assert set(known["duplicate_sends"]) == {"ssti"}
    assert known["duplicate_sends"]["ssti"]["count"] == 4


# ── 実際の RequestLogger と httpx での probe identity 相関 ─────────────────

async def _httpx_sends(tmp_path, handler, urls_per_scope, follow):
    import httpx
    from wscan.injection_point import InjectionPoint
    from wscan.request_logger import RequestLogger

    logger = RequestLogger(tmp_path)
    logger.enabled = True
    ip = InjectionPoint.for_url_param("GET", "http://testserver/redir", "q")
    transport = httpx.MockTransport(handler)
    for urls in urls_per_scope:
        with logger.probe_scope(ip, "test_check", role="attack", wave="standard"):
            async with httpx.AsyncClient(
                transport=transport, follow_redirects=follow,
                event_hooks={"request": [logger.log_httpx_submission],
                             "response": [logger.log_httpx_response]},
            ) as client:
                for u in urls:
                    await client.get(u)
    reqs = [e for e in logger.probe_ledger.events.values() if e.get("record_kind") == "request"]
    return reqs, BaseScanner._reconcile_manifest_requests(reqs)


def _always_302(request):
    import httpx
    return httpx.Response(302, headers={"Location": "http://testserver/other"})


def _chain(request):
    import httpx
    nxt = {"/redir": "/step2", "/step2": "/step3"}.get(request.url.path)
    if nxt:
        return httpx.Response(302, headers={"Location": f"http://testserver{nxt}"})
    return httpx.Response(200, text="ok")


@pytest.mark.asyncio
async def test_real_logger_non_followed_3xx_double_send_is_detected(tmp_path):
    """追従しない 3xx で、同じ probe から同じ payload を 2 回送ると二重送信になる（隠れない）。"""
    reqs, (initial, dup) = await _httpx_sends(
        tmp_path, _always_302, [["http://testserver/redir?q=p", "http://testserver/redir?q=p"]], False)
    assert len(reqs) == 2 and initial == 2 and dup is True


@pytest.mark.asyncio
async def test_real_logger_different_payloads_after_3xx_are_not_hops(tmp_path):
    """3xx 応答の後に別 probe の別 payload が来ても hop にも二重送信にもならない（誤警報なし）。"""
    reqs, (initial, dup) = await _httpx_sends(
        tmp_path, _always_302, [["http://testserver/redir?q=p1"], ["http://testserver/redir?q=p2"]], False)
    assert len(reqs) == 2 and initial == 2 and dup is False


@pytest.mark.asyncio
async def test_real_logger_followed_chain_counts_one_initial(tmp_path):
    reqs, (initial, dup) = await _httpx_sends(
        tmp_path, _chain, [["http://testserver/redir?q=p"]], True)
    assert len(reqs) == 3 and initial == 1 and dup is False
    assert all(str(r.get("rationale") or "").startswith("redirect_hop") for r in reqs[1:])


@pytest.mark.asyncio
async def test_real_logger_followed_3xx_double_send_is_detected(tmp_path):
    """追従する 3xx でも、同じ probe から 2 回送れば二重送信。2 回目の hop も hop として除外される。"""
    reqs, (initial, dup) = await _httpx_sends(
        tmp_path, _chain, [["http://testserver/redir?q=p", "http://testserver/redir?q=p"]], True)
    assert len(reqs) == 6 and initial == 2 and dup is True


# ── xss: 重複で record_finding が None でも、発見による早期 break を照合に渡す ──

@pytest.mark.asyncio
async def test_xss_passes_found_vuln_to_reconciliation_when_finding_deduplicated(tmp_path):
    from types import SimpleNamespace
    from unittest.mock import AsyncMock, patch
    from wscan.injection_point import InjectionPoint
    from wscan.request_logger import RequestLogger
    from wscan.scanners.xss import XSSScanner

    scanner = object.__new__(XSSScanner)
    scanner.engine = SimpleNamespace(login_url="", logged_in_marker="", max_payloads=10, sleep_factor=0.0,
                                     wave_errors=[], request_logger=RequestLogger(tmp_path), checkpoint=None)
    scanner.browser = SimpleNamespace(page=SimpleNamespace(url="http://example.com/t"), reset_dialog=lambda: None,
                                      dialog_fired=False, dialog_message="", navigate=AsyncMock(),
                                      get_page_source=AsyncMock(return_value=""))
    scanner.monitor = None
    scanner._should_route_to_api_get = lambda ip: False
    scanner._field_budget_gate = lambda: False
    scanner.may_scan_injection_point = lambda ip: True
    scanner._response_body_for = lambda url: ""
    scanner._baseline_handlers = AsyncMock(return_value=([], None, ""))
    # 1 件目で反射を検出するが、record_finding は重複として None を返す
    scanner._analyze_reflection = lambda *a: {"context": "html", "confidence": "likely", "snippet": "x"}
    scanner.record_finding = AsyncMock(return_value=None)
    scanner.log_payload_test = AsyncMock()
    scanner._apply_ip = AsyncMock(return_value=("<b>x</b>", {"response": {"status": 200}}))
    scanner._probe_decision = lambda *a, **k: None
    scanner.get_payloads = AsyncMock(return_value=["<p1>", "<p2>", "<p3>"])
    calls = []
    scanner._reconcile_probe_ledger_wave = lambda ip, wave="standard", **kw: calls.append((wave, kw))

    ip = InjectionPoint.for_form("http://example.com/t", "q", 0)
    with patch.object(scanner, "evolved_payloads", AsyncMock(return_value=[])):
        await scanner.scan_injection_point(ip, {})

    standard = [kw for wave, kw in calls if wave == "standard"]
    assert standard and standard[0]["executed_count"] == 1 and standard[0]["planned_count"] == 3
    assert standard[0]["findings_count"] == 1


# ── 送信挙動の不変（台帳の相関は記録だけで、送る数・順序・内容を変えない） ─────

@pytest.mark.asyncio
async def test_navigate_retry_sends_are_unchanged_by_default():
    """navigate の既定再試行（retries=2 → 最大 3 送信）は従来どおり。engine 設定で変えない。"""
    import inspect
    from types import SimpleNamespace
    from unittest.mock import patch
    from wscan.browser import BrowserManager

    assert inspect.signature(BrowserManager.navigate).parameters["retries"].default == 2
    assert "navigation_retries" not in inspect.signature(BrowserManager.__init__).parameters

    calls = []

    async def goto(url, **kw):
        calls.append(url)
        raise RuntimeError("net::ERR_NAME_NOT_RESOLVED")

    bm = object.__new__(BrowserManager)
    bm.page = SimpleNamespace(goto=goto)
    bm.network = SimpleNamespace(clear=lambda: None, probe_context=None)
    bm.timeout = 1000
    with patch("wscan.browser.asyncio.sleep"):
        assert await bm.navigate("http://x/redirect?next=p") is False
    assert calls == ["http://x/redirect?next=p"] * 3


@pytest.mark.asyncio
@pytest.mark.parametrize("follow", [True, False])
async def test_ledger_hooks_do_not_change_httpx_transmissions(tmp_path, follow):
    """台帳フックの有無で、transport に届く request の数・順序・URL・body が同一であること。"""
    import httpx
    from wscan.injection_point import InjectionPoint
    from wscan.request_logger import RequestLogger

    async def run(with_hooks):
        seen = []

        def handler(request):
            seen.append((request.method, str(request.url), request.content))
            return _chain(request)

        logger = RequestLogger(tmp_path / str(with_hooks))
        logger.enabled = True
        ip = InjectionPoint.for_url_param("GET", "http://testserver/redir", "q")
        hooks = ({"request": [logger.log_httpx_submission], "response": [logger.log_httpx_response]}
                 if with_hooks else {})
        for payload in ("p1", "p2"):
            with logger.probe_scope(ip, "test_check", role="attack", wave="standard"):
                async with httpx.AsyncClient(transport=httpx.MockTransport(handler),
                                             follow_redirects=follow, event_hooks=hooks) as client:
                    await client.get(f"http://testserver/redir?q={payload}")
                    await client.post("http://testserver/form", data={"q": payload})
        return seen

    assert await run(True) == await run(False)
