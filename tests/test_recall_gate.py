"""recall_gate 純粋ロジックのユニットテスト。

ブラウザ非依存。見逃し0（recall 100%）ゲートの合否・分母の数え方・target_check 絞り込みを固定。
"""
import dataclasses

import pytest

from wscan.recall_gate import compute_recall, spec_key, RecallReport


def _spec(check, path, field="q", note="planted"):
    return {"check": check, "path": path, "field": field, "note": note}


def test_full_recall_all_matched():
    expected = [_spec("xss", "/a"), _spec("sqli", "/b")]
    reported = [("xss", "/a", "q"), ("sqli", "/b", "q")]
    r = compute_recall(expected, reported)
    assert r.recall == 1.0
    assert r.is_complete
    assert r.missed == ()


def test_false_negative_lowers_recall_and_lists_miss():
    expected = [_spec("xss", "/a"), _spec("sqli", "/b", note="blind")]
    reported = [("xss", "/a", "q")]  # /b sqli 未検出
    r = compute_recall(expected, reported)
    assert r.matched_total == 1 and r.expected_total == 2
    assert r.recall == 0.5
    assert not r.is_complete
    assert len(r.missed) == 1 and r.missed[0]["path"] == "/b"
    assert "blind" in r.describe()  # note がゲートメッセージに出る


def test_empty_expected_is_vacuously_complete():
    r = compute_recall([], [("xss", "/a", "q")])
    assert r.recall == 1.0 and r.is_complete
    assert r.expected_total == 0


def test_target_checks_filters_denominator():
    # sqli を無効化したスキャンで、sqli spec の未検出を見逃し扱いしない
    expected = [_spec("xss", "/a"), _spec("sqli", "/b")]
    reported = [("xss", "/a", "q")]
    r = compute_recall(expected, reported, target_checks=["xss"])
    assert r.expected_total == 1 and r.is_complete
    assert "sqli" not in r.by_check


def test_duplicate_keys_counted_once():
    expected = [_spec("xss", "/a", note="n1"), _spec("xss", "/a", note="n2")]
    r = compute_recall(expected, [])
    assert r.expected_total == 1  # 同一キーは分母1回


def test_extra_reported_keys_ignored_for_recall():
    # expected 外の報告（precision の話）は recall に無関係
    expected = [_spec("xss", "/a")]
    reported = [("xss", "/a", "q"), ("os", "/z", "cmd")]
    r = compute_recall(expected, reported)
    assert r.recall == 1.0


def test_by_check_breakdown():
    expected = [_spec("xss", "/a"), _spec("xss", "/b"), _spec("sqli", "/c")]
    reported = [("xss", "/a", "q")]
    r = compute_recall(expected, reported)
    assert r.by_check["xss"] == (1, 2)
    assert r.by_check["sqli"] == (0, 1)


def test_spec_key_normalizes_missing_fields():
    assert spec_key({"check": "xss", "path": "/a"}) == ("xss", "/a", "")


def test_report_is_frozen_dataclass():
    # frozen dataclass への代入は FrozenInstanceError を送出する。broad except で握りつぶすと
    # 不変性が壊れてもテストが通ってしまうため、期待例外を明示して assert する。
    r = compute_recall([_spec("xss", "/a")], [("xss", "/a", "q")])
    assert isinstance(r, RecallReport)
    with pytest.raises(dataclasses.FrozenInstanceError):
        r.matched_total = 0  # type: ignore[misc]


def test_report_is_snapshot_isolated_from_inputs():
    # 呼び出し側が元 spec を後から変更しても report は不変（snapshot 分離・P3 の失敗シナリオ）
    spec = _spec("xss", "/a", note="orig")
    expected = [spec, _spec("sqli", "/b")]
    r = compute_recall(expected, [])  # 両方 miss
    spec["note"] = "MUTATED"
    spec["check"] = "zzz"
    assert "MUTATED" not in r.describe()
    assert "orig" in r.describe()


def test_report_is_json_serializable():
    # 素の dict/tuple/str/int のみ＝dataclasses.asdict→json.dumps 可（P2: serializable 契約）
    import dataclasses
    import json

    r = compute_recall([_spec("xss", "/a"), _spec("sqli", "/b")], [("xss", "/a", "q")])
    payload = json.dumps(dataclasses.asdict(r))
    round_tripped = json.loads(payload)
    assert round_tripped["expected_total"] == 2
    assert round_tripped["matched_total"] == 1
    assert round_tripped["by_check"]["xss"] == [1, 1]  # tuple → JSON list


from wscan.recall_gate import (
    DetectionGateVerdict,
    NightlyFreshnessVerdict,
    evaluate_detection_gate,
    evaluate_nightly_freshness,
)


def test_detection_gate_passes_with_perfect_recall_report():
    report = compute_recall([_spec("xss", "/a"), _spec("sqli", "/b")], [("xss", "/a", "q"), ("sqli", "/b", "q")])
    safe_twin = {"fp": 0, "tn": 2, "total": 2, "incomplete": 0}
    verdict = evaluate_detection_gate(report, safe_twin_report=safe_twin)
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0
    assert verdict.expected_total == 2
    assert verdict.attempted_cases == 4
    assert verdict.fn == 0
    assert verdict.fp == 0
    assert "PASSED" in verdict.describe()


def test_detection_gate_rejects_empty_expected_vacuous_pass():
    # 期待値0件（または試行0件）は空虚合格として拒絶する
    report = compute_recall([], [])
    verdict = evaluate_detection_gate(report)
    assert verdict.passed is False
    assert any("expected_total == 0" in r for r in verdict.reasons)
    assert any("attempted_cases == 0" in r for r in verdict.reasons)


def test_detection_gate_rejects_fn_missed():
    report = compute_recall([_spec("xss", "/a"), _spec("sqli", "/b")], [("xss", "/a", "q")])
    safe_twin = {"fp": 0, "tn": 2, "total": 2}
    verdict = evaluate_detection_gate(report, safe_twin_report=safe_twin)
    assert verdict.passed is False
    assert verdict.fn == 1
    assert any("missed vulnerable case" in r for r in verdict.reasons)


def test_detection_gate_rejects_fp_on_safe_twin():
    report = compute_recall([_spec("xss", "/a")], [("xss", "/a", "q")])
    safe_twin = {"fp": 1, "tn": 1, "total": 2}
    verdict = evaluate_detection_gate(report, safe_twin_report=safe_twin)
    assert verdict.passed is False
    assert verdict.fp == 1
    assert any("False positive on safe twin" in r for r in verdict.reasons)


def test_detection_gate_rejects_incomplete_safe_cases():
    report = compute_recall([_spec("xss", "/a")], [("xss", "/a", "q")])
    safe_twin = {"fp": 0, "tn": 1, "total": 2, "incomplete": 1}
    verdict = evaluate_detection_gate(report, safe_twin_report=safe_twin)
    assert verdict.passed is False
    assert verdict.incomplete_cases == 1
    assert any("Incomplete measurement" in r for r in verdict.reasons)


def test_detection_gate_with_scorecard_passes():
    scorecard = {
        "overall_status": "COMPLETE",
        "case_counts": {"planned": 4, "completed": 4, "incomplete": 0},
        "metrics": {
            "confirmed": {
                "tp": 2, "fn": 0, "fp": 0, "tn": 2,
                "recall": 1.0, "precision": 1.0,
                "recall_denominator": 2, "precision_denominator": 2,
            }
        },
        "cases": [
            {"case_id": "v1", "expected": "vulnerable", "state": "completed", "classification": {"confirmed": "tp"}},
            {"case_id": "v2", "expected": "vulnerable", "state": "completed", "classification": {"confirmed": "tp"}},
            {"case_id": "s1", "expected": "safe", "state": "completed", "classification": {"confirmed": "tn"}},
            {"case_id": "s2", "expected": "safe", "state": "completed", "classification": {"confirmed": "tn"}},
        ],
    }
    verdict = evaluate_detection_gate(scorecard, tier="confirmed")
    assert verdict.passed is True
    assert verdict.reasons == ()
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0


def test_detection_gate_scorecard_rejects_dropout_states():
    scorecard = {
        "overall_status": "PARTIAL",
        "case_counts": {"planned": 2, "completed": 1, "incomplete": 1},
        "metrics": {
            "confirmed": {"tp": 1, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0, "precision": 1.0, "recall_denominator": 1}
        },
        "cases": [
            {"case_id": "v1", "expected": "vulnerable", "state": "completed"},
            {"case_id": "v2", "expected": "vulnerable", "state": "timeout"},
        ],
    }
    verdict = evaluate_detection_gate(scorecard)
    assert verdict.passed is False
    assert verdict.incomplete_cases >= 1
    assert any("Incomplete measurement" in r for r in verdict.reasons)


def test_detection_gate_scorecard_rejects_baseline_regression():
    baseline = {
        "metrics": {"confirmed": {"tp": 1, "fn": 0, "fp": 0, "tn": 1, "recall": 1.0, "precision": 1.0, "recall_denominator": 1}},
        "cases": [
            {"case_id": "v1", "classification": {"confirmed": "tp"}},
            {"case_id": "s1", "classification": {"confirmed": "tn"}},
        ],
    }
    current = {
        "overall_status": "COMPLETE",
        "case_counts": {"planned": 2, "completed": 2, "incomplete": 0},
        "metrics": {"confirmed": {"tp": 0, "fn": 1, "fp": 0, "tn": 1, "recall": 0.0, "precision": 0.0, "recall_denominator": 1}},
        "cases": [
            {"case_id": "v1", "state": "completed", "classification": {"confirmed": "fn"}},
            {"case_id": "s1", "state": "completed", "classification": {"confirmed": "tn"}},
        ],
    }
    verdict = evaluate_detection_gate(current, baseline=baseline)
    assert verdict.passed is False
    assert "v1" in verdict.regressed_cases
    assert any("Baseline case regression" in r for r in verdict.reasons)


def test_detection_gate_scorecard_rejects_removed_baseline_cases():
    baseline = {
        "metrics": {"confirmed": {"tp": 2, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0, "precision": 1.0, "recall_denominator": 2}},
        "cases": [
            {"case_id": "v1", "classification": {"confirmed": "tp"}},
            {"case_id": "v2", "classification": {"confirmed": "tp"}},
        ],
    }
    current = {
        "overall_status": "COMPLETE",
        "case_counts": {"planned": 1, "completed": 1, "incomplete": 0},
        "metrics": {"confirmed": {"tp": 1, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0, "precision": 1.0, "recall_denominator": 1}},
        "cases": [
            {"case_id": "v1", "state": "completed", "classification": {"confirmed": "tp"}},
        ],
    }
    verdict = evaluate_detection_gate(current, baseline=baseline)
    assert verdict.passed is False
    assert "v2" in verdict.removed_cases
    assert any("Baseline cases removed" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_success_and_valid():
    now_ts = 1763260000.0
    record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 42,
        "branch": "main",
        "completed_at": now_ts - 3600.0,  # 1 hour ago
    }
    verdict = evaluate_nightly_freshness(record, now_ts=now_ts)
    assert verdict.ready is True
    assert verdict.age_seconds == 3600.0
    assert verdict.reasons == ()
    assert "READY" in verdict.describe()


def test_evaluate_nightly_freshness_rejects_missing_or_invalid_record():
    verdict_none = evaluate_nightly_freshness(None, now_ts=1000.0)
    assert verdict_none.ready is False
    assert verdict_none.age_seconds is None

    verdict_str = evaluate_nightly_freshness("invalid", now_ts=1000.0)  # type: ignore[arg-type]
    assert verdict_str.ready is False


def test_evaluate_nightly_freshness_rejects_failed_conclusion():
    record = {
        "conclusion": "failure",
        "recall_complete": True,
        "attempted_total": 10,
        "branch": "main",
        "completed_at": 1000.0,
    }
    verdict = evaluate_nightly_freshness(record, now_ts=1050.0)
    assert verdict.ready is False
    assert any("conclusion is 'failure'" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_rejects_incomplete_recall():
    record = {
        "conclusion": "success",
        "recall_complete": False,
        "attempted_total": 10,
        "branch": "main",
        "completed_at": 1000.0,
    }
    verdict = evaluate_nightly_freshness(record, now_ts=1050.0)
    assert verdict.ready is False
    assert any("recall_complete is False" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_rejects_zero_attempts():
    record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 0,
        "branch": "main",
        "completed_at": 1000.0,
    }
    verdict = evaluate_nightly_freshness(record, now_ts=1050.0)
    assert verdict.ready is False
    assert any("attempted_total is 0" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_rejects_branch_mismatch():
    record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 10,
        "branch": "feature/branch",
        "completed_at": 1000.0,
    }
    verdict = evaluate_nightly_freshness(record, now_ts=1050.0, expected_branch="main")
    assert verdict.ready is False
    assert any("branch is 'feature/branch'" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_rejects_stale_record():
    now_ts = 1763260000.0
    record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 20,
        "branch": "main",
        "completed_at": now_ts - (40 * 3600),  # 40 hours ago > 36h default
    }
    verdict = evaluate_nightly_freshness(record, now_ts=now_ts)
    assert verdict.ready is False
    assert any("stale" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_rejects_future_record():
    now_ts = 1763260000.0
    record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 20,
        "branch": "main",
        "completed_at": now_ts + 3600.0,  # 1 hour in the future
    }
    verdict = evaluate_nightly_freshness(record, now_ts=now_ts)
    assert verdict.ready is False
    assert any("in the future" in r for r in verdict.reasons)


def test_evaluate_nightly_freshness_parses_iso_timestamp():
    now_ts = 1763260000.0
    iso_time = "2025-11-15T12:00:00+00:00"
    from datetime import datetime
    expected_ts = datetime.fromisoformat(iso_time).timestamp()
    record = {
        "conclusion": "success",
        "recall_complete": True,
        "attempted_total": 10,
        "branch": "main",
        "completed_at": iso_time,
    }
    verdict = evaluate_nightly_freshness(record, now_ts=expected_ts + 7200.0)
    assert verdict.ready is True
    assert verdict.age_seconds == 7200.0


def test_verdicts_are_frozen_and_json_serializable():
    import dataclasses
    import json

    gate_v = DetectionGateVerdict(passed=True, reasons=(), recall=1.0, fpr=0.0, expected_total=1, attempted_cases=1)
    with pytest.raises(dataclasses.FrozenInstanceError):
        gate_v.passed = False  # type: ignore[misc]
    gate_json = json.dumps(dataclasses.asdict(gate_v))
    assert json.loads(gate_json)["passed"] is True

    nightly_v = NightlyFreshnessVerdict(ready=True, age_seconds=120.0, reasons=())
    with pytest.raises(dataclasses.FrozenInstanceError):
        nightly_v.ready = False  # type: ignore[misc]
    nightly_json = json.dumps(dataclasses.asdict(nightly_v))
    assert json.loads(nightly_json)["ready"] is True


def test_evaluate_detection_gate_with_normal_scan_scorecard():
    from wscan.normal_scan_scorecard import load_normal_scorecard_file
    from pathlib import Path
    baseline_path = Path(__file__).resolve().parents[1] / "benchmarks" / "baselines" / "normal_scan_realistic_site.json"
    card = load_normal_scorecard_file(baseline_path)
    verdict = evaluate_detection_gate(card, baseline=card)
    assert verdict.passed is True
    assert verdict.recall == 1.0
    assert verdict.fpr == 0.0
    assert verdict.expected_total == 11
    assert verdict.attempted_cases == 4048


