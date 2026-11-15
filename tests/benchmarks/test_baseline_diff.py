"""benchmark scorecard の baseline 差分の純粋テスト。

main baseline との差分（追加/消失/回帰/改善）を case 単位で検出できることを固定する。
精度の回帰（TP→FN 等）と measurement の欠落（分類 None）を混同しないことも確認する。
"""
import pytest

from wscan.benchmark_model import compute_baseline_diff


def _card(cases):
    # scorecard の必要部分だけを持つ最小 dict（cases: [{case_id, classification:{candidate,confirmed}}]）
    return {"cases": cases}


def _case(case_id, candidate=None, confirmed=None):
    return {
        "case_id": case_id,
        "classification": {"candidate": candidate, "confirmed": confirmed},
    }


def test_new_and_removed_cases():
    current = _card([_case("a", "tp"), _case("b", "tp")])
    baseline = _card([_case("a", "tp"), _case("c", "tp")])
    diff = compute_baseline_diff(current, baseline)
    assert diff["new"] == ["b"]
    assert diff["removed"] == ["c"]
    assert diff["regressed"] == [] and diff["improved"] == []


def test_regressed_detects_tp_to_fn_and_tn_to_fp():
    baseline = _card([_case("v", "tp"), _case("s", "tn")])
    current = _card([_case("v", "fn"), _case("s", "fp")])  # 取りこぼし・誤検知に悪化
    diff = compute_baseline_diff(current, baseline)
    assert diff["regressed"] == ["s", "v"]
    assert diff["improved"] == []


def test_improved_detects_fn_to_tp_and_fp_to_tn():
    baseline = _card([_case("v", "fn"), _case("s", "fp")])
    current = _card([_case("v", "tp"), _case("s", "tn")])
    diff = compute_baseline_diff(current, baseline)
    assert diff["improved"] == ["s", "v"]
    assert diff["regressed"] == []


def test_measurement_dropout_is_not_a_regression():
    # baseline は TP、current は未完了（分類 None）＝measurement 欠落。精度回帰に数えない。
    baseline = _card([_case("v", "tp")])
    current = _card([_case("v", None)])
    diff = compute_baseline_diff(current, baseline)
    assert diff["regressed"] == [] and diff["improved"] == []


def test_confirmed_tier_compared_independently():
    baseline = _card([_case("v", candidate="tp", confirmed="tp")])
    current = _card([_case("v", candidate="tp", confirmed="fn")])  # confirmed だけ悪化
    assert compute_baseline_diff(current, baseline, tier="candidate")["regressed"] == []
    assert compute_baseline_diff(current, baseline, tier="confirmed")["regressed"] == ["v"]


def test_invalid_tier_rejected():
    with pytest.raises(ValueError):
        compute_baseline_diff(_card([]), _card([]), tier="bogus")


def test_empty_scorecards_have_empty_diff():
    diff = compute_baseline_diff({}, {})
    assert diff == {"new": [], "removed": [], "regressed": [], "improved": []}


def test_detection_gate_integration_with_baseline_diff():
    from wscan.recall_gate import evaluate_detection_gate

    baseline = {
        "metrics": {"confirmed": {"tp": 2, "fn": 0, "fp": 0, "tn": 0, "recall": 1.0, "precision": 1.0, "recall_denominator": 2}},
        "cases": [_case("v1", confirmed="tp"), _case("v2", confirmed="tp")],
    }
    # v1 regressed to fn
    current = {
        "case_counts": {"planned": 2, "completed": 2, "incomplete": 0},
        "metrics": {"confirmed": {"tp": 1, "fn": 1, "fp": 0, "tn": 0, "recall": 0.5, "precision": 1.0, "recall_denominator": 2}},
        "cases": [
            {"case_id": "v1", "state": "completed", "classification": {"confirmed": "fn"}},
            {"case_id": "v2", "state": "completed", "classification": {"confirmed": "tp"}},
        ],
    }
    verdict = evaluate_detection_gate(current, baseline=baseline, tier="confirmed")
    assert verdict.passed is False
    assert "v1" in verdict.regressed_cases
    assert any("Baseline case regression" in r for r in verdict.reasons)

