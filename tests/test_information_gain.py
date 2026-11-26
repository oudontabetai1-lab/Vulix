"""情報利得ランキング（純粋関数）の真理値テスト。"""
from __future__ import annotations

import math

import pytest

from wscan.information_gain import (
    HYPOTHESIS_STATE_PRIOR,
    PROBE_CLASS_MODEL,
    ProbeCandidate,
    binary_entropy,
    binary_outcome_model,
    expected_information_gain,
    hypothesis_state,
    rank_candidates,
    score_candidate,
)


def test_binary_entropy_truth_values():
    assert binary_entropy(0.5) == pytest.approx(1.0)
    assert binary_entropy(0.0) == 0.0
    assert binary_entropy(1.0) == 0.0
    assert binary_entropy(-0.2) == 0.0 and binary_entropy(1.5) == 0.0
    assert binary_entropy(float("nan")) == 0.0
    assert binary_entropy(0.25) == pytest.approx(0.8112781244591328)


def test_eig_perfect_probe_gives_prior_entropy():
    # 完全な観測は事前エントロピーをすべて消す
    assert expected_information_gain(0.5, [(1.0, 0.0), (0.0, 1.0)]) == pytest.approx(1.0)
    assert expected_information_gain(0.25, [(1.0, 0.0), (0.0, 1.0)]) == pytest.approx(binary_entropy(0.25))


def test_eig_uninformative_probe_is_zero():
    assert expected_information_gain(0.5, [(0.5, 0.5), (0.5, 0.5)]) == pytest.approx(0.0, abs=1e-12)
    assert expected_information_gain(0.3, [(0.7, 0.7), (0.3, 0.3)]) == pytest.approx(0.0, abs=1e-12)


def test_eig_matches_hand_computed_value():
    # prior=0.5, tpr=0.9, fpr=0.05 を別経路（手計算）で
    p_pos, p_neg = 0.5 * 0.9 + 0.5 * 0.05, 0.5 * 0.1 + 0.5 * 0.95
    def h(p):
        return -(p * math.log2(p) + (1 - p) * math.log2(1 - p))
    expected = 1.0 - (p_pos * h(0.45 / p_pos) + p_neg * h(0.05 / p_neg))
    assert expected_information_gain(0.5, binary_outcome_model("deterministic")) == pytest.approx(expected)
    assert 0.5 < expected < 1.0


@pytest.mark.parametrize("prior", [0.0, 1.0, -1.0, 2.0])
def test_eig_zero_when_prior_entropy_is_zero(prior):
    assert expected_information_gain(prior, binary_outcome_model("deterministic")) == 0.0


def test_eig_is_nonnegative_and_peaks_near_even_prior():
    model = binary_outcome_model("deterministic")
    values = [expected_information_gain(p / 20, model) for p in range(0, 21)]
    assert all(v >= 0 for v in values)
    assert values.index(max(values)) in (9, 10, 11)


def test_eig_rejects_invalid_models():
    with pytest.raises(ValueError):
        expected_information_gain(0.5, [])
    with pytest.raises(ValueError):
        expected_information_gain(0.5, [(0.6, 0.5), (0.5, 0.5)])  # H 側が 1 にならない
    with pytest.raises(ValueError):
        expected_information_gain(0.5, [(-0.1, 0.5), (1.1, 0.5)])


def test_eig_skips_impossible_outcomes():
    # P(o)=0 の結果があっても落ちない
    assert expected_information_gain(0.5, [(1.0, 1.0), (0.0, 0.0)]) == pytest.approx(0.0, abs=1e-12)


def test_coarse_mapping_tables_are_explicit_and_ordered():
    assert HYPOTHESIS_STATE_PRIOR == {"unverified": 0.25, "partial": 0.5, "confirmed": 0.95, "rejected": 0.05}
    assert PROBE_CLASS_MODEL == {"deterministic": (0.9, 0.05), "heuristic": (0.7, 0.2), "weak": (0.55, 0.45)}
    assert (HYPOTHESIS_STATE_PRIOR["rejected"] < HYPOTHESIS_STATE_PRIOR["unverified"]
            < HYPOTHESIS_STATE_PRIOR["partial"] < HYPOTHESIS_STATE_PRIOR["confirmed"])


@pytest.mark.parametrize("hypothesis,expected", [
    (None, "unverified"),
    ({}, "unverified"),
    ({"status": "proposed"}, "unverified"),
    ({"status": "inconclusive"}, "unverified"),
    ({"dynamic_verified": True}, "partial"),
    ({"status": "accepted"}, "partial"),
    ({"evidence_ids": ["ev-1"]}, "partial"),
    ({"deterministic_confirmed": True, "dynamic_verified": True}, "confirmed"),
    ({"status": "rejected"}, "rejected"),
])
def test_hypothesis_state_mapping(hypothesis, expected):
    assert hypothesis_state(hypothesis) == expected


def test_partial_evidence_outranks_unverified_and_confirmed():
    ranked = rank_candidates([
        ProbeCandidate("confirmed", state="confirmed", probe_class="deterministic"),
        ProbeCandidate("unverified", state="unverified", probe_class="deterministic"),
        ProbeCandidate("partial", state="partial", probe_class="deterministic"),
    ])
    assert [r.candidate_id for r in ranked] == ["partial", "unverified", "confirmed"]
    assert [r.rank for r in ranked] == [1, 2, 3]
    assert all(r.reasons for r in ranked)


def test_better_probe_class_outranks_weaker_one():
    ranked = rank_candidates([
        ProbeCandidate("weak", state="partial", probe_class="weak"),
        ProbeCandidate("det", state="partial", probe_class="deterministic"),
    ])
    assert ranked[0].candidate_id == "det"


def test_empty_candidates_returns_empty():
    assert rank_candidates([]) == []


def test_cost_zero_is_finite_and_cost_discounts_score():
    free = score_candidate(ProbeCandidate("a", state="partial", probe_class="deterministic", cost=0))[0]
    paid = score_candidate(ProbeCandidate("a", state="partial", probe_class="deterministic", cost=3))[0]
    assert math.isfinite(free) and free > 0
    assert paid == pytest.approx(free / 4)


def test_risk_one_zeroes_score_but_keeps_candidate():
    ranked = rank_candidates([
        ProbeCandidate("risky", state="partial", probe_class="deterministic", risk=1.0),
        ProbeCandidate("safe", state="unverified", probe_class="weak"),
    ])
    assert [r.candidate_id for r in ranked] == ["safe", "risky"]
    assert ranked[1].score == 0.0


def test_repeat_penalty_demotes_retried_candidate():
    ranked = rank_candidates([
        ProbeCandidate("retried", state="partial", probe_class="deterministic", repeats=2),
        ProbeCandidate("fresh", state="partial", probe_class="deterministic", repeats=0),
    ])
    assert ranked[0].candidate_id == "fresh"


def test_invalid_inputs_are_coerced_not_inflated():
    s, eig, prior, reasons = score_candidate(ProbeCandidate(
        "x", state="bogus", probe_class="bogus", cost=float("nan"), risk=float("nan"), repeats=-5))
    assert prior == HYPOTHESIS_STATE_PRIOR["unverified"]
    assert math.isfinite(s) and s >= 0
    assert "unknown_state_as_unverified" in reasons and "unknown_probe_class_as_weak" in reasons
    assert score_candidate(ProbeCandidate("y", cost=float("inf")))[0] >= 0


def test_ties_break_deterministically_by_input_order_then_id():
    same = [ProbeCandidate(i, state="partial", probe_class="deterministic") for i in ("c", "a", "b")]
    assert [r.candidate_id for r in rank_candidates(same)] == ["c", "a", "b"]  # 入力順（baseline）
    assert [r.candidate_id for r in rank_candidates(list(reversed(same)))] == ["b", "a", "c"]
    # 再実行しても同一
    assert rank_candidates(same) == rank_candidates(same)


def test_ranking_is_a_permutation_and_mandatory_block_leads():
    cands = [
        ProbeCandidate("opt-hi", state="partial", probe_class="deterministic"),
        ProbeCandidate("must-lo", state="confirmed", probe_class="weak", mandatory=True),
        ProbeCandidate("must-hi", state="partial", probe_class="deterministic", mandatory=True),
        ProbeCandidate("opt-lo", state="rejected", probe_class="weak"),
    ]
    guarded = rank_candidates(cands)
    assert sorted(r.candidate_id for r in guarded) == sorted(c.candidate_id for c in cands)
    assert [r.candidate_id for r in guarded][:2] == ["must-hi", "must-lo"]
    pure = rank_candidates(cands, mandatory_first=False)
    assert sorted(r.candidate_id for r in pure) == sorted(c.candidate_id for c in cands)
    assert pure[0].candidate_id in {"opt-hi", "must-hi"}


def test_no_information_gain_is_explained():
    r = rank_candidates([ProbeCandidate("done", state="rejected", probe_class="weak")])[0]
    assert r.eig_bits < 0.01
