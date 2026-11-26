"""情報利得ランキングの shadow 検証。実際の work 順序・必須 baseline・replay 比較を守る。"""
from __future__ import annotations

import asyncio

import pytest

from tests.benchmarks.ig_shadow_compare import compare_trace
from tests.fixtures.agent_replay import SCENARIOS, _spec, run_scenario
from wscan import information_gain
from wscan.agent_harness import AgentHarness, AgentRole, WorkStatus


def _seed(harness: AgentHarness) -> None:
    # 検証役（任意）と探索/検査（必須 baseline）を混在させる。状態の異なる仮説も置く。
    harness.enqueue(AgentRole.EXPLORER, "http://lab.test/")
    harness.enqueue(AgentRole.PROBE_SPECIALIST, "pt-a", check_type="xss")
    harness.enqueue(AgentRole.PROBE_SPECIALIST, "pt-b", check_type="sqli")
    harness.note_hypotheses([
        {"candidate_id": "h-conf", "check_type": "xss", "injection_point_id": "pt-a",
         "deterministic_confirmed": True},
        {"candidate_id": "h-part", "check_type": "sqli", "injection_point_id": "pt-b",
         "dynamic_verified": True},
        {"candidate_id": "h-new", "check_type": "xss", "injection_point_id": ""},
    ])
    for cid in ("h-conf", "h-part", "h-new"):
        harness.enqueue(AgentRole.VERIFIER, cid, check_type="xss")


def _drain(harness: AgentHarness) -> list[str]:
    order = []
    while (work := harness.next_work()) is not None:
        order.append(work.work_id)
        harness.finish_work(work.work_id, WorkStatus.COMPLETE)
    return order


def test_shadow_is_off_by_default(tmp_path):
    harness = AgentHarness(tmp_path, _spec(60))
    assert harness.information_gain_shadow is False
    _seed(harness)
    _drain(harness)
    assert not [e for e in harness.state.events if e["event_type"] == "information_gain_shadow"]


def test_shadow_does_not_change_actual_order_and_emits_events(tmp_path):
    off = AgentHarness(tmp_path / "off", _spec(60))
    on = AgentHarness(tmp_path / "on", _spec(60), information_gain_shadow=True)
    _seed(off)
    _seed(on)
    order_off, order_on = _drain(off), _drain(on)
    assert order_on == order_off and len(order_on) == 6
    events = [e for e in on.state.events if e["event_type"] == "information_gain_shadow"]
    assert len(events) == 6
    first = events[0]["details"]
    assert first["baseline_work_id"] == order_on[0] and first["candidate_count"] == 6
    assert first["ranking"] and {"id", "rank", "score", "eig_bits", "reasons"} <= set(first["ranking"][0])
    # 必須 baseline は IG 順位の先頭ブロックに残り、順序は変わらない
    assert [w.status for w in on.state.work_queue] == [w.status for w in off.state.work_queue]


def test_shadow_failure_never_breaks_scheduling(tmp_path, monkeypatch):
    harness = AgentHarness(tmp_path, _spec(60), information_gain_shadow=True)
    _seed(harness)

    def boom(*_a, **_k):
        raise RuntimeError("shadow failure")

    monkeypatch.setattr(information_gain, "rank_candidates", boom)
    assert len(_drain(harness)) == 6


def test_mandatory_baseline_always_executes_regardless_of_ig_rank(tmp_path):
    harness = AgentHarness(tmp_path, _spec(60), information_gain_shadow=True)
    _seed(harness)
    mandatory = {w.work_id for w in harness.state.work_queue if w.role != AgentRole.VERIFIER}
    cands = harness.information_gain_candidates(harness.state.work_queue)
    assert {c.candidate_id for c in cands if c.mandatory} == mandatory
    # 純 IG（ガードなし）では任意候補が必須より先になり得る → 既定のガード付き順位は必須ブロックが先頭
    guarded = [r.candidate_id for r in information_gain.rank_candidates(cands)]
    assert set(guarded[: len(mandatory)]) == mandatory
    executed = set(_drain(harness))
    assert mandatory <= executed


def test_queue_state_to_ig_rank_is_meaningful(tmp_path):
    harness = AgentHarness(tmp_path, _spec(60))
    _seed(harness)
    verifiers = [w for w in harness.state.work_queue if w.role == AgentRole.VERIFIER]
    ranked = information_gain.rank_candidates(harness.information_gain_candidates(verifiers), mandatory_first=False)
    by_target = {w.work_id: w.target for w in verifiers}
    # 部分的証拠 > 未検証 > 確証済み（確証済みを再 probe しても得る情報は小さい）
    assert [by_target[r.candidate_id] for r in ranked] == ["h-part", "h-new", "h-conf"]


@pytest.fixture(scope="module")
def shadow_results(tmp_path_factory):
    base = tmp_path_factory.mktemp("ig-replay")

    async def main():
        return [await run_scenario(sc, base / sc["name"], information_gain_shadow=True) for sc in SCENARIOS]

    return asyncio.run(main())


def test_replay_ig_is_no_worse_than_fifo_and_keeps_coverage(shadow_results):
    """同じシナリオ・同じ step budget で FIFO と IG の仮想順序を比べる（shadow）。"""
    compared = 0
    for scenario, result in zip(SCENARIOS, shadow_results):
        assert result["safe_twin_fp"] == 0 and result["unexpected_findings"] == 0
        budget = scenario.get("max_steps", 60)
        rows = compare_trace(result["work_trace"], budget=budget)
        for fifo, ig in zip(rows["fifo"], rows["ig"]):
            compared += 1
            # 必須 baseline は ranking に関係なく予算内で必ず覆われる
            assert ig["mandatory_covered_in_budget"] and fifo["mandatory_covered_in_budget"]
            # 同じ work 集合なので確証数は順序に依らない（FP も同値）
            assert ig["confirmed"] == fifo["confirmed"]
            if fifo["first_confirm_step"] is not None:
                assert ig["first_confirm_step"] is not None
                assert ig["first_confirm_step"] <= fifo["first_confirm_step"]
    assert compared >= 10  # 比較対象が空でないこと


def test_compare_trace_detects_an_improvement_when_state_differs():
    """状態が違えば IG が FIFO より早く確証へ到達することを comparator が検出できる。"""
    batch = {
        "candidates": [
            information_gain.ProbeCandidate("a", state="unverified", probe_class="deterministic"),
            information_gain.ProbeCandidate("b", state="partial", probe_class="deterministic"),
            information_gain.ProbeCandidate("c", state="unverified", probe_class="deterministic"),
        ],
        "results": {"a": 0, "b": 2, "c": 0},
    }
    rows = compare_trace([batch])
    assert rows["fifo"][0]["first_confirm_step"] == 2
    assert rows["ig"][0]["first_confirm_step"] == 1
    assert rows["ig"][0]["confirmed"] == rows["fifo"][0]["confirmed"] == 1


def test_replay_with_shadow_matches_gate_inputs_without_shadow(shadow_results, tmp_path):
    """shadow を入れても recall/FP/scope 逸脱などの測定値は変わらない。"""
    plain = asyncio.run(run_scenario(SCENARIOS[0], tmp_path / "plain"))
    shadowed = next(r for r in shadow_results if r["scenario"] == SCENARIOS[0]["name"])
    for key in ("recalled", "ground_truth_total", "safe_twin_fp", "scope_violations", "probes_sent",
                "harness_status", "hypotheses_dropped"):
        assert shadowed[key] == plain[key]
    assert len(plain["work_statuses"]) == len(shadowed["work_statuses"])
