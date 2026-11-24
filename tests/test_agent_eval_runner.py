from __future__ import annotations

import json

import pytest

from tests.fixtures.agent_lab_app import EXPECTED_FINDINGS, SAFE_ENDPOINTS
from wscan.agent_eval_gate import AgentEvalThresholds, GateVerdictKind, evaluate_agent_eval_gate
from wscan.agent_eval_model import AgentRunMetrics
from wscan.agent_eval_runner import run_agent_eval, write_eval_artifacts


class FakeAgent:
    async def run_episode(self, *, profile, seed, budget, **_kwargs):
        assert profile in {"standard", "candidate"}
        assert isinstance(seed, int) and budget["max_steps"] == 30
        # Lab ground truth is data, not live site content; findings/evidence never enter artifacts.
        return AgentRunMetrics(
            total_items=len(EXPECTED_FINDINGS), covered_items=len(EXPECTED_FINDINGS),
            coverage_rate=1.0, ground_truth_total=len(EXPECTED_FINDINGS), recalled_findings=len(EXPECTED_FINDINGS),
            recall=1.0 if profile == "standard" else 0.0, safe_twin_total=len(SAFE_ENDPOINTS),
            safe_twin_fp=0, safe_twin_fpr=0.0, steps_consumed=10, step_budget=budget["max_steps"],
            input_tokens=0, output_tokens=0, total_tokens=0, llm_calls=0, duration_seconds=.01,
            estimated_cost_usd=0.0, scope_violations=0, false_complete_claims=0,
        )


@pytest.mark.asyncio
async def test_fake_runner_builds_scorecards_and_rolls_back_candidate(tmp_path):
    fake = FakeAgent()
    result = await run_agent_eval(
        target="http://localhost:8000", trials=3, seed=7,
        budget={"max_steps": 30, "max_trials": 3}, episode=fake.run_episode,
        thresholds=AgentEvalThresholds(min_runs=3, min_recall=.9),
    )
    assert result.scorecards["standard"].runs_count == 3
    assert result.scorecards["candidate"].runs_count == 3
    assert result.verdict.verdict in {GateVerdictKind.FAIL, GateVerdictKind.WARN}
    assert result.rollback_recorded
    assert result.promoted_profile == "standard"
    assert result.warnings  # registry's not_monitored invariants are visible as WARN.
    json_path, md_path = write_eval_artifacts(result, tmp_path)
    artifact = json.loads(json_path.read_text())
    assert artifact["gate"]["rollback_recorded"] is True
    assert "evidence" not in json_path.read_text()
    assert md_path.exists()


@pytest.mark.asyncio
async def test_empty_runs_missing_keys_and_live_provider_are_not_passes():
    verdict = evaluate_agent_eval_gate([])
    assert verdict.verdict == GateVerdictKind.INCONCLUSIVE and not verdict.passed
    assert evaluate_agent_eval_gate([{"bad": True}]).verdict == GateVerdictKind.INCONCLUSIVE
    async def unused(**_kwargs):
        raise AssertionError("must not execute")
    with pytest.raises(ValueError, match="live provider"):
        await run_agent_eval(target="http://localhost", trials=1, seed=1,
                             budget={"max_steps": 2}, episode=unused, provider="openai")
    with pytest.raises(ValueError, match="loopback"):
        await run_agent_eval(target="http://example.com", trials=1, seed=1,
                             budget={"max_steps": 2}, episode=unused)
    with pytest.raises(ValueError, match="at least one"):
        await run_agent_eval(target="http://localhost", trials=0, seed=1,
                             budget={"max_steps": 2}, episode=unused)
