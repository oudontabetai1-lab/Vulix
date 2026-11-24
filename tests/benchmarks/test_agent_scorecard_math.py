"""Agent / Hybrid 評価 Scorecard の純粋な統計計算とデータモデルのテスト。

ブラウザ・ネットワーク・外部 LLM を一切使用しない純粋単体テスト。
"""
from __future__ import annotations

import math
import pytest

from wscan.agent_eval_model import (
    AgentAggregateScorecard,
    AgentEvalStatus,
    AgentFindingRecord,
    AgentRunMetadata,
    AgentRunMetrics,
    AgentRunScorecard,
    MetricDistribution,
    build_agent_scorecard,
    compute_distribution,
)


def test_distribution_empty():
    """N=0 の場合は全て 0.0 を返す。"""
    dist = compute_distribution([])
    assert dist.count == 0
    assert dist.mean == 0.0
    assert dist.stddev == 0.0
    assert dist.variance == 0.0
    assert dist.ci_lower == 0.0
    assert dist.ci_upper == 0.0


def test_distribution_single_sample():
    """N=1 の境界値: 分散・標準偏差は0、信頼区間は単一値。"""
    dist = compute_distribution([42.0])
    assert dist.count == 1
    assert dist.mean == 42.0
    assert dist.min_value == 42.0
    assert dist.max_value == 42.0
    assert dist.stddev == 0.0
    assert dist.variance == 0.0
    assert dist.ci_lower == 42.0
    assert dist.ci_upper == 42.0


def test_distribution_zero_variance():
    """全要素が同一（分散 0）の場合、標準偏差 0 かつ信頼区間幅は 0。"""
    dist = compute_distribution([10.0, 10.0, 10.0, 10.0])
    assert dist.count == 4
    assert dist.mean == 10.0
    assert dist.stddev == 0.0
    assert dist.variance == 0.0
    assert dist.ci_lower == 10.0
    assert dist.ci_upper == 10.0


def test_distribution_n3():
    """N=3 の境界値: t 分布（df=2, t=4.303）による信頼区間計算。"""
    vals = [10.0, 20.0, 30.0]
    dist = compute_distribution(vals)
    assert dist.count == 3
    assert dist.mean == 20.0
    assert dist.min_value == 10.0
    assert dist.max_value == 30.0
    # variance = ((10-20)^2 + 0 + (30-20)^2) / 2 = 200 / 2 = 100
    assert math.isclose(dist.variance, 100.0, rel_tol=1e-5)
    # stddev = 10.0
    assert math.isclose(dist.stddev, 10.0, rel_tol=1e-5)
    # se = 10 / sqrt(3) = 5.7735
    # t(df=2) = 4.303 -> margin = 4.303 * 5.7735 = 24.843
    se = 10.0 / math.sqrt(3)
    expected_margin = 4.303 * se
    assert math.isclose(dist.ci_lower, 20.0 - expected_margin, rel_tol=1e-4)
    assert math.isclose(dist.ci_upper, 20.0 + expected_margin, rel_tol=1e-4)


def test_distribution_large_n():
    """N > 30 の場合、正規分布近似 (z=1.96) が使われる。"""
    vals = [float(i) for i in range(50)]
    dist = compute_distribution(vals)
    assert dist.count == 50
    assert dist.mean == 24.5
    assert dist.ci_lower < dist.mean < dist.ci_upper


def test_distribution_confidence_level_changes_interval():
    vals = [10.0, 20.0, 30.0]
    ci90 = compute_distribution(vals, confidence_level=0.90)
    ci99 = compute_distribution(vals, confidence_level=0.99)
    assert ci90.confidence_level == 0.90
    assert ci99.confidence_level == 0.99
    assert ci90.ci_upper < ci99.ci_upper
    assert ci90.ci_lower > ci99.ci_lower


@pytest.mark.parametrize("df,critical", [(1, 63.657), (2, 9.925), (5, 4.032), (30, 2.750)])
def test_distribution_99_percent_t_critical_values_and_width(df, critical):
    values = [float(i) for i in range(df + 1)]
    dist = compute_distribution(values, confidence_level=0.99)
    expected_width = 2 * critical * math.sqrt((df + 2) / 12)
    assert math.isclose(dist.ci_upper - dist.ci_lower, expected_width, rel_tol=1e-4)


def test_distribution_99_percent_df2_matches_student_t_reference():
    dist = compute_distribution([0.0, 1.0, 2.0], confidence_level=0.99)
    assert math.isclose(dist.ci_upper - dist.ci_lower, 11.4604, rel_tol=1e-4)


@pytest.mark.parametrize("values", [[float("nan")], [float("inf")], [-float("inf")]])
def test_distribution_rejects_nonfinite_values(values):
    with pytest.raises(ValueError, match="finite"):
        compute_distribution(values)


def test_distribution_rejects_invalid_confidence_level():
    with pytest.raises(ValueError, match="confidence_level"):
        compute_distribution([1.0, 2.0], confidence_level=0.92)


def test_metadata_serialization():
    """AgentRunMetadata の to_dict / from_dict ラウンドトリップ。"""
    meta = AgentRunMetadata(
        provider="anthropic",
        model="claude-3-5-sonnet",
        model_version="20241022",
        fixture="realistic_site",
        budget={"token_budget": 50000, "step_budget": 30},
        seed=12345,
        config_name="candidate",
        capability_manifest_version="v2",
        timestamp="2026-11-24T00:00:00Z",
    )
    d = meta.to_dict()
    restored = AgentRunMetadata.from_dict(d)
    assert restored == meta


def test_metrics_serialization():
    """AgentRunMetrics の to_dict / from_dict ラウンドトリップ。"""
    metrics = AgentRunMetrics(
        input_tokens=1500,
        output_tokens=300,
        total_tokens=1800,
        duration_seconds=12.5,
        llm_calls=5,
        duplicate_probes=1,
        status=AgentEvalStatus.COMPLETE.value,
        coverage_rate=0.85,
        covered_items=17,
        total_items=20,
        total_findings=3,
        verified_findings=2,
        unverified_findings=1,
        findings_by_label={"agent_assumed": 1, "agent_confirmed": 2},
        ground_truth_total=5,
        recalled_findings=2,
        recall=0.4,
        safe_twin_fp=0,
        safe_twin_total=10,
        safe_twin_fpr=0.0,
        scope_violations=0,
        secret_leaks=0,
        unauthorized_tool_calls=0,
        unexecuted_actions_claimed=0,
        false_complete_claims=0,
        unverified_promoted_to_confirmed=0,
        estimated_cost_usd=0.015,
    )
    d = metrics.to_dict()
    restored = AgentRunMetrics.from_dict(d)
    assert restored == metrics


def test_scorecard_agent_layer_invariants():
    """Agent 層の基準: Agent の自己申告 Finding は消さず、ラベルと確証有無を保持する。"""
    f1 = AgentFindingRecord(
        check_type="sqli",
        url="http://target/vuln",
        parameter="q",
        label="agent_confirmed",
        verified=True,
    )
    f2 = AgentFindingRecord(
        check_type="xss",
        url="http://target/search",
        parameter="kw",
        label="agent_assumed",
        verified=False,
    )
    m = AgentRunMetrics(
        total_findings=2,
        verified_findings=1,
        unverified_findings=1,
        findings_by_label={"agent_confirmed": 1, "agent_assumed": 1},
    )
    scorecard = AgentRunScorecard(
        run_id="run_1",
        metadata=AgentRunMetadata(config_name="standard"),
        metrics=m,
        findings=(f1, f2),
    )

    agg = build_agent_scorecard([scorecard])
    assert agg.runs_count == 1
    # 2件の Finding が消されずに保持されている
    assert len(agg.all_findings) == 2
    assert agg.all_findings[0].check_type == "sqli"
    assert agg.all_findings[0].verified is True
    assert agg.all_findings[1].check_type == "xss"
    assert agg.all_findings[1].verified is False
    # 分布にも反映されている
    assert agg.distributions["total_findings"].mean == 2.0
    assert agg.distributions["verified_findings"].mean == 1.0
    assert agg.distributions["unverified_findings"].mean == 1.0


def test_build_agent_scorecard_multiple_runs():
    """複数 run の集約と分布計算。"""
    runs = []
    for i in range(3):
        m = AgentRunMetrics(
            input_tokens=1000 + i * 100,
            output_tokens=200 + i * 50,
            total_tokens=1200 + i * 150,
            duration_seconds=10.0 + i * 2.0,
            llm_calls=4 + i,
            duplicate_probes=i,
            status=AgentEvalStatus.COMPLETE.value,
            coverage_rate=0.7 + i * 0.1,
            total_findings=2 + i,
            verified_findings=1 + i,
            unverified_findings=1,
            estimated_cost_usd=0.01 + i * 0.005,
            scope_violations=0,
        )
        runs.append(
            AgentRunScorecard(
                run_id=f"run_{i}",
                metadata=AgentRunMetadata(config_name="candidate"),
                metrics=m,
            )
        )

    agg = build_agent_scorecard(runs)
    assert agg.runs_count == 3
    assert agg.config_name == "candidate"
    assert agg.distributions["duration_seconds"].mean == 12.0
    assert agg.distributions["llm_calls"].mean == 5.0
    assert agg.status_counts[AgentEvalStatus.COMPLETE.value] == 3
    assert agg.total_immediate_failures["scope_violations"] == 0

    # JSON シリアライズ検証
    d = agg.to_dict()
    restored = AgentAggregateScorecard.from_dict(d)
    assert restored.runs_count == 3
    assert restored.distributions["duration_seconds"].mean == 12.0
