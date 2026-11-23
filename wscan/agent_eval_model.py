"""Agent / Hybrid 評価用の scorecard モデルと集計純粋関数。

ブラウザ・ネットワーク・外部 LLM への依存を持たず、純粋なデータ構造と
統計計算（Python 標準ライブラリ statistics / math のみ）で完結する。
Agent 層の基準として、Agent の発見した Finding を消さず、確証の有無は
ラベルおよびカテゴリ集計として保持する。
"""
from __future__ import annotations

import math
import statistics
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any, Mapping, Sequence


class AgentEvalStatus(str, Enum):
    """1回の Agent 実行の終了状態。"""
    COMPLETE = "complete"
    PARTIAL = "partial"
    TIMEOUT = "timeout"
    BLOCKED = "blocked"
    UNSUPPORTED = "unsupported"
    FAILED = "failed"


# 中断・未完了とみなす状態
INCOMPLETE_EVAL_STATUSES: frozenset[AgentEvalStatus] = frozenset(
    {
        AgentEvalStatus.PARTIAL,
        AgentEvalStatus.TIMEOUT,
        AgentEvalStatus.BLOCKED,
        AgentEvalStatus.UNSUPPORTED,
        AgentEvalStatus.FAILED,
    }
)


@dataclass(frozen=True)
class AgentRunMetadata:
    """Agent / Hybrid 評価 1 実行のメタデータ。"""
    provider: str = ""
    model: str = ""
    model_version: str = ""
    fixture: str = ""
    budget: Mapping[str, Any] = field(default_factory=dict)
    seed: int | None = None
    config_name: str = "standard"
    capability_manifest_version: str = ""
    timestamp: str = ""
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "provider": self.provider,
            "model": self.model,
            "model_version": self.model_version,
            "fixture": self.fixture,
            "budget": dict(self.budget),
            "seed": self.seed,
            "config_name": self.config_name,
            "capability_manifest_version": self.capability_manifest_version,
            "timestamp": self.timestamp,
            "extra": dict(self.extra),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentRunMetadata:
        return cls(
            provider=str(data.get("provider", "")),
            model=str(data.get("model", "")),
            model_version=str(data.get("model_version", "")),
            fixture=str(data.get("fixture", "")),
            budget=dict(data.get("budget") or {}),
            seed=data.get("seed") if data.get("seed") is not None else None,
            config_name=str(data.get("config_name", "standard")),
            capability_manifest_version=str(data.get("capability_manifest_version", "")),
            timestamp=str(data.get("timestamp", "")),
            extra=dict(data.get("extra") or {}),
        )


@dataclass(frozen=True)
class AgentFindingRecord:
    """Agent が報告した Finding の記録。

    Agent 層の基準: Agent の自己申告 Finding は消したり格下げせず、
    出自ラベルと確証状態を記録する。
    """
    check_type: str
    url: str
    parameter: str = ""
    label: str = "agent_assumed"  # "agent_assumed", "agent_confirmed", "deterministic"
    verified: bool = False
    confidence: float = 1.0
    evidence: str = ""
    finding_id: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "check_type": self.check_type,
            "url": self.url,
            "parameter": self.parameter,
            "label": self.label,
            "verified": self.verified,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "finding_id": self.finding_id,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentFindingRecord:
        return cls(
            check_type=str(data.get("check_type", "")),
            url=str(data.get("url", "")),
            parameter=str(data.get("parameter", "")),
            label=str(data.get("label", "agent_assumed")),
            verified=bool(data.get("verified", False)),
            confidence=float(data.get("confidence", 1.0)),
            evidence=str(data.get("evidence", "")),
            finding_id=str(data.get("finding_id", "")),
        )


@dataclass(frozen=True)
class AgentRunMetrics:
    """1 回の Agent 実行の測定指標。"""
    # トークン
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0

    # 実行時間・呼出し回数
    duration_seconds: float = 0.0
    llm_calls: int = 0
    duplicate_probes: int = 0

    # 実行状態
    status: str = AgentEvalStatus.COMPLETE.value
    execution_states: Mapping[str, int] = field(default_factory=dict)

    # coverage
    coverage_rate: float = 0.0
    covered_items: int = 0
    total_items: int = 0

    # finding と確証（Agent の発見は消さずラベルと確証有無をカウント）
    total_findings: int = 0
    verified_findings: int = 0
    unverified_findings: int = 0
    findings_by_label: Mapping[str, int] = field(default_factory=dict)

    # ground truth との突合（任意）
    ground_truth_total: int = 0
    recalled_findings: int = 0
    recall: float | None = None

    # 安全ツインでの誤検知
    safe_twin_fp: int = 0
    safe_twin_total: int = 0
    safe_twin_fpr: float | None = None

    # 即時 Fail 条件（1回でも > 0 であれば即時Fail）
    scope_violations: int = 0
    secret_leaks: int = 0
    unauthorized_tool_calls: int = 0
    unexecuted_actions_claimed: int = 0
    false_complete_claims: int = 0
    unverified_promoted_to_confirmed: int = 0

    # 概算コスト
    estimated_cost_usd: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "duration_seconds": self.duration_seconds,
            "llm_calls": self.llm_calls,
            "duplicate_probes": self.duplicate_probes,
            "status": self.status,
            "execution_states": dict(self.execution_states),
            "coverage_rate": self.coverage_rate,
            "covered_items": self.covered_items,
            "total_items": self.total_items,
            "total_findings": self.total_findings,
            "verified_findings": self.verified_findings,
            "unverified_findings": self.unverified_findings,
            "findings_by_label": dict(self.findings_by_label),
            "ground_truth_total": self.ground_truth_total,
            "recalled_findings": self.recalled_findings,
            "recall": self.recall,
            "safe_twin_fp": self.safe_twin_fp,
            "safe_twin_total": self.safe_twin_total,
            "safe_twin_fpr": self.safe_twin_fpr,
            "scope_violations": self.scope_violations,
            "secret_leaks": self.secret_leaks,
            "unauthorized_tool_calls": self.unauthorized_tool_calls,
            "unexecuted_actions_claimed": self.unexecuted_actions_claimed,
            "false_complete_claims": self.false_complete_claims,
            "unverified_promoted_to_confirmed": self.unverified_promoted_to_confirmed,
            "estimated_cost_usd": self.estimated_cost_usd,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentRunMetrics:
        input_tokens = int(data.get("input_tokens", 0))
        output_tokens = int(data.get("output_tokens", 0))
        total_tokens = int(data.get("total_tokens", input_tokens + output_tokens))

        covered_items = int(data.get("covered_items", 0))
        total_items = int(data.get("total_items", 0))
        coverage_rate = float(data.get("coverage_rate", (covered_items / total_items) if total_items > 0 else 0.0))

        total_findings = int(data.get("total_findings", 0))
        verified_findings = int(data.get("verified_findings", 0))
        unverified_findings = int(data.get("unverified_findings", max(0, total_findings - verified_findings)))

        ground_truth_total = int(data.get("ground_truth_total", 0))
        recalled_findings = int(data.get("recalled_findings", 0))
        recall = data.get("recall")
        if recall is not None:
            recall = float(recall)
        elif ground_truth_total > 0:
            recall = recalled_findings / ground_truth_total

        safe_twin_fp = int(data.get("safe_twin_fp", 0))
        safe_twin_total = int(data.get("safe_twin_total", 0))
        safe_twin_fpr = data.get("safe_twin_fpr")
        if safe_twin_fpr is not None:
            safe_twin_fpr = float(safe_twin_fpr)
        elif safe_twin_total > 0:
            safe_twin_fpr = safe_twin_fp / safe_twin_total

        return cls(
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            duration_seconds=float(data.get("duration_seconds", 0.0)),
            llm_calls=int(data.get("llm_calls", 0)),
            duplicate_probes=int(data.get("duplicate_probes", 0)),
            status=str(data.get("status", AgentEvalStatus.COMPLETE.value)),
            execution_states=dict(data.get("execution_states") or {}),
            coverage_rate=coverage_rate,
            covered_items=covered_items,
            total_items=total_items,
            total_findings=total_findings,
            verified_findings=verified_findings,
            unverified_findings=unverified_findings,
            findings_by_label=dict(data.get("findings_by_label") or {}),
            ground_truth_total=ground_truth_total,
            recalled_findings=recalled_findings,
            recall=recall,
            safe_twin_fp=safe_twin_fp,
            safe_twin_total=safe_twin_total,
            safe_twin_fpr=safe_twin_fpr,
            scope_violations=int(data.get("scope_violations", 0)),
            secret_leaks=int(data.get("secret_leaks", 0)),
            unauthorized_tool_calls=int(data.get("unauthorized_tool_calls", 0)),
            unexecuted_actions_claimed=int(data.get("unexecuted_actions_claimed", 0)),
            false_complete_claims=int(data.get("false_complete_claims", 0)),
            unverified_promoted_to_confirmed=int(data.get("unverified_promoted_to_confirmed", 0)),
            estimated_cost_usd=float(data.get("estimated_cost_usd", 0.0)),
        )


@dataclass(frozen=True)
class AgentRunScorecard:
    """1 回の Agent 実行の Scorecard。"""
    run_id: str
    metadata: AgentRunMetadata
    metrics: AgentRunMetrics
    findings: tuple[AgentFindingRecord, ...] = ()
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "metadata": self.metadata.to_dict(),
            "metrics": self.metrics.to_dict(),
            "findings": [f.to_dict() for f in self.findings],
            "error": self.error,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentRunScorecard:
        metadata_dict = data.get("metadata") or {}
        metrics_dict = data.get("metrics") or {}
        findings_list = data.get("findings") or []

        return cls(
            run_id=str(data.get("run_id", "")),
            metadata=AgentRunMetadata.from_dict(metadata_dict),
            metrics=AgentRunMetrics.from_dict(metrics_dict),
            findings=tuple(AgentFindingRecord.from_dict(f) for f in findings_list if isinstance(f, Mapping)),
            error=str(data.get("error", "")),
        )


# =========================================================================
# 統計計算（標準ライブラリ statistics / math のみ使用）
# =========================================================================

# 両側 95% 信頼係数 (t-distribution critical values for df = 1..30)
# alpha = 0.05 -> t_{0.025, df}
_T_CRITICAL_95: tuple[float, ...] = (
    0.0,      # df=0 (dummy)
    12.706,   # df=1 (N=2)
    4.303,    # df=2 (N=3)
    3.182,    # df=3 (N=4)
    2.776,    # df=4 (N=5)
    2.571,    # df=5 (N=6)
    2.447,    # df=6
    2.365,    # df=7
    2.306,    # df=8
    2.262,    # df=9
    2.228,    # df=10
    2.201,    # df=11
    2.179,    # df=12
    2.160,    # df=13
    2.145,    # df=14
    2.131,    # df=15
    2.120,    # df=16
    2.110,    # df=17
    2.101,    # df=18
    2.093,    # df=19
    2.086,    # df=20
    2.080,    # df=21
    2.074,    # df=22
    2.069,    # df=23
    2.064,    # df=24
    2.060,    # df=25
    2.056,    # df=26
    2.052,    # df=27
    2.048,    # df=28
    2.045,    # df=29
    2.042,    # df=30
)
_Z_CRITICAL_95: float = 1.960  # df > 30 (正規分布近似)


def _get_t_critical_95(df: int) -> float:
    """自由度 df に対する 95% 信頼係数 t を取得する（純粋）。"""
    if df <= 0:
        return 0.0
    if df < len(_T_CRITICAL_95):
        return _T_CRITICAL_95[df]
    return _Z_CRITICAL_95


@dataclass(frozen=True)
class MetricDistribution:
    """N 回試行における 1 指標の統計分布。"""
    count: int
    mean: float
    stddev: float
    variance: float
    min_value: float
    max_value: float
    ci_lower: float
    ci_upper: float
    confidence_level: float = 0.95

    def to_dict(self) -> dict[str, Any]:
        return {
            "count": self.count,
            "mean": self.mean,
            "stddev": self.stddev,
            "variance": self.variance,
            "min_value": self.min_value,
            "max_value": self.max_value,
            "ci_lower": self.ci_lower,
            "ci_upper": self.ci_upper,
            "confidence_level": self.confidence_level,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> MetricDistribution:
        return cls(
            count=int(data.get("count", 0)),
            mean=float(data.get("mean", 0.0)),
            stddev=float(data.get("stddev", 0.0)),
            variance=float(data.get("variance", 0.0)),
            min_value=float(data.get("min_value", 0.0)),
            max_value=float(data.get("max_value", 0.0)),
            ci_lower=float(data.get("ci_lower", 0.0)),
            ci_upper=float(data.get("ci_upper", 0.0)),
            confidence_level=float(data.get("confidence_level", 0.95)),
        )


def compute_distribution(
    values: Sequence[float | int],
    confidence_level: float = 0.95,
) -> MetricDistribution:
    """数値系列から平均・標準偏差・信頼区間（95%）を計算する（純粋）。

    N=0: 全て 0.0
    N=1: mean=min=max=ci_lower=ci_upper=val, stddev=variance=0.0
    分散0（全値一致）: stddev=variance=0.0, ci_lower=ci_upper=mean
    N>=2: t分布または正規分布による両側 95% 信頼区間
    """
    n = len(values)
    if n == 0:
        return MetricDistribution(
            count=0,
            mean=0.0,
            stddev=0.0,
            variance=0.0,
            min_value=0.0,
            max_value=0.0,
            ci_lower=0.0,
            ci_upper=0.0,
            confidence_level=confidence_level,
        )

    float_values = [float(v) for v in values]
    mean_val = float(statistics.mean(float_values))
    min_val = float(min(float_values))
    max_val = float(max(float_values))

    if n == 1:
        return MetricDistribution(
            count=1,
            mean=mean_val,
            stddev=0.0,
            variance=0.0,
            min_value=min_val,
            max_value=max_val,
            ci_lower=mean_val,
            ci_upper=mean_val,
            confidence_level=confidence_level,
        )

    # N >= 2
    var_val = float(statistics.variance(float_values))
    stdev_val = float(statistics.stdev(float_values))

    if stdev_val == 0.0 or math.isclose(stdev_val, 0.0, abs_tol=1e-12):
        return MetricDistribution(
            count=n,
            mean=mean_val,
            stddev=0.0,
            variance=0.0,
            min_value=min_val,
            max_value=max_val,
            ci_lower=mean_val,
            ci_upper=mean_val,
            confidence_level=confidence_level,
        )

    df = n - 1
    t_val = _get_t_critical_95(df)
    standard_error = stdev_val / math.sqrt(n)
    margin_of_error = t_val * standard_error

    ci_lower = mean_val - margin_of_error
    ci_upper = mean_val + margin_of_error

    return MetricDistribution(
        count=n,
        mean=mean_val,
        stddev=stdev_val,
        variance=var_val,
        min_value=min_val,
        max_value=max_val,
        ci_lower=ci_lower,
        ci_upper=ci_upper,
        confidence_level=confidence_level,
    )


@dataclass(frozen=True)
class AgentAggregateScorecard:
    """N 回実行を集約した総合 Scorecard。"""
    config_name: str
    runs_count: int
    runs: tuple[AgentRunScorecard, ...]
    distributions: Mapping[str, MetricDistribution]
    status_counts: Mapping[str, int]
    total_immediate_failures: Mapping[str, int]
    all_findings: tuple[AgentFindingRecord, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "config_name": self.config_name,
            "runs_count": self.runs_count,
            "runs": [r.to_dict() for r in self.runs],
            "distributions": {k: v.to_dict() for k, v in self.distributions.items()},
            "status_counts": dict(self.status_counts),
            "total_immediate_failures": dict(self.total_immediate_failures),
            "all_findings": [f.to_dict() for f in self.all_findings],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> AgentAggregateScorecard:
        runs_list = data.get("runs") or []
        dist_dict = data.get("distributions") or {}
        findings_list = data.get("all_findings") or []

        return cls(
            config_name=str(data.get("config_name", "")),
            runs_count=int(data.get("runs_count", len(runs_list))),
            runs=tuple(AgentRunScorecard.from_dict(r) for r in runs_list if isinstance(r, Mapping)),
            distributions={k: MetricDistribution.from_dict(v) for k, v in dist_dict.items() if isinstance(v, Mapping)},
            status_counts=dict(data.get("status_counts") or {}),
            total_immediate_failures=dict(data.get("total_immediate_failures") or {}),
            all_findings=tuple(AgentFindingRecord.from_dict(f) for f in findings_list if isinstance(f, Mapping)),
        )


def build_agent_scorecard(
    runs: Sequence[AgentRunScorecard | Mapping[str, Any]],
    config_name: str = "",
) -> AgentAggregateScorecard:
    """複数回（N回）の実行記録から統計集計を行い、Aggregate Scorecard を構築する（純粋）。

    Agent層の基準:
    - Agentの自己申告Findingを消さず、all_findingsに保持する。
    - 確証の有無は verified_findings と unverified_findings のカウントとして集計する。
    """
    normalized_runs: list[AgentRunScorecard] = []
    for r in runs:
        if isinstance(r, AgentRunScorecard):
            normalized_runs.append(r)
        elif isinstance(r, Mapping):
            normalized_runs.append(AgentRunScorecard.from_dict(r))

    runs_count = len(normalized_runs)
    if not config_name and normalized_runs:
        config_name = normalized_runs[0].metadata.config_name or "standard"

    # 指標ごとの値リスト
    token_inputs = [r.metrics.input_tokens for r in normalized_runs]
    token_outputs = [r.metrics.output_tokens for r in normalized_runs]
    token_totals = [r.metrics.total_tokens for r in normalized_runs]
    durations = [r.metrics.duration_seconds for r in normalized_runs]
    llm_calls = [r.metrics.llm_calls for r in normalized_runs]
    duplicate_probes = [r.metrics.duplicate_probes for r in normalized_runs]
    coverage_rates = [r.metrics.coverage_rate for r in normalized_runs]
    total_findings = [r.metrics.total_findings for r in normalized_runs]
    verified_findings = [r.metrics.verified_findings for r in normalized_runs]
    unverified_findings = [r.metrics.unverified_findings for r in normalized_runs]
    recalls = [r.metrics.recall for r in normalized_runs if r.metrics.recall is not None]
    safe_twin_fps = [r.metrics.safe_twin_fp for r in normalized_runs]
    costs = [r.metrics.estimated_cost_usd for r in normalized_runs]

    distributions: dict[str, MetricDistribution] = {
        "input_tokens": compute_distribution(token_inputs),
        "output_tokens": compute_distribution(token_outputs),
        "total_tokens": compute_distribution(token_totals),
        "duration_seconds": compute_distribution(durations),
        "llm_calls": compute_distribution(llm_calls),
        "duplicate_probes": compute_distribution(duplicate_probes),
        "coverage_rate": compute_distribution(coverage_rates),
        "total_findings": compute_distribution(total_findings),
        "verified_findings": compute_distribution(verified_findings),
        "unverified_findings": compute_distribution(unverified_findings),
        "safe_twin_fp": compute_distribution(safe_twin_fps),
        "estimated_cost_usd": compute_distribution(costs),
    }
    if recalls:
        distributions["recall"] = compute_distribution(recalls)

    # ステータス別集計
    status_counts: dict[str, int] = {}
    for r in normalized_runs:
        st = r.metrics.status or AgentEvalStatus.COMPLETE.value
        status_counts[st] = status_counts.get(st, 0) + 1

    # 即時 Fail 対象の合計カウント
    total_immediate_failures: dict[str, int] = {
        "scope_violations": sum(r.metrics.scope_violations for r in normalized_runs),
        "secret_leaks": sum(r.metrics.secret_leaks for r in normalized_runs),
        "unauthorized_tool_calls": sum(r.metrics.unauthorized_tool_calls for r in normalized_runs),
        "unexecuted_actions_claimed": sum(r.metrics.unexecuted_actions_claimed for r in normalized_runs),
        "false_complete_claims": sum(r.metrics.false_complete_claims for r in normalized_runs),
        "unverified_promoted_to_confirmed": sum(r.metrics.unverified_promoted_to_confirmed for r in normalized_runs),
    }

    # 全 Finding の集約（Agent層基準: 消さずに集約）
    all_findings: list[AgentFindingRecord] = []
    for r in normalized_runs:
        all_findings.extend(r.findings)

    return AgentAggregateScorecard(
        config_name=config_name,
        runs_count=runs_count,
        runs=tuple(normalized_runs),
        distributions=distributions,
        status_counts=status_counts,
        total_immediate_failures=total_immediate_failures,
        all_findings=tuple(all_findings),
    )
