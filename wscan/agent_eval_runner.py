"""課金しない Agent / Hybrid 評価 runner。実モデル経路は既定で閉じる。"""
from __future__ import annotations

import inspect
import ipaddress
import json
import random
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Awaitable, Callable, Mapping
from urllib.parse import urlsplit

from wscan.agent_eval_gate import AgentEvalThresholds, evaluate_agent_eval_gate
from wscan.agent_eval_model import (
    AgentAggregateScorecard, AgentRunMetadata, AgentRunMetrics, AgentRunScorecard,
    build_agent_scorecard,
)


@dataclass(frozen=True)
class EvalRun:
    scorecards: Mapping[str, AgentAggregateScorecard]
    verdict: Any
    rollback_recorded: bool
    promoted_profile: str
    warnings: tuple[str, ...]


Episode = Callable[..., AgentRunScorecard | AgentRunMetrics | Awaitable[AgentRunScorecard | AgentRunMetrics]]


def _require_localhost(target: str) -> None:
    parts = urlsplit(target)
    if parts.scheme not in {"http", "https"} or not parts.hostname:
        raise ValueError("target must be an HTTP localhost fixture URL")
    host = parts.hostname.casefold()
    is_localhost_name = host == "localhost" or host.endswith(".localhost")
    try:
        is_loopback_address = ipaddress.ip_address(host).is_loopback
    except ValueError:
        is_loopback_address = False
    if not (is_localhost_name or is_loopback_address):
        raise ValueError("target must be a localhost or loopback fixture")


async def run_agent_eval(
    *, target: str, trials: int, seed: int, budget: Mapping[str, int], episode: Episode,
    provider: str = "fake", allow_live_provider: bool = False,
    thresholds: AgentEvalThresholds | None = None,
) -> EvalRun:
    """Standard と candidate を各 N 回 Fake episode で走らせ、gate 判定する。

    episode(target, profile, seed, budget) は公開可能な集計値だけを返す。
    """
    _require_localhost(target)
    if provider.casefold() not in {"none", "fake", "replay", "deterministic-fake"} and not allow_live_provider:
        raise ValueError("live provider is disabled; explicit allow_live_provider is required")
    if type(trials) is not int or trials < 0 or trials > int(budget.get("max_trials", 100)):
        raise ValueError("trials must be within the configured max_trials budget")
    if type(seed) is not int or int(budget.get("max_steps", 0)) <= 0:
        raise ValueError("seed and positive max_steps budget are required")
    rng = random.Random(seed)
    runs: dict[str, list[AgentRunScorecard]] = {"standard": [], "candidate": []}
    for profile in runs:
        for index in range(trials):
            run_seed = rng.randrange(0, 2**32)
            value = episode(target=target, profile=profile, seed=run_seed, budget=dict(budget))
            if inspect.isawaitable(value):
                value = await value
            if isinstance(value, AgentRunMetrics):
                value = AgentRunScorecard(
                    run_id=f"{profile}-{index}",
                    metadata=AgentRunMetadata(provider="fake", fixture="agent_lab_app", seed=run_seed, config_name=profile,
                                              budget={"max_steps": int(budget["max_steps"])}),
                    metrics=value,
                )
            if not isinstance(value, AgentRunScorecard):
                raise TypeError("episode must return AgentRunMetrics or AgentRunScorecard")
            if value.metrics.steps_consumed is not None and value.metrics.steps_consumed > int(budget["max_steps"]):
                raise ValueError("episode exceeded max_steps budget")
            runs[profile].append(value)
    scorecards = {key: build_agent_scorecard(value, config_name=key) for key, value in runs.items()}
    verdict = evaluate_agent_eval_gate(runs["candidate"], runs["standard"], thresholds=thresholds)
    # WARN (including not_monitored invariants) is explicitly not PASS; never
    # make the candidate the default unless the gate positively passes.
    rollback = not verdict.passed
    warnings = tuple(verdict.unmonitored_invariants)
    return EvalRun(scorecards, verdict, rollback, "standard" if rollback else "candidate", warnings)


def _safe_artifact(result: EvalRun) -> dict[str, Any]:
    """固定 schema のみ公開し、run の findings/evidence/metadata を出力しない。"""
    safe_metrics = ("coverage_rate", "recall", "safe_twin_fp", "total_findings", "duration_seconds",
                    "total_tokens", "estimated_cost_usd")
    return {
        "schema_version": 1,
        "profiles": {
            profile: {"runs_count": card.runs_count, "status_counts": dict(card.status_counts),
                      "metrics": {key: card.distributions[key].to_dict() if key in card.distributions else None
                                  for key in safe_metrics}}
            for profile, card in result.scorecards.items()
        },
        "gate": {"verdict": result.verdict.verdict.value, "passed": bool(result.verdict.passed),
                 "rollback_recorded": result.rollback_recorded, "promoted_profile": result.promoted_profile,
                 "warnings_count": len(result.warnings)},
    }


def write_eval_artifacts(result: EvalRun, output_dir: str | Path) -> tuple[Path, Path]:
    """Allowlist artifact を書き、公開直後に safety scanner で fail-closed 検査。"""
    from wscan.eval_artifact_safety import check_artifacts

    directory = Path(output_dir)
    directory.mkdir(parents=True, exist_ok=True)
    data = _safe_artifact(result)
    json_path = directory / "agent_eval_scorecard.json"
    md_path = directory / "agent_eval_summary.md"
    json_path.write_text(json.dumps(data, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    gate = data["gate"]
    md_path.write_text(
        "# Agent evaluation summary\n\n"
        f"- Gate: `{gate['verdict']}`\n- Candidate promotion: `{gate['promoted_profile']}`\n"
        f"- Rollback recorded: `{str(gate['rollback_recorded']).lower()}`\n"
        f"- Unmonitored invariants: {gate['warnings_count']} (WARN)\n",
        encoding="utf-8",
    )
    check_artifacts([json_path, md_path])
    return json_path, md_path
