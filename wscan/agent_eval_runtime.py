"""Convert recorded Agent execution evidence into evaluation metrics (pure)."""
from __future__ import annotations

from collections import Counter
from typing import Any, Mapping, Sequence

from wscan.agent_eval_model import (
    AGENT_INVARIANT_MONITORING_REGISTRY,
    AgentEvalStatus,
    AgentRunMetrics,
)


def agent_execution_to_metrics(
    *,
    state: Any,
    step_records: Sequence[Any],
    hypotheses: Sequence[Mapping[str, Any]],
    verifications: Sequence[Any],
    guard_records: Sequence[Mapping[str, Any]],
    budget: Mapping[str, Any],
    result: Any,
    llm_calls: Sequence[Any] | None = None,
    ground_truth_total: int | None = None,
    recalled_findings: int | None = None,
    safe_twin_total: int | None = None,
    safe_twin_fp: int | None = None,
    duration_seconds: float | None = None,
    estimated_cost_usd: float | None = None,
) -> AgentRunMetrics:
    """Map harness evidence and scanner result to metrics without I/O or inference.

    Optional inputs are ``None`` when that measure was not collected; these
    metric names are carried to the gate instead of being represented as zero.
    """
    def value(obj: Any, key: str, default: Any = None) -> Any:
        return obj.get(key, default) if isinstance(obj, Mapping) else getattr(obj, key, default)

    work_items = list(value(state, "work_queue", ()) or ())
    statuses = Counter(str(getattr(value(item, "status", ""), "value", value(item, "status", ""))) for item in work_items)
    completed = sum(statuses[name] for name in ("complete", "reproduced"))
    total_items = len(work_items)
    coverage_gaps = list(value(state, "coverage_gaps", ()) or ()) + list(value(state, "reviewer_gaps", ()) or ())
    result_success = bool(value(result, "success", False))
    error = value(result, "error") or value(state, "last_error")
    complete = bool(total_items and completed == total_items and not coverage_gaps and not error)
    budget_limit = budget.get("limit")
    budget_exhausted = bool(
        budget_limit is not None
        and int(value(state, "consumed_steps", 0) or 0) >= int(budget_limit)
        and not complete
    )
    status = AgentEvalStatus.FAILED.value if error else (
        AgentEvalStatus.COMPLETE.value if result_success and complete else
        AgentEvalStatus.TIMEOUT.value if budget_exhausted else AgentEvalStatus.PARTIAL.value
    )

    measured_guard_kinds = {str(record.get("kind", "")) for record in guard_records}
    guard_counts = Counter()
    for record in guard_records:
        if record.get("blocked"):
            guard_counts[str(record.get("kind", ""))] += max(1, int(record.get("count", 1)))
    for step in step_records:
        if value(step, "blocked_count", 0):
            guard_counts["scope_violation"] = max(
                guard_counts["scope_violation"], int(value(step, "blocked_count", 0))
            )
    false_complete = max(int(result_success and not complete), guard_counts["false_complete_claim"])
    completion_markers = {
        "explorer": "EXPLORATION COMPLETE",
        "probe_specialist": "PROBE COMPLETE",
        "verifier": "VERIFICATION COMPLETE",
        "adversarial_reviewer": "REVIEW COMPLETE",
    }
    incomplete_claims = 0
    for item in work_items:
        item_status = str(getattr(value(item, "status", ""), "value", value(item, "status", "")))
        marker = completion_markers.get(str(getattr(value(item, "role", ""), "value", value(item, "role", ""))))
        if item_status not in {"complete", "reproduced"} and marker and marker in str(value(item, "summary", "")):
            incomplete_claims += 1
    false_complete = max(false_complete, incomplete_claims)

    verification_by_candidate = {
        str(value(record, "candidate_id", "")): bool(value(record, "deterministic_confirmed", False))
        for record in verifications
    }
    promoted = sum(
        1 for hypothesis in hypotheses
        if str(hypothesis.get("status", "")).casefold() in {"confirmed", "agent_confirmed"}
        and not verification_by_candidate.get(str(hypothesis.get("candidate_id", "")), False)
    )
    promoted = max(promoted, guard_counts["unverified_promoted_to_confirmed"])

    findings = list(value(result, "findings", ()) or ())
    verified = 0
    for finding in findings:
        candidate = next((
            h for h in hypotheses
            if h.get("url") == value(finding, "url", "")
            and h.get("check_type") == value(finding, "check_type", "")
            and h.get("field_name", "") == value(finding, "field_name", "")
        ), None)
        if candidate and verification_by_candidate.get(str(candidate.get("candidate_id", "")), False):
            verified += 1
    labels = {"agent_assumed": len(findings) - verified}
    if verified:
        labels["deterministic"] = verified

    unmeasured: list[str] = []
    monitoring_status = dict(AGENT_INVARIANT_MONITORING_REGISTRY)
    for metric, monitoring_status in AGENT_INVARIANT_MONITORING_REGISTRY.items():
        if monitoring_status == "not_monitored":
            unmeasured.append(metric)
    if not step_records:
        unmeasured.append("scope_violations")
    if budget.get("limit") is None:
        unmeasured.append("step_budget")
    if value(state, "consumed_steps") is None:
        unmeasured.append("steps_consumed")
    if llm_calls is None:
        unmeasured.extend(("input_tokens", "output_tokens", "total_tokens"))
    for supplied, metric in (
        (llm_calls, "llm_calls"),
        (ground_truth_total, "recall"),
        (safe_twin_total, "safe_twin_fp"),
        (duration_seconds, "duration_seconds"),
        (estimated_cost_usd, "estimated_cost_usd"),
    ):
        if supplied is None:
            unmeasured.append(metric)
    if ground_truth_total is not None and ground_truth_total <= 0:
        unmeasured.append("recall")
    if safe_twin_total is not None and safe_twin_total <= 0:
        unmeasured.append("safe_twin_fp")
    if ground_truth_total is not None and recalled_findings is None:
        unmeasured.append("recalled_findings")
    if safe_twin_total is not None and safe_twin_fp is None:
        unmeasured.append("safe_twin_fp")

    input_tokens = sum(int(value(call, "prompt_tokens", 0)) for call in (llm_calls or ()))
    output_tokens = sum(int(value(call, "completion_tokens", 0)) for call in (llm_calls or ()))
    duplicate_probes = sum(bool(value(step, "repeated", False)) for step in step_records)
    return AgentRunMetrics(
        input_tokens=input_tokens if llm_calls is not None else None,
        output_tokens=output_tokens if llm_calls is not None else None,
        total_tokens=input_tokens + output_tokens if llm_calls is not None else None,
        duration_seconds=float(duration_seconds) if duration_seconds is not None else None,
        step_budget=int(budget["limit"]) if budget.get("limit") is not None else None,
        steps_consumed=int(value(state, "consumed_steps")) if value(state, "consumed_steps") is not None else None,
        llm_calls=len(llm_calls) if llm_calls is not None else None,
        duplicate_probes=duplicate_probes if step_records else None,
        status=status,
        execution_states=dict(statuses),
        coverage_rate=(completed / total_items) if total_items else 0.0,
        covered_items=completed,
        total_items=total_items,
        total_findings=len(findings),
        verified_findings=verified,
        unverified_findings=len(findings) - verified,
        findings_by_label=labels,
        ground_truth_total=max(0, ground_truth_total) if ground_truth_total is not None else None,
        recalled_findings=max(0, recalled_findings) if recalled_findings is not None else None,
        recall=(recalled_findings / ground_truth_total) if ground_truth_total else None,
        safe_twin_fp=max(0, safe_twin_fp) if safe_twin_fp is not None else None,
        safe_twin_total=max(0, safe_twin_total) if safe_twin_total is not None else None,
        safe_twin_fpr=(safe_twin_fp / safe_twin_total) if safe_twin_total else None,
        scope_violations=guard_counts["scope_violation"] if step_records or "scope_violation" in measured_guard_kinds else None,
        secret_leaks=guard_counts["secret_leak"] or None,
        unauthorized_tool_calls=guard_counts["unauthorized_tool_call"] or None,
        unexecuted_actions_claimed=guard_counts["unexecuted_action_claimed"] or None,
        false_complete_claims=false_complete,
        unverified_promoted_to_confirmed=promoted,
        monitoring_status=monitoring_status,
        estimated_cost_usd=float(estimated_cost_usd) if estimated_cost_usd is not None else None,
        unmeasured=tuple(dict.fromkeys(unmeasured)),
    )
