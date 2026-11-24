"""Canonical presentation and process outcome for scan terminal statuses."""
from __future__ import annotations


_OUTCOMES = {
    "done": {
        "label": "Scan complete",
        "label_ja": "スキャン完了",
        "severity": "success",
        "color": "#38a169",
        "console_style": "bold green",
        "emoji": "✅",
        "is_success": True,
        "exit_code": 0,
    },
    "incomplete": {
        "label": "Scan incomplete",
        "label_ja": "スキャン不完全",
        "severity": "warning",
        "color": "#d69e2e",
        "console_style": "bold yellow",
        "emoji": "⚠️",
        "is_success": False,
        "exit_code": 2,
    },
    "aborted": {
        "label": "Scan aborted (partial report)",
        "label_ja": "スキャン中断（部分レポート）",
        "severity": "warning",
        "color": "#d69e2e",
        "console_style": "bold yellow",
        "emoji": "⏹️",
        "is_success": False,
        "exit_code": 2,
    },
    "failed": {
        "label": "Scan failed",
        "label_ja": "スキャン失敗",
        "severity": "error",
        "color": "#e53e3e",
        "console_style": "bold red",
        "emoji": "❌",
        "is_success": False,
        "exit_code": 1,
    },
    "scanning": {
        "label": "Scan in progress",
        "label_ja": "スキャン中",
        "severity": "info",
        "color": "#4299e1",
        "console_style": "bold cyan",
        "emoji": "⟳",
        "is_success": False,
        "exit_code": 2,
    },
    "idle": {
        "label": "Idle",
        "label_ja": "待機中",
        "severity": "neutral",
        "color": "#718096",
        "console_style": "dim",
        "emoji": "—",
        "is_success": False,
        "exit_code": 2,
    },
}

_ALIASES = {
    "complete": "done",
    "completed": "done",
    "success": "done",
    "partial": "incomplete",
    "evidence_incomplete": "incomplete",
    "cancelled": "aborted",
    "canceled": "aborted",
    "paused": "aborted",
    "error": "failed",
    "running": "scanning",
    "aborting": "scanning",
    "active": "scanning",
}


def terminal_outcome(status: str, reason: str = "") -> dict:
    """Return the sole user-facing interpretation of a scan status.

    The function is deterministic and side-effect free. Reasons use the shared
    event redactor so every consumer receives the same safe text.
    """
    raw_status = str(status or "unknown").strip().lower()
    canonical = _ALIASES.get(raw_status, raw_status)
    base = _OUTCOMES.get(canonical)
    if base is None:
        base = {
            "label": f"Scan status: {raw_status}",
            "label_ja": f"スキャン状態: {raw_status}",
            "severity": "warning",
            "color": "#d69e2e",
            "console_style": "bold yellow",
            "emoji": "⚠️",
            "is_success": False,
            "exit_code": 2,
        }
    from wscan.url_scope import redact_event_data

    safe_reason = redact_event_data({"reason": str(reason or "")})["reason"]
    label = base["label"]
    return {
        "status": canonical,
        **base,
        "reason": safe_reason,
        "message": f"{label}: {safe_reason}" if safe_reason else label,
    }


def agent_result_outcome(result) -> dict:
    """Interpret an Agent result through the canonical terminal outcome table."""
    if result is None:
        return terminal_outcome("idle")

    error = str(getattr(result, "error", None) or "")
    harness_status = str(getattr(result, "harness_status", "") or "").strip().lower()
    successful = bool(getattr(result, "success", False))
    reason = error or str(getattr(result, "incomplete_reason", "") or "")
    if not reason:
        gaps = [
            *(getattr(result, "coverage_gaps", []) or []),
            *(getattr(result, "network_guard_errors", []) or []),
        ]
        reason = "; ".join(str(gap) for gap in gaps)
    if error:
        return terminal_outcome("failed", reason)
    if harness_status:
        outcome = terminal_outcome(harness_status, reason)
        # A contradictory harness completion cannot override a non-success result.
        if outcome["is_success"] and not successful:
            return terminal_outcome("incomplete", reason)
        return outcome
    return terminal_outcome("done" if successful else "incomplete", reason)
