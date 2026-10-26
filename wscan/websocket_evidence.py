"""Strict, private WebSocket probe evidence validation."""
from __future__ import annotations

import re

from wscan.probe_ledger import ProbeOutcome, ProbeRole, sha256_hex

DISCOVERY = "websocket_discovery"
RULES = ("websocket_xss_reflection", "websocket_sqli_error",
         "websocket_os_echo", "websocket_ssti_eval")
VERIFY_RULES = frozenset(RULES)
DECISIONS = {DISCOVERY, *RULES}
_OUTCOMES = {o.value for o in ProbeOutcome}
_ROLES = {o.value for o in ProbeRole}
_HASH = re.compile(r"^[0-9a-f]{64}$")
_KEY = re.compile(r"^endpoint_sha256=([0-9a-f]{64});message_sha256=([0-9a-f]{64})$")
_TERMINALS = {"received", "closed", "timeout", "open_error", "send_error",
              "socket_error", "evaluation_error", "malformed", "no_endpoint",
              "endpoint_limit", "state_profile_policy", "missing_replay_context"}


def subject(endpoint_hash: str, message_hash: str, rule: str) -> str:
    return sha256_hex(f"{endpoint_hash}:{message_hash}:{rule}")


def valid_shape(row: dict) -> bool:
    """Validate the WebSocket-only wire shape; shared transport schemas stay strict."""
    kind = row.get("record_kind")
    if kind not in {"websocket_attempt", "websocket_request", "websocket_observation",
                    "websocket_cleanup", "websocket_discovery", "websocket_decision"}:
        return False
    if (row.get("check") != "websocket" or row.get("actor") != "websocket_oracle"
            or row.get("decision_version") != "1" or row.get("decision_rule") not in DECISIONS
            or row.get("role") not in _ROLES or row.get("browser") is not None
            or not _HASH.fullmatch(str(row.get("decision_subject", "")))
            or not isinstance(row.get("rationale"), str)
            or not isinstance(row.get("injection_key", ""), str)):
        return False
    if kind in {"websocket_attempt", "websocket_request", "websocket_observation"}:
        key = _KEY.fullmatch(row.get("injection_key", ""))
        if not key or row.get("decision_rule") not in VERIFY_RULES:
            return False
        endpoint_hash, message_hash = key.groups()
        if row.get("decision_subject") != subject(endpoint_hash, message_hash, row["decision_rule"]):
            return False
        if row.get("role") not in {ProbeRole.ATTACK.value, ProbeRole.VERIFY.value}:
            return False
    if kind == "websocket_attempt":
        return (row.get("outcome") is None and row.get("request") is None
                and row.get("response") is None and not row.get("parent_id")
                and not row.get("request_attempt_id") and row.get("rationale") == "started"
                and not row.get("related_attempt_ids"))
    if kind == "websocket_request":
        request = row.get("request")
        return (row.get("outcome") is None and isinstance(request, dict)
                and request.get("transport") == "websocket" and request.get("method") == "SEND"
                and request.get("url") == "" and request.get("sent") is True
                and _HASH.fullmatch(str(request.get("body_hash", "")))
                and request.get("body_hash") == key.group(2)
                and type(request.get("body_length")) is int and request["body_length"] >= 0
                and row.get("response") is None and bool(row.get("parent_id"))
                and not row.get("request_attempt_id") and not row.get("related_attempt_ids"))
    if kind == "websocket_observation":
        request, response = row.get("request"), row.get("response")
        return (row.get("outcome") in {ProbeOutcome.MATCHED.value, ProbeOutcome.NO_MATCH.value}
                and isinstance(request, dict) and request.get("transport") == "websocket"
                and request.get("method") == "SEND" and request.get("url") == ""
                and request.get("sent") is True and request.get("body_hash") == key.group(2)
                and isinstance(response, dict) and _HASH.fullmatch(str(response.get("body_hash", "")))
                and type(response.get("body_length")) is int and response["body_length"] >= 0
                and bool(row.get("parent_id")) and bool(row.get("request_attempt_id"))
                and row.get("rationale") == "captured_frame" and not row.get("related_attempt_ids"))
    if kind == "websocket_discovery":
        return (row.get("role") == ProbeRole.DISCOVER.value and row.get("outcome") is None
                and row.get("request") is None and row.get("response") is None
                and row.get("rationale") in {"endpoint_observed", "frame_observed"}
                and not row.get("request_attempt_id") and not row.get("parent_id")
                and not row.get("related_attempt_ids"))
    if kind == "websocket_cleanup":
        return (row.get("role") == ProbeRole.CLEANUP.value and row.get("outcome") in
                {None, ProbeOutcome.TRANSPORT_ERROR.value}
                and row.get("request") is None and row.get("response") is None
                and row.get("rationale") in {"socket_close_requested", "socket_close_error",
                                               "page_listener_removed", "page_listener_remove_error"}
                and not row.get("request_attempt_id") and not row.get("related_attempt_ids"))
    if kind == "websocket_decision":
        return _decision_shape(row)
    return False


def _decision_shape(row: dict) -> bool:
    if (row.get("record_kind") != "websocket_decision" or row.get("outcome") not in _OUTCOMES
            or row.get("request") is not None or row.get("response") is not None):
        return False
    rationale = row.get("rationale", "")
    match = re.fullmatch(r"terminal=([a-z_]+);frames=([0-9]+);close_error=([01])", rationale)
    if not match or match.group(1) not in _TERMINALS:
        return False
    if row.get("decision_rule") == DISCOVERY:
        return (row.get("role") == ProbeRole.DISCOVER.value
                and row.get("outcome") in {ProbeOutcome.MATCHED.value, ProbeOutcome.NO_MATCH.value}
                and not row.get("request_attempt_id"))
    if row.get("role") == ProbeRole.ATTACK.value:
        return row.get("outcome") in _OUTCOMES
    return row.get("role") == ProbeRole.VERIFY.value and row.get("outcome") in _OUTCOMES


def accepted_decisions(events: dict[str, dict]) -> dict[str, list[dict]]:
    """Rebuild accepted decisions from persisted events; any orphan poisons its unit."""
    by_unit: dict[str, list[dict]] = {}
    for row in events.values():
        if str(row.get("record_kind", "")).startswith("websocket_"):
            by_unit.setdefault(row.get("completion_unit", ""), []).append(row)
    result = {}
    for unit, rows in by_unit.items():
        rows.sort(key=_sequence)
        decisions = [r for r in rows if r.get("record_kind") == "websocket_decision"]
        attempts = [r for r in rows if r.get("record_kind") == "websocket_attempt"]
        if any(not valid_shape(r) for r in rows):
            result[unit] = []
            continue
        attempt_decisions = [r for r in decisions if r.get("decision_rule") in VERIFY_RULES
                             and r.get("parent_id") in {a["attempt_id"] for a in attempts}]
        standalone_skips = [r for r in decisions if r.get("decision_rule") in VERIFY_RULES
                            and not r.get("parent_id") and not r.get("request_attempt_id")
                            and r.get("outcome") in {ProbeOutcome.SKIPPED.value, ProbeOutcome.UNEXECUTABLE.value}]
        if len(attempt_decisions) != len(attempts) or (not attempts and not standalone_skips and not [d for d in decisions if d.get("decision_rule") == DISCOVERY]):
            result[unit] = []
            continue
        valid = []
        poisoned = False
        for decision in decisions:
            if decision.get("decision_rule") == DISCOVERY:
                if not _valid_discovery(decision, rows):
                    poisoned = True
                else:
                    valid.append(decision)
                continue
            terminal = _terminal(decision)
            if (not decision.get("request_attempt_id") and not decision.get("parent_id")
                    and decision.get("outcome") in {ProbeOutcome.SKIPPED.value, ProbeOutcome.UNEXECUTABLE.value}
                    and terminal in {"state_profile_policy", "missing_replay_context", "no_endpoint"}
                    and not decision.get("related_attempt_ids")):
                valid.append(decision)
                continue
            root = events.get(decision.get("parent_id"), {})
            key = _KEY.fullmatch(root.get("injection_key", "")) if root else None
            req_id = decision.get("request_attempt_id", "")
            request = events.get(req_id, {}) if req_id else {}
            observations = [r for r in rows if r.get("record_kind") == "websocket_observation"
                            and r.get("request_attempt_id") == req_id] if req_id else []
            cleanups = [r for r in rows if r.get("record_kind") == "websocket_cleanup"
                        and r.get("parent_id") == root.get("attempt_id")]
            related = list(decision.get("related_attempt_ids", []))
            source_ids = [i for i in related if events.get(i, {}).get("role") == ProbeRole.ATTACK.value
                          and events.get(i, {}).get("record_kind") == "websocket_decision"]
            expected = [r["attempt_id"] for r in observations] + [r["attempt_id"] for r in cleanups] + source_ids
            outcome = decision.get("outcome")
            terminal = _terminal(decision)
            sent = bool(req_id)
            ok = (root.get("record_kind") == "websocket_attempt" and key is not None
                  and root.get("role") == decision.get("role")
                  and _same(root, decision) and _sequence(root) < _sequence(decision)
                  and len(cleanups) == 1 and related == expected
                  and cleanups[0].get("role") == ProbeRole.CLEANUP.value
                  and _same_identity(cleanups[0], root))
            if sent:
                ok = (ok and request.get("record_kind") == "websocket_request"
                      and request.get("parent_id") == root.get("attempt_id")
                      and request.get("role") == decision.get("role") and _same(root, request)
                      and _sequence(root) < _sequence(request) < _sequence(decision)
                      and decision.get("outcome") not in {ProbeOutcome.SKIPPED.value,
                                                           ProbeOutcome.UNEXECUTABLE.value})
                for obs in observations:
                    ok = (ok and obs.get("parent_id") == req_id and _same(request, obs)
                          and obs.get("role") == request.get("role")
                          and _sequence(request) < _sequence(obs) < _sequence(decision))
                if outcome == ProbeOutcome.MATCHED.value:
                    ok = ok and any(o.get("outcome") == ProbeOutcome.MATCHED.value for o in observations)
                elif outcome == ProbeOutcome.NO_MATCH.value:
                    ok = ok and bool(observations) and all(o.get("outcome") == ProbeOutcome.NO_MATCH.value
                                                            for o in observations)
                elif outcome == ProbeOutcome.TIMEOUT.value:
                    ok = ok and not observations and terminal == "timeout"
                elif outcome == ProbeOutcome.TRANSPORT_ERROR.value:
                    ok = ok and terminal in {"socket_error", "open_error", "send_error"}
                elif outcome == ProbeOutcome.VERIFICATION_ERROR.value:
                    ok = ok and terminal in {"evaluation_error", "malformed"}
            else:
                ok = (ok and not observations and terminal in {"open_error", "send_error", "timeout",
                                                               "evaluation_error", "malformed",
                                                               "state_profile_policy", "missing_replay_context",
                                                               "no_endpoint", "endpoint_limit"})
                if terminal in {"open_error", "send_error"}:
                    ok = ok and outcome == ProbeOutcome.TRANSPORT_ERROR.value
                elif terminal == "timeout":
                    ok = ok and outcome == ProbeOutcome.TIMEOUT.value
                elif terminal in {"evaluation_error", "malformed"}:
                    ok = ok and outcome == ProbeOutcome.VERIFICATION_ERROR.value
                elif terminal == "state_profile_policy":
                    ok = ok and outcome == ProbeOutcome.SKIPPED.value
                elif terminal in {"missing_replay_context", "no_endpoint", "endpoint_limit"}:
                    ok = ok and outcome == ProbeOutcome.UNEXECUTABLE.value
            if decision.get("role") == ProbeRole.VERIFY.value:
                source = events.get(source_ids[0], {}) if len(source_ids) == 1 else {}
                ok = (ok and source.get("outcome") == ProbeOutcome.MATCHED.value
                      and source.get("role") == ProbeRole.ATTACK.value
                      and source.get("decision_rule") == decision.get("decision_rule")
                      and source.get("decision_subject") == decision.get("decision_subject")
                      and _sequence(source) < _sequence(root))
            elif source_ids:
                ok = False
            if not ok:
                poisoned = True
            else:
                valid.append(decision)
        if poisoned:
            valid = []
        result[unit] = valid
    return result


def _valid_discovery(decision: dict, rows: list[dict]) -> bool:
    linked = [r for r in rows if r.get("record_kind") == "websocket_discovery"
              or (r.get("record_kind") == "websocket_cleanup"
                  and r.get("decision_rule") == DISCOVERY)]
    refs = decision.get("related_attempt_ids", [])
    return (decision.get("parent_id", "") == "" and not decision.get("request_attempt_id")
            and refs == [r["attempt_id"] for r in linked]
            and (decision.get("outcome") == ProbeOutcome.MATCHED.value
                 or decision.get("outcome") == ProbeOutcome.NO_MATCH.value))


def _same_identity(a: dict, b: dict) -> bool:
    return all(a.get(k) == b.get(k) for k in
               ("scan_id", "check", "completion_unit", "decision_rule", "decision_version", "wave"))


def _same(a: dict, b: dict) -> bool:
    return (_same_identity(a, b) and a.get("role") == b.get("role")
            and a.get("injection_key") == b.get("injection_key")
            and a.get("decision_subject") == b.get("decision_subject"))


def _terminal(row: dict) -> str:
    return row.get("rationale", "").split(";", 1)[0].removeprefix("terminal=")


def _sequence(row: dict) -> int:
    try:
        return int(row.get("attempt_id", "").rpartition(":")[2])
    except (TypeError, ValueError):
        return -1
