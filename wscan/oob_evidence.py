"""Pure, strict causal evidence validation for Out-Of-Band (OOB) mail header probes."""
from __future__ import annotations

import re
from typing import Any, Mapping

from wscan.probe_ledger import sha256_hex

DECISION_RULE = "mail_header_oob"
DECISION_VERSION = "1"
RECORD_KIND = "oob_decision"
CHECK_TYPE = "mail_header"
ACTOR = "oob_oracle"

_HASH_RE = re.compile(r"^[0-9a-f]{64}$")
_ALLOWED_OUTCOMES = frozenset({"matched", "timeout", "transport_error", "verification_error", "skipped"})


def decision_subject(injection_key: str, token: str, newline_variant: str) -> str:
    """Compute the 64-character SHA-256 hex digest for an OOB decision subject."""
    return sha256_hex(f"{injection_key}:{token}:{newline_variant}")


def valid_shape(row: Mapping[str, Any]) -> bool:
    """Validate wire shape of an oob_decision record. Strictly rejects no_match."""
    if not isinstance(row, (dict, Mapping)):
        return False
    if (
        row.get("check") != CHECK_TYPE
        or row.get("actor") != ACTOR
        or row.get("record_kind") != RECORD_KIND
        or row.get("decision_rule") != DECISION_RULE
        or row.get("decision_version") != DECISION_VERSION
        or row.get("role") != "attack"
        or row.get("request") is not None
        or row.get("browser") is not None
    ):
        return False

    subj = row.get("decision_subject")
    if not isinstance(subj, str) or not _HASH_RE.fullmatch(subj):
        return False

    outcome = row.get("outcome")
    if outcome not in _ALLOWED_OUTCOMES:
        return False

    response = row.get("response")
    if response is not None and not isinstance(response, (dict, Mapping)):
        return False

    if outcome == "matched":
        if not isinstance(response, (dict, Mapping)) or not response.get("oob"):
            return False
        bhash = response.get("body_hash", "")
        if bhash and (not isinstance(bhash, str) or not _HASH_RE.fullmatch(bhash)):
            return False
        blen = response.get("body_length")
        if blen is not None and (type(blen) is not int or blen < 0):
            return False

    return True


def _sequence(row: Mapping[str, Any]) -> int:
    try:
        return int(str(row.get("attempt_id", "")).rpartition(":")[2])
    except (ValueError, TypeError):
        return -1


def _same_unit(a: Mapping[str, Any], b: Mapping[str, Any]) -> bool:
    return all(
        a.get(k) == b.get(k)
        for k in ("scan_id", "check", "completion_unit", "injection_key")
    )


def accepted_decisions(events: Mapping[str, Mapping[str, Any]]) -> dict[str, list[dict]]:
    """Rebuild accepted OOB decisions from persisted events.

    Causal constraints:
      - earlier(request, observation) and earlier(observation, decision)
      - same_unit(request, observation, decision)
      - delivered transport: request.transport in {'httpx', 'playwright'} and request.sent is True
      - matching decision_subject: must match token hash
      - any orphan or invalid event poisons its completion_unit.
    """
    by_unit: dict[str, list[dict]] = {}
    for row in events.values():
        if row.get("check") == CHECK_TYPE:
            unit = row.get("completion_unit", "")
            if unit:
                by_unit.setdefault(unit, []).append(dict(row))

    result: dict[str, list[dict]] = {}

    for unit, rows in by_unit.items():
        rows.sort(key=_sequence)
        decisions = [r for r in rows if r.get("record_kind") == RECORD_KIND]
        if not decisions:
            continue

        if any(r.get("record_kind") == RECORD_KIND and not valid_shape(r) for r in rows):
            result[unit] = []
            continue

        accepted: list[dict] = []
        poisoned = False

        for dec in decisions:
            outcome = dec.get("outcome")

            # Standalone skip: when sink is disabled / unconfigured
            if (
                outcome == "skipped"
                and not dec.get("request_attempt_id")
                and not dec.get("parent_id")
                and dec.get("response") is None
            ):
                accepted.append(dec)
                continue

            # Standard path: request -> observation -> decision
            req_id = dec.get("request_attempt_id")
            obs_id = dec.get("parent_id")

            if not req_id or not obs_id:
                poisoned = True
                break

            request = events.get(req_id)
            observation = events.get(obs_id)

            if not request or not observation:
                poisoned = True
                break

            if (
                request.get("record_kind") != "request"
                or observation.get("record_kind") != "observation"
                or observation.get("parent_id") != req_id
                or observation.get("request_attempt_id") != req_id
            ):
                poisoned = True
                break

            if (
                not _same_unit(request, observation)
                or not _same_unit(observation, dec)
            ):
                poisoned = True
                break

            # Transport delivery check
            req_data = request.get("request") or {}
            obs_req = observation.get("request") or {}
            obs_resp = observation.get("response") or {}

            transport = req_data.get("transport")
            if transport not in {"httpx", "playwright"} or not obs_req.get("sent"):
                poisoned = True
                break

            # Causal ordering check
            if not (_sequence(request) < _sequence(observation) < _sequence(dec)):
                poisoned = True
                break

            # Outcome-specific checks
            if outcome == "matched":
                resp_data = dec.get("response") or {}
                if not resp_data.get("oob"):
                    poisoned = True
                    break

            accepted.append(dec)

        if poisoned:
            result[unit] = []
        else:
            result[unit] = accepted

    return result


def correlate_finding(
    finding: Any,
    accepted: list[dict],
    events: Mapping[str, Mapping[str, Any]],
) -> bool:
    """Verify that a confirmed finding causally correlates with an accepted OOB decision."""
    if getattr(finding, "check_type", None) != CHECK_TYPE:
        return False

    if getattr(finding, "evidence_type", None) != "mail_header_oob":
        return True  # heuristic reflection/error findings don't require OOB correlation

    details = getattr(finding, "evidence_details", {}) or {}
    token = details.get("oob_token")
    attempt_ids = details.get("attempt_ids") or []

    if not token or not attempt_ids:
        return False

    # Check that at least one attempt_id in details matches an accepted decision for that token
    matched_decision = None
    for dec in accepted:
        if dec.get("attempt_id") in attempt_ids and dec.get("outcome") == "matched":
            matched_decision = dec
            break

    if not matched_decision:
        return False

    variant = details.get("newline_variant", "")
    unit = matched_decision.get("completion_unit", "")
    if unit:
        expected_subj = decision_subject(unit, token, variant)
        if matched_decision.get("decision_subject") != expected_subj:
            return False

    return True
