"""Bounded causal validation for GraphQL; ordinary comparison rules stay strict."""
from urllib.parse import urlsplit

DISCOVERY = "graphql_discovery"
RULES = ("graphql_introspection", "graphql_batch", "graphql_dos_alias",
         "graphql_dos_depth", "graphql_dos", "graphql_injection", "graphql_sensitive")
VERIFY_RULES = {"graphql_introspection", "graphql_batch", "graphql_injection", "graphql_sensitive"}
ERRORS = {"timeout", "transport_error", "verification_error", "unexecutable"}


def valid_shape(row):
    return (row.get("check") == "graphql" and row.get("actor") == "graphql_oracle"
            and row.get("decision_version") == "1"
            and row.get("decision_rule") in {DISCOVERY, *RULES}
            and row.get("role") in {"baseline", "attack", "verify"}
            and row.get("request") is None
            and (row.get("response") is None or isinstance(row.get("response"), dict))
            and row.get("browser") is None and row.get("outcome") is not None
            and isinstance(row.get("decision_subject"), str) and len(row["decision_subject"]) == 64
            and all(c in "0123456789abcdef" for c in row["decision_subject"]))


def accepted_decisions(events):
    def earlier(a, b):
        return int(a["attempt_id"].rpartition(":")[2]) < int(b["attempt_id"].rpartition(":")[2])

    def same(a, b):
        return all(a.get(k) == b.get(k) for k in
                   ("scan_id", "check", "completion_unit", "injection_key"))

    def endpoint(row):
        parts = urlsplit((row.get("request") or {}).get("url", ""))
        return parts.scheme, parts.netloc, parts.path

    def delivered(observation, row):
        request = events.get(observation.get("request_attempt_id"), {})
        response = observation.get("response") or {}
        digest = response.get("body_hash", "")
        return (observation.get("record_kind") == "observation"
                and request.get("record_kind") == "request"
                and observation.get("parent_id") == request.get("attempt_id")
                and same(request, observation) and same(observation, row)
                and observation.get("role") == request.get("role")
                and observation.get("wave") == request.get("wave")
                and (observation.get("request") or {}).get("sent") is True
                and (request.get("request") or {}).get("transport") == "graphql"
                and all((observation.get("request") or {}).get(k) ==
                        (request.get("request") or {}).get(k)
                        for k in ("method", "url", "transport", "body_hash", "body_length"))
                and isinstance(digest, str) and len(digest) == 64
                and all(c in "0123456789abcdef" for c in digest)
                and type(response.get("body_length")) is int and response["body_length"] >= 0
                and earlier(request, observation) and earlier(observation, row))

    cache = {}

    def valid(row):
        aid = row.get("attempt_id")
        if aid in cache:
            return cache[aid]
        cache[aid] = False
        if row.get("record_kind") != "graphql_decision" or not valid_shape(row):
            return False
        request = events.get(row.get("request_attempt_id"), {})
        parent = events.get(row.get("parent_id"), {})
        refs = row.get("related_attempt_ids", [])
        baselines = row.get("baseline_attempt_ids", [])
        rule, role = row.get("decision_rule"), row.get("role")
        if (not row.get("request_attempt_id") and not row.get("parent_id")
                and row.get("request") is None and row.get("response") is None
                and row.get("outcome") in {"skipped", "unexecutable"}
                and row.get("rationale") in {"state_profile_policy", "missing_replay_payload"}
                and not refs and not baselines and not row.get("control_attempt_ids")):
            cache[aid] = True
            return True
        if (request.get("record_kind") != "request" or not same(request, row)
                or request.get("role") != role or request.get("wave") != row.get("wave")
                or (request.get("request") or {}).get("transport") != "graphql"
                or not earlier(request, row) or row.get("control_attempt_ids")
                or len(set(refs)) != len(refs) or len(set(baselines)) != len(baselines)):
            return False
        terminal = (parent == request and row.get("response") is None
                    and row.get("outcome") in ERRORS)
        if not terminal and not (parent.get("request_attempt_id") == request.get("attempt_id")
                and parent.get("role") == role and parent.get("wave") == row.get("wave")
                and delivered(parent, row)
                and all((row.get("response") or {}).get(k) == (parent.get("response") or {}).get(k)
                        for k in ("body_hash", "body_length", "status", "final_url"))):
            return False
        if role == "baseline":
            ok = rule == DISCOVERY and not baselines and not refs
        elif role == "verify":
            original = events.get(refs[0], {}) if len(refs) == 1 else {}
            original_request = events.get(original.get("request_attempt_id"), {})
            ok = (rule in VERIFY_RULES and not baselines
                  and original.get("role") == "attack" and original.get("outcome") == "matched"
                  and original.get("scan_id") == row.get("scan_id")
                  and original.get("decision_rule") == rule and earlier(original, request)
                  and original.get("decision_subject") == row.get("decision_subject")
                  and (original_request.get("request") or {}).get("url") ==
                      (request.get("request") or {}).get("url")
                  and all((original_request.get("request") or {}).get(k) ==
                          (request.get("request") or {}).get(k) for k in ("method", "body_hash", "body_length"))
                  and valid(original))
        else:
            ok = bool(baselines) and rule in RULES
            for ref in baselines:
                baseline = events.get(ref, {})
                roots = [r for r in events.values() if r.get("request_attempt_id") == ref
                         and r.get("record_kind") == "graphql_decision"
                         and r.get("outcome") == "matched" and r.get("role") == "baseline"]
                ok = (ok and same(baseline, row) and endpoint(baseline) == endpoint(request)
                      and earlier(baseline, request) and any(earlier(r, request) and valid(r) for r in roots))
            if rule == "graphql_dos":
                other = events.get(refs[0], {}) if len(refs) == 1 else {}
                legs = {r.get("decision_rule"): r for r in events.values()
                        if r.get("record_kind") == "graphql_decision"
                        and r.get("parent_id") in {row.get("parent_id"), other.get("attempt_id")}
                        and r.get("decision_rule") in {"graphql_dos_alias", "graphql_dos_depth"}
                        and earlier(r, row) and valid(r)}
                ok = (ok and len(refs) == 1 and delivered(other, row)
                      and other.get("role") == "attack" and other.get("wave") == row.get("wave")
                      and other.get("request_attempt_id") != request.get("attempt_id")
                      and endpoint(events.get(other.get("request_attempt_id"), {})) == endpoint(request)
                      and len(legs) == 2)
                if row.get("outcome") in {"matched", "no_match"}:
                    outcomes = {r.get("outcome") for r in legs.values()}
                    ok = ok and outcomes <= {"matched", "no_match"}
                    ok = ok and ((row["outcome"] == "matched") == (outcomes == {"matched"}))
                elif row.get("outcome") == "blocked":
                    outcomes = {r.get("outcome") for r in legs.values()}
                    ok = ok and "blocked" in outcomes and outcomes <= {"matched", "no_match", "blocked"}
            else:
                ok = ok and not refs
        cache[aid] = bool(ok)
        return bool(ok)

    result = {}
    for row in events.values():
        if row.get("record_kind") == "graphql_decision":
            result.setdefault(row.get("completion_unit"), []).append(row if valid(row) else None)
    for unit, rows in result.items():
        requests = [r for r in events.values() if r.get("record_kind") == "request"
                    and r.get("check") == "graphql" and r.get("completion_unit") == unit]
        decided = {r.get("request_attempt_id") for r in rows if r is not None}
        if None in rows or any(r["attempt_id"] not in decided for r in requests):
            result[unit] = []
    return result
