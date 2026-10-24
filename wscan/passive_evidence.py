"""共有した実 HTTP ヘッダ入力と受動判定の永続相関（非 network 証拠とは分離）。"""


def accepted_decisions(events):
    def earlier(a, b):
        return int(a["attempt_id"].rpartition(":")[2]) < int(b["attempt_id"].rpartition(":")[2])

    def valid(row):
        observation = events.get(row.get("parent_id"), {})
        request = events.get(row.get("request_attempt_id"), {})
        response = observation.get("response") or {}
        observed_request = observation.get("request") or {}
        submitted_request = request.get("request") or {}
        if not (observation.get("record_kind") == "observation"
                and request.get("record_kind") == "request"
                and observation.get("request_attempt_id") == request.get("attempt_id")
                and observation.get("parent_id") == request.get("attempt_id")
                and observation.get("actor") == request.get("actor") == "api_get_capture"
                and observation.get("check") == request.get("check") == ""
                and observation.get("completion_unit") == request.get("completion_unit") == ""
                and observation.get("role") == request.get("role") == "discover"
                and observation.get("scan_id") == request.get("scan_id") == row.get("scan_id")
                and observation.get("injection_key") == request.get("injection_key") == row.get("injection_key")
                and len(row.get("injection_key", "")) == 64
                and observed_request.get("sent") is True
                and submitted_request.get("method") == "GET"
                and submitted_request.get("transport") == "playwright"
                and all(observed_request.get(k) == submitted_request.get(k)
                        for k in ("method", "url", "transport", "body_hash", "body_length"))
                and type(response.get("status")) is int and 200 <= response["status"] < 300
                and isinstance(response.get("headers_hash"), str)
                and len(response["headers_hash"]) == 64
                and all(c in "0123456789abcdef" for c in response["headers_hash"])
                and type(response.get("headers_length")) is int and response["headers_length"] >= 2
                and all((row.get("response") or {}).get(k) == response.get(k)
                        for k in ("status", "final_url", "headers_hash", "headers_length"))
                and (row.get("request") or {}).get("sent") is True
                and earlier(request, observation) and earlier(observation, row)):
            return False
        parents = row.get("control_attempt_ids", [])
        if row.get("role") == "attack":
            return not parents
        if row.get("role") != "verify" or len(parents) != 1:
            return False
        original = events.get(parents[0], {})
        rule = row.get("decision_rule", "")
        original_rule = original.get("decision_rule", "")
        return (original.get("record_kind") == "passive_decision"
                and original.get("role") == "attack" and original.get("outcome") == "matched"
                and original.get("check") == row.get("check")
                and original.get("injection_key") == row.get("injection_key")
                and original_rule == row.get("wave")
                and (original_rule == rule or rule == "security_header_missing"
                     and original_rule.startswith("missing_"))
                and earlier(original, request) and valid(original))

    result = {}
    for row in events.values():
        if row.get("record_kind") == "passive_decision":
            result.setdefault(row.get("completion_unit"), []).append(row if valid(row) else None)
    return {unit: [] if None in rows else rows for unit, rows in result.items()}
