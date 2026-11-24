"""Agent evaluation public artifact schema and canonical summary template."""
from __future__ import annotations

import json
import math
import re
from typing import Any, Mapping

PROFILES = ("standard", "candidate")
STATUSES = ("complete", "partial", "timeout", "blocked", "unsupported", "failed")
GATE_VERDICTS = ("pass", "warn", "fail", "inconclusive")
_DISTRIBUTION_FIELDS = (
    "count", "mean", "stddev", "variance", "min_value", "max_value",
    "ci_lower", "ci_upper", "confidence_level",
)
_METRIC_NAMES = (
    "coverage_rate", "recall", "safe_twin_fp", "total_findings",
    "duration_seconds", "total_tokens", "estimated_cost_usd",
)


def _object(properties: Mapping[str, Any], *, required: tuple[str, ...] | None = None) -> dict[str, Any]:
    return {
        "type": "object", "properties": dict(properties),
        "required": list(required if required is not None else properties),
        "additionalProperties": False,
    }


_INTEGER = {"type": "integer", "minimum": 0, "maximum": 1_000_000_000}
_NUMBER = {"type": "number", "minimum": -1_000_000_000_000, "maximum": 1_000_000_000_000}
_DISTRIBUTION = _object({
    "count": _INTEGER,
    "mean": _NUMBER,
    "stddev": {"type": "number", "minimum": 0, "maximum": 1_000_000_000_000},
    "variance": {"type": "number", "minimum": 0, "maximum": 1_000_000_000_000},
    "min_value": _NUMBER,
    "max_value": _NUMBER,
    "ci_lower": _NUMBER,
    "ci_upper": _NUMBER,
    "confidence_level": {"type": "number", "enum": [0.9, 0.95, 0.99]},
})
_NULLABLE_DISTRIBUTION = {"type": ["object", "null"], "objectSchema": _DISTRIBUTION}
_METRICS = _object({name: _NULLABLE_DISTRIBUTION for name in _METRIC_NAMES})
_STATUS_COUNTS = {
    "type": "object", "propertyNames": {"enum": list(STATUSES)},
    "additionalProperties": _INTEGER, "maxProperties": len(STATUSES),
}
_PROFILE = _object({
    "runs_count": _INTEGER,
    "status_counts": _STATUS_COUNTS,
    "metrics": _METRICS,
})

# This object is shared by the writer and verifier. All object levels close
# additionalProperties; any string field is constrained to an enum.
SCORECARD_SCHEMA = _object({
    "schema_version": {"type": "integer", "enum": [1]},
    "profiles": _object({profile: _PROFILE for profile in PROFILES}),
    "gate": _object({
        "verdict": {"type": "string", "enum": list(GATE_VERDICTS), "maxLength": 16},
        "passed": {"type": "boolean"},
        "rollback_recorded": {"type": "boolean"},
        "promoted_profile": {"type": "string", "enum": list(PROFILES), "maxLength": 16},
        "warnings_count": _INTEGER,
    }),
})


def _fail(path: str, message: str) -> None:
    raise ValueError(f"invalid scorecard at {path}: {message}")


def _validate(value: Any, schema: Mapping[str, Any], path: str) -> None:
    expected = schema["type"]
    allowed_types = expected if isinstance(expected, list) else [expected]
    matches = (
        ("object" in allowed_types and isinstance(value, dict))
        or ("array" in allowed_types and isinstance(value, list))
        or ("string" in allowed_types and isinstance(value, str))
        or ("boolean" in allowed_types and type(value) is bool)
        or ("integer" in allowed_types and type(value) is int)
        or ("number" in allowed_types and type(value) in (int, float))
        or ("null" in allowed_types and value is None)
    )
    if not matches:
        _fail(path, f"expected {allowed_types}")
    if value is None:
        return
    if "enum" in schema and value not in schema["enum"]:
        _fail(path, "value is outside the allowed enumeration")
    if isinstance(value, str):
        if len(value) > schema.get("maxLength", 4096):
            _fail(path, "string exceeds maximum length")
        if not value.isascii() or any(ord(char) < 0x20 for char in value):
            _fail(path, "string contains disallowed characters")
        if "pattern" in schema and not re.fullmatch(schema["pattern"], value):
            _fail(path, "string does not match its identifier pattern")
    if type(value) in (int, float):
        if isinstance(value, float) and not math.isfinite(value):
            _fail(path, "number must be finite")
        if value < schema.get("minimum", value) or value > schema.get("maximum", value):
            _fail(path, "number is outside the allowed range")
    if isinstance(value, dict):
        if len(value) > schema.get("maxProperties", len(value)):
            _fail(path, "too many object properties")
        for key in schema.get("required", ()):
            if key not in value:
                _fail(path, f"missing required key {key!r}")
        props = schema.get("properties", {})
        for key, child in value.items():
            if not isinstance(key, str) or not key.isascii() or len(key) > 64:
                _fail(path, "object key is not an allowed ASCII identifier")
            if "propertyNames" in schema:
                _validate(key, {"type": "string", **schema["propertyNames"]}, f"{path}.<key>")
            child_schema = props.get(key)
            if child_schema is None:
                child_schema = schema.get("additionalProperties")
                if child_schema is False or child_schema is None:
                    _fail(path, f"unexpected key {key!r}")
            if child_schema is True:
                continue
            if "objectSchema" in child_schema and isinstance(child, dict):
                _validate(child, child_schema["objectSchema"], f"{path}.{key}")
            else:
                _validate(child, child_schema, f"{path}.{key}")
    if isinstance(value, list):
        if len(value) > schema.get("maxItems", 0):
            _fail(path, "array is not permitted or exceeds its limit")


def validate_scorecard(value: Any) -> dict[str, Any]:
    """Validate exact structure, bounded types, enums, nested keys, and invariants."""
    _validate(value, SCORECARD_SCHEMA, "$scorecard")
    gate = value["gate"]
    if gate["passed"] != (gate["verdict"] == "pass"):
        _fail("$.gate", "passed must be true exactly when verdict is pass")
    expected_profile = "candidate" if gate["passed"] else "standard"
    expected_rollback = not gate["passed"]
    if gate["promoted_profile"] != expected_profile or gate["rollback_recorded"] != expected_rollback:
        _fail("$.gate", "promotion and rollback must match the gate decision")
    return value


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key: {key}")
        result[key] = value
    return result


def parse_scorecard(text: str) -> dict[str, Any]:
    try:
        value = json.loads(text, object_pairs_hook=_reject_duplicate_keys,
                           parse_constant=lambda value: (_ for _ in ()).throw(ValueError(f"invalid number: {value}")))
    except (json.JSONDecodeError, TypeError) as exc:
        raise ValueError("scorecard is not valid strict JSON") from exc
    return validate_scorecard(value)


def render_summary(scorecard: Mapping[str, Any]) -> str:
    """Canonical Markdown: every interpolated value has already passed schema validation."""
    data = validate_scorecard(scorecard)
    gate = data["gate"]
    return (
        "# Agent evaluation summary\n\n"
        f"- Gate: `{gate['verdict']}`\n"
        f"- Candidate promotion: `{gate['promoted_profile']}`\n"
        f"- Rollback recorded: `{str(gate['rollback_recorded']).lower()}`\n"
        f"- Unmonitored invariants: {gate['warnings_count']} (WARN)\n"
        f"- Standard runs: {data['profiles']['standard']['runs_count']}\n"
        f"- Candidate runs: {data['profiles']['candidate']['runs_count']}\n"
    )
