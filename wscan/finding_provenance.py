"""Typed evidence payloads at producer boundaries.

These schemas describe existing keys, not verification decisions. Finding keeps
its open evidence_details dict so legacy and scanner-specific keys survive.
"""
from typing import TypedDict


class AgentEvidenceDetails(TypedDict):
    """Agent replay observation, separate from deterministic verification."""

    agent_dynamic_reproduced: bool


class JsStaticEvidenceDetails(TypedDict):
    """Location and data flow behind a static JavaScript observation."""

    sink: str
    source: str
    tainted: bool
    line: int
    script: str
    snippet: str
