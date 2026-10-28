"""Versioned Scanner Capability Manifest Module.

Pure module to derive a versioned backend capability manifest from the
SCANNERS registry and ScannerContract metadata.

INVARIANT: Declaration != Runtime Execution Coverage
---------------------------------------------------
This manifest represents *declared static capabilities* (what scanners
declare they are designed to inspect). It explicitly does NOT claim
runtime execution coverage, tested verification, or dynamic detection
efficacy. Downstream consumers (e.g. UI capability readers) must never
manufacture execution coverage or pass/fail claims from this declaration.
"""
from __future__ import annotations

import copy
from typing import Any, Mapping, Sequence

from wscan.scanner_contract import (
    Carrier,
    CarrierCapability,
    CapabilityState,
    CostClass,
    ExecutionKind,
    Prerequisite,
    ScannerContract,
    StateChangeClass,
)
from wscan.scanners.base import _cvss_for


SCHEMA_VERSION: str = "1.0.0"
MANIFEST_KIND: str = "scanner_capability_manifest"
DEFAULT_CHECKS: tuple[str, ...] = ("sqli", "xss", "os")
DEFAULT_APPLICABLE_MODES: tuple[str, ...] = ("normal", "hybrid")
DECLARATION_DISCLAIMER: str = (
    "Static capability declaration derived from scanner registry and contract metadata. "
    "Represents declared static capabilities only; does NOT assert runtime execution "
    "coverage, tested verification, or dynamic pass/fail guarantees."
)

REQUIRED_TOP_LEVEL_FIELDS: tuple[str, ...] = (
    "schema_version",
    "manifest_kind",
    "declaration_only",
    "execution_coverage_claimed",
    "declaration_disclaimer",
    "default_checks",
    "scanner_count",
    "scanner_ids",
    "scanners",
)

REQUIRED_SCANNER_FIELDS: tuple[str, ...] = (
    "id",
    "name",
    "check_type",
    "severity",
    "cvss",
    "is_default",
    "applicable_modes",
    "state_change",
    "cost",
    "prerequisites",
    "execution_kinds",
    "has_page_level",
    "supports_json_body",
    "supports_xml_body",
    "always_state_changing",
    "declared_carriers",
    "declaration_only",
)

REQUIRED_CARRIER_FIELDS: tuple[str, ...] = (
    "carrier",
    "state",
    "value_kinds",
    "transports",
    "payload_shapes",
    "browser_required",
    "structured_payload",
    "reason",
    "task",
    "declaration_only",
)


def _extract_carrier_capability(cap: CarrierCapability | None, carrier: Carrier) -> dict[str, Any]:
    """Extract a carrier declaration entry without asserting runtime coverage."""
    if cap is None:
        return {
            "carrier": carrier.value,
            "state": "unclassified",
            "value_kinds": [],
            "transports": [],
            "payload_shapes": [],
            "browser_required": False,
            "structured_payload": False,
            "reason": "",
            "task": "",
            "declaration_only": True,
        }
    return {
        "carrier": carrier.value,
        "state": cap.state.value,
        "value_kinds": sorted(vk.value for vk in cap.value_kinds),
        "transports": sorted(t.value for t in cap.transports),
        "payload_shapes": sorted(s.value for s in cap.payload_shapes),
        "browser_required": bool(cap.browser_required),
        "structured_payload": bool(cap.structured_payload),
        "reason": str(cap.reason or ""),
        "task": str(cap.task or ""),
        "declaration_only": True,
    }


def _extract_scanner_capability(
    scanner_id: str,
    scanner_cls: type,
    *,
    default_checks: Sequence[str],
) -> dict[str, Any]:
    """Extract metadata and declared capabilities for a single scanner class."""
    check_type = str(getattr(scanner_cls, "CHECK_TYPE", scanner_id))
    severity = str(getattr(scanner_cls, "SEVERITY", "medium"))
    cvss_vector, cvss_score = _cvss_for(check_type)

    contract: ScannerContract | None = getattr(scanner_cls, "CONTRACT", None)
    if not isinstance(contract, ScannerContract):
        contract = None

    # Applicable scan modes: deterministic scanners default to normal and hybrid.
    raw_modes = getattr(scanner_cls, "APPLICABLE_MODES", None) or getattr(scanner_cls, "MODES", None)
    if raw_modes is not None:
        applicable_modes = sorted(str(m) for m in raw_modes)
    else:
        applicable_modes = list(DEFAULT_APPLICABLE_MODES)

    # Carrier declarations: iterate all defined Carriers deterministically
    carriers_dict: dict[str, Any] = {}
    for carrier in sorted(Carrier, key=lambda c: c.value):
        cap = contract.capability(carrier) if contract else None
        carriers_dict[carrier.value] = _extract_carrier_capability(cap, carrier)

    if contract:
        state_change = contract.state_change.value
        cost = contract.cost.value
        prerequisites = sorted(p.value for p in contract.prerequisites)
        execution_kinds = sorted(e.value for e in contract.execution_kinds)
        has_page = bool(getattr(scanner_cls, "HAS_PAGE_LEVEL", False) or contract.has_page_level)
        supp_json = bool(getattr(scanner_cls, "SUPPORTS_JSON_BODY", False) or contract.supports_json_body)
        always_state = bool(getattr(scanner_cls, "ALWAYS_STATE_CHANGING", False) or contract.always_state_changing)
    else:
        state_change = StateChangeClass.CONDITIONAL.value
        cost = CostClass.MEDIUM.value
        prerequisites = []
        execution_kinds = []
        has_page = bool(getattr(scanner_cls, "HAS_PAGE_LEVEL", False))
        supp_json = bool(getattr(scanner_cls, "SUPPORTS_JSON_BODY", False))
        always_state = bool(getattr(scanner_cls, "ALWAYS_STATE_CHANGING", False))

    supp_xml = bool(getattr(scanner_cls, "SUPPORTS_XML_BODY", False))

    return {
        "id": scanner_id,
        "name": scanner_cls.__name__,
        "check_type": check_type,
        "severity": severity,
        "cvss": {
            "score": float(cvss_score),
            "vector": str(cvss_vector),
        },
        "is_default": scanner_id in default_checks or check_type in default_checks,
        "applicable_modes": applicable_modes,
        "state_change": state_change,
        "cost": cost,
        "prerequisites": prerequisites,
        "execution_kinds": execution_kinds,
        "has_page_level": has_page,
        "supports_json_body": supp_json,
        "supports_xml_body": supp_xml,
        "always_state_changing": always_state,
        "declared_carriers": carriers_dict,
        "declaration_only": True,
    }


def build_capability_manifest(
    registry: Mapping[str, type] | None = None,
    *,
    default_checks: Sequence[str] = DEFAULT_CHECKS,
) -> dict[str, Any]:
    """Build a versioned, static capability manifest from scanner registry.

    Pure function: deterministic output, no I/O, no browser dependency.

    Parameters:
        registry: check_type -> scanner class mapping. If None, imports SCANNERS.
        default_checks: Sequence of check names considered default (sqli, xss, os).

    Returns:
        JSON-serializable manifest dict conforming to schema_version 1.0.0.
    """
    if registry is None:
        from wscan.scanners import SCANNERS
        registry = SCANNERS

    defaults_list = list(default_checks)
    scanners: dict[str, Any] = {}
    for scanner_id in sorted(registry.keys()):
        cls = registry[scanner_id]
        scanners[scanner_id] = _extract_scanner_capability(
            scanner_id,
            cls,
            default_checks=defaults_list,
        )

    return {
        "schema_version": SCHEMA_VERSION,
        "manifest_kind": MANIFEST_KIND,
        "declaration_only": True,
        "execution_coverage_claimed": False,
        "declaration_disclaimer": DECLARATION_DISCLAIMER,
        "default_checks": defaults_list,
        "scanner_count": len(scanners),
        "scanner_ids": sorted(scanners.keys()),
        "scanners": scanners,
    }


def validate_capability_manifest(
    manifest: Any,
    *,
    expected_schema_version: str = SCHEMA_VERSION,
) -> list[str]:
    """Validate a capability manifest dictionary against schema rules.

    Pure function: returns a list of human-readable error messages.
    An empty list indicates the manifest is fully valid.
    """
    errors: list[str] = []
    if not isinstance(manifest, dict):
        return ["Manifest must be a JSON object / dict"]

    # Schema version
    if "schema_version" not in manifest:
        errors.append("Missing required top-level field 'schema_version'")
    elif manifest["schema_version"] != expected_schema_version:
        errors.append(
            f"Schema version mismatch: expected '{expected_schema_version}', "
            f"got '{manifest['schema_version']}'"
        )

    # Top-level required fields
    for field in REQUIRED_TOP_LEVEL_FIELDS:
        if field == "schema_version":
            continue
        if field not in manifest:
            errors.append(f"Missing required top-level field '{field}'")

    if manifest.get("manifest_kind") != MANIFEST_KIND:
        errors.append(
            f"Invalid manifest_kind: expected '{MANIFEST_KIND}', "
            f"got '{manifest.get('manifest_kind')}'"
        )

    # Invariant: declaration != execution coverage
    if manifest.get("declaration_only") is not True:
        errors.append("Manifest invalid: 'declaration_only' must be True")
    if manifest.get("execution_coverage_claimed") is not False:
        errors.append(
            "Manifest invalid: 'execution_coverage_claimed' must be False "
            "(declaration manifest cannot claim runtime execution coverage)"
        )

    # Disclaimer
    if "declaration_disclaimer" in manifest:
        disclaimer = manifest.get("declaration_disclaimer")
        if not isinstance(disclaimer, str) or not disclaimer.strip():
            errors.append("Field 'declaration_disclaimer' must be a non-empty string")

    # default_checks
    if "default_checks" in manifest:
        default_checks = manifest.get("default_checks")
        if not isinstance(default_checks, list):
            errors.append("Field 'default_checks' must be a list of strings")

    # scanner_ids and count
    if "scanner_ids" in manifest:
        scanner_ids = manifest.get("scanner_ids")
        if not isinstance(scanner_ids, list):
            errors.append("Field 'scanner_ids' must be a list of strings")

    if "scanner_count" in manifest:
        scanner_count = manifest.get("scanner_count")
        if not isinstance(scanner_count, int):
            errors.append("Field 'scanner_count' must be an integer")

    scanners = manifest.get("scanners")
    if not isinstance(scanners, dict):
        errors.append("Field 'scanners' must be a dict")
        return errors

    if "scanner_ids" in manifest and isinstance(manifest.get("scanner_ids"), list):
        if sorted(scanners.keys()) != sorted(manifest["scanner_ids"]):
            errors.append("Field 'scanner_ids' does not match keys of 'scanners'")

    if "scanner_count" in manifest and isinstance(manifest.get("scanner_count"), int):
        if len(scanners) != manifest["scanner_count"]:
            errors.append(
                f"Field 'scanner_count' ({manifest['scanner_count']}) does not match "
                f"number of entries in 'scanners' ({len(scanners)})"
            )

    # Validate each scanner entry
    for scanner_id, sc in scanners.items():
        if not isinstance(sc, dict):
            errors.append(f"Scanner entry '{scanner_id}' must be a dict")
            continue

        if sc.get("id") != scanner_id:
            errors.append(f"Scanner entry id '{sc.get('id')}' does not match key '{scanner_id}'")

        if sc.get("declaration_only") is not True:
            errors.append(f"Scanner '{scanner_id}' declaration_only must be True")

        for req_field in REQUIRED_SCANNER_FIELDS:
            if req_field not in sc:
                errors.append(f"Scanner '{scanner_id}' missing required field '{req_field}'")

        if "cvss" in sc:
            cvss = sc.get("cvss")
            if not isinstance(cvss, dict):
                errors.append(f"Scanner '{scanner_id}' field 'cvss' must be a dict")
            else:
                if "score" not in cvss or not isinstance(cvss.get("score"), (int, float)):
                    errors.append(f"Scanner '{scanner_id}' cvss missing numeric 'score'")
                if "vector" not in cvss or not isinstance(cvss.get("vector"), str):
                    errors.append(f"Scanner '{scanner_id}' cvss missing string 'vector'")

        if "applicable_modes" in sc:
            modes = sc.get("applicable_modes")
            if not isinstance(modes, list):
                errors.append(f"Scanner '{scanner_id}' applicable_modes must be a list of strings")

        if "declared_carriers" in sc:
            declared_carriers = sc.get("declared_carriers")
            if not isinstance(declared_carriers, dict):
                errors.append(f"Scanner '{scanner_id}' field 'declared_carriers' must be a dict")
            else:
                for carrier_name, ccap in declared_carriers.items():
                    if not isinstance(ccap, dict):
                        errors.append(f"Scanner '{scanner_id}' carrier '{carrier_name}' must be a dict")
                        continue
                    if ccap.get("declaration_only") is not True:
                        errors.append(
                            f"Scanner '{scanner_id}' carrier '{carrier_name}' declaration_only must be True"
                        )
                    for req_cfield in REQUIRED_CARRIER_FIELDS:
                        if req_cfield not in ccap:
                            errors.append(
                                f"Scanner '{scanner_id}' carrier '{carrier_name}' missing required field '{req_cfield}'"
                            )

    return errors


def assert_valid_capability_manifest(
    manifest: Any,
    *,
    expected_schema_version: str = SCHEMA_VERSION,
) -> None:
    """Validate manifest and raise ValueError if any schema rule is violated."""
    errors = validate_capability_manifest(manifest, expected_schema_version=expected_schema_version)
    if errors:
        raise ValueError(
            f"Capability manifest failed schema validation ({len(errors)} error(s)):\n"
            + "\n".join(f"- {e}" for e in errors)
        )


_CACHED_MANIFEST: dict[str, Any] | None = None


def get_capability_manifest(*, refresh: bool = False) -> dict[str, Any]:
    """Return the cached or freshly built manifest for the current SCANNERS registry.

    Returns a deep copy so caller mutations cannot corrupt cached state.
    """
    global _CACHED_MANIFEST
    if _CACHED_MANIFEST is None or refresh:
        manifest = build_capability_manifest()
        assert_valid_capability_manifest(manifest)
        _CACHED_MANIFEST = manifest
    return copy.deepcopy(_CACHED_MANIFEST)
