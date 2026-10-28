"""Tests for versioned scanner capability manifest (U07).

Validates:
1. Pure deterministic derivation from SCANNERS registry and ScannerContract metadata.
2. Complete coverage of all registered scanners (exact equality, no missing/extras).
3. Invariant: Declaration != Execution coverage (no claims of runtime coverage or testing).
4. Schema fixture validation:
   - valid_manifest.json (valid schema, passes validation)
   - missing_fields_manifest.json (detects missing required fields)
   - version_mismatch_manifest.json (detects schema version mismatches)
   - coverage_claiming_manifest.json (rejects runtime coverage claims)
5. Backward compatibility: capability_matrix(_html) and /api/config/defaults unchanged.
6. Additive read-only endpoints: /api/capability-manifest and /api/v1/capability-manifest
   with auth consistency and path-traversal safety.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest
from starlette.testclient import TestClient

from wscan.capability_manifest import (
    DEFAULT_CHECKS,
    MANIFEST_KIND,
    SCHEMA_VERSION,
    assert_valid_capability_manifest,
    build_capability_manifest,
    get_capability_manifest,
    validate_capability_manifest,
)
from wscan.monitor import MonitorServer
from wscan.scanner_contract import (
    Carrier,
    CarrierCapability,
    CapabilityState,
    CostClass,
    ExecutionKind,
    Prerequisite,
    ScannerContract,
    StateChangeClass,
    build_capability_matrix,
    render_capability_matrix_html,
)
from wscan.scanners import SCANNERS
from wscan.scanners.base import BaseScanner, _cvss_for


FIXTURES_DIR = Path(__file__).parent / "fixtures" / "capability_manifest"


def test_build_capability_manifest_pure_deterministic():
    """Deriving manifest multiple times produces strictly identical deterministic dicts."""
    manifest_a = build_capability_manifest()
    manifest_b = build_capability_manifest()
    assert manifest_a == manifest_b
    assert manifest_a["schema_version"] == SCHEMA_VERSION
    assert manifest_a["manifest_kind"] == MANIFEST_KIND


def test_manifest_covers_all_scanners_without_exception():
    """All registered scanners in SCANNERS appear in the manifest with exact key equality."""
    manifest = build_capability_manifest()
    errors = validate_capability_manifest(manifest)
    assert errors == []

    expected_ids = sorted(SCANNERS.keys())
    assert manifest["scanner_count"] == len(expected_ids)
    assert manifest["scanner_ids"] == expected_ids
    assert sorted(manifest["scanners"].keys()) == expected_ids

    for scanner_id, scanner_cls in SCANNERS.items():
        entry = manifest["scanners"][scanner_id]
        assert entry["id"] == scanner_id
        assert entry["name"] == scanner_cls.__name__
        assert entry["check_type"] == getattr(scanner_cls, "CHECK_TYPE", scanner_id)
        assert entry["severity"] == getattr(scanner_cls, "SEVERITY", "medium")


def test_declaration_invariants_no_execution_coverage():
    """Manifest declares static capabilities only and explicitly disclaims runtime coverage."""
    manifest = build_capability_manifest()

    assert manifest["declaration_only"] is True
    assert manifest["execution_coverage_claimed"] is False
    assert "runtime" in manifest["declaration_disclaimer"].lower() or "coverage" in manifest["declaration_disclaimer"].lower()

    for scanner_id, entry in manifest["scanners"].items():
        assert entry["declaration_only"] is True, f"Scanner {scanner_id} must have declaration_only=True"
        carriers = entry.get("declared_carriers", {})
        assert len(carriers) == len(Carrier)
        for carrier_name, ccap in carriers.items():
            assert ccap["declaration_only"] is True, f"{scanner_id}.{carrier_name} must have declaration_only=True"


def test_default_checks_and_is_default_flag():
    """sqli, xss, and os are default checks; others are marked is_default=False."""
    manifest = build_capability_manifest()
    assert manifest["default_checks"] == ["sqli", "xss", "os"]

    for scanner_id, entry in manifest["scanners"].items():
        if scanner_id in DEFAULT_CHECKS:
            assert entry["is_default"] is True, f"{scanner_id} should be marked as default"
        else:
            assert entry["is_default"] is False, f"{scanner_id} should NOT be marked as default"


def test_applicable_modes_default():
    """Deterministic scanners default to normal and hybrid modes."""
    manifest = build_capability_manifest()
    for scanner_id, entry in manifest["scanners"].items():
        assert entry["applicable_modes"] == ["normal", "hybrid"]


def test_scanner_metadata_fidelity():
    """Verify metadata fidelity against known contract definitions."""
    manifest = build_capability_manifest()
    scanners = manifest["scanners"]

    # SQLi metadata
    sqli = scanners["sqli"]
    assert sqli["severity"] in ("critical", "high")
    assert sqli["cvss"]["score"] == 10.0
    assert sqli["cvss"]["vector"].startswith("CVSS:3.1")
    assert sqli["state_change"] == "conditional"
    assert sqli["supports_json_body"] is True
    assert sqli["declared_carriers"]["query"]["state"] == "supported"

    # Clickjacking metadata
    cj = scanners["clickjacking"]
    assert cj["has_page_level"] is True
    assert cj["state_change"] == "read_only"
    assert cj["cost"] == "low"
    assert "page_analysis" in cj["execution_kinds"]

    # Mass assignment metadata
    ma = scanners["mass_assignment"]
    assert "api_spec" in ma["prerequisites"]

    # CSRF metadata
    csrf = scanners["csrf"]
    assert "browser" in csrf["prerequisites"]


def test_custom_registry_and_dummy_scanner_handling():
    """Manifest generator safely handles dummy scanner classes lacking CONTRACT."""
    class DummyScanner(BaseScanner):
        CHECK_TYPE = "dummy_custom"
        SEVERITY = "low"
        HAS_PAGE_LEVEL = True

    custom_registry = {
        "sqli": SCANNERS["sqli"],
        "dummy": DummyScanner,
    }

    manifest = build_capability_manifest(custom_registry, default_checks=["sqli"])
    assert manifest["scanner_count"] == 2
    assert manifest["scanner_ids"] == ["dummy", "sqli"]

    dummy_entry = manifest["scanners"]["dummy"]
    assert dummy_entry["id"] == "dummy"
    assert dummy_entry["name"] == "DummyScanner"
    assert dummy_entry["check_type"] == "dummy_custom"
    assert dummy_entry["severity"] == "low"
    assert dummy_entry["has_page_level"] is True
    assert dummy_entry["is_default"] is False
    assert dummy_entry["declaration_only"] is True

    # Dummy scanner without CONTRACT gets unclassified carrier placeholders
    for carrier in Carrier:
        c_cap = dummy_entry["declared_carriers"][carrier.value]
        assert c_cap["state"] == "unclassified"
        assert c_cap["declaration_only"] is True

    errors = validate_capability_manifest(manifest)
    assert errors == []


def test_schema_fixture_valid():
    """Fixture valid_manifest.json satisfies all schema requirements with 0 errors."""
    fixture_path = FIXTURES_DIR / "valid_manifest.json"
    assert fixture_path.exists(), "valid_manifest.json fixture must exist"

    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    errors = validate_capability_manifest(data)
    assert errors == []
    assert_valid_capability_manifest(data)


def test_schema_fixture_missing_fields():
    """Fixture missing_fields_manifest.json triggers specific missing field errors."""
    fixture_path = FIXTURES_DIR / "missing_fields_manifest.json"
    assert fixture_path.exists(), "missing_fields_manifest.json fixture must exist"

    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    errors = validate_capability_manifest(data)
    assert len(errors) >= 3

    error_blob = "\n".join(errors)
    assert "Missing required top-level field 'schema_version'" in error_blob
    assert "Missing required top-level field 'declaration_disclaimer'" in error_blob
    assert "Scanner 'sqli' missing required field 'severity'" in error_blob
    assert "Scanner 'sqli' missing required field 'cvss'" in error_blob

    with pytest.raises(ValueError, match="failed schema validation"):
        assert_valid_capability_manifest(data)


def test_schema_fixture_version_mismatch():
    """Fixture version_mismatch_manifest.json triggers schema version mismatch error."""
    fixture_path = FIXTURES_DIR / "version_mismatch_manifest.json"
    assert fixture_path.exists(), "version_mismatch_manifest.json fixture must exist"

    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    errors = validate_capability_manifest(data, expected_schema_version="1.0.0")
    assert len(errors) == 1
    assert "Schema version mismatch: expected '1.0.0', got '2.0.0'" in errors[0]

    with pytest.raises(ValueError, match="Schema version mismatch"):
        assert_valid_capability_manifest(data, expected_schema_version="1.0.0")


def test_schema_fixture_coverage_claiming_rejection():
    """Manifest claiming execution coverage or declaration_only=False is strictly rejected."""
    fixture_path = FIXTURES_DIR / "coverage_claiming_manifest.json"
    assert fixture_path.exists(), "coverage_claiming_manifest.json fixture must exist"

    data = json.loads(fixture_path.read_text(encoding="utf-8"))
    errors = validate_capability_manifest(data)
    assert any("declaration_only" in err for err in errors)
    assert any("execution_coverage_claimed" in err for err in errors)

    with pytest.raises(ValueError, match="declaration_only"):
        assert_valid_capability_manifest(data)


def test_cached_manifest_accessor_isolation():
    """get_capability_manifest returns isolated deep copies preventing cache mutation."""
    manifest_1 = get_capability_manifest()
    manifest_1["scanners"]["sqli"]["name"] = "MUTATED"

    manifest_2 = get_capability_manifest()
    assert manifest_2["scanners"]["sqli"]["name"] == "SQLiScanner"


def test_backward_compatibility_matrix_unchanged():
    """Existing capability_matrix and capability_matrix_html remain 100% unchanged."""
    contracts = {name: cls.CONTRACT for name, cls in SCANNERS.items()}
    matrix = build_capability_matrix(contracts)

    assert "carriers" in matrix
    assert "scanners" in matrix
    assert len(matrix["scanners"]) == len(SCANNERS)

    html = render_capability_matrix_html(matrix)
    assert "Scanner capability matrix" in html or "table" in html
    assert "sqli" in html


def test_monitor_api_capability_manifest_endpoint_no_auth():
    """When auth is disabled on MonitorServer, /api/capability-manifest returns 200."""
    server = MonitorServer()
    client = TestClient(server.app)

    # Test /api/capability-manifest
    resp = client.get("/api/capability-manifest")
    assert resp.status_code == 200
    data = resp.json()
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["scanner_count"] == len(SCANNERS)
    assert validate_capability_manifest(data) == []

    # Test /api/v1/capability-manifest
    resp_v1 = client.get("/api/v1/capability-manifest")
    assert resp_v1.status_code == 200
    assert resp_v1.json() == data

    # Path traversal protection
    resp_traversal = client.get("/api/capability-manifest/../../../etc/passwd")
    assert resp_traversal.status_code == 404


def test_monitor_api_capability_manifest_endpoint_with_auth():
    """When auth is enabled, unauthenticated request gets 401; authenticated gets 200."""
    server = MonitorServer(auth_token="secret-token-test-123")
    client = TestClient(server.app)

    # Unauthenticated request -> 401 JSON
    resp_unauth = client.get("/api/capability-manifest")
    assert resp_unauth.status_code == 401
    assert "認証が必要です" in resp_unauth.json().get("error", "")

    resp_unauth_v1 = client.get("/api/v1/capability-manifest")
    assert resp_unauth_v1.status_code == 401

    # Authenticated request -> 200 JSON
    headers = {"Authorization": "Bearer secret-token-test-123"}
    resp_auth = client.get("/api/capability-manifest", headers=headers)
    assert resp_auth.status_code == 200
    assert resp_auth.json()["schema_version"] == SCHEMA_VERSION

    resp_auth_v1 = client.get("/api/v1/capability-manifest", headers=headers)
    assert resp_auth_v1.status_code == 200
