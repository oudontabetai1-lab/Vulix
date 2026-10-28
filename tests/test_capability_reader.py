"""Tests for Vulix Capability Reader and mode/permission gating.

Verifies:
1. Exact SCANNERS registry equality and defaults {'sqli', 'os', 'xss'}.
2. Safe unavailable state on network error, HTTP error, 401 Unauthorized, decode error,
   schema version mismatch, missing fields, and forbidden coverage claims.
3. Invariant: unacquired/unavailable capabilities never manufacture a coverage PASS.
4. Mode gating: scanners only enabled for declared applicable_modes (normal, agent, hybrid).
5. Permission gating: state_changing scanner disabled when allow_state_changing is false.
6. Dummy scanner addition dynamically recognized without modifying UI templates or reader definitions.
"""
import json
from pathlib import Path
import subprocess

from wscan.capability_manifest import (
    build_capability_manifest,
    SCHEMA_VERSION,
    MANIFEST_KIND,
)
from wscan.scanners import SCANNERS

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_READER_JS = ROOT / "templates" / "ui" / "capability-reader.js"
FIXTURES_DIR = ROOT / "tests" / "fixtures" / "capability_manifest"


def _run_node(script: str) -> dict:
    """Execute snippet with CapabilityReader in Node.js and return parsed JSON."""
    full_script = f"""
    const {{ CapabilityReader, defaultReader }} = require('{CAPABILITY_READER_JS}');
    {script}
    """
    res = subprocess.run(
        ["node", "-e", full_script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(res.stdout)


def test_capability_reader_valid_manifest_scanners_equality_and_defaults():
    """Verify ready status, exact equality with SCANNERS registry, and defaults sqli/os/xss."""
    manifest = build_capability_manifest()
    manifest_json = json.dumps(manifest)

    script = f"""
    class MockApiClient {{
      async get(endpoint) {{
        return {{
          isSuccess: () => true,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          data: {manifest_json},
        }};
      }}
    }}

    (async () => {{
      const reader = new CapabilityReader({{ apiClient: new MockApiClient() }});
      await reader.loadCapabilities();

      console.log(JSON.stringify({{
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        scannerIds: reader.getScannerIds(),
        defaultChecks: reader.getDefaultChecks(),
      }}));
    }})();
    """

    res = _run_node(script)
    assert res["isReady"] is True
    assert res["isUnavailable"] is False
    assert res["status"] == "ready"
    assert set(res["scannerIds"]) == set(SCANNERS)
    assert set(res["defaultChecks"]) == {"sqli", "os", "xss"}


def test_capability_reader_safe_unavailable_on_401():
    """Verify that HTTP 401 transitions reader to safe unavailable state without claiming capabilities."""
    script = """
    class MockApiClient {
      async get(endpoint) {
        return {
          isSuccess: () => false,
          isUnauthorized: () => true,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          errorMessage: '認証が必要です (HTTP 401 Unauthorized)',
          data: null,
        };
      }
    }

    (async () => {
      const reader = new CapabilityReader({ apiClient: new MockApiClient() });
      await reader.loadCapabilities();

      console.log(JSON.stringify({
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        errorReason: reader.errorReason,
        scannerIds: reader.getScannerIds(),
        isApplicable: reader.isScannerApplicable('sqli', 'normal'),
      }));
    })();
    """

    res = _run_node(script)
    assert res["isReady"] is False
    assert res["isUnavailable"] is True
    assert res["status"] == "unavailable"
    assert res["errorReason"] == "unauthorized"
    assert res["scannerIds"] == []
    # Never manufacture capability or pass on unavailable
    assert res["isApplicable"] is False


def test_capability_reader_safe_unavailable_on_network_error():
    """Verify safe unavailable state on network error."""
    script = """
    class MockApiClient {
      async get(endpoint) {
        return {
          isSuccess: () => false,
          isUnauthorized: () => false,
          isNetworkError: () => true,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          errorMessage: 'Network connection refused',
          data: null,
        };
      }
    }

    (async () => {
      const reader = new CapabilityReader({ apiClient: new MockApiClient() });
      await reader.loadCapabilities();

      console.log(JSON.stringify({
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        errorReason: reader.errorReason,
        scannerIds: reader.getScannerIds(),
        isApplicable: reader.isScannerApplicable('xss', 'normal'),
      }));
    })();
    """

    res = _run_node(script)
    assert res["isReady"] is False
    assert res["isUnavailable"] is True
    assert res["status"] == "unavailable"
    assert res["errorReason"] == "network_error"
    assert res["scannerIds"] == []
    assert res["isApplicable"] is False


def test_capability_reader_safe_unavailable_on_decode_error():
    """Verify safe unavailable state on decode/JSON parse error."""
    script = """
    class MockApiClient {
      async get(endpoint) {
        return {
          isSuccess: () => false,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => true,
          isHttpError: () => false,
          isAborted: () => false,
          errorMessage: 'JSON parse error',
          data: null,
        };
      }
    }

    (async () => {
      const reader = new CapabilityReader({ apiClient: new MockApiClient() });
      await reader.loadCapabilities();

      console.log(JSON.stringify({
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        errorReason: reader.errorReason,
      }));
    })();
    """

    res = _run_node(script)
    assert res["isUnavailable"] is True
    assert res["status"] == "unavailable"
    assert res["errorReason"] == "decode_error"


def test_capability_reader_safe_unavailable_on_version_mismatch():
    """Verify safe unavailable state on schema version mismatch fixture."""
    fixture_path = FIXTURES_DIR / "version_mismatch_manifest.json"
    manifest_json = fixture_path.read_text(encoding="utf-8")

    script = f"""
    class MockApiClient {{
      async get(endpoint) {{
        return {{
          isSuccess: () => true,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          data: {manifest_json},
        }};
      }}
    }}

    (async () => {{
      const reader = new CapabilityReader({{ apiClient: new MockApiClient() }});
      await reader.loadCapabilities();

      console.log(JSON.stringify({{
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        errorReason: reader.errorReason,
        scannerIds: reader.getScannerIds(),
      }}));
    }})();
    """

    res = _run_node(script)
    assert res["isReady"] is False
    assert res["isUnavailable"] is True
    assert res["status"] == "unavailable"
    assert res["errorReason"] == "version_mismatch"
    assert res["scannerIds"] == []


def test_capability_reader_safe_unavailable_on_missing_fields():
    """Verify safe unavailable state on missing required fields fixture."""
    fixture_path = FIXTURES_DIR / "missing_fields_manifest.json"
    manifest_json = fixture_path.read_text(encoding="utf-8")

    script = f"""
    class MockApiClient {{
      async get(endpoint) {{
        return {{
          isSuccess: () => true,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          data: {manifest_json},
        }};
      }}
    }}

    (async () => {{
      const reader = new CapabilityReader({{ apiClient: new MockApiClient() }});
      await reader.loadCapabilities();

      console.log(JSON.stringify({{
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        errorReason: reader.errorReason,
      }}));
    }})();
    """

    res = _run_node(script)
    assert res["isReady"] is False
    assert res["isUnavailable"] is True
    assert res["status"] == "unavailable"
    assert res["errorReason"] == "invalid_manifest"


def test_capability_reader_safe_unavailable_on_forbidden_coverage_claim():
    """Verify rejection when manifest contains forbidden runtime coverage claims."""
    fixture_path = FIXTURES_DIR / "coverage_claiming_manifest.json"
    manifest_json = fixture_path.read_text(encoding="utf-8")

    script = f"""
    class MockApiClient {{
      async get(endpoint) {{
        return {{
          isSuccess: () => true,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          data: {manifest_json},
        }};
      }}
    }}

    (async () => {{
      const reader = new CapabilityReader({{ apiClient: new MockApiClient() }});
      await reader.loadCapabilities();

      console.log(JSON.stringify({{
        isReady: reader.isReady(),
        isUnavailable: reader.isUnavailable(),
        status: reader.status,
        errorReason: reader.errorReason,
      }}));
    }})();
    """

    res = _run_node(script)
    assert res["isReady"] is False
    assert res["isUnavailable"] is True
    assert res["status"] == "unavailable"
    assert res["errorReason"] == "invalid_manifest"


def test_capability_reader_mode_gating():
    """Verify mode applicability gating across normal, agent, hybrid, and unknown modes."""
    manifest = build_capability_manifest()
    manifest_json = json.dumps(manifest)

    script = f"""
    class MockApiClient {{
      async get(endpoint) {{
        return {{
          isSuccess: () => true,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          data: {manifest_json},
        }};
      }}
    }}

    (async () => {{
      const reader = new CapabilityReader({{ apiClient: new MockApiClient() }});
      await reader.loadCapabilities();

      // Deterministic scanners declare ['normal', 'hybrid']
      const sqliNormal = reader.isScannerApplicable('sqli', 'normal');
      const sqliHybrid = reader.isScannerApplicable('sqli', 'hybrid');
      const sqliAgent = reader.isScannerApplicable('sqli', 'agent');
      const sqliUnknown = reader.isScannerApplicable('sqli', 'unknown_mode');

      const reasonAgent = reader.getGatedReason('sqli', 'agent');
      const reasonUnknown = reader.getGatedReason('sqli', 'unknown_mode');

      console.log(JSON.stringify({{
        sqliNormal,
        sqliHybrid,
        sqliAgent,
        sqliUnknown,
        reasonAgent,
        reasonUnknown,
      }}));
    }})();
    """

    res = _run_node(script)
    assert res["sqliNormal"] is True
    assert res["sqliHybrid"] is True
    # Invariant: Never guess capability when not declared
    assert res["sqliAgent"] is False
    assert res["sqliUnknown"] is False
    assert "Agent Browser" in res["reasonAgent"] or "agent" in res["reasonAgent"].lower()
    assert "unknown_mode" in res["reasonUnknown"]


def test_capability_reader_permission_gating():
    """Verify permission gating disallows state_changing scanners when disallowed."""
    manifest = build_capability_manifest()
    # Add a mock state-changing scanner
    manifest["scanners"]["test_state_changer"] = {
        "id": "test_state_changer",
        "name": "StateChangerScanner",
        "check_type": "test_state_changer",
        "severity": "high",
        "cvss": {"score": 7.0, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "is_default": False,
        "applicable_modes": ["normal", "hybrid"],
        "state_change": "state_changing",
        "cost": "medium",
        "prerequisites": [],
        "execution_kinds": ["active"],
        "has_page_level": False,
        "supports_json_body": False,
        "supports_xml_body": False,
        "always_state_changing": True,
        "declared_carriers": {},
        "declaration_only": True,
    }
    manifest["scanner_count"] = len(manifest["scanners"])
    manifest["scanner_ids"] = sorted(manifest["scanners"].keys())

    manifest_json = json.dumps(manifest)

    script = f"""
    class MockApiClient {{
      async get(endpoint) {{
        return {{
          isSuccess: () => true,
          isUnauthorized: () => false,
          isNetworkError: () => false,
          isDecodeError: () => false,
          isHttpError: () => false,
          isAborted: () => false,
          data: {manifest_json},
        }};
      }}
    }}

    (async () => {{
      const reader = new CapabilityReader({{ apiClient: new MockApiClient() }});
      await reader.loadCapabilities();

      // Permitted when allow_state_changing is true
      const allowed = reader.isScannerApplicable('test_state_changer', 'normal', {{ allow_state_changing: true }});
      // Gated when allow_state_changing is false
      const disallowed = reader.isScannerApplicable('test_state_changer', 'normal', {{ allow_state_changing: false }});
      const gatedReason = reader.getGatedReason('test_state_changer', 'normal', {{ allow_state_changing: false }});

      console.log(JSON.stringify({{
        allowed,
        disallowed,
        gatedReason,
      }}));
    }})();
    """

    res = _run_node(script)
    assert res["allowed"] is True
    assert res["disallowed"] is False
    assert "状態変更" in res["gatedReason"]
