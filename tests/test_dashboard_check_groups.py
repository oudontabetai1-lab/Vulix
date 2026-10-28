"""Tests for dashboard check groups and capability reader integration.

Verifies:
1. Capability reader accurately reflects all registered SCANNERS without duplicate IDs.
2. Default checks strictly match {"sqli", "os", "xss"}.
3. No duplicate scanner IDs exist in capability reader output or dashboard templates.
4. Adding a dummy scanner to the manifest dynamically surfaces in the capability reader
   without requiring any UI code or template changes.
"""
import json
from pathlib import Path
import subprocess

from wscan.capability_manifest import build_capability_manifest
from wscan.scanners import SCANNERS

ROOT = Path(__file__).resolve().parents[1]
CAPABILITY_READER_JS = ROOT / "templates" / "ui" / "capability-reader.js"
DASHBOARD_HTML = ROOT / "templates" / "dashboard.html"


def _run_node_script(script: str) -> dict:
    """Run a small JavaScript snippet via Node.js and return parsed JSON."""
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


def test_dashboard_capability_reader_matches_scanner_registry():
    """Verify that CapabilityReader with manifest matches the SCANNERS registry exactly."""
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
      const scannerIds = reader.getScannerIds();
      const defaultChecks = reader.getDefaultChecks();
      const grouped = reader.getGroupedScanners('normal');

      // Flatten all visible scanners across groups
      const allGroupedScanners = [];
      for (const groupList of Object.values(grouped)) {{
        allGroupedScanners.push(...groupList);
      }}

      console.log(JSON.stringify({{
        status: reader.status,
        scannerIds: scannerIds,
        defaultChecks: defaultChecks,
        allGroupedIds: allGroupedScanners.map(s => s.id),
        defaultsFromGroups: allGroupedScanners.filter(s => s.def).map(s => s.id),
      }}));
    }})();
    """

    data = _run_node_script(script)
    assert data["status"] == "ready"

    # Exact equality with backend SCANNERS
    visible_ids = set(data["scannerIds"])
    assert visible_ids == set(SCANNERS)
    assert len(data["scannerIds"]) == len(visible_ids)

    # All grouped scanners must also match SCANNERS exactly
    assert set(data["allGroupedIds"]) == set(SCANNERS)
    assert len(data["allGroupedIds"]) == len(set(data["allGroupedIds"]))

    # Defaults must be strictly {"sqli", "os", "xss"}
    assert set(data["defaultChecks"]) == {"sqli", "os", "xss"}
    assert set(data["defaultsFromGroups"]) == {"sqli", "os", "xss"}


def test_dummy_scanner_addition_requires_no_ui_code_change():
    """Demonstrate that adding a dummy scanner requires zero UI template/code modifications."""
    manifest = build_capability_manifest()
    dummy_id = "test_synthetic_custom_probe"
    manifest["scanners"][dummy_id] = {
        "id": dummy_id,
        "name": "SyntheticCustomProbeScanner",
        "check_type": "test_synthetic_custom_probe",
        "severity": "high",
        "cvss": {"score": 7.5, "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"},
        "is_default": False,
        "applicable_modes": ["normal", "hybrid"],
        "state_change": "read_only",
        "cost": "low",
        "prerequisites": [],
        "execution_kinds": ["active"],
        "has_page_level": False,
        "supports_json_body": False,
        "supports_xml_body": False,
        "always_state_changing": False,
        "declared_carriers": {},
        "declaration_only": True,
    }
    manifest["scanner_count"] = len(manifest["scanners"])
    manifest["scanner_ids"] = sorted(manifest["scanners"].keys())

    manifest_json = json.dumps(manifest)

    # Prove that the dummy scanner ID does NOT exist in templates/dashboard.html or capability-reader.js
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    js = CAPABILITY_READER_JS.read_text(encoding="utf-8")
    assert dummy_id not in html
    assert dummy_id not in js

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
      const scannerIds = reader.getScannerIds();
      const grouped = reader.getGroupedScanners('normal');

      let foundDummy = null;
      for (const [groupName, groupList] of Object.entries(grouped)) {{
        const match = groupList.find(s => s.id === '{dummy_id}');
        if (match) {{
          foundDummy = {{ group: groupName, scanner: match }};
          break;
        }}
      }}

      console.log(JSON.stringify({{
        hasDummyInIds: scannerIds.includes('{dummy_id}'),
        foundDummy: foundDummy,
      }}));
    }})();
    """

    data = _run_node_script(script)
    assert data["hasDummyInIds"] is True
    assert data["foundDummy"] is not None
    assert data["foundDummy"]["scanner"]["id"] == dummy_id
    assert data["foundDummy"]["scanner"]["applicable"] is True
    # Label is automatically formatted from class name or id without UI hardcoding
    assert data["foundDummy"]["scanner"]["label"] == "SyntheticCustomProbe"
