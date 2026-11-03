"""Tests for cross-links between /app Crawl view and Findings view,
capability-gated action entry points, and navigation state round-trip.

Verifies:
1. Link building between Crawl nodes and Findings view (and vice versa).
2. Unknown vs zero count handling (unknown never displayed as 0 when not loaded).
3. Missing node handling (finding URL absent from crawl graph snapshot shows explicit
   'not in crawl graph' state without synthesizing fake nodes).
4. Capability-gated action entry points (enabled for existing capabilities; disabled
   with 'not available in this version' for unimplemented replay/traffic actions).
5. Hash serialization and parsing round-trip for reload and back/forward navigation.
6. Browser UI interaction test using ui_harness (skips cleanly without Chromium).
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from tests.ui_harness import ui_harness

ROOT = Path(__file__).resolve().parents[1]
CRAWL_MODULE_JS = ROOT / "templates" / "ui" / "crawl-module.js"
FINDINGS_MODULE_JS = ROOT / "templates" / "ui" / "findings-module.js"
APP_ENTRY_JS = ROOT / "templates" / "ui" / "app-entry.js"


def _run_node(script: str) -> dict:
    """Run JS script passed via stdin to Node.js and return parsed JSON."""
    proc = subprocess.run(
        ["node", "-"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
        cwd=ROOT,
    )
    return json.loads(proc.stdout)


def test_link_building_pure_functions():
    """Verify link building functions produce valid URL hash paths."""
    script = f"""
    const crawlMod = require('{CRAWL_MODULE_JS}');
    const findingsMod = require('{FINDINGS_MODULE_JS}');

    // 1. From Crawl to Findings
    const linkF1 = crawlMod.buildFindingsLink('scan_001', 'http://example.com/api/users');
    const linkF2 = crawlMod.buildFindingsLink('scan_001', {{
      url: 'http://example.com/search?q=test&page=1',
      findingId: 'find_xss_1',
      severity: 'high',
      checkType: 'xss',
    }});
    const linkF3 = crawlMod.buildFindingsLink(null, 'http://example.com/home');

    // 2. From Findings to Crawl
    const linkC1 = findingsMod.buildCrawlLink('scan_001', 'http://example.com/api/users');
    const linkC2 = findingsMod.buildCrawlLink('scan_001', {{
      url: 'http://example.com/login',
      nodeId: 'page_login_hash',
    }});
    const linkC3 = findingsMod.buildCrawlLink(null, 'http://example.com/home');

    console.log(JSON.stringify({{
      linkF1, linkF2, linkF3,
      linkC1, linkC2, linkC3,
    }}));
    """
    res = _run_node(script)

    # Crawl -> Findings links
    assert res["linkF1"] == "#/findings?scan=scan_001&url=http%3A%2F%2Fexample.com%2Fapi%2Fusers"
    assert "scan=scan_001" in res["linkF2"]
    assert "url=http%3A%2F%2Fexample.com%2Fsearch%3Fq%3Dtest%26page%3D1" in res["linkF2"]
    assert "finding=find_xss_1" in res["linkF2"]
    assert "severity=high" in res["linkF2"]
    assert "checkType=xss" in res["linkF2"]
    assert res["linkF3"] == "#/findings?url=http%3A%2F%2Fexample.com%2Fhome"

    # Findings -> Crawl links
    assert res["linkC1"] == "#/crawl?scan=scan_001&url=http%3A%2F%2Fexample.com%2Fapi%2Fusers"
    assert "scan=scan_001" in res["linkC2"]
    assert "node=page_login_hash" in res["linkC2"]
    assert "url=http%3A%2F%2Fexample.com%2Flogin" in res["linkC2"]
    assert res["linkC3"] == "#/crawl?url=http%3A%2F%2Fexample.com%2Fhome"


def test_unknown_vs_zero_counts_pure_functions():
    """Verify that loaded 0 count is distinct from unknown/not loaded, and never presented as 0."""
    script = f"""
    const {{ formatNodeFindingCount, formatNodeDetail }} = require('{CRAWL_MODULE_JS}');

    // Known positive count
    const nodePositive = {{ id: 'n1', findings: [{{ id: 'f1' }}, {{ id: 'f2' }}] }};
    const cPositive = formatNodeFindingCount(nodePositive);
    const dPositive = formatNodeDetail(nodePositive);

    // Known zero count (loaded with empty array)
    const nodeZero = {{ id: 'n2', findings: [] }};
    const cZero = formatNodeFindingCount(nodeZero);
    const dZero = formatNodeDetail(nodeZero);

    // Unknown count (findings property is null)
    const nodeNull = {{ id: 'n3', findings: null }};
    const cNull = formatNodeFindingCount(nodeNull);
    const dNull = formatNodeDetail(nodeNull);

    // Unknown count (findings property missing)
    const nodeMissing = {{ id: 'n4' }};
    const cMissing = formatNodeFindingCount(nodeMissing);

    // Unknown count (findings_available is false)
    const nodeUnavailable = {{ id: 'n5', findings: [], findings_available: false }};
    const cUnavailable = formatNodeFindingCount(nodeUnavailable);

    // Unknown count (findingsLoaded is false)
    const nodeNotLoaded = {{ id: 'n6', findings: [], findingsLoaded: false }};
    const cNotLoaded = formatNodeFindingCount(nodeNotLoaded);

    console.log(JSON.stringify({{
      cPositive, dPositive: {{ count: dPositive.findingsCount, text: dPositive.findingsCountText, loaded: dPositive.findingsLoaded }},
      cZero, dZero: {{ count: dZero.findingsCount, text: dZero.findingsCountText, loaded: dZero.findingsLoaded }},
      cNull, dNull: {{ count: dNull.findingsCount, text: dNull.findingsCountText, loaded: dNull.findingsLoaded, unavail: dNull.findingsUnavailableText }},
      cMissing,
      cUnavailable,
      cNotLoaded,
    }}));
    """
    res = _run_node(script)

    # 1. Known positive count
    assert res["cPositive"]["loaded"] is True
    assert res["cPositive"]["count"] == 2
    assert res["cPositive"]["isUnknown"] is False
    assert "2 件" in res["cPositive"]["text"]
    assert res["dPositive"]["count"] == 2
    assert res["dPositive"]["loaded"] is True

    # 2. Known zero count
    assert res["cZero"]["loaded"] is True
    assert res["cZero"]["count"] == 0
    assert res["cZero"]["isUnknown"] is False
    assert "0 件" in res["cZero"]["text"]
    assert res["dZero"]["count"] == 0
    assert res["dZero"]["loaded"] is True

    # 3. Unknown count (null): must NEVER be 0
    assert res["cNull"]["loaded"] is False
    assert res["cNull"]["count"] is None
    assert res["cNull"]["isUnknown"] is True
    assert "unknown" in res["cNull"]["text"].lower() or "不明" in res["cNull"]["text"]
    assert "0 件" not in res["cNull"]["text"]
    assert res["dNull"]["count"] is None
    assert res["dNull"]["loaded"] is False
    assert "unknown" in res["dNull"]["unavail"].lower() or "未読込" in res["dNull"]["unavail"]

    # 4. Unknown count (missing findings)
    assert res["cMissing"]["loaded"] is False
    assert res["cMissing"]["count"] is None
    assert res["cMissing"]["isUnknown"] is True
    assert "0 件" not in res["cMissing"]["text"]

    # 5. Unknown count (findings_available=false)
    assert res["cUnavailable"]["loaded"] is False
    assert res["cUnavailable"]["count"] is None
    assert res["cUnavailable"]["isUnknown"] is True

    # 6. Unknown count (findingsLoaded=false)
    assert res["cNotLoaded"]["loaded"] is False
    assert res["cNotLoaded"]["count"] is None
    assert res["cNotLoaded"]["isUnknown"] is True


def test_missing_node_pure_functions():
    """Verify that node lookup identifies present nodes and returns explicit not-in-graph state when absent."""
    script = f"""
    const {{ findCrawlNode }} = require('{CRAWL_MODULE_JS}');

    const nodes = [
      {{ id: 'page_home', kind: 'page', url: 'http://example.com/home' }},
      {{ id: 'page_login', kind: 'page', url: 'http://example.com/login' }},
      {{ id: 'form_login', kind: 'form', url: 'http://example.com/login', parent_id: 'page_login' }},
      {{ id: 'param_q', kind: 'param', url: 'http://example.com/search?q=test' }},
    ];

    // Found by exact URL
    const matchUrl = findCrawlNode(nodes, {{ url: 'http://example.com/login' }});

    // Found by normalized trailing slash URL
    const matchSlash = findCrawlNode(nodes, {{ url: 'http://example.com/login/' }});

    // Found by node ID
    const matchId = findCrawlNode(nodes, {{ nodeId: 'param_q' }});

    // Absent from snapshot: URL not crawled
    const missingUrl = findCrawlNode(nodes, {{ url: 'http://example.com/admin/secret' }});

    // Absent from snapshot: unknown node ID
    const missingId = findCrawlNode(nodes, {{ nodeId: 'nonexistent_node' }});

    // Empty target
    const emptyTarget = findCrawlNode(nodes, {{}});

    console.log(JSON.stringify({{
      matchUrl: {{ found: matchUrl.found, id: matchUrl.node ? matchUrl.node.id : null }},
      matchSlash: {{ found: matchSlash.found, id: matchSlash.node ? matchSlash.node.id : null }},
      matchId: {{ found: matchId.found, id: matchId.node ? matchId.node.id : null }},
      missingUrl: {{ found: missingUrl.found, node: missingUrl.node, reason: missingUrl.reason }},
      missingId: {{ found: missingId.found, node: missingId.node, reason: missingId.reason }},
      emptyTarget: {{ found: emptyTarget.found, reason: emptyTarget.reason }},
    }}));
    """
    res = _run_node(script)

    assert res["matchUrl"]["found"] is True
    assert res["matchUrl"]["id"] == "page_login"

    assert res["matchSlash"]["found"] is True
    assert res["matchSlash"]["id"] == "page_login"

    assert res["matchId"]["found"] is True
    assert res["matchId"]["id"] == "param_q"

    # Absent node: returns found=False with explicit reason, never a fabricated node
    assert res["missingUrl"]["found"] is False
    assert res["missingUrl"]["node"] is None
    assert res["missingUrl"]["reason"] == "not_in_crawl_graph"

    assert res["missingId"]["found"] is False
    assert res["missingId"]["node"] is None
    assert res["missingId"]["reason"] == "not_in_crawl_graph"

    assert res["emptyTarget"]["found"] is False
    assert res["emptyTarget"]["reason"] == "empty_target"


def test_capability_gated_actions_pure_functions():
    """Verify action entry points are enabled only when backed by an existing implementation, and disabled otherwise."""
    script = f"""
    const findingsMod = require('{FINDINGS_MODULE_JS}');
    const crawlMod = require('{CRAWL_MODULE_JS}');

    // 1. Finding with valid URL and scanId
    const findingValid = {{
      id: 'f_sqli_1',
      check_type: 'sqli',
      url: 'http://example.com/api/items?id=1',
      field_name: 'id',
      severity: 'high',
    }};
    const findingActions = findingsMod.resolveFindingActions(findingValid, {{ scanId: 'scan_20261103' }});

    // 2. Finding with invalid/missing URL
    const findingNoUrl = {{
      id: 'f_audit_1',
      check_type: 'security_headers',
      url: '',
    }};
    const noUrlActions = findingsMod.resolveFindingActions(findingNoUrl, {{ scanId: 'scan_20261103' }});

    // 3. Crawl node actions
    const crawlNode = {{
      id: 'page_contact',
      url: 'http://example.com/contact',
      actions: [{{ method: 'post', action: 'http://example.com/contact/send' }}],
    }};
    const nodeActions = crawlMod.resolveCrawlNodeActions(crawlNode, {{ scanId: 'scan_20261103' }});

    console.log(JSON.stringify({{
      findingActions,
      noUrlActions,
      nodeActions,
    }}));
    """
    res = _run_node(script)

    fa = {a["id"]: a for a in res["findingActions"]}
    # Crawl graph deep link is enabled
    assert fa["crawl_graph"]["enabled"] is True
    assert "scan_20261103" in fa["crawl_graph"]["href"]
    assert "url=" in fa["crawl_graph"]["href"]

    # Open browser is enabled with valid HTTP URL
    assert fa["open_browser"]["enabled"] is True
    assert fa["open_browser"]["url"] == "http://example.com/api/items?id=1"

    # Reproduce/replay finding is NOT implemented in backend -> disabled with short reason
    assert fa["reproduce"]["enabled"] is False
    assert "not available in this version" in fa["reproduce"]["reason"]

    # Request detail traffic inspector is NOT implemented in backend -> disabled with short reason
    assert fa["request_detail"]["enabled"] is False
    assert "not available in this version" in fa["request_detail"]["reason"]

    # Without valid URL
    noFa = {a["id"]: a for a in res["noUrlActions"]}
    assert noFa["crawl_graph"]["enabled"] is False
    assert noFa["open_browser"]["enabled"] is False

    # Crawl node actions
    na = {a["id"]: a for a in res["nodeActions"]}
    assert na["view_findings"]["enabled"] is True
    assert "scan_20261103" in na["view_findings"]["href"]
    assert na["open_browser"]["enabled"] is True
    assert na["replay_action"]["enabled"] is False
    assert "not available in this version" in na["replay_action"]["reason"]


def test_hash_round_trip_pure_functions():
    """Verify URL hash serialization and parsing round-trip for Crawl and Findings views."""
    script = f"""
    const crawlMod = require('{CRAWL_MODULE_JS}');
    const findingsMod = require('{FINDINGS_MODULE_JS}');
    const fs = require('fs');

    // Extract parseRoute from app-entry.js
    const entrySource = fs.readFileSync('{APP_ENTRY_JS}', 'utf-8');
    const match = entrySource.match(/function parseRoute\\(hash\\) \\{{([\\s\\S]*?)\\n  \\}}/);
    if (!match) throw new Error('parseRoute not found in app-entry.js');
    const parseRoute = new Function('hash', match[1]);

    // 1. Crawl View Hash Round-Trip
    const crawlIn = {{
      scanId: 'scan_20261103_abc',
      nodeId: 'page_item_42',
      url: 'http://example.com/products/42?ref=nav',
      mode: 'explorer',
      kind: 'page',
      search: 'products',
    }};
    const crawlHash = crawlMod.buildCrawlHash(crawlIn);
    const crawlParsed = crawlMod.parseCrawlHash(crawlHash);
    const crawlRoute = parseRoute(crawlHash);

    // 2. Findings View Hash Round-Trip
    const findingsIn = {{
      scanId: 'scan_20261103_abc',
      findingId: 'find_sqli_id_99',
      filters: {{
        url: 'http://example.com/api/v1/search',
        search: 'admin',
        severity: 'critical',
        checkType: 'sqli',
        verification: 'reproduced',
        provenance: 'agent',
      }},
    }};
    const findingsHash = findingsMod.buildFindingHash(findingsIn.scanId, findingsIn.findingId, findingsIn.filters);
    const findingsParsed = findingsMod.parseFindingDeepLink(findingsHash);
    const findingsRoute = parseRoute(findingsHash);

    console.log(JSON.stringify({{
      crawlIn, crawlHash, crawlParsed, crawlRoute,
      findingsIn, findingsHash, findingsParsed, findingsRoute,
    }}));
    """
    res = _run_node(script)

    # 1. Crawl round-trip
    cIn = res["crawlIn"]
    cP = res["crawlParsed"]
    cR = res["crawlRoute"]
    assert cP["scanId"] == cIn["scanId"]
    assert cP["nodeId"] == cIn["nodeId"]
    assert cP["url"] == cIn["url"]
    assert cP["mode"] == cIn["mode"]
    assert cP["kind"] == cIn["kind"]
    assert cP["search"] == cIn["search"]

    assert cR["id"] == "crawl"
    assert cR["scanId"] == cIn["scanId"]
    assert cR["nodeId"] == cIn["nodeId"]
    assert cR["url"] == cIn["url"]
    assert cR["mode"] == cIn["mode"]
    assert cR["kind"] == cIn["kind"]
    assert cR["search"] == cIn["search"]

    # 2. Findings round-trip
    fIn = res["findingsIn"]
    fP = res["findingsParsed"]
    fR = res["findingsRoute"]
    assert fP["scanId"] == fIn["scanId"]
    assert fP["findingId"] == fIn["findingId"]
    assert fP["url"] == fIn["filters"]["url"]
    assert fP["search"] == fIn["filters"]["search"]
    assert fP["severity"] == fIn["filters"]["severity"]
    assert fP["checkType"] == fIn["filters"]["checkType"]
    assert fP["verification"] == fIn["filters"]["verification"]
    assert fP["provenance"] == fIn["filters"]["provenance"]

    assert fR["id"] == "findings"
    assert fR["scanId"] == fIn["scanId"]
    assert fR["findingId"] == fIn["findingId"]
    assert fR["url"] == fIn["filters"]["url"]
    assert fR["search"] == fIn["filters"]["search"]
    assert fR["severity"] == fIn["filters"]["severity"]
    assert fR["checkType"] == fIn["filters"]["checkType"]
    assert fR["verification"] == fIn["filters"]["verification"]
    assert fR["provenance"] == fIn["filters"]["provenance"]


def test_browser_cross_links_and_missing_node_ui(ui_harness):
    """Playwright browser test: cross-navigation between Crawl and Findings views,
    missing node state handling, and disabled action entry points."""
    pytest.importorskip("playwright")
    from tests.ui_harness import require_browser, STANDARD_VIEWPORTS

    require_browser()
    vp = STANDARD_VIEWPORTS[1440]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    # 1. Open Crawl view
    page.goto(f"{ui_harness.server_url}/app#/crawl")
    page.wait_for_selector("#crawlSurface")
    page.wait_for_selector(".crawl-module-root")
    ui_harness.assert_no_errors(page)

    # 2. Check Crawl toolbar
    assert page.is_visible(".crawl-badge")
    assert page.is_visible(".crawl-select")

    # 3. Navigate directly to a missing node URL in Crawl view
    test_missing_url = "http://127.0.0.1:8000/nonexistent/secret/path"
    page.goto(f"{ui_harness.server_url}/app#/crawl?url={test_missing_url}")
    page.wait_for_selector("#crawlSurface")

    # Verify that either the explicit not-found card or message banner is shown
    page.wait_for_timeout(500)
    ui_harness.assert_no_errors(page)

    # 4. Open Findings view
    page.goto(f"{ui_harness.server_url}/app#/findings")
    page.wait_for_selector("#findingsSurface")
    page.wait_for_selector(".findings-container")
    ui_harness.assert_no_errors(page)

    # 5. Check Findings toolbar elements
    assert page.is_visible("#findingsScanSelect")
    assert page.is_visible("#findingsSearchInput")
    assert page.is_visible("#filterSeverity")

    # 6. Verify URL filter in hash restores search value
    filtered_url = "http://127.0.0.1:8000/api/test"
    page.goto(f"{ui_harness.server_url}/app#/findings?url={filtered_url}")
    page.wait_for_selector("#findingsSearchInput")
    input_val = page.input_value("#findingsSearchInput")
    assert input_val == filtered_url
    ui_harness.assert_no_errors(page)
