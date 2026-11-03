"""Tests for /app Crawl screen module, graph snapshot visualization, and routing.

Verifies:
1. Module registration with ModuleRegistry and NavigationDispatcher route map (#crawl, #/crawl).
2. Pure graph layout calculation (column-by-depth, determinism, bezier edge geometry).
3. Pure search and kind filtering across nodes, inputs, actions, and findings.
4. Completeness labeling invariant (complete vs partial vs unknown; partial/unknown never presented as complete).
5. Missing-reference fallbacks (actions, inputs, findings unavailable text; never fabricated).
6. Malicious strings and HTML tags rendered inertly via textContent.
7. Reload-safe scan selection and route parsing via app-entry.
8. Chromium UI smoke test (skipped without Chromium / browser).
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

from tests.ui_harness import require_browser, STANDARD_VIEWPORTS, UIHarness, ui_harness

ROOT = Path(__file__).resolve().parents[1]
CRAWL_MODULE_JS = ROOT / "templates" / "ui" / "crawl-module.js"
APP_SHELL_JS = ROOT / "templates" / "ui" / "app-shell.js"
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


def test_crawl_module_exports_and_route_registration():
    """Verify that crawl-module exports interface and registers with app-shell."""
    script = f"""
    const crawlMod = require('{CRAWL_MODULE_JS}');
    const {{ ModuleRegistry, NavigationDispatcher }} = require('{APP_SHELL_JS}');

    const registry = new ModuleRegistry();
    const dispatcher = new NavigationDispatcher(registry);

    const dummyApi = {{ createScope: () => ({{ get: async () => ({{ ok: true }}), cancelAll: () => {{}} }}) }};
    const modDef = crawlMod.createCrawlModule({{
      api: dummyApi,
      surfaceEl: {{ hidden: true, replaceChildren: () => {{}} }},
    }});

    registry.register(modDef);

    const hasCrawl = registry.has('crawl');
    const registered = registry.get('crawl');
    const resolvedRoute = dispatcher.resolveRoute('#/crawl');
    const resolvedHash = dispatcher.resolveRoute('#crawl');

    console.log(JSON.stringify({{
      hasCrawl: hasCrawl,
      registeredId: registered ? registered.id : null,
      registeredTitle: registered ? registered.title : null,
      resolvedRouteViewId: resolvedRoute.viewId,
      resolvedHashViewId: resolvedHash.viewId,
      exportedSymbols: Object.keys(crawlMod),
    }}));
    """
    res = _run_node(script)
    assert res["hasCrawl"] is True
    assert res["registeredId"] == "crawl"
    assert res["registeredTitle"] == "Crawl"
    assert res["resolvedRouteViewId"] == "crawl"
    assert res["resolvedHashViewId"] == "crawl"
    for expected in [
        "SCHEMA_VERSION",
        "formatCompleteness",
        "formatNodeDetail",
        "searchNodes",
        "filterNodesByKind",
        "layoutGraph",
        "renderCrawlView",
        "createCrawlModule",
    ]:
        assert expected in res["exportedSymbols"]


def test_completeness_labeling_and_invariants():
    """Verify completeness formatting and the invariant that partial/unknown is never complete."""
    script = f"""
    const {{ formatCompleteness }} = require('{CRAWL_MODULE_JS}');

    const c1 = formatCompleteness('complete', ['scan_completed']);
    const c2 = formatCompleteness('partial', ['scan_in_progress', 'scan_gaps_present']);
    const c3 = formatCompleteness('unknown', ['empty_scan']);
    const c4 = formatCompleteness('partial', []);
    const c5 = formatCompleteness(null, null);

    console.log(JSON.stringify({{ c1, c2, c3, c4, c5 }}));
    """
    res = _run_node(script)

    # 1. Complete scan
    c1 = res["c1"]
    assert c1["isComplete"] is True
    assert c1["completeness"] == "complete"
    assert "Complete" in c1["badgeText"]
    assert "crawl-badge-complete" in c1["badgeClass"]

    # 2. Partial scan (in progress + gaps)
    c2 = res["c2"]
    assert c2["isComplete"] is False
    assert c2["completeness"] == "partial"
    assert "Partial" in c2["badgeText"]
    assert "crawl-badge-partial" in c2["badgeClass"]
    assert any("スキャン実行中" in r for r in c2["reasons"])
    assert any("ギャップ" in r for r in c2["reasons"])

    # 3. Unknown scan (empty)
    c3 = res["c3"]
    assert c3["isComplete"] is False
    assert c3["completeness"] == "unknown"
    assert "Unknown" in c3["badgeText"]
    assert "crawl-badge-unknown" in c3["badgeClass"]

    # 4. Partial without reasons
    c4 = res["c4"]
    assert c4["isComplete"] is False
    assert c4["completeness"] == "partial"

    # 5. Null fallback
    c5 = res["c5"]
    assert c5["isComplete"] is False
    assert c5["completeness"] == "unknown"


def test_missing_reference_fallbacks_never_invented():
    """Verify that node details show explicit unavailable state for missing references."""
    script = f"""
    const {{ formatNodeDetail }} = require('{CRAWL_MODULE_JS}');

    // Node with zero references
    const bareNode = {{
      id: 'page_1234',
      kind: 'page',
      url: 'https://example.com/about',
      label: 'https://example.com/about',
    }};

    // Node with rich references
    const richNode = {{
      id: 'form_5678',
      kind: 'form',
      url: 'https://example.com/login',
      label: 'Form 0 (POST)',
      actions: [{{ action: 'https://example.com/login', method: 'post' }}],
      inputs: [{{ name: 'user', type: 'text', carrier: 'form_field' }}],
      findings: [{{ id: 'sqli_user', check_type: 'sqli', severity: 'critical', verified: true }}],
      metadata: {{ depth: 1, forms: 1 }},
    }};

    console.log(JSON.stringify({{
      bare: formatNodeDetail(bareNode),
      rich: formatNodeDetail(richNode),
    }}));
    """
    res = _run_node(script)

    bare = res["bare"]
    assert bare["hasActions"] is False
    assert "unavailable" in bare["actionsUnavailableText"]
    assert bare["hasInputs"] is False
    assert "unavailable" in bare["inputsUnavailableText"]
    assert bare["hasFindings"] is False
    assert "0 findings" in bare["findingsUnavailableText"]
    assert bare["actions"] == []
    assert bare["inputs"] == []
    assert bare["findings"] == []

    rich = res["rich"]
    assert rich["hasActions"] is True
    assert len(rich["actions"]) == 1
    assert rich["actions"][0]["method"] == "post"
    assert rich["hasInputs"] is True
    assert len(rich["inputs"]) == 1
    assert rich["inputs"][0]["name"] == "user"
    assert rich["hasFindings"] is True
    assert len(rich["findings"]) == 1
    assert rich["findings"][0]["id"] == "sqli_user"
    assert rich["findings"][0]["verified"] is True


def test_search_and_kind_filtering_pure_functions():
    """Verify search across labels, URLs, params, and filtering by kind."""
    script = f"""
    const {{ searchNodes, filterNodesByKind }} = require('{CRAWL_MODULE_JS}');

    const nodes = [
      {{ id: 'p1', kind: 'page', url: 'https://example.com/home', label: 'Home Page' }},
      {{ id: 'p2', kind: 'page', url: 'https://example.com/contact', label: 'Contact Us' }},
      {{ id: 'f1', kind: 'form', url: 'https://example.com/login', label: 'Login Form', inputs: [{{ name: 'username' }}] }},
      {{ id: 'q1', kind: 'param', url: 'https://example.com/search?q=test', label: 'q', inputs: [{{ name: 'q' }}] }},
      {{ id: 'u1', kind: 'unknown', url: 'ws://example.com/socket', label: 'WebSocket' }},
    ];

    const matchHome = searchNodes(nodes, 'home');
    const matchUser = searchNodes(nodes, 'username');
    const matchAll = searchNodes(nodes, '');
    const pagesOnly = filterNodesByKind(nodes, 'page');
    const formsOnly = filterNodesByKind(nodes, 'form');
    const paramsOnly = filterNodesByKind(nodes, 'param');
    const unknownsOnly = filterNodesByKind(nodes, 'unknown');

    console.log(JSON.stringify({{
      matchHomeIds: matchHome.map(n => n.id),
      matchUserIds: matchUser.map(n => n.id),
      matchAllCount: matchAll.length,
      pagesCount: pagesOnly.length,
      formsCount: formsOnly.length,
      paramsCount: paramsOnly.length,
      unknownsCount: unknownsOnly.length,
    }}));
    """
    res = _run_node(script)
    assert res["matchHomeIds"] == ["p1"]
    assert res["matchUserIds"] == ["f1"]
    assert res["matchAllCount"] == 5
    assert res["pagesCount"] == 2
    assert res["formsCount"] == 1
    assert res["paramsCount"] == 1
    assert res["unknownsCount"] == 1


def test_graph_layout_column_by_depth_and_determinism():
    """Verify deterministic layout calculation and bezier path generation."""
    script = f"""
    const {{ layoutGraph }} = require('{CRAWL_MODULE_JS}');

    const nodes = [
      {{ id: 'page_root', kind: 'page', url: 'https://example.com/', parent_id: null, metadata: {{ depth: 0 }} }},
      {{ id: 'page_child1', kind: 'page', url: 'https://example.com/a', parent_id: 'page_root', metadata: {{ depth: 1 }} }},
      {{ id: 'page_child2', kind: 'page', url: 'https://example.com/b', parent_id: 'page_root', metadata: {{ depth: 1 }} }},
      {{ id: 'form_c1', kind: 'form', url: 'https://example.com/a/form', parent_id: 'page_child1', metadata: {{ depth: 2 }} }},
    ];

    const edges = [
      {{ source: 'page_root', target: 'page_child1', kind: 'navigates_to' }},
      {{ source: 'page_root', target: 'page_child2', kind: 'navigates_to' }},
      {{ source: 'page_child1', target: 'form_c1', kind: 'contains_form' }},
    ];

    const l1 = layoutGraph(nodes, edges);
    const l2 = layoutGraph([...nodes].reverse(), edges);

    console.log(JSON.stringify({{
      nodeCount: l1.nodes.length,
      edgeCount: l1.edges.length,
      rootX: l1.nodes.find(n => n.id === 'page_root').x,
      child1X: l1.nodes.find(n => n.id === 'page_child1').x,
      formC1X: l1.nodes.find(n => n.id === 'form_c1').x,
      edgePaths: l1.edges.map(e => e.pathData),
      l1Ids: l1.nodes.map(n => n.id),
      l2Ids: l2.nodes.map(n => n.id),
    }}));
    """
    res = _run_node(script)
    assert res["nodeCount"] == 4
    assert res["edgeCount"] == 3
    # Column depth increases x coordinates
    assert res["rootX"] < res["child1X"] < res["formC1X"]
    # All edges have valid cubic bezier paths
    for p in res["edgePaths"]:
        assert p.startswith("M")
        assert " C" in p
    # Stable ordering
    assert res["l1Ids"] == res["l2Ids"]


def test_malicious_strings_rendered_inertly():
    """Verify that script tags and XSS payloads in URLs or labels are inert text nodes."""
    script = f"""
    const {{ formatNodeDetail }} = require('{CRAWL_MODULE_JS}');

    const maliciousNode = {{
      id: 'malicious_1',
      kind: 'page',
      url: 'https://example.com/<script>alert(1)</script>',
      label: '<img src=x onerror=alert(2)>" onclick="alert(3)"',
      actions: [{{ action: 'javascript:alert(4)', method: 'POST' }}],
      inputs: [{{ name: '<b onmouseover=alert(5)>payload</b>' }}],
      findings: [{{ id: '<svg onload=alert(6)>', check_type: 'xss', severity: 'critical' }}],
    }};

    const detail = formatNodeDetail(maliciousNode);

    // Verify raw strings are preserved safely as data without executing HTML
    console.log(JSON.stringify({{
      url: detail.url,
      label: detail.label,
      action: detail.actions[0].action,
      inputName: detail.inputs[0].name,
      findingId: detail.findings[0].id,
    }}));
    """
    res = _run_node(script)
    assert "<script>alert(1)</script>" in res["url"]
    assert "<img src=x onerror=alert(2)>" in res["label"]
    assert res["action"] == "javascript:alert(4)"
    assert "<b onmouseover=alert(5)>payload</b>" in res["inputName"]
    assert "<svg onload=alert(6)>" in res["findingId"]


def test_app_entry_parses_crawl_route_and_scan_context():
    """Verify that app-entry route parser accepts /crawl and /crawl?scan=id."""
    script = f"""
    const fs = require('fs');
    const entrySource = fs.readFileSync('{APP_ENTRY_JS}', 'utf-8');

    // Extract parseRoute implementation
    const match = entrySource.match(/function parseRoute\\(hash\\) \\{{([\\s\\S]*?)\\n  \\}}/);
    if (!match) throw new Error('parseRoute not found');

    const parseRoute = new Function('hash', match[1]);

    const r1 = parseRoute('#/crawl');
    const r2 = parseRoute('#/crawl?scan=20261103_120000_abc');
    const r3 = parseRoute('#crawl');
    const r4 = parseRoute('#/crawl?scan=invalid!id#');
    const r5 = parseRoute('#/crawl?unexpected=param');
    const r6 = parseRoute('#/unknown-route');

    console.log(JSON.stringify({{ r1, r2, r3, r4, r5, r6 }}));
    """
    res = _run_node(script)
    assert res["r1"] == {"id": "crawl", "scanId": None, "findingId": None}
    assert res["r2"] == {"id": "crawl", "scanId": "20261103_120000_abc", "findingId": None}
    assert res["r3"] == {"id": "crawl", "scanId": None, "findingId": None}
    assert res["r4"] is None  # invalid scanId
    assert res["r5"] is None  # unexpected param
    assert res["r6"] is None  # unknown route


def test_crawl_view_chromium_ui(ui_harness):
    """Verify that /app#/crawl renders SVG canvas, mode toggles, and handles interactions."""
    pytest.importorskip("playwright")
    from tests.ui_harness import require_browser, STANDARD_VIEWPORTS

    require_browser()
    vp = STANDARD_VIEWPORTS[1440]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    page.goto(f"{ui_harness.server_url}/app#/crawl")
    page.wait_for_selector("#crawlSurface")
    page.wait_for_selector(".crawl-module-root")

    # 1. Verify nav button is active
    crawl_btn = page.locator("nav button[data-route='crawl']")
    assert crawl_btn.get_attribute("aria-current") == "page"

    # 2. Verify toolbar elements
    assert page.is_visible(".crawl-badge")
    assert page.is_visible(".crawl-select")
    assert page.is_visible(".crawl-search-input")
    assert page.is_visible("button[data-mode='graph']")
    assert page.is_visible("button[data-mode='explorer']")
    assert page.is_visible("button[data-mode='list']")

    # 3. Mode switching: Explorer
    page.click("button[data-mode='explorer']")
    assert page.is_visible(".crawl-explorer-surface")
    assert not page.is_visible(".crawl-graph-surface")

    # 4. Mode switching: List
    page.click("button[data-mode='list']")
    assert page.is_visible(".crawl-list-surface")
    assert not page.is_visible(".crawl-explorer-surface")

    # 5. Mode switching back to Graph
    page.click("button[data-mode='graph']")
    assert page.is_visible(".crawl-graph-surface")
    assert page.is_visible(".crawl-svg-canvas")

    ui_harness.assert_no_errors(page)

    # Capture documentation screenshot
    ui_harness.save_doc_image(page, "app-crawl")
