"""Tests for Agent Capabilities ("skills") display and backend manifest declarations."""
from __future__ import annotations

import copy
import json
from pathlib import Path
import subprocess

import pytest

from wscan.capability_manifest import (
    ALLOWED_AGENT_CAPABILITY_FIELDS,
    ALLOWED_TOP_LEVEL_FIELDS,
    DEFAULT_AGENT_CAPABILITIES,
    MANIFEST_KIND,
    REQUIRED_AGENT_CAPABILITY_FIELDS,
    SCHEMA_VERSION,
    build_agent_capabilities,
    build_capability_manifest,
    validate_capability_manifest,
)

ROOT = Path(__file__).resolve().parents[1]
AGENT_SKILLS_MODULE_JS = ROOT / "templates" / "ui" / "agent-skills-module.js"
APP_SHELL_JS = ROOT / "templates" / "ui" / "app-shell.js"
CAPABILITY_READER_JS = ROOT / "templates" / "ui" / "capability-reader.js"


def _run_node(script: str) -> dict:
    """Execute snippet with agent skills module in Node.js via stdin and return parsed JSON."""
    res = subprocess.run(
        ["node", "-"],
        input=script,
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(res.stdout)


# ---------------------------------------------------------------------------
# Backend Manifest Tests
# ---------------------------------------------------------------------------

def test_backend_agent_capabilities_declared_and_deterministic():
    """Agent capabilities are derived deterministically and conform to schema."""
    caps1 = build_agent_capabilities()
    caps2 = build_agent_capabilities()
    assert caps1 == caps2
    assert len(caps1) >= 6

    manifest = build_capability_manifest()
    assert "agent_capabilities" in manifest
    assert manifest["agent_capabilities"] == caps1
    assert "agent_capabilities" in ALLOWED_TOP_LEVEL_FIELDS

    errors = validate_capability_manifest(manifest)
    assert errors == []

    declared_ids = {c["id"] for c in caps1}
    assert "browser_interaction" in declared_ids
    assert "security_scope_guard" in declared_ids
    assert "sensitive_data_protection" in declared_ids
    assert "request_scoped_headers" in declared_ids
    assert "vulnerability_hypothesis" in declared_ids
    assert "recon_url_discovery" in declared_ids

    for cap in caps1:
        assert isinstance(cap["id"], str) and cap["id"]
        assert isinstance(cap["name"], str) and cap["name"]
        assert isinstance(cap["description"], str) and cap["description"]
        assert isinstance(cap["applicable_modes"], list) and len(cap["applicable_modes"]) > 0
        assert isinstance(cap["available"], bool)


def test_backend_agent_capabilities_strict_validation():
    """Validation rejects missing fields, non-boolean available, and extra fields."""
    base_manifest = build_capability_manifest()

    # Missing required field
    bad_manifest = copy.deepcopy(base_manifest)
    del bad_manifest["agent_capabilities"][0]["name"]
    errors = validate_capability_manifest(bad_manifest)
    assert any("missing required field 'name'" in e for e in errors)

    # Non-boolean available
    bad_available = copy.deepcopy(base_manifest)
    bad_available["agent_capabilities"][0]["available"] = "yes"
    errors = validate_capability_manifest(bad_available)
    assert any("'available' must be a boolean" in e for e in errors)

    # Non-list applicable_modes
    bad_modes = copy.deepcopy(base_manifest)
    bad_modes["agent_capabilities"][0]["applicable_modes"] = "agent"
    errors = validate_capability_manifest(bad_modes)
    assert any("'applicable_modes' must be a list" in e for e in errors)

    # Unexpected extra field
    bad_extra = copy.deepcopy(base_manifest)
    bad_extra["agent_capabilities"][0]["unexpected_prop"] = 123
    errors = validate_capability_manifest(bad_extra)
    assert any("unexpected extra field 'unexpected_prop'" in e for e in errors)


def test_backend_agent_capabilities_rejects_coverage_claims():
    """Agent capability entries strictly reject forbidden coverage claims."""
    base_manifest = build_capability_manifest()
    for forbidden_key in ("coverage", "tested", "passed", "verified", "runtime_coverage"):
        bad_manifest = copy.deepcopy(base_manifest)
        bad_manifest["agent_capabilities"][0][forbidden_key] = True
        errors = validate_capability_manifest(bad_manifest)
        assert any(forbidden_key in e for e in errors), f"expected rejection for {forbidden_key}"


# ---------------------------------------------------------------------------
# Frontend Node.js Tests (Browser-Independent via stdin)
# ---------------------------------------------------------------------------

def test_js_registry_and_route_registration():
    """Module can be registered into ModuleRegistry and routeMap resolves #agent-skills."""
    script = f"""
    const {{ ModuleRegistry, NavigationDispatcher }} = require('{APP_SHELL_JS}');
    const {{ createAgentSkillsModule, registerAgentSkillsModule }} = require('{AGENT_SKILLS_MODULE_JS}');

    const registry = new ModuleRegistry();
    let mounted = false;
    let unmounted = false;

    const def = createAgentSkillsModule({{
      container: {{
        hidden: true,
        replaceChildren() {{}},
      }},
    }});
    // Override mount/unmount for testing lifecycle dispatcher
    const originalMount = def.mount;
    const originalUnmount = def.unmount;
    def.mount = (ctx) => {{ mounted = true; if (originalMount) originalMount(ctx); }};
    def.unmount = (ctx) => {{ unmounted = true; if (originalUnmount) originalUnmount(ctx); }};

    registry.register(def);
    const dispatcher = new NavigationDispatcher(registry);

    const resolved = dispatcher.resolveRoute('#agent-skills');
    dispatcher.navigateTo(resolved.viewId, {{ updateHash: false }});
    const activeAfterMount = registry.getActiveId();

    registry.destroy();
    const activeAfterDestroy = registry.getActiveId();

    console.log(JSON.stringify({{
      hasModule: registry.has('agent-skills'),
      resolvedViewId: resolved.viewId,
      isFallback: resolved.isFallback,
      activeAfterMount: activeAfterMount,
      mounted: mounted,
      unmounted: unmounted,
      activeAfterDestroy: activeAfterDestroy,
    }}));
    """
    res = _run_node(script)
    assert res["hasModule"] is True
    assert res["resolvedViewId"] == "agent-skills"
    assert res["isFallback"] is False
    assert res["activeAfterMount"] == "agent-skills"
    assert res["mounted"] is True
    assert res["unmounted"] is True
    assert res["activeAfterDestroy"] is None


def test_js_fallback_for_unknown_and_absent_metadata():
    """Unknown, absent, or malformed metadata renders explicit fallbacks, never invented values."""
    script = f"""
    const {{ normalizeCapability, renderSkillsTable, renderSkillsError, loadAndRenderAgentSkills }} = require('{AGENT_SKILLS_MODULE_JS}');

    // Mock DOM environment
    class MockElement {{
      constructor(tagName) {{
        this.tagName = String(tagName).toUpperCase();
        this.children = [];
        this.textContent = '';
        this.className = '';
        this.attributes = {{}};
      }}
      appendChild(child) {{
        this.children.push(child);
        return child;
      }}
      append(...items) {{
        for (const item of items) this.appendChild(item);
      }}
      replaceChildren(...items) {{
        this.children = [];
        this.textContent = '';
        for (const item of items) this.appendChild(item);
      }}
      setAttribute(k, v) {{ this.attributes[k] = v; }}
      getAttribute(k) {{ return this.attributes[k] || null; }}
    }}

    const mockDoc = {{
      createElement(tag) {{ return new MockElement(tag); }}
    }};

    // 1. normalizeCapability fallbacks
    const normNull = normalizeCapability(null);
    const normEmpty = normalizeCapability({{}});
    const normPartial = normalizeCapability({{ id: 'custom_id' }});

    // 2. renderSkillsTable with missing fields
    const container = new MockElement('div');
    renderSkillsTable(container, [
      {{ id: 'unknown_fields_cap' }},
      {{ id: 'empty_strings', name: '   ', description: '  ', applicable_modes: [], available: null }},
    ], mockDoc);

    // Collect all textContents in the tree
    function collectText(el) {{
      const texts = [];
      if (el.textContent) texts.push(el.textContent);
      for (const c of el.children) texts.push(...collectText(c));
      return texts;
    }}
    const allTexts = collectText(container);

    console.log(JSON.stringify({{
      normNull,
      normEmpty,
      normPartial,
      allTexts,
    }}));
    """
    res = _run_node(script)

    assert res["normNull"]["name"] == "unknown"
    assert res["normNull"]["description"] == "unknown"
    assert res["normNull"]["applicableModes"] == ["unknown"]
    assert res["normNull"]["availableLabel"] == "unavailable"

    assert res["normEmpty"]["name"] == "unknown"
    assert res["normPartial"]["id"] == "custom_id"
    assert res["normPartial"]["name"] == "unknown"
    assert res["normPartial"]["description"] == "unknown"
    assert res["normPartial"]["availableLabel"] == "unavailable"

    # Both missing name and description rendered safe "unknown" and status "unavailable"
    rendered_blob = " ".join(res["allTexts"])
    assert "unknown" in rendered_blob
    assert "unavailable" in rendered_blob


def test_js_fallback_for_absent_and_unsupported_version_manifest():
    """Manifest failure or unsupported schema version triggers explicit unavailable fallback."""
    script = f"""
    const {{ loadAndRenderAgentSkills }} = require('{AGENT_SKILLS_MODULE_JS}');

    class MockElement {{
      constructor(tagName) {{
        this.tagName = String(tagName).toUpperCase();
        this.children = [];
        this.textContent = '';
        this.className = '';
      }}
      appendChild(child) {{ this.children.push(child); return child; }}
      append(...items) {{ for (const item of items) this.appendChild(item); }}
      replaceChildren(...items) {{ this.children = []; this.textContent = ''; for (const item of items) this.appendChild(item); }}
    }}

    const mockDoc = {{
      createElement(tag) {{ return new MockElement(tag); }}
    }};

    function collectText(el) {{
      const texts = [];
      if (el.textContent) texts.push(el.textContent);
      for (const c of el.children) texts.push(...collectText(c));
      return texts;
    }}

    (async () => {{
      // Case A: Unsupported schema version
      const containerA = new MockElement('div');
      await loadAndRenderAgentSkills(containerA, {{
        document: mockDoc,
        manifest: {{
          schema_version: '2.0.0',
          manifest_kind: 'scanner_capability_manifest',
          agent_capabilities: [{{ id: 'a', name: 'A', description: 'B', applicable_modes: ['agent'], available: true }}],
        }},
      }});
      const textA = collectText(containerA).join(' ');

      // Case B: API error (network / 500)
      const containerB = new MockElement('div');
      await loadAndRenderAgentSkills(containerB, {{
        document: mockDoc,
        api: {{
          async get() {{ return {{ ok: false, data: null }}; }}
        }},
      }});
      const textB = collectText(containerB).join(' ');

      // Case C: Empty capabilities array
      const containerC = new MockElement('div');
      await loadAndRenderAgentSkills(containerC, {{
        document: mockDoc,
        manifest: {{
          schema_version: '1.0.0',
          manifest_kind: 'scanner_capability_manifest',
          agent_capabilities: [],
        }},
      }});
      const textC = collectText(containerC).join(' ');

      console.log(JSON.stringify({{
        textA,
        textB,
        textC,
      }}));
    }})();
    """
    res = _run_node(script)
    assert "unavailable" in res["textA"]
    assert "unavailable" in res["textB"]
    assert "unavailable" in res["textC"]


def test_js_malicious_strings_rendered_inert():
    """All strings from backend are rendered as textContent, keeping HTML/script tags inert."""
    script = f"""
    const {{ renderSkillsTable }} = require('{AGENT_SKILLS_MODULE_JS}');

    class MockElement {{
      constructor(tagName) {{
        this.tagName = String(tagName).toUpperCase();
        this.children = [];
        this.textContent = '';
        this.className = '';
      }}
      appendChild(child) {{ this.children.push(child); return child; }}
      append(...items) {{ for (const item of items) this.appendChild(item); }}
      replaceChildren(...items) {{ this.children = []; this.textContent = ''; for (const item of items) this.appendChild(item); }}
      getElementsByTagName(name) {{
        const upper = name.toUpperCase();
        const results = [];
        for (const child of this.children) {{
          if (child.tagName === upper) results.push(child);
          results.push(...child.getElementsByTagName(name));
        }}
        return results;
      }}
    }}

    const mockDoc = {{
      createElement(tag) {{ return new MockElement(tag); }}
    }};

    const container = new MockElement('div');
    const maliciousPayloads = [
      {{
        id: '<script>window.pwned=1</script>',
        name: '<b>Malicious Name</b><img src=x onerror=alert(1)>',
        description: '<iframe src="javascript:alert(1)"></iframe>Description',
        applicable_modes: ['<svg onload=alert(1)>', 'agent'],
        available: true,
      }}
    ];

    renderSkillsTable(container, maliciousPayloads, mockDoc);

    const scriptTags = container.getElementsByTagName('script');
    const imgTags = container.getElementsByTagName('img');
    const bTags = container.getElementsByTagName('b');
    const iframeTags = container.getElementsByTagName('iframe');
    const svgTags = container.getElementsByTagName('svg');

    function collectText(el) {{
      const texts = [];
      if (el.textContent) texts.push(el.textContent);
      for (const c of el.children) texts.push(...collectText(c));
      return texts;
    }}
    const allText = collectText(container).join(' ');

    console.log(JSON.stringify({{
      scriptTagCount: scriptTags.length,
      imgTagCount: imgTags.length,
      bTagCount: bTags.length,
      iframeTagCount: iframeTags.length,
      svgTagCount: svgTags.length,
      containsRawName: allText.includes('<b>Malicious Name</b><img src=x onerror=alert(1)>'),
      containsRawDesc: allText.includes('<iframe src="javascript:alert(1)"></iframe>Description'),
    }}));
    """
    res = _run_node(script)
    assert res["scriptTagCount"] == 0
    assert res["imgTagCount"] == 0
    assert res["bTagCount"] == 0
    assert res["iframeTagCount"] == 0
    assert res["svgTagCount"] == 0
    assert res["containsRawName"] is True
    assert res["containsRawDesc"] is True


def test_js_mode_applicability_shown_as_declared():
    """Mode applicability formats known modes to Japanese labels and preserves raw custom modes."""
    script = f"""
    const {{ formatMode, renderSkillsTable }} = require('{AGENT_SKILLS_MODULE_JS}');

    const normal = formatMode('normal');
    const agent = formatMode('agent');
    const hybrid = formatMode('hybrid');
    const custom = formatMode('custom_mode');
    const blank = formatMode('  ');

    class MockElement {{
      constructor(tagName) {{
        this.tagName = String(tagName).toUpperCase();
        this.children = [];
        this.textContent = '';
        this.className = '';
      }}
      appendChild(child) {{ this.children.push(child); return child; }}
      append(...items) {{ for (const item of items) this.appendChild(item); }}
      replaceChildren(...items) {{ this.children = []; this.textContent = ''; for (const item of items) this.appendChild(item); }}
      getElementsByClassName(name) {{
        const results = [];
        if (this.className.split(' ').includes(name)) results.push(this);
        for (const child of this.children) {{
          results.push(...child.getElementsByClassName(name));
        }}
        return results;
      }}
    }}

    const mockDoc = {{ createElement(tag) {{ return new MockElement(tag); }} }};
    const container = new MockElement('div');
    renderSkillsTable(container, [
      {{
        id: 'multi_mode',
        name: 'Multi Mode Skill',
        description: 'Test skill',
        applicable_modes: ['normal', 'agent', 'hybrid'],
        available: true,
      }},
    ], mockDoc);

    const badges = container.getElementsByClassName('agent-skill-mode-badge');
    const badgeTexts = badges.map(b => b.textContent);
    const hasAgentClass = badges.some(b => b.className.includes('mode-agent'));
    const hasHybridClass = badges.some(b => b.className.includes('mode-hybrid'));

    console.log(JSON.stringify({{
      normal,
      agent,
      hybrid,
      custom,
      blank,
      badgeTexts,
      hasAgentClass,
      hasHybridClass,
    }}));
    """
    res = _run_node(script)
    assert res["normal"] == "通常"
    assert res["agent"] == "Agent"
    assert res["hybrid"] == "Hybrid"
    assert res["custom"] == "custom_mode"
    assert res["blank"] == "unknown"

    assert "通常" in res["badgeTexts"]
    assert "Agent" in res["badgeTexts"]
    assert "Hybrid" in res["badgeTexts"]
    assert res["hasAgentClass"] is True
    assert res["hasHybridClass"] is True
