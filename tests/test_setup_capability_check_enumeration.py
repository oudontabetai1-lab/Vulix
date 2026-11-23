"""Tests for dynamic scanner check enumeration in /app Setup view.

Verifies:
1. Dynamic enumeration matches backend SCANNERS registry keys (currently 41, avoiding hardcoding).
2. Dynamic scanner injection is reflected in UI without UI code changes.
3. Carrier support status determination (supported, partial, unsupported) and prerequisite badges.
4. Selected-check payload parity across Normal, Hybrid, and Agent modes.
5. Zero-check validation behavior across modes (Normal and Hybrid blocked; Agent allowed).
6. Malformed/unavailable manifest visibility and start-scan gating.
7. User check selection preservation across mode transitions.
"""

import json
from pathlib import Path
import subprocess
from unittest.mock import patch

import pytest

from wscan.capability_manifest import build_capability_manifest
from wscan.scanners import SCANNERS
from wscan.scanners.base import BaseScanner
from wscan.settings_schema import build_settings_schema

ROOT = Path(__file__).resolve().parent.parent


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


def test_registry_dynamic_enumeration_matches_backend_scanners_without_hardcoding():
    """Verify that renderSettingsSchemaForm dynamically enumerates all registry scanners without drift."""
    manifest = build_capability_manifest()
    registry_keys = sorted(SCANNERS.keys())
    assert manifest["scanner_count"] == len(registry_keys)
    assert manifest["scanner_ids"] == registry_keys

    script = f"""
const {{ renderSettingsSchemaForm }} = require('./templates/ui/setup-module.js');

function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  const classes = new Set();
  return {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    dataset: {{}},
    style: {{}},
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{ children.push(c); c.parentNode = this; }},
    replaceChildren(...c) {{ children.length = 0; children.push(...c); }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatch(evt, data) {{
      (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
    }},
    focus() {{ this._focused = true; }},
    classList: {{
      add(c) {{ classes.add(c); }},
      remove(c) {{ classes.delete(c); }},
      contains(c) {{ return classes.has(c); }},
    }},
    querySelector(sel) {{
      if (sel === 'input[type=checkbox]') {{
        return children.find(c => c.tagName === 'label')?.children?.find(ch => ch.tagName === 'input') || null;
      }}
      return null;
    }},
    querySelectorAll(sel) {{
      return [];
    }},
  }};
}}

const mockDoc = {{
  createElement: makeElement,
}};

const container = makeElement('div');
const field = {{
  key: 'checks',
  type: 'list[string]',
  label: '検査項目',
  default: ['sqli', 'xss', 'os'],
}};

const manifest = {json.dumps(manifest)};
const fieldMap = {{}};

renderSettingsSchemaForm(container, [field], {{
  document: mockDoc,
  currentMode: 'normal',
  fieldMap: fieldMap,
  fieldWrappers: [],
  capabilityManifest: manifest,
}});

const checkList = fieldMap['checks'];
const renderedCheckIds = checkList.children
  .filter(c => c.dataset && c.dataset.checkId)
  .map(c => c.dataset.checkId);

console.log(JSON.stringify({{
  count: renderedCheckIds.length,
  ids: renderedCheckIds,
}}));
"""
    res = _run_node(script)
    assert res["count"] == len(registry_keys)
    assert res["ids"] == registry_keys


def test_dynamic_scanner_injection_reflected_in_ui_without_ui_code_change():
    """Verify that adding a new scanner class to SCANNERS dynamically reflects in UI."""
    class DummyDynamicScanner(BaseScanner):
        CHECK_TYPE = "dummy_dynamic_scanner_test"
        SEVERITY = "info"

    with patch.dict(SCANNERS, {DummyDynamicScanner.CHECK_TYPE: DummyDynamicScanner}):
        manifest = build_capability_manifest()
        assert "dummy_dynamic_scanner_test" in manifest["scanner_ids"]

        script = f"""
const {{ renderSettingsSchemaForm }} = require('./templates/ui/setup-module.js');

function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  return {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    dataset: {{}},
    style: {{}},
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{ children.push(c); c.parentNode = this; }},
    addEventListener() {{}},
    classList: {{ add() {{}}, remove() {{}}, contains() {{ return false; }} }},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
  }};
}}

const mockDoc = {{ createElement: makeElement }};
const container = makeElement('div');
const field = {{ key: 'checks', type: 'list[string]', default: ['sqli'] }};
const manifest = {json.dumps(manifest)};
const fieldMap = {{}};

renderSettingsSchemaForm(container, [field], {{
  document: mockDoc,
  currentMode: 'normal',
  fieldMap: fieldMap,
  fieldWrappers: [],
  capabilityManifest: manifest,
}});

const renderedCheckIds = fieldMap['checks'].children
  .filter(c => c.dataset && c.dataset.checkId)
  .map(c => c.dataset.checkId);

console.log(JSON.stringify({{
  hasDynamic: renderedCheckIds.includes('dummy_dynamic_scanner_test'),
  count: renderedCheckIds.length,
}}));
"""
        res = _run_node(script)
        assert res["hasDynamic"] is True
        assert res["count"] == len(SCANNERS)


def test_get_scanner_support_info_pure_helper():
    """Verify carrier support resolution for supported, partial, and unsupported scanners."""
    script = """
const { getScannerSupportInfo } = require('./templates/ui/setup-module.js');

const pageOnly = {
  has_page_level: true,
  declared_carriers: {},
};

const fullCarriers = {
  has_page_level: false,
  declared_carriers: {
    url_param: { carrier: 'url_param', state: 'supported' },
    form_body: { carrier: 'form_body', state: 'supported' },
  },
};

const partialCarriers = {
  has_page_level: false,
  declared_carriers: {
    url_param: { carrier: 'url_param', state: 'supported' },
    json_body: { carrier: 'json_body', state: 'planned' },
  },
};

const unsupportedCarriers = {
  has_page_level: false,
  declared_carriers: {
    url_param: { carrier: 'url_param', state: 'unsupported' },
  },
};

console.log(JSON.stringify({
  page: getScannerSupportInfo(pageOnly),
  full: getScannerSupportInfo(fullCarriers),
  partial: getScannerSupportInfo(partialCarriers),
  unsupported: getScannerSupportInfo(unsupportedCarriers),
  nullCase: getScannerSupportInfo(null),
}));
"""
    res = _run_node(script)
    assert res["page"]["state"] == "supported"
    assert res["page"]["badgeClass"] == "setup-status-pass"
    assert res["page"]["label"] == "対応"

    assert res["full"]["state"] == "supported"
    assert res["full"]["badgeClass"] == "setup-status-pass"

    assert res["partial"]["state"] == "partial"
    assert res["partial"]["badgeClass"] == "setup-status-warning"
    assert res["partial"]["label"] == "一部対応"

    assert res["unsupported"]["state"] == "unsupported"
    assert res["unsupported"]["badgeClass"] == "setup-status-not-applicable"
    assert res["unsupported"]["label"] == "非対応"

    assert res["nullCase"]["state"] == "unsupported"


def test_payload_parity_and_no_silent_default_on_zero_checks():
    """Verify buildScanPayload parity: selected checks preserved, zero checks produces empty array."""
    script = """
const { buildScanPayload } = require('./templates/ui/setup-module.js');

function makeElement(tag) {
  return {
    tagName: tag,
    value: '',
    checked: false,
    dataset: {},
    getAttribute() { return null; },
  };
}

// Normal mode with specific checks
const normalPayload = buildScanPayload('normal', {
  values: {
    url: 'https://example.com/target',
    checks: ['sqli', 'csrf', 'ssrf'],
  },
});

// Normal mode with explicit zero checks
const zeroNormalPayload = buildScanPayload('normal', {
  values: {
    url: 'https://example.com/target',
    checks: [],
  },
});

// Hybrid mode with specific checks
const hybridPayload = buildScanPayload('hybrid', {
  values: {
    url: 'https://example.com/target',
    checks: ['nosql', 'xxe'],
  },
});

// Hybrid mode with explicit zero checks
const zeroHybridPayload = buildScanPayload('hybrid', {
  values: {
    url: 'https://example.com/target',
    checks: [],
  },
});

// Agent mode with zero deterministic checks
const agentZeroDetPayload = buildScanPayload('agent', {
  values: {
    url: 'https://example.com/target',
    checks: [],
  },
});

console.log(JSON.stringify({
  normalChecks: normalPayload.checks,
  zeroNormalChecks: zeroNormalPayload.checks,
  hybridChecks: hybridPayload.checks,
  zeroHybridChecks: zeroHybridPayload.checks,
  agentChecks: agentZeroDetPayload.checks,
}));
"""
    res = _run_node(script)
    assert res["normalChecks"] == ["sqli", "csrf", "ssrf"]
    assert res["zeroNormalChecks"] == []  # Removed silent default fallback!
    assert res["hybridChecks"] == ["nosql", "xxe"]
    assert res["zeroHybridChecks"] == []  # Removed silent default fallback!
    # Agent retains its declared agentChecks semantics
    assert set(res["agentChecks"]) == {"xss", "sqli", "ssti", "os", "path_traversal", "ssrf"}


def test_zero_checks_validation_and_mode_applicability_in_ui():
    """Verify that zero checks blocks scan start in Normal/Hybrid but NOT in Agent mode."""
    manifest = build_capability_manifest()
    schema = build_settings_schema()

    script = f"""
const {{ renderSetupView }} = require('./templates/ui/setup-module.js');

const elementsById = {{}};
const allCheckboxes = [];

function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  const classes = new Set();
  const el = {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    dataset: {{}},
    style: {{}},
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{ children.push(c); c.parentNode = this; }},
    replaceChildren(...c) {{ children.length = 0; children.push(...c); }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatch(evt, data) {{
      (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
    }},
    focus() {{ this._focused = true; }},
    classList: {{
      add(c) {{ classes.add(c); }},
      remove(c) {{ classes.delete(c); }},
      toggle(c, force) {{
        if (force === undefined) force = !classes.has(c);
        if (force) classes.add(c);
        else classes.delete(c);
      }},
      contains(c) {{ return classes.has(c); }},
    }},
    querySelector(sel) {{
      if (sel === 'input[type=checkbox]') {{
        return children.find(c => c.tagName === 'label')?.children?.find(ch => ch.tagName === 'input') || null;
      }}
      if (sel === '.setup-check-gated-badge') {{
        return children.find(c => c.className && c.className.includes('setup-check-gated-badge')) || null;
      }}
      return null;
    }},
    querySelectorAll(sel) {{
      if (sel.includes('input[type=checkbox][data-check]')) {{
        return allCheckboxes;
      }}
      if (sel.includes('.setup-check-item')) {{
        return elementsById['setupChecks'] ? elementsById['setupChecks'].children.filter(c => c.className && c.className.includes('setup-check-item')) : [];
      }}
      return [];
    }},
  }};
  return el;
}}

const mockDoc = {{
  createElement: (tag) => {{
    const el = makeElement(tag);
    return el;
  }},
  getElementById: (id) => elementsById[id] || null,
  querySelectorAll: (sel) => {{
    if (sel.includes('input[type=checkbox][data-check]')) return allCheckboxes;
    if (sel.includes('.setup-check-item')) {{
      return elementsById['setupChecks'] ? elementsById['setupChecks'].children.filter(c => c.className && c.className.includes('setup-check-item')) : [];
    }}
    return [];
  }},
}};

const container = makeElement('div');
const manifest = {json.dumps(manifest)};
const schema = {json.dumps(schema)};

let startedPayload = null;
const view = renderSetupView(container, schema, {{
  document: mockDoc,
  capabilityManifest: manifest,
  onStartScan: (p) => {{ startedPayload = p; }},
}});

// Wire elements into elementsById by id attribute
function indexElements(node) {{
  const id = node.getAttribute('id') || node.id;
  if (id) elementsById[id] = node;
  if (node.tagName === 'input' && (node.type === 'checkbox' || node.getAttribute('type') === 'checkbox') && node.dataset && node.dataset.check) {{
    allCheckboxes.push(node);
  }}
  (node.children || []).forEach(indexElements);
}}
indexElements(container);

// Set valid URL
const urlInput = elementsById['cfgInputUrl'];
urlInput.value = 'https://example.com/test';

// Uncheck all checkboxes to simulate zero checks
allCheckboxes.forEach(cb => {{ cb.checked = false; }});

const startBtn = elementsById['setupStartScanBtn'];
const checksError = elementsById['setupChecksError'];
const checksList = elementsById['setupChecks'];

// 1. In Normal mode, zero checks should block
startedPayload = null;
startBtn.dispatch('click');
const normalBlocked = startedPayload === null;
const normalError = checksError.textContent;
const normalAriaInvalid = checksList.getAttribute('aria-invalid');

// 2. Switch to Hybrid mode, zero checks should also block
view.applyMode('hybrid');
startedPayload = null;
startBtn.dispatch('click');
const hybridBlocked = startedPayload === null;
const hybridError = checksError.textContent;

// 3. Switch to Agent mode, zero deterministic checks should NOT block
view.applyMode('agent');
startedPayload = null;
startBtn.dispatch('click');
const agentStarted = startedPayload !== null;

console.log(JSON.stringify({{
  normalBlocked,
  normalError,
  normalAriaInvalid,
  hybridBlocked,
  hybridError,
  agentStarted,
}}));
"""
    res = _run_node(script)
    assert res["normalBlocked"] is True
    assert "検査項目を1つ以上選択してください" in res["normalError"]
    assert res["normalAriaInvalid"] == "true"

    assert res["hybridBlocked"] is True
    assert "検査項目を1つ以上選択してください" in res["hybridError"]

    assert res["agentStarted"] is True


def test_unavailable_manifest_shows_accessible_alert_and_blocks_normal_scan():
    """Verify that unavailable/malformed manifest displays accessible alert and gates start scan."""
    schema = build_settings_schema()
    malformed_manifest = {
        "schema_version": "0.0.1",  # Invalid version
        "manifest_kind": "wrong_kind",
    }

    script = f"""
const {{ renderSetupView }} = require('./templates/ui/setup-module.js');

const elementsById = {{}};
function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  const el = {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    dataset: {{}},
    style: {{}},
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{ children.push(c); c.parentNode = this; }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatch(evt, data) {{
      (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
    }},
    focus() {{ this._focused = true; }},
    classList: {{ add() {{}}, remove() {{}}, toggle() {{}}, contains() {{ return false; }} }},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
  }};
  return el;
}}

const mockDoc = {{
  createElement: makeElement,
  getElementById: (id) => elementsById[id] || null,
  querySelectorAll: () => [],
}};

const container = makeElement('div');
const schema = {json.dumps(schema)};
const malformedManifest = {json.dumps(malformed_manifest)};

let startedPayload = null;
const view = renderSetupView(container, schema, {{
  document: mockDoc,
  capabilityManifest: malformedManifest,
  onStartScan: (p) => {{ startedPayload = p; }},
}});

function indexElements(node) {{
  const id = node.getAttribute('id') || node.id;
  if (id) elementsById[id] = node;
  (node.children || []).forEach(indexElements);
}}
indexElements(container);

const urlInput = elementsById['cfgInputUrl'];
if (urlInput) urlInput.value = 'https://example.com/test';

const startBtn = elementsById['setupStartScanBtn'];
const checksError = elementsById['setupChecksError'];

startBtn.dispatch('click');
const blocked = startedPayload === null;
const errorText = checksError ? checksError.textContent : '';

console.log(JSON.stringify({{
  blocked,
  errorText,
}}));
"""
    res = _run_node(script)
    assert res["blocked"] is True
    assert "機能マニフェストが利用できないため" in res["errorText"]


def test_mode_switching_preserves_user_selections():
    """Verify that toggling between Normal, Agent, and Normal preserves user check selections."""
    manifest = build_capability_manifest()
    schema = build_settings_schema()

    script = f"""
const {{ renderSetupView }} = require('./templates/ui/setup-module.js');

const elementsById = {{}};
const allCheckboxes = [];

function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  const classes = new Set();
  const el = {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    dataset: {{}},
    style: {{}},
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{ children.push(c); c.parentNode = this; }},
    replaceChildren(...c) {{ children.length = 0; children.push(...c); }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatch(evt, data) {{
      (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
    }},
    classList: {{
      add(c) {{ classes.add(c); }},
      remove(c) {{ classes.delete(c); }},
      toggle(c, force) {{
        if (force === undefined) force = !classes.has(c);
        if (force) classes.add(c);
        else classes.delete(c);
      }},
      contains(c) {{ return classes.has(c); }},
    }},
    querySelector(sel) {{
      if (sel === 'input[type=checkbox]') {{
        return children.find(c => c.tagName === 'label')?.children?.find(ch => ch.tagName === 'input') || null;
      }}
      if (sel === '.setup-check-gated-badge') {{
        return children.find(c => c.className && c.className.includes('setup-check-gated-badge')) || null;
      }}
      return null;
    }},
    querySelectorAll(sel) {{
      if (sel.includes('input[type=checkbox][data-check]')) return allCheckboxes;
      if (sel.includes('.setup-check-item')) {{
        return elementsById['setupChecks'] ? elementsById['setupChecks'].children.filter(c => c.className && c.className.includes('setup-check-item')) : [];
      }}
      return [];
    }},
  }};
  return el;
}}

const mockDoc = {{
  createElement: makeElement,
  getElementById: (id) => elementsById[id] || null,
  querySelectorAll: (sel) => {{
    if (sel.includes('input[type=checkbox][data-check]')) return allCheckboxes;
    if (sel.includes('.setup-check-item')) {{
      return elementsById['setupChecks'] ? elementsById['setupChecks'].children.filter(c => c.className && c.className.includes('setup-check-item')) : [];
    }}
    return [];
  }},
}};

const container = makeElement('div');
const manifest = {json.dumps(manifest)};
const schema = {json.dumps(schema)};

const view = renderSetupView(container, schema, {{
  document: mockDoc,
  capabilityManifest: manifest,
}});

function indexElements(node) {{
  const id = node.getAttribute('id') || node.id;
  if (id) elementsById[id] = node;
  if (node.tagName === 'input' && (node.type === 'checkbox' || node.getAttribute('type') === 'checkbox') && node.dataset && node.dataset.check) {{
    allCheckboxes.push(node);
  }}
  (node.children || []).forEach(indexElements);
}}
indexElements(container);

// Select specific checks: only 'nosql' and 'cors'
allCheckboxes.forEach(cb => {{
  cb.checked = (cb.dataset.check === 'nosql' || cb.dataset.check === 'cors');
}});

// 1. Initial Normal checked
const initialChecked = allCheckboxes.filter(cb => cb.checked).map(cb => cb.dataset.check);

// 2. Switch to Agent mode (deterministic checks get disabled/gated)
view.applyMode('agent');
const agentDisabled = allCheckboxes.find(cb => cb.dataset.check === 'cors')?.disabled;
const agentChecked = allCheckboxes.filter(cb => cb.checked).map(cb => cb.dataset.check);

// 3. Switch back to Normal mode (deterministic checks re-enabled, selections retained)
view.applyMode('normal');
const normalRestoredDisabled = allCheckboxes.find(cb => cb.dataset.check === 'cors')?.disabled;
const normalRestoredChecked = allCheckboxes.filter(cb => cb.checked).map(cb => cb.dataset.check);

console.log(JSON.stringify({{
  initialChecked,
  agentDisabled,
  agentChecked,
  normalRestoredDisabled,
  normalRestoredChecked,
}}));
"""
    res = _run_node(script)
    assert set(res["initialChecked"]) == {"nosql", "cors"}
    assert res["agentDisabled"] is True
    assert set(res["agentChecked"]) == {"nosql", "cors"}
    assert res["normalRestoredDisabled"] is False
    assert set(res["normalRestoredChecked"]) == {"nosql", "cors"}
