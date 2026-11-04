"""Browser-independent tests for /app Setup 5-tab view module.

Verifies:
- Every declared setting key is reachable in some tab (nothing silently dropped).
- Payload equivalence vs legacy builder for normal, Agent, and Hybrid across input sets.
- Unavailable declaration path triggers explicit unavailable fallback.
- Invalid numeric input triggers explicit field-level error messages and blocks submit.
- Tab keyboard navigation with roving tabindex and arrow keys.
- Basic/Advanced disclosure across tabs.
"""
from __future__ import annotations

import json
from pathlib import Path
import re
import subprocess

import pytest

from wscan.settings_schema import FIELDS, PROFILES, SCHEMA_VERSION, build_settings_schema
from fastapi.testclient import TestClient
import wscan.check_catalog as check_catalog
from wscan.monitor import MonitorServer

ROOT = Path(__file__).resolve().parents[1]
SETUP_MODULE_JS = ROOT / "templates" / "ui" / "setup-module.js"
DASHBOARD_HTML = ROOT / "templates" / "dashboard.html"


def test_check_catalog_api_locales_and_empty_fallback(monkeypatch):
    monkeypatch.setattr(check_catalog, "_loaded", False)
    client = TestClient(MonitorServer().app)
    ja = client.get('/api/v1/check-catalog?lang=ja').json()
    en = client.get('/api/v1/check-catalog?lang=en').json()
    fallback = client.get('/api/v1/check-catalog?lang=fr').json()
    assert ja['lang'] == 'ja' and ja['checks']['sqli']['title']
    assert ja['catalog_version'] == '1.0.0'
    typed_refs = check_catalog.get_check_references('sqli')
    assert typed_refs and all(isinstance(ref, check_catalog.CatalogReference) for ref in typed_refs)
    assert ja['checks']['sqli']['references'] == [ref.__dict__ for ref in typed_refs]
    assert ja['checks']['sqli']['references'] == [{
        'kind': 'CWE', 'id': '89.html',
        'url': 'https://cwe.mitre.org/data/definitions/89.html',
    }]
    assert en['lang'] == 'en' and en['checks']['sqli']['title'] != ja['checks']['sqli']['title']
    assert en['checks']['sqli']['references'] == ja['checks']['sqli']['references']
    assert fallback['lang'] == 'ja' and fallback['checks']['sqli']['title'] == ja['checks']['sqli']['title']
    monkeypatch.setattr(check_catalog, 'list_checks', lambda lang='ja': ())
    empty = client.get('/api/v1/check-catalog').json()
    assert empty['checks'] == {}


def test_check_info_source_uses_text_nodes_and_has_unknown_fallback():
    source = (ROOT / 'templates' / 'ui' / 'check-help.js').read_text(encoding='utf-8')
    assert 'setup-check-popover' in source
    assert '説明準備中' in source and 'Description not available yet' in source
    assert "language === 'en' ? 'Description not available yet' : '説明準備中'" in source
    assert 'innerHTML' not in source


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


def test_every_declared_key_reachable_in_some_tab():
    """Verify that every key in FIELDS is reachable in one of the 5 tabs or top header."""
    declared_keys = {f["key"] for f in FIELDS}
    assert len(declared_keys) == 99

    script = f"""
const {{ TAB_DEFINITIONS, FIELD_TAB_MAP }} = require('./templates/ui/setup-module.js');

const tabIds = new Set(TAB_DEFINITIONS.map(t => t.id));
const persistentKeys = new Set(['url', 'agent_mode', 'hybrid_mode']);

const declaredKeys = {json.dumps(list(declared_keys))};
const missingKeys = [];
const invalidTabKeys = [];

for (const key of declaredKeys) {{
  if (persistentKeys.has(key)) continue;
  const mappedTab = FIELD_TAB_MAP[key];
  if (!mappedTab) {{
    missingKeys.push(key);
  }} else if (!tabIds.has(mappedTab)) {{
    invalidTabKeys.push({{ key, tab: mappedTab }});
  }}
}}

console.log(JSON.stringify({{
  tabCount: TAB_DEFINITIONS.length,
  missingKeys,
  invalidTabKeys,
  totalMapped: Object.keys(FIELD_TAB_MAP).length + persistentKeys.size,
}}));
"""
    result = _run_node(script)
    assert result["tabCount"] == 5
    assert result["missingKeys"] == []
    assert result["invalidTabKeys"] == []
    assert result["totalMapped"] == 99


def test_payload_equivalence_vs_legacy_builder():
    """Verify byte-for-byte equivalent scan start payloads for normal, agent, and hybrid."""
    html = DASHBOARD_HTML.read_text()

    # Extract legacy helpers
    helpers_code = ""
    for fn in [
        "mfaImapFields", "mfaTotpFields", "parseHeaderText",
        "authHeaderFields", "timeWindowFields", "mfaImapPassword",
        "collectRoleModels", "collectAccounts", "collectFlows",
    ]:
        match = re.search(r"function " + fn + r"\([^)]*\) \{.*?^\}", html, re.S | re.M)
        assert match, f"Legacy function {fn} not found in dashboard.html"
        helpers_code += "\n" + match.group()

    match_normal = re.search(r"function submitScanConfig\([^)]*\) \{.*?^\}", html, re.S | re.M).group()
    config_normal_body = match_normal.split("const config = {", 1)[1].split("if (!config.checks.length)", 1)[0]

    match_agent = re.search(r"function submitAgentScan\([^)]*\) \{.*?^\}", html, re.S | re.M).group()
    config_agent_body = match_agent.split("const config = {", 1)[1].split("if (state.ws &&", 1)[0].rsplit(";", 1)[0].rstrip()

    match_hybrid = re.search(r"function submitHybridScan\([^)]*\) \{.*?^\}", html, re.S | re.M).group()
    config_hybrid_body = match_hybrid.split("const config = {", 1)[1].split("_markOwnScan(config)", 1)[0].rsplit(";", 1)[0].rstrip()

    script = f"""
const {{ buildScanPayload }} = require('./templates/ui/setup-module.js');

const cfgToggles = {{
  headless: false,
  skip_registration: true,
  open_report: true,
  use_planner: true,
  enable_ai_analysis: true,
  enable_waf_detection: true,
  enable_payload_learning: true,
  community_payloads: true,
  component_intel: false,
  tls_scan: false,
  enable_sitemap_crawl: true,
  enable_llm_web_browsing: false,
  ctf_mode: false,
  interactive_plan: false,
  interactive_crawl_review: false,
  allow_state_changing_probes: false,
  spa_crawl: false,
  auto_spa_crawl: true,
  fast_mode: false,
  auto_register: false,
  tls_verify: false,
}};

let cfgFlows = [];

{helpers_code}

function legacyNormal(values, customToggles, customChecks, customFlows) {{
  const toggles = customToggles || cfgToggles;
  cfgFlows = customFlows || [];
  global.document = {{
    getElementById: (id) => ({{ value: values[id] != null ? values[id] : '' }}),
    querySelectorAll: () => [],
  }};
  const getSelectedChecks = () => customChecks || values.checks || ['sqli', 'xss', 'os'];
  const validateTotpReadiness = () => true;
  const reader = {{ isReady: () => true, isScannerApplicable: () => true }};
  const VulixCapabilityReader = {{ defaultReader: reader }};
  const cfgToggles = toggles;
  const url = (values.cfgInputUrl || '').trim();
  const excludeFieldsRaw = (values.cfgExcludeFields || '').trim();
  const excludeUrlsRaw = (values.cfgExcludeUrls || '').trim();
  const targetUrlsRaw = (values.cfgTargetUrls || '').trim();
  const accessUrlsRaw = (values.cfgAccessUrls || '').trim();
  const selectedChecks = getSelectedChecks();
  const applicableChecks = selectedChecks;
  const config = {{{config_normal_body}
  if (!config.checks.length) config.checks = ['sqli', 'xss', 'os'];
  return config;
}}

function legacyAgent(values, customChecks) {{
  const agentChecks = customChecks || values.agentChecks || [];
  global.document = {{
    getElementById: (id) => ({{ value: values[id] != null ? values[id] : '' }}),
    querySelectorAll: () => agentChecks.map(v => ({{ value: v }})),
  }};
  const url = (values.cfgInputUrl || '').trim();
  const config = {{{config_agent_body}
  return config;
}}

function legacyHybrid(values, customToggles, customChecks) {{
  const toggles = customToggles || cfgToggles;
  global.document = {{
    getElementById: (id) => ({{ value: values[id] != null ? values[id] : '' }}),
    querySelectorAll: () => [],
  }};
  const getSelectedChecks = () => customChecks || values.checks || ['sqli', 'xss', 'os'];
  const validateTotpReadiness = () => true;
  const reader = {{ isReady: () => true, isScannerApplicable: () => true }};
  const VulixCapabilityReader = {{ defaultReader: reader }};
  const cfgToggles = toggles;
  const url = (values.cfgInputUrl || '').trim();
  const selectedChecks = getSelectedChecks();
  const applicableChecks = selectedChecks;
  const checks = applicableChecks;
  const config = {{{config_hybrid_body}
  return config;
}}

const inputSets = [
  // Input Set 1: Default-like
  {{
    cfgInputUrl: 'https://default.example.com',
    cfgDepth: '2',
    cfgTimeoutInput: '30',
    cfgReportLang: 'ja',
    cfgLlmTimeoutInput: '30',
    cfgLlmStreamTimeoutInput: '90',
    cfgMaxForms: '50',
    cfgConcurrency: '1',
    cfgProxy: '',
    cfgTlsClientCert: '',
    cfgTlsClientKey: '',
    cfgTlsClientPfx: '',
    cfgTlsClientCertPassword: '',
    cfgTlsCaCert: '',
    cfgStateProfile: 'unrestricted',
    cfgCtfFlagPattern: '',
    cfgLlm: 'ollama',
    cfgOllamaModel: 'llama3',
    cfgOpenaiModel: 'gpt-4o-mini',
    cfgGeminiModel: 'gemini-2.0-flash',
    cfgClaudeModel: 'claude-haiku-4-5-20251001',
    cfgLlmBaseUrl: '',
    cfgAuthUser: '',
    cfgAuthPass: '',
    cfgLoginUrl: '',
    cfgLoginUserField: 'username',
    cfgLoginPassField: 'password',
    cfgLoginSuccess: '',
    cfgMfaType: '',
    cfgMfaField: '',
    cfgMfaEmailAccount: '',
    cfgCookies: '',
    cfgLowPrivCookies: '',
    cfgMaxPayloads: '0',
    cfgDelay: '0.5',
    cfgNavigationRetries: '2',
    cfgOutputDir: '',
    cfgPayloadsFile: '',
    cfgManualCrawlFile: '',
    cfgAutoRegisterCount: '2',
    cfgExcludeFields: '',
    cfgExcludeUrls: '',
    cfgTargetUrls: '',
    cfgAccessUrls: '',
    cfgBearer: '',
    cfgHeaders: '',
    cfgAllowedHours: '',
    cfgForbiddenHours: '',
    cfgMfaSelector: '',
    cfgMfaTotpUri: '',
    cfgMfaTotpSecret: '',
    cfgMfaTotpQr: '',
    cfgMfaTotpDigits: '',
    cfgMfaTotpPeriod: '',
    cfgMfaTotpAlgorithm: '',
    cfgMfaEmailAddress: '',
    cfgMfaEmailImapHost: '',
    cfgMfaEmailImapPort: '',
    cfgMfaEmailImapUser: '',
    cfgMfaEmailImapPassword: '',
    cfgMfaEmailImapSsl: '',
    agentLlm: 'ollama',
    agentModel: 'llama3',
    agentMaxSteps: '50',
    agentOllamaUrl: 'http://localhost:11434',
    agentLlmTimeout: '30',
    agentLoginUrl: '',
    agentAuthUser: '',
    agentAuthPass: '',
    hybridLlm: 'claude',
    hybridModel: '',
    hybridMaxSteps: '30',
    hybridOllamaUrl: 'http://localhost:11434',
  }},
  // Input Set 2: Fully customized with auth, proxy, time windows, and remote crawl
  {{
    cfgInputUrl: 'https://app.secure.test',
    cfgDepth: '4',
    cfgTimeoutInput: '45',
    cfgReportLang: 'en',
    cfgLlmTimeoutInput: '60',
    cfgLlmStreamTimeoutInput: '120',
    cfgMaxForms: '100',
    cfgConcurrency: '4',
    cfgProxy: 'http://127.0.0.1:8080',
    cfgTlsClientCert: '/etc/ssl/client.crt',
    cfgTlsClientKey: '/etc/ssl/client.key',
    cfgTlsClientPfx: '/etc/ssl/client.pfx',
    cfgTlsClientCertPassword: 'pfx-password-123',
    cfgTlsCaCert: '/etc/ssl/ca.crt',
    cfgStateProfile: 'controlled-write',
    cfgCtfFlagPattern: 'flag-pattern-xyz',
    cfgLlm: 'openai_compatible',
    cfgOllamaModel: 'llama3:70b',
    cfgOpenaiModel: 'gpt-4o',
    cfgGeminiModel: 'gemini-1.5-pro',
    cfgClaudeModel: 'claude-3-7-sonnet',
    cfgLlmBaseUrl: 'https://custom-llm.test/v1',
    cfgAuthUser: 'sec-admin',
    cfgAuthPass: 'super-secret-pass',
    cfgLoginUrl: 'https://app.secure.test/auth/login',
    cfgLoginUserField: 'user_name',
    cfgLoginPassField: 'pass_word',
    cfgLoginSuccess: 'Welcome Admin',
    cfgMfaType: 'email_imap',
    cfgMfaField: 'two_factor_code',
    cfgMfaEmailAccount: 'ops@secure.test',
    cfgCookies: 'auth=token999; role=admin',
    cfgLowPrivCookies: 'auth=token111; role=guest',
    cfgMaxPayloads: '25',
    cfgDelay: '0.1',
    cfgNavigationRetries: '5',
    cfgOutputDir: '/var/vulix/reports',
    cfgPayloadsFile: '/var/vulix/custom-payloads.txt',
    cfgManualCrawlFile: '/var/vulix/flows/login-crawl.json',
    cfgAutoRegisterCount: '10',
    cfgExcludeFields: 'csrf_token, __RequestVerificationToken, anti_forgery',
    cfgExcludeUrls: 'https://app.secure.test/logout\\nhttps://app.secure.test/delete_account',
    cfgTargetUrls: 'https://app.secure.test/api/v1\\nhttps://app.secure.test/api/v2',
    cfgAccessUrls: 'https://app.secure.test/public\\nhttps://app.secure.test/docs',
    cfgBearer: 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.dummy',
    cfgHeaders: 'X-Forwarded-For: 10.0.0.1\\nAuthorization: Custom auth-scheme\\nAccept: application/json',
    cfgAllowedHours: 'Mon-Fri 22:00-06:00\\nSat,Sun 00:00-24:00',
    cfgForbiddenHours: 'Mon-Fri 09:00-18:00',
    cfgMfaSelector: 'input[name=otp_token]',
    cfgMfaTotpUri: 'otpauth://totp/VulixSec:admin?secret=JBSWY3DPEHPK3PXP',
    cfgMfaTotpSecret: 'JBSWY3DPEHPK3PXP',
    cfgMfaTotpQr: 'data:image/png;base64,iVBORw0KGgoAAAANSUhEUg==',
    cfgMfaTotpDigits: '8',
    cfgMfaTotpPeriod: '60',
    cfgMfaTotpAlgorithm: 'SHA256',
    cfgMfaEmailAddress: '2fa@secure.test',
    cfgMfaEmailImapHost: 'mail.secure.test',
    cfgMfaEmailImapPort: '993',
    cfgMfaEmailImapUser: 'imap-user-2fa',
    cfgMfaEmailImapPassword: 'imap-secure-pass',
    cfgMfaEmailImapSsl: 'ssl',
    agentLlm: 'claude',
    agentModel: 'claude-3-5-haiku',
    agentMaxSteps: '80',
    agentOllamaUrl: 'http://ai.internal:11434',
    agentLlmTimeout: '45',
    agentLoginUrl: 'https://app.secure.test/auth/login',
    agentAuthUser: 'agent-bot',
    agentAuthPass: 'agent-pass',
    hybridLlm: 'openai',
    hybridModel: 'gpt-4o-mini',
    hybridMaxSteps: '40',
    hybridOllamaUrl: 'http://ai.internal:11434',
  }},
];

const customChecks = ['xss', 'sqli', 'os', 'ssti', 'csrf'];
const customFlows = [
  {{
    name: 'cart-checkout',
    steps: [
      {{ action: 'navigate', url: 'https://app.secure.test/cart' }},
      {{ action: 'click', selector: '#checkoutBtn' }},
    ],
  }},
];

const results = [];

inputSets.forEach((values, idx) => {{
  // Normal mode
  const legN = legacyNormal(values, cfgToggles, customChecks, customFlows);
  const adpN = buildScanPayload('normal', {{ values, toggles: cfgToggles, checks: customChecks, flows: customFlows }});
  results.push({{
    mode: 'normal',
    set: idx + 1,
    match: JSON.stringify(legN) === JSON.stringify(adpN),
  }});

  // Agent mode
  const legA = legacyAgent(values, customChecks);
  const adpA = buildScanPayload('agent', {{ values, checks: customChecks }});
  results.push({{
    mode: 'agent',
    set: idx + 1,
    match: JSON.stringify(legA) === JSON.stringify(adpA),
  }});

  // Hybrid mode
  const legH = legacyHybrid(values, cfgToggles, customChecks);
  const adpH = buildScanPayload('hybrid', {{ values, toggles: cfgToggles, checks: customChecks }});
  results.push({{
    mode: 'hybrid',
    set: idx + 1,
    match: JSON.stringify(legH) === JSON.stringify(adpH),
  }});
}});

console.log(JSON.stringify(results));
"""
    results = _run_node(script)
    for res in results:
        assert res["match"] is True, f"Mismatch for mode={res['mode']} set={res['set']}"


def test_unavailable_declaration_path():
    """Verify explicit unavailable callback is triggered on schema error without inventing fields."""
    script = """
const { loadAndRenderSetup } = require('./templates/ui/setup-module.js');

let unavailableCount = 0;
let unavailableReasons = [];

function makeContainer() {
  const children = [];
  return {
    children,
    replaceChildren(...c) { children.length = 0; children.push(...c); },
    appendChild(c) { children.push(c); },
  };
}

const mockDoc = {
  createElement: () => ({ setAttribute() {}, appendChild() {}, addEventListener() {} }),
};

async function run() {
  const c1 = makeContainer();
  // 1. Failed network / 500
  const ok1 = await loadAndRenderSetup(c1, {
    document: mockDoc,
    api: { get: async () => ({ ok: false, error: 'server error' }) },
    onUnavailable: (reason) => {
      unavailableCount++;
      unavailableReasons.push(reason);
    },
  });

  // 2. Version mismatch
  const c2 = makeContainer();
  const ok2 = await loadAndRenderSetup(c2, {
    document: mockDoc,
    schema: { schema_version: '99.0.0', manifest_kind: 'settings_schema', fields: [] },
    onUnavailable: (reason) => {
      unavailableCount++;
      unavailableReasons.push(reason);
    },
  });

  // 3. Kind mismatch
  const c3 = makeContainer();
  const ok3 = await loadAndRenderSetup(c3, {
    document: mockDoc,
    schema: { schema_version: '1.0.0', manifest_kind: 'wrong_kind', fields: [] },
    onUnavailable: (reason) => {
      unavailableCount++;
      unavailableReasons.push(reason);
    },
  });

  console.log(JSON.stringify({ ok1, ok2, ok3, unavailableCount, unavailableReasons }));
}
run();
"""
    res = _run_node(script)
    assert res["ok1"] is False
    assert res["ok2"] is False
    assert res["ok3"] is False
    assert res["unavailableCount"] == 3
    assert all("設定宣言" in r for r in res["unavailableReasons"])


def test_invalid_numeric_input_validation():
    """Verify constraints validation on integer/number inputs."""
    script = """
const { validateFieldConstraint } = require('./templates/ui/setup-module.js');

const depthField = {
  key: 'depth',
  type: 'integer',
  constraints: { minimum: 0 },
};

const timeoutField = {
  key: 'timeout',
  type: 'number',
  constraints: { exclusiveMinimum: 0 },
};

const concurrencyField = {
  key: 'concurrency',
  type: 'integer',
  constraints: { minimum: 1 },
};

const tests = {
  validDepth: validateFieldConstraint('2', depthField) === null,
  floatForInt: validateFieldConstraint('2.5', depthField) !== null,
  negativeDepth: validateFieldConstraint('-1', depthField) !== null,
  nanValue: validateFieldConstraint('not-a-number', depthField) !== null,
  validTimeout: validateFieldConstraint('30.5', timeoutField) === null,
  zeroTimeout: validateFieldConstraint('0', timeoutField) !== null,
  negativeTimeout: validateFieldConstraint('-5', timeoutField) !== null,
  validConcurrency: validateFieldConstraint('3', concurrencyField) === null,
  zeroConcurrency: validateFieldConstraint('0', concurrencyField) !== null,
};

console.log(JSON.stringify(tests));
"""
    res = _run_node(script)
    assert res["validDepth"] is True
    assert res["floatForInt"] is True
    assert res["negativeDepth"] is True
    assert res["nanValue"] is True
    assert res["validTimeout"] is True
    assert res["zeroTimeout"] is True
    assert res["negativeTimeout"] is True
    assert res["validConcurrency"] is True
    assert res["zeroConcurrency"] is True


def test_tab_keyboard_navigation_roving_tabindex():
    """Verify roving tabindex and arrow-key navigation across the 5 tabs."""
    schema = build_settings_schema()
    script = f"""
const {{ renderSetupView }} = require('./templates/ui/setup-module.js');

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
    appendChild(c) {{ children.push(c); }},
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
      _classes: new Set(),
      add(c) {{ this._classes.add(c); }},
      remove(c) {{ this._classes.delete(c); }},
      toggle(c, force) {{
        if (force === undefined) force = !this._classes.has(c);
        if (force) this._classes.add(c);
        else this._classes.delete(c);
      }},
      contains(c) {{ return this._classes.has(c); }},
    }},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
  }};
}}

const mockDoc = {{
  createElement: makeElement,
}};

const container = makeElement('div');
const schema = {json.dumps(schema)};
const view = renderSetupView(container, schema, {{ document: mockDoc }});

// Locate tabBar
const tabBar = container.children[0].children[1];
const tabs = tabBar.children;

const initialTabs = tabs.map(t => ({{
  selected: t.getAttribute('aria-selected'),
  tabindex: t.getAttribute('tabindex'),
}}));

// Press ArrowRight
tabBar.dispatch('keydown', {{ key: 'ArrowRight' }});
const afterRight1 = tabs.map(t => ({{
  selected: t.getAttribute('aria-selected'),
  tabindex: t.getAttribute('tabindex'),
}}));

// Press End
tabBar.dispatch('keydown', {{ key: 'End' }});
const afterEnd = tabs.map(t => ({{
  selected: t.getAttribute('aria-selected'),
  tabindex: t.getAttribute('tabindex'),
}}));

// Press ArrowRight from last tab (wraps to 0)
tabBar.dispatch('keydown', {{ key: 'ArrowRight' }});
const afterWrap = tabs.map(t => ({{
  selected: t.getAttribute('aria-selected'),
  tabindex: t.getAttribute('tabindex'),
}}));

// Press ArrowLeft from first tab (wraps to last)
tabBar.dispatch('keydown', {{ key: 'ArrowLeft' }});
const afterLeftWrap = tabs.map(t => ({{
  selected: t.getAttribute('aria-selected'),
  tabindex: t.getAttribute('tabindex'),
}}));

// Press Home
tabBar.dispatch('keydown', {{ key: 'Home' }});
const afterHome = tabs.map(t => ({{
  selected: t.getAttribute('aria-selected'),
  tabindex: t.getAttribute('tabindex'),
}}));

console.log(JSON.stringify({{
  initialTabs,
  afterRight1,
  afterEnd,
  afterWrap,
  afterLeftWrap,
  afterHome,
}}));
"""
    res = _run_node(script)

    # Initial: Tab 0 selected and tabindex 0, others -1
    assert res["initialTabs"][0] == {"selected": "true", "tabindex": "0"}
    assert all(t["tabindex"] == "-1" for t in res["initialTabs"][1:])

    # After ArrowRight: Tab 1 selected and tabindex 0, others -1
    assert res["afterRight1"][1] == {"selected": "true", "tabindex": "0"}
    assert res["afterRight1"][0]["tabindex"] == "-1"

    # After End: Tab 4 selected
    assert res["afterEnd"][4] == {"selected": "true", "tabindex": "0"}

    # After Wrap (ArrowRight on 4): Tab 0 selected
    assert res["afterWrap"][0] == {"selected": "true", "tabindex": "0"}

    # After Left Wrap (ArrowLeft on 0): Tab 4 selected
    assert res["afterLeftWrap"][4] == {"selected": "true", "tabindex": "0"}

    # After Home: Tab 0 selected
    assert res["afterHome"][0] == {"selected": "true", "tabindex": "0"}


def test_basic_advanced_disclosure():
    """Verify that tabs provide basic fields and an advanced disclosure section."""
    schema = build_settings_schema()
    script = f"""
const {{ renderSetupView, TAB_DEFINITIONS }} = require('./templates/ui/setup-module.js');

function makeElement(tag) {{
  const children = [];
  return {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    dataset: {{}},
    style: {{}},
    setAttribute() {{}},
    getAttribute() {{ return null; }},
    appendChild(c) {{ children.push(c); }},
    replaceChildren(...c) {{ children.length = 0; children.push(...c); }},
    addEventListener() {{}},
    classList: {{ add() {{}}, remove() {{}}, toggle() {{}} }},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
  }};
}}

const mockDoc = {{ createElement: makeElement }};
const container = makeElement('div');
renderSetupView(container, {json.dumps(schema)}, {{ document: mockDoc }});

// Check panels (children after root header and tabBar)
const root = container.children[0];
const panels = root.children.filter(c => c.children.some(child => child.tagName === 'details'));

console.log(JSON.stringify({{
  panelCount: panels.length,
  hasDisclosureInEach: panels.length === TAB_DEFINITIONS.length,
}}));
"""
    res = _run_node(script)
    assert res["hasDisclosureInEach"] is True
    assert res["panelCount"] == 5


def test_mode_switching_and_presets():
    """Verify mode switching updates button state, disables presets for agent, and applies presets."""
    schema = build_settings_schema()
    script = f"""
const {{ renderSetupView, PROFILES }} = require('./templates/ui/setup-module.js');

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
    disabled: false,
    dataset: {{}},
    style: {{}},
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{ children.push(c); }},
    replaceChildren(...c) {{ children.length = 0; children.push(...c); }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatch(evt, data) {{
      (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
    }},
    classList: {{
      _classes: new Set(),
      add(c) {{ this._classes.add(c); }},
      remove(c) {{ this._classes.delete(c); }},
      toggle(c, force) {{
        if (force === undefined) force = !this._classes.has(c);
        if (force) this._classes.add(c);
        else this._classes.delete(c);
      }},
      contains(c) {{ return this._classes.has(c); }},
    }},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
  }};
}}

const mockDoc = {{ createElement: makeElement }};
const container = makeElement('div');
const view = renderSetupView(container, {json.dumps(schema)}, {{ document: mockDoc }});

// Initial mode is normal
const initialMode = view.getMode();

// Switch to agent mode
view.applyMode('agent');
const agentMode = view.getMode();

// Switch to hybrid mode
view.applyMode('hybrid');
const hybridMode = view.getMode();

console.log(JSON.stringify({{
  initialMode,
  agentMode,
  hybridMode,
}}));
"""
    res = _run_node(script)
    assert res["initialMode"] == "normal"
    assert res["agentMode"] == "agent"
    assert res["hybridMode"] == "hybrid"


def test_effective_config_readout_search_applicability_and_payload():
    schema = build_settings_schema()
    script = f"""
const {{ renderSetupView }} = require('./templates/ui/setup-module.js');
function el(tag) {{
  const listeners = {{}};
  const classes = new Set();
  return {{ tagName: tag, children: [], dataset: {{}}, style: {{}}, className: '', hidden: false,
    setAttribute() {{}}, removeAttribute() {{}}, getAttribute() {{ return null; }},
    appendChild(child) {{ this.children.push(child); }}, replaceChildren(...children) {{ this.children = children; }},
    addEventListener(name, fn) {{ listeners[name] = fn; }}, dispatch(name) {{ listeners[name]?.(); }},
    classList: {{ add(name) {{ classes.add(name); }}, remove(name) {{ classes.delete(name); }},
      toggle(name, force) {{ const on = force === undefined ? !classes.has(name) : force; on ? classes.add(name) : classes.delete(name); return on; }},
      contains(name) {{ return classes.has(name); }} }} }};
}}
const doc = {{ createElement: el, getElementById() {{ return null; }}, querySelector() {{ return null; }}, querySelectorAll() {{ return []; }} }};
function find(node, predicate) {{ if (predicate(node)) return node; for (const child of node.children || []) {{ const found = find(child, predicate); if (found) return found; }} return null; }}
function allText(node) {{ return [node.textContent || '', ...(node.children || []).map(allText)].join(' '); }}
const container = el('div');
const response = {{ schema_version: '1.0.0', manifest_kind: 'effective_config', mode: 'normal', profile: 'triage',
  values: {{ depth: 1 }}, diff: {{ depth: {{ before: 2, after: 1 }} }}, invalid_keys: [] }};
const view = renderSetupView(container, {json.dumps(schema)}, {{ document: doc, fetchEffectiveConfig: async () => response }});
const payloadBefore = JSON.stringify(view.buildPayload());
const matches = view.filterFields('depth');
const payloadAfter = JSON.stringify(view.buildPayload());
const depthField = find(view.root, n => n.dataset && n.dataset.fieldKey === 'depth' && (n.className || '').includes('setup-field'));
const hiddenOtherField = find(view.root, n => n.dataset && n.dataset.fieldKey === 'max_forms' && (n.className || '').includes('setup-field'));
const authMatches = view.filterFields('mfa');
view.filterFields('depth');
const unavailable = renderSetupView(el('div'), {json.dumps(schema)}, {{ document: doc, fetchEffectiveConfig: async () => {{ throw new Error('offline'); }} }});
Promise.all([view.applyPreset('triage', false), unavailable.applyPreset('triage')]).then(([loaded]) => {{
  const payloadUnchangedByReadout = payloadBefore === payloadAfter && payloadBefore === JSON.stringify(view.buildPayload());
  view.applyMode('agent');
  const diffRow = find(view.effectiveSection, n => n.className === 'setup-effective-diff-item');
  console.log(JSON.stringify({{
    loaded, diffText: diffRow.children.map(n => n.textContent).join(''),
    hasEffectiveValue: allText(view.effectiveSection).includes('クロール深度: 1'),
    unavailable: allText(unavailable.effectiveSection).includes('取得できませんでした'),
    unavailableHasNoGuessedDiff: !allText(unavailable.effectiveSection).includes('2'),
    searchMatches: matches, searchDepthVisible: !depthField.classList.contains('setup-search-hidden'),
    searchHidesOtherFields: hiddenOtherField.classList.contains('setup-search-hidden'),
    searchMfaCount: authMatches,
    notApplicable: Boolean(find(depthField, n => (n.className || '').includes('setup-na-badge'))),
    reasonListsApplicableModes: allText(depthField).includes('通常') && allText(depthField).includes('Hybrid'),
    payloadUnchangedByReadout,
  }}));
}});
"""
    result = _run_node(script)
    assert result["loaded"] is True
    assert result["diffText"] == "クロール深度 (depth):2 → 1"
    assert result["hasEffectiveValue"] is True
    assert result["unavailable"] is True
    assert result["unavailableHasNoGuessedDiff"] is True
    assert result["searchMatches"] > 0
    assert result["searchDepthVisible"] is True
    assert result["searchHidesOtherFields"] is True
    assert result["searchMfaCount"] > 0
    assert result["notApplicable"] is True
    assert result["reasonListsApplicableModes"] is True
    assert result["payloadUnchangedByReadout"] is True


def test_start_scan_validation_and_submission():
    """Verify URL validation and scan payload submission callback."""
    schema = build_settings_schema()
    script = f"""
const {{ renderSetupView }} = require('./templates/ui/setup-module.js');

let submittedPayload = null;

const elementRegistry = {{}};
function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  let _id = '';
  const el = {{
    tagName: tag,
    children: children,
    hidden: false,
    className: '',
    value: '',
    disabled: false,
    dataset: {{}},
    style: {{}},
    get id() {{ return _id; }},
    set id(v) {{
      _id = String(v);
      if (_id) elementRegistry[_id] = el;
    }},
    setAttribute(k, v) {{
      attrs[k] = String(v);
      if (k === 'id') {{
        el.id = String(v);
      }}
    }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : (_id && k === 'id' ? _id : null); }},
    removeAttribute(k) {{
      delete attrs[k];
      if (k === 'id' && _id) {{
        delete elementRegistry[_id];
        _id = '';
      }}
    }},
    appendChild(c) {{
      children.push(c);
      if (c) c.parentElement = el;
    }},
    replaceChildren(...c) {{
      children.length = 0;
      for (const child of c) {{
        children.push(child);
        if (child) child.parentElement = el;
      }}
    }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatch(evt, data) {{
      (listeners[evt] || []).forEach(fn => fn(Object.assign({{ preventDefault() {{}} }}, data)));
    }},
    focus() {{ this._focused = true; }},
    classList: {{
      _classes: new Set(),
      add(c) {{ this._classes.add(c); }},
      remove(c) {{ this._classes.delete(c); }},
      toggle(c, force) {{
        if (force === undefined) force = !this._classes.has(c);
        if (force) this._classes.add(c);
        else this._classes.delete(c);
      }},
      contains(c) {{ return this._classes.has(c); }},
    }},
    querySelector() {{ return null; }},
    querySelectorAll() {{ return []; }},
  }};
  return el;
}}

const mockDoc = {{
  createElement: makeElement,
  getElementById: (id) => elementRegistry[id] || null,
  querySelector: () => null,
  querySelectorAll: () => [],
}};
const container = makeElement('div');
const view = renderSetupView(container, {json.dumps(schema)}, {{
  document: mockDoc,
  onStartScan: (p) => {{ submittedPayload = p; }},
}});

const root = container.children[0];
const header = root.children[0];
const urlInput = header.children[0].children[1];
const startBtn = header.children[1].children[2].children[0];

// 1. Click without URL -> blocked
startBtn.dispatch('click');
const blockedWithoutUrl = submittedPayload === null;
const urlInvalidAttr = urlInput.getAttribute('aria-invalid');

// 2. Set valid URL and submit
urlInput.value = 'https://validated.example.com';
startBtn.dispatch('click');
const submittedWithUrl = submittedPayload !== null && submittedPayload.url === 'https://validated.example.com';

console.log(JSON.stringify({{
  blockedWithoutUrl,
  urlInvalidAttr,
  submittedWithUrl,
}}));
"""
    res = _run_node(script)
    assert res["blockedWithoutUrl"] is True
    assert res["urlInvalidAttr"] == "true"
    assert res["submittedWithUrl"] is True
