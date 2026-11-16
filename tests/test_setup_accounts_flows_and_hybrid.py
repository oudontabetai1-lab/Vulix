"""Unit tests for Scan Setup Accounts/Flows Interactive Editors, Hybrid Parity, and Account Auth Outcomes."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest
from unittest.mock import AsyncMock, MagicMock

import pytest

from wscan.engine import ScanEngine
from wscan.scanners.privesc import PrivEscScanner
from wscan.settings_schema import build_settings_schema

ROOT = Path(__file__).resolve().parents[1]


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


def test_accounts_interactive_editor_dom_and_payload():
    """Verify adding, editing, removing accounts via DOM and payload serialization."""
    schema = build_settings_schema()
    script = f"""
const {{ renderSettingsSchemaForm, getAccounts, buildScanPayload }} = require('./templates/ui/setup-module.js');

function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  return {{
    tagName: tag.toUpperCase(),
    children: children,
    hidden: false,
    className: '',
    value: '',
    type: 'text',
    autocomplete: '',
    placeholder: '',
    dataset: {{}},
    style: {{}},
    parentNode: null,
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{
      c.parentNode = this;
      children.push(c);
      return c;
    }},
    insertBefore(c, ref) {{
      c.parentNode = this;
      const idx = children.indexOf(ref);
      if (idx === -1) children.push(c);
      else children.splice(idx, 0, c);
      return c;
    }},
    removeChild(c) {{
      const idx = children.indexOf(c);
      if (idx !== -1) {{
        c.parentNode = null;
        children.splice(idx, 1);
      }}
      return c;
    }},
    remove() {{
      if (this.parentNode && typeof this.parentNode.removeChild === 'function') {{
        this.parentNode.removeChild(this);
      }}
    }},
    replaceChildren(...c) {{
      children.length = 0;
      for (const item of c) {{
        item.parentNode = this;
        children.push(item);
      }}
    }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatchEvent(evt) {{
      const fns = listeners[evt.type] || [];
      fns.forEach(fn => fn(evt));
      return true;
    }},
    querySelector(sel) {{
      return this.querySelectorAll(sel)[0] || null;
    }},
    querySelectorAll(sel) {{
      const res = [];
      function walk(n) {{
        for (const ch of n.children || []) {{
          let match = false;
          if (sel.startsWith('#') && (ch.getAttribute('id') === sel.slice(1) || ch.id === sel.slice(1))) match = true;
          else if (sel.startsWith('.') && (ch.className || '').split(' ').includes(sel.slice(1))) match = true;
          else if (sel.toLowerCase() === (ch.tagName || '').toLowerCase()) match = true;
          if (match) res.push(ch);
          walk(ch);
        }}
      }}
      walk(this);
      return res;
    }},
  }};
}}

const container = makeElement('div');
const mockDoc = {{
  createElement: makeElement,
  querySelector: (sel) => container.querySelector(sel),
  querySelectorAll: (sel) => container.querySelectorAll(sel),
  getElementById: (id) => container.querySelector('#' + id),
}};

const schema = {json.dumps(schema)};
const accountsField = schema.fields.find(f => f.key === 'accounts');

let changeNotified = false;
const options = {{
  document: mockDoc,
  currentMode: 'normal',
  onConfigChange: () => {{ changeNotified = true; }},
}};

renderSettingsSchemaForm(container, [accountsField], options);

const accountsList = container.querySelector('#accountsList');
const addBtn = container.querySelector('#addAccountRowBtn');

// Step 1: Add first account
addBtn.dispatchEvent({{ type: 'click' }});
const row1 = accountsList.children[0];
const user1 = row1.querySelector('.acc-user');
const pass1 = row1.querySelector('.acc-pass');
const role1 = row1.querySelector('.acc-role');
user1.value = 'admin_user';
pass1.value = 'AdminPass123!';
role1.value = 'admin';

// Step 2: Add second account
addBtn.dispatchEvent({{ type: 'click' }});
const row2 = accountsList.children[1];
const user2 = row2.querySelector('.acc-user');
const pass2 = row2.querySelector('.acc-pass');
const role2 = row2.querySelector('.acc-role');
user2.value = 'standard_user';
pass2.value = 'UserPass456!';
role2.value = 'user';

const serializedTwo = getAccounts({{ document: mockDoc }});

// Step 3: Remove first account
const removeBtn1 = row1.querySelector('.acc-remove-btn');
removeBtn1.dispatchEvent({{ type: 'click' }});
const serializedAfterRemove = getAccounts({{ document: mockDoc }});

// Step 4: Verify buildScanPayload behavior for modes
const fakeValues = {{ cfgInputUrl: 'https://example.test' }};
const normalPayload = buildScanPayload('normal', {{
  values: fakeValues,
  document: mockDoc,
  env: {{ accounts: serializedAfterRemove }},
}});
const hybridPayload = buildScanPayload('hybrid', {{
  values: fakeValues,
  document: mockDoc,
  env: {{ accounts: serializedAfterRemove }},
}});
const agentPayload = buildScanPayload('agent', {{
  values: fakeValues,
  document: mockDoc,
  env: {{ accounts: serializedAfterRemove }},
}});

console.log(JSON.stringify({{
  accountsListExists: Boolean(accountsList),
  addBtnExists: Boolean(addBtn),
  initialRowsAfterAdd: accountsList.children.length,
  serializedTwo,
  serializedAfterRemove,
  normalHasAccounts: Array.isArray(normalPayload.accounts),
  normalAccountsLen: (normalPayload.accounts || []).length,
  hybridHasAccounts: Array.isArray(hybridPayload.accounts),
  hybridAccountsLen: (hybridPayload.accounts || []).length,
  agentHasAccounts: 'accounts' in agentPayload,
}}));
"""
    res = _run_node(script)
    assert res["accountsListExists"] is True
    assert res["addBtnExists"] is True
    assert len(res["serializedTwo"]) == 2
    assert res["serializedTwo"][0] == {"username": "admin_user", "password": "AdminPass123!", "role": "admin"}
    assert res["serializedTwo"][1] == {"username": "standard_user", "password": "UserPass456!", "role": "user"}
    assert len(res["serializedAfterRemove"]) == 1
    assert res["serializedAfterRemove"][0] == {"username": "standard_user", "password": "UserPass456!", "role": "user"}
    assert res["normalHasAccounts"] is True
    assert res["normalAccountsLen"] == 1
    assert res["hybridHasAccounts"] is True
    assert res["hybridAccountsLen"] == 1
    # Agent mode MUST NOT include accounts
    assert res["agentHasAccounts"] is False


def test_flows_interactive_builder_dom_and_serialization():
    """Verify adding, configuring, removing flows and steps via DOM and serialization."""
    schema = build_settings_schema()
    script = f"""
const {{ renderSettingsSchemaForm, getFlows, buildScanPayload }} = require('./templates/ui/setup-module.js');

function makeElement(tag) {{
  const children = [];
  const attrs = {{}};
  const listeners = {{}};
  return {{
    tagName: tag.toUpperCase(),
    children: children,
    hidden: false,
    className: '',
    value: '',
    type: 'text',
    placeholder: '',
    dataset: {{}},
    style: {{}},
    parentNode: null,
    setAttribute(k, v) {{ attrs[k] = String(v); }},
    getAttribute(k) {{ return attrs[k] !== undefined ? attrs[k] : null; }},
    removeAttribute(k) {{ delete attrs[k]; }},
    appendChild(c) {{
      c.parentNode = this;
      children.push(c);
      return c;
    }},
    insertBefore(c, ref) {{
      c.parentNode = this;
      const idx = children.indexOf(ref);
      if (idx === -1) children.push(c);
      else children.splice(idx, 0, c);
      return c;
    }},
    removeChild(c) {{
      const idx = children.indexOf(c);
      if (idx !== -1) {{
        c.parentNode = null;
        children.splice(idx, 1);
      }}
      return c;
    }},
    remove() {{
      if (this.parentNode && typeof this.parentNode.removeChild === 'function') {{
        this.parentNode.removeChild(this);
      }}
    }},
    replaceChildren(...c) {{
      children.length = 0;
      for (const item of c) {{
        item.parentNode = this;
        children.push(item);
      }}
    }},
    addEventListener(evt, fn) {{
      listeners[evt] = listeners[evt] || [];
      listeners[evt].push(fn);
    }},
    dispatchEvent(evt) {{
      const fns = listeners[evt.type] || [];
      fns.forEach(fn => fn(evt));
      return true;
    }},
    querySelector(sel) {{
      return this.querySelectorAll(sel)[0] || null;
    }},
    querySelectorAll(sel) {{
      const res = [];
      function walk(n) {{
        for (const ch of n.children || []) {{
          let match = false;
          if (sel.startsWith('#') && (ch.getAttribute('id') === sel.slice(1) || ch.id === sel.slice(1))) match = true;
          else if (sel.startsWith('.') && (ch.className || '').split(' ').includes(sel.slice(1))) match = true;
          else if (sel.toLowerCase() === (ch.tagName || '').toLowerCase()) match = true;
          if (match) res.push(ch);
          walk(ch);
        }}
      }}
      walk(this);
      return res;
    }},
  }};
}}

const container = makeElement('div');
const mockDoc = {{
  createElement: makeElement,
  querySelector: (sel) => container.querySelector(sel),
  querySelectorAll: (sel) => container.querySelectorAll(sel),
  getElementById: (id) => container.querySelector('#' + id),
}};

const schema = {json.dumps(schema)};
const flowsField = schema.fields.find(f => f.key === 'flows');

const options = {{
  document: mockDoc,
  currentMode: 'normal',
}};

renderSettingsSchemaForm(container, [flowsField], options);

const flowsList = container.querySelector('#cfgFlowsList');
const addFlowBtn = container.querySelector('#addFlowBtn');

// Add first flow
addFlowBtn.dispatchEvent({{ type: 'click' }});
const flowItem = flowsList.children[0];
const flowNameInput = flowItem.querySelector('.flow-name');
flowNameInput.value = 'Checkout Purchase';

const addStepBtn = flowItem.querySelector('.add-flow-step-btn');
const stepsList = flowItem.querySelector('.flow-steps-list');

// Step 1: navigate
addStepBtn.dispatchEvent({{ type: 'click' }});
const step1 = stepsList.children[0];
step1.querySelector('.flow-step-action').value = 'navigate';
step1.querySelector('.flow-step-target').value = 'https://store.test/cart';

// Step 2: click
addStepBtn.dispatchEvent({{ type: 'click' }});
const step2 = stepsList.children[1];
step2.querySelector('.flow-step-action').value = 'click';
step2.querySelector('.flow-step-target').value = '#checkout-btn';

// Step 3: fill
addStepBtn.dispatchEvent({{ type: 'click' }});
const step3 = stepsList.children[2];
step3.querySelector('.flow-step-action').value = 'fill';
step3.querySelector('.flow-step-target').value = '#promo-code';
step3.querySelector('.flow-step-value').value = 'DISCOUNT50';

// Step 4: wait
addStepBtn.dispatchEvent({{ type: 'click' }});
const step4 = stepsList.children[3];
step4.querySelector('.flow-step-action').value = 'wait';
step4.querySelector('.flow-step-value').value = '2000';

const serializedFourSteps = getFlows({{ document: mockDoc }});

// Remove wait step
step4.querySelector('.remove-flow-step-btn').dispatchEvent({{ type: 'click' }});
const serializedThreeSteps = getFlows({{ document: mockDoc }});

// Verify payload integration
const normalPayload = buildScanPayload('normal', {{
  values: {{ cfgInputUrl: 'https://example.test' }},
  document: mockDoc,
  flows: serializedThreeSteps,
}});
const hybridPayload = buildScanPayload('hybrid', {{
  values: {{ cfgInputUrl: 'https://example.test' }},
  document: mockDoc,
  flows: serializedThreeSteps,
}});

console.log(JSON.stringify({{
  flowsListExists: Boolean(flowsList),
  addFlowBtnExists: Boolean(addFlowBtn),
  serializedFourSteps,
  serializedThreeSteps,
  normalFlowsCount: normalPayload.flows.length,
  hybridFlowsCount: hybridPayload.flows.length,
}}));
"""
    res = _run_node(script)
    assert res["flowsListExists"] is True
    assert res["addFlowBtnExists"] is True
    four = res["serializedFourSteps"]
    assert len(four) == 1
    assert four[0]["name"] == "Checkout Purchase"
    assert len(four[0]["steps"]) == 4
    assert four[0]["steps"][0]["action"] == "navigate"
    assert four[0]["steps"][0]["url"] == "https://store.test/cart"
    assert four[0]["steps"][1]["action"] == "click"
    assert four[0]["steps"][1]["selector"] == "#checkout-btn"
    assert four[0]["steps"][2]["action"] == "fill"
    assert four[0]["steps"][2]["selector"] == "#promo-code"
    assert four[0]["steps"][2]["value"] == "DISCOUNT50"
    assert four[0]["steps"][3]["action"] == "wait"
    assert four[0]["steps"][3]["ms"] == 2000

    three = res["serializedThreeSteps"]
    assert len(three[0]["steps"]) == 3
    assert res["normalFlowsCount"] == 1
    assert res["hybridFlowsCount"] == 1


def test_hybrid_payload_parity_and_explicit_zero_handling():
    """Verify hybrid payload parity fields and that explicit '0' numeric input is preserved."""
    script = """
const { buildScanPayload } = require('./templates/ui/setup-module.js');

const toggles = {
  allow_state_changing_probes: true,
  spa_crawl: true,
  auto_spa_crawl: true,
  enable_sitemap_crawl: true,
  tls_verify: false,
  auto_register: true,
  header_scope_enforce: true,
  popup_header_intercept: true,
};

const valuesZero = {
  cfgInputUrl: 'https://target.test',
  cfgDepth: '0',
  cfgMaxForms: '0',
  cfgAutoRegisterCount: '0',
  cfgStateProfile: 'controlled-write',
  cfgProxy: 'http://proxy.test:8080',
  cfgTlsClientCert: '/path/to/cert.pem',
  cfgTlsClientKey: '/path/to/key.pem',
  cfgTlsClientPfx: '/path/to/cert.pfx',
  cfgTlsClientCertPassword: 'pfx-password',
  cfgTlsCaCert: '/path/to/ca.pem',
  cfgExcludeFields: 'csrf_token, token',
  cfgExcludeUrls: 'https://target.test/logout\\nhttps://target.test/exit',
};

const hybridZero = buildScanPayload('hybrid', { values: valuesZero, toggles });
const normalZero = buildScanPayload('normal', { values: valuesZero, toggles });

const valuesDefault = {
  cfgInputUrl: 'https://target.test',
  cfgDepth: '',
  cfgMaxForms: '',
  cfgAutoRegisterCount: '',
};

const hybridDefault = buildScanPayload('hybrid', { values: valuesDefault, toggles: {} });
const normalDefault = buildScanPayload('normal', { values: valuesDefault, toggles: {} });

console.log(JSON.stringify({
  hybridZeroDepth: hybridZero.depth,
  normalZeroDepth: normalZero.depth,
  normalZeroMaxForms: normalZero.max_forms,
  hybridZeroAutoRegisterCount: hybridZero.auto_register_count,
  normalZeroAutoRegisterCount: normalZero.auto_register_count,

  hybridDefaultDepth: hybridDefault.depth,
  normalDefaultDepth: normalDefault.depth,
  normalDefaultMaxForms: normalDefault.max_forms,
  hybridDefaultAutoRegisterCount: hybridDefault.auto_register_count,
  normalDefaultAutoRegisterCount: normalDefault.auto_register_count,

  hybridParity: {
    state_profile: hybridZero.state_profile,
    allow_state_changing_probes: hybridZero.allow_state_changing_probes,
    spa_crawl: hybridZero.spa_crawl,
    auto_spa_crawl: hybridZero.auto_spa_crawl,
    enable_sitemap_crawl: hybridZero.enable_sitemap_crawl,
    proxy: hybridZero.proxy,
    tls_client_cert: hybridZero.tls_client_cert,
    tls_client_key: hybridZero.tls_client_key,
    tls_client_pfx: hybridZero.tls_client_pfx,
    tls_client_cert_password: hybridZero.tls_client_cert_password,
    tls_ca_cert: hybridZero.tls_ca_cert,
    tls_verify: hybridZero.tls_verify,
    exclude_fields: hybridZero.exclude_fields,
    exclude_urls: hybridZero.exclude_urls,
    auto_register: hybridZero.auto_register,
    header_scope_enforce: hybridZero.header_scope_enforce,
    popup_header_intercept: hybridZero.popup_header_intercept,
  },
}));
"""
    res = _run_node(script)
    # Explicit '0' preserved
    assert res["hybridZeroDepth"] == 0
    assert res["normalZeroDepth"] == 0
    assert res["normalZeroMaxForms"] == 0
    assert res["hybridZeroAutoRegisterCount"] == 0
    assert res["normalZeroAutoRegisterCount"] == 0

    # Default fallback when empty string
    assert res["hybridDefaultDepth"] == 2
    assert res["normalDefaultDepth"] == 2
    assert res["normalDefaultMaxForms"] == 50
    assert res["hybridDefaultAutoRegisterCount"] == 2
    assert res["normalDefaultAutoRegisterCount"] == 2

    # Hybrid parity fields check
    parity = res["hybridParity"]
    assert parity["state_profile"] == "controlled-write"
    assert parity["allow_state_changing_probes"] is True
    assert parity["spa_crawl"] is True
    assert parity["auto_spa_crawl"] is True
    assert parity["enable_sitemap_crawl"] is True
    assert parity["proxy"] == "http://proxy.test:8080"
    assert parity["tls_client_cert"] == "/path/to/cert.pem"
    assert parity["tls_client_key"] == "/path/to/key.pem"
    assert parity["tls_client_pfx"] == "/path/to/cert.pfx"
    assert parity["tls_client_cert_password"] == "pfx-password"
    assert parity["tls_ca_cert"] == "/path/to/ca.pem"
    assert parity["tls_verify"] is False
    assert parity["exclude_fields"] == ["csrf_token", "token"]
    assert parity["exclude_urls"] == ["https://target.test/logout", "https://target.test/exit"]
    assert parity["auto_register"] is True
    assert parity["header_scope_enforce"] is True
    assert parity["popup_header_intercept"] is True


class DummyBrowser:
    def __init__(self, sessions_map=None):
        self.sessions_map = sessions_map or {}

    async def create_session_for_account(
        self,
        username: str,
        password: str,
        login_url: str,
        user_field: str = "username",
        pass_field: str = "password",
        success_indicator: str = "",
        logged_in_marker: str = "",
    ):
        return self.sessions_map.get((username, password))


@pytest.mark.asyncio
async def test_engine_setup_account_sessions_status_and_redaction():
    """Verify ScanEngine._setup_account_sessions populates account_auth_outcomes without leaking passwords/cookies."""
    engine = ScanEngine(
        url="https://app.test",
        login_url="https://app.test/login",
        accounts=[
            {"username": "admin", "password": "SuperAdminPassword!", "role": "admin"},
            {"username": "attacker", "password": "WrongPassword!", "role": "user"},
            {"username": "", "password": "NoUsername!", "role": "user"},
        ],
    )
    dummy_browser = DummyBrowser({
        ("admin", "SuperAdminPassword!"): "session_token=admin_cookie_12345; Path=/",
    })
    engine._browser = dummy_browser

    await engine._setup_account_sessions()

    # 1. account_sessions should only contain successfully authenticated accounts
    assert len(engine.account_sessions) == 1
    assert engine.account_sessions[0] == {
        "username": "admin",
        "cookies": "session_token=admin_cookie_12345; Path=/",
        "role": "admin",
    }

    # 2. account_auth_outcomes should record structured outcomes for all accounts
    assert len(engine.account_auth_outcomes) == 3

    admin_outcome = next(o for o in engine.account_auth_outcomes if o["username"] == "admin")
    assert admin_outcome["status"] == "authenticated"
    assert admin_outcome["role"] == "admin"
    assert admin_outcome["reason"] == "login_succeeded"

    attacker_outcome = next(o for o in engine.account_auth_outcomes if o["username"] == "attacker")
    assert attacker_outcome["status"] == "incomplete"
    assert attacker_outcome["role"] == "user"
    assert attacker_outcome["reason"] == "login_failed"

    missing_outcome = next(o for o in engine.account_auth_outcomes if o["username"] == "<unknown>")
    assert missing_outcome["status"] == "incomplete"
    assert missing_outcome["reason"] == "missing_credentials"

    # 3. REDACTION check: neither passwords nor raw cookies must exist in account_auth_outcomes
    serialized_outcomes = json.dumps(engine.account_auth_outcomes)
    assert "SuperAdminPassword!" not in serialized_outcomes
    assert "WrongPassword!" not in serialized_outcomes
    assert "NoUsername!" not in serialized_outcomes
    assert "admin_cookie_12345" not in serialized_outcomes
    assert "cookies" not in serialized_outcomes
    assert "password" not in serialized_outcomes


@pytest.mark.asyncio
async def test_engine_setup_account_sessions_no_login_url():
    """Verify behavior when accounts are provided without a login_url."""
    engine = ScanEngine(
        url="https://app.test",
        login_url="",
        accounts=[
            {"username": "alice", "password": "secretPassword!", "role": "user"},
        ],
    )
    engine._browser = DummyBrowser()

    await engine._setup_account_sessions()

    assert len(engine.account_sessions) == 0
    assert len(engine.account_auth_outcomes) == 1
    outcome = engine.account_auth_outcomes[0]
    assert outcome["username"] == "alice"
    assert outcome["role"] == "user"
    assert outcome["status"] == "incomplete"
    assert outcome["reason"] == "no_login_url"

    serialized = json.dumps(engine.account_auth_outcomes)
    assert "secretPassword!" not in serialized
    assert "cookies" not in serialized


@pytest.mark.asyncio
async def test_privesc_scanner_compatible_with_engine_account_sessions():
    """Verify PrivEscScanner uses authenticated account_sessions seamlessly."""
    class DummyEngine:
        def __init__(self, sessions):
            self.account_sessions = sessions
            self.browser = object()
            self.payload_gen = None
            self.proxy = ""
            self.timeout = 10
            self.cookies = ""
            self.all_findings = []
            self.monitor = None
            self.low_priv_cookies = ""
            self.allow_state_changing_probes = False

    sessions = [
        {"username": "admin@test.local", "cookies": "sid=admin", "role": "admin"},
        {"username": "user@test.local", "cookies": "sid=user", "role": "user"},
    ]
    engine = DummyEngine(sessions)
    scanner = PrivEscScanner(engine)

    scanner._get = AsyncMock(side_effect=[
        (200, "<html><h1>User Settings</h1><p>Owner: admin@test.local</p></html>"),
        (200, "<html><h1>User Settings</h1><p>Owner: admin@test.local</p></html>"),
        (200, "<html><h1>User Settings</h1><p>Owner: user@test.local</p></html>"),
        (403, "forbidden"),
    ])

    findings = await scanner._test_cross_account(
        "http://test.local/user/100",
        engine.account_sessions,
        timeout=3,
    )
    assert len(findings) == 1
    assert findings[0].check_type == "privesc_cross_acct"
    assert "admin@test.local" in findings[0].evidence
