"""Browser-independent tests for /app Settings view module.

Verifies:
- Module registration with ModuleRegistry and NavigationDispatcher route map.
- Notification settings masking preservation (backend masked hints never leak raw secrets,
  UI never sends back masked hint as credentials, inputs start empty).
- Explicit save and test only (no autosave on input, blur, or change).
- Explicit unavailable states when endpoints fail (no fake data manufactured).
- Schema declaration and effective configuration table rendering with redaction badges and diffs.
- Test notification path exercised strictly against mocks without external network calls.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
SETTINGS_MODULE_JS = ROOT / "templates" / "ui" / "settings-module.js"
APP_SHELL_JS = ROOT / "templates" / "ui" / "app-shell.js"
API_CLIENT_JS = ROOT / "templates" / "ui" / "api-client.js"

COMMON_DOM_STUB = """
function makeElement(tag) {
  const children = [];
  return {
    tagName: tag,
    children: children,
    hidden: false,
    value: '',
    placeholder: '',
    textContent: '',
    checked: false,
    disabled: false,
    className: '',
    style: {},
    _attrs: {},
    _listeners: {},
    setAttribute(k, v) { this._attrs[k] = v; },
    getAttribute(k) { return this._attrs[k]; },
    appendChild(child) { children.push(child); },
    replaceChildren(...newChildren) {
      children.length = 0;
      newChildren.forEach(c => children.push(c));
    },
    addEventListener(evt, fn) {
      this._listeners[evt] = this._listeners[evt] || [];
      this._listeners[evt].push(fn);
    },
    trigger(evt) {
      (this._listeners[evt] || []).forEach(fn => fn({ preventDefault: () => {} }));
    }
  };
}

global.document = {
  createElement: makeElement,
  createTextNode: (txt) => ({ text: txt }),
};
"""


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


def test_settings_module_exports_and_route_registration():
    """Verify that settings-module exports interface and registers with app-shell."""
    script = f"""
    const settingsMod = require('{SETTINGS_MODULE_JS}');
    const {{ ModuleRegistry, NavigationDispatcher }} = require('{APP_SHELL_JS}');

    const registry = new ModuleRegistry();
    const dispatcher = new NavigationDispatcher(registry);

    const dummyApi = {{ createScope: () => ({{ get: async () => ({{ ok: true }}), cancelAll: () => {{}} }}) }};
    const modDef = settingsMod.createSettingsModule({{
      api: dummyApi,
      surfaceEl: {{ hidden: true, replaceChildren: () => {{}} }},
    }});

    registry.register(modDef);

    const hasSettings = registry.has('settings');
    const registered = registry.get('settings');
    const resolvedRoute = dispatcher.resolveRoute('#/settings');
    const resolvedHash = dispatcher.resolveRoute('#settings');

    console.log(JSON.stringify({{
      hasSettings: hasSettings,
      route: registered.route,
      resolvedRouteView: resolvedRoute.viewId,
      resolvedRouteFallback: resolvedRoute.isFallback,
      resolvedHashView: resolvedHash.viewId,
      resolvedHashFallback: resolvedHash.isFallback,
      exportedKeys: Object.keys(settingsMod).sort(),
    }}));
    """
    res = _run_node(script)
    assert res["hasSettings"] is True
    assert res["route"] == "#/settings"
    assert res["resolvedRouteView"] == "settings"
    assert res["resolvedRouteFallback"] is False
    assert res["resolvedHashView"] == "settings"
    assert res["resolvedHashFallback"] is False
    assert "createSettingsModule" in res["exportedKeys"]
    assert "renderSettingsView" in res["exportedKeys"]
    assert "buildSettingsDOM" in res["exportedKeys"]


def test_masking_preserved_and_no_credential_leak():
    """Verify that backend masked hints are preserved, never pre-fill the input,
    and are not re-sent on save when unchanged."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const maskedHint = 'https://hooks.slack.com/services/T01/B02/SECRET_MASKED_HINT';
    const calls = [];

    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async (path) => {{
          calls.push({{ method: 'GET', path: path }});
          if (path === '/api/v1/settings') {{
            return {{
              ok: true,
              data: {{
                notifications: {{
                  enabled: true,
                  min_severity: 'high',
                  notify_complete: true,
                  webhook_set: true,
                  webhook_hint: maskedHint,
                }}
              }}
            }};
          }}
          if (path.startsWith('/api/v1/settings/schema')) {{
            return {{ ok: true, data: {{ fields: [] }} }};
          }}
          if (path.startsWith('/api/v1/settings/effective')) {{
            return {{ ok: true, data: {{ values: {{}}, diff: {{}} }} }};
          }}
          return {{ ok: false }};
        }},
        post: async (path, body) => {{
          calls.push({{ method: 'POST', path: path, body: body }});
          return {{ ok: true, data: {{ status: 'ok' }} }};
        }},
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    // Wait for initial load
    setTimeout(() => {{
      const dom = view.dom;
      const initialValue = dom.webhookInput.value;
      const initialPlaceholder = dom.webhookInput.placeholder;
      const hintText = dom.webhookHint.textContent;

      // 1. User clicks save WITHOUT typing a URL -> webhook_url must NOT be sent
      dom.saveSettingsBtn.trigger('click');

      setTimeout(() => {{
        const saveCallWithoutUrl = calls.find(c => c.method === 'POST' && c.path === '/api/v1/settings');
        const sentPayload1 = saveCallWithoutUrl ? saveCallWithoutUrl.body : null;

        // 2. User enters a brand new URL and clicks save -> webhook_url MUST be sent
        dom.webhookInput.value = 'https://hooks.slack.com/services/NEW/SECRET/WEBHOOK';
        dom.saveSettingsBtn.trigger('click');

        setTimeout(() => {{
          const postCalls = calls.filter(c => c.method === 'POST' && c.path === '/api/v1/settings');
          const sentPayload2 = postCalls.length > 1 ? postCalls[1].body : null;
          const valueAfterSave = dom.webhookInput.value;

          console.log(JSON.stringify({{
            initialValue: initialValue,
            initialPlaceholder: initialPlaceholder,
            hintText: hintText,
            sentPayload1: sentPayload1,
            sentPayload2: sentPayload2,
            valueAfterSave: valueAfterSave,
          }}));
        }}, 20);
      }}, 20);
    }}, 20);
    """
    res = _run_node(script)
    assert res["initialValue"] == ""
    assert "設定済み" in res["initialPlaceholder"]
    assert "SECRET_MASKED_HINT" in res["hintText"]
    # Save without modifying URL must NOT send webhook_url
    assert "webhook_url" not in res["sentPayload1"]["notifications"]
    assert res["sentPayload1"]["notifications"]["enabled"] is True
    # Save with user-entered URL must send that exact URL
    assert res["sentPayload2"]["notifications"]["webhook_url"] == "https://hooks.slack.com/services/NEW/SECRET/WEBHOOK"
    # Input is cleared after save to not hold credentials in UI state
    assert res["valueAfterSave"] == ""


def test_explicit_save_and_test_only_no_autosave():
    """Verify that changing form controls never triggers autosave; save/test are explicit clicks."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const postCalls = [];
    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async (path) => {{
          if (path === '/api/v1/settings') {{
            return {{ ok: true, data: {{ notifications: {{ enabled: false, min_severity: 'high' }} }} }};
          }}
          return {{ ok: true, data: {{ fields: [] }} }};
        }},
        post: async (path, body) => {{
          postCalls.push({{ path: path, body: body }});
          return {{ ok: true, data: {{ status: 'sent' }} }};
        }},
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    setTimeout(() => {{
      const dom = view.dom;

      // Simulate user interactions without clicking Save/Test
      dom.notifyEnabled.checked = true;
      dom.notifyEnabled.trigger('change');
      dom.notifyComplete.checked = true;
      dom.notifyComplete.trigger('change');
      dom.notifyMinSeverity.value = 'critical';
      dom.notifyMinSeverity.trigger('change');
      dom.webhookInput.value = 'https://example.com/test';
      dom.webhookInput.trigger('input');
      dom.webhookInput.trigger('blur');

      const callsBeforeExplicitAction = postCalls.length;

      // Explicit test notification click
      dom.testNotificationBtn.trigger('click');

      // Explicit save click
      dom.saveSettingsBtn.trigger('click');

      setTimeout(() => {{
        console.log(JSON.stringify({{
          callsBeforeExplicitAction: callsBeforeExplicitAction,
          totalPostCalls: postCalls.length,
          testCall: postCalls[0] || null,
          saveCall: postCalls[1] || null,
        }}));
      }}, 20);
    }}, 20);
    """
    res = _run_node(script)
    assert res["callsBeforeExplicitAction"] == 0
    assert res["totalPostCalls"] == 2
    assert res["testCall"]["path"] == "/api/v1/settings/test"
    assert res["saveCall"]["path"] == "/api/v1/settings"


def test_unavailable_state_when_endpoints_fail():
    """Verify explicit unavailable states when endpoints return errors, never manufacturing fake values."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async (path) => {{
          // Simulate HTTP 500 / network failure on all endpoints
          return {{
            ok: false,
            kind: 'http_error',
            status: 500,
            statusText: 'Internal Server Error',
            errorMessage: 'HTTP 500: Server unavailable',
            data: null,
          }};
        }},
        post: async () => ({{ ok: false }}),
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    setTimeout(() => {{
      const dom = view.dom;
      console.log(JSON.stringify({{
        notifyLoadingHidden: dom.notifyLoading.hidden,
        notifyErrorHidden: dom.notifyError.hidden,
        notifyErrorText: dom.notifyError.textContent,
        notifyFormHidden: dom.notifyForm.hidden,
        configLoadingHidden: dom.configLoading.hidden,
        configUnavailableHidden: dom.configUnavailable.hidden,
        configUnavailableText: dom.configUnavailable.textContent,
        configTableWrapHidden: dom.configTableWrap.hidden,
      }}));
    }}, 20);
    """
    res = _run_node(script)
    assert res["notifyLoadingHidden"] is True
    assert res["notifyErrorHidden"] is False
    assert "利用不可" in res["notifyErrorText"]
    assert res["notifyFormHidden"] is True
    assert res["configLoadingHidden"] is True
    assert res["configUnavailableHidden"] is False
    assert "利用不可" in res["configUnavailableText"]
    assert res["configTableWrapHidden"] is True


def test_reference_table_rendering_modes_redaction_and_diff():
    """Verify settings schema & effective config table rendering with mode filter, redaction, and diff."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const schema = {{
      fields: [
        {{ key: 'depth', label: '深度', type: 'integer', applicable_modes: ['normal', 'hybrid'], redacted: false }},
        {{ key: 'secret_key', label: '秘密キー', type: 'string', applicable_modes: ['normal', 'agent'], redacted: true }},
        {{ key: 'agent_only', label: 'Agent専用', type: 'string', applicable_modes: ['agent'], redacted: false }},
      ]
    }};

    const effective = {{
      values: {{
        depth: 1,
        secret_key: null,
      }},
      diff: {{
        depth: {{ before: 2, after: 1 }},
      }},
      redacted_keys: ['secret_key'],
    }};

    const tbody = document.createElement('tbody');
    // Normal mode render
    settingsMod.renderConfigRows(tbody, schema, effective, 'normal', '');

    const rows = tbody.children;
    const row0 = rows[0]; // depth
    const row1 = rows[1]; // secret_key

    console.log(JSON.stringify({{
      rowCount: rows.length,
      row0Key: row0.children[0].children[0].textContent,
      row0Label: row0.children[1].textContent,
      row0Type: row0.children[2].children[0].textContent,
      row0Val: row0.children[4].children[0].textContent,
      row0Diff: row0.children[5].children[0].textContent,
      row1Key: row1.children[0].children[0].textContent,
      row1Val: row1.children[4].children[0].textContent,
    }}));
    """
    res = _run_node(script)
    assert res["rowCount"] == 2  # 'agent_only' excluded in normal mode
    assert res["row0Key"] == "depth"
    assert res["row0Label"] == "深度"
    assert res["row0Type"] == "integer"
    assert res["row0Val"] == "1"
    assert "2 → 1" in res["row0Diff"]
    assert res["row1Key"] == "secret_key"
    assert res["row1Val"] == "[非公開]"


def test_test_notification_path_exercised_against_mock_only():
    """Verify that test notification only exercises mocked backend without real network calls."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const mockDispatches = [];
    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async () => ({{ ok: true, data: {{ notifications: {{ enabled: true }} }} }}),
        post: async (path) => {{
          if (path === '/api/v1/settings/test') {{
            mockDispatches.push({{ path: path, timestamp: Date.now() }});
            // Returns mocked success without touching external webhooks
            return {{ ok: true, data: {{ status: 'sent' }} }};
          }}
          return {{ ok: false }};
        }},
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    setTimeout(() => {{
      view.dom.testNotificationBtn.trigger('click');
      setTimeout(() => {{
        console.log(JSON.stringify({{
          dispatchCount: mockDispatches.length,
          lastPath: mockDispatches[0]?.path,
          statusText: view.dom.notifyStatus.textContent,
        }}));
      }}, 20);
    }}, 20);
    """
    res = _run_node(script)
    assert res["dispatchCount"] == 1
    assert res["lastPath"] == "/api/v1/settings/test"
    assert "テスト通知を送信しました" in res["statusText"]


def test_oob_settings_ui_masking_and_save():
    """Verify OOB settings UI masking preservation, non-prefilled password, and explicit save."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const calls = [];
    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async (path) => {{
          calls.push({{ method: 'GET', path: path }});
          if (path === '/api/v1/settings/oob') {{
            return {{
              ok: true,
              data: {{
                protocol: 'imap',
                host: 'mail.test',
                port: 993,
                username: 'scanner@test',
                password_set: true,
                password_hint: '••••••••',
                source: 'dashboard',
              }}
            }};
          }}
          if (path === '/api/v1/settings') return {{ ok: true, data: {{ notifications: {{}} }} }};
          return {{ ok: true, data: {{ fields: [] }} }};
        }},
        post: async (path, body) => {{
          calls.push({{ method: 'POST', path: path, body: body }});
          return {{ ok: true, data: {{ status: 'ok' }} }};
        }},
        delete: async (path) => {{
          calls.push({{ method: 'DELETE', path: path }});
          return {{ ok: true, data: {{ status: 'ok' }} }};
        }},
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    setTimeout(() => {{
      const dom = view.dom;
      const initialPasswordValue = dom.oobPassword.value;
      const placeholder = dom.oobPassword.placeholder;
      const hint = dom.oobPasswordHint.textContent;

      // 1. Save without entering password -> password key must NOT be sent
      dom.saveOobBtn.trigger('click');

      setTimeout(() => {{
        const saveCall1 = calls.find(c => c.method === 'POST' && c.path === '/api/v1/settings/oob');
        const sent1 = saveCall1 ? saveCall1.body : null;

        // 2. Save with new password entered -> password must be sent
        dom.oobPassword.value = 'new_secret_pass';
        dom.saveOobBtn.trigger('click');

        setTimeout(() => {{
          const postCalls = calls.filter(c => c.method === 'POST' && c.path === '/api/v1/settings/oob');
          const sent2 = postCalls.length > 1 ? postCalls[1].body : null;
          const passwordAfterSave = dom.oobPassword.value;

          console.log(JSON.stringify({{
            initialPasswordValue: initialPasswordValue,
            placeholder: placeholder,
            hint: hint,
            sent1HasPassword: 'password' in (sent1 || {{}}),
            sent2Password: sent2 ? sent2.password : null,
            passwordAfterSave: passwordAfterSave,
          }}));
        }}, 20);
      }}, 20);
    }}, 20);
    """
    res = _run_node(script)
    assert res["initialPasswordValue"] == ""
    assert "設定済み" in res["placeholder"]
    assert "設定済み" in res["hint"] or "••••••••" in res["hint"]
    assert res["sent1HasPassword"] is False
    assert res["sent2Password"] == "new_secret_pass"
    assert res["passwordAfterSave"] == ""


def test_oob_settings_ui_env_source_read_only():
    """Verify that when source is environment, UI shows read-only notice and disables inputs/save/clear."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async (path) => {{
          if (path === '/api/v1/settings/oob') {{
            return {{
              ok: true,
              data: {{
                protocol: 'imap',
                host: 'env.mail.test',
                port: 993,
                username: 'envuser',
                password_set: true,
                password_hint: 'env_pass_hint',
                source: 'environment',
              }}
            }};
          }}
          if (path === '/api/v1/settings') return {{ ok: true, data: {{ notifications: {{}} }} }};
          return {{ ok: true, data: {{ fields: [] }} }};
        }},
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    setTimeout(() => {{
      const dom = view.dom;
      console.log(JSON.stringify({{
        noticeHidden: dom.oobEnvNotice.hidden,
        saveDisabled: dom.saveOobBtn.disabled,
        clearDisabled: dom.clearOobBtn.disabled,
        hostDisabled: dom.oobHost.disabled,
        passwordDisabled: dom.oobPassword.disabled,
        hostValue: dom.oobHost.value,
      }}));
    }}, 20);
    """
    res = _run_node(script)
    assert res["noticeHidden"] is False
    assert res["saveDisabled"] is True
    assert res["clearDisabled"] is True
    assert res["hostDisabled"] is True
    assert res["passwordDisabled"] is True
    assert res["hostValue"] == "env.mail.test"


def test_oob_settings_ui_clear_and_test_connection():
    """Verify Test uses saved settings and Clear calls DELETE."""
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');

    const dispatches = [];
    const mockApi = {{
      createScope: () => ({{
        getActiveCount: () => 1,
        get: async (path) => {{
          if (path === '/api/v1/settings/oob') {{
            return {{
              ok: true,
              data: {{
                protocol: 'imap',
                host: 'mail.test',
                password_set: true,
                source: 'dashboard',
              }}
            }};
          }}
          if (path === '/api/v1/settings') return {{ ok: true, data: {{ notifications: {{}} }} }};
          return {{ ok: true, data: {{ fields: [] }} }};
        }},
        delete: async (path) => {{
          dispatches.push({{ method: 'DELETE', path: path }});
          return {{ ok: true, data: {{ status: 'ok' }} }};
        }},
        post: async (path, body) => {{
          dispatches.push({{ method: 'POST', path: path, body: body }});
          if (path === '/api/v1/settings/oob/test') {{
            return {{
              ok: true,
              data: {{
                ok: true,
                stage: 'done',
                error_kind: null,
                message: '接続と認証に成功しました。',
              }}
            }};
          }}
          return {{ ok: true }};
        }},
        cancelAll: () => {{}},
      }})
    }};

    const container = document.createElement('div');
    const view = settingsMod.renderSettingsView(container, {{ api: mockApi }});

    setTimeout(() => {{
      const dom = view.dom;

      // Click test connection
      dom.testOobBtn.trigger('click');

      setTimeout(() => {{
        const statusAfterTest = dom.oobStatus.textContent;

        // Click clear
        dom.clearOobBtn.trigger('click');

        setTimeout(() => {{
          console.log(JSON.stringify({{
            dispatches: dispatches,
            statusAfterTest: statusAfterTest,
            statusAfterClear: dom.oobStatus.textContent,
          }}));
        }}, 20);
      }}, 20);
    }}, 20);
    """
    res = _run_node(script)
    assert any(d["method"] == "POST" and d["path"] == "/api/v1/settings/oob/test" for d in res["dispatches"])
    test_call = next(d for d in res["dispatches"] if d["path"] == "/api/v1/settings/oob/test")
    assert test_call["body"] == {}
    assert any(d["method"] == "DELETE" and d["path"] == "/api/v1/settings/oob" for d in res["dispatches"])
    assert "成功" in res["statusAfterTest"]
    assert "削除" in res["statusAfterClear"]


def test_oob_settings_ui_requires_save_before_testing_edits():
    script = f"""
    {COMMON_DOM_STUB}
    const settingsMod = require('{SETTINGS_MODULE_JS}');
    let testCalls = 0;
    const mockApi = {{ createScope: () => ({{
      getActiveCount: () => 1,
      get: async (path) => path === '/api/v1/settings/oob'
        ? {{ ok: true, data: {{ host: 'mail.test', source: 'dashboard' }} }}
        : {{ ok: true, data: {{ notifications: {{}} }} }},
      post: async (path) => {{ if (path === '/api/v1/settings/oob/test') testCalls++; return {{ ok: true, data: {{ ok: true }} }}; }},
      cancelAll: () => {{}},
    }}) }};
    const view = settingsMod.renderSettingsView(document.createElement('div'), {{ api: mockApi }});
    setTimeout(() => {{
      view.dom.oobHost.value = 'edited.mail.test';
      view.dom.oobHost.trigger('input');
      view.dom.testOobBtn.trigger('click');
      setTimeout(() => console.log(JSON.stringify({{ testCalls, status: view.dom.oobStatus.textContent }})), 20);
    }}, 20);
    """
    res = _run_node(script)
    assert res["testCalls"] == 0
    assert "先に設定を保存" in res["status"]
