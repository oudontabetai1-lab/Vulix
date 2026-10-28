"""Tests for UI v3 U06: Credential state & export remediation (No secrets in UI state).

Verifies that no secrets or credentials appear in:
1. Client pendingScanConfig / lastScanConfig state (nonsecret descriptor, nonce correlation preserved)
2. localStorage ('wscan_config' allowlist & cleanup)
3. Exported config JSON (recursive nonsecret redaction)
4. Route / URL representations (userinfo & sensitive query parameter removal)
5. Replayable / observation state
6. Rerun credential re-entry behavior
"""
import shutil
import subprocess
from pathlib import Path
import pytest

SOURCE = (Path(__file__).parents[1] / "templates" / "dashboard.html").read_text(encoding="utf-8")


def _extract_dashboard_js_slice():
    start = SOURCE.index("function _markOwnScan(config)")
    end = SOURCE.index("// finding の安定キー", start)
    return SOURCE[start:end]


def _extract_rerun_js_slice():
    start = SOURCE.index("function _markOwnScan(config)")
    end = SOURCE.index("function openManualCrawlAfterScan()", start)
    return SOURCE[start:end]


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_pure_function_url_sanitization():
    js_slice = _extract_dashboard_js_slice()
    script = f"""
{js_slice}

// 1. userinfo credentials removal
const urlWithUserPass = 'https://alice:supersecret@example.com/app';
const sanitizedUserPass = sanitizeUrlForExport(urlWithUserPass);
if (sanitizedUserPass.includes('supersecret') || sanitizedUserPass.includes('alice')) {{
  throw new Error('userinfo credential leaked: ' + sanitizedUserPass);
}}
if (sanitizedUserPass !== 'https://example.com/app') {{
  throw new Error('unexpected sanitized userpass url: ' + sanitizedUserPass);
}}

// 2. Sensitive query parameters removal
const sensitiveQueries = [
  'https://example.com/?api_key=SECRET123&keep=ok',
  'https://example.com/?token=SECRET123&keep=ok',
  'https://example.com/?password=SECRET123&keep=ok',
  'https://example.com/?auth_token=SECRET123&keep=ok',
  'https://example.com/?secret=SECRET123&keep=ok',
  'https://example.com/?access_token=SECRET123&keep=ok',
  'https://example.com/?sig=SECRET123&keep=ok',
  'https://example.com/?jwt=SECRET123&keep=ok',
  'https://example.com/?jsessionid=SECRET123&keep=ok',
];
for (const raw of sensitiveQueries) {{
  const clean = sanitizeUrlForExport(raw);
  if (clean.includes('SECRET123')) throw new Error('Query secret leaked: ' + clean);
  if (!clean.includes('keep=ok')) throw new Error('Safe query param dropped: ' + clean);
}}

// 3. Matrix & fragment sensitive removal
const matrixUrl = 'https://example.com/app;jsessionid=SECRET123/dashboard?view=1';
const cleanMatrix = sanitizeUrlForExport(matrixUrl);
if (cleanMatrix.includes('SECRET123')) throw new Error('Matrix secret leaked: ' + cleanMatrix);
if (!cleanMatrix.includes('view=1')) throw new Error('Safe matrix view param dropped: ' + cleanMatrix);

const fragUrl = 'https://example.com/app#token=SECRET123&tab=overview';
const cleanFrag = sanitizeUrlForExport(fragUrl);
if (cleanFrag.includes('SECRET123')) throw new Error('Fragment secret leaked: ' + cleanFrag);
if (!cleanFrag.includes('tab=overview')) throw new Error('Safe fragment param dropped: ' + cleanFrag);
"""
    result = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_sentinels_absent_from_state_and_export():
    js_slice = _extract_dashboard_js_slice()

    script = f"""
global.self = {{ crypto: {{ randomUUID: () => 'nonce-u06-sentinel-test' }} }};

const state = {{
  lastScanConfig: null,
  lastScanConfigRedacted: false,
  pendingScanConfig: null,
  myScanNonce: null,
}};

{js_slice}

const SENTINELS = {{
  AUTH_PASS: 'SENTINEL_AUTH_PASS_SECRET_98765',
  COOKIE: 'SENTINEL_COOKIE_SECRET_54321',
  LOW_COOKIE: 'SENTINEL_LOW_COOKIE_11223',
  TLS_PASS: 'SENTINEL_TLS_PASS_SECRET_33445',
  TOTP_SECRET: 'SENTINEL_TOTP_JBSWY3DPEHPK3PXP',
  BEARER: 'SENTINEL_BEARER_SECRET_99887',
  HEADER_VAL: 'SENTINEL_HEADER_VAL_SECRET_77665',
  IMAP_PASS: 'SENTINEL_IMAP_PASS_SECRET_44556',
  ACCOUNT_PASS: 'SENTINEL_ACCOUNT_PASS_SECRET_12345',
  FLOW_FILL: 'SENTINEL_FLOW_FILL_SECRET_67890',
  URL_USERINFO: 'SENTINEL_URL_PASS_SECRET_13579',
  URL_QUERY: 'SENTINEL_URL_QUERY_SECRET_24680',
  URL_HASH: 'SENTINEL_URL_HASH_SECRET_35791',
}};

const fullRawConfig = {{
  url: `https://user:${{SENTINELS.URL_USERINFO}}@example.test/portal?api_key=${{SENTINELS.URL_QUERY}}#token=${{SENTINELS.URL_HASH}}`,
  auth_user: 'scanner-admin',
  auth_pass: SENTINELS.AUTH_PASS,
  cookies: `session=${{SENTINELS.COOKIE}}`,
  low_priv_cookies: `low_session=${{SENTINELS.LOW_COOKIE}}`,
  tls_client_cert_password: SENTINELS.TLS_PASS,
  bearer: `Bearer ${{SENTINELS.BEARER}}`,
  headers: {{
    'Authorization': `Bearer ${{SENTINELS.HEADER_VAL}}`,
    'X-Custom-Secret': 'SENTINEL_CUSTOM_SECRET',
  }},
  mfa_totp_secret: SENTINELS.TOTP_SECRET,
  mfa_totp_uri: `otpauth://totp/WScan?secret=${{SENTINELS.TOTP_SECRET}}`,
  mfa_email_imap_password: SENTINELS.IMAP_PASS,
  accounts: [
    {{ username: 'admin_user', password: SENTINELS.ACCOUNT_PASS, role: 'admin' }},
    {{ username: 'regular_user', password: 'SENTINEL_REGULAR_PASS', role: 'user' }},
  ],
  flows: [
    {{
      name: 'login-flow',
      steps: [
        {{ action: 'fill', field: 'username', value: 'admin_user' }},
        {{ action: 'fill', field: 'password', value: SENTINELS.FLOW_FILL }},
        {{ action: 'fill', field: 'user_secret_token', value: 'SENTINEL_CUSTOM_TOKEN' }},
        {{ action: 'navigate', url: `https://user:${{SENTINELS.URL_USERINFO}}@example.test/admin?token=${{SENTINELS.URL_QUERY}}` }},
      ],
    }},
  ],
  target_urls: `https://user:${{SENTINELS.URL_USERINFO}}@example.test/target?key=${{SENTINELS.URL_QUERY}}`,
  access_urls: `https://example.test/api?token=${{SENTINELS.URL_QUERY}}`,
  depth: 2,
  timeout: 30,
  checks: ['sqli', 'xss'],
}};

// ─── 1. TEST _markOwnScan: pendingScanConfig MUST be nonsecret descriptor ─────
_markOwnScan(fullRawConfig);

if (!state.myScanNonce) {{
  throw new Error('Nonce was not assigned');
}}
if (fullRawConfig._client_nonce !== state.myScanNonce) {{
  throw new Error('Client nonce was not attached to config');
}}
if (state.pendingScanConfig._client_nonce !== state.myScanNonce) {{
  throw new Error('Nonce correlation was not preserved in descriptor');
}}
if (state.pendingScanConfig.requires_credentials !== true) {{
  throw new Error('Credential requirement flag was not set in descriptor');
}}

// Assert no sentinels appear in pendingScanConfig
const pendingStr = JSON.stringify(state.pendingScanConfig);
for (const [name, sentinel] of Object.entries(SENTINELS)) {{
  if (pendingStr.includes(sentinel)) {{
    throw new Error(`Sentinel ${{name}} leaked into pendingScanConfig: ` + pendingStr);
  }}
}}
if (pendingStr.includes('SENTINEL_CUSTOM_SECRET') ||
    pendingStr.includes('SENTINEL_REGULAR_PASS') ||
    pendingStr.includes('SENTINEL_CUSTOM_TOKEN')) {{
  throw new Error('Custom sentinel leaked into pendingScanConfig');
}}

// ─── 2. TEST _promotePendingScan: lastScanConfig MUST be nonsecret ───────────
_promotePendingScan({{
  _client_nonce: state.myScanNonce,
  url: 'https://example.test/portal',
}});

if (state.pendingScanConfig !== null) {{
  throw new Error('pendingScanConfig was not cleared on promotion');
}}
if (!state.lastScanConfig) {{
  throw new Error('lastScanConfig was not set');
}}
if (state.lastScanConfig._client_nonce !== state.myScanNonce) {{
  throw new Error('Nonce correlation not preserved in lastScanConfig');
}}
if (state.lastScanConfig.requires_credentials !== true) {{
  throw new Error('requires_credentials flag not preserved in lastScanConfig');
}}

const lastStr = JSON.stringify(state.lastScanConfig);
for (const [name, sentinel] of Object.entries(SENTINELS)) {{
  if (lastStr.includes(sentinel)) {{
    throw new Error(`Sentinel ${{name}} leaked into lastScanConfig: ` + lastStr);
  }}
}}

// ─── 3. TEST _sanitizeConfigForExport: Export JSON MUST be nonsecret ──────────
const exported = _sanitizeConfigForExport(fullRawConfig);
const exportStr = JSON.stringify(exported);

for (const [name, sentinel] of Object.entries(SENTINELS)) {{
  if (exportStr.includes(sentinel)) {{
    throw new Error(`Sentinel ${{name}} leaked into export config: ` + exportStr);
  }}
}}
if (exportStr.includes('SENTINEL_CUSTOM_SECRET') ||
    exportStr.includes('SENTINEL_REGULAR_PASS') ||
    exportStr.includes('SENTINEL_CUSTOM_TOKEN')) {{
  throw new Error('Custom sentinel leaked into export');
}}

// Verify nonsecret fields are preserved in export
if (exported.depth !== 2 || exported.timeout !== 30) {{
  throw new Error('Nonsecret fields altered in export');
}}
if (!Array.isArray(exported.checks) || exported.checks[0] !== 'sqli') {{
  throw new Error('Checks array altered in export');
}}
if (exported.accounts[0].username !== 'admin_user') {{
  throw new Error('Account username altered in export');
}}
if (exported.accounts[0].password !== undefined) {{
  throw new Error('Account password not deleted in export');
}}
if (exported.flows[0].steps[1].value !== '') {{
  throw new Error('Flow fill password value was not blanked in export');
}}
if (exported.url !== 'https://example.test/portal') {{
  throw new Error('URL was not properly sanitized: ' + exported.url);
}}
"""
    result = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_storage_allowlist_and_rerun_behavior():
    js_slice = _extract_rerun_js_slice()

    script = f"""
global.self = global;
let sentMessages = [];
let statuses = [];
let eventLogs = [];
let activeOverlays = new Set();

const document = {{
  getElementById: id => ({{
    value: '',
    classList: {{
      add: cls => activeOverlays.add(cls),
      remove: cls => activeOverlays.delete(cls),
      contains: cls => activeOverlays.has(cls),
    }},
    style: {{}},
  }}),
  querySelector: () => null,
  querySelectorAll: () => [],
}};

function setStatus(msg, lvl) {{ statuses.push({{ msg, lvl }}); }}
function addEventLog(type, msg) {{ eventLogs.push({{ type, msg }}); }}
function showPostScanActions() {{}}

const state = {{
  lastScanConfig: null,
  lastScanConfigRedacted: false,
  pendingScanConfig: null,
  myScanNonce: null,
  ws: {{
    readyState: 1, // WebSocket.OPEN
    send: data => sentMessages.push(JSON.parse(data)),
  }},
}};

{js_slice}

// ─── 1. Rerun when credentials were required: MUST prompt re-entry ────────────
state.lastScanConfig = {{
  url: 'https://example.test/app',
  checks: ['xss'],
  requires_credentials: true,
}};
state.lastScanConfigRedacted = false;

rerunLastScan();

if (sentMessages.length !== 0) {{
  throw new Error('Rerun sent scan message without credential re-entry');
}}
if (!activeOverlays.has('active')) {{
  throw new Error('Setup overlay was not reopened for credential re-entry');
}}
if (!statuses.some(s => s.msg.includes('認証情報を再入力'))) {{
  throw new Error('Re-entry status message not presented: ' + JSON.stringify(statuses));
}}

// ─── 2. Rerun when no credentials were required: sends start_scan ─────────────
activeOverlays.clear();
sentMessages = [];
statuses = [];

state.lastScanConfig = {{
  url: 'https://example.test/public',
  checks: ['xss', 'sqli'],
  requires_credentials: false,
}};

rerunLastScan();

if (sentMessages.length !== 1) {{
  throw new Error('Normal rerun failed to send start_scan');
}}
if (sentMessages[0].action !== 'start_scan') {{
  throw new Error('Action was not start_scan: ' + JSON.stringify(sentMessages[0]));
}}
if (sentMessages[0].config.url !== 'https://example.test/public') {{
  throw new Error('Config url altered in rerun');
}}
if (sentMessages[0].config.requires_credentials !== undefined) {{
  throw new Error('requires_credentials was leaked in outgoing start_scan config');
}}
"""
    result = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_storage_allowlist_and_legacy_cleanup():
    start = SOURCE.index("const CONFIG_SAVE_ALLOWLIST = [")
    end = SOURCE.index("async function loadDefaultConfigFromServer()", start)
    js_slice = SOURCE[start:end]

    script = f"""
const fields = new Map();
const document = {{
  getElementById: id => ({{
    value: fields.get(id) || '',
  }}),
  querySelectorAll: () => [],
}};
const cfgToggles = {{}};
const collectRoleModels = () => ({{}});
const mfaImapFields = () => ({{}});
const mfaTotpFields = () => ({{}});
const timeWindowFields = () => ({{}});
const applyMfaImap = () => {{}};
const applyMfaTotp = () => {{}};
const applyAuthHeaders = () => {{}};
const applyTimeWindows = () => {{}};
const getSelectedChecks = () => ['sqli'];

let store = {{}};
const localStorage = {{
  getItem: k => store[k] || null,
  setItem: (k, v) => {{ store[k] = v; }},
}};

{js_slice}

// 1. Verify legacy sensitive keys in storage are purged upon loading
store['wscan_config'] = JSON.stringify({{
  url: 'https://example.test',
  depth: 2,
  auth_pass: 'SENTINEL_OLD_PASS',
  cookies: 'SENTINEL_OLD_COOKIE',
  low_priv_cookies: 'SENTINEL_OLD_LOW_COOKIE',
  tls_client_cert_password: 'SENTINEL_OLD_TLS_PASS',
  password: 'SENTINEL_OLD_RAW_PASS',
}});

loadConfigFromStorage();

// Storage must have been overwritten without any sensitive keys
const cleaned = JSON.parse(store['wscan_config']);
for (const badKey of ['auth_pass', 'cookies', 'low_priv_cookies', 'tls_client_cert_password', 'password']) {{
  if (badKey in cleaned) {{
    throw new Error('Legacy sensitive key remained in storage: ' + badKey);
  }}
}}
const cleanedStr = JSON.stringify(cleaned);
if (cleanedStr.includes('SENTINEL_OLD')) {{
  throw new Error('Sentinel remained in overwritten storage: ' + cleanedStr);
}}

// 2. Verify saveConfigToStorage excludes credentials even if field has value
fields.set('cfgInputUrl', 'https://example.test');
fields.set('cfgAuthPass', 'SENTINEL_INPUT_PASS');
fields.set('cfgCookies', 'SENTINEL_INPUT_COOKIE');
fields.set('cfgLowPrivCookies', 'SENTINEL_INPUT_LOW_COOKIE');
fields.set('cfgTlsClientCertPassword', 'SENTINEL_INPUT_TLS_PASS');
saveConfigToStorage();

const reSavedStr = store['wscan_config'];
if (reSavedStr.includes('SENTINEL_INPUT')) {{
  throw new Error('Sentinel entered storage via saveConfigToStorage: ' + reSavedStr);
}}
"""
    result = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_route_and_url_parameters_no_sentinel():
    js_slice = _extract_dashboard_js_slice()

    script = f"""
{js_slice}

// Simulated route / URL inputs with sentinels in various positions
const sentinelUrls = [
  'https://user:SENTINEL_ROUTE_PASS@example.test/scan/123/findings',
  'https://example.test/scan/123/findings?token=SENTINEL_ROUTE_TOKEN&finding=xss_1',
  'https://example.test/scan/123/findings#auth_token=SENTINEL_ROUTE_FRAG&view=detail',
  'https://example.test/app;jsessionid=SENTINEL_ROUTE_SESSION/findings?id=1',
];

for (const raw of sentinelUrls) {{
  const sanitized = sanitizeUrlForExport(raw);
  if (sanitized.includes('SENTINEL_ROUTE')) {{
    throw new Error('Sentinel leaked in route sanitization: ' + sanitized);
  }}
}}
"""
    result = subprocess.run([shutil.which("node"), "-e", script], capture_output=True, text=True, check=False)
    assert result.returncode == 0, result.stderr

