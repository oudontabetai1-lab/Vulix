import shutil
import subprocess
from pathlib import Path

import pytest


SOURCE = (Path(__file__).parents[1] / "templates" / "dashboard.html").read_text()


def test_persistence_allowlist_includes_numeric_scan_controls():
    allowlist = SOURCE.split("const CONFIG_SAVE_ALLOWLIST = [", 1)[1].split("];", 1)[0]
    assert "'max_payloads'" in allowlist
    assert "'auto_register_count'" in allowlist
    assert "max_payloads: document.getElementById('cfgMaxPayloads').value" in SOURCE
    assert "auto_register_count: document.getElementById('cfgAutoRegisterCount').value" in SOURCE


def test_all_scan_start_paths_persist_non_secret_config():
    for name, following in (
        ("submitScanConfig", "_collectFullConfigForExport"),
        ("submitAgentScan", "CONFIG_SAVE_ALLOWLIST"),
        ("submitHybridScan", "handleWafDetected"),
    ):
        body = SOURCE.split(f"function {name}()", 1)[1].split(following, 1)[0]
        assert "saveConfigToStorage();" in body


def test_url_bearing_fields_pass_through_secret_filter_before_storage():
    assert "if (parsed.username || parsed.password || hasSensitiveMatrixParam(parsed.pathname)) return undefined;" in SOURCE
    assert "CONFIG_SENSITIVE_URL_KEY.test(key)" in SOURCE
    for field in ("cfgInputUrl", "cfgProxy", "cfgLlmBaseUrl", "cfgLoginUrl"):
        assert f"safeUrlForStorage(document.getElementById('{field}').value)" in SOURCE
    for field in ("cfgTargetUrls", "cfgAccessUrls"):
        assert f"safeUrlListForStorage(document.getElementById('{field}').value)" in SOURCE


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_url_credentials_are_excluded_from_storage():
    start = SOURCE.index("const CONFIG_SENSITIVE_URL_KEY =")
    end = SOURCE.index("function saveConfigToStorage()", start)
    helpers = SOURCE[start:end]
    script = f"""
{helpers}
const rejected = [
  'https://example.test/?key=SECRET',
  'https://example.test/?APIKEY=SECRET',
  'https://example.test/?access_key=SECRET',
  'https://example.test/?auth-token=SECRET',
  'https://example.test/object?X-Amz-Credential=SECRET&X-Amz-Signature=SECRET',
  'https://example.test/object?X-Amz-Security-Token=SECRET',
  'https://example.test/object?X-Goog-Credential=SECRET',
  'https://example.test/object?X-Goog-Signature=SECRET',
  'https://example.test/object?sig=SECRET',
  'https://example.test/object?signature=SECRET',
  'https://example.test/object?client_credential=SECRET',
  'https://example.test/object?sid=SECRET',
  'https://example.test/object?jwt=SECRET',
  'https://example.test/object?auth=SECRET',
  'https://example.test/object?bearer=SECRET',
  'https://example.test/object?otp=SECRET',
  'https://example.test/app;jsessionid=SECRET/home',
  'https://example.test/app;sid=SECRET/home',
  'https://example.test/(S(lit3py55t21z5v55vlm25s))/home',
  'https://example.test/#key=SECRET',
  'https://example.test/#sig=SECRET',
  'https://example.test/#jwt=SECRET',
  'not-a-url?key=SECRET',
  'not-a-url?%6bey=SECRET',
  'not-a-url?X-Amz-Signature=SECRET',
  'not-a-url?%73ig=SECRET',
  'not-a-url?sid=SECRET',
  'not-a-url;jsessionid=SECRET/home',
];
for (const url of rejected) {{
  if (safeUrlForStorage(url) !== undefined) throw new Error(url);
}}
const kept = [
  'https://example.test/?monkey=banana',
  'https://example.test/?keyboard=us',
  'https://example.test/?signal=green',
  'https://example.test/?author=jane',
  'https://example.test/app;view=grid/home',
  'not-a-url?monkey=banana',
  'localhost:8080',
];
for (const url of kept) {{
  if (safeUrlForStorage(url) !== url) throw new Error(url);
}}
if (safeUrlListForStorage('https://example.test/?key=SECRET\\nhttps://example.test/ok')
    !== 'https://example.test/ok') throw new Error('URL list');
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr


def test_restore_target_gating_present_in_source():
    # 指摘3: per-scan credential が省かれた復元では target/url を戻さない配線が存在すること。
    assert ("restore_target: !CONFIG_SECRET_FIELD_IDS.some(id =>" in SOURCE)
    assert "const restoreTarget = cfg.restore_target === true;" in SOURCE
    assert ("if (restoreTarget && cfg.url && safeUrlForStorage(cfg.url) "
            "!== undefined) document.getElementById('cfgInputUrl').value = cfg.url;") in SOURCE
    assert "if (restoreTarget && cfg.target_urls)" in SOURCE
    assert "if (restoreTarget && cfg.access_urls)" in SOURCE


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_login_success_indicator_credentials_are_not_persisted():
    start = SOURCE.index("const CONFIG_SAVE_ALLOWLIST =")
    end = SOURCE.index("function loadConfigFromStorage()", start)
    script = f"""
{SOURCE[start:end]}
const fields = new Map();
const document = {{ getElementById: id => ({{ value: fields.get(id) || '' }}) }};
const cfgToggles = {{}};
const collectRoleModels = () => ({{}});
const mfaImapFields = () => ({{}});
const mfaTotpFields = () => ({{}});
const timeWindowFields = () => ({{}});
const getSelectedChecks = () => [];
let saved;
const localStorage = {{ setItem: (_, value) => {{ saved = JSON.parse(value); }} }};
for (const indicator of [
  'https://user:password@example.test/landing',
  'https://example.test/callback?access_token=SECRET',
  'not-a-url?access_token=SECRET',
]) {{
  fields.set('cfgLoginSuccess', indicator);
  saveConfigToStorage();
  if (Object.hasOwn(saved, 'login_success_indicator')) throw new Error(indicator);
}}
for (const indicator of ['Welcome back', 'dashboard', 'https://example.test/home']) {{
  fields.set('cfgLoginSuccess', indicator);
  saveConfigToStorage();
  if (saved.login_success_indicator !== indicator) throw new Error(indicator);
}}
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", script], capture_output=True, text=True, check=False
    )
    assert result.returncode == 0, result.stderr
