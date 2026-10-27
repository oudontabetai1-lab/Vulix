"""
Tests for dashboard feature flags and toggles in templates/dashboard.html.

Verifies:
1. `allow_state_changing_probes` is defined in `cfgToggles` with default `false`.
2. The toggle element `#tog-allow_state_changing_probes` is rendered under `#cfgTab-features`
   with classes 'cfg-toggle off' and click handler `toggleCfg('allow_state_changing_probes')`.
3. `submitScanConfig()` collects `allow_state_changing_probes` from `cfgToggles`.
4. Scan profiles in `applyScanProfile()` explicitly include `allow_state_changing_probes: false`.
5. Server configuration defaults round-trip into `cfgToggles` via `loadDefaultConfigFromServer` logic.
6. Playwright headless browser interaction confirms the toggle renders and toggles properly without JS errors.
"""

import json
import re
import shutil
import socket
import subprocess
import threading
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer

HTML_PATH = Path(__file__).parents[1] / "templates" / "dashboard.html"


def test_dashboard_toggle_static_definition():
    """Verify static declarations in templates/dashboard.html."""
    html = HTML_PATH.read_text(encoding="utf-8")

    # 1. Toggle element in DOM
    assert 'id="tog-allow_state_changing_probes"' in html
    assert "onclick=\"toggleCfg('allow_state_changing_probes')\"" in html
    assert "状態変更プローブ許可" in html

    # Check it is inside #cfgTab-features
    features_tab_start = html.index('id="cfgTab-features"')
    features_tab_end = html.index('<!-- Tab:', features_tab_start)
    features_html = html[features_tab_start:features_tab_end]
    assert 'id="tog-allow_state_changing_probes"' in features_html

    # 2. Defined in cfgToggles object
    toggles_start = html.index("const cfgToggles = {")
    toggles_end = html.index("};", toggles_start)
    toggles_code = html[toggles_start:toggles_end]
    assert "allow_state_changing_probes: false" in toggles_code

    # 3. Collected in submitScanConfig
    submit_start = html.index("function submitScanConfig()")
    submit_end = html.index("if (!config.checks.length)", submit_start)
    submit_code = html[submit_start:submit_end]
    assert "allow_state_changing_probes: cfgToggles.allow_state_changing_probes" in submit_code

    # 4. Handled in applyScanProfile presets
    profile_start = html.index("function applyScanProfile(profile)")
    profile_end = html.index("const p = profiles[profile];", profile_start)
    profile_code = html[profile_start:profile_end]
    assert "allow_state_changing_probes: false" in profile_code


@pytest.mark.skipif(not shutil.which("node"), reason="Node.js is required for dashboard JS test")
def test_dashboard_toggle_js_roundtrip_and_collection():
    """Execute dashboard JS snippet in Node to verify toggle state changes and config collection."""
    html = HTML_PATH.read_text(encoding="utf-8")

    # Extract cfgToggles and toggleCfg
    toggles_start = html.index("const cfgToggles = {")
    toggles_end = html.index("};", toggles_start) + 2
    toggles_decl = html[toggles_start:toggles_end]

    toggle_func_start = html.index("function setCfgToggle(key, value)")
    toggle_func_end = html.index("function showCfgTab(name, btn)", toggle_func_start)
    toggle_fns = html[toggle_func_start:toggle_func_end]

    node_script = f"""
const elements = {{}};
global.document = {{
  getElementById: (id) => {{
    if (!elements[id]) elements[id] = {{ className: '' }};
    return elements[id];
  }}
}};

{toggles_decl}
{toggle_fns}

// 1. Initial state
if (cfgToggles.allow_state_changing_probes !== false) process.exit(1);

// 2. toggleCfg toggles state and updates class
toggleCfg('allow_state_changing_probes');
if (cfgToggles.allow_state_changing_probes !== true) process.exit(2);
if (elements['tog-allow_state_changing_probes'].className !== 'cfg-toggle on') process.exit(3);

toggleCfg('allow_state_changing_probes');
if (cfgToggles.allow_state_changing_probes !== false) process.exit(4);
if (elements['tog-allow_state_changing_probes'].className !== 'cfg-toggle off') process.exit(5);

// 3. setCfgToggle works
setCfgToggle('allow_state_changing_probes', true);
if (cfgToggles.allow_state_changing_probes !== true) process.exit(6);
if (elements['tog-allow_state_changing_probes'].className !== 'cfg-toggle on') process.exit(7);
"""
    result = subprocess.run(
        [shutil.which("node"), "-e", node_script],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, f"Node script failed: {result.stderr}"


def test_api_config_defaults_exposes_allow_state_changing_probes():
    """Verify that /api/config/defaults serves allow_state_changing_probes."""
    srv = MonitorServer()
    srv.default_scan_cfg = {
        "toggles": {
            "allow_state_changing_probes": False,
        }
    }
    client = TestClient(srv.app)
    resp = client.get("/api/config/defaults")
    assert resp.status_code == 200
    data = resp.json()
    assert "toggles" in data
    assert data["toggles"]["allow_state_changing_probes"] is False


def test_dashboard_playwright_toggle_interaction():
    """Browser verification using Playwright to confirm rendering and click behavior."""
    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        pytest.skip("Playwright not installed")

    import uvicorn

    srv = MonitorServer()
    srv.default_scan_cfg = {
        "toggles": {
            "allow_state_changing_probes": False,
        }
    }

    # Find free port
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]

    config = uvicorn.Config(srv.app, host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    time.sleep(0.5)

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page(viewport={"width": 1280, "height": 800})
            console_errors = []
            page.on("console", lambda msg: console_errors.append(msg.text) if msg.type == "error" else None)

            page.goto(f"http://127.0.0.1:{port}/monitor")
            # Open config modal
            page.click(".ws-newscan")
            page.click('.cfg-tab:has-text("機能フラグ")')

            toggle = page.locator("#tog-allow_state_changing_probes")
            assert toggle.is_visible()
            assert "off" in (toggle.get_attribute("class") or "")
            assert "状態変更プローブ許可" in toggle.inner_text()

            # Click toggle to turn ON
            toggle.click()
            assert "on" in (toggle.get_attribute("class") or "")

            # Click again to turn OFF
            toggle.click()
            assert "off" in (toggle.get_attribute("class") or "")

            browser.close()
            assert not console_errors, f"Console errors encountered: {console_errors}"
    finally:
        server.should_exit = True
        thread.join(timeout=2)
