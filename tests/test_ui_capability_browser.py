"""Browser verification for capability reader and checks presentation using UIHarness.

Verifies via real Chromium browser:
1. Normal mode: All registered scanners from capability manifest render across categories.
2. Default checks strictly have 'checked' class (sqli, os, xss).
3. Select All / Deselect All interactive buttons function properly.
4. Mode gating: In Agent mode, non-agent deterministic scanners become gated (opacity, disabled, reason).
5. Safe unavailable state: When capability manifest endpoint fails or returns error,
   #checksUnavailableBanner is safely displayed with the reason, no unhandled exceptions crash the UI,
   and unacquired capabilities are never claimed as passed.
6. Layout integrity and responsive screenshots at 1440, 1280, and 768 viewports without overflow.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path

import pytest

from tests.ui_harness import (
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)
from wscan.scanners import SCANNERS

VIEWPORT_WIDTHS = [1440, 1280, 768]
SCREENSHOTS_DEST = (
    Path(os.environ["WSCAN_SCREENSHOT_DIR"]) if os.environ.get("WSCAN_SCREENSHOT_DIR") else None
)


@pytest.mark.parametrize("width", VIEWPORT_WIDTHS)
def test_capability_reader_browser_normal_and_agent_gating(ui_harness: UIHarness, width: int):
    """Verify normal scanner checklist rendering, defaults, interactive toggling, and mode gating."""
    require_browser()
    vp = STANDARD_VIEWPORTS[width]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    try:
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        # Open Setup overlay
        page.evaluate("() => { if (typeof openConfigOverlay === 'function') openConfigOverlay(); else document.getElementById('scanConfigOverlay').classList.add('active'); }")
        page.wait_for_selector("#scanConfigOverlay.active")

        # Switch to Checks tab
        page.evaluate("() => window.showCfgTab('checks')")
        page.wait_for_selector("#cfgTab-checks.active")

        # Wait for capability-reader to load manifest and render items
        page.wait_for_function("() => document.querySelectorAll('.cfg-check-item').length > 0")

        # 1. Total rendered items must match SCANNERS count exactly
        rendered_count = page.evaluate("() => document.querySelectorAll('.cfg-check-item').length")
        assert rendered_count == len(SCANNERS), f"Expected {len(SCANNERS)} scanners, got {rendered_count}"

        # 2. Defaults must be strictly sqli, os, xss
        checked_ids = page.evaluate(
            "() => [...document.querySelectorAll('.cfg-check-item.checked')].map(el => el.dataset.check)"
        )
        assert set(checked_ids) == {"sqli", "os", "xss"}

        # 3. Interactive testing: Click a non-default check (nosql) to toggle
        page.click('.cfg-check-item[data-check="nosql"]')
        page.wait_for_timeout(50)
        is_nosql_checked = page.evaluate("() => document.querySelector('.cfg-check-item[data-check=\"nosql\"]').classList.contains('checked')")
        assert is_nosql_checked is True

        # Test Deselect All
        page.click('button[onclick="selectAllChecks(false)"]')
        page.wait_for_timeout(50)
        after_deselect = page.evaluate("() => document.querySelectorAll('.cfg-check-item.checked').length")
        assert after_deselect == 0

        # Test Select All
        page.click('button[onclick="selectAllChecks(true)"]')
        page.wait_for_timeout(50)
        after_select_all = page.evaluate("() => document.querySelectorAll('.cfg-check-item.checked').length")
        assert after_select_all == len(SCANNERS)

        # 4. Mode gating verification: Switch to Agent mode and verify non-agent scanners are gated
        page.evaluate("() => window.setScanMode('agent')")
        page.wait_for_timeout(50)

        # In Agent mode, deterministic scanners must have 'gated' class
        gated_count = page.evaluate("() => document.querySelectorAll('.cfg-check-item.gated').length")
        assert gated_count > 0, "Expected non-agent scanners to be gated in Agent mode"

        # Check tooltip reason on a gated scanner
        sqli_title = page.evaluate("() => document.querySelector('.cfg-check-item[data-check=\"sqli\"]').title")
        assert "Agent" in sqli_title or "非対応" in sqli_title

        # Clicking a gated item does NOT toggle its checked status
        was_checked = page.evaluate("() => document.querySelector('.cfg-check-item[data-check=\"sqli\"]').classList.contains('checked')")
        page.click('.cfg-check-item[data-check="sqli"]')
        page.wait_for_timeout(50)
        is_checked_now = page.evaluate("() => document.querySelector('.cfg-check-item[data-check=\"sqli\"]').classList.contains('checked')")
        assert was_checked == is_checked_now

        # Switch back to Normal mode and verify gating is cleared and selections preserved
        page.evaluate("() => window.setScanMode('normal')")
        page.wait_for_timeout(50)
        gated_after_return = page.evaluate("() => document.querySelectorAll('.cfg-check-item.gated').length")
        assert gated_after_return == 0
        checked_after_return = page.evaluate("() => document.querySelectorAll('.cfg-check-item.checked').length")
        assert checked_after_return == len(SCANNERS), f"Expected all {len(SCANNERS)} to remain checked after returning to normal mode"

        # 5. Assert layout integrity and no console/page errors
        max_allowed = 1000 if width == 768 else None
        ui_harness.assert_no_horizontal_overflow(page, max_allowed=max_allowed)
        ui_harness.assert_no_errors(page)

        # 6. Capture screenshot
        screenshot_path, w, h = ui_harness.capture_screenshot(
            page, "checks_capability_normal", width, dest_dir=SCREENSHOTS_DEST
        )
        assert screenshot_path.is_file()
        assert w == width
    finally:
        page.close()


def test_capability_reader_browser_unavailable_banner(ui_harness: UIHarness):
    """Verify safe presentation when capability reader encounters fresh boot failure (401)."""
    require_browser()
    page = ui_harness.new_page(width=1280, height=800)

    try:
        # Intercept capability manifest request before page boot to simulate true fresh boot failure
        page.route(
            "**/api/capability-manifest*",
            lambda route: route.fulfill(
                status=401,
                body='{"error": "unauthorized"}',
                headers={"content-type": "application/json"},
            ),
        )
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        # Open Setup overlay and Checks tab
        page.evaluate("() => { if (typeof openConfigOverlay === 'function') openConfigOverlay(); else document.getElementById('scanConfigOverlay').classList.add('active'); }")
        page.evaluate("() => window.showCfgTab('checks')")
        page.wait_for_selector("#cfgTab-checks.active")
        page.wait_for_timeout(100)

        # Verify #checksUnavailableBanner is visible with reason
        banner_display = page.evaluate("() => window.getComputedStyle(document.getElementById('checksUnavailableBanner')).display")
        assert banner_display != "none"

        reason_text = page.locator("#checksUnavailableReason").inner_text()
        assert "401" in reason_text or "認証" in reason_text

        # Invariant check: In a fresh boot failure, exactly 0 check items should be rendered
        rendered_checks = page.evaluate("() => document.querySelectorAll('.cfg-check-item').length")
        assert rendered_checks == 0, f"Expected 0 rendered checks on boot failure, got {rendered_checks}"

        # Invariant check: isScannerApplicable returns false, never true
        is_sqli_applicable = page.evaluate("() => window.VulixCapabilityReader.defaultReader.isScannerApplicable('sqli')")
        assert is_sqli_applicable is False

        # No uncaught console errors (excluding expected 401 resource response)
        errors = [
            e for e in ui_harness.get_errors(page)
            if "401" not in e and "Failed to load resource" not in e
        ]
        assert not errors, f"Unexpected page errors: {errors}"

        screenshot_path, w, h = ui_harness.capture_screenshot(
            page, "checks_capability_unavailable", 1280, dest_dir=SCREENSHOTS_DEST
        )
        assert screenshot_path.is_file()
        assert w == 1280
        assert h == 800

        # Refresh documentation screenshot
        doc_img_path = Path("docs/images/dashboard-checks-unavailable.png")
        if doc_img_path.parent.is_dir():
            shutil.copyfile(screenshot_path, doc_img_path)
    finally:
        page.close()


def test_capability_check_selection_retention_and_tabs(ui_harness: UIHarness):
    """Verify check selection retention across mode transitions, tabs, and storage restore (B1)."""
    require_browser()
    page = ui_harness.new_page(width=1280, height=800)

    try:
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        page.evaluate("() => { if (typeof openConfigOverlay === 'function') openConfigOverlay(); else document.getElementById('scanConfigOverlay').classList.add('active'); }")
        page.evaluate("() => window.showCfgTab('checks')")
        page.wait_for_function("() => document.querySelectorAll('.cfg-check-item').length > 0")

        # 1. Defaults on initial fresh boot strictly sqli, os, xss
        initial_checked = set(page.evaluate("() => getSelectedChecks()"))
        assert initial_checked == {"sqli", "os", "xss"}

        # 2. Custom selection: uncheck all, select csrf and sqli
        page.click('button[onclick="selectAllChecks(false)"]')
        page.click('.cfg-check-item[data-check="csrf"]')
        page.click('.cfg-check-item[data-check="sqli"]')
        custom_selected = set(page.evaluate("() => getSelectedChecks()"))
        assert custom_selected == {"csrf", "sqli"}

        # 3. Transition to Agent mode: items become gated, but selection is retained
        page.evaluate("() => window.showCfgTab('agent')")
        gated_count = page.evaluate("() => document.querySelectorAll('.cfg-check-item.gated').length")
        assert gated_count > 0
        agent_selected_intent = set(page.evaluate("() => getSelectedChecks(false)"))
        assert agent_selected_intent == {"csrf", "sqli"}
        # But applicable checks in Agent mode (for transmission) is empty
        agent_applicable = page.evaluate("() => getSelectedChecks(true)")
        assert agent_applicable == []

        # 4. Transition to Hybrid mode: selection retained
        page.evaluate("() => window.showCfgTab('hybrid')")
        hybrid_selected = set(page.evaluate("() => getSelectedChecks()"))
        assert hybrid_selected == {"csrf", "sqli"}

        # 5. Navigate across other tabs (basic, auth, features) and return to checks tab
        for tab_name in ["basic", "auth", "features", "exclusions", "manualcrawl", "flows"]:
            page.evaluate(f"() => window.showCfgTab('{tab_name}')")
            page.wait_for_timeout(30)
        page.evaluate("() => window.showCfgTab('checks')")
        returned_selected = set(page.evaluate("() => getSelectedChecks()"))
        assert returned_selected == {"csrf", "sqli"}, f"Expected {{'csrf', 'sqli'}}, got {returned_selected}"

        # 6. Explicit Deselect All and tab switching (must not restore defaults)
        page.click('button[onclick="selectAllChecks(false)"]')
        assert page.evaluate("() => getSelectedChecks()") == []
        for tab_name in ["basic", "agent", "hybrid", "auth", "checks"]:
            page.evaluate(f"() => window.showCfgTab('{tab_name}')")
            page.wait_for_timeout(30)
        assert page.evaluate("() => getSelectedChecks()") == [], "Explicit deselect all must be retained across tabs"

        # 7. LocalStorage Save and Restore
        page.click('.cfg-check-item[data-check="nosql"]')
        assert set(page.evaluate("() => getSelectedChecks()")) == {"nosql"}
        page.evaluate("() => saveConfigToStorage()")

        # Clear DOM selection then restore from storage
        page.click('button[onclick="selectAllChecks(false)"]')
        assert page.evaluate("() => getSelectedChecks()") == []
        page.evaluate("() => loadConfigFromStorage()")
        assert set(page.evaluate("() => getSelectedChecks()")) == {"nosql"}

        # Test restoring explicit empty checks from storage
        page.click('button[onclick="selectAllChecks(false)"]')
        page.evaluate("() => saveConfigToStorage()")
        page.click('.cfg-check-item[data-check="xss"]')
        page.evaluate("() => loadConfigFromStorage()")
        assert page.evaluate("() => getSelectedChecks()") == [], "Saved empty checks must restore to empty"

        ui_harness.assert_no_errors(page)
    finally:
        page.close()


def test_capability_submission_guards_and_agent_nonregression(ui_harness: UIHarness):
    """Verify submission prevention for Normal/Hybrid on unavailable manifest and Agent non-regression (B2)."""
    require_browser()

    # Scenario A: Manifest returns HTTP 401
    page = ui_harness.new_page(width=1280, height=800)
    try:
        page.route(
            "**/api/capability-manifest*",
            lambda route: route.fulfill(
                status=401,
                body='{"error": "unauthorized"}',
                headers={"content-type": "application/json"},
            ),
        )
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        page.evaluate("""() => {
            if (typeof openConfigOverlay === 'function') openConfigOverlay();
            else document.getElementById('scanConfigOverlay').classList.add('active');
            document.getElementById('cfgInputUrl').value = 'http://127.0.0.1:8000';
            window.__sentMessages = [];
            if (state.ws) {
                state.ws.send = (msg) => { window.__sentMessages.push(JSON.parse(msg)); };
            }
        }""")
        page.wait_for_timeout(100)

        # 1. Normal scan submission must be blocked (0 messages sent)
        page.evaluate("() => submitScanConfig()")
        sent = page.evaluate("() => window.__sentMessages")
        assert len(sent) == 0, f"Expected 0 sent messages on 401 unavailable, got {sent}"

        # 2. Hybrid scan submission must be blocked (0 messages sent)
        page.evaluate("() => submitHybridScan()")
        sent_hybrid = page.evaluate("() => window.__sentMessages")
        assert len(sent_hybrid) == 0, f"Expected 0 sent messages on Hybrid 401, got {sent_hybrid}"

        # 3. Agent scan submission must NOT be blocked (Agent non-regression)
        page.evaluate("() => submitAgentScan()")
        sent_agent = page.evaluate("() => window.__sentMessages")
        assert len(sent_agent) == 1, "Agent scan must send start_scan even when capability manifest is unavailable"
        assert sent_agent[0]["config"].get("agent_mode") is True
    finally:
        page.close()

    # Scenario B: Manifest route fails with network abort
    page2 = ui_harness.new_page(width=1280, height=800)
    try:
        page2.route("**/api/capability-manifest*", lambda route: route.abort())
        page2.goto(f"{ui_harness.server_url}/monitor")
        page2.wait_for_selector(".main")

        page2.evaluate("""() => {
            if (typeof openConfigOverlay === 'function') openConfigOverlay();
            else document.getElementById('scanConfigOverlay').classList.add('active');
            document.getElementById('cfgInputUrl').value = 'http://127.0.0.1:8000';
            window.__sentMessages = [];
            if (state.ws) {
                state.ws.send = (msg) => { window.__sentMessages.push(JSON.parse(msg)); };
            }
        }""")
        page2.wait_for_timeout(100)

        page2.evaluate("() => submitScanConfig()")
        assert len(page2.evaluate("() => window.__sentMessages")) == 0
        page2.evaluate("() => submitHybridScan()")
        assert len(page2.evaluate("() => window.__sentMessages")) == 0
    finally:
        page2.close()

    # Scenario C: Manifest reader is in loading state
    page3 = ui_harness.new_page(width=1280, height=800)
    try:
        page3.goto(f"{ui_harness.server_url}/monitor")
        page3.wait_for_selector(".main")
        page3.evaluate("""() => {
            if (typeof openConfigOverlay === 'function') openConfigOverlay();
            else document.getElementById('scanConfigOverlay').classList.add('active');
            document.getElementById('cfgInputUrl').value = 'http://127.0.0.1:8000';
            window.__sentMessages = [];
            if (state.ws) {
                state.ws.send = (msg) => { window.__sentMessages.push(JSON.parse(msg)); };
            }
            window.VulixCapabilityReader.defaultReader.status = 'loading';
        }""")
        page3.evaluate("() => submitScanConfig()")
        assert len(page3.evaluate("() => window.__sentMessages")) == 0
        page3.evaluate("() => submitHybridScan()")
        assert len(page3.evaluate("() => window.__sentMessages")) == 0
    finally:
        page3.close()

    # Scenario D: Ready state normal submission
    page4 = ui_harness.new_page(width=1280, height=800)
    try:
        page4.goto(f"{ui_harness.server_url}/monitor")
        page4.wait_for_selector(".main")
        page4.wait_for_function("() => window.VulixCapabilityReader && window.VulixCapabilityReader.defaultReader.isReady()")
        page4.evaluate("""() => {
            if (typeof openConfigOverlay === 'function') openConfigOverlay();
            else document.getElementById('scanConfigOverlay').classList.add('active');
            document.getElementById('cfgInputUrl').value = 'http://127.0.0.1:8000';
            window.__sentMessages = [];
            if (state.ws) {
                state.ws.send = (msg) => { window.__sentMessages.push(JSON.parse(msg)); };
            }
        }""")
        page4.evaluate("() => submitScanConfig()")
        sent_normal = page4.evaluate("() => window.__sentMessages")
        assert len(sent_normal) == 1
        assert sent_normal[0]["action"] == "start_scan"
        assert set(sent_normal[0]["config"]["checks"]) == {"sqli", "os", "xss"}

        # Hybrid submission
        page4.evaluate("() => submitHybridScan()")
        sent_hybrid = page4.evaluate("() => window.__sentMessages")
        assert len(sent_hybrid) == 2
        assert sent_hybrid[1]["config"]["hybrid_mode"] is True
    finally:
        page4.close()
