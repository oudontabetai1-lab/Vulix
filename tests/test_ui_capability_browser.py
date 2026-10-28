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

import pytest

from tests.ui_harness import (
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)
from wscan.scanners import SCANNERS

VIEWPORT_WIDTHS = [1440, 1280, 768]


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

        # Switch back to Normal mode and verify gating is cleared
        page.evaluate("() => window.setScanMode('normal')")
        page.wait_for_timeout(50)
        gated_after_return = page.evaluate("() => document.querySelectorAll('.cfg-check-item.gated').length")
        assert gated_after_return == 0

        # 5. Assert layout integrity and no console/page errors
        max_allowed = 1000 if width == 768 else None
        ui_harness.assert_no_horizontal_overflow(page, max_allowed=max_allowed)
        ui_harness.assert_no_errors(page)

        # 6. Capture screenshot
        screenshot_path, w, h = ui_harness.capture_screenshot(page, "checks_capability_normal", width)
        assert screenshot_path.is_file()
        assert w == width
    finally:
        page.close()


def test_capability_reader_browser_unavailable_banner(ui_harness: UIHarness):
    """Verify safe presentation when capability reader transitions to unavailable."""
    require_browser()
    page = ui_harness.new_page(width=1280, height=800)

    try:
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        # Open Setup overlay and Checks tab
        page.evaluate("() => { if (typeof openConfigOverlay === 'function') openConfigOverlay(); else document.getElementById('scanConfigOverlay').classList.add('active'); }")
        page.evaluate("() => window.showCfgTab('checks')")
        page.wait_for_selector("#cfgTab-checks.active")

        # Simulate reader failure / unavailable state in browser context
        page.evaluate("""() => {
            const reader = window.VulixCapabilityReader.defaultReader;
            reader.status = 'unavailable';
            reader.errorReason = 'unauthorized';
            reader.errorMessage = '認証が必要です (HTTP 401 Unauthorized)';
            window.renderCheckGroups({}, 'normal');
        }""")
        page.wait_for_timeout(50)

        # Verify #checksUnavailableBanner is visible with reason
        banner_display = page.evaluate("() => window.getComputedStyle(document.getElementById('checksUnavailableBanner')).display")
        assert banner_display != "none"

        reason_text = page.locator("#checksUnavailableReason").inner_text()
        assert "401" in reason_text or "認証" in reason_text

        # Invariant check: isScannerApplicable returns false, never true
        is_sqli_applicable = page.evaluate("() => window.VulixCapabilityReader.defaultReader.isScannerApplicable('sqli')")
        assert is_sqli_applicable is False

        # No uncaught console errors
        ui_harness.assert_no_errors(page)

        screenshot_path, w, h = ui_harness.capture_screenshot(page, "checks_capability_unavailable", 1280)
        assert screenshot_path.is_file()
    finally:
        page.close()
