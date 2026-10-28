"""Regression smoke tests for Portal, Monitor (3 panes), and Setup on UI test harness.

Verifies:
1. Portal initial render and responsive layout at 1440, 1280, and 768 viewports:
   - Header, status pill, search input, and seeded scan table rows.
   - Interactive search filtering.
   - Computed design tokens (background, typography).
   - Zero console/page errors and no unbounded horizontal overflow.
   - Screenshot capture with PIL-free PNG IHDR dimension validation.

2. Monitor 3-pane layout at 1440, 1280, and 768 viewports:
   - Navigation rail (Live Monitor, Scan History, Audit Log).
   - Left pane: Event Log.
   - Center pane: Scan Workspace (sitemap graph tabs).
   - Right pane: Findings panel and Network activity.
   - Deterministic live event injection updates badge counts and panels.
   - Zero console/page errors and no unbounded horizontal overflow.
   - Screenshot capture with PIL-free PNG IHDR dimension validation.

3. Setup configuration overlay and tabs at 1440, 1280, and 768 viewports:
   - Opening configuration overlay via new-scan trigger.
   - Tab switching across existing Setup tabs (basic, checks, auth, llm, features, exclusions, etc.).
   - Key inputs and controls rendered properly.
   - Zero console/page errors and no unbounded horizontal overflow.
   - Screenshot capture with PIL-free PNG IHDR dimension validation.
"""
from __future__ import annotations

import pytest

from tests.ui_harness import (
    parse_png_dimensions,
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)

VIEWPORT_WIDTHS = [1440, 1280, 768]


@pytest.mark.parametrize("width", VIEWPORT_WIDTHS)
def test_portal_responsive_smoke(ui_harness: UIHarness, width: int):
    """Verify Portal rendering, scan history table, search filter, tokens, and screenshots."""
    require_browser()
    vp = STANDARD_VIEWPORTS[width]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    try:
        page.goto(f"{ui_harness.server_url}/")
        page.wait_for_selector("#nowPill")
        page.wait_for_selector("#scanRows tr")

        # 1. Verify key Portal elements exist
        assert page.is_visible("#nowPill")
        assert page.is_visible("#newScanBtn")
        assert page.is_visible("#histSearch")

        # 2. Verify all seeded baseline scans render in the table
        rows = page.locator("#scanRows tr")
        row_count = rows.count()
        assert row_count == 3, f"Expected 3 seeded scans, found {row_count}"

        # Verify expected targets are present
        table_text = page.locator("#scanRows").inner_text()
        assert "store.internal.local" in table_text
        assert "api.internal.local" in table_text
        assert "admin.internal.local" in table_text

        # 3. Test interactive search filter
        search_input = page.locator("#histSearch")
        search_input.fill("store")
        page.wait_for_timeout(100)
        filtered_count = page.locator("#scanRows tr").count()
        assert filtered_count == 1, f"Expected 1 scan matching 'store', got {filtered_count}"

        # Clear search
        search_input.fill("")
        page.wait_for_timeout(100)
        assert page.locator("#scanRows tr").count() == 3

        # 4. Computed token check
        bg_style = page.evaluate("() => window.getComputedStyle(document.body).backgroundImage")
        token_bg = page.evaluate("() => window.getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()")
        assert "radial-gradient" in bg_style or token_bg == "#070b14", f"Unexpected background style: {bg_style}, token: {token_bg}"

        # 5. Assert layout integrity (desktop exact, 768 bounded) and no console errors
        max_allowed = 900 if width == 768 else None
        ui_harness.assert_no_horizontal_overflow(page, max_allowed=max_allowed)
        ui_harness.assert_no_errors(page)

        # 6. Capture screenshot and verify dimensions via PNG IHDR
        screenshot_path, w, h = ui_harness.capture_screenshot(page, "portal", width)
        assert screenshot_path.is_file()
        assert w == width
    finally:
        page.close()


@pytest.mark.parametrize("width", VIEWPORT_WIDTHS)
def test_monitor_three_panes_responsive_smoke(ui_harness: UIHarness, width: int):
    """Verify Monitor 3-pane layout, event injection, findings update, tokens, and screenshots."""
    require_browser()
    vp = STANDARD_VIEWPORTS[width]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    try:
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        # 1. Navigation rail presence (rail on desktop >= 1280, top nav on <= 1200)
        if width >= 1280:
            assert page.is_visible("#navLiveMonitor")
            assert page.is_visible("#navScanHistory")
            assert page.is_visible("#navAuditLog")

        # 2. Verify 3-pane structure
        # Left pane: Event log
        assert page.is_visible("#eventLog")
        assert page.is_visible("#eventCount")

        # Center pane: Scan Workspace with tabs
        assert page.is_visible("#sitemapContainer")
        assert page.is_visible("#ctab-sitemap")
        assert page.is_visible("#ctab-browser")
        assert page.is_visible("#ctab-progress")

        # Right pane: Findings panel and network activity
        assert page.is_visible("#findingsPanel")
        assert page.is_visible("#findingCount")

        # 3. Inject deterministic live monitor baseline events
        ui_harness.populate_live_monitor(page)

        # Verify badge and list updates
        event_count_text = page.locator("#eventCount").inner_text()
        assert int(event_count_text) >= 5, f"Expected event count >= 5, got {event_count_text}"

        finding_count_text = page.locator("#findingCount").inner_text()
        assert int(finding_count_text) >= 1, f"Expected finding count >= 1, got {finding_count_text}"

        # Verify finding card rendered in right panel
        findings_text = page.locator("#findingsPanel").inner_text()
        assert "xss" in findings_text.lower() or "critical" in findings_text.lower()

        # 4. Center tab switching interactivity
        page.click("#ctab-browser")
        page.wait_for_timeout(50)
        assert "active" in (page.locator("#ctab-browser").get_attribute("class") or "")

        page.click("#ctab-sitemap")
        page.wait_for_timeout(50)
        assert "active" in (page.locator("#ctab-sitemap").get_attribute("class") or "")

        # 5. Computed token check: extracted design tokens from tokens.css
        token_bg = page.evaluate("() => window.getComputedStyle(document.documentElement).getPropertyValue('--bg').trim()")
        token_accent = page.evaluate("() => window.getComputedStyle(document.documentElement).getPropertyValue('--accent').trim()")
        assert token_bg == "#161826", f"Expected --bg #161826, got {token_bg}"
        assert token_accent == "#9184d9", f"Expected --accent #9184d9, got {token_accent}"

        # 6. Assert layout integrity (desktop exact, 768 bounded)
        max_allowed = 1000 if width == 768 else None
        ui_harness.assert_no_horizontal_overflow(page, max_allowed=max_allowed)
        ui_harness.assert_no_errors(page)

        # 7. Screenshot capture and IHDR dimension assertion
        screenshot_path, w, h = ui_harness.capture_screenshot(page, "monitor_three_panes", width)
        assert screenshot_path.is_file()
        assert w == width
    finally:
        page.close()


@pytest.mark.parametrize("width", VIEWPORT_WIDTHS)
def test_setup_tabs_responsive_smoke(ui_harness: UIHarness, width: int):
    """Verify Setup configuration overlay, tab navigation, input fields, and screenshots."""
    require_browser()
    vp = STANDARD_VIEWPORTS[width]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    try:
        page.goto(f"{ui_harness.server_url}/monitor")
        page.wait_for_selector(".main")

        # 1. Open Setup configuration overlay via real UI trigger button
        if page.is_visible(".ws-newscan"):
            page.click(".ws-newscan")
        elif page.is_visible(".hdr-newscan"):
            page.click(".hdr-newscan")
        else:
            page.evaluate("() => document.getElementById('scanConfigOverlay').classList.add('active')")
        page.wait_for_selector("#scanConfigOverlay.active")
        assert page.is_visible("#scanConfigOverlay")

        # 2. Verify target URL row and Basic tab (initial active tab)
        assert page.is_visible("#cfgInputUrl")
        assert page.is_visible("#cfgTab-basic")
        assert page.is_visible("#cfgDepth")

        # 3. Test switching across key configuration tabs
        tabs_to_verify = [
            ("checks", "#cfgTab-checks"),
            ("auth", "#cfgTab-auth"),
            ("llm", "#cfgTab-llm"),
            ("features", "#cfgTab-features"),
            ("exclusions", "#cfgTab-exclusions"),
            ("manualcrawl", "#cfgTab-manualcrawl"),
            ("flows", "#cfgTab-flows"),
            ("agent", "#cfgTab-agent"),
            ("hybrid", "#cfgTab-hybrid"),
            ("basic", "#cfgTab-basic"),
        ]

        for tab_name, panel_selector in tabs_to_verify:
            page.evaluate(f"() => window.showCfgTab('{tab_name}')")
            page.wait_for_timeout(50)
            assert page.is_visible(panel_selector), f"Panel {panel_selector} not visible after selecting tab {tab_name}"

        # 4. Check that target URL input is functional
        target_input = page.locator("#cfgInputUrl")
        target_input.fill("http://test-target.internal")
        assert target_input.input_value() == "http://test-target.internal"

        # 5. Assert layout integrity (overlay has internal scrolling if needed) and no console errors
        max_allowed = 1000 if width == 768 else None
        ui_harness.assert_no_horizontal_overflow(page, max_allowed=max_allowed)
        ui_harness.assert_no_errors(page)

        # 6. Screenshot capture of active setup overlay and IHDR dimension assertion
        screenshot_path, w, h = ui_harness.capture_screenshot(page, "setup_tabs", width)
        assert screenshot_path.is_file()
        assert w == width
    finally:
        page.close()
