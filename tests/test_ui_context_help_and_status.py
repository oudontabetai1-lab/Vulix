"""Real-Chromium E2E and integration tests for Context Help Popovers & Cross-Screen Status Bar.

Validates:
1. Help popover opens on click and keyboard (Enter), closes on Escape and outside click.
2. Restores focus to the trigger button upon close.
3. Clamps within 768px and 1280px viewports without horizontal/vertical overflow.
4. Only one popover is open at a time across the page.
5. #scanContext status bar accurately reflects scan ID, execution state, connection state,
   and freshness across route transitions without leaking credentials.
6. Preserves backwards compatibility with existing assertions (Scan <id> · <status>).
"""
from __future__ import annotations

import pytest

from tests.ui_harness import (
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)


def test_help_popover_click_keyboard_and_single_active(ui_harness: UIHarness):
    """Verify help popover opens on click/Enter, closes on Escape/outside, restores focus, and enforces single active popover."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        page.goto(f"{ui_harness.server_url}/app#/setup", wait_until="domcontentloaded")
        page.locator("#setupSurface").wait_for(state="visible")

        # Find help buttons in Setup view
        help_btns = page.locator(".setup-mode-section .setup-check-info")
        help_btns.first.wait_for(state="visible")
        assert help_btns.count() >= 3, "Expected mode help buttons"

        btn1 = help_btns.nth(0)
        btn2 = help_btns.nth(1)

        # 1. Open on click
        btn1.click()
        popover = page.locator(".setup-check-popover")
        popover.wait_for(state="visible")
        assert popover.count() == 1
        assert popover.get_attribute("role") == "dialog"

        # Check heading and sections
        heading = popover.locator("h3")
        assert heading.is_visible()
        heading_id = heading.get_attribute("id")
        assert popover.get_attribute("aria-labelledby") == heading_id
        assert "通常スキャン" in heading.inner_text()

        h4_labels = popover.locator("h4").all_inner_texts()
        assert any("意味" in l or "内容" in l for l in h4_labels)
        assert any("影響" in l or "用途" in l for l in h4_labels)
        assert any("制約" in l for l in h4_labels)

        # 2. Close on outside click and verify popover closes
        page.mouse.click(50, 50)
        popover.wait_for(state="detached")
        assert popover.count() == 0

        # 3. Open via Keyboard (Enter)
        btn1.focus()
        page.keyboard.press("Enter")
        popover = page.locator(".setup-check-popover")
        popover.wait_for(state="visible")
        assert popover.count() == 1

        # 4. Close via Escape and verify focus restored to trigger
        page.keyboard.press("Escape")
        popover.wait_for(state="detached")
        assert popover.count() == 0

        # Focus restored to trigger on Escape
        is_focused = page.evaluate("() => document.activeElement === document.querySelectorAll('.setup-mode-section .setup-check-info')[0]")
        assert is_focused is True

        # 5. Enforce single active popover across page
        btn1.click()
        popover.wait_for(state="visible")
        assert popover.count() == 1
        assert "通常スキャン" in popover.locator("h3").inner_text()

        # Click second button -> previous popover closes, new one opens
        btn2.click()
        popover.wait_for(state="visible")
        assert popover.count() == 1
        assert "Agent" in popover.locator("h3").inner_text()

        # Close via close button and verify focus restoration
        close_btn = popover.locator(".setup-check-popover-close")
        close_btn.click()
        popover.wait_for(state="detached")
        assert popover.count() == 0

        # Focus restored to second trigger
        is_focused2 = page.evaluate("() => document.activeElement === document.querySelectorAll('.setup-mode-section .setup-check-info')[1]")
        assert is_focused2 is True
        assert len(ui_harness.get_errors(page)) == 0
    finally:
        page.close()


@pytest.mark.parametrize("width", [1280, 768])
def test_help_popover_viewport_clamping(ui_harness: UIHarness, width: int):
    """Verify help popover stays completely within viewport at 1280px and 768px widths."""
    require_browser()
    vp = STANDARD_VIEWPORTS[width]
    page = ui_harness.new_page(width=vp["width"], height=vp["height"])

    try:
        page.goto(f"{ui_harness.server_url}/app#/setup", wait_until="domcontentloaded")
        page.locator("#setupSurface").wait_for(state="visible")

        # Open mode help button
        help_btn = page.locator(".setup-mode-section .setup-check-info").first
        help_btn.click()
        popover = page.locator(".setup-check-popover")
        popover.wait_for(state="visible")

        box = popover.bounding_box()
        assert box is not None
        # Clamp left/right
        assert box["x"] >= 6, f"Popover left edge {box['x']} violates left margin 6px"
        assert box["x"] + box["width"] <= width - 4, f"Popover right edge {box['x'] + box['width']} exceeds viewport {width}"

        # Clamp top/bottom
        assert box["y"] >= 6, f"Popover top edge {box['y']} violates top margin 6px"
        assert box["y"] + box["height"] <= vp["height"] - 4, f"Popover bottom edge {box['y'] + box['height']} exceeds viewport height {vp['height']}"

        assert len(ui_harness.get_errors(page)) == 0
    finally:
        page.close()


def test_scan_context_status_bar_rendering_and_redaction(ui_harness: UIHarness):
    """Verify #scanContext status bar structure, status text preservation, credentials redaction, and help trigger."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        page.goto(f"{ui_harness.server_url}/app#/portal", wait_until="domcontentloaded")
        page.locator("#summarySurface").wait_for(state="visible")

        # 1. On Portal with no scan, scanContext should be empty
        scan_ctx = page.locator("#scanContext")
        assert scan_ctx.inner_text() == ""

        # 2. Render status bar with credentialed URL and full state
        secret_pass = "SECRET_PASSWORD_XYZ_987"
        secret_token = "SECRET_API_TOKEN_ABC_123"
        raw_url = f"https://admin:{secret_pass}@api.internal.test:9000/v1/scan?auth_token={secret_token}&debug=true"

        page.evaluate(
            f"""() => {{
              if (window.VulixAppShell && window.VulixAppShell.renderScanStatus) {{
                window.VulixAppShell.renderScanStatus({{
                  scan_id: 'scan_20261116_test01',
                  status: 'scanning',
                  mode: 'hybrid',
                  target: '{raw_url}',
                  phase: 'attack',
                  connection: 'connected',
                  freshness: 'fresh',
                }});
              }}
            }}"""
        )

        page.wait_for_function("() => document.querySelector('#scanContext .scan-status-bar') !== null")
        ctx_text = scan_ctx.inner_text()

        # 3. Substring compatibility check: 'Scan <id> · <status>'
        assert "Scan scan_20261116_test01 · scanning" in ctx_text

        # 4. Mode badge, phase, connection, and freshness badges
        assert "[HYBRID]" in ctx_text or "[hybrid]" in ctx_text
        assert "phase: attack" in ctx_text
        assert "connected" in ctx_text
        assert "fresh" in ctx_text.lower()

        # 5. Strict Credential Redaction Check
        full_html = scan_ctx.evaluate("el => el.innerHTML")
        assert secret_pass not in ctx_text
        assert secret_pass not in full_html
        assert secret_token not in ctx_text
        assert secret_token not in full_html
        assert "<redacted>@" in ctx_text or "<redacted>@" in full_html
        assert "auth_token=<redacted>" in ctx_text or "auth_token=<redacted>" in full_html

        # 6. Status Help Button trigger
        status_help = scan_ctx.locator(".setup-check-info")
        assert status_help.count() == 1
        status_help.click()

        popover = page.locator(".setup-check-popover")
        popover.wait_for(state="visible")
        assert "実行状態と通信状態の分離" in popover.locator("h3").inner_text()
        popover.locator(".setup-check-popover-close").click()
        popover.wait_for(state="detached")

        assert len(ui_harness.get_errors(page)) == 0
    finally:
        page.close()


def test_scan_context_cross_route_transitions(ui_harness: UIHarness):
    """Verify #scanContext correctly reflects scan ID across route transitions (Portal, Monitor, Findings, Crawl, Traffic, Settings)."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        test_scan_id = "20261026_100000"

        # 1. Findings with scan query param
        page.goto(f"{ui_harness.server_url}/app#/findings?scan={test_scan_id}", wait_until="domcontentloaded")
        page.locator("#findingsSurface").wait_for(state="visible")
        page.wait_for_function(f"() => document.querySelector('#scanContext')?.textContent?.includes('{test_scan_id}')")
        assert test_scan_id in page.locator("#scanContext").inner_text()
        assert "snapshot" in page.locator("#scanContext").inner_text()

        # 2. Crawl with scan query param
        page.evaluate(f"() => {{ location.hash = '#/crawl?scan={test_scan_id}'; }}")
        page.locator("#crawlSurface").wait_for(state="visible")
        page.wait_for_function(f"() => document.querySelector('#scanContext')?.textContent?.includes('{test_scan_id}')")
        assert test_scan_id in page.locator("#scanContext").inner_text()

        # 3. Traffic with scan query param
        page.evaluate(f"() => {{ location.hash = '#/traffic?scan={test_scan_id}'; }}")
        page.locator("#trafficSurface").wait_for(state="visible")
        page.wait_for_function(f"() => document.querySelector('#scanContext')?.textContent?.includes('{test_scan_id}')")
        assert test_scan_id in page.locator("#scanContext").inner_text()

        # 4. Settings with scan query param
        page.evaluate(f"() => {{ location.hash = '#/settings?scan={test_scan_id}'; }}")
        page.locator("#settingsSurface").wait_for(state="visible")
        page.wait_for_function(f"() => document.querySelector('#scanContext')?.textContent?.includes('{test_scan_id}')")
        assert test_scan_id in page.locator("#scanContext").inner_text()

        # 5. Clean Portal without scan query param -> clears to empty
        page.evaluate("() => { location.hash = '#/portal'; }")
        page.locator("#summarySurface").wait_for(state="visible")
        page.wait_for_function("() => document.querySelector('#scanContext')?.textContent === ''")
        assert page.locator("#scanContext").inner_text() == ""

        # 6. Portal WITH scan query param -> reflects scan status bar
        page.evaluate(f"() => {{ location.hash = '#/portal?scan={test_scan_id}'; }}")
        page.wait_for_function(f"() => document.querySelector('#scanContext')?.textContent?.includes('{test_scan_id}')")
        assert test_scan_id in page.locator("#scanContext").inner_text()

        assert len(ui_harness.get_errors(page)) == 0
    finally:
        page.close()
