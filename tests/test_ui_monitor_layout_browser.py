"""Browser-based tests for Monitor responsive layout reachability and pane controls.

Validates Monitor pane layout reachability:
- Collapsed Monitor panes remain reachable at narrow widths (640px, 768px, 200% zoom).
- Preset controls and pane restore affordances remain visible and operational.
- Desktop preferences and widths are preserved when transitioning between wide and narrow.
- Keyboard, focus-visible, and ARIA accessibility across all viewports.
- Clean persistence under versioned storage key without secret/scan leakage.
"""
from __future__ import annotations

import json
import time
from typing import Any

import pytest
from tests.ui_harness import UIHarness, require_browser, ui_harness


def _wait_for_websocket_count(page: Any, sockets: list[str], expected: int, timeout_s: float = 5.0) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        if len(sockets) >= expected:
            return
        page.wait_for_timeout(50)
    assert len(sockets) >= expected, f"expected {expected} websockets, got {len(sockets)}"


def test_narrow_monitor_can_reach_all_panes_repro(ui_harness: UIHarness):
    """Reproduction and green verification: log-focused at 1440px -> resize to 640px keeps Findings and toolbar visible."""
    require_browser()
    page = ui_harness.new_page(width=1440, height=900)
    try:
        page.goto(f"{ui_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )
        host = page.locator("#monitorModule")

        # 1. Click log-focused preset at wide (1440px), which collapses right pane (Findings)
        host.locator('[data-preset="log-focused"]').click()
        page.wait_for_timeout(100)

        # 2. Resize to narrow (640x800)
        page.set_viewport_size({"width": 640, "height": 800})
        page.wait_for_timeout(150)

        # 3. Assert right panel (Findings) and preset toolbar are both visible
        panel_right = host.locator(".main > .panel").nth(2)
        toolbar = host.locator(".monitor-layout-toolbar")

        assert toolbar.is_visible(), "Preset toolbar must remain visible at narrow viewport (640px)"
        assert panel_right.is_visible(), "Saved collapsed pane must remain reachable/visible at narrow viewport (640px)"

        # 4. Verify browser-focused preset (collapses left pane / Event Log)
        host.locator('[data-preset="browser-focused"]').click()
        page.wait_for_timeout(100)
        panel_left = host.locator(".main > .panel").nth(0)
        assert panel_left.is_visible(), "Collapsed left pane must remain reachable/visible at narrow viewport"
        assert toolbar.is_visible(), "Preset toolbar must remain visible"
    finally:
        page.close()


def test_monitor_wide_narrow_restore_wide_cycle(ui_harness: UIHarness):
    """Verify selecting preset at wide -> narrow -> restore -> wide retains preferences and reachability."""
    require_browser()
    page = ui_harness.new_page(width=1440, height=900)
    try:
        page.goto(f"{ui_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )
        host = page.locator("#monitorModule")

        # Step 1: Wide (1440px) - select log-focused preset (left wide, right collapsed)
        host.locator('[data-preset="log-focused"]').click()
        page.wait_for_timeout(100)

        is_right_col_wide = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[2].classList.contains('is-collapsed')"
        )
        assert is_right_col_wide is True

        # Step 2: Transition to narrow (640x800)
        page.set_viewport_size({"width": 640, "height": 800})
        page.wait_for_timeout(150)

        # In narrow mode, collapsed pane renders horizontal affordance bar
        right_panel = host.locator(".main > .panel").nth(2)
        assert right_panel.is_visible()

        collapsed_bar = host.locator('.pane-collapsed-bar[data-pane="right"]')
        assert collapsed_bar.is_visible(), "Horizontal collapsed bar must be visible on collapsed Findings pane"
        assert collapsed_bar.get_attribute("role") == "button"
        assert collapsed_bar.get_attribute("tabindex") == "0"
        assert "Findings" in (collapsed_bar.get_attribute("aria-label") or "")

        # Expand button inside bar
        expand_btn = collapsed_bar.locator('.pane-header-btn[data-action="expand"]')
        assert expand_btn.is_visible()

        # Step 3: Restore affordance test - click collapsed bar to expand Findings
        collapsed_bar.click()
        page.wait_for_timeout(100)

        is_right_col_narrow_after = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[2].classList.contains('is-collapsed')"
        )
        assert is_right_col_narrow_after is False, "Findings pane must expand upon clicking collapsed bar"
        assert host.locator("#findingsPanel").is_visible(), "Findings content must be visible when expanded"

        # Step 4: Re-collapse using pane header collapse button at narrow
        collapse_btn = host.locator('.pane-header-btn.btn-collapse[data-pane="right"]')
        assert collapse_btn.is_visible(), "Header actions must remain accessible at narrow viewport"
        collapse_btn.click()
        page.wait_for_timeout(100)

        is_recollapsed = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[2].classList.contains('is-collapsed')"
        )
        assert is_recollapsed is True

        # Step 5: Restore via layout toolbar preset button
        host.locator('[data-preset="standard"]').click()
        page.wait_for_timeout(100)
        is_all_expanded = page.evaluate(
            """() => {
                const panels = document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel');
                return Array.from(panels).every(p => !p.classList.contains('is-collapsed'));
            }"""
        )
        assert is_all_expanded is True

        # Step 6: Return to wide (1440x900)
        page.set_viewport_size({"width": 1440, "height": 900})
        page.wait_for_timeout(150)

        # Separators and 3-pane layout must be interactive again
        sep_left = host.locator("#sepLeft")
        assert sep_left.is_visible()
        sep_right = host.locator("#sepRight")
        assert sep_right.is_visible()
    finally:
        page.close()


def test_monitor_keyboard_accessibility_and_focus(ui_harness: UIHarness):
    """Verify keyboard navigation, ARIA states, and focus-visible across responsive widths."""
    require_browser()
    page = ui_harness.new_page(width=640, height=800)
    try:
        page.goto(f"{ui_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )
        host = page.locator("#monitorModule")

        # 1. Toolbar ARIA and pressed states
        toolbar = host.locator(".monitor-layout-toolbar")
        assert toolbar.get_attribute("role") == "toolbar"
        assert toolbar.get_attribute("aria-label") == "レイアウトプリセット"

        std_btn = host.locator('[data-preset="standard"]')
        assert std_btn.get_attribute("aria-pressed") == "true"

        # 2. Switch to log-focused and test collapsed bar keyboard activation (Enter)
        host.locator('[data-preset="log-focused"]').click()
        page.wait_for_timeout(100)

        right_bar = host.locator('.pane-collapsed-bar[data-pane="right"]')
        assert right_bar.is_visible()
        right_bar.focus()

        # Check visible focus styling
        focus_info = page.evaluate(
            """() => {
                const bar = document.querySelector('#monitorModule').shadowRoot.querySelector('.pane-collapsed-bar[data-pane="right"]');
                const cs = getComputedStyle(bar);
                return {
                    outlineStyle: cs.outlineStyle,
                    outlineWidth: parseFloat(cs.outlineWidth),
                };
            }"""
        )
        assert focus_info["outlineStyle"] != "none" and focus_info["outlineWidth"] > 0

        # Press Enter on focused collapsed bar to expand
        page.keyboard.press("Enter")
        page.wait_for_timeout(100)

        is_expanded = page.evaluate(
            "() => !document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[2].classList.contains('is-collapsed')"
        )
        assert is_expanded is True

        # 3. Test multi-width responsiveness without horizontal overflow
        for w in (1440, 1280, 768, 640):
            page.set_viewport_size({"width": w, "height": 800})
            page.wait_for_timeout(50)
            ui_harness.assert_no_horizontal_overflow(page, max_allowed=w + 2)
    finally:
        page.close()


def test_monitor_persisted_layout_reload_and_no_leakage(ui_harness: UIHarness):
    """Verify stored preferences survive reload, reject secrets/scan state, and maintain single WebSocket."""
    require_browser()
    page = ui_harness.new_page(width=1440, height=900)
    sockets: list[str] = []
    page.on("websocket", lambda ws: sockets.append(ws.url))

    try:
        page.goto(f"{ui_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )
        host = page.locator("#monitorModule")

        # Select browser-focused preset
        host.locator('[data-preset="browser-focused"]').click()
        page.wait_for_timeout(100)

        # Verify single persistent websocket
        _wait_for_websocket_count(page, sockets, 1)
        assert len(sockets) == 1

        # Check localStorage contents
        stored_raw = page.evaluate("() => localStorage.getItem('vulix:monitor-layout:v1')")
        assert stored_raw is not None
        stored = json.loads(stored_raw)
        assert stored["version"] == 1
        assert stored["preset"] == "browser-focused"
        assert stored["collapsed"]["left"] is True

        # Safety: no secrets, scan IDs, or history mixed into layout key
        for forbidden in ("token", "password", "bearer", "scanId", "secret", "findings"):
            assert forbidden not in stored_raw.lower()

        # Resize to narrow (640x800) and reload
        page.set_viewport_size({"width": 640, "height": 800})
        page.reload(wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )

        host_after = page.locator("#monitorModule")
        # Preserved browser-focused: left panel is collapsed but reachable via collapsed bar
        left_bar = host_after.locator('.pane-collapsed-bar[data-pane="left"]')
        assert left_bar.is_visible()
        toolbar = host_after.locator(".monitor-layout-toolbar")
        assert toolbar.is_visible()
        assert host_after.locator('[data-preset="browser-focused"]').get_attribute("aria-pressed") == "true"

        # Corrupted storage recovery test
        page.evaluate("() => localStorage.setItem('vulix:monitor-layout:v1', '{invalid json payload')")
        page.reload(wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )
        # Should gracefully fall back to standard preset without crash
        host_fallback = page.locator("#monitorModule")
        assert host_fallback.locator('[data-preset="standard"]').is_visible()
    finally:
        page.close()


def test_monitor_200_percent_zoom_reachability(ui_harness: UIHarness):
    """Verify effective widths at 200% zoom (720x450 and 640x400) maintain pane and toolbar reachability."""
    require_browser()
    page = ui_harness.new_page(width=1440, height=900)
    try:
        page.goto(f"{ui_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function(
            '() => Boolean(document.querySelector("#monitorModule")?.shadowRoot?.querySelector("#sepLeft"))'
        )
        host = page.locator("#monitorModule")

        # Test both 720x450 (1440/2) and 640x400 (1280/2)
        for w, h in [(720, 450), (640, 400)]:
            page.set_viewport_size({"width": w, "height": h})
            page.wait_for_timeout(100)

            # Select log-focused
            host.locator('[data-preset="log-focused"]').click()
            page.wait_for_timeout(100)

            panel_right = host.locator(".main > .panel").nth(2)
            toolbar = host.locator(".monitor-layout-toolbar")

            assert toolbar.is_visible(), f"Toolbar must be visible at {w}x{h}"
            assert panel_right.is_visible(), f"Findings pane must be reachable at {w}x{h}"

            # Restore to standard
            host.locator('[data-preset="standard"]').click()
            page.wait_for_timeout(100)

            ui_harness.assert_no_horizontal_overflow(page, max_allowed=w + 2)
    finally:
        page.close()
