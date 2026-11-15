"""Unit and Playwright Chromium E2E tests for Sidebar Workflow Grouping,
Active Route Navigation, Typography Tokens, and Visual Hierarchy.
"""
from __future__ import annotations

import re
from pathlib import Path
import pytest

from tests.ui_harness import (
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)

ROOT_DIR = Path(__file__).resolve().parent.parent
APP_HTML_PATH = ROOT_DIR / "templates" / "app.html"
TOKENS_CSS_PATH = ROOT_DIR / "templates" / "ui" / "tokens.css"
COMPONENTS_CSS_PATH = ROOT_DIR / "templates" / "ui" / "components.css"


def test_nav_groups_structure_and_accessibility_unit():
    """Verify static app.html contains 4 accessible nav-group sections with labels and 10 buttons."""
    content = APP_HTML_PATH.read_text(encoding="utf-8")

    # 1. Verify 4 nav-group sections with role="group" and aria-labelledby
    groups = re.findall(
        r'<div class="nav-group"\s+role="group"\s+data-nav-group="([^"]+)"\s+aria-labelledby="([^"]+)">',
        content,
    )
    assert len(groups) == 4, f"Expected 4 nav-group elements, found {len(groups)}"

    group_keys = [g[0] for g in groups]
    assert group_keys == ["overview", "scan", "investigation", "operations"]

    for group_key, label_id in groups:
        assert label_id == f"nav-group-{group_key}"
        # Check label element exists
        label_pattern = rf'<div class="nav-group-label" id="{label_id}">([^<]+)</div>'
        match = re.search(label_pattern, content)
        assert match is not None, f"Missing label for group {group_key}"
        assert len(match.group(1).strip()) > 0

    # 2. Verify all 10 buttons are mapped to their respective groups
    expected_group_routes = {
        "overview": ["portal", "history"],
        "scan": ["setup", "monitor"],
        "investigation": ["findings", "crawl", "traffic"],
        "operations": ["audit", "agent-skills", "settings"],
    }

    for group_key, routes in expected_group_routes.items():
        # Find the block for this group
        group_block_match = re.search(
            rf'data-nav-group="{group_key}"[^>]*>(.*?)(?:</div>\s*</div>|</div>\s*<div class="nav-group"|\s*</nav>)',
            content,
            re.DOTALL,
        )
        assert group_block_match is not None, f"Could not find block for {group_key}"
        block = group_block_match.group(1)
        for r in routes:
            assert f'data-route="{r}"' in block, f"Route {r} not in group {group_key}"

    # 3. Verify count badges exist inside investigation buttons
    for route in ["findings", "crawl", "traffic"]:
        badge_pattern = rf'<button[^>]*data-route="{route}"[^>]*>.*?<span class="nav-count-badge" data-nav-badge="{route}" hidden>0</span></button>'
        assert re.search(badge_pattern, content, re.DOTALL) is not None, f"Missing count badge in {route} button"

    # 4. Verify viewGroupBadge exists in header
    assert '<span id="viewGroupBadge" class="view-group-badge">概要</span><strong id="viewTitle">' in content


def test_typography_and_badge_tokens_unit():
    """Verify tokens.css defines required typography tokens and components.css defines badge hierarchy and overflow wrap."""
    tokens_content = TOKENS_CSS_PATH.read_text(encoding="utf-8")

    # Required typography tokens
    expected_tokens = [
        ("--font-size-2xs", "0.7rem"),
        ("--font-size-xs", "0.75rem"),
        ("--font-size-sm", "0.8125rem"),
        ("--font-size-base", "0.875rem"),
        ("--font-size-md", "1rem"),
        ("--font-size-lg", "1.15rem"),
        ("--line-height-tight", "1.25"),
        ("--line-height-base", "1.5"),
        ("--line-height-relaxed", "1.65"),
    ]
    for token_name, expected_val in expected_tokens:
        assert f"{token_name}: {expected_val};" in tokens_content, f"Missing token {token_name}"

    components_content = COMPONENTS_CSS_PATH.read_text(encoding="utf-8")

    # Badge hierarchy classes
    assert ".sev-badge" in components_content
    assert ".verify-badge" in components_content
    assert ".review-badge" in components_content
    assert ".provenance-badge" in components_content
    assert "border-radius: 9999px" in components_content  # pill shape on verify-badge

    # Overflow wrap
    assert "overflow-wrap: anywhere;" in components_content
    assert "word-break: break-word;" in components_content

    # Primary vs Secondary CTA distinction
    assert ".btn-primary" in components_content or ".setup-start-btn" in components_content
    assert ".btn-secondary" in components_content or ".setup-prelaunch-rerun-btn" in components_content


def test_navigation_active_route_and_group_e2e(ui_harness: UIHarness):
    """Verify switching routes updates aria-current, nav-group active state, viewGroupBadge, and viewTitle."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    routes_and_expectations = [
        ("portal", "overview", "概要", "ポータル"),
        ("history", "overview", "概要", "スキャン履歴"),
        ("setup", "scan", "スキャン実行", "Scan Setup"),
        ("monitor", "scan", "スキャン実行", "Monitor"),
        ("findings", "investigation", "結果・調査", "Findings"),
        ("crawl", "investigation", "結果・調査", "Crawl"),
        ("traffic", "investigation", "結果・調査", "Traffic"),
        ("audit", "operations", "運用・設定", "監査ログ"),
        ("agent-skills", "operations", "運用・設定", "Agent Skills"),
        ("settings", "operations", "運用・設定", "Settings"),
    ]

    try:
        page.goto(f"{ui_harness.server_url}/app", wait_until="domcontentloaded")
        page.wait_for_function("() => location.hash.includes('/portal')")

        for route_id, expected_group, expected_group_label, expected_title in routes_and_expectations:
            btn = page.locator(f'[data-route="{route_id}"]')
            btn.click()

            # Wait for button to be marked aria-current="page"
            page.wait_for_function(
                f"() => document.querySelector('[data-route=\"{route_id}\"]')?.getAttribute('aria-current') === 'page'"
            )

            # Check viewGroupBadge
            badge_text = page.locator("#viewGroupBadge").inner_text().strip()
            assert badge_text == expected_group_label, f"Route {route_id}: expected group label {expected_group_label}, got {badge_text}"

            # Check viewTitle
            title_text = page.locator("#viewTitle").inner_text().strip()
            assert title_text == expected_title, f"Route {route_id}: expected title {expected_title}, got {title_text}"

            # Check active nav group
            active_group = page.locator(f'.nav-group[data-nav-group="{expected_group}"]')
            assert active_group.get_attribute("data-active") == "true", f"Route {route_id}: group {expected_group} missing data-active"
            assert "nav-group-active" in (active_group.get_attribute("class") or "")

            # Check other nav groups are inactive
            for other_group in ["overview", "scan", "investigation", "operations"]:
                if other_group != expected_group:
                    og = page.locator(f'.nav-group[data-nav-group="{other_group}"]')
                    assert og.get_attribute("data-active") is None, f"Route {route_id}: other group {other_group} marked active"
                    assert "nav-group-active" not in (og.get_attribute("class") or "")
    finally:
        page.close()


def test_active_scan_id_preservation_e2e(ui_harness: UIHarness):
    """Verify active scan_id query parameter is preserved across compatible route transitions."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        # Load directly with a valid scan_id
        test_scan_id = "test_scan_20261115_01"
        page.goto(f"{ui_harness.server_url}/app#/findings?scan={test_scan_id}", wait_until="domcontentloaded")
        page.wait_for_function("() => location.hash.includes('/findings')")

        # 1. Click crawl -> should retain scan_id
        page.locator('[data-route="crawl"]').click()
        page.wait_for_function(f"() => location.hash.includes('/crawl?scan={test_scan_id}')")
        assert test_scan_id in page.evaluate("() => location.hash")

        # 2. Click traffic -> should retain scan_id
        page.locator('[data-route="traffic"]').click()
        page.wait_for_function(f"() => location.hash.includes('/traffic?scan={test_scan_id}')")
        assert test_scan_id in page.evaluate("() => location.hash")

        # 3. Click setup -> should retain scan_id
        page.locator('[data-route="setup"]').click()
        page.wait_for_function(f"() => location.hash.includes('/setup?scan={test_scan_id}')")
        assert test_scan_id in page.evaluate("() => location.hash")

        # 4. Click history -> history does not support scan query, should cleanly omit it
        page.locator('[data-route="history"]').click()
        page.wait_for_function("() => location.hash === '#/history'")
        assert page.evaluate("() => location.hash") == "#/history"
    finally:
        page.close()


def test_live_scan_counts_update_badges_e2e(ui_harness: UIHarness):
    """Verify live scan summary counts update data-nav-count attributes and display badges on investigation buttons."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        page.goto(f"{ui_harness.server_url}/app", wait_until="domcontentloaded")
        page.wait_for_function("() => location.hash.includes('/portal')")

        # Initially badges should be hidden
        for route in ["findings", "crawl", "traffic"]:
            badge = page.locator(f'[data-nav-badge="{route}"]')
            assert badge.is_hidden()

        # Update counts via VulixAppEntry.updateNavCounts
        page.evaluate("""() => {
            window.VulixAppEntry.updateNavCounts({
                findings_count: 7,
                crawled_urls_count: 24,
                traffic_count: 153,
            });
        }""")

        # Verify buttons have data-nav-count and badges are visible with correct counts
        f_btn = page.locator('[data-route="findings"]')
        assert f_btn.get_attribute("data-nav-count") == "7"
        f_badge = page.locator('[data-nav-badge="findings"]')
        assert f_badge.is_visible()
        assert f_badge.inner_text().strip() == "7"

        c_btn = page.locator('[data-route="crawl"]')
        assert c_btn.get_attribute("data-nav-count") == "24"
        c_badge = page.locator('[data-nav-badge="crawl"]')
        assert c_badge.is_visible()
        assert c_badge.inner_text().strip() == "24"

        t_btn = page.locator('[data-route="traffic"]')
        assert t_btn.get_attribute("data-nav-count") == "153"
        t_badge = page.locator('[data-nav-badge="traffic"]')
        assert t_badge.is_visible()
        assert t_badge.inner_text().strip() == "153"

        # Update with 0 / null counts -> badges should be hidden and attributes removed
        page.evaluate("""() => {
            window.VulixAppEntry.updateNavCounts(null);
        }""")
        for route in ["findings", "crawl", "traffic"]:
            btn = page.locator(f'[data-route="{route}"]')
            assert btn.get_attribute("data-nav-count") is None
            badge = page.locator(f'[data-nav-badge="{route}"]')
            assert badge.is_hidden()
    finally:
        page.close()


def test_responsive_navigation_and_keyboard_a11y_e2e(ui_harness: UIHarness):
    """Verify responsive layouts at 1280x800 and 768x900 without horizontal overflow and full keyboard operability."""
    require_browser()

    # Test viewports
    for width, height in [(1280, 800), (768, 900)]:
        page = ui_harness.new_page(width=width, height=height)
        try:
            page.goto(f"{ui_harness.server_url}/app#/portal", wait_until="domcontentloaded")
            page.wait_for_selector("#summarySurface", state="visible")

            # 1. No horizontal overflow
            ui_harness.assert_no_horizontal_overflow(page)

            # 2. Check aside has vertical scroll behavior on compact height
            aside_overflow_y = page.evaluate("() => window.getComputedStyle(document.querySelector('aside')).overflowY")
            assert aside_overflow_y in ("auto", "scroll"), f"Expected aside overflow-y auto or scroll, got {aside_overflow_y}"

            # 3. Test keyboard navigation: Tab to portal button and press Enter to navigate
            portal_btn = page.locator('[data-route="portal"]')
            portal_btn.focus()
            ui_harness.assert_focus_visible(page, '[data-route="portal"]')

            # Tab through all 10 buttons
            for route in ["history", "setup", "monitor", "findings", "crawl", "traffic", "audit", "agent-skills", "settings"]:
                page.keyboard.press("Tab")
                focused_route = page.evaluate("() => document.activeElement ? document.activeElement.getAttribute('data-route') : null")
                assert focused_route == route, f"Expected focus on {route}, got {focused_route}"
                ui_harness.assert_focus_visible(page, f'[data-route="{route}"]')

            # Press Enter on settings button -> navigates to settings
            page.keyboard.press("Enter")
            page.wait_for_function("() => location.hash.includes('/settings') && document.querySelector('[data-route=\"settings\"]').getAttribute('aria-current') === 'page'")
            assert page.locator("#settingsSurface").is_visible()

            # 4. Zoom test: 200% zoom does not produce horizontal overflow
            page.evaluate("() => { document.body.style.zoom = '200%'; }")
            page.wait_for_timeout(100)
            ui_harness.assert_no_horizontal_overflow(page)
            page.evaluate("() => { document.body.style.zoom = '100%'; }")
        finally:
            page.close()


def test_typography_tokens_and_badge_hierarchy_computed_styles_e2e(ui_harness: UIHarness):
    """Verify computed font sizes, line heights, and visual hierarchy for sev, verify, review, and provenance badges."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        page.goto(f"{ui_harness.server_url}/app#/findings", wait_until="domcontentloaded")
        page.wait_for_selector("#findingsSurface", state="visible")

        # 1. Check computed typography CSS custom properties on :root
        tokens = page.evaluate("""() => {
            const cs = window.getComputedStyle(document.documentElement);
            return {
                fs2xs: cs.getPropertyValue('--font-size-2xs').trim(),
                fsSm: cs.getPropertyValue('--font-size-sm').trim(),
                fsMd: cs.getPropertyValue('--font-size-md').trim(),
                lhTight: cs.getPropertyValue('--line-height-tight').trim(),
                lhBase: cs.getPropertyValue('--line-height-base').trim(),
            };
        }""")
        assert tokens["fs2xs"] == "0.7rem"
        assert tokens["fsSm"] == "0.8125rem"
        assert tokens["fsMd"] == "1rem"
        assert tokens["lhTight"] == "1.25"
        assert tokens["lhBase"] == "1.5"

        # 2. Check visual hierarchy difference between badges:
        # Create temporary badge elements in the DOM to measure computed styles
        hierarchy = page.evaluate("""() => {
            const container = document.createElement('div');
            container.innerHTML = `
                <span class="sev-badge sev-critical">CRITICAL</span>
                <span class="verify-badge verify-reproduced">REPRODUCED</span>
                <span class="review-badge review-reviewed">REVIEWED</span>
                <span class="provenance-badge provenance-agent">AGENT</span>
            `;
            document.body.appendChild(container);

            const sev = window.getComputedStyle(container.querySelector('.sev-badge'));
            const verify = window.getComputedStyle(container.querySelector('.verify-badge'));
            const review = window.getComputedStyle(container.querySelector('.review-badge'));
            const prov = window.getComputedStyle(container.querySelector('.provenance-badge'));

            const result = {
                sevWeight: parseInt(sev.fontWeight, 10),
                verifyWeight: parseInt(verify.fontWeight, 10),
                reviewWeight: parseInt(review.fontWeight, 10),
                provWeight: parseInt(prov.fontWeight, 10),
                verifyBorderRadius: verify.borderRadius,
                reviewOpacity: parseFloat(review.opacity),
            };
            container.remove();
            return result;
        }""")

        # Primary (.sev-badge): 700 bold weight
        assert hierarchy["sevWeight"] >= 700
        # Secondary (.verify-badge): 600 weight, distinct pill shape
        assert hierarchy["verifyWeight"] >= 600
        assert "9999px" in hierarchy["verifyBorderRadius"] or "50%" in hierarchy["verifyBorderRadius"] or int(hierarchy["verifyBorderRadius"].replace("px", "").split()[0]) >= 20
        # Tertiary (.review-badge, .provenance-badge): subtle compact weight <= 500, opacity < 1
        assert hierarchy["reviewWeight"] <= 500
        assert hierarchy["provWeight"] <= 500
        assert hierarchy["reviewOpacity"] < 1.0
    finally:
        page.close()
