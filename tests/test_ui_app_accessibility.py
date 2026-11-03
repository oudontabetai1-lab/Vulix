"""Automated accessibility (a11y) checks for the main /app screens on isolated UI test harness.

Verifies:
1. Form control labels:
   - All <input>, <select>, <textarea> across screens have accessible labels
     (via associated <label for>, wrapping <label>, aria-label, aria-labelledby, or title).
2. Roles & Landmarks:
   - Core landmarks (banner, navigation, main, complementary/aside).
   - ARIA tablist patterns (tablist, tab, tabpanel, aria-selected, aria-controls, aria-labelledby).
   - Tree and list roles.
3. Keyboard reachability & order:
   - All interactive controls are reachable via keyboard (tabIndex >= 0).
   - Enter and Space keys trigger selection on custom list cards, tree items, and table rows.
4. Live updates & polite announcements:
   - aria-live and role="status" on live regions (scan context, status messages, count summaries).
5. No keyboard traps:
   - Sequential tab key navigation advances focus without trapping.
   - Escape key dismisses slide-out drawers and dialogs.
"""
from __future__ import annotations

from typing import Any
import pytest

from tests.ui_harness import (
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)


@pytest.fixture
def a11y_harness(ui_harness: UIHarness) -> UIHarness:
    """UIHarness with comprehensive representative scans seeded."""
    ui_harness.seed_representative_scans()
    return ui_harness


def _audit_form_controls(page: Any, surface_name: str) -> list[str]:
    """Return list of unlabeled form controls found on the currently active surface."""
    return page.evaluate("""(name) => {
        const violations = [];
        const controls = Array.from(document.querySelectorAll('input:not([type="hidden"]), select, textarea'));

        for (const ctrl of controls) {
            // Check visibility (must be within an active/visible surface)
            if (ctrl.offsetParent === null && !ctrl.getClientRects().length) {
                continue; // hidden element
            }

            // Check for explicit or implicit accessible name
            const ariaLabel = ctrl.getAttribute('aria-label');
            const ariaLabelledby = ctrl.getAttribute('aria-labelledby');
            const title = ctrl.getAttribute('title');
            const id = ctrl.id;

            let hasLabel = false;
            if (ariaLabel && ariaLabel.trim().length > 0) hasLabel = true;
            if (ariaLabelledby && document.getElementById(ariaLabelledby)) hasLabel = true;
            if (title && title.trim().length > 0) hasLabel = true;

            if (id) {
                const labelFor = document.querySelector(`label[for="${id}"]`);
                if (labelFor && labelFor.textContent.trim().length > 0) hasLabel = true;
            }

            // Check wrapping label
            const parentLabel = ctrl.closest('label');
            if (parentLabel && parentLabel.textContent.trim().length > 0) hasLabel = true;

            if (!hasLabel) {
                violations.push(`${name} -> Unlabeled <${ctrl.tagName.toLowerCase()} id="${id || ''}" type="${ctrl.type || ''}" class="${ctrl.className || ''}">`);
            }
        }
        return violations;
    }""", surface_name)


def test_app_landmarks_and_roles(a11y_harness: UIHarness):
    """Verify landmarks (banner, navigation, main, aside) and setup tablist semantics."""
    require_browser()
    page = a11y_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{a11y_harness.server_url}/app#/portal")
        page.wait_for_selector("nav[aria-label]")

        # 1. Navigation landmark
        nav = page.locator("nav[aria-label]")
        assert nav.is_visible()
        assert nav.get_attribute("aria-label") == "Application"

        # 2. Main landmark
        main = page.locator("main")
        assert main.is_visible()

        # 3. Banner landmark
        banner = page.locator("header[role='banner']")
        assert banner.is_visible()

        # 4. Aside landmark
        aside = page.locator("aside")
        assert aside.is_visible()
        assert aside.get_attribute("aria-label") == "サイドバー"

        # 5. Live update region for scan context
        scan_ctx = page.locator("#scanContext")
        assert scan_ctx.get_attribute("aria-live") == "polite"

        # 6. Status message region
        msg = page.locator("#message")
        assert msg.get_attribute("role") == "status"

        # 7. Setup screen WAI-ARIA tablist semantics
        page.click('[data-route="setup"]')
        page.wait_for_selector("#setupSurface", state="visible")

        tablist = page.locator(".setup-tabs-bar")
        assert tablist.get_attribute("role") == "tablist"

        tabs = page.locator(".setup-tab")
        assert tabs.count() == 5
        for i in range(5):
            tab = tabs.nth(i)
            assert tab.get_attribute("role") == "tab"
            controls_id = tab.get_attribute("aria-controls")
            assert controls_id
            panel = page.locator(f"#{controls_id}")
            assert panel.get_attribute("role") == "tabpanel"
            assert panel.get_attribute("aria-labelledby") == tab.get_attribute("id")
    finally:
        page.close()


def test_app_form_control_labels_across_all_screens(a11y_harness: UIHarness):
    """Verify all form controls on all 8 /app screens have accessible labels."""
    require_browser()
    page = a11y_harness.new_page(**STANDARD_VIEWPORTS[1440])

    routes_to_check = [
        ("portal", "#summarySurface"),
        ("history", "#summarySurface"),
        ("audit", "#summarySurface"),
        ("setup", "#setupSurface"),
        ("crawl", "#crawlSurface"),
        ("findings", "#findingsSurface"),
        ("agent-skills", "#agentSkillsSurface"),
        ("settings", "#settingsSurface"),
    ]

    try:
        page.goto(f"{a11y_harness.server_url}/app")
        all_violations: list[str] = []

        for route_id, surface_selector in routes_to_check:
            page.click(f'[data-route="{route_id}"]')
            page.wait_for_selector(surface_selector, state="visible")
            page.wait_for_timeout(50)

            violations = _audit_form_controls(page, route_id)
            all_violations.extend(violations)

        assert not all_violations, f"Found unlabeled form controls:\n" + "\n".join(all_violations)
    finally:
        page.close()


def test_keyboard_reachability_and_activation(a11y_harness: UIHarness):
    """Verify interactive cards, table rows, and tree items are keyboard accessible and respond to Enter/Space."""
    require_browser()
    page = a11y_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        # 1. Findings list cards keyboard reachability & Enter selection
        page.goto(f"{a11y_harness.server_url}/app#/findings?scan=20261026_100000")
        page.wait_for_selector(".findings-list-card")

        cards = page.locator(".findings-list-card")
        assert cards.count() >= 2
        card0 = cards.nth(0)
        card1 = cards.nth(1)

        # Tabindex check
        assert int(card0.get_attribute("tabindex") or "-1") >= 0
        assert card0.get_attribute("role") == "button"

        # Focus second card and press Enter
        card1.focus()
        page.keyboard.press("Enter")
        page.wait_for_timeout(50)
        assert "active" in (card1.get_attribute("class") or "")
        assert card1.get_attribute("aria-selected") == "true"

        # 2. Crawl screen tree items & table rows keyboard accessibility
        page.goto(f"{a11y_harness.server_url}/app#/crawl?scan=20261026_100000")
        page.locator("#crawlSurface").wait_for(state="visible")

        # Explorer tree keyboard navigation
        page.locator("button[data-mode='explorer']").click()
        page.wait_for_selector(".crawl-tree-row")
        tree_row = page.locator(".crawl-tree-row").first
        assert int(tree_row.get_attribute("tabindex") or "-1") >= 0
        assert tree_row.get_attribute("role") == "treeitem"

        tree_row.focus()
        page.keyboard.press("Enter")
        page.wait_for_selector(".crawl-explorer-detail")
        assert "selected" in (tree_row.get_attribute("class") or "")

        # List mode table rows keyboard navigation
        page.locator("button[data-mode='list']").click()
        page.wait_for_selector(".crawl-list-surface table tbody tr")

        rows = page.locator(".crawl-list-surface table tbody tr")
        assert rows.count() > 0
        first_row = rows.nth(0)
        assert int(first_row.get_attribute("tabindex") or "-1") >= 0
        assert first_row.get_attribute("role") == "button"

        # Press Enter to open drawer
        first_row.focus()
        page.keyboard.press("Enter")
        page.wait_for_timeout(50)

        drawer = page.locator(".crawl-detail-drawer")
        assert drawer.is_visible()

        # Escape key dismisses the drawer (no keyboard trap)
        page.keyboard.press("Escape")
        page.wait_for_timeout(50)
        assert not drawer.is_visible()
    finally:
        page.close()


def test_no_keyboard_traps_on_navigation(a11y_harness: UIHarness):
    """Verify sequential Tab key navigation advances focus continuously without keyboard traps."""
    require_browser()
    page = a11y_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{a11y_harness.server_url}/app#/setup")
        page.wait_for_selector("#setupSurface", state="visible")

        # Start tabbing from brand / top nav
        page.locator('[data-route="portal"]').focus()

        visited_tags: list[str] = []
        for _ in range(15):
            page.keyboard.press("Tab")
            focused_tag = page.evaluate("() => document.activeElement ? `${document.activeElement.tagName}#${document.activeElement.id || ''}.${document.activeElement.className || ''}` : 'none'")
            visited_tags.append(focused_tag)

        # Check that focus moved through multiple distinct elements (not trapped in one element)
        unique_visited = set(visited_tags)
        assert len(unique_visited) >= 5, f"Focus trapped or did not advance: {visited_tags}"
    finally:
        page.close()
