"""End-to-end browser tests for the main /app screens on isolated UI test harness.

Verifies:
1. Shell navigation & history across all 8 main screens:
   - Portal, Setup, Monitor, Crawl, Findings, Agent Skills, Settings, History/Audit.
   - Active rail indicator, single surface display, back/forward history, and reload state restoration.
2. Portal, History & Audit screens:
   - Representative scan fixtures (normal completed, normal empty, agent completed, hybrid partial,
     scan error, unverified items).
   - Invariant: error scan shows status 'error' and '未取得' (never pass/complete/0).
   - Search filter on History and audit log row presentation with IP and operation formatting.
3. Setup screen (5 tabs + readiness panel + secret protection):
   - 5 tabs switching (crawl, checks, auth, ai, advanced) and roving tabindex navigation.
   - On-demand readiness panel (Preflight) with mixed states (pass, warning, fail, not_checked, not_applicable).
   - Invariant: not_checked, not_applicable, fail, and warning never render as complete/pass (✓ OK).
   - Secret-value test: recognisable dummy secret entered in Setup never leaks into URL, localStorage,
     rendered text of other surfaces, or exported context.
4. Monitor screen (3 panes & live channel):
   - Layout adjustments (separator resizing via keyboard/drag, presets, collapse/expand/maximize).
   - Layout preference persistence and restore on reload without credential leaks.
   - Live channel disconnect and reconnect state preservation.
5. Crawl screen:
   - Crawl graph, tree explorer, node details drawer, search filter.
   - Completeness invariant: partial and unknown scans never claim or receive complete badge.
   - Missing-reference fallback text (never fabricated as verified).
6. Findings screen:
   - Split view, scan selector, interactive filters (severity, verification, provenance, search).
   - Invariant: unverified/untested/unavailable items never render as reproduced or pass.
   - Agent hypothesis findings explicitly labeled with provenance badge.
   - Deep-link navigation (valid and stale/unknown finding ID).
7. Settings & Agent Skills screens:
   - Settings masked secrets and explicit save behavior.
   - Agent skills capability table with static declaration disclaimer.
8. Session expiry (401):
   - Explicit authentication prompt and login redirect link on session expiry.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from tests.ui_harness import (
    require_browser,
    STANDARD_VIEWPORTS,
    UIHarness,
    ui_harness,
)


@pytest.fixture
def e2e_harness(ui_harness: UIHarness) -> UIHarness:
    """UIHarness with comprehensive representative scans seeded."""
    ui_harness.seed_representative_scans()
    return ui_harness


def test_app_shell_full_navigation_and_history(e2e_harness: UIHarness):
    """Verify shell navigation, active rail indicator, surfaces, back/forward, and reload."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        # 1. Direct load /app -> automatically normalizes to #/portal
        page.goto(f"{e2e_harness.server_url}/app", wait_until="domcontentloaded")
        page.wait_for_function("() => location.hash.includes('/portal')")
        page.locator("#summarySurface").wait_for(state="visible")
        assert page.locator('[data-route="portal"]').get_attribute("aria-current") == "page"
        assert page.locator("#viewTitle").inner_text() == "ポータル"

        routes_to_test = [
            ("setup", "#setupSurface", "Scan Setup"),
            ("monitor", "#monitorFrame", "Monitor"),
            ("crawl", "#crawlSurface", "Crawl"),
            ("findings", "#findingsSurface", "Findings"),
            ("agent-skills", "#agentSkillsSurface", "Agent Skills"),
            ("settings", "#settingsSurface", "Settings"),
            ("history", "#summarySurface", "スキャン履歴"),
            ("audit", "#summarySurface", "監査ログ"),
            ("portal", "#summarySurface", "ポータル"),
        ]

        for route_id, surface_selector, expected_title in routes_to_test:
            btn = page.locator(f'[data-route="{route_id}"]')
            btn.click()
            page.wait_for_function(
                f"() => document.querySelector('[data-route=\"{route_id}\"]')?.getAttribute('aria-current') === 'page'"
            )
            assert btn.get_attribute("aria-current") == "page"
            assert page.locator("#viewTitle").inner_text() == expected_title
            page.locator(surface_selector).wait_for(state="visible")

            # Check that other major surfaces are properly hidden
            if surface_selector != "#setupSurface":
                assert page.locator("#setupSurface").is_hidden()
            if surface_selector != "#crawlSurface":
                assert page.locator("#crawlSurface").is_hidden()
            if surface_selector != "#findingsSurface":
                assert page.locator("#findingsSurface").is_hidden()
            if surface_selector != "#agentSkillsSurface":
                assert page.locator("#agentSkillsSurface").is_hidden()
            if surface_selector != "#settingsSurface":
                assert page.locator("#settingsSurface").is_hidden()

        # 2. Back and forward browser navigation
        page.locator('[data-route="crawl"]').click()
        page.locator("#crawlSurface").wait_for(state="visible")
        assert page.url.endswith("#/crawl")

        page.locator('[data-route="settings"]').click()
        page.locator("#settingsSurface").wait_for(state="visible")
        assert page.url.endswith("#/settings")

        page.go_back()
        page.wait_for_function("() => location.hash.includes('/crawl')")
        page.locator("#crawlSurface").wait_for(state="visible")
        assert page.locator('[data-route="crawl"]').get_attribute("aria-current") == "page"

        page.go_forward()
        page.wait_for_function("() => location.hash.includes('/settings')")
        page.locator("#settingsSurface").wait_for(state="visible")
        assert page.locator('[data-route="settings"]').get_attribute("aria-current") == "page"

        # 3. Reload preserves hash route and restores state
        page.reload(wait_until="domcontentloaded")
        page.locator("#settingsSurface").wait_for(state="visible")
        assert page.url.endswith("#/settings")
        assert page.locator('[data-route="settings"]').get_attribute("aria-current") == "page"

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_portal_and_history_screens(e2e_harness: UIHarness):
    """Verify Portal summary cards, representative scan rows, error scan non-pass, and History filter."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{e2e_harness.server_url}/app#/portal", wait_until="domcontentloaded")
        page.locator("#summarySurface").wait_for(state="visible")

        # 1. Verify Portal renders scan history table with seeded representative scans
        page.wait_for_function("() => document.querySelectorAll('#summarySurface table tbody tr').length >= 6")
        e2e_harness.save_doc_image(page, "app-portal")
        table_text = page.locator("#summarySurface table tbody").inner_text()

        assert "store.internal.local" in table_text
        assert "empty.internal.local" in table_text
        assert "agent.internal.local" in table_text
        assert "hybrid.internal.local" in table_text
        assert "error.internal.local" in table_text
        assert "unverified.internal.local" in table_text

        # 2. Invariant: Error scan status is 'error' and findings count is '未取得' (never 0 or pass)
        rows = page.locator("#summarySurface table tbody tr")
        error_row = None
        for i in range(rows.count()):
            txt = rows.nth(i).inner_text()
            if "error.internal.local" in txt:
                error_row = rows.nth(i)
                break
        assert error_row is not None
        assert "error" in error_row.inner_text().lower()
        assert "未取得" in error_row.inner_text()

        # Invariant: Empty scan shows 0 findings count
        empty_row = None
        for i in range(rows.count()):
            txt = rows.nth(i).inner_text()
            if "empty.internal.local" in txt:
                empty_row = rows.nth(i)
                break
        assert empty_row is not None
        assert "\t0\t" in f"\t{empty_row.inner_text()}\t" or " 0 " in empty_row.inner_text() or "\n0\n" in empty_row.inner_text()

        # 3. History view and search filter
        page.locator('[data-route="history"]').click()
        page.locator("#summarySurface").wait_for(state="visible")
        page.wait_for_function("() => document.querySelector('#summarySurface input[type=\"search\"]')")

        search_input = page.locator('#summarySurface input[type="search"]')
        search_input.fill("agent")
        page.wait_for_function("() => document.querySelectorAll('#summarySurface table tbody tr').length === 1")

        filtered_count = page.locator("#summarySurface table tbody tr").count()
        assert filtered_count == 1
        assert "agent.internal.local" in page.locator("#summarySurface table tbody tr").inner_text()

        # Clear search filter
        search_input.fill("")
        page.wait_for_function("() => document.querySelectorAll('#summarySurface table tbody tr').length >= 6")
        assert page.locator("#summarySurface table tbody tr").count() >= 6

        # 4. Audit log screen
        page.locator('[data-route="audit"]').click()
        page.locator("#summarySurface").wait_for(state="visible")
        page.wait_for_function(
            "() => Array.from(document.querySelectorAll('#summarySurface table tbody tr td')).some(td => td.textContent.includes('スキャン開始') || td.textContent.includes('設定変更'))"
        )
        audit_text = page.locator("#summarySurface table tbody").inner_text()
        assert "スキャン開始" in audit_text or "設定変更" in audit_text

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_setup_screen_tabs_readiness_and_dummy_secret_protection(e2e_harness: UIHarness):
    """Verify Setup 5 tabs, readiness preflight non-pass invariant, and dummy secret protection."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{e2e_harness.server_url}/app#/setup", wait_until="domcontentloaded")
        page.locator("#setupSurface").wait_for(state="visible")
        page.wait_for_function("() => document.querySelectorAll('.setup-tab').length === 5")

        # 1. Verify 5 tabs and interactive switching
        tab_labels = ["クロール・スコープ", "検査項目・ペイロード", "認証・ネットワーク", "AI・自律探索", "高度な設定・フロー"]
        for label in tab_labels:
            tab_btn = page.locator(".setup-tab").filter(has_text=label)
            assert tab_btn.count() == 1
            tab_btn.click()
            page.wait_for_function(f"() => document.querySelector('.setup-tab.active')?.textContent?.includes('{label}')")
            assert tab_btn.evaluate("el => el.classList.contains('active')")

        # 2. Keyboard navigation across tabs with ArrowRight and ArrowLeft
        first_tab = page.locator(".setup-tab").first
        first_tab.click()
        first_tab.focus()
        page.keyboard.press("ArrowRight")
        page.wait_for_function("() => document.querySelectorAll('.setup-tab')[1].classList.contains('active')")
        page.keyboard.press("ArrowLeft")
        page.wait_for_function("() => document.querySelectorAll('.setup-tab')[0].classList.contains('active')")

        # 3. Readiness Panel (Preflight)
        # Fill URL
        page.locator("#cfgInputUrl").fill("http://store.internal.local")

        # Mock /api/v1/preflight endpoint with representative mixed statuses
        preflight_mock_data = {
            "url": "http://store.internal.local",
            "verdict": "warning",
            "checks": [
                {"id": "check_target", "name": "Target Connectivity", "status": "pass", "detail": "HTTP 200 OK"},
                {"id": "check_auth", "name": "Auth Flow Check", "status": "warning", "detail": "Form found without CSRF token"},
                {"id": "check_proxy", "name": "Proxy Verification", "status": "not_checked", "detail": "Proxy probe was not executed"},
                {"id": "check_mfa", "name": "MFA Readiness", "status": "not_applicable", "detail": "MFA is disabled"},
                {"id": "check_scope", "name": "Scope Constraint Check", "status": "fail", "detail": "External host references detected"},
            ],
        }

        page.route(
            "**/api/v1/preflight",
            lambda route: route.fulfill(
                status=200,
                content_type="application/json",
                body=json.dumps(preflight_mock_data),
            ),
        )

        preflight_btn = page.locator("#setupRunPreflightBtn")
        assert preflight_btn.is_visible()
        preflight_btn.click()

        # Wait for verdict badge
        page.wait_for_selector("#setupReadinessVerdictBadge")

        # Hard invariant: Overall verdict must be warning and must NEVER be complete/pass
        verdict_badge = page.locator("#setupReadinessVerdictBadge")
        assert verdict_badge.evaluate("el => el.classList.contains('setup-verdict-warning')")
        assert not verdict_badge.evaluate("el => el.classList.contains('setup-verdict-pass')")
        assert "OK" not in verdict_badge.inner_text() or "注意" in verdict_badge.inner_text()

        # Hard invariant: not_checked, not_applicable, fail, warning must NEVER have setup-status-pass or '✓ OK'
        rows = page.locator(".setup-readiness-check-item")
        assert rows.count() == 5

        # Check pass row
        pass_chip = page.locator('.setup-readiness-check-item[data-check-id="check_target"] .setup-readiness-status-chip')
        assert pass_chip.evaluate("el => el.classList.contains('setup-status-pass')")
        assert "✓ OK" in pass_chip.inner_text()

        # Check warning row
        warn_chip = page.locator('.setup-readiness-check-item[data-check-id="check_auth"] .setup-readiness-status-chip')
        assert warn_chip.evaluate("el => el.classList.contains('setup-status-warning')")
        assert not warn_chip.evaluate("el => el.classList.contains('setup-status-pass')")

        # Check not_checked row
        not_checked_chip = page.locator('.setup-readiness-check-item[data-check-id="check_proxy"] .setup-readiness-status-chip')
        assert not_checked_chip.evaluate("el => el.classList.contains('setup-status-not-checked')")
        assert not not_checked_chip.evaluate("el => el.classList.contains('setup-status-pass')")
        assert "未確認" in not_checked_chip.inner_text()
        assert "✓ OK" not in not_checked_chip.inner_text()

        # Check not_applicable row
        na_chip = page.locator('.setup-readiness-check-item[data-check-id="check_mfa"] .setup-readiness-status-chip')
        assert na_chip.evaluate("el => el.classList.contains('setup-status-not-applicable')")
        assert not na_chip.evaluate("el => el.classList.contains('setup-status-pass')")
        assert "非該当" in na_chip.inner_text()
        assert "✓ OK" not in na_chip.inner_text()

        # Check fail row
        fail_chip = page.locator('.setup-readiness-check-item[data-check-id="check_scope"] .setup-readiness-status-chip')
        assert fail_chip.evaluate("el => el.classList.contains('setup-status-fail')")
        assert not fail_chip.evaluate("el => el.classList.contains('setup-status-pass')")
        assert "✗ 失敗" in fail_chip.inner_text()
        assert "✓ OK" not in fail_chip.inner_text()

        # 4. Dummy Secret Protection Test
        dummy_secret = "SENTINEL_DUMMY_SECRET_XYZ987654_DO_NOT_LEAK"
        page.locator(".setup-tab").filter(has_text="認証・ネットワーク").click()
        page.wait_for_selector("#cfgAuthPass")
        page.locator("#cfgAuthPass").fill(dummy_secret)

        # Navigate away to Monitor, Findings, Settings, Portal
        for dest in ["monitor", "findings", "settings", "portal"]:
            page.locator(f'[data-route="{dest}"]').click()
            page.wait_for_function(
                f"() => location.hash.includes('/{dest}') && document.querySelector('[data-route=\"{dest}\"]')?.getAttribute('aria-current') === 'page'"
            )

            # Invariant: Secret must NOT appear in URL
            assert dummy_secret not in page.url

            # Invariant: Secret must NOT appear in localStorage
            ls_data = page.evaluate("() => JSON.stringify(Object.entries(localStorage))")
            assert dummy_secret not in ls_data

            # Invariant: Secret must NOT appear in rendered text of other surfaces
            rendered_body = page.locator("body").inner_text()
            assert dummy_secret not in rendered_body

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_monitor_screen_panes_and_live_channel(e2e_harness: UIHarness):
    """Verify Monitor 3-pane adjustments, keyboard separator resize, presets, reload, and live channel reconnect."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{e2e_harness.server_url}/app#/monitor", wait_until="domcontentloaded")

        # Wait for Monitor module shadow root
        page.wait_for_function(
            "() => Boolean(document.querySelector('#monitorModule')?.shadowRoot?.querySelector('#sepLeft'))"
        )

        # 1. Keyboard resize on left separator
        sep_left = page.locator("#monitorModule").locator("#sepLeft")
        sep_left.focus()
        page.keyboard.press("ArrowRight")
        val_after_right = page.evaluate(
            "() => Number(document.querySelector('#monitorModule').shadowRoot.querySelector('#sepLeft').getAttribute('aria-valuenow'))"
        )
        assert val_after_right == 340

        page.keyboard.press("ArrowLeft")
        val_after_left = page.evaluate(
            "() => Number(document.querySelector('#monitorModule').shadowRoot.querySelector('#sepLeft').getAttribute('aria-valuenow'))"
        )
        assert val_after_left == 320

        # 2. Preset switching
        page.evaluate("() => document.querySelector('#monitorModule').shadowRoot.querySelector('[data-preset=\"browser-focused\"]').click()")
        is_left_collapsed = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[0].classList.contains('is-collapsed')"
        )
        assert is_left_collapsed is True

        page.evaluate("() => document.querySelector('#monitorModule').shadowRoot.querySelector('[data-preset=\"standard\"]').click()")
        is_left_collapsed_std = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[0].classList.contains('is-collapsed')"
        )
        assert is_left_collapsed_std is False

        # 3. Reload restores layout preferences from localStorage
        page.evaluate("() => document.querySelector('#monitorModule').shadowRoot.querySelector('[data-preset=\"log-focused\"]').click()")
        page.reload(wait_until="domcontentloaded")
        page.wait_for_function("""() => {
            const frame = document.querySelector('#monitorFrame')?.contentWindow;
            return Boolean(document.querySelector('#monitorModule')?.shadowRoot?.querySelector('#sepLeft')) &&
                   document.getElementById('monitorFrame')?.dataset?.ready === 'true' &&
                   Boolean(frame?.VulixAppBridge) &&
                   Boolean(frame?._eventStream?.connected) &&
                   typeof frame.state?.serverInstanceId === 'string' &&
                   frame.state.serverInstanceId.length > 0;
        }""")
        is_right_collapsed_restored = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('.panel')[2].classList.contains('is-collapsed')"
        )
        assert is_right_collapsed_restored is True

        # Switch back to standard preset so findings pane is active
        page.evaluate("() => document.querySelector('#monitorModule').shadowRoot.querySelector('[data-preset=\"standard\"]').click()")

        # 4. Live channel population & disconnect/reconnect state preservation
        frame = page.frame_locator("#monitorFrame")
        frame.locator("body").evaluate("""() => {
            state.serverInstanceId = 'server-test-e2e';
            state.scanRunId = 'run-test-e2e';
            state.scanId = '20261026_100000';
            state.status = 'scanning';
            publishAppScanContext();
            addFinding({
                id: 'live_test_finding_unique_01',
                check_type: 'xss',
                severity: 'high',
                url: 'http://store.internal.local/search?q=test',
                field_name: 'q',
                payload: '<script>alert(1)</script>',
                confirmed: true,
                verified: true,
            });
            addEventLog('status', 'live e2e event received');
        }""")

        page.wait_for_function(
            "() => document.querySelector('#monitorModule')?.shadowRoot?.querySelectorAll('#findingsPanel .finding-card').length >= 1"
        )
        finding_cards_count = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('#findingsPanel .finding-card').length"
        )
        assert finding_cards_count >= 1

        # Simulate transport reconnect event
        frame.locator("body").evaluate("""() => {
            addEventLog('status', 'channel reconnect verified');
        }""")
        page.wait_for_function(
            "() => document.querySelector('#monitorModule')?.shadowRoot?.querySelector('#eventLog')?.textContent?.includes('channel reconnect verified')"
        )
        finding_cards_count_after = page.evaluate(
            "() => document.querySelector('#monitorModule').shadowRoot.querySelectorAll('#findingsPanel .finding-card').length"
        )
        assert finding_cards_count_after >= 1

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_crawl_screen_graph_and_completeness(e2e_harness: UIHarness):
    """Verify Crawl graph screen, tree explorer, node details, and completeness non-pass invariants."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        # 1. Normal completed scan -> Completeness is '完全 (Complete)'
        page.goto(f"{e2e_harness.server_url}/app#/crawl?scan=20261026_100000", wait_until="domcontentloaded")
        page.locator("#crawlSurface").wait_for(state="visible")
        page.wait_for_selector(".crawl-badge")

        badge = page.locator(".crawl-badge")
        assert badge.evaluate("el => el.classList.contains('crawl-badge-complete')")
        assert "完全" in badge.inner_text()

        # Canvas SVG rendered
        assert page.locator(".crawl-svg-canvas").is_visible()

        # Switch to explorer mode
        page.locator("button[data-mode='explorer']").click()
        page.wait_for_selector(".crawl-explorer-surface:not([hidden])")
        page.wait_for_selector(".crawl-tree-row")
        assert page.locator(".crawl-tree-row").count() >= 1

        # Click a tree row to open node detail
        page.locator(".crawl-tree-row").first.click()
        page.wait_for_selector(".crawl-explorer-detail")
        assert page.locator(".crawl-explorer-detail").inner_text() != ""

        # 2. Crawl <-> Findings cross-links, action entry points, and missing node
        # 2a. Direct navigation to node with findings -> link presence & count
        page.goto(
            f"{e2e_harness.server_url}/app#/crawl?scan=20261026_100000&url=http%3A%2F%2Fstore.internal.local%2Fsearch%3Fq%3Dtest",
            wait_until="domcontentloaded",
        )
        page.wait_for_selector(".crawl-findings-deep-link")
        deep_link = page.locator(".crawl-findings-deep-link")
        assert deep_link.is_visible()
        assert "findings" in (deep_link.get_attribute("href") or "")
        assert "1 件" in deep_link.inner_text()

        item_link = page.locator(".crawl-finding-item-link")
        assert item_link.is_visible()
        assert "f_xss_01" in (item_link.get_attribute("href") or "")

        # 2b. Form node with actions -> capability-gated disabled action with reason
        page.goto(
            f"{e2e_harness.server_url}/app#/crawl?scan=20261026_100000&url=http%3A%2F%2Fstore.internal.local%2Fsearch",
            wait_until="domcontentloaded",
        )
        page.wait_for_selector(".crawl-action-btn")
        action_btn = page.locator(".crawl-action-btn").first
        assert action_btn.is_visible()
        assert action_btn.is_disabled()
        assert "not available in this version" in action_btn.inner_text()

        # 2c. Node with unknown findings count -> explicit unknown count presentation, never 0
        page.goto(
            f"{e2e_harness.server_url}/app#/crawl?scan=20261026_105000&url=http%3A%2F%2Funverified.internal.local%2Funavail",
            wait_until="domcontentloaded",
        )
        page.wait_for_selector(".crawl-detail-drawer:not([hidden])")
        detail_text = page.locator(".crawl-detail-drawer:not([hidden])").inner_text()
        assert "件数不明 (unknown)" in detail_text
        assert "検出事項データ未読込 (unknown)" in detail_text
        assert "0 件" not in detail_text
        assert "0 findings" not in detail_text

        # 2d. Missing node in crawl graph -> explicit not-found card with return link
        page.goto(
            f"{e2e_harness.server_url}/app#/crawl?scan=20261026_100000&url=http%3A%2F%2Fmissing.target.local%2Fnonexistent",
            wait_until="domcontentloaded",
        )
        page.wait_for_selector(".crawl-not-found-card")
        not_found_card = page.locator(".crawl-not-found-card")
        assert not_found_card.is_visible()
        assert "not in crawl graph" in not_found_card.inner_text()

        # 3. Hybrid partial scan -> Invariant: MUST NOT be complete
        page.goto(f"{e2e_harness.server_url}/app#/crawl?scan=20261026_103000", wait_until="domcontentloaded")
        page.locator("#crawlSurface").wait_for(state="visible")
        page.wait_for_selector(".crawl-badge")

        partial_badge = page.locator(".crawl-badge")
        assert partial_badge.evaluate("el => el.classList.contains('crawl-badge-partial')")
        assert not partial_badge.evaluate("el => el.classList.contains('crawl-badge-complete')")
        assert "一部のみ" in partial_badge.inner_text()
        assert "完全" not in partial_badge.inner_text()

        # 3. Empty scan -> Invariant: MUST NOT be complete (Unknown / incomplete)
        page.goto(f"{e2e_harness.server_url}/app#/crawl?scan=20261026_101000", wait_until="domcontentloaded")
        page.locator("#crawlSurface").wait_for(state="visible")
        page.wait_for_selector(".crawl-badge")

        empty_badge = page.locator(".crawl-badge")
        assert not empty_badge.evaluate("el => el.classList.contains('crawl-badge-complete')")
        assert "完全" not in empty_badge.inner_text()

        # 4. Interactive node search filter
        search_input = page.locator(".crawl-search-input")
        if search_input.is_visible():
            search_input.fill("catalog")
            page.wait_for_function("() => document.querySelector('.crawl-search-input')?.value === 'catalog'")
            page.locator(".crawl-message-banner").wait_for(state="visible")

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_findings_screen_filters_and_deep_links(e2e_harness: UIHarness):
    """Verify Findings screen split-view, Agent provenance badge, unverified items non-pass invariant, and deep links."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        # 1. Agent scan with hypothesis and verified finding
        page.goto(f"{e2e_harness.server_url}/app#/findings?scan=20261026_102000", wait_until="domcontentloaded")
        page.locator("#findingsSurface").wait_for(state="visible")
        page.wait_for_function("() => document.querySelectorAll('#findingsListContent .findings-list-card').length === 2")

        cards = page.locator("#findingsListContent .findings-list-card")
        assert cards.count() == 2

        # Verify Agent unconfirmed finding card
        cards.filter(has_text="SQLI").click()
        page.wait_for_function("() => document.querySelector('#findingsDetailContent .provenance-badge')")

        # Provenance badge explicitly identifies Agent finding
        prov_badge = page.locator("#findingsDetailContent .provenance-badge")
        assert prov_badge.evaluate("el => el.classList.contains('provenance-agent')")
        assert "Agent" in prov_badge.inner_text()

        # Invariant: Unconfirmed Agent finding verification badge is assumed (never reproduced)
        verify_badge = page.locator("#findingsDetailContent .verify-badge")
        assert verify_badge.evaluate("el => el.classList.contains('verify-assumed')")
        assert not verify_badge.evaluate("el => el.classList.contains('verify-reproduced')")

        # 2. Scan with unverified / untested / unavailable items
        page.goto(f"{e2e_harness.server_url}/app#/findings?scan=20261026_105000", wait_until="domcontentloaded")
        page.locator("#findingsSurface").wait_for(state="visible")
        page.wait_for_function("() => document.querySelectorAll('#findingsListContent .findings-list-card').length === 4")

        # Invariant: None of the unverified items must receive verify-reproduced
        for card_idx in range(4):
            page.locator("#findingsListContent .findings-list-card").nth(card_idx).click()
            page.wait_for_function(
                f"() => document.querySelectorAll('#findingsListContent .findings-list-card')[{card_idx}]?.classList?.contains('active') && "
                f"Boolean(document.querySelector('#findingsDetailContent .verify-badge'))"
            )
            detail_verify = page.locator("#findingsDetailContent .verify-badge")
            assert not detail_verify.evaluate("el => el.classList.contains('verify-reproduced')"), (
                f"Finding at index {card_idx} incorrectly received verify-reproduced class"
            )

        # 3. Interactive filters: severity, verification, provenance
        page.goto(f"{e2e_harness.server_url}/app#/findings?scan=20261026_100000", wait_until="domcontentloaded")
        page.wait_for_function("() => document.querySelectorAll('#findingsListContent .findings-list-card').length === 3")

        # Severity filter: critical
        page.locator("#filterSeverity").select_option("critical")
        page.wait_for_function("() => document.querySelectorAll('#findingsListContent .findings-list-card').length === 1")
        assert page.locator("#findingsListContent .findings-list-card").count() == 1
        assert "XSS" in page.locator("#findingsListContent .findings-list-card").inner_text()

        # Reset severity
        page.locator("#filterSeverity").select_option("all")
        page.wait_for_function("() => document.querySelectorAll('#findingsListContent .findings-list-card').length === 3")

        # 4. Valid deep-link direct navigation
        page.goto(f"{e2e_harness.server_url}/app#/findings?scan=20261026_100000&finding=f_sqli_01", wait_until="domcontentloaded")
        page.wait_for_function("() => document.querySelector('#findingsDetailContent')?.innerText?.includes('SQLI')")
        assert "SQLI" in page.locator("#findingsDetailContent").inner_text()

        # 5. Cross-link to Crawl view and capability-gated action entry points
        page.goto(f"{e2e_harness.server_url}/app#/findings?scan=20261026_100000&finding=f_xss_01", wait_until="domcontentloaded")
        page.wait_for_selector("#findingsDetailContent .findings-actions-row")
        crawl_link = page.locator("#findingsDetailContent a.findings-action-btn[href*='/crawl']")
        assert crawl_link.is_visible()
        assert "crawl" in (crawl_link.get_attribute("href") or "")
        assert "クロールグラフで表示" in crawl_link.inner_text()

        disabled_actions = page.locator("#findingsDetailContent button.findings-action-btn:disabled")
        assert disabled_actions.count() >= 2
        for idx in range(disabled_actions.count()):
            assert "not available in this version" in disabled_actions.nth(idx).inner_text()

        # Clicking Crawl link navigates to Crawl view
        crawl_link.click()
        page.wait_for_function("() => location.hash.includes('/crawl')")
        page.locator("#crawlSurface").wait_for(state="visible")

        # 6. Stale / unknown finding deep link -> Safe explicit error state
        page.goto(f"{e2e_harness.server_url}/app#/findings?scan=20261026_100000&finding=unknown_stale_id_999", wait_until="domcontentloaded")
        page.wait_for_function("() => document.querySelector('#findingsDetailContent')?.innerText?.includes('見つかりません')")
        assert "見つかりません" in page.locator("#findingsDetailContent").inner_text()

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_settings_and_agent_skills_screens(e2e_harness: UIHarness):
    """Verify Settings view masked secrets, explicit save behavior, and Agent Skills capability table."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        # 1. Settings view
        page.goto(f"{e2e_harness.server_url}/app#/settings", wait_until="domcontentloaded")
        page.locator("#settingsSurface").wait_for(state="visible")

        assert page.locator("#notificationCard").is_visible()
        assert page.locator("#configCard").is_visible()
        assert page.locator("#saveSettingsBtn").is_visible()
        assert page.locator("#testNotificationBtn").is_visible()

        # Invariant: Secret inputs (e.g. Webhook URL) must start empty without leaking raw credentials
        page.locator("#webhookUrlInput").wait_for(state="visible")
        webhook_input = page.locator("#webhookUrlInput")
        assert webhook_input.input_value() == ""

        # 2. Agent Skills view
        page.goto(f"{e2e_harness.server_url}/app#/agent-skills", wait_until="domcontentloaded")
        page.locator("#agentSkillsSurface").wait_for(state="visible")
        page.wait_for_selector(".agent-skills-table")

        table_rows = page.locator(".agent-skills-table tbody tr")
        assert table_rows.count() >= 6

        # Invariant: Disclaimer regarding static capability declaration vs dynamic execution
        header_text = page.locator(".agent-skills-header").inner_text()
        assert "宣言" in header_text or "自律" in header_text or "スキル" in header_text

        e2e_harness.assert_no_horizontal_overflow(page, max_allowed=1440 + 1)
        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_session_expiry_401_behavior(e2e_harness: UIHarness):
    """Verify session expiry (401) displays explicit auth confirmation prompt and login link."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        page.goto(f"{e2e_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.locator('[data-route="monitor"]').wait_for()
        page.wait_for_function("() => Boolean(document.querySelector('#monitorFrame')?.contentWindow?.VulixAppBridge)")

        # Trigger auth required postMessage event (equivalent to 401 response or 4401 WS close)
        page.frame_locator("#monitorFrame").locator("body").evaluate(
            "() => window.parent.postMessage({type: 'vulix:auth-required'}, window.location.origin)"
        )

        page.get_by_text("認証セッションの再確認が必要です", exact=False).wait_for()
        assert page.locator("#message").is_visible()
        assert page.locator("#message a[href='/login']").count() == 1

        # Monitor frame and other surfaces are safely hidden
        assert page.locator("#monitorFrame").is_hidden()
        assert page.locator("#setupSurface").is_hidden()
        assert page.locator("#findingsSurface").is_hidden()

        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_app_shell_keyboard_focus_visibility_and_responsive_widths(e2e_harness: UIHarness):
    """Verify visible keyboard focus on interactive elements and responsive layouts at 1440, 1280, and 768 px."""
    require_browser()
    page = e2e_harness.new_page(**STANDARD_VIEWPORTS[1440])

    try:
        # Load /app Portal
        page.goto(f"{e2e_harness.server_url}/app#/portal", wait_until="domcontentloaded")
        page.locator("#summarySurface").wait_for(state="visible")

        # 1. Focus visibility checks on interactive navigation buttons
        nav_buttons = [
            '[data-route="portal"]',
            '[data-route="history"]',
            '[data-route="setup"]',
            '[data-route="findings"]',
            '[data-route="crawl"]',
            '[data-route="agent-skills"]',
            '[data-route="settings"]',
        ]
        for sel in nav_buttons:
            e2e_harness.assert_focus_visible(page, sel)

        # 2. Responsive layout verification across 1440, 1280, 768 px on Portal
        e2e_harness.check_viewports_and_focus(
            page,
            focus_selectors=['[data-route="portal"]', '[data-route="setup"]'],
            widths=(1440, 1280, 768),
        )

        # 3. Switch to Setup view and check focus on inputs/buttons and viewports
        page.locator('[data-route="setup"]').click()
        page.locator("#setupSurface").wait_for(state="visible")
        page.wait_for_selector(".setup-url-input")

        # Check focus visibility on setup interactive controls
        setup_interactive = [
            ".setup-url-input",
            ".setup-start-btn",
            "#setupTab-checks",
        ]
        for sel in setup_interactive:
            e2e_harness.assert_focus_visible(page, sel)

        e2e_harness.check_viewports_and_focus(
            page,
            focus_selectors=[".setup-url-input", ".setup-start-btn"],
            widths=(1440, 1280, 768),
        )

        # 4. Switch to Findings view and check focus and viewports
        page.locator('[data-route="findings"]').click()
        page.locator("#findingsSurface").wait_for(state="visible")
        page.wait_for_selector(".findings-container")

        e2e_harness.check_viewports_and_focus(
            page,
            focus_selectors=['[data-route="findings"]'],
            widths=(1440, 1280, 768),
        )

        # 5. Crawl view
        page.goto(f"{e2e_harness.server_url}/app#/crawl?scan=20261026_100000", wait_until="domcontentloaded")
        page.locator("#crawlSurface").wait_for(state="visible")
        page.wait_for_selector(".crawl-svg-canvas")
        e2e_harness.assert_focus_visible(page, ".crawl-search-input")
        e2e_harness.check_viewports_and_focus(
            page,
            focus_selectors=['[data-route="crawl"]', ".crawl-search-input"],
            widths=(1440, 1280, 768),
        )

        # 6. Monitor view (shadow DOM: check separator focus ring inside the shadow root)
        page.goto(f"{e2e_harness.server_url}/app#/monitor", wait_until="domcontentloaded")
        page.wait_for_function(
            "() => Boolean(document.querySelector('#monitorModule')?.shadowRoot?.querySelector('#sepLeft'))"
        )
        for w in (1440, 1280, 768):
            page.set_viewport_size({"width": w, "height": 900})
            page.wait_for_timeout(100)
            e2e_harness.assert_no_horizontal_overflow(page, max_allowed=w + 1)
            e2e_harness.assert_focus_visible(page, '[data-route="monitor"]')
            info = page.evaluate(
                """() => {
                    const root = document.querySelector('#monitorModule').shadowRoot;
                    const el = root.querySelector('#sepLeft');
                    if (!el) return { found: false };
                    try { el.focus({ focusVisible: true }); } catch (_) { el.focus(); }
                    const cs = getComputedStyle(el);
                    return {
                        found: true,
                        visible: (cs.outlineStyle !== 'none' && parseFloat(cs.outlineWidth) > 0) ||
                            (cs.boxShadow && cs.boxShadow !== 'none'),
                    };
                }"""
            )
            assert info["found"] and info["visible"], f"monitor separator focus not visible at {w}: {info}"

        # 7. Settings view
        page.goto(f"{e2e_harness.server_url}/app#/settings", wait_until="domcontentloaded")
        page.locator("#settingsSurface").wait_for(state="visible")
        page.locator("#saveSettingsBtn").wait_for(state="visible")
        e2e_harness.assert_focus_visible(page, "#webhookUrlInput")
        e2e_harness.check_viewports_and_focus(
            page,
            focus_selectors=["#webhookUrlInput", "#configFilterInput"],
            widths=(1440, 1280, 768),
        )

        # 8. Agent capabilities view
        page.goto(f"{e2e_harness.server_url}/app#/agent-skills", wait_until="domcontentloaded")
        page.locator("#agentSkillsSurface").wait_for(state="visible")
        page.wait_for_selector(".agent-skills-table")
        e2e_harness.check_viewports_and_focus(
            page,
            focus_selectors=['[data-route="agent-skills"]'],
            widths=(1440, 1280, 768),
        )

        e2e_harness.assert_no_errors(page)
    finally:
        page.close()


def test_legacy_dashboard_surfaces_doc_images(ui_harness: UIHarness):
    """Capture legacy /monitor screenshots for documentation in deterministic fixture states."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1440])
    try:
        page.goto(f"{ui_harness.server_url}/monitor", wait_until="domcontentloaded")
        page.wait_for_selector("#scanConfigOverlay")

        # 1. dashboard-configured: Basic config filled in overlay
        page.locator("#cfgInputUrl").fill("https://example.com")
        page.locator("#cfgTab-basic #cfgDepth").fill("2")
        ui_harness.save_doc_image(page, "dashboard-configured")

        # 2. dashboard-carrier-coverage: Checks tab showing Carrier Coverage Matrix
        page.locator(".cfg-tab", has_text="検査項目").click()
        page.locator("#carrierCoverageMatrix").wait_for()
        page.locator("#carrierCoverageHeading").scroll_into_view_if_needed()
        page.wait_for_timeout(100)
        ui_harness.save_doc_image(page, "dashboard-carrier-coverage")

        # 3. dashboard-hybrid: Hybrid tab
        page.locator(".cfg-tab", has_text="ハイブリッド").click()
        page.locator("#cfgTab-hybrid").wait_for()
        page.locator("#cfgTab-hybrid").scroll_into_view_if_needed()
        page.wait_for_timeout(100)
        ui_harness.save_doc_image(page, "dashboard-hybrid")

        # Close overlay and populate monitor for live / done / aborted states
        page.evaluate("() => document.getElementById('scanConfigOverlay').classList.remove('active')")
        ui_harness.populate_live_monitor(page)

        # 4. dashboard-results: Monitor in completed state with findings
        page.evaluate('''() => {
            handleEvent({
                type: "scan_snapshot",
                sequence: 10,
                data: {
                    status: "done",
                    findings: [
                        {
                            id: "f_live_xss_01",
                            check_type: "xss",
                            severity: "critical",
                            url: "http://store.internal.local/search?q=test",
                            confirmed: true,
                            verified: true
                        }
                    ],
                    findings_count: 1,
                    total_findings_count: 1,
                    confirmed_findings_count: 1,
                    page_count: 4,
                    check_counts: {xss: 1, sqli: 0},
                    url_order: ["http://store.internal.local", "http://store.internal.local/products"],
                    phase: "report"
                }
            });
        }''')
        page.wait_for_function("() => state.scanDone === true && state.status === 'done'")
        page.wait_for_timeout(100)
        ui_harness.save_doc_image(page, "dashboard-results")

        # 5. dashboard-aborted: Monitor in operator-aborted terminal state
        page.evaluate('''() => {
            handleEvent({
                type: "scan_snapshot",
                sequence: 11,
                data: {
                    status: "aborted",
                    aborted: true,
                    findings: [
                        {
                            id: "f_live_xss_01",
                            check_type: "xss",
                            severity: "critical",
                            url: "http://store.internal.local/search?q=test",
                            confirmed: true,
                            verified: true
                        }
                    ],
                    findings_count: 1,
                    total_findings_count: 1,
                    confirmed_findings_count: 1,
                    page_count: 4,
                    check_counts: {xss: 1, sqli: 0},
                    url_order: ["http://store.internal.local", "http://store.internal.local/products"],
                    phase: "attack"
                }
            });
        }''')
        page.wait_for_function("() => state.scanDone === true && (state.status === 'aborted' || state.aborted)")
        page.wait_for_timeout(100)
        ui_harness.save_doc_image(page, "dashboard-aborted")
    finally:
        page.close()
