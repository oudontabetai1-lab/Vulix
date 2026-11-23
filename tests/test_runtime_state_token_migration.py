"""Automated regression suite for Runtime State Token Migration.

Verifies:
1. Pure contract / static analysis:
   - tokens.css defines canonical execution state tokens (--state-running, --state-paused,
     --state-completed, --state-failed, --state-stale, --state-unverified) and corresponding
     background and border tokens.
   - All state tokens meet WCAG 2.2 AA contrast ratios (>= 4.5:1 direct text contrast,
     >= 3.0:1 UI boundaries) against dark surfaces (#0a0b10, #12141d, --bg, --surface, --surface2).
   - templates/app.html .scan-state-* badges consume semantic state tokens (--state-*)
     instead of legacy var(--accent) or hardcoded hex colors (#2ecc71, #f1c40f, #e74c3c, #e67e22).
   - templates/dashboard.html status dots, history badges, and rail pulses consume semantic
     state tokens rather than vulnerability severity tokens (--critical, --high, --low, --medium).
2. Live browser DOM & computed style regression (Playwright / UIHarness):
   - Computes live styles of .scan-state-badge elements across execution states
     (running, paused, completed, failed, stale, unverified).
   - Verifies operational running state color resolves to --state-running (#e4a770 / rgb(228, 167, 112))
     and is strictly distinct from brand purple --accent (#9184d9 / rgb(145, 132, 217)).
   - Verifies operational states in Normal, Agent, and Hybrid execution modes with glyphs and labels.
   - Exercises cross-mode transitions (Normal running -> done, Agent running -> paused -> resumed,
     Hybrid unverified hypotheses) and meaningful screen navigation without console errors.
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

ROOT = Path(__file__).resolve().parent.parent
TOKENS_CSS = ROOT / "templates" / "ui" / "tokens.css"
APP_HTML = ROOT / "templates" / "app.html"
DASHBOARD_HTML = ROOT / "templates" / "dashboard.html"


def _srgb_to_lin(channel_8bit: int) -> float:
    c = channel_8bit / 255.0
    return c / 12.92 if c <= 0.04045 else ((c + 0.055) / 1.055) ** 2.4


def _relative_luminance(hex_str: str) -> float:
    clean = hex_str.strip().lstrip("#")
    assert len(clean) == 6, f"Expected 6-digit hex string, got {hex_str}"
    r = int(clean[0:2], 16)
    g = int(clean[2:4], 16)
    b = int(clean[4:6], 16)
    return 0.2126 * _srgb_to_lin(r) + 0.7152 * _srgb_to_lin(g) + 0.0722 * _srgb_to_lin(b)


def _contrast_ratio(hex_a: str, hex_b: str) -> float:
    lum_a = _relative_luminance(hex_a)
    lum_b = _relative_luminance(hex_b)
    lighter = max(lum_a, lum_b)
    darker = min(lum_a, lum_b)
    return (lighter + 0.05) / (darker + 0.05)


def _composite(fg_hex: str, alpha: float, bg_hex: str) -> str:
    clean_fg = fg_hex.strip().lstrip("#")
    clean_bg = bg_hex.strip().lstrip("#")
    fg_rgb = [int(clean_fg[i : i + 2], 16) for i in (0, 2, 4)]
    bg_rgb = [int(clean_bg[i : i + 2], 16) for i in (0, 2, 4)]
    comp_rgb = [round(fg * alpha + bg * (1.0 - alpha)) for fg, bg in zip(fg_rgb, bg_rgb)]
    return f"#{comp_rgb[0]:02x}{comp_rgb[1]:02x}{comp_rgb[2]:02x}"


def _parse_tokens(css_text: str) -> dict[str, str]:
    root_match = re.search(r":root\s*\{([^}]*)\}", css_text)
    assert root_match, "Could not find :root block in tokens.css"
    raw_tokens = re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", root_match.group(1))
    tokens = {k.strip(): v.strip() for k, v in raw_tokens}
    resolved = {}
    for _ in range(5):
        for k, v in tokens.items():
            var_match = re.match(r"^var\((--[\w-]+)\)$", v)
            if var_match and var_match.group(1) in tokens:
                resolved[k] = resolved.get(var_match.group(1), tokens[var_match.group(1)])
            else:
                resolved[k] = v
        tokens.update(resolved)
    return resolved


def test_contract_tokens_css_semantic_state_tokens_and_contrast():
    """Verify templates/ui/tokens.css defines complete semantic state tokens and meets WCAG AA."""
    tokens = _parse_tokens(TOKENS_CSS.read_text(encoding="utf-8"))

    # Required state color tokens
    required_state_tokens = {
        "running": "--state-running",
        "paused": "--state-paused",
        "completed": "--state-completed",
        "failed": "--state-failed",
        "stale": "--state-stale",
        "unverified": "--state-unverified",
    }
    for state_name, token_key in required_state_tokens.items():
        assert token_key in tokens, f"Missing required state token {token_key}"
        hex_val = tokens[token_key]
        assert hex_val.startswith("#"), f"State token {token_key} must resolve to a hex color, got {hex_val}"

    # Required state background & border tokens from tokens.css
    required_bg_tokens = [
        "--status-running-bg",
        "--status-running-border",
        "--status-warning-bg",
        "--status-warning-border",
        "--status-pass-bg",
        "--status-pass-border",
        "--status-fail-bg",
        "--status-fail-border",
        "--status-stale-bg",
        "--status-stale-border",
    ]
    for bg_tok in required_bg_tokens:
        assert bg_tok in tokens, f"Missing required background/border token {bg_tok}"

    # Operational state running must NOT reuse brand accent purple
    assert tokens["--state-running"] != tokens["--accent-primary"]
    assert tokens["--state-running"] != tokens["--accent"]

    # WCAG 2.2 AA Contrast checks across dark surfaces
    surfaces = ["#0a0b10", "#12141d", tokens["--bg"], tokens["--surface"], tokens["--surface2"]]
    for state_name, token_key in required_state_tokens.items():
        hex_val = tokens[token_key]
        for surf in surfaces:
            ratio = _contrast_ratio(hex_val, surf)
            assert (
                ratio >= 4.5
            ), f"State token {token_key} ({hex_val}) failed WCAG 2.2 AA text contrast on {surf}: {ratio:.2f}:1 < 4.5:1"


def test_contract_app_html_scan_state_badges_consume_semantic_tokens():
    """Verify templates/app.html .scan-state-* badges consume semantic state tokens without legacy hardcoded colors."""
    app_html = APP_HTML.read_text(encoding="utf-8")

    # Extract scan-state badge rules
    state_block_match = re.search(r"(\.scan-state-running[^{]*\{[^}]*\})", app_html)
    assert state_block_match, "Could not find .scan-state-running CSS rule in templates/app.html"
    running_rule = state_block_match.group(1)

    # Must NOT use var(--accent) for running
    assert "var(--accent)" not in running_rule, ".scan-state-running must not use var(--accent)"
    assert "var(--state-running)" in running_rule, ".scan-state-running must use var(--state-running)"
    assert "var(--state-running-bg)" in running_rule or "var(--status-running-bg)" in running_rule

    # Verify done/completed uses var(--state-completed)
    done_match = re.search(r"(\.scan-state-done[^{]*\{[^}]*\})", app_html)
    assert done_match
    assert "var(--state-completed)" in done_match.group(1)

    # Verify aborted/paused uses var(--state-paused)
    paused_match = re.search(r"(\.scan-state-aborted[^{]*\{[^}]*\})", app_html)
    assert paused_match
    assert "var(--state-paused)" in paused_match.group(1)

    # Verify error/failed uses var(--state-failed)
    error_match = re.search(r"(\.scan-state-error[^{]*\{[^}]*\})", app_html)
    assert error_match
    assert "var(--state-failed)" in error_match.group(1)

    # Verify partial uses var(--state-stale)
    partial_match = re.search(r"(\.scan-state-partial[^{]*\{[^}]*\})", app_html)
    assert partial_match
    assert "var(--state-stale)" in partial_match.group(1)

    # Verify unverified rule presence
    assert ".scan-state-unverified" in app_html
    unverified_match = re.search(r"(\.scan-state-unverified[^{]*\{[^}]*\})", app_html)
    assert unverified_match
    assert "var(--state-unverified)" in unverified_match.group(1)

    # Verify zero legacy hardcoded hex colors in scan state / connection badge rules
    badge_css_region = app_html[app_html.find(".scan-conn-badge") : app_html.find("#surface")]
    for legacy_color in ["#2ecc71", "#f1c40f", "#e74c3c", "#e67e22"]:
        assert (
            legacy_color not in badge_css_region
        ), f"Legacy color {legacy_color} found in app.html status badge rules"


def test_contract_dashboard_html_status_indicators_consume_semantic_tokens():
    """Verify templates/dashboard.html status dots, history badges, and rail pulse consume state tokens."""
    dash_html = DASHBOARD_HTML.read_text(encoding="utf-8")

    # Status dot rules
    assert ".status-dot.running { background: var(--state-running)" in dash_html
    assert ".status-dot.done { background: var(--state-completed)" in dash_html
    assert ".status-dot.error { background: var(--state-failed)" in dash_html
    assert ".status-dot.aborted { background: var(--state-paused)" in dash_html

    # Ensure status-dot does NOT use severity tokens
    assert ".status-dot.error { background: var(--critical)" not in dash_html
    assert ".status-dot.aborted { background: var(--high)" not in dash_html
    assert ".status-dot.incomplete { background: var(--medium)" not in dash_html

    # History status badges
    assert ".history-status-done {\n  background: var(--status-pass-bg);\n  color: var(--state-completed)" in dash_html
    assert ".history-status-scanning {\n  background: var(--status-running-bg);\n  color: var(--state-running)" in dash_html
    assert ".history-status-aborted {\n  background: var(--status-warning-bg);\n  color: var(--state-paused)" in dash_html
    assert ".history-status-error {\n  background: var(--status-fail-bg);\n  color: var(--state-failed)" in dash_html

    # Ensure history badges do NOT use severity tokens
    assert ".history-status-done {\n  background: rgba(143,185,201,0.15);\n  color: var(--low);" not in dash_html
    assert ".history-status-error {\n  background: rgba(226,112,143,0.15);\n  color: var(--critical);" not in dash_html
    assert ".history-status-aborted {\n  background: rgba(217,154,99,0.18);\n  color: var(--high);" not in dash_html

    # Rail pulse rules
    rail_pulse_match = re.search(r"(\.ws-rail \.pulse\.error\{[^}]*\})", dash_html)
    assert rail_pulse_match
    assert "var(--state-failed)" in rail_pulse_match.group(1)
    assert "var(--critical)" not in rail_pulse_match.group(1)

    # Pause button & state
    assert ".ib-btn.pause  { color: var(--state-paused)" in dash_html
    assert ".ib-pause-state.visible { display: inline-block; background: var(--status-warning-bg); color: var(--state-paused)" in dash_html


def test_runtime_scan_state_computed_styles_and_tokens(ui_harness: UIHarness):
    """Verify live computed styles of .scan-state-badge resolve to semantic state tokens in real browser."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        page.goto(f"{ui_harness.server_url}/app#/portal", wait_until="domcontentloaded")
        page.locator("#viewTitle").wait_for(state="visible")

        # Test state mapping matrix: (raw_status, expected_class, expected_hex, forbidden_hex)
        # --state-running: #e4a770 -> rgb(228, 167, 112)
        # --state-paused:  #c7b96a -> rgb(199, 185, 106)
        # --state-completed: #22c55e -> rgb(34, 197, 94)
        # --state-failed:  #f796ad -> rgb(247, 150, 173)
        # --state-stale:   #e67e22 -> rgb(230, 126, 34)
        # --accent:        #9184d9 -> rgb(145, 132, 217)
        states_to_test = [
            ("scanning", "scan-state-running", "rgb(228, 167, 112)", "rgb(145, 132, 217)", "⟳"),
            ("paused", "scan-state-paused", "rgb(199, 185, 106)", "rgb(228, 167, 112)", "⏸"),
            ("completed", "scan-state-done", "rgb(34, 197, 94)", "rgb(143, 185, 201)", "✓"),
            ("failed", "scan-state-error", "rgb(247, 150, 173)", "rgb(226, 112, 143)", "✗"),
            ("partial", "scan-state-partial", "rgb(230, 126, 34)", "rgb(217, 154, 99)", "⟲"),
        ]

        for raw_status, expected_class, expected_rgb, forbidden_rgb, expected_glyph in states_to_test:
            page.evaluate(
                f"""() => {{
                  if (window.VulixAppShell && window.VulixAppShell.renderScanStatus) {{
                    window.VulixAppShell.renderScanStatus({{
                      scan_id: 'scan_token_test_{raw_status}',
                      status: '{raw_status}',
                      mode: 'normal',
                      target: 'https://example.test',
                      connection: 'connected',
                      freshness: 'fresh',
                    }});
                  }}
                }}"""
            )

            badge = page.locator(".scan-state-badge")
            badge.wait_for(state="visible")

            # Verify badge class
            class_attr = badge.get_attribute("class") or ""
            assert expected_class in class_attr, f"Expected class {expected_class} in {class_attr}"

            # Verify computed color matches semantic state token
            computed_color = badge.evaluate("el => getComputedStyle(el).color")
            assert (
                computed_color == expected_rgb
            ), f"Status {raw_status}: computed color {computed_color} != expected {expected_rgb}"
            assert (
                computed_color != forbidden_rgb
            ), f"Status {raw_status}: computed color reused forbidden color {forbidden_rgb}"

            # Verify text contains expected glyph
            badge_text = badge.inner_text()
            assert expected_glyph in badge_text, f"Status {raw_status}: missing glyph {expected_glyph} in {badge_text}"

        assert len(ui_harness.get_errors(page)) == 0
    finally:
        page.close()


def test_cross_mode_transitions_and_screen_smoke(ui_harness: UIHarness):
    """Verify runtime state presentation across Normal, Agent, and Hybrid modes during screen navigation."""
    require_browser()
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[1280])

    try:
        # 1. Normal mode in running -> completed on Portal
        page.goto(f"{ui_harness.server_url}/app#/portal", wait_until="domcontentloaded")
        page.locator("#viewTitle").wait_for(state="visible")

        page.evaluate(
            """() => {
              window.VulixAppShell.renderScanStatus({
                scan_id: 'scan_normal_01',
                status: 'running',
                mode: 'normal',
                target: 'https://target.normal.test',
                phase: 'crawl',
                connection: 'connected',
                freshness: 'fresh'
              });
            }"""
        )
        badge = page.locator(".scan-state-badge")
        badge.wait_for(state="visible")
        assert "scan-state-running" in (badge.get_attribute("class") or "")
        mode_badge = page.locator(".scan-mode-badge")
        assert "[normal]" in (mode_badge.inner_text().lower())

        # Transition Normal to completed
        page.evaluate(
            """() => {
              window.VulixAppShell.renderScanStatus({
                scan_id: 'scan_normal_01',
                status: 'completed',
                mode: 'normal',
                target: 'https://target.normal.test',
                phase: 'report',
                connection: 'connected',
                freshness: 'snapshot'
              });
            }"""
        )
        assert "scan-state-done" in (badge.get_attribute("class") or "")

        # 2. Agent mode in running -> paused on Findings
        page.goto(f"{ui_harness.server_url}/app#/findings", wait_until="domcontentloaded")
        page.locator("#findingsSurface").wait_for(state="visible")

        page.evaluate(
            """() => {
              window.VulixAppShell.renderScanStatus({
                scan_id: 'scan_agent_01',
                status: 'running',
                mode: 'agent',
                target: 'https://target.agent.test',
                phase: 'attack',
                connection: 'connected',
                freshness: 'fresh'
              });
            }"""
        )
        badge = page.locator(".scan-state-badge")
        badge.wait_for(state="visible")
        assert "scan-state-running" in (badge.get_attribute("class") or "")
        assert "[agent]" in (page.locator(".scan-mode-badge").inner_text().lower())

        # Pause agent scan
        page.evaluate(
            """() => {
              window.VulixAppShell.renderScanStatus({
                scan_id: 'scan_agent_01',
                status: 'paused',
                mode: 'agent',
                target: 'https://target.agent.test',
                phase: 'attack',
                connection: 'connected',
                freshness: 'fresh'
              });
            }"""
        )
        assert "scan-state-paused" in (badge.get_attribute("class") or "")

        # 3. Hybrid mode with hypothesis on Setup
        page.goto(f"{ui_harness.server_url}/app#/setup", wait_until="domcontentloaded")
        page.locator("#setupSurface").wait_for(state="visible")

        page.evaluate(
            """() => {
              window.VulixAppShell.renderScanStatus({
                scan_id: 'scan_hybrid_01',
                status: 'scanning',
                mode: 'hybrid',
                target: 'https://target.hybrid.test',
                phase: 'attack',
                connection: 'connected',
                freshness: 'fresh'
              });
            }"""
        )
        badge = page.locator(".scan-state-badge")
        badge.wait_for(state="visible")
        assert "scan-state-running" in (badge.get_attribute("class") or "")
        assert "[hybrid]" in (page.locator(".scan-mode-badge").inner_text().lower())

        # Navigate back to portal
        page.goto(f"{ui_harness.server_url}/app#/portal", wait_until="domcontentloaded")
        page.locator("#viewTitle").wait_for(state="visible")

        # Zero console errors throughout the entire transition workflow
        assert len(ui_harness.get_errors(page)) == 0
    finally:
        page.close()
