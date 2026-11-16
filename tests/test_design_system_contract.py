"""Automated contract tests for Vulix UI v3 Design System,

tokens contrast refinement, typography/density hierarchy, and composited badge contrast.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DESIGN_SYSTEM_DOC = ROOT / "docs" / "design_system.md"
TOKENS_CSS = ROOT / "templates" / "ui" / "tokens.css"


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
    # Resolve var() references within tokens
    resolved = {}
    for k, v in tokens.items():
        var_match = re.match(r"^var\((--[\w-]+)\)$", v)
        if var_match and var_match.group(1) in tokens:
            resolved[k] = tokens[var_match.group(1)]
        else:
            resolved[k] = v
    return resolved


def test_design_system_doc_structure_and_sections():
    """Verify docs/design_system.md exists and contains the 4 required sections and details."""
    assert DESIGN_SYSTEM_DOC.is_file(), f"Missing required document: {DESIGN_SYSTEM_DOC}"
    doc_content = DESIGN_SYSTEM_DOC.read_text(encoding="utf-8")

    # 1. Required core sections
    required_sections = [
        "Visual Anti-Pattern Checklist",
        "Decoration & Semantic Color Separation",
        "Typography & Data Density Guide",
        "Design Decision Log",
    ]
    for section in required_sections:
        assert section in doc_content, f"Missing section '{section}' in docs/design_system.md"

    # 2. Visual Anti-Pattern Checklist coverage
    required_anti_patterns = [
        "Decorative Gradients",
        "Gratuitous Glass",
        "Uniform Large Border-Radius",
        "Purposeless Card-in-Card Nesting",
        "Bento Grids",
        "Mixed Icon Families",
        "Vague CTA Labels",
    ]
    for pattern in required_anti_patterns:
        assert pattern in doc_content, f"Missing anti-pattern '{pattern}' in Visual Anti-Pattern Checklist"

    # Anti-pattern criteria, allowed uses, exception rationale
    assert "PROHIBITED" in doc_content
    assert "Allowed Uses" in doc_content
    assert "Exception Rationale" in doc_content

    # 3. Design Decision Log coverage for primary views
    required_views = [
        "Overview",
        "Scan Setup",
        "Live Monitor",
        "Crawl",
        "Findings",
        "Traffic",
        "Reports",
        "Settings",
    ]
    for view in required_views:
        assert view in doc_content, f"Missing view '{view}' in Design Decision Log"

    # Required table columns in Design Decision Log
    required_log_columns = [
        "User Task",
        "Primary Emphasis",
        "Visual / Interaction Order",
        "Adopted Pattern",
        "Rejected Template Alternative",
    ]
    for col in required_log_columns:
        assert col in doc_content, f"Missing column '{col}' in Design Decision Log table"


def test_tokens_typography_scale_and_density_scale():
    """Verify templates/ui/tokens.css defines typography hierarchy and row density tokens."""
    tokens = _parse_tokens(TOKENS_CSS.read_text(encoding="utf-8"))

    # Font family tokens
    assert "--font-sans" in tokens
    assert "--font-mono" in tokens

    # Typography scale
    assert tokens.get("--text-base") == "0.875rem"
    assert tokens.get("--text-xs") == "0.75rem"
    assert tokens.get("--text-2xs") == "0.7rem"
    assert tokens.get("--text-lg") == "1.15rem"
    assert "--text-xl" in tokens
    assert "--text-2xl" in tokens

    # Preservation of font-size-* tokens for backwards compatibility
    assert tokens.get("--font-size-base") == "0.875rem"
    assert tokens.get("--font-size-xs") == "0.75rem"
    assert tokens.get("--font-size-2xs") == "0.7rem"
    assert tokens.get("--font-size-lg") == "1.15rem"

    # Row density tokens
    assert tokens.get("--density-row-compact") == "28px"
    assert tokens.get("--density-row-standard") == "36px"


def test_tokens_semantic_separation_and_distinctness():
    """Verify brand, severity, execution state, and selection tokens are explicitly defined and separated."""
    tokens = _parse_tokens(TOKENS_CSS.read_text(encoding="utf-8"))

    # Brand tokens
    assert tokens.get("--accent-primary") == "#9184d9"
    assert tokens.get("--accent") == "#9184d9"

    # Severity tokens
    severity_tokens = {
        "critical": tokens.get("--critical"),
        "high": tokens.get("--high"),
        "medium": tokens.get("--medium"),
        "low": tokens.get("--low"),
        "info": tokens.get("--info"),
    }
    for sev_name, val in severity_tokens.items():
        assert val is not None, f"Missing severity token --{sev_name}"
        assert val.startswith("#"), f"Severity token --{sev_name} must be a hex color, got {val}"
        # Brand purple must not be reused for severity
        assert val != tokens["--accent-primary"], f"Severity {sev_name} must not reuse brand accent"

    # Execution / freshness state tokens
    required_states = ["running", "unverified", "stale", "paused", "completed", "failed"]
    for st in required_states:
        token_key = f"--state-{st}"
        assert token_key in tokens, f"Missing state token {token_key}"
        assert tokens[token_key].startswith("#"), f"State token {token_key} must resolve to a hex color"

    # Selection & focus tokens
    assert "--focus-ring" in tokens
    assert "--focus-outline" in tokens
    assert "--selection-bg" in tokens
    assert "--selection-border" in tokens
    assert tokens.get("--selection-border") == "#9184d9"


def test_wcag_22_aa_contrast_ratios_on_dark_surfaces():
    """Verify WCAG 2.2 AA contrast compliance (>= 4.5:1 text, >= 3.0:1 UI components) on dark surfaces."""
    tokens = _parse_tokens(TOKENS_CSS.read_text(encoding="utf-8"))

    # Dark background surfaces to test against
    surfaces = ["#0a0b10", "#12141d", tokens["--bg"], tokens["--surface"], tokens["--surface2"]]

    # Normal text tokens (WCAG 2.2 AA requires >= 4.5:1)
    normal_text_tokens = [
        ("--text", tokens["--text"]),
        ("--text-muted", tokens["--text-muted"]),
        ("--accent-primary", tokens["--accent-primary"]),
        ("--critical", tokens["--critical"]),
        ("--high", tokens["--high"]),
        ("--medium", tokens["--medium"]),
        ("--low", tokens["--low"]),
        ("--info", tokens["--info"]),
        ("--state-running", tokens["--state-running"]),
        ("--state-unverified", tokens["--state-unverified"]),
        ("--state-stale", tokens["--state-stale"]),
        ("--status-pass", tokens["--status-pass"]),
    ]

    for name, hex_val in normal_text_tokens:
        for surf in surfaces:
            ratio = _contrast_ratio(hex_val, surf)
            assert (
                ratio >= 4.5
            ), f"Token {name} ({hex_val}) failed WCAG 2.2 AA text contrast on surface {surf}: {ratio:.2f}:1 < 4.5:1"

    # UI component & selection border tokens (WCAG 2.2 AA requires >= 3.0:1)
    ui_component_tokens = [
        ("--selection-border", tokens["--selection-border"]),
    ]
    for name, hex_val in ui_component_tokens:
        for surf in surfaces:
            ratio = _contrast_ratio(hex_val, surf)
            assert (
                ratio >= 3.0
            ), f"Token {name} ({hex_val}) failed WCAG 2.2 AA UI boundary contrast on surface {surf}: {ratio:.2f}:1 < 3.0:1"


def test_severity_badge_text_contrast_on_composited_backgrounds():
    """Verify severity badge text against real 0.22-alpha composited background meets WCAG AA (>= 4.5:1)."""
    tokens = _parse_tokens(TOKENS_CSS.read_text(encoding="utf-8"))
    surfaces = ["#0a0b10", "#12141d", tokens["--bg"], tokens["--surface"], tokens["--surface2"]]

    severity_badge_tokens = [
        ("critical", tokens["--critical"]),
        ("high", tokens["--high"]),
        ("medium", tokens["--medium"]),
        ("low", tokens["--low"]),
        ("info", tokens["--info"]),
    ]

    badge_alpha = 0.22
    for sev_name, fg_hex in severity_badge_tokens:
        for surf_hex in surfaces:
            comp_bg = _composite(fg_hex, badge_alpha, surf_hex)
            ratio = _contrast_ratio(fg_hex, comp_bg)
            assert (
                ratio >= 4.5
            ), f"Badge {sev_name} ({fg_hex}) on {surf_hex} (composite: {comp_bg}) failed WCAG AA: {ratio:.2f}:1 < 4.5:1"


def test_tokens_css_comment_annotations_for_decorations():
    """Verify templates/ui/tokens.css includes explicit comment annotations for allowed vs prohibited decorations."""
    css_content = TOKENS_CSS.read_text(encoding="utf-8")

    # Extract the header comment block
    comment_match = re.search(r"/\*.*?\*/", css_content, re.DOTALL)
    assert comment_match, "Missing header comment in tokens.css"
    header_comment = comment_match.group(0)

    # Must contain decoration categories in comment bullets with PROHIBITED and ALLOWED rules
    categories = ["shadow", "blur", "radius", "border", "accent", "animation"]
    for cat in categories:
        assert re.search(
            rf"- {cat}s?:\s*PROHIBITED:.*?ALLOWED:", header_comment, re.IGNORECASE | re.DOTALL
        ), f"Missing structured decoration rule for '{cat}' in tokens.css header comment"



