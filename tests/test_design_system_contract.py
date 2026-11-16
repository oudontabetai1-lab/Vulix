"""Automated contract tests for Vulix UI v3 Design System,

tokens contrast refinement, typography/density hierarchy, and scope immutability.
"""
from __future__ import annotations

import re
import subprocess
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


def _parse_tokens(css_text: str) -> dict[str, str]:
    root_match = re.search(r":root\s*\{([^}]*)\}", css_text)
    assert root_match, "Could not find :root block in tokens.css"
    raw_tokens = re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", root_match.group(1))
    return {k.strip(): v.strip() for k, v in raw_tokens}


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
    assert tokens.get("--text-2xs") in {"0.6875rem", "0.7rem"}
    assert "--text-lg" in tokens
    assert "--text-xl" in tokens
    assert "--text-2xl" in tokens

    # Preservation of font-size-* tokens for backwards compatibility
    assert tokens.get("--font-size-base") == "0.875rem"
    assert tokens.get("--font-size-xs") == "0.75rem"
    assert tokens.get("--font-size-2xs") in {"0.6875rem", "0.7rem"}

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
    required_states = ["running", "unverified", "stale"]
    for st in required_states:
        token_key = f"--state-{st}"
        assert token_key in tokens, f"Missing state token {token_key}"
        assert tokens[token_key].startswith("#"), f"State token {token_key} must be a hex color"

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


def test_tokens_css_comment_annotations_for_decorations():
    """Verify templates/ui/tokens.css includes explicit comment annotations for allowed vs prohibited decorations."""
    css_content = TOKENS_CSS.read_text(encoding="utf-8")

    # Must contain decoration categories in comments
    categories = ["shadow", "blur", "radius", "border", "accent", "animation"]
    for cat in categories:
        assert cat in css_content.lower(), f"Missing decoration rule for '{cat}' in tokens.css comments"

    assert "PROHIBITED" in css_content
    assert "ALLOWED" in css_content


def test_protected_modules_remain_unmodified():
    """Verify templates/ui/findings-module.js, crawl-module.js, and traffic-module.js are untouched."""
    protected_files = [
        "templates/ui/findings-module.js",
        "templates/ui/crawl-module.js",
        "templates/ui/traffic-module.js",
    ]
    # Check git diff against origin/main for protected files
    diff_output = subprocess.check_output(
        ["git", "diff", "--name-only", "origin/main", "--"] + protected_files,
        cwd=ROOT,
        text=True,
    ).strip()

    assert not diff_output, (
        f"Protected files were modified! Diff detected in:\n{diff_output}\n"
        "Scope rule: Do NOT touch findings-module.js, crawl-module.js, or traffic-module.js"
    )
