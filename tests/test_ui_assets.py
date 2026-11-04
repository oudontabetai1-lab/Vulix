"""Dashboard shared-asset contract checks."""
import re
from pathlib import Path

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value


ROOT = Path(__file__).parents[1]
TOKENS = ROOT / "templates" / "ui" / "tokens.css"
COMPONENTS = ROOT / "templates" / "ui" / "components.css"
EXPECTED_TOKENS = {
    "--bg": "#161826",
    "--surface": "#1c1e2c",
    "--surface2": "#232532",
    "--rail": "#12141f",
    "--border": "#3f424d",
    "--text": "#e9e9ed",
    "--text-muted": "#9397ab",
    "--accent": "#9184d9",
    "--accent-glow": "rgba(145,132,217,0.18)",
    "--critical": "#e2708f",
    "--high": "#d99a63",
    "--medium": "#c7b96a",
    "--low": "#8fb9c9",
    "--info": "#b5abfc",
    "--success": "var(--status-pass)",
    "--warning": "var(--status-warning)",
    "--running": "var(--status-running)",
    "--status-pass": "#22c55e",
    "--status-pass-bg": "rgba(34, 197, 94, 0.12)",
    "--status-pass-border": "rgba(34, 197, 94, 0.3)",
    "--status-fail": "#e2708f",
    "--status-fail-bg": "rgba(226, 112, 143, 0.12)",
    "--status-fail-border": "rgba(226, 112, 143, 0.3)",
    "--status-warning": "#c7b96a",
    "--status-warning-bg": "rgba(199, 185, 106, 0.12)",
    "--status-warning-border": "rgba(199, 185, 106, 0.3)",
    "--status-not-checked": "#9397ab",
    "--status-not-checked-bg": "#232532",
    "--status-not-checked-border": "#3f424d",
    "--status-unknown": "#9397ab",
    "--status-unknown-bg": "#232532",
    "--status-unknown-border": "#3f424d",
    "--status-unavailable": "#e2708f",
    "--status-unavailable-bg": "rgba(226, 112, 143, 0.12)",
    "--status-unavailable-border": "rgba(226, 112, 143, 0.3)",
    "--status-stale": "#d99a63",
    "--status-stale-bg": "rgba(217, 154, 99, 0.12)",
    "--status-stale-border": "rgba(217, 154, 99, 0.3)",
    "--status-running": "#d99a63",
    "--status-running-bg": "rgba(217, 154, 99, 0.12)",
    "--status-running-border": "rgba(217, 154, 99, 0.3)",
    "--space-xs": "4px",
    "--space-sm": "8px",
    "--space-md": "12px",
    "--space-lg": "16px",
    "--space-xl": "20px",
    "--space-2xl": "24px",
    "--space-3xl": "32px",
    "--density-compact-padding": "4px 8px",
    "--density-compact-gap": "4px",
    "--density-comfortable-padding": "8px 14px",
    "--density-comfortable-gap": "8px",
    "--density-spacious-padding": "16px 20px",
    "--density-spacious-gap": "16px",
    "--focus-ring": "0 0 0 2px var(--accent)",
    "--focus-ring-offset": "2px",
    "--focus-outline": "2px solid var(--accent)",
    "--state-error-text": "#e2708f",
    "--state-error-bg": "rgba(226, 112, 143, 0.12)",
    "--state-error-border": "rgba(226, 112, 143, 0.3)",
    "--state-loading-text": "#9397ab",
    "--state-empty-text": "#9397ab",
    "--graph-node-page": "#9184d9",
    "--graph-node-form": "#d99a63",
    "--graph-node-param": "#8fb9c9",
    "--graph-node-unknown": "#9397ab",
    "--graph-node-bg": "#1c1e2c",
    "--graph-node-findings": "#e2708f",
    "--graph-node-text": "#e9e9ed",
    "--graph-node-subtext": "#9397ab",
    "--graph-edge": "#4a5568",
    "--graph-edge-dot": "#9184d9",
}

EXPECTED_COMPONENT_SELECTORS = [
    ".history-btn",
    ".history-btn:hover",
    ".history-btn:focus-visible",
    ".history-btn.primary",
    ".history-btn.primary:hover",
    ".history-search-input",
    ".history-search-input:focus",
    ".history-filter-select",
    ".audit-btn",
    ".audit-btn:hover",
    ".audit-btn:focus-visible",
    ".audit-btn.primary",
    ".audit-btn.primary:hover",
    ".audit-search-input",
    ".audit-search-input:focus",
    ".audit-filter-select",
    ".ui-settings-container",
    ".ui-card",
    ".ui-card-header",
    ".ui-card-title",
    ".ui-form",
    ".ui-form-group",
    ".ui-form-row",
    ".ui-label",
    ".ui-checkbox-label",
    ".ui-hint",
    ".ui-input",
    ".ui-input:focus-visible",
    ".ui-select",
    ".ui-select:focus-visible",
    ".ui-actions",
    ".ui-status-text",
    ".ui-note",
    ".ui-toolbar",
    ".ui-table-wrap",
    ".ui-table-wrap:focus-visible",
    ".ui-table",
    ".ui-table th",
    ".ui-table td",
    ".ui-table tbody tr:hover",
    ".ui-table-empty",
    ".ui-badge",
    ".ui-badge.redacted",
    ".ui-badge.type",
    ".ui-badge.mode",
    ".ui-badge.diff",
    ".ui-code",
    ".ui-status",
    ".ui-status.loading",
    ".ui-status.error, .ui-status.unavailable",
    ".ui-status.success",
    ".ui-muted",
    ".ui-dialog-overlay, .ui-drawer-overlay",
    ".ui-dialog",
    ".ui-drawer",
    ".ui-dialog-header",
    ".ui-dialog-body",
    ".ui-dialog-footer",
    ".setup-readiness-section",
    ".setup-readiness-header",
    ".setup-readiness-title-row",
    ".setup-readiness-title",
    ".setup-readiness-desc",
    ".setup-preflight-btn",
    ".setup-preflight-btn:hover:not(:disabled)",
    ".setup-preflight-btn:disabled",
    ".setup-readiness-unavailable",
    ".setup-readiness-verdict-bar",
    ".setup-readiness-verdict-title",
    ".setup-readiness-verdict-badge",
    ".setup-readiness-checks-list",
    ".setup-readiness-check-item",
    ".setup-readiness-check-id",
    ".setup-readiness-status-chip",
    ".setup-readiness-check-detail",
    ".setup-prelaunch-summary",
    ".setup-prelaunch-header",
    ".setup-prelaunch-title-group",
    ".setup-prelaunch-title",
    ".setup-prelaunch-badge",
    ".setup-prelaunch-rerun-btn",
    ".setup-prelaunch-rerun-btn:hover:not(:disabled)",
    ".setup-prelaunch-rerun-btn:disabled",
    ".setup-prelaunch-message",
    ".setup-prelaunch-checks",
    ".setup-prelaunch-check-item",
    ".setup-prelaunch-check-id",
    ".setup-prelaunch-check-chip",
    ".setup-prelaunch-check-detail",
    ".setup-prelaunch-empty",
    ".setup-status-pass, .setup-verdict-pass",
    ".setup-status-warning, .setup-verdict-warning",
    ".setup-status-fail, .setup-verdict-fail",
    ".setup-status-not-checked, .setup-status-not-applicable, .setup-status-unknown, .setup-verdict-unknown",
    ".ui-status-badge",
    ".ui-status-pass, .ui-status-badge.pass",
    ".ui-status-fail, .ui-status-badge.fail",
    ".ui-status-warning, .ui-status-badge.warning",
    ".ui-status-not-checked, .ui-status-badge.not-checked",
    ".ui-status-unknown, .ui-status-badge.unknown",
    ".ui-status-unavailable, .ui-status-badge.unavailable",
    ".ui-status-stale, .ui-status-badge.stale",
    ".ui-status-running, .ui-status-badge.running",
    ".ui-state-empty",
    ".ui-state-loading",
    ".ui-state-error",
    ".ui-focus-ring:focus-visible, :focus-visible",
    ".crawl-kind-page",
    ".crawl-kind-form",
    ".crawl-kind-param",
    ".crawl-kind-unknown",
    ".crawl-tree-dot",
    ".crawl-svg-marker-path",
    ".crawl-svg-edge",
    ".crawl-svg-edge-dot",
    ".crawl-svg-node",
    ".crawl-svg-node-rect",
    ".crawl-svg-node-rect.has-findings",
    ".crawl-svg-node-rect.is-selected",
    ".crawl-svg-kind-dot",
    ".crawl-svg-title",
    ".crawl-svg-subtitle",
    ".crawl-clickable",
    ".crawl-mt-14",
    ".crawl-mt-6",
    ".crawl-zoom-group.crawl-hidden",
    ".findings-notfound-title",
    ".findings-notfound-text",
    ".findings-detail-th",
    ".findings-chip-clear",
    ".setup-search-hidden",
    ".setup-check-item",
    ".setup-check-item > label",
    ".setup-check-info, .setup-check-popover-close",
    ".setup-check-info",
    ".setup-check-info:focus-visible, .setup-check-popover-close:focus-visible",
    ".setup-check-popover",
    ".setup-check-popover h3",
    ".setup-check-popover h4",
    ".setup-check-popover p",
    ".setup-check-popover-close",
]


def _token_map(css):
    root = re.search(r":root\s*\{([^}]*)\}", css)
    assert root
    return dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", root.group(1)))


def _parse_css_rules(css_text):
    clean = re.sub(r"/\*.*?\*/", "", css_text, flags=re.DOTALL)
    blocks = re.findall(r"([^{}]+)\{([^{}]+)\}", clean)
    rules = []
    for sel, decls in blocks:
        sel_clean = " ".join(sel.split())
        decl_list = [
            tuple(part.strip() for part in d.split(":", 1))
            for d in decls.split(";")
            if d.strip() and ":" in d
        ]
        rules.append((sel_clean, decl_list))
    return rules


def test_dashboard_tokens_match_frozen_values_and_load_before_styles():
    html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    link = '<link rel="stylesheet" href="/ui/tokens.css">'
    assert link in html
    assert html.index(link) < html.index("<style>")
    assert _token_map(TOKENS.read_text(encoding="utf-8")) == EXPECTED_TOKENS


def test_dashboard_components_match_exact_selectors_and_order():
    html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    link = '<link rel="stylesheet" href="/ui/components.css">'
    tokens_link = '<link rel="stylesheet" href="/ui/tokens.css">'
    assert link in html
    assert tokens_link in html
    assert html.index(tokens_link) < html.index(link) < html.index("<style>")

    css_content = COMPONENTS.read_text(encoding="utf-8")
    rules = _parse_css_rules(css_content)
    selectors = [r[0] for r in rules]
    assert selectors == EXPECTED_COMPONENT_SELECTORS

    # Assert required states are present for button, input, select
    assert any(":focus" in s or ":focus-visible" in s for s in selectors)
    assert any(":hover" in s for s in selectors)

    # Declarations assert for sample component rules
    rules_dict = dict(rules)
    assert ("cursor", "pointer") in rules_dict[".history-btn"]
    assert ("border-color", "var(--accent)") in rules_dict[".history-btn:hover"]
    assert ("outline", "2px solid var(--accent)") in rules_dict[".history-btn:focus-visible"]
    assert ("border-color", "var(--accent)") in rules_dict[".history-search-input:focus"]


def test_ui_assets_are_scoped_and_protected():
    client = TestClient(MonitorServer().app)

    # tokens.css
    response = client.get("/ui/tokens.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]

    # components.css
    response_comp = client.get("/ui/components.css")
    assert response_comp.status_code == 200
    assert "text/css" in response_comp.headers["content-type"]

    # api-client.js
    response_api = client.get("/ui/api-client.js")
    assert response_api.status_code == 200
    assert any(m in response_api.headers["content-type"] for m in ["javascript", "text/javascript"])

    # evidence viewer registry
    response_evidence = client.get("/ui/evidence-viewer-registry.js")
    assert response_evidence.status_code == 200
    assert any(m in response_evidence.headers["content-type"] for m in ["javascript", "text/javascript"])

    # missing and traversal
    assert client.get("/ui/missing.css").status_code == 404
    assert client.get("/ui/%2e%2e/dashboard.html").status_code in {403, 404}

    token = "test-auth-token"
    protected = TestClient(MonitorServer(auth_token=token).app)
    headers = {"accept": "text/css"}
    asset = protected.get("/ui/tokens.css", headers=headers)
    asset_comp = protected.get("/ui/components.css", headers=headers)
    asset_api = protected.get("/ui/api-client.js")
    asset_evidence = protected.get("/ui/evidence-viewer-registry.js")
    existing = protected.get("/reports/missing/file.css", headers=headers)
    assert asset.status_code == asset_comp.status_code == asset_api.status_code == asset_evidence.status_code == existing.status_code == 401
    protected.cookies.set(SESSION_COOKIE, _session_value(token))
    assert protected.get("/ui/tokens.css").status_code == 200
    assert protected.get("/ui/components.css").status_code == 200
    assert protected.get("/ui/api-client.js").status_code == 200
    assert protected.get("/ui/evidence-viewer-registry.js").status_code == 200


def test_logo_and_favicon_asset_delivery_and_auth_protection():
    client = TestClient(MonitorServer().app)

    # 1. Successful 200 and correct image MIME types
    logo_res = client.get("/ui/vulix-logo.png")
    assert logo_res.status_code == 200
    assert "image/png" in logo_res.headers["content-type"]

    mark_res = client.get("/ui/vulix-logo-mark.png")
    assert mark_res.status_code == 200
    assert "image/png" in mark_res.headers["content-type"]

    fav_res = client.get("/ui/favicon.png")
    assert fav_res.status_code == 200
    assert "image/png" in fav_res.headers["content-type"]

    fav_ico_res = client.get("/ui/favicon.ico")
    assert fav_ico_res.status_code == 200
    assert any(mime in fav_ico_res.headers["content-type"] for mime in ["image/x-icon", "image/vnd.microsoft.icon"])

    apple_res = client.get("/ui/apple-touch-icon.png")
    assert apple_res.status_code == 200
    assert "image/png" in apple_res.headers["content-type"]

    # Root /favicon.ico and /apple-touch-icon.png are public and work without auth
    root_ico = client.get("/favicon.ico")
    assert root_ico.status_code == 200
    assert any(mime in root_ico.headers["content-type"] for mime in ["image/x-icon", "image/vnd.microsoft.icon"])

    root_apple = client.get("/apple-touch-icon.png")
    assert root_apple.status_code == 200
    assert "image/png" in root_apple.headers["content-type"]

    # Missing asset returns 404
    assert client.get("/ui/missing-logo.png").status_code == 404

    # Path traversal rejected
    assert client.get("/ui/%2e%2e/dashboard.html").status_code in {403, 404}

    # 2. Auth behavior: only explicit login assets are public without auth
    token = "test-auth-token"
    protected = TestClient(MonitorServer(auth_token=token).app)
    img_headers = {"accept": "image/png"}

    # Public login assets accessible without session -> 200
    assert protected.get("/ui/vulix-logo-mark.png", headers=img_headers).status_code == 200
    assert protected.get("/ui/favicon.png", headers=img_headers).status_code == 200
    assert protected.get("/ui/favicon.ico").status_code == 200
    assert protected.get("/ui/apple-touch-icon.png", headers=img_headers).status_code == 200
    assert protected.get("/favicon.ico").status_code == 200
    assert protected.get("/apple-touch-icon.png").status_code == 200

    # Non-public assets rejected without session -> 401
    assert protected.get("/ui/vulix-logo.png", headers=img_headers).status_code == 401
    assert protected.get("/ui/tokens.css").status_code == 401

    # Referer: /login spoof must NOT grant access to non-public assets
    assert protected.get("/ui/vulix-logo.png", headers={"referer": "/login"}).status_code == 401
    assert protected.get("/ui/tokens.css", headers={"referer": "/login"}).status_code == 401
    assert protected.get("/ui/tokens.css", headers={"referer": "http://testserver/login"}).status_code == 401

    # With session cookie -> 200
    protected.cookies.set(SESSION_COOKIE, _session_value(token))
    assert protected.get("/ui/vulix-logo.png").status_code == 200
    assert protected.get("/ui/tokens.css").status_code == 200
    assert protected.get("/ui/vulix-logo-mark.png").status_code == 200
    assert protected.get("/ui/favicon.png").status_code == 200
    assert protected.get("/ui/apple-touch-icon.png").status_code == 200


def test_html_brand_wiring_and_vulix_wordmark():
    server = MonitorServer()

    # 1. Dashboard (/monitor)
    dash_html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    assert "<title>Vulix — Live Monitor</title>" in dash_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in dash_html
    assert '<link rel="apple-touch-icon" href="/ui/apple-touch-icon.png">' in dash_html
    assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in dash_html
    assert 'class="hdr-brand"' in dash_html
    assert 'Vulix <span>Scan Setup</span>' in dash_html
    # Ensure tool name remains untouched
    assert "tool: 'WScan'" in dash_html

    # 2. Portal (/)
    portal_html = (ROOT / "templates" / "portal.html").read_text(encoding="utf-8")
    assert "<title>Vulix — Server Portal</title>" in portal_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in portal_html
    assert '<link rel="apple-touch-icon" href="/ui/apple-touch-icon.png">' in portal_html
    assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in portal_html
    assert '<h1>Vulix</h1>' in portal_html

    # 3. Login page (/login)
    login_html = server._login_html()
    assert "<title>Vulix — ログイン</title>" in login_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in login_html
    assert '<link rel="apple-touch-icon" href="/ui/apple-touch-icon.png">' in login_html
    assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in login_html
    assert '<h1>Vulix</h1>' in login_html

    # 4. App Shell (/app)
    app_html = (ROOT / "templates" / "app.html").read_text(encoding="utf-8")
    assert "<title>Vulix</title>" in app_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in app_html
    assert '<link rel="apple-touch-icon" href="/ui/apple-touch-icon.png">' in app_html
    assert '<header role="banner"><img src="/ui/vulix-logo-mark.png" alt="Vulix"' in app_html
    assert '<div class="brand"><img src="/ui/vulix-logo-mark.png" alt="Vulix">Vulix</div>' in app_html

    # Invariant: Every dashboard page must use accessible alt text and avoid empty alt attributes on the logo
    for name, html_content in [
        ("dashboard", dash_html),
        ("portal", portal_html),
        ("login", login_html),
        ("app", app_html),
    ]:
        assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in html_content, f"Missing accessible logo mark in {name}"
        assert '<img src="/ui/vulix-logo-mark.png" alt=""' not in html_content, f"Empty alt found in {name}"


def _png_dimensions(data: bytes) -> tuple[int, int]:
    """PNG の IHDR チャンクから (width, height) をビッグエンディアン uint32 でパースする。"""
    assert len(data) >= 24, "PNG data too short"
    assert data[:8] == b"\x89PNG\r\n\x1a\n", "Invalid PNG signature"
    assert data[12:16] == b"IHDR", "Missing IHDR chunk"
    import struct
    width, height = struct.unpack(">II", data[16:24])
    return width, height


def _ico_dimensions(data: bytes) -> set[tuple[int, int]]:
    """ICO ファイルヘッダとディレクトリエントリから解像度一覧をパースする（PIL 不要）。"""
    assert len(data) >= 6, "ICO data too short"
    import struct
    reserved, ico_type, count = struct.unpack("<HHH", data[:6])
    assert reserved == 0 and ico_type == 1, "Invalid ICO header"
    sizes: set[tuple[int, int]] = set()
    for i in range(count):
        offset = 6 + i * 16
        assert len(data) >= offset + 16, "ICO directory entry truncated"
        width, height = struct.unpack("<BB", data[offset:offset + 2])
        w = 256 if width == 0 else width
        h = 256 if height == 0 else height
        sizes.add((w, h))
    return sizes


def test_vulix_logo_sha256_byte_parity_and_favicon_dimensions():
    import hashlib

    logo_path = ROOT / "templates" / "ui" / "vulix-logo.png"
    assert logo_path.is_file()

    expected_sha = "d6aa10fbd221d54ffb050cf08a96fb1512b8437b08e80944690b50674aa70219"
    actual_sha = hashlib.sha256(logo_path.read_bytes()).hexdigest()
    assert actual_sha == expected_sha, f"Logo SHA mismatch: {actual_sha} != {expected_sha}"
    assert _png_dimensions(logo_path.read_bytes()) == (1254, 1254)

    fav_path = ROOT / "templates" / "ui" / "favicon.png"
    assert fav_path.is_file()
    assert _png_dimensions(fav_path.read_bytes()) == (32, 32)

    mark_path = ROOT / "templates" / "ui" / "vulix-logo-mark.png"
    assert mark_path.is_file()
    assert _png_dimensions(mark_path.read_bytes()) == (96, 96)

    apple_path = ROOT / "templates" / "ui" / "apple-touch-icon.png"
    assert apple_path.is_file()
    assert _png_dimensions(apple_path.read_bytes()) == (180, 180)

    ico_path = ROOT / "templates" / "ui" / "favicon.ico"
    assert ico_path.is_file()
    assert ico_path.stat().st_size > 0
    assert _ico_dimensions(ico_path.read_bytes()) == {(16, 16), (32, 32), (48, 48)}


def test_semantic_state_tokens_presence_and_structure():
    """Verify presence of all semantic status, spacing, density, and state tokens."""
    token_dict = _token_map(TOKENS.read_text(encoding="utf-8"))

    # 1. Status colours: pass, fail, warning, not checked, unknown, unavailable, stale, running
    required_status_keys = [
        "pass", "fail", "warning", "not-checked", "unknown", "unavailable", "stale", "running"
    ]
    for key in required_status_keys:
        assert f"--status-{key}" in token_dict, f"Missing status token: --status-{key}"
        assert f"--status-{key}-bg" in token_dict, f"Missing status bg token: --status-{key}-bg"
        assert f"--status-{key}-border" in token_dict, f"Missing status border token: --status-{key}-border"

    # Brand colours isolated from status
    assert token_dict["--accent"] == "#9184d9"
    assert token_dict["--accent-glow"] == "rgba(145,132,217,0.18)"
    assert token_dict["--status-pass"] != token_dict["--accent"]

    # 2. Spacing scale
    for sp in ["xs", "sm", "md", "lg", "xl", "2xl", "3xl"]:
        assert f"--space-{sp}" in token_dict, f"Missing spacing token: --space-{sp}"

    # 3. Density scale
    for density in ["compact", "comfortable", "spacious"]:
        assert f"--density-{density}-padding" in token_dict
        assert f"--density-{density}-gap" in token_dict

    # 4. Focus ring
    assert "--focus-ring" in token_dict
    assert "--focus-ring-offset" in token_dict
    assert "--focus-outline" in token_dict

    # 5. State patterns
    assert "--state-error-text" in token_dict
    assert "--state-error-bg" in token_dict
    assert "--state-error-border" in token_dict
    assert "--state-loading-text" in token_dict
    assert "--state-empty-text" in token_dict


def test_token_usage_in_components_and_app_shell():
    """Verify components.css and app.html utilize semantic tokens rather than raw colors."""
    components_css = COMPONENTS.read_text(encoding="utf-8")
    app_html = (ROOT / "templates" / "app.html").read_text(encoding="utf-8")

    # Tokens referenced in components.css
    assert "var(--status-pass" in components_css
    assert "var(--status-fail" in components_css
    assert "var(--status-warning" in components_css
    assert "var(--status-not-checked" in components_css
    assert "var(--status-unknown" in components_css
    assert "var(--status-unavailable" in components_css
    assert "var(--status-stale" in components_css
    assert "var(--status-running" in components_css
    assert "var(--space-" in components_css
    assert "var(--state-error-" in components_css
    assert "var(--state-loading-" in components_css
    assert "var(--state-empty-" in components_css

    # Tokens referenced in app.html
    assert "var(--status-pass" in app_html
    assert "var(--status-fail" in app_html
    assert "var(--status-warning" in app_html
    assert "var(--status-not-checked" in app_html
    assert "var(--status-unknown" in app_html
    assert "var(--status-stale" in app_html
    assert "var(--focus-outline" in app_html or "outline: 2px solid var(--accent)" in app_html


def test_all_status_states_have_text_labels():
    """Verify that every semantic status state corresponds to an explicit text label (never colour alone)."""
    # 1. Setup module readiness status mappings
    setup_code = (ROOT / "templates" / "ui" / "setup-module.js").read_text(encoding="utf-8")
    expected_setup_mappings = {
        "pass": "✓ OK",
        "warning": "警告",
        "fail": "✗ 失敗",
        "not_checked": "未確認",
        "not_applicable": "非該当",
        "unknown": "不明",
    }
    for state_key, text_label in expected_setup_mappings.items():
        assert text_label in setup_code, f"Setup module missing text label for {state_key}: {text_label}"

    # 2. Crawl module completeness badges
    crawl_code = (ROOT / "templates" / "ui" / "crawl-module.js").read_text(encoding="utf-8")
    expected_crawl_labels = ["完全 (Complete)", "一部のみ (Partial)", "未確定 (Unknown)"]
    for label in expected_crawl_labels:
        assert label in crawl_code, f"Crawl module missing text label: {label}"

    # 3. Agent Skills availability badges
    skills_code = (ROOT / "templates" / "ui" / "agent-skills-module.js").read_text(encoding="utf-8")
    assert "availableLabel" in skills_code
    for label in ["利用可能", "利用不可", "unavailable"]:
        assert label in skills_code, f"Agent skills module missing text label: {label}"

    # 4. Findings module verification state badges
    findings_code = (ROOT / "templates" / "ui" / "findings-module.js").read_text(encoding="utf-8")
    expected_findings_labels = [
        "reproduced", "assumed（推定）", "not reproduced", "skipped (needs review)",
        "not tested（未検査）", "unknown（未確定）", "not verified（未確証）"
    ]
    for label in expected_findings_labels:
        assert label in findings_code, f"Findings module missing text label: {label}"
