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
    "--success": "#8fb9c9",
    "--running": "#d99a63",
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

    # missing and traversal
    assert client.get("/ui/missing.css").status_code == 404
    assert client.get("/ui/%2e%2e/dashboard.html").status_code in {403, 404}

    token = "test-auth-token"
    protected = TestClient(MonitorServer(auth_token=token).app)
    headers = {"accept": "text/css"}
    asset = protected.get("/ui/tokens.css", headers=headers)
    asset_comp = protected.get("/ui/components.css", headers=headers)
    existing = protected.get("/reports/missing/file.css", headers=headers)
    assert asset.status_code == asset_comp.status_code == existing.status_code == 401
    protected.cookies.set(SESSION_COOKIE, _session_value(token))
    assert protected.get("/ui/tokens.css").status_code == 200
    assert protected.get("/ui/components.css").status_code == 200


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

    # Root /favicon.ico is public and works without auth
    root_ico = client.get("/favicon.ico")
    assert root_ico.status_code == 200
    assert any(mime in root_ico.headers["content-type"] for mime in ["image/x-icon", "image/vnd.microsoft.icon"])

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
    assert protected.get("/favicon.ico").status_code == 200

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


def test_html_brand_wiring_and_vulix_wordmark():
    server = MonitorServer()

    # 1. Dashboard
    dash_html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    assert "<title>Vulix — Live Monitor</title>" in dash_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in dash_html
    assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in dash_html
    assert 'Vulix <span>Scan Setup</span>' in dash_html
    # Ensure tool name remains untouched
    assert "tool: 'WScan'" in dash_html

    # 2. Portal
    portal_html = (ROOT / "templates" / "portal.html").read_text(encoding="utf-8")
    assert "<title>Vulix — Server Portal</title>" in portal_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in portal_html
    assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in portal_html
    assert '<h1>Vulix</h1>' in portal_html

    # 3. Login page
    login_html = server._login_html()
    assert "<title>Vulix — ログイン</title>" in login_html
    assert '<link rel="icon" type="image/png" href="/ui/favicon.png">' in login_html
    assert '<img src="/ui/vulix-logo-mark.png" alt="Vulix"' in login_html
    assert '<h1>Vulix</h1>' in login_html


def test_vulix_logo_sha256_byte_parity_and_favicon_dimensions():
    import hashlib
    from PIL import Image

    logo_path = ROOT / "templates" / "ui" / "vulix-logo.png"
    assert logo_path.is_file()

    expected_sha = "d6aa10fbd221d54ffb050cf08a96fb1512b8437b08e80944690b50674aa70219"
    actual_sha = hashlib.sha256(logo_path.read_bytes()).hexdigest()
    assert actual_sha == expected_sha, f"Logo SHA mismatch: {actual_sha} != {expected_sha}"

    fav_path = ROOT / "templates" / "ui" / "favicon.png"
    assert fav_path.is_file()
    with Image.open(fav_path) as im:
        assert im.size == (32, 32)

    mark_path = ROOT / "templates" / "ui" / "vulix-logo-mark.png"
    assert mark_path.is_file()
    with Image.open(mark_path) as im:
        assert im.size == (96, 96)
