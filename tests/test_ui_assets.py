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
