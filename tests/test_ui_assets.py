"""Dashboard shared-asset contract checks."""
import re
from pathlib import Path

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value


ROOT = Path(__file__).parents[1]
TOKENS = ROOT / "templates" / "ui" / "tokens.css"
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


def _token_map(css):
    root = re.search(r":root\s*\{([^}]*)\}", css)
    assert root
    return dict(re.findall(r"(--[\w-]+)\s*:\s*([^;]+);", root.group(1)))


def test_dashboard_tokens_match_frozen_values_and_load_before_styles():
    html = (ROOT / "templates" / "dashboard.html").read_text(encoding="utf-8")
    link = '<link rel="stylesheet" href="/ui/tokens.css">'
    assert link in html
    assert html.index(link) < html.index("<style>")
    assert _token_map(TOKENS.read_text(encoding="utf-8")) == EXPECTED_TOKENS


def test_ui_assets_are_scoped_and_protected():
    client = TestClient(MonitorServer().app)
    response = client.get("/ui/tokens.css")
    assert response.status_code == 200
    assert "text/css" in response.headers["content-type"]
    assert client.get("/ui/missing.css").status_code == 404
    assert client.get("/ui/%2e%2e/dashboard.html").status_code in {403, 404}

    token = "test-auth-token"
    protected = TestClient(MonitorServer(auth_token=token).app)
    headers = {"accept": "text/css"}
    asset = protected.get("/ui/tokens.css", headers=headers)
    existing = protected.get("/reports/missing/file.css", headers=headers)
    assert asset.status_code == existing.status_code == 401
    protected.cookies.set(SESSION_COOKIE, _session_value(token))
    assert protected.get("/ui/tokens.css").status_code == 200
