"""ログイン形態網羅マトリクス検証用ループバック FastAPI フィクスチャ。

以下の7形態のログイン・保護リソース・パスワード不一致経路を提供する：
  (1) plain HTML form + cookie
  (2) username step then password step (多段ログイン)
  (3) login form inside a modal on the landing page (モーダル内フォーム)
  (4) SPA fetch login returning a JWT (Bearer) with no cookie (Cookie なしトークン)
  (5) cookie login that then requires an OTP page (未設定 solver → CHALLENGE / 未完了)
  (6) login that redirects to in-scope IdP and back (同一ホスト内 IdP 連携)
  (7) login that silently fails redirecting to public page with rotated non-auth cookie (非認証 Cookie のみ)
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from html import escape
from typing import List

from fastapi import FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

USERNAME = "fixture-user@example.test"
PASSWORD = "fixture-password"
WRONG_PASSWORD = "wrong-fixture-password"


@dataclass(frozen=True)
class LoginVariantSpec:
    """ログイン形態の検証仕様定義。"""
    variant_id: int
    name: str
    description: str
    login_path: str
    protected_path: str
    expected_valid_auto_login: bool
    expected_valid_state: str
    expected_valid_reasons: List[str]
    expected_valid_proof: str
    expected_valid_authenticated_coverage: bool
    expected_wrong_auto_login: bool = False
    expected_wrong_state: str = "failure"
    expected_wrong_reasons: List[str] = field(default_factory=lambda: ["http_401"])
    expected_wrong_proof: str = "unknown"
    expected_wrong_authenticated_coverage: bool = False


VARIANTS: List[LoginVariantSpec] = [
    LoginVariantSpec(
        variant_id=1,
        name="plain_html_form_cookie",
        description="Plain HTML form with session cookie",
        login_path="/v1/login",
        protected_path="/v1/protected",
        expected_valid_auto_login=True,
        expected_valid_state="success",
        expected_valid_reasons=[],
        expected_valid_proof="verified",
        expected_valid_authenticated_coverage=True,
    ),
    LoginVariantSpec(
        variant_id=2,
        name="username_then_password_step",
        description="Username-first step followed by password-only step",
        login_path="/v2/login",
        protected_path="/v2/protected",
        expected_valid_auto_login=True,
        expected_valid_state="success",
        expected_valid_reasons=[],
        expected_valid_proof="verified",
        expected_valid_authenticated_coverage=True,
    ),
    LoginVariantSpec(
        variant_id=3,
        name="modal_login_form",
        description="Login form embedded inside a modal on landing page",
        login_path="/v3/login",
        protected_path="/v3/protected",
        expected_valid_auto_login=True,
        expected_valid_state="success",
        expected_valid_reasons=[],
        expected_valid_proof="verified",
        expected_valid_authenticated_coverage=True,
    ),
    LoginVariantSpec(
        variant_id=4,
        name="spa_fetch_jwt_no_cookie",
        description="SPA fetch login returning JWT Bearer token with no cookie",
        login_path="/v4/login",
        protected_path="/v4/protected",
        expected_valid_auto_login=True,
        expected_valid_state="success",
        expected_valid_reasons=[],
        expected_valid_proof="verified",
        expected_valid_authenticated_coverage=True,
    ),
    LoginVariantSpec(
        variant_id=5,
        name="cookie_then_otp_challenge",
        description="Cookie login that transitions to an OTP verification page",
        login_path="/v5/login",
        protected_path="/v5/protected",
        expected_valid_auto_login=False,
        expected_valid_state="challenge",
        expected_valid_reasons=["mfa"],
        expected_valid_proof="unknown",
        expected_valid_authenticated_coverage=False,
    ),
    LoginVariantSpec(
        variant_id=6,
        name="idp_redirect_and_back",
        description="Login redirecting to in-scope IdP host path and returning via callback",
        login_path="/v6/login",
        protected_path="/v6/protected",
        expected_valid_auto_login=True,
        expected_valid_state="success",
        expected_valid_reasons=[],
        expected_valid_proof="verified",
        expected_valid_authenticated_coverage=True,
    ),
    LoginVariantSpec(
        variant_id=7,
        name="silent_failure_rotated_cookie",
        description="Silently fails by redirecting to public page with rotated non-auth cookie",
        login_path="/v7/login",
        protected_path="/v7/protected",
        expected_valid_auto_login=False,
        expected_valid_state="failure",
        expected_valid_reasons=["protected_access_denied"],
        expected_valid_proof="denied",
        expected_valid_authenticated_coverage=False,
        expected_wrong_reasons=["protected_access_denied"],
        expected_wrong_proof="denied",
    ),
]


def _protected_html(variant_id: int, q: str = "", safe_q: str = "") -> str:
    """脆弱性検査用の保護リソース HTML（XSS 反射 + 安全ツイン）。"""
    reflected = f'<div id="reflected-vuln">Results for: {q}</div>' if q else ""
    safe_reflected = f'<div id="reflected-safe">Safe: {escape(safe_q)}</div>' if safe_q else ""
    return f"""<!doctype html>
<html>
  <head><title>Protected Resource v{variant_id}</title></head>
  <body>
    <h1>Protected Resource v{variant_id}</h1>
    <a href="/v{variant_id}/logout">Log out</a>
    <p>Confidential data for authorized users only.</p>
    <form action="/v{variant_id}/protected" method="get">
      <label for="q">Vulnerable Query</label>
      <input id="q" name="q" value="{escape(q)}">
      <label for="safe_q">Safe Query</label>
      <input id="safe_q" name="safe_q" value="{escape(safe_q)}">
      <button type="submit">Search</button>
    </form>
    {reflected}
    {safe_reflected}
  </body>
</html>"""


def create_app() -> FastAPI:
    """全7形態のテスト用エンドポイントを提供する FastAPI アプリケーションを構築する。"""
    app = FastAPI(title="Login Matrix E2E Fixture App")

    # =========================================================================
    # Variant 1: Plain HTML form + cookie
    # =========================================================================
    @app.get("/v1/login", response_class=HTMLResponse)
    async def v1_login_get():
        return """<!doctype html><html><body>
<h1>Sign in</h1>
<form action="/v1/login" method="post">
  <label for="username">Username</label>
  <input id="username" name="username" type="text" autocomplete="username">
  <label for="password">Password</label>
  <input id="password" name="password" type="password" autocomplete="current-password">
  <button id="login-submit" type="submit">Log in</button>
</form>
</body></html>"""

    @app.post("/v1/login")
    async def v1_login_post(username: str = Form(""), password: str = Form("")):
        if username == USERNAME and password == PASSWORD:
            resp = RedirectResponse("/v1/dashboard", status_code=303)
            resp.set_cookie("session_v1", "valid_session_v1", path="/", httponly=True)
            return resp
        return HTMLResponse(
            '<p>Invalid credentials</p><form action="/v1/login" method="post">'
            '<input name="username"><input name="password" type="password"><button type="submit">Log in</button></form>',
            status_code=401,
        )

    @app.get("/v1/dashboard", response_class=HTMLResponse)
    async def v1_dashboard(request: Request):
        if request.cookies.get("session_v1") == "valid_session_v1":
            return '<h1>Dashboard</h1><a href="/v1/logout">Log out</a><p>Protected area v1</p>'
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v1/protected", response_class=HTMLResponse)
    async def v1_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.cookies.get("session_v1") == "valid_session_v1":
            return _protected_html(1, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v1/logout")
    async def v1_logout():
        resp = RedirectResponse("/v1/login", status_code=303)
        resp.delete_cookie("session_v1", path="/")
        return resp

    # =========================================================================
    # Variant 2: Username step then password step
    # =========================================================================
    @app.get("/v2/login", response_class=HTMLResponse)
    async def v2_login_get():
        return """<!doctype html><html><body>
<h2>Sign in</h2>
<form action="/v2/step2" method="post">
  <label for="email">Email</label>
  <input type="email" id="email" name="email">
  <button id="step1-submit" type="submit">Next</button>
</form>
</body></html>"""

    @app.post("/v2/step2", response_class=HTMLResponse)
    async def v2_step2(email: str = Form("")):
        return f"""<!doctype html><html><body>
<h2>Enter your password</h2>
<form action="/v2/do-login" method="post">
  <input type="hidden" name="email" value="{escape(email)}">
  <label for="password">Password</label>
  <input type="password" id="password" name="password" autocomplete="current-password">
  <button id="step2-submit" type="submit">Sign in</button>
</form>
</body></html>"""

    @app.post("/v2/do-login")
    async def v2_do_login(email: str = Form(""), password: str = Form("")):
        if password == PASSWORD:
            resp = RedirectResponse("/v2/dashboard", status_code=303)
            resp.set_cookie("session_v2", "valid_session_v2", path="/", httponly=True)
            return resp
        return HTMLResponse(
            '<p>Invalid credentials</p><form action="/v2/do-login" method="post">'
            '<input type="password" name="password"><button type="submit">Sign in</button></form>',
            status_code=401,
        )

    @app.get("/v2/dashboard", response_class=HTMLResponse)
    async def v2_dashboard(request: Request):
        if request.cookies.get("session_v2") == "valid_session_v2":
            return '<h1>Dashboard</h1><a href="/v2/logout">Log out</a>'
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v2/protected", response_class=HTMLResponse)
    async def v2_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.cookies.get("session_v2") == "valid_session_v2":
            return _protected_html(2, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v2/logout")
    async def v2_logout():
        resp = RedirectResponse("/v2/login", status_code=303)
        resp.delete_cookie("session_v2", path="/")
        return resp

    # =========================================================================
    # Variant 3: Login form inside a modal on landing page
    # =========================================================================
    @app.get("/v3/login", response_class=HTMLResponse)
    async def v3_login_get():
        return """<!doctype html><html><body>
<h1>Welcome</h1>
<button id="open" type="button">Log in</button>
<div class="modal" hidden>
  <h3>Log in</h3>
  <form action="/v3/do-login" method="post">
    <label for="u3">Username</label>
    <input id="u3" name="username" type="text" autocomplete="username">
    <label for="p3">Password</label>
    <input id="p3" name="password" type="password" autocomplete="current-password">
    <button id="m-submit" type="submit">Log in</button>
  </form>
</div>
<script>
document.getElementById("open").onclick = function() {
  document.querySelector(".modal").hidden = false;
};
</script>
</body></html>"""

    @app.post("/v3/do-login")
    async def v3_do_login(username: str = Form(""), password: str = Form("")):
        if username == USERNAME and password == PASSWORD:
            resp = RedirectResponse("/v3/dashboard", status_code=303)
            resp.set_cookie("session_v3", "valid_session_v3", path="/", httponly=True)
            return resp
        return HTMLResponse(
            '<p>Invalid credentials</p><form action="/v3/do-login" method="post">'
            '<input name="username"><input name="password" type="password"><button type="submit">Log in</button></form>',
            status_code=401,
        )

    @app.get("/v3/dashboard", response_class=HTMLResponse)
    async def v3_dashboard(request: Request):
        if request.cookies.get("session_v3") == "valid_session_v3":
            return '<h1>Dashboard</h1><a href="/v3/logout">Log out</a>'
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v3/protected", response_class=HTMLResponse)
    async def v3_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.cookies.get("session_v3") == "valid_session_v3":
            return _protected_html(3, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v3/logout")
    async def v3_logout():
        resp = RedirectResponse("/v3/login", status_code=303)
        resp.delete_cookie("session_v3", path="/")
        return resp

    # =========================================================================
    # Variant 4: SPA fetch login returning JWT (Bearer) with no cookie
    # =========================================================================
    JWT_TOKEN = "jwt-matrix-token-v4"

    @app.get("/v4/login", response_class=HTMLResponse)
    async def v4_login_get():
        return """<!doctype html><html><body>
<div id="login-container">
  <h1>Sign in</h1>
  <form id="login-form">
    <label for="u">Username</label>
    <input id="u" name="username" type="text" autocomplete="username">
    <label for="p">Password</label>
    <input id="p" name="password" type="password" autocomplete="current-password">
    <button id="b" type="submit">Sign in</button>
  </form>
  <div id="error"></div>
</div>
<div id="app-view"></div>
<script>
document.getElementById("login-form").addEventListener("submit", async function(e) {
  e.preventDefault();
  const u = document.getElementById("u").value;
  const p = document.getElementById("p").value;
  const res = await fetch("/v4/api/login", {
    method: "POST",
    headers: {"Content-Type": "application/json"},
    body: JSON.stringify({username: u, password: p})
  });
  if (res.ok) {
    const data = await res.json();
    localStorage.setItem("token", data.token);
    document.getElementById("login-container").remove();
    document.getElementById("app-view").innerHTML = '<h1>Dashboard</h1><a href="/v4/logout">Log out</a>';
    await fetch("/v4/api/user", {
      headers: {"Authorization": "Bearer " + data.token}
    });
  } else {
    document.getElementById("error").innerHTML = "<p>Invalid credentials</p>";
  }
});
</script>
</body></html>"""

    @app.post("/v4/api/login")
    async def v4_api_login(request: Request):
        try:
            data = await request.json()
        except Exception:
            return JSONResponse({"error": "invalid payload"}, status_code=400)
        if data.get("username") == USERNAME and data.get("password") == PASSWORD:
            return JSONResponse({"token": JWT_TOKEN, "access_token": JWT_TOKEN})
        return JSONResponse({"error": "invalid credentials"}, status_code=401)

    @app.get("/v4/api/user")
    async def v4_api_user(request: Request):
        if request.headers.get("authorization") == f"Bearer {JWT_TOKEN}":
            return JSONResponse({"username": USERNAME, "status": "authenticated"})
        return JSONResponse({"error": "unauthorized"}, status_code=401)

    @app.get("/v4/dashboard", response_class=HTMLResponse)
    async def v4_dashboard(request: Request):
        if request.headers.get("authorization") == f"Bearer {JWT_TOKEN}":
            return '<h1>Dashboard</h1><a href="/v4/logout">Log out</a>'
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v4/protected", response_class=HTMLResponse)
    async def v4_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.headers.get("authorization") == f"Bearer {JWT_TOKEN}":
            return _protected_html(4, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    # =========================================================================
    # Variant 5: Cookie login requiring OTP page (no solver => CHALLENGE/incomplete)
    # =========================================================================
    @app.get("/v5/login", response_class=HTMLResponse)
    async def v5_login_get():
        return """<!doctype html><html><body>
<h1>Sign in</h1>
<form action="/v5/login" method="post">
  <label for="u5">Username</label>
  <input id="u5" name="username" type="text" autocomplete="username">
  <label for="p5">Password</label>
  <input id="p5" name="password" type="password" autocomplete="current-password">
  <button id="v5-submit" type="submit">Log in</button>
</form>
</body></html>"""

    @app.post("/v5/login")
    async def v5_login_post(username: str = Form(""), password: str = Form("")):
        if username == USERNAME and password == PASSWORD:
            resp = RedirectResponse("/v5/mfa", status_code=303)
            resp.set_cookie("partial_session_v5", "pre_otp_valid", path="/", httponly=True)
            return resp
        return HTMLResponse(
            '<p>Invalid credentials</p><form action="/v5/login" method="post">'
            '<input name="username"><input name="password" type="password"><button type="submit">Log in</button></form>',
            status_code=401,
        )

    @app.get("/v5/mfa", response_class=HTMLResponse)
    async def v5_mfa_get():
        return """<!doctype html><html><body>
<h2>Two-factor authentication</h2>
<p>Enter the verification code from your authenticator app.</p>
<form action="/v5/verify-otp" method="post">
  <label for="x1">Verification code</label>
  <input id="x1" name="x1" inputmode="numeric" maxlength="6">
  <button id="otp-submit" type="submit">Verify</button>
</form>
</body></html>"""

    @app.post("/v5/verify-otp")
    async def v5_verify_otp(request: Request, x1: str = Form("")):
        if x1 == "123456" and request.cookies.get("partial_session_v5") == "pre_otp_valid":
            resp = RedirectResponse("/v5/dashboard", status_code=303)
            resp.set_cookie("session_v5", "valid_session_v5", path="/", httponly=True)
            return resp
        return HTMLResponse("<p>Invalid verification code</p>", status_code=401)

    @app.get("/v5/dashboard", response_class=HTMLResponse)
    async def v5_dashboard(request: Request):
        if request.cookies.get("session_v5") == "valid_session_v5":
            return '<h1>Dashboard</h1><a href="/v5/logout">Log out</a>'
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v5/protected", response_class=HTMLResponse)
    async def v5_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.cookies.get("session_v5") == "valid_session_v5":
            return _protected_html(5, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    # =========================================================================
    # Variant 6: Redirect to in-scope IdP and back
    # =========================================================================
    @app.get("/v6/login")
    async def v6_login_get():
        return RedirectResponse("/v6/idp/login?redirect_uri=/v6/callback", status_code=302)

    @app.get("/v6/idp/login", response_class=HTMLResponse)
    async def v6_idp_login_get(redirect_uri: str = "/v6/callback"):
        return f"""<!doctype html><html><body>
<h1>Identity Provider Sign in</h1>
<form action="/v6/idp/login" method="post">
  <input type="hidden" name="redirect_uri" value="{escape(redirect_uri)}">
  <label for="u6">Username</label>
  <input id="u6" name="username" type="text" autocomplete="username">
  <label for="p6">Password</label>
  <input id="p6" name="password" type="password" autocomplete="current-password">
  <button id="idp-submit" type="submit">Sign in</button>
</form>
</body></html>"""

    @app.post("/v6/idp/login")
    async def v6_idp_login_post(
        redirect_uri: str = Form("/v6/callback"),
        username: str = Form(""),
        password: str = Form(""),
    ):
        if username == USERNAME and password == PASSWORD:
            sep = "&" if "?" in redirect_uri else "?"
            return RedirectResponse(f"{redirect_uri}{sep}code=valid_idp_code_v6", status_code=303)
        return HTMLResponse(
            f'<p>Invalid credentials</p><form action="/v6/idp/login" method="post">'
            f'<input type="hidden" name="redirect_uri" value="{escape(redirect_uri)}">'
            f'<input name="username"><input name="password" type="password"><button type="submit">Sign in</button></form>',
            status_code=401,
        )

    @app.get("/v6/callback")
    async def v6_callback(code: str = ""):
        if code == "valid_idp_code_v6":
            resp = RedirectResponse("/v6/dashboard", status_code=303)
            resp.set_cookie("session_v6", "valid_session_v6", path="/", httponly=True)
            return resp
        return HTMLResponse("<h1>Invalid auth code</h1>", status_code=400)

    @app.get("/v6/dashboard", response_class=HTMLResponse)
    async def v6_dashboard(request: Request):
        if request.cookies.get("session_v6") == "valid_session_v6":
            return '<h1>Dashboard</h1><a href="/v6/logout">Log out</a>'
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v6/protected", response_class=HTMLResponse)
    async def v6_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.cookies.get("session_v6") == "valid_session_v6":
            return _protected_html(6, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    @app.get("/v6/logout")
    async def v6_logout():
        resp = RedirectResponse("/v6/login", status_code=303)
        resp.delete_cookie("session_v6", path="/")
        return resp

    # =========================================================================
    # Variant 7: Silent failure with rotated non-auth cookie (must NOT be success)
    # =========================================================================
    @app.get("/v7/login", response_class=HTMLResponse)
    async def v7_login_get():
        return """<!doctype html><html><body>
<h1>Sign in</h1>
<form action="/v7/login" method="post">
  <label for="u7">Username</label>
  <input id="u7" name="username" type="text" autocomplete="username">
  <label for="p7">Password</label>
  <input id="p7" name="password" type="password" autocomplete="current-password">
  <button id="v7-submit" type="submit">Log in</button>
</form>
</body></html>"""

    @app.post("/v7/login")
    async def v7_login_post():
        resp = RedirectResponse("/v7/public", status_code=303)
        # 非認証の追跡/CSRF Cookie をローテーション（認証セッションではない）
        resp.set_cookie("anon_csrf", f"rotated_{time.time()}", path="/", httponly=True)
        return resp

    @app.get("/v7/public", response_class=HTMLResponse)
    async def v7_public():
        return "<h1>Welcome to our site</h1><p>This is a public page for anonymous visitors.</p>"

    @app.get("/v7/protected", response_class=HTMLResponse)
    async def v7_protected(request: Request, q: str = "", safe_q: str = ""):
        if request.cookies.get("session_v7") == "valid_session_v7":
            return _protected_html(7, q=q, safe_q=safe_q)
        return HTMLResponse("<h1>Authentication required</h1>", status_code=401)

    # =========================================================================
    # JS 制御フォーム（fetch JSON 送信）の脆弱＋安全ツイン。
    # VARIANTS には入れない（7 形態網羅テスト len==7 を壊さない）。
    # ネイティブ form 送信が preventDefault され、ページ内 JS が JSON API へ
    # fetch する形態。/v8/api/login は username の引用符を文字列連結の破壊と
    # みなして SQL エラーを返す（脆弱）、/v8/api/safe-login はパラメータ化相当
    # （安全ツイン）。正規認証情報でのログインは両方とも成功する。
    # =========================================================================
    V8_TOKEN = "jwt-matrix-token-v8"

    def _v8_login_page(api_path: str) -> str:
        # ページ構造は v4（SPA fetch login）と同一系。id は v8 接頭辞で分離。
        return f"""<!doctype html><html><body>
<div id="login-container">
  <h1>Sign in</h1>
  <form id="login-form">
    <label for="u8">Username</label>
    <input id="u8" name="username" type="text" autocomplete="username">
    <label for="p8">Password</label>
    <input id="p8" name="password" type="password" autocomplete="current-password">
    <button id="b8" type="submit">Sign in</button>
  </form>
  <div id="error"></div>
</div>
<div id="app-view"></div>
<script>
document.getElementById("login-form").addEventListener("submit", async function(e) {{
  e.preventDefault();
  const u = document.getElementById("u8").value;
  const p = document.getElementById("p8").value;
  const res = await fetch("{api_path}", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{username: u, password: p}})
  }});
  if (res.ok) {{
    const data = await res.json();
    localStorage.setItem("token", data.token);
    document.getElementById("login-container").remove();
    document.getElementById("app-view").innerHTML = '<h1>Dashboard</h1>';
  }} else {{
    document.getElementById("error").innerHTML = "<p>Invalid credentials</p>";
  }}
}});
</script>
</body></html>"""

    @app.get("/v8/login", response_class=HTMLResponse)
    async def v8_login_get():
        return HTMLResponse(_v8_login_page("/v8/api/login"))

    @app.get("/v8/safe/login", response_class=HTMLResponse)
    async def v8_safe_login_get():
        return HTMLResponse(_v8_login_page("/v8/api/safe-login"))

    def _v8_api_login(vulnerable: bool):
        async def handler(request: Request):
            try:
                data = await request.json()
            except Exception:
                return JSONResponse({"error": "invalid payload"}, status_code=400)
            username = str(data.get("username") or "")
            password = str(data.get("password") or "")
            # 決定論的な SQLi シミュレーション: username の引用符が「文字列連結の
            # 破壊」を起こし、バックエンドが生 SQL エラーをそのまま返す（脆弱側のみ）。
            # 安全側はパラメータ化相当で引用符も値として扱う（エラーなし 401）。
            if vulnerable and ("'" in username or '"' in username):
                return JSONResponse(
                    {"error": f'SQL syntax error: unrecognized token: "{username}"'},
                    status_code=500,
                )
            if username == USERNAME and password == PASSWORD:
                return JSONResponse({"token": V8_TOKEN, "access_token": V8_TOKEN})
            return JSONResponse({"error": "invalid credentials"}, status_code=401)
        return handler

    @app.post("/v8/api/login")
    async def v8_api_login(request: Request):
        return await _v8_api_login(vulnerable=True)(request)

    @app.post("/v8/api/safe-login")
    async def v8_api_safe_login(request: Request):
        return await _v8_api_login(vulnerable=False)(request)

    return app


def create_parallel_app(bearer: bool = False, expire: bool = False) -> FastAPI:
    """並列認証検証用。記録はダミーのセッション番号と要求の有効性のみ。"""
    app = FastAPI()
    sessions: dict[str, bool] = {}
    records: list[dict] = []
    expired: list[str] = []
    variant = 4 if bearer else 1
    source = create_app()
    login_endpoint = next(r.endpoint for r in source.routes
                          if getattr(r, "path", "") == f"/v{variant}/login"
                          and "GET" in r.methods)

    @app.get(f"/v{variant}/login", response_class=HTMLResponse)
    async def login():
        if bearer:
            return await login_endpoint()
        return '''<form method="post"><input name="username" autocomplete="username">
        <input name="password" type="password" autocomplete="current-password">
        <button type="submit">Sign in</button></form>'''

    async def issue(request: Request):
        data = await request.json() if bearer else await request.form()
        if data.get("username") != USERNAME or data.get("password") != PASSWORD:
            return JSONResponse({"error": "invalid credentials"}, status_code=401)
        sid = "dummy-parallel-session-" + str(len(sessions) + 1)
        sessions[sid] = True
        if bearer:
            return JSONResponse({"token": sid, "access_token": sid})
        response = RedirectResponse(f"/v{variant}/protected", status_code=303)
        response.set_cookie("parallel_session", sid, httponly=True)
        return response

    app.post(f"/v{variant}/api/login" if bearer else f"/v{variant}/login")(issue)

    @app.middleware("http")
    async def protect(request: Request, call_next):
        path = request.url.path
        if "/protected" in path or path.endswith("/api/user"):
            sid = (request.headers.get("authorization", "").removeprefix("Bearer ")
                   if bearer else request.cookies.get("parallel_session", ""))
            attack = bool(request.query_params.get("q") or request.query_params.get("safe_q"))
            if expire and attack and not expired and sessions.get(sid):
                sessions[sid] = False
                expired.append(sid)
            valid = sessions.get(sid, False)
            records.append(dict(session=sid, path=path, valid=valid, attack=attack, logged_in=bool(sessions)))
            if not valid:
                return HTMLResponse("<h1>Authentication required</h1>", status_code=401)
        return await call_next(request)

    @app.get(f"/v{variant}/api/user")
    async def user():
        return {"username": USERNAME, "status": "authenticated"}

    @app.get(f"/v{variant}/protected", response_class=HTMLResponse)
    @app.get(f"/v{variant}/protected/{{number}}", response_class=HTMLResponse)
    async def protected(request: Request, number: int = 0, q: str = "", safe_q: str = ""):
        links = "".join(f'<a href="/v{variant}/protected/{i}">Page {i}</a>' for i in range(1, 4))
        return (links + f'<h1>Protected</h1><a href="/logout">Log out</a>'
                + f'<form><input name="q"><button>Search</button></form>{q}'
                + f'<form><input name="safe_q"><button>Search</button></form>{escape(safe_q)}')

    @app.get("/test/stats")
    async def stats():
        return dict(records=records, logins=len(sessions), expired=expired)

    @app.post("/test/expire/{sid}")
    async def invalidate(sid: str):
        if sid not in sessions:
            return JSONResponse({"error": "unknown session"}, status_code=404)
        sessions[sid] = False
        return {"expired": sid}

    return app
