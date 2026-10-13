"""Login surface 判定用フィクスチャ（ログイン形態＋紛らわしい安全ツイン＋曖昧ケース）。

- ``EXPECTED_SURFACES`` … login と判定し、対象欄/step を特定すべきページ。
- ``SAFE_ENDPOINTS``    … login と誤分類してはならないページ（registration/reset/search）。
- ``AMBIGUOUS_ENDPOINTS`` … 自動で一意に決められず INCOMPLETE 相当を返すべきページ。
- ``/do-login*`` … 送信後状態（success/failure/incomplete/challenge）の観測元。
"""
from __future__ import annotations

from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

# ローカルテスト専用の公開資格情報。
USERNAME = "fixture-user"
PASSWORD = "fixture-password"

PAGES = {
    "/login": '''<h1>Sign in</h1><form action="/do-login" method="post">
<input name="user" autocomplete="username"><input name="pw" type="password" autocomplete="current-password">
<button id="go" type="submit">Log in</button></form>
<a href="/forgot">Forgot password?</a> <a href="/signup">Sign up</a>''',
    "/login-step1": '''<h2>Sign in</h2><form action="/identify" method="post">
<input type="email" id="email" name="email"><button type="submit">Next</button></form>''',
    "/login-step2": '''<h2>Enter your password</h2><form action="/do-login" method="post">
<input type="password" name="pw"><button type="submit">Sign in</button></form>''',
    "/login-modal": '''<button id="open">Log in</button><form role="search"><input type="search" name="q"></form>
<div class="modal" hidden><h3>Log in</h3><form action="/do-login" method="post">
<input name="login_id"><input name="pw" type="password"><button id="m-submit">Log in</button></form></div>''',
    "/spa-login": '''<div id="app"><h1>Sign in</h1><input id="u" type="email">
<input id="p" type="password"><button id="b" type="button">Sign in</button></div>''',
    "/mfa": '''<p>Enter the verification code from your authenticator app.</p>
<form action="/verify" method="post"><input name="x1" inputmode="numeric" maxlength="6">
<button type="submit">Verify</button></form>''',
    # 安全ツイン（login と誤分類しない）
    "/signup": '''<h1>Create account</h1><form action="/register" method="post"><input name="email" type="email">
<input name="password" type="password"><input name="password2" type="password"><button>Sign up</button></form>
<p>Already have an account? <a href="/login">Log in</a></p>''',
    "/forgot": '''<h1>Forgot your password?</h1><form action="/reset" method="post">
<input name="email" type="email"><button>Send reset link</button></form><a href="/login">Back to login</a>''',
    "/reset-new": '''<h1>Reset password</h1><form action="/reset/confirm" method="post">
<input type="password" name="p1" autocomplete="new-password"><input type="password" name="p2" autocomplete="new-password">
<button>Save</button></form>''',
    "/search": '''<h1>Search users</h1><form action="/search"><input name="q"><button>Search</button></form>''',
    # 曖昧（自動判定しない）
    "/two-logins": '''<h2>Customer login</h2><form action="/a"><input name="user"><input name="pw" type="password">
<button>Log in</button></form><h2>Staff login</h2><form action="/b"><input name="staff">
<input name="spw" type="password"><button>Log in</button></form>''',
    "/new-password-only": '''<form action="/x"><input type="password" name="np" autocomplete="new-password">
<button>Save</button></form>''',
}

EXPECTED_SURFACES = {
    "/login": {"step": "single", "user": 'input[name="user"]', "pass": 'input[name="pw"]'},
    "/login-step1": {"step": "username_first", "user": 'input[id="email"]', "pass": ""},
    "/login-step2": {"step": "password_only", "user": "", "pass": 'input[name="pw"]'},
    "/login-modal": {"step": "single", "user": 'input[name="login_id"]', "pass": 'input[name="pw"]'},
    "/spa-login": {"step": "single", "user": 'input[id="u"]', "pass": 'input[id="p"]'},
    "/mfa": {"step": "otp", "user": "", "pass": ""},
}
SAFE_ENDPOINTS = {"/signup": "registration", "/forgot": "reset", "/reset-new": "reset", "/search": "search"}
AMBIGUOUS_ENDPOINTS = ("/two-logins", "/new-password-only")


def create_app() -> FastAPI:
    app = FastAPI(title="login surface fixture")

    for path, html in PAGES.items():
        app.add_api_route(path, (lambda h=html: HTMLResponse(h)), methods=["GET"])

    @app.post("/do-login")
    async def do_login(user: str = Form(""), pw: str = Form("")):
        if user == USERNAME and pw == PASSWORD:
            resp = RedirectResponse("/home", status_code=303)
            resp.set_cookie("session", "fixture-session", httponly=True)
            return resp
        # 失敗ページは入力値を反射する（結果に秘密値が残らないことの確認用）
        return HTMLResponse(f"<p>Invalid credentials for {user}</p>" + PAGES["/login"])

    @app.post("/do-login-silent")
    async def do_login_silent():
        # 失敗文言なしでフォームを再表示＝原因不明（INCOMPLETE であるべき）
        return HTMLResponse(PAGES["/login"])

    @app.get("/home", response_class=HTMLResponse)
    async def home():
        return '<h1>Dashboard</h1><a href="/logout">Log out</a>'

    @app.post("/api/session")
    async def api_session():
        return JSONResponse({"token": "fixture-token"})

    return app
