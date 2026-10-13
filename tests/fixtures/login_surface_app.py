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
    "/login-external-submit": '''<button id="external-go" form="external-login">Sign in</button>
<form id="external-login" action="/do-login"><input type="email" name="email"></form>''',
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
    # 先行する登録 form の name 無し password 欄があり、login の password 欄を一意に決められない
    "/signup-then-login": '''<h2>Create account</h2><form action="/register"><input name="email" type="email">
<input type="password"><input type="password"><button>Sign up</button></form>
<h2>Log in</h2><form action="/do-login"><input name="user"><input type="password"><button>Log in</button></form>''',
    # 安全ツイン: name 無し password 欄が文書内で唯一なら型 selector で特定できる
    "/login-unnamed-pw": '''<h2>Log in</h2><form action="/do-login"><input name="user">
<input type="password"><button>Log in</button></form>''',
    # OTP 欄だけの確認画面（MFA の定型文言なし）。送信後に出たら CHALLENGE
    "/verify-code": '''<h2>Verify</h2><form action="/verify" method="post"><input name="otp">
<button type="submit">Continue</button></form>''',
    # 未認証でも開ける公開ヘルプ。「Log out」は説明文で操作要素ではない
    "/help": '''<h1>Help</h1><p>When you are done, choose Log out from the account menu.</p>''',
    # 認証後ページに閉じた login modal が残る（安全ツイン: 開いた modal は残存扱い）
    "/home-hidden-modal": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<div class="modal" hidden><form action="/do-login"><input name="user"><input name="pw" type="password">
<button>Log in</button></form></div>''',
    "/home-open-modal": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<div class="modal"><form action="/do-login"><input name="user"><input name="pw" type="password">
<button>Log in</button></form></div>''',
    "/home-security-settings": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<p>Enable two-factor authentication and reCAPTCHA to protect your account.</p>''',
    "/home-hidden-captcha": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<div hidden><iframe src="https://www.google.com/recaptcha/api2/anchor"></iframe>
<input name="g-recaptcha-response"></div>''',
    "/home-visible-captcha": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<iframe src="https://www.google.com/recaptcha/api2/anchor"></iframe>''',
    # disabled fieldset 配下の操作不能な login form（残存の根拠にしない）
    "/home-disabled-fieldset-login": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<form action="/do-login"><fieldset disabled><input name="user"><input name="pw" type="password">
<button>Log in</button></fieldset></form>''',
    # 安全ツイン: 有効な fieldset 配下の login form は残存＝INCOMPLETE
    "/home-enabled-fieldset-login": '''<h1>Dashboard</h1><a href="/logout">Log out</a>
<form action="/do-login"><fieldset><input name="user"><input name="pw" type="password">
<button>Log in</button></fieldset></form>''',
    "/new-password-only": '''<form action="/x"><input type="password" name="np" autocomplete="new-password">
<button>Save</button></form>''',
}

# 操作できない logout 要素（logout_control の根拠にしない）と、操作可能な安全ツイン
NON_OPERABLE_LOGOUT = {
    "disabled_button": '<h1>Dashboard</h1><button type="button" disabled>Log out</button>',
    "disabled_submit": '<h1>Dashboard</h1><form action="/logout"><input type="submit" value="Sign out" disabled></form>',
    "anchor_without_href": '<h1>Dashboard</h1><a>Log out</a>',
    "empty_form": '<h1>Dashboard</h1><form action="/logout" method="post"></form>',
    "hidden_descendant_link": '<h1>Dashboard</h1><a href="/account"><span hidden>Log out</span></a>',
    "hidden_descendant_button": '<h1>Dashboard</h1><button type="button"><span style="display:none">Sign out</span></button>',
    "disabled_fieldset_button": '<h1>Dashboard</h1><fieldset disabled><button type="button">Log out</button></fieldset>',
}
OPERABLE_LOGOUT = {
    "link": '<h1>Dashboard</h1><a href="/logout">Log out</a>',
    "button": '<h1>Dashboard</h1><button type="button">Sign out</button>',
    "submit": '<h1>Dashboard</h1><form action="/x"><input type="submit" value="Sign out"></form>',
    "form": '<h1>Dashboard</h1><form action="/logout" method="post"><button>Bye</button></form>',
    "visible_label_with_hidden_icon": '<h1>Dashboard</h1><a href="/bye"><span hidden>icon</span>Log out</a>',
}

EXPECTED_SURFACES = {
    "/login": {"step": "single", "user": 'input[name="user"]', "pass": 'input[name="pw"]'},
    "/login-step1": {"step": "username_first", "user": 'input[id="email"]', "pass": ""},
    "/login-step2": {"step": "password_only", "user": "", "pass": 'input[name="pw"]'},
    "/login-modal": {"step": "single", "user": 'input[name="login_id"]', "pass": 'input[name="pw"]'},
    "/spa-login": {"step": "single", "user": 'input[id="u"]', "pass": 'input[id="p"]'},
    "/mfa": {"step": "otp", "user": "", "pass": ""},
    "/login-unnamed-pw": {"step": "single", "user": 'input[name="user"]', "pass": 'input[type="password"]'},
}
SAFE_ENDPOINTS = {"/signup": "registration", "/forgot": "reset", "/reset-new": "reset", "/search": "search"}
AMBIGUOUS_ENDPOINTS = ("/two-logins", "/new-password-only")
# login と判定できても対象欄が一意に決まらず INCOMPLETE（incomplete_reason）を返すべきページ
UNRESOLVED_FIELD_ENDPOINTS = {"/signup-then-login": "field_not_unique:pass_selector"}
# API: ログイン（検出必須）と再設定/登録（検出禁止の安全ツイン）。いずれも email+password キー
API_LOGIN_ENDPOINTS = ("/api/session", "/api/login", "/api?action=login")
API_SAFE_ENDPOINTS = ("/api/register", "/api/reset", "/api/forgot", "/api/password/reset",
                      "/api/change-password", "/api/changePassword",
                      "/api?action=register", "/api?action=reset-password")


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

    # query で操作を切り替える /api は action=login のときだけ token を返す
    @app.post("/api")
    async def api_action(action: str = ""):
        return JSONResponse({"token": "fixture-token"} if action == "login" else {"ok": True})

    for path in API_LOGIN_ENDPOINTS:
        if "?" not in path:
            app.add_api_route(path, lambda: JSONResponse({"token": "fixture-token"}), methods=["POST"])
    for path in API_SAFE_ENDPOINTS:
        if "?" not in path:
            app.add_api_route(path, lambda: JSONResponse({"ok": True}), methods=["POST"])

    return app
