"""login_surface の純粋判定と、フィクスチャ（httpx）での誤分類ガード。"""
from __future__ import annotations

import asyncio

import httpx
import pytest

from tests.fixtures import login_surface_app as fx
from wscan import login_surface as ls


def _get(path: str) -> str:
    async def go():
        transport = httpx.ASGITransport(app=fx.create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return (await c.get(path)).text
    return asyncio.run(go())


def _post(path: str, data: dict) -> httpx.Response:
    async def go():
        transport = httpx.ASGITransport(app=fx.create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return await c.post(path, data=data, follow_redirects=True)
    return asyncio.run(go())


@pytest.mark.parametrize("path", list(fx.EXPECTED_SURFACES))
def test_expected_login_surfaces_and_fields(path):
    html = _get(path)
    exp = fx.EXPECTED_SURFACES[path]
    assert ls.classify_surface(html).kind == ls.LOGIN
    plan = ls.locate_auth_fields(html)
    assert plan.step == exp["step"]
    assert plan.user_selector == exp["user"]
    assert plan.pass_selector == exp["pass"]
    assert plan.incomplete_reason == ""


@pytest.mark.parametrize("path,kind", list(fx.SAFE_ENDPOINTS.items()))
def test_confusable_surfaces_are_not_login(path, kind):
    html = _get(path)
    assert ls.classify_surface(html).kind == kind
    assert ls.locate_auth_fields(html).incomplete_reason  # 自動ではログインを実行しない


@pytest.mark.parametrize("path", fx.AMBIGUOUS_ENDPOINTS)
def test_ambiguous_surfaces_are_incomplete(path):
    html = _get(path)
    assert ls.classify_surface(html).kind == ls.AMBIGUOUS
    plan = ls.locate_auth_fields(html)
    assert plan.incomplete_reason and not plan.user_selector


@pytest.mark.parametrize("path,reason", list(fx.UNRESOLVED_FIELD_ENDPOINTS.items()))
def test_unresolvable_fields_are_incomplete(path, reason):
    html = _get(path)
    assert ls.classify_surface(html).kind == ls.LOGIN
    plan = ls.locate_auth_fields(html)
    # 登録 form の password 欄へ fallback せず、理由付きで止める
    assert plan.pass_selector == "" and plan.incomplete_reason == reason


def test_modal_and_spa_submit_paths():
    modal = ls.locate_auth_fields(_get("/login-modal"))
    assert modal.requires_reveal and modal.submit_strategy == "enter"
    spa = ls.locate_auth_fields(_get("/spa-login"))
    # form 外の type=button は submit ボタンにしない＝Enter 送信へ
    assert spa.submit_strategy == "enter" and not spa.requires_reveal
    single = ls.locate_auth_fields(_get("/login"))
    assert single.submit == 'button[id="go"]' and single.submit_strategy == "button"
    assert ls.locate_auth_fields(_get("/mfa")).otp_selector == 'input[name="x1"]'


def test_external_form_submit_is_associated_by_form_id():
    plan = ls.locate_auth_fields(_get("/login-external-submit"))
    assert plan.step == "username_first"
    assert plan.user_selector == 'input[name="email"]'
    assert plan.submit == 'button[id="external-go"]'
    assert plan.submit_strategy == "button" and plan.incomplete_reason == ""


def test_explicit_selectors_take_priority():
    plan = ls.locate_auth_fields(_get("/two-logins"), user_selector='input[name="staff"]',
                                 pass_selector='input[name="spw"]', submit_selector="#s")
    assert (plan.user_selector, plan.pass_selector, plan.submit) == (
        'input[name="staff"]', 'input[name="spw"]', "#s")
    assert plan.sources == {"user": "explicit", "pass": "explicit", "submit": "explicit"}
    assert plan.incomplete_reason == ""
    # 一部だけ明示なら残りは自動検出で補う
    mixed = ls.locate_auth_fields(_get("/login"), pass_selector="#pw")
    assert mixed.sources == {"user": "auto", "pass": "explicit"}


@pytest.mark.parametrize("path", fx.API_LOGIN_ENDPOINTS)
def test_api_login_endpoints(path):
    assert ls.locate_api_login("http://t" + path, "POST", ["email", "password"]) is not None


@pytest.mark.parametrize("path", fx.API_SAFE_ENDPOINTS)
def test_api_reset_and_register_are_not_login(path):
    assert ls.locate_api_login("http://t" + path, "POST", ["email", "password"]) is None


def test_api_login_detection():
    t = ls.locate_api_login("http://t/api/session", "POST", ["email", "password"])
    assert (t.user_key, t.pass_key) == ("email", "password")
    assert ls.locate_api_login("http://t/api/register", "POST", ["email", "password"]) is None
    assert ls.locate_api_login("http://t/api/x", "POST", ["email", "password", "password_confirm"]) is None
    assert ls.locate_api_login("http://t/api/session", "GET", ["email", "password"]) is None
    assert ls.locate_api_login("http://t/search", "POST", ["q"]) is None
    # 新旧パスワードのキーを持つ操作はパスワード変更（login ではない）
    for keys in (["email", "current_password", "password"], ["email", "old_password", "password"]):
        assert ls.locate_api_login("http://t/api/account", "POST", keys) is None


def test_api_fixture_routes_match_classification():
    # フィクスチャの実ルートで、login 経路だけが token を返す（正解データの整合）
    async def go(path):
        transport = httpx.ASGITransport(app=fx.create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return (await c.post(path, json={"email": "a", "password": "b"})).json()
    for path in fx.API_LOGIN_ENDPOINTS:
        assert "token" in asyncio.run(go(path))
    for path in fx.API_SAFE_ENDPOINTS:
        assert "token" not in asyncio.run(go(path))


def _obs(**kw):
    return ls.LoginObservation(login_url="http://t/login", **kw)


def test_success_requires_two_independent_signals():
    resp = _post("/do-login", {"user": fx.USERNAME, "pw": fx.PASSWORD})
    a = ls.assess_login_state(_obs(post_url=str(resp.url), body=resp.text, status=resp.status_code,
                                   auth_cookie_set=True))
    assert a.state == ls.SUCCESS
    assert {"left_login_page", "auth_cookie_set", "logout_control"} <= set(a.evidence)
    # URL 遷移だけでは成功にしない
    only_url = ls.assess_login_state(_obs(post_url="http://t/welcome", body="<p>hi</p>"))
    assert only_url.state == ls.INCOMPLETE
    assert "insufficient_success_evidence" in only_url.reasons
    # 単一文字列（ログアウト語）だけでも成功にしない
    only_text = ls.assess_login_state(_obs(post_url="http://t/login", body="<a>Log out</a>"))
    assert only_text.state == ls.INCOMPLETE


def test_explicit_indicator_and_cookie_absence():
    ok = ls.assess_login_state(_obs(post_url="http://t/login", body="<p>Welcome back</p>",
                                    success_indicator="Welcome back"))
    assert ok.state == ls.SUCCESS
    missing = ls.assess_login_state(_obs(post_url="http://t/home", body="<a>Log out</a>",
                                         auth_cookie_set=True, success_indicator="Dashboard"))
    assert missing.state == ls.INCOMPLETE and "success_indicator_missing" in missing.reasons
    no_cookie = ls.assess_login_state(_obs(post_url="http://t/home", body="<a>Log out</a>",
                                           auth_cookie_set=False))
    assert no_cookie.state == ls.INCOMPLETE


def test_failure_challenge_and_incomplete_states():
    bad = _post("/do-login", {"user": "x", "pw": "y"})
    assert ls.assess_login_state(_obs(post_url=str(bad.url), body=bad.text)).state == ls.FAILURE
    silent = _post("/do-login-silent", {})
    s = ls.assess_login_state(_obs(post_url=str(silent.url), body=silent.text))
    assert s.state == ls.INCOMPLETE and s.reasons == ["login_form_still_present"]
    assert ls.assess_login_state(_obs(status=401)).state == ls.FAILURE
    assert ls.assess_login_state(_obs(body=_get("/mfa"))).reasons == ["mfa"]
    assert ls.assess_login_state(_obs(body=_get("/login-step2"))).reasons == ["password_step"]
    assert ls.assess_login_state(_obs(body='<div class="g-recaptcha" data-sitekey="fixture-key"></div>')).state == ls.CHALLENGE
    # CAPTCHA/MFA の設定案内だけでは challenge にせず、他の成功証拠を評価する
    settings = ls.assess_login_state(_obs(post_url="http://t/home", auth_cookie_set=True,
                                          body=_get("/home-security-settings")))
    assert settings.state == ls.SUCCESS
    for kw in ({"transport_error": "ConnectError"}, {"status": 503}, {"status": 429}):
        assert ls.assess_login_state(_obs(**kw)).state == ls.INCOMPLETE


def test_results_never_carry_secret_values():
    bad = _post("/do-login", {"user": "s3cr3t-user", "pw": fx.PASSWORD})
    assert "s3cr3t-user" in bad.text  # 失敗ページは入力値を反射する
    a = ls.assess_login_state(_obs(post_url=str(bad.url), body=bad.text, mfa_field="otp"))
    plan = ls.locate_auth_fields(bad.text)
    dumped = repr(a) + repr(plan) + repr(ls.classify_surface(bad.text))
    for secret in ("s3cr3t-user", fx.PASSWORD, "fixture-session"):
        assert secret not in dumped


@pytest.mark.parametrize("html,kind", [
    ('<h1>ログイン</h1><form><input name=mail><input type=password name=p>'
     '<button>ログイン</button></form><a>新規登録</a>', ls.LOGIN),
    ('<h1>会員登録</h1><form><input name=mail><input type=password name=p>'
     '<button>登録する</button></form>', ls.REGISTRATION),
    ("", ls.OTHER),
])
def test_japanese_and_empty_pages(html, kind):
    assert ls.classify_surface(html).kind == kind


def test_logout_text_without_control_is_not_evidence():
    # 未認証で公開 /help に遷移しただけ：説明文の「Log out」は logout control ではない
    help_page = ls.assess_login_state(_obs(post_url="http://t/help", body=_get("/help")))
    assert help_page.state == ls.INCOMPLETE and "logout_control" not in help_page.evidence
    # 安全ツイン: 実際のリンク/ボタン/ログアウト form は control として数える
    for body in (_get("/home"), '<button type="button">Sign out</button>',
                 '<form action="/logout" method="post"><button>Bye</button></form>'):
        a = ls.assess_login_state(_obs(post_url="http://t/home", body=body))
        assert a.state == ls.SUCCESS and "logout_control" in a.evidence
    hidden = ls.assess_login_state(_obs(post_url="http://t/home", body='<a href="/logout" hidden>Log out</a>'))
    assert "logout_control" not in hidden.evidence


@pytest.mark.parametrize("name", list(fx.NON_OPERABLE_LOGOUT))
def test_non_operable_logout_is_not_evidence(name):
    # 遷移で login 画面を離れただけ＋操作できない logout 要素では SUCCESS にしない
    a = ls.assess_login_state(_obs(post_url="http://t/home", body=fx.NON_OPERABLE_LOGOUT[name]))
    assert "logout_control" not in a.evidence
    assert a.state == ls.INCOMPLETE and a.reasons == ["insufficient_success_evidence"]


@pytest.mark.parametrize("name", list(fx.OPERABLE_LOGOUT))
def test_operable_logout_is_evidence(name):
    a = ls.assess_login_state(_obs(post_url="http://t/home", body=fx.OPERABLE_LOGOUT[name]))
    assert a.state == ls.SUCCESS and "logout_control" in a.evidence


def test_login_form_in_disabled_fieldset_is_not_leftover():
    kw = dict(post_url="http://t/home", auth_cookie_set=True)
    ok = ls.assess_login_state(_obs(body=_get("/home-disabled-fieldset-login"), **kw))
    assert ok.state == ls.SUCCESS
    # 安全ツイン: 有効な fieldset 配下の login form は残存＝INCOMPLETE
    still = ls.assess_login_state(_obs(body=_get("/home-enabled-fieldset-login"), **kw))
    assert still.state == ls.INCOMPLETE and still.reasons == ["login_form_still_present"]


def test_otp_only_page_is_challenge():
    html = _get("/verify-code")
    assert not ls.looks_like_mfa_page(html)  # 定型 MFA 文言に頼らないケース
    assert ls.classify_surface(html).reasons == ["login_step:otp"]
    a = ls.assess_login_state(_obs(post_url="http://t/verify", body=html))
    assert a.state == ls.CHALLENGE and a.reasons == ["mfa"]
    # 安全ツイン: 通常の login form 残存は CHALLENGE にしない
    assert ls.assess_login_state(_obs(body=_get("/login"))).state == ls.INCOMPLETE


def test_hidden_login_modal_does_not_block_success():
    kw = dict(post_url="http://t/home", auth_cookie_set=True)
    ok = ls.assess_login_state(_obs(body=_get("/home-hidden-modal"), **kw))
    assert ok.state == ls.SUCCESS
    # 安全ツイン: 可視の login modal は残存＝INCOMPLETE
    still = ls.assess_login_state(_obs(body=_get("/home-open-modal"), **kw))
    assert still.state == ls.INCOMPLETE and still.reasons == ["login_form_still_present"]


def test_hidden_captcha_does_not_block_success_but_visible_captcha_does():
    kw = dict(post_url="http://t/home", auth_cookie_set=True)
    hidden = ls.assess_login_state(_obs(body=_get("/home-hidden-captcha"), **kw))
    assert hidden.state == ls.SUCCESS
    visible = ls.assess_login_state(_obs(body=_get("/home-visible-captcha"), **kw))
    assert visible.state == ls.CHALLENGE and visible.reasons == ["captcha_unsupported"]


def test_explicit_success_resolves_persistent_form_without_overriding_challenges():
    kw = dict(post_url="http://t/home", auth_cookie_set=True, logged_in_marker="Dashboard")
    assert ls.assess_login_state(_obs(body=_get("/home-open-modal"), **kw)).state == ls.SUCCESS
    assert ls.assess_login_state(_obs(body=_get("/home-open-modal"), status=403, **kw)).state == ls.INCOMPLETE
    assert ls.assess_login_state(_obs(body=_get("/home-visible-captcha"), **kw)).state == ls.CHALLENGE
    no_cookie = {**kw, "auth_cookie_set": False}
    assert ls.assess_login_state(_obs(body=_get("/home-open-modal"), **no_cookie)).state == ls.INCOMPLETE


def test_transport_error_retains_only_known_type_names():
    for error in ("secretBearerToken123", "https://user:secret@example.test/?token=secret", "SecretError"):
        result = ls.assess_login_state(_obs(transport_error=error))
        assert result.reasons == ["transport_error:unknown"]
    assert ls.assess_login_state(_obs(transport_error="ConnectError")).reasons == ["transport_error:ConnectError"]


@pytest.mark.parametrize("blocked", ["disabled", "readonly"])
def test_modal_does_not_make_uneditable_fields_executable(blocked):
    html = (f'<div class="modal" hidden><form action="/login"><input name="user" {blocked}>'
            f'<input name="pw" type="password" {blocked}></form></div>')
    assert ls.locate_auth_fields(html).incomplete_reason
    assert not ls.locate_auth_fields(html.replace(f" {blocked}", "")).incomplete_reason


def test_external_inputs_and_submit_belong_to_the_referenced_form():
    html = ('<input form="f" name="email" type="email"><button form="f" id="go">Sign in</button>'
            '<form id="f" action="/login"></form>')
    plan = ls.locate_auth_fields(html)
    assert plan.step == "username_first" and plan.user_selector == 'input[name="email"]'
    assert plan.submit == 'button[id="go"]' and not plan.incomplete_reason


def test_mfa_settings_with_unrelated_field_is_not_a_challenge():
    body = (_get("/home-security-settings")
            + '<form action="/preferences"><input name="displayName"></form>')
    assert ls.assess_login_state(_obs(body=body, post_url="http://t/home", auth_cookie_set=True)).state == ls.SUCCESS
    assert ls.assess_login_state(_obs(body=_get("/mfa"))).state == ls.CHALLENGE


@pytest.mark.parametrize("group", [
    '<input name="code"><button>Continue</button>',
    '<form><input name="code"><button>Continue</button></form>',
])
def test_visible_weak_otp_with_mfa_context_is_challenge(group):
    body = '<h1>Two-factor authentication</h1>' + group
    assert ls.classify_surface(body, visible_only=True).reasons == ["login_step:otp"]
    assert ls.assess_login_state(_obs(body=body, post_url="http://t/verify",
                                     auth_cookie_set=True)).state == ls.CHALLENGE
    for safe in (group, '<h1>Two-factor authentication</h1><input name="displayName">',
                 '<h1>Two-factor authentication</h1><input name="code" hidden>'):
        assert ls.assess_login_state(_obs(body=safe, post_url="http://t/home",
                                         auth_cookie_set=True)).state == ls.SUCCESS


@pytest.mark.parametrize("wrapper", [
    '<div class="modal" hidden>{}</div>', '<template>{}</template>',
    '<dialog>{}</dialog>', '<fieldset disabled>{}</fieldset>',
    '<script>var field="{}"</script>', '<div hidden>{}</div>', '{}',
])
def test_configured_mfa_requires_operable_input(wrapper):
    field = '<input name="x1">'
    body = wrapper.format(field)
    kw = dict(post_url="http://t/home", auth_cookie_set=True, mfa_field="x1")
    expected = ls.CHALLENGE if wrapper == '{}' else ls.SUCCESS
    assert ls.assess_login_state(_obs(body=body, **kw)).state == expected
    if wrapper == '{}':
        for attr in ('hidden', 'disabled', 'readonly', 'type="hidden"'):
            assert ls.assess_login_state(_obs(body=f'<input name="x1" {attr}>', **kw)).state == ls.SUCCESS
    assert ls.assess_login_state(_obs(body='<input name="x10">', **kw)).state == ls.SUCCESS



@pytest.mark.parametrize("tag", ['button', 'input'])
@pytest.mark.parametrize("blocked", ['hidden', 'disabled', 'style="display:none"'])
def test_submit_ranking_prefers_operable_control(tag, blocked):
    inactive = (f'<button id="bad" {blocked}>Sign in</button>' if tag == 'button'
                else f'<input type="submit" id="bad" value="Sign in" {blocked}>')
    html = ('<form action="/login"><input name="user"><input name="pw" type="password">'
            + inactive + '<button id="go">Continue</button></form>')
    plan = ls.locate_auth_fields(html)
    assert plan.submit == 'button[id="go"]' and not plan.incomplete_reason
    assert ls.locate_auth_fields(html.replace(f' {blocked}', '')).submit == f'{tag}[id="bad"]'




@pytest.mark.parametrize("heading,button", [
    ("2-Step Verification", "Next"), ("Two-factor authentication", "Continue"),
])
@pytest.mark.parametrize("url", ["http://t/mfa", "http://t/verify", "http://t/login"])
def test_mfa_flow_and_settings_safe_twin(heading, button, url):
    body = (f'<h2>{heading}</h2><form><label>Code</label>'
            f'<input name="code" inputmode="numeric"><button>{button}</button></form>')
    assert ls.assess_login_state(_obs(body=body, post_url=url, auth_cookie_set=True)).state == ls.CHALLENGE
    settings = body.replace('</h2>', '</h2><p>Enter the code from your authenticator app to enable 2FA</p>')
    for settings_url in ("http://t/settings", "http://t/home"):
        assert ls.assess_login_state(_obs(body=settings, post_url=settings_url,
                                         auth_cookie_set=True)).state == ls.SUCCESS
    assert ls.assess_login_state(_obs(body=body, post_url="http://t/settings",
                                     auth_cookie_set=True)).state == ls.SUCCESS
    assert ls.assess_login_state(_obs(body=settings, post_url="http://t/mfa",
                                     auth_cookie_set=True)).state == ls.CHALLENGE
    assert ls.assess_login_state(_obs(body=settings, post_url="http://t/challenge",
                                     auth_cookie_set=True)).state == ls.CHALLENGE


@pytest.mark.parametrize("blocked", ['hidden', 'disabled', 'style="display:none"'])
def test_inoperable_only_submit_falls_back_to_enter(blocked):
    body = ('<form action="/login"><input name="user"><input name="pw" type="password">'
            f'<button name="bad" {blocked}>Log in</button></form>')
    plan = ls.locate_auth_fields(body)
    assert not plan.submit and plan.submit_strategy == "enter" and not plan.incomplete_reason
