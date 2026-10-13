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


def test_modal_and_spa_submit_paths():
    modal = ls.locate_auth_fields(_get("/login-modal"))
    assert modal.requires_reveal and modal.submit == 'button[id="m-submit"]'
    spa = ls.locate_auth_fields(_get("/spa-login"))
    # form 外の type=button は submit ボタンにしない＝Enter 送信へ
    assert spa.submit_strategy == "enter" and not spa.requires_reveal
    single = ls.locate_auth_fields(_get("/login"))
    assert single.submit == 'button[id="go"]' and single.submit_strategy == "button"
    assert ls.locate_auth_fields(_get("/mfa")).otp_selector == 'input[name="x1"]'


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


def test_api_login_detection():
    t = ls.locate_api_login("http://t/api/session", "POST", ["email", "password"])
    assert (t.user_key, t.pass_key) == ("email", "password")
    assert ls.locate_api_login("http://t/api/register", "POST", ["email", "password"]) is None
    assert ls.locate_api_login("http://t/api/x", "POST", ["email", "password", "password_confirm"]) is None
    assert ls.locate_api_login("http://t/api/session", "GET", ["email", "password"]) is None
    assert ls.locate_api_login("http://t/search", "POST", ["q"]) is None


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
    assert ls.assess_login_state(_obs(body="<div>Please complete the reCAPTCHA</div>")).state == ls.CHALLENGE
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
