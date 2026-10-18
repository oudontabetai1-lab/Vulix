"""マルチアカウント経路: engine の create_session_for_account 呼び出しと browser 側シグネチャの整合。"""
import ast
import asyncio
import inspect
from pathlib import Path
from unittest.mock import AsyncMock, Mock

import pytest

from wscan.browser import BrowserManager
from wscan.engine import ScanEngine

ENGINE = Path(__file__).resolve().parent.parent / "wscan" / "engine.py"


def test_engine_calls_match_signature():
    params = inspect.signature(BrowserManager.create_session_for_account).parameters
    calls = [
        n for n in ast.walk(ast.parse(ENGINE.read_text(encoding="utf-8")))
        if isinstance(n, ast.Call) and getattr(n.func, "attr", "") == "create_session_for_account"
    ]
    assert len(calls) >= 2
    for c in calls:
        for kw in c.keywords:
            assert kw.arg in params, f"unknown kwarg {kw.arg} at engine.py:{c.lineno}"


class _Page:
    def __init__(self, url, body):
        self.url, self._body = url, body

    def set_default_timeout(self, _): pass
    async def goto(self, *a, **k): pass
    async def evaluate(self, *a, **k): pass
    async def wait_for_load_state(self, *a, **k): pass
    async def content(self): return self._body


class _Ctx:
    def __init__(self, page): self._page = page
    async def new_page(self): return self._page
    async def cookies(self): return [{"name": "sid", "value": "1"}]
    async def close(self): pass


class _Browser:
    def __init__(self, page): self._page = page
    async def new_context(self, **k): return _Ctx(self._page)


def _run(body, marker, url="http://t/home", success_indicator=""):
    bm = BrowserManager.__new__(BrowserManager)
    bm._browser = _Browser(_Page(url, body))
    bm.proxy, bm.timeout = None, 1000
    return asyncio.run(bm.create_session_for_account(
        "u", "p", "http://t/login", logged_in_marker=marker,
        success_indicator=success_indicator))


def test_logged_in_marker_is_enforced():
    assert _run("<a>Logout</a>", "Logout") == "sid=1"
    assert _run("<p>welcome</p>", "Logout") is None
    assert _run("<p>welcome</p>", "") == "sid=1"


@pytest.mark.parametrize(("body", "marker", "indicator", "expected"), [
    ("<p>Authentication failed</p>", "/dashboard", "", None),
    ("<p>Authenticated /dashboard</p>", "/dashboard", "", "sid=1"),
    ("<p>Authentication failed</p>", "", "/dashboard", "sid=1"),
    ("<p>Authenticated</p>", "", "Authenticated", "sid=1"),
    ("<p>Authenticated /dashboard</p>", "/dashboard", "Missing", None),
    ("<p>Welcome</p>", "/dashboard", "/dashboard", None),
])
def test_marker_requires_body_but_success_indicator_keeps_url_support(body, marker, indicator, expected):
    assert _run(body, marker, "http://t/login?next=/dashboard", indicator) == expected


@pytest.mark.parametrize(("fields", "expected"), [
    ({}, ['input[name="user"]', 'input[name="pw"]']),
    ({"user_field": "user", "pass_field": "pw"},
     ['input[name="user"],input[id="user"]', 'input[name="pw"],input[id="pw"]']),
    ({"user_field": 'input[name="user"]', "pass_field": 'input[name="pw"]'},
     ['input[name="user"]', 'input[name="pw"]']),
])
def test_auto_login_uses_login_form_with_default_named_registration_fields(fields, expected):
    from tests.fixtures.login_surface_app import PAGES
    bm = BrowserManager.__new__(BrowserManager)
    bm.auth_user, bm.auth_pass = "u", "p"
    bm.page, bm.network, bm.mfa_solver = Mock(), Mock(), None
    bm.page.url = "http://t/home"
    bm.page.fill = AsyncMock()
    locator = bm.page.locator.return_value
    locator.evaluate = AsyncMock(return_value=True)
    locator.element_handle = AsyncMock(return_value=object())
    locator.click = AsyncMock()
    bm.navigate = AsyncMock(return_value=True)
    bm.get_page_source = AsyncMock(side_effect=[PAGES["/mixed-default-login"],
                                               '<h1>Dashboard</h1><a href="/logout">Log out</a>'])
    bm._editable_auth_selector = AsyncMock(side_effect=lambda s: s if s.startswith("input[") else "")
    assert asyncio.run(bm.auto_login("http://t/login", **fields))
    assert [call.args[0] for call in bm.page.fill.call_args_list] == expected


def test_account_session_caller_passes_only_explicit_marker():
    engine = ScanEngine.__new__(ScanEngine)
    engine.login_url = "http://t/login"
    engine.accounts = [{"username": "u", "password": "p", "role": "admin"}]
    engine.login_user_field, engine.login_pass_field = "username", "password"
    engine.login_success_indicator = "/dashboard"
    engine.logged_in_marker = "/dashboard"  # fallback used by auto_login
    engine._explicit_logged_in_marker = ""
    engine.account_sessions = []
    engine._browser = Mock()
    engine._browser.create_session_for_account = AsyncMock(return_value="sid=1")

    asyncio.run(engine._setup_account_sessions())

    assert engine.account_sessions == [{"username": "u", "cookies": "sid=1", "role": "admin"}]
    assert engine._browser.create_session_for_account.call_args.kwargs["logged_in_marker"] == ""

    engine._explicit_logged_in_marker = "/dashboard"
    engine._browser.create_session_for_account.reset_mock(return_value=True)
    engine._browser.create_session_for_account.return_value = None
    asyncio.run(engine._setup_account_sessions())
    assert engine._browser.create_session_for_account.call_args.kwargs["logged_in_marker"] == "/dashboard"
