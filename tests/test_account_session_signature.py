"""マルチアカウント経路: engine の create_session_for_account 呼び出しと browser 側シグネチャの整合。"""
import ast
import asyncio
import inspect
from pathlib import Path

from wscan.browser import BrowserManager

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


def _run(body, marker):
    bm = BrowserManager.__new__(BrowserManager)
    bm._browser = _Browser(_Page("http://t/home", body))
    bm.proxy, bm.timeout = None, 1000
    return asyncio.run(bm.create_session_for_account(
        "u", "p", "http://t/login", logged_in_marker=marker))


def test_logged_in_marker_is_enforced():
    assert _run("<a>Logout</a>", "Logout") == "sid=1"
    assert _run("<p>welcome</p>", "Logout") is None
    assert _run("<p>welcome</p>", "") == "sid=1"
