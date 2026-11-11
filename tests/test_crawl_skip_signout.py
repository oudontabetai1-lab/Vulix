"""認証クロールがサインアウト系リンクを踏まないことの検証（通常層）。"""
from __future__ import annotations

import asyncio
import tempfile

import pytest

from tests.fixtures import login_matrix_app as fx
from tests.test_login_matrix_e2e import _CHROMIUM_OK, _e2e_enabled, serving
from wscan.browser import is_signout_url
from wscan.engine import ScanEngine


@pytest.mark.parametrize("url,expected", [
    ("http://h/v1/logout", True),
    ("http://h/LogOut", True),
    ("http://h/log-out", True),
    ("http://h/a/sign_out/", True),
    ("http://h/signoff", True),
    ("http://h/%6cogout", True),          # エンコード偽装
    ("http://h/%256cogout", True),        # 二重エンコード
    ("http://h/blogout-news", False),     # 長い語の一部
    ("http://h/catalogout", False),
    ("http://h/news?next=/logout", False),  # query は見ない
    ("http://h/dashboard", False),
    ("", False),
])
def test_is_signout_url(url, expected):
    assert is_signout_url(url) is expected


def _engine(**kw) -> ScanEngine:
    return ScanEngine("http://127.0.0.1:9/app", checks=["xss"], llm_provider="none",
                      output_dir=tempfile.mkdtemp(), open_report=False, **kw)


def test_skip_only_when_authenticated_and_recorded_once():
    eng = _engine(login_url="http://127.0.0.1:9/login", auth_user="u", auth_pass="p")
    assert eng._skip_signout_in_crawl("http://127.0.0.1:9/logout") is True
    assert eng._skip_signout_in_crawl("http://127.0.0.1:9/logout") is True
    rows = [r for r in eng.scan_matrix if r["check"] == "access"]
    assert len(rows) == 1 and "sign-out link skipped" in rows[0]["note"]
    assert eng._skip_signout_in_crawl("http://127.0.0.1:9/dashboard") is False


def test_no_skip_without_auth_or_for_explicit_seed():
    assert _engine()._skip_signout_in_crawl("http://127.0.0.1:9/logout") is False
    eng = _engine(login_url="http://127.0.0.1:9/login", auth_user="u", auth_pass="p",
                  seed_urls=["http://127.0.0.1:9/logout"])
    assert eng._skip_signout_in_crawl("http://127.0.0.1:9/logout/") is False


def _counting_app(hits: list):
    app = fx.create_app()

    @app.middleware("http")
    async def _count(request, call_next):
        hits.append((request.method, request.url.path))
        return await call_next(request)

    @app.get("/open")
    async def _open():
        from fastapi.responses import HTMLResponse
        return HTMLResponse('<h1>Public</h1><a href="/v1/logout">Log out</a>')

    return app


async def _crawl(base: str, *, authed: bool, start: str = "/v1/dashboard") -> ScanEngine:
    kw = dict(login_url=f"{base}/v1/login", auth_user=fx.USERNAME, auth_pass=fx.PASSWORD) if authed else {}
    with tempfile.TemporaryDirectory() as tmp:
        eng = ScanEngine(
            f"{base}{start}", checks=["xss"], llm_provider="none", headless=True,
            output_dir=tmp, open_report=False, enable_waf_detection=False,
            enable_ai_analysis=False, enable_payload_learning=False,
            enable_adaptive_payloads=False, enable_sitemap_crawl=False, depth=2,
            fast_mode=True, max_payloads=1, request_delay=0, use_planner=False,
            sarif=False, timeout=8, navigation_retries=0, **kw)
        await asyncio.wait_for(eng.run(), timeout=60)
        return eng


@pytest.mark.skipif(not _e2e_enabled(), reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.skipif(not _CHROMIUM_OK, reason="Chromium 利用不可")
def test_crawl_does_not_follow_logout_when_authenticated():
    hits: list = []
    with serving(_counting_app(hits)) as base:
        eng = asyncio.run(_crawl(base, authed=True))
    assert ("GET", "/v1/logout") not in hits
    notes = [r["note"] for r in eng.scan_matrix if r["check"] == "access"]
    assert any("sign-out link skipped" in n for n in notes)


@pytest.mark.skipif(not _e2e_enabled(), reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.skipif(not _CHROMIUM_OK, reason="Chromium 利用不可")
def test_unauthenticated_crawl_still_visits_logout_link():
    hits: list = []
    with serving(_counting_app(hits)) as base:
        asyncio.run(_crawl(base, authed=False, start="/open"))
    assert ("GET", "/v1/logout") in hits
