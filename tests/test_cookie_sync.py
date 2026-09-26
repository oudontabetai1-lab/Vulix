"""自動再ログイン後の Cookie 同期（ドメイン方向）のテスト。

ブラウザの送出規則に合わせ、対象ホスト宛に送られる Cookie（完全一致 or 親ドメイン
スコープ）だけを self.cookies へ写すこと。サブドメインスコープの Cookie を親へ
持ち込まない（セッション漏えい防止）。
"""
import asyncio
import types
import unittest

from wscan.engine import ScanEngine


class _Ctx:
    def __init__(self, cookies):
        self._cookies = cookies

    async def cookies(self):
        return self._cookies


def _run_sync(target_url, cookies, initial="", for_url=""):
    browser = types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx(cookies)))
    eng = types.SimpleNamespace(target_url=target_url, cookies=initial)
    asyncio.run(ScanEngine._sync_cookies_from_browser(eng, browser, for_url=for_url))
    return eng.cookies


class CookiePathMatchTests(unittest.TestCase):
    def test_path_match_pure(self):
        from wscan.engine import _cookie_path_matches
        self.assertTrue(_cookie_path_matches("/api/users", "/"))
        self.assertTrue(_cookie_path_matches("/admin/x", "/admin"))
        self.assertTrue(_cookie_path_matches("/admin", "/admin"))
        self.assertFalse(_cookie_path_matches("/api/users", "/admin"))
        # 境界チェック: /admin は /administrator にマッチしない
        self.assertFalse(_cookie_path_matches("/administrator", "/admin"))

    def test_path_scoped_cookie_not_sent_to_other_path(self):
        cookies = [{"name": "s", "value": "x", "domain": "example.com", "path": "/admin"}]
        result = _run_sync("https://example.com/", cookies,
                           for_url="https://example.com/api/users")
        self.assertEqual(result, "")

    def test_longer_path_cookie_sent_first(self):
        # RFC 6265 §5.4: 同名 Cookie が / と /admin にあるとき、より具体的な
        # /admin（長い path）を先頭に送る。最初の値を使うフレームワークが
        # root の Cookie で誤ったセッションを選ばないようにする。
        cookies = [
            {"name": "sid", "value": "root", "domain": "example.com", "path": "/"},
            {"name": "sid", "value": "admin", "domain": "example.com", "path": "/admin"},
        ]
        result = _run_sync("https://example.com/admin/panel", cookies,
                           for_url="https://example.com/admin/panel")
        # 両方 path 一致するが、/admin が先頭に来る
        self.assertEqual(result, "sid=admin; sid=root")


class CookieHeaderForUrlTests(unittest.TestCase):
    def _hdr(self, cookies, url):
        browser = types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx(cookies)))
        eng = types.SimpleNamespace(browser=browser)
        return asyncio.run(ScanEngine.cookie_header_for_url(eng, url))

    def test_origin_vs_page_path_scope(self):
        # cookie_header_for_url は URL 単位で path スコープする（#157）。
        cookies = [
            {"name": "root", "value": "r", "domain": "example.com", "path": "/"},
            {"name": "adm", "value": "a", "domain": "example.com", "path": "/admin"},
        ]
        # origin ルート(/): Path=/ の Cookie のみ（Path=/admin は送らない）。
        self.assertEqual(self._hdr(cookies, "https://example.com"), "root=r")
        # page(/admin): 両方送る（長い path が先）。
        self.assertEqual(self._hdr(cookies, "https://example.com/admin"), "adm=a; root=r")

    def test_no_browser_returns_unavailable(self):
        eng = types.SimpleNamespace(browser=types.SimpleNamespace(page=None))
        self.assertIsNone(asyncio.run(ScanEngine.cookie_header_for_url(eng, "https://x.test")))

    def test_empty_jar_and_failed_jar_are_distinct(self):
        from wscan.engine import _scoped_cookie_header
        self.assertEqual(self._hdr([], "https://x.test"), "")
        self.assertEqual(_scoped_cookie_header([], "https://x.test"), "")
        self.assertIsNone(_scoped_cookie_header(None, "https://x.test"))

    def test_cookie_fetch_exception_returns_unavailable(self):
        from unittest.mock import AsyncMock
        ctx = types.SimpleNamespace(cookies=AsyncMock(side_effect=RuntimeError("cookie-secret")))
        eng = types.SimpleNamespace(browser=types.SimpleNamespace(page=types.SimpleNamespace(context=ctx)))
        self.assertIsNone(asyncio.run(ScanEngine.cookie_header_for_url(eng, "https://x.test")))

    def test_secure_cookie_excluded_over_http(self):
        # Secure Cookie は HTTP 宛には送らず、HTTPS 宛には送る（Codex #157）。
        from wscan.engine import _scoped_cookie_header
        cookies = [
            {"name": "sid", "value": "s", "domain": "example.com", "path": "/", "secure": True},
            {"name": "lang", "value": "ja", "domain": "example.com", "path": "/", "secure": False},
        ]
        self.assertEqual(_scoped_cookie_header(cookies, "http://example.com/"), "lang=ja")
        self.assertEqual(_scoped_cookie_header(cookies, "https://example.com/"), "sid=s; lang=ja")


class CookieDomainSyncTests(unittest.TestCase):
    def test_exact_and_parent_accepted_subdomain_rejected(self):
        cookies = [
            {"name": "a", "value": "1", "domain": "example.com"},        # exact
            {"name": "b", "value": "2", "domain": "admin.example.com"},  # subdomain → reject
            {"name": "c", "value": "3", "domain": ".example.com"},       # parent → accept
        ]
        result = _run_sync("https://example.com/app", cookies)
        self.assertIn("a=1", result)
        self.assertIn("c=3", result)
        self.assertNotIn("b=2", result)

    def test_domain_cookie_reaches_subdomain(self):
        # ドメイン Cookie（先頭ドット）は子サブドメインへ届く
        cookies = [{"name": "s", "value": "x", "domain": ".example.com"}]
        result = _run_sync("https://app.example.com/", cookies)
        self.assertIn("s=x", result)

    def test_host_only_cookie_not_sent_to_subdomain(self):
        # host-only Cookie（先頭ドット無し）は子サブドメインへ送らない
        cookies = [{"name": "s", "value": "x", "domain": "example.com"}]
        result = _run_sync("https://app.example.com/", cookies)
        self.assertEqual(result, "")

    def test_unrelated_domain_rejected(self):
        cookies = [{"name": "z", "value": "9", "domain": "evil.test"}]
        result = _run_sync("https://example.com/", cookies)
        self.assertEqual(result, "")

    def test_empty_jar_clears_cookies(self):
        # ブラウザの cookie jar が空ならクリアする（stale を送り続けない）
        result = _run_sync("https://example.com/", [], initial="old=stale")
        self.assertEqual(result, "")

    def test_stale_cookie_cleared_when_no_match(self):
        # 前 URL 用の cookie が残っていても、当該ホストに一致が無ければクリアする
        # （別ホストの Cookie を誤送信しない）。
        cookies = [{"name": "api", "value": "1", "domain": "api.example.com"}]
        result = _run_sync(
            "https://www.example.com/", cookies,
            initial="old=fromprevioushost", for_url="https://other.example.org/x",
        )
        self.assertEqual(result, "")


class ParallelWorkerCookieIsolationTests(unittest.TestCase):
    """並列 worker の pre-attack flow 後 Cookie が worker task 内に閉じることの検証（0067）。

    共有 engine を複数 task が同時に使っても、_sync_cookies_from_browser の書き込みが
    task-local な ContextVar に閉じ、別 worker（と直列用 self.cookies）を汚染しないこと。
    ブラウザ非依存（cookie jar は _Ctx スタブ）。
    """

    def test_store_and_effective_routing(self):
        # 直列（ContextVar 未種付け）: 共有 self.cookies へ書き、そこから読む。
        from wscan.engine import _store_synced_cookies, _effective_cookies
        eng = types.SimpleNamespace(cookies="base=1")
        self.assertEqual(_effective_cookies(eng), "base=1")
        _store_synced_cookies(eng, "serial=2")
        self.assertEqual(eng.cookies, "serial=2")
        self.assertEqual(_effective_cookies(eng), "serial=2")

    def test_worker_context_does_not_touch_shared(self):
        # worker task 内（ContextVar 種付け済み）: 書き込みは ContextVar に閉じ、
        # 共有 self.cookies は不変。
        from wscan.engine import (
            _store_synced_cookies, _effective_cookies, _WORKER_COOKIES,
        )

        async def _worker():
            token = _WORKER_COOKIES.set(_effective_cookies(eng))  # baseline を種付け
            try:
                _store_synced_cookies(eng, "flow=worker")
                # task-local には反映、共有 self.cookies は不変
                self.assertEqual(_effective_cookies(eng), "flow=worker")
                self.assertEqual(eng.cookies, "shared=base")
            finally:
                _WORKER_COOKIES.reset(token)

        eng = types.SimpleNamespace(cookies="shared=base")
        asyncio.run(_worker())
        # worker 退出後、共有 self.cookies は依然不変（直列読みは baseline）
        self.assertEqual(eng.cookies, "shared=base")
        self.assertEqual(_effective_cookies(eng), "shared=base")

    def test_two_workers_do_not_contaminate_each_other(self):
        # 共有 engine を 2 worker が同時使用。各 worker が自分の browser jar から
        # 別セッション Cookie を sync し、自分の auth_headers にだけ載ることを検証。
        from wscan.engine import _WORKER_COOKIES

        eng = types.SimpleNamespace(
            cookies="",  # 初期ログイン Cookie（本テストでは空）
            target_url="https://example.com/",
            header_manager=types.SimpleNamespace(current=lambda: {}),
        )

        def _browser(jar):
            return types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx(jar)))

        async def _run_worker(name, jar):
            # worker_loop 相当: task-local Cookie を共有 baseline で種付け
            token = _WORKER_COOKIES.set(eng.cookies)
            try:
                # pre-attack flow 後の sync（browser jar → task-local Cookie）
                await ScanEngine._sync_cookies_from_browser(
                    eng, _browser(jar), for_url="https://example.com/app"
                )
                # 他 worker に yield させて交錯を誘発
                await asyncio.sleep(0)
                # HTTP scanner が使う auth_headers の Cookie を採取
                headers = ScanEngine.auth_headers(eng)
                return headers.get("Cookie", "")
            finally:
                _WORKER_COOKIES.reset(token)

        async def _main():
            jar_a = [{"name": "sid", "value": "AAA", "domain": "example.com", "path": "/"}]
            jar_b = [{"name": "sid", "value": "BBB", "domain": "example.com", "path": "/"}]
            return await asyncio.gather(
                _run_worker("A", jar_a),
                _run_worker("B", jar_b),
            )

        cookie_a, cookie_b = asyncio.run(_main())
        self.assertEqual(cookie_a, "sid=AAA")
        self.assertEqual(cookie_b, "sid=BBB")
        # 共有 self.cookies は両 worker の同期に汚染されず初期のまま
        self.assertEqual(eng.cookies, "")


if __name__ == "__main__":
    unittest.main()
