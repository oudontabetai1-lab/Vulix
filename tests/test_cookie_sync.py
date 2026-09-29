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


class WorkerCookieAccessorTests(unittest.TestCase):
    """0067 Codex P1: 直読み consumer の worker-local 経由・排他ゲート。"""

    def _engine(self, cookies="base=1"):
        return ScanEngine("https://example.com/", cookies=cookies, checks=["xss"])

    def test_direct_cookies_read_is_worker_local(self):
        from wscan.engine import _WORKER_COOKIES
        eng = self._engine()
        self.assertEqual(eng.cookies, "base=1")
        token = _WORKER_COOKIES.set("base=1")
        try:
            eng.cookies = "flow=2"
            # getattr 経由（cms/jwt 等の直読み）も worker-local を返し、共有は不変
            self.assertEqual(getattr(eng, "cookies", ""), "flow=2")
            self.assertEqual(eng._cookies, "base=1")
        finally:
            _WORKER_COOKIES.reset(token)
        self.assertEqual(eng.cookies, "base=1")

    def test_serial_setter_writes_shared(self):
        eng = self._engine()
        eng.cookies = "new=3"
        self.assertEqual(eng._cookies, "new=3")

    def test_worker_cookie_not_promoted_and_verify_rescopes_from_jar(self):
        from wscan.engine import _WORKER_COOKIES
        eng = self._engine("base=1")
        eng.target_url = "https://example.com/"
        jar = [{"name": "sid", "value": "PUB", "domain": "example.com", "path": "/"}]
        b = types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx(jar)))

        async def _worker():
            tok = _WORKER_COOKIES.set(eng._cookies)
            try:
                eng.cookies = "sid=ADMIN"
            finally:
                _WORKER_COOKIES.reset(tok)

        asyncio.run(_worker())
        self.assertEqual(eng._cookies, "base=1")  # global へ昇格しない

        async def _verify():
            await eng._sync_cookies_from_browser(b, for_url="https://example.com/public")
            return eng.auth_headers().get("Cookie")

        self.assertEqual(asyncio.run(_verify()), "sid=PUB")  # jar から URL 毎に再スコープ

    def test_sync_returns_completion_bool(self):
        eng = self._engine("base=1")
        ok = types.SimpleNamespace(page=types.SimpleNamespace(context=_Ctx([])))
        self.assertTrue(asyncio.run(eng._sync_cookies_from_browser(ok)))  # 空 jar は観測結果
        self.assertFalse(asyncio.run(eng._sync_cookies_from_browser(types.SimpleNamespace(page=None))))

        class _Boom:
            async def cookies(self):
                raise RuntimeError("transient")

        bad = types.SimpleNamespace(page=types.SimpleNamespace(context=_Boom()))
        eng.cookies = "keep=1"
        self.assertFalse(asyncio.run(eng._sync_cookies_from_browser(bad)))
        self.assertEqual(eng._cookies, "keep=1")  # 失敗は据え置き

    def test_verify_resync_failure_skips_instead_of_stale_cookie(self):
        # Codex P2: 並列 attack 後の per-finding 再同期が失敗したら、前 finding の scoped Cookie で
        # 検証せず skipped（未検証・要手動確認）に倒す。finding は保持し CONFIRMED にしない。
        from wscan.engine import Finding
        eng = self._engine("base=1")
        seen = []

        class _Boom:
            async def cookies(self):
                raise RuntimeError("transient")

        eng._browser = types.SimpleNamespace(page=types.SimpleNamespace(context=_Boom()))
        eng._concurrent_attack_ran = True
        eng.cookies = "sid=PREV_HOST"  # 前 finding の scoped 値が残っている状態
        eng.monitor = None
        eng.wave_errors = []

        async def _verify_one(finding):
            seen.append(eng.auth_headers().get("Cookie"))
            return "reproduced"

        eng._verify_one = _verify_one
        f = Finding(check_type="sqli", url="https://other.example.com/x", field_name="q",
                    payload="'", evidence="e", severity="high")
        eng.all_findings = [f]
        asyncio.run(eng._phase_verify())
        self.assertEqual(seen, [])  # 誤セッションで _verify_one を呼ばない
        self.assertFalse(f.verified)
        self.assertEqual(f.verification_state, "skipped")
        self.assertEqual(len(eng.all_findings), 1)

    def test_verify_resync_hang_is_bounded_and_skipped(self):
        # verify 時の cookie 再同期が wedge しても timeout で有界化され skipped になる。
        import wscan.engine as E
        from wscan.engine import Finding
        eng = self._engine("base=1")

        class _Hang:
            async def cookies(self):
                await asyncio.sleep(3600)

        eng._browser = types.SimpleNamespace(page=types.SimpleNamespace(context=_Hang()))
        eng._concurrent_attack_ran = True
        eng.monitor = None
        eng.wave_errors = []
        seen = []

        async def _verify_one(finding):
            seen.append(1)
            return "reproduced"

        eng._verify_one = _verify_one
        f = Finding(check_type="sqli", url="https://example.com/x", field_name="q",
                    payload="'", evidence="e", severity="high")
        eng.all_findings = [f]
        old = E._VERIFY_ONE_TIMEOUT_S
        E._VERIFY_ONE_TIMEOUT_S = 0.05
        try:
            asyncio.run(asyncio.wait_for(eng._phase_verify(), timeout=5))
        finally:
            E._VERIFY_ONE_TIMEOUT_S = old
        self.assertEqual(seen, [])
        self.assertEqual(f.verification_state, "skipped")

    def test_flow_gate_cancelled_writer_wakes_readers(self):
        from wscan.engine import _FlowGate

        async def _main():
            gate = _FlowGate()
            await gate.acquire(False)  # reader 保持中
            writer = asyncio.ensure_future(gate.acquire(True))
            await asyncio.sleep(0.01)
            reader2 = asyncio.ensure_future(gate.acquire(False))  # writer 待ちでブロック
            await asyncio.sleep(0.01)
            self.assertFalse(reader2.done())
            writer.cancel()
            await asyncio.wait_for(reader2, timeout=1)  # cancel 後に起床する

        asyncio.run(_main())

    def test_relogin_under_concurrency_records_note(self):
        eng = ScanEngine("https://example.com/", checks=["xss"], concurrency=2)
        eng.relogin_on_expiry = True
        eng.login_url = "https://example.com/login"
        eng.wave_errors = []

        class _B:
            auth_user = "u"
            auth_pass = "p"
            page = types.SimpleNamespace(url="https://example.com/a", content=None)

            async def navigate(self, *a, **k):
                return True

            async def auto_login(self, *a, **k):
                return True

        async def _content():
            return "<html>body</html>"

        b = _B()
        b.page.content = _content
        eng._browser = b
        eng.browser  # 文脈対応 property の存在確認

        async def _relogin(*a, **k):
            return True

        eng._relogin_if_needed = _relogin
        eng._is_login_target_url = lambda u: False
        asyncio.run(eng._maybe_relogin_for_page("https://example.com/a"))
        self.assertIn("cookie_jar_shared_relogin:concurrency_gt_1", eng.wave_errors)

    def test_flow_gate_exclusive_waits_for_shared(self):
        from wscan.engine import _FlowGate

        async def _main():
            gate = _FlowGate()
            log = []

            async def shared(n, delay):
                await gate.acquire(False)
                log.append(f"s{n}+")
                await asyncio.sleep(delay)
                log.append(f"s{n}-")
                await gate.release(False)

            async def excl():
                await asyncio.sleep(0.01)
                await gate.acquire(True)
                log.append("x+")
                await asyncio.sleep(0.02)
                log.append("x-")
                await gate.release(True)

            await asyncio.gather(shared(1, 0.05), shared(2, 0.05), excl())
            return log

        log = asyncio.run(_main())
        # 排他は shared 全退出後に開始（重なりなし）
        self.assertLess(max(log.index("s1-"), log.index("s2-")), log.index("x+"))


if __name__ == "__main__":
    unittest.main()
