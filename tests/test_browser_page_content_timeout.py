"""F06: get_page_source が page.content() の無限ハングで停止しないことを検証する。

realistic_site 通し E2E が SQLi 再検証の page.content() 待ちで 900 秒 timeout していた。
待機を asyncio.wait_for で有界化したので、(1) ハングしても "" を返して速やかに戻る、
(2) 呼び出し側 cancel（scan 全体の SCAN_TIMEOUT_S 等）は内側 task を drain した上で
握りつぶさず伝播する、ことを確認する。
"""
import asyncio
import time
import unittest
from unittest.mock import patch

import wscan.browser as browser_mod
from wscan.browser import BrowserManager


class _HangingPage:
    def __init__(self):
        self.cancelled = False

    async def content(self):
        try:
            await asyncio.sleep(5)  # patched timeout より十分長い
            return "<html>late</html>"
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class _FastPage:
    async def content(self):
        return "<html>ok</html>"


def _make_bm(page):
    bm = BrowserManager.__new__(BrowserManager)  # __init__ を通さず page だけ差す
    bm.page = page
    return bm


def test_get_page_source_returns_quickly_when_content_hangs():
    page = _HangingPage()
    bm = _make_bm(page)
    with patch.object(browser_mod, "_PAGE_CONTENT_TIMEOUT", 0.05):
        start = time.monotonic()
        result = asyncio.run(bm.get_page_source())
        elapsed = time.monotonic() - start
    assert result == ""          # 取得不能は空に合流（ハングしない）
    assert elapsed < 2.0         # 5秒待たず有界時間で戻る
    assert page.cancelled        # 内側 task は cancel＋drain 済み（orphan を残さない）


def test_get_page_source_returns_content_when_available():
    bm = _make_bm(_FastPage())
    assert asyncio.run(bm.get_page_source()) == "<html>ok</html>"


def test_caller_cancel_propagates_after_inner_drained():
    # scan 全体の cancel が来た場合、内側 page.content の cleanup を drain してから
    # CancelledError を伝播する（"" を返して cancel 済み scan を継続しない）。
    finished = {"v": False}

    class _SlowCleanupPage:
        async def content(self):
            try:
                await asyncio.sleep(3600)
            except asyncio.CancelledError:
                await asyncio.sleep(0.05)   # cleanup（drain されるべき）
                finished["v"] = True
                raise

    async def run():
        inner = asyncio.ensure_future(browser_mod._bounded_page_content(_SlowCleanupPage()))
        await asyncio.sleep(0.05)  # wait_for の await に入らせる
        inner.cancel()
        try:
            await inner
            return "no-raise"
        except asyncio.CancelledError:
            return "cancelled"

    assert asyncio.run(run()) == "cancelled"  # cancellation は握りつぶさず伝播
    assert finished["v"]                       # 内側 task の cleanup 完了後に伝播した


# --- dialog.dismiss() の有界化（F06/0059）--------------------------------

class _HangingDialog:
    def __init__(self):
        self.message = "xss"
        self.dismissed = False
        self.cancelled = False

    async def dismiss(self):
        try:
            await asyncio.sleep(5)      # patched timeout より十分長い
            self.dismissed = True
        except asyncio.CancelledError:
            self.cancelled = True
            raise


class _FastDialog:
    def __init__(self):
        self.message = "xss"
        self.dismissed = False

    async def dismiss(self):
        self.dismissed = True


class _DialogPage:
    async def screenshot(self, **kw):
        return b"\xff\xd8\xff"          # 最小 JPEG 相当（内容は問わない）


def _make_dialog_bm():
    bm = BrowserManager.__new__(BrowserManager)
    bm.page = _DialogPage()
    bm.dialog_fired = False
    bm.dialog_message = ""
    bm.dialog_screenshot_b64 = ""
    return bm


def test_on_dialog_returns_quickly_when_dismiss_hangs():
    # alert() の dismiss() がハングしても _on_dialog は有界時間で戻る（以降のページ操作を
    # wedge しない）。内側 task は cancel+drain され orphan future を残さない（F06/0059）。
    bm = _make_dialog_bm()
    dialog = _HangingDialog()
    with patch.object(browser_mod, "_DIALOG_DISMISS_TIMEOUT", 0.05):
        start = time.monotonic()
        asyncio.run(bm._on_dialog(dialog))
        elapsed = time.monotonic() - start
    assert elapsed < 2.0            # 5秒待たず有界時間で戻る
    assert dialog.cancelled         # dismiss は cancel+drain 済み
    assert bm.dialog_fired          # signal 自体は記録される


def test_on_dialog_dismisses_when_fast():
    bm = _make_dialog_bm()
    dialog = _FastDialog()
    asyncio.run(bm._on_dialog(dialog))
    assert dialog.dismissed
    assert bm.dialog_fired


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


@unittest.skipUnless(_chromium_available(), 'Playwright Chromium browser is not installed (run: playwright install chromium)')
class ChromiumDialogFloodTests(unittest.IsolatedAsyncioTestCase):
    """実 Chromium で alert 連鎖後にページ操作を継続できる最小再現。"""

    async def asyncSetUp(self):
        from playwright.async_api import async_playwright
        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=True)
        self._page = await self._browser.new_page()

    async def asyncTearDown(self):
        await self._browser.close()
        await self._pw.stop()

    async def test_dialog_flood_is_dismissed_and_page_remains_usable(self):
        bm = BrowserManager()
        bm.page = self._page
        self._page.on('dialog', bm._on_dialog)
        await asyncio.wait_for(self._page.set_content("<script>for (let i = 0; i < 12; i++) alert('flood-' + i);</script><main>ready</main>"), timeout=10)
        await self._page.evaluate("() => { document.body.dataset.recovered = 'yes'; }")
        self.assertEqual(bm.dialog_total, 12)
        self.assertTrue(bm.dialog_fired)
        self.assertEqual(await self._page.evaluate('() => document.body.dataset.recovered'), 'yes')

    async def test_delayed_old_page_dialog_does_not_mark_replacement(self):
        from types import SimpleNamespace
        from unittest.mock import AsyncMock
        from wscan.injection_point import InjectionPoint
        from wscan.scanners.xss import XSSScanner
        context = await self._browser.new_context()
        await context.route('**/*', lambda route: route.fulfill(body='<main>safe</main>'))
        old = await context.new_page()
        bm = BrowserManager()
        bm._context, bm.page = (context, old)
        dialogs = asyncio.Queue()
        old.on('dialog', dialogs.put_nowait)
        trigger = asyncio.create_task(old.evaluate("alert('unrelated-old-page')"))
        dialog = await asyncio.wait_for(dialogs.get(), timeout=3)
        await dialog.dismiss()
        await trigger
        self.assertTrue(await bm.recreate_page())
        safe_url = 'http://safe.test/?q=clean'
        scanner = XSSScanner(SimpleNamespace(browser=bm, monitor=None, payload_gen=None))
        scanner.get_payloads = AsyncMock(return_value=['<script>alert(1)</script>'])
        scanner._baseline_handlers = AsyncMock(return_value=([], '/', '<main>safe</main>'))
        scanner.evolved_payloads = AsyncMock(return_value=[])
        scanner.run_equivalence_probe = AsyncMock(return_value=None)
        scanner.log_payload_test = AsyncMock()
        scanner.record_finding = AsyncMock(return_value=SimpleNamespace(dialog_confirmed=True))

        async def apply(ip, payload):
            await bm.page.goto(safe_url)
            await bm._on_dialog(dialog)
            return (await bm.get_page_source(), {})
        scanner._apply_ip = apply
        bm.sleep_factor = 0
        findings = await scanner.scan_injection_point(InjectionPoint.for_url_param(safe_url, 'q'), {'name': 'q'})
        self.assertEqual(findings, [])
        scanner.record_finding.assert_not_awaited()
        self.assertFalse(bm.dialog_fired)
        self.assertEqual(bm.dialog_total, 0)
        self.assertEqual(bm.dialog_message, '')
        self.assertFalse(bm.dialog_dismiss_failed)
        self.assertFalse(getattr(bm, '_dialog_screenshot_attempted', False))


def test_reset_discards_inflight_dialog_screenshot():
    async def run():
        started, release = asyncio.Event(), asyncio.Event()

        class Page:
            async def screenshot(self, **kwargs):
                started.set()
                await release.wait()
                return b"old evidence"

        bm = BrowserManager()
        bm.page = Page()
        callback = asyncio.create_task(bm._on_dialog(_FastDialog()))
        await started.wait()
        bm.reset_dialog()
        release.set()
        await callback
        assert not bm.dialog_fired
        assert bm.dialog_screenshot_b64 == ""
        assert not bm._dialog_screenshot_attempted

    asyncio.run(run())


def test_on_dialog_dismisses_before_screenshot():
    # OUD-87: 開いた dialog 上の page.screenshot は dismiss まで返らない（実 Chromium 実測で 1 件 3.0s の
    # native timeout を毎回浪費→alert 多発の realistic_site 通し E2E が 900s を超過）。dismiss を先に行い、
    # 撮影は閉じた後に成功することを固定する（実ブラウザ不要の決定論テスト）。
    dismissed = asyncio.Event()

    class _BlockedWhileOpenDialog:
        message = "xss"

        async def dismiss(self):
            dismissed.set()

    class _Page:
        async def screenshot(self, **kw):
            if not dismissed.is_set():
                await asyncio.sleep(kw.get("timeout", 3000) / 1000)  # 実機: dialog 未解消だと timeout まで待つ
                raise TimeoutError("screenshot blocked by open dialog")
            return b"\xff\xd8\xff"

    bm = _make_dialog_bm()
    bm.page = _Page()
    dialog = _BlockedWhileOpenDialog()
    dialog.page = bm.page
    start = time.monotonic()
    asyncio.run(bm._on_dialog(dialog))
    assert time.monotonic() - start < 1.0      # native timeout(3s) を待たない
    assert bm.dialog_screenshot_b64            # 閉じた後に証跡撮影できている
