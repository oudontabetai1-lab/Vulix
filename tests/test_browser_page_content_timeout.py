"""F06: get_page_source が page.content() の無限ハングで停止しないことを検証する。

realistic_site 通し E2E が SQLi 再検証の page.content() 待ちで 900 秒 timeout していた。
待機を asyncio.wait_for で有界化したので、(1) ハングしても "" を返して速やかに戻る、
(2) 呼び出し側 cancel（scan 全体の SCAN_TIMEOUT_S 等）は内側 task を drain した上で
握りつぶさず伝播する、ことを確認する。
"""
import asyncio
import time
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


# --- ページ回復（recover_page / dialog wedge フラグ）Codex #171 P1 --------------

import types as _types


def test_on_dialog_flags_page_recovery_when_dismiss_hangs():
    # dismiss が返らなかったら、後続の再利用前に作り直すフラグを立てる。
    bm = _make_dialog_bm()
    bm._needs_page_recovery = False
    dialog = _HangingDialog()
    with patch.object(browser_mod, "_DIALOG_DISMISS_TIMEOUT", 0.05):
        asyncio.run(bm._on_dialog(dialog))
    assert bm._needs_page_recovery is True


def test_on_dialog_fast_dismiss_does_not_flag_recovery():
    bm = _make_dialog_bm()
    bm._needs_page_recovery = False
    asyncio.run(bm._on_dialog(_FastDialog()))
    assert bm._needs_page_recovery is False


class _RecoverablePage:
    def __init__(self):
        self.closed = False
        self.events = []

    def set_default_timeout(self, t):
        self._to = t

    def on(self, event, cb):
        self.events.append(event)

    async def close(self):
        self.closed = True


class _RecoverCtx:
    def __init__(self, new_page):
        self._new_page = new_page

    async def new_page(self):
        return self._new_page


def _make_recover_bm(old, new):
    bm = BrowserManager.__new__(BrowserManager)
    bm._use_scoped_headers = False
    bm._header_intercept_mode = "none"
    bm.timeout = 30000
    bm.network = _types.SimpleNamespace(on_request=lambda *a, **k: None)
    bm.dialog_fired = True
    bm.dialog_message = "xss"
    bm.dialog_screenshot_b64 = "shot"
    bm._needs_page_recovery = True
    bm.page = old
    bm._context = _RecoverCtx(new)
    return bm


def test_recover_page_recreates_and_rewires_and_clears_flag():
    old, new = _RecoverablePage(), _RecoverablePage()
    bm = _make_recover_bm(old, new)
    ok = asyncio.run(bm.recover_page())
    assert ok is True
    assert bm.page is new                 # 新ページへ差し替え
    assert old.closed is True             # 旧ページは close
    assert bm._needs_page_recovery is False
    assert bm.dialog_fired is False       # reset_dialog 済み
    # 再配線（request/response/dialog ハンドラ）が張られている
    assert {"request", "response", "dialog"} <= set(new.events)


def test_recover_page_without_context_is_noop():
    bm = BrowserManager.__new__(BrowserManager)
    bm._context = None
    bm.page = None
    bm._needs_page_recovery = True
    assert asyncio.run(bm.recover_page()) is False
    assert bm._needs_page_recovery is False


class _HangingCtx:
    """new_page がハングする context（wedge した接続を模す・Codex #171 P1 C4）。"""
    async def new_page(self):
        await asyncio.sleep(5)   # patched _PAGE_RECOVERY_TIMEOUT より十分長い
        return _RecoverablePage()


def test_recover_page_bounds_hanging_new_page():
    bm = BrowserManager.__new__(BrowserManager)
    bm._use_scoped_headers = False
    bm._header_intercept_mode = "none"
    bm.timeout = 30000
    bm._needs_page_recovery = True
    bm.page = _RecoverablePage()
    bm._context = _HangingCtx()
    with patch.object(browser_mod, "_PAGE_RECOVERY_TIMEOUT", 0.05):
        start = time.monotonic()
        ok = asyncio.run(bm.recover_page())
        elapsed = time.monotonic() - start
    assert ok is False           # new_page がハング → 有界時間で回復失敗を返す
    assert elapsed < 2.0         # 5秒待たない


def test_recover_page_cdp_mode_awaits_header_attach():
    # CDP scoped header モードでは新ページへ明示 attach を await する（#171 P1 C3）。
    old, new = _RecoverablePage(), _RecoverablePage()
    bm = _make_recover_bm(old, new)
    bm._header_intercept_mode = "cdp"
    attached = {}

    async def _fake_attach(page):
        attached["page"] = page

    bm._attach_header_interception = _fake_attach
    ok = asyncio.run(bm.recover_page())
    assert ok is True
    assert attached.get("page") is new   # 新ページに対して attach を await した
