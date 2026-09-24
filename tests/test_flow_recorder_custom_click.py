"""flow recorder のカスタム操作要素 click 記録と、再生側 actionability skip を実 Chromium で検証する（vault 0078）。

Playwright Chromium が使えない環境では skip する（既存 E2E の skip 判定に倣う）。
"""
from __future__ import annotations

import unittest

from wscan.flow_recorder import _build_recorder_script
from wscan.flow_runner import FlowRunner, ScanFlow


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    try:
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


# 記録テスト用 HTML: カスタム操作要素と、記録してはいけない装飾 span を混在させる。
_RECORD_HTML = (
    "data:text/html,"
    "<!doctype html><html><body>"
    "<div id='addcart' role='button'><span>Add to cart</span></div>"
    "<input id='btn' type='button' value='Btn'>"
    "<label id='lbl' for='chk'>Agree</label>"
    "<input id='chk' type='checkbox' style='display:none'>"
    "<div id='onc' onclick='void 0'>onclick div</div>"
    "<span id='deco'>decoration</span>"
    "</body></html>"
)


class _PageBrowser:
    """FlowRunner が必要とする最小の browser（page + navigate）だけを備えるラッパー。"""

    def __init__(self, page):
        self.page = page

    async def navigate(self, url: str) -> bool:
        await self.page.goto(url)
        return True


@unittest.skipUnless(
    _chromium_available(),
    "Playwright Chromium browser is not installed (run: playwright install chromium)",
)
class FlowRecorderCustomClickTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        from playwright.async_api import async_playwright

        self._pw = await async_playwright().start()
        self._browser = await self._pw.chromium.launch(headless=True)
        self._context = await self._browser.new_context()

    async def asyncTearDown(self):
        await self._context.close()
        await self._browser.close()
        await self._pw.stop()

    async def test_records_custom_operation_elements(self):
        """role=button / input[type=button] / label / [onclick] は記録され、装飾 span は拾わない。"""
        steps: list[dict] = []
        page = await self._context.new_page()
        await page.expose_function("F", lambda selector, value: steps.append(
            {"action": "fill", "selector": selector, "value": value}))
        await page.expose_function("C", lambda selector: steps.append(
            {"action": "click", "selector": selector}))
        await page.expose_function("S", lambda selector: steps.append(
            {"action": "submit", "selector": selector}))
        await page.expose_function("N", lambda message: None)
        await page.add_init_script(_build_recorder_script("F", "C", "S", "N"))
        await page.goto(_RECORD_HTML)

        for sel in ("#addcart", "#btn", "#lbl", "#onc", "#deco"):
            await page.click(sel)
        await page.wait_for_timeout(150)  # expose_function IPC の到達待ち

        clicked = {s["selector"] for s in steps if s["action"] == "click"}
        # カスタム操作要素は closest 解決で記録される（子 span をクリックしても祖先 #addcart）。
        self.assertIn("#addcart", clicked)
        self.assertIn("#btn", clicked)
        self.assertIn("#lbl", clicked)
        self.assertIn("#onc", clicked)
        # 装飾 span は操作要素セレクタに一致せず記録されない。
        self.assertNotIn("#deco", clicked)
        await page.close()

    async def test_replay_clicks_custom_element(self):
        """記録した click ステップを FlowRunner が再生し、要素の onclick が実行される。"""
        page = await self._context.new_page()
        runner = FlowRunner(_PageBrowser(page))
        html = (
            "data:text/html,"
            "<!doctype html><html><body>"
            "<div id='addcart' role='button' onclick=\"document.title='CLICKED'\">Add</div>"
            "</body></html>"
        )
        flow = ScanFlow.from_dict({
            "name": "custom-click",
            "steps": [
                {"action": "navigate", "url": html},
                {"action": "click", "selector": "#addcart"},
            ],
        })
        ok = await runner.run(flow)
        self.assertTrue(ok)
        self.assertEqual(await page.title(), "CLICKED")
        await page.close()

    async def test_replay_skips_unclickable_step(self):
        """actionability を通らない click は skip され flow 全体は落ちない（後続も継続）。"""
        page = await self._context.new_page()
        runner = FlowRunner(_PageBrowser(page))
        # overlay がポインタイベントを奪い、#target の click は timeout する。
        html = (
            "data:text/html,"
            "<!doctype html><html><body>"
            "<div id='target' role='button' onclick=\"window.__clicked=true\">T</div>"
            "<div id='overlay' style='position:fixed;top:0;left:0;right:0;bottom:0;z-index:9999'></div>"
            "</body></html>"
        )
        flow = ScanFlow.from_dict({
            "name": "unclickable",
            "steps": [
                {"action": "navigate", "url": html},
                {"action": "click", "selector": "#target", "timeout": 1.0},
                {"action": "wait", "timeout": 0.05},
            ],
        })
        ok = await runner.run(flow)
        # click 不能でも skip-notify で flow は成功（後続 wait も実行される）。
        self.assertTrue(ok)
        clicked = await page.evaluate("() => !!window.__clicked")
        self.assertFalse(clicked)
        await page.close()


if __name__ == "__main__":
    unittest.main()
