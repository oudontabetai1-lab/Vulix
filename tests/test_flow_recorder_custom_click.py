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
    "<div id='addcart' role='button'><span id='addcart-child'>Add to cart</span></div>"
    "<input id='btn' type='button' value='Btn'>"
    "<label id='lbl' for='chk'>Agree</label>"
    "<input id='chk' type='checkbox' style='display:none'>"
    "<label id='standalone'>Standalone action</label>"
    "<label id='upload-label' for='upload'>Upload</label>"
    "<input id='upload' type='file'>"
    "<div id='onc' onclick='void 0'>onclick div</div>"
    "<div id='plain'>plain child</div>"
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
        notices: list[str] = []
        await page.expose_function("N", lambda message: notices.append(message))
        await page.add_init_script(_build_recorder_script("F", "C", "S", "N"))
        await page.goto(_RECORD_HTML)

        # BODY の inline handler は descendant click の closest 候補になるが、root は記録不能。
        await page.evaluate("() => document.body.setAttribute('onclick', 'void 0')")
        for sel in ("#addcart-child", "#btn", "#lbl", "#standalone", "#upload-label", "#onc", "#plain", "#deco"):
            await page.click(sel)
        await page.wait_for_timeout(150)  # expose_function IPC の到達待ち

        clicked = {s["selector"] for s in steps if s["action"] == "click"}
        self.assertIn("#addcart-child", clicked)
        self.assertNotIn("#addcart", clicked)
        self.assertIn("#btn", clicked)
        self.assertIn("#standalone", clicked)
        self.assertIn("#onc", clicked)
        # 関連 checkbox は change handler が状態を記録するため label click を重ねない。
        self.assertNotIn("#lbl", clicked)
        self.assertTrue(any(s.get("selector") == "#chk" for s in steps))
        # file label は replay 不能な chooser を開く step にせず通知する。
        self.assertNotIn("#upload-label", clicked)
        self.assertTrue(any("file input" in message for message in notices))
        # body[onclick] へ解決されても空 selector/root click は保存しない。
        self.assertNotIn("", clicked)
        # 装飾 span は操作要素セレクタに一致せず記録されない。
        self.assertNotIn("#deco", clicked)
        await page.close()

    async def _recording_page(self, html: str):
        steps: list[dict] = []
        notices: list[str] = []
        page = await self._context.new_page()
        await page.expose_function("F", lambda selector, value: steps.append(
            {"action": "fill", "selector": selector, "value": value}))
        await page.expose_function("C", lambda selector: steps.append(
            {"action": "click", "selector": selector}))
        await page.expose_function("S", lambda selector: steps.append(
            {"action": "submit", "selector": selector}))
        await page.expose_function("N", lambda message: notices.append(message))
        await page.add_init_script(_build_recorder_script("F", "C", "S", "N"))
        await page.goto(html)
        return page, steps, notices

    async def test_direct_checkbox_radio_file_and_image_are_not_click_steps(self):
        """直接一致する checkbox/radio/file/image input は click step を残さない。"""
        page, steps, notices = await self._recording_page(
            "data:text/html,<!doctype html><html><body><form onsubmit='return false'>"
            "<input id='chk' type='checkbox' tabindex='0' onclick='void 0'>"
            "<input id='rad' type='radio' name='r' tabindex='0' onclick='void 0'>"
            "<input id='file' type='file' tabindex='0' onclick='event.preventDefault()'>"
            "<input id='img' type='image' alt='go' tabindex='0'>"
            "</form></body></html>"
        )
        for sel in ("#chk", "#rad", "#file", "#img"):
            await page.click(sel)
        await page.wait_for_timeout(150)

        clicks = [s["selector"] for s in steps if s["action"] == "click"]
        self.assertEqual(clicks.count("#chk"), 1)
        self.assertEqual(clicks.count("#rad"), 1)
        self.assertNotIn("#file", clicks)
        self.assertNotIn("#img", clicks)
        self.assertTrue(any("file input" in message and "#file" in message for message in notices))
        self.assertTrue(any("image input" in message and "#img" in message for message in notices))
        await page.close()

    async def test_request_submit_from_click_records_only_click(self):
        """click handler 内の submitter なし requestSubmit は click と二重記録しない。"""
        page, steps, _notices = await self._recording_page(
            "data:text/html,<!doctype html><html><body>"
            "<form id='f' onsubmit='event.preventDefault()'>"
            "<input id='btn' type='button' value='Save' onclick='this.form.requestSubmit()'>"
            "<div id='role' role='button' onclick=\"document.getElementById('f').requestSubmit()\">Role</div>"
            "</form></body></html>"
        )
        await page.click("#btn")
        await page.click("#role")
        await page.wait_for_timeout(150)

        self.assertEqual([s["action"] for s in steps], ["click", "click"])
        self.assertEqual([s["selector"] for s in steps], ["#btn", "#role"])
        await page.press("body", "Enter")
        await page.evaluate("() => document.getElementById('f').requestSubmit()")
        await page.wait_for_timeout(150)
        self.assertEqual(steps[-1]["action"], "submit")
        await page.close()

    async def test_replay_preserves_delegated_child_target(self):
        """委譲ハンドラの子要素 click は子を再生し、祖先 handler の event.target を保つ。"""
        page, steps, _notices = await self._recording_page(
            "data:text/html,<!doctype html><html><body>"
            "<div id='menu' onclick=\"document.title=event.target.id\">"
            "<span id='first'>First</span><span id='second' style='margin-left:120px'>Second</span>"
            "</div></body></html>"
        )
        await page.click("#second")
        await page.wait_for_timeout(150)
        self.assertEqual(steps, [{"action": "click", "selector": "#second"}])
        await page.close()

        replay_page = await self._context.new_page()
        runner = FlowRunner(_PageBrowser(replay_page))
        flow = ScanFlow.from_dict({
            "name": "delegated-child",
            "steps": [
                {"action": "navigate", "url": (
                    "data:text/html,<!doctype html><html><body>"
                    "<div id='menu' onclick=\"document.title=event.target.id\">"
                    "<span id='first'>First</span><span id='second' style='margin-left:120px'>Second</span>"
                    "</div></body></html>"
                )},
                steps[0],
            ],
        })
        self.assertTrue(await runner.run(flow))
        self.assertEqual(await replay_page.title(), "second")
        await replay_page.close()

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

    async def test_replay_rejects_invalid_selector(self):
        """actionability timeout 以外（selector 構文不正）は flow を失敗させる。"""
        page = await self._context.new_page()
        runner = FlowRunner(_PageBrowser(page))
        flow = ScanFlow.from_dict({
            "name": "invalid-selector",
            "steps": [
                {"action": "navigate", "url": "data:text/html,<button>ok</button>"},
                {"action": "click", "selector": "[", "timeout": 1.0},
            ],
        })
        self.assertFalse(await runner.run(flow))
        await page.close()

    async def test_replay_rejects_missing_click_target(self):
        """存在しない selector の timeout は actionability skip に丸めない。"""
        page = await self._context.new_page()
        runner = FlowRunner(_PageBrowser(page))
        flow = ScanFlow.from_dict({
            "name": "missing-selector",
            "steps": [
                {"action": "navigate", "url": "data:text/html,<button>ok</button>"},
                {"action": "click", "selector": "#missing", "timeout": 0.1},
            ],
        })
        self.assertFalse(await runner.run(flow))
        await page.close()


if __name__ == "__main__":
    unittest.main()
