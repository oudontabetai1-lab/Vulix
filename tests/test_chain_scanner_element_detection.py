"""chain_scanner の要素照合（実 DOM 要素の存在）を Chromium で固定する単体テスト。

escape 済み格納は page.content() の再シリアライズで内側の引用符が残り、部分文字列
``id="wscc_UID"`` が現れるが要素にはならない。要素照合はその FP を避ける根拠。
"""
import html
from pathlib import Path

import pytest

playwright_sync = pytest.importorskip("playwright.sync_api")

UID = "deadbeef"
RAW = f'<span id="wscc_{UID}">x</span>'


@pytest.fixture(scope="module")
def page():
    with playwright_sync.sync_playwright() as pw:
        if not Path(pw.chromium.executable_path).is_file():
            pytest.skip("Chromium is not installed (playwright install chromium)")
        browser = pw.chromium.launch(headless=True)
        try:
            yield browser.new_page()
        finally:
            browser.close()


def _exists(page) -> bool:
    return page.query_selector(f"#wscc_{UID}") is not None


def test_raw_markup_is_element(page):
    page.set_content(f"<body><div>{RAW}</div></body>")
    assert _exists(page)


def test_escaped_markup_is_not_element_despite_substring(page):
    page.set_content(f"<body><div>{html.escape(RAW)}</div></body>")
    assert f'id="wscc_{UID}"' in page.content()  # 旧・部分文字列照合なら FP になっていた
    assert not _exists(page)


def test_tag_stripped_text_is_not_element(page):
    page.set_content(f"<body><div>x wscc_{UID}</div></body>")
    assert not _exists(page)


# --- 実メソッド ChainScanner._probe_rendered_as_element を実ブラウザで駆動 ---

import asyncio
from concurrent.futures import ThreadPoolExecutor
from types import SimpleNamespace

from wscan.chain_scanner import ChainScanner


def _probe_results(bodies: dict) -> dict:
    """各 body を実 Chromium で描画し、実メソッドの判定結果を返す。"""
    from playwright.async_api import async_playwright

    async def go():
        async with async_playwright() as pw:
            if not Path(pw.chromium.executable_path).is_file():
                pytest.skip("Chromium is not installed (playwright install chromium)")
            browser = await pw.chromium.launch(headless=True)
            try:
                pg = await browser.new_page()
                # __init__ の副作用を避けつつ、実メソッドが読む self.browser.page だけ実ページにする
                scanner = ChainScanner(SimpleNamespace(page=pg))
                out = {}
                for name, body in bodies.items():
                    await pg.set_content(f"<body><div>{body}</div></body>")
                    if name == "escaped":  # 旧・部分文字列照合なら FP になっていた
                        assert f'id="wscc_{UID}"' in await pg.content()
                    out[name] = await scanner._probe_rendered_as_element(UID)
                return out
            finally:
                await browser.close()

    # モジュール fixture の sync Playwright がスレッドの event loop を占有するため別スレッドで実行する
    with ThreadPoolExecutor(1) as ex:
        return ex.submit(asyncio.run, go()).result()


def test_real_probe_method_distinguishes_element_from_text():
    res = _probe_results({
        "raw_span": RAW,
        "raw_img": f'<img id="wscc_{UID}" src="x">',
        "escaped": html.escape(RAW),
        "stripped": f"x wscc_{UID}",
    })
    assert res == {"raw_span": True, "raw_img": True, "escaped": False, "stripped": False}
