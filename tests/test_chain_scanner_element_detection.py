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
