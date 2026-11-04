"""Opt-in Chromium integration for script discovery (WSCAN_E2E=1)."""
import os

import pytest

from wscan.browser import BrowserManager
from wscan.engine import ScanEngine


@pytest.mark.skipif(
    os.environ.get("WSCAN_E2E", "").strip().lower() not in {"1", "true", "yes", "on"},
    reason="set WSCAN_E2E=1 to run the script discovery browser test",
)
@pytest.mark.asyncio
async def test_script_src_discovery_uses_base_uri_and_scope_blocks_external_request():
    browser = BrowserManager(headless=True)
    requests = []

    async def block_requests(route):
        requests.append(route.request.url)
        await route.abort()

    try:
        await browser.init()
        await browser.page.route("**/*", block_requests)
        await browser.page.set_content(
            '<base href="https://scope.test/assets/">'
            '<script src="../bundle.js"></script>'
            '<script src="https://outside.invalid/tracker.js"></script>'
        )
        found = await browser.collect_links("https://scope.test/page", same_domain=False)

        assert "https://scope.test/bundle.js" in found
        outside = "https://outside.invalid/tracker.js"
        assert outside in found
        engine = ScanEngine.__new__(ScanEngine)
        engine.target_urls = ["https://scope.test"]
        engine.access_urls = []
        assert not engine._is_access_allowed_url(outside)
        assert outside in requests  # intercepted by Chromium before any network connection
    finally:
        await browser.close()


@pytest.mark.skipif(
    os.environ.get("WSCAN_E2E", "").strip().lower() not in {"1", "true", "yes", "on"},
    reason="set WSCAN_E2E=1 to run the script discovery browser test",
)
@pytest.mark.asyncio
async def test_collect_links_rich_excludes_scripts_from_navigation_links():
    # Edge 1: collect_links_rich は script[src] をナビゲーションリンクから除外し、Crawl BFS を肥大化させない
    browser = BrowserManager(headless=True)
    try:
        await browser.init()
        await browser.page.set_content(
            '<base href="https://scope.test/assets/">'
            '<a href="/dashboard">Dashboard</a>'
            '<script src="../bundle.js"></script>'
        )
        rich_links = await browser.collect_links_rich("https://scope.test/page", same_domain=False)
        urls = [entry["url"] for entry in rich_links]
        # 安全ツイン: 遷移先リンク（/dashboard）は保持され、スクリプト（bundle.js）は除外される
        assert "https://scope.test/dashboard" in urls
        assert "https://scope.test/bundle.js" not in urls
    finally:
        await browser.close()


def test_crawl_queue_subresource_filtering_pure():
    # Edge 1 の純粋判定テスト（ブラウザ非依存）
    from wscan.url_extraction import is_script_subresource_url

    # スクリプトサブリソースは navigation queue から除外対象
    assert is_script_subresource_url("http://target.test/static/chunk-123.js") is True
    assert is_script_subresource_url("http://target.test/static/vendor.mjs?v=2") is True
    assert is_script_subresource_url("http://target.test/module.cjs") is True

    # 安全ツイン: 通常ページや API エンドポイントは除外されず navigation queue に残る
    assert is_script_subresource_url("http://target.test/dashboard") is False
    assert is_script_subresource_url("http://target.test/docs/index.html") is False
    assert is_script_subresource_url("http://target.test/api/v1/users") is False
