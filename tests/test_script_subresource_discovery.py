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
