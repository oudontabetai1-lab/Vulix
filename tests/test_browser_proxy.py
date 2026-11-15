from wscan.browser import _playwright_proxy_options


def test_playwright_proxy_options_split_credentials_and_preserve_safe_cases():
    assert _playwright_proxy_options("http://user:pass@proxy.test:8080") == {
        "server": "http://proxy.test:8080", "username": "user", "password": "pass"
    }
    assert _playwright_proxy_options("http://proxy.test:8080") == {"server": "http://proxy.test:8080"}
    assert _playwright_proxy_options("") is None


def test_httpx_client_kwargs_trust_env_and_detect_bypass_gap(tmp_path):
    import asyncio
    from types import SimpleNamespace
    import httpx
    from wscan.engine import ScanEngine
    from wscan.request_logger import RequestLogger
    from wscan.tls_config import TLSConfig

    logger = RequestLogger(tmp_path)
    engine = SimpleNamespace(
        proxy="http://user:secret@127.0.0.1:8080",
        tls_config=TLSConfig.from_values(),
        request_logger=logger,
    )

    # 1. trust_env is defaulted to False and configured_proxy is redacted
    mock_transport = httpx.MockTransport(lambda req: httpx.Response(200))
    kwargs = ScanEngine.httpx_client_kwargs(engine, mounts={"all://": mock_transport})
    assert kwargs["trust_env"] is False
    assert kwargs["proxy"] == "http://user:secret@127.0.0.1:8080"
    assert logger.configured_proxy == "http://127.0.0.1:8080"

    # 2. When transport bypasses proxy, proxy_configured_but_bypassed is noted in gaps
    async def run_bypassed():
        async with httpx.AsyncClient(**kwargs) as client:
            await client.get("http://example.com")

    asyncio.run(run_bypassed())
    assert "proxy_configured_but_bypassed" in logger.probe_ledger.manifest.gaps

    # 3. When transport matches configured proxy, no bypass gap is noted
    class ProxiedMockTransport(httpx.MockTransport):
        def __init__(self, handler):
            super().__init__(handler)
            self._pool = SimpleNamespace(_proxy_url=httpx.URL("http://127.0.0.1:8080"))

    logger2 = RequestLogger(tmp_path / "proxied")
    engine2 = SimpleNamespace(
        proxy="http://user:secret@127.0.0.1:8080",
        tls_config=TLSConfig.from_values(),
        request_logger=logger2,
    )
    proxied_transport = ProxiedMockTransport(lambda req: httpx.Response(200))
    kwargs2 = ScanEngine.httpx_client_kwargs(engine2, mounts={"all://": proxied_transport})

    async def run_proxied():
        async with httpx.AsyncClient(**kwargs2) as client:
            await client.get("http://example.com")

    asyncio.run(run_proxied())
    assert "proxy_configured_but_bypassed" not in logger2.probe_ledger.manifest.gaps


def test_manual_crawl_session_applies_playwright_proxy_options():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch
    from wscan.manual_crawl import ManualCrawlSession

    mock_page = AsyncMock()
    mock_page.main_frame = mock_page
    mock_page.url = "http://example.com"
    mock_context = MagicMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_context.on = MagicMock()
    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_chromium = AsyncMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw = AsyncMock()
    mock_pw.chromium = mock_chromium

    session = ManualCrawlSession()

    async def run_manual():
        with patch("playwright.async_api.async_playwright") as mock_ap:
            mock_ap.return_value.start = AsyncMock(return_value=mock_pw)
            session._bind_page = AsyncMock()
            await session.start("http://example.com", "out.json", proxy="http://user:secret@127.0.0.1:8080")
            launch_kwargs = mock_chromium.launch.call_args[1]
            context_kwargs = mock_browser.new_context.call_args[1]
            expected_proxy = {"server": "http://127.0.0.1:8080", "username": "user", "password": "secret"}
            assert launch_kwargs["proxy"] == expected_proxy
            assert context_kwargs["proxy"] == expected_proxy
            assert "secret" not in launch_kwargs["proxy"]["server"]
            assert "secret" not in context_kwargs["proxy"]["server"]

    asyncio.run(run_manual())


def test_triage_engine_applies_playwright_proxy_options():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch
    from wscan.triage import TriageEngine

    mock_page = AsyncMock()
    mock_page.main_frame = mock_page
    mock_page.url = "http://example.com"
    mock_context = MagicMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_chromium = AsyncMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw = AsyncMock()
    mock_pw.chromium = mock_chromium

    triage = TriageEngine("http://example.com", proxy="http://user:secret@127.0.0.1:8080")

    async def run_triage():
        with patch("playwright.async_api.async_playwright") as mock_ap:
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = mock_pw
            mock_ap.return_value = mock_cm
            mock_resp = MagicMock()
            mock_resp.all_headers = AsyncMock(return_value={})
            mock_page.goto = AsyncMock(return_value=mock_resp)
            mock_page.content = AsyncMock(return_value="<html></html>")
            mock_page.evaluate = AsyncMock(return_value=[])
            await triage.run()
            launch_kwargs = mock_chromium.launch.call_args[1]
            context_kwargs = mock_browser.new_context.call_args[1]
            expected_proxy = {"server": "http://127.0.0.1:8080", "username": "user", "password": "secret"}
            assert launch_kwargs["proxy"] == expected_proxy
            assert context_kwargs["proxy"] == expected_proxy
            assert "secret" not in launch_kwargs["proxy"]["server"]
            assert "secret" not in context_kwargs["proxy"]["server"]

    asyncio.run(run_triage())


def test_flow_recorder_applies_playwright_proxy_options():
    import asyncio
    from unittest.mock import AsyncMock, MagicMock, patch
    from wscan.flow_recorder import FlowRecorder

    mock_page = MagicMock()
    mock_page.main_frame = mock_page
    mock_page.url = "http://example.com"
    mock_page.on = MagicMock()
    mock_page.goto = AsyncMock(side_effect=KeyboardInterrupt)
    mock_context = MagicMock()
    mock_context.new_page = AsyncMock(return_value=mock_page)
    mock_browser = AsyncMock()
    mock_browser.new_context = AsyncMock(return_value=mock_context)
    mock_chromium = AsyncMock()
    mock_chromium.launch = AsyncMock(return_value=mock_browser)
    mock_pw = AsyncMock()
    mock_pw.chromium = mock_chromium

    recorder = FlowRecorder(proxy="http://user:secret@127.0.0.1:8080")

    async def run_flow():
        with patch("playwright.async_api.async_playwright") as mock_ap:
            mock_cm = AsyncMock()
            mock_cm.__aenter__.return_value = mock_pw
            mock_ap.return_value = mock_cm
            try:
                await recorder.record_interactive("http://example.com", "out.json")
            except (KeyboardInterrupt, Exception):
                pass
            launch_kwargs = mock_chromium.launch.call_args[1]
            context_kwargs = mock_browser.new_context.call_args[1]
            expected_proxy = {"server": "http://127.0.0.1:8080", "username": "user", "password": "secret"}
            assert launch_kwargs["proxy"] == expected_proxy
            assert context_kwargs["proxy"] == expected_proxy
            assert "secret" not in launch_kwargs["proxy"]["server"]
            assert "secret" not in context_kwargs["proxy"]["server"]

    asyncio.run(run_flow())
