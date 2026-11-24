"""Agent Browser の task cancel がブラウザを確実に停止することを検証する。"""

import asyncio
import sys
import types
from unittest.mock import patch

import pytest

from wscan.llm_agent_browser import AgentBrowserScanner


def test_agent_browser_cancel_stops_browser(monkeypatch):
    started = asyncio.Event()
    browsers = []

    class FakeBrowserSession:
        def __init__(self, **_kwargs):
            self.stopped = False
            browsers.append(self)

        async def stop(self):
            self.stopped = True

    class FakeAgent:
        def __init__(self, **_kwargs):
            pass

        async def run(self, **_kwargs):
            started.set()
            await asyncio.Event().wait()

    browser_use = types.ModuleType("browser_use")
    browser_use.Agent = FakeAgent
    browser_use.BrowserSession = FakeBrowserSession
    profile = types.ModuleType("browser_use.browser.profile")
    profile.BrowserProfile = type("FakeBrowserProfile", (), {"__init__": lambda self, **_kwargs: None})

    async def guard_ready(_session):
        return True

    async def run_test():
        scanner = AgentBrowserScanner(target_url="http://fixture.test")
        monkeypatch.setitem(sys.modules, "browser_use", browser_use)
        monkeypatch.setitem(sys.modules, "browser_use.browser.profile", profile)
        monkeypatch.setattr(scanner, "_enable_request_scoped_headers", guard_ready)
        monkeypatch.setattr(scanner, "_enable_agent_network_guard", guard_ready)
        with patch("wscan.llm_agent_browser._build_llm", return_value=object()):
            task = asyncio.create_task(scanner.run())
            await started.wait()
            task.cancel()
            with pytest.raises(asyncio.CancelledError):
                await task

    asyncio.run(run_test())

    assert len(browsers) == 1
    assert browsers[0].stopped is True
