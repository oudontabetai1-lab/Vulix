import asyncio
import sys
import types
from types import SimpleNamespace
from unittest.mock import patch

import pytest

from wscan.agent_engine import AgentEngine
from wscan.llm_agent_browser import AgentBrowserScanner


def _proxy_sdk_modules():
    browser_use = types.ModuleType("browser_use")
    browser_use.__path__ = []
    browser = types.ModuleType("browser_use.browser")
    browser.__path__ = []
    profile = types.ModuleType("browser_use.browser.profile")

    class ProxySettings:
        def __init__(self, *, server):
            self.server = server

    profile.ProxySettings = ProxySettings
    return {
        "browser_use": browser_use,
        "browser_use.browser": browser,
        "browser_use.browser.profile": profile,
    }


def test_agent_browser_profile_receives_normalized_proxy_without_sdk_global_config():
    scanner = AgentBrowserScanner("http://fixture.test", proxy="127.0.0.1:8080")
    captured = {}

    class Profile:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    with patch.dict(sys.modules, _proxy_sdk_modules()):
        scanner._build_browser_profile(Profile)

    assert captured["proxy"].server == "http://127.0.0.1:8080"


def test_proxy_profile_rejects_sdk_without_proxy_support():
    scanner = AgentBrowserScanner("http://fixture.test", proxy="http://127.0.0.1:8080")

    class LegacyProfile:
        def __init__(self, *, headless, disable_security, allowed_domains, storage_state):
            pass

    with patch.dict(sys.modules, _proxy_sdk_modules()):
        with pytest.raises(RuntimeError, match="proxy を browser-use profile"):
            scanner._build_browser_profile(LegacyProfile)


def test_agent_browser_profile_keeps_no_proxy_default():
    scanner = AgentBrowserScanner("http://fixture.test")
    captured = {}

    class Profile:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    scanner._build_browser_profile(Profile)

    assert "proxy" not in captured


def test_agent_engine_run_forwards_proxy_to_scanner(tmp_path):
    captured = {}

    class Scanner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def run(self):
            return SimpleNamespace(error="fixture stop", findings=[], preserve_existing_artifacts=True)

    engine = AgentEngine(
        "http://fixture.test", proxy="127.0.0.1:8080", output_dir=str(tmp_path)
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", Scanner):
        result = asyncio.run(engine.run())

    assert result.error == "fixture stop"
    assert captured["proxy"] == "http://127.0.0.1:8080"


@pytest.mark.asyncio
async def test_agent_engine_recon_forwards_proxy_to_scanner(tmp_path):
    captured = {}

    class Scanner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def run(self):
            return SimpleNamespace(error="fixture stop")

    engine = AgentEngine(
        "http://fixture.test", proxy="http://127.0.0.1:8080", output_dir=str(tmp_path)
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", Scanner):
        with pytest.raises(RuntimeError, match="Agent recon failed"):
            await engine.run_recon()

    assert captured["proxy"] == "http://127.0.0.1:8080"
