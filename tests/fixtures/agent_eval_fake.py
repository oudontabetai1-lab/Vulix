"""Shared browser-use fakes for deterministic Agent execution tests."""
from __future__ import annotations

import types


class FakeHistory:
    def __init__(self, text: str, *, successful: bool = True):
        self.text = text
        self.successful = successful

    def is_successful(self) -> bool:
        return self.successful

    def final_result(self) -> str:
        return self.text

    def extracted_content(self) -> list[str]:
        return []

    def errors(self) -> list[str]:
        return []


class FakeBrowser:
    """Implements only the Browser methods used by AgentBrowserScanner tests."""

    def __init__(self, **_kwargs):
        pass

    async def stop(self) -> None:
        pass


def fake_browser_use(agent_class) -> types.ModuleType:
    module = types.ModuleType("browser_use")
    module.Agent = agent_class
    module.Browser = FakeBrowser
    return module
