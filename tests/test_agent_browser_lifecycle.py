import asyncio
import sys
import types
from unittest.mock import patch

import pytest
from wscan.llm_agent_browser import AgentBrowserScanner


@pytest.mark.asyncio
@pytest.mark.parametrize('ending', ['success', 'error', 'cancel'])
async def test_shared_session_survives_episodes_and_is_killed(tmp_path, monkeypatch, ending):
    sessions, navigations = [], []

    class Profile:
        def __init__(self, **kwargs):
            self.keep_alive = kwargs.get('keep_alive', False)

    class Browser:
        def __init__(self, browser_profile=None, **kwargs):
            self.profile = browser_profile
            self.connected = True
            self.killed = False
            sessions.append(self)

        async def kill(self):
            self.killed = True
            self.connected = False

        async def stop(self):
            if not self.profile.keep_alive:
                await self.kill()

    class History:
        def is_successful(self): return True
        def final_result(self): return 'EXPLORATION COMPLETE'
        def extracted_content(self): return []
        def errors(self): return []

    class Agent:
        def __init__(self, **kwargs): self.browser = kwargs['browser_session']
        async def run(self, **kwargs):
            assert self.browser.connected, 'CDP client not initialized'
            navigations.append(self.browser)
            if len(navigations) == 2:
                if ending == 'error': raise RuntimeError('episode failed')
                if ending == 'cancel': raise asyncio.CancelledError()
            if not self.browser.profile.keep_alive:
                await self.browser.kill()
            return History()

    module = types.ModuleType('browser_use')
    module.Agent, module.Browser, module.BrowserSession = Agent, Browser, Browser
    profile = types.ModuleType('browser_use.browser.profile')
    profile.BrowserProfile = Profile
    monkeypatch.setitem(sys.modules, 'browser_use', module)
    monkeypatch.setitem(sys.modules, 'browser_use.browser.profile', profile)
    scanner = AgentBrowserScanner('http://fixture.test', harness_output_dir=tmp_path, max_steps=8)
    with patch('wscan.llm_agent_browser._build_llm', return_value=object()):
        if ending == 'cancel':
            with pytest.raises(asyncio.CancelledError): await scanner.run()
        else:
            result = await scanner.run()
            assert result.error == ('episode failed' if ending == 'error' else None)
    assert len(navigations) >= 2
    assert all(session is sessions[0] for session in navigations)
    assert all(session.killed for session in sessions)

@pytest.mark.asyncio
async def test_execution_trace_only_records_actions_with_results(tmp_path):
    import json
    from wscan.agent_harness import AgentHarness, AgentRunSpec
    scanner = AgentBrowserScanner('http://fixture.test')
    scanner._harness = AgentHarness(tmp_path, AgentRunSpec(mode='agent', target_url='http://fixture.test', max_steps=8, target_urls=(), access_urls=(), exclude_urls=(), exclude_fields=(), checks=(), provider='none', model='none'))
    actions = [{'navigate': {'url': 'http://fixture.test'}}, {'click': {'index': 2}}]
    await scanner._on_step(types.SimpleNamespace(url='http://fixture.test'), types.SimpleNamespace(action=actions), 1)
    item = types.SimpleNamespace(model_output=types.SimpleNamespace(action=actions), result=[object()])
    await scanner._on_step_end(types.SimpleNamespace(history=types.SimpleNamespace(history=[item])))
    records = [json.loads(line) for line in (tmp_path / 'agent_steps.jsonl').read_text().splitlines()]
    assert records[0]['executed_actions'] == []
    assert len(records[-1]['executed_actions']) == 1
    assert 'navigate' in str(records[-1]['executed_actions'])
    assert records[-1]['step_id'] == records[0]['step_id']
    assert scanner._harness.state.consumed_steps == 1
