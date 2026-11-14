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
@pytest.mark.parametrize('case', ['success', 'before_actions_error', 'mid_actions_error', 'stale_history', 'wrong_step', 'wrong_agent', 'wrong_episode'])
async def test_execution_trace_requires_current_step_evidence(tmp_path, case):
    import json
    from wscan.agent_harness import AgentHarness, AgentRunSpec
    scanner = AgentBrowserScanner('http://fixture.test')
    scanner._harness = AgentHarness(tmp_path, AgentRunSpec(mode='agent', target_url='http://fixture.test', max_steps=8, target_urls=(), access_urls=(), exclude_urls=(), exclude_fields=(), checks=(), provider='none', model='none'))
    actions = [{'navigate': {'url': 'http://fixture.test'}}, {'click': {'index': 2}}]
    old_item = types.SimpleNamespace(model_output=types.SimpleNamespace(action=actions), result=[types.SimpleNamespace(error=None)], metadata=types.SimpleNamespace(step_number=1))
    agent = types.SimpleNamespace(history=types.SimpleNamespace(history=[old_item]))
    await scanner._on_step_start(agent)
    await scanner._on_step(types.SimpleNamespace(url='http://fixture.test'), types.SimpleNamespace(action=actions), 2)
    results = [types.SimpleNamespace(error=None)]
    if case in ('before_actions_error', 'mid_actions_error'):
        # 途中例外でも実行済み prefix は汎用エラーで置き換えられる。
        results = [types.SimpleNamespace(error='Interrupted before actions' if case == 'before_actions_error' else 'Interrupted during actions')]
    if case != 'stale_history':
        agent.history.history.append(types.SimpleNamespace(model_output=types.SimpleNamespace(action=actions), result=results, metadata=types.SimpleNamespace(step_number=1 if case == 'wrong_step' else 2)))
    if case == 'wrong_agent':
        agent = types.SimpleNamespace(history=agent.history)
    if case == 'wrong_episode':
        scanner._active_episode_id = 'another-episode'
    await scanner._on_step_end(agent)
    records = [json.loads(line) for line in (tmp_path / 'agent_steps.jsonl').read_text().splitlines()]
    assert records[0]['executed_actions'] == []
    assert len(records[-1]['executed_actions']) == (1 if case == 'success' else 0)
    assert records[-1]['execution_status'] == ('confirmed' if case == 'success' else 'unconfirmed')
    assert records[-1]['step_id'] == records[0]['step_id']
    assert scanner._harness.state.consumed_steps == 2
    assert scanner._harness.state.repeated_steps == 0
    # 再通知でも前の pending record を使い回さない。
    await scanner._on_step_end(agent)
    assert len((tmp_path / 'agent_steps.jsonl').read_text().splitlines()) == len(records)
