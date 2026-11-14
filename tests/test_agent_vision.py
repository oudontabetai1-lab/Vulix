import sys
import types
from unittest.mock import AsyncMock, patch

import pytest
from wscan.llm_agent_browser import AgentBrowserScanner, decide_agent_vision


@pytest.mark.parametrize('capabilities,expected', [(['vision'], True), (['completion'], False), (None, True), ({'error': 'unavailable'}, True)])
def test_capability_decision(capabilities, expected):
    assert decide_agent_vision('auto', capabilities) is expected
    assert decide_agent_vision('on', capabilities) is True
    assert decide_agent_vision('off', capabilities) is False


def test_backward_compatible_default(tmp_path):
    assert AgentBrowserScanner('http://fixture.test').agent_vision == 'auto'
    import main
    config = tmp_path / 'settings.yaml'
    config.write_text('{}')
    assert main._load_config(config)['agent_vision'] == 'auto'
    config.write_text('agent_vision: \"off\"')
    assert main._load_config(config)['agent_vision'] == 'off'
    assert main._build_parser().parse_args(['agent', 'http://fixture.test']).agent_vision == 'auto'


@pytest.mark.asyncio
async def test_first_multimodal_error_restarts_text_only(monkeypatch):
    llm = types.SimpleNamespace(ainvoke=AsyncMock(side_effect=[RuntimeError('HTTP 400: model does not support multimodal requests'), 'ok']))
    invoke = llm.ainvoke
    modes = []
    browsers = []
    class Browser:
        def __init__(self, **kwargs): browsers.append(self)
        async def stop(self): pass
    class History:
        def is_successful(self): return False
        def final_result(self): return ''
        def extracted_content(self): return []
        def errors(self): return []
        def model_actions(self): return []
        def urls(self): return []
    class Agent:
        def __init__(self, **kwargs): modes.append(kwargs['use_vision'])
        async def run(self, **kwargs):
            await llm.ainvoke([])
            return History()
    module = types.ModuleType('browser_use')
    module.Agent, module.Browser = Agent, Browser
    monkeypatch.setitem(sys.modules, 'browser_use', module)
    with patch('wscan.llm_agent_browser._build_llm', return_value=llm), patch('httpx.AsyncClient.post', side_effect=__import__('httpx').ConnectError('unavailable')):
        result = await AgentBrowserScanner('http://fixture.test', llm_provider='ollama').run()
    assert modes == [True, False]
    assert len(browsers) == 2
    assert invoke.await_count == 2
    assert 'vision:text_only' in result.coverage_gaps
    assert 'running text-only' in result.final_summary


@pytest.mark.asyncio
@pytest.mark.parametrize('retry_fails', [False, True])
async def test_auth_then_first_vision_request_falls_back_once(tmp_path, retry_fails, monkeypatch):
    modes = []
    class Browser:
        def __init__(self, **kwargs): pass
        async def stop(self): pass
    class Profile:
        def __init__(self, **kwargs): pass
    class History:
        def is_successful(self): return True
        def final_result(self): return 'AUTH COMPLETE'
        def extracted_content(self): return []
        def errors(self): return []
    async def invoke(*args, **kwargs):
        if len(modes) == 2 or (retry_fails and len(modes) == 3):
            raise RuntimeError('HTTP 400: model does not support multimodal requests')
        return 'ok'
    llm = types.SimpleNamespace(ainvoke=invoke)
    class Agent:
        def __init__(self, **kwargs): self.kwargs = kwargs
        async def run(self, **kwargs):
            modes.append(self.kwargs['use_vision'])
            await llm.ainvoke([])
            return History()
    module = types.ModuleType('browser_use')
    module.Agent, module.Browser, module.BrowserSession = Agent, Browser, Browser
    profile = types.ModuleType('browser_use.browser.profile')
    profile.BrowserProfile = Profile
    monkeypatch.setitem(sys.modules, 'browser_use', module)
    monkeypatch.setitem(sys.modules, 'browser_use.browser.profile', profile)
    with patch('wscan.llm_agent_browser._build_llm', return_value=llm), patch('httpx.AsyncClient.post', side_effect=__import__('httpx').ConnectError('unavailable')):
        result = await AgentBrowserScanner(
            'http://fixture.test', llm_provider='ollama',
            login_url='http://fixture.test/login', auth_user='fixture-user',
            auth_pass='fixture-password', harness_output_dir=tmp_path, max_steps=8,
        ).run()
    assert modes[:3] == [False, True, False]
    assert modes.count(True) == 1
    assert 'vision:text_only' in result.coverage_gaps
    if retry_fails:
        assert len(modes) == 3
        assert 'does not support multimodal' in result.error
    else:
        assert len(modes) > 3
        assert all(mode is False for mode in modes[3:])
        assert result.error is None
