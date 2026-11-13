from types import SimpleNamespace

import pytest
from wscan import url_scope
from wscan.browser import NetworkCapture
from wscan.header_manager import HeaderManager
from wscan.engine import ScanEngine
from wscan.agent_engine import AgentEngine


@pytest.fixture(autouse=True)
def clean_registry():
    url_scope.clear_secret_values()
    yield
    url_scope.clear_secret_values()


def test_captured_bearer_registered():
    capture = NetworkCapture()
    capture._remember_auth_header(SimpleNamespace(url='http://example.test/api', headers={'Authorization': 'Bearer synthetic-rotated-token'}))
    assert url_scope.redact_secret_values('synthetic-rotated-token') != 'synthetic-rotated-token'


@pytest.mark.asyncio
async def test_rotated_header_registered():
    manager = HeaderManager()
    await manager.update({'Authorization': 'Bearer synthetic-new-token'})
    assert url_scope.redact_secret_values('synthetic-new-token') != 'synthetic-new-token'


def test_rotated_cookie_registered(tmp_path, monkeypatch):
    monkeypatch.setenv('WSCAN_STATE_DIR', str(tmp_path / 'state'))
    engine = ScanEngine('http://example.test', output_dir=str(tmp_path / 'out'))
    engine.cookies = 'sid=synthetic-new-cookie'
    assert url_scope.redact_secret_values('synthetic-new-cookie') != 'synthetic-new-cookie'


@pytest.mark.asyncio
async def test_agent_live_scope_and_error_cleanup(tmp_path, monkeypatch):
    from wscan.llm_agent_browser import AgentBrowserScanner
    async def fail(scanner):
        assert url_scope.redact_secret_values('synthetic-agent-password') != 'synthetic-agent-password'
        from wscan.monitor import MonitorServer
        monitor = MonitorServer()
        await monitor.emit('status', {'message': 'synthetic-agent-password'})
        assert 'synthetic-agent-password' not in str(list(monitor.event_history))
        raise RuntimeError('expected')
    monkeypatch.setattr(AgentBrowserScanner, 'run', fail)
    engine = AgentEngine('http://example.test', output_dir=str(tmp_path), auth_pass='synthetic-agent-password')
    with pytest.raises(RuntimeError, match='expected'):
        await engine.run()
    assert url_scope.redact_secret_values('synthetic-agent-password') == 'synthetic-agent-password'


@pytest.mark.asyncio
async def test_sequential_scan_isolation_and_identifier_preservation(tmp_path, monkeypatch):
    monkeypatch.setenv('WSCAN_STATE_DIR', str(tmp_path / 'state'))
    for secret in ('synthetic-first-secret', 'synthetic-second-secret'):
        engine = ScanEngine('http://example.test', output_dir=str(tmp_path / secret), auth_pass=secret)
        async def fail():
            assert url_scope.redact_secret_values(secret) != secret
            finding = url_scope.redact_finding_dict({'field_name': secret, 'evidence': secret})
            assert finding['field_name'] == secret
            assert finding['evidence'] != secret
            raise RuntimeError('expected')
        monkeypatch.setattr(engine, '_run', fail)
        with pytest.raises(RuntimeError, match='expected'):
            await engine.run()
        assert url_scope.redact_secret_values(secret) == secret


def test_response_cookie_registered_before_logging():
    capture = NetworkCapture()
    capture.on_response(SimpleNamespace(url='http://example.test/api', request=None,
        status=200, headers={'set-cookie': 'sid=synthetic-response-cookie; HttpOnly'}))
    assert url_scope.redact_secret_values('synthetic-response-cookie') != 'synthetic-response-cookie'


def test_serve_rejects_concurrent_scan():
    from fastapi.testclient import TestClient
    from wscan.monitor import MonitorServer
    server = MonitorServer()
    server.scan_in_progress = True
    response = TestClient(server.app).post('/api/v1/scan', json={'url': 'http://example.test'})
    assert response.status_code == 409
