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


def _assert_payload_artifacts(engine, finding, payload):
    import json
    from html import escape
    from wscan.report import ReportGenerator
    engine.all_findings.append(finding)
    engine._init_checkpoint()
    assert engine._save_checkpoint()
    engine._save_evidence()
    report = ReportGenerator(engine.output_dir).generate(
        engine.target_url, [finding], [], [finding.check_type])
    assert escape(payload) in report.read_text()
    for name in ('checkpoint.json', 'evidence.json'):
        data = json.loads((engine.output_dir / name).read_text())
        assert data['findings'][0]['payload'] == finding.payload
        assert payload in str(data['findings'][0]['evidence_details'])


@pytest.mark.asyncio
async def test_observed_forged_jwt_preserved_in_artifacts(tmp_path, monkeypatch):
    from wscan.scanners.jwt_scanner import JWTScanner
    monkeypatch.setenv('WSCAN_STATE_DIR', str(tmp_path / 'state'))
    engine = ScanEngine('http://example.test', output_dir=str(tmp_path / 'out'))
    scanner = JWTScanner(engine)
    capture = NetworkCapture()
    async def probe(url, token, headers, timeout):
        capture._remember_auth_header(SimpleNamespace(
            url=url, headers={'Authorization': f'Bearer {token}'}))
        return True
    monkeypatch.setattr(scanner, '_probe_token', probe)
    finding = await scanner._test_alg_none(
        engine.target_url, 'original-token', {'alg': 'HS256'}, {'sub': 'attacker'},
        'header', 1, {})
    forged = finding.evidence_details['probe_token']
    assert url_scope.redact_secret_values(forged) == forged
    _assert_payload_artifacts(engine, finding, forged)


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
async def test_adopted_credentials_redacted_in_evidence_and_report(tmp_path, monkeypatch):
    from wscan.engine import _store_synced_token
    from wscan.report import ReportGenerator
    from wscan.scanners.base import Finding
    monkeypatch.setenv('WSCAN_STATE_DIR', str(tmp_path / 'state'))
    engine = ScanEngine('http://example.test', output_dir=str(tmp_path / 'out'))
    engine.cookies = 'sid=synthetic-adopted-cookie'
    _store_synced_token(engine, engine.target_url,
                        {'Authorization': 'Bearer synthetic-adopted-token'})
    await engine.header_manager.update({'Authorization': 'Bearer synthetic-refreshed-token'})
    secrets = ('synthetic-adopted-cookie', 'synthetic-adopted-token', 'synthetic-refreshed-token')
    finding = Finding(check_type='sqli', severity='high', url=engine.target_url,
        field_name='q', payload="' OR 1=1 --", evidence=' '.join(secrets))
    engine.all_findings.append(finding)
    engine._init_checkpoint()
    assert engine._save_checkpoint()
    engine._save_evidence()
    report = ReportGenerator(engine.output_dir).generate(
        engine.target_url, [finding], [], ['sqli'])
    artifacts = report.read_text() + ''.join(
        (engine.output_dir / name).read_text() for name in ('evidence.json', 'checkpoint.json'))
    assert all(secret not in artifacts for secret in secrets)
    assert "' OR 1=1 --" in (engine.output_dir / 'evidence.json').read_text()


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


@pytest.mark.parametrize('payload', ['cookie-injection-probe', 'true', 'english', 'dark'])
def test_unadopted_response_cookie_preserved(tmp_path, monkeypatch, payload):
    from wscan.scanners.base import Finding
    monkeypatch.setenv('WSCAN_STATE_DIR', str(tmp_path / 'state'))
    engine = ScanEngine('http://example.test', output_dir=str(tmp_path / 'out'))
    capture = NetworkCapture()
    capture.on_response(SimpleNamespace(url=engine.target_url, request=None,
        status=200, headers={'set-cookie': f'echo={payload}; HttpOnly'}))
    assert url_scope.redact_secret_values(payload) == payload
    finding = Finding(check_type='header_injection', severity='high', url=engine.target_url,
        field_name='q', payload=payload, evidence=f'echoed {payload}',
        evidence_details={'reflected_value': payload})
    _assert_payload_artifacts(engine, finding, payload)


def test_adopted_browser_token_registered():
    from wscan.engine import _store_synced_token
    engine = SimpleNamespace()
    _store_synced_token(engine, 'http://example.test',
                        {'Authorization': 'Bearer synthetic-adopted-token'})
    assert url_scope.redact_secret_values('synthetic-adopted-token') != 'synthetic-adopted-token'


def test_serve_rejects_concurrent_scan():
    from fastapi.testclient import TestClient
    from wscan.monitor import MonitorServer
    server = MonitorServer()
    server.scan_in_progress = True
    response = TestClient(server.app).post('/api/v1/scan', json={'url': 'http://example.test'})
    assert response.status_code == 409
