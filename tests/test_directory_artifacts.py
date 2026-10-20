import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.fixtures.directory_artifacts import app, LISTING, ROOT_LISTING, ROOT_SAFE, SAFE, EXPECTED_FINDINGS, SAFE_ENDPOINTS
from wscan.directory_artifacts import (
    classify_directory_listing, classify_backup, control_matches,
    derive_artifact_candidates, normalize_candidate_url, parse_source_map,
    source_mapping_references,
)
from wscan.scanners.directory_artifacts import DirectoryArtifactsScanner
from wscan.scanners.base import PageDocumentUnavailable

HTTPX_CLIENT = httpx.AsyncClient

@pytest.mark.parametrize('body,family', [
    (LISTING, 'nginx'),
    ('<title>Index of /exposed/</title><table><tr><th>Name Last modified Size</th></tr><tr><td><a href="a.txt">a.txt</a></td></tr></table>', 'apache'),
    ('<pre><a href="../">[To Parent Directory]</a> 01/01/2026 12:00 <a href="a.txt">a.txt</a> <a href="b.txt">b.txt</a></pre>', 'iis'),
    ('<title>Directory listing for /exposed/</title><ul><li><a href="a.txt">a.txt</a></li><li><a href="b.txt">b.txt</a></li></ul>', 'python'),
])
def test_server_families(body, family):
    observation = classify_directory_listing(body, 'http://fixture.test/exposed/')
    assert observation.composite
    assert observation.family == family

@pytest.mark.parametrize('body', [SAFE, 'Index of /', '<title>404 Not found</title>' + LISTING, '<pre>[To Parent Directory]</pre>'])
def test_single_signal_and_error_are_not_confirmed(body):
    assert not classify_directory_listing(body, 'http://fixture.test/safe/').composite

def test_candidates_are_observation_derived():
    candidates = derive_artifact_candidates('http://fixture.test/assets/app.js')
    urls = {c.url for c in candidates}
    assert 'http://fixture.test/assets/app.js.bak' in urls
    assert 'http://fixture.test/assets/.app.js.swp' in urls
    assert 'http://fixture.test/assets/app.tar.gz' in urls
    assert 'http://fixture.test/assets/app.js.map' in urls
    assert 'http://fixture.test/assets/' in urls
    assert not any('config.php' in u for u in urls)

@pytest.mark.parametrize('url', ['file:///tmp/x', 'http://u:p@fixture.test/a', 'http://fixture.test/%252e%252e/a', 'http://fixture.test/a%5cb'])
def test_candidate_trust_boundary(url):
    assert not normalize_candidate_url(url)

def test_controls_and_backup_content():
    assert control_matches('<h1>Index of /exposed/</h1>', 'http://fixture.test/exposed/', '<h1>Index of /missing/</h1>', 'http://fixture.test/missing/')
    assert classify_backup(b'PK\x03\x04zip', 'application/zip', '/app.zip') == ('archive_signature',)
    assert not classify_backup(b'<html>const demo = 42;</html>', 'text/html', '/app.bak')
    assert 'source_code' in classify_backup(b'const secret = 42;', 'text/plain', '/app.bak')

def test_source_maps_external_inline_and_indexed():
    raw = json.dumps({'version': 3, 'sources': ['../private/a.js'], 'sourcesContent': ['const x = 1;']})
    inline = 'data:application/json;base64,' + base64.b64encode(raw.encode()).decode()
    assert parse_source_map(inline).exposed
    assert parse_source_map(json.dumps({'version': 3, 'sections': [{'map': json.loads(raw)}]})).exposed
    assert source_mapping_references('//# sourceMappingURL=a.js.map\n/*# sourceMappingURL=' + inline + ' */') == ('a.js.map', inline)
    assert not parse_source_map('{"version":3,"sources":["public.js"]}').exposed
    assert parse_source_map('data:application/json;base64,!!') is None


def scanner(monkeypatch, handler=None):
    engine = SimpleNamespace(browser=None, monitor=None, payload_gen=None, wave_errors=[], timeout=2, reached_urls=set(), scanners={}, all_findings=[], _is_access_allowed_url=lambda u: u.startswith('http://fixture.test/'), _is_url_excluded=lambda u: '/blocked/' in u)
    scan = DirectoryArtifactsScanner(engine)
    scan.record_finding = AsyncMock(side_effect=lambda **kw: SimpleNamespace(**kw))
    original = HTTPX_CLIENT
    transport = httpx.MockTransport(handler) if handler else httpx.ASGITransport(app=app)
    monkeypatch.setattr('wscan.scanners.directory_artifacts.httpx.AsyncClient', lambda **kw: original(transport=transport, **kw))
    return scan

@pytest.mark.asyncio
async def test_fixture_twins_and_reverification(monkeypatch):
    scan = scanner(monkeypatch)
    findings = await scan.scan_page('http://fixture.test/exposed/')
    for expected in EXPECTED_FINDINGS:
        finding = next(f for f in findings if f.url.endswith(expected['path']) and f.field_name == expected['field'])
        assert finding.confidence == 'tentative'
        assert await scan.verify_finding(finding) is True
        assert 'internal' not in finding.pair['response']['body']
    safe_scan = scanner(monkeypatch)
    safe = await safe_scan.scan_page('http://fixture.test/safe/')
    for finding in safe:
        if any(finding.url.endswith(e['path']) for e in SAFE_ENDPOINTS):
            assert await safe_scan.verify_finding(finding) is False
    for state in ('planned', 'executed'):
        assert f'candidate_{state}:directory_artifacts' in scan.engine.wave_errors

@pytest.mark.asyncio
async def test_root_directory_listing_reverification_matches_nonroot_and_safe_twin(monkeypatch):
    def handle(request):
        path = request.url.path
        host = request.url.host
        if path == '/':
            body = ROOT_SAFE if host == 'safe.fixture.test' else ROOT_LISTING
            return httpx.Response(200, text=body, request=request)
        if path == '/exposed/':
            return httpx.Response(200, text=LISTING, request=request)
        if path == '/safe/':
            return httpx.Response(200, text=SAFE, request=request)
        return httpx.Response(404, text='Not found', request=request)

    async def verdict(url):
        scan = scanner(monkeypatch, handle)
        scan.engine._is_access_allowed_url = lambda value: value.startswith((
            'http://fixture.test/', 'http://safe.fixture.test/'
        ))
        findings = await scan.scan_page(url)
        finding = next(f for f in findings if f.url == url and f.evidence_type == 'directory_listing')
        assert finding.confidence == 'tentative'
        return await scan.verify_finding(finding)

    assert await verdict('http://fixture.test/') is True
    assert await verdict('http://safe.fixture.test/') is False
    assert await verdict('http://fixture.test/exposed/') is True

@pytest.mark.asyncio
async def test_redirect_scope_and_exclusion(monkeypatch):
    requested = []
    def handle(request):
        requested.append(str(request.url))
        return httpx.Response(302, headers={'location': 'https://outside.test/leak'})
    scan = scanner(monkeypatch, handle)
    assert await scan._fetch('http://fixture.test/app.js', 'http://fixture.test') is None
    assert requested == ['http://fixture.test/app.js']
    assert not scan._allowed('http://fixture.test/blocked/app.js', 'http://fixture.test')

@pytest.mark.asyncio
async def test_soft404_and_transport_unknown(monkeypatch):
    scan = scanner(monkeypatch, lambda req: httpx.Response(200, text=LISTING))
    assert await scan.scan_page('http://fixture.test/exposed/') == []
    assert 'control_suppressed:directory_artifacts' in scan.engine.wave_errors
    def fail(req):
        raise httpx.ConnectError('offline', request=req)
    scan = scanner(monkeypatch, fail)
    with pytest.raises(PageDocumentUnavailable):
        await scan.scan_page('http://fixture.test/exposed/')
    assert 'candidate_error:directory_artifacts' in scan.engine.wave_errors

@pytest.mark.asyncio
async def test_single_signal_preserved_then_promoted(monkeypatch):
    scan = scanner(monkeypatch)
    response = httpx.Response(200, text='<title>Index of /exposed/</title>', request=httpx.Request('GET', 'http://fixture.test/exposed/'))
    from wscan.directory_artifacts import ArtifactCandidate
    finding = await scan._record(ArtifactCandidate(str(response.url), 'directory', str(response.url)), response, 'directory_listing', ['heading'], {}, True)
    assert finding.confidence == 'tentative'
    assert await scan.verify_finding(finding) is True

@pytest.mark.asyncio
async def test_source_content_handoff(monkeypatch):
    scan = scanner(monkeypatch)
    sink = SimpleNamespace(_record_body_findings=AsyncMock(return_value=[]))
    scan.engine.scanners['secret_leak'] = sink
    await scan.scan_page('http://fixture.test/exposed/')
    assert any('privateSetting' in c.args[1] for c in sink._record_body_findings.call_args_list)

@pytest.mark.asyncio
async def test_secret_handoff_redacts_persisted_evidence(monkeypatch, tmp_path):
    from wscan.report import ReportGenerator
    from wscan.scanners.secret_leak import SecretLeakScanner, _redact
    scan = scanner(monkeypatch)
    sink = SecretLeakScanner(scan.engine)
    scan.engine.browser = SimpleNamespace(screenshot_b64=AsyncMock(return_value=''))
    scan.engine.monitor = SimpleNamespace(emit_finding=AsyncMock())
    scan.engine._finding_dedup = set()
    sink.browser = scan.engine.browser
    sink.monitor = scan.engine.monitor
    scan.engine.scanners['secret_leak'] = sink
    tokens = ['ghp_' + 'abc123XYZdef456UVWghi789RSTjkl012Mno',
              'ghp_' + 'aBcD1234EFgh5678IJkl9012MNop3456QRst']
    body = ' '.join(tokens * 2)
    findings = await scan._handoff('http://fixture.test/app.js.bak', body)
    assert len(findings) == 1
    assert await sink._record_body_findings('http://fixture.test/app.js.bak', body) == []
    serialized = json.dumps([f.to_dict() for f in scan.engine.all_findings], ensure_ascii=False)
    output = tmp_path / 'findings.jsonl'
    output.write_text(serialized + '\n')
    emitted = json.dumps(scan.engine.monitor.emit_finding.call_args.args[0], ensure_ascii=False)
    report = ReportGenerator(tmp_path).generate(
        'http://fixture.test/', scan.engine.all_findings, [], ['secret_leak'])
    for token in tokens:
        assert token not in output.read_text()
        assert token not in emitted
        assert token not in report.read_text()
    assert _redact(tokens[0]) in serialized
    assert 'snippet' in findings[0].evidence_details

@pytest.mark.asyncio
@pytest.mark.parametrize('delay', [0, 0.25])
async def test_fetch_delay_before_each_redirect_request(monkeypatch, delay):
    events = []
    async def sleep(value):
        events.append(('delay', value))
    def handle(request):
        events.append(('request', request.url.path))
        if request.url.path == '/app.js':
            return httpx.Response(302, headers={'location': '/bundle.js'})
        return httpx.Response(200, text='const x = 1;')
    scan = scanner(monkeypatch, handle)
    scan.engine._effective_delay = delay
    monkeypatch.setattr('wscan.scanners.directory_artifacts.asyncio.sleep', sleep)
    assert await scan._fetch('http://fixture.test/app.js', 'http://fixture.test') is not None
    expected = [('request', '/app.js'), ('request', '/bundle.js')]
    if delay:
        expected = [('delay', delay), expected[0], ('delay', delay), expected[1]]
    assert events == expected

@pytest.mark.asyncio
async def test_control_auth_failure_is_unknown(monkeypatch):
    scan = scanner(monkeypatch, lambda req: httpx.Response(403, text='Denied') if 'wscan-missing-' in req.url.path else httpx.Response(200, text=LISTING))
    with pytest.raises(PageDocumentUnavailable):
        await scan.scan_page('http://fixture.test/exposed/')
    assert 'candidate_error:directory_artifacts' in scan.engine.wave_errors

@pytest.mark.asyncio
async def test_budget_and_outside_candidates_are_observable(monkeypatch):
    scan = scanner(monkeypatch)
    scan.MAX_CANDIDATES_PER_ORIGIN = 1
    scan.engine.reached_urls = {'http://fixture.test/blocked/app.js', 'https://outside.test/app.js'}
    await scan.scan_page('http://fixture.test/exposed/')
    assert 'candidate_skipped:directory_artifacts' in scan.engine.wave_errors
    assert 'target_cap:directory_artifacts' in scan.engine.wave_errors
