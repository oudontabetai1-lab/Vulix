import base64
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from tests.fixtures.directory_artifacts import app, LISTING, ROOT_LISTING, ROOT_SAFE, SAFE, EXPECTED_FINDINGS, SAFE_ENDPOINTS
from wscan.directory_artifacts import (
    ArtifactCandidate, bind_verification_target, classify_directory_listing,
    classify_backup, control_matches, derive_artifact_candidates,
    has_archive_signature, has_script_evidence, is_archive_artifact_name,
    is_backup_artifact_name, is_truncated_script_snapshot,
    lookup_verification_target, normalize_candidate_url, parse_source_map,
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


def test_pure_detection_functions_and_safe_twins():
    # Edge 1: 50KB 打ち切り判定純粋関数
    assert is_truncated_script_snapshot("a" * 50_000)
    assert is_truncated_script_snapshot("a" * 60_000)
    assert not is_truncated_script_snapshot("a" * 49_999)
    assert not is_truncated_script_snapshot("")
    assert not is_truncated_script_snapshot(None)

    # Edge 2: 拡張子なしスクリプト候補抽出純粋関数
    bundle_candidates = derive_artifact_candidates("http://fixture.test/bundle", is_script=True)
    kinds = {c.kind for c in bundle_candidates}
    assert "resource" in kinds
    assert "directory" in kinds
    res_cand = next(c for c in bundle_candidates if c.kind == "resource")
    assert res_cand.url == "http://fixture.test/bundle"
    # 安全ツイン: スクリプト証拠のない通常のディレクトリ風パス（ナビゲーション等）は resource 候補にならない
    dir_candidates = derive_artifact_candidates("http://fixture.test/admin")
    assert not any(c.kind == "resource" for c in dir_candidates)
    assert any(c.kind == "directory" for c in dir_candidates)
    # JS Content-Type または JS 本文の証拠がある場合もスクリプト資源とみなされる
    assert has_script_evidence("http://fixture.test/bundle", content_type="application/javascript")
    assert has_script_evidence("http://fixture.test/bundle", body="const x = 1;\n//# sourceMappingURL=bundle.map")
    assert not has_script_evidence("http://fixture.test/admin", body="<html><body>Admin</body></html>")

    # Edge 3: 検証ターゲット紐付け純粋関数
    targets = {}
    f1 = SimpleNamespace(url="http://fixture.test/app.js.map?token=[REDACTED]", evidence_type="source_map")
    bind_verification_target(targets, f1, "http://fixture.test/app.js.map?token=secret1", f1.url, f1.evidence_type)
    assert lookup_verification_target(targets, f1) == "http://fixture.test/app.js.map?token=secret1"
    # 重複判定で None の場合は上書きされない
    assert not bind_verification_target(targets, None, "http://fixture.test/app.js.map?token=secret2", f1.url, f1.evidence_type)
    assert lookup_verification_target(targets, f1) == "http://fixture.test/app.js.map?token=secret1"

    # Edge 4: バックアップ拡張子判定純粋関数
    assert is_backup_artifact_name("site-backup.zip")
    assert is_backup_artifact_name("site-backup.tar.gz")
    assert is_backup_artifact_name("site-backup.tgz")
    assert is_backup_artifact_name("app.js.bak")
    assert is_backup_artifact_name("app.js.old")
    assert is_backup_artifact_name("app.js.orig")
    assert is_backup_artifact_name("app.js.swp")
    assert is_backup_artifact_name(".app.js.swp")
    assert is_backup_artifact_name("app.js~")
    # 安全ツイン: 通常拡張子・拡張子なし・.map はバックアップではない
    assert not is_backup_artifact_name("app.js")
    assert not is_backup_artifact_name("bundle")
    assert not is_backup_artifact_name("app.js.map")
    assert not is_backup_artifact_name("")

    # Edge 5: アーカイブシグネチャ判定純粋関数
    assert has_archive_signature(b"PK\x03\x04rest_of_zip")
    assert has_archive_signature(b"\x1f\x8brest_of_gzip")
    assert has_archive_signature(b"\x00" * 257 + b"ustar" + b"\x00" * 5)
    # 安全ツイン: 画像や通常ファイル・HTML
    assert not has_archive_signature(b"GIF89a")
    assert not has_archive_signature(b"<html><head><title>404</title></head></html>")
    assert not has_archive_signature(b"\x00" * 300)
    assert not has_archive_signature(None)

    # Edge 5: バックアップ分類純粋関数（実シグネチャ判定と .zip 偽陽性抑止）
    # 陽性: 実シグネチャが存在する .zip -> archive_signature
    assert classify_backup(b"PK\x03\x04" + b"\x00" * 300, "application/octet-stream", "http://fixture.test/oversized-backup.zip") == ("archive_signature",)
    assert classify_backup(b"\x1f\x8b" + b"\x00" * 300, "application/octet-stream", "http://fixture.test/oversized-backup.tar.gz") == ("archive_signature",)
    # 安全ツイン: 拡張子はアーカイブだがシグネチャを持たない大きな無害レスポンス（JSON/バイナリ等） -> 検出されない（served_file 偽陽性抑止）
    assert classify_backup(b'{"status": "ok", "items": []}' + b" " * 300, "application/octet-stream", "http://fixture.test/oversized-backup.zip") == ()
    assert classify_backup(b"\x00" * 300, "application/octet-stream", "http://fixture.test/oversized-backup.zip") == ()
    assert classify_backup(b"\x89PNG\r\n\x1a\n" + b"\x00" * 300, "application/octet-stream", "http://fixture.test/oversized-backup.zip") == ()


@pytest.mark.asyncio
async def test_edge1_refetch_truncated_script_and_safe_twin(monkeypatch):
    scan = scanner(monkeypatch)
    # 50KB に打ち切られたスナップショット（末尾の sourceMappingURL が切れている）
    truncated_body = "const a = 1;\n" * 4500
    truncated_snapshot = truncated_body[:50000]
    assert len(truncated_snapshot) == 50000
    assert "sourceMappingURL" not in truncated_snapshot

    page = SimpleNamespace(
        url="http://fixture.test/exposed/",
        external_scripts={"http://fixture.test/exposed/truncated-bundle.js": truncated_snapshot},
    )
    findings = await scan.scan_page_context(page)
    finding = next((f for f in findings if "truncated-bundle.js.map" in f.url and f.evidence_type == "source_map"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True

    # 安全ツイン: 50KB 打ち切りだが sourceMappingURL を持たないスクリプトは検出されない
    safe_scan = scanner(monkeypatch)
    safe_page = SimpleNamespace(
        url="http://fixture.test/safe/",
        external_scripts={"http://fixture.test/safe/truncated-safe.js": truncated_snapshot},
    )
    safe_findings = await safe_scan.scan_page_context(safe_page)
    assert not any("truncated-safe" in f.url for f in safe_findings)


@pytest.mark.asyncio
async def test_edge2_extensionless_script_and_safe_twin(monkeypatch):
    scan = scanner(monkeypatch)
    page = SimpleNamespace(
        url="http://fixture.test/exposed/",
        external_scripts={"http://fixture.test/exposed/bundle": "const a = 1;\n//# sourceMappingURL=bundle.map"},
    )
    findings = await scan.scan_page_context(page)
    finding = next((f for f in findings if "bundle.map" in f.url and f.evidence_type == "source_map"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True

    # 安全ツイン: sourceMappingURL を持たない拡張子なしスクリプトは検出されない
    safe_scan = scanner(monkeypatch)
    safe_page = SimpleNamespace(
        url="http://fixture.test/safe/",
        external_scripts={"http://fixture.test/safe/bundle": "const a = 1;\n"},
    )
    safe_findings = await safe_scan.scan_page_context(safe_page)
    assert not any("bundle.map" in f.url for f in safe_findings)

    # 安全ツイン: スクリプトではなく通常のディレクトリ/ナビゲーションとして観測されたパスは resource 候補にならない
    nav_scan = scanner(monkeypatch, lambda req: httpx.Response(200, text='<html><body><a href="/safe/catalog">Catalog</a><script src="/exposed/bundle"></script></body></html>'))
    nav_scan.engine.reached_urls = {"http://fixture.test/safe/catalog"}
    nav_findings = await nav_scan.scan_page("http://fixture.test/safe/nav")
    # /safe/catalog は directory 候補として扱われ、resource 候補としては計画・実行されない
    assert not any(c == ("http://fixture.test/safe/catalog", "resource") for c in nav_scan._checked)
    assert not any(c == ("http://fixture.test/safe/catalog", "resource") for c in nav_scan._planned)
    # 一方で <script src="/exposed/bundle"> はスクリプト証拠があるため resource 候補として計画される
    assert ("http://fixture.test/exposed/bundle", "resource") in nav_scan._planned


@pytest.mark.asyncio
async def test_edge3_bind_verification_targets_to_emitted_findings_and_safe_twin(monkeypatch):
    scan = scanner(monkeypatch)
    # 同一アーティファクトで異なる機微クエリパラメータ
    url_valid = "http://fixture.test/exposed/query-map.js.map?token=valid_token"
    url_invalid = "http://fixture.test/exposed/query-map.js.map?token=invalid_token"
    resp_valid = httpx.Response(200, text=json.dumps({"version": 3, "sources": ["webpack:///src/secret.js"], "sourcesContent": ['const s = 1;']}), request=httpx.Request("GET", url_valid))
    resp_invalid = httpx.Response(403, text="Forbidden", request=httpx.Request("GET", url_invalid))

    cand_valid = ArtifactCandidate(url_valid, "source_map", url_valid)
    cand_invalid = ArtifactCandidate(url_invalid, "source_map", url_invalid)

    f1 = await scan._record(cand_valid, resp_valid, "source_map", ["valid_map", "source_content"], {}, True)
    assert f1 is not None

    # 重複判定を模倣: record_finding が None を返す（dedup）
    scan.record_finding = AsyncMock(return_value=None)
    f2 = await scan._record(cand_invalid, resp_invalid, "source_map", ["valid_map"], {}, True)
    assert f2 is None

    # f1 の検証対象生 URL は valid_token のまま保持され、再検証が成功する
    assert await scan.verify_finding(f1) is True

    # 安全ツイン: 秘密情報を含まない公開マップは再検証で False
    safe_scan = scanner(monkeypatch)
    cand_safe = ArtifactCandidate("http://fixture.test/safe/query-map.js.map?token=valid_token", "source_map", "http://fixture.test/safe/query-map.js.map?token=valid_token")
    resp_safe = httpx.Response(200, text=json.dumps({"version": 3, "sources": ["public.js"], "mappings": ""}), request=httpx.Request("GET", cand_safe.url))
    f_safe = await safe_scan._record(cand_safe, resp_safe, "source_map", ["valid_map"], {}, True)
    assert await safe_scan.verify_finding(f_safe) is False


@pytest.mark.asyncio
async def test_edge4_explicitly_observed_backup_artifacts_and_safe_twin(monkeypatch):
    scan = scanner(monkeypatch)
    # 直接観測されたバックアップ URL
    scan.engine.reached_urls = {"http://fixture.test/exposed/site-backup.zip"}
    findings = await scan.scan_page("http://fixture.test/exposed/")
    finding = next((f for f in findings if f.url.endswith("site-backup.zip") and f.evidence_type == "derived_backup"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True

    # 安全ツイン: 404 を返すバックアップ URL は検出されない
    safe_scan = scanner(monkeypatch)
    safe_scan.engine.reached_urls = {"http://fixture.test/safe/site-backup.zip"}
    safe_findings = await safe_scan.scan_page("http://fixture.test/safe/")
    assert not any("site-backup.zip" in f.url for f in safe_findings)


@pytest.mark.asyncio
async def test_edge5_oversized_artifact_capped_prefix_and_safe_twin(monkeypatch):
    scan = scanner(monkeypatch)
    # 1MB を超える ZIP バックアップ（陽性: 実シグネチャ -> 検出される）
    scan.engine.reached_urls = {"http://fixture.test/exposed/oversized-backup.zip"}
    findings = await scan.scan_page("http://fixture.test/exposed/")
    finding = next((f for f in findings if f.url.endswith("oversized-backup.zip") and f.evidence_type == "derived_backup"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True

    # 安全ツイン: 1MB を超える無害な非アーカイブレスポンス（.zip かつ application/octet-stream だがアーカイブシグネチャなし）は検出されない
    safe_scan = scanner(monkeypatch)
    safe_scan.engine.reached_urls = {"http://fixture.test/safe/oversized-backup.zip"}
    safe_findings = await safe_scan.scan_page("http://fixture.test/safe/")
    assert not any("oversized-backup.zip" in f.url for f in safe_findings)


@pytest.mark.asyncio
async def test_edge1_truncated_script_inline_map(monkeypatch):
    scan = scanner(monkeypatch)
    # 50KB 打ち切りスナップショット（末尾のインライン data: map が切れている）
    truncated_body = "const a = 1;\n" * 4500
    truncated_snapshot = truncated_body[:50000]

    page = SimpleNamespace(
        url="http://fixture.test/exposed/",
        external_scripts={"http://fixture.test/exposed/truncated-inline.js": truncated_snapshot},
    )
    findings = await scan.scan_page_context(page)
    finding = next((f for f in findings if f.evidence_type == "inline_source_map"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("backup_path", [
    "/exposed/site-backup.tar.gz",
    "/exposed/app.js.old",
    "/exposed/app.js~",
])
async def test_edge4_various_directly_observed_backup_extensions(monkeypatch, backup_path):
    scan = scanner(monkeypatch)
    url = f"http://fixture.test{backup_path}"
    scan.engine.reached_urls = {url}
    findings = await scan.scan_page("http://fixture.test/exposed/")
    finding = next((f for f in findings if f.url == url and f.evidence_type == "derived_backup"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True


@pytest.mark.asyncio
@pytest.mark.parametrize("oversized_path", [
    "/exposed/oversized-backup.tar.gz",
    "/exposed/oversized-backup.tar",
])
async def test_edge5_oversized_tar_and_gzip_backups(monkeypatch, oversized_path):
    scan = scanner(monkeypatch)
    url = f"http://fixture.test{oversized_path}"
    scan.engine.reached_urls = {url}
    findings = await scan.scan_page("http://fixture.test/exposed/")
    finding = next((f for f in findings if f.url == url and f.evidence_type == "derived_backup"), None)
    assert finding is not None
    assert await scan.verify_finding(finding) is True
