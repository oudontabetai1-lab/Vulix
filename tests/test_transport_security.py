"""Transport checks run without Chromium, sockets or optional TLS packages."""
import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock, patch

import httpx
import pytest

from tests.fixtures.transport_security_app import create_app, EXPECTED_FINDINGS, SAFE_ENDPOINTS
from wscan import transport_security as rules
from wscan.engine import ScanEngine
from wscan.report import ReportGenerator
from wscan.scanners import SCANNERS
from wscan.scanners.base import Finding, PageDocumentUnavailable, finding_dedup_key, finding_dedup_key_for
from wscan.scanners.transport_security import TransportSecurityScanner


def engine_for(transport, pairs=()):
    engine = SimpleNamespace(
        browser=SimpleNamespace(network=SimpleNamespace(pairs=pairs)), monitor=None,
        payload_gen=None, wave_errors=[], _finding_dedup=set(), all_findings=[],
        timeout=1, proxy="", _is_access_allowed_url=lambda u: httpx.URL(u).host == "fixture.test",
        _is_url_excluded=lambda u: False,
        httpx_client_kwargs=lambda **kw: {**kw, "transport": transport},
        request_logger=SimpleNamespace(log_payload=Mock()),
    )
    scanner = TransportSecurityScanner(engine)
    engine.scanners = {"transport_security": scanner}
    return engine, scanner


async def scan_fixture(scanner, url, html=None):
    with patch.object(rules, "observe_tls", AsyncMock(return_value=({}, ["test_tls_unavailable"]))):
        if html is not None:
            return await scanner.scan_page_context(SimpleNamespace(url=url, html=html))
        return await scanner.scan_page(url)


@pytest.mark.parametrize("statuses,expected", [
    ((200, 404, 200, 404), True), ((200, 200, 200, 200), False),
    ((404, 404, 200, 405), False), ((200, 404, 405, 405), False),
    ((200, 404, 302, 404), False), ((200, 404, 200, 403), False),
])
def test_methods_require_reached_resource_and_real_control(statuses, expected):
    assert rules.method_difference(*statuses) == expected


def test_webdav_requires_xml_namespace_and_resource():
    assert rules.webdav_capabilities(207, "<html>soft 404</html>") == []
    assert rules.webdav_capabilities(207, "<multistatus><response><href>/</href></response></multistatus>") == []
    assert rules.webdav_capabilities(207, '<d:multistatus xmlns:d="DAV:"><d:response><d:href>/</d:href></d:response></d:multistatus>') == ["PROPFIND"]


def test_override_requires_canonical_and_invalid_control():
    base, canonical = (200, (), "page"), (204, ("GET", "OPTIONS"), "")
    assert rules.override_matches(canonical, canonical, base, base)
    assert not rules.override_matches(base, base, base, base)
    assert not rules.override_matches(canonical, canonical, base, canonical)


def test_mixed_content_excludes_passive_and_handles_base():
    html = '<base href="http://cdn.test/"><script src="a.js"></script><link rel="stylesheet" href="a.css"><iframe src="http://frame.test/"></iframe><img src="http://cdn.test/i.png"><a href="http://link.test/">x</a>'
    assert rules.active_mixed_content("https://fixture.test/", html) == ["http://cdn.test/a.css", "http://cdn.test/a.js", "http://frame.test/"]
    assert rules.active_mixed_content("http://fixture.test/", html) == []


@pytest.mark.parametrize("status,location,expected", [(200, "", "plaintext"), (308, "/login", "insecure_redirect"),
    (301, "https://fixture.test/", "upgraded"), (403, "", "unknown")])
def test_first_hop_https_upgrade(status, location, expected):
    assert rules.https_redirect_status("http://fixture.test/", status, location) == expected


def test_plaintext_observations_return_names_only():
    request = {"url": "http://alice:password@fixture.test/?access_token=private-query",
               "headers": {"Cookie": "sid=private-cookie", "Authorization": "Bearer private-auth"},
               "post_data": '{"password":"private-body"}'}
    names = rules.plaintext_sensitive_fields(request)
    assert names == ["body:password", "header:authorization", "header:cookie", "query:access_token", "url:userinfo"]
    assert "private" not in str(names)
    request["url"] = "https://fixture.test/"
    assert rules.plaintext_sensitive_fields(request) == []


def test_redaction_registration_is_not_credential_classification():
    from wscan.request_logger import register_sensitive_headers, clear_sensitive_headers
    register_sensitive_headers(["X-API-Version"])
    try:
        assert rules.plaintext_sensitive_fields({"url": "http://fixture.test/",
            "headers": {"X-API-Version": "v2", "X-Access-Token": "private-token"}}) == ["header:x-access-token"]
    finally:
        clear_sensitive_headers()


@pytest.mark.parametrize("host,dns,ips,expected", [
    ("a.test", ["*.test"], [], True), ("b.a.test", ["*.test"], [], False),
    ("fixture.test", ["fixture.test"], [], True), ("fixture.test", ["other.test"], [], False),
    ("127.0.0.1", ["127.0.0.1"], [], False), ("127.0.0.1", [], ["127.0.0.1"], True),
])
def test_hostname_san_matching(host, dns, ips, expected):
    assert rules.hostname_matches(host, dns, ips) == expected


def test_tls_facts_classified_without_network():
    now = datetime(2026, 1, 1, tzinfo=timezone.utc)
    facts = {"not_after": "2025-12-31T00:00:00+00:00", "hostname_match": False,
             "trust_chain": False, "signature_hash": "sha1", "key_type": "RSA", "key_bits": 1024,
             "protocol": "TLSv1", "cipher": "RC4-SHA", "cipher_bits": 128}
    assert set(rules.tls_weaknesses(facts, now)) == {"certificate_expired", "certificate_hostname", "certificate_trust",
        "certificate_signature", "certificate_key", "negotiated_protocol", "negotiated_cipher"}
    assert rules.tls_weaknesses({"not_after": "2027-01-01T00:00:00+00:00", "hostname_match": True,
        "trust_chain": True, "signature_hash": "sha256", "key_type": "RSA", "key_bits": 2048,
        "protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256}, now) == []


def test_fixture_twins_and_readonly_requests():
    async def scenario():
        seen = []
        underlying = httpx.ASGITransport(app=create_app())
        class Capture(httpx.AsyncBaseTransport):
            async def handle_async_request(self, request):
                seen.append(request.method)
                return await underlying.handle_async_request(request)
        engine, scanner = engine_for(Capture())
        vulnerable = await scan_fixture(scanner, "http://fixture.test/status")
        safe = await scan_fixture(scanner, "http://fixture.test/status-safe")
        assert {f.evidence_type for f in vulnerable} == {"http_without_https_upgrade"}
        assert safe == []
        assert EXPECTED_FINDINGS[0]["path"] == "/status" and SAFE_ENDPOINTS[0]["path"] == "/status-safe"
        assert not {"PUT", "DELETE", "PATCH", "POST"} & set(seen)
        assert engine.request_logger.log_payload.call_count == len(seen)
        assert any(row["unit"] == "write_methods" and row["status"] == "gap" for row in scanner.coverage)
    asyncio.run(scenario())


def test_fixture_methods_and_override_detected_with_controls():
    async def scenario():
        engine, scanner = engine_for(httpx.ASGITransport(app=create_app()))
        found = await scan_fixture(scanner, "https://fixture.test/methods")
        kinds = [f.evidence_type for f in found]
        assert kinds.count("http_trace_xst") == 1
        assert kinds.count("http_connect_capability") == 1
        assert kinds.count("http_webdav_enabled") == 1
        assert kinds.count("http_method_override") == 3
        assert next(f for f in found if f.evidence_type == "http_webdav_enabled").evidence_details["capabilities"] == ["PROPFIND"]
        assert any(row["unit"] == "tls_peer" and row["status"] == "gap" for row in scanner.coverage)
    asyncio.run(scenario())


def test_generic_200_and_options_advertising_are_not_confirmed():
    async def scenario():
        calls = []
        def respond(request):
            calls.append(request.method)
            return httpx.Response(200, text="uniform page", headers={"Allow": "PUT, CONNECT, PROPFIND, TRACE"})
        _, scanner = engine_for(httpx.MockTransport(respond))
        assert await scan_fixture(scanner, "https://fixture.test/soft404") == []
        assert calls == ["GET", "GET"]
        assert any(row["reason"] == "resource_or_nonexistent_control_unconfirmed" for row in scanner.coverage)
    asyncio.run(scenario())


def test_probe_failure_remains_unknown_and_retriable():
    async def scenario():
        def respond(request):
            if request.method == "TRACE":
                raise httpx.ConnectError("private error detail")
            if "wscan-missing" in request.url.path:
                return httpx.Response(404)
            return httpx.Response(200, text="page")
        engine, scanner = engine_for(httpx.MockTransport(respond))
        with pytest.raises(PageDocumentUnavailable):
            await scan_fixture(scanner, "https://fixture.test/a")
        assert not scanner._checked
        assert "transport_error:transport_security:method_probe" in engine.wave_errors
        assert "private error" not in str(scanner.coverage)
    asyncio.run(scenario())


def test_tls_observer_gaps_and_proxy_no_bypass():
    async def scenario():
        engine, scanner = engine_for(httpx.MockTransport(lambda r: httpx.Response(404)))
        engine.proxy = "http://proxy.test:8080"
        with patch.object(rules, "observe_tls", AsyncMock()) as observer:
            assert await scanner._tls("https://fixture.test/") == []
            observer.assert_not_called()
        assert scanner.coverage[0]["status"] == "gap"
        engine.proxy = ""
        facts = {"protocol": "TLSv1.3", "cipher": "TLS_AES_256_GCM_SHA384", "cipher_bits": 256,
                 "trust_chain": False, "hostname_match": False}
        with patch.object(rules, "observe_tls", AsyncMock(return_value=(facts, ["leaf_only"]))) as observer:
            found = await scanner._tls("https://fixture.test/")
        assert {f.evidence_type for f in found} == {"certificate_hostname", "certificate_trust"}
        assert any(row["unit"] == "tls_enumeration" and row["status"] == "gap" for row in scanner.coverage)
    asyncio.run(scenario())


def test_scoped_control_does_not_block_passive_document_checks():
    async def scenario():
        engine, scanner = engine_for(httpx.MockTransport(lambda r: httpx.Response(200, text="page")))
        engine._is_access_allowed_url = lambda url: httpx.URL(url).path == "/status"
        found = await scan_fixture(scanner, "http://fixture.test/status")
        assert [f.evidence_type for f in found] == ["http_without_https_upgrade"]
        assert any(row["reason"] == "nonexistent_control_outside_scope" for row in scanner.coverage)
    asyncio.run(scenario())


def test_sensitive_evidence_and_logging_are_redacted():
    async def scenario():
        pairs = [{"request": {"url": "http://fixture.test/a?access_token=private-query", "headers": {"Cookie": "private-cookie"}}}]
        engine, scanner = engine_for(httpx.MockTransport(lambda r: httpx.Response(404)), pairs)
        found = await scan_fixture(scanner, "http://fixture.test/a?access_token=private-query")
        assert len(found) == 1 and found[0].evidence_type == "plaintext_credentials"
        serialized = str([f.to_dict() for f in found]) + str(scanner.coverage) + str(engine.request_logger.log_payload.call_args_list)
        assert "private-query" not in serialized and "private-cookie" not in serialized
    asyncio.run(scenario())


def test_write_fixture_cleanup_is_isolated():
    async def scenario():
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=create_app()), base_url="http://fixture.test") as client:
            path = "/disposable/test-marker"
            assert (await client.put(path, content="probe")).status_code == 201
            try:
                assert (await client.patch(path, content="changed")).status_code == 204
                assert (await client.get(path)).text == "changed"
            finally:
                assert (await client.delete(path)).status_code == 204
            assert (await client.get(path)).status_code == 404
    asyncio.run(scenario())


def test_transport_dedup_preserves_existing_scanner_keys():
    for kind, field in (("http_trace_xst", "(TRACE method)"), ("http_webdav_enabled", "(WebDAV)")):
        old = finding_dedup_key("http_methods", "https://fixture.test", field, kind)
        assert old == ("https://fixture.test", field, "http_methods", kind)
        assert finding_dedup_key("transport_security", "https://fixture.test/", field, kind) == old
        finding = Finding("transport_security", "low", "https://fixture.test/", field, "probe", "evidence", evidence_type=kind)
        assert finding_dedup_key_for(finding) == old


def test_inert_scripts_are_not_active_mixed_content():
    assert rules.active_mixed_content("https://fixture.test/",
        '<template><script src="http://cdn.test/a.js"></script></template>'
        '<noscript><iframe src="http://cdn.test/"></iframe></noscript>'
        '<script type="application/json" src="http://cdn.test/a.json"></script>') == []


@pytest.mark.parametrize("wrapper", ["textarea", "title", "TITLE", "xmp", "noembed", "noframes", "style"])
def test_raw_text_contents_are_not_active_mixed_content(wrapper):
    html = f'<{wrapper}><script src="http://cdn.test/x.js"></script><iframe src="http://cdn.test/"></iframe></{wrapper}>'
    assert rules.active_mixed_content("https://fixture.test/", html) == []
    assert rules.active_mixed_content("https://fixture.test/", "<!-- <script src=http://cdn.test/x.js></script> -->") == []


@pytest.mark.parametrize("html", [
    "<textarea/><script src=http://cdn.test/x.js></script>",
    "<plaintext><script src=http://cdn.test/x.js></script>"])
def test_self_closed_rcdata_and_plaintext_are_inert(html):
    assert rules.active_mixed_content("https://fixture.test/", html) == []


@pytest.mark.parametrize("html", [
    "<textarea/>x</textarea foo><script src=http://cdn.test/x.js></script>",
    "<title>t</title foo><script src=http://cdn.test/x.js></script>",
    "<svg><plaintext/></svg><script src=http://cdn.test/x.js></script>",
    "<svg><title><script src=http://cdn.test/x.js></script></title></svg>",
    "<math><textarea><script src=http://cdn.test/x.js></script>",
    "<!--><script src=http://cdn.test/x.js></script>",
    "<!---><script src=http://cdn.test/x.js></script>",
    "<!-- a --!><script src=http://cdn.test/x.js></script>",
    "<![CDATA[ a > <script src=http://cdn.test/x.js></script> ]]>",
    "<noscript><template></noscript><script src=http://cdn.test/x.js></script>",
    "<select><xmp></select><script src=http://cdn.test/x.js></script>",
    "<script src=http://cdn.test/x.js src=https://cdn.test/x.js></script>",
    "<script data-x='>' src=http://cdn.test/x.js></script>"])
def test_ambiguous_or_closed_inert_regions_still_detect_active_content(html):
    # FN-safe: ブラウザが実行しうる構文は抑制しない
    assert rules.active_mixed_content("https://fixture.test/", html) == ["http://cdn.test/x.js"]


def test_plain_body_script_is_active_mixed_content():
    assert rules.active_mixed_content("https://fixture.test/",
        "<script src=http://cdn.test/x.js></script>") == ["http://cdn.test/x.js"]


def test_raw_text_does_not_hide_real_resources():
    html = ('<title>t</title><textarea><script src="http://cdn.test/inert.js"></script></textarea>'
            '<script src="http://cdn.test/real.js"></script>'
            '<iframe src="http://frame.test/"><script src="http://cdn.test/fallback.js"></script></iframe>'
            '<script src="http://cdn.test/after.js"></script>')
    assert rules.active_mixed_content("https://fixture.test/", html) == [
        "http://cdn.test/after.js", "http://cdn.test/real.js", "http://frame.test/"]


def test_document_kind_uses_real_content_type():
    assert rules.document_kind("text/html; charset=utf-8") == "html"
    assert rules.document_kind("Application/XHTML+XML") == "html"
    assert rules.document_kind("application/json") == "non_html"
    assert rules.document_kind("text/plain") == "non_html"
    assert rules.document_kind("") == "unknown"


def test_non_html_https_body_is_not_active_mixed_content():
    async def scenario():
        body = '{"example":"<script src=http://cdn.test/example.js></script>"}'
        for content_type in ("application/json", "text/plain; charset=utf-8"):
            _, scanner = engine_for(httpx.MockTransport(
                lambda r: httpx.Response(200, text=body, headers={"content-type": content_type})))
            found = await scan_fixture(scanner, "https://fixture.test/api")
            assert "active_mixed_content" not in {f.evidence_type for f in found}
            row = next(r for r in scanner.coverage if r["unit"] == "active_mixed_content")
            assert row["status"] == "not_applicable" and row["reason"] == "non_html_document"
        _, scanner = engine_for(httpx.MockTransport(lambda r: httpx.Response(200, content=body.encode())))
        assert "active_mixed_content" not in {f.evidence_type for f in await scan_fixture(scanner, "https://fixture.test/api")}
        row = next(r for r in scanner.coverage if r["unit"] == "active_mixed_content")
        assert row["status"] == "gap" and row["reason"] == "missing_content_type"
    asyncio.run(scenario())


def test_fixture_mixed_content_twins():
    async def scenario():
        _, scanner = engine_for(httpx.ASGITransport(app=create_app()))
        vulnerable = await scan_fixture(scanner, "https://fixture.test/mixed")
        safe = await scan_fixture(scanner, "https://fixture.test/api/example-safe")
        safe += await scan_fixture(scanner, "https://fixture.test/mixed-text-safe")
        for extra in ("mixed-selfclosed-textarea-safe", "mixed-plaintext-safe"):
            safe += await scan_fixture(scanner, "https://fixture.test/" + extra)
        mixed = [f for f in vulnerable if f.evidence_type == "active_mixed_content"]
        assert len(mixed) == 1 and mixed[0].evidence_details["resources"] == ["http://cdn.test/example.js"]
        assert "active_mixed_content" not in {f.evidence_type for f in safe}
        assert {e["path"] for e in EXPECTED_FINDINGS} >= {"/mixed"}
        assert {e["path"] for e in SAFE_ENDPOINTS} >= {"/api/example-safe", "/mixed-text-safe",
                                                           "/mixed-selfclosed-textarea-safe", "/mixed-plaintext-safe"}
        units = {(r["url"], r["status"]) for r in scanner.coverage if r["unit"] == "active_mixed_content"}
        assert units == {("https://fixture.test/mixed", "observed"), ("https://fixture.test/mixed-text-safe", "observed"),
                         ("https://fixture.test/mixed-selfclosed-textarea-safe", "observed"),
                         ("https://fixture.test/mixed-plaintext-safe", "observed"),
                         ("https://fixture.test/api/example-safe", "not_applicable")}
    asyncio.run(scenario())


def test_tls_handshakes_validate_chain_and_collect_without_sockets():
    import ssl
    async def scenario():
        contexts = []
        writers = []
        async def connect(*args, **kwargs):
            context = kwargs["ssl"]
            contexts.append(context)
            if len(contexts) == 1:
                error = ssl.SSLCertVerificationError("expired")
                error.verify_code = 10
                raise error
            peer = SimpleNamespace(version=lambda: "TLSv1.3", cipher=lambda: ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                                   getpeercert=lambda **kw: b"leaf-der")
            writer = SimpleNamespace(get_extra_info=lambda key: peer, close=Mock(), wait_closed=AsyncMock())
            writers.append(writer)
            return object(), writer
        with patch.object(asyncio, "open_connection", side_effect=connect), patch.object(rules, "certificate_facts", return_value={"hostname_match": False}) as parser:
            facts, gaps = await rules.observe_tls("fixture.test", 443, 1)
        assert contexts[0].verify_mode == ssl.CERT_REQUIRED and contexts[0].check_hostname is False
        assert contexts[1].verify_mode == ssl.CERT_NONE
        assert facts["trust_chain"] is False and facts["verify_code"] == 10
        assert facts["cipher_bits"] == 256 and facts["hostname_match"] is False
        assert gaps == ["intermediate_certificate_strength_not_inspected"]
        parser.assert_called_once_with(b"leaf-der", "fixture.test")
        writers[0].close.assert_called_once()
    asyncio.run(scenario())


def test_tls_connection_failure_and_missing_parser_are_gaps():
    async def scenario():
        with patch.object(asyncio, "open_connection", AsyncMock(side_effect=OSError("private detail"))):
            assert await rules.observe_tls("fixture.test", 443, 1) == ({}, ["tls_handshake_unavailable"])
        peer = SimpleNamespace(version=lambda: "TLSv1.3", cipher=lambda: ("TLS_AES_256_GCM_SHA384", "TLSv1.3", 256),
                               getpeercert=lambda **kw: b"leaf-der")
        writer = SimpleNamespace(get_extra_info=lambda key: peer, close=Mock(), wait_closed=AsyncMock())
        with patch.object(asyncio, "open_connection", AsyncMock(return_value=(None, writer))), patch.object(rules, "certificate_facts", side_effect=ImportError()):
            facts, gaps = await rules.observe_tls("fixture.test", 443, 1)
        assert facts["trust_chain"] is True
        assert "certificate_parser_unavailable" in gaps
    asyncio.run(scenario())


def test_leaf_certificate_decoding_has_expiry_hostname_and_key_facts():
    x509 = pytest.importorskip("cryptography.x509")
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import rsa
    from cryptography.x509.oid import NameOID
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.test")])
    cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(1).not_valid_before(datetime(2024, 1, 1, tzinfo=timezone.utc))
            .not_valid_after(datetime(2025, 1, 1, tzinfo=timezone.utc))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.test")]), critical=False)
            .sign(key, hashes.SHA256()))
    der = cert.public_bytes(serialization.Encoding.DER)
    facts = rules.certificate_facts(der, "fixture.test")
    assert facts["hostname_match"] is True and facts["key_bits"] == 2048
    assert facts["signature_hash"] == "sha256" and len(facts["fingerprint_sha256"]) == 64
    assert rules.tls_weaknesses(facts, datetime(2026, 1, 1, tzinfo=timezone.utc)) == ["certificate_expired"]
    assert rules.certificate_facts(der, "other.test")["hostname_match"] is False


def test_coverage_export_and_html_show_unknown(tmp_path):
    engine, scanner = engine_for(httpx.MockTransport(lambda r: httpx.Response(404)))
    scanner._coverage("https://fixture.test/?access_token=secret", "tls", "gap", "parser_unavailable", {"cipher": "<unsafe>"})
    engine.scan_matrix = []
    engine.reached_urls = set()
    engine.checks = ["transport_security"]
    summary = ScanEngine.coverage_summary(engine)
    assert summary["transport_security"] == scanner.coverage
    html = ReportGenerator(tmp_path)._build_coverage_html(summary)
    assert "parser_unavailable" in html and "Gaps are untested, not safe" in html
    assert "<unsafe>" not in html and "&lt;unsafe&gt;" in html
    assert "access_token=secret" not in html
    from wscan.sarif import SarifExporter
    properties = SarifExporter().export([], coverage=summary)["runs"][0]["properties"]
    assert properties["coverage"]["transport_security"] == scanner.coverage


def test_check_registered_and_cli_defaults_preserved():
    import main
    assert SCANNERS["transport_security"] is TransportSecurityScanner
    with patch("sys.argv", ["vulix", "scan", "https://fixture.test", "--checks", "transport_security"]):
        assert main.parse_args().checks == ["transport_security"]
    with patch("sys.argv", ["vulix", "scan", "https://fixture.test"]):
        assert main.parse_args().checks == ["sqli", "xss", "os"]
