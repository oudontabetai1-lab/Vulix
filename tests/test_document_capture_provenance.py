"""共有 document fallback が別 query/POST/XHR の証拠を GET にしない回帰。"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wscan.browser import NetworkCapture
from wscan.scanners import SCANNERS
from wscan.scanners.base import PageDocumentUnavailable


CHECKS = ("info_disclosure", "sri", "secret_leak", "clickjacking",
          "security_headers", "outdated_components")
URL = "http://fixture.test/error?mode=safe"
BODY = ('<html>Traceback (most recent call last) '
        'AKIA5JZQNVRT7H3KX9PQ <script src="https://cdn.jsdelivr.net/npm/jquery@1.0.0/a.js">'
        '</script></html>')


async def capture(network, url=URL, method="GET", resource_type="document", status=200, body=BODY,
                  location=None, redirected_from=None):
    request = SimpleNamespace(url=url, method=method, resource_type=resource_type,
                              headers={}, post_data=None, redirected_from=redirected_from)
    headers = {"content-type": "text/html"}
    if location:
        headers["location"] = location
    response = SimpleNamespace(url=url, request=request, status=status,
                               headers=headers, text=AsyncMock(return_value=body))
    network.on_request(request)
    network.on_response(response)
    await network.enrich_response(response)
    return network.pairs[-1]


def scanner_for(check, network):
    engine = SimpleNamespace(browser=SimpleNamespace(network=network), monitor=None,
                             payload_gen=None, wave_errors=[], component_intel={"enabled": True})
    scanner = SCANNERS[check](engine)
    scanner._get = AsyncMock(side_effect=RuntimeError("direct GET unavailable"))
    scanner.record_finding = AsyncMock(return_value=object())
    if check == "info_disclosure":
        scanner._check_sensitive_files = AsyncMock(return_value=[])
        scanner._check_directory_listing = AsyncMock(return_value=[])
        scanner._check_tech_headers = AsyncMock(return_value=[])
    if check == "outdated_components":
        scanner._scan_eol = AsyncMock(return_value=[])
        scanner._scan_osv = AsyncMock(return_value=[])
    return scanner, engine


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("invalid", ["query", "safe_query", "post", "xhr", "unknown_type",
                                     "unknown_id", "unknown_sequence", "unknown_method", "mismatched_id",
                                     "redirect", "response_url", "empty"])
async def test_unproven_capture_is_unavailable_for_every_consumer(check, invalid):
    network = NetworkCapture()
    if invalid != "empty":
        pair = await capture(network,
            url=URL.replace("safe", "other") if invalid in ("query", "safe_query") else URL,
            method="POST" if invalid == "post" else "GET",
            resource_type="xhr" if invalid == "xhr" else "document",
            status=302 if invalid == "redirect" else 200,
            body="<html>safe</html>" if invalid == "safe_query" else BODY)
        if invalid == "unknown_type":
            pair["request"].pop("resource_type")
        if invalid == "unknown_id":
            pair["response"].pop("_req_id")
        if invalid == "unknown_sequence":
            pair["request"].pop("_capture_sequence")
        if invalid == "unknown_method":
            pair["request"].pop("method")
        if invalid == "mismatched_id":
            pair["response"]["_req_id"] += 1
        if invalid == "response_url":
            pair["response"]["url"] = URL.replace("safe", "debug")
    scanner, engine = scanner_for(check, network)
    with pytest.raises(PageDocumentUnavailable):
        await scanner.scan_page(URL)
    assert any(note.startswith(f"transport_error:{check}:") for note in engine.wave_errors)
    scanner.record_finding.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
async def test_exact_get_document_survives_later_xhr_and_query(check):
    network = NetworkCapture()
    await capture(network)
    await capture(network, method="POST", resource_type="xhr", body="safe")
    await capture(network, url=URL.replace("safe", "debug"), body="safe")
    scanner, engine = scanner_for(check, network)
    findings = await scanner.scan_page(URL + "#fragment")
    assert not engine.wave_errors
    if check == "outdated_components":
        scanner._scan_osv.assert_awaited_once()
        assert scanner._scan_osv.call_args.args[2] == BODY
    else:
        assert findings
        assert scanner.record_finding.call_args.kwargs["pair"]["request"]["method"] == "GET"


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
async def test_exact_safe_document_is_available(check):
    network = NetworkCapture()
    await capture(network, body="<html>safe</html>")
    scanner, engine = scanner_for(check, network)
    findings = await scanner.scan_page(URL)
    assert not engine.wave_errors
    if check in ("info_disclosure", "sri", "secret_leak", "outdated_components"):
        assert not findings


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("status", [404, 500])
async def test_exact_non_2xx_capture_preserves_consumer_policy(check, status):
    network = NetworkCapture()
    await capture(network, status=status)
    scanner, engine = scanner_for(check, network)
    if status == 500 and check in ("clickjacking", "security_headers", "outdated_components"):
        with pytest.raises(PageDocumentUnavailable):
            await scanner.scan_page(URL)
        assert engine.wave_errors
    else:
        findings = await scanner.scan_page(URL)
        if check in ("info_disclosure", "sri", "secret_leak"):
            assert findings
        elif check in ("clickjacking", "security_headers"):
            assert not findings


@pytest.mark.asyncio
async def test_same_url_reverse_enrichment_preserves_request_identity():
    network = NetworkCapture()
    responses = []
    for method, resource_type, body in [("POST", "document", BODY),
                                         ("GET", "document", "safe"), ("GET", "xhr", BODY)]:
        req = SimpleNamespace(url=URL, method=method, resource_type=resource_type, headers={}, post_data=None)
        resp = SimpleNamespace(url=URL, request=req, status=200, headers={}, text=AsyncMock(return_value=body))
        network.on_request(req)
        responses.append(resp)
    for resp in reversed(responses):
        network.on_response(resp)
    for resp in reversed(responses):
        await network.enrich_response(resp)
    assert [pair["response"]["body"] for pair in network.pairs] == [BODY, "safe", BODY]
    scanner, engine = scanner_for("info_disclosure", network)
    assert await scanner.scan_page(URL) == []
    assert not engine.wave_errors


@pytest.mark.asyncio
async def test_missing_body_keeps_headers_available_but_content_unavailable():
    network = NetworkCapture()
    pair = await capture(network)
    pair["response"].pop("body")
    header_scanner, _ = scanner_for("clickjacking", network)
    assert await header_scanner.scan_page(URL)
    for check in ("info_disclosure", "sri", "secret_leak"):
        scanner, engine = scanner_for(check, network)
        with pytest.raises(PageDocumentUnavailable):
            await scanner.scan_page(URL)
        assert any("body_unavailable" in note for note in engine.wave_errors)


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("newer", ["pending", "post", "unknown", "bad_identity"])
async def test_newest_document_request_blocks_older_success(check, newer):
    network = NetworkCapture()
    await capture(network, body="<html>safe</html>")
    if newer == "pending":
        request = SimpleNamespace(url=URL, method="GET", resource_type="document", headers={}, post_data=None)
        network.on_request(request)  # failed same-generation retry has no response
    else:
        pair = await capture(network, method="POST" if newer == "post" else "GET")
        if newer == "unknown":
            pair["request"].pop("resource_type")
        if newer == "bad_identity":
            pair["response"].pop("_req_id")
    scanner, engine = scanner_for(check, network)
    with pytest.raises(PageDocumentUnavailable):
        await scanner.scan_page(URL)
    assert engine.wave_errors
    scanner.record_finding.assert_not_awaited()


@pytest.mark.asyncio
async def test_clear_fences_late_response_and_enrichment():
    network = NetworkCapture()
    request = SimpleNamespace(url=URL, method="GET", resource_type="document", headers={}, post_data=None)
    response = SimpleNamespace(url=URL, request=request, status=200, headers={}, text=AsyncMock(return_value=BODY))
    network.on_request(request)
    network.clear()
    network.on_response(response)  # no matching on_request in the current generation
    await network.enrich_response(response)
    scanner, _ = scanner_for("info_disclosure", network)
    with pytest.raises(PageDocumentUnavailable):
        await scanner.scan_page(URL)


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
async def test_unavailable_capture_leaves_engine_page_checkpoint_incomplete(check):
    from unittest.mock import Mock
    from wscan.engine import ScanEngine

    network = NetworkCapture()
    await capture(network, method="POST")
    scanner, engine = scanner_for(check, network)
    engine.scanners = {check: scanner}
    engine._profile = Mock()
    engine._maybe_relogin_for_page = AsyncMock()
    engine._match_pre_attack_flows = Mock(return_value=[])
    engine._checkpoint_is_done = Mock(return_value=False)
    engine._checkpoint_mark_done = Mock()
    engine._record_scan_matrix = Mock()
    engine._record_finding = Mock()
    engine._save_checkpoint = Mock()
    engine._dialog_wedged_since = Mock(return_value=False)
    engine._recover_if_dialog_flood = AsyncMock()
    engine._page_recovery_failed = Mock(return_value=False)
    page = SimpleNamespace(url=URL, html=None, forms=[], url_params=[])
    await ScanEngine._attack_one_page(engine, page, {})
    engine._checkpoint_mark_done.assert_not_called()
    engine._record_scan_matrix.assert_called_once()
    assert engine._record_scan_matrix.call_args.kwargs["status"] == "error"



async def _redirect_chain(network, final_url, final_method="GET"):
    """Chromium と同じく hop ごとに別 request を作り、後続 hop が redirected_from で元を指す。"""
    hops = []
    for url, method, status, redirected_from in [(URL, "GET", 302, None),
                                                 (final_url, final_method, 200, "prev")]:
        request = SimpleNamespace(url=url, method=method, resource_type="document", headers={},
                                  post_data=None, redirected_from=hops[-1] if redirected_from else None)
        headers = {"content-type": "text/html"}
        if status == 302:
            headers["location"] = final_url
        response = SimpleNamespace(url=url, request=request, status=status, headers=headers,
                                   text=AsyncMock(return_value="" if status == 302 else BODY))
        network.on_request(request)
        network.on_response(response)
        await network.enrich_response(response)
        hops.append(request)


@pytest.mark.asyncio
@pytest.mark.parametrize("check", CHECKS)
@pytest.mark.parametrize("final_url, method, proven", [
    ("http://fixture.test/error/final?mode=safe", "GET", True),       # same-host: _get と同じく追従
    ("http://outside.test/error?mode=safe", "GET", False),             # 別ホスト: 追従しない
    ("http://fixture.test/error/final?mode=safe", "POST", False),      # POST を GET に偽装しない
])
async def test_redirect_requires_native_provenance_and_protected_hop(check, final_url, method, proven):
    network = NetworkCapture()
    await _redirect_chain(network, final_url, method)
    scanner, engine = scanner_for(check, network)
    if proven:
        findings = await scanner.scan_page(URL)
        assert not engine.wave_errors
        if check == "outdated_components":
            assert scanner._scan_osv.call_args.args[2] == BODY
        else:
            assert findings
    else:
        with pytest.raises(PageDocumentUnavailable):
            await scanner.scan_page(URL)
        scanner.record_finding.assert_not_awaited()


@pytest.mark.asyncio
async def test_redirect_without_captured_successor_is_unavailable():
    network = NetworkCapture()
    await capture(network, status=302, body="", location="/error/final?mode=safe")
    scanner, engine = scanner_for("security_headers", network)
    with pytest.raises(PageDocumentUnavailable):
        await scanner.scan_page(URL)
    assert engine.wave_errors
