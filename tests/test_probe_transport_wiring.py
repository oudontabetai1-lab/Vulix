"""Browser-free evidence wiring checks; transport and detector results stay untouched."""
import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from wscan.engine import ScanEngine
from wscan.browser import NetworkCapture
from wscan.probe_ledger import ProbeRole
from wscan.request_logger import RequestLogger, register_sensitive_headers, clear_sensitive_headers
from wscan.scanners.base import BaseScanner
from wscan.scanners.websocket import WebSocketScanner


def rows(logger):
    return [json.loads(line) for line in logger.probe_ledger.path.read_text().splitlines()]


def test_browser_pairs_preserve_old_log_and_do_not_infer_outcome(tmp_path):
    logger = RequestLogger(tmp_path)
    pair = {
        "request": {"url": "https://target.test/?token=hidden", "method": "POST",
                    "headers": {"Authorization": "secret"},
                    "post_data": '{"password":"hidden","q":"probe"}'},
        "response": {"status": 403, "headers": {"Set-Cookie": "secret"}},
    }
    logger.log_http(pair)
    row, = rows(logger)
    assert logger.http_count == 1
    assert json.loads(logger.http_path.read_text())["status"] == 403
    assert row["request"]["sent"] is True
    assert row["request"]["transport"] == "playwright"
    assert row["outcome"] is None
    assert "hidden" not in logger.probe_ledger.path.read_text()
    assert "secret" not in logger.probe_ledger.path.read_text()
    assert pair["request"]["headers"]["Authorization"] == "secret"
    assert logger.probe_ledger.write_manifest()
    restored = RequestLogger(tmp_path)
    restored.log_http(pair)
    assert len({r["attempt_id"] for r in rows(restored)}) == 2
    assert not restored.probe_ledger.evidence_incomplete


def test_browser_correlates_request_identity_and_retains_unanswered_submission(tmp_path):
    logger = RequestLogger(tmp_path)
    capture = NetworkCapture(logger=logger)
    requests = [SimpleNamespace(url="https://t.test/?token=hidden", method="POST",
                               headers={"Authorization": "private"}, post_data="private-body",
                               resource_type="document", redirected_from=None) for _ in range(3)]
    for request in requests:
        capture.on_request(request)
    for request in reversed(requests[:2]):
        capture.on_response(SimpleNamespace(request=request, url=request.url, status=403, headers={}))
    first, second, unanswered, response2, response1 = rows(logger)
    assert response2["parent_id"] == second["attempt_id"]
    assert response1["parent_id"] == first["attempt_id"]
    assert unanswered["response"] is None and unanswered["request"]["sent"] is False
    assert all(row["outcome"] is None for row in rows(logger))
    assert logger.http_count == 2
    for secret in ("hidden", "private", "private-body"):
        assert secret not in logger.probe_ledger.path.read_text()


def test_browser_url_fallback_does_not_claim_identity_correlation(tmp_path):
    logger = RequestLogger(tmp_path)
    capture = NetworkCapture(logger=logger)
    request = SimpleNamespace(url="https://t.test/", method="GET", headers={}, post_data=None)
    capture.on_request(request)
    capture.on_response(SimpleNamespace(request=SimpleNamespace(resource_type="document"),
                                        url=request.url, status=200, headers={}))
    submission, response = rows(logger)
    assert submission["response"] is None
    assert response["parent_id"] == ""


def test_browser_submission_failure_is_observable_and_capture_continues(caplog):
    capture = NetworkCapture(logger=SimpleNamespace(
        log_browser_submission=Mock(side_effect=RuntimeError("private")), log_http=Mock()))
    request = SimpleNamespace(url="https://t.test/", method="GET", headers={}, post_data=None)
    capture.on_request(request)
    assert capture._pending
    assert "probe_submission_error:RuntimeError" in caplog.text
    assert "private" not in caplog.text


@pytest.mark.asyncio
async def test_httpx_redirects_and_concurrent_same_urls_keep_distinct_ids_and_streams(tmp_path):
    logger = RequestLogger(tmp_path)
    observed_hooks = []
    streams = []

    class Stream(httpx.AsyncByteStream):
        async def __aiter__(self):
            yield b"private-body"

    async def original_response_hook(response):
        observed_hooks.append(response.status_code)
        assert not response.is_stream_consumed

    async def respond(request):
        await asyncio.sleep(0)
        stream = Stream()
        streams.append(stream)
        if request.url.path == "/redirect":
            return httpx.Response(302, headers={"location": "/final?token=hidden"}, stream=stream)
        return httpx.Response(403, stream=stream)

    hooks = {"response": [original_response_hook]}
    engine = SimpleNamespace(request_logger=logger, proxy="", tls_config=SimpleNamespace(
        httpx_options=lambda: {"verify": True}))
    kwargs = ScanEngine.httpx_client_kwargs(engine, event_hooks=hooks,
                                           transport=httpx.MockTransport(respond))
    async with httpx.AsyncClient(**kwargs) as client:
        async def send():
            async with client.stream("POST", "https://t.test/redirect", content=Stream(),
                                     follow_redirects=True) as response:
                assert not response.is_stream_consumed
                assert await response.aread() == b"private-body"
        await asyncio.gather(send(), send())
    records = rows(logger)
    submissions = {r["attempt_id"]: r for r in records if not r["response"]}
    responses = [r for r in records if r["response"]]
    assert len(submissions) == len(responses) == 4
    assert len({r["parent_id"] for r in responses}) == 4
    for response in responses:
        assert response["request"]["url"] == submissions[response["parent_id"]]["request"]["url"]
        assert response["response"]["body_hash"] == ""
        assert response["outcome"] is None
    assert hooks == {"response": [original_response_hook]}
    assert sorted(observed_hooks) == [302, 302, 403, 403]
    assert "private-body" not in logger.probe_ledger.path.read_text()
    assert "hidden" not in logger.probe_ledger.path.read_text()


@pytest.mark.asyncio
@pytest.mark.parametrize("fail_final", [False, True])
async def test_api_get_records_each_redirect_hop_without_reading_intermediate_body(tmp_path, fail_final):
    logger = RequestLogger(tmp_path)
    redirect = SimpleNamespace(status=302, url="https://t.test/", headers={"location": "/final"},
                               text=AsyncMock(), dispose=AsyncMock())
    final = SimpleNamespace(status=403, url="https://t.test/final", headers={},
                            text=AsyncMock(return_value="unchanged"), dispose=AsyncMock())
    failure = RuntimeError("private")
    request = SimpleNamespace(get=AsyncMock(side_effect=[redirect, failure if fail_final else final]))
    browser = SimpleNamespace(_context=SimpleNamespace(request=request))
    scanner = object.__new__(WebSocketScanner)
    scanner.engine = SimpleNamespace(request_logger=logger, browser=browser)
    scanner.browser = browser
    if fail_final:
        with pytest.raises(RuntimeError, match="private"):
            await scanner._get("https://t.test/")
    else:
        direct = await scanner._get("https://t.test/")
        assert direct.text == "unchanged" and direct.status_code == 403
        final.text.assert_awaited_once()
    redirect.text.assert_not_awaited()
    first, response1, second, *remaining = rows(logger)
    assert response1["parent_id"] == first["attempt_id"]
    assert response1["response"]["status"] == 302
    assert second["request"]["url"] == "https://t.test/final"
    if fail_final:
        assert not remaining
    else:
        assert remaining[0]["parent_id"] == second["attempt_id"]
        assert remaining[0]["response"]["status"] == 403
    assert all(row["outcome"] is None for row in rows(logger))


@pytest.mark.parametrize("check,role", [
    ("ssti", "attack"), ("ssti_baseline", "baseline"),
    ("sqli_verify_control", "control"), ("ssti_verify", "verify"),
    ("ssti_verify_baseline", "baseline"),
])
def test_payload_submission_has_explicit_role_but_no_claim_of_delivery(tmp_path, check, role):
    logger = RequestLogger(tmp_path)
    logger.log_payload("q", "private-payload", check, "https://t.test/?token=hidden")
    row, = rows(logger)
    assert row["role"] == role
    assert row["check"] == check
    assert row["request"] is None
    assert row["outcome"] is None
    assert "private-payload" not in logger.probe_ledger.path.read_text()
    assert "hidden" not in logger.probe_ledger.path.read_text()
    assert "payload_sha256=" in row["rationale"]
    assert logger.payload_count == 1


@pytest.mark.asyncio
async def test_httpx_hook_preserves_hooks_streams_response_and_timeout(tmp_path):
    logger = RequestLogger(tmp_path)
    seen = []

    async def original_hook(request):
        seen.append(str(request.url))

    async def respond(request):
        if request.url.path == "/timeout":
            raise httpx.ReadTimeout("secret URL must not enter ledger", request=request)
        return httpx.Response(200, content=b"unchanged")

    engine = SimpleNamespace(request_logger=logger, proxy="", tls_config=SimpleNamespace(
        httpx_options=lambda: {"verify": True}))
    original_hooks = {"request": [original_hook]}
    kwargs = ScanEngine.httpx_client_kwargs(
        engine, transport=httpx.MockTransport(respond), event_hooks=original_hooks)
    register_sensitive_headers(["X-Company-Auth"])
    try:
        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.post("https://t.test/ok?token=hidden", content=b"body",
                                         headers={"X-Company-Auth": "private"})
            assert response.content == b"unchanged"
            with pytest.raises(httpx.ReadTimeout):
                await client.get("https://t.test/timeout")
    finally:
        clear_sensitive_headers()
    assert len(seen) == 2
    assert original_hooks == {"request": [original_hook]}
    submitted, observed, timeout = rows(logger)
    assert observed["parent_id"] == submitted["attempt_id"]
    assert observed["request"]["sent"] is True
    assert observed["response"]["status"] == 200
    assert observed["response"]["body_hash"] == ""
    assert submitted["request"]["sent"] is False
    assert timeout["request"]["sent"] is False and timeout["response"] is None
    assert all(r["outcome"] is None for r in rows(logger))
    assert all(r["request"]["transport"] == "httpx" for r in rows(logger))
    assert "hidden" not in logger.probe_ledger.path.read_text()
    assert "private" not in logger.probe_ledger.path.read_text()


def test_observation_failure_is_visible_and_does_not_interrupt_legacy_logging(tmp_path):
    logger = RequestLogger(tmp_path)
    logger.probe_ledger.append = Mock(side_effect=RuntimeError("secret"))
    logger.log_payload("q", "value", "xss")
    assert logger.payload_count == 1
    assert logger.probe_ledger.evidence_incomplete
    assert logger.probe_ledger.manifest.write_errors[-1]["error"] == "probe_observation_error:RuntimeError"


def test_disabled_logger_does_not_create_ledger(tmp_path):
    logger = RequestLogger(tmp_path, enabled=False)
    logger.log_payload("q", "value", "xss")
    logger.log_http({"request": {"url": "https://t.test"}})
    assert not list(tmp_path.iterdir())


@pytest.mark.asyncio
async def test_httpx_response_recording_failure_does_not_change_transport_result(tmp_path):
    logger = RequestLogger(tmp_path)
    engine = SimpleNamespace(request_logger=logger, proxy="", tls_config=SimpleNamespace(
        httpx_options=lambda: {"verify": True}))
    original = logger.log_probe

    def fail_response(**kwargs):
        if kwargs.get("sent"):
            raise RuntimeError("private")
        return original(**kwargs)

    logger.log_probe = fail_response
    kwargs = ScanEngine.httpx_client_kwargs(engine, transport=httpx.MockTransport(
        lambda request: httpx.Response(403, content=b"unchanged")))
    async with httpx.AsyncClient(**kwargs) as client:
        response = await client.get("https://t.test/")
    assert response.status_code == 403 and response.content == b"unchanged"
    assert logger.probe_ledger.evidence_incomplete
    assert logger.probe_ledger.manifest.write_errors[-1]["error"] == "probe_observation_error:RuntimeError"
    assert "private" not in logger.probe_ledger.path.read_text()


def test_failed_ledger_append_does_not_return_a_correlation_id(tmp_path):
    logger = RequestLogger(tmp_path)
    logger.probe_ledger.append = Mock(return_value=False)
    assert logger.log_probe(role=ProbeRole.ATTACK) is None


@pytest.mark.asyncio
async def test_websocket_attack_verify_and_failure_preserve_return_values(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = object.__new__(WebSocketScanner)
    scanner.engine = SimpleNamespace(request_logger=logger, wave_errors=[], sleep_factor=0)
    page = SimpleNamespace(evaluate=AsyncMock(return_value=["observed"]))
    scanner.browser = SimpleNamespace(page=page)
    assert await scanner._send_ws_message("wss://t.test", "probe") == ["observed"]
    assert await scanner._send_ws_message("wss://t.test", "probe", role=ProbeRole.VERIFY) == ["observed"]
    page.evaluate.side_effect = RuntimeError("secret")
    assert await scanner._send_ws_message("wss://t.test", "probe") == []
    assert [r["role"] for r in rows(logger)] == ["attack", "attack", "verify", "verify", "attack"]
    attack, received, verify, verified, failed = rows(logger)
    assert received["parent_id"] == attack["attempt_id"]
    assert verified["parent_id"] == verify["attempt_id"]
    assert received["response"]["body_length"] == len("observed")
    assert received["response"]["body_excerpt"] == ""
    assert failed["response"] is None
    assert all(r["request"]["sent"] is False and r["outcome"] is None for r in rows(logger))
    assert scanner.engine.wave_errors == ["websocket_observation_error:RuntimeError"]


def test_scanner_evidence_failure_does_not_escape():
    scanner = object.__new__(WebSocketScanner)
    scanner.engine = SimpleNamespace(request_logger=SimpleNamespace(
        log_probe=Mock(side_effect=ValueError("secret"))), wave_errors=[])
    BaseScanner._record_probe_evidence(scanner, role=ProbeRole.ATTACK)
    assert scanner.engine.wave_errors == ["probe_evidence_error:ValueError"]


@pytest.mark.asyncio
async def test_api_get_records_headers_without_an_additional_body_read(tmp_path):
    logger = RequestLogger(tmp_path)
    response = SimpleNamespace(status=200, url="https://t.test/", headers={"server": "fixture"},
                               text=AsyncMock(return_value="unchanged"), dispose=AsyncMock())
    request = SimpleNamespace(get=AsyncMock(return_value=response))
    browser = SimpleNamespace(_context=SimpleNamespace(request=request))
    scanner = object.__new__(WebSocketScanner)
    scanner.engine = SimpleNamespace(request_logger=logger, browser=browser)
    scanner.browser = browser
    direct = await scanner._get("https://t.test/")
    assert direct.text == "unchanged"
    assert direct.status_code == 200
    response.text.assert_awaited_once()
    submission, row = rows(logger)
    assert row["parent_id"] == submission["attempt_id"]
    assert row["actor"] == "api_get_capture"
    assert row["request"]["sent"] is True
    assert row["response"]["status"] == 200
    assert row["response"]["body_hash"] == ""
    assert row["outcome"] is None
