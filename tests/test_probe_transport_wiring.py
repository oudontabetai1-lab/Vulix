"""Browser-free evidence wiring checks; transport and detector results stay untouched."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import httpx
import pytest

from wscan.engine import ScanEngine
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
    assert len(rows(logger)) == 2
    assert all(r["request"]["sent"] is False and r["outcome"] is None for r in rows(logger))
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
    assert [r["role"] for r in rows(logger)] == ["attack", "verify", "attack"]
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
    row, = rows(logger)
    assert row["actor"] == "api_get_capture"
    assert row["request"]["sent"] is True
    assert row["response"]["status"] == 200
    assert row["response"]["body_hash"] == ""
    assert row["outcome"] is None
