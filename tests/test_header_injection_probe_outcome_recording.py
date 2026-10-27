"""Browser-independent verification of header_injection probe outcome normalization into ProbeLedger."""
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from wscan.injection_point import InjectionPoint
from wscan.request_logger import RequestLogger
from wscan.scanners.base import Finding
from wscan.scanners.header_injection import HeaderInjectionScanner


def records(logger: RequestLogger):
    path = logger.probe_ledger.path
    return [json.loads(line) for line in path.read_text().splitlines()] if path.is_file() else []


def make_scanner(tmp_path: Path, browser_mock=None):
    logger = RequestLogger(tmp_path)
    engine = SimpleNamespace(
        request_logger=logger,
        browser=browser_mock or SimpleNamespace(),
        monitor=None,
        payload_gen=None,
        wave_errors=[],
        timeout=1,
        proxy="",
        sleep_factor=0.0,
    )
    scanner = HeaderInjectionScanner(engine)
    return scanner, logger


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "exc,expected_outcome",
    [
        (httpx.ReadTimeout("read timed out"), "timeout"),
        (TimeoutError("async timeout"), "timeout"),
        (httpx.ConnectError("connection refused"), "transport_error"),
        (ConnectionResetError("reset by peer"), "transport_error"),
        (ValueError("invalid state"), "verification_error"),
    ],
)
async def test_header_injection_apply_payload_failure_normalizes_outcome(tmp_path, exc, expected_outcome):
    class _FailingBrowser:
        async def test_url_param(self, *a, **k):
            raise exc

        async def navigate(self, *a, **k):
            raise exc

        async def fill_and_submit_form(self, *a, **k):
            raise exc

    scanner, logger = make_scanner(tmp_path, _FailingBrowser())
    ip = InjectionPoint.for_url_param("http://target.test/view", "q")

    source, pair = await scanner._apply_ip(ip, "\r\nX-Injected: 1")
    assert (source, pair) == ("", {})

    rows = records(logger)
    assert len(rows) == 1
    decision = rows[0]
    assert decision["record_kind"] == "decision"
    assert decision["outcome"] == expected_outcome
    assert decision["check"] == "header_injection"
    assert decision["role"] == "attack"
    assert decision["rationale"] == "no correlated outgoing response"
    assert any(f"transport_error:header_injection:{type(exc).__name__}" in err for err in scanner.engine.wave_errors)


@pytest.mark.asyncio
async def test_header_injection_verify_finding_failure_normalizes_outcome(tmp_path):
    class _FailingBrowser:
        async def test_url_param(self, *a, **k):
            raise httpx.ReadTimeout("read timed out")

    scanner, logger = make_scanner(tmp_path, _FailingBrowser())
    finding = Finding(
        check_type="header_injection",
        severity="high",
        url="http://target.test/view?q=test",
        field_name="q",
        payload="\r\nX-WscanHdrInject: 1",
        evidence="HTTP header injection confirmed",
    )

    result = await scanner.verify_finding(finding)
    assert result is False

    rows = records(logger)
    assert len(rows) >= 1
    assert any(r["outcome"] == "timeout" for r in rows)
    assert any("transport_error:header_injection:ReadTimeout" in err for err in scanner.engine.wave_errors)


@pytest.mark.asyncio
async def test_header_injection_happy_path_no_exception(tmp_path):
    class _SuccessBrowser:
        async def test_url_param(self, *a, **k):
            return "<html>ok</html>", {
                "request": {"url": "http://target.test/view?q=test"},
                "response": {"status": 200, "headers": {"content-type": "text/html"}, "body": "<html>ok</html>"},
            }

    scanner, logger = make_scanner(tmp_path, _SuccessBrowser())
    ip = InjectionPoint.for_url_param("http://target.test/view", "q")

    source, pair = await scanner._apply_ip(ip, "safe_value")
    assert source == "<html>ok</html>"
    assert pair["response"]["status"] == 200
    assert scanner.engine.wave_errors == []
