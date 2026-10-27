"""Browser-independent verification of open_redirect probe outcome normalization into ProbeLedger."""
import json
from pathlib import Path
from types import SimpleNamespace

import httpx
import pytest

from wscan.injection_point import InjectionPoint
from wscan.request_logger import RequestLogger
from wscan.scanners.base import Finding
from wscan.scanners.open_redirect import OpenRedirectScanner


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
    scanner = OpenRedirectScanner(engine)
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
async def test_open_redirect_apply_payload_failure_normalizes_outcome(tmp_path, exc, expected_outcome):
    class _FailingBrowser:
        async def test_url_param(self, *a, **k):
            raise exc

        async def navigate(self, *a, **k):
            raise exc

        async def fill_and_submit_form(self, *a, **k):
            raise exc

    scanner, logger = make_scanner(tmp_path, _FailingBrowser())
    ip = InjectionPoint.for_url_param("http://target.test/redirect", "next")

    source, pair = await scanner._apply_ip(ip, "https://evil.example.com")
    assert (source, pair) == ("", {})

    rows = records(logger)
    assert len(rows) == 1
    decision = rows[0]
    assert decision["record_kind"] == "decision"
    assert decision["outcome"] == expected_outcome
    assert decision["check"] == "open_redirect"
    assert decision["role"] == "attack"
    assert decision["rationale"] == "no correlated outgoing response"
    assert any(f"transport_error:open_redirect:{type(exc).__name__}" in err for err in scanner.engine.wave_errors)
