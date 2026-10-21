"""Detector decisions remain separate from transport observations."""
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan.engine import ScanEngine
from wscan.request_logger import RequestLogger
from wscan.scanners.base import Finding
from wscan.scanners.cors import CORSScanner, _CANARY_ORIGIN


def records(logger):
    return [json.loads(line) for line in logger.probe_ledger.path.read_text().splitlines()]


def scanner_for(tmp_path, headers, status=200, failure=None, enabled=True):
    logger = RequestLogger(tmp_path, enabled=enabled)
    calls = []

    def respond(request):
        calls.append(request)
        if failure:
            raise failure
        return httpx.Response(status, headers=headers, content=b"private-body")

    engine = SimpleNamespace(
        request_logger=logger, proxy="", timeout=1, monitor=None,
        browser=object(), payload_gen=object(), wave_errors=[],
        tls_config=SimpleNamespace(httpx_options=lambda: {"verify": True}),
    )
    engine.httpx_client_kwargs = lambda **kwargs: ScanEngine.httpx_client_kwargs(
        engine, transport=httpx.MockTransport(respond), **kwargs)
    scanner = CORSScanner(engine)
    scanner.record_finding = AsyncMock(return_value=object())
    return scanner, logger, calls


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [200, 403, 500])
@pytest.mark.parametrize("matched", [False, True])
async def test_cors_attack_records_header_decision_independently_of_status(tmp_path, status, matched):
    headers = {"access-control-allow-origin": _CANARY_ORIGIN if matched else "https://safe.test",
               "Set-Cookie": "sid=private-cookie",
               "Location": "https://alice:private-password@t.test/"}
    scanner, logger, calls = scanner_for(tmp_path, headers, status)
    url = "https://bob:private-userinfo@t.test/?token=private-token"
    findings = await scanner.scan_page(url)
    submission, observed, decision = records(logger)
    assert len(calls) == 1 and len(findings) == int(matched)
    assert calls[0].headers["Origin"] == _CANARY_ORIGIN
    assert observed["parent_id"] == submission["attempt_id"]
    assert decision["parent_id"] == observed["attempt_id"]
    assert submission["outcome"] is observed["outcome"] is None
    assert decision["outcome"] == ("matched" if matched else "no_match")
    assert decision["role"] == "attack"
    assert decision["decision_rule"] == "cors_origin_reflection"
    assert decision["decision_version"] == "1"
    assert decision["response"]["status"] == status
    assert not scanner.engine.wave_errors
    assert await scanner.scan_page(url) == []
    assert len(records(logger)) == 3
    for secret in ("private-cookie", "private-password", "private-userinfo", "private-token", "private-body"):
        assert secret not in logger.probe_ledger.path.read_text()


@pytest.mark.asyncio
@pytest.mark.parametrize("rule,headers,matched", [
    ("cors_wildcard_credentials", {"access-control-allow-origin": "*",
                                   "access-control-allow-credentials": "true"}, True),
    ("cors_wildcard_credentials", {"access-control-allow-origin": "*"}, False),
    ("cors_origin_reflection", {"access-control-allow-origin": _CANARY_ORIGIN,
                               "access-control-allow-credentials": "true"}, True),
    ("cors_origin_reflection", {"access-control-allow-origin": _CANARY_ORIGIN}, False),
])
async def test_cors_verification_records_existing_boolean_result(tmp_path, rule, headers, matched):
    scanner, logger, calls = scanner_for(tmp_path, headers)
    finding = Finding(check_type="cors", severity="high", url="https://t.test/",
                      field_name="Origin", payload="probe", evidence="headers",
                      evidence_type=rule, evidence_details={"acac": "true"})
    assert await scanner.verify_finding(finding) is matched
    submission, observed, decision = records(logger)
    assert len(calls) == 1
    assert decision["parent_id"] == observed["attempt_id"]
    assert decision["role"] == "verify" and decision["decision_rule"] == rule
    assert decision["outcome"] == ("matched" if matched else "no_match")
    assert submission["outcome"] is observed["outcome"] is None


@pytest.mark.asyncio
@pytest.mark.parametrize("verify", [False, True])
async def test_failed_probe_has_no_detector_outcome_and_is_observable(tmp_path, verify):
    scanner, logger, calls = scanner_for(tmp_path, {}, failure=httpx.ReadTimeout("private-error"))
    if verify:
        finding = Finding(check_type="cors", severity="high", url="https://t.test/",
                          field_name="Origin", payload="probe", evidence="headers",
                          evidence_type="cors_origin_reflection")
        assert await scanner.verify_finding(finding) is None
    else:
        assert await scanner.scan_page("https://t.test/") == []
    submission, decision = records(logger)
    assert submission["outcome"] is None and submission["response"] is None
    assert decision["outcome"] == "timeout"
    assert decision["decision_rule"] == "cors_origin_reflection"
    assert decision["decision_version"] == "1"
    assert decision["rationale"] == "probe request failed before response"
    assert len(calls) == 1
    assert any("ReadTimeout" in note for note in scanner.engine.wave_errors)
    assert "private-error" not in str(scanner.engine.wave_errors)


@pytest.mark.asyncio
async def test_decision_append_failure_preserves_finding_and_transport(tmp_path):
    scanner, logger, calls = scanner_for(tmp_path, {"access-control-allow-origin": _CANARY_ORIGIN})
    original = logger.log_probe

    def fail_decision(**kwargs):
        if kwargs.get("outcome") is not None:
            raise RuntimeError("private-error")
        return original(**kwargs)

    logger.log_probe = fail_decision
    assert len(await scanner.scan_page("https://t.test/")) == 1
    assert len(calls) == 1 and len(records(logger)) == 2
    assert scanner.engine.wave_errors == ["probe_evidence_error:RuntimeError"]


@pytest.mark.asyncio
async def test_disabled_ledger_preserves_detector_result(tmp_path):
    scanner, logger, calls = scanner_for(tmp_path, {}, enabled=False)
    assert await scanner.scan_page("https://t.test/") == []
    assert len(calls) == 1 and not list(tmp_path.iterdir())


def test_probe_exception_normalization_is_pure_and_message_free():
    from wscan.probe_ledger import ProbeOutcome
    from wscan.scanners.cors import _normalize_probe_exception

    assert _normalize_probe_exception(httpx.ReadTimeout("private-token")) is ProbeOutcome.TIMEOUT
    assert _normalize_probe_exception(httpx.ConnectError("private-token")) is ProbeOutcome.TRANSPORT_ERROR
    assert _normalize_probe_exception(ValueError("private-token")) is ProbeOutcome.VERIFICATION_ERROR


def test_foreign_logger_observation_is_not_linked(tmp_path):
    scanner, logger, _ = scanner_for(tmp_path, {})
    response = httpx.Response(200, request=httpx.Request("GET", "https://t.test/"))
    response.extensions["vulix_probe_observation"] = (object(), "foreign:000001")
    from wscan.probe_ledger import ProbeRole
    scanner._record_cors_decision(response, "https://t.test/", False,
                                  ProbeRole.VERIFY, "cors_origin_reflection")
    decision, = records(logger)
    assert decision["parent_id"] == "" and decision["outcome"] == "no_match"
