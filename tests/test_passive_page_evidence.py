"""実 detector と共有 API GET の因果関係。fake transport は unit proof のみ。"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wscan.engine import ScanEngine
from wscan.checkpoint import unit_key
from wscan.probe_recorder import ProbeLedger
from wscan.request_logger import RequestLogger
from wscan.scanners import SCANNERS
from wscan.scanners.base import PageDocumentUnavailable

URL = "http://fixture.test/page"
SAFE = {"content-type": "text/html", "x-frame-options": "DENY",
        "strict-transport-security": "max-age=31536000", "content-security-policy": "default-src 'self'",
        "x-content-type-options": "nosniff", "referrer-policy": "same-origin",
        "permissions-policy": "camera=()", "cross-origin-opener-policy": "same-origin"}


def fixture(tmp_path, headers=None, status=200):
    logger = RequestLogger(tmp_path)
    response = SimpleNamespace(status=status, headers=dict(SAFE if headers is None else headers), url=URL,
                               text=AsyncMock(return_value="<html>password=private-body</html>"), dispose=AsyncMock())
    request = SimpleNamespace(get=AsyncMock(return_value=response))
    engine = SimpleNamespace(browser=SimpleNamespace(_context=SimpleNamespace(request=request)),
                             monitor=None, payload_gen=None, wave_errors=[], request_logger=logger)
    scanners = {c: SCANNERS[c](engine) for c in ("clickjacking", "security_headers")}
    async def finding(**kwargs):
        return SimpleNamespace(url=kwargs["url"], field_name=kwargs["field_name"], evidence_type=kwargs.get("evidence_type", ""),
                               evidence_details=kwargs.get("evidence_details", {}))
    for scanner in scanners.values():
        scanner.record_finding = AsyncMock(side_effect=finding)
    return engine, scanners, request, response


def scope(engine, scanner, role="attack", finding=None):
    key = unit_key(URL, "(page)", 0, scanner.CHECK_TYPE)
    rules = scanner.PASSIVE_RULES
    if finding:
        key = unit_key(URL, finding.field_name, 0, scanner.CHECK_TYPE) + "\x1everify:" + finding.evidence_type
        rules = (finding.evidence_type,)
    return ScanEngine._evidence_scope(engine, key, scanner.CHECK_TYPE, rules=rules, role=role)


def summary(engine):
    return engine.request_logger.probe_ledger.completion_summary(["clickjacking", "security_headers"])


def records(engine):
    return list(engine.request_logger.probe_ledger.events.values())


@pytest.mark.asyncio
@pytest.mark.parametrize("headers,counts", [(SAFE, (0, 0)), ({}, (1, 6)),
    ({**SAFE, "strict-transport-security": "max-age=60", "content-security-policy": "script-src 'unsafe-inline'"}, (0, 2))])
async def test_real_rules_share_one_input_and_restore(tmp_path, headers, counts):
    engine, scanners, request, _ = fixture(tmp_path, {**headers, "set-cookie": "session=hidden-cookie"})
    for (check, scanner), count in zip(scanners.items(), counts):
        with scope(engine, scanner):
            assert len(await scanner.scan_page(URL)) == count
    assert request.get.await_count == 1
    ledger = engine.request_logger.probe_ledger
    assert summary(engine)["status"] == "COMPLETE"
    decisions = [r for r in records(engine) if r["record_kind"] == "passive_decision"]
    assert len(decisions) == 9 and len({r["parent_id"] for r in decisions}) == 1
    assert len([r for r in records(engine) if r["record_kind"] == "request"]) == 1
    assert {r["check"] for r in decisions} == set(scanners)
    raw = ledger.path.read_text()
    assert "hidden-cookie" not in raw and "private-body" not in raw
    assert len(decisions[0]["response"]["headers_hash"]) == 64
    assert ledger.write_manifest()
    restored = ProbeLedger(tmp_path, tmp_path.name)
    assert restored.completion_summary(scanners)["status"] == "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("status", [302, 401, 500])
async def test_non_2xx_body_never_completes(tmp_path, status):
    engine, scanners, _, _ = fixture(tmp_path, {}, status)
    for scanner in scanners.values():
        with scope(engine, scanner):
            if status == 500:
                with pytest.raises(PageDocumentUnavailable):
                    await scanner.scan_page(URL)
            else:
                assert await scanner.scan_page(URL) == []
    assert summary(engine)["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_transport_and_logger_failure_preserve_outcome(tmp_path):
    engine, scanners, request, _ = fixture(tmp_path)
    request.get.side_effect = TimeoutError()
    with pytest.raises(PageDocumentUnavailable), scope(engine, scanners["clickjacking"]):
        await scanners["clickjacking"].scan_page(URL)
    assert summary(engine)["status"] != "COMPLETE"
    engine, scanners, _, _ = fixture(tmp_path / "logger", {})
    engine.request_logger.probe_ledger._quarantined = True
    with scope(engine, scanners["clickjacking"]):
        assert len(await scanners["clickjacking"].scan_page(URL)) == 1
    assert summary(engine)["status"] != "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("mutation", ["wrong_parent", "foreign_scan", "stale_order", "snapshot", "partial", "legacy", "wrong_check", "wrong_unit"])
async def test_persisted_causality_rejects_mutations(tmp_path, mutation):
    engine, scanners, _, _ = fixture(tmp_path)
    scanner = scanners["security_headers"]
    with scope(engine, scanner):
        await scanner.scan_page(URL)
    ledger = engine.request_logger.probe_ledger
    assert ledger.completion_summary([scanner.CHECK_TYPE])["status"] == "COMPLETE"
    decision = next(r for r in ledger.events.values() if r["record_kind"] == "passive_decision")
    if mutation == "wrong_parent": decision["parent_id"] = "foreign:1"
    if mutation == "foreign_scan": decision["scan_id"] = "foreign"
    if mutation == "stale_order":
        observation = ledger.events[decision["parent_id"]]
        observation["attempt_id"] = decision["attempt_id"]
    if mutation == "snapshot": decision["response"]["headers_hash"] = "f" * 64
    if mutation == "partial": ledger.events.pop(decision["attempt_id"])
    if mutation == "legacy": decision["record_kind"] = "legacy"
    if mutation == "wrong_check": decision["check"] = "clickjacking"
    if mutation == "wrong_unit": decision["completion_unit"] = "f" * 64
    assert ledger.completion_summary([scanner.CHECK_TYPE])["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_cached_mutation_and_foreign_logger_are_incomplete(tmp_path):
    engine, scanners, _, _ = fixture(tmp_path)
    scanner = scanners["security_headers"]
    pair = await scanner._response_pair(URL)
    pair["response"]["headers"]["content-security-policy"] = "mutated"
    with scope(engine, scanner):
        for rule in scanner.PASSIVE_RULES:
            scanner._passive_decision(pair, False, rule)
    assert summary(engine)["status"] != "COMPLETE"
    pair["_passive_binding"] = (RequestLogger(tmp_path / "foreign"), *pair["_passive_binding"][1:])
    assert scanner._passive_decision(pair, False, scanner.PASSIVE_RULES[0])


@pytest.mark.asyncio
@pytest.mark.parametrize("mode,expected", [("match", True), ("safe", False), ("missing-parent", True),
                                          ("500", None), ("transport", None), ("missing-detail", None)])
async def test_verification_parent_and_exact_return_policy(tmp_path, mode, expected):
    engine, scanners, request, response = fixture(tmp_path, {})
    scanner = scanners["security_headers"]
    with scope(engine, scanner):
        findings = await scanner.scan_page(URL)
    finding = findings[0]
    if mode == "safe": response.headers = SAFE
    if mode == "missing-parent": finding.evidence_details.pop("probe_attempt_id")
    if mode == "500": response.status = 500
    if mode == "transport": request.get.side_effect = TimeoutError()
    if mode == "missing-detail": finding.evidence_details.pop("header")
    with scope(engine, scanner, "verify", finding):
        assert await scanner.verify_finding(finding) is expected
    states = [v["status"] for v in summary(engine)["checks"]["security_headers"]["units"].values()]
    assert (set(states) == {"COMPLETE"}) == (mode in {"match", "safe"})


@pytest.mark.asyncio
async def test_verifier_keeps_different_hsts_threshold(tmp_path):
    engine, scanners, _, response = fixture(tmp_path, {**SAFE, "strict-transport-security": "max-age=60"})
    scanner = scanners["security_headers"]
    with scope(engine, scanner):
        findings = await scanner.scan_page(URL)
    finding = findings[0]
    response.headers["strict-transport-security"] = "max-age=100000"
    with scope(engine, scanner, "verify", finding):
        assert await scanner.verify_finding(finding) is True
    assert summary(engine)["checks"]["security_headers"]["status"] == "COMPLETE"


@pytest.mark.asyncio
async def test_verifier_rejects_other_header_parent(tmp_path):
    engine, scanners, _, _ = fixture(tmp_path, {})
    scanner = scanners["security_headers"]
    with scope(engine, scanner):
        findings = await scanner.scan_page(URL)
    findings[0].evidence_details["probe_attempt_id"] = findings[1].evidence_details["probe_attempt_id"]
    with scope(engine, scanner, "verify", findings[0]):
        assert await scanner.verify_finding(findings[0]) is True
    assert summary(engine)["checks"]["security_headers"]["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_redirect_uses_real_final_hop_identity(tmp_path):
    engine, scanners, request, response = fixture(tmp_path)
    redirect = SimpleNamespace(status=302, headers={"location":"/final"}, dispose=AsyncMock())
    response.url = URL.replace('/page', '/final')
    request.get.side_effect = [redirect, response]
    scanner = scanners["clickjacking"]
    with scope(engine, scanner):
        assert await scanner.scan_page(URL) == []
    ledger = engine.request_logger.probe_ledger
    decision = next(r for r in records(engine) if r["record_kind"] == "passive_decision")
    submission = ledger.events[decision["request_attempt_id"]]
    assert request.get.await_count == 2
    assert submission["request"]["url"] == response.url
    assert decision["response"]["final_url"] == response.url
    assert ledger.completion_summary([scanner.CHECK_TYPE])["status"] == "COMPLETE"


@pytest.mark.asyncio
async def test_late_cached_input_cannot_borrow_another_unit(tmp_path):
    engine, scanners, _, _ = fixture(tmp_path)
    scanner = scanners["clickjacking"]
    pair = await scanner._response_pair(URL)
    key = unit_key(URL + "?other=1", "(page)", 0, scanner.CHECK_TYPE)
    with ScanEngine._evidence_scope(engine, key, scanner.CHECK_TYPE, rules=scanner.PASSIVE_RULES):
        scanner._passive_decision(pair, False, scanner.PASSIVE_RULES[0])
    assert engine.request_logger.probe_ledger.completion_summary([scanner.CHECK_TYPE])["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_malformed_and_legacy_restoration_fail_closed(tmp_path):
    import json
    engine, scanners, _, _ = fixture(tmp_path)
    scanner = scanners["clickjacking"]
    with scope(engine, scanner):
        await scanner.scan_page(URL)
    ledger = engine.request_logger.probe_ledger
    assert ledger.write_manifest()
    original = ledger.path.read_text()
    persisted = [json.loads(line) for line in original.splitlines()]
    decision = next(r for r in persisted if r["record_kind"] == "passive_decision")
    decision["response"]["headers_hash"] = 42
    ledger.path.write_text(''.join(json.dumps(row)+'\n' for row in persisted))
    restored = ProbeLedger(tmp_path, tmp_path.name)
    assert restored.evidence_incomplete
    assert restored.completion_summary([scanner.CHECK_TYPE])["status"] != "COMPLETE"


@pytest.mark.asyncio
async def test_native_capture_fallback_keeps_detection_without_inventing_http(tmp_path):
    from wscan.browser import NetworkCapture
    from tests.test_document_capture_provenance import capture
    engine, scanners, request, _ = fixture(tmp_path)
    network = NetworkCapture(logger=engine.request_logger)
    engine.browser.network = network
    await capture(network, url=URL, body="<html>safe</html>")
    request.get.side_effect = TimeoutError()
    scanner = scanners["clickjacking"]
    with scope(engine, scanner):
        assert len(await scanner.scan_page(URL)) == 1
    assert engine.request_logger.probe_ledger.completion_summary([scanner.CHECK_TYPE])["status"] != "COMPLETE"
    submitted = [r for r in records(engine) if r["record_kind"] == "request"]
    assert len(submitted) == 1 and request.get.await_count == 1
    assert any(r["outcome"] == "timeout" for r in records(engine))
