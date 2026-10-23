"""Persisted browser causality rejects missing inputs and late/cross-page events."""
import json
from types import SimpleNamespace

import pytest

from wscan.browser import BrowserManager
from wscan.browser_evidence import emit, snapshot, operation, decision
from wscan.probe_recorder import ProbeLedger
from wscan.probe_ledger import BrowserInput, sha256_hex
from wscan.request_logger import RequestLogger
from wscan.flow_runner import FlowRunner, ScanFlow, FlowStep


class Page:
    main_frame = object()
    url = "http://fixture.test/"


def prepared(tmp_path):
    logger = RequestLogger(tmp_path)
    browser = SimpleNamespace(request_logger=logger, page=Page())
    source = emit(browser, "page_source", input_hash="a" * 64, input_length=1, complete=True)
    snapshot(browser, SimpleNamespace(html="<main>safe</main>"), source)
    unit = logger.probe_ledger.expect("page", "js_static", rules=["js_static_snapshot"])
    return browser, logger, unit


def finish(browser, logger, unit, **kwargs):
    with logger.probe_ledger.unit_scope(unit), operation(browser, "js_static") as context:
        did = decision(browser, context, complete=True, rule="js_static_snapshot",
                       inputs=(BrowserInput("a" * 64, sha256_hex("<main>safe</main>"), 17, True),),
                       required_inputs=1, **kwargs)
    logger.probe_ledger.write_manifest()
    return did


def status(logger):
    logger.probe_ledger.reconcile_persisted()
    return logger.probe_ledger.completion_summary(["js_static"])["status"]


def test_page_proof_has_no_synthetic_request_and_survives_restore(tmp_path):
    br, logger, unit = prepared(tmp_path)
    finish(br, logger, unit)
    assert status(logger) == "COMPLETE"
    restored = ProbeLedger(tmp_path, tmp_path.name)
    assert restored.completion_summary(["js_static"])["status"] == "COMPLETE"
    assert all(row["request"] is None for row in restored.events.values())
    assert json.loads((tmp_path / "probe_attempts_manifest.json").read_text())["logical_requests"] == 0


@pytest.mark.parametrize("broken", ["parent", "snapshot", "page", "frame", "generation", "outcome", "operation", "body"])
def test_tampered_nonnetwork_chain_cannot_complete(tmp_path, broken):
    br, logger, unit = prepared(tmp_path)
    did = finish(br, logger, unit)
    path = logger.probe_ledger.path
    rows = [json.loads(line) for line in path.read_text().splitlines()]
    decision_row = next(r for r in rows if r["attempt_id"] == did)
    if broken == "parent":
        decision_row["parent_id"] = "foreign:000001"
    elif broken in {"page", "frame", "generation", "snapshot", "operation"}:
        decision_row["browser"][broken + ("_id" if broken != "generation" else "")] = "foreign"
    elif broken == "outcome":
        decision_row["outcome"] = "verification_error"
    else:
        next(r for r in rows if (r.get("browser") or {}).get("kind") == "snapshot")["browser"]["input_length"] = 0
    path.write_text("".join(json.dumps(r) + "\n" for r in rows))
    assert status(logger) != "COMPLETE"


def test_logger_failure_does_not_complete_or_throw(tmp_path):
    br, logger, unit = prepared(tmp_path)
    directory = tmp_path / "blocked"
    directory.mkdir()
    logger.probe_ledger._path = directory
    finish(br, logger, unit)
    assert logger.probe_ledger.quarantined
    assert status(logger) == "EVIDENCE_INCOMPLETE"


@pytest.mark.asyncio
async def test_flow_first_failure_recorded_before_bool_return_without_secret(tmp_path):
    br, logger, _ = prepared(tmp_path)
    class FlowPage(Page):
        async def evaluate(self, *args):
            return {"ok": False}
    br.page = FlowPage()
    seen = []
    flow = ScanFlow("private-name", [FlowStep("fill", field="password", value="secret-sentinel"), FlowStep("wait", timeout=0)])
    assert await FlowRunner(br, recorder=lambda i,t,o: seen.append((i,t,o))).run(flow) is False
    assert seen == [(1, 2, "started"), (1, 2, "unexecutable")]
    assert "secret-sentinel" not in logger.probe_ledger.path.read_text()


@pytest.mark.asyncio
async def test_dialog_captures_origin_before_wait_dedupes_and_cannot_complete_later_unit(tmp_path):
    br, logger, unit = prepared(tmp_path)
    manager = BrowserManager(request_logger=logger)
    manager.page = br.page
    manager._evidence_pages = br._evidence_pages
    manager._evidence_snapshot = br._evidence_snapshot
    class Dialog:
        page = br.page
        message = "secret-sentinel"
        async def dismiss(self):
            pass
    dialog = Dialog()
    with logger.probe_ledger.unit_scope(unit), operation(manager, "js_static") as origin:
        callback = manager._capture_dialog(dialog, manager.page)
    manager.page = Page()
    with logger.probe_ledger.unit_scope(unit), operation(manager, "js_static"):
        await callback
        await manager._on_dialog(dialog, origin)
        assert not getattr(manager, "dialog_fired", False)
    rows = list(logger.probe_ledger.events.values())
    captured = [r for r in rows if (r.get("browser") or {}).get("kind") == "dialog"]
    assert len(captured) == 1
    assert captured[0]["parent_id"] == origin["operation_id"]
    assert captured[0]["browser"]["page_id"] == origin["page_id"]
    assert "secret-sentinel" not in logger.probe_ledger.path.read_text()
    assert not any((r.get("browser") or {}).get("kind") == "decision" for r in rows)
    assert status(logger) != "COMPLETE"


@pytest.mark.asyncio
@pytest.mark.parametrize("html,external,expected", [
    ("<main>safe</main>", {}, "COMPLETE"),
    ('<script src="/missing.js"></script>', {}, "EVIDENCE_INCOMPLETE"),
    ('<script src="/ok.js"></script>', {"http://fixture.test/ok.js":"void 0;"}, "COMPLETE"),
    ("", {}, "EVIDENCE_INCOMPLETE"),
])
async def test_static_input_manifest_zero_references_vs_missing_body(tmp_path, html, external, expected):
    from wscan.scanners.js_static import JsStaticScanner
    br, logger, unit = prepared(tmp_path)
    page = SimpleNamespace(url=Page.url, html=html, external_scripts=external)
    source = emit(br, "page_source", input_hash=sha256_hex(html), input_length=len(html), complete=bool(html))
    snapshot(br, page, source)
    scanner = JsStaticScanner(SimpleNamespace(browser=br, request_logger=logger, monitor=None, payload_gen=None))
    with logger.probe_ledger.unit_scope(unit):
        assert await scanner.scan_page_context(page) == []
    assert status(logger) == expected


@pytest.mark.asyncio
async def test_flow_recorder_error_preserves_execution_and_observes_gap(tmp_path):
    br, logger, _ = prepared(tmp_path)
    def fail(*args):
        raise OSError("secret-sentinel")
    assert await FlowRunner(br, recorder=fail).run(ScanFlow("test", [FlowStep("wait",timeout=0)])) is True
    assert logger.probe_ledger.evidence_incomplete
    assert "secret-sentinel" not in str(logger.probe_ledger.manifest.to_dict())


@pytest.mark.asyncio
@pytest.mark.parametrize("failure", ["none", "exception", "timeout"])
async def test_dom_verification_inability_is_never_negative(tmp_path, failure):
    from unittest.mock import AsyncMock
    from wscan.scanners.dom_xss import DOMXSSScanner
    from wscan.scanners.base import Finding
    br, logger, _ = prepared(tmp_path)
    unit = logger.probe_ledger.expect("verify", "dom_xss", rules=["dom_xss_verify"], role="verify")
    scanner = DOMXSSScanner(SimpleNamespace(browser=br, request_logger=logger, monitor=None, payload_gen=None))
    scanner.log_payload_test = AsyncMock()
    br.reset_dialog = lambda: None
    finding = Finding(check_type="dom_xss", severity="critical", url=Page.url, field_name="q", payload="payload", evidence="", evidence_type="dom_xss_sink")
    if failure != "none":
        finding.evidence_details = {"marker":"__WSCAN_DOMXSS__123"}
        scanner._ensure_hook = AsyncMock(side_effect=TimeoutError() if failure == "timeout" else RuntimeError())
    with logger.probe_ledger.unit_scope(unit):
        assert await scanner.verify_finding(finding) is None
    records = list(logger.probe_ledger.events.values())
    assert any(r["outcome"] == ("unexecutable" if failure == "none" else "timeout" if failure == "timeout" else "verification_error") for r in records)
    assert not any(r["outcome"] == "no_match" and r["check"] == "dom_xss" for r in records)
    assert logger.probe_ledger.completion_summary(["dom_xss"])["status"] != "COMPLETE"


def test_late_network_callback_keeps_captured_operation_after_clear_and_replays_count_once(tmp_path):
    from wscan.browser import NetworkCapture
    from wscan.injection_point import InjectionPoint
    from wscan.request_logger import current_probe
    logger = RequestLogger(tmp_path)
    capture = NetworkCapture(logger)
    frame = object()
    capture.probe_frame = frame
    def request():
        return SimpleNamespace(url=Page.url, method="GET", headers={}, post_data=None,
                               resource_type="document", redirected_from=None, frame=frame)
    a, b = request(), request()
    ip = InjectionPoint.for_url_param(Page.url, "q")
    with logger.probe_scope(ip, "dom_xss", parent_id="operation-a") as ca:
        capture.probe_context = ca
        capture.on_request(a)
    capture.clear()
    with logger.probe_scope(ip, "dom_xss", parent_id="operation-b") as cb:
        capture.probe_context = cb
        capture.on_request(b)
        capture.on_response(SimpleNamespace(request=a, url=Page.url, status=200, headers={}))
        capture.on_request(a)  # replay of the same outgoing object, not another send
        capture.on_response(SimpleNamespace(request=b, url=Page.url, status=200, headers={}))
    records = list(logger.probe_ledger.events.values())
    requests = [r for r in records if r["record_kind"] == "request"]
    assert len(requests) == 2
    assert len(ca["requests"]) == len(cb["requests"]) == 1
    observed = [r for r in records if r["record_kind"] == "observation"]
    assert [r["parent_id"] for r in observed] == [ca["requests"][0], cb["requests"][0]]
