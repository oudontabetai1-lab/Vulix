"""Exercise the real WebSocket scanner, browser evaluate hooks, and persisted causal evidence."""
import asyncio
import copy
import json
import os
import re
import socket
import tempfile
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock, Mock

import pytest
import uvicorn
from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse

from wscan.browser import BrowserManager
from wscan.engine import ScanEngine
from wscan.probe_ledger import ProbeAttemptRecord, ProbeOutcome, ProbeRole, Transport, sha256_hex
from wscan.probe_recorder import ProbeLedger
from wscan.request_logger import RequestLogger
from wscan.scanners.base import Finding
from wscan.scanners.websocket import WebSocketScanner
from wscan.websocket_evidence import (
    DECISIONS,
    DISCOVERY,
    RULES,
    VERIFY_RULES,
    accepted_decisions,
    subject,
    valid_shape,
)


def persisted(logger: RequestLogger) -> list[dict]:
    if not logger.probe_ledger.path or not logger.probe_ledger.path.exists():
        return []
    return [json.loads(line) for line in logger.probe_ledger.path.read_text().splitlines()]


def make_scanner(logger: RequestLogger) -> WebSocketScanner:
    engine = SimpleNamespace(
        request_logger=logger,
        wave_errors=[],
        sleep_factor=0.0,
        browser=None,
        monitor=None,
        payload_gen=None,
        checks=["websocket"],
    )
    scanner = WebSocketScanner(engine)
    return scanner


def test_websocket_valid_causal_lifecycle(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)

    # 1. Attack that matches (e.g. XSS reflection)
    scanner.browser = SimpleNamespace(page=SimpleNamespace(evaluate=AsyncMock(return_value={
        "terminal": "received",
        "sent": True,
        "frames": ["<script>alert('wsxss')</script>"],
        "close_error": False,
    })))
    res = asyncio.run(scanner._send_ws_message(
        "wss://target.test/ws", "<script>alert('wsxss')</script>",
        role=ProbeRole.ATTACK, rule="websocket_xss_reflection", pattern=r"<script>alert\('wsxss'\)</script>"
    ))
    assert res == ["<script>alert('wsxss')</script>"]
    attack_decision_id = scanner.last_decision_id
    assert attack_decision_id

    # 2. Attack that does not match
    scanner.browser = SimpleNamespace(page=SimpleNamespace(evaluate=AsyncMock(return_value={
        "terminal": "received",
        "sent": True,
        "frames": ["safe plain echo"],
        "close_error": False,
    })))
    asyncio.run(scanner._send_ws_message(
        "wss://target.test/ws", "' OR '1'='1",
        role=ProbeRole.ATTACK, rule="websocket_sqli_error", pattern=r"(?i)(sql|syntax|mysql)"
    ))

    # Verify rows in ledger
    rows = persisted(logger)
    assert len(rows) == 10
    kinds = [r["record_kind"] for r in rows]
    assert kinds == [
        "websocket_attempt", "websocket_request", "websocket_observation", "websocket_cleanup", "websocket_decision",
        "websocket_attempt", "websocket_request", "websocket_observation", "websocket_cleanup", "websocket_decision",
    ]
    # Check outcomes
    assert rows[2]["outcome"] == ProbeOutcome.MATCHED.value
    assert rows[4]["outcome"] == ProbeOutcome.MATCHED.value
    assert rows[7]["outcome"] == ProbeOutcome.NO_MATCH.value
    assert rows[9]["outcome"] == ProbeOutcome.NO_MATCH.value

    # Correlated decisions
    decisions = logger.probe_ledger._correlated_decisions()
    assert len(decisions[""]) == 2
    assert decisions[""][0]["outcome"] == ProbeOutcome.MATCHED.value
    assert decisions[""][1]["outcome"] == ProbeOutcome.NO_MATCH.value

    # Reopen from disk
    restored = ProbeLedger(tmp_path, logger.probe_ledger.scan_id)
    restored_decisions = restored._correlated_decisions()
    assert len(restored_decisions[""]) == 2
    assert not restored.evidence_incomplete


def test_websocket_valid_verify_replay(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)
    ws_url = "wss://target.test/ws"
    payload = "<script>alert('wsxss')</script>"
    pattern = r"<script>alert\('wsxss'\)</script>"
    rule = "websocket_xss_reflection"

    # Attack phase
    scanner.browser = SimpleNamespace(page=SimpleNamespace(evaluate=AsyncMock(return_value={
        "terminal": "received",
        "sent": True,
        "frames": [payload],
        "close_error": False,
    })))
    asyncio.run(scanner._send_ws_message(
        ws_url, payload, role=ProbeRole.ATTACK, rule=rule, pattern=pattern
    ))
    attack_decision_id = scanner.last_decision_id
    subj = scanner.last_decision_subject
    scanner._replay_map[subj] = (ws_url, payload, pattern)

    finding = Finding(
        check_type="websocket",
        severity="high",
        url="http://target.test/page",
        field_name="ws:message",
        payload=payload,
        evidence="ws xss",
        evidence_type=rule,
        evidence_details={
            "ws_url": ws_url,
            "pattern": pattern,
            "sent": payload,
            "decision_subject": subj,
            "source_decision_id": attack_decision_id,
        },
    )

    # Verify phase
    result = asyncio.run(scanner.verify_finding(finding))
    assert result is True
    verify_decision_id = scanner.last_decision_id
    assert verify_decision_id
    assert finding.evidence_details["verification_attempt_ids"] == (verify_decision_id,)

    # Inspect ledger
    rows = persisted(logger)
    verify_rows = [r for r in rows if r["role"] == ProbeRole.VERIFY.value]
    assert len(verify_rows) == 4  # attempt, request, observation, decision (cleanup is cleanup role)
    verify_dec = [r for r in verify_rows if r["record_kind"] == "websocket_decision"][0]
    assert verify_dec["outcome"] == ProbeOutcome.MATCHED.value
    assert attack_decision_id in verify_dec["related_attempt_ids"]

    # Reopened ledger verifies correlation
    decisions = logger.probe_ledger._correlated_decisions()
    accepted = decisions[""]
    assert len(accepted) == 2
    assert accepted[0]["role"] == ProbeRole.ATTACK.value
    assert accepted[1]["role"] == ProbeRole.VERIFY.value


def test_websocket_strict_counterexamples_and_rejections(tmp_path):
    events = {}

    def add_row(kind, **kwargs):
        seq = len(events) + 1
        aid = f"scan1:{seq:06d}"
        row = {
            "scan_id": "scan1",
            "attempt_id": aid,
            "role": kwargs.get("role", "attack"),
            "check": "websocket",
            "actor": "websocket_oracle",
            "decision_version": "1",
            "decision_rule": kwargs.get("rule", "websocket_xss_reflection"),
            "decision_subject": kwargs.get("subject", subject("11"*32, "22"*32, kwargs.get("rule", "websocket_xss_reflection"))),
            "injection_key": kwargs.get("key", f"endpoint_sha256={'11'*32};message_sha256={'22'*32}"),
            "record_kind": kind,
            "parent_id": kwargs.get("parent_id", ""),
            "request_attempt_id": kwargs.get("request_attempt_id", ""),
            "related_attempt_ids": kwargs.get("related_attempt_ids", []),
            "rationale": kwargs.get("rationale", ""),
            "outcome": kwargs.get("outcome", None),
            "request": kwargs.get("request", None),
            "response": kwargs.get("response", None),
            "browser": None,
            "completion_unit": "u1",
            "wave": "",
        }
        events[aid] = row
        return row

    # 1. Missing cleanup causes unit rejection
    events.clear()
    a = add_row("websocket_attempt", rationale="started")
    r = add_row("websocket_request", parent_id=a["attempt_id"],
                request={"transport": "websocket", "method": "SEND", "url": "", "sent": True,
                         "body_hash": "22"*32, "body_length": 5})
    o = add_row("websocket_observation", parent_id=r["attempt_id"], request_attempt_id=r["attempt_id"],
                outcome="matched", rationale="captured_frame",
                request={"transport": "websocket", "method": "SEND", "url": "", "sent": True,
                         "body_hash": "22"*32, "body_length": 5},
                response={"body_hash": "33"*32, "body_length": 10})
    # NO cleanup row!
    d = add_row("websocket_decision", parent_id=a["attempt_id"], request_attempt_id=r["attempt_id"],
                related_attempt_ids=[o["attempt_id"]],
                rationale="terminal=received;frames=1;close_error=0", outcome="matched")
    decisions = accepted_decisions(events)
    assert decisions.get("u1") == []  # poisoned

    # 2. Mismatched decision outcome (observations NO_MATCH, but decision claims MATCHED)
    events.clear()
    a = add_row("websocket_attempt", rationale="started")
    r = add_row("websocket_request", parent_id=a["attempt_id"],
                request={"transport": "websocket", "method": "SEND", "url": "", "sent": True,
                         "body_hash": "22"*32, "body_length": 5})
    o = add_row("websocket_observation", parent_id=r["attempt_id"], request_attempt_id=r["attempt_id"],
                outcome="no_match", rationale="captured_frame",
                request={"transport": "websocket", "method": "SEND", "url": "", "sent": True,
                         "body_hash": "22"*32, "body_length": 5},
                response={"body_hash": "33"*32, "body_length": 10})
    c = add_row("websocket_cleanup", parent_id=a["attempt_id"], role="cleanup", rationale="socket_close_requested")
    d = add_row("websocket_decision", parent_id=a["attempt_id"], request_attempt_id=r["attempt_id"],
                related_attempt_ids=[o["attempt_id"], c["attempt_id"]],
                rationale="terminal=received;frames=1;close_error=0", outcome="matched")
    decisions = accepted_decisions(events)
    assert decisions.get("u1") == []  # poisoned

    # 3. Valid chain is accepted
    d["outcome"] = "no_match"
    decisions = accepted_decisions(events)
    assert len(decisions.get("u1", [])) == 1

    # 4. Late frame arriving from wrong attempt
    events.clear()
    a1 = add_row("websocket_attempt", rationale="started")
    r1 = add_row("websocket_request", parent_id=a1["attempt_id"],
                 request={"transport": "websocket", "method": "SEND", "url": "", "sent": True,
                          "body_hash": "22"*32, "body_length": 5})
    c1 = add_row("websocket_cleanup", parent_id=a1["attempt_id"], role="cleanup", rationale="socket_close_requested")
    d1 = add_row("websocket_decision", parent_id=a1["attempt_id"], request_attempt_id=r1["attempt_id"],
                 related_attempt_ids=[c1["attempt_id"]],
                 rationale="terminal=timeout;frames=0;close_error=0", outcome="timeout")
    # Now late observation arrives claiming r1 as request_attempt_id after d1
    o_late = add_row("websocket_observation", parent_id=r1["attempt_id"], request_attempt_id=r1["attempt_id"],
                     outcome="matched", rationale="captured_frame",
                     request={"transport": "websocket", "method": "SEND", "url": "", "sent": True,
                              "body_hash": "22"*32, "body_length": 5},
                     response={"body_hash": "33"*32, "body_length": 10})
    decisions = accepted_decisions(events)
    assert decisions.get("u1") == []  # late frame poisons or breaks correlation


def test_websocket_failure_terminals(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)

    cases = [
        ({"terminal": "open_error", "sent": False, "frames": [], "close_error": False},
         ProbeOutcome.TRANSPORT_ERROR.value, False),
        ({"terminal": "send_error", "sent": False, "frames": [], "close_error": False},
         ProbeOutcome.TRANSPORT_ERROR.value, False),
        ({"terminal": "timeout", "sent": True, "frames": [], "close_error": False},
         ProbeOutcome.TIMEOUT.value, True),
        ({"terminal": "socket_error", "sent": True, "frames": [], "close_error": False},
         ProbeOutcome.TRANSPORT_ERROR.value, True),
        ({"terminal": "evaluation_error", "sent": False, "frames": [], "close_error": False},
         ProbeOutcome.VERIFICATION_ERROR.value, False),
    ]

    for eval_result, expected_outcome, expected_sent in cases:
        scanner.browser = SimpleNamespace(page=SimpleNamespace(evaluate=AsyncMock(return_value=eval_result)))
        asyncio.run(scanner._send_ws_message("wss://target.test/ws", "test", rule="websocket_os_echo"))
        assert scanner.last_outcome == expected_outcome

    rows = persisted(logger)
    decisions = [r for r in rows if r["record_kind"] == "websocket_decision"]
    assert len(decisions) == len(cases)
    for dec, (case, expected_outcome, expected_sent) in zip(decisions, cases):
        assert dec["outcome"] == expected_outcome
        if expected_sent:
            assert dec["request_attempt_id"] != ""
        else:
            assert dec["request_attempt_id"] == ""


def test_websocket_discovery_and_cleanup(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)

    page_mock = SimpleNamespace(
        on=Mock(),
        remove_listener=Mock(),
        evaluate=AsyncMock(return_value={"terminal": "closed", "sent": False, "frames": [], "close_error": False}),
    )
    scanner.browser = SimpleNamespace(
        page=page_mock,
        navigate=AsyncMock(),
    )

    # 1. Page with 0 WebSockets discovered
    findings = asyncio.run(scanner.scan_page("http://target.test/nowebsocket"))
    assert findings == []
    rows = persisted(logger)
    assert len(rows) == 2  # cleanup + discovery decision
    cln, dec = rows
    assert cln["record_kind"] == "websocket_cleanup"
    assert cln["decision_rule"] == DISCOVERY
    assert dec["record_kind"] == "websocket_decision"
    assert dec["decision_rule"] == DISCOVERY
    assert dec["outcome"] == ProbeOutcome.NO_MATCH.value

    # Correlated decisions accepts discovery NO_MATCH
    decisions = logger.probe_ledger._correlated_decisions()
    assert len(decisions[""]) == 1
    assert decisions[""][0]["outcome"] == ProbeOutcome.NO_MATCH.value


def test_websocket_privacy_sentinel_scan(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)

    secret_token = "SECRET_TOKEN_ALPHA_9999"
    secret_body = "SECRET_PAYLOAD_BODY_7777"
    secret_ws_url = f"wss://target.test/ws?token={secret_token}"

    scanner.browser = SimpleNamespace(page=SimpleNamespace(evaluate=AsyncMock(return_value={
        "terminal": "received",
        "sent": True,
        "frames": [f"reflected: {secret_body}"],
        "close_error": False,
    })))

    asyncio.run(scanner._send_ws_message(
        secret_ws_url, secret_body,
        rule="websocket_xss_reflection", pattern=r"reflected:"
    ))

    # Inspect persisted files on disk
    jsonl_content = logger.probe_ledger.path.read_text()
    assert secret_token not in jsonl_content, "Secret token leaked into probe_attempts.jsonl"
    assert secret_body not in jsonl_content, "Raw payload body leaked into probe_attempts.jsonl"
    assert "reflected: " not in jsonl_content, "Raw response body leaked into probe_attempts.jsonl"

    rows = persisted(logger)
    req = [r for r in rows if r["record_kind"] == "websocket_request"][0]
    obs = [r for r in rows if r["record_kind"] == "websocket_observation"][0]

    # Verify hashes and lengths only
    assert req["request"]["url"] == ""
    assert req["request"]["body_hash"] == sha256_hex(secret_body)
    assert req["request"]["body_length"] == len(secret_body)
    assert obs["response"]["body_hash"] == sha256_hex(f"reflected: {secret_body}")
    assert obs["response"]["body_length"] == len(f"reflected: {secret_body}")


def test_websocket_logger_append_error_quarantines(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)

    # Inject append error
    logger.probe_ledger.append = Mock(return_value=False)

    scanner.browser = SimpleNamespace(page=SimpleNamespace(evaluate=AsyncMock(return_value={
        "terminal": "received", "sent": True, "frames": ["hello"], "close_error": False
    })))

    asyncio.run(scanner._send_ws_message("wss://target.test/ws", "hello"))

    # Scanner completes without unhandled exception, but ledger notes write error
    assert logger.probe_ledger.manifest.write_errors


def test_websocket_resume_missing_replay_context(tmp_path):
    logger = RequestLogger(tmp_path)
    scanner = make_scanner(logger)

    finding = Finding(
        check_type="websocket",
        severity="high",
        url="http://target.test/page",
        field_name="ws:message",
        payload="{{7*7}}",
        evidence="ws ssti",
        evidence_type="websocket_ssti_eval",
        evidence_details={
            "ws_url": "wss://target.test/ws",
            "pattern": "49",
            "sent": "{{7*7}}",
            "decision_subject": "aa"*32,
            "source_decision_id": "scan1:000005",
        },
    )

    # Replay map is empty (e.g. fresh scanner after resume from checkpoint)
    res = asyncio.run(scanner.verify_finding(finding))
    assert res is None  # Cannot fabricate replay

    rows = persisted(logger)
    assert len(rows) == 1
    dec = rows[0]
    assert dec["record_kind"] == "websocket_decision"
    assert dec["outcome"] == ProbeOutcome.UNEXECUTABLE.value
    assert "missing_replay_context" in dec["rationale"]


def chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as p:
            b = p.chromium.launch()
            b.close()
        return True
    except Exception:
        return False


requires_chromium = pytest.mark.skipif(not chromium_available(), reason="Chromium required")


@pytest.fixture(scope="module")
def ws_server():
    app = FastAPI()

    @app.websocket("/ws/vuln")
    async def ws_vuln(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                msg = await ws.receive_text()
                if "wsxss" in msg:
                    await ws.send_text(f"echo: {msg}")
                elif "1'='1" in msg or "UNION SELECT" in msg:
                    await ws.send_text("syntax error near sqlite statement")
                elif "wsostest" in msg:
                    await ws.send_text("output: wsostest123")
                elif "7*7" in msg:
                    await ws.send_text("eval: 49")
                else:
                    await ws.send_text(f"echo: {msg}")
        except WebSocketDisconnect:
            pass

    @app.websocket("/ws/safe")
    async def ws_safe(ws: WebSocket):
        await ws.accept()
        try:
            while True:
                msg = await ws.receive_text()
                await ws.send_text("safe fixed response")
        except WebSocketDisconnect:
            pass

    @app.get("/vuln_page", response_class=HTMLResponse)
    async def vuln_page():
        return """
        <!DOCTYPE html>
        <html><body>
        <h1>Vulnerable WebSocket Test</h1>
        <script>
            const ws = new WebSocket("ws://" + location.host + "/ws/vuln");
            ws.onopen = () => { ws.send(JSON.stringify({message: "init"})); };
        </script>
        </body></html>
        """

    @app.get("/safe_page", response_class=HTMLResponse)
    async def safe_page():
        return """
        <!DOCTYPE html>
        <html><body>
        <h1>Safe WebSocket Test</h1>
        <script>
            const ws = new WebSocket("ws://" + location.host + "/ws/safe");
            ws.onopen = () => { ws.send(JSON.stringify({message: "init"})); };
        </script>
        </body></html>
        """

    @app.get("/nowebsocket", response_class=HTMLResponse)
    async def no_ws_page():
        return """<!DOCTYPE html><html><body><h1>No WebSocket</h1></body></html>"""

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, log_level="error"))
    thread = threading.Thread(target=lambda: server.run(sockets=[sock]), daemon=True)
    thread.start()

    deadline = time.monotonic() + 5
    while not server.started:
        time.sleep(0.01)
        if time.monotonic() > deadline:
            break

    try:
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()


@pytest.mark.asyncio
async def test_websocket_engine_verify_confirmation(tmp_path):
    output_dir = tmp_path / "engine_verify"
    output_dir.mkdir(parents=True, exist_ok=True)
    engine = ScanEngine("http://fixture.test/", checks=["websocket"], output_dir=str(output_dir))
    scanner = WebSocketScanner(engine)
    engine.scanners["websocket"] = scanner

    ws_url = "wss://fixture.test/ws"
    payload = "<script>alert('wsxss')</script>"
    pattern = r"<script>alert\('wsxss'\)</script>"
    rule = "websocket_xss_reflection"
    endpoint_hash = sha256_hex(ws_url)
    message_hash = sha256_hex(payload)
    subj = subject(endpoint_hash, message_hash, rule)

    # 1. Without correlated attack decision in ledger, verify cannot reproduce -> "assumed"
    finding = Finding(
        check_type="websocket",
        severity="high",
        url="http://fixture.test/page",
        field_name="ws:message",
        payload=payload,
        evidence="ws xss",
        evidence_type=rule,
        evidence_details={
            "ws_url": ws_url,
            "pattern": pattern,
            "sent": payload,
            "decision_subject": subj,
            "source_decision_id": "nonexistent:000001",
        },
    )
    result = await engine._verify_one(finding)
    assert result == "assumed"


@requires_chromium
@pytest.mark.asyncio
async def test_websocket_scanner_with_real_server_and_chromium(ws_server, tmp_path):
    output_dir = tmp_path / "ws_scan_output"
    output_dir.mkdir(parents=True, exist_ok=True)

    engine = ScanEngine(
        ws_server,
        checks=["websocket"],
        output_dir=str(output_dir),
    )
    engine.sleep_factor = 0.2
    scanner = WebSocketScanner(engine)
    engine.scanners["websocket"] = scanner
    browser_manager = BrowserManager(headless=True)
    engine._browser = browser_manager
    scanner.browser = browser_manager
    await browser_manager.init()

    try:
        # 1. Scan vulnerable page
        vuln_url = f"{ws_server}/vuln_page"
        findings = await scanner.scan_page(vuln_url)
        assert len(findings) > 0, "Vulnerable page should produce Findings"
        types = {f.evidence_type for f in findings}
        assert "websocket_xss_reflection" in types

        # Verify a finding using scanner.verify_finding
        finding_to_verify = findings[0]
        verified = await scanner.verify_finding(finding_to_verify)
        assert verified is True

        # 2. Scan safe page
        safe_url = f"{ws_server}/safe_page"
        safe_findings = await scanner.scan_page(safe_url)
        assert len(safe_findings) == 0, "Safe page must produce 0 findings"

        # 3. Scan page without WebSocket
        nowebsocket_url = f"{ws_server}/nowebsocket"
        no_ws_findings = await scanner.scan_page(nowebsocket_url)
        assert len(no_ws_findings) == 0

        # Verify persisted ledger
        rows = persisted(engine.request_logger)
        assert len(rows) > 0
        kinds = {r["record_kind"] for r in rows}
        assert "websocket_discovery" in kinds
        assert "websocket_attempt" in kinds
        assert "websocket_request" in kinds
        assert "websocket_observation" in kinds
        assert "websocket_cleanup" in kinds
        assert "websocket_decision" in kinds

        # Reopen from disk
        ledger = ProbeLedger(output_dir, engine.request_logger.probe_ledger.scan_id)
        decisions = ledger._correlated_decisions()
        assert len(decisions) > 0
        assert not ledger.evidence_incomplete

    finally:
        await browser_manager.close()
