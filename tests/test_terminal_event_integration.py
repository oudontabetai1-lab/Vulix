"""Serve lifecycle integration through real engines and MonitorServer."""
from __future__ import annotations

import asyncio
import contextlib
import socket
import sys
import threading
import time
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest
import uvicorn
from fastapi.testclient import TestClient

import main
from wscan.engine import ScanEngine
from wscan.intervention import AbortScan
from wscan.llm_agent_browser import AgentMemory, AgentScanResult
from wscan.monitor import MonitorServer
from tests.fixtures.vuln_app import create_app


@pytest.fixture(scope="module")
def vuln_fixture_url():
    """One local HTTP fixture is shared by the twelve short serve lifecycles."""
    with contextlib.closing(socket.socket()) as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    fixture_server = uvicorn.Server(
        uvicorn.Config(create_app(), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=fixture_server.run, daemon=True)
    thread.start()
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        try:
            with contextlib.closing(socket.create_connection(("127.0.0.1", port), timeout=.2)):
                break
        except OSError:
            time.sleep(.02)
    else:
        raise RuntimeError("local vulnerable fixture did not start")
    yield f"http://127.0.0.1:{port}/"
    fixture_server.should_exit = True
    thread.join(timeout=5)


@pytest.mark.parametrize("mode", ["scan", "agent", "hybrid"])
@pytest.mark.parametrize("terminal", ["done", "incomplete", "failed", "aborted"])
def test_serve_engine_lifecycle_publishes_one_stable_terminal_pair(
    tmp_path, monkeypatch, mode, terminal, vuln_fixture_url
):
    """Run serve, real ScanEngine/browser against localhost, and fake Agent LLM boundary."""
    server_done = asyncio.Event()
    server_ref = []
    monitors = []
    request = {
        "url": vuln_fixture_url,
        "llm": "none",
        "checks": ["security_headers"],
        "agent_mode": mode == "agent",
        "hybrid_mode": mode == "hybrid",
        "hybrid_llm": "none",
        "headless": True,
        "open_report": False,
        "enable_waf_detection": False,
        "request_delay": 0,
        "depth": 1,
        "timeout": 3,
        "fast_mode": True,
        "max_payloads": 1,
        "enable_ai_analysis": False,
        "enable_payload_learning": False,
        "enable_sitemap_crawl": False,
        "output_dir": str(tmp_path / f"{mode}-{terminal}"),
    }

    class FakeServer:
        should_exit = False

        def __init__(self, config):
            server_ref.append(self)

        async def serve(self):
            await server_done.wait()

    awaiting_calls = 0

    async def submit_one_scan(monitor):
        nonlocal awaiting_calls
        awaiting_calls += 1
        if awaiting_calls == 1:
            monitors.append(monitor)
            monitor.scan_request_data = request
            monitor.scan_request_event.set()
        else:
            server_ref[0].should_exit = True
            server_done.set()

    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setattr(MonitorServer, "emit_awaiting_config", submit_one_scan)
    monkeypatch.setattr(MonitorServer, "prune_old_scans", lambda _: [])
    monkeypatch.setattr(MonitorServer, "trigger_due_schedules", lambda _: None)
    monkeypatch.setattr(MonitorServer, "send_scan_complete_notification", AsyncMock())
    monkeypatch.setattr(main.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(main, "_CFG", {"report_lang": "ja", "llm_provider": "none"})
    monkeypatch.setattr(
        sys, "argv", ["main.py", "serve", "--host", "127.0.0.1", "--port", "0"]
    )

    async def phase_crawl(engine):
        result = await original_phase_crawl(engine)
        if mode == "scan" and terminal == "incomplete":
            engine.authentication_state = {"state": "failure"}
            engine.wave_errors.append("authentication_incomplete:synthetic_transport_failure")
        return result

    original_phase_crawl = ScanEngine._phase_crawl

    async def phase_attack(engine, *_args):
        if terminal == "failed":
            raise RuntimeError("synthetic scanner failure")
        if terminal == "aborted":
            raise AbortScan("synthetic operator abort")

    monkeypatch.setattr(ScanEngine, "_phase_crawl", phase_crawl)
    if terminal in {"failed", "aborted"}:
        monkeypatch.setattr(ScanEngine, "_phase_attack", phase_attack)

    recon_status = "incomplete" if mode == "hybrid" and terminal == "incomplete" else "done"

    class FakeAgentBrowserScanner:
        def __init__(self, **_kwargs):
            self._network_guard_errors = []

        async def run(self):
            status = recon_status if mode == "hybrid" else terminal
            return AgentScanResult(
                target_url=request["url"],
                success=status == "done",
                error="synthetic agent failure" if status == "failed" else None,
                harness_status=status,
                coverage_gaps=["synthetic_recon_gap"] if status == "incomplete" else [],
                memory=AgentMemory(),
            )

    monkeypatch.setattr("wscan.llm_agent_browser.AgentBrowserScanner", FakeAgentBrowserScanner)
    monkeypatch.setattr("wscan.reproduction.write_reproduction_package", lambda *_args, **_kwargs: None)

    args = SimpleNamespace(
        port=0, host="127.0.0.1", auth_token="", insecure=False, open_browser=False,
    )
    asyncio.run(asyncio.wait_for(main.run_serve(args), timeout=20))

    monitor = monitors[0]
    terminal_events = []
    completion_events = []
    terminal_sequence = []
    for event in monitor.event_history:
        data = event.get("data") or {}
        if event.get("type") == "status" and data.get("terminal_outcome"):
            state = data["terminal_outcome"]["status"]
            terminal_events.append(state)
            terminal_sequence.append(("status", state))
        elif event.get("type") == "scan_complete":
            state = data["terminal_outcome"]["status"]
            completion_events.append(state)
            terminal_sequence.append(("scan_complete", state))

    assert terminal_events == [terminal], (mode, terminal, terminal_events)
    assert completion_events == [terminal], (mode, terminal, completion_events)
    assert terminal_sequence == [("status", terminal), ("scan_complete", terminal)]
    assert TestClient(monitor.app).get("/api/v1/scan/status").json()["status"] == terminal
    assert main._scan_exit_code(terminal) == {
        "done": 0, "incomplete": 2, "failed": 1, "aborted": 2,
    }[terminal]
    assert MonitorServer.send_scan_complete_notification.await_count == 1


def test_done_terminal_status_is_not_logged_as_a_second_completion():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    dashboard = (root / "templates/dashboard.html").read_text()
    status_case = dashboard.split("case 'status':", 1)[1].split("case 'page_start':", 1)[0]
    completion_case = dashboard.split("case 'scan_complete':", 1)[1].split("case 'plan_review':", 1)[0]
    assert "if (!data.terminal_outcome) addEventLog('status', data.message)" in status_case
    assert "addEventLog('status', `${outcome.label}. Report: ${data.report_path}`)" in completion_case

    app_entry = (root / "templates/ui/app-entry.js").read_text()
    app_status_bar = app_entry.split("function renderScanStatusBar", 1)[1].split("function ", 1)[0]
    assert "context.replaceChildren()" in app_status_bar
