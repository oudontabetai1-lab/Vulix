import asyncio
import sys
from unittest.mock import MagicMock
import pytest
import uvicorn
import main
from wscan.monitor import MonitorServer


@pytest.mark.parametrize("mode", ["agent", "hybrid"])
def test_agent_and_hybrid_phase1_kwargs_propagation(tmp_path, monkeypatch, mode):
    captured_kwargs = []
    done = asyncio.Event()
    server_ref = []

    class FakeServer:
        should_exit = False

        def __init__(self, config):
            server_ref.append(self)

        async def serve(self):
            await done.wait()
            self.should_exit = True

    is_agent = mode == "agent"
    scan_data = {
        "url": "http://fixture.test/",
        "llm": "none",
        "agent_mode": is_agent,
        "hybrid_mode": not is_agent,
        "mfa_totp_secret": "JBSWY3DPEHPK3PXP",
        "storage_state": "/path/to/storage.json",
        "target_urls": ["http://fixture.test/api"],
        "access_urls": ["http://fixture.test/login"],
        "exclude_urls": ["http://fixture.test/logout"],
        "exclude_fields": ["csrf_token"],
    }

    submitted = False

    async def awaiting(monitor):
        nonlocal submitted
        if not submitted:
            submitted = True
            monitor.scan_request_data = scan_data
            monitor.scan_request_event.set()

    class FakeAgentEngine:
        def __init__(self, **kwargs):
            captured_kwargs.append(kwargs)
            self.output_dir = tmp_path

        async def run(self):
            if server_ref:
                server_ref[0].should_exit = True
            done.set()
            return MagicMock(error=None, success=True, findings=[])

        async def run_recon(self):
            if server_ref:
                server_ref[0].should_exit = True
            done.set()
            from wscan.agent_engine import AgentHandoffData
            return AgentHandoffData(discovered_urls=["http://fixture.test/"])

    class FakeScanEngine:
        def __init__(self, **kwargs):
            self.output_dir = tmp_path

        async def run(self):
            return

    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setattr(MonitorServer, "emit_awaiting_config", awaiting)
    monkeypatch.setattr(MonitorServer, "prune_old_scans", lambda _: [])
    monkeypatch.setattr(MonitorServer, "trigger_due_schedules", lambda _: None)
    monkeypatch.setattr("wscan.agent_engine.AgentEngine", FakeAgentEngine)
    monkeypatch.setattr("wscan.engine.ScanEngine", FakeScanEngine)
    monkeypatch.setattr(main.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(main, "_CFG", {"report_lang": "ja", "llm_provider": "none"})
    monkeypatch.setattr(sys, "argv", ["main.py", "serve", "--host", "127.0.0.1", "--port", "19876"])

    asyncio.run(asyncio.wait_for(main.run_serve(main.parse_args()), timeout=5))

    assert len(captured_kwargs) >= 1
    kw = captured_kwargs[0]
    assert kw["totp_secret"] == "JBSWY3DPEHPK3PXP"
    assert kw["storage_state"] == "/path/to/storage.json"
    assert kw["target_urls"] == ["http://fixture.test/api"]
    assert kw["access_urls"] == ["http://fixture.test/login"]
    assert kw["exclude_urls"] == ["http://fixture.test/logout"]
    assert kw["exclude_fields"] == ["csrf_token"]


def test_agent_receives_direct_totp_secret_key(tmp_path, monkeypatch):
    captured_kwargs = []
    done = asyncio.Event()
    server_ref = []

    class FakeServer:
        should_exit = False

        def __init__(self, config):
            server_ref.append(self)

        async def serve(self):
            await done.wait()
            self.should_exit = True

    scan_data = {
        "url": "http://fixture.test/",
        "llm": "none",
        "agent_mode": True,
        "totp_secret": "DIRECTSECRET123",
        "storage_state": "state.json",
    }

    submitted = False

    async def awaiting(monitor):
        nonlocal submitted
        if not submitted:
            submitted = True
            monitor.scan_request_data = scan_data
            monitor.scan_request_event.set()

    class FakeAgentEngine:
        def __init__(self, **kwargs):
            captured_kwargs.append(kwargs)
            self.output_dir = tmp_path

        async def run(self):
            if server_ref:
                server_ref[0].should_exit = True
            done.set()
            return MagicMock(error=None, success=True, findings=[])

    monkeypatch.setattr(uvicorn, "Server", FakeServer)
    monkeypatch.setattr(MonitorServer, "emit_awaiting_config", awaiting)
    monkeypatch.setattr(MonitorServer, "prune_old_scans", lambda _: [])
    monkeypatch.setattr(MonitorServer, "trigger_due_schedules", lambda _: None)
    monkeypatch.setattr("wscan.agent_engine.AgentEngine", FakeAgentEngine)
    monkeypatch.setattr(main.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(main, "_CFG", {"report_lang": "ja", "llm_provider": "none"})
    monkeypatch.setattr(sys, "argv", ["main.py", "serve", "--host", "127.0.0.1", "--port", "19877"])

    asyncio.run(asyncio.wait_for(main.run_serve(main.parse_args()), timeout=5))

    assert len(captured_kwargs) == 1
    assert captured_kwargs[0]["totp_secret"] == "DIRECTSECRET123"
    assert captured_kwargs[0]["storage_state"] == "state.json"
    assert captured_kwargs[0]["target_urls"] == []
    assert captured_kwargs[0]["access_urls"] == []
    assert captured_kwargs[0]["exclude_urls"] == []
    assert captured_kwargs[0]["exclude_fields"] == []
