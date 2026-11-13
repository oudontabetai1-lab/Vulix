"""値ベース redaction 登録のライフサイクル（serve の開始失敗・409・次スキャン）。

`scan_started` はエンジン構築前に配信されるため、配信前に資格情報を登録する。
その代償として、開始が途中で失敗すると登録値がプロセスに残る。serve は
「受理した境界」と「終了時の finally」で登録を捨て、409（既に実行中）では
走行中スキャンの登録に触れないことを固定する。
"""
import asyncio
import socket
import sys

import pytest
import uvicorn
from fastapi.testclient import TestClient

import main
from wscan import url_scope
from wscan.engine import ScanEngine
from wscan.monitor import MonitorServer

USER = "alice.admin@example.test"
PASSWORD = "Zx9-very-secret"


@pytest.fixture(autouse=True)
def _clean_registry():
    url_scope.clear_secret_values()
    yield
    url_scope.clear_secret_values()


def _free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def test_conflict_does_not_clear_running_scan_registration():
    """409（実行中）は開始境界へ到達しない＝走行中スキャンの登録を壊さない。"""
    monitor = MonitorServer(port=0, auth_token="")
    monitor.scan_in_progress = True
    url_scope.register_secret_values([("auth_user", USER)])

    res = TestClient(monitor.app).post("/api/v1/scan", json={"url": "http://t.test/"})

    assert res.status_code == 409
    assert url_scope.redact_secret_values(USER) == "[REDACTED:auth_user]"


def test_invalid_start_does_not_leak_registration_into_next_start(tmp_path, monkeypatch):
    """検証エラーで開始できなかった後、登録値が残らず次の開始が正しく動く。"""
    observed: list[tuple[str, str]] = []
    done = asyncio.Event()
    server_ref: list = []
    awaiting_calls = {"n": 0}

    class _FakeServer:
        should_exit = False

        def __init__(self, config):
            server_ref.append(self)

        async def serve(self):
            await done.wait()
            self.should_exit = True

    def _config(output_name: str, **overrides) -> dict:
        cfg = {
            "url": "http://fixture.test/",
            "llm": "none",
            "agent_mode": False,
            "hybrid_mode": False,
            "checks": ["xss"],
            "auth_user": USER,
            "auth_pass": PASSWORD,
            "login_success_indicator": USER,
            "output_dir": str(tmp_path / output_name),
        }
        cfg.update(overrides)
        return cfg

    async def _awaiting(monitor):
        awaiting_calls["n"] += 1
        if awaiting_calls["n"] == 1:
            observed.append(("before-first-start", url_scope.redact_secret_values(USER)))
            # タイムアウト不正 → scan_started 配信後に検証エラーで開始できない。
            monitor.scan_request_data = _config("invalid", timeout=-1)
            monitor.scan_request_event.set()
        elif awaiting_calls["n"] == 2:
            # 失敗した開始の登録が残っていないこと（ここが回帰の主眼）。
            observed.append(("after-failed-start", url_scope.redact_secret_values(USER)))
            monitor.scan_request_data = _config("valid")
            monitor.scan_request_event.set()
        else:
            if server_ref:
                server_ref[0].should_exit = True
            done.set()

    async def _run(self):
        # 受理されたスキャンでは engine が同じ資格情報を登録し直している。
        observed.append(("during-valid-scan", url_scope.redact_secret_values(USER)))
        if server_ref:
            server_ref[0].should_exit = True
        done.set()

    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    monkeypatch.setattr(MonitorServer, "emit_awaiting_config", _awaiting)
    monkeypatch.setattr(MonitorServer, "prune_old_scans", lambda _: [])
    monkeypatch.setattr(MonitorServer, "trigger_due_schedules", lambda _: None)
    monkeypatch.setattr("wscan.agent_engine.OUTPUT_BASE", tmp_path / "agent_out")
    monkeypatch.setattr(ScanEngine, "run", _run)
    monkeypatch.setattr(main.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(main, "_CFG", {"report_lang": "ja", "llm_provider": "none"})
    monkeypatch.setattr(
        sys,
        "argv",
        ["main.py", "serve", "--host", "127.0.0.1", "--port", str(_free_port())],
    )

    asyncio.run(asyncio.wait_for(main.run_serve(main.parse_args()), timeout=60))

    assert observed == [
        ("before-first-start", USER),                 # 開始前は未登録
        ("after-failed-start", USER),                 # 失敗した開始の登録は残らない
        ("during-valid-scan", "[REDACTED:auth_user]"),  # 次の開始は正しく登録される
    ]