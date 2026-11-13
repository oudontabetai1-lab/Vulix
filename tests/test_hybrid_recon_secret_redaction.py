"""Hybrid Phase 1（Agent 偵察）のライブイベントでも設定済み資格情報を伏せる。

Hybrid は ScanEngine より先に AgentEngine.run_recon を実行するため、Phase 1 の間は
値ベース redaction の登録が無く、偵察中のイベントに資格情報が平文で出ていた。
"""
import asyncio
import json
import sys
from types import SimpleNamespace
from unittest.mock import patch

import pytest
import uvicorn

import main
from wscan import url_scope
from wscan.agent_engine import AgentEngine
from wscan.engine import ScanEngine
from wscan.monitor import MonitorServer

USER = "alice.admin@example.test"
PASSWORD = "Zx9-very-secret"
HEADER_VALUE = "Bearer tok-abcdef-123"


@pytest.fixture(autouse=True)
def _clean_secret_registry():
    url_scope.clear_secret_values()
    yield
    url_scope.clear_secret_values()


class _EventfulScanner:
    """偵察中に資格情報を含むライブイベントを出す偽スキャナ。"""

    def __init__(self, **kwargs):
        self.monitor = kwargs.get("monitor")

    async def run(self):
        if self.monitor is not None:
            await self.monitor.emit_request(
                {
                    "method": "POST",
                    "url": f"http://fixture.test/login?user={USER}",
                    "headers": {"Authorization": HEADER_VALUE},
                    "post_data": json.dumps({"username": USER, "password": PASSWORD}),
                }
            )
            await self.monitor.emit_status(f"{USER} でログイン（{PASSWORD}）")
        return SimpleNamespace(
            error=None,
            success=True,
            findings=[],
            memory=SimpleNamespace(visited_urls=["http://fixture.test/dashboard"]),
            final_summary="recon done",
        )


class _RaisingScanner:
    def __init__(self, **_kwargs):
        pass

    async def run(self):
        raise RuntimeError("recon exploded")


def _event_text(monitor) -> str:
    return json.dumps([event["data"] for event in monitor.event_history], ensure_ascii=False)


@pytest.mark.asyncio
async def test_recon_live_events_mask_configured_credentials(tmp_path):
    # 再現: Phase 1 のイベント履歴に資格情報が平文で残る。
    monitor = MonitorServer()
    engine = AgentEngine(
        url="http://fixture.test",
        llm_provider="none",
        auth_user=USER,
        auth_pass=PASSWORD,
        extra_headers={"Authorization": HEADER_VALUE},
        monitor=monitor,
        output_dir=str(tmp_path),
        open_report=False,
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _EventfulScanner):
        await engine.run_recon()

    text = _event_text(monitor)
    assert USER not in text
    assert PASSWORD not in text
    assert HEADER_VALUE not in text
    assert "[REDACTED:auth_password]" in text


@pytest.mark.asyncio
async def test_recon_clears_registered_values_after_success(tmp_path):
    monitor = MonitorServer()
    engine = AgentEngine(
        url="http://fixture.test",
        llm_provider="none",
        auth_user=USER,
        auth_pass=PASSWORD,
        monitor=monitor,
        output_dir=str(tmp_path),
        open_report=False,
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _EventfulScanner):
        await engine.run_recon()

    # 偵察終了後は登録を残さない（serve の次スキャンへ持ち越さない）。
    assert url_scope.redact_secret_values(PASSWORD) == PASSWORD


@pytest.mark.asyncio
async def test_recon_clears_registered_values_on_error(tmp_path):
    monitor = MonitorServer()
    engine = AgentEngine(
        url="http://fixture.test",
        llm_provider="none",
        auth_user=USER,
        auth_pass=PASSWORD,
        monitor=monitor,
        output_dir=str(tmp_path),
        open_report=False,
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _RaisingScanner):
        with pytest.raises(RuntimeError):
            await engine.run_recon()

    assert url_scope.redact_secret_values(PASSWORD) == PASSWORD


@pytest.mark.asyncio
async def test_phase2_registration_survives_phase1_clear(tmp_path):
    # Phase 1 終了時の clear が Phase 2（ScanEngine 開始時）の登録を消さない順序であること。
    monitor = MonitorServer()
    recon = AgentEngine(
        url="http://fixture.test",
        llm_provider="none",
        auth_user=USER,
        auth_pass=PASSWORD,
        monitor=monitor,
        output_dir=str(tmp_path / "phase1"),
        open_report=False,
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _EventfulScanner):
        await recon.run_recon()
    assert url_scope.redact_secret_values(PASSWORD) == PASSWORD  # Phase 1 はクリア済み

    ScanEngine(
        url="http://fixture.test",
        output_dir=str(tmp_path / "phase2"),
        auth_user=USER,
        auth_pass=PASSWORD,
        headers={"Authorization": HEADER_VALUE},
        fast_mode=True,
    )
    try:
        text = f"pw={PASSWORD} hdr={HEADER_VALUE}"
        assert "[REDACTED:auth_password]" in url_scope.redact_secret_values(text)
        assert HEADER_VALUE not in url_scope.redact_secret_values(text)
    finally:
        url_scope.clear_secret_values()


def test_serve_hybrid_boundary_does_not_emit_plaintext_credentials(tmp_path, monkeypatch):
    """Phase 1 解除 → ScanEngine 構築の境目に資格情報入り URL のイベントを出さない。

    serve の Hybrid 経路（実 run_serve・実 MonitorServer イベント履歴・実 AgentEngine.run_recon・
    実 ScanEngine の構築）で、Phase 1 終了後〜Phase 2 登録完了前に送るステータスイベントが
    平文の資格情報を履歴へ残さないことを固定する。
    """
    password = PASSWORD
    url = f"http://fixture.test/{password}/login"
    monitors: list = []
    done = asyncio.Event()
    server_ref: list = []

    class _FakeServer:
        should_exit = False

        def __init__(self, config):
            server_ref.append(self)

        async def serve(self):
            await done.wait()
            self.should_exit = True

    submitted = False

    async def _awaiting(monitor):
        nonlocal submitted
        monitors.append(monitor)
        if not submitted:
            submitted = True
            monitor.scan_request_data = {
                "url": url,
                "llm": "none",
                "agent_mode": False,
                "hybrid_mode": True,
                "hybrid_llm": "none",
                "auth_user": USER,
                "auth_pass": password,
                "output_dir": str(tmp_path / "out"),
            }
            monitor.scan_request_event.set()

    async def _phase2_run(self):
        # 実 ScanEngine の構築（＝登録）後に送るイベントは伏字化される。
        if self.monitor is not None:
            await self.monitor.emit_status(f"phase2 sees {self.target_url}", "running")
        if server_ref:
            server_ref[0].should_exit = True
        done.set()

    monkeypatch.setattr(uvicorn, "Server", _FakeServer)
    monkeypatch.setattr(MonitorServer, "emit_awaiting_config", _awaiting)
    monkeypatch.setattr(MonitorServer, "prune_old_scans", lambda _: [])
    monkeypatch.setattr(MonitorServer, "trigger_due_schedules", lambda _: None)
    monkeypatch.setattr("wscan.agent_engine.OUTPUT_BASE", tmp_path / "agent_out")
    monkeypatch.setattr(ScanEngine, "run", _phase2_run)
    monkeypatch.setattr(main.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(main, "_CFG", {"report_lang": "ja", "llm_provider": "none"})
    monkeypatch.setattr(
        sys, "argv", ["main.py", "serve", "--host", "127.0.0.1", "--port", "19879"]
    )

    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _EventfulScanner):
        asyncio.run(asyncio.wait_for(main.run_serve(main.parse_args()), timeout=30))

    # 境界の status イベント（Phase 1 解除後〜Phase 2 登録前）に平文を残さない。
    status_text = json.dumps(
        [e["data"] for e in monitors[0].event_history if e["type"] == "status"],
        ensure_ascii=False,
    )
    assert password not in status_text
    assert "[REDACTED:auth_password]" in status_text
