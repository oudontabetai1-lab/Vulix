"""Agent 初期化失敗を正常な 0 findings と誤表示しないことを検証する。"""

import sys
from io import StringIO
from types import SimpleNamespace
from unittest.mock import patch

import pytest
from rich.console import Console

import main
from wscan.llm_agent_browser import (
    AgentBrowserScanner,
    _agent_config_directory_result,
)


def test_agent_config_directory_result_accepts_writable_directory():
    assert _agent_config_directory_result("/writable/config", True) == (True, "")


def test_agent_config_directory_result_has_actionable_xdg_guidance():
    ok, message = _agent_config_directory_result("/read-only/config", False)

    assert ok is False
    assert "/read-only/config" in message
    assert "XDG_CONFIG_HOME" in message
    assert "書込み可能" in message


def test_agent_exit_code_flags_errors_and_unsuccessful_empty_runs():
    # 明示エラー → 1。
    assert main._agent_exit_code(
        SimpleNamespace(error="initialization failed", success=False, findings=[])
    ) == 1
    # 正常成功（success=True）→ 0。
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=True, findings=[])
    ) == 0
    # history 上の非成功 かつ 0 findings は incomplete → 2。
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=False, findings=[])
    ) == 2
    # partial/incomplete の findings は保持するが終了状態は非成功 → 2。
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=False, findings=[object()])
    ) == 2
    assert main._agent_exit_code(None) == 0
    assert main._agent_exit_code(
        SimpleNamespace(error="", success=False, findings=[object()], harness_status="partial")
    ) == 2


@pytest.mark.asyncio
async def test_agent_initialization_error_prints_failed_not_zero_findings():
    output = StringIO()
    scanner = AgentBrowserScanner(target_url="http://fixture.test")

    with patch(
        "wscan.llm_agent_browser.check_agent_config_directory",
        return_value=(True, ""),
    ), patch(
        "wscan.llm_agent_browser._build_llm",
        side_effect=RuntimeError("provider unavailable"),
    ), patch(
        "wscan.llm_agent_browser.console",
        Console(file=output, force_terminal=False, color_system=None),
    ):
        result = await scanner.run()

    rendered = output.getvalue()
    assert result.error == "provider unavailable"
    assert main._agent_exit_code(result) == 1
    assert "Scan failed: provider unavailable" in rendered
    assert "脆弱性は検出されませんでした" not in rendered
    assert "0 findings" not in rendered


@pytest.mark.asyncio
async def test_agent_missing_browser_use_is_failed_not_traceback():
    # browser-use 未導入は _build_llm が ModuleNotFoundError(ImportError)を投げる。
    # traceback で漏らさず FAILED＋非0 exit にする。
    output = StringIO()
    scanner = AgentBrowserScanner(target_url="http://fixture.test")
    with patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, ""),
    ), patch(
        "wscan.llm_agent_browser._build_llm",
        side_effect=ModuleNotFoundError("No module named 'browser_use'"),
    ), patch(
        "wscan.llm_agent_browser.console",
        Console(file=output, force_terminal=False, color_system=None),
    ):
        result = await scanner.run()

    assert result.error is not None
    assert main._agent_exit_code(result) == 1
    assert "Scan failed" in output.getvalue()


@pytest.mark.asyncio
async def test_agent_unsuccessful_history_is_incomplete_not_clean(monkeypatch):
    # browser-use が例外でなく history.is_successful()=False で失敗を報告し、findings が
    # 空のとき、「正常完了・0 findings」と誤表示せず INCOMPLETE＋非0 exit にする。
    import types
    from wscan.monitor import MonitorServer

    output = StringIO()

    class _FakeHistory:
        def is_successful(self):
            return False

        def final_result(self):
            return ""

        def extracted_content(self):
            return []

        def errors(self):
            return []

        def model_actions(self):
            return []

        def urls(self):
            return []

    class _FakeAgent:
        def __init__(self, **_kwargs):
            pass

        async def run(self, **_kwargs):
            return _FakeHistory()

    class _FakeBrowser:
        def __init__(self, **_kwargs):
            pass

        async def stop(self):
            return None

    browser_use = types.ModuleType("browser_use")
    browser_use.Agent = _FakeAgent
    browser_use.Browser = _FakeBrowser
    browser_use.BrowserSession = _FakeBrowser
    profile = types.ModuleType("browser_use.browser.profile")
    profile.BrowserProfile = type("FakeBrowserProfile", (), {"__init__": lambda self, **_kwargs: None})

    monitor = MonitorServer()
    scanner = AgentBrowserScanner(target_url="http://fixture.test", monitor=monitor)
    monkeypatch.setitem(sys.modules, "browser_use", browser_use)
    monkeypatch.setitem(sys.modules, "browser_use.browser.profile", profile)

    async def guard_ready(_session):
        return True

    monkeypatch.setattr(scanner, "_enable_request_scoped_headers", guard_ready)
    monkeypatch.setattr(scanner, "_enable_agent_network_guard", guard_ready)
    with patch(
        "wscan.llm_agent_browser.check_agent_config_directory", return_value=(True, ""),
    ), patch(
        "wscan.llm_agent_browser._build_llm", return_value=object(),
    ), patch(
        "wscan.llm_agent_browser.console",
        Console(file=output, force_terminal=False, color_system=None),
    ):
        result = await scanner.run()

    rendered = output.getvalue()
    assert result.error is None
    assert result.success is False
    assert not result.findings
    assert main._agent_exit_code(result) == 2
    assert monitor.api_scan_status == "incomplete"
    assert monitor._terminal_outcome()["status"] == "incomplete"
    assert "Scan incomplete" in rendered
    assert "Scan complete" not in rendered
    assert "脆弱性は検出されませんでした" not in rendered



@pytest.mark.asyncio
async def test_monitored_agent_incomplete_empty_returns_before_sleep(monkeypatch):
    # monitored 経路（ダッシュボード有り）でも、incomplete-empty（success=False かつ
    # 0 findings）のとき sleep(3600) に入らず result を返し、_agent_exit_code が非0を
    # 返せることを検証する。early-return 条件を
    # `result.error` だけにしていると、Ctrl+C 待ちの sleep に落ちて非0 exit が消える。
    import types

    sleep_calls: list = []

    async def _fake_sleep(delay, *a, **k):
        sleep_calls.append(delay)
        return None

    incomplete = SimpleNamespace(error=None, success=False, findings=[])

    class _FakeEngine:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            return incomplete

    class _FakeMonitor:
        def __init__(self, **_kwargs):
            self.app = object()

    class _FakeConfig:
        def __init__(self, **_kwargs):
            pass

    class _FakeServer:
        def __init__(self, config):
            self.should_exit = False

        async def serve(self):
            return None

    fake_uvicorn = types.SimpleNamespace(Config=_FakeConfig, Server=_FakeServer)

    args = SimpleNamespace(
        url="http://fixture.test",
        llm="none",
        model="",
        ollama_url="http://localhost:11434",
        llm_base_url="",
        checks=["xss"],
        no_headless=True,
        auth_user="",
        auth_pass="",
        login_url="",
        max_steps=1,
        output="",
        open_report=False,
        no_open_report=True,
        no_monitor=False,
        port=9099,
        header_file="",
        bearer="",
        header=[],
    )

    monkeypatch.setitem(sys.modules, "uvicorn", fake_uvicorn)
    with patch(
        "wscan.monitor.MonitorServer", _FakeMonitor
    ), patch(
        "wscan.agent_engine.AgentEngine", _FakeEngine
    ), patch(
        "main.webbrowser.open", lambda *a, **k: None
    ), patch(
        "main.asyncio.sleep", _fake_sleep
    ):
        result = await main.run_agent(args)

    assert result is incomplete
    assert main._agent_exit_code(result) == 2
    # sleep(3600)（Ctrl+C 待ち）へは絶対に入らない。
    assert 3600 not in sleep_calls


@pytest.mark.asyncio
async def test_monitored_agent_cancel_publishes_aborted_outcome(monkeypatch):
    import asyncio
    import types

    class _FakeEngine:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            raise asyncio.CancelledError

    class _FakeMonitor:
        instances = []

        def __init__(self, **_kwargs):
            self.app = object()
            self.events = []
            self.__class__.instances.append(self)

        async def emit_status(self, message, state):
            self.events.append((message, state))

    class _FakeConfig:
        def __init__(self, **_kwargs):
            pass

    class _FakeServer:
        def __init__(self, _config):
            self.should_exit = False

        async def serve(self):
            return None

    args = SimpleNamespace(
        url="http://fixture.test", llm="none", model="", ollama_url="http://localhost:11434",
        llm_base_url="", checks=["xss"], no_headless=True, auth_user="", auth_pass="",
        login_url="", max_steps=1, output="", open_report=False, no_open_report=True,
        no_monitor=False, port=9099, header_file="", bearer="", header=[],
    )
    monkeypatch.setitem(
        sys.modules, "uvicorn", types.SimpleNamespace(Config=_FakeConfig, Server=_FakeServer)
    )
    with patch("wscan.monitor.MonitorServer", _FakeMonitor), patch(
        "wscan.agent_engine.AgentEngine", _FakeEngine
    ), patch("main.webbrowser.open", lambda *_a, **_k: None):
        result = await main.run_agent(args)

    assert result.harness_status == "cancelled"
    assert args._scan_terminal_status == "aborted"
    assert main._agent_exit_code(result) == 2
    assert _FakeMonitor.instances[-1].events[-1][1] == "aborted"


@pytest.mark.asyncio
async def test_run_recon_raises_on_hard_error_for_hybrid_fallback(tmp_path):
    # Hybrid Phase 1: browser-use 未導入等で scanner.run() が result.error を立てたとき、
    # run_recon は「偵察完了」と誤表示せず送出する。呼び出し側の Hybrid 失敗ブランチ
    # （seed 無しで Phase 2 続行＋警告）が使われる。
    from wscan.agent_engine import AgentEngine

    class _FailingScanner:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            return SimpleNamespace(
                error="No module named 'browser_use'",
                success=False,
                findings=[],
                memory=SimpleNamespace(visited_urls=[]),
                final_summary="",
            )

    engine = AgentEngine(url="http://fixture.test", llm_provider="none",
                         output_dir=str(tmp_path))
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _FailingScanner):
        with pytest.raises(RuntimeError, match="Agent recon failed"):
            await engine.run_recon()


@pytest.mark.asyncio
async def test_run_recon_returns_handoff_on_success(tmp_path):
    # 正常時（error なし）は従来どおり handoff を返す（回帰防止）。
    from wscan.agent_engine import AgentEngine

    class _OkScanner:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            return SimpleNamespace(
                error=None,
                success=True,
                findings=[],
                memory=SimpleNamespace(visited_urls=["http://fixture.test/a"]),
                final_summary="done",
            )

    engine = AgentEngine(url="http://fixture.test", llm_provider="none",
                         output_dir=str(tmp_path))
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _OkScanner):
        handoff = await engine.run_recon()

    assert "http://fixture.test" in handoff.discovered_urls
    assert "http://fixture.test/a" in handoff.discovered_urls


@pytest.mark.asyncio
async def test_run_recon_raises_on_unsuccessful_empty(tmp_path):
    # 例外を投げずに step 上限/失敗で終わり（error=None・success=False・URL/findings 無し）
    # の INCOMPLETE 偵察は「偵察完了」と誤表示せず送出する。
    from wscan.agent_engine import AgentEngine

    class _IncompleteScanner:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            return SimpleNamespace(
                error=None,
                success=False,
                findings=[],
                memory=SimpleNamespace(visited_urls=[]),
                final_summary="",
            )

    engine = AgentEngine(url="http://fixture.test", llm_provider="none",
                         output_dir=str(tmp_path))
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _IncompleteScanner):
        with pytest.raises(RuntimeError, match="incomplete"):
            await engine.run_recon()


@pytest.mark.asyncio
async def test_run_recon_keeps_partial_recon_urls_when_unsuccessful(tmp_path):
    # success=False でも URL を発見していれば partial recon として有効（到達性の価値を
    # 捨てない）。target-only でない handoff は送出せず返す。
    from wscan.agent_engine import AgentEngine

    class _PartialScanner:
        def __init__(self, **_kwargs):
            pass

        async def run(self):
            return SimpleNamespace(
                error=None,
                success=False,
                findings=[],
                memory=SimpleNamespace(
                    visited_urls=["http://fixture.test/a", "http://fixture.test/b"]
                ),
                final_summary="partial",
            )

    engine = AgentEngine(url="http://fixture.test", llm_provider="none",
                         output_dir=str(tmp_path))
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", _PartialScanner):
        handoff = await engine.run_recon()

    assert "http://fixture.test/a" in handoff.discovered_urls
    assert "http://fixture.test/b" in handoff.discovered_urls
