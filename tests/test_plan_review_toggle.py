"""プラン手動レビュー（planner.interactive）の設定がダッシュボード実行でも守られること。"""
import asyncio
from unittest.mock import AsyncMock

from wscan.monitor import MonitorServer
from tests.test_api_first_planner import _planner_engine


class _FakeMonitor:
    def __init__(self, edits=None):
        self.emit_status = AsyncMock()
        self.emit_plan_review = AsyncMock()
        self.wait_for_plan_confirm = AsyncMock(return_value=edits or {})


_FORMS = [{"inputs": [{"name": "q", "type": "text"}]}]


def _run(interactive: bool):
    engine, _, pages = _planner_engine(forms=_FORMS)
    engine.interactive_plan = interactive
    engine.monitor = _FakeMonitor()
    plans = asyncio.run(engine._phase_plan(pages))
    return engine.monitor, plans


def test_non_interactive_dashboard_scan_does_not_wait_for_plan_confirm():
    monitor, plans = _run(False)
    assert plans  # 計画は生成され、そのまま攻撃へ進む
    monitor.wait_for_plan_confirm.assert_not_awaited()
    monitor.emit_plan_review.assert_not_awaited()  # 確認モーダル（Start Attack）を出さない
    assert "自動で攻撃を開始" in monitor.emit_status.await_args.args[0]


def test_interactive_dashboard_scan_still_blocks_on_plan_confirm():
    monitor, plans = _run(True)
    assert plans
    monitor.emit_plan_review.assert_awaited_once()
    monitor.wait_for_plan_confirm.assert_awaited_once()


def test_plan_confirm_timeout_says_scan_continues_and_clears_pending_review():
    srv = MonitorServer(port=0, auth_token="")
    asyncio.run(srv.emit_plan_review([{"url": "http://x/"}]))
    messages = []

    async def _status(message, level="info"):
        messages.append(message)

    srv.emit_status = _status
    edits = asyncio.run(srv.wait_for_plan_confirm(timeout=0.01))
    assert edits == {}
    assert srv.pending_interactive is None  # 再接続時に古いモーダルを出さない
    assert "継続" in messages[0] or "continu" in messages[0]


def test_plan_confirm_timeout_ignores_previous_scan_edits():
    srv = MonitorServer(port=0, auth_token="")
    srv.confirmed_plan_edits = {"http://old/": {"q": {"skip": True}}}
    srv.emit_status = AsyncMock()
    assert asyncio.run(srv.wait_for_plan_confirm(timeout=0.01)) == {}


def test_new_scan_resets_previous_plan_confirmation_state():
    srv = MonitorServer(port=0, auth_token="")
    srv._handle_client_message('{"action":"plan_confirm","edits":{"http://old/":{}}}')
    assert srv.plan_confirm_event.is_set() and srv.confirmed_plan_edits
    srv._begin_scan_snapshot()
    assert not srv.plan_confirm_event.is_set()
    assert srv.confirmed_plan_edits == {}
