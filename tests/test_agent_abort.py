"""Agent scan abort handling in serve mode."""
from __future__ import annotations

import asyncio

import pytest

import main


class _Monitor:
    def __init__(self):
        self.command_queue = asyncio.Queue()
        self.scan_abort_event = asyncio.Event()
        self.statuses = []

    def request_abort(self):
        self.scan_abort_event.set()
        self.command_queue.put_nowait("abort")

    async def emit_status(self, message, state):
        self.statuses.append((message, state))


@pytest.mark.asyncio
async def test_agent_abort_cancels_operation_and_waits_for_cleanup():
    monitor = _Monitor()
    started = asyncio.Event()
    cleaned_up = asyncio.Event()

    async def operation():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    task = asyncio.create_task(
        main._run_with_abort_monitor(
            operation, monitor, phase_label="Agent Browser scan"
        )
    )
    await started.wait()
    monitor.command_queue.put_nowait("abort")

    result, aborted = await asyncio.wait_for(task, timeout=1)

    assert (result, aborted) == (None, True)
    assert cleaned_up.is_set()
    assert monitor.statuses == [("Agent Browser scan を中断しました。", "aborted")]


@pytest.mark.asyncio
async def test_agent_abort_monitor_reports_unsupported_commands_without_leaking_them():
    monitor = _Monitor()
    started = asyncio.Event()
    cleaned_up = asyncio.Event()

    async def operation():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    task = asyncio.create_task(
        main._run_with_abort_monitor(operation, monitor, phase_label="Agent")
    )
    await started.wait()
    monitor.command_queue.put_nowait("pause")
    monitor.command_queue.put_nowait("resume")
    monitor.command_queue.put_nowait("abort")

    await asyncio.wait_for(task, timeout=1)

    assert cleaned_up.is_set()
    assert monitor.command_queue.empty()
    assert monitor.statuses == [
        (
            "Agent モードでは一時停止・再開はできません。実行中のスキャンは中断できます。",
            "running",
        ),
        ("Agent を中断しました。", "aborted"),
    ]


@pytest.mark.asyncio
async def test_agent_completion_drains_commands_queued_at_shutdown():
    monitor = _Monitor()
    monitor.command_queue.put_nowait("pause")
    monitor.command_queue.put_nowait("resume")

    async def completed_operation():
        return "finished"

    result, aborted = await main._run_with_abort_monitor(
        completed_operation, monitor, phase_label="Agent"
    )

    assert (result, aborted) == ("finished", False)
    assert monitor.command_queue.empty()
    assert monitor.statuses == [
        (
            "Agent モードでは一時停止・再開はできません。実行中のスキャンは中断できます。",
            "running",
        )
    ]


@pytest.mark.asyncio
async def test_hybrid_recon_abort_stops_before_phase_two():
    monitor = _Monitor()
    started = asyncio.Event()
    cleaned_up = asyncio.Event()
    attempts = []

    async def recon_operation():
        attempts.append(True)
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    task = asyncio.create_task(
        main._run_hybrid_recon_with_retries(
            recon_operation, monitor, max_retries=2
        )
    )
    await started.wait()
    monitor.command_queue.put_nowait("abort")

    handoff, continue_to_phase2 = await asyncio.wait_for(task, timeout=1)

    assert handoff is not None
    assert handoff.incomplete_reason == "recon_aborted"
    assert continue_to_phase2 is False
    assert attempts == [True]
    assert cleaned_up.is_set()
    assert monitor.command_queue.empty()
    assert monitor.statuses[-1] == ("ハイブリッド Phase 1 を中断しました。", "aborted")


@pytest.mark.asyncio
async def test_hybrid_recon_abort_with_time_window_monitor_stops_before_phase_two():
    from datetime import datetime

    monitor = _Monitor()
    started = asyncio.Event()
    cleaned_up = asyncio.Event()
    current = datetime(2024, 1, 1, 11, 0)

    async def recon_operation():
        started.set()
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    task = asyncio.create_task(
        main._run_hybrid_recon_with_retries(
            recon_operation,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: current,
        )
    )
    await started.wait()
    monitor.command_queue.put_nowait("abort")

    handoff, continue_to_phase2 = await asyncio.wait_for(task, timeout=2)

    assert handoff is not None
    assert handoff.incomplete_reason == "recon_aborted"
    assert continue_to_phase2 is False
    assert cleaned_up.is_set()
    assert monitor.command_queue.empty()
    assert monitor.statuses[-1] == ("ハイブリッド Phase 1 を中断しました。", "aborted")


@pytest.mark.asyncio
async def test_hybrid_recon_window_close_cancels_abort_monitored_operation():
    from datetime import datetime

    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 11, 59, 59)]
    cleaned_up = asyncio.Event()

    async def fake_sleep(_delay):
        current[0] = datetime(2024, 1, 1, 12, 0)

    async def recon_operation():
        try:
            await asyncio.Event().wait()
        finally:
            cleaned_up.set()

    handoff, continue_to_phase2 = await asyncio.wait_for(
        main._run_hybrid_recon_with_retries(
            recon_operation,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
            max_retries=0,
        ),
        timeout=1,
    )

    assert handoff is not None
    assert handoff.incomplete_reason == "retry_limit"
    assert continue_to_phase2 is True
    assert cleaned_up.is_set()
    assert monitor.command_queue.empty()
    assert monitor.statuses[-1][1] == "warning"


@pytest.mark.asyncio
@pytest.mark.parametrize("race_order", ["abort-first", "window-first", "same-turn"])
async def test_hybrid_abort_wins_at_time_window_boundary(race_order):
    """Boundary cancellation cleanup must not erase an abort from the same turn."""
    from datetime import datetime

    monitor = _Monitor()
    current = [datetime(2024, 1, 1, 11, 59, 59)]
    boundary_waiting = asyncio.Event()
    release_boundary = asyncio.Event()
    cleanup_started = asyncio.Event()
    release_cleanup = asyncio.Event()
    recon_finished = asyncio.Event()

    async def fake_sleep(_delay):
        boundary_waiting.set()
        await release_boundary.wait()
        current[0] = datetime(2024, 1, 1, 12, 0)

    async def recon_operation():
        try:
            await asyncio.Event().wait()
        finally:
            cleanup_started.set()
            await release_cleanup.wait()
            recon_finished.set()

    task = asyncio.create_task(
        main._run_hybrid_recon_with_retries(
            recon_operation,
            monitor,
            ["Mon 10:00-12:00"],
            None,
            now_fn=lambda: current[0],
            sleep_fn=fake_sleep,
            max_retries=0,
        )
    )
    await boundary_waiting.wait()

    if race_order == "abort-first":
        monitor.request_abort()
        release_boundary.set()
        release_cleanup.set()
    elif race_order == "window-first":
        release_boundary.set()
        await cleanup_started.wait()
        monitor.request_abort()
        release_cleanup.set()
    else:
        monitor.request_abort()
        current[0] = datetime(2024, 1, 1, 12, 0)
        release_boundary.set()
        release_cleanup.set()

    handoff, continue_to_phase2 = await asyncio.wait_for(task, timeout=1)
    if not release_cleanup.is_set():
        release_cleanup.set()

    assert handoff is not None
    assert handoff.incomplete_reason == "recon_aborted"
    assert continue_to_phase2 is False
    assert recon_finished.is_set()
    assert monitor.scan_abort_event.is_set()
    assert monitor.command_queue.empty()
    assert monitor.statuses[-1][1] == "aborted"
