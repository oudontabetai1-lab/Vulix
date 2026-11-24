"""Agent scan abort handling at the serve orchestration boundary."""
from __future__ import annotations

import asyncio

import pytest

import main


class _Monitor:
    def __init__(self):
        self.command_queue = asyncio.Queue()
        self.statuses = []

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
async def test_agent_abort_monitor_preserves_non_abort_commands():
    monitor = _Monitor()
    started = asyncio.Event()

    async def operation():
        started.set()
        await asyncio.Event().wait()

    task = asyncio.create_task(
        main._run_with_abort_monitor(operation, monitor, phase_label="Agent")
    )
    await started.wait()
    monitor.command_queue.put_nowait("pause")
    monitor.command_queue.put_nowait("abort")

    await asyncio.wait_for(task, timeout=1)

    assert monitor.command_queue.get_nowait() == "pause"
