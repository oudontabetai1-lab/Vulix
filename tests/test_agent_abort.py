"""Agent scan abort handling in serve mode."""
from __future__ import annotations

import asyncio

import pytest

import main
from wscan.monitor import MonitorServer


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
@pytest.mark.parametrize("interrupt_after_completion", [False, True])
async def test_ctrl_c_with_real_monitor_publishes_stable_terminal_sequence(
    interrupt_after_completion,
):
    """Ctrl+C during a scan and while the dashboard waits preserve event order."""
    from fastapi.testclient import TestClient

    monitor = MonitorServer()
    monitor._begin_scan_snapshot()
    started = asyncio.Event()

    async def operation():
        started.set()
        await asyncio.Event().wait()

    if interrupt_after_completion:
        await monitor.emit_status("scan completed", "done")
        await monitor.emit("scan_complete", {"status": "done"})
        monitor._transition_scan_status("aborted", "Ctrl+C after scan")
    else:
        task = asyncio.create_task(
            main._run_with_abort_monitor(operation, monitor, phase_label="Agent")
        )
        await started.wait()
        monitor.command_queue.put_nowait("abort")
        await asyncio.wait_for(task, timeout=1)
        await monitor.emit("scan_complete", {"status": "aborted", "aborted": True})

    terminal_sequence = []
    for event in monitor.event_history:
        data = event.get("data") or {}
        if event.get("type") == "status" and data.get("terminal_outcome"):
            terminal_sequence.append(("status", data["terminal_outcome"]["status"]))
        elif event.get("type") == "scan_complete":
            terminal_sequence.append(("scan_complete", data["terminal_outcome"]["status"]))

    expected = "done" if interrupt_after_completion else "aborted"
    assert terminal_sequence == [("status", expected), ("scan_complete", expected)]
    response = TestClient(monitor.app).get("/api/v1/scan/status")
    assert response.status_code == 200
    assert response.json()["status"] == expected
    assert main._scan_exit_code(response.json()["status"]) == (0 if expected == "done" else 2)


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


@pytest.mark.parametrize("mode", ["scan", "agent", "hybrid"])
@pytest.mark.parametrize("terminal_status", ["done", "incomplete", "failed", "aborted"])
def test_each_mode_publishes_terminal_status_and_scan_complete_once(
    mode, terminal_status
):
    async def exercise():
        monitor = MonitorServer()
        monitor._begin_scan_snapshot()

        if mode == "scan" and terminal_status == "failed":
            # ScanEngine's exception path emits error, then its finally emits failed.
            try:
                raise RuntimeError("synthetic scan failure")
            except RuntimeError as exc:
                await monitor.emit_status(f"Scan error: {exc}", "error")
        elif mode == "agent" and terminal_status == "aborted":
            started = asyncio.Event()

            async def operation():
                started.set()
                await asyncio.Event().wait()

            task = asyncio.create_task(
                main._run_with_abort_monitor(operation, monitor, phase_label="Agent")
            )
            await started.wait()
            monitor.command_queue.put_nowait("abort")
            await asyncio.wait_for(task, timeout=1)
        elif mode == "hybrid" and terminal_status == "aborted":
            started = asyncio.Event()

            async def operation():
                started.set()
                await asyncio.Event().wait()

            task = asyncio.create_task(
                main._run_hybrid_recon_with_retries(operation, monitor)
            )
            await started.wait()
            monitor.command_queue.put_nowait("abort")
            handoff, continue_to_phase2 = await asyncio.wait_for(task, timeout=1)
            assert handoff.incomplete_reason == "recon_aborted"
            assert continue_to_phase2 is False
        elif mode == "hybrid" and terminal_status == "incomplete":
            from datetime import datetime

            async def interrupted_by_window():
                await asyncio.Event().wait()

            handoff, continue_to_phase2 = await main._run_hybrid_recon_with_retries(
                interrupted_by_window,
                monitor,
                ["Mon 10:00-12:00"],
                now_fn=lambda: datetime(2024, 1, 1, 12, 1),
                max_retries=0,
            )
            assert handoff.incomplete_reason == "retry_limit"
            assert continue_to_phase2 is True
        else:
            await monitor.emit_status(
                f"{mode} terminal status {terminal_status}", terminal_status
            )

        # Some mode wrappers return an incomplete handoff before the final
        # scan result is published. Exercise that shared publication
        # step explicitly for every mode/state pair.
        await monitor.emit_status(
            f"{mode} final outcome {terminal_status}", terminal_status
        )

        completion = {
            "status": terminal_status,
            "aborted": terminal_status == "aborted",
            "total_findings": 3,
            "report_path": "/tmp/terminal-report.html",
        }
        await monitor.emit("scan_complete", completion)
        # Reproduce duplicate completion from a repeated cleanup/finalizer call.
        await monitor.emit("scan_complete", completion)
        # Duplicate producers and a conflicting late producer must not add a second
        # terminal event or mutate the first canonical outcome.
        await monitor.emit_status("duplicate terminal status", terminal_status)
        rejected_status = "failed" if terminal_status != "failed" else "done"
        await monitor.emit_status("late conflicting status", rejected_status)
        await monitor.emit(
            "scan_complete", {**completion, "status": rejected_status}
        )

        terminal_status_events = []
        scan_complete_events = []
        event_sequence = []
        for event in monitor.event_history:
            data = event.get("data") or {}
            if event.get("type") == "status" and data.get("terminal_outcome"):
                state = data["terminal_outcome"]["status"]
                terminal_status_events.append(state)
                event_sequence.append(("status", state))
            elif event.get("type") == "scan_complete":
                state = data["terminal_outcome"]["status"]
                scan_complete_events.append(state)
                event_sequence.append(("scan_complete", state))
        return monitor, terminal_status_events, scan_complete_events, event_sequence

    monitor, status_events, completion_events, event_sequence = asyncio.run(exercise())
    assert len(status_events) == 1, (mode, terminal_status, status_events)
    assert len(completion_events) == 1, (mode, terminal_status, completion_events)
    assert status_events == [terminal_status]
    assert completion_events == [terminal_status]
    assert event_sequence == [
        ("status", terminal_status),
        ("scan_complete", terminal_status),
    ], (mode, terminal_status)
    assert monitor._terminal_outcome()["status"] == terminal_status
    assert monitor._scan_complete_data["status"] == terminal_status
    assert monitor._scan_complete_data["report_path"] == "/tmp/terminal-report.html"
