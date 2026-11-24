"""新しいスキャンへ古い介入コマンドを持ち越さないことを確認する。"""
import asyncio

from fastapi.testclient import TestClient

import main
from wscan.intervention import ScanController
from wscan.monitor import ABORT_IDLE_MESSAGE, MonitorServer


def test_idle_websocket_abort_is_rejected_and_next_agent_run_completes():
    monitor = MonitorServer(port=0, auth_token="")
    client = TestClient(monitor.app)

    with client.websocket_connect("/ws") as websocket:
        assert websocket.receive_json()["type"] == "scan_snapshot"
        websocket.send_json({"action": "intervention", "command": "abort"})
        response = websocket.receive_json()

    assert response["type"] == "status"
    assert response["data"]["state"] == "warning"
    assert response["data"]["message"] == ABORT_IDLE_MESSAGE
    assert monitor.command_queue.empty()
    assert not monitor.scan_abort_event.is_set()

    monitor._begin_scan_snapshot()

    async def complete():
        async def operation():
            return "completed"

        return await main._run_with_abort_monitor(
            operation, monitor, phase_label="Agent"
        )

    assert asyncio.run(complete()) == ("completed", False)


def test_new_scan_discards_and_records_previous_commands_for_all_modes():
    monitor = MonitorServer(port=0, auth_token="")
    previous_run_id = monitor._scan_run_id
    monitor.command_queue.put_nowait("abort")
    monitor.command_queue.put_nowait("pause")
    monitor.scan_abort_event.set()

    monitor._begin_scan_snapshot()

    assert monitor.command_queue.empty()
    assert not monitor.scan_abort_event.is_set()
    assert [entry["command"] for entry in monitor.discarded_scan_commands] == [
        "abort",
        "pause",
    ]
    assert all(
        entry["run_id"] == previous_run_id
        and entry["reason"] == "new_scan_started"
        for entry in monitor.discarded_scan_commands
    )

    async def check_runs():
        async def completed_operation():
            return "completed"

        agent_result = await main._run_with_abort_monitor(
            completed_operation, monitor, phase_label="Agent"
        )
        hybrid_result = await main._run_hybrid_recon_with_retries(
            completed_operation, monitor, max_retries=0
        )

        controller = ScanController()
        controller._active = True
        reader = asyncio.create_task(controller._monitor_reader(monitor))
        await asyncio.sleep(0)
        controller._active = False
        reader.cancel()
        await asyncio.gather(reader, return_exceptions=True)
        return agent_result, hybrid_result, controller.abort_requested()

    agent_result, hybrid_result, ordinary_abort = asyncio.run(check_runs())
    assert agent_result == ("completed", False)
    assert hybrid_result == ("completed", True)
    assert not ordinary_abort


def test_active_websocket_abort_still_reaches_regular_scan_controller():
    monitor = MonitorServer(port=0, auth_token="")
    monitor.scan_in_progress = True
    assert monitor._handle_client_message(
        '{"action":"intervention","command":"abort"}'
    ) is None

    controller = ScanController()
    controller._active = True

    async def consume_abort():
        command = await monitor.command_queue.get()
        await controller._handle_command(command, monitor)

    asyncio.run(consume_abort())

    assert controller.abort_requested()
    assert monitor.scan_abort_event.is_set()
