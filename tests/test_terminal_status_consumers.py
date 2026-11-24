import json
from unittest.mock import AsyncMock

import pytest

import main
from wscan.monitor import MonitorServer
from wscan.notification import NotificationManager
from wscan.report import ReportGenerator


def test_cli_scan_exit_code_does_not_treat_incomplete_as_success():
    assert main._scan_exit_code("done") == 0
    assert main._scan_exit_code("incomplete") != 0
    assert main._scan_exit_code("aborted") != 0


def test_report_coverage_and_observability_label_incomplete(tmp_path):
    generator = ReportGenerator(tmp_path)
    coverage = generator._build_coverage_html({
        "scan_status": "incomplete",
        "completion_reasons": ["hybrid_agent_recon_incomplete:retry_limit"],
    })
    observability = generator._build_observability_html({
        "scan_status": "incomplete",
        "completion_reasons": ["hybrid_agent_recon_incomplete:retry_limit"],
    })
    assert "Scan incomplete" in coverage
    assert "Scan incomplete" in observability
    assert "retry_limit" in coverage


def test_dashboard_receivers_render_incomplete_as_non_success():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    app_entry = (root / "templates/ui/app-entry.js").read_text(encoding="utf-8")
    app_styles = (root / "templates/app.html").read_text(encoding="utf-8")
    dashboard = (root / "templates/dashboard.html").read_text(encoding="utf-8")
    assert "else if (/incomplete/.test(rawStatus)) execState = 'incomplete'" in app_entry
    assert ".scan-state-incomplete" in app_styles
    assert "const isIncomplete = data.status === 'incomplete'" in dashboard
    assert "Scan incomplete (partial report)" in dashboard
    assert "Scan coverage is incomplete" in dashboard


def test_json_evidence_and_observability_keep_incomplete_status():
    import json
    evidence = {"status": "incomplete", "observability": {
        "scan_status": "incomplete", "completion_reasons": ["retry_limit"],
    }}
    restored = json.loads(json.dumps(evidence))
    assert restored["status"] == restored["observability"]["scan_status"] == "incomplete"
    assert restored["observability"]["completion_reasons"] == ["retry_limit"]


@pytest.mark.asyncio
async def test_websocket_terminal_event_and_api_snapshot_keep_incomplete_reason():
    monitor = MonitorServer()
    await monitor.emit("scan_complete", {
        "status": "incomplete",
        "coverage_gaps": ["hybrid_agent_recon_incomplete:retry_limit"],
    })
    snapshot = monitor._scan_snapshot_event()["data"]
    assert snapshot["status"] == "incomplete"
    assert snapshot["complete"]["status"] == "incomplete"
    assert snapshot["complete"]["coverage_gaps"] == ["hybrid_agent_recon_incomplete:retry_limit"]
    from fastapi.testclient import TestClient
    response = TestClient(monitor.app).get("/api/v1/scan/status")
    assert response.status_code == 200
    assert response.json()["status"] == "incomplete"


def test_observability_report_summary_marks_incomplete_terminal_state():
    from wscan.engine import ScanEngine
    engine = ScanEngine.__new__(ScanEngine)
    engine.scan_aborted = False
    engine.authentication_state = {"state": "unknown"}
    engine.wave_errors = ["hybrid_agent_recon_incomplete:retry_limit"]
    engine.request_logger = None
    engine.token_lifecycle_manager = False
    summary = ScanEngine._observability_report_data(engine)
    assert summary["scan_status"] == "incomplete"
    assert summary["completion_reasons"] == ["hybrid_agent_recon_incomplete:retry_limit"]


@pytest.mark.asyncio
async def test_serve_notification_uses_incomplete_status_with_mocked_transport(monkeypatch):
    monitor = MonitorServer()
    monitor.api_scan_status = "incomplete"
    monitor.api_target = "https://example.test"
    monitor._scan_complete_data = {
        "status": "incomplete",
        "coverage_gaps": ["hybrid_agent_recon_incomplete:retry_limit"],
    }
    monitor._notify_settings = lambda: {
        "enabled": True, "webhook_url": "https://webhook.invalid",
        "min_severity": "high", "notify_complete": True,
    }
    sent = AsyncMock()
    monkeypatch.setattr(NotificationManager, "_send", sent)

    await monitor.send_scan_complete_notification()

    sent.assert_awaited_once()
    payload = sent.await_args.args[0]
    assert payload["status"] == "incomplete"
    assert payload["event"] == "scan_incomplete"
    assert "完了" not in json.dumps(payload, ensure_ascii=False)
    assert "retry_limit" in payload["status_reason"]
