import json
import re
import unicodedata
from collections import Counter
from unittest.mock import AsyncMock
from types import SimpleNamespace

import pytest

import main
from wscan.monitor import MonitorServer
from wscan.notification import NotificationManager
from wscan.report import ReportGenerator


_TERMINAL_COPY = re.compile(
    r"\b(?:agent\s+)?scan\s+(?:complete(?:d)?|incomplete|finished|failed|aborted)\b"
    r"|\bagent\s+browser\s+(?:complete(?:d)?|finished|完了)\b"
    r"|スキャン(?:完了|不完全|中断|失敗)",
    re.IGNORECASE,
)


def _terminal_copy_counts(sources):
    observed = Counter()
    for path, source in sources.items():
        normalized = unicodedata.normalize("NFKC", source)
        for match in _TERMINAL_COPY.finditer(normalized):
            observed[(path, match.group(0).casefold())] += 1
    return observed


def test_cli_scan_exit_code_does_not_treat_incomplete_as_success():
    assert main._scan_exit_code("done") == 0
    assert main._scan_exit_code("incomplete") == 2
    assert main._scan_exit_code("aborted") == 2
    assert main._scan_exit_code("failed") == 1


@pytest.mark.parametrize(
    ("harness_status", "success", "error", "expected_status", "expected_exit"),
    [
        ("partial", True, "", "incomplete", 2),
        ("incomplete", False, "", "incomplete", 2),
        ("failed", False, "", "failed", 1),
        ("", False, "browser stopped", "failed", 1),
        ("aborted", False, "", "aborted", 2),
        ("done", True, "", "done", 0),
        ("complete", True, "", "done", 0),
        ("complete", False, "", "incomplete", 2),
    ],
)
def test_agent_normal_and_hybrid_statuses_share_canonical_outcome(
    harness_status, success, error, expected_status, expected_exit
):
    import asyncio
    from wscan.terminal_outcome import agent_result_outcome, terminal_outcome

    result = SimpleNamespace(
        harness_status=harness_status, success=success, error=error,
        findings=[object()] if harness_status == "partial" else [],
        coverage_gaps=["coverage_gap"] if expected_status == "incomplete" else [],
        network_guard_errors=[],
    )
    agent = agent_result_outcome(result)
    expected = terminal_outcome(expected_status, agent["reason"])
    assert agent == expected
    assert main._agent_exit_code(result) == expected_exit
    # Normal scans use the same mapping for their exit code.
    normal = terminal_outcome(expected_status, agent["reason"])
    assert normal == agent
    assert main._scan_exit_code(expected_status) == expected_exit
    # Hybrid and Agent events enter MonitorServer with the canonical status.
    monitor = MonitorServer()
    asyncio.run(monitor.emit("scan_complete", {
        "status": expected_status,
        "completion_reasons": [agent["reason"]] if agent["reason"] else [],
    }))
    assert monitor._terminal_outcome() == terminal_outcome(
        expected_status, agent["reason"]
    )


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
    assert "setTerminalStatus(outcome," in dashboard
    assert "terminal_outcome" in dashboard


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
    assert response.json()["terminal_outcome"]["is_success"] is False
    assert response.json()["terminal_outcome"]["label"] == "Scan incomplete"


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
    assert summary["terminal_outcome"]["exit_code"] == 2


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


@pytest.mark.parametrize(
    ("status", "label", "label_ja", "severity", "success", "exit_code"),
    [
        ("complete", "Scan complete", "スキャン完了", "success", True, 0),
        ("done", "Scan complete", "スキャン完了", "success", True, 0),
        ("partial", "Scan incomplete", "スキャン不完全", "warning", False, 2),
        ("incomplete", "Scan incomplete", "スキャン不完全", "warning", False, 2),
        ("failed", "Scan failed", "スキャン失敗", "error", False, 1),
        ("aborted", "Scan aborted (partial report)", "スキャン中断（部分レポート）", "warning", False, 2),
    ],
)
def test_terminal_outcome_is_canonical_for_all_terminal_states(
    status, label, label_ja, severity, success, exit_code
):
    from wscan.terminal_outcome import terminal_outcome

    outcome = terminal_outcome(status)
    assert outcome["label"] == label
    assert outcome["label_ja"] == label_ja
    assert outcome["severity"] == severity
    assert outcome["is_success"] is success
    assert outcome["exit_code"] == exit_code
    assert outcome["message"] == label
    assert bool(outcome["color"]) and bool(outcome["console_style"])


@pytest.mark.parametrize("status", ["done", "incomplete", "failed", "aborted"])
def test_monitor_api_and_websocket_publish_shared_outcome(status):
    import asyncio
    from fastapi.testclient import TestClient
    from wscan.terminal_outcome import terminal_outcome

    monitor = MonitorServer()
    asyncio.run(monitor.emit("scan_complete", {
        "status": status,
        "completion_reasons": ["retry_limit"] if status == "incomplete" else [],
    }))
    expected = terminal_outcome(status, "retry_limit" if status == "incomplete" else "")
    snapshot = monitor._scan_snapshot_event()["data"]
    response = TestClient(monitor.app).get("/api/v1/scan/status")
    findings = TestClient(monitor.app).get("/api/v1/scan/findings")
    results = TestClient(monitor.app).get("/api/v1/scan/results")
    assert snapshot["terminal_outcome"] == expected
    assert snapshot["complete"]["terminal_outcome"] == expected
    assert response.json()["terminal_outcome"] == expected
    assert findings.json()["terminal_outcome"] == expected
    assert results.json()["terminal_outcome"] == expected


@pytest.mark.parametrize(
    ("status", "expected_exit"),
    [("done", 0), ("incomplete", 2), ("failed", 1), ("aborted", 2)],
)
def test_cli_and_serve_terminal_display_and_exit_mapping(status, expected_exit):
    class Console:
        def __init__(self):
            self.messages = []

        def print(self, message):
            self.messages.append(str(message))

    console = Console()
    outcome = main._print_terminal_outcome(console, status, report_path="/tmp/report.html")
    assert outcome["label"] in console.messages[-1]
    assert outcome["console_style"] in console.messages[-1]
    assert "/tmp/report.html" in console.messages[-1]
    assert main._scan_exit_code(status) == expected_exit


@pytest.mark.parametrize("status", ["done", "incomplete", "failed", "aborted"])
def test_notification_payload_uses_canonical_status_outcome(status):
    from wscan.terminal_outcome import terminal_outcome

    outcome = terminal_outcome(status)
    payload = NotificationManager._build_complete_payload(
        {"total": 0, "critical": 0, "high": 0, "medium": 0, "low": 0},
        "https://example.test", "", "", status=status,
    )
    assert payload["terminal_outcome"] == outcome
    assert outcome["label_ja"] in payload["text"]
    if not outcome["is_success"]:
        assert payload["event"] != "scan_complete"
        assert payload["attachments"][0]["color"] == outcome["color"]
        assert "🟢" not in json.dumps(payload, ensure_ascii=False)


@pytest.mark.parametrize("status,expected_exit", [("done", 0), ("incomplete", 2), ("failed", 1), ("aborted", 2)])
@pytest.mark.parametrize("no_monitor", [False, True])
def test_main_scan_exit_code_is_status_driven(monkeypatch, status, expected_exit, no_monitor):
    args = SimpleNamespace(command="scan", no_monitor=no_monitor)
    monkeypatch.setattr(main, "parse_args", lambda: args)
    def return_status(coroutine):
        coroutine.close()
        return status

    monkeypatch.setattr(main.asyncio, "run", return_status)
    if expected_exit:
        with pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == expected_exit
    else:
        main.main()


@pytest.mark.parametrize("status,expected_exit", [("done", 0), ("incomplete", 2), ("failed", 1), ("aborted", 2)])
def test_main_serve_exit_code_uses_last_scan_outcome(monkeypatch, status, expected_exit):
    args = SimpleNamespace(command="serve")
    monkeypatch.setattr(main, "parse_args", lambda: args)

    def interrupt_after_scan(coroutine):
        coroutine.close()
        args._scan_terminal_status = status
        raise KeyboardInterrupt

    monkeypatch.setattr(main.asyncio, "run", interrupt_after_scan)
    if expected_exit:
        with pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == expected_exit
    else:
        with pytest.raises(SystemExit) as exc:
            main.main()
        assert exc.value.code == 0


def test_status_output_routes_use_the_terminal_outcome_function():
    import inspect

    scan_source = inspect.getsource(main.run_scan)
    serve_source = inspect.getsource(main.run_serve)
    assert scan_source.count("_print_terminal_outcome(") >= 3  # monitor off, monitor on, failure
    assert "engine._terminal_status()" in scan_source
    assert "_print_terminal_outcome(" in serve_source
    assert "args._scan_terminal_status = status" in serve_source
    assert "terminal_outcome(status)[\"exit_code\"]" in inspect.getsource(main.main)


def test_terminal_display_copy_is_centralized_with_documented_exceptions():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    # Negative controls ensure casing and full-width forms normalize to matches.
    probe = _terminal_copy_counts({
        "probe.py": "Agent scan COMPLETE; Ａｇｅｎｔ　Ｓｃａｎ　Ｃｏｍｐｌｅｔｅｄ; Scan finished"
    })
    assert probe == Counter({
        ("probe.py", "agent scan complete"): 1,
        ("probe.py", "agent scan completed"): 1,
        ("probe.py", "scan finished"): 1,
    })
    expected = Counter({
        ("wscan/terminal_outcome.py", "scan complete"): 1,
        ("wscan/terminal_outcome.py", "scan incomplete"): 1,
        ("wscan/terminal_outcome.py", "scan aborted"): 1,
        ("wscan/terminal_outcome.py", "scan failed"): 1,
        ("wscan/terminal_outcome.py", "スキャン完了"): 1,
        ("wscan/terminal_outcome.py", "スキャン不完全"): 1,
        ("wscan/terminal_outcome.py", "スキャン中断"): 1,
        ("wscan/terminal_outcome.py", "スキャン失敗"): 1,
        # The following are not final scan outcomes: abort causes, crawl-step/audit labels,
        # notification toggles, and scanner error descriptions.
        ("wscan/tls_scan.py", "スキャン失敗"): 1,
        ("wscan/engine.py", "scan aborted"): 1,
        ("wscan/engine.py", "スキャン失敗"): 1,
        ("wscan/intervention.py", "scan aborted"): 5,
        ("wscan/scanners/base.py", "scan aborted"): 1,
        ("wscan/scanners/tls_config_scan.py", "スキャン失敗"): 1,
        ("templates/portal.html", "スキャン完了"): 1,
        ("templates/dashboard.html", "スキャン中断"): 1,
        ("templates/dashboard.html", "scan completed"): 1,
        ("templates/ui/summary-modules.js", "スキャン中断"): 1,
        ("templates/ui/settings-module.js", "スキャン完了"): 1,
        ("templates/ui/crawl-module.js", "スキャン中断"): 1,
        ("templates/ui/crawl-module.js", "スキャン完了"): 1,
        ("wscan/eta_estimator.py", "scan finished"): 1,
    })
    # Allowlist rationales are explicit so a new phrase cannot silently bypass review.
    exception_reasons = {
        "wscan/tls_scan.py": "scanner documentation describes an individual TLS failure, not a run outcome",
        "wscan/engine.py": "abort prompt and diff-scan error describe local actions, not terminal labels",
        "wscan/intervention.py": "exception reason records the operator abort cause for the scan engine",
        "wscan/scanners/base.py": "exception reason records the operator abort cause for the scan engine",
        "wscan/scanners/tls_config_scan.py": "scanner module documentation describes a local no-finding error behavior",
        "templates/portal.html": "checkbox names a notification trigger, not a scan result",
        "templates/dashboard.html": "audit labels are actions; the English sentence warns that zero findings do not imply completion",
        "templates/ui/summary-modules.js": "audit action log label is an operator action, not a scan result",
        "templates/ui/settings-module.js": "checkbox names a notification trigger, not a scan result",
        "templates/ui/crawl-module.js": "crawl substep status is independent from the overall scan terminal state",
        "wscan/eta_estimator.py": "internal estimator lifecycle docstring names its finished state; it is not user-facing status copy",
    }
    source_paths = [root / "main.py", *(root / "wscan").rglob("*.py"),
                    *(root / "templates").rglob("*.js"), *(root / "templates").rglob("*.html")]
    sources = {
        path.relative_to(root).as_posix(): path.read_text(encoding="utf-8")
        for path in source_paths
    }
    observed = _terminal_copy_counts(sources)
    assert "agent_result_outcome" in sources["wscan/llm_agent_browser.py"]
    assert "agent_result_outcome" in sources["wscan/agent_engine.py"]
    assert "agent_result_outcome" in sources["main.py"]
    assert "status_label" not in sources["wscan/agent_engine.py"]
    assert "Agent scan {" not in sources["wscan/agent_engine.py"]
    assert observed == expected
    for (path, _phrase), count in expected.items():
        if path != "wscan/terminal_outcome.py":
            assert count > 0 and exception_reasons.get(path)


def test_user_docs_explain_incomplete_status_and_cli_exit_code():
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    readme = (root / "README.md").read_text(encoding="utf-8")
    usage = (root / "docs/dashboard_usage_ja.md").read_text(encoding="utf-8")
    advanced = (root / "docs/advanced_features.md").read_text(encoding="utf-8")
    assert "不完全または中断で 2" in readme
    assert "`incomplete` は必要な検査が残った不完全終了" in usage
    assert "`terminal_outcome`" in advanced
