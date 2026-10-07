"""出力言語と各入口の配線をブラウザ・スキャン対象なしで検証する。"""
import asyncio
import json
import re
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

import main
from wscan.engine import ScanEngine
from wscan.i18n import normalize_lang, translate, untranslated_keys
from wscan.remediation import _get_static
from wscan.report import ReportGenerator
from wscan.sarif import SarifExporter, _RULE_DESCS, write_sarif
from wscan.scanners.base import Finding


@pytest.mark.parametrize("value,expected", [(None, "ja"), ("", "ja"), ("fr", "ja"), ("EN_us", "en"), (" ja-JP ", "ja")])
def test_language_normalization(value, expected):
    assert normalize_lang(value) == expected


def test_catalog_fallback_and_parameters():
    assert not untranslated_keys("en")
    assert translate("unknown", "en") == "unknown"
    assert translate("report.exec.checks_count", "en", count=3) == "Checks: 3"


@pytest.mark.parametrize("template", ["audit", "executive", "developer"])
def test_templates_default_and_both_languages(tmp_path, template):
    finding = Finding(check_type="sqli", severity="high", url="http://fixture.test/", field_name="q",
                      payload="'", evidence="証拠 <script>", verification_state="assumed")
    finding.ai_fix = _get_static("sqli")
    kwargs = dict(target="http://fixture.test/", findings=[finding], visited_urls=[finding.url],
                  checks=["sqli"], template=template, observability={"total": 1})
    default = ReportGenerator(tmp_path).generate(**kwargs).read_text()
    japanese = ReportGenerator(tmp_path, lang="ja").generate(**kwargs).read_text()
    assert default == japanese
    english = ReportGenerator(tmp_path, lang="en").generate(**kwargs).read_text()
    assert '<html lang="en">' in english
    assert "0 findings does not necessarily mean" in english
    assert "未確証" not in english
    if template != "executive":
        assert "証拠 &lt;script&gt;" in english
        assert "parameterized queries" in english
    assert finding.ai_fix == _get_static("sqli")


def test_empty_developer_and_language_override(tmp_path):
    gen = ReportGenerator(tmp_path)
    path = gen.generate("fixture", [], [], [], template="developer", lang="en")
    assert "✓ No vulnerabilities were detected." in path.read_text()


@pytest.mark.parametrize("lang", ["ja", "en"])
def test_engine_renders_all_templates_in_selected_language(tmp_path, lang):
    engine = SimpleNamespace(
        output_dir=tmp_path, report_lang=lang, previous_scan_dir="", target_url="fixture",
        all_findings=[], visited_urls=set(), checks=[], attack_plans=[], ctf_found_flags=[],
        page_graph={}, _scan_matrix_for_display=lambda: [], _llm_runtime_summary=lambda: {},
        _observability_report_data=lambda: {}, coverage_summary=lambda: {},
    )
    ScanEngine._render_report_templates(engine)
    for name in ("report.html", "report_executive.html", "report_developer.html"):
        assert f'<html lang="{lang}">' in (tmp_path / name).read_text()


def test_sarif_translates_rules_only_and_preserves_default(tmp_path):
    findings = [dict(check_type=ct, severity="high", url="http://fixture.test/", field_name="q",
                     payload="'", evidence="証拠", verification_state="assumed") for ct in _RULE_DESCS]
    default = SarifExporter().export(findings)
    assert default == SarifExporter("ja").export(findings)
    english = SarifExporter("en").export(findings)
    assert english["runs"][0]["results"] == default["runs"][0]["results"]
    assert english["runs"][0]["properties"] == default["runs"][0]["properties"]
    for rule in english["runs"][0]["tool"]["driver"]["rules"]:
        assert not re.search(r"[ぁ-んァ-ヶ一-龥]", rule["shortDescription"]["text"] + rule["help"]["text"])
    out = write_sarif(findings, "fixture", tmp_path / "report.sarif", lang="en")
    assert json.loads(out.read_text())["runs"][0]["results"] == english["runs"][0]["results"]


@pytest.mark.parametrize("configured,expected", [("", "ja"), ("output:\n  language: en", "en"), ("output:\n  language: unknown", "ja")])
def test_config_and_cli_defaults(tmp_path, monkeypatch, configured, expected):
    path = tmp_path / "config.yaml"
    path.write_text(configured)
    cfg = main._load_config(path)
    assert cfg["report_lang"] == expected
    monkeypatch.setattr(main, "_CFG", cfg)
    for argv in (["scan", "http://fixture.test/"], ["agent", "http://fixture.test/"], ["batch", "targets.yaml"]):
        monkeypatch.setattr(sys, "argv", ["main.py", *argv])
        assert main.parse_args().report_lang == expected
        monkeypatch.setattr(sys, "argv", ["main.py", *argv, "--report-lang", "en"])
        assert main.parse_args().report_lang == "en"


def test_scan_cli_passes_language_to_engine(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "argv", ["main.py", "scan", "http://fixture.test/", "--llm", "none", "--no-monitor", "--report-lang", "en", "--output", str(tmp_path)])
    captured = []
    class Engine:
        def __init__(self, **kwargs):
            captured.append(kwargs["report_lang"])
        async def run(self):
            pass
    monkeypatch.setattr("wscan.engine.ScanEngine", Engine)
    asyncio.run(main.run_scan(main.parse_args()))
    assert captured == ["en"]


def test_agent_cli_passes_language(tmp_path, monkeypatch):
    captured = []
    class Engine:
        def __init__(self, **kwargs):
            captured.append(kwargs["report_lang"])
        async def run(self):
            pass
    monkeypatch.setattr("wscan.agent_engine.AgentEngine", Engine)
    monkeypatch.setattr(sys, "argv", ["main.py", "agent", "http://fixture.test/", "--no-monitor", "--report-lang", "en"])
    asyncio.run(main.run_agent(main.parse_args()))
    assert captured == ["en"]


def test_batch_cli_passes_language(tmp_path, monkeypatch):
    from wscan.batch_runner import BatchRunner
    target_file = tmp_path / "targets.yaml"
    target_file.write_text("targets:\n  - url: http://fixture.test/\n")
    captured = []
    async def run(runner):
        captured.append(runner.global_kwargs["report_lang"])
    monkeypatch.setattr(BatchRunner, "run", run)
    monkeypatch.setattr(BatchRunner, "save_batch_summary_json", lambda _: tmp_path / "batch.json")
    monkeypatch.setattr(sys, "argv", ["main.py", "batch", str(target_file), "--report-lang", "en"])
    asyncio.run(main.run_batch(main.parse_args()))
    assert captured == ["en"]


@pytest.mark.parametrize("agent_mode", [False, True])
def test_serve_submission_passes_language(tmp_path, monkeypatch, agent_mode):
    import uvicorn
    from wscan.monitor import MonitorServer
    from wscan.agent_engine import AgentEngine
    captured = []
    done = asyncio.Event()
    class Server:
        should_exit = False
        def __init__(self, config):
            pass
        async def serve(self):
            await done.wait()
            self.should_exit = True
    async def awaiting(monitor):
        assert monitor.default_scan_cfg["report_lang"] == "ja"
        monitor.scan_request_data = {"url": "http://fixture.test/", "report_lang": "en", "llm": "none", "agent_mode": agent_mode}
        monitor.scan_request_event.set()
    class Engine:
        def __init__(self, **kwargs):
            captured.append(kwargs["report_lang"])
            self.output_dir = tmp_path
        async def run(self):
            done.set()
            await asyncio.sleep(0)
    monkeypatch.setattr(uvicorn, "Server", Server)
    monkeypatch.setattr(MonitorServer, "emit_awaiting_config", awaiting)
    monkeypatch.setattr(MonitorServer, "prune_old_scans", lambda _: [])
    monkeypatch.setattr(MonitorServer, "trigger_due_schedules", lambda _: None)
    monkeypatch.setattr("wscan.engine.ScanEngine", Engine)
    monkeypatch.setattr("wscan.agent_engine.AgentEngine", Engine)
    monkeypatch.setattr(main.webbrowser, "open", lambda _: None)
    monkeypatch.setattr(main, "_CFG", {"report_lang": "ja", "llm_provider": "none"})
    monkeypatch.setattr(sys, "argv", ["main.py", "serve", "--host", "127.0.0.1", "--port", "18765"])
    asyncio.run(asyncio.wait_for(main.run_serve(main.parse_args()), timeout=5))
    assert captured == ["en"]
