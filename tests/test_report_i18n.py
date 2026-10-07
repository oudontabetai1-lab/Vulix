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
from tests.fixtures import report_i18n_inputs
from wscan import i18n
from wscan.i18n import normalize_lang, translate, translate_or, untranslated_keys
from wscan.remediation import _get_static
from wscan.report import ReportGenerator, _js_str
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
    english = ReportGenerator(tmp_path, lang="en").generate(**kwargs).read_text()
    assert '<html lang="en">' in english
    assert "0 findings does not necessarily mean" in english
    assert "未確証" not in english
    if template != "executive":
        assert "証拠 &lt;script&gt;" in english
        assert "parameterized queries" in english
    assert finding.ai_fix == _get_static("sqli")


BASELINE_DIR = Path(__file__).parent / "fixtures" / "report_i18n_baseline"


@pytest.mark.parametrize("name", ["audit.html", "executive.html", "developer.html", "report.sarif.json"])
def test_default_output_is_byte_identical_to_pre_i18n_baseline(tmp_path, name):
    # 期待値は多言語化前の main に同じ固定入力を与えて生成したバイト列（新実装同士の比較ではない）。
    rendered = report_i18n_inputs.render_all(tmp_path)
    assert rendered[name] == (BASELINE_DIR / name).read_bytes()


def test_explicit_ja_matches_baseline(tmp_path, monkeypatch):
    original = ReportGenerator.__init__
    monkeypatch.setattr(ReportGenerator, "__init__", lambda self, out: original(self, out, lang="ja"))
    rendered = report_i18n_inputs.render_all(tmp_path)
    assert rendered["audit.html"] == (BASELINE_DIR / "audit.html").read_bytes()


def test_english_audit_script_literals_are_translated(tmp_path):
    html = ReportGenerator(tmp_path, lang="en").generate(
        "fixture", [], [], [], attack_plans=report_i18n_inputs._attack_plans(),
        page_graph=report_i18n_inputs._page_graph()).read_text()
    assert "'▲ Hide payloads'" in html and "Clicked element: " in html
    assert "@@" not in html


def test_js_str_keeps_non_ascii_and_cannot_break_out():
    assert _js_str("▲ ペイロードを隠す") == "'▲ ペイロードを隠す'"
    literal = _js_str("a'b\"c\\</script>&\n")
    assert "</script>" not in literal and "&" not in literal and "\n" not in literal
    assert literal == r"""'a\'b\"c\\\u003c/script\u003e\u0026\n'"""


def test_untranslated_keys_fall_back_to_japanese(tmp_path, monkeypatch):
    assert translate_or("sarif.rule.sqli", "fr", "ja原文") == "ja原文"
    monkeypatch.delitem(i18n._MESSAGES["en"], "sarif.rule.sqli")
    monkeypatch.delitem(i18n._MESSAGES["en"], "remediation.sqli")
    finding = dict(check_type="sqli", severity="high", url="http://fixture.test/", field_name="q",
                   payload="'", evidence="e", verification_state="assumed")
    rule = SarifExporter("en").export([finding])["runs"][0]["tool"]["driver"]["rules"][0]
    assert rule["shortDescription"]["text"] == _RULE_DESCS["sqli"]
    assert "sarif.rule" not in json.dumps(rule)
    assert rule["help"]["text"] == _get_static("sqli")
    # 個別訳がある check は英訳、ja にも無い未知 check は英語の汎用文。
    assert _get_static("xss", lang="en") == translate("remediation.xss", "en")
    assert "countermeasures" in _get_static("totally_unknown", lang="en")


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


def test_en_remediation_keeps_specific_ja_guidance_over_generic_family():
    # 個別 ja ガイダンスがあり en 未訳の check は、同系統の一般英訳で具体策を潰さない。
    from wscan.remediation import _STATIC_FIX
    assert "remediation.privesc_bypass" not in i18n.available_keys("en")
    for check in ("privesc_bypass", "privesc_unauth"):
        assert _get_static(check, lang="en") == _STATIC_FIX[check]
        assert _get_static(check, lang="en") != translate("remediation.privesc", "en")
    # 個別 ja が無い派生 check だけ同系統の英訳を使う。
    assert _get_static("privesc_unknown_variant", lang="en") == translate("remediation.privesc", "en")


def test_en_coverage_reasons_translated_or_fall_back_to_japanese(tmp_path, monkeypatch):
    from wscan.check_coverage import _PREREQUISITE_REASONS, _STATE_PROFILE_REASON
    coverage = {"prerequisite_coverage": {
        "prerequisite_missing": [{"check": "mass_assignment", "missing_prerequisites": ["api_spec"],
                                  "reasons": [_PREREQUISITE_REASONS["api_spec"]]}],
        "state_profile_skipped": [{"check": "csrf",
                                   "reason": _STATE_PROFILE_REASON.format(profile="read-only")}],
    }}
    en = ReportGenerator(tmp_path, lang="en")._build_coverage_html(coverage)
    assert "No API spec seed configured" in en and "does not send state-changing checks" in en and "read-only" in en
    assert "API 仕様シード未設定" not in en and "送信しません" not in en
    ja = ReportGenerator(tmp_path)._build_coverage_html(coverage)
    assert _PREREQUISITE_REASONS["api_spec"] in ja
    monkeypatch.delitem(i18n._MESSAGES["en"], "coverage.reason.prereq.api_spec")
    en2 = ReportGenerator(tmp_path, lang="en")._build_coverage_html(coverage)
    assert _PREREQUISITE_REASONS["api_spec"] in en2
