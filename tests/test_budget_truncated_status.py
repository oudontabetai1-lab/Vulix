"""時間枠で打ち切られた check の表示 status を検証する。

budget 打ち切りは checkpoint/resume では従来どおり「未完」として扱う（再試行する）。
ここでは「tested と表示して完全実行に見せない」ことだけを確認する。
"""
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import AsyncMock

import wscan.engine as eng
from wscan.engine import ScanEngine
from wscan.report import ReportGenerator
from wscan.scanners.base import BaseScanner


class _TruncatingScanner(BaseScanner):
    CHECK_TYPE = "sqli"

    def __init__(self, engine):
        super().__init__(engine)
        self.calls = 0

    async def scan_field(self, *args, **kwargs):
        return []

    async def scan_injection_point(self, ip, field):
        self.calls += 1
        # 2 回目（adaptive パス）で時間枠超過を模す。baseline 行は既に tested。
        if self.calls == 2:
            eng._FIELD_BUDGET_TRUNCATED.get().add("sqli")
        return []


class BudgetTruncatedStatusTests(unittest.IsolatedAsyncioTestCase):
    async def test_adaptive_truncation_marks_baseline_row_partial(self):
        with tempfile.TemporaryDirectory() as tmp:
            engine = ScanEngine(
                "http://127.0.0.1:1/",
                checks=["sqli"],
                llm_provider="none",
                output_dir=tmp,
                open_report=False,
                use_planner=False,
                enable_payload_learning=False,
                enable_checkpoint=False,
                enable_payload_evolution=False,
                enable_payload_mutation=False,
                enable_adaptive_payloads=True,
            )
            scanner = _TruncatingScanner(engine)
            engine.scanners = {"sqli": scanner}
            engine.adaptive_enabled = True
            engine._adaptive_llm_available = True
            engine.adaptive_engine = SimpleNamespace(
                generate=AsyncMock(return_value=(["adaptive-payload"], "ok"))
            )
            engine._browser = SimpleNamespace(
                dialog_total=0,
                page=SimpleNamespace(content=AsyncMock(return_value="")),
                get_page_source=AsyncMock(return_value="<html></html>"),
            )

            await engine._scan_field(
                "http://127.0.0.1:1/search", 0, {"name": "q", "type": "text"}
            )

        rows = [r for r in engine.scan_matrix if r["check"] == "sqli"]
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["status"], "partial")
        self.assertIn("budget exceeded", rows[0]["note"])
        self.assertIn("incomplete", rows[0]["note"])
        # checkpoint は完了扱いにしない（enable_checkpoint=False でも状態は同じ）。
        ip = engine._injection_point_for(
            "http://127.0.0.1:1/search", "q", 0, False, -1, {"name": "q"}
        )
        self.assertFalse(engine._checkpoint_is_done_ip(ip, "sqli"))
        self.assertEqual(scanner.calls, 2)

    def test_coverage_summary_counts_partial_separately_from_tested(self):
        engine = ScanEngine(
            "http://127.0.0.1:1/",
            checks=["sqli"],
            llm_provider="none",
            open_report=False,
        )
        engine.scan_matrix = [
            {
                "url": "http://127.0.0.1:1/search",
                "field_name": "q",
                "check": "sqli",
                "status": "partial",
                "location": "form field",
                "severity": "",
                "finding_count": 0,
                "note": "field attack budget exceeded; check remains incomplete",
            }
        ]
        engine.reached_urls = set()
        engine.visited_urls = set()
        coverage = engine.coverage_summary()
        self.assertEqual(coverage["by_status"], {"partial": 1})
        self.assertNotIn("tested", coverage["by_status"])

    def test_report_renders_partial_pill(self):
        with tempfile.TemporaryDirectory() as tmp:
            gen = ReportGenerator(Path(tmp), lang="ja")
            report_path = gen.generate(
                target="http://127.0.0.1:1/",
                findings=[],
                visited_urls=[],
                checks=["sqli"],
                scan_matrix=[
                    {
                        "url": "http://127.0.0.1:1/search",
                        "field_name": "q",
                        "check": "sqli",
                        "status": "partial",
                        "location": "form field",
                        "severity": "",
                        "finding_count": 0,
                        "note": "field attack budget exceeded; check remains incomplete",
                    }
                ],
            )
            html = report_path.read_text(encoding="utf-8")
        self.assertIn("status-partial", html)
        self.assertIn("partial: 1", html)
        self.assertIn("budget exceeded", html)
