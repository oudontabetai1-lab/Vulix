"""マルチパラメータ同時投入経路が各フィールドの payload を payloads.jsonl へ記録する（ブラウザ非依存）。"""
import json
import tempfile
import types
import unittest
from unittest.mock import AsyncMock

from wscan.engine import CrawledPage, ScanEngine
from wscan.request_logger import RequestLogger
from wscan.scanners.base import BaseScanner


class _Scanner(BaseScanner):
    CHECK_TYPE = "xss"

    async def scan_field(self, *a, **k):  # pragma: no cover - stub
        return []


class MultiParamPayloadLedgerTests(unittest.IsolatedAsyncioTestCase):
    async def test_each_field_payload_is_recorded_before_submit(self):
        page = CrawledPage(
            url="http://t/form", html="",
            forms=[{"index": 0, "method": "POST", "action": "/form",
                    "inputs": [{"name": "a", "type": "text"}, {"name": "b", "type": "text"}]}],
            url_params=[], depth=0,
        )

        class _PG:
            default_payloads = {"xss": ["<x>"]}

        with tempfile.TemporaryDirectory() as d:
            logger = RequestLogger(d)
            order: list[str] = []
            holder = types.SimpleNamespace(
                request_logger=logger, monitor=None, controller=None,
                browser=object(), payload_gen=object(),
            )
            scanner = _Scanner(holder)
            orig = logger.log_payload
            logger.log_payload = lambda *a, **k: (order.append("log"), orig(*a, **k))[1]

            async def _submit(*a, **k):
                order.append("submit")
                return "", {}

            eng = types.SimpleNamespace(
                max_forms=5, exclude_fields=set(), scanners={"xss": scanner},
                payload_gen=_PG(),
                controller=types.SimpleNamespace(wait_if_paused_or_abort=AsyncMock()),
                navigation_retries=0, _effective_delay=0, flag_finder=None,
                _recover_if_dialog_flood=AsyncMock(return_value=0), wave_errors=[],
                _page_recovery_failed=lambda w: False, _urls_same_page=lambda a, b: a == b,
                _record_unscannable_url=lambda *a, **k: None, _navigation_failure_note=lambda: "",
                _record_finding=lambda *a, **k: None, _check_page_for_flags=lambda *a, **k: None,
                browser=types.SimpleNamespace(
                    dialog_total=0, dialog_fired=False, dialog_message="",
                    navigate=AsyncMock(return_value=True), reset_dialog=lambda: None,
                    fill_and_submit_form_multi=_submit,
                    page=types.SimpleNamespace(url=page.url)),
            )
            for n in ("_recovered_page_healthy", "_landed_on_target"):
                setattr(eng, n, getattr(ScanEngine, n).__get__(eng))

            await ScanEngine._phase_multi_param(eng, page, None)

            rows = [json.loads(line) for line in logger.payload_path.read_text().splitlines() if line.strip()]
            self.assertEqual([(r["field"], r["payload"], r["check_type"]) for r in rows],
                             [("a", "<x>", "xss"), ("b", "<x>", "xss")])
            self.assertTrue(all(r.get("probe_attempt_id") for r in rows))
            self.assertEqual(order, ["log", "log", "submit"])


if __name__ == "__main__":
    unittest.main()
