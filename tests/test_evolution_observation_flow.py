"""Exercise evolution observations through the real engine caller seam."""
import asyncio
import json
import tempfile
import types
import unittest
from pathlib import Path
from contextvars import ContextVar
from unittest.mock import AsyncMock, MagicMock, patch

from wscan.adaptive_payload import AdaptivePayloadEngine
from wscan.engine import ScanEngine
from wscan.payload_gen import PayloadGenerator
from wscan.request_logger import RequestLogger
from wscan.scanners.base import BaseScanner


class _ProbeScanner(BaseScanner):
    CHECK_TYPE = "xss"

    def __init__(self, engine):
        super().__init__(engine)

    async def scan_field(self, *_args, **_kwargs):
        return []

    async def scan_injection_point(self, ip, field):
        await self.evolved_payloads(
            ip.url, ip.form_index, ip.parameter_id,
            ip.legacy_is_url_param(), dom_index=ip.submit_index,
        )
        return []


class EvolutionObservationFlowTests(unittest.IsolatedAsyncioTestCase):
    def _scanner(self, observe):
        current = ContextVar(f"observation-{id(observe)}", default=None)
        scanner = types.SimpleNamespace()
        scanner._begin_evolution_observation = lambda: current.set(None)
        scanner._get_evolution_observation = current.get
        scanner._restore_evolution_observation = current.reset

        async def scan(ip, field):
            await observe(ip, field, current)
            return []

        scanner.scan_injection_point = AsyncMock(side_effect=scan)
        return scanner

    def _engine(self, scanner):
        engine = object.__new__(ScanEngine)
        engine._field_attack_budget_s = 0
        engine.scanners = {"xss": scanner}
        engine.payload_gen = types.SimpleNamespace(
            default_payloads={"xss": []},
            _check_llm_available=AsyncMock(return_value=True),
        )
        engine.adaptive_engine = types.SimpleNamespace(
            generate=AsyncMock(return_value=([], "ok"))
        )
        engine._adaptive_llm_available = None
        engine._adaptive_llm_availability_lock = asyncio.Lock()
        engine._injection_point_for = types.MethodType(ScanEngine._injection_point_for, engine)
        engine._adaptive_attack_field = types.MethodType(ScanEngine._adaptive_attack_field, engine)
        engine._checkpoint_is_done_ip = types.MethodType(ScanEngine._checkpoint_is_done_ip, engine)
        engine._checkpoint_mark_done_ip = types.MethodType(ScanEngine._checkpoint_mark_done_ip, engine)
        engine._record_scan_matrix = MagicMock()
        engine._record_finding = MagicMock()
        engine._save_checkpoint = MagicMock(return_value=True)
        engine._dialog_wedged_since = lambda _since: False
        engine._page_js_risks = lambda *_args: []
        engine._browser = types.SimpleNamespace(
            dialog_total=0,
            page=types.SimpleNamespace(content=AsyncMock(return_value="<html></html>")),
            get_page_source=AsyncMock(return_value="<html></html>"),
        )
        engine.waf_detector = types.SimpleNamespace(_detected=None)
        engine.all_findings = []
        engine.wave_errors = []
        engine.flag_finder = None
        engine.adaptive_enabled = True
        engine.enable_checkpoint = False
        engine.checkpoint = None
        engine.enable_evolution_observation_reuse = True
        engine.completed_fields = 0
        engine.total_fields = 1
        engine.monitor = None
        return engine

    async def test_first_pass_observation_reaches_adaptive_generation(self):
        with tempfile.TemporaryDirectory() as output:
            engine = self._engine(None)
            engine.request_logger = RequestLogger(output)
            engine._adaptive_llm_available = True
            engine.adaptive_engine = AdaptivePayloadEngine(PayloadGenerator(provider="ollama"))
            browser = engine.browser
            captured = {}

            async def fake_complete_text(_pg, prompt, **_kwargs):
                captured["prompt"] = prompt
                return "", "blocked"

            async def submit(_dom, _field, probe):
                body = f'<input value="{probe}">'
                return body, {"response": {"body": body}}

            browser.navigate = AsyncMock(return_value=True)
            browser.fill_and_submit_form = AsyncMock(side_effect=submit)
            scanner = _ProbeScanner(engine)
            engine.scanners = {"xss": scanner}
            with patch("wscan.adaptive_payload.llm_client.complete_text", new=fake_complete_text):
                await ScanEngine._scan_field(engine, "https://example.test/", 0, {"name": "q"})

            audit = [json.loads(line) for line in Path(output, "payloads.jsonl").read_text().splitlines()]
            self.assertEqual(len(audit), 1)
            self.assertEqual(audit[0]["check_type"], "xss_evolution_probe")
            browser.fill_and_submit_form.assert_awaited_once()
            prompt = captured["prompt"]
            self.assertIn("double_quoted_attr", prompt)
            self.assertIn("surviving unescaped", prompt)
            self.assertNotIn("wscanEVO", prompt)

    async def test_parallel_fields_keep_their_own_observation(self):
        async def observe(_ip, field, current):
            await asyncio.sleep(0)
            current.set(({"context": field["name"]}, {field["name"]}))

        scanner = self._scanner(observe)
        engine = self._engine(scanner)
        await asyncio.gather(
            ScanEngine._scan_field(engine, "https://example.test/", 0, {"name": "first"}),
            ScanEngine._scan_field(engine, "https://example.test/", 0, {"name": "second"}),
        )

        prompts = {
            call.kwargs["field_name"]: call.kwargs["extra_observations"]
            for call in engine.adaptive_engine.generate.await_args_list
        }
        self.assertIn("first", prompts["first"])
        self.assertNotIn("second", prompts["first"])
        self.assertIn("second", prompts["second"])
        self.assertNotIn("first", prompts["second"])

    async def test_completed_field_not_rescanned_on_in_memory_checkpoint(self):
        """Verify that an already-completed field is not re-probed when marked done in checkpoint."""
        with tempfile.TemporaryDirectory() as output:
            engine = self._engine(None)
            engine.enable_checkpoint = True
            from wscan.checkpoint import CheckpointState
            engine.checkpoint = CheckpointState()
            engine.request_logger = RequestLogger(output)
            engine._adaptive_llm_available = True
            engine.adaptive_engine = AdaptivePayloadEngine(PayloadGenerator(provider="ollama"))
            browser = engine.browser
            captured = []

            async def fake_complete_text(_pg, prompt, **_kwargs):
                captured.append(prompt)
                return "", "blocked"

            async def submit(_dom, _field, probe):
                body = f'<input value="{probe}">'
                return body, {"response": {"body": body}}

            browser.navigate = AsyncMock(return_value=True)
            browser.fill_and_submit_form = AsyncMock(side_effect=submit)
            scanner = _ProbeScanner(engine)
            engine.scanners = {"xss": scanner}

            with patch("wscan.adaptive_payload.llm_client.complete_text", new=fake_complete_text):
                await ScanEngine._scan_field(engine, "https://example.test/", 0, {"name": "q"})

            audit = [json.loads(line) for line in Path(output, "payloads.jsonl").read_text().splitlines()]
            self.assertEqual(len(audit), 1)
            self.assertEqual(len(captured), 1)
            self.assertIn("double_quoted_attr", captured[0])

            # Re-scanning the same field: in-memory checkpoint marks it done, so second pass skips adaptive
            with patch("wscan.adaptive_payload.llm_client.complete_text", new=fake_complete_text):
                await ScanEngine._scan_field(engine, "https://example.test/", 0, {"name": "q"})

            # Audit still has exactly 1 probe; no duplicate probe sent
            audit2 = [json.loads(line) for line in Path(output, "payloads.jsonl").read_text().splitlines()]
            self.assertEqual(len(audit2), 1)
            self.assertEqual(len(captured), 1)
