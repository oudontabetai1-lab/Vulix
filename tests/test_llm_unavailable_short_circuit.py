"""LLM 恒久不達の short-circuit 検証。

使えない provider（provider none・キー/クライアント不在・不達ホスト）への実試行は
provider 全体で scan 中 1 回まで、モデル固有の恒久失敗（4xx≠429 等）への実試行は
鍵 (provider, base URL, model) ごとに 1 回まで。以降の同一鍵の呼び出し
（planner/payload/adaptive/triage/report）が probe 無しで打ち切ること。
鍵単位の倒れは provider 全体を落とさない＝別モデルを使う他 role の LLM 呼び出しは
減らないこと（単一 role の不在による偽陰性の防止）。一時失敗
（transient/empty/blocked）では可用性を倒さず retry・resume の挙動を変えないこと。
"""
import asyncio
import os
import types
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from wscan.adaptive_payload import AdaptivePayloadEngine
from wscan.attack_planner import AttackPlanner
from wscan.llm_client import availability_key, complete_text, is_permanent_status
from wscan.payload_gen import PayloadGenerator


class _Response:
    def __init__(self, status_code, data=None):
        self.status_code = status_code
        self.headers = {}
        self._data = data or {}

    def json(self):
        return self._data


def _mock_async_client(responses):
    client = MagicMock()
    client.post = AsyncMock(side_effect=responses)
    context = MagicMock()
    context.__aenter__ = AsyncMock(return_value=client)
    context.__aexit__ = AsyncMock(return_value=None)
    return client, context


def _real_pg(provider="openai", role_models=None, **overrides):
    """実 PayloadGenerator（共有可用性フラグを持つ）。env キーを固定して決定論化。"""
    env = {"OPENAI_API_KEY": "test-key", "GEMINI_API_KEY": "test-key"}
    with patch.dict(os.environ, env, clear=False):
        pg = PayloadGenerator(
            provider=provider,
            ollama_model="llama-test",
            ollama_url="http://127.0.0.1:1",
            openai_model="gpt-test",
            role_models=role_models,
        )
    pg.wave_errors = []
    for k, v in overrides.items():
        setattr(pg, k, v)
    return pg


class IsPermanentStatusTests(unittest.TestCase):
    def test_4xx_except_429_is_permanent(self):
        for status in (400, 401, 403, 404, 422):
            self.assertTrue(is_permanent_status(status), status)
        for status in (200, 408, 429, 500, 502, 503, None, "404"):
            self.assertFalse(is_permanent_status(status), status)


class CompleteTextShortCircuitTests(unittest.IsolatedAsyncioTestCase):
    async def test_permanent_marks_role_key_and_later_calls_attempt_nothing(self):
        pg = _real_pg("openai")
        client, context = _mock_async_client([_Response(404, {"error": "gone"})])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text, status = await complete_text(pg, "p", return_status=True, caller="t")
        self.assertEqual(status, "permanent")
        self.assertIsNone(text)
        # 鍵単位の倒れ：provider 全体のフラグは倒さない。
        self.assertIsNone(pg._llm_available)
        self.assertFalse(pg._provider_llm_unavailable)
        self.assertTrue(pg.is_llm_unavailable(availability_key(pg, model="gpt-test")))
        self.assertEqual(client.post.await_count, 1)
        # 鍵ごとに 1 行だけ観測 note が残る（model 接尾辞付き）。
        self.assertEqual(pg.wave_errors, ["llm_unavailable:permanent:gpt-test"])

        # 以降の同一鍵（既定モデル）の呼び出しは HTTP 試行ゼロで unavailable。
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text2, status2 = await complete_text(pg, "p", return_status=True, caller="t2")
        self.assertEqual(status2, "unavailable")
        self.assertIsNone(text2)
        self.assertEqual(client.post.await_count, 1)

    async def test_unreachable_ollama_costs_only_the_config_probe(self):
        pg = _real_pg("ollama")  # ollama_url は閉じたポート
        probe_client, probe_ctx = _mock_async_client([])
        probe_client.get = AsyncMock(side_effect=Exception("connection refused"))
        with patch("wscan.payload_gen.httpx.AsyncClient", return_value=probe_ctx):
            self.assertIs(await pg._check_llm_available(), False)
        # gate が倒れた後は planner/baseline/adaptive/report 全て試行ゼロ。
        call_client, call_ctx = _mock_async_client([])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=call_ctx):
            text, status = await complete_text(pg, "p", return_status=True)
        self.assertEqual(status, "unavailable")
        self.assertEqual(call_client.post.await_count, 0)
        self.assertEqual(
            await pg._check_llm_available(), False,
        )

    async def test_transient_does_not_flip_and_keeps_retrying(self):
        pg = _real_pg("openai")
        responses = [_Response(500)] * 6  # 既定 retries=2 → 各呼び出し 3 試行で transient 収束
        client, context = _mock_async_client(responses)
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text, status = await complete_text(pg, "p", return_status=True, caller="t")
        self.assertEqual(status, "transient")
        self.assertIsNone(pg._llm_available)
        self.assertEqual(pg.wave_errors, [])
        self.assertEqual(client.post.await_count, 3)
        # 続く呼び出しも普通に試行する（resume 回収の可能性を保持）。
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text2, status2 = await complete_text(pg, "p", return_status=True)
        self.assertEqual(status2, "transient")
        self.assertEqual(client.post.await_count, 6)

    async def test_empty_and_blocked_do_not_flip(self):
        pg = _real_pg("openai")
        client, context = _mock_async_client([
            _Response(200, {"choices": [{"message": {"content": "  "}}]}),
        ])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text, status = await complete_text(pg, "p", return_status=True)
        self.assertEqual(status, "empty")
        self.assertIsNone(pg._llm_available)

    async def test_working_provider_is_unchanged(self):
        pg = _real_pg("openai")
        responses = [
            _Response(200, {"choices": [{"message": {"content": "a"}}]}),
            _Response(200, {"choices": [{"message": {"content": "b"}}]}),
        ]
        client, context = _mock_async_client(responses)
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            t1, s1 = await complete_text(pg, "p1", return_status=True)
            t2, s2 = await complete_text(pg, "p2", return_status=True)
        self.assertEqual((s1, s2), ("ok", "ok"))
        self.assertEqual((t1, t2), ("a", "b"))
        self.assertIsNone(pg._llm_available)  # 倒れていない
        self.assertEqual(client.post.await_count, 2)

    async def test_missing_key_flips_and_later_calls_attempt_nothing(self):
        pg = _real_pg("openai")
        pg.openai_api_key = ""
        client, context = _mock_async_client([])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            text, status = await complete_text(pg, "p", return_status=True, caller="t")
        self.assertEqual(status, "unavailable")
        self.assertEqual(client.post.await_count, 0)
        self.assertIs(pg._llm_available, False)
        self.assertEqual(pg.wave_errors, ["llm_unavailable:unavailable"])


class RoleDivergenceTests(unittest.IsolatedAsyncioTestCase):
    """単一 role のモデル不在で他 role を落とさない回帰（review HOLD の再発防止）。"""

    async def test_planner_model_missing_but_payload_role_still_calls(self):
        pg = _real_pg("openai", role_models={"planner": "missing-model"})
        # planner role の 404 → 鍵 (openai, base, missing-model) だけ倒れる。
        bad_client, bad_ctx = _mock_async_client([_Response(404, {"error": "no model"})])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=bad_ctx):
            with pg.use_role("planner"):
                _, status = await complete_text(pg, "p", return_status=True)
        self.assertEqual(status, "permanent")
        self.assertIsNone(pg._llm_available)  # provider 全体は生きている
        self.assertTrue(pg.is_llm_unavailable(availability_key(pg, model="missing-model")))
        self.assertFalse(pg.is_llm_unavailable(availability_key(pg, model="gpt-test")))

        # payload role（既定モデル gpt-test）は普通に試行し成功する。
        good_client, good_ctx = _mock_async_client([
            _Response(200, {"choices": [{"message": {"content": "ok"}}]}),
        ])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=good_ctx):
            with pg.use_role("payload"):
                text, status = await complete_text(pg, "p", return_status=True)
        self.assertEqual((status, text), ("ok", "ok"))
        self.assertEqual(good_client.post.await_count, 1)

        # planner role の再呼び出しは実試行ゼロで打ち切る（実試行は鍵ごとに 1 回）。
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=bad_ctx):
            with pg.use_role("planner"):
                _, status = await complete_text(pg, "p", return_status=True)
        self.assertEqual(status, "unavailable")
        self.assertEqual(bad_client.post.await_count, 1)

    async def test_provider_wide_unavailable_closes_every_role(self):
        pg = _real_pg("openai", role_models={"planner": "model-a", "payload": "model-b"})
        pg.mark_llm_unavailable("unavailable", caller="x")
        client, context = _mock_async_client([])
        with patch("wscan.llm_client.httpx.AsyncClient", return_value=context):
            for role in ("planner", "payload", "adaptive", "triage", "report"):
                with pg.use_role(role):
                    _, status = await complete_text(pg, "p", return_status=True)
                self.assertEqual(status, "unavailable", role)
        self.assertEqual(client.post.await_count, 0)  # 実試行は合計 0 回
        self.assertEqual(pg.wave_errors.count("llm_unavailable:unavailable"), 1)

    async def test_mark_key_is_idempotent_per_key(self):
        pg = _real_pg("openai")
        key = availability_key(pg, model="gpt-test")
        pg.mark_llm_unavailable("permanent", caller="x", key=key)
        pg.mark_llm_unavailable("permanent", caller="y", key=key)
        self.assertEqual(pg.wave_errors.count("llm_unavailable:permanent:gpt-test"), 1)
        self.assertTrue(pg.is_llm_unavailable(key))


class MarkUnavailableTests(unittest.IsolatedAsyncioTestCase):
    async def test_mark_is_idempotent_and_gates_check_llm_available(self):
        pg = _real_pg("ollama")
        pg.mark_llm_unavailable("permanent", caller="x")
        pg.mark_llm_unavailable("permanent", caller="y")
        self.assertEqual(pg.wave_errors.count("llm_unavailable:permanent"), 1)
        self.assertIs(pg._llm_available, False)
        # 2 回目以降の gate も probe 無しで False。
        probe_client, probe_ctx = _mock_async_client([])
        probe_client.get = AsyncMock()
        with patch("wscan.payload_gen.httpx.AsyncClient", return_value=probe_ctx):
            self.assertIs(await pg._check_llm_available(), False)
        probe_client.get.assert_not_called()


class AttackPlannerFlipTests(unittest.IsolatedAsyncioTestCase):
    def _plan(self):
        return {"page_purpose": "login", "fields": [{
            "name": "q", "type": "text", "risk_score": 8,
            "priority_checks": ["sqli"], "rationale": "r",
            "custom_payloads": {},
        }]}

    async def test_permanent_streaming_failure_marks_role_key_only(self):
        pg = _real_pg("ollama")
        pg._llm_available = True  # gate の実 probe を代替（未達 provider の 404 を想定）
        planner = AttackPlanner(payload_gen=pg, enabled_checks=["sqli"])

        async def _bad_ollama(prompt):
            planner._last_call_bad_status = 404
            return None

        with patch.object(planner, "_call_ollama", side_effect=_bad_ollama):
            plan = await planner._llm_plan(
                "http://t.test/", "<html><title>x</title></html>",
                [{"inputs": [{"name": "q", "type": "text"}]}], [],
            )
        self.assertIsNone(plan)  # heuristic へフォールバック（挙動不変）
        # 鍵単位の倒れ：provider 全体のフラグは倒さない（テストが True を前提 Set 済み）。
        self.assertIsNot(pg._llm_available, False)
        self.assertFalse(pg._provider_llm_unavailable)
        self.assertTrue(pg.is_llm_unavailable(availability_key(pg, model="llama-test")))
        self.assertEqual(pg.wave_errors.count("llm_unavailable:permanent:llama-test"), 1)

        # 再呼び出しは streaming helper に到達しない（実試行は鍵ごとに 1 回）。
        with patch.object(planner, "_call_ollama") as stream:
            await planner._llm_plan(
                "http://t.test/", "<html><title>x</title></html>",
                [{"inputs": [{"name": "q", "type": "text"}]}], [],
            )
        stream.assert_not_called()

    async def test_transient_streaming_failure_does_not_flip(self):
        pg = _real_pg("ollama")
        pg._llm_available = True
        planner = AttackPlanner(payload_gen=pg, enabled_checks=["sqli"])

        async def _flaky_ollama(prompt):
            planner._last_call_bad_status = 503
            return None

        with patch.object(planner, "_call_ollama", side_effect=_flaky_ollama):
            await planner._llm_plan(
                "http://t.test/", "<html><title>x</title></html>",
                [{"inputs": [{"name": "q", "type": "text"}]}], [],
            )
        self.assertIs(pg._llm_available, True)  # 倒れていない


class MutatePayloadFlipTests(unittest.IsolatedAsyncioTestCase):
    async def test_permanent_streaming_failure_marks_role_key_only(self):
        pg = _real_pg("ollama")
        pg._llm_available = True
        engine = AdaptivePayloadEngine(pg)

        async def _bad_stream(prompt):
            engine._last_call_bad_status = 404
            return None

        with patch.object(engine, "_stream_ollama", side_effect=_bad_stream):
            result = await engine.mutate_payload("sqli", ["' OR 1=1"], field_name="q")
        self.assertEqual(result, [])
        # 鍵単位の倒れ：provider 全体のフラグは倒さない（テストが True を前提 Set 済み）。
        self.assertIsNot(pg._llm_available, False)
        self.assertFalse(pg._provider_llm_unavailable)
        self.assertTrue(pg.is_llm_unavailable(availability_key(pg, model="llama-test")))
        self.assertEqual(pg.wave_errors.count("llm_unavailable:permanent:llama-test"), 1)

        # 再呼び出しは streaming helper に到達しない（実試行は鍵ごとに 1 回）。
        with patch.object(engine, "_stream_ollama") as stream:
            await engine.mutate_payload("sqli", ["p"], field_name="q")
        stream.assert_not_called()

    async def test_provider_wide_gate_closes_streaming(self):
        pg = _real_pg("ollama")
        pg.mark_llm_unavailable("unavailable", caller="x")
        engine = AdaptivePayloadEngine(pg)
        # gate が閉じていれば streaming helper に到達しない。
        with patch.object(engine, "_stream_ollama") as stream:
            result = await engine.mutate_payload("sqli", ["p"], field_name="q")
        self.assertEqual(result, [])
        stream.assert_not_called()


if __name__ == "__main__":
    unittest.main()
