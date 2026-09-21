"""0065: LLM streaming timeout（planner/adaptive）を config/CLI から設定可能にした回帰。"""
import asyncio
import math
import tempfile
from pathlib import Path
from unittest.mock import patch

from wscan.payload_gen import PayloadGenerator
from wscan.attack_planner import AttackPlanner


def test_stream_timeout_default_is_90():
    pg = PayloadGenerator(provider="none")
    assert pg.llm_stream_timeout_seconds == 90.0


def test_stream_timeout_custom_value():
    pg = PayloadGenerator(provider="none", llm_stream_timeout_seconds=45)
    assert pg.llm_stream_timeout_seconds == 45.0


def test_stream_timeout_invalid_falls_back_to_90():
    for bad in (0, -5, float("nan"), float("inf"), "x", None):
        pg = PayloadGenerator(provider="none", llm_stream_timeout_seconds=bad)
        assert pg.llm_stream_timeout_seconds == 90.0, bad


def test_config_reads_stream_timeout_seconds():
    from main import _load_config
    # 既定 config には stream_timeout_seconds: 90 がある。
    assert _load_config()["llm_stream_timeout_seconds"] == 90.0
    # 欠落した最小 config でも既定 90（後方互換）。
    with tempfile.TemporaryDirectory() as d:
        p = Path(d) / "c.yaml"
        p.write_text("llm:\n  timeout_seconds: 12\n", encoding="utf-8")
        assert _load_config(p)["llm_stream_timeout_seconds"] == 90.0


def test_planner_ollama_uses_stream_timeout():
    # planner の httpx 呼び出しが pg.llm_stream_timeout_seconds を timeout に使う（配線の end-to-end）。
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=45)
    planner = AttackPlanner(pg, ["xss"])
    captured = {}

    class _FakeClient:
        def __init__(self, *a, **k):
            captured["timeout"] = k.get("timeout")

        async def __aenter__(self):
            raise RuntimeError("stop after capturing timeout")

        async def __aexit__(self, *a):
            return False

    with patch("httpx.AsyncClient", _FakeClient):
        asyncio.run(planner._call_ollama("prompt"))
    assert captured["timeout"] == 45.0


def test_one_shot_timeout_invalid_falls_back_to_30():
    # one-shot timeout も serve API 等の null/非数値/不正で例外化せず既定 30 に倒す（Codex #173 P2）。
    for bad in (0, -1, float("nan"), float("inf"), "x", None):
        pg = PayloadGenerator(provider="none", llm_timeout_seconds=bad)
        assert pg.llm_timeout_seconds == 30.0, bad
    assert PayloadGenerator(provider="none", llm_timeout_seconds=45).llm_timeout_seconds == 45.0


def test_report_analysis_uses_configured_one_shot_timeout():
    # report 分析は固定 60s ではなく設定済み one-shot timeout を使う（Codex #173 P2）。
    import types
    from wscan.engine import ScanEngine
    from wscan import llm_client
    pg = PayloadGenerator(provider="ollama", llm_timeout_seconds=25)
    captured = {}

    async def _fake_complete(payload_gen, prompt, **kw):
        captured.update(kw)
        return "analysis"

    eng = types.SimpleNamespace(payload_gen=pg)
    with patch.object(llm_client, "complete_text", _fake_complete):
        out = asyncio.run(ScanEngine._call_llm_text(eng, "prompt"))
    assert out == "analysis"
    assert captured.get("timeout") == 25.0     # 固定 60 ではなく設定値


def test_stream_ollama_bounded_by_overall_deadline():
    # チャンクが届き続けても全体が llm_stream_timeout_seconds を超えたら打ち切る（Codex #173 P2）。
    import types
    from wscan.adaptive_payload import AdaptivePayloadEngine

    class _SlowStream:
        status_code = 200
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        async def aiter_lines(self):
            # 各行は届くが全体で deadline を超える（無限に近いチャンク列）。
            while True:
                await asyncio.sleep(0.02)
                yield '{"response": "x", "done": false}'

    class _FakeClient:
        def __init__(self, *a, **k): pass
        async def __aenter__(self): return self
        async def __aexit__(self, *a): return False
        def stream(self, *a, **k): return _SlowStream()

    import time as _time
    import httpx
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=0.1)
    eng = AdaptivePayloadEngine.__new__(AdaptivePayloadEngine)
    eng.pg = pg
    with patch.object(httpx, "AsyncClient", _FakeClient):
        start = _time.monotonic()
        asyncio.run(eng._stream_ollama("prompt"))
        elapsed = _time.monotonic() - start
    # deadline(0.1s) 付近で打ち切られる。チャンクが届き続けても無限には回らない。
    assert elapsed < 2.0
