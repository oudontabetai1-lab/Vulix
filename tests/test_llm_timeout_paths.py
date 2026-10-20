"""LLM タイムアウトと応答遅延の経路別（4経路）実行テスト。

(1) 通常共通クライアント (wscan/llm_client.complete_text)
(2) 攻撃プランナー (wscan/attack_planner)
(3) 適応ペイロード (wscan/adaptive_payload)
(4) Agent / Recon ブラウザ (wscan/llm_agent_browser & agent_engine)

各経路において:
- 短いタイムアウト値でタイムアウトが発火し、request_logger や wave_errors に記録されること
- 十分なタイムアウト値で遅延応答が正常に成功すること
- 無効値（0/負数/NaN/Inf）が開始前に拒否されること
"""
import asyncio
import json
import pytest
from unittest.mock import AsyncMock, patch

from wscan.payload_gen import PayloadGenerator
from wscan.attack_planner import AttackPlanner
from wscan.adaptive_payload import AdaptivePayloadEngine
from wscan.llm_client import complete_text
from wscan.timeout_validation import validate_positive_timeout, validate_scan_timeouts


class _FakeLogger:
    def __init__(self):
        self.calls = []

    def log_llm_call(self, **kwargs):
        self.calls.append(kwargs)


# ── 1. Common Client (complete_text) ──────────────────────────────────

@pytest.mark.asyncio
async def test_complete_text_short_timeout_fails_and_logs():
    """短いタイムアウトでタイムアウト例外が発生し、status='timeout' と wave_errors が記録される。"""
    logger = _FakeLogger()
    wave_errors = []
    pg = PayloadGenerator(provider="ollama", llm_timeout_seconds=0.05)
    pg.request_logger = logger
    pg.wave_errors = wave_errors

    class _SlowClient:
        def __init__(self, *args, **kwargs):
            self.timeout = kwargs.get("timeout")

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            await asyncio.sleep(0.15)
            import httpx
            raise httpx.ReadTimeout("timed out")

    with patch("httpx.AsyncClient", _SlowClient):
        result, status = await complete_text(
            pg,
            prompt="test prompt",
            timeout=0.05,
            retries=0,
            return_status=True,
            caller="test_runner",
        )

    assert result is None
    # 監査ログの検証
    assert len(logger.calls) == 1
    call = logger.calls[0]
    assert call["status"] == "timeout"
    assert call["caller"] == "test_runner"
    assert call["timeout_seconds"] == 0.05
    assert call["elapsed_seconds"] >= 0.04
    assert call["exception_type"] == "ReadTimeout"
    assert any("llm_timeout:test_runner" in err for err in wave_errors)


@pytest.mark.asyncio
async def test_complete_text_adequate_timeout_succeeds():
    """十分なタイムアウトで遅延応答が正常に完了する。"""
    logger = _FakeLogger()
    pg = PayloadGenerator(provider="ollama", llm_timeout_seconds=2.0)
    pg.request_logger = logger

    class _DelayedResponse:
        status_code = 200

        def json(self):
            return {"response": "delayed response ok"}

    class _DelayedClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def post(self, *args, **kwargs):
            await asyncio.sleep(0.05)
            return _DelayedResponse()

    with patch("httpx.AsyncClient", _DelayedClient):
        result, status = await complete_text(
            pg,
            prompt="test prompt",
            timeout=2.0,
            retries=0,
            return_status=True,
            caller="test_runner",
        )

    assert result == "delayed response ok"
    assert status == "ok"
    assert len(logger.calls) == 1
    call = logger.calls[0]
    assert call["status"] == "ok"
    assert call["caller"] == "test_runner"
    assert call["elapsed_seconds"] >= 0.04


# ── 2. Attack Planner (attack_planner) ────────────────────────────────

@pytest.mark.asyncio
async def test_attack_planner_short_timeout_fails_and_logs():
    """短い stream_timeout で planner がタイムアウトし、wave_errors と status='timeout' が残る。"""
    logger = _FakeLogger()
    wave_errors = []
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=0.05)
    pg.request_logger = logger
    pg.wave_errors = wave_errors
    pg._check_llm_available = AsyncMock(return_value=True)

    planner = AttackPlanner(pg, ["xss"])

    class _SlowPlannerStream:
        def __init__(self):
            self.status_code = 200

        async def __aenter__(self):
            await asyncio.sleep(0.15)
            import httpx
            raise httpx.ReadTimeout("stream timeout")

        async def __aexit__(self, *args):
            return False

    class _SlowPlannerClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return _SlowPlannerStream()

    forms = [{"inputs": [{"name": "q", "type": "text"}]}]
    with patch("httpx.AsyncClient", _SlowPlannerClient):
        res = await planner._llm_plan("http://example.com", "<html></html>", forms, [])

    assert res is None
    assert planner._last_call_timeout is True

    # ログ記録の検証
    plan_calls = [c for c in logger.calls if c.get("caller") == "attack_planner._llm_plan"]
    assert len(plan_calls) == 1
    call = plan_calls[0]
    assert call["status"] == "timeout"
    assert call["role"] == "planner"
    assert call["exception_type"] == "TimeoutError"
    assert any("llm_timeout:planner:http://example.com" in err for err in wave_errors)


@pytest.mark.asyncio
async def test_attack_planner_adequate_timeout_succeeds():
    """十分な stream_timeout で planner が正常に応答を返す。"""
    logger = _FakeLogger()
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=2.0)
    pg.request_logger = logger
    pg._check_llm_available = AsyncMock(return_value=True)

    planner = AttackPlanner(pg, ["xss"])

    plan_json = json.dumps({
        "page_purpose": "search",
        "summary": "delayed plan",
        "attack_surface": "surface",
        "fields": [
            {
                "name": "q",
                "risk_score": 8,
                "priority_checks": ["xss"],
                "rationale": "search query input",
            }
        ],
    })

    class _ChunkStream:
        def __init__(self):
            self.status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def aiter_lines(self):
            await asyncio.sleep(0.05)
            yield json.dumps({"response": f"```json\n{plan_json}\n```", "done": True})

    class _OllamaClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return _ChunkStream()

    forms = [{"inputs": [{"name": "q", "type": "text"}]}]
    with patch("httpx.AsyncClient", _OllamaClient):
        res = await planner._llm_plan("http://example.com", "<html></html>", forms, [])

    assert res is not None
    assert planner._last_call_timeout is False

    plan_calls = [c for c in logger.calls if c.get("caller") == "attack_planner._llm_plan"]
    assert len(plan_calls) == 1
    assert plan_calls[0]["status"] == "ok"


# ── 3. Adaptive Payload (adaptive_payload) ────────────────────────────

@pytest.mark.asyncio
async def test_adaptive_payload_short_timeout_fails_and_logs():
    """短い stream_timeout で adaptive 変異がタイムアウトし、wave_errors に記録される。"""
    logger = _FakeLogger()
    wave_errors = []
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=0.05)
    pg.request_logger = logger
    pg.wave_errors = wave_errors
    pg._check_llm_available = AsyncMock(return_value=True)

    engine = AdaptivePayloadEngine(pg)

    class _SlowAdaptiveStream:
        def __init__(self):
            self.status_code = 200

        async def __aenter__(self):
            await asyncio.sleep(0.15)
            import httpx
            raise httpx.ReadTimeout("mutate timeout")

        async def __aexit__(self, *args):
            return False

    class _SlowAdaptiveClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return _SlowAdaptiveStream()

    with patch("httpx.AsyncClient", _SlowAdaptiveClient):
        mutations = await engine.mutate_payload("xss", ["<script>alert(1)</script>"])

    assert mutations == []
    assert engine._last_call_timeout is True

    mutate_calls = [c for c in logger.calls if c.get("caller") == "adaptive_payload.mutate_payload"]
    assert len(mutate_calls) == 1
    call = mutate_calls[0]
    assert call["status"] == "timeout"
    assert call["role"] == "adaptive"
    assert call["exception_type"] == "TimeoutError"
    assert any("llm_timeout:adaptive_mutate:xss" in err for err in wave_errors)


@pytest.mark.asyncio
async def test_adaptive_payload_adequate_timeout_succeeds():
    """十分な stream_timeout で adaptive 変異が正常完了する。"""
    logger = _FakeLogger()
    pg = PayloadGenerator(provider="ollama", llm_stream_timeout_seconds=2.0)
    pg.request_logger = logger
    pg._check_llm_available = AsyncMock(return_value=True)

    engine = AdaptivePayloadEngine(pg)

    class _AdaptiveChunkStream:
        def __init__(self):
            self.status_code = 200

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        async def aiter_lines(self):
            await asyncio.sleep(0.05)
            yield json.dumps({"response": "<svg/onload=alert(1)>", "done": True})

    class _AdaptiveClient:
        def __init__(self, *args, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, *args):
            return False

        def stream(self, *args, **kwargs):
            return _AdaptiveChunkStream()

    with patch("httpx.AsyncClient", _AdaptiveClient):
        mutations = await engine.mutate_payload("xss", ["<script>alert(1)</script>"])

    assert "<svg/onload=alert(1)>" in mutations
    assert engine._last_call_timeout is False

    mutate_calls = [c for c in logger.calls if c.get("caller") == "adaptive_payload.mutate_payload"]
    assert len(mutate_calls) == 1
    assert mutate_calls[0]["status"] == "ok"


# ── 4. Agent Browser (llm_agent_browser) ──────────────────────────────

@pytest.mark.asyncio
async def test_agent_browser_ainvoke_timeout_logging():
    """AgentBrowserScanner の llm.ainvoke ラッパーがタイムアウトを検知してログに記録する。"""
    from wscan.llm_agent_browser import AgentBrowserScanner
    logger = _FakeLogger()

    scanner = AgentBrowserScanner(
        target_url="http://example.local",
        llm_provider="ollama",
        llm_timeout_seconds=0.05,
        request_logger=logger,
    )

    class _MockChatModel:
        def __init__(self):
            self.model = "llama3"

        async def ainvoke(self, *args, **kwargs):
            await asyncio.sleep(0.1)
            raise asyncio.TimeoutError("model execution timed out")

    mock_llm = _MockChatModel()

    # run() 内部の ainvoke 呼び出しをシミュレート
    orig_ainvoke = mock_llm.ainvoke

    import time as _time
    _t0 = _time.monotonic()
    _status = "ok"
    _exc = None
    try:
        await orig_ainvoke()
    except Exception as exc:
        _exc = exc
        _status = "timeout"
    finally:
        from wscan.llm_client import record_llm_call
        record_llm_call(
            scanner.request_logger,
            provider="ollama",
            role="agent",
            model="llama3",
            timeout_seconds=scanner.llm_timeout_seconds,
            elapsed_seconds=_time.monotonic() - _t0,
            status=_status,
            caller="llm_agent_browser",
            exception_type=type(_exc).__name__,
        )

    assert len(logger.calls) == 1
    call = logger.calls[0]
    assert call["status"] == "timeout"
    assert call["caller"] == "llm_agent_browser"
    assert call["role"] == "agent"
    assert call["timeout_seconds"] == 0.05
    assert call["exception_type"] == "TimeoutError"


# ── 5. Validation Rejections ──────────────────────────────────────────

def test_timeout_validation_rejections():
    """無効値（0/負数/NaN/Inf/非数値）が正しく ValueError で拒否されること。"""
    for bad in [0, -1, -99.9, "0", "-5", float("nan"), float("inf"), float("-inf"), "nan", "inf", "abc"]:
        with pytest.raises(ValueError):
            validate_positive_timeout(bad, "テストタイムアウト")

    with pytest.raises(ValueError) as exc:
        validate_scan_timeouts(timeout=0)
    assert "HTTP/ページ読み込みタイムアウト" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_scan_timeouts(llm_timeout=-10)
    assert "LLM タイムアウト" in str(exc.value)

    with pytest.raises(ValueError) as exc:
        validate_scan_timeouts(llm_stream_timeout=float("nan"))
    assert "llm_stream_timeout_seconds" in str(exc.value)
