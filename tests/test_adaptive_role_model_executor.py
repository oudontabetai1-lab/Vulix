"""_stream_claude が use_role("adaptive") の role model を executor 越しに使う回帰。

ContextVar は run_in_executor のワーカースレッドへ伝播しないため、モデルを async 文脈で
確定してから executor へ渡す必要がある（LLM-004 の ContextVar 化で生じた thread 境界の穴）。
本テストは修正前なら default モデルを送ってしまい fail する。
"""
import asyncio

from wscan.adaptive_payload import AdaptivePayloadEngine
from wscan.payload_gen import PayloadGenerator


class _FakeStream:
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    @property
    def text_stream(self):
        return iter(())


class _FakeBlock:
    text = "payload"


class _FakeResponse:
    content = [_FakeBlock()]


class _FakeMessages:
    def __init__(self, sink):
        self._sink = sink

    def stream(self, *, model, **kw):
        self._sink.append(model)
        return _FakeStream()

    async def create(self, *, model, **kw):
        # AsyncAnthropic 化後（Codex #173 P2）: adaptive/planner は async create を使う。
        self._sink.append(model)
        if getattr(self, "delay", 0):
            await asyncio.sleep(self.delay)
        return _FakeResponse()


class _FakeClient:
    def __init__(self, sink, opts=None):
        self.messages = _FakeMessages(sink)
        self._opts = opts if opts is not None else []

    def with_options(self, **kw):
        self._opts.append(kw)
        return self


def test_stream_claude_uses_adaptive_role_model_across_executor():
    used_models = []
    pg = PayloadGenerator(
        provider="claude",
        claude_model="DEFAULT-MODEL",
        role_models={"adaptive": "ADAPTIVE-MODEL"},
    )
    pg._get_async_anthropic_client = lambda: _FakeClient(used_models)
    engine = AdaptivePayloadEngine(pg)

    async def run():
        with pg.use_role("adaptive"):
            await engine._stream_claude("hi")

    asyncio.run(run())
    assert used_models == ["ADAPTIVE-MODEL"], used_models


def test_stream_claude_disables_sdk_retries_for_deadline_call():
    # deadline を wait_for で縛るため、SDK 内 retry を max_retries=0 で無効化する（Codex #173 P1）。
    opts = []
    pg = PayloadGenerator(provider="claude", claude_model="M")
    pg._get_async_anthropic_client = lambda: _FakeClient([], opts=opts)
    engine = AdaptivePayloadEngine(pg)

    async def run():
        await engine._stream_claude("hi")

    asyncio.run(run())
    assert opts and opts[0].get("max_retries") == 0, opts


def test_stream_claude_enforces_deadline_without_grace():
    # overall deadline は設定値そのもの（+5s 猶予なし）で、超過時は cancel して None（Codex #173 P2）。
    import time
    pg = PayloadGenerator(provider="claude", claude_model="M", llm_stream_timeout_seconds=0.2)
    client = _FakeClient([])
    client.messages.delay = 5
    pg._get_async_anthropic_client = lambda: client
    engine = AdaptivePayloadEngine(pg)
    t = time.monotonic()
    assert asyncio.run(engine._stream_claude("hi")) is None
    assert time.monotonic() - t < 1.5
