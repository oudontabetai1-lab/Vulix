"""フォーム送達待機は相関した応答本文の取得までに限る。"""
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wscan.browser import BrowserManager


def pair(query="q=probe", body="", sequence=2):
    return {"request": {"url": f"http://example.test/form?{query}",
                        "method": "GET", "_capture_sequence": sequence},
            "response": {"body": body} if body is not None else {}}


@pytest.mark.asyncio
async def test_completed_carrier_does_not_sleep(monkeypatch):
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    browser = SimpleNamespace(network=SimpleNamespace(pairs=[pair()]))
    await BrowserManager._wait_for_form_response(
        browser, {"q": "probe"}, {"action": "http://example.test/form", "method": "GET"}, 1)
    sleep.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("initial", [[], [pair(body=None)], [pair(sequence=1)],
                                     [pair("q=other")], [pair("q=probe&b=other")]])
async def test_waits_for_fresh_complete_carrier(monkeypatch, initial):
    browser = SimpleNamespace(network=SimpleNamespace(pairs=initial))
    async def complete(_):
        browser.network.pairs.append(pair("q=probe&b=second"))
    sleep = AsyncMock(side_effect=complete)
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    await BrowserManager._wait_for_form_response(
        browser, {"q": "probe", "b": "second"},
        {"action": "http://example.test/form", "method": "GET"}, 1)
    sleep.assert_awaited_once()


@pytest.mark.asyncio
async def test_missing_response_has_bounded_wait():
    import time
    browser = SimpleNamespace(network=SimpleNamespace(pairs=[]))
    started = time.monotonic()
    await BrowserManager._wait_for_form_response(
        browser, {"q": "probe"}, {"action": "http://example.test/form", "method": "GET"}, 1)
    assert 0.19 <= time.monotonic() - started < 1
