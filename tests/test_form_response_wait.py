"""フォーム送達待機は、相関応答を取得して通信が静止するまで続ける。"""
import asyncio
import time
from types import SimpleNamespace

import pytest

from wscan.browser import BrowserManager, _request_carries_form_value, form_response_is_quiet

SUBMISSION = {"action": "http://example.test/form", "method": "GET"}


def pair(query="q=probe", body="", sequence=2, resource="xhr"):
    return {"request": {"url": f"http://example.test/form?{query}", "method": "GET",
                        "_capture_sequence": sequence, "resource_type": resource},
            "response": {"body": body} if body is not None else {}}


def test_quiet_response_requires_all_three_conditions():
    args = dict(pending=0, correlated=True, last_activity=0., now=.05)
    assert form_response_is_quiet(**args)
    assert not form_response_is_quiet(**dict(args, pending=1))
    assert not form_response_is_quiet(**dict(args, correlated=False))
    assert not form_response_is_quiet(**dict(args, now=.049))


@pytest.mark.asyncio
@pytest.mark.parametrize("resource", ["document", "xhr"],
                         ids=["classic_then_xhr", "validation_then_submit"])
async def test_observes_later_correlated_response(resource):
    net = SimpleNamespace(pairs=[pair(body="validation ok", resource=resource)])
    async def late_response():
        await asyncio.sleep(.05)
        net.pairs.append(pair(body="you have an error in your sql syntax", sequence=3))
    task = asyncio.create_task(late_response())
    try:
        await BrowserManager._wait_for_form_response(
            SimpleNamespace(network=net), {"q": "probe"}, SUBMISSION, 1)
        selected = next(p for p in reversed(net.pairs) if _request_carries_form_value(
            p, "q", "probe", submission=SUBMISSION, since=1))
        assert "error in your sql syntax" in selected["response"]["body"]
    finally:
        await task


@pytest.mark.asyncio
@pytest.mark.parametrize("initial", [[], [pair(body=None)], [pair(sequence=1)],
                                     [pair("q=other")], [pair("q=probe&b=other")]])
async def test_waits_for_fresh_complete_carrier(initial):
    net = SimpleNamespace(pairs=initial)
    async def complete():
        await asyncio.sleep(.03)
        net.pairs.append(pair("q=probe&b=second"))
    task = asyncio.create_task(complete())
    try:
        started = time.monotonic()
        await BrowserManager._wait_for_form_response(
            SimpleNamespace(network=net), {"q": "probe", "b": "second"}, SUBMISSION, 1)
        assert time.monotonic() - started >= .075
    finally:
        await task


@pytest.mark.asyncio
async def test_pending_request_prevents_early_return():
    net = SimpleNamespace(pairs=[pair()], _pending={1: {"_capture_sequence": 3}})
    started = time.monotonic()
    await BrowserManager._wait_for_form_response(
        SimpleNamespace(network=net), {"q": "probe"}, SUBMISSION, 1)
    assert .19 <= time.monotonic() - started < 1


@pytest.mark.asyncio
async def test_completed_carrier_waits_for_quiet_period():
    net = SimpleNamespace(pairs=[pair()])
    started = time.monotonic()
    await BrowserManager._wait_for_form_response(
        SimpleNamespace(network=net), {"q": "probe"}, SUBMISSION, 1)
    assert .045 <= time.monotonic() - started < .19


@pytest.mark.asyncio
async def test_old_pairs_are_only_inspected_once():
    class CountDict(dict):
        reads = 0
        def get(self, *args):
            type(self).reads += 1
            return super().get(*args)
    net = SimpleNamespace(pairs=[CountDict(pair(sequence=1)) for _ in range(20000)])
    started = time.monotonic()
    await BrowserManager._wait_for_form_response(
        SimpleNamespace(network=net), {"q": "probe"}, SUBMISSION, 1)
    assert .19 <= time.monotonic() - started < 1
    assert CountDict.reads == 20000
