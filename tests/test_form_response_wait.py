"""通常送信の観測時間を保ち、fast の文書遷移だけ待機を省く。"""
import asyncio
import os
from types import SimpleNamespace
from unittest.mock import AsyncMock

import pytest

from wscan.browser import BrowserManager, _request_carries_form_value, form_submit_wait_seconds


@pytest.mark.parametrize("fast", [False, True])
@pytest.mark.parametrize("navigated", [False, True])
@pytest.mark.parametrize("observed", [False, True])
def test_submit_wait_policy(fast, navigated, observed):
    assert form_submit_wait_seconds(fast=fast, navigated=navigated, observed=observed) == (
        0 if fast and navigated and observed else .2)


@pytest.mark.asyncio
@pytest.mark.parametrize("factor,results,delay", [
    (1., [], .2), (.5, [], .2), (0., [True, False], 0),
    (0., [True, True], .2), (0., [None], .2), (0., [True, None], .2),
    (0., [RuntimeError("unavailable")], .2),
    (0., [True, RuntimeError("unavailable"), True], .2),
])
async def test_document_observation_and_fallback(monkeypatch, factor, results, delay):
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=results))
    browser = SimpleNamespace(page=page, sleep_factor=factor)
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    async with BrowserManager._form_submit_wait(browser):
        pass
    if delay:
        sleep.assert_awaited_once_with(.2)
    else:
        sleep.assert_not_awaited()
    if factor:
        page.evaluate.assert_not_awaited()


@pytest.mark.asyncio
async def test_marker_is_removed_when_submission_raises(monkeypatch):
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[True, True]))
    browser = SimpleNamespace(page=page, sleep_factor=0)
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    with pytest.raises(RuntimeError, match="submission"):
        async with BrowserManager._form_submit_wait(browser):
            raise RuntimeError("submission")
    assert page.evaluate.await_count == 2
    assert "delete document[key]" in page.evaluate.call_args.args[0]
    sleep.assert_not_awaited()


@pytest.mark.asyncio
@pytest.mark.parametrize("fast", [False, True])
@pytest.mark.parametrize("resource,delay", [("document", .05), ("xhr", .05), ("xhr", .1)],
                         ids=["classic_then_xhr", "validation_then_submit", "late_request"])
async def test_preserves_delayed_response_without_observed_navigation(fast, resource, delay):
    def pair(sequence, body):
        return {"request": {"url": "http://example.test/form?q=probe", "method": "GET",
                            "_capture_sequence": sequence, "resource_type": resource},
                "response": {"body": body}}
    pairs = [pair(2, "validation ok")]
    browser = SimpleNamespace(sleep_factor=0 if fast else 1,
                              page=SimpleNamespace(evaluate=AsyncMock(side_effect=[True, True])))
    async def late():
        await asyncio.sleep(delay)
        await asyncio.sleep(.01)
        pairs.append(pair(3, "you have an error in your sql syntax"))
    task = asyncio.create_task(late())
    try:
        async with BrowserManager._form_submit_wait(browser):
            pass
        selected = next(p for p in reversed(pairs) if _request_carries_form_value(
            p, "q", "probe", submission={"action": "http://example.test/form", "method": "GET"}, since=1))
        assert "error in your sql syntax" in selected["response"]["body"]
    finally:
        await task


@pytest.mark.skipif(os.getenv("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 で実ブラウザ検証")
@pytest.mark.asyncio
@pytest.mark.parametrize("fast", [False, True])
@pytest.mark.parametrize("multi", [False, True])
@pytest.mark.parametrize("js", [False, True])
async def test_native_navigation_and_delayed_js_submission(monkeypatch, fast, multi, js):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    from tests.test_totp_login_e2e import serving
    import wscan.browser as module

    app = FastAPI()
    @app.get("/form", response_class=HTMLResponse)
    async def form():
        handler = """<script>document.querySelector('form').onsubmit = event => {
            event.preventDefault(); const form = event.currentTarget;
            setTimeout(() => fetch(form.action, {method: 'POST',
              body: new URLSearchParams(new FormData(form))}), 100);
        };</script>""" if js else ""
        return ('<form method="post" action="/form"><input name="q">'
                '<input name="other"><button>Submit</button></form>' + handler)

    @app.post("/form", response_class=HTMLResponse)
    async def result():
        await asyncio.sleep(.01)
        return "you have an error in your sql syntax"

    observations = []
    def policy(**kwargs):
        seconds = form_submit_wait_seconds(**kwargs)
        observations.append((kwargs, seconds))
        return seconds
    monkeypatch.setattr(module, "form_submit_wait_seconds", policy)
    with serving(app) as base:
        browser = BrowserManager(headless=True, sleep_factor=0 if fast else 1)
        await browser.init()
        try:
            await browser.navigate(base + "/form")
            if multi:
                _, captured = await browser.fill_and_submit_form_multi(0, {"q": "probe", "other": "second"})
            else:
                _, captured = await browser.fill_and_submit_form(0, "q", "probe")
            assert browser.last_probe_delivered
            assert "error in your sql syntax" in captured["response"]["body"]
            observation, seconds = observations[-1]
            assert seconds == (0 if fast and not js else .2)
            if fast:
                assert observation["observed"] and observation["navigated"] == (not js)
            assert await browser.page.evaluate(
                "() => Object.getOwnPropertyNames(document).filter(k => k.startsWith('__vulix_form_')).length"
            ) == 0
        finally:
            await browser.close()
