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
@pytest.mark.parametrize("default_prevented", [None, False, True])
def test_submit_wait_policy(fast, navigated, observed, default_prevented):
    assert form_submit_wait_seconds(fast=fast, navigated=navigated, observed=observed, default_prevented=default_prevented) == (
        0 if fast and navigated and observed and default_prevented is False else .2)


@pytest.mark.asyncio
@pytest.mark.parametrize("factor,results,delay", [
    (1., [], .2), (.5, [], .2), (0., [True, False], 0),
    (0., [True, True], .2), (0., [None, True], .2), (0., [True, None], .2),
    (0., [RuntimeError("unavailable"), True], .2),
    (0., [True, RuntimeError("unavailable"), True], .2),
])
async def test_document_observation_and_fallback(monkeypatch, factor, results, delay):
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=results), expose_binding=AsyncMock())
    browser = SimpleNamespace(page=page, sleep_factor=factor)
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    result = {}
    async with BrowserManager._form_submit_wait(browser, result, 0):
        if factor == 0:
            result["default_prevented"] = False
    if delay:
        sleep.assert_awaited_once_with(.2)
    else:
        sleep.assert_not_awaited()
    if factor:
        page.evaluate.assert_not_awaited()


@pytest.mark.asyncio
async def test_marker_is_removed_when_submission_raises(monkeypatch):
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[True, True]), expose_binding=AsyncMock())
    browser = SimpleNamespace(page=page, sleep_factor=0)
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    with pytest.raises(RuntimeError, match="submission"):
        async with BrowserManager._form_submit_wait(browser, {}, 0):
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
                              page=SimpleNamespace(evaluate=AsyncMock(side_effect=[True, True]), expose_binding=AsyncMock()))
    async def late():
        await asyncio.sleep(delay)
        await asyncio.sleep(.01)
        pairs.append(pair(3, "you have an error in your sql syntax"))
    task = asyncio.create_task(late())
    try:
        async with BrowserManager._form_submit_wait(browser, {}, 0):
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
@pytest.mark.parametrize("js", [False, True, "redirect", "window_redirect", "direct"])
async def test_native_navigation_and_delayed_js_submission(monkeypatch, fast, multi, js):
    from fastapi import FastAPI
    from fastapi.responses import HTMLResponse
    from tests.test_totp_login_e2e import serving
    import wscan.browser as module

    app = FastAPI()
    @app.get("/form", response_class=HTMLResponse)
    async def form():
        handler = ""
        if js is True:
            handler = """<script>document.querySelector('form').onsubmit = event => {
                event.preventDefault(); const form = event.currentTarget;
                setTimeout(() => fetch(form.action, {method: 'POST',
                  body: new URLSearchParams(new FormData(form))}), 100);
            };</script>"""
        elif js in ("redirect", "window_redirect"):
            target = "window" if js == "window_redirect" else "document.querySelector('form')"
            handler = """<script>TARGET.addEventListener('submit', event => {
                event.preventDefault();
                fetch('/form', {method: 'POST', body: new URLSearchParams(new FormData(event.target))});
                location.assign('/done');
            });</script>""".replace("TARGET", target)
        button = "" if js == "direct" else "<button>Submit</button>"
        return ('<form method="post" action="/form"><input name="q">'
                '<input name="other">' + button + '</form>' + handler)

    @app.get("/done", response_class=HTMLResponse)
    async def done():
        return "Done"

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
            if js not in ("redirect", "window_redirect"):
                assert browser.last_probe_delivered
                assert "error in your sql syntax" in captured["response"]["body"]
            observation, seconds = observations[-1]
            native = js in (False, "direct")
            if js == "direct":
                # evaluate と文書遷移が競合した場合も、観測不能なら待機を維持する。
                assert seconds == form_submit_wait_seconds(**observation)
                if multi:
                    assert observation["default_prevented"] is False
            else:
                assert seconds == (0 if fast and native else .2)
            if fast and js != "direct":
                assert observation["observed"]
                assert observation["navigated"] == (js is not True)
                if js not in ("window_redirect", "direct"):
                    assert observation["default_prevented"] is (False if native else True)
            assert await browser.page.evaluate(
                "() => Object.getOwnPropertyNames(document).filter(k => k.startsWith('__vulix_form_')).length"
            ) == 0
        finally:
            await browser.close()


@pytest.mark.asyncio
async def test_submit_binding_is_reused_and_validates_observations(monkeypatch):
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[True, False, True, False]),
                           expose_binding=AsyncMock(), main_frame=object())
    browser = SimpleNamespace(page=page, sleep_factor=0)
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    for prevented in [True, False]:
        result = {}
        async with BrowserManager._form_submit_wait(browser, result, 0):
            key = next(iter(page._vulix_submit_observers))
            record = page.expose_binding.call_args.args[1]
            record({"frame": object()}, key, False)
            record({"frame": page.main_frame}, [], False)
            record({"frame": page.main_frame}, key, "false")
            assert result["default_prevented"] is None
            record({"frame": page.main_frame}, key, prevented)
            record({"frame": page.main_frame}, key, False)
        assert result["default_prevented"] is prevented
        assert page._vulix_submit_observers == {}
    page.expose_binding.assert_awaited_once()
    sleep.assert_awaited_once_with(.2)


@pytest.mark.asyncio
async def test_direct_submit_does_not_require_submit_event(monkeypatch):
    page = SimpleNamespace(evaluate=AsyncMock(side_effect=[True, False]), expose_binding=AsyncMock())
    browser = SimpleNamespace(page=page, sleep_factor=0)
    sleep = AsyncMock()
    monkeypatch.setattr("wscan.browser.asyncio.sleep", sleep)
    result = {}
    async with BrowserManager._form_submit_wait(browser, result, 0, direct_submit=True):
        pass
    assert result["default_prevented"] is False
    page.expose_binding.assert_not_awaited()
    sleep.assert_not_awaited()
