"""Loopback fixture tests for client-side form validation bypass.

HTML5 制約検証（type=url, required, pattern=, number 等）によりブラウザ側で
送信阻止されていたフォームプローブが、noValidate / type=text 化によるバイパスで
正しく送達され、脆弱なエンドポイントでは所見が検出され、安全ツインでは偽陽性なく
クリーンになることを検証する。
また、JavaScript onsubmit ハンドラ（return false）による送信抑止時の挙動も検証する。
"""

import asyncio
import html
import sqlite3
import pytest
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

from tests.test_totp_login_e2e import serving
from wscan.browser import BrowserManager
from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import BaseScanner
from wscan.scanners.xss import XSSScanner


@pytest.mark.asyncio
async def test_xss_behind_type_url_required_vulnerable_and_safe_twin():
    """type=url + required のフォームで XSS 脆弱エンドポイントが検出され、safe twin は clean。"""
    app = FastAPI()

    @app.get("/xss_url/vuln", response_class=HTMLResponse)
    async def vuln(dest: str | None = None):
        if dest is None:
            return HTMLResponse(
                '<form action="/xss_url/vuln" method="get">'
                '<input type="url" name="dest" required>'
                '<button type="submit">Submit</button>'
                '</form>'
            )
        # 脆弱: 生反射
        return HTMLResponse(f"<html><body>Result: {dest}</body></html>")

    @app.get("/xss_url/safe", response_class=HTMLResponse)
    async def safe(dest: str | None = None):
        if dest is None:
            return HTMLResponse(
                '<form action="/xss_url/safe" method="get">'
                '<input type="url" name="dest" required>'
                '<button type="submit">Submit</button>'
                '</form>'
            )
        # 安全ツイン: HTML エスケープ
        return HTMLResponse(f"<html><body>Result: {html.escape(dest)}</body></html>")

    with serving(app) as url:
        # 1. 脆弱側
        engine_vuln = ScanEngine(
            url + "/xss_url/vuln",
            checks=["xss"],
            llm_provider="none",
            headless=True,
            open_report=False,
            depth=1,
            timeout=5,
        )
        await engine_vuln.run()
        vuln_findings = [f for f in engine_vuln.all_findings if f.field_name == "dest"]
        assert len(vuln_findings) >= 1, "Vulnerable type=url+required must be detected"
        assert all(f.check_type == "xss" for f in vuln_findings)

        # 2. 安全ツイン
        engine_safe = ScanEngine(
            url + "/xss_url/safe",
            checks=["xss"],
            llm_provider="none",
            headless=True,
            open_report=False,
            depth=1,
            timeout=5,
        )
        await engine_safe.run()
        safe_findings = [f for f in engine_safe.all_findings if f.field_name == "dest"]
        assert len(safe_findings) == 0, f"Safe twin must be clean, got: {safe_findings}"
        assert not any("probe_not_delivered" in err for err in engine_safe.wave_errors)


@pytest.mark.asyncio
async def test_xss_behind_pattern_vulnerable_and_safe_twin():
    """pattern= のフォームで XSS 脆弱エンドポイントが検出され、safe twin は clean。"""
    app = FastAPI()

    @app.get("/xss_pattern/vuln", response_class=HTMLResponse)
    async def vuln(dest: str | None = None):
        if dest is None:
            return HTMLResponse(
                '<form action="/xss_pattern/vuln" method="get">'
                '<input type="text" name="dest" pattern="[0-9]+">'
                '<button type="submit">Submit</button>'
                '</form>'
            )
        return HTMLResponse(f"<html><body>Code: {dest}</body></html>")

    @app.get("/xss_pattern/safe", response_class=HTMLResponse)
    async def safe(dest: str | None = None):
        if dest is None:
            return HTMLResponse(
                '<form action="/xss_pattern/safe" method="get">'
                '<input type="text" name="dest" pattern="[0-9]+">'
                '<button type="submit">Submit</button>'
                '</form>'
            )
        return HTMLResponse(f"<html><body>Code: {html.escape(dest)}</body></html>")

    with serving(app) as url:
        # 1. 脆弱側
        engine_vuln = ScanEngine(
            url + "/xss_pattern/vuln",
            checks=["xss"],
            llm_provider="none",
            headless=True,
            open_report=False,
            depth=1,
            timeout=5,
        )
        await engine_vuln.run()
        vuln_findings = [f for f in engine_vuln.all_findings if f.field_name == "dest"]
        assert len(vuln_findings) >= 1, "Vulnerable pattern=[0-9]+ must be detected"

        # 2. 安全ツイン
        engine_safe = ScanEngine(
            url + "/xss_pattern/safe",
            checks=["xss"],
            llm_provider="none",
            headless=True,
            open_report=False,
            depth=1,
            timeout=5,
        )
        await engine_safe.run()
        safe_findings = [f for f in engine_safe.all_findings if f.field_name == "dest"]
        assert len(safe_findings) == 0, f"Safe twin must be clean, got: {safe_findings}"
        assert not any("probe_not_delivered" in err for err in engine_safe.wave_errors)


@pytest.mark.asyncio
async def test_sqli_behind_type_url_and_pattern():
    """SQLi 脆弱エンドポイントが type=url / pattern= の背後でも検出され、safe twin は clean。"""
    app = FastAPI()
    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE users (id TEXT, name TEXT)")
    db.execute("INSERT INTO users VALUES ('1', 'Alice')")
    db.commit()

    @app.get("/sqli_pattern/vuln", response_class=HTMLResponse)
    async def vuln(id: str | None = None):
        if id is None:
            return HTMLResponse(
                '<form action="/sqli_pattern/vuln" method="get">'
                '<input type="text" name="id" pattern="[0-9]+">'
                '<button type="submit">Search</button>'
                '</form>'
            )
        try:
            res = db.execute(f"SELECT * FROM users WHERE id = '{id}'").fetchall()
            return HTMLResponse(f"<p>Found: {len(res)}</p>")
        except Exception as e:
            return HTMLResponse(f"<p>DB Error: sqlite3.OperationalError: {e}</p>")

    @app.get("/sqli_pattern/safe", response_class=HTMLResponse)
    async def safe(id: str | None = None):
        if id is None:
            return HTMLResponse(
                '<form action="/sqli_pattern/safe" method="get">'
                '<input type="text" name="id" pattern="[0-9]+">'
                '<button type="submit">Search</button>'
                '</form>'
            )
        try:
            res = db.execute("SELECT * FROM users WHERE id = ?", (id,)).fetchall()
            return HTMLResponse(f"<p>Found: {len(res)}</p>")
        except Exception as e:
            return HTMLResponse(f"<p>DB Error: {e}</p>")

    with serving(app) as url:
        engine_vuln = ScanEngine(
            url + "/sqli_pattern/vuln",
            checks=["sqli"],
            llm_provider="none",
            headless=True,
            open_report=False,
            depth=1,
            timeout=5,
        )
        await engine_vuln.run()
        vuln_findings = [f for f in engine_vuln.all_findings if f.field_name == "id"]
        assert len(vuln_findings) >= 1, "SQLi behind pattern=[0-9]+ must be detected"

        engine_safe = ScanEngine(
            url + "/sqli_pattern/safe",
            checks=["sqli"],
            llm_provider="none",
            headless=True,
            open_report=False,
            depth=1,
            timeout=5,
        )
        await engine_safe.run()
        safe_findings = [f for f in engine_safe.all_findings if f.field_name == "id"]
        assert len(safe_findings) == 0, f"Safe twin must be clean, got: {safe_findings}"
        assert not any("probe_not_delivered" in err for err in engine_safe.wave_errors)


@pytest.mark.asyncio
async def test_js_validated_form_behavior():
    """JavaScript onsubmit ハンドラ（return false）で阻止されるフォームの挙動。

    HTML5 制約検証は合格しているが JS イベントハンドラが送信をキャンセルするため、
    送達は未達（last_probe_delivered=False）となり、probe_not_delivered が記録される。
    誤検知（偽陽性/偽陰性）として誤認せず、正しく送達不能として扱われる。
    """
    app = FastAPI()
    received = []

    @app.get("/js_val", response_class=HTMLResponse)
    async def form():
        return HTMLResponse(
            '<form action="/js_submit" method="post" onsubmit="return false;">'
            '<input type="text" name="q">'
            '<button type="submit">Submit</button>'
            '</form>'
        )

    @app.post("/js_submit", response_class=HTMLResponse)
    async def submit():
        received.append(True)
        return HTMLResponse("ok")

    with serving(app) as url:
        b = BrowserManager(headless=True, timeout=5)
        await b.init()
        try:
            assert await b.navigate(url + "/js_val")
            source, pair = await b.fill_and_submit_form(0, "q", "<script>alert(1)</script>")
            # 1. サーバーには何も送信されていないこと
            assert len(received) == 0
            # 2. 送達フラグが False であり、理由が記録されていること
            assert not b.last_probe_delivered
            assert b.last_probe_delivery_reason == "submit_not_dispatched"
        finally:
            await b.close()


@pytest.mark.asyncio
async def test_counting_endpoint_at_most_one_request_per_probe():
    """State-changing counting endpoint proves at most one request is sent per probe."""
    app = FastAPI()
    call_counts = {"novalidate": 0, "constrained": 0, "unverified": 0}

    @app.get("/count/novalidate", response_class=HTMLResponse)
    async def page_novalidate():
        return HTMLResponse(
            '<form action="/count/submit_novalidate" method="post" novalidate>'
            '<input type="url" name="dest" required>'
            '<button type="submit">Submit</button>'
            '</form>'
        )

    @app.post("/count/submit_novalidate", response_class=HTMLResponse)
    async def submit_novalidate():
        call_counts["novalidate"] += 1
        return HTMLResponse("ok")

    @app.get("/count/constrained", response_class=HTMLResponse)
    async def page_constrained():
        return HTMLResponse(
            '<form action="/count/submit_constrained" method="post">'
            '<input type="url" name="dest" required>'
            '<button type="submit">Submit</button>'
            '</form>'
        )

    @app.post("/count/submit_constrained", response_class=HTMLResponse)
    async def submit_constrained():
        call_counts["constrained"] += 1
        return HTMLResponse("ok")

    @app.get("/count/unverified", response_class=HTMLResponse)
    async def page_unverified():
        # Dispatches a request without payload value upon submit
        return HTMLResponse(
            '<form action="/count/submit_unverified" method="post">'
            '<input type="text" name="other" value="fixed">'
            '<button type="submit">Submit</button>'
            '</form>'
        )

    @app.post("/count/submit_unverified", response_class=HTMLResponse)
    async def submit_unverified():
        call_counts["unverified"] += 1
        return HTMLResponse("ok")

    with serving(app) as url:
        b = BrowserManager(headless=True, timeout=5)
        await b.init()
        try:
            # 1. Novalidate form: Dispatches request on attempt 1.
            # Must NOT retry; server receives at most 1 request.
            assert await b.navigate(url + "/count/novalidate")
            source, pair = await b.fill_and_submit_form(0, "dest", "payload_str")
            assert call_counts["novalidate"] == 1, "Novalidate form must receive at most 1 request"

            # 2. Constrained form: Blocked by browser validation on attempt 1 (0 requests),
            # retried with bypass on attempt 2 (1 request). Server receives at most 1 request.
            assert await b.navigate(url + "/count/constrained")
            source, pair = await b.fill_and_submit_form(0, "dest", "payload_str")
            assert call_counts["constrained"] == 1, "Constrained form retry must result in at most 1 request"
            assert b.last_probe_delivered

            # 3. Request dispatched but value unverified: Must NOT retry; at most 1 request.
            assert await b.navigate(url + "/count/unverified")
            source, pair = await b.fill_and_submit_form(0, "dest", "payload_str")
            assert call_counts["unverified"] <= 1, "Unverified dispatch must never retry"
        finally:
            await b.close()


@pytest.mark.asyncio
async def test_evidence_isolation_between_attempts():
    """Attempt 1 network capture and probe context must not leak into attempt 2 evidence."""
    app = FastAPI()

    @app.get("/iso_form", response_class=HTMLResponse)
    async def form_page():
        return HTMLResponse(
            '<form action="/iso_submit" method="post">'
            '<input type="url" name="dest" required>'
            '<button type="submit">Submit</button>'
            '</form>'
        )

    @app.post("/iso_submit", response_class=HTMLResponse)
    async def submit_page():
        return HTMLResponse("<html><body>Submitted</body></html>")

    @app.get("/background_noise", response_class=HTMLResponse)
    async def noise():
        return HTMLResponse("noise")

    with serving(app) as url:
        b = BrowserManager(headless=True, timeout=5)
        await b.init()
        try:
            assert await b.navigate(url + "/iso_form")

            # Inject a background request right before fill_and_submit_form
            await b.page.evaluate(f"fetch('{url}/background_noise')")
            await asyncio.sleep(0.1)

            source, pair = await b.fill_and_submit_form(0, "dest", "payload_123")
            assert b.last_probe_delivered
            # Returned pair must be the form submission carrier, NOT the background noise
            req_url = (pair.get("request") or {}).get("url", "")
            assert "/iso_submit" in req_url, f"Evidence pair leaked background request: {req_url}"
            assert "/background_noise" not in req_url

            # All pairs in b.network.pairs must belong only to the delivered attempt
            for captured in b.network.pairs:
                captured_url = (captured.get("request") or {}).get("url", "")
                assert "/background_noise" not in captured_url, (
                    f"Attempt 1 background request leaked into attempt 2 pairs: {captured_url}"
                )
        finally:
            await b.close()

