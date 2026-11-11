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
            assert b.last_probe_delivery_reason in ("request_value_unverified", "submit_not_dispatched")
        finally:
            await b.close()
