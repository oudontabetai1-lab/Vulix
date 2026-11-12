"""マルチパラメータ同時投入の反射判定・送達判定の回帰。

JS ハンドリングのフォーム（preventDefault + fetch、ページは入力を反射しない）に対して
「ページ自身の <script> を payload の反射と誤認する」誤検知と、未達の結合 probe を
判定してしまう問題を固定する。判定ロジックは純粋関数、ブラウザ依存部分は
WSCAN_E2E のループバックで検証する。
"""
from __future__ import annotations

import contextlib
import os
import socket
import tempfile
import threading
import time
import unittest
from typing import Generator

import pytest
import uvicorn
from fastapi import FastAPI, Form
from fastapi.responses import HTMLResponse, JSONResponse

from wscan.engine import CrawledPage, ScanEngine
from wscan.json_body_detect import analyze_xss_reflection

PAYLOAD = "<script>alert('XSS')</script>"

# ページ自身が持つインライン <script>（payload のマーカー <script> / alert( を含む）。
# 入力は一切反射しない。
PAGE_WITH_OWN_SCRIPT = """<!doctype html><html><head><title>Sign in</title></head><body>
<div id="app-view"></div>
<script>
function unusedHandler() { alert("static page handler"); }
document.getElementById("app-view").textContent = "static";
</script>
</body></html>"""

FORM_PAGE = '<!doctype html><html><body><form method="post"></form></body></html>'


class ReflectionDecisionTests(unittest.TestCase):
    """結合送信の反射判定は「ページ自身のマーカー」を payload の証拠にしない。"""

    def test_page_own_script_matches_generic_markers_without_baseline(self):
        # 修正前のマルチパラメータ経路（baseline 無し）が誤検知した原因そのもの。
        self.assertTrue(analyze_xss_reflection(PAGE_WITH_OWN_SCRIPT, PAYLOAD))

    def test_page_own_script_is_rejected_against_baseline(self):
        self.assertEqual(
            analyze_xss_reflection(PAGE_WITH_OWN_SCRIPT, PAYLOAD, PAGE_WITH_OWN_SCRIPT),
            {},
        )

    def test_existing_handler_after_escaped_reflection_is_not_attributed(self):
        # 変わった（エスケープ済みの）反射が元からあるハンドラの直前にあっても、
        # ハンドラ自体は baseline と同一なので payload の証拠にしない。
        def page(a: str, b: str) -> str:
            return (f"<body><p>a={a}</p><p>b={b}</p>"
                    '<button onclick="alert(1)">legit</button></body>')

        for payload, escaped in ((PAYLOAD, "&lt;script&gt;alert(&#x27;XSS&#x27;)&lt;/script&gt;"),
                                 ("javascript:alert(1)", "javascript:alert(1)")):
            self.assertEqual(
                analyze_xss_reflection(page(escaped, "2"), payload, page("1", "2")), {})
            self.assertEqual(
                analyze_xss_reflection(page("1", escaped), payload, page("1", "2")), {})

    def test_verbatim_combined_reflection_is_still_detected(self):
        reflected = f'<html><body><input name="echo" value="{PAYLOAD}"></body></html>'
        reflection = analyze_xss_reflection(reflected, PAYLOAD, FORM_PAGE)
        self.assertTrue(reflection)
        self.assertTrue(reflection.get("raw_payload_present"))


# =============================================================================
# ループバック E2E（実ブラウザ・WSCAN_E2E=1 のみ）
# =============================================================================

def _e2e_enabled() -> bool:
    return os.environ.get("WSCAN_E2E", "").strip().lower() in {"1", "true", "yes", "on"}


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as pw:
            browser = pw.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


# WSCAN_E2E 未設定時は Chromium を起動しない（通常の pytest 収集を軽く保つ）。
_CHROMIUM_OK = _chromium_available() if _e2e_enabled() else False

_requires_browser = pytest.mark.skipif(
    not (_e2e_enabled() and _CHROMIUM_OK),
    reason="WSCAN_E2E opt-in and Chromium required",
)


def _js_form_page(action_hint: str, extra_body: str = "") -> str:
    return f"""<!doctype html><html><head><title>Sign in</title></head><body>
<h1>Sign in</h1>
<form id="login-form">
  <label for="u">Username</label>
  <input id="u" name="username" type="text">
  <label for="p">Password</label>
  <input id="p" name="password" type="password">
  <button id="b" type="submit">Sign in</button>
</form>
<div id="app-view"></div>
{extra_body}
<script>
function unusedHandler() {{ alert("static page handler"); }}
document.getElementById("login-form").addEventListener("submit", async function(e) {{
  e.preventDefault();
  const u = document.getElementById("u").value;
  const p = document.getElementById("p").value;
  await fetch("{action_hint}", {{
    method: "POST",
    headers: {{"Content-Type": "application/json"}},
    body: JSON.stringify({{username: u, password: p}})
  }});
}});
</script>
</body></html>"""


def create_app() -> FastAPI:
    app = FastAPI(title="MultiParam Reflection Truth Fixture")

    def _form(action: str, method: str = "post") -> str:
        return (
            f'<form id="f" action="{action}" method="{method}">'
            '<input name="username" type="text">'
            '<input name="password" type="password">'
            '<button type="submit">Sign in</button></form>'
        )

    @app.get("/js/login", response_class=HTMLResponse)
    async def js_login():
        # JS が送信を握る（ネイティブ送信なし）・ページは入力を反射しない。
        return _js_form_page("/js/api/login")

    @app.post("/js/api/login")
    async def js_api_login():
        return JSONResponse({"error": "invalid credentials"}, status_code=401)

    @app.get("/js/sqli", response_class=HTMLResponse)
    async def js_sqli():
        # ページ自身が SQL エラー風の文言を持つ（payload 起因ではない）。
        return _js_form_page(
            "/js/api/sqli",
            extra_body='<pre id="log">SQL syntax error near \'static\'</pre>',
        )

    @app.post("/js/api/sqli")
    async def js_api_sqli():
        return JSONResponse({"error": "invalid credentials"}, status_code=401)

    @app.get("/native/reflect", response_class=HTMLResponse)
    async def native_reflect_get():
        return _form("/native/reflect")

    @app.post("/native/reflect", response_class=HTMLResponse)
    async def native_reflect_post(
        username: str = Form(""), password: str = Form("")
    ):
        # 属性値として生のまま結合反射する（タグとして実行はされない）。
        return (
            '<!doctype html><html><body><h1>Result</h1>'
            f'<input id="echo" name="echo" value="{username} {password}">'
            "</body></html>"
        )

    @app.get("/native/dialog", response_class=HTMLResponse)
    async def native_dialog_get():
        return _form("/native/dialog")

    @app.post("/native/dialog", response_class=HTMLResponse)
    async def native_dialog_post(
        username: str = Form(""), password: str = Form("")
    ):
        return (
            "<!doctype html><html><body><h1>Result</h1>"
            "<script>alert('combined-xss')</script></body></html>"
        )

    @app.get("/native/static-script", response_class=HTMLResponse)
    async def native_static_get():
        return _form("/native/static-script")

    @app.post("/native/static-script", response_class=HTMLResponse)
    async def native_static_post(
        username: str = Form(""), password: str = Form("")
    ):
        # 送達はされるが入力を反射しない。ページ自身の <script> だけがある。
        return PAGE_WITH_OWN_SCRIPT

    return app


@contextlib.contextmanager
def serving(app) -> Generator[str, None, None]:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", log_level="error"))
    thread = threading.Thread(target=server.run, kwargs={"sockets": [sock]}, daemon=True)
    thread.start()
    try:
        deadline = time.monotonic() + 10.0
        while not server.started:
            if time.monotonic() > deadline:
                raise RuntimeError("multiparam fixture server did not start")
            time.sleep(0.02)
        yield f"http://127.0.0.1:{port}"
    finally:
        server.should_exit = True
        thread.join(timeout=5.0)
        sock.close()


def _form_meta(url: str, method: str = "post") -> list[dict]:
    return [{
        "index": 0,
        "method": method.upper(),
        "action": url,
        "inputs": [
            {"name": "username", "type": "text"},
            {"name": "password", "type": "password"},
        ],
    }]


async def _run_multi_param(url: str, checks: list[str], method: str = "post"):
    with tempfile.TemporaryDirectory() as tmp:
        engine = ScanEngine(
            url,
            checks=checks,
            llm_provider="none",
            headless=True,
            output_dir=tmp,
            open_report=False,
            enable_waf_detection=False,
            enable_ai_analysis=False,
            enable_payload_learning=False,
            enable_adaptive_payloads=False,
            enable_sitemap_crawl=False,
            fast_mode=True,
        )
        await engine.browser.init()
        try:
            assert await engine.browser.navigate(url)
            page = CrawledPage(
                url=url,
                html="",
                forms=_form_meta(url, method),
                url_params=[],
                depth=0,
            )
            await engine._phase_multi_param(page, None)
            return list(engine.all_findings), list(engine.wave_errors)
        finally:
            await engine.browser.close()


def _multi_findings(findings, check_type: str):
    return [
        f for f in findings
        if f.check_type == check_type and "[MultiParam]" in (f.evidence or "")
    ]


@_requires_browser
class MultiParamDeliveryTruthE2ETests(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls._server = serving(create_app())
        cls.base = cls._server.__enter__()

    @classmethod
    def tearDownClass(cls):
        cls._server.__exit__(None, None, None)

    async def test_js_handled_non_reflecting_form_is_not_reported(self):
        findings, notes = await _run_multi_param(
            f"{self.base}/js/login", ["xss"], method="get"
        )
        self.assertEqual(_multi_findings(findings, "xss"), [])
        self.assertTrue(
            any(
                n == "transport_error:xss:probe_not_delivered:/js/login|multi[0]"
                or (n.startswith("transport_error:xss:probe_not_delivered:/js/login|multi[0]"))
                for n in notes
            ),
            notes,
        )

    async def test_js_handled_form_static_sql_error_text_is_not_judged(self):
        findings, notes = await _run_multi_param(
            f"{self.base}/js/sqli", ["sqli"], method="get"
        )
        self.assertEqual(_multi_findings(findings, "sqli"), [])
        self.assertTrue(
            any(
                n.startswith("transport_error:sqli:probe_not_delivered:/js/sqli|multi[0]")
                for n in notes
            ),
            notes,
        )

    async def test_reflecting_twin_still_reports_reflection(self):
        findings, _notes = await _run_multi_param(
            f"{self.base}/native/reflect", ["xss"]
        )
        multi = _multi_findings(findings, "xss")
        self.assertEqual(len(multi), 1, findings)
        self.assertIn(
            "XSS reflected in combined submission", multi[0].evidence
        )
        self.assertEqual(multi[0].field_name, "multi[username,password]")

    async def test_dialog_twin_still_reports_execution(self):
        findings, _notes = await _run_multi_param(
            f"{self.base}/native/dialog", ["xss"]
        )
        multi = _multi_findings(findings, "xss")
        self.assertEqual(len(multi), 1, findings)
        self.assertIn("XSS dialog triggered", multi[0].evidence)

    async def test_delivered_form_with_static_script_is_not_attributed(self):
        findings, _notes = await _run_multi_param(
            f"{self.base}/native/static-script", ["xss"]
        )
        self.assertEqual(_multi_findings(findings, "xss"), [])


if __name__ == "__main__":
    unittest.main()
