"""差別化 benchmark 用の脆弱 / 安全ツイン。

既存 evolution/mutation の ON/OFF は実スキャナで採点するが、検出優位は保証しない。
transformation_graph / reward_search / state_graph / dom_taint は別 capability で、
実装と対応 runner が揃うまで manifest の gate=gap を維持する。
シェルとファイルは仮想シンクで再現し、実 OS コマンドやホストの機密ファイルは使わない。
"""
from __future__ import annotations

import asyncio
import html
import os
import re
import secrets
import sqlite3
from urllib.parse import unquote

from fastapi import FastAPI, Form, Query, Request
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse


# ---------------------------------------------------------------------------
# 正解データ
# ---------------------------------------------------------------------------
EXPECTED_FINDINGS = [
    {"check": "path_traversal", "path": "/vault/download", "field": "file"},
    {"check": "os", "path": "/net/ping", "field": "target"},
    {"check": "sqli", "path": "/orders/lookup", "field": "ref"},
    {"check": "stored_xss", "path": "/notes/view", "field": "body"},
    {"check": "privesc", "path": "/api/invoice", "field": "id"},
    {"check": "sqli", "path": "/search/fuzzy", "field": "q"},
]
SAFE_ENDPOINTS = [
    {"path": "/vault/fetch", "field": "file"},
    {"path": "/net/resolve", "field": "target"},
    {"path": "/orders/status", "field": "ref"},
    {"path": "/notes/view-safe", "field": "body"},
    {"path": "/api/invoice-safe", "field": "id"},
    {"path": "/search/strict", "field": "q"},
]


# ---------------------------------------------------------------------------
# 補助データ
# ---------------------------------------------------------------------------
_PASSWD = (
    "root:x:0:0:root:/root:/bin/bash\n"
    "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin\n"
    "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin\n"
)
# 仮想サンドボックス外の機密ファイル（path traversal が到達すると content を返す）。
_VIRTUAL_FS = {"/srv/secret/etc/passwd": _PASSWD, "/etc/passwd": _PASSWD}
_SANDBOX = "/srv/app/public"

_OS_SLEEP_SECONDS = 3  # scanner の time-based 閾値(2.8s)を超える実遅延


def _layout(title: str, body: str) -> str:
    return (
        f"<!doctype html><html><head><meta charset='utf-8'>"
        f"<title>{html.escape(title)}</title></head><body>{body}</body></html>"
    )


def _resolve_traversal(decoded_path: str) -> str | None:
    """decode 済みパスを ``_SANDBOX`` 基準で正規化し、仮想 FS にヒットすれば content を返す。

    NULL バイト切詰め（``\\x00`` 以降を捨てる素朴実装）も再現する。
    """
    truncated = decoded_path.split("\x00", 1)[0]
    joined = os.path.normpath(os.path.join(_SANDBOX, truncated))
    if joined in _VIRTUAL_FS:
        return _VIRTUAL_FS[joined]
    return None


def create_app() -> FastAPI:
    app = FastAPI(title="Vulix Differentiation Lab")

    db = sqlite3.connect(":memory:", check_same_thread=False)
    db.execute("CREATE TABLE orders (ref TEXT, customer TEXT)")
    db.executemany(
        "INSERT INTO orders VALUES (?, ?)",
        [("ORD-1001", "alice"), ("ORD-1002", "bob")],
    )
    app.state.db = db
    app.state.notes: dict[str, str] = {}

    @app.get("/", response_class=HTMLResponse)
    async def home():
        vuln = "".join(f'<li><a href="{e["path"]}?{e["field"]}=sample">{e["check"]}</a></li>' for e in EXPECTED_FINDINGS)
        safe = "".join(f'<li><a href="{s["path"]}?{s["field"]}=sample">safe</a></li>' for s in SAFE_ENDPOINTS)
        return _layout("Differentiation Lab", f"<h1>Lab</h1><ul>{vuln}</ul><ul>{safe}</ul>")

    # ── 変換バイパス: path traversal（自動採点対象）─────────────────────────
    @app.get("/vault/download", response_class=PlainTextResponse)
    async def vault_download(file: str = Query("report.pdf")):
        # FastAPI が 1 回 decode 済みの値を受け取る。
        # 素朴フィルタ: 生の ".." と先頭スラッシュだけを弾く（%2e 等の二重エンコードは見逃す）。
        if ".." in file or file.startswith("/"):
            return "rejected: path not allowed"
        # VULNERABLE: 検証の「後で」もう一度 decode する（二重エンコードが ../ に戻る）。
        decoded = unquote(file)
        content = _resolve_traversal(decoded)
        if content is not None:
            return content
        return f"stub content for {html.escape(decoded)}"

    @app.get("/vault/fetch", response_class=PlainTextResponse)
    async def vault_fetch(file: str = Query("report.pdf")):
        # SAFE: 先に完全 decode し、正規化後にサンドボックス内か検証してからサーブ。
        decoded = unquote(file).split("\x00", 1)[0]
        joined = os.path.normpath(os.path.join(_SANDBOX, decoded))
        if not joined.startswith(_SANDBOX + os.sep) and joined != _SANDBOX:
            return "rejected: outside sandbox"
        return f"stub content for {html.escape(os.path.basename(joined))}"

    # ── 変換バイパス: OS コマンド注入（自動採点対象・time-based）─────────────
    @app.get("/net/ping", response_class=PlainTextResponse)
    async def net_ping(target: str = Query("127.0.0.1")):
        # 素朴フィルタ: 空白と echo を弾く（${IFS} は空白を使わないので見逃す）。
        if re.search(r"\s", target) or "echo" in target.lower():
            return "rejected: invalid characters"
        # VULNERABLE: ${IFS} を空白に展開してからシェル解釈する想定。
        cmd = target.replace("${IFS}", " ")
        out = await _simulate_shell(cmd)
        if out is not None:
            return f"PING {html.escape(target)}\n{out}"
        return f"PING {html.escape(target)}: 1 packets transmitted, 1 received\n"

    @app.get("/net/resolve", response_class=PlainTextResponse)
    async def net_resolve(target: str = Query("example.com")):
        # SAFE: 厳格な allow-list（英数・ドット・ハイフンのみ）。シェルに渡さない。
        if not re.fullmatch(r"[A-Za-z0-9.\-]{1,253}", target):
            return "invalid hostname"
        return f"{target} has address 10.0.0.5\n"

    # ── ground-truth: SQLi 二重 decode（gate=gap）───────────────────────────
    @app.get("/orders/lookup", response_class=HTMLResponse)
    async def orders_lookup(ref: str = Query("ORD-1001")):
        if "'" in ref or '"' in ref:   # 素朴フィルタ: 生の引用符を弾く
            return _layout("Order", "<p>rejected: invalid ref</p>")
        decoded = unquote(ref)          # VULNERABLE: 検証の後で再 decode
        try:
            rows = app.state.db.execute(
                f"SELECT customer FROM orders WHERE ref = '{decoded}'"
            ).fetchall()
        except sqlite3.Error as exc:
            return _layout("Order error", f"<p>SQLite error: {html.escape(str(exc))} "
                                          f"(unrecognized token)</p>")
        return _layout("Order", f"<p>rows: {len(rows)}</p>")

    @app.get("/orders/status", response_class=HTMLResponse)
    async def orders_status(ref: str = Query("ORD-1001")):
        decoded = unquote(ref)
        rows = app.state.db.execute(   # SAFE: パラメータ化（連結しない）
            "SELECT customer FROM orders WHERE ref = ?", (decoded,)
        ).fetchall()
        return _layout("Order status", f"<p>rows: {len(rows)}</p>")

    # ── ground-truth: 多段 chain（stored XSS）（gate=gap）────────────────────
    @app.post("/notes/save", response_class=PlainTextResponse)
    async def notes_save(note_id: str = Form("n1"), body: str = Form("")):
        app.state.notes[note_id] = body   # 無害化せず保存
        return "saved"

    @app.get("/notes/view", response_class=HTMLResponse)
    async def notes_view(note_id: str = Query("n1")):
        # VULNERABLE: 保存値を無害化せず innerHTML 相当で描画（格納型 XSS）。
        return _layout("Note", f"<div>{app.state.notes.get(note_id, '')}</div>")

    @app.get("/notes/view-safe", response_class=HTMLResponse)
    async def notes_view_safe(note_id: str = Query("n1")):
        # SAFE: textContent 相当（html.escape）。
        return _layout("Note", f"<div>{html.escape(app.state.notes.get(note_id, ''))}</div>")

    # ── ground-truth: state 依存 BOLA / IDOR（gate=gap）─────────────────────
    _invoices = {"1": {"owner": "alice", "total": 120}, "2": {"owner": "bob", "total": 999}}
    _sessions: dict[str, str] = {}

    @app.post("/session", response_class=JSONResponse)
    async def login(user: str = Form(...), password: str = Form(...)):
        if user not in {"alice", "bob"} or password != f"{user}-password":
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        response = JSONResponse({"user": user})
        token = secrets.token_urlsafe(32)
        _sessions[token] = user
        response.set_cookie("session", token, httponly=True)
        return response

    @app.get("/api/invoice", response_class=JSONResponse)
    async def api_invoice(request: Request, id: str = Query("1")):
        if request.cookies.get("session") not in _sessions:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        # VULNERABLE: 所有者チェック無し。任意 id を返す（BOLA）。
        return _invoices.get(id, {})

    @app.get("/api/invoice-safe", response_class=JSONResponse)
    async def api_invoice_safe(request: Request, id: str = Query("1")):
        user = _sessions.get(request.cookies.get("session"))
        if user is None:
            return JSONResponse({"error": "unauthorized"}, status_code=401)
        # SAFE: 所有者チェック。
        inv = _invoices.get(id)
        if not inv or inv["owner"] != user:
            return JSONResponse({"error": "forbidden"}, status_code=403)
        return inv

    # ── ground-truth: 部分報酬探索（gate=gap）───────────────────────────────
    @app.get("/search/fuzzy", response_class=HTMLResponse)
    async def search_fuzzy(q: str = Query("")):
        # 反射は最初の3文字だけ、SQLエラーは隠す。結果件数が探索の部分観測となる。
        try:
            rows = app.state.db.execute(f"SELECT * FROM orders WHERE ref LIKE '%{q}%'").fetchall()
        except sqlite3.Error:
            rows = []  # エラー本文を出さず、結果件数だけを部分的な観測として返す。
        return _layout("Search", f"<p>q: {html.escape(q[:3])}; rows: {len(rows)}</p>")

    @app.get("/search/strict", response_class=HTMLResponse)
    async def search_strict(q: str = Query("")):
        rows = app.state.db.execute(   # SAFE: パラメータ化
            "SELECT * FROM orders WHERE ref LIKE ?", (f"%{q}%",)
        ).fetchall()
        return _layout("Search", f"<p>rows: {len(rows)}</p>")

    return app


async def _simulate_shell(cmd: str) -> str | None:
    """注入された追記コマンドを解釈。区切り文字が無ければ None（注入なし）。"""
    if not re.search(r"[;|&`]|\$\(", cmd):
        return None
    m = re.search(r"\bsleep\s+(\d+)", cmd)
    if m:
        await asyncio.sleep(min(int(m.group(1)), _OS_SLEEP_SECONDS))
        return f"(injected delay {m.group(1)}s)\n"
    if re.search(r"\bcat\b.*passwd", cmd):
        return _PASSWD
    if re.search(r"\bid\b", cmd):
        return "uid=0(root) gid=0(root) groups=0(root)\n"
    return ""
