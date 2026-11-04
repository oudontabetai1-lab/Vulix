"""OOB（帯域外）メール受信シンク。

Blind XSS / SSRF、メールヘッダインジェクション、second-order など
「対象アプリがメールを送って初めて確証できる」脆弱性のために、専用の
受信メールボックス（IMAP / POP3）を監視し、ペイロードに埋め込んだ一意
トークンと突合する。

設計方針:
- 送信した payload に ``<token>@<catch-all-domain>`` 形式の一意アドレス／
  トークンを埋め込む（``make_oob_token`` / ``oob_address``）。
- 脆弱性が発火すると catch-all メールボックスへメールが届く。
- ``EmailSink.search(token)`` / ``wait_for(token, timeout)`` で受信箱を検索し、
  To ヘッダ・件名・本文のいずれかにトークンを含むメールを返す。

トランスポート（imaplib / poplib）と解析・突合ロジックを分離してあり、
解析系（``parse_email`` / ``email_matches_token`` / ``filter_messages``）は
ネットワーク非依存で単体テストできる。設定は環境変数から読む
（``OOBEmailConfig.from_env``）ため、認証情報をコードに埋め込まない。
"""
from __future__ import annotations

import email
import imaplib
import os
import poplib
import secrets
import socket
import ssl
import time
import unicodedata
from dataclasses import dataclass, field
from email.message import Message
from email.utils import getaddresses
from pathlib import Path
from typing import Mapping, Optional


# ── トークン / アドレス生成 ────────────────────────────────────────────────
_TOKEN_ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"


class OOBEmailValidationError(ValueError):
    """Raised when a mail setting contains protocol control characters."""


def _validate_connection_fields(cfg: "OOBEmailConfig") -> None:
    for name in ("host", "username", "password", "mailbox"):
        if any(unicodedata.category(char) == "Cc" for char in getattr(cfg, name)):
            raise OOBEmailValidationError(f"{name} に制御文字は使用できません。")


def make_oob_token(scan_id: str = "") -> str:
    """ペイロードに埋め込む一意トークンを生成する。

    ``wscan-oob-<scan_id>-<nonce>`` 形式。英数字とハイフンのみで、メール
    アドレスのローカルパートやヘッダ値に安全に使える。
    """
    nonce = "".join(secrets.choice(_TOKEN_ALPHABET) for _ in range(12))
    sid = "".join(c for c in scan_id.lower() if c in _TOKEN_ALPHABET)[:16]
    return f"wscan-oob-{sid}-{nonce}" if sid else f"wscan-oob-{nonce}"


def oob_address(token: str, domain: str) -> str:
    """catch-all ドメイン上の OOB 受信アドレスを返す。"""
    return f"{token}@{domain}"


# ── 設定 ──────────────────────────────────────────────────────────────────
@dataclass
class OOBEmailConfig:
    protocol: str = "imap"          # "imap" | "pop3"
    host: str = ""
    port: int = 0                    # 0 → プロトコル既定 (IMAPS 993 / POP3S 995)
    username: str = ""
    password: str = ""
    use_ssl: bool = True
    mailbox: str = "INBOX"          # IMAP のみ
    domain: str = ""                 # OOB アドレスの catch-all ドメイン

    @property
    def effective_port(self) -> int:
        if self.port:
            return self.port
        if self.protocol == "pop3":
            return 995 if self.use_ssl else 110
        return 993 if self.use_ssl else 143

    @property
    def configured(self) -> bool:
        return bool(self.host and self.username and self.password)

    @classmethod
    def from_env(cls, env: Optional[dict] = None) -> "OOBEmailConfig":
        e = env if env is not None else os.environ

        def _bool(key: str, default: bool) -> bool:
            v = e.get(key)
            if v is None:
                return default
            return v.strip().lower() in ("1", "true", "yes", "on")

        def _int(key: str, default: int) -> int:
            try:
                return int(e.get(key, default))
            except (TypeError, ValueError):
                return default

        protocol = (e.get("WSCAN_OOB_PROTOCOL", "imap") or "imap").strip().lower()
        return cls(
            protocol="pop3" if protocol == "pop3" else "imap",
            host=(e.get("WSCAN_OOB_HOST", "") or "").strip(),
            port=_int("WSCAN_OOB_PORT", 0),
            username=(e.get("WSCAN_OOB_USERNAME", "") or "").strip(),
            password=e.get("WSCAN_OOB_PASSWORD", "") or "",
            use_ssl=_bool("WSCAN_OOB_SSL", True),
            mailbox=(e.get("WSCAN_OOB_MAILBOX", "INBOX") or "INBOX").strip(),
            domain=(e.get("WSCAN_OOB_DOMAIN", "") or "").strip(),
        )

    @classmethod
    def from_dict(cls, data: Optional[dict] = None) -> "OOBEmailConfig":
        d = data or {}
        protocol = str(d.get("protocol") or "imap").strip().lower()
        try:
            port = int(d.get("port") or 0)
        except (TypeError, ValueError):
            port = 0
        use_ssl = bool(d.get("use_ssl", d.get("ssl", True)))
        return cls(
            protocol="pop3" if protocol == "pop3" else "imap",
            host=str(d.get("host") or "").strip(),
            port=port,
            username=str(d.get("username") or "").strip(),
            password=str(d.get("password") or ""),
            use_ssl=use_ssl,
            mailbox=str(d.get("mailbox") or "INBOX").strip(),
            domain=str(d.get("domain") or "").strip(),
        )


OOB_ENV_KEYS = (
    "WSCAN_OOB_HOST",
    "WSCAN_OOB_USERNAME",
    "WSCAN_OOB_PASSWORD",
    "WSCAN_OOB_PROTOCOL",
    "WSCAN_OOB_PORT",
    "WSCAN_OOB_SSL",
    "WSCAN_OOB_MAILBOX",
    "WSCAN_OOB_DOMAIN",
)


def is_oob_env_set(env: Optional[Mapping[str, str]] = None) -> bool:
    """環境変数 WSCAN_OOB_* が 1 つでも有効値を持つか判定する。"""
    e = os.environ if env is None else env
    return any(bool((e.get(k) or "").strip()) for k in OOB_ENV_KEYS)


def resolve_oob_config(
    settings_path: Optional[Path] = None,
    env: Optional[Mapping[str, str]] = None,
) -> tuple[OOBEmailConfig, str]:
    """優先順位に従って実効 OOB 設定を解決する。

    優先順位:
    1. 環境変数 (WSCAN_OOB_*) が設定されていれば最優先 (source="environment")
    2. ダッシュボード保存設定 (wscan_settings.json) があればそれを採用 (source="dashboard")
    3. いずれも無ければ未設定 (source="unset")
    """
    if is_oob_env_set(env):
        return OOBEmailConfig.from_env(dict(env) if env is not None else None), "environment"

    path = settings_path
    if path is None:
        try:
            from .monitor import OUTPUT_BASE
            path = OUTPUT_BASE / "wscan_settings.json"
        except Exception:
            path = Path.cwd() / "output" / "wscan_settings.json"

    if path.is_file():
        try:
            import json
            data = json.loads(path.read_text(encoding="utf-8")) or {}
            saved = data.get("oob")
            if isinstance(saved, dict) and (saved.get("host") or saved.get("username")):
                return OOBEmailConfig.from_dict(saved), "dashboard"
        except Exception:
            pass

    return OOBEmailConfig(), "unset"


# ── 接続テスト ────────────────────────────────────────────────────────────
def _test_imap_connection(cfg: OOBEmailConfig, timeout: float = 10.0) -> dict:
    _validate_connection_fields(cfg)
    stage = "connect"
    conn = None
    try:
        if cfg.use_ssl:
            conn = imaplib.IMAP4_SSL(cfg.host, cfg.effective_port, timeout=timeout)
        else:
            conn = imaplib.IMAP4(cfg.host, cfg.effective_port, timeout=timeout)

        stage = "login"
        conn.login(cfg.username, cfg.password)

        stage = "select"
        status, _ = conn.select(cfg.mailbox or "INBOX", readonly=True)
        if status != "OK":
            raise imaplib.IMAP4.error("mailbox selection failed")
        conn.list()

        return {
            "ok": True,
            "stage": "done",
            "error_kind": None,
            "message": "接続と認証に成功しました。",
        }
    except (TimeoutError, socket.timeout):
        return {
            "ok": False,
            "stage": stage,
            "error_kind": "timeout",
            "message": "接続がタイムアウトしました。ホスト名とポート番号を確認してください。",
        }
    except ssl.SSLError:
        return {
            "ok": False,
            "stage": stage,
            "error_kind": "ssl",
            "message": "SSL/TLS ハンドシェイクに失敗しました。SSL 設定を確認してください。",
        }
    except (ConnectionError, OSError, socket.gaierror):
        return {
            "ok": False,
            "stage": stage,
            "error_kind": "network",
            "message": "サーバーへの接続に失敗しました。ホスト名とポート番号を確認してください。",
        }
    except imaplib.IMAP4.error:
        error_kind = "auth" if stage == "login" else "mailbox"
        msg = (
            "認証に失敗しました。ユーザー名またはパスワードを確認してください。"
            if stage == "login"
            else "メールボックスの選択に失敗しました。メールボックス名を確認してください。"
        )
        return {
            "ok": False,
            "stage": stage,
            "error_kind": error_kind,
            "message": msg,
        }
    except Exception:
        error_kind = "auth" if stage == "login" else ("mailbox" if stage == "select" else "error")
        msg = (
            "認証に失敗しました。ユーザー名またはパスワードを確認してください。"
            if stage == "login"
            else "接続テストに失敗しました。"
        )
        return {
            "ok": False,
            "stage": stage,
            "error_kind": error_kind,
            "message": msg,
        }
    finally:
        if conn is not None:
            try:
                conn.logout()
            except Exception:
                pass


def _test_pop3_connection(cfg: OOBEmailConfig, timeout: float = 10.0) -> dict:
    _validate_connection_fields(cfg)
    stage = "connect"
    conn = None
    try:
        if cfg.use_ssl:
            conn = poplib.POP3_SSL(cfg.host, cfg.effective_port, timeout=timeout)
        else:
            conn = poplib.POP3(cfg.host, cfg.effective_port, timeout=timeout)

        stage = "login"
        conn.user(cfg.username)
        conn.pass_(cfg.password)

        stage = "list"
        conn.list()

        return {
            "ok": True,
            "stage": "done",
            "error_kind": None,
            "message": "接続と認証に成功しました。",
        }
    except (TimeoutError, socket.timeout):
        return {
            "ok": False,
            "stage": stage,
            "error_kind": "timeout",
            "message": "接続がタイムアウトしました。ホスト名とポート番号を確認してください。",
        }
    except ssl.SSLError:
        return {
            "ok": False,
            "stage": stage,
            "error_kind": "ssl",
            "message": "SSL/TLS ハンドシェイクに失敗しました。SSL 設定を確認してください。",
        }
    except (ConnectionError, OSError, socket.gaierror):
        return {
            "ok": False,
            "stage": stage,
            "error_kind": "network",
            "message": "サーバーへの接続に失敗しました。ホスト名とポート番号を確認してください。",
        }
    except poplib.error_proto:
        error_kind = "auth" if stage == "login" else "mailbox"
        msg = (
            "認証に失敗しました。ユーザー名またはパスワードを確認してください。"
            if stage == "login"
            else "メールボックスの一覧取得に失敗しました。"
        )
        return {
            "ok": False,
            "stage": stage,
            "error_kind": error_kind,
            "message": msg,
        }
    except Exception:
        error_kind = "auth" if stage == "login" else "error"
        msg = (
            "認証に失敗しました。ユーザー名またはパスワードを確認してください。"
            if stage == "login"
            else "接続テストに失敗しました。"
        )
        return {
            "ok": False,
            "stage": stage,
            "error_kind": error_kind,
            "message": msg,
        }
    finally:
        if conn is not None:
            try:
                conn.quit()
            except Exception:
                pass


def test_oob_connection(config: OOBEmailConfig, timeout: float = 10.0) -> dict:
    """OOB メール受信サーバーへの接続・認証・一覧テストを実行する（読み取り専用）。

    機微情報（パスワード）やサーバーの生のエラー文字列は返却値・ログに含めない。
    """
    if not config.configured:
        return {
            "ok": False,
            "stage": "config",
            "error_kind": "not_configured",
            "message": "OOB 設定が不完全です（host, username, password を指定してください）。",
        }
    _validate_connection_fields(config)
    if config.protocol == "pop3":
        return _test_pop3_connection(config, timeout=timeout)
    return _test_imap_connection(config, timeout=timeout)


# ── 受信メール表現 ────────────────────────────────────────────────────────
@dataclass
class ReceivedEmail:
    uid: str = ""
    from_addr: str = ""
    to_addrs: list = field(default_factory=list)
    subject: str = ""
    date: str = ""
    body: str = ""
    size: int = 0

    def to_dict(self) -> dict:
        return {
            "uid": self.uid,
            "from": self.from_addr,
            "to": self.to_addrs,
            "subject": self.subject,
            "date": self.date,
            "body": self.body[:4000],
            "size": self.size,
        }


# ── 解析・突合（ネットワーク非依存・テスト対象） ──────────────────────────
def _extract_body(msg: Message) -> str:
    """メールから text/plain（無ければ text/html）本文を抽出する。"""
    if msg.is_multipart():
        plain, html = "", ""
        for part in msg.walk():
            ctype = part.get_content_type()
            if part.get_content_disposition() == "attachment":
                continue
            try:
                payload = part.get_payload(decode=True)
            except Exception:
                payload = None
            if not payload:
                continue
            text = payload.decode(part.get_content_charset() or "utf-8", "replace")
            if ctype == "text/plain" and not plain:
                plain = text
            elif ctype == "text/html" and not html:
                html = text
        return plain or html
    try:
        payload = msg.get_payload(decode=True)
    except Exception:
        payload = None
    if payload:
        return payload.decode(msg.get_content_charset() or "utf-8", "replace")
    return msg.get_payload() or ""


def parse_email(raw: bytes, uid: str = "") -> ReceivedEmail:
    """生のメールバイト列を ``ReceivedEmail`` に解析する（純粋関数）。"""
    msg = email.message_from_bytes(raw)
    to_pairs = getaddresses(msg.get_all("to", []) + msg.get_all("cc", []) + msg.get_all("delivered-to", []))
    to_addrs = [addr for _, addr in to_pairs if addr]
    return ReceivedEmail(
        uid=uid,
        from_addr=(msg.get("from", "") or "").strip(),
        to_addrs=to_addrs,
        subject=(msg.get("subject", "") or "").strip(),
        date=(msg.get("date", "") or "").strip(),
        body=_extract_body(msg),
        size=len(raw),
    )


def email_matches_token(received: ReceivedEmail, token: str) -> bool:
    """受信メールがトークンを含む（To / 件名 / 本文）か判定する。"""
    if not token:
        return False
    t = token.lower()
    if any(t in (addr or "").lower() for addr in received.to_addrs):
        return True
    if t in (received.subject or "").lower():
        return True
    if t in (received.body or "").lower():
        return True
    if t in (received.from_addr or "").lower():
        return True
    return False


def filter_messages(raw_messages, token: str) -> list:
    """``[(uid, raw_bytes), ...]`` からトークン一致メールを抽出する（純粋関数）。"""
    out = []
    for uid, raw in raw_messages:
        try:
            received = parse_email(raw, uid=str(uid))
        except Exception:
            continue
        if email_matches_token(received, token):
            out.append(received)
    return out


# ── トランスポート（IMAP / POP3） ─────────────────────────────────────────
class EmailSink:
    """設定済みメールボックスからトークン一致メールを取得する。"""

    def __init__(self, config: OOBEmailConfig):
        self.config = config
        self._conn = None

    # -- IMAP --
    def _connect_imap(self):
        cfg = self.config
        _validate_connection_fields(cfg)
        if cfg.use_ssl:
            conn = imaplib.IMAP4_SSL(cfg.host, cfg.effective_port)
        else:
            conn = imaplib.IMAP4(cfg.host, cfg.effective_port)
        conn.login(cfg.username, cfg.password)
        conn.select(cfg.mailbox)
        return conn

    def _search_imap(self, token: str) -> list:
        conn = self._connect_imap()
        try:
            uids: list[bytes] = []
            # サーバ側検索（To / Cc / Subject / Body / Delivered-To）。catch-all 宛
            # なので To/Delivered-To が主だが、メールヘッダ注入で追加された Cc に
            # トークンが現れるケースも拾えるよう CC と HEADER も検索する。
            for crit in (
                ["TO", token],
                ["CC", token],
                ["SUBJECT", token],
                ["BODY", token],
                ["HEADER", "Delivered-To", token],
            ):
                try:
                    typ, data = conn.uid("search", None, *crit)
                except Exception:
                    continue
                if typ == "OK" and data and data[0]:
                    uids.extend(data[0].split())
            seen: set[bytes] = set()
            raws: list = []
            for uid in uids:
                if uid in seen:
                    continue
                seen.add(uid)
                typ, msg_data = conn.uid("fetch", uid, "(RFC822)")
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                raws.append((uid.decode(), msg_data[0][1]))
            return filter_messages(raws, token)
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    # -- POP3 (サーバ側検索が無いので全件取得してフィルタ) --
    def _search_pop3(self, token: str) -> list:
        cfg = self.config
        _validate_connection_fields(cfg)
        if cfg.use_ssl:
            conn = poplib.POP3_SSL(cfg.host, cfg.effective_port)
        else:
            conn = poplib.POP3(cfg.host, cfg.effective_port)
        try:
            conn.user(cfg.username)
            conn.pass_(cfg.password)
            count = len(conn.list()[1])
            raws = []
            # 直近メールを優先（最大100件）して負荷を抑える。
            start = max(1, count - 100 + 1)
            for i in range(start, count + 1):
                resp, lines, octets = conn.retr(i)
                raws.append((str(i), b"\r\n".join(lines)))
            return filter_messages(raws, token)
        finally:
            try:
                conn.quit()
            except Exception:
                pass

    def search(self, token: str) -> list:
        """トークンに一致する受信メールのリストを返す。"""
        if not self.config.configured:
            raise RuntimeError(
                "OOB email is not configured (set WSCAN_OOB_HOST / "
                "WSCAN_OOB_USERNAME / WSCAN_OOB_PASSWORD)."
            )
        if self.config.protocol == "pop3":
            return self._search_pop3(token)
        return self._search_imap(token)

    # -- 直近メールの一括取得（複数トークンをメモリ内で突合するため） --
    def _fetch_recent_imap(self, limit: int) -> list:
        conn = self._connect_imap()
        try:
            typ, data = conn.uid("search", None, "ALL")
            if typ != "OK" or not data or not data[0]:
                return []
            uids = data[0].split()[-max(1, limit):]
            out = []
            for uid in uids:
                typ, msg_data = conn.uid("fetch", uid, "(RFC822)")
                if typ != "OK" or not msg_data or not msg_data[0]:
                    continue
                try:
                    out.append(parse_email(msg_data[0][1], uid=uid.decode()))
                except Exception:
                    continue
            return out
        finally:
            try:
                conn.logout()
            except Exception:
                pass

    def _fetch_recent_pop3(self, limit: int) -> list:
        cfg = self.config
        _validate_connection_fields(cfg)
        if cfg.use_ssl:
            conn = poplib.POP3_SSL(cfg.host, cfg.effective_port)
        else:
            conn = poplib.POP3(cfg.host, cfg.effective_port)
        try:
            conn.user(cfg.username)
            conn.pass_(cfg.password)
            count = len(conn.list()[1])
            out = []
            start = max(1, count - max(1, limit) + 1)
            for i in range(start, count + 1):
                resp, lines, octets = conn.retr(i)
                try:
                    out.append(parse_email(b"\r\n".join(lines), uid=str(i)))
                except Exception:
                    continue
            return out
        finally:
            try:
                conn.quit()
            except Exception:
                pass

    def fetch_recent(self, limit: int = 50) -> list:
        """直近 ``limit`` 件の受信メールを **1 回のログイン**で取得・解析して返す。

        複数トークンを 1 ポーリングで突合したいときに使う。トークン毎に
        :meth:`search` を呼ぶとログインが多発しメールボックスを絞られ得るため、
        ここで一括取得し、突合は ``email_matches_token`` でメモリ内に行う。
        """
        if not self.config.configured:
            raise RuntimeError(
                "OOB email is not configured (set WSCAN_OOB_HOST / "
                "WSCAN_OOB_USERNAME / WSCAN_OOB_PASSWORD)."
            )
        if self.config.protocol == "pop3":
            return self._fetch_recent_pop3(limit)
        return self._fetch_recent_imap(limit)

    def wait_for(
        self, token: str, timeout: float = 60.0, interval: float = 5.0
    ) -> Optional[ReceivedEmail]:
        """トークン一致メールが届くまで最大 ``timeout`` 秒ポーリングする。"""
        deadline = time.time() + max(0.0, timeout)
        while True:
            try:
                hits = self.search(token)
            except Exception:
                hits = []
            if hits:
                return hits[0]
            if time.time() >= deadline:
                return None
            time.sleep(max(0.5, interval))
