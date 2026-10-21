"""HTTP リクエスト / ペイロードのログを JSONL 形式で保存するユーティリティ。

スキャン中に送信したすべての HTTP リクエスト（メソッド・URL・ヘッダ・
``post_data``）とレスポンスのステータス、および各フィールドへ投入した
ペイロードを ``output_dir`` 配下のファイルへ追記する。スキャン後の監査・
再現・デバッグ用途に利用する。

- ``http_requests.jsonl`` … ブラウザが送信した全リクエスト/レスポンス
- ``payloads.jsonl``       … 各フィールドへ投入したペイロード

いずれも 1 行 1 レコードの JSON Lines 形式。ログ書き込みはスキャン本体を
妨げないよう、失敗しても例外を握りつぶす（ベストエフォート）。
"""
import json
import re
import threading
import time
from pathlib import Path
from typing import Optional

from wscan import url_scope

# 巨大な post_data でログが肥大化するのを防ぐための上限（文字数）
_MAX_POST_DATA = 20000


def _count_existing_records(path: Path) -> int:
    """既存 JSONL の有効レコード行数を数える（純粋・ベストエフォート）。

    append 再利用時にカウンタを既存行数から始めるため。壊れた行/欠損ファイルは 0 側に倒す
    （空・非 JSON 行は数えない）。
    """
    try:
        # errors="replace": 中断で末尾に不完全な UTF-8 が残っても UnicodeDecodeError で
        # 初期化を落とさず、その行を非 JSON として数えないだけにする。
        with open(path, "r", encoding="utf-8", errors="replace") as fp:
            count = 0
            for line in fp:
                line = line.strip()
                if not line:
                    continue
                try:
                    json.loads(line)
                except Exception:
                    continue
                count += 1
            return count
    except OSError:
        return 0

# 監査ログは output/ 配下に保存され、ダッシュボードが（既定では認証なしで）
# 配信しうる。認証情報がそのまま残ると閲覧者に漏れるため、書き込み前に
# 機微なヘッダ値・ボディフィールドをマスクする。
_REDACTED = url_scope.REDACTED

# 値をマスクするヘッダ名（小文字・完全一致）。
# ここが機密ヘッダの**単一の正典**。scanners/base（merge_template_headers / evidence redaction）も
# この集合＋runtime 登録を `is_sensitive_header` 経由で共有する（二重管理の同期漏れ防止）。
_SENSITIVE_HEADERS = frozenset({
    "authorization", "proxy-authorization", "authentication",
    "cookie", "set-cookie", "x-api-key", "api-key", "apikey",
    "x-auth-token", "x-access-token", "x-amz-security-token",
    "x-csrf-token", "x-xsrf-token",
})

# ユーザーが --header/ダッシュボードで設定したカスタムヘッダ名（実行時登録）。
# 非標準名の認証ヘッダ（X-Company-Auth 等）も伏字化するために使う。
_RUNTIME_SENSITIVE_HEADERS: set[str] = set()


def register_sensitive_headers(names) -> None:
    """カスタムヘッダ名を伏字対象に登録する（小文字化。冪等）。"""
    _RUNTIME_SENSITIVE_HEADERS.update(str(name).lower() for name in names)


def clear_sensitive_headers() -> None:
    """登録済みのカスタムヘッダ名を消す（主にテスト用）。"""
    _RUNTIME_SENSITIVE_HEADERS.clear()


def _is_sensitive_header(name) -> bool:
    normalized = str(name).lower()
    return (
        normalized in _SENSITIVE_HEADERS
        or normalized in _RUNTIME_SENSITIVE_HEADERS
    )


def is_sensitive_header(name) -> bool:
    """ヘッダ名が機密（静的集合 or runtime 登録）かを返す（正典の公開 API）。

    scanners/base の資格情報判定（テンプレ上書き禁止・evidence redaction）が独自集合を
    持たずにここへ委譲するための単一の正典。runtime 登録ヘッダも拾う。
    """
    return _is_sensitive_header(name)


# urlencoded / JSON ボディや URL クエリでマスクするキーのトークン（部分一致）。
# 正典は url_scope（URL redaction と同じ集合・正規表現を共有する）。名前は後方互換のため残す。
_SENSITIVE_BODY_KEYS = url_scope.SENSITIVE_KEY_TOKENS
_KEYS_ALT = url_scope.KEYS_ALT

# RFC 3986 userinfo plus @ handles malformed credentials without crossing header structure.
_URL_USERINFO = re.compile(r"(?i)((?:[a-z][a-z0-9+.\-]*:)?//)([A-Za-z0-9._~%!$&'()*+,;=:@\-]*)@")


def _redact_url_userinfo(text):
    """Mask embedded URL credentials without changing the original value."""
    if not isinstance(text, str):
        return text
    return _URL_USERINFO.sub(lambda match: f"{match.group(1)}{_REDACTED}@", text)


def _redact_headers(headers: dict) -> dict:
    if not isinstance(headers, dict):
        return headers
    return {
        k: (_REDACTED if _is_sensitive_header(k) else _redact_text(v))
        for k, v in headers.items()
    }


def _redact_text(text):
    """urlencoded ボディ / JSON ボディ中の機微フィールド値をマスクする（url_scope へ委譲）。"""
    return url_scope.redact_kv_values(_redact_url_userinfo(text))


def _redact_url(url):
    """URL の機微値をマスクする（クエリ・フラグメント・userinfo）。

    OAuth implicit 等はトークンを **fragment**（`#access_token=...`）に載せ、`user:pass@host` の
    **userinfo** も資格情報。クエリだけでなくこれらも永続化前に伏せる。判定は url_scope が正典。"""
    return url_scope.redact_url(url)


def redact_text(text):
    """機微ボディ値（urlencoded / JSON）をマスクする正典の公開 API（共有点）。

    probe 証跡台帳など他モジュールが独自 redaction を持たずにここへ委譲するための公開入口。"""
    return _redact_text(text)


def redact_url(url):
    """URL クエリの機微パラメータ値をマスクする正典の公開 API（redact_text と同じ意図）。"""
    return _redact_url(url)


class RequestLogger:
    """リクエスト/ペイロードを JSONL ファイルへ追記するロガー。"""

    def __init__(self, output_dir, *, enabled: bool = True):
        self.output_dir = Path(output_dir)
        self.enabled = enabled
        self.http_path = self.output_dir / "http_requests.jsonl"
        self.payload_path = self.output_dir / "payloads.jsonl"
        self.llm_path = self.output_dir / "llm_calls.jsonl"
        # NetworkCapture（同期）と Monitor（async）双方から呼ばれうるので
        # ファイル追記をロックで直列化する。
        self._lock = threading.Lock()
        # 末尾改行を確認済みの path（再利用ファイルの最初の追記時に 1 度だけ検査する）。
        self._tail_checked: set = set()
        # 既存 output dir（resume で --output=--resume 同一等）を append で再利用すると、
        # ファイルには前回行が残るのにカウンタを 0 開始すると evidence/HTML が今回分しか数えず
        # JSONL 実数と食い違う。既存 JSONL の有効行数からカウンタを初期化する。
        self.http_count = _count_existing_records(self.http_path)
        self.payload_count = _count_existing_records(self.payload_path)
        self.llm_call_count = _count_existing_records(self.llm_path)
        # Import lazily: the ledger schema shares this module's redaction helpers.
        from wscan.probe_recorder import ProbeLedger
        self.probe_ledger = ProbeLedger(self.output_dir, self.output_dir.name, enabled=enabled)

    def log_probe(self, *, role, pair=None, transport=None, check="", field="",
                  payload=None, url="", sent=False, actor="", rationale="",
                  parent_id="", outcome=None, decision_rule="", decision_version="") -> Optional[str]:
        """Append observation only; return its ID only after a successful write."""
        # shortcut: transport captures use discover; add an observation-only role before phase accounting.
        if not self.enabled:
            return
        try:
            from wscan.probe_ledger import (
                ProbeAttemptRecord, RequestRecord, ResponseRecord,
                body_length, redact_excerpt, sha256_hex,
            )
            req = (pair or {}).get("request") or {}
            resp = (pair or {}).get("response") or {}
            request = None
            if transport is not None:
                body = req.get("post_data")
                request = RequestRecord(
                    method=req.get("method", ""), url=req.get("url", url),
                    transport=transport, sent=sent,
                    headers_excerpt=redact_excerpt("\n".join(
                        f"{k}: {v}" for k, v in (req.get("headers") or {}).items())),
                    # Hash metadata avoids retaining arbitrary captured body secrets.
                    body_hash=sha256_hex(body), body_length=body_length(body),
                )
            response = None
            if resp:
                body = resp.get("body")
                response = ResponseRecord(
                    status=resp.get("status"), final_url=resp.get("url", ""),
                    headers_excerpt=redact_excerpt("\n".join(
                        f"{k}: {v}" for k, v in (resp.get("headers") or {}).items())),
                    body_hash=sha256_hex(body), body_length=body_length(body),
                )
            # Submission payloads have no known carrier or sent request yet.
            if payload is not None:
                rationale = f"payload_sha256={sha256_hex(payload)}; bytes={body_length(payload)}; {rationale}"
            record = ProbeAttemptRecord(
                scan_id=self.probe_ledger.scan_id,
                attempt_id=self.probe_ledger.next_attempt_id(), role=role, parent_id=parent_id,
                check=check, injection_key=redact_excerpt(field), actor=actor,
                started_at=req.get("timestamp") or time.time(),
                ended_at=resp.get("timestamp"), request=request, response=response,
                outcome=outcome, decision_rule=decision_rule, decision_version=decision_version,
                completion_unit=self.probe_ledger.current_unit(),
                rationale=redact_excerpt(rationale),
            )
            if self.probe_ledger.append(record):
                return record.attempt_id
        except Exception as exc:
            self.probe_ledger.manifest.note_gap(f"probe_observation_error:{type(exc).__name__}")

    async def log_httpx_submission(self, request) -> None:
        """HTTPX event hook; never consume a streaming request body."""
        from wscan.probe_ledger import ProbeRole, Transport
        try:
            attempt_id = self.log_probe(
                role=ProbeRole.DISCOVER, transport=Transport.HTTPX, actor="transport_capture",
                pair={"request": {"method": request.method, "url": str(request.url),
                                  "headers": dict(request.headers)}},
                rationale="transport submission; detector role and delivery unknown",
            )
            request.extensions["vulix_probe_submission"] = (self, attempt_id)
        except Exception as exc:
            self.probe_ledger.manifest.note_gap(f"probe_observation_error:{type(exc).__name__}")

    async def log_httpx_response(self, response) -> None:
        """Correlate headers to the actual request; leave streaming bodies untouched."""
        from wscan.probe_ledger import ProbeRole, Transport
        try:
            request = response.request
            owner, attempt_id = request.extensions.get("vulix_probe_submission", (None, None))
            observation_id = self.log_probe(
                role=ProbeRole.DISCOVER, transport=Transport.HTTPX, actor="transport_capture",
                parent_id=attempt_id if owner is self and attempt_id else "", sent=True,
                pair={"request": {"method": request.method, "url": str(request.url),
                                  "headers": dict(request.headers)},
                      "response": {"status": response.status_code, "url": str(response.url),
                                   "headers": dict(response.headers), "timestamp": time.time()}},
                rationale="HTTP response observed; detector role and outcome unknown",
            )
            response.extensions["vulix_probe_observation"] = (self, observation_id)
        except Exception as exc:
            self.probe_ledger.manifest.note_gap(f"probe_observation_error:{type(exc).__name__}")

    def log_browser_submission(self, request: dict) -> Optional[str]:
        from wscan.probe_ledger import ProbeRole, Transport
        return self.log_probe(
            role=ProbeRole.DISCOVER, transport=Transport.PLAYWRIGHT, actor="transport_capture",
            pair={"request": request},
            rationale="browser submission; detector role and delivery unknown",
        )

    def _append(self, path: Path, record: dict) -> bool:
        """1 行追記する。実際に永続化できたら True（カウンタ整合の判定に使う）。"""
        if not self.enabled:
            return False
        try:
            line = json.dumps(record, ensure_ascii=False)
        except Exception:
            return False
        with self._lock:
            try:
                prefix = ""
                if path not in self._tail_checked:
                    # 再利用ファイルが改行無しで終わる（中断で途切れた行・完全な JSON でも改行欠落）と
                    # 追記行が `}{...}` と連結され無効行になる。最初の追記前に区切りを入れる。
                    try:
                        with open(path, "rb") as rf:
                            rf.seek(0, 2)
                            if rf.tell() > 0:
                                rf.seek(-1, 2)
                                if rf.read(1) != b"\n":
                                    prefix = "\n"
                    except FileNotFoundError:
                        pass
                with open(path, "a", encoding="utf-8") as fp:
                    fp.write(prefix + line + "\n")
                self._tail_checked.add(path)
                return True
            except Exception:
                # ログ保存はベストエフォート。失敗してもスキャンは継続する。
                return False

    def log_http(self, pair: Optional[dict]) -> None:
        """NetworkCapture が組み立てた request/response ペアを記録する。"""
        if not self.enabled or not pair:
            return
        req = pair.get("request", {}) or {}
        resp = pair.get("response", {}) or {}
        post_data = req.get("post_data")
        if isinstance(post_data, str) and len(post_data) > _MAX_POST_DATA:
            post_data = post_data[:_MAX_POST_DATA] + "...<truncated>"
        # 認証情報（Cookie/Authorization ヘッダ・パスワード等のボディ/クエリ）を
        # マスクしてから保存する。output/ は閲覧者へ配信されうるため。
        record = {
            "ts": req.get("timestamp") or time.time(),
            "method": req.get("method", ""),
            "url": _redact_url(req.get("url", "")),
            "request_headers": _redact_headers(req.get("headers", {})),
            "post_data": _redact_text(post_data),
            "status": resp.get("status"),
            "response_headers": _redact_headers(resp.get("headers", {})),
        }
        self._append(self.http_path, record)
        self.http_count += 1
        from wscan.probe_ledger import ProbeRole, Transport
        self.log_probe(role=ProbeRole.DISCOVER, pair=pair, transport=Transport.PLAYWRIGHT,
                       sent=True, actor="transport_capture",
                       parent_id=(req.get("_probe_attempt_id") or "")
                       if req.get("_req_id") is not None
                       and req.get("_req_id") == resp.get("_req_id") else "",
                       rationale="HTTP response observed; detector role and outcome unknown")

    def log_payload(self, field: str, payload: str, check_type: str, url: str = "") -> None:
        """フィールドへ投入したペイロードを記録する。"""
        if not self.enabled:
            return
        from wscan.probe_ledger import ProbeRole
        labels = check_type.split("_")
        role = next((role for token, role in (
            ("baseline", ProbeRole.BASELINE), ("control", ProbeRole.CONTROL),
            ("verify", ProbeRole.VERIFY), ("cleanup", ProbeRole.CLEANUP),
        ) if token in labels), ProbeRole.ATTACK)
        attempt_id = self.log_probe(
            role=role, check=check_type, field=field, payload=payload,
            url=url, actor="payload_submission",
            rationale=f"url={redact_url(url)}; payload prepared; transport, delivery and outcome unknown",
        )
        record = {
            "ts": time.time(),
            "url": _redact_url(url),
            "field": field,
            "check_type": check_type,
            "payload": payload,
        }
        if attempt_id:
            record["probe_attempt_id"] = attempt_id
        self._append(self.payload_path, record)
        self.payload_count += 1

    def log_llm_call(
        self, *, provider: str = "", role: str = "", model: str = "",
        timeout_seconds=None, elapsed_seconds=None, status: str = "",
        retries=None, prompt_chars=None, response_chars=None,
        input_tokens=None, output_tokens=None, exception_type=None, caller: str = "",
    ) -> None:
        """LLM 呼び出し1回のメタデータを記録する（観測性）。

        **本文（prompt/response）は保存しない**（文字数のみ）。例外は種別名のみ記録し
        `str(exc)` は保存しない：Gemini の URL には APIキーが平文で入り、httpx 例外文字列に
        URL が載りうるため（output/ は閲覧者へ配信されうる）。ベストエフォート（失敗しても継続）。
        """
        if not self.enabled:
            return
        record = {
            "ts": time.time(),
            "provider": provider,
            "role": role,
            "model": model,
            "timeout_seconds": timeout_seconds,
            "elapsed_seconds": elapsed_seconds,
            "status": status,
            "retries": retries,
            "prompt_chars": prompt_chars,
            "response_chars": response_chars,
            "input_tokens": input_tokens,
            "output_tokens": output_tokens,
            "exception_type": exception_type,
            "caller": caller,
        }
        # 実際に永続化できた行だけ数える。失敗時に加算すると evidence.json の総数が
        # llm_calls.jsonl の実行数と食い違う。
        if self._append(self.llm_path, record):
            self.llm_call_count += 1
