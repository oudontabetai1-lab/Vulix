"""
セッション失効検知（純粋関数）
==============================
長時間スキャン中にログインセッションが切れると、以降のリクエストが全て
ログイン画面/401 に化けて「検出力が静かにゼロになる」。これを検知して
自動再ログインへ繋ぐための判定ロジック。

判定は :mod:`wscan.auth_detect` の純粋関数（``on_login_page`` /
``has_login_form`` / ``has_failure_text``）を再利用し、誤って再ログインを
連発しないよう **強いシグナルが揃ったときだけ** 失効とみなす。

実際の再ログイン副作用（ブラウザ操作・再クロール）は ``engine`` 側が担い、
本モジュールは「失効しているか」の真偽だけを返す（IO 非依存・テスト可能）。
"""
from __future__ import annotations

from typing import Optional

from . import auth_detect

# 認証切れを示す HTTP ステータス。403 は正規の認可拒否（権限不足）でも返るため
# 単独では失効とみなさない（誤再ログイン抑止）。401 のみ強シグナルとして扱う。
_UNAUTHORIZED_STATUSES = {401}


def looks_logged_out(
    *,
    status: Optional[int],
    final_url: str,
    body: str,
    login_url: str = "",
    logged_in_marker: str = "",
) -> bool:
    """応答がログアウト（セッション失効）状態を示すか。

    True を返す条件（いずれか）:
      1. HTTP 401。
      2. ログインページに着地していて、かつログインフォームが残存している
         （＝保護ページから login へリダイレクトされた典型パターン）。
      3. ``logged_in_marker`` 指定時、その印が本文から消え、かつログイン
         フォームが出現している（認証済みページの目印が消えた）。

    誤検知（不要な再ログイン）を避けるため、URL がログインに見えるだけ／
    フォームが在るだけ／403 だけでは失効とみなさない。
    """
    if status in _UNAUTHORIZED_STATUSES:
        return True

    has_form = auth_detect.has_login_form(body or "")

    if has_form and auth_detect.on_login_page(final_url or "", login_url):
        return True

    if logged_in_marker:
        marker_gone = logged_in_marker not in (body or "")
        if marker_gone and has_form:
            return True

    return False


from .url_scope import same_origin

_RECOGNIZED_AUTH_HEADERS = ("authorization", "x-api-key", "x-auth-token", "x-access-token")
_CANONICAL_AUTH_HEADER_NAMES = {
    "authorization": "Authorization",
    "x-api-key": "X-API-Key",
    "x-auth-token": "X-Auth-Token",
    "x-access-token": "X-Access-Token",
}


def _normalize_auth_header(name: str, value: str) -> tuple[str, str] | None:
    """認証ヘッダ名と値が対象スキーム（Bearer/Token または API-key）に合致するか判定する。"""
    lowered = str(name or "").lower()
    val = str(value or "").strip()
    if not val:
        return None
    if lowered == "authorization":
        parts = val.split(None, 1)
        if len(parts) >= 2 and parts[0].lower() in ("bearer", "token") and parts[1].strip():
            return "Authorization", val
        return None
    elif lowered in _CANONICAL_AUTH_HEADER_NAMES:
        return _CANONICAL_AUTH_HEADER_NAMES[lowered], val
    return None


def extract_latest_auth_header(
    pairs: list[dict] | None,
    target_url: str,
    user_headers: dict | None = None,
) -> dict[str, str]:
    """捕捉レコードから target_url と同一 origin 宛に送られた最新の認証ヘッダを抽出する（純粋）。

    対象:
      - Authorization（スキーム Bearer または Token）
      - X-API-Key / X-Auth-Token / X-Access-Token

    規則:
      - target_url と同一 origin 宛のリクエストのみ対象（cross-origin は一切含めない）。
      - 直近に送信されたヘッダを優先採用（latest wins）。
      - user_headers に同名ヘッダが既に存在する場合、そのヘッダは採用しない（ユーザー設定優先）。
    """
    if not pairs or not target_url:
        return {}
    user_keys = {str(k).lower() for k in (user_headers or {})}
    for pair in reversed(pairs):
        req = pair.get("request") if isinstance(pair, dict) and "request" in pair else pair
        if not isinstance(req, dict):
            continue
        req_url = req.get("url") or ""
        if not req_url or not same_origin(req_url, target_url):
            continue
        headers = req.get("headers")
        if not isinstance(headers, dict) or not headers:
            continue
        for cand in _RECOGNIZED_AUTH_HEADERS:
            if cand in user_keys:
                continue
            for k, v in headers.items():
                if str(k).lower() == cand:
                    normalized = _normalize_auth_header(str(k), str(v))
                    if normalized:
                        return {normalized[0]: normalized[1]}
    return {}

