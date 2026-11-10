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

from typing import Any, Optional

from . import auth_detect
from .url_scope import same_origin

# 認証切れを示す HTTP ステータス。403 は正規の認可拒否（権限不足）でも返るため
# 単独では失効とみなさない（誤再ログイン抑制）。401 のみ強シグナルとして扱う。
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
    source: Any,
    target_url: str,
    user_headers: dict | None = None,
) -> dict[str, str]:
    """捕捉元から target_url と同一 origin 宛の最新認証ヘッダを抽出する（純粋）。

    ``source`` には :class:`wscan.browser.NetworkCapture` か、従来どおり
    request/response ペアの list を渡せる。NetworkCapture の場合は次の 2 系統を読む:

      1. ``_observed_auth_headers`` … on_request が redaction **前**に退避した
         origin ごとの最新認証ヘッダ（ログインフロー中でもこのスロットにだけ残る）。
      2. ``pairs`` … ログインフロー外（通常の SPA fetch 等）の捕捉ペア。

    スロットは「認証ヘッダ付きリクエストのたびに上書きされる最新値」なので pairs より
    新しく、こちらを優先する（latest wins）。どちらもメモリ内の読み取りのみで、状態を
    変更しない。

    対象:
      - Authorization（スキーム Bearer または Token）
      - X-API-Key / X-Auth-Token / X-Access-Token

    規則:
      - target_url と同一 origin 宛のリクエストのみ対象（cross-origin は一切含めない）。
      - user_headers に同名ヘッダが既に存在する場合、そのヘッダは採用しない（ユーザー設定優先）。
    """
    if not target_url:
        return {}
    user_keys = {str(k).lower() for k in (user_headers or {})}
    for record in _auth_records_latest_first(source):
        matched = _match_auth_record(record, target_url, user_keys)
        if matched:
            return matched
    return {}


def _auth_records_latest_first(source: Any):
    """認証ヘッダ候補レコードを「新しい順」に列挙する（読み取り専用）。

    まず NetworkCapture の非永続スロット（redaction 前の最新観測値）、次に pairs。
    """
    slot = getattr(source, "_observed_auth_headers", None)
    if isinstance(slot, dict):
        for record in reversed(list(slot.values())):
            yield record
    pairs = getattr(source, "pairs", None)
    if pairs is None and isinstance(source, (list, tuple)):
        pairs = source
    if isinstance(pairs, (list, tuple)):
        for record in reversed(pairs):
            yield record


def _match_auth_record(record: Any, target_url: str, user_keys: set[str]) -> dict[str, str] | None:
    """1 レコードから同一 origin の認識済み認証ヘッダを 1 つ返す（純粋）。"""
    if not isinstance(record, dict):
        return None
    req = record.get("request") if "request" in record else record
    if not isinstance(req, dict):
        return None
    req_url = req.get("url") or ""
    if not req_url or not same_origin(req_url, target_url):
        return None
    headers = req.get("headers")
    if not isinstance(headers, dict) or not headers:
        return None
    for cand in _RECOGNIZED_AUTH_HEADERS:
        if cand in user_keys:
            continue
        for k, v in headers.items():
            if str(k).lower() == cand:
                normalized = _normalize_auth_header(str(k), str(v))
                if normalized:
                    return {normalized[0]: normalized[1]}
    return None


def should_route_to_api_get(
    injection_point: Any = None,
    *,
    url: str = "",
    source: str = "",
    is_url_param: bool = True,
    synced_token: dict | None = None,
    engine: Any = None,
) -> bool:
    """SPA XHR/fetch 由来の same-origin API GET 注入点を HTTP 経路へルーティングすべきか判定する純粋関数。

    条件:
      1. location が url_param / is_url_param が True（GET URL パラメータであること）
      2. source が 'spa'、または engine の _spa_harvested_urls に登録された API であること
         （top-level document は除外）
      3. synced_token に有効なトークンヘッダが存在すること
      4. url が synced_token の origin と same-origin であること

    いずれかを満たさない場合（トップレベル文書の URL パラメータ、トークン未同期、別オリジン、
    form 注入など）は False（ブラウザナビゲーションを維持）。
    """
    if injection_point is not None:
        loc = getattr(injection_point, "location", "")
        if loc and loc != "url_param":
            return False
        if not url:
            url = getattr(injection_point, "url", "")
        if not source:
            source = getattr(injection_point, "source", "") or getattr(injection_point, "template_source", "")
    elif not is_url_param:
        return False

    if not url:
        return False

    is_spa_source = str(source or "").lower() == "spa"
    if not is_spa_source and engine is not None:
        spa_urls = getattr(engine, "_spa_harvested_urls", ()) or ()
        from urllib.parse import urlsplit
        p = urlsplit(url)
        clean_endpoint = f"{p.scheme}://{p.netloc}{p.path}" if p.scheme and p.netloc else url
        if url in spa_urls or clean_endpoint in spa_urls:
            is_spa_source = True

    if not is_spa_source:
        return False

    if not isinstance(synced_token, dict):
        return False

    token_origin = synced_token.get("origin", "")
    token_headers = synced_token.get("headers", {})
    if not token_origin or not token_headers:
        return False

    return same_origin(url, token_origin)

