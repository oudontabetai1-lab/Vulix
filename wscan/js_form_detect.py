"""JS 制御フォーム（fetch JSON 送信）の検出 — LLM 非依存の純粋関数。

フォームの submit が ``preventDefault`` され、ページ内 JS が同一オリジンの JSON API へ
``fetch``/``XHR`` でフォーム値を送る形態（SPA ログイン等）では、ネイティブ form 送信が
発生しないため従来の送達相関（``_request_carries_form_value`` の method/action 照合）は
常に失敗する。このモジュールは probe 直後の network 観測から「フォーム送信が JSON API へ
流れた」ことを判定し、そのエンドポイントを json 注入テンプレートへ整形する。

判定は観測した request のみを根拠にする（ページ本文のスクリプト解析はしない）。
認証フロー（``authentication_active``）で捕捉した request は赤字化済み（post_data が
``"[REDACTED]"``）のため parse に失敗して自然に除外される。
"""
from __future__ import annotations

import json
from typing import Any, Optional
from urllib.parse import urlparse


# JS 送信として扱う resource_type。document（ナビゲーション）は除外条件側で使う。
_JS_SEND_RESOURCE_TYPES = frozenset({"fetch", "xhr"})
# ナビゲーション検出用 resource_type。window 内にこれがあれば submit が遷移した＝非 JS 制御。
_DOCUMENT_RESOURCE_TYPES = frozenset({"document"})


def _same_origin(url_a: str, url_b: str) -> bool:
    """netloc（scheme 含まない host:port）一致で同一オリジン判定（純粋）。"""
    try:
        return urlparse(url_a).netloc != "" and urlparse(url_a).netloc == urlparse(url_b).netloc
    except Exception:
        return False


def _header_value(request: dict, name: str) -> str:
    headers = request.get("headers")
    if not isinstance(headers, dict):
        return ""
    for key, value in headers.items():
        if str(key).lower() == name:
            return str(value or "")
    return ""


def js_form_json_target(
    requests: list,
    page_url: str,
    field_names,
    target_field: str = "",
) -> Optional[dict]:
    """probe 直後の観測 request 群から JS 制御フォームの送信先 JSON API を特定する（純粋）。

    ``requests`` は probe window（submit 直接後〜判定時点）に捕捉した request dict のリスト
    （完了 pair の request と in-flight の pending 両方を含めて呼び出し側で束ねる）。
    以下を**全て**満たす request があればテンプレート用 dict を返す（無ければ None）:

    - 同一オリジン（page_url と netloc 一致）
    - ``resource_type`` が fetch/xhr（ページ遷移でない JS 送信）
    - post_data が JSON object として parse でき、フォームのフィールド名を top-level キーとして
      運んでいる（target_field 必須＋``min(2, len(field_names))`` 個以上一致）
    - window 内に document（ナビゲーション）request が**無い**（submit が preventDefault された）

    返り値は engine の json 注入テンプレート（injection_templates）と同じ形:
    ``{method, url, endpoint, json_body, content_type, headers, field_names}``。
    値は probe 時に観測したもの（payload＋safe 値）であり、認証情報は呼び出し側で
    :func:`sanitize_credential_values` を通してから template 登録する。
    """
    if not isinstance(requests, list) or not page_url:
        return None
    names = tuple(str(n) for n in (field_names or ()) if n)
    target_field = str(target_field or "")
    # ナビゲーションが window 内にあれば submit が遷移した（JS 制御でない）。
    for req in requests:
        if not isinstance(req, dict):
            continue
        if str(req.get("resource_type", "")).lower() in _DOCUMENT_RESOURCE_TYPES:
            return None
    required_matches = max(1, min(2, len(names)))
    for req in requests:
        if not isinstance(req, dict):
            continue
        url = req.get("url")
        if not isinstance(url, str) or not url:
            continue
        if str(req.get("resource_type", "")).lower() not in _JS_SEND_RESOURCE_TYPES:
            continue
        if str(req.get("method", "")).upper() not in {"POST", "PUT", "PATCH", "DELETE"}:
            continue
        if not _same_origin(url, page_url):
            continue
        # 赤字化済み（認証フロー由来）の request は parse に失敗して除外される。
        post_data = req.get("post_data")
        if not isinstance(post_data, str) or not post_data:
            continue
        try:
            body = json.loads(post_data)
        except (TypeError, ValueError):
            continue
        if not isinstance(body, dict):
            continue
        content_type = _header_value(req, "content-type")
        keys = {str(k) for k in body.keys()}
        matched = [n for n in names if n in keys]
        if target_field and target_field not in keys:
            continue
        if len(matched) < required_matches:
            continue
        # replay headers の抽出は spa_harvest と同一規約（content-type は分離、cookie 温存）。
        from .spa_harvest import _extract_replay_headers
        content_type, replay_headers = _extract_replay_headers(req.get("headers") or {})
        return {
            "method": str(req.get("method", "POST")).upper(),
            "url": url.split("#", 1)[0],
            "endpoint": urlparse(url)._replace(query="", fragment="").geturl(),
            "json_body": body,
            "content_type": content_type or "application/json",
            "headers": replay_headers,
            "field_names": tuple(matched),
        }
    return None


def sanitize_credential_values(obj: Any, secrets) -> Any:
    """template 値から投入値・認証情報を除去する（純粋関数）。

    ``secrets``（認証情報 auth_user/auth_pass、現在 probe 中の payload 等）と
    **完全一致**する文字列値を空文字へ置換する。probe 観測 body には他フィールドの
    safe 値として認証情報が入ることがある（browser の fill スクリプトが auth 欄を
    safe 値として流用する）ため、観測 body をそのまま template 化すると認証情報が
    再送・永続化されうる。また payload 値が template に残ると兄弟フィールドの scan で
    「payload 由来の誤検知」を招くため、現在 payload と一致する値も除去する。
    部分一致は置換しない（他の値そのものを壊さない）。
    """
    secret_set = tuple(str(s) for s in (secrets or ()) if s)

    def _clean(value: Any) -> Any:
        if isinstance(value, str):
            return "" if value in secret_set else value
        if isinstance(value, dict):
            return {k: _clean(v) for k, v in value.items()}
        if isinstance(value, list):
            return [_clean(v) for v in value]
        if isinstance(value, tuple):
            return tuple(_clean(v) for v in value)
        return value

    return _clean(obj)
