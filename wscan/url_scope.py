"""URL / origin / scope 判定の正典ヘルパー（すべて純粋関数）。

origin 同一性（scheme＋IDNA ホスト＋実効ポート）・scope 包含（path 境界・query・``;params``）・
永続化用 URL の redaction（userinfo・機微 query 値）は、engine / manual_crawl / url_normalize /
scanners / request_logger に散在して細部が食い違っていた。ここへ集約して 1 つの規則にする。

HTTP/ブラウザには依存しない（判定だけを持つ）。解析不能な入力は例外を投げず安全側
（scope 判定は False、redaction は入力を最大限伏せた形）へ倒す。
"""
from __future__ import annotations

import re
from urllib.parse import urlparse, urlsplit

# 既定ポート。``http://h:80`` と ``http://h`` を同一 origin として扱うために補完する。
# ws/wss を含めないのは header_scope 由来の既存挙動（明示ポートをそのまま残す）を保つため。
DEFAULT_PORTS = {"http": 80, "https": 443}


def idna_host(host: str) -> str:
    """ホスト名を小文字＋IDNA（Punycode）へ正規化する。

    Chromium は page.url の IDN ホストを Punycode で保存するため、Unicode 設定のまま比較すると
    同一サイトが cross-origin 扱いになる。変換不能（壊れたホスト名）なら小文字表現へ戻す。
    """
    low = str(host or "").lower()
    try:
        return low.encode("idna").decode("ascii")
    except (UnicodeError, UnicodeDecodeError):
        return low


def origin_tuple(url: str) -> tuple[str, str, int | None]:
    """``(scheme, IDNA ホスト, 実効ポート)`` を返す。既定ポートは補完する。

    解析不能・ポート不正（範囲外）などは ``("", "", None)`` を返し、呼び出し側の比較を
    False へ倒す（例外で巡回や scope 判定を落とさない）。
    """
    try:
        parsed = urlsplit(str(url or "").strip())
        scheme = (parsed.scheme or "").lower()
        host = idna_host(parsed.hostname or "")
        port = parsed.port or DEFAULT_PORTS.get(scheme)
    except (TypeError, ValueError):
        return "", "", None
    return scheme, host, port


def same_origin(url: str, other: str) -> bool:
    """同一 origin か（scheme＋IDNA ホスト＋実効ポート）。

    netloc だけの比較は (1) scheme を無視して http↔https を同一視し、(2) 明示既定ポートと省略
    （``app.test:443`` と ``app.test``）を別 origin 扱いする。どちらも正す。scheme かホストを
    取れない入力は常に False。
    """
    a, b = origin_tuple(url), origin_tuple(other)
    return bool(a[0] and a[1]) and a == b


def origin_string(url: str) -> str:
    """比較用の ``scheme://host[:port]`` を返す（既定ポートは省略・IPv6 は括弧）。

    scheme/ホストを取れない入力は ""。``same_origin`` と同じ正規化規則を文字列で表したもの。
    """
    scheme, host, port = origin_tuple(url)
    if not scheme or not host:
        return ""
    if ":" in host:
        host = f"[{host}]"
    suffix = f":{port}" if port is not None and port != DEFAULT_PORTS.get(scheme) else ""
    return f"{scheme}://{host}{suffix}"


def host_matches(host: str, domain: str, *, allow_subdomain: bool = True) -> bool:
    """ホストが domain 自身か、その配下（サブドメイン）かを返す。

    cookie の domain 属性（先頭ドット）とホスト系 scope（``auth.example.com``）で共有する。
    *allow_subdomain* を False にすると完全一致のみ（host-only cookie 用）。空はどちらも False。
    ホスト表記の揺れ（大小・IDN）は ``idna_host`` で吸収する。
    """
    h = idna_host(host)
    d = idna_host(str(domain or "").strip(".")) if domain else ""
    if not h or not d:
        return False
    if h == d:
        return True
    return allow_subdomain and h.endswith("." + d)


def request_path(url: str) -> str:
    """要求パスを ``;params`` 込みで返す（空は ``/``）。

    ``/dav;jsessionid=...`` の ``;params`` は crawl したリソースの一部なので落とさない
    （落とすと別リソースを probe して tested 扱いにしてしまう）。
    """
    parsed = urlparse(str(url or ""))
    path = parsed.path or "/"
    return f"{path};{parsed.params}" if parsed.params else path


def path_within(path: str, scope_path: str) -> bool:
    """*path* が *scope_path* 自身かその配下か（境界は ``/``）。

    ``/admin`` が ``/administrator`` に誤マッチしないよう、プレフィックス一致に加えて境界が
    スラッシュであることを要求する。RFC6265 の cookie path-match とも同じ規則。
    """
    p = path or "/"
    s = scope_path or "/"
    if p == s:
        return True
    if not p.startswith(s):
        return False
    return s.endswith("/") or p[len(s):len(s) + 1] == "/"


def url_in_scope(url: str, scope: str, *, host_scope: bool = False) -> bool:
    """URL が 1 つの scope に含まれるか。

    scope の形で規則が変わる:
    - ``http(s)://`` 始まり … URL 全体の前方一致（境界は ``/``）。query を書いた scope は
      query ごと厳密一致になる（query 限定 target を access-only へ落とさないため、query は
      呼び出し側が必要に応じて除いてから再判定する）。
    - ``/`` を含む（パス系。``/admin`` 等）… パス境界一致。``;params`` は比較から外し
      ``/dav;jsessionid=1`` を ``/dav`` 配下とみなす（URL 文字列側の ``;params`` は保持）。
    - それ以外（``auth.example.com`` 等）… *host_scope* が True のときだけホスト系として
      完全一致/サブドメイン一致で判定する。False ならパス系として扱う（従来の engine 挙動）。

    両辺の末尾スラッシュは比較時にだけ落とす（``/app/`` と ``/app`` を同一視）。空 scope は False。
    """
    candidate = str(url or "").rstrip("/")
    target = str(scope or "").strip().rstrip("/")
    if not target:
        return False
    if target.startswith(("http://", "https://")):
        return candidate == target or candidate.startswith(target + "/")
    if host_scope and "/" not in target:
        return host_matches(urlsplit(candidate).hostname or "", target)
    return path_within(urlparse(candidate).path, target)


def url_matches_any_scope(url: str, scopes, *, host_scope: bool = False) -> bool:
    """いずれかの scope に含まれるか（``url_in_scope`` の総当たり）。"""
    return any(url_in_scope(url, scope, host_scope=host_scope) for scope in (scopes or []))


def without_fragment(url: str) -> str:
    """fragment を除いた URL（サーバへ送られない成分を落として scope 再判定するため）。"""
    try:
        return urlsplit(url)._replace(fragment="").geturl()
    except ValueError:
        return url


def without_query(url: str) -> str:
    """query と fragment を除いた URL（path 限定 scope との突合に使う）。"""
    try:
        return urlsplit(url)._replace(query="", fragment="").geturl()
    except ValueError:
        return url


def is_route_fragment(fragment: str) -> bool:
    """fragment が SPA のクライアントルート（``#/admin`` / ``#!/x``）かを返す。

    単なるページ内アンカー（``#section``）は別ページではないので False。route らしい fragment を
    落とすと ``/app#/users`` と ``/app#/admin`` が同一 URL になり、2 つ目が「既知」として
    probe されなくなる。
    """
    frag = str(fragment or "")
    return bool(frag) and (frag[:1] in ("/", "!") or "/" in frag)


# --- redaction -------------------------------------------------------------

REDACTED = "<redacted>"

# 値をマスクするキーのトークン（部分一致）。URL query/fragment と urlencoded/JSON ボディで
# 共有する単一の正典。
SENSITIVE_KEY_TOKENS = (
    "password", "passwd", "pwd", "secret", "token", "api_key", "apikey",
    "apitoken", "access_token", "refresh_token", "client_secret",
    "sessionid", "session_id", "csrf", "xsrf", "authenticity_token",
)
KEYS_ALT = "|".join(re.escape(k) for k in SENSITIVE_KEY_TOKENS)
# urlencoded: <key>=<value>（key が機微トークンを含むとき value をマスク）
_RE_URLENCODED = re.compile(rf"(?i)([^&=?\s]*(?:{KEYS_ALT})[^&=]*)=[^&]*")
# JSON: "<key>": "<value>"
# 値は escape-aware（`\"` を含む JSON scalar 全体を伏せる。`"[^"]*"` だと `\"` で切れて末尾漏れ）
_RE_JSON = re.compile(rf'(?i)("(?:[^"\\]*(?:{KEYS_ALT})[^"\\]*)"\s*:\s*)"(?:\\.|[^"\\])*"')

_RE_URL_SCHEME = re.compile(r"(?i)^[a-z][a-z0-9+.\-]*://")


def redact_kv_values(text):
    """urlencoded / JSON の機微フィールド値をマスクする（URL query と body で共有）。"""
    if not isinstance(text, str) or not text:
        return text
    text = _RE_URLENCODED.sub(lambda m: f"{m.group(1)}={REDACTED}", text)
    text = _RE_JSON.sub(lambda m: f'{m.group(1)}"{REDACTED}"', text)
    return text


def is_sensitive_query_key(key: str) -> bool:
    """query キーが機微（値を伏せる対象）かを返す。"""
    low = str(key or "").lower()
    return any(token in low for token in SENSITIVE_KEY_TOKENS)


def redact_url(url, *, drop_userinfo: bool = False):
    """永続化用に URL の資格情報を伏せる（userinfo・機微 query/fragment 値）。

    OAuth implicit 等はトークンを **fragment**（``#access_token=...``）に載せ、``user:pass@host`` の
    **userinfo** も資格情報。checkpoint/レポート/監査ログへ残す前にどちらも伏せる。
    query の**順序・キー・非機微値・``;params``** は保持する（証跡として URL を再現できるように）。

    *drop_userinfo* が True なら userinfo を ``<redacted>@`` ではなく丸ごと除去する
    （Basic 認証 probe の URL を finding へ載せる scanner 向けの意図的な差）。
    """
    if not isinstance(url, str) or not url:
        return url
    result = url
    # userinfo: scheme://user:pass@host → 資格情報を伏せる
    m = _RE_URL_SCHEME.match(result)
    if m:
        after = result[m.end():]
        cut = [i for i in (after.find("/"), after.find("?"), after.find("#")) if i != -1]
        authority_end = min(cut) if cut else len(after)
        authority = after[:authority_end]
        if "@" in authority:
            host = authority.rpartition("@")[2]
            prefix = host if drop_userinfo else f"{REDACTED}@{host}"
            result = result[:m.end()] + prefix + after[authority_end:]
    # query（? 以降。# があれば分離してフラグメントも処理）
    if "?" in result:
        base, _, rest = result.partition("?")
        query, hsep, frag = rest.partition("#")
        result = f"{base}?{redact_kv_values(query)}"
        if hsep:
            result += f"#{redact_kv_values(frag)}"
    elif "#" in result:
        base, _, frag = result.partition("#")
        result = f"{base}#{redact_kv_values(frag)}"
    return result
