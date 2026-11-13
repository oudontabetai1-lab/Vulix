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


def same_page(current: str, target: str) -> bool:
    """flow 選択・着地先検証用の URL 同一ページ判定（純粋関数）。

    規則（checkpoint 用 ``url_normalize.normalize_url_for_key`` と**あえて別**）:
    - 通常の同一文書内アンカー（``#settings``）は無視して同一ページ扱い。
    - route 的 fragment（SPA の ``#/admin`` / ``#!/x``）は保持して区別。
    - path 末尾スラッシュは query も route fragment も無いときだけ吸収。query があれば
      ``/app/?x`` と ``/app?x`` を区別。
    - **query 値は厳密一致**を要求する（csrf/nonce 等のトークンを保持。checkpoint 正規化と別）。

    engine の flow マッチ／着地検証と flow 再生（flow_runner・flow_recorder）の via_click
    fallback 判定が共有する単一の正典。
    """

    def _norm(u: str):
        u = u or ""
        p = urlsplit(u)
        frag = p.fragment
        keep_frag = frag if is_route_fragment(frag) else ""
        path = p.path if (p.query or keep_frag) else p.path.rstrip("/")
        # 明示的な空クエリ ``?`` を保持する（``/confirm?`` と ``/confirm`` を区別）。urlsplit は
        # 両方 query="" で表すため、``?`` の有無を key に含める（url_normalize.py と整合）。
        had_query_delim = "?" in u.split("#", 1)[0]
        return (p.scheme, p.netloc, path, p.query, had_query_delim, keep_frag)

    try:
        return _norm(current) == _norm(target)
    except Exception:
        return False


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


# 設定済み資格情報の**値**そのもの（キー名に依らず伏せる）。値→label。プロセス全体で 1 スキャン分
# （serve は同時 1 スキャン前提。engine が scan 境界で clear→register する）。
MIN_SECRET_LEN = 4  # これ未満は証跡（"a" 等）を壊すため登録しない（skipped_secret_labels に記録）
_SECRET_VALUES: dict[str, str] = {}
skipped_secret_labels: list[str] = []


def clear_secret_values() -> None:
    _SECRET_VALUES.clear()
    skipped_secret_labels.clear()


def register_secret_values(items) -> None:
    """(label, value) を登録する。マーカーは ``[REDACTED:<label>]``。短すぎる値は登録せず記録する。

    YAML 等で型が付いた数値の資格情報も伏せるため int/float は文字列化して登録する。
    bool は ``"True"``/``"False"`` を伏せると証跡を壊すため登録しない。
    """
    for label, value in items:
        if isinstance(value, bool) or not isinstance(value, (str, int, float)):
            continue
        value = str(value)
        if not value:
            continue
        if len(value) < MIN_SECRET_LEN:
            skipped_secret_labels.append(label)
        else:
            _SECRET_VALUES[value] = label


def collect_configured_secret_values(
    auth_user=None,
    auth_pass=None,
    accounts=None,
    cookies="",
    low_priv_cookies="",
    cookie_list=None,
    low_priv_cookie_list=None,
    headers=None,
):
    """設定済み資格情報から redaction 登録用の値一覧と Cookie 名集合を作る（純粋関数）。

    ``ScanEngine`` と serve（``scan_started`` の配信前）が**同じ値集合**を登録するための
    単一の正典。文字列 Cookie / Cookie リスト / ヘッダ（``Cookie`` を含む）を横断して
    ``(label, value)`` と ``cookie_names`` を返す。登録・クリアのライフサイクルは呼出側が持つ。

    *headers* は呼出側で有効ヘッダ（Bearer 合成・文字列形式の解釈済み）を渡すこと。
    """
    items: list[tuple[str, object]] = [
        ("auth_user", auth_user),
        ("auth_password", auth_pass),
    ]
    for i, acct in enumerate(accounts or []):
        if isinstance(acct, dict):
            items += [
                (f"account{i}_user", acct.get("username")),
                (f"account{i}_password", acct.get("password")),
            ]
    cookie_names: set[str] = set()
    for label, raw in (("cookie", cookies), ("low_priv_cookie", low_priv_cookies)):
        for part in str(raw or "").split(";"):
            cookie_name, sep, value = part.partition("=")
            if sep and cookie_name.strip():
                cookie_names.add(cookie_name.strip())
                items.append((label, value.strip()))
    for cookie in [*(cookie_list or []), *(low_priv_cookie_list or [])]:
        if isinstance(cookie, dict):
            if isinstance(cookie.get("name"), str):
                cookie_names.add(cookie["name"])
            items.append(("cookie", cookie.get("value")))
    for name, value in (headers or {}).items():
        value = str(value or "")
        if str(name).lower() == "cookie":
            cookie_names.update(
                part.partition("=")[0].strip() for part in value.split(";") if "=" in part
            )
        # Authorization 等は "Bearer <token>" 形式なので値全体とトークン単体の両方を登録する。
        items += [(f"header:{name}", value), (f"header:{name}", value.rpartition(" ")[2])]
    return items, cookie_names


def redact_secret_values(text):
    """登録済みの資格情報値（生・URL エンコード・JSON エスケープ形）を固定マーカーへ置換する。"""
    if not isinstance(text, str) or not text or not _SECRET_VALUES:
        return text
    from urllib.parse import quote, quote_plus
    import html as _html, json as _json, shlex
    for value in sorted(_SECRET_VALUES, key=len, reverse=True):
        marker = f"[REDACTED:{_SECRET_VALUES[value]}]"
        for form in {value, quote(value, safe=""), quote_plus(value), _json.dumps(value)[1:-1],
                     _html.escape(value), _html.escape(value, quote=False), shlex.quote(value)[1:-1]
                     if shlex.quote(value).startswith("'") else shlex.quote(value)}:
            if form in text:
                text = text.replace(form, marker)
    return text


# label は保存時の run が決めるため、再開側の登録状態に依存せず形だけで判定する。
# token_lifecycle の ``[REDACTED:len=N]`` は別マーカーなので除く。
_RE_SECRET_MARKER = re.compile(r"\[REDACTED:(?!len=\d+\])[^\]]+\]")


def has_secret_marker(text) -> bool:
    """*text* に資格情報の伏せ字マーカー（``[REDACTED:<label>]``）が含まれるか（label 非依存）。"""
    return isinstance(text, str) and _RE_SECRET_MARKER.search(text) is not None


def redact_url_values(url):
    """URL の userinfo・query・fragment だけ登録済み値を伏せる。path（識別子）は変えない。"""
    if not isinstance(url, str) or not url or not _SECRET_VALUES:
        return url
    head, rest = "", url
    m = _RE_URL_SCHEME.match(url)
    if m:
        after = url[m.end():]
        cut = min((i for i in (after.find("/"), after.find("?"), after.find("#")) if i != -1),
                  default=len(after))
        userinfo, at, host = after[:cut].rpartition("@")
        head, rest = url[:m.end()] + redact_secret_values(userinfo) + at + host, after[cut:]
    cut = min((i for i in (rest.find("?"), rest.find("#")) if i != -1), default=len(rest))
    return head + rest[:cut] + redact_secret_values(rest[cut:])


# 証跡として永続化する finding のフィールド。これ以外（check_type/field_name/payload/injection_*/
# 各種 id 等の識別子）は値ベース置換の対象にしない（resume のキー一致・再検証を壊さないため）。
_EVIDENCE_FIELDS = ("request", "response", "evidence", "response_body_excerpt", "evidence_details",
                    "reproduction_steps", "verification_note", "dialog_message")


def redact_leaves(value, key=""):
    """文字列葉だけを置換した複製を返す（構造・キー・非文字列は不変）。``*url`` キーは URL 規則。"""
    if isinstance(value, dict):
        return {k: redact_leaves(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_leaves(v, key) for v in value]
    if isinstance(value, str):
        return redact_url_values(value) if key.lower().endswith("url") else redact_secret_values(value)
    return value


# ダッシュボードが識別子として engine へ返す/照合に使うキー。値は伏せない（伏せると返送時に引けない）。
_EVENT_IDENTIFIER_KEYS = frozenset(
    ("name", "field", "field_name", "type", "check_type", "method", "selector", "id"))


def _looks_like_url(text: str) -> bool:
    """値の形で URL を判定する（キー名に依らない）。空白の無い 1 トークンで、絶対 URL か ``/`` 始まり。

    空白を含む文（``http://x 認証失敗: admin`` 等）は URL 規則だと path/本文が残るため自由文として全文置換する。"""
    return len(text.split()) == 1 and (bool(_RE_URL_SCHEME.match(text)) or text.startswith("/"))


def redact_event_data(value, key=""):
    """ダッシュボードのライブイベント用。文字列葉だけ伏せた複製を返す（構造・キー・非文字列は不変）。

    - 値が URL の形（または ``*url`` キー）なら userinfo・query・fragment だけ伏せ、path は不変
      （サイトマップの親子・plan 編集の戻りなど URL を照合キーに使うため）。
    - 識別子キー（name/field/type/check_type/method/selector/id 等）の文字列は伏せない。
    - それ以外（status・メッセージ・request/response 断片・payload 等の自由文）は値ベースで全文置換。
    画像（``image`` / ``*_b64``）は走査せず素通し。資格情報が未登録なら元の値をそのまま返す。"""
    if not _SECRET_VALUES:
        return value
    low = str(key).lower()
    if low == "image" or low.endswith("b64"):
        return value
    if isinstance(value, dict):
        return {k: redact_event_data(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [redact_event_data(v, key) for v in value]
    if not isinstance(value, str) or low in _EVENT_IDENTIFIER_KEYS:
        return value
    if low.endswith("url") or _looks_like_url(value):
        return redact_url_values(value)
    return redact_secret_values(value)


def redact_url_fields(value, key=""):
    """``*url`` / ``*urls`` キーの URL だけ伏せた複製を返す（他の文字列・キー・構造は不変）。

    checkpoint/evidence の URL 系構造（reached_urls・scan_matrix・visited_urls 等）用。値ベースの
    全文置換と違い識別子を書き換えない。"""
    low = str(key).lower()
    if isinstance(value, dict):
        return {k: redact_url_fields(v, str(k)) for k, v in value.items()}
    if isinstance(value, (list, tuple, set)):
        return [redact_url_fields(v, key) for v in value]
    if isinstance(value, str) and (low.endswith("url") or low.endswith("urls")):
        return redact_url_values(value)
    return value


def redact_finding_dict(finding: dict) -> dict:
    """永続化用に finding dict の証跡フィールドの文字列葉と url のクエリ等だけ伏せた複製を返す。

    JSON 文字列へ直列化した後ではなく、dict に対して適用する（値が ``true`` 等でも JSON を壊さない）。"""
    if not isinstance(finding, dict) or not _SECRET_VALUES:
        return finding
    out = dict(finding)
    for name in _EVIDENCE_FIELDS:
        if name in out:
            out[name] = redact_leaves(out[name], name)
    if "url" in out:
        out["url"] = redact_url_values(out["url"])
    return out


def redact_kv_values(text):
    """urlencoded / JSON の機微フィールド値をマスクする（URL query と body で共有）。

    キー名ベースに加え、登録済みの資格情報値はキー名に依らず伏せる。"""
    if not isinstance(text, str) or not text:
        return text
    text = redact_secret_values(text)
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
    result = redact_secret_values(url)  # パス部の値も対象
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
