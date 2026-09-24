"""url_scope（URL/origin/scope 判定の正典ヘルパー）の表形式テスト。"""
from __future__ import annotations

import pytest

from wscan import url_scope


# --- IDNA / origin ---------------------------------------------------------

@pytest.mark.parametrize(
    "host,expected",
    [
        ("例え.jp", "xn--r8jz45g.jp"),            # Unicode → Punycode
        ("xn--r8jz45g.jp", "xn--r8jz45g.jp"),      # Punycode は冪等
        ("APP.TEST", "app.test"),                  # 大小は畳む
        ("sub.例え.jp", "sub.xn--r8jz45g.jp"),     # ラベル単位で変換
        ("127.0.0.1", "127.0.0.1"),
        ("::1", "::1"),
        ("", ""),
        ("host..test", "host..test"),              # 変換不能でも例外にせず小文字表現
        ("\udcff.test", "\udcff.test"),            # 壊れたサロゲートも例外にしない
    ],
)
def test_idna_host(host, expected):
    assert url_scope.idna_host(host) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("https://app.test/x", ("https", "app.test", 443)),   # 既定ポート補完
        ("https://app.test:443/x", ("https", "app.test", 443)),
        ("http://app.test/x", ("http", "app.test", 80)),
        ("http://app.test:80/x", ("http", "app.test", 80)),
        ("http://app.test:8080/x", ("http", "app.test", 8080)),
        ("HTTPS://APP.Test/x", ("https", "app.test", 443)),
        ("https://例え.jp/x", ("https", "xn--r8jz45g.jp", 443)),
        ("ftp://app.test/x", ("ftp", "app.test", None)),      # 既定ポート未定義は None
        ("http://app.test:99999/x", ("", "", None)),          # ポート範囲外は安全側
        ("not a url", ("", "", None)),
        ("", ("", "", None)),
    ],
)
def test_origin_tuple(url, expected):
    assert url_scope.origin_tuple(url) == expected


@pytest.mark.parametrize(
    "a,b,expected",
    [
        ("https://app.test/a?b=1", "https://app.test/c", True),
        ("https://app.test/x", "https://app.test:443/y", True),   # 既定ポート補完
        ("http://app.test:80/x", "http://app.test/y", True),
        ("https://xn--r8jz45g.jp/a", "https://例え.jp/", True),    # IDN 相互
        ("http://app.test/x", "https://app.test/y", False),        # scheme 差
        ("https://app.test:8443/x", "https://app.test/y", False),  # 明示ポート差
        ("https://app.test/x", "https://evil.test/x", False),
        ("https://xn--r8jz45g.jp/a", "https://例.jp/", False),
        ("", "https://app.test", False),
        ("not a url", "https://app.test", False),
        ("/relative", "/relative", False),                          # scheme/host 無しは常に False
    ],
)
def test_same_origin(a, b, expected):
    assert url_scope.same_origin(a, b) is expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("HTTPS://APP.Example:443/path", "https://app.example"),
        ("http://app.test:80/", "http://app.test"),
        ("http://app.test:8080/", "http://app.test:8080"),
        ("https://例え.test/path", "https://xn--r8jz45g.test"),
        ("HTTPS://[2001:DB8::1]:443/path", "https://[2001:db8::1]"),
        ("http://[::1]:8080/a", "http://[::1]:8080"),
        ("/relative/path", ""),
        ("", ""),
    ],
)
def test_origin_string(url, expected):
    assert url_scope.origin_string(url) == expected


def test_origin_string_agrees_with_same_origin():
    # 文字列表現と tuple 比較が食い違わないこと（両者は同じ正規化規則）。
    pairs = [("https://例え.jp/a", "https://xn--r8jz45g.jp:443/b"),
             ("http://h:80/x", "http://h/y")]
    for a, b in pairs:
        assert url_scope.origin_string(a) == url_scope.origin_string(b)
        assert url_scope.same_origin(a, b)


# --- host / path 境界 ------------------------------------------------------

@pytest.mark.parametrize(
    "host,domain,allow_sub,expected",
    [
        ("example.test", "example.test", True, True),
        ("app.example.test", ".example.test", True, True),
        ("app.example.test", "example.test", False, False),   # host-only cookie
        ("example.test", "example.test", False, True),
        ("example.test", "sso.evil.test", True, False),
        ("notexample.test", "example.test", True, False),     # 境界はドット
        ("例え.jp", "xn--r8jz45g.jp", True, True),             # IDN 相互
        ("", "example.test", True, False),
        ("example.test", "", True, False),
    ],
)
def test_host_matches(host, domain, allow_sub, expected):
    assert url_scope.host_matches(host, domain, allow_subdomain=allow_sub) is expected


@pytest.mark.parametrize(
    "path,scope,expected",
    [
        ("/admin", "/admin", True),
        ("/admin/x", "/admin", True),
        ("/administrator", "/admin", False),   # 境界が / でない
        ("/api/users", "/", True),
        ("/api/users", "/admin", False),
        ("/admin/x", "/admin/", True),
        ("", "/", True),                        # 空は / 扱い
    ],
)
def test_path_within(path, scope, expected):
    assert url_scope.path_within(path, scope) is expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://h/dav;jsessionid=1", "/dav;jsessionid=1"),   # ;params を保持
        ("http://h/dav;jsessionid=1?q=1", "/dav;jsessionid=1"),
        ("http://h/a;p/b", "/a;p/b"),                          # 途中の ; は path の一部
        ("http://h/a;p/b;q", "/a;p/b;q"),
        ("http://h/admin?q=1", "/admin"),
        ("http://h", "/"),
        ("", "/"),
    ],
)
def test_request_path_keeps_params(url, expected):
    assert url_scope.request_path(url) == expected


# --- scope 包含 ------------------------------------------------------------

@pytest.mark.parametrize(
    "url,scope,expected",
    [
        # full URL scope: 境界は /
        ("http://app.test/app/sub", "http://app.test/app", True),
        ("http://app.test/app/", "http://app.test/app", True),
        ("http://app.test/app", "http://app.test/app/", True),      # 両辺の末尾 / を吸収
        ("http://app.test/application", "http://app.test/app", False),
        ("https://app.test/app", "http://app.test/app", False),      # scheme 差
        # query 付き scope は query ごと厳密一致
        ("http://app.test/action?op=save", "http://app.test/action?op=save", True),
        ("http://app.test/action?op=drop", "http://app.test/action?op=save", False),
        # query 順序は別 operation になりうるので同一視しない
        ("http://app.test/a?x=1&y=2", "http://app.test/a?y=2&x=1", False),
        # full URL scope は文字列前方一致なので ;params 付きは含まれない（境界が / でない）。
        ("http://app.test/dav;jsessionid=1", "http://app.test/dav", False),
        # パス系 scope
        ("http://any.test/admin/x", "/admin", True),
        ("http://any.test/administrator", "/admin", False),
        ("http://any.test/dav;jsessionid=1", "/dav", True),          # ;params は境界扱い
        # 空 scope は常に False
        ("http://app.test/x", "", False),
        ("http://app.test/x", "   ", False),
    ],
)
def test_url_in_scope(url, scope, expected):
    assert url_scope.url_in_scope(url, scope) is expected


@pytest.mark.parametrize(
    "url,scope,host_scope,expected",
    [
        # ホスト系 scope は host_scope=True のときだけホストとして解釈する。
        ("https://auth.example.com/login", "auth.example.com", True, True),
        ("https://sso.auth.example.com/x", "auth.example.com", True, True),
        ("https://evil.com/x", "auth.example.com", True, False),
        ("https://例え.jp/x", "xn--r8jz45g.jp", True, True),
        # host_scope=False（engine 既定）ではパスとして扱うので一致しない。
        ("https://auth.example.com/login", "auth.example.com", False, False),
    ],
)
def test_url_in_scope_host_form(url, scope, host_scope, expected):
    assert url_scope.url_in_scope(url, scope, host_scope=host_scope) is expected


@pytest.mark.parametrize(
    "scopes,expected",
    [
        ([], False),
        (None, False),
        (["http://other.test"], False),
        (["http://other.test", "http://app.test"], True),
        (["", None, "http://app.test/x"], True),
    ],
)
def test_url_matches_any_scope(scopes, expected):
    assert url_scope.url_matches_any_scope("http://app.test/x/y", scopes) is expected


@pytest.mark.parametrize(
    "url,no_frag,no_query",
    [
        ("http://h/a?q=1#f", "http://h/a?q=1", "http://h/a"),
        ("http://h/a;p?q=1#f", "http://h/a;p?q=1", "http://h/a;p"),   # ;params 保持
        ("http://h/a", "http://h/a", "http://h/a"),
        ("http://h/a#/route", "http://h/a", "http://h/a"),
    ],
)
def test_strippers_keep_params(url, no_frag, no_query):
    assert url_scope.without_fragment(url) == no_frag
    assert url_scope.without_query(url) == no_query


@pytest.mark.parametrize(
    "fragment,expected",
    [
        ("/admin", True),
        ("!/x", True),
        ("a/b", True),
        ("section", False),
        ("", False),
        (None, False),
    ],
)
def test_is_route_fragment(fragment, expected):
    assert url_scope.is_route_fragment(fragment) is expected


# --- redaction -------------------------------------------------------------

@pytest.mark.parametrize(
    "url,expected",
    [
        # userinfo
        ("http://alice:secret@app.test/x", "http://<redacted>@app.test/x"),
        ("http://alice@app.test/x", "http://<redacted>@app.test/x"),
        ("https://app.test/x", "https://app.test/x"),
        ("http://u:p@app.test:8080/x?a=1", "http://<redacted>@app.test:8080/x?a=1"),
        # 機微 query 値
        ("http://h/p?access_token=abc&q=1", "http://h/p?access_token=<redacted>&q=1"),
        ("http://h/p?route=dav", "http://h/p?route=dav"),
        ("http://h/p?PASSWORD=x", "http://h/p?PASSWORD=<redacted>"),   # 大小無視
        # fragment（OAuth implicit）。キー名は証跡として残し値だけ伏せる。
        ("http://h/#access_token=z", "http://h/#access_token=<redacted>"),
        ("http://h/x?a=1#refresh_token=z", "http://h/x?a=1#refresh_token=<redacted>"),
        # 非機微は保持（順序・キー・;params も保つ）
        ("http://h/a;jsessionid=1?b=2&a=1", "http://h/a;jsessionid=1?b=2&a=1"),
        ("", ""),
    ],
)
def test_redact_url(url, expected):
    assert url_scope.redact_url(url) == expected


@pytest.mark.parametrize(
    "url,expected",
    [
        ("http://alice:secret@app.test/x", "http://app.test/x"),
        ("https://app.test/x", "https://app.test/x"),
        ("http://u:p@h/p?access_token=abc", "http://h/p?access_token=<redacted>"),
    ],
)
def test_redact_url_drop_userinfo(url, expected):
    # scanners/http_methods は証跡 URL を再実行可能に保つため userinfo を丸ごと落とす。
    assert url_scope.redact_url(url, drop_userinfo=True) == expected


def test_redact_url_keeps_query_order_and_non_string():
    # query の順序・キー名は証跡として保持し、非文字列はそのまま返す。
    url = "http://h/p?z=1&token=s&a=2"
    assert url_scope.redact_url(url) == "http://h/p?z=1&token=<redacted>&a=2"
    assert url_scope.redact_url(None) is None


@pytest.mark.parametrize(
    "text,expected",
    [
        ("a=1&password=hunter2", "a=1&password=<redacted>"),
        ('{"api_key": "abc"}', '{"api_key": "<redacted>"}'),
        (r'{"secret": "a\"b"}', '{"secret": "<redacted>"}'),   # escape-aware
        ("a=1&b=2", "a=1&b=2"),
        ("", ""),
    ],
)
def test_redact_kv_values(text, expected):
    assert url_scope.redact_kv_values(text) == expected


@pytest.mark.parametrize(
    "key,expected",
    [
        ("access_token", True),
        ("X-CSRF", True),
        ("SessionId", True),
        ("page", False),
        ("", False),
    ],
)
def test_is_sensitive_query_key(key, expected):
    assert url_scope.is_sensitive_query_key(key) is expected


# --- 既存呼び出し側との整合 -------------------------------------------------

def test_callers_delegate_to_canonical_helper():
    """重複していた各モジュールの判定が正典と同じ結果になること。"""
    from wscan import manual_crawl, request_logger
    from wscan.engine import _cookie_path_matches, _idna_host
    from wscan.header_scope import _url_origin
    from wscan.scanners import http_methods

    assert manual_crawl._same_origin("https://例え.jp/a", "https://xn--r8jz45g.jp:443/b")
    assert manual_crawl._origin_tuple("http://h:80/x") == url_scope.origin_tuple("http://h:80/x")
    assert _idna_host("例え.jp") == url_scope.idna_host("例え.jp")
    assert _cookie_path_matches("/admin/x", "/admin") is True
    assert _cookie_path_matches("/administrator", "/admin") is False
    assert _url_origin("https://例え.test/path") == url_scope.origin_string("https://例え.test/path")
    url = "http://u:p@h/x?access_token=s"
    assert request_logger.redact_url(url) == url_scope.redact_url(url)
    assert http_methods.redact_url(url) == url_scope.redact_url(url, drop_userinfo=True)
