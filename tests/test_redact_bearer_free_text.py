"""自由テキスト中の Authorization / Bearer 等の認証情報の伏せ字化テスト。

通常層と Agent 層で共有している redact_text が、自由テキスト中の
Authorization ヘッダ行、JSON 値、認証スキーム（Bearer / Basic / Token 等）の
値を適切に伏せ、スキーム名とキー名を保持しつつ、非機密の普通文を伏せすぎない
ことを検証する。
"""
import pytest

from wscan.request_logger import redact_text, register_sensitive_headers, clear_sensitive_headers


@pytest.fixture(autouse=True)
def _clean_headers():
    clear_sensitive_headers()
    yield
    clear_sensitive_headers()


# --- 1. ヘッダ行形式のテスト ---

@pytest.mark.parametrize(
    "text,expected",
    [
        ("Authorization: Bearer secret-token-123", "Authorization: Bearer <redacted>"),
        ("authorization:bearer secret-token-123", "authorization:bearer <redacted>"),
        ("AUTHORIZATION: BEARER secret-token-123", "AUTHORIZATION: BEARER <redacted>"),
        ("Proxy-Authorization: Basic dXNlcjpwYXNz", "Proxy-Authorization: Basic <redacted>"),
        ("proxy-authorization: basic dXNlcjpwYXNz", "proxy-authorization: basic <redacted>"),
        ("Authorization: Token 9944b09199c62bcf", "Authorization: Token <redacted>"),
        ("Authentication: Bearer secret-token-123", "Authentication: Bearer <redacted>"),
        ("Authentication: Token gh_token_12345", "Authentication: Token <redacted>"),
        ("Authorization:Bearer secret-token-123", "Authorization:Bearer <redacted>"),
        ("Authorization : Bearer secret-token-123", "Authorization : Bearer <redacted>"),
        ("Authorization = Bearer secret-token-123", "Authorization = Bearer <redacted>"),
        ("Authorization:\tBearer\tsecret-token-123", "Authorization:\tBearer\t<redacted>"),
        ("Authorization: Bearer secret-token-123\r\nNext: val", "Authorization: Bearer <redacted>\r\nNext: val"),
        ("Authorization: Bearer secret-token-123\nNext: val", "Authorization: Bearer <redacted>\nNext: val"),
        ("Authorization: secret-no-scheme-value", "Authorization: <redacted>"),
        ("\"Authorization\": \"secret-no-scheme-value\"", "\"Authorization\": \"<redacted>\""),
        ("\"authorization\": \"secret-no-scheme-value\"", "\"authorization\": \"<redacted>\""),
        ("\"Proxy-Authorization\": \"secret-proxy-value\"", "\"Proxy-Authorization\": \"<redacted>\""),
        ("\"X-Api-Key\": \"my-secret-key-123\"", "\"X-Api-Key\": \"<redacted>\""),
        ("'Authorization': 'secret-no-scheme-value'", "'Authorization': '<redacted>'"),
        ("'X-Api-Key': 'secret-key-456'", "'X-Api-Key': '<redacted>'"),
        ("curl -H \"Authorization: Bearer secret-token-123\" https://api.example.com",
         "curl -H \"Authorization: Bearer <redacted>\" https://api.example.com"),
        ("curl -H 'Authorization: Bearer secret-token-123' https://api.example.com",
         "curl -H 'Authorization: Bearer <redacted>' https://api.example.com"),
        ("curl -H 'authorization:bearer secret-token-123' https://api.example.com",
         "curl -H 'authorization:bearer <redacted>' https://api.example.com"),
    ],
)
def test_header_line_redaction(text, expected):
    assert redact_text(text) == expected


# --- 2. JSON 値形式のテスト ---

@pytest.mark.parametrize(
    "text,expected",
    [
        ('{"Authorization": "Bearer eyJhbGciOi..."}', '{"Authorization": "Bearer <redacted>"}'),
        ('{"authorization":"bearer secret-token-123"}', '{"authorization":"bearer <redacted>"}'),
        ('{"token": "Bearer secret-token-123"}', '{"token": "Bearer <redacted>"}'),
        ('{"token": "bearer secret-token-123"}', '{"token": "bearer <redacted>"}'),
        ('{"access_token": "Bearer secret-token-123"}', '{"access_token": "Bearer <redacted>"}'),
        ('{"auth": "Bearer secret-token-123"}', '{"auth": "Bearer <redacted>"}'),
        ('{"custom_header": "Bearer secret-token-123"}', '{"custom_header": "Bearer <redacted>"}'),
        ('{"Authorization": "Basic dXNlcjpwYXNz"}', '{"Authorization": "Basic <redacted>"}'),
        ('{"Authorization": "Token 9944b09199c62bcf"}', '{"Authorization": "Token <redacted>"}'),
        ('{"token": "Basic dXNlcjpwYXNz"}', '{"token": "Basic <redacted>"}'),
        ('{"token": "Bearer secret-token-123", "limit": 10}',
         '{"token": "Bearer <redacted>", "limit": 10}'),
        ('{"Authorization": "secret-no-scheme-value"}', '{"Authorization": "<redacted>"}'),
        ('{"X-Api-Key": "my-secret-key-123"}', '{"X-Api-Key": "<redacted>"}'),
        ('{"Authorization": "secret-no-scheme-value", "page": 1}',
         '{"Authorization": "<redacted>", "page": 1}'),
        ("{'Authorization': 'Bearer secret-token-123'}", "{'Authorization': 'Bearer <redacted>'}"),
        ("{'token': 'Bearer secret-token-123'}", "{'token': 'Bearer <redacted>'}"),
    ],
)
def test_json_value_redaction(text, expected):
    assert redact_text(text) == expected


# --- 3. 自由テキスト中の単体 Bearer トークンのテスト ---

@pytest.mark.parametrize(
    "text,expected",
    [
        ("Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9", "Bearer <redacted>"),
        ("bearer secret-value-xyz", "bearer <redacted>"),
        ("BEARER tok-abcdef-12345", "BEARER <redacted>"),
        ("The server returned Bearer eyJhbGciOi... in the body.",
         "The server returned Bearer <redacted>... in the body."),
        ("Token was Bearer secret123;", "Token was Bearer <redacted>;"),
        ("Bearer x", "Bearer <redacted>"),
        ("Use the Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9 token.",
         "Use the Bearer <redacted> token."),
        ("Send a valid Bearer secret-token-12345", "Send a valid Bearer <redacted>"),
        ("the Bearer secret123", "the Bearer <redacted>"),
        ("valid Bearer dXNlcjpwYXNz", "valid Bearer <redacted>"),
        ("The server returned valid Bearer tok_9944b09199c62bcf in header.",
         "The server returned valid Bearer <redacted> in header."),
    ],
)
def test_raw_bearer_redaction(text, expected):
    assert redact_text(text) == expected


# --- 4. 非機密の普通文（伏せすぎてはならない例）のテスト ---

@pytest.mark.parametrize(
    "prose",
    [
        "He was the bearer of bad news.",
        "The bearer of this ticket gets a discount.",
        "The bearer shall present valid identification upon entry.",
        "Bearer bonds are financial instruments.",
        "A bearer token is used for authentication.",
        "Bearer authentication is standard in OAuth2.",
        "The passport bearer signed the document.",
        "The standard bearer led the ceremony.",
        "Basic knowledge of python is required.",
        "This is a basic tutorial.",
        "A token of appreciation was given.",
        "The token represents the user entity in the conceptual model.",
        "passport bearer confirmed identity.",
        "A valid bearer token is required.",
        "The bearer of bad news arrived.",
        "He is a rightful bearer of this heritage.",
        '"Content-Type": "application/json"',
        '"Accept": "text/html"',
        '"User-Agent": "Mozilla/5.0"',
    ],
)
def test_non_secret_prose_is_preserved(prose):
    assert redact_text(prose) == prose


# --- 5. 冪等性（繰り返し適用しても壊れない）のテスト ---

@pytest.mark.parametrize(
    "text",
    [
        "Authorization: Bearer secret123",
        "authorization:bearer secret123",
        "Authorization: Basic dXNlcjpwYXNz",
        "Authorization: Token secret123",
        '{"Authorization": "Bearer eyJhbGciOi..."}',
        '{"token": "Bearer secret123"}',
        "The server returned Bearer secret123;",
        "He was the bearer of bad news.",
        "curl -H 'Authorization: Bearer secret123' https://example.test",
    ],
)
def test_redact_text_idempotence(text):
    first = redact_text(text)
    second = redact_text(first)
    assert first == second


# --- 6. 既存のキー名・形による判定や攻撃ペイロードを壊さないこと ---

def test_custom_runtime_sensitive_header():
    register_sensitive_headers(["X-Company-Auth"])
    text = "X-Company-Auth: Bearer my-company-secret"
    assert redact_text(text) == "X-Company-Auth: Bearer <redacted>"


def test_attack_payload_and_ordinary_query_not_broken():
    # SQLi や XSS などの通常層ペイロードは壊さない
    sqli = "' OR '1'='1"
    xss = "<script>alert(1)</script>"
    ordinary_json = '{"q": "search words", "page": 2}'
    assert redact_text(sqli) == sqli
    assert redact_text(xss) == xss
    assert redact_text(ordinary_json) == ordinary_json


# --- 7. 性能回帰テスト（計算量・二乗走査防止の検証） ---

def test_header_line_auth_no_catastrophic_backtracking():
    """ヘッダ区切り文字に続く空白でバックトラック爆発が起きず、高速に完了すること。

    所有格数量子がない場合（修正前）は n=50000 で約 23 秒以上を要するが、
    修正後は数ミリ秒（0.5 秒以下、上限 2.0 秒）で完了する。
    """
    import time

    n = 50000
    start = time.perf_counter()
    res = redact_text("a:" + "\n" * n + "}")
    elapsed = time.perf_counter() - start

    assert res == "a:" + "\n" * n + "}"
    assert elapsed < 2.0, f"header line backtracking took too long: {elapsed:.2f}s"


def test_linear_performance_with_mass_bearer_tokens():
    """敵性サイトが数 MB で数千回の Bearer を含む応答を返しても、局所窓により高速に完了すること。

    全文走査のままの場合（修正前）は n=5000 で約 110 秒以上を要するが、
    64 文字の局所窓により 0.5 秒以下（上限 2.0 秒）で完了する。
    """
    import time

    chunk = ("payload_data " * 10) + "Bearer x_secret_token_12345 "
    n = 5000

    start = time.perf_counter()
    res = redact_text(chunk * n)
    elapsed = time.perf_counter() - start

    assert "x_secret_token_12345" not in res
    assert "Bearer <redacted>" in res
    assert elapsed < 2.0, f"mass bearer redaction took too long: {elapsed:.2f}s"


def test_urlencoded_no_catastrophic_scanning():
    """urlencoded のキー走査で二乗走査が発生せず、高速に完了すること。

    先頭境界条件や所有格数量子がない場合（修正前）は n=20000 で約 12〜16 秒以上を要するが、
    修正後は数ミリ秒（0.5 秒以下、上限 2.0 秒）で完了する。
    """
    import time
    from wscan.url_scope import redact_kv_values

    # 正しい伏せ字化が行われることの検証
    assert (
        redact_kv_values("user_password=secret&other=safe")
        == "user_password=<redacted>&other=safe"
    )

    n = 20000
    # ケース1: キー境界のない単一文字の繰り返し
    start = time.perf_counter()
    res = redact_kv_values("x" * n)
    elapsed = time.perf_counter() - start
    assert res == "x" * n
    assert elapsed < 2.0, f"urlencoded scanning (x) took too long: {elapsed:.2f}s"

    # ケース2: 機微キー語の連続（区切りなし）
    start = time.perf_counter()
    res_token = redact_kv_values("token" * n)
    elapsed_token = time.perf_counter() - start
    assert res_token == "token" * n
    assert elapsed_token < 2.0, f"urlencoded scanning (token) took too long: {elapsed_token:.2f}s"


def test_url_userinfo_no_catastrophic_scanning():
    """URL の userinfo 走査で二乗走査が発生せず、高速に完了すること。

    先頭境界条件や所有格数量子がない場合（修正前）は n=50000 で約 18 秒以上を要するが、
    修正後は数ミリ秒（0.5 秒以下、上限 2.0 秒）で完了する。
    """
    import time

    # 正しい伏せ字化が行われることの検証
    assert (
        redact_text("http://user:pass@example.com/api")
        == "http://<redacted>@example.com/api"
    )

    n = 50000
    start = time.perf_counter()
    res = redact_text("x" * n)
    elapsed = time.perf_counter() - start

    assert res == "x" * n
    assert elapsed < 2.0, f"url userinfo scanning took too long: {elapsed:.2f}s"
