"""
ログイン成否判定（純粋関数）。

``browser.auto_login`` の成功判定は元々「URL が変わった or ログインページの
パスから外れた」だけで成功としていたため、``/login?error=1`` のような
「ログインページに留まったままの失敗」を成功と誤判定し得た。

本モジュールは判定ロジックを I/O から切り離した純粋関数として提供する:
- ``on_login_page``     … 現在 URL がログインページか（パス一致 + 既知パスの推定）。
- ``has_failure_text``  … 失敗メッセージが本文にあるか（大小文字無視・広めの語彙）。
- ``has_login_form``    … ログインフォーム（パスワード欄＋ユーザ欄/送信/フォーム）が残るか。
- ``login_succeeded``   … 上記を統合した最終判定。

判定方針: 「ログインページから抜け、ログインフォームが残っておらず、失敗文言も
MFA も無い」場合に成功とみなす。URL が変わっただけでは成功と認めない（厳格化）。
"""
from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Iterable, Mapping, Optional
from urllib.parse import urlparse


# 失敗メッセージ（大小文字無視で部分一致）。元実装より語彙を増やした。
_FAILURE_MARKERS = (
    "invalid login",
    "login failed",
    "incorrect password",
    "invalid password",
    "wrong password",
    "incorrect username",
    "invalid username",
    "invalid credentials",
    "incorrect credentials",
    "authentication failed",
    "auth failed",
    "login unsuccessful",
    "could not log",
    "couldn't log",
    "アカウントまたはパスワード",
    "パスワードが正しく",
    "ログインに失敗",
    "認証に失敗",
    "ユーザー名またはパスワード",
)

# 既知のログインパス断片（login_url 未指定時の推定に使う）。
_LOGIN_PATH_HINTS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/account/login",
    "/users/sign_in",
    "/session/new",
)

_PASSWORD_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]?password['\"]?", re.IGNORECASE
)
# ログイン特有のユーザ名/メール欄（name/id に user/email/login 等を含む）。
_USERNAME_INPUT_RE = re.compile(
    r"<input\b[^>]*\b(?:name|id)\s*=\s*['\"]?[^'\">]*"
    r"(?:user|email|login|account|mail)[^'\">]*['\"]?",
    re.IGNORECASE,
)
# type=email の入力欄（名前が user 等でなくてもログイン欄とみなす）。
_EMAIL_INPUT_RE = re.compile(
    r"<input\b[^>]*\btype\s*=\s*['\"]?email['\"]?", re.IGNORECASE
)


def _norm(url: str) -> str:
    return (url or "").rstrip("/").lower()


_LOGIN_URL_KEYWORDS = ("/login", "/signin", "/sign-in", "/auth/login", "/account/login")
# クエリルータの param 名（値がルートを表す）。redirect 系（next/redirect/return/url/...）は
# 含めない＝redirect 値を login と誤判定しないため。
# 検索用 param（q/query/search 等）はルータでないため含めない（/search?q=/login を誤判定しない）。
_ROUTE_PARAM_NAMES = ("route", "page", "action", "controller", "module", "mod", "do", "view", "option")


def _path_has_login_hint(path: str) -> bool:
    """パス成分が login ルート様か（``/login`` 完全一致 or ``/account/login`` 等の末尾一致）。"""
    path = (path or "").rstrip("/")
    if not path:
        return False
    for kw in _LOGIN_URL_KEYWORDS:
        if path == kw or path.endswith(kw):
            return True
    return False


def url_looks_like_login(url: str) -> bool:
    """URL の**ルート成分**（path＋SPA hash ルート fragment）が login ページ様か（純粋）。

    ``on_login_page`` は path だけを見るため SPA の hash ルート（例 ``/#/login``）を拾えない。
    一方で URL 全体の部分文字列一致にすると、``/dashboard?next=/login`` のような**クエリ値**に
    login パスを含む無関係ページまで login と誤判定し、本物の失効（→/login redirect）検知を
    抑止してしまう。そこで path と hash ルート fragment のみに heuristic を適用し、任意の
    クエリ値には適用しない。browser.is_on_login_page の空 login_url 分岐と本関数を共有して
    「login ページか」と「login ページへの意図的訪問か」の判定を対称化する。
    """
    from urllib.parse import urlparse
    parsed = urlparse((url or "").lower())
    if _path_has_login_hint(parsed.path):
        return True
    frag = parsed.fragment
    # SPA の hash ルータ形式（``#/login`` / ``#!/login``）だけをルートとして扱う。
    # 通常のドキュメントアンカー（``#examples/login`` 等）はルートでないので除外する。
    if frag.startswith("!/"):
        frag = frag[1:]
    if frag.startswith("/"):
        frag_path = frag.split("?", 1)[0]
        if _path_has_login_hint(frag_path):
            return True
    # クエリ param（``?route=…`` / ``?page=…`` 等）は**アプリのルータ仕様を知らないと曖昧**で、
    # どの param 名も content になりうる（next/q/page 等で false positive が続いた）。
    # そこで **login_url 未設定の heuristic では query を判定に使わない**（曖昧さを閉じる）。
    # クエリ符号化された login ルート（例 ``/index.php?route=account/login``）は、login_url を
    # 明示設定した場合に _is_login_target_url の完全一致分岐（query param を厳密照合）で扱う。
    return False


def on_login_page(current_url: str, login_url: str) -> bool:
    """現在 URL がログインページに見えるか。``browser.is_on_login_page`` の純粋版。"""
    current = _norm(current_url)
    if not current:
        return False
    if login_url:
        login = _norm(login_url)
        if current == login:
            return True
        cur_parsed = urlparse(current)
        login_parsed = urlparse(login)
        # パス一致は同一ホストのときだけ適用する。SSO/IdP のログインで別ホスト
        # の同一パスへ遷移した場合（auth.example.com/ -> app.example.com/）を
        # 「まだログインページ」と誤判定して未認証スキャンに落とさない。
        #
        # NOTE: login_url がルート（空パス）の構成では、ここで空パスを "/" に
        # 正規化して比較してはいけない。そうすると同一ホストのルート系 SPA 成功
        # 遷移（"/?view=dashboard" や "/#/dashboard" 等）まで「ログインページ」と
        # 誤判定し、success_indicator 未指定の auth_login がタイムアウトまで失敗扱い
        # になる（偽陰性）。ルートログインに留まる失敗は has_login_form /
        # has_failure_text 側で拾えるため、ここでは login パスが空なら判定しない。
        if cur_parsed.netloc == login_parsed.netloc and login_parsed.path:
            if cur_parsed.path == login_parsed.path:
                return True
        return False
    cur_path = urlparse(current).path
    for hint in _LOGIN_PATH_HINTS:
        if cur_path == hint or cur_path.endswith(hint):
            return True
    return False


def has_failure_text(body: str) -> bool:
    """本文にログイン失敗を示す語句が含まれるか（大小文字無視）。"""
    if not body:
        return False
    low = body.lower()
    return any(marker in low for marker in _FAILURE_MARKERS)


def has_login_form(body: str) -> bool:
    """本文にログインフォームが残っているか。

    パスワード入力欄に加え、**ログイン特有のユーザ名/メール欄**（name/id に
    user・email・login 等を含む、または type=email）が共存する時にのみ
    「ログインフォーム」とみなす。送信ボタンや ``<form>`` だけでは判定しない
    （パスワード変更/アカウント設定など、ログイン後にパスワード欄を持つ正規
    ページを失敗と誤判定しないため）。
    """
    if not body:
        return False
    if not _PASSWORD_INPUT_RE.search(body):
        return False
    return bool(
        _USERNAME_INPUT_RE.search(body) or _EMAIL_INPUT_RE.search(body)
    )


def login_succeeded(
    *,
    post_url: str,
    login_url: str,
    body: str,
    mfa_present: bool = False,
    success_indicator: str = "",
    auth_cookie_present: bool | None = None,
) -> bool:
    """ログイン後の状態から成功したかを判定する。

    - ``success_indicator`` 指定時は、URL か本文に含まれ、かつ失敗文言が無い時に成功。
    - 未指定時は「失敗文言なし・MFA 未提示・ログインページから離脱・ログイン
      フォーム非残存」を全て満たす時にのみ成功とする。
    - ``auth_cookie_present`` が明示的に ``False`` の場合は成功を否定する
      （URL は遷移したが認証 Cookie が無い＝未認証の疑い）。判定材料が無ければ
      ``None`` を渡せば無視される。
    """
    failed = has_failure_text(body)
    # 失敗文言や未解決の MFA がある間は、success_indicator 指定でも成功としない。
    # OTP 送信直後に MFA 画面（URL/本文に成功語を含む）へ留まったケースを成功と
    # 誤認して未認証のままスキャンを進めるのを防ぐ。
    if failed or mfa_present:
        return False
    # 認証 Cookie が「明示的に無い」と分かっている場合は、success_indicator が
    # 本文/URL に出ていても成功と認めない（docstring の契約）。success_indicator
    # は別ページにも現れ得るため、Cookie 不在の方を優先する。
    if auth_cookie_present is False:
        return False
    if success_indicator:
        hit = success_indicator in (post_url or "") or success_indicator in (body or "")
        return bool(hit)

    if on_login_page(post_url, login_url):
        return False
    if has_login_form(body):
        return False
    return True


AGENT_AUTH_VERIFIED = "verified"
AGENT_AUTH_UNVERIFIED = "unverified_auth_claim"
AGENT_AUTH_COVERAGE_GAP = "auth:login_not_verified"


@dataclass
class AgentAuthVerification:
    status: str
    reasons: list[str] = field(default_factory=list)
    cookie_or_token_gained: bool = False
    left_login_page: bool = False
    login_form_absent: bool = False
    coverage_gap: str = ""

    @property
    def is_verified(self) -> bool:
        return self.status == AGENT_AUTH_VERIFIED

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "reasons": list(self.reasons),
            "cookie_or_token_gained": self.cookie_or_token_gained,
            "left_login_page": self.left_login_page,
            "login_form_absent": self.login_form_absent,
            "coverage_gap": self.coverage_gap,
            "is_verified": self.is_verified,
        }


def _detect_token_diff(
    before_tokens: Optional[Iterable[Mapping[str, Any]]] = None,
    after_tokens: Optional[Iterable[Mapping[str, Any]]] = None,
) -> bool:
    """localStorage/sessionStorage トークンの新規獲得または変更を検出する（純粋関数）。

    事前スナップショットが存在しない（None）場合は推測せず未獲得（False）として扱い、
    前後で新規追加または値が変更されたエントリのみを獲得と判定する。
    """
    if before_tokens is None or not after_tokens:
        return False

    def _normalize(items: Iterable[Mapping[str, Any]]) -> dict[tuple[str, str], str]:
        normalized = {}
        for item in items:
            if not isinstance(item, Mapping):
                continue
            storage = str(item.get("storage") or "local").strip().lower()
            key = str(item.get("key") or item.get("name") or "").strip()
            val = str(item.get("value") or "")
            if key and val:
                normalized[(storage, key)] = val
        return normalized

    before_map = _normalize(before_tokens)
    after_map = _normalize(after_tokens)

    # 新規または変更されたストレージ項目が存在するか
    for key_tuple, val in after_map.items():
        if key_tuple not in before_map:
            return True
        if before_map[key_tuple] != val:
            return True

    return False


def verify_agent_auth_claim(
    *,
    claimed_success: bool = True,
    before_cookies: Optional[Iterable[Mapping[str, Any]]] = None,
    after_cookies: Optional[Iterable[Mapping[str, Any]]] = None,
    before_tokens: Optional[Iterable[Mapping[str, Any]]] = None,
    after_tokens: Optional[Iterable[Mapping[str, Any]]] = None,
    has_cookie_diff: Optional[bool] = None,
    has_token_diff: Optional[bool] = None,
    current_url: str = "",
    login_url: str = "",
    body: str = "",
    left_login_page: Optional[bool] = None,
    login_form_present: Optional[bool] = None,
) -> AgentAuthVerification:
    """Agent の認証完了主張（AUTH COMPLETE 等）を決定論的シグナルで検証する（純粋関数）。

    LLM の自己申告のみを信頼せず、以下の独立した3つのグラウンドトゥルースを検証する:
    1. セッション成果物の獲得: ログイン前後に新規/変更 Cookie または トークンが獲得されたか
       （login_surface.detect_cookie_diff / _detect_token_diff）
    2. ログインページ離脱: 現在 URL がログインページから遷移したか（auth_detect.on_login_page）
    3. ログインフォーム非残存: ログインフォームおよび失敗文言が本文に残っていないか
       （auth_detect.has_login_form / has_failure_text）

    全て満たせば "verified"、1つでも欠ければ "unverified_auth_claim"（カバレッジ注記
    "auth:login_not_verified"）を返す。Agent の Finding やその severity は変更しない。
    """
    reasons = []

    if not claimed_success:
        return AgentAuthVerification(
            status=AGENT_AUTH_UNVERIFIED,
            reasons=["auth_not_claimed"],
            coverage_gap=AGENT_AUTH_COVERAGE_GAP,
        )

    # 1. Cookie / Token 差分
    if has_cookie_diff is None:
        if after_cookies is not None:
            from wscan.login_surface import detect_cookie_diff
            has_cookie_diff = detect_cookie_diff(before_cookies, after_cookies, target_url=login_url)
        else:
            has_cookie_diff = False

    if has_token_diff is None:
        if after_tokens is not None:
            has_token_diff = _detect_token_diff(before_tokens, after_tokens)
        else:
            has_token_diff = False

    cookie_or_token_gained = bool(has_cookie_diff or has_token_diff)
    if not cookie_or_token_gained:
        reasons.append("missing_session_artifact")

    # 2. ログインページ離脱
    if left_login_page is None:
        if current_url:
            norm_cur = _norm(current_url)
            norm_login = _norm(login_url) if login_url else ""
            left_login_page = (
                not on_login_page(current_url, login_url)
                and (norm_cur != norm_login if norm_login else True)
            )
        else:
            left_login_page = False
    if not left_login_page:
        reasons.append("still_on_login_page")

    # 3. ログインフォーム非残存 & 失敗文言非存在
    if login_form_present is None:
        form_present = has_login_form(body) if body else False
        failure_detected = has_failure_text(body) if body else False
        login_form_absent = (not form_present) and (not failure_detected)
        if form_present:
            reasons.append("login_form_still_present")
        if failure_detected:
            reasons.append("auth_failure_text_detected")
    else:
        login_form_absent = not login_form_present
        if login_form_present:
            reasons.append("login_form_still_present")

    if cookie_or_token_gained and left_login_page and login_form_absent:
        return AgentAuthVerification(
            status=AGENT_AUTH_VERIFIED,
            reasons=[],
            cookie_or_token_gained=True,
            left_login_page=True,
            login_form_absent=True,
            coverage_gap="",
        )
    else:
        return AgentAuthVerification(
            status=AGENT_AUTH_UNVERIFIED,
            reasons=reasons,
            cookie_or_token_gained=cookie_or_token_gained,
            left_login_page=left_login_page,
            login_form_absent=login_form_absent,
            coverage_gap=AGENT_AUTH_COVERAGE_GAP,
        )

