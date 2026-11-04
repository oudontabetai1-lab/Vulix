"""Anti-CSRF / Nonce トークン・ライフサイクル契約モジュール（純粋モジュール）。

本モジュールは、CSRF トークンやワンタイム nonce などのセキュリティトークンを扱うための
型付き契約（dataclass / Enum）および純粋関数群を提供する。

【設計原則と不変条件】
1. 純粋性と無副作用:
   ネットワーク I/O やブラウザ操作、スキャナ実装への依存を持たない純粋関数・純粋型のみで構成。
2. 生シークレットの秘匿（Redaction）:
   トークンの生値（raw secret）はデフォルトのシリアライズ（asdict, json, repr, evidence）に
   一切含めない。不可逆な参照識別子（token_ref_id）とマスク値（redacted_value）、出自情報
   （provenance）のみを外部公開する。
3. 脆弱性・安全判定の誤認防止:
   トークン更新に失敗したプローブ結果は、決して脆弱性確定（confirmed）や安全（negative）に
   倒してはならない。必ず BLOCKED または INCONCLUSIVE として分類する。
4. 宣言 != 実行保証（Declaration != Runtime Execution Coverage）:
   capability matrix は各キャリアおよびトランスポートが静的に宣言する対応能力であり、
   動的な実行カバレッジやテスト合格を保証するものではない。
5. HTTP ステータスコードのヒント扱い:
   HTTP 403 / 419 / 422 などのステータスコード単体では STALE と断定せず、レスポンス本文や
   ヘッダの明示的シグナルがない限り INCONCLUSIVE とする。

【統合状況】
opt-in フラグの下で、HTTPX の form / JSON・XML・header、Playwright の form と FlowRunner、
SPA API の JSON・header は token manager に接続済み。HAR replay、Agent、Hybrid、multipart、
cookie は未接続（宣言上の能力と実行時の接続は別）。
flow_runner.py のページ全体 DOM 抽出と base.py の browser manager 経路、および
mail_header.py のフォーム範囲・リクエストごとの抽出は意図して分離する。selector、key の大文字小文字、
テスト済みフィールドの除外、抽出範囲の意味が異なり、統合すると検出結果が変わる。
"""
from __future__ import annotations

import hashlib
from html.parser import HTMLParser
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Mapping, Protocol, Sequence


# ── 1. 定数および免責事項 ────────────────────────────────────────────────

TOKEN_LIFECYCLE_DISCLAIMER: str = (
    "Declared token lifecycle capability matrix. "
    "Represents declared static carrier/transport support contracts only; "
    "explicitly does NOT claim runtime execution coverage, dynamic verification, "
    "or automatic refresh success in active scan sessions."
)

SCHEMA_VERSION: str = "1.0.0"
CONTRACT_KIND: str = "token_lifecycle_contract"




# ── 2. 列挙型（Enums） ────────────────────────────────────────────────────

class TokenSourceType(str, Enum):
    """トークン取得元の種別。"""
    FORM_FIELD = "form_field"      # HTML form hidden/input フィールド
    HEADER = "header"              # HTTP リクエスト/レスポンスヘッダ
    COOKIE = "cookie"              # Cookie ヘッダ
    JSON_PATH = "json_path"        # JSON ペイロード内のプロパティパス
    GRAPHQL = "graphql"            # GraphQL 変数またはヘッダ
    MULTIPART = "multipart"        # multipart/form-data のパート
    META_TAG = "meta_tag"          # HTML <meta name="csrf-token" content="...">
    URL_QUERY = "query"            # URL クエリパラメータ
    CUSTOM = "custom"              # 独自取得方式


class ConsumptionCondition(str, Enum):
    """トークンの消費・失効条件。"""
    ONE_TIME = "one-time"          # 1回消費で失効（nonce）
    ROTATING = "rotating"          # 一定間隔・リクエスト毎にローテーション
    STATIC = "static"              # アプリ起動時またはプロセス単位で固定
    SESSION_BOUND = "session-bound"# 同一セッション内で有効


class RefreshKind(str, Enum):
    """トークンの再取得・更新戦略。"""
    NONE = "none"                  # 更新不要（static など）
    PAGE_RELOAD = "page_reload"    # 元ページの HTML を再取得して DOM/meta/hidden から再抽出
    API_CALL = "api_call"          # 専用トークン発行エンドポイントの呼び出し
    SESSION_REFRESH = "session_refresh" # 認証/セッション再確立
    DOM_EVAL = "dom_eval"          # ブラウザ JS コンテキスト評価（window.csrfToken など）
    CUSTOM = "custom"              # 独自更新戦略


class TokenOutcomeKind(str, Enum):
    """トークン検証結果の分類。"""
    OK = "ok"                      # 正常受理
    STALE = "stale"                # トークン失効・不一致（リフレッシュで回復可能性あり）
    MISSING = "missing"            # トークン欠落（リクエスト側またはレスポンス側）
    BLOCKED = "blocked"            # WAF/認可拒否/IP制限など（トークン再送では解消不能）
    INCONCLUSIVE = "inconclusive"  # 判定不能（ステータスコードのみのヒント、情報不足）
    RETRYABLE = "retryable"        # 一時的ネットワークエラー・上流タイムアウト等


class TokenCarrier(str, Enum):
    """トークンの搬送形式（キャリア）。"""
    FORM_URLENCODED = "form-urlencoded"
    MULTIPART = "multipart"
    JSON = "json"
    XML = "xml"
    GRAPHQL = "graphql"
    HTTP_HEADER = "header"
    COOKIE = "cookie"


class TokenTransport(str, Enum):
    """トークンを送出・伝播するトランスポート層。"""
    PLAYWRIGHT = "playwright"      # 実ブラウザ DOM / ナビゲーション
    HTTPX = "httpx"                # 直接 HTTP クライアント
    SPA_API = "spa_api"            # SPA API 経由
    HAR_REPLAY = "har_replay"      # HAR 記録トラフィックの再生
    FLOW = "flow"                  # マルチステップ・シナリオ実行
    AGENT = "agent"                # 自律 LLM エージェント
    HYBRID = "hybrid"              # ハイブリッド探索エンジン


class DeclaredStatus(str, Enum):
    """静的機能宣言ステータス。"""
    SUPPORTED = "supported"        # 実行時統合済み・対応完了
    PLANNED = "planned"            # 将来スライスで統合予定（現スライス未統合）
    UNSUPPORTED = "unsupported"    # 設計上非対応
    BLOCKED = "blocked"            # 仕様上・構造上の制約により遮断（例: HAR 再生時のワンタイム nonce）


# 全キャリアおよび全トランスポートのタプル
ALL_TOKEN_CARRIERS: tuple[TokenCarrier, ...] = tuple(TokenCarrier)
ALL_TOKEN_TRANSPORTS: tuple[TokenTransport, ...] = tuple(TokenTransport)


# ── 3. データクラス（Typed Contracts） ────────────────────────────────────

@dataclass(frozen=True)
class TokenSource:
    """トークン取得元の宣言とディスカバリ用メタデータ。"""
    source_type: TokenSourceType
    identifier: str                     # フィールド名・ヘッダ名・キー名 (例: "csrf_token", "X-CSRF-Token")
    extraction_path: str = ""           # セレクタ、JSONPath、正規表現等
    discovery_url: str = ""             # トークン発見元 URL
    discovery_method: str = "GET"
    is_discovered: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenBinding:
    """トークンの紐付け対象・スコープ・消費条件。"""
    consumption: ConsumptionCondition = ConsumptionCondition.SESSION_BOUND
    actor_id: str = ""                  # 紐付け先アクター (ユーザー名やロール名)
    session_id_ref: str = ""            # 紐付け先セッションの安全な参照ID (生IDではない)
    scope: str = ""                     # トークンの有効スコープ (オリジン、パス、action 等)
    max_age_seconds: float | None = None# TTL (秒)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RefreshStrategy:
    """送信直前のトークン更新戦略。"""
    strategy: RefreshKind = RefreshKind.NONE
    endpoint_url: str = ""
    method: str = "GET"
    selector_or_key: str = ""
    headers: dict[str, str] = field(default_factory=dict)
    max_retries: int = 1
    timeout_seconds: float = 10.0
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class TokenSnapshot:
    """取得済みトークンの安全なスナップショット。

    不変条件:
    生シークレットは永続化・保持されない。TokenSnapshot はマスク済み値 (redacted_value)、
    出自情報 (provenance)、非秘密の参照ID (token_ref_id) 等の安全なメタデータのみを保持する。
    生トークン値はインスタンス属性、モジュールグローバル、キャッシュ等にいかなる形でも保持されない。
    実送信時の生トークン値は RefreshStrategy を通じて適用時 (apply-time) に
    呼び出し元から過渡的に渡され、TokenSnapshot には保持されない。
    """
    token_ref_id: str                   # 安定した非秘密参照ID (例: tok_ref_xxxx)
    redacted_value: str                 # マスク済み値 (例: ab12***ef (len=32))
    provenance: str                     # 出自情報 (例: "form:csrfmiddlewaretoken @ /login")
    issued_at: float                    # 取得時刻 (UNIX timestamp)
    scope: str = ""                     # 有効スコープ
    binding: TokenBinding | None = None
    source: TokenSource | None = None
    value_length: int = 0
    token_hash_hint: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def __post_init__(self) -> None:
        if self.metadata is None:
            object.__setattr__(self, "metadata", {})

    def reveal_secret_for_transport(self) -> None:
        """トランスポート層向け生シークレット取得アクセサ（本スライスでは常に None を返す）。

        契約の設計方針として、TokenSnapshot は生トークン値を一切保持しない。
        実送信時の生トークン値は RefreshStrategy を通じて適用時 (apply-time) に
        都度取得・過渡利用されるため、本スナップショットからは常に None を返す。
        """
        return None

    def release_secret(self) -> None:
        """生シークレット破棄用メソッド（no-op）。

        TokenSnapshot は生トークン値を保持しないため、本操作は何の副作用も伴わない no-op である。
        """
        return None

    def to_dict(self) -> dict[str, Any]:
        """安全なシリアライズ用辞書を返す。生シークレットは含まれない。"""
        return {
            "token_ref_id": self.token_ref_id,
            "redacted_value": self.redacted_value,
            "provenance": self.provenance,
            "issued_at": self.issued_at,
            "scope": self.scope,
            "binding": {
                "consumption": self.binding.consumption.value,
                "actor_id": self.binding.actor_id,
                "session_id_ref": self.binding.session_id_ref,
                "scope": self.binding.scope,
            } if self.binding else None,
            "source": {
                "source_type": self.source.source_type.value,
                "identifier": self.source.identifier,
                "extraction_path": self.source.extraction_path,
                "discovery_url": self.source.discovery_url,
            } if self.source else None,
            "value_length": self.value_length,
            "token_hash_hint": self.token_hash_hint,
            "metadata": dict(self.metadata),
        }

    def to_evidence(self) -> dict[str, Any]:
        """監査証跡 (evidence) 記録用の安全な辞書を返す。生シークレットは含まれない。"""
        return {
            "evidence_kind": "token_snapshot",
            "token_ref_id": self.token_ref_id,
            "redacted_value": self.redacted_value,
            "provenance": self.provenance,
            "scope": self.scope,
            "issued_at": self.issued_at,
            "value_length": self.value_length,
            "token_hash_hint": self.token_hash_hint,
        }


@dataclass(frozen=True)
class TokenOutcome:
    """トークン送出および応答検証の結果分類。"""
    outcome: TokenOutcomeKind
    reason_code: str                     # 短い理由コード (例: "stale_token_mismatch", "status_hint_only")
    detail: str = ""                     # 人間可読な詳細説明
    http_status_hint: int | None = None  # HTTP ステータスコード (ヒント情報)
    is_retryable: bool = False           # 有界リトライの対象となり得るか
    evidence_metadata: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class RetryDecision:
    """トークン再送要否の判定結果。"""
    should_retry: bool                   # 再試行すべきか
    reason: str                          # 判定理由
    attempt_count: int                   # 現在の試行回数
    max_retries: int                     # 最大リトライ上限
    requires_refresh: bool = False       # 再送前にトークン更新が必要か
    suggested_strategy: RefreshStrategy | None = None


@dataclass(frozen=True)
class CarrierCapabilityEntry:
    """キャリア×トランスポート単位の静的機能宣言エントリー。"""
    carrier: TokenCarrier
    transport: TokenTransport
    status: DeclaredStatus
    reason: str = ""
    declaration_only: bool = True


@dataclass(frozen=True)
class TokenCapabilityMatrix:
    """トークンライフサイクル機能マトリクス。

    不変条件: 宣言 != 実行保証 (Declaration != Runtime Execution Coverage)
    """
    entries: tuple[CarrierCapabilityEntry, ...]
    declaration_only: bool = True
    execution_coverage_claimed: bool = False
    disclaimer: str = TOKEN_LIFECYCLE_DISCLAIMER

    def get_entry(self, carrier: TokenCarrier | str, transport: TokenTransport | str) -> CarrierCapabilityEntry:
        c = normalize_carrier(carrier)
        t = normalize_transport(transport)
        for entry in self.entries:
            if entry.carrier == c and entry.transport == t:
                return entry
        raise KeyError(f"No entry declared for carrier={c} and transport={t}")

    def get_status(self, carrier: TokenCarrier | str, transport: TokenTransport | str) -> DeclaredStatus:
        return self.get_entry(carrier, transport).status

    def is_supported(self, carrier: TokenCarrier | str, transport: TokenTransport | str) -> bool:
        return self.get_status(carrier, transport) == DeclaredStatus.SUPPORTED

    def is_planned(self, carrier: TokenCarrier | str, transport: TokenTransport | str) -> bool:
        return self.get_status(carrier, transport) == DeclaredStatus.PLANNED

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "contract_kind": CONTRACT_KIND,
            "declaration_only": self.declaration_only,
            "execution_coverage_claimed": self.execution_coverage_claimed,
            "disclaimer": self.disclaimer,
            "matrix": {
                f"{e.transport.value}::{e.carrier.value}": {
                    "carrier": e.carrier.value,
                    "transport": e.transport.value,
                    "status": e.status.value,
                    "reason": e.reason,
                    "declaration_only": e.declaration_only,
                }
                for e in self.entries
            },
        }


# ── 4. マスキング・参照ID導出（Redaction Pure Helpers） ───────────────────

def redact_token_value(value: str, keep_prefix: int = 4, keep_suffix: int = 2) -> str:
    """生トークン文字列を安全にマスクする純粋関数。

    Args:
        value: 生のトークン文字列
        keep_prefix: 先頭に残す文字数
        keep_suffix: 末尾に残す文字数

    Returns:
        マスクされた安全な文字列
    """
    if not value:
        return "[EMPTY]"
    length = len(value)
    if length <= 8:
        return f"[REDACTED:len={length}]"
    prefix = value[:keep_prefix]
    suffix = value[-keep_suffix:]
    return f"{prefix}***{suffix} (len={length})"


def derive_token_ref_id(value: str, prefix: str = "tok_ref_") -> str:
    """生シークレットから不可逆かつ安定した参照IDを導出する。

    生シークレットのハッシュからプレフィックス付きの識別子を生成し、
    ログや監査証跡で生シークレットの代わりに参照として用いる。
    """
    if not value:
        return f"{prefix}empty"
    digest = hashlib.sha256(value.encode("utf-8")).hexdigest()[:12]
    return f"{prefix}{digest}"


def create_token_snapshot(
    raw_value: str,
    provenance: str,
    scope: str = "",
    binding: TokenBinding | None = None,
    source: TokenSource | None = None,
    issued_at: float | None = None,
    metadata: dict[str, Any] | None = None,
    retain_secret_for_transport: bool = False,
) -> TokenSnapshot:
    """生トークンから安全な TokenSnapshot を構築する純粋ファクトリ関数。

    不変条件:
    生トークン値は TokenSnapshot 内やモジュールグローバルには一切保持・永続化されない。
    マスク済み値 (redacted_value)、非秘密の参照ID (token_ref_id)、出自情報 (provenance)
    などの安全なメタデータのみを保持する。
    実送信時の生トークン値は RefreshStrategy を通じて適用時 (apply-time) に
    都度取得・過渡利用される（TokenSnapshot には保持されない）。
    グローバル状態の変更や副作用を持たない純粋関数である。
    """
    ts = issued_at if issued_at is not None else time.time()
    redacted = redact_token_value(raw_value)
    ref_id = derive_token_ref_id(raw_value)
    val_len = len(raw_value)
    hash_hint = hashlib.sha256(raw_value.encode("utf-8")).hexdigest()[:8] if raw_value else ""

    return TokenSnapshot(
        token_ref_id=ref_id,
        redacted_value=redacted,
        provenance=provenance,
        issued_at=ts,
        scope=scope,
        binding=binding,
        source=source,
        value_length=val_len,
        token_hash_hint=hash_hint,
        metadata=dict(metadata) if metadata is not None else {},
    )


# Anti-CSRF / Nonce トークンフィールド名の判定セット（純粋定義）
TOKEN_FIELD_NAMES: frozenset[str] = frozenset({
    "csrf",
    "_csrf",
    "csrf_token",
    "csrftoken",
    "csrfmiddlewaretoken",
    "xsrf",
    "_xsrf",
    "xsrf_token",
    "xsrftoken",
    "anti_csrf",
    "anti_csrf_token",
    "authenticity_token",
    "verification_token",
    "requestverificationtoken",
    "__requestverificationtoken",
    "_wpnonce",
    "nonce",
    "_nonce",
    "form_token",
    "formtoken",
    "security_token",
    "sec_token",
    "requesttoken",
    "request_token",
    "_token",
    "token",
    "x_csrf_token",
    "x_xsrf_token",
})


def is_token_field_name(name: str | None) -> bool:
    """フィールド名が anti-CSRF または nonce トークンであるかを純粋判定する。

    通常のユーザー入力フィールド（username, search, email, q 等）を誤認しないよう、
    ハイフン・空白・アンダースコアを正規化した完全一致で検証する。
    """
    if not name or not isinstance(name, str):
        return False
    norm = name.strip().lower().replace("-", "_").replace(" ", "_")
    return norm in TOKEN_FIELD_NAMES


class _PureFormParser(HTMLParser):
    """HTML 内の <form> と入力フィールドを解析する純粋パーサ。"""

    def __init__(self):
        super().__init__()
        self.forms: list[dict[str, Any]] = []
        self._current_form: dict[str, Any] | None = None
        self._form_index = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]):
        tag_lower = tag.lower()
        attr_dict = {k.lower(): (v or "") for k, v in attrs}
        if tag_lower == "form":
            self._current_form = {
                "index": self._form_index,
                "action": attr_dict.get("action", ""),
                "method": (attr_dict.get("method") or "GET").upper(),
                "fields": {},
                "token_fields": {},
            }
            self.forms.append(self._current_form)
            self._form_index += 1
        elif self._current_form is not None:
            name = attr_dict.get("name") or attr_dict.get("id")
            if not name:
                return
            val = attr_dict.get("value", "")
            if tag_lower == "input":
                inp_type = (attr_dict.get("type") or "text").lower()
                if inp_type in ("submit", "button", "reset", "image", "file"):
                    return
                self._current_form["fields"][name] = val
                if is_token_field_name(name):
                    self._current_form["token_fields"][name] = val
            elif tag_lower in ("textarea", "select"):
                self._current_form["fields"][name] = val

    def handle_endtag(self, tag: str):
        if tag.lower() == "form":
            self._current_form = None


def extract_form_tokens(html: str, form_index: int = 0) -> dict[str, str]:
    """HTMLから指定されたフォームの anti-CSRF / nonce トークンフィールドとその値を抽出する純粋関数。"""
    if not html or not isinstance(html, str):
        return {}
    parser = _PureFormParser()
    try:
        parser.feed(html)
    except Exception:
        return {}
    if 0 <= form_index < len(parser.forms):
        return dict(parser.forms[form_index]["token_fields"])
    return {}


def extract_form_details(html: str, form_index: int = 0) -> dict[str, Any] | None:
    """HTMLから指定されたフォームの action, method, fields, token_fields を抽出する純粋関数。"""
    if not html or not isinstance(html, str):
        return None
    parser = _PureFormParser()
    try:
        parser.feed(html)
    except Exception:
        return None
    if 0 <= form_index < len(parser.forms):
        return parser.forms[form_index]
    return None


# ── 5. レスポンス分類（Outcome Classification Pure Function） ────────────

# 明示的な CSRF トークン不一致・失効シグナル
_CSRF_STALE_KEYWORDS: tuple[str, ...] = (
    "csrf token mismatch",
    "csrf verification failed",
    "invalid csrf token",
    "csrf token is invalid",
    "csrf token has expired",
    "csrf token expired",
    "anti-forgery token",
    "antiforgery",
    "can't verify csrf token authenticity",
    "page expired",             # Laravel 419 default message
    "stale token",
    "ebadcsrcftoken",           # Express csurf error code
    "bad csrf token",
    "token expired",
    "form expired",
    "session token expired",
)

# 明示的なトークン欠落シグナル
_CSRF_MISSING_KEYWORDS: tuple[str, ...] = (
    "csrf token missing",
    "missing csrf token",
    "csrf cookie not set",
    "no csrf token",
    "csrf token required",
)

# WAF / 認可拒否シグナル
_BLOCKED_KEYWORDS: tuple[str, ...] = (
    "cloudflare",
    "mod_security",
    "modsecurity",
    "access denied",
    "request blocked",
    "blocked by web application firewall",
    "security violation",
    "forbidden by administrative rules",
    "rate limit exceeded",
    "too many requests",
)


def classify_token_response(
    status_code: int,
    headers: Mapping[str, str] | None = None,
    body: str | bytes | None = None,
    binding: TokenBinding | None = None,
    token_present: bool = True,
    refresh_attempted: bool = False,
    refresh_succeeded: bool = False,
    lifecycle_signal: str | None = None,
) -> TokenOutcome:
    """レスポンスまたは実行シグナルから TokenOutcome を分類する純粋関数。

    【重要規則】
    1. HTTP ステータス（403/419/422）単体はヒントであり、それだけで STALE とは断定しない。
       明示的な本文・ヘッダシグナルが無い場合は INCONCLUSIVE とする。
    2. トークン更新を試行して失敗したプローブ（refresh_attempted=True かつ not refresh_succeeded）は、
       決して確定（positive / confirmed）または安全（negative）と誤認してはならず、
       BLOCKED または INCONCLUSIVE に分類する。
    """
    # ── 規則 1: トークン更新失敗時のプローブ結果は確定・陰性に倒さず BLOCKED/INCONCLUSIVE に倒す ──
    if refresh_attempted and not refresh_succeeded:
        return TokenOutcome(
            outcome=TokenOutcomeKind.BLOCKED,
            reason_code="refresh_failed",
            detail="Token refresh was attempted but failed; probe cannot be confirmed as vulnerable or safe.",
            http_status_hint=status_code,
            is_retryable=False,
            evidence_metadata={"refresh_attempted": True, "refresh_succeeded": False},
        )

    # ── 規則 2: 意図的または偶発的なトークン非送信プローブの分類 ──
    if not token_present:
        # トークン非送信でサーバが受理した場合（2xx / 3xx）: トークン検証が欠如しているシグナル
        if 200 <= status_code < 400:
            return TokenOutcome(
                outcome=TokenOutcomeKind.MISSING,
                reason_code="token_absent_accepted",
                detail="Request sent without token was accepted by server (potential missing CSRF protection).",
                http_status_hint=status_code,
                is_retryable=False,
                evidence_metadata={"token_present": False, "status": status_code},
            )
        # トークン非送信で拒否された場合
        return TokenOutcome(
            outcome=TokenOutcomeKind.MISSING,
            reason_code="token_absent_rejected",
            detail="Server rejected request sent without token (token enforcement active).",
            http_status_hint=status_code,
            is_retryable=False,
            evidence_metadata={"token_present": False, "status": status_code},
        )

    # ── 規則 3: 一時的ネットワークエラー・上流障害 ──
    if status_code in (408, 502, 503, 504):
        return TokenOutcome(
            outcome=TokenOutcomeKind.RETRYABLE,
            reason_code="transient_upstream_error",
            detail=f"Transient status {status_code} received; bounded retry warranted.",
            http_status_hint=status_code,
            is_retryable=True,
        )

    # 本文テキストの正規化
    body_text = ""
    if body is not None:
        if isinstance(body, bytes):
            body_text = body.decode("utf-8", errors="replace").lower()
        else:
            body_text = str(body).lower()

    # ヘッダシグナルの確認
    hdr_dict = {k.lower(): v.lower() for k, v in (headers or {}).items()}
    csrf_error_header = hdr_dict.get("x-csrf-error", "") or hdr_dict.get("x-action-error", "")

    # ── 規則 4: 明示的ライフサイクルシグナルの適用 ──
    if lifecycle_signal:
        sig = lifecycle_signal.lower()
        if "one_time" in sig or "second_use" in sig or "nonce_reused" in sig:
            return TokenOutcome(
                outcome=TokenOutcomeKind.STALE,
                reason_code="stale_one_time_consumed",
                detail="One-time nonce was already consumed or replayed.",
                http_status_hint=status_code,
                is_retryable=True,
            )
        if "rotating" in sig or "replayed" in sig:
            return TokenOutcome(
                outcome=TokenOutcomeKind.STALE,
                reason_code="stale_rotating_token",
                detail="Rotating token was invalidated by prior request.",
                http_status_hint=status_code,
                is_retryable=True,
            )
        if "session" in sig or "session_expired" in sig:
            return TokenOutcome(
                outcome=TokenOutcomeKind.STALE,
                reason_code="stale_session_bound",
                detail="Session bound token expired or session invalidated.",
                http_status_hint=status_code,
                is_retryable=True,
            )
        if "static_rejected" in sig:
            return TokenOutcome(
                outcome=TokenOutcomeKind.BLOCKED,
                reason_code="static_token_rejected",
                detail="Static token was rejected by server; cannot be resolved by refresh.",
                http_status_hint=status_code,
                is_retryable=False,
            )

    # ── 規則 5: 消費条件（ConsumptionCondition）とエラーの相関 ──
    if binding and binding.consumption == ConsumptionCondition.STATIC:
        # STATIC トークンでエラーになった場合、リフレッシュしても変化しないため BLOCKED
        if status_code in (400, 401, 403, 419, 422) and any(k in body_text for k in _CSRF_STALE_KEYWORDS):
            return TokenOutcome(
                outcome=TokenOutcomeKind.BLOCKED,
                reason_code="static_token_rejected",
                detail="Static token mismatch cannot be resolved by refresh.",
                http_status_hint=status_code,
                is_retryable=False,
            )

    # ── 規則 6: 本文/ヘッダの明示的シグナル検査 ──
    # WAF ブロック判定
    if any(k in body_text for k in _BLOCKED_KEYWORDS):
        return TokenOutcome(
            outcome=TokenOutcomeKind.BLOCKED,
            reason_code="blocked_waf_or_policy",
            detail="Request blocked by WAF, rate limit, or security access policy.",
            http_status_hint=status_code,
            is_retryable=False,
        )

    # 明示的な CSRF 欠落シグナル
    if any(k in body_text for k in _CSRF_MISSING_KEYWORDS):
        return TokenOutcome(
            outcome=TokenOutcomeKind.MISSING,
            reason_code="missing_token_error",
            detail="Server explicitly reported missing CSRF token in response body.",
            http_status_hint=status_code,
            is_retryable=True,
        )

    # 明示的な CSRF 不一致・失効シグナル
    if csrf_error_header or any(k in body_text for k in _CSRF_STALE_KEYWORDS):
        return TokenOutcome(
            outcome=TokenOutcomeKind.STALE,
            reason_code="stale_token_mismatch",
            detail="Server reported CSRF token mismatch or expiration.",
            http_status_hint=status_code,
            is_retryable=True,
        )

    # ── 規則 7: HTTP ステータス単体（403/419/422）はヒント扱い（断定せず INCONCLUSIVE） ──
    if status_code in (403, 419, 422):
        return TokenOutcome(
            outcome=TokenOutcomeKind.INCONCLUSIVE,
            reason_code="status_hint_only",
            detail=f"HTTP status {status_code} received without explicit token error signals; status alone is inconclusive.",
            http_status_hint=status_code,
            is_retryable=False,
        )

    # ── 規則 8: 正常受理（2xx / 3xx） ──
    if 200 <= status_code < 400:
        return TokenOutcome(
            outcome=TokenOutcomeKind.OK,
            reason_code="ok",
            detail="Request accepted successfully with token.",
            http_status_hint=status_code,
            is_retryable=False,
        )

    # その他未知のエラー
    return TokenOutcome(
        outcome=TokenOutcomeKind.INCONCLUSIVE,
        reason_code="unclassified_status",
        detail=f"Unclassified response with status {status_code}.",
        http_status_hint=status_code,
        is_retryable=False,
    )


def is_probe_conclusive(outcome: TokenOutcome) -> bool:
    """プローブ結果が脆弱性の確定判定 (confirmed / negative) に有効かを判定する純粋関数。

    BLOCKED または INCONCLUSIVE の結果は、プローブ自体が成立していない（WAF阻害、
    トークン更新失敗、情報不足）ため、確定判定に使用してはならない。
    """
    return outcome.outcome not in (TokenOutcomeKind.BLOCKED, TokenOutcomeKind.INCONCLUSIVE)


# ── 6. 有界リトライ判定（Bounded Retry Pure Function） ─────────────────────

def decide_token_retry(
    outcome: TokenOutcome,
    attempt_count: int = 1,
    max_retries: int = 1,
    binding: TokenBinding | None = None,
    refresh_strategy: RefreshStrategy | None = None,
) -> RetryDecision:
    """有界リトライ (bounded retry) の要否を決定する純粋関数。

    規則:
    1. attempt_count >= max_retries の場合、上限到達によりリトライ不可（有界性の厳格保証）。
    2. outcome が BLOCKED または INCONCLUSIVE の場合、トークン再送では解決しないためリトライ不可。
    3. outcome が OK の場合、すでに成功しているためリトライ不要。
    4. outcome が STALE の場合:
       - binding が STATIC のときは値が変わらないためリトライ不可。
       - refresh_strategy が利用可能（strategy != NONE）であれば、リフレッシュ付きリトライを許可。
       - refresh_strategy が NONE または未指定の場合、リフレッシュできないためリトライ不可。
    5. outcome が RETRYABLE（一時障害）の場合、上限内であればリトライを許可。
    6. outcome が MISSING かつ refresh_strategy が利用可能な場合、取得を試みるリトライを許可。
    """
    # 規則 1: 上限到達
    if attempt_count >= max_retries:
        return RetryDecision(
            should_retry=False,
            reason=f"Max retry limit reached ({attempt_count}/{max_retries})",
            attempt_count=attempt_count,
            max_retries=max_retries,
            requires_refresh=False,
            suggested_strategy=refresh_strategy,
        )

    # 規則 2: 成功時は再試行不要
    if outcome.outcome == TokenOutcomeKind.OK:
        return RetryDecision(
            should_retry=False,
            reason="Outcome is already OK; no retry needed",
            attempt_count=attempt_count,
            max_retries=max_retries,
            requires_refresh=False,
        )

    # 規則 3: BLOCKED / INCONCLUSIVE は再試行不可
    if outcome.outcome in (TokenOutcomeKind.BLOCKED, TokenOutcomeKind.INCONCLUSIVE):
        return RetryDecision(
            should_retry=False,
            reason=f"Outcome is {outcome.outcome.value} ({outcome.reason_code}); blind retry is not warranted",
            attempt_count=attempt_count,
            max_retries=max_retries,
            requires_refresh=False,
        )

    # 規則 4: 一時的エラー（RETRYABLE）
    if outcome.outcome == TokenOutcomeKind.RETRYABLE:
        return RetryDecision(
            should_retry=True,
            reason=f"Transient retryable signal ({outcome.reason_code}); bounded retry warranted",
            attempt_count=attempt_count,
            max_retries=max_retries,
            requires_refresh=False,
            suggested_strategy=refresh_strategy,
        )

    # 規則 5: STALE（失効・不一致）の場合
    if outcome.outcome == TokenOutcomeKind.STALE:
        # STATIC トークンはリフレッシュ不可能
        if binding and binding.consumption == ConsumptionCondition.STATIC:
            return RetryDecision(
                should_retry=False,
                reason="Token binding is STATIC; refreshing is not applicable",
                attempt_count=attempt_count,
                max_retries=max_retries,
                requires_refresh=False,
            )
        # リフレッシュ戦略の有無を確認
        if refresh_strategy and refresh_strategy.strategy != RefreshKind.NONE:
            return RetryDecision(
                should_retry=True,
                reason=f"Token is stale ({outcome.reason_code}); refresh and retry warranted",
                attempt_count=attempt_count,
                max_retries=max_retries,
                requires_refresh=True,
                suggested_strategy=refresh_strategy,
            )
        return RetryDecision(
            should_retry=False,
            reason="Token is stale but no active refresh strategy is configured",
            attempt_count=attempt_count,
            max_retries=max_retries,
            requires_refresh=False,
        )

    # 規則 6: MISSING の場合
    if outcome.outcome == TokenOutcomeKind.MISSING:
        if refresh_strategy and refresh_strategy.strategy != RefreshKind.NONE:
            return RetryDecision(
                should_retry=True,
                reason="Token was missing; attempting token acquisition and retry",
                attempt_count=attempt_count,
                max_retries=max_retries,
                requires_refresh=True,
                suggested_strategy=refresh_strategy,
            )
        return RetryDecision(
            should_retry=False,
            reason="Token is missing and no discovery/refresh strategy is configured",
            attempt_count=attempt_count,
            max_retries=max_retries,
            requires_refresh=False,
        )

    return RetryDecision(
        should_retry=False,
        reason=f"Default no-retry for outcome {outcome.outcome.value}",
        attempt_count=attempt_count,
        max_retries=max_retries,
        requires_refresh=False,
    )


# ── 7. 正規化ヘルパー ─────────────────────────────────────────────────────

def normalize_carrier(val: TokenCarrier | str) -> TokenCarrier:
    """文字列または Enum を TokenCarrier に正規化する。"""
    if isinstance(val, TokenCarrier):
        return val
    s = str(val).strip().lower().replace("_", "-")
    if s in ("form", "form-urlencoded", "urlencoded", "form_urlencoded"):
        return TokenCarrier.FORM_URLENCODED
    if s in ("multipart", "form-data", "multipart-form-data"):
        return TokenCarrier.MULTIPART
    if s in ("json", "application-json"):
        return TokenCarrier.JSON
    if s in ("xml", "application-xml", "text-xml"):
        return TokenCarrier.XML
    if s in ("graphql", "gql"):
        return TokenCarrier.GRAPHQL
    if s in ("header", "http-header", "http_header"):
        return TokenCarrier.HTTP_HEADER
    if s in ("cookie", "cookies"):
        return TokenCarrier.COOKIE
    return TokenCarrier(s)


def normalize_transport(val: TokenTransport | str) -> TokenTransport:
    """文字列または Enum を TokenTransport に正規化する。"""
    if isinstance(val, TokenTransport):
        return val
    s = str(val).strip().lower().replace("-", "_")
    if s in ("playwright", "pw", "browser"):
        return TokenTransport.PLAYWRIGHT
    if s in ("httpx", "http"):
        return TokenTransport.HTTPX
    if s in ("spa_api", "spa", "spa-api"):
        return TokenTransport.SPA_API
    if s in ("har_replay", "har", "har-replay"):
        return TokenTransport.HAR_REPLAY
    if s in ("flow", "scenario"):
        return TokenTransport.FLOW
    if s in ("agent", "llm_agent"):
        return TokenTransport.AGENT
    if s in ("hybrid", "hybrid_mode"):
        return TokenTransport.HYBRID
    return TokenTransport(s)


def normalize_status(val: DeclaredStatus | str) -> DeclaredStatus:
    """文字列または Enum を DeclaredStatus に正規化する。"""
    if isinstance(val, DeclaredStatus):
        return val
    s = str(val).strip().lower()
    return DeclaredStatus(s)


# ── 8. 機能マトリクスビルダー（Capability Matrix Builder） ─────────────────

# 各キャリア × トランスポートのデフォルト宣言定義
# INVARIANT: 宣言 != 実行保証（Declaration != Runtime Execution Coverage）
_DEFAULT_DECLARATIONS: dict[tuple[TokenCarrier, TokenTransport], tuple[DeclaredStatus, str]] = {
    # Playwright (ブラウザ DOM / ナビゲーション)
    (TokenCarrier.FORM_URLENCODED, TokenTransport.PLAYWRIGHT): (
        DeclaredStatus.SUPPORTED, "Supported: DOM form navigation and hidden token field extraction"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.PLAYWRIGHT): (
        DeclaredStatus.PLANNED, "Planned: File input attachment with DOM token retention"
    ),
    (TokenCarrier.JSON, TokenTransport.PLAYWRIGHT): (
        DeclaredStatus.PLANNED, "Planned: In-page fetch/XHR dispatch with page context token"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.PLAYWRIGHT): (
        DeclaredStatus.PLANNED, "Planned: Page client GraphQL dispatch with session context"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.PLAYWRIGHT): (
        DeclaredStatus.PLANNED, "Planned: Route interception and setExtraHTTPHeaders"
    ),
    (TokenCarrier.COOKIE, TokenTransport.PLAYWRIGHT): (
        DeclaredStatus.PLANNED, "Planned: Browser context cookie jar synchronization"
    ),

    # HTTPX (直接 HTTP クライアント)
    (TokenCarrier.FORM_URLENCODED, TokenTransport.HTTPX): (
        DeclaredStatus.SUPPORTED, "Supported: Pre-send HTML form re-extraction for fresh hidden token in shared HTTPX transport"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.HTTPX): (
        DeclaredStatus.PLANNED, "Planned: Multipart body generation with extracted token part"
    ),
    (TokenCarrier.JSON, TokenTransport.HTTPX): (
        DeclaredStatus.SUPPORTED, "Supported: Pre-send JSON token refresh in shared HTTPX transport"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.HTTPX): (
        DeclaredStatus.PLANNED, "Planned: POST /graphql with token headers/variables"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.HTTPX): (
        DeclaredStatus.SUPPORTED, "Supported: Pre-send recognized CSRF header refresh in shared HTTPX transport"
    ),
    (TokenCarrier.XML, TokenTransport.HTTPX): (
        DeclaredStatus.SUPPORTED, "Supported: Pre-send XML token refresh in shared HTTPX transport"
    ),
    (TokenCarrier.COOKIE, TokenTransport.HTTPX): (
        DeclaredStatus.PLANNED, "Planned: Client cookie jar propagation"
    ),

    # SPA API (SPA エンドポイント)
    (TokenCarrier.FORM_URLENCODED, TokenTransport.SPA_API): (
        DeclaredStatus.UNSUPPORTED, "SPA endpoints communicate via JSON/GraphQL, not urlencoded forms"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.SPA_API): (
        DeclaredStatus.PLANNED, "Planned: FormData multipart upload via SPA API client"
    ),
    (TokenCarrier.JSON, TokenTransport.SPA_API): (
        DeclaredStatus.SUPPORTED, "Supported: Pre-send JSON token refresh in shared SPA API transport"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.SPA_API): (
        DeclaredStatus.PLANNED, "Planned: Primary GraphQL API endpoint format"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.SPA_API): (
        DeclaredStatus.SUPPORTED, "Supported: Pre-send recognized CSRF header refresh in shared SPA API transport"
    ),
    (TokenCarrier.COOKIE, TokenTransport.SPA_API): (
        DeclaredStatus.PLANNED, "Planned: SameSite cookie credential inclusion"
    ),

    # HAR Replay (記録トラフィックの再生)
    # HAR 再生では静的記録値を用いるため、動的/回転する nonce は構造的に遮断される
    (TokenCarrier.FORM_URLENCODED, TokenTransport.HAR_REPLAY): (
        DeclaredStatus.BLOCKED, "Static recorded form tokens fail dynamic one-time/rotating nonce checks"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.HAR_REPLAY): (
        DeclaredStatus.BLOCKED, "Recorded multipart bodies contain expired nonces"
    ),
    (TokenCarrier.JSON, TokenTransport.HAR_REPLAY): (
        DeclaredStatus.BLOCKED, "Recorded JSON payload tokens are stale upon replay"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.HAR_REPLAY): (
        DeclaredStatus.BLOCKED, "Recorded GraphQL operation tokens fail dynamic validation"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.HAR_REPLAY): (
        DeclaredStatus.BLOCKED, "Recorded CSRF headers fail server-side session checks"
    ),
    (TokenCarrier.COOKIE, TokenTransport.HAR_REPLAY): (
        DeclaredStatus.BLOCKED, "Recorded session cookies/nonces expire across sessions"
    ),

    # Flow (マルチステップ・シナリオ)
    (TokenCarrier.FORM_URLENCODED, TokenTransport.FLOW): (
        DeclaredStatus.SUPPORTED, "Supported: Prior step token extraction chained to subsequent step form"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.FLOW): (
        DeclaredStatus.PLANNED, "Planned: Flow state token injection into multipart step"
    ),
    (TokenCarrier.JSON, TokenTransport.FLOW): (
        DeclaredStatus.PLANNED, "Planned: JSON body token substitution from flow context"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.FLOW): (
        DeclaredStatus.PLANNED, "Planned: GraphQL variable substitution from flow state"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.FLOW): (
        DeclaredStatus.PLANNED, "Planned: Step-extracted token propagated to next step headers"
    ),
    (TokenCarrier.COOKIE, TokenTransport.FLOW): (
        DeclaredStatus.PLANNED, "Planned: Flow session cookie jar maintained across step boundaries"
    ),

    # Agent (自律 LLM エージェント)
    (TokenCarrier.FORM_URLENCODED, TokenTransport.AGENT): (
        DeclaredStatus.PLANNED, "Planned: Agent DOM exploration fills and submits forms"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.AGENT): (
        DeclaredStatus.UNSUPPORTED, "Agent raw multipart stream construction not currently declared"
    ),
    (TokenCarrier.JSON, TokenTransport.AGENT): (
        DeclaredStatus.PLANNED, "Planned: Agent constructs structured JSON tool payloads"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.AGENT): (
        DeclaredStatus.UNSUPPORTED, "Direct GraphQL AST generation not currently declared"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.AGENT): (
        DeclaredStatus.PLANNED, "Planned: Agent specifies custom request headers"
    ),
    (TokenCarrier.COOKIE, TokenTransport.AGENT): (
        DeclaredStatus.PLANNED, "Planned: Agent operates within authenticated browser session"
    ),

    # Hybrid (ハイブリッド探索)
    (TokenCarrier.FORM_URLENCODED, TokenTransport.HYBRID): (
        DeclaredStatus.PLANNED, "Planned: Deterministic scanner handles form token lifecycle"
    ),
    (TokenCarrier.MULTIPART, TokenTransport.HYBRID): (
        DeclaredStatus.PLANNED, "Planned: Deterministic scanner handles multipart token lifecycle"
    ),
    (TokenCarrier.JSON, TokenTransport.HYBRID): (
        DeclaredStatus.PLANNED, "Planned: Deterministic + agent coordinate JSON token lifecycle"
    ),
    (TokenCarrier.GRAPHQL, TokenTransport.HYBRID): (
        DeclaredStatus.PLANNED, "Planned: Deterministic scanner handles GraphQL token injection"
    ),
    (TokenCarrier.HTTP_HEADER, TokenTransport.HYBRID): (
        DeclaredStatus.PLANNED, "Planned: Both engines propagate authenticated token headers"
    ),
    (TokenCarrier.COOKIE, TokenTransport.HYBRID): (
        DeclaredStatus.PLANNED, "Planned: Shared session cookies preserved across handoff"
    ),
}


@dataclass(frozen=True)
class TokenRefreshResult:
    """refresh_form_tokens の結果（生トークンは保持しない）。"""
    outcome: TokenOutcome
    snapshots: tuple[TokenSnapshot, ...]
    refreshed: bool
    residual_stale: bool
    fields: Mapping[str, str] | None = None


def refresh_form_tokens(
    fresh_values: Mapping[str, str],
    *,
    provenance: str,
    status_code: int,
    headers: Mapping[str, str] | None = None,
    body: str | bytes | None = None,
    refreshed: bool = False,
    fields: Mapping[str, str] | None = None,
) -> TokenRefreshResult:
    """フォームトークン再送後の最終応答を分類する純粋ヘルパ（I/O なし）。

    生トークンは TokenSnapshot 化（redacted/ref_id のみ）後に release_secret し、保持しない。
    residual_stale は最終応答が STALE のまま（BLOCKED/WAF 403 は含まない）。
    """
    snaps = []
    substituted = dict(fields or {})
    for name, raw in fresh_values.items():
        snap = create_token_snapshot(str(raw), provenance=f"form:{name} @ {provenance}")
        snaps.append(snap)
        snap.release_secret()
        substituted[name] = str(raw)
    outcome = classify_token_response(status_code=status_code, headers=headers, body=body)
    return TokenRefreshResult(
        outcome=outcome,
        snapshots=tuple(snaps),
        refreshed=refreshed,
        residual_stale=outcome.outcome == TokenOutcomeKind.STALE,
        fields=substituted if fields is not None else None,
    )


def build_token_capability_matrix(
    overrides: Mapping[tuple[TokenCarrier | str, TokenTransport | str], DeclaredStatus | str] | None = None,
) -> TokenCapabilityMatrix:
    """キャリア×トランスポート単位の機能マトリクスを構築する純粋関数。

    【不変条件】
    本マトリクスは静的な対応能力の宣言 (declared capability) のみを表し、
    実行時カバレッジや動的成功保証を一切意味しない。
    """
    normalized_overrides: dict[tuple[TokenCarrier, TokenTransport], DeclaredStatus] = {}
    if overrides:
        for (c, t), s in overrides.items():
            norm_c = normalize_carrier(c)
            norm_t = normalize_transport(t)
            norm_s = normalize_status(s)
            normalized_overrides[(norm_c, norm_t)] = norm_s

    entries: list[CarrierCapabilityEntry] = []
    for c in ALL_TOKEN_CARRIERS:
        for t in ALL_TOKEN_TRANSPORTS:
            pair = (c, t)
            if pair in normalized_overrides:
                status = normalized_overrides[pair]
                reason = f"Custom override: {status.value}"
            elif pair in _DEFAULT_DECLARATIONS:
                status, reason = _DEFAULT_DECLARATIONS[pair]
            elif c == TokenCarrier.XML:
                status = DeclaredStatus.BLOCKED if t == TokenTransport.HAR_REPLAY else DeclaredStatus.PLANNED
                reason = "Planned: XML request body token refresh" if status == DeclaredStatus.PLANNED else "Recorded XML tokens may be stale"
            else:
                status = DeclaredStatus.UNSUPPORTED
                reason = "Not declared in default matrix"

            entries.append(
                CarrierCapabilityEntry(
                    carrier=c,
                    transport=t,
                    status=status,
                    reason=reason,
                    declaration_only=True,
                )
            )

    return TokenCapabilityMatrix(
        entries=tuple(entries),
        declaration_only=True,
        execution_coverage_claimed=False,
        disclaimer=TOKEN_LIFECYCLE_DISCLAIMER,
    )

# Opt-in, write-only lifecycle telemetry. Values are deliberately primitive and secret-free.
_TOKEN_TELEMETRY_REASONS = frozenset({"stale", "refresh_failed", "retry", "transport_error", "unknown"})

@dataclass(frozen=True)
class TokenLifecycleEvent:
    probe_attempt_id: str | None
    evidence_id: str | None
    check: str
    carrier: TokenCarrier
    transport: TokenTransport
    attempt_count: int
    refresh_reason: str | None
    final_status: int | None
    final_lifecycle_status: str

    def __post_init__(self):
        if self.attempt_count < 1:
            raise ValueError("attempt_count must be >= 1")
        if self.final_status is not None and (type(self.final_status) is not int):
            raise TypeError("final_status must be int or None")
        if self.refresh_reason not in (None, *_TOKEN_TELEMETRY_REASONS):
            raise ValueError("invalid refresh_reason")

    def to_dict(self) -> dict:
        return {
            "probe_attempt_id": self.probe_attempt_id,
            "evidence_id": self.evidence_id,
            "check": self.check,
            "carrier": self.carrier.value,
            "transport": self.transport.value,
            "attempt_count": self.attempt_count,
            "refresh_reason": self.refresh_reason,
            "final_status": self.final_status,
            "final_lifecycle_status": self.final_lifecycle_status,
        }

class TokenSourceAdapter(Protocol):
    async def read(self, *, transport: TokenTransport, url: str, carrier: TokenCarrier, session: Any, source: TokenSource | None = None) -> TokenRefreshResult: ...
class ExpiryRecoveryAdapter(Protocol):
    def classify(self, *, status_code: int | None, headers: Mapping[str, str], body: str | bytes | None) -> TokenOutcome: ...
    async def recover(self, *, outcome: TokenOutcome, attempt_count: int, max_retries: int, source: TokenSourceAdapter, session: Any, request: Any) -> RetryDecision: ...
class ParallelSessionIsolation(Protocol):
    def session_for(self, *, worker_id: str, base_session: Any) -> Any: ...
class TokenDependencyAnalyzer(Protocol):
    def dependencies(self, *, injection_point: Any, token_sources: Sequence[TokenSource]) -> Sequence[str]: ...
class PlannedTokenDependencyAnalyzer:
    def dependencies(self, *, injection_point: Any, token_sources: Sequence[TokenSource]) -> Sequence[str]:
        raise NotImplementedError("token dependency analysis is PLANNED")
