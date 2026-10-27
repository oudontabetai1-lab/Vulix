"""
Mass Assignment Scanner（新クラス・API ファースト連携）
======================================================
OWASP API Top 10 の「Mass Assignment / 過剰割り当て」。クライアントが送れない
はずの特権プロパティ（``role`` / ``isAdmin`` / ``verified`` 等）を JSON ボディに
混ぜて送り、サーバがそれを受理して反映するかを検査する。

検査対象は **API スペック（OpenAPI/Postman）取り込みで得た JSON 操作**
（``engine.api_seed_requests`` の :class:`RequestTemplate`）。各操作について
  1. テンプレートのボディでベースライン応答を取り、
  2. 特権フィールド（一意なセンチネル値つき）を足したボディを送り、
  3. センチネル値がベースラインに無く汚染応答に現れたら過剰割り当てと判定。

検知判定は純粋関数（``augment_body`` / ``detect_mass_assignment``）に切り出す。
"""
from __future__ import annotations

import json
import secrets
import time
from contextlib import nullcontext
from typing import Optional, TYPE_CHECKING

import httpx

from wscan.probe_ledger import Transport
from wscan.request_logger import _redact_headers, redact_text, redact_url

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding, merge_template_headers


def _redact_finding_request(url, method, body, headers):
    return {"url": redact_url(url), "method": method, "body": redact_text(body),
            "headers": _redact_headers(dict(headers or {}))}


if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# 攻撃者が握れてはいけない特権/機微プロパティ名
PRIVILEGED_FIELDS = (
    "role", "roles", "is_admin", "isAdmin", "admin", "is_staff",
    "is_superuser", "superuser", "verified", "is_verified", "email_verified",
    "active", "is_active", "approved", "permissions", "scope", "scopes",
    "group", "groups", "account_type", "plan", "premium", "balance",
    "credit", "account_balance", "price", "discount",
)


def make_sentinels(fields=PRIVILEGED_FIELDS) -> dict[str, str]:
    """各特権フィールドに一意なセンチネル値を割り当てる（純粋）。

    値を一意にすることで、応答に現れた値がどのフィールド由来か特定でき、
    かつ偶然の一致による誤検知を避けられる。
    """
    token = secrets.token_hex(4)
    return {f: f"wscanMA{token}{i}" for i, f in enumerate(fields)}


def injectable_sentinels(
    base_body: Optional[dict], sentinels: dict[str, str]
) -> dict[str, str]:
    """ベースボディに**無い**特権フィールドだけを残す（純粋）。

    テンプレートが既に ``role``/``isAdmin`` 等を文書化している（＝契約上クライアントが
    送れる）場合、その値を sentinel で上書きして 2xx エコーを「過剰割り当て」と誤検知
    してしまう。文書化済みフィールドは対象外にし、未文書のものだけを注入する。
    """
    base = base_body or {}
    return {k: v for k, v in sentinels.items() if k not in base}


def augment_body(base_body: Optional[dict], sentinels: dict[str, str]) -> dict:
    """ベースボディに特権フィールド（センチネル値）を足した dict を返す（純粋）。

    既に base にあるキーは上書きしない（文書化済みフィールドの保護）。注入対象の
    絞り込みは :func:`injectable_sentinels` で行い、本関数は冪等な合成に徹する。
    """
    out = dict(base_body or {})
    for field_name, value in sentinels.items():
        if field_name in out:
            continue
        out[field_name] = value
    return out


def acceptance_ok(status: int) -> bool:
    """更新が「受理された」とみなせる HTTP ステータスか（純粋）。

    API は 400/422 等のバリデーションエラーでも送信 JSON をそのままエコーする
    ことが多く、その場合 sentinel が応答に現れても特権フィールドは *拒否* されて
    いる。受理（2xx）でないレスポンスは過剰割り当ての証拠にしない（誤検知抑止）。
    """
    return 200 <= int(status) < 300


def detect_mass_assignment(
    baseline_body: str,
    polluted_body: str,
    sentinels: dict[str, str],
) -> Optional[tuple[str, str]]:
    """過剰割り当ての証拠を探す（純粋）。

    センチネル値が汚染応答に現れ、ベースライン応答には無いものを 1 件返す
    （``(field_name, value)``）。無ければ None。ベースラインにも在る値は
    単なる入力反射として除外する（誤検知抑止）。
    """
    base = baseline_body or ""
    polluted = polluted_body or ""
    for field_name, value in sentinels.items():
        if value in polluted and value not in base:
            return field_name, value
    return None


class MassAssignmentScanner(BaseScanner):
    """Mass Assignment（過剰割り当て）スキャナ。API スペック由来の JSON 操作を検査。"""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "mass_assignment"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.OBJECT}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.STRUCTURED}),
                structured_payload=True,
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="API spec 由来 JSON body 特化",
            ),
        ),
        prerequisites=frozenset({Prerequisite.API_SPEC}),
        state_change=StateChangeClass.ALWAYS,
        cost=CostClass.HIGH,
    )

    ALWAYS_STATE_CHANGING = True
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """渡された ``url`` に一致する API テンプレート（JSON 操作）だけを検査する。

        以前は全テンプレートを一括検査して ``_done`` を立てていたが、エンジンは
        テンプレート URL ごとに ``scan_page`` を呼び `(url, check)` 単位で
        チェックポイントを刻む。URL でフィルタしないと、resume 時に未マークの URL を
        処理する際へ全テンプレート（状態変更系 POST/PUT/PATCH 含む）を再送して
        しまう。URL 一致のテンプレートのみを対象にして冪等性と再開整合性を保つ。
        """
        templates = [
            t for t in (getattr(self.engine, "api_seed_requests", []) or [])
            if getattr(t, "url", None) == url
            and (getattr(t, "method", "GET") or "GET").upper() in ("POST", "PUT", "PATCH")
        ]
        if not templates:
            return []

        if self.monitor:
            await self.monitor.emit_status(
                f"Mass assignment check on {len(templates)} API operation(s) for {url}"
            )

        findings: list[Finding] = []
        for tmpl in templates:
            f = await self._test_template(tmpl)
            if f:
                findings.append(f)
        return findings

    def _client_kwargs(self, content_type: str, url: str) -> dict:
        hdrs: dict = {"Content-Type": content_type}
        if hasattr(self.engine, "auth_headers"):
            base = self.auth_headers_for_url(url)
            base.update(hdrs)
            hdrs = base
        kwargs: dict = {"timeout": getattr(self.engine, "timeout", 15),
                        "follow_redirects": True, "headers": hdrs}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif getattr(self.engine, "proxy", ""):
            kwargs["proxy"] = self.engine.proxy
        return kwargs

    def _evidence_gap(self, reason: str) -> None:
        try:
            self._record_scan_note(reason)
        except Exception:
            pass
        ledger = getattr(getattr(self.engine, "request_logger", None), "probe_ledger", None)
        try:
            if ledger is not None:
                ledger.manifest.note_gap(reason)
        except Exception:
            pass

    def _observe_response(self, context, response) -> None:
        logger = getattr(self.engine, "request_logger", None)
        if logger is None:
            return
        try:
            owner, request_id = response.request.extensions.get("vulix_probe_submission", (None, None))
            bound = response.request.extensions.get("vulix_probe_context")
            if owner is not logger or not request_id or bound is None:
                self._evidence_gap("mass_assignment_request_missing")
                return
            bound_context, request = bound
            pair = {"request": request, "response": {"status": response.status_code,
                    "url": str(response.url), "headers": _redact_headers(dict(response.headers)),
                    "body": response.content, "timestamp": time.time()}}
            # Baselines must be completed evidence too; their own reference makes the
            # observation locally valid without claiming a detector decision.
            observation = logger.scoped_probe(bound_context, pair=pair, transport=Transport.HTTPX,
                sent=True, parent_id=request_id, request_attempt_id=request_id,
                record_kind="observation", outcome=None,
                rationale="baseline response recorded for comparison")
            if observation:
                bound_context.setdefault("observations", {})[request_id] = observation
                context["observations"] = bound_context["observations"]
                context["request_id"] = request_id
            else:
                self._evidence_gap("mass_assignment_observation_missing")
        except Exception as exc:
            self._evidence_gap(f"mass_assignment_observation_error:{type(exc).__name__}")

    def _evidence_decision(self, context, outcome, rationale) -> None:
        logger = getattr(self.engine, "request_logger", None)
        if not callable(getattr(logger, "scoped_probe", None)):
            return
        try:
            requests = context.get("requests", [])
            if not requests:
                self._evidence_gap("mass_assignment_request_missing")
                return
            attempt = requests[-1]
            parent = context.get("observations", {}).get(attempt, attempt)
            result = logger.scoped_probe(context, record_kind="decision", outcome=outcome,
                parent_id=parent, request_attempt_id=attempt,
                decision_rule="mass_assignment_reflection", decision_version="1", rationale=rationale)
            if not result:
                self._evidence_gap("mass_assignment_decision_missing")
        except Exception as exc:
            self._evidence_gap(f"mass_assignment_decision_error:{type(exc).__name__}")

    def _response_observation(self, response) -> None:
        self._record_probe_status(response)

    async def _test_template(self, tmpl) -> Optional[Finding]:
        sentinels = make_sentinels()
        base_body = tmpl.json_body if isinstance(tmpl.json_body, dict) else {}
        # 文書化済み（base に既出）の特権フィールドは対象外。未文書のものだけ注入し、
        # 検出も注入したフィールドに限定する（契約上のフィールドの 2xx エコーを誤検知
        # しない）。注入できるものが無ければこのテンプレートはスキップ。
        sentinels = injectable_sentinels(base_body, sentinels)
        if not sentinels:
            return None
        polluted = augment_body(base_body, sentinels)
        kwargs = self._client_kwargs(
            getattr(tmpl, "content_type", "application/json"),
            tmpl.url,
        )
        # スペックで宣言された必須ヘッダ（X-API-Version/tenant 等）を載せる。欠落すると
        # 400/401/404 で検査が空振りするため。ただし認証情報ヘッダ（Authorization/
        # API-key）は利用者の --header / 更新トークン（auth_headers 由来）を spec の
        # example/default で上書きしない（merge_template_headers が保護）。
        tmpl_headers = getattr(tmpl, "headers", None)
        if isinstance(tmpl_headers, dict) and tmpl_headers:
            kwargs["headers"] = merge_template_headers(
                kwargs.get("headers", {}), tmpl_headers
            )
        method = (tmpl.method or "POST").upper()

        baseline_payload = json.dumps(base_body)
        polluted_payload = json.dumps(polluted)
        await self.log_payload_test("(JSON body)", polluted_payload, "mass_assignment", tmpl.url)

        logger = getattr(self.engine, "request_logger", None)
        if getattr(logger, "enabled", False) and callable(getattr(logger, "log_httpx_submission", None)):
            hooks = dict(kwargs.get("event_hooks") or {})
            hooks["request"] = [*hooks.get("request", []), logger.log_httpx_submission]
            kwargs["event_hooks"] = hooks
        if logger is None or not getattr(logger, "enabled", False):
            self._evidence_gap("mass_assignment_evidence_unavailable")

        try:
            async with httpx.AsyncClient(**kwargs) as client:
                scope = (logger.probe_scope(None, self.CHECK_TYPE, role="baseline", transport=Transport.HTTPX)
                         if getattr(logger, "enabled", False) and callable(getattr(logger, "probe_scope", None)) else nullcontext({"requests": []}))
                with scope as baseline_context:
                    try:
                        baseline = await client.request(method, tmpl.url, content=baseline_payload)
                    except Exception as exc:
                        self._evidence_decision(baseline_context,
                            "timeout" if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else "transport_error",
                            type(exc).__name__)
                        raise
                    self._response_observation(baseline)
                    self._observe_response(baseline_context, baseline)
                baseline_ids = tuple(baseline_context.get("requests", []))
                scope = (logger.probe_scope(None, self.CHECK_TYPE, role="attack",
                            baseline_attempt_ids=baseline_ids, transport=Transport.HTTPX)
                         if getattr(logger, "enabled", False) and callable(getattr(logger, "probe_scope", None)) else nullcontext({"requests": []}))
                with scope as attack_context:
                    try:
                        tainted = await client.request(method, tmpl.url, content=polluted_payload)
                    except Exception as exc:
                        self._evidence_decision(attack_context,
                            "timeout" if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else "transport_error",
                            type(exc).__name__)
                        raise
                    self._response_observation(tainted)
                    self._observe_response(attack_context, tainted)
        except Exception as exc:
            self._evidence_gap(f"mass_assignment_transport_error:{type(exc).__name__}")
            return None

        # 実メソッドの応答で認証失効を検知したらエンジンへ通知する。GET プレフライトでは
        # 検知できない「メソッド限定保護」エンドポイント（GET=404/405, POST=401）で、
        # 失効 cookie のまま検査して空 Finding を「済み」記録するのを防ぐ
        # （_run_api_template_checks が再ログイン+再試行/未マークにする）。
        from wscan import session_guard
        if session_guard.looks_logged_out(
            status=baseline.status_code,
            final_url=str(getattr(baseline, "url", tmpl.url)),
            body=baseline.text,
            login_url=getattr(self.engine, "login_url", ""),
            logged_in_marker=getattr(self.engine, "logged_in_marker", ""),
        ):
            try:
                self.engine._api_auth_failed = True
            except Exception:
                pass
            self._evidence_gap("mass_assignment_session_guard_incomplete")
            return None

        # 受理（2xx）された場合のみ過剰割り当てとみなす。400/422 等の
        # バリデーションエラーで送信 JSON がエコーされただけのケースを除外する。
        if not acceptance_ok(tainted.status_code):
            return None

        hit = detect_mass_assignment(baseline.text, tainted.text, sentinels)
        self._evidence_decision(attack_context, "matched" if hit else "no_match",
                                "privileged sentinel reflected" if hit else "no privileged sentinel reflected")
        if not hit:
            return None
        field_name, value = hit

        return await self.record_finding(
            url=redact_url(tmpl.url),
            field_name=f"(JSON body: {field_name})",
            payload=redact_text(polluted_payload),
            evidence=redact_text((
                f"Mass assignment: the privileged property '{field_name}' was "
                f"accepted and reflected (value '{value}') when added to the "
                f"{method} body of {tmpl.url}, but was absent from the baseline "
                f"response. Clients can set fields they should not control "
                f"(e.g. role/admin/verified/balance)."
            )),
            pair={
                "request": _redact_finding_request(tmpl.url, method, polluted_payload, kwargs.get("headers", {})),
                "response": {"status": tainted.status_code, "url": redact_url(str(tainted.url)),
                             "headers": _redact_headers(dict(tainted.headers)),
                             "body": redact_text(tainted.text[:1000])},
            },
            severity="high",
            confidence="likely",
            evidence_type="mass_assignment",
            evidence_details={"field": field_name, "method": method},
            reproduction_steps=[f"Send {method} to {redact_url(tmpl.url)} with JSON body {redact_text(polluted_payload)}"],
        )
