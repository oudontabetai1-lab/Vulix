"""
Web Cache Poisoning / Deception Scanner（新クラス）
==================================================
CDN/リバースプロキシキャッシュ前提の現代 Web 向け。

  1. Cache Poisoning: キャッシュキーに含まれない「unkeyed」入力
     （``X-Forwarded-Host`` 等）が応答に反射し、かつ応答がキャッシュ可能なとき、
     攻撃者が汚染レスポンスを他ユーザに配らせられる。**自分専用のキャッシュ
     バスター付き URL** で検査し、本番キャッシュを汚さない。
  2. Cache Deception: ``/account`` を ``/account/nonexistent.css`` のように
     静的拡張子付きで要求すると、動的（認証済み）コンテンツがキャッシュ可能と
     して返るパターン。攻撃者が被害者の機微情報をキャッシュに載せ取得できる。

検知判定はすべて純粋関数（``is_cacheable`` / ``cache_hit`` / ``reflected`` /
``UNKEYED_HEADERS``）に切り出してテストする。
"""
from __future__ import annotations

import secrets
import time
from contextlib import nullcontext
from typing import TYPE_CHECKING
from urllib.parse import urlparse, urlunparse

import httpx

from wscan.probe_ledger import Transport
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine


# 試行する unkeyed ヘッダ候補（ヘッダ名 → 注入する値の組み立て関数の素）。
# 値にはマーカーを含め、応答本文での反射を観測する。
UNKEYED_HEADERS = (
    "X-Forwarded-Host",
    "X-Forwarded-Scheme",
    "X-Forwarded-Server",
    "X-Host",
    "X-Forwarded-Port",
    "X-Original-Url",
)

# 静的アセットに見せかけるための拡張子（Cache Deception 用）
_DECEPTION_EXTENSIONS = (".css", ".js", ".png", ".ico")


def is_cacheable(headers: dict) -> bool:
    """応答ヘッダがキャッシュ可能を示すか（純粋）。

    ``Cache-Control: no-store/no-cache/private`` があれば不可。``public`` または
    正の ``max-age``/``s-maxage``、あるいは CDN のキャッシュ印（Age / X-Cache /
    CF-Cache-Status）があれば可とみなす。
    """
    low = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    cc = low.get("cache-control", "").lower()
    if any(tok in cc for tok in ("no-store", "no-cache", "private")):
        return False
    if "public" in cc:
        return True
    for directive in ("s-maxage", "max-age"):
        if directive in cc:
            # max-age=0 はキャッシュ不可寄り
            try:
                val = cc.split(directive + "=", 1)[1].split(",")[0].strip()
                if int(val) > 0:
                    return True
            except (IndexError, ValueError):
                pass
    if cache_hit(low):
        return True
    return False


def cache_hit(headers: dict) -> bool:
    """応答がキャッシュから返ったことを示す印があるか（純粋）。"""
    low = {str(k).lower(): str(v).lower() for k, v in (headers or {}).items()}
    if "hit" in low.get("x-cache", ""):
        return True
    if "hit" in low.get("cf-cache-status", ""):
        return True
    if "hit" in low.get("x-cache-status", ""):
        return True
    age = low.get("age", "")
    try:
        if int(age) > 0:
            return True
    except ValueError:
        pass
    return False


def reflected(body: str, marker: str) -> bool:
    """マーカー（注入したホスト名等）が本文に反射しているか（純粋）。"""
    return bool(marker) and marker in (body or "")


def deception_succeeded(
    *,
    base_status: int,
    base_body: str,
    css_status: int,
    css_body: str,
    css_headers: dict,
) -> bool:
    """静的拡張子付き URL が動的コンテンツをキャッシュ可能に返したか（純粋）。

    条件: ``.css`` 版が 200 で、ベース動的ページと実質同一の本文を返し、かつ
    キャッシュ可能。404/別物を返すなら安全（誤検知抑止）。
    """
    if css_status != 200 or base_status != 200:
        return False
    if not css_body or not base_body:
        return False
    # 本文がベースと十分似ている（同じ動的ページがキャッシュ拡張子で出た）
    if not _bodies_similar(base_body, css_body):
        return False
    return is_cacheable(css_headers)


def _build_deception_url(parsed, suffix: str) -> str:
    """パス末尾に静的拡張子付きセグメントを足した URL を組む（純粋）。

    クエリ文字列は保持したまま、suffix はパス側にだけ付与する
    （例: ``/account?tab=1`` → ``/account/wscanXXX.css?tab=1``）。
    """
    base_path = (parsed.path or "/").rstrip("/")
    new_path = f"{base_path}/{suffix}"
    return urlunparse((
        parsed.scheme, parsed.netloc, new_path,
        parsed.params, parsed.query, "",
    ))


def _bodies_similar(a: str, b: str, threshold: float = 0.9) -> bool:
    """長さベースの粗い類似判定（純粋・高速）。完全一致でなくてもよい。"""
    if a == b:
        return True
    la, lb = len(a), len(b)
    if la == 0 or lb == 0:
        return False
    ratio = min(la, lb) / max(la, lb)
    if ratio < threshold:
        return False
    # 先頭/末尾の一致でテンプレ流用を確認
    head = min(200, la, lb)
    return a[:head] == b[:head]


class CachePoisoningScanner(BaseScanner):
    """Web Cache Poisoning / Deception スキャナ。"""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "cache_poisoning"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="cache header/path probe 以外は注入しない",
            ),
        ),
        state_change=StateChangeClass.CONDITIONAL,
        cost=CostClass.HIGH,
    )

    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        findings: list[Finding] = []
        if self.monitor:
            await self.monitor.emit_status(f"Cache poisoning check on {url}")

        findings += await self._scan_poisoning(url)
        findings += await self._scan_deception(url)
        return findings

    def _client_kwargs(self) -> dict:
        kwargs: dict = {"timeout": getattr(self.engine, "timeout", 15),
                        "follow_redirects": False}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif getattr(self.engine, "proxy", ""):
            kwargs["proxy"] = self.engine.proxy
        logger = getattr(self.engine, "request_logger", None)
        if getattr(logger, "enabled", False) and callable(getattr(logger, "log_httpx_submission", None)):
            kwargs["event_hooks"] = {"request": [logger.log_httpx_submission]}
        return kwargs

    def _evidence_gap(self, reason: str) -> None:
        self._record_scan_note(reason)
        logger = getattr(self.engine, "request_logger", None)
        ledger = getattr(logger, "probe_ledger", None)
        if ledger is not None:
            ledger.manifest.note_gap(reason)

    def _evidence_scope(self, role, *, baselines=(), parent_id=""):
        logger = getattr(self.engine, "request_logger", None)
        scope = (logger.probe_scope(None, self.CHECK_TYPE, role=role,
                                   baseline_attempt_ids=baselines, parent_id=parent_id)
                 if callable(getattr(logger, "probe_scope", None))
                 else nullcontext({"requests": []}))
        if logger is None or not getattr(logger, "enabled", False):
            self._evidence_gap(f"{self.CHECK_TYPE}_evidence_unavailable")

        class _ScopeContextManager:
            def __enter__(_self):
                _self.context = scope.__enter__()
                return _self.context

            def __exit__(_self, exc_type, exc, tb):
                try:
                    if exc is not None:
                        outcome = ("timeout" if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else
                                   "transport_error" if isinstance(exc, (httpx.TransportError, OSError)) else
                                   "verification_error" if role == "verify" else "unexecutable")
                        self._evidence_decision(_self.context, outcome, f"{self.CHECK_TYPE}_transport", type(exc).__name__)
                finally:
                    return scope.__exit__(exc_type, exc, tb)

        return _ScopeContextManager()

    def _observe_response(self, response) -> None:
        logger = getattr(self.engine, "request_logger", None)
        if logger is None:
            return
        try:
            owner, request_id = response.request.extensions.get("vulix_probe_submission", (None, None))
            bound = response.request.extensions.get("vulix_probe_context")
            if owner is not logger or not request_id or bound is None:
                self._evidence_gap(f"{self.CHECK_TYPE}_request_missing")
                return
            context, request = bound
            pair = {"request": request, "response": {
                "status": response.status_code, "url": str(response.url),
                "headers": dict(response.headers), "body": response.content, "timestamp": time.time()}}
            if context["role"] == "baseline":
                observation = logger.scoped_probe(context, pair=pair, transport=Transport.HTTPX,
                    sent=True, parent_id=request_id, request_attempt_id=request_id,
                    record_kind="observation", outcome=None,
                    decision_rule="cache_deception_baseline", decision_version="1",
                    rationale="baseline response received; comparison measurement only")
            else:
                observation = logger.observe_request(context, request_id, pair, Transport.HTTPX)
            if observation:
                context.setdefault("observations", {})[request_id] = observation
            else:
                self._evidence_gap(f"{self.CHECK_TYPE}_observation_missing")
        except Exception as exc:
            self._evidence_gap(f"{self.CHECK_TYPE}_observation_error:{type(exc).__name__}")

    def _evidence_decision(self, context, outcome, rule, rationale):
        logger = getattr(self.engine, "request_logger", None)
        if not callable(getattr(logger, "scoped_probe", None)):
            return
        try:
            requests = context.get("requests", [])
            if not requests:
                self._evidence_gap(f"{self.CHECK_TYPE}_request_missing")
                return
            for request_id in requests:
                parent = context.get("observations", {}).get(request_id, request_id)
                if not logger.scoped_probe(context, record_kind="decision", outcome=outcome,
                        parent_id=parent, request_attempt_id=request_id, decision_rule=rule,
                        decision_version="1", rationale=rationale):
                    self._evidence_gap(f"{self.CHECK_TYPE}_decision_missing")
        except Exception as exc:
            self._evidence_gap(f"{self.CHECK_TYPE}_decision_error:{type(exc).__name__}")

    def _auth_headers(self, url: str) -> dict:
        if hasattr(self.engine, "auth_headers"):
            return dict(self.auth_headers_for_url(url))
        return {}

    async def _scan_poisoning(self, url: str) -> list[Finding]:
        findings: list[Finding] = []
        sep = "&" if "?" in url else "?"
        marker_host = f"wscan{secrets.token_hex(4)}.example.com"

        for header in UNKEYED_HEADERS:
            # ヘッダごとに固有の cache-buster を使う。共通 URL だと最初の試行が
            # （当該ヘッダが反射しなくても）キャッシュを温め、後続ヘッダが
            # キャッシュから返って X-Host 等の脆弱性を取りこぼす。
            cb = secrets.token_hex(6)
            probe_url = f"{url}{sep}cb={cb}"
            inj_headers = self._auth_headers(probe_url)
            inj_headers[header] = marker_host
            await self.log_payload_test(
                f"(header) {header}", marker_host, "cache_poisoning", url
            )
            try:
                with self._evidence_scope("attack") as attack_ctx:
                    async with httpx.AsyncClient(**self._client_kwargs()) as client:
                        poisoned = await client.get(probe_url, headers=inj_headers)
                        self._record_probe_status(poisoned)
                    self._observe_response(poisoned)
                    is_refl = reflected(poisoned.text, marker_host)
                    is_cache = is_cacheable(dict(poisoned.headers))
                    matched = is_refl and is_cache
                    self._evidence_decision(
                        attack_ctx,
                        "matched" if matched else "no_match",
                        "cache_poisoning_reflection",
                        f"status {poisoned.status_code}; reflected={is_refl}; cacheable={is_cache}",
                    )
            except Exception:
                continue

            if not reflected(poisoned.text, marker_host):
                continue
            if not is_cacheable(dict(poisoned.headers)):
                continue

            attack_attempt_id = (attack_ctx.get("requests", []) or [None])[-1]
            baselines = (attack_attempt_id,) if attack_attempt_id else ()

            # 反射 + キャッシュ可能。クリーン再取得で汚染が残るか確認。
            confirmed = False
            try:
                with self._evidence_scope("verify", baselines=baselines) as verify_ctx:
                    async with httpx.AsyncClient(**self._client_kwargs()) as client:
                        clean = await client.get(
                            probe_url,
                            headers=self._auth_headers(probe_url),
                        )
                        self._record_probe_status(clean)
                    self._observe_response(clean)
                    confirmed = reflected(clean.text, marker_host) and cache_hit(
                        dict(clean.headers)
                    )
                    self._evidence_decision(
                        verify_ctx,
                        "matched" if confirmed else "no_match",
                        "cache_poisoning_persistence",
                        f"status {clean.status_code}; persisted={confirmed}",
                    )
            except Exception:
                confirmed = False

            finding = await self.record_finding(
                url=url,
                field_name=f"(unkeyed header: {header})",
                payload=f"{header}: {marker_host}",
                evidence=(
                    f"Web cache poisoning: unkeyed request header '{header}' was "
                    f"reflected in a cacheable response"
                    + (
                        " and persisted on a clean cache-hit request "
                        "(confirmed poisoning)."
                        if confirmed
                        else " (response is cacheable; poisoning likely)."
                    )
                    + " An attacker can poison the shared cache so other users "
                    "receive attacker-controlled content."
                ),
                pair={
                    "request": {"url": probe_url, "headers": {header: marker_host}},
                    "response": {"status": poisoned.status_code,
                                 "headers": dict(poisoned.headers)},
                },
                severity="high",
                confidence="confirmed" if confirmed else "tentative",
                evidence_type="cache_poisoning",
                evidence_details={"header": header, "marker": marker_host,
                                  "persisted": confirmed},
            )
            if finding:
                findings.append(finding)
            break  # 1 ヘッダ確認できれば十分
        return findings

    async def _scan_deception(self, url: str) -> list[Finding]:
        parsed = urlparse(url)
        # ルートや既に拡張子付きの URL は対象外（動的パスのみ）
        path = parsed.path or "/"
        if path.endswith(_DECEPTION_EXTENSIONS) or path in ("", "/"):
            return []

        ext = _DECEPTION_EXTENSIONS[0]
        # 静的拡張子はパス末尾に付ける。クエリ付き URL に生のまま付けると
        # "/account?tab=1/x.css" のようにクエリ値へ紛れ込むため、パスとクエリを
        # 分けて "/account/x.css?tab=1" を組み立てる。
        css_url = _build_deception_url(parsed, f"wscan{secrets.token_hex(3)}{ext}")
        # プローブ送信「前」に log_payload_test を通す。これは監査記録であると同時に
        # abort チェックポイントも兼ねる（BaseScanner.log_payload_test）。送信後に呼ぶと
        # abort が「送信済みプローブの評価をスキップ」する形になり resume で再送になるため、
        # 送信前に置いて真の pre-send チェックポイントにする。
        await self.log_payload_test("(path)", css_url, "cache_deception", url)
        try:
            with self._evidence_scope("baseline") as base_ctx:
                async with httpx.AsyncClient(**self._client_kwargs()) as client:
                    base = await client.get(url, headers=self._auth_headers(url))
                    self._record_probe_status(base)
                self._observe_response(base)

            base_attempt_id = (base_ctx.get("requests", []) or [None])[-1]
            baselines = (base_attempt_id,) if base_attempt_id else ()

            with self._evidence_scope("attack", baselines=baselines) as attack_ctx:
                async with httpx.AsyncClient(**self._client_kwargs()) as client:
                    css = await client.get(
                        css_url,
                        headers=self._auth_headers(css_url),
                    )
                    self._record_probe_status(css)
                self._observe_response(css)
                succeeded = deception_succeeded(
                    base_status=base.status_code,
                    base_body=base.text,
                    css_status=css.status_code,
                    css_body=css.text,
                    css_headers=dict(css.headers),
                )
                self._evidence_decision(
                    attack_ctx,
                    "matched" if succeeded else "no_match",
                    "cache_deception_match",
                    f"base_status={base.status_code}; css_status={css.status_code}; succeeded={succeeded}",
                )
        except Exception:
            return []

        if not deception_succeeded(
            base_status=base.status_code,
            base_body=base.text,
            css_status=css.status_code,
            css_body=css.text,
            css_headers=dict(css.headers),
        ):
            return []

        finding = await self.record_finding(
            url=url,
            field_name="(path — cache deception)",
            payload=css_url,
            evidence=(
                f"Web cache deception: requesting '{css_url}' returned the same "
                f"dynamic content as '{url}' but with a cacheable response. An "
                f"attacker can trick a victim into caching their authenticated "
                f"page under a static-looking URL, then retrieve it."
            ),
            pair={
                "request": {"url": css_url},
                "response": {"status": css.status_code, "headers": dict(css.headers)},
            },
            severity="high",
            confidence="likely",
            evidence_type="cache_deception",
            evidence_details={"static_url": css_url},
        )
        return [finding] if finding else []
