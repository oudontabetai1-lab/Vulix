"""
CORS Misconfiguration Scanner (V-2)
Detects dangerous Cross-Origin Resource Sharing configurations:
  1. Wildcard ACAO (*) combined with Access-Control-Allow-Credentials: true
  2. Arbitrary Origin reflection — server echoes back whatever Origin header is sent,
     which allows any website to make credentialed cross-origin requests.
"""
import httpx
from typing import TYPE_CHECKING

from wscan.probe_ledger import ProbeOutcome, ProbeRole, Transport
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Canary origin used to test arbitrary-Origin reflection
_CANARY_ORIGIN = "https://evil.wscan-test.example.com"


def _normalize_probe_exception(exc: BaseException) -> ProbeOutcome:
    """Classify request failures without retaining their potentially sensitive messages."""
    if isinstance(exc, httpx.TimeoutException):
        return ProbeOutcome.TIMEOUT
    if isinstance(exc, httpx.TransportError):
        return ProbeOutcome.TRANSPORT_ERROR
    return ProbeOutcome.VERIFICATION_ERROR


class CORSScanner(BaseScanner):
    """CORS misconfiguration scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "cors"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                # scan_page が _get_with_origin() で canary Origin ヘッダを HTTPX 注入し
                # arbitrary Origin reflection を検査するため supported。
                carrier=Carrier.HEADER, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
        ),
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.LOW,
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
        """Check CORS headers on the page response."""
        if url in self._checked_urls:
            return []
        self._checked_urls.add(url)

        if self.monitor:
            await self.monitor.emit_status(f"CORS check on {url}")

        findings = []

        # ── Check 1: wildcard ACAO + credentials ──────────────────────
        pair = self.current_page_pair(url)
        resp_headers = {
            k.lower(): v
            for k, v in pair.get("response", {}).get("headers", {}).items()
        }
        acao = resp_headers.get("access-control-allow-origin", "")
        acac = resp_headers.get("access-control-allow-credentials", "").lower()

        # The passive comparison needs its own decision; an Origin probe cannot prove it ran.
        if pair.get("response", {}).get("status") is not None:
            self._record_probe_evidence(
                role=ProbeRole.ATTACK, transport=Transport.PLAYWRIGHT, check=self.CHECK_TYPE,
                actor=self.__class__.__name__, pair=pair, sent=True,
                outcome=ProbeOutcome.MATCHED if acao == "*" and acac == "true" else ProbeOutcome.NO_MATCH,
                decision_rule="cors_wildcard_credentials", decision_version="1",
                rationale="CORS captured response header comparison completed",
            )

        if acao == "*" and acac == "true":
            finding = await self.record_finding(
                url=url,
                field_name="(CORS response headers)",
                payload="(no payload — header analysis)",
                evidence=(
                    "CORS misconfiguration: Access-Control-Allow-Origin: * combined with "
                    "Access-Control-Allow-Credentials: true. Any origin can make "
                    "credentialed cross-origin requests."
                ),
                pair=pair,
                severity="high",
                confidence="likely",
                evidence_type="cors_wildcard_credentials",
                evidence_details={"acao": acao, "acac": acac},
            )
            findings.append(finding)

        # ── Check 2: arbitrary Origin reflection ──────────────────────
        try:
            req_headers = self._origin_headers(_CANARY_ORIGIN)
            r = await self._get_with_origin(url, _CANARY_ORIGIN)

            reflected_acao = r.headers.get("access-control-allow-origin", "")
            reflected_acac = r.headers.get("access-control-allow-credentials", "").lower()

            matched = reflected_acao == _CANARY_ORIGIN
            self._record_cors_decision(r, url, matched,
                                      ProbeRole.ATTACK, "cors_origin_reflection")
            if matched:
                severity = "critical" if reflected_acac == "true" else "high"
                finding = await self.record_finding(
                    url=url,
                    field_name="(CORS: Origin header)",
                    payload=f"Origin: {_CANARY_ORIGIN}",
                    evidence=(
                        f"CORS arbitrary origin reflection: server responded with "
                        f"Access-Control-Allow-Origin: {reflected_acao}"
                        + (
                            " AND Access-Control-Allow-Credentials: true "
                            "(attacker can exfiltrate authenticated responses)"
                            if reflected_acac == "true"
                            else " (unauthenticated data may be readable cross-origin)"
                        )
                    ),
                    pair={"request": {"url": url, "headers": req_headers},
                          "response": {"status": r.status_code,
                                       "headers": dict(r.headers)}},
                    severity=severity,
                    confidence="likely",
                    evidence_type="cors_origin_reflection",
                    evidence_details={
                        "origin": _CANARY_ORIGIN,
                        "acao": reflected_acao,
                        "acac": reflected_acac,
                    },
                )
                findings.append(finding)

        except Exception as exc:
            self._record_cors_error(exc, url, ProbeRole.ATTACK, "cors_origin_reflection")
            self._record_scan_note(f"probe_error:{self.CHECK_TYPE}:{type(exc).__name__}")
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] cors: arbitrary-origin probe failed on {url}: {exc}"
                )

        return findings

    async def _get_with_origin(self, url: str, origin: str):
        proxy = getattr(self.engine, "proxy", "") or None
        headers = self._origin_headers(origin)
        if hasattr(self.engine, "auth_headers"):
            base = self.auth_headers_for_url(url)
            base.update(headers)
            headers = base
        kwargs: dict = {
            "headers": headers,
            "timeout": getattr(self.engine, "timeout", 15),
            "follow_redirects": True,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        elif proxy:
            kwargs["proxy"] = proxy

        async with httpx.AsyncClient(**kwargs) as client:
            response = await client.get(url)
            self._record_probe_status(response)
        return response

    def _origin_headers(self, origin: str) -> dict:
        return {
            "Origin": origin,
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        }

    def _record_cors_decision(self, response, url: str, matched: bool,
                              role: ProbeRole, rule: str) -> None:
        try:
            logger = getattr(self.engine, "request_logger", None)
            owner, parent_id = getattr(response, "extensions", {}).get(
                "vulix_probe_observation", (None, None))
            self._record_probe_evidence(
                role=role, transport=Transport.HTTPX, check=self.CHECK_TYPE,
                actor=self.__class__.__name__, sent=True,
                parent_id=parent_id if owner is logger and parent_id else "",
                pair={"request": {"method": "GET", "url": url},
                      "response": {"status": getattr(response, "status_code", None),
                                   "url": str(getattr(response, "url", url)),
                                   "headers": dict(response.headers)}},
                outcome=ProbeOutcome.MATCHED if matched else ProbeOutcome.NO_MATCH,
                decision_rule=rule, decision_version="1",
                rationale="CORS header comparison completed",
            )
        except Exception as exc:
            self._record_scan_note(f"probe_evidence_error:{type(exc).__name__}")

    def _record_cors_error(self, exc: Exception, url: str, role: ProbeRole, rule: str) -> None:
        request = getattr(exc, "request", None)
        extensions = getattr(request, "extensions", {}) or {}
        owner, parent_id = extensions.get("vulix_probe_submission", (None, None))
        logger = getattr(self.engine, "request_logger", None)
        self._record_probe_evidence(
            role=role, transport=Transport.HTTPX, check=self.CHECK_TYPE,
            actor=self.__class__.__name__, sent=False,
            parent_id=parent_id if owner is logger and parent_id else "",
            pair={"request": {"method": getattr(request, "method", "GET"),
                              "url": str(getattr(request, "url", url)),
                              "headers": dict(getattr(request, "headers", {}))}},
            outcome=_normalize_probe_exception(exc), decision_rule=rule,
            decision_version="1", rationale="probe request failed before response",
        )

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        if finding.evidence_type == "cors_wildcard_credentials":
            try:
                r = await self._get_with_origin(finding.url, _CANARY_ORIGIN)
            except Exception as exc:
                self._record_cors_error(exc, finding.url, ProbeRole.VERIFY,
                                        "cors_wildcard_credentials")
                self._record_scan_note(f"verification_error:{self.CHECK_TYPE}:{type(exc).__name__}")
                return None
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            matched = acao == "*" and acac == "true"
            self._record_cors_decision(r, finding.url, matched, ProbeRole.VERIFY,
                                      "cors_wildcard_credentials")
            return matched

        if finding.evidence_type == "cors_origin_reflection":
            origin = details.get("origin") or _CANARY_ORIGIN
            try:
                r = await self._get_with_origin(finding.url, origin)
            except Exception as exc:
                self._record_cors_error(exc, finding.url, ProbeRole.VERIFY,
                                        "cors_origin_reflection")
                self._record_scan_note(f"verification_error:{self.CHECK_TYPE}:{type(exc).__name__}")
                return None
            acao = r.headers.get("access-control-allow-origin", "")
            acac = r.headers.get("access-control-allow-credentials", "").lower()
            expected_acac = details.get("acac", "")
            matched = acao == origin and (not expected_acac or acac == expected_acac)
            self._record_cors_decision(r, finding.url, matched, ProbeRole.VERIFY,
                                      "cors_origin_reflection")
            return matched

        return None
