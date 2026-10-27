"""
HTTP Request Smuggling Scanner (V-9)
Detects potential HTTP request smuggling vulnerabilities by sending
ambiguous Transfer-Encoding / Content-Length headers and observing
timing anomalies or error responses.

Attack types tested:
  CL.TE — frontend uses Content-Length, backend uses Transfer-Encoding
  TE.CL — frontend uses Transfer-Encoding, backend uses Content-Length
  TE.TE — both use Transfer-Encoding but one obfuscates it

NOTE: True request smuggling confirmation requires out-of-band interaction
(e.g. a Burp Collaborator-like callback). This scanner can only detect
indicators such as:
  - Timeout differentials suggesting the backend is waiting for more data
  - Error messages referencing chunked encoding / content-length conflicts
  - HTTP 400 / 505 responses that suggest header parsing disagreement

This scanner operates at the HTTP level (httpx), bypassing Playwright.
"""
from contextlib import contextmanager, nullcontext
import time
from urllib.parse import urlparse
from typing import TYPE_CHECKING

import httpx

from wscan.probe_ledger import Transport
from wscan.request_logger import _redact_headers, current_probe, redact_text, redact_url
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# Error patterns that suggest smuggling-related parsing issues
_SMUGGLE_ERROR_PATTERNS = [
    r"400 Bad Request",
    r"chunked.*content-length",
    r"content-length.*chunked",
    r"invalid chunk",
    r"transfer.encoding.*not.*supported",
    r"request.*too.*large",
    r"invalid.*transfer.encoding",
]

# Timeout differential threshold (seconds) that suggests the backend
# is waiting for more data (indicating TE/CL discrepancy)
_TIMEOUT_DELTA_THRESHOLD = 5.0

_PROBE_DEFINITIONS = {
    "CL.TE": {
        "body": b"0\r\n\r\n",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "6",
            "Transfer-Encoding": "chunked",
        },
    },
    "TE.CL": {
        "body": None,
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": "4",
            "Transfer-Encoding": "chunked",
        },
    },
    "TE.TE (obfuscated)": {
        "body": b"0\r\n\r\n",
        "headers": {
            "Content-Type": "application/x-www-form-urlencoded",
            "Transfer-Encoding": "chunked",
            "Transfer-Encoding ": "xchunked",
        },
    },
}


def _probe_body(probe_name: str) -> bytes:
    if probe_name == "TE.CL":
        chunk = b"POST / HTTP/1.1\r\nHost: localhost\r\nContent-Length: 4\r\n\r\ntest"
        chunk_hex = hex(len(chunk))[2:].encode()
        return chunk_hex + b"\r\n" + chunk + b"\r\n0\r\n\r\n"
    body = _PROBE_DEFINITIONS.get(probe_name, {}).get("body")
    return body if isinstance(body, bytes) else b""


class RequestSmugglingScanner(BaseScanner):
    """HTTP request smuggling detection scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "request_smuggling"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.MULTIPART, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.PLANNED,
                reason="raw path probe は未接続",
                task="0035-D",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="HTTP request framing header 特化",
            ),
        ),
        prerequisites=frozenset({Prerequisite.SECOND_REQUEST}),
        state_change=StateChangeClass.ALWAYS,
        cost=CostClass.HIGH,
    )

    ALWAYS_STATE_CHANGING = True
    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_hosts: set[str] = set()

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        """Run smuggling probes once per host."""
        parsed = urlparse(url)
        host = parsed.netloc
        if host in self._checked_hosts:
            return []
        self._checked_hosts.add(host)

        if self.monitor:
            await self.monitor.emit_status(f"Request smuggling probe on {host}")

        findings = []
        findings += await self._probe_cl_te(url)
        findings += await self._probe_te_cl(url)
        findings += await self._probe_te_te(url)
        return findings

    # ------------------------------------------------------------------

    async def _probe_cl_te(self, url: str) -> list[Finding]:
        """
        CL.TE probe: send a request where Content-Length says body is 6 bytes,
        but the body is actually chunked with an incomplete final chunk.
        A vulnerable backend (that reads by TE) will hang waiting for the
        0-length terminating chunk, causing a timeout differential.
        """
        probe_name = "CL.TE"
        return await self._time_probe(
            url,
            dict(_PROBE_DEFINITIONS[probe_name]["headers"]),
            _probe_body(probe_name),
            probe_name,
        )

    async def _probe_te_cl(self, url: str) -> list[Finding]:
        """
        TE.CL probe: send a valid chunked body but set Content-Length to a
        smaller value. A backend reading by CL will process only part of the
        chunked body, potentially treating the remainder as a new request.
        """
        probe_name = "TE.CL"
        return await self._time_probe(
            url,
            dict(_PROBE_DEFINITIONS[probe_name]["headers"]),
            _probe_body(probe_name),
            probe_name,
        )

    async def _probe_te_te(self, url: str) -> list[Finding]:
        """
        TE.TE probe: send obfuscated Transfer-Encoding headers.
        If one server accepts "chunked" and another accepts "xchunked",
        they will disagree on how to parse the body.
        """
        probe_name = "TE.TE (obfuscated)"
        return await self._time_probe(
            url,
            dict(_PROBE_DEFINITIONS[probe_name]["headers"]),
            _probe_body(probe_name),
            probe_name,
        )

    def _client(self, timeout: float, proxy: str | None) -> httpx.AsyncClient:
        kwargs = dict(timeout=timeout, follow_redirects=False,
                      **({"proxy": proxy} if proxy else {}))
        logger = getattr(self.engine, "request_logger", None)
        if callable(getattr(logger, "log_httpx_submission", None)):
            # Capture the body after get/post returns, rather than a header-only response hook.
            kwargs["event_hooks"] = {"request": [logger.log_httpx_submission]}
        return httpx.AsyncClient(**kwargs)

    def _evidence_gap(self, reason: str) -> None:
        self._record_scan_note(reason)
        logger = getattr(self.engine, "request_logger", None)
        ledger = getattr(logger, "probe_ledger", None)
        if ledger is not None:
            ledger.manifest.note_gap(reason)

    @contextmanager
    def _evidence_scope(self, role, *, baselines=(), parent_id=""):
        logger = getattr(self.engine, "request_logger", None)
        scope = (logger.probe_scope(None, self.CHECK_TYPE, role=role,
                                   baseline_attempt_ids=baselines, parent_id=parent_id)
                 if callable(getattr(logger, "probe_scope", None))
                 else nullcontext({"requests": []}))
        if logger is None or not getattr(logger, "enabled", False):
            self._evidence_gap("request_smuggling_evidence_unavailable")
        with scope as context:
            try:
                yield context
            except Exception as exc:
                outcome = ("timeout" if isinstance(exc, (httpx.TimeoutException, TimeoutError)) else
                           "transport_error" if isinstance(exc, (httpx.TransportError, OSError)) else
                           "verification_error" if role == "verify" else "unexecutable")
                self._evidence_decision(context, outcome, "request_smuggling_transport", type(exc).__name__)
                raise

    def _observe_response(self, response) -> None:
        logger = getattr(self.engine, "request_logger", None)
        if logger is None:
            return
        try:
            owner, request_id = response.request.extensions.get("vulix_probe_submission", (None, None))
            bound = response.request.extensions.get("vulix_probe_context")
            if owner is not logger or not request_id or bound is None:
                self._evidence_gap("request_smuggling_request_missing")
                return
            context, request = bound
            pair = {"request": request, "response": {
                "status": response.status_code, "url": str(response.url),
                "headers": dict(response.headers), "body": response.content, "timestamp": time.time()}}
            if context["role"] == "baseline":
                # A baseline measurement terminates here; it is not an attack comparison decision.
                observation = logger.scoped_probe(context, pair=pair, transport=Transport.HTTPX,
                    sent=True, parent_id=request_id, request_attempt_id=request_id,
                    record_kind="observation", outcome=None,
                    decision_rule="request_smuggling_baseline", decision_version="1",
                    rationale="baseline response received; comparison measurement only")
            else:
                observation = logger.observe_request(context, request_id, pair, Transport.HTTPX)
            if observation:
                context.setdefault("observations", {})[request_id] = observation
            else:
                self._evidence_gap("request_smuggling_observation_missing")
        except Exception as exc:
            self._evidence_gap(f"request_smuggling_observation_error:{type(exc).__name__}")

    def _evidence_decision(self, context, outcome, rule, rationale):
        logger = getattr(self.engine, "request_logger", None)
        if not callable(getattr(logger, "scoped_probe", None)):
            return
        try:
            requests = context["requests"]
            if not requests:
                self._evidence_gap("request_smuggling_request_missing")
                return
            for request_id in requests:
                parent = context.get("observations", {}).get(request_id, request_id)
                if not logger.scoped_probe(context, record_kind="decision", outcome=outcome,
                        parent_id=parent, request_attempt_id=request_id, decision_rule=rule,
                        decision_version="1", rationale=rationale):
                    self._evidence_gap("request_smuggling_decision_missing")
        except Exception as exc:
            self._evidence_gap(f"request_smuggling_decision_error:{type(exc).__name__}")

    async def _measure_normal(self, url: str, timeout: float, proxy: str | None) -> float:
        normal_start = time.monotonic()
        headers = (
            self.auth_headers_for_url(url)
            if hasattr(self.engine, "auth_headers")
            else {}
        )
        async with self._client(timeout, proxy) as client:
            response = await client.get(url, headers=headers)
            self._record_probe_status(response)
        elapsed = time.monotonic() - normal_start
        self._observe_response(response)
        return elapsed

    async def _send_probe(
        self,
        url: str,
        headers: dict,
        body: bytes,
        timeout: float,
        proxy: str | None,
    ) -> tuple[float, str, int]:
        probe_start = time.monotonic()
        try:
            # Merge engine custom headers underneath probe-specific ones so
            # smuggling probes still authenticate against gated endpoints.
            if hasattr(self.engine, "auth_headers"):
                base = self.auth_headers_for_url(url)
                base.update(headers or {})
                headers = base
            async with self._client(timeout, proxy) as client:
                r_probe = await client.post(url, content=body, headers=headers)
            self._record_probe_status(r_probe)
            elapsed = time.monotonic() - probe_start
            self._observe_response(r_probe)
            return elapsed, r_probe.text, r_probe.status_code
        except httpx.ReadTimeout:
            context = current_probe(getattr(self.engine, "request_logger", None))
            if context is not None:
                self._evidence_decision(context, "timeout", "request_smuggling_timeout",
                    "ReadTimeout without response; legacy delay heuristic remains tentative")
            return timeout, "", 0

    def _classify_probe(
        self,
        url: str,
        headers: dict,
        probe_name: str,
        normal_elapsed: float,
        probe_elapsed: float,
        probe_body: str,
        probe_status: int,
    ) -> tuple[str, str, dict, str] | None:
        delta = probe_elapsed - normal_elapsed
        details = {
            "probe_name": probe_name,
            "headers": dict(headers),
            "normal_elapsed": round(normal_elapsed, 4),
            "probe_elapsed": round(probe_elapsed, 4),
            "delta": round(delta, 4),
            **({} if probe_status == 0 else {"probe_status": probe_status}),
        }
        if delta >= _TIMEOUT_DELTA_THRESHOLD or probe_status == 0:
            if probe_status == 0:
                evidence = (
                    f"HTTP Request Smuggling indicator ({probe_name}): "
                    f"probe timed out after {probe_elapsed:.1f}s vs baseline {normal_elapsed:.1f}s "
                    f"(+{delta:.1f}s). Backend may be waiting for more data, "
                    f"suggesting a CL/TE parsing disagreement."
                )
            else:
                evidence = (
                    f"HTTP Request Smuggling indicator ({probe_name}): "
                    f"probe response took {probe_elapsed:.1f}s vs baseline {normal_elapsed:.1f}s "
                    f"(+{delta:.1f}s). Backend may be waiting for more data, "
                    f"suggesting a CL/TE parsing disagreement."
                )
            return "request_smuggling_timing", "high", details, evidence

        err = self.check_response_for_patterns(probe_body, _SMUGGLE_ERROR_PATTERNS)
        if err and probe_status in (400, 501, 505):
            details["matched_error"] = err[:100]
            evidence = (
                f"HTTP Request Smuggling indicator ({probe_name}): "
                f"server returned HTTP {probe_status} with message: '{err[:100]}'. "
                f"This may indicate a proxy/server disagreement on header parsing."
            )
            return "request_smuggling_parser_error", "medium", details, evidence
        return None

    async def _time_probe(
        self,
        url: str,
        headers: dict,
        body: bytes,
        probe_name: str,
    ) -> list[Finding]:
        """Send the probe and measure response time / check for error patterns."""
        proxy = getattr(self.engine, "proxy", "") or None
        base_timeout = min(getattr(self.engine, "timeout", 15), 10)

        try:
            with self._evidence_scope("baseline") as baseline:
                normal_elapsed = await self._measure_normal(url, base_timeout, proxy)
            with self._evidence_scope("attack", baselines=tuple(baseline["requests"])) as attack:
                probe_elapsed, probe_body, probe_status = await self._send_probe(
                    url, headers, body, base_timeout, proxy
                )
                probe_timed_out = probe_status == 0
                classified = self._classify_probe(
                    url, headers, probe_name, normal_elapsed, probe_elapsed, probe_body, probe_status
                )
                if probe_status != 0:
                    self._evidence_decision(attack, "matched" if classified else "no_match",
                        classified[0] if classified else "request_smuggling_oracle",
                        f"response status {probe_status}; elapsed {probe_elapsed:.4f}s vs baseline {normal_elapsed:.4f}s")
            if classified:
                evidence_type, severity, details, evidence = classified
                if attack["requests"]:
                    details["probe_attempt_id"] = attack["requests"][-1]
                    details["attempt_ids"] = baseline["requests"] + attack["requests"]
                if baseline["requests"]:
                    details["baseline_attempt_id"] = baseline["requests"][-1]
                safe_headers = _redact_headers(headers)
                pair = {"request": {"url": redact_url(url), "headers": safe_headers}}
                if not probe_timed_out:
                    pair["response"] = {
                        "status": probe_status,
                        "body": redact_text(probe_body[:500]),
                    }
                safe_details = dict(details)
                if probe_timed_out:
                    safe_details.pop("probe_status", None)
                safe_details["headers"] = safe_headers
                safe_evidence = redact_text(evidence)
                safe_reproduction_steps = [redact_text(step) for step in
                                           self._default_reproduction_steps(url, "(HTTP request headers)", probe_name)]
                finding = await self.record_finding(
                    url=redact_url(url),
                    field_name="(HTTP request headers)",
                    payload=probe_name,
                    evidence=safe_evidence,
                    pair=pair,
                    severity=severity,
                    confidence="tentative",
                    evidence_type=evidence_type,
                    evidence_details=safe_details,
                    reproduction_steps=safe_reproduction_steps,
                )
                return [finding]

        except Exception:
            pass

        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        probe_name = details.get("probe_name") or finding.payload
        if probe_name not in _PROBE_DEFINITIONS:
            return None
        proxy = getattr(self.engine, "proxy", "") or None
        base_timeout = min(getattr(self.engine, "timeout", 15), 10)
        headers = dict(_PROBE_DEFINITIONS[probe_name]["headers"])
        body = _probe_body(probe_name)
        logger = getattr(self.engine, "request_logger", None)
        original_id = details.get("probe_attempt_id", "")
        events = getattr(getattr(logger, "probe_ledger", None), "events", {})
        if original_id not in events:
            original_id = ""
        try:
            with self._evidence_scope("baseline", parent_id=original_id) as baseline:
                normal_elapsed = await self._measure_normal(finding.url, base_timeout, proxy)
            with self._evidence_scope("verify", baselines=tuple(baseline["requests"]),
                                      parent_id=original_id) as verification:
                probe_elapsed, probe_body, probe_status = await self._send_probe(
                    finding.url, headers, body, base_timeout, proxy
                )
        except Exception:
            return None
        classified = self._classify_probe(
            finding.url, headers, probe_name, normal_elapsed, probe_elapsed, probe_body, probe_status
        )
        verified = bool(classified and classified[0] == finding.evidence_type)
        if probe_status != 0:
            self._evidence_decision(verification, "matched" if verified else "no_match",
                finding.evidence_type,
                f"verification response status {probe_status}; elapsed {probe_elapsed:.4f}s vs baseline {normal_elapsed:.4f}s")
        return verified
