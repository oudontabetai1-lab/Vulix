"""Additive, read-only HTTP method and transport security observations."""
from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import secrets
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from wscan import transport_security as rules
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    ScannerContract, StateChangeClass,
)
from wscan.url_scope import origin_string, redact_url, same_origin
from .base import BaseScanner, Finding, PageDocumentUnavailable
from .http_methods import parse_allow_methods, trace_reflection_strength


class TransportSecurityScanner(BaseScanner):
    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "transport_security"
    SEVERITY = "medium"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=tuple(CarrierCapability(
            carrier=c, state=CapabilityState.UNSUPPORTED,
            reason="Read-only method probes and transport observations, no parameter injection",
        ) for c in Carrier),
        state_change=StateChangeClass.READ_ONLY, cost=CostClass.MEDIUM,
    )
    MAX_TARGETS_PER_ORIGIN = 25

    def __init__(self, engine):
        super().__init__(engine)
        self.coverage = []
        self._checked = set()
        self._tls_checked = set()
        self._lock = asyncio.Lock()

    async def scan_field(self, url, form_index, field, is_url_param=False):
        return []

    def _allowed(self, url):
        if urlsplit(url).scheme not in {"http", "https"}:
            return False
        excluded = getattr(self.engine, "_is_url_excluded", None)
        allowed = getattr(self.engine, "_is_access_allowed_url", None)
        return bool(callable(allowed) and allowed(url) and not (callable(excluded) and excluded(url)))

    def _coverage(self, url, unit, status, reason="", details=None):
        row = {"url": redact_url(url, drop_userinfo=True), "unit": unit,
               "status": status, "reason": reason, "details": details or {}}
        if row not in self.coverage:
            self.coverage.append(row)
        if status == "gap":
            self._record_scan_note(f"coverage_gap:{self.CHECK_TYPE}:{unit}:{reason}")

    async def _record(self, url, kind, details, method="GET", status=None,
                      field=None, severity="medium", confidence="likely"):
        display = redact_url(url, drop_userinfo=True)
        return await self.record_finding(
            url=display, field_name=field or f"({kind})", payload=method,
            evidence=f"Observed {kind}; {details.get('summary', 'review transport configuration')}.",
            pair={"request": {"url": display, "method": method},
                  "response": {"status": status, "body": "[Response omitted to protect secrets]"}},
            screenshot_b64="", severity=severity, confidence=confidence,
            evidence_type=kind, evidence_details=details,
            cvss_score=3.7 if severity == "low" else None,
            cvss_vector="CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N" if severity == "low" else "",
            reproduction_steps=[f"Inspect {display}", f"Confirm {kind} using the recorded controls.",
                                "Restrict unused methods and require validated HTTPS transport."],
        )

    async def scan_page(self, url):
        return await self._scan(url, None)

    async def scan_page_context(self, page):
        return await self._scan(page.url, getattr(page, "html", None))

    async def _scan(self, url, html):
        async with self._lock:
            return await self._scan_serial(url, html)

    async def _scan_serial(self, url, html):
        if not self._allowed(url):
            self._coverage(url, "scope", "gap", "outside_allowed_scope")
            return []
        parts = urlsplit(url)
        # Do not synthesize Basic credentials for any probe.
        target = urlunsplit(parts._replace(netloc=parts.netloc.rsplit("@", 1)[-1], fragment=""))
        if target in self._checked:
            return []
        origin = origin_string(target)
        if sum(same_origin(t, origin) for t in self._checked) >= self.MAX_TARGETS_PER_ORIGIN:
            self._coverage(target, "methods", "gap", "target_budget_exhausted")
            return []
        if self.monitor:
            await self.monitor.emit_status(f"Transport security on {redact_url(target, drop_userinfo=True)}")
        findings = []
        if parts.scheme == "https" and origin not in self._tls_checked:
            findings.extend(await self._tls(target))
        self._coverage(target, "write_methods", "gap", "PUT_DELETE_PATCH_not_sent_outside_dedicated_fixture")
        self._coverage(target, "write_overrides", "gap", "state_changing_overrides_not_sent")
        network = getattr(self.browser, "network", None)
        observed = list(getattr(network, "pairs", None) or [])
        self._coverage(target, "plaintext_credentials", "observed" if observed else "gap",
                       "" if observed else "no_captured_requests")
        for pair in observed:
            request = pair.get("request") or {}
            observed_url = request.get("url", "")
            if not self._allowed(observed_url):
                continue
            sensitive = rules.plaintext_sensitive_fields(request)
            if sensitive:
                finding = await self._record(observed_url, "plaintext_credentials", {"fields": sensitive},
                                             method=request.get("method", "GET"), confidence="confirmed")
                if finding:
                    findings.append(finding)
        control = urlunsplit(urlsplit(target)._replace(
            path=parts.path.rsplit("/", 1)[0] + "/wscan-missing-" + secrets.token_hex(8)))
        kwargs = {"timeout": getattr(self.engine, "timeout", 15), "follow_redirects": False}
        if hasattr(self.engine, "httpx_client_kwargs"):
            kwargs = self.engine.httpx_client_kwargs(**kwargs)
        # Anonymous read-only probes: observe real credentials passively instead of replaying them.
        kwargs.update(headers={}, auth=None, cookies=None)
        try:
            async with httpx.AsyncClient(**kwargs) as client:
                async def probe(method, destination, headers=None):
                    delay = getattr(self.engine, "_effective_delay", 0)
                    if delay:
                        await asyncio.sleep(delay)
                    await self.log_payload_test("(transport probe)", method, self.CHECK_TYPE,
                                                redact_url(destination, drop_userinfo=True))
                    response = await client.request(method, destination, headers=headers or {})
                    self._record_probe_status(response)
                    if response.status_code in (408, 429) or response.status_code >= 500 and response.status_code != 501:
                        raise httpx.RequestError("temporary response")
                    return response

                baseline = await probe("GET", target)
                upgrade = rules.https_redirect_status(target, baseline.status_code, baseline.headers.get("location", ""))
                self._coverage(target, "https_upgrade", "gap" if upgrade in {"unknown", "not_applicable"} else "observed",
                               "include_HTTP_target_to_test_upgrade" if upgrade == "not_applicable" else upgrade)
                if upgrade in {"plaintext", "insecure_redirect"}:
                    finding = await self._record(target, "http_without_https_upgrade", {"first_hop": upgrade},
                                                 status=baseline.status_code, severity="low")
                    if finding:
                        findings.append(finding)
                document = html if html is not None else baseline.text
                if parts.scheme == "https":
                    mixed = rules.active_mixed_content(target, document)
                    self._coverage(target, "active_mixed_content", "observed")
                    if mixed:
                        finding = await self._record(target, "active_mixed_content", {"resources": mixed,
                            "summary": "HTTP executable resources declared by an HTTPS document; browser execution not asserted"})
                        if finding:
                            findings.append(finding)
                if not self._allowed(control):
                    self._coverage(target, "methods", "gap", "nonexistent_control_outside_scope")
                    return findings
                missing = await probe("GET", control)
                if not (200 <= baseline.status_code < 300 and missing.status_code in (404, 410)):
                    self._coverage(target, "methods", "gap", "resource_or_nonexistent_control_unconfirmed",
                                   {"existing_status": baseline.status_code, "missing_status": missing.status_code})
                    return findings
                options = await probe("OPTIONS", target)
                options_control = await probe("OPTIONS", control)
                self._coverage(target, "options", "observed", details={
                    "existing_allow": sorted(parse_allow_methods(options.headers.get("allow", ""))),
                    "control_allow": sorted(parse_allow_methods(options_control.headers.get("allow", ""))),
                    "existing_status": options.status_code, "control_status": options_control.status_code})
                for method in ("TRACE", "CONNECT", "PROPFIND"):
                    token = "transport-" + secrets.token_hex(8)
                    headers = {"X-Xst-Probe": token} if method == "TRACE" else {"Depth": "0"} if method == "PROPFIND" else {}
                    result = await probe(method, target, headers)
                    counterpart = await probe(method, control, headers)
                    differential = rules.method_difference(baseline.status_code, missing.status_code,
                                                          result.status_code, counterpart.status_code)
                    details = {"method": method, "status": result.status_code,
                               "control_status": counterpart.status_code, "resource_specific": differential}
                    self._coverage(target, method, "observed", details=details)
                    kind, field = "", None
                    if method == "TRACE" and trace_reflection_strength(result.status_code, dict(result.headers), result.text, token) == "confirmed":
                        kind, field = "http_trace_xst", "(TRACE method)"
                        details["reflected_token"] = True
                        details["probe_marker"] = token
                    elif method == "CONNECT" and differential:
                        kind = "http_connect_capability"
                        details["summary"] = "CONNECT accepted at the target resource; external tunneling not tested"
                    elif method == "PROPFIND":
                        capabilities = rules.webdav_capabilities(result.status_code, result.text)
                        if capabilities:
                            kind, field = "http_webdav_enabled", "(WebDAV)"
                            details["capabilities"] = capabilities
                    if kind:
                        finding = await self._record(target, kind, details, method=method, status=result.status_code,
                                                     field=field, severity="medium" if method == "TRACE" else "low",
                                                     confidence="confirmed" if method != "CONNECT" else "likely")
                        if finding:
                            findings.append(finding)
                for name in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
                    overridden = await probe("GET", target, {name: "OPTIONS"})
                    invalid = await probe("GET", target, {name: "WSCANINVALID"})
                    signature = lambda r: (r.status_code, tuple(sorted(parse_allow_methods(r.headers.get("allow", "")))), r.text)
                    matched = rules.override_matches(signature(options), signature(overridden), signature(baseline), signature(invalid))
                    self._coverage(target, name, "observed", details={"effective_method": "OPTIONS", "matched_canonical": matched})
                    if matched:
                        finding = await self._record(target, "http_method_override", {"header": name, "effective_method": "OPTIONS",
                            "canonical_status": options.status_code, "override_status": overridden.status_code,
                            "control_status": invalid.status_code, "summary": "read-only method override accepted; write/auth bypass not tested"},
                            field=f"(Override: {name})", severity="low", status=overridden.status_code)
                        if finding:
                            findings.append(finding)
        except httpx.HTTPError as exc:
            self._coverage(target, "methods", "gap", type(exc).__name__)
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:method_probe")
            raise PageDocumentUnavailable("Transport method probes incomplete", findings=findings) from exc
        self._checked.add(target)
        return findings

    async def _tls(self, target):
        config = getattr(self.engine, "tls_config", None)
        if getattr(self.engine, "proxy", "") or (config and config.has_client_certificate()):
            self._coverage(target, "tls", "gap", "proxy_or_client_certificate_requires_configured_analyzer")
            return []
        parts = urlsplit(target)
        origin = origin_string(target)
        await self.log_payload_test("(TLS handshake)", "TLS", self.CHECK_TYPE, origin)
        try:
            facts, gaps = await rules.observe_tls(parts.hostname, parts.port or 443,
                float(getattr(self.engine, "timeout", 15)), getattr(config, "ca_cert", ""))
        except (OSError, ValueError) as exc:
            facts, gaps = {}, [type(exc).__name__]
        self._coverage(origin, "tls_peer", "gap" if gaps else "observed", ",".join(gaps), facts)
        self._coverage(origin, "tls_enumeration", "gap",
                       "negotiation_is_not_enumeration; use_tls_scan_for_protocols; weak_cipher_enumeration_not_performed")
        findings = []
        for kind in rules.tls_weaknesses(facts, datetime.now(timezone.utc)):
            finding = await self._record(origin, kind, facts, method="TLS", confidence="confirmed")
            if finding:
                findings.append(finding)
        if facts.get("protocol"):
            self._tls_checked.add(origin)
        return findings
