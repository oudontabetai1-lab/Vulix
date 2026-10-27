"""
File Upload Vulnerability Scanner
Detects insecure file upload endpoints that allow:
  1. Uploading web shells (PHP/JSP/ASP) disguised as images
  2. Unrestricted MIME type acceptance
  3. Double-extension bypass (shell.php.jpg)
  4. Path traversal in filename parameter
  5. WAF/フィルタ・バイパス変種（代替拡張子・大文字小文字・末尾ドット/空白・
     画像マジックバイト polyglot・Content-Type 偽装）。種は
     :func:`wscan.waf_bypass.upload_bypass_probes` が決定論的に列挙する。
"""
import io
import re
import time
from contextlib import nullcontext
from typing import TYPE_CHECKING
from urllib.parse import urljoin

import httpx

from wscan.probe_ledger import Transport
from wscan.request_logger import _redact_headers, redact_text, redact_url

from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding
from ..waf_bypass import UploadProbe, upload_bypass_probes

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

# 投入するプローブファイル一式（WAF/フィルタ・バイパス変種を含む）。
_PROBE_FILES: list[UploadProbe] = upload_bypass_probes()

_UPLOAD_FIELD_NAMES = re.compile(
    r"(?:file|upload|image|photo|avatar|attachment|document|picture|media)",
    re.IGNORECASE,
)
_SUCCESS_RE = re.compile(
    r"(?:upload(?:ed|ing)?|success|saved|stored|file\s+received)",
    re.IGNORECASE,
)
_SHELL_ECHO_RE = re.compile(r"wscan-probe-(?:jsp|\d+\.\d+)", re.IGNORECASE)


def _is_upload_field(field: dict) -> bool:
    ftype = (field.get("type") or "").lower()
    name = (field.get("name") or field.get("id") or "").lower()
    return ftype == "file" or bool(_UPLOAD_FIELD_NAMES.search(name))


class FileUploadScanner(BaseScanner):
    """Insecure file upload vulnerability scanner."""

    CHECK_TYPE = "file_upload"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.FORM, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.JSON, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.XML, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                # _form_action_url() が browser.navigate()/page.evaluate() で form action を
                # 解決してから _upload_file() の HTTPX POST を送るため browser 必須。
                carrier=Carrier.MULTIPART, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.BINARY, ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT, TransportKind.HTTPX}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.BINARY}),
            ),
            CarrierCapability(
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.COOKIE, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.PATH, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.GRAPHQL, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
            CarrierCapability(
                carrier=Carrier.WEBSOCKET, state=CapabilityState.UNSUPPORTED,
                reason="file upload は multipart 特化",
            ),
        ),
        state_change=StateChangeClass.ALWAYS,
        cost=CostClass.HIGH,
    )

    ALWAYS_STATE_CHANGING = True
    SEVERITY = "critical"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_forms: set[tuple] = set()

    def _probe_by_filename(self, filename: str) -> UploadProbe | None:
        for probe in _PROBE_FILES:
            if probe.filename == filename:
                return probe
        return None

    async def _form_action_url(self, page_url: str, form_index: int) -> str:
        try:
            await self.browser.navigate(page_url)
            action = await self.browser.page.evaluate(
                """
                ([formIndex]) => {
                    const form = document.querySelectorAll('form')[formIndex];
                    return form ? (form.action || window.location.href) : window.location.href;
                }
                """,
                [form_index],
            )
            return urljoin(page_url, action or page_url)
        except Exception:
            return page_url

    async def _upload_file(
        self,
        url: str,
        field_name: str,
        filename: str,
        content: bytes,
        content_type: str = "image/jpeg",
        *,
        evidence: bool = True,
    ) -> tuple[str, int, dict]:
        self._last_upload_response = None
        timeout = getattr(self.engine, "timeout", 15)
        client_kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": True,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs(**client_kwargs)
        elif getattr(self.engine, "proxy", ""):
            client_kwargs["proxy"] = getattr(self.engine, "proxy", "")
            client_kwargs["verify"] = False
        if hasattr(self.engine, "auth_headers"):
            client_kwargs["headers"] = self.auth_headers_for_url(url)

        request_kwargs = {
            "files": {field_name: (filename, io.BytesIO(content), content_type)},
        }
        logger = getattr(self.engine, "request_logger", None)
        if evidence and callable(getattr(logger, "log_httpx_submission", None)):
            client_kwargs["event_hooks"] = {"request": [logger.log_httpx_submission]}
        scope = (logger.probe_scope(None, self.CHECK_TYPE, role="attack", transport=Transport.HTTPX)
                 if evidence and callable(getattr(logger, "probe_scope", None)) else nullcontext({"requests": []}))
        if evidence and (logger is None or not getattr(logger, "enabled", False)):
            ledger = getattr(logger, "probe_ledger", None)
            if ledger is not None:
                ledger.manifest.note_gap("file_upload_evidence_unavailable")
            self._record_scan_note("file_upload_evidence_unavailable")
        with scope as context:
            try:
                async with httpx.AsyncClient(**client_kwargs) as client:
                    response = await client.post(url, **request_kwargs)
                    self._record_probe_status(response)
            except Exception as exc:
                if evidence:
                    self._upload_decision(context, self._probe_exception_outcome(exc), "file_upload_transport",
                                          "upload request failed without a response")
                raise
            if evidence:
                self._upload_observe(context, response)
            context["response"] = response
            self._last_upload_response = response
        pair = {
            "request": {"url": url, "method": "POST", "filename": filename},
            "response": {"status": response.status_code, "body": response.text[:1000]},
        }
        return response.text, response.status_code, pair

    def _upload_observe(self, context, response):
        logger = getattr(self.engine, "request_logger", None)
        if logger is None:
            return
        owner, request_id = response.request.extensions.get("vulix_probe_submission", (None, None))
        bound = response.request.extensions.get("vulix_probe_context")
        if owner is not logger or not request_id or bound is None:
            logger.probe_ledger.manifest.note_gap("file_upload_request_missing")
            return
        bound_context, request = bound
        pair = {"request": request, "response": {"status": response.status_code, "url": str(response.url),
                "headers": dict(response.headers), "body": response.content, "timestamp": time.time()}}
        observation = logger.observe_request(bound_context, request_id, pair, Transport.HTTPX)
        if observation:
            bound_context.setdefault("observations", {})[request_id] = observation
            context["request_id"] = request_id
            context["observation_id"] = observation
        else:
            logger.probe_ledger.manifest.note_gap("file_upload_observation_missing")

    def _upload_decision(self, context, outcome, rule, rationale):
        logger = getattr(self.engine, "request_logger", None)
        if not callable(getattr(logger, "scoped_probe", None)):
            return
        requests = context.get("requests", [])
        if not requests:
            logger.probe_ledger.manifest.note_gap("file_upload_request_missing")
            return
        attempt = requests[-1]
        parent = context.get("observations", {}).get(attempt, attempt)
        logger.scoped_probe(context, record_kind="decision", outcome=outcome, parent_id=parent,
            request_attempt_id=attempt, decision_rule=rule, decision_version="1", rationale=rationale)

    def _classify(
        self,
        body: str,
        status_code: int,
        filename: str,
        description: str,
    ) -> tuple[str, str, str, dict] | None:
        if _SHELL_ECHO_RE.search(body or ""):
            return (
                "file_upload_executable",
                "critical",
                (
                    f"File upload: uploaded file was executed as code — "
                    f"server returned probe output. Filename: {filename!r}. "
                    f"Description: {description}."
                ),
                {"filename": filename, "description": description},
            )
        if status_code in (200, 201) and _SUCCESS_RE.search(body or ""):
            return (
                "file_upload_dangerous_accept",
                "high",
                (
                    f"File upload: server accepted {description} ({filename!r}) "
                    f"without rejection. Verify whether the file is accessible/executable."
                ),
                {"filename": filename, "description": description},
            )
        return None

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        if is_url_param or not _is_upload_field(field):
            return []

        key = (url, form_index)
        if key in self._checked_forms:
            return []
        self._checked_forms.add(key)

        field_name = field.get("name") or field.get("id") or "file"
        findings: list[Finding] = []
        action_url = await self._form_action_url(url, form_index)

        for probe in _PROBE_FILES:
            filename, description = probe.filename, probe.description
            # log_payload_test(field_name, payload, check_type, url)
            await self.log_payload_test(
                field_name, filename, self.CHECK_TYPE, url
            )
            try:
                body, status_code, pair = await self._upload_file(
                    action_url, field_name, filename, probe.content, probe.content_type
                )

            except Exception as exc:
                if self.monitor:
                    await self.monitor.emit_status(
                        f"[warn] file_upload: request failed on {url}: {exc}"
                    )
                continue

            classified = self._classify(body, status_code, filename, description)
            # _upload_file's scope ends after the response; its saved context is carried on response.request.
            response = getattr(self, "_last_upload_response", None)
            evidence_context = (response.request.extensions.get("vulix_probe_context", (None, {}))[0]
                                if response is not None else None)
            request_ids = evidence_context.get("requests", []) if evidence_context else []
            observation_ids = evidence_context.get("observations", {}) if evidence_context else {}
            attempt_id = request_ids[-1] if request_ids else ""
            # terminal decision is emitted after the unchanged classifier has made its choice
            if evidence_context:
                self._upload_decision(evidence_context, "matched" if classified else "no_match",
                    classified[0] if classified else "file_upload_classifier",
                    "upload response classified" if classified else "successful upload response had no classifier match")

            if classified:
                evidence_type, severity, evidence, evidence_details = classified
                finding = await self.record_finding(
                    url=redact_url(action_url),
                    field_name=field_name,
                    payload=filename,
                    evidence=redact_text(evidence),
                    pair={"request": {"url": redact_url(action_url), "method": "POST", "filename": filename},
                          "response": {"status": status_code, "body": redact_text(pair["response"]["body"]) }},
                    severity=severity,
                    confidence="likely",
                    evidence_type=evidence_type,
                    evidence_details={**evidence_details, "probe_attempt_id": attempt_id,
                        "headers": _redact_headers(dict(getattr(response.request, "headers", {}))) if response else {}},
                    reproduction_steps=[redact_text(step) for step in
                        self._default_reproduction_steps(redact_url(action_url), field_name, filename)],
                )
                findings.append(finding)
                break

        return findings

    async def scan_page(self, url: str) -> list[Finding]:
        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        probe = self._probe_by_filename(finding.payload)
        if not probe:
            return None
        try:
            # Verification remains the legacy replay path until Finding carries a trustworthy parent attempt ID.
            body, status_code, _pair = await self._upload_file(
                finding.url,
                finding.field_name,
                probe.filename,
                probe.content,
                probe.content_type,
                evidence=False,
            )
        except Exception:
            return None
        classified = self._classify(body, status_code, probe.filename, probe.description)
        return bool(classified and classified[0] == finding.evidence_type)
