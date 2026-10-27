"""
Race Condition / TOCTOU Scanner
Sends a burst of identical state-changing requests in parallel and checks
whether the server processes them more than once (double-spend, duplicate
registration, inventory oversell, etc.).

Only active on endpoints that look like state-changing operations (charge,
buy, register, transfer, submit, coupon, apply, vote, etc.).
"""
import asyncio
from contextlib import nullcontext
import re
import time
from typing import TYPE_CHECKING
from urllib.parse import urlencode, urljoin

import httpx

from wscan.probe_ledger import ProbeOutcome, Transport
from wscan.request_logger import redact_text, _redact_headers
from wscan.url_scope import redact_url
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, Prerequisite, ScannerContract, StateChangeClass, TransportKind,
    ValueKind,
)

from .base import BaseScanner, Finding

if TYPE_CHECKING:
    from wscan.engine import ScanEngine

_STATE_CHANGE_RE = re.compile(
    r"(?:buy|purchase|order|checkout|pay(?:ment)?|charge|transfer|"
    r"register|signup|sign.up|coupon|promo|discount|apply|redeem|"
    r"submit|vote|like|follow|confirm|activate|withdraw|refund)",
    re.IGNORECASE,
)

_DUPLICATE_RE = re.compile(
    r"(?:already|duplicate|exists|conflict|twice|double|"
    r"insufficient|balance|limit\s+exceeded|only\s+once)",
    re.IGNORECASE,
)

_SUCCESS_RE = re.compile(
    r"(?:success|confirmed|completed|accepted|processed|approved|thank)",
    re.IGNORECASE,
)

_BURST_SIZE = 8  # simultaneous requests per race probe
_URL_RE = re.compile(r"(?:[a-z][a-z0-9+.\-]*:)?//[^\s\'\"<>]+", re.IGNORECASE)
_URL_USERINFO = re.compile(r"(?i)((?:[a-z][a-z0-9+.\-]*:)?//)([A-Za-z0-9._~%!$&'()*+,;=:@\-]*)@")


def sanitize_exception(exc: Exception | str | None) -> str:
    """Sanitize exception message for display/logging by redacting userinfo from URLs."""
    if exc is None:
        return ""
    text = str(exc)
    if not text:
        return ""

    def _replace_url(match: re.Match) -> str:
        raw_url = match.group(0)
        trailing = ""
        while raw_url and raw_url[-1] in ".,;:!?)>]'\"":
            trailing = raw_url[-1] + trailing
            raw_url = raw_url[:-1]
        try:
            cleaned = redact_url(raw_url, drop_userinfo=True)
        except Exception:
            cleaned = _URL_USERINFO.sub(r"\1", raw_url)
        return cleaned + trailing

    replaced = _URL_RE.sub(_replace_url, text)
    return _URL_USERINFO.sub(r"\1", replaced)


def select_primary_burst_pair(
    pairs: list[tuple[str | None, str | None]],
) -> tuple[str, str]:
    """Select the primary (observation_id, request_id) pair from burst tasks.

    Guarantees that primary observation and request come from the same task pair.
    If the selected task is missing its request ID, an empty string is returned rather than
    mismatched with another task's request ID.
    """
    for req_id, obs_id in pairs:
        if obs_id:
            return obs_id, (req_id or "")
    return "", ""


def split_verification_and_display_urls(url: str) -> tuple[str, str]:
    """Separate re-verification URL (retaining userinfo authentication) from
    redacted persistent/display/evidence URL.

    Returns:
        (verification_url, display_url)
    """
    display_url = redact_url(url, drop_userinfo=True)
    return url, display_url


def get_verification_url(finding: Finding) -> str:
    """Return the URL to use for re-verification, preserving userinfo if available."""
    return (
        getattr(finding, "verification_url", None)
        or getattr(finding, "_verification_url", None)
        or finding.url
    )


def _looks_like_state_change(url: str, field: dict) -> bool:
    name = (field.get("name") or field.get("id") or "").lower()
    return bool(_STATE_CHANGE_RE.search(url) or _STATE_CHANGE_RE.search(name))


class RaceConditionScanner(BaseScanner):
    """Race condition / TOCTOU vulnerability scanner."""

    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "race_condition"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS, ExecutionKind.FIELD_INJECTION}),
        capabilities=(
            CarrierCapability(
                carrier=Carrier.QUERY, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
            ),
            CarrierCapability(
                # scan_field が form fields を urlencode し _send_burst() で 8 回連続 POST して
                # race condition を検査するため supported。
                # _form_request_template() が browser.navigate()/page.evaluate() で form を取得し
                # てから _send_burst() の HTTPX burst を送るため browser 必須。
                carrier=Carrier.FORM, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.PLAYWRIGHT, TransportKind.HTTPX}),
                browser_required=True,
                payload_shapes=frozenset({PayloadShape.SCALAR}),
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
                carrier=Carrier.HEADER, state=CapabilityState.UNSUPPORTED,
                reason="page/response 解析でありパラメータ注入をしない",
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
        prerequisites=frozenset({Prerequisite.SECOND_REQUEST}),
        state_change=StateChangeClass.CONDITIONAL,
        cost=CostClass.HIGH,
    )

    SEVERITY = "high"

    def __init__(self, engine: "ScanEngine"):
        super().__init__(engine)
        self._checked_urls: set[str] = set()

    async def _form_request_template(
        self,
        page_url: str,
        form_index: int,
    ) -> tuple[str, str, str, dict]:
        await self.browser.navigate(page_url)
        form = await self.browser.page.evaluate(
            """
            ([formIndex]) => {
                const form = document.querySelectorAll('form')[formIndex];
                if (!form) return null;
                const fields = {};
                const els = form.querySelectorAll(
                    'input:not([type=submit]):not([type=button]):not([type=reset]):not([type=image]):not([type=file]), textarea, select'
                );
                els.forEach((el) => {
                    const name = el.name || el.id;
                    if (!name || el.type === 'checkbox' || el.type === 'radio') return;
                    fields[name] = el.value || 'wscan-race';
                });
                return {
                    action: form.action || window.location.href,
                    method: (form.method || 'GET').toUpperCase(),
                    fields,
                };
            }
            """,
            [form_index],
        )
        if not form:
            return page_url, "GET", "", {}
        action_url = urljoin(page_url, form.get("action") or page_url)
        method = (form.get("method") or "GET").upper()
        body = urlencode(form.get("fields") or {})
        headers = {
            "Content-Type": "application/x-www-form-urlencoded",
            "User-Agent": (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            ),
        }
        return action_url, method, body, headers

    async def _send_burst(
        self,
        url: str,
        method: str,
        body: str,
        headers: dict,
        *,
        role: str = "attack",
    ) -> list:
        timeout = getattr(self.engine, "timeout", 15)
        client_kwargs: dict = {
            "timeout": timeout,
            "follow_redirects": False,
        }
        if hasattr(self.engine, "httpx_client_kwargs"):
            client_kwargs = self.engine.httpx_client_kwargs(**client_kwargs)
        elif getattr(self.engine, "proxy", ""):
            client_kwargs["proxy"] = getattr(self.engine, "proxy", "")
            client_kwargs["verify"] = False
        if hasattr(self.engine, "auth_headers"):
            base_headers = self.auth_headers_for_url(url)
            base_headers.update(headers or {})
            headers = base_headers

        logger = getattr(self.engine, "request_logger", None)
        evidence_enabled = (
            getattr(logger, "enabled", False)
            and callable(getattr(logger, "probe_scope", None))
            and callable(getattr(logger, "log_httpx_submission", None))
        )
        if evidence_enabled:
            hooks = dict(client_kwargs.get("event_hooks") or {})
            request_hooks = list(hooks.get("request", ()))
            if logger.log_httpx_submission not in request_hooks:
                request_hooks.append(logger.log_httpx_submission)
            hooks["request"] = request_hooks
            # _observe_response() owns observation; the engine-wide response hook would
            # record a second observation for the same probe.
            response_hook = getattr(logger, "log_httpx_response", None)
            if response_hook is not None:
                remaining = [h for h in (hooks.get("response") or ()) if h != response_hook]
                if remaining:
                    hooks["response"] = remaining
                else:
                    hooks.pop("response", None)
            client_kwargs["event_hooks"] = hooks
        else:
            self._evidence_gap("race_condition_evidence_unavailable")

        async def _one_request(session: httpx.AsyncClient) -> httpx.Response:
            scope = (
                logger.probe_scope(None, self.CHECK_TYPE, role=role, transport=Transport.HTTPX)
                if evidence_enabled else nullcontext({"requests": []})
            )
            with scope as context:
                try:
                    if method == "POST":
                        response = await session.post(url, content=body, headers=headers)
                    else:
                        response = await session.get(url, headers=headers)
                except Exception as exc:
                    if evidence_enabled:
                        self._evidence_failure(context, exc)
                    raise
                if evidence_enabled:
                    observed = self._observe_response(response)
                    response.extensions["vulix_race_evidence"] = (context, observed)
                return response

        async with httpx.AsyncClient(**client_kwargs) as session:
            responses = await asyncio.gather(
                *[_one_request(session) for _ in range(_BURST_SIZE)],
                return_exceptions=True,
            )
            for response in responses:
                if not isinstance(response, Exception):
                    self._record_probe_status(response)
        return responses

    def _evidence_gap(self, reason: str) -> None:
        logger = getattr(self.engine, "request_logger", None)
        ledger = getattr(logger, "probe_ledger", None)
        manifest = getattr(ledger, "manifest", None)
        if callable(getattr(manifest, "note_gap", None)):
            manifest.note_gap(reason)
        self._record_scan_note(reason)

    def _observe_response(self, response: httpx.Response) -> str | None:
        logger = getattr(self.engine, "request_logger", None)
        if logger is None:
            return None
        owner, request_id = response.request.extensions.get("vulix_probe_submission", (None, None))
        bound = response.request.extensions.get("vulix_probe_context")
        if owner is not logger or not request_id or bound is None:
            self._evidence_gap("race_condition_request_missing")
            return None
        context, request = bound
        pair = {
            "request": request,
            "response": {
                "status": response.status_code,
                "url": str(response.url),
                "headers": dict(response.headers),
                "body": response.content,
                "timestamp": time.time(),
            },
        }
        observation = logger.observe_request(context, request_id, pair, Transport.HTTPX)
        if not observation:
            self._evidence_gap("race_condition_observation_missing")
        else:
            context.setdefault("observations", {})[request_id] = observation
        return observation

    def _evidence_failure(self, context: dict, exc: Exception) -> None:
        logger = getattr(self.engine, "request_logger", None)
        if not callable(getattr(logger, "scoped_probe", None)):
            self._evidence_gap("race_condition_evidence_unavailable")
            return
        outcome = self._probe_exception_outcome(exc)
        requests = context.get("requests", [])
        if not requests:
            self._evidence_gap("race_condition_request_missing")
            return
        for request_id in requests:
            if not logger.scoped_probe(
                context,
                record_kind="decision",
                outcome=outcome,
                parent_id=request_id,
                request_attempt_id=request_id,
                decision_rule="race_condition_burst",
                decision_version="1",
                rationale=type(exc).__name__,
            ):
                self._evidence_gap("race_condition_decision_missing")

    def _record_burst_decision(
        self,
        responses: list,
        classified: tuple[str, dict] | None,
        url: str,
        *,
        role: str = "attack",
        related_sources: tuple[str, ...] = (),
    ) -> str | None:
        logger = getattr(self.engine, "request_logger", None)
        if logger is None or not getattr(logger, "enabled", False):
            return None

        consumed_observations = []
        task_pairs: list[tuple[str | None, str | None]] = []
        has_transport_failure = False
        for r in responses:
            if isinstance(r, Exception):
                has_transport_failure = True
            elif isinstance(r, httpx.Response):
                bound = r.extensions.get("vulix_race_evidence")
                owner, req_id = (
                    r.request.extensions.get("vulix_probe_submission", (None, None))
                    if hasattr(r, "request") else (None, None)
                )
                if bound and owner is logger:
                    context, obs_id = bound
                    valid_req = req_id if isinstance(req_id, str) and req_id else None
                    valid_obs = obs_id if isinstance(obs_id, str) and obs_id else None
                    task_pairs.append((valid_req, valid_obs))
                    if valid_obs:
                        consumed_observations.append(valid_obs)

        if not consumed_observations:
            if has_transport_failure:
                self._evidence_gap("race_condition_transport_failure")
            return None

        if classified is not None:
            outcome = ProbeOutcome.MATCHED.value
            evidence, details = classified
            rationale = (
                f"success_count={details['success_count']}; "
                f"duplicate_count={details['duplicate_count']}; "
                f"burst_size={details['burst_size']}; "
                f"consumed={len(consumed_observations)}"
            )
        else:
            if has_transport_failure:
                self._evidence_gap("race_condition_partial_burst")
                return None
            outcome = ProbeOutcome.NO_MATCH.value
            ok_count = sum(
                1 for r in responses
                if isinstance(r, httpx.Response) and hasattr(r, "text") and _SUCCESS_RE.search(r.text)
            )
            dup_count = sum(
                1 for r in responses
                if isinstance(r, httpx.Response) and hasattr(r, "text") and _DUPLICATE_RE.search(r.text)
            )
            rationale = (
                f"success_count={ok_count}; "
                f"duplicate_count={dup_count}; "
                f"burst_size={_BURST_SIZE}; "
                f"consumed={len(consumed_observations)}"
            )

        primary_obs, primary_req = select_primary_burst_pair(task_pairs)

        related = list(consumed_observations)
        for src in related_sources:
            if src not in related:
                related.append(src)

        decision_id = logger.log_probe(
            role=role,
            check=self.CHECK_TYPE,
            record_kind="decision",
            outcome=outcome,
            parent_id=primary_obs,
            request_attempt_id=primary_req,
            decision_rule="race_condition_burst",
            decision_version="1",
            rationale=rationale,
            related_attempt_ids=tuple(related),
        )
        if not decision_id:
            self._evidence_gap("race_condition_decision_missing")
        return decision_id

    def _classify_responses(self, responses: list, url: str) -> tuple[str, dict] | None:
        ok_responses = [
            r for r in responses
            if not isinstance(r, Exception)
            and hasattr(r, "text")
            and _SUCCESS_RE.search(r.text)
        ]
        dup_responses = [
            r for r in responses
            if not isinstance(r, Exception)
            and hasattr(r, "text")
            and _DUPLICATE_RE.search(r.text)
        ]
        if len(ok_responses) >= 2:
            evidence = (
                f"Race condition: {len(ok_responses)}/{_BURST_SIZE} parallel requests "
                f"to {url} returned a success response, "
                + (f"while {len(dup_responses)} returned a duplicate/conflict error. " if dup_responses else "")
                + "The endpoint may process the same state change multiple times under concurrent load."
            )
            return evidence, {
                "success_count": len(ok_responses),
                "duplicate_count": len(dup_responses),
                "burst_size": _BURST_SIZE,
            }
        return None

    async def scan_field(
        self,
        url: str,
        form_index: int,
        field: dict,
        is_url_param: bool = False,
    ) -> list[Finding]:
        if is_url_param:
            return []
        action_url, method, body, headers = await self._form_request_template(url, form_index)
        key = f"{method} {action_url} {body}"
        if key in self._checked_urls:
            return []
        if not (
            _STATE_CHANGE_RE.search(action_url)
            or _looks_like_state_change(url, field)
            or _STATE_CHANGE_RE.search(body)
        ):
            return []
        self._checked_urls.add(key)

        verification_url, display_url = split_verification_and_display_urls(action_url)

        if self.monitor:
            await self.monitor.emit_status(f"Race condition form probe on {display_url}")

        try:
            responses = await self._send_burst(verification_url, method, body, headers, role="attack")
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] race_condition: form burst failed on {display_url}: {sanitize_exception(exc)}"
                )
            return []

        classified = self._classify_responses(responses, display_url)
        decision_id = self._record_burst_decision(responses, classified, display_url, role="attack")
        if not classified:
            return []
        evidence, details = classified
        safe_headers = _redact_headers(headers)
        safe_body = redact_text(body)
        details.update({
            "method": method,
            "body": safe_body,
            "headers": safe_headers,
            "attempt_ids": [decision_id] if decision_id else [],
        })
        finding = await self.record_finding(
            url=display_url,
            field_name=field.get("name") or field.get("id") or "(form race)",
            payload=f"{_BURST_SIZE}x simultaneous {method} requests",
            evidence=evidence,
            pair={
                "request": {"url": display_url, "method": method, "body": safe_body, "headers": safe_headers},
                "response": {
                    "status": "mixed",
                    "body": f"{details['success_count']} success, {details['duplicate_count']} duplicate",
                },
            },
            severity="high",
            confidence="likely",
            evidence_type="race_condition_burst",
            evidence_details=details,
        )
        if finding:
            finding.verification_url = verification_url
            finding._verification_url = verification_url
            return [finding]
        return []

    async def scan_page(self, url: str) -> list[Finding]:
        if url in self._checked_urls:
            return []
        if not _STATE_CHANGE_RE.search(url):
            return []
        self._checked_urls.add(url)

        verification_url, display_url = split_verification_and_display_urls(url)

        if self.monitor:
            await self.monitor.emit_status(f"Race condition probe on {display_url}")

        # Capture the last form submission body from the browser's network log
        pair = self.current_page_pair(url)
        req = pair.get("request", {})
        method = req.get("method", "GET").upper()
        body = req.get("post_data") or req.get("body") or ""
        headers = {
            k: v for k, v in req.get("headers", {}).items()
            if k.lower() not in ("content-length",)
        }
        if not headers.get("User-Agent") and not headers.get("user-agent"):
            headers["User-Agent"] = (
                "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
                "(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"
            )

        # state profile gate: page-level burst は捕捉済み POST を 8 回リプレイするため、
        # _scan_field の事前 gate を通らない。ここで profile を適用し、read-only や
        # controlled-write の破壊的操作（purchase/transfer 等）の反復送信を防ぐ。
        from wscan.state_profile import may_submit
        if not may_submit(
            getattr(self.engine, "state_profile", "unrestricted"),
            method=method,
            action=url,
        ):
            self._record_scan_note(f"state_change_skipped:{self.CHECK_TYPE}")
            return []

        try:
            responses = await self._send_burst(verification_url, method, body, headers, role="attack")
        except Exception as exc:
            if self.monitor:
                await self.monitor.emit_status(
                    f"[warn] race_condition: burst failed on {display_url}: {sanitize_exception(exc)}"
                )
            return []

        classified = self._classify_responses(responses, display_url)
        decision_id = self._record_burst_decision(responses, classified, display_url, role="attack")
        if classified:
            evidence, details = classified
            safe_headers = _redact_headers(headers)
            safe_body = redact_text(body)
            details.update({
                "method": method,
                "body": safe_body,
                "headers": safe_headers,
                "attempt_ids": [decision_id] if decision_id else [],
            })
            finding = await self.record_finding(
                url=display_url,
                field_name="(page-level race)",
                payload=f"{_BURST_SIZE}x simultaneous {method} requests",
                evidence=evidence,
                pair={
                    "request": {"url": display_url, "method": method, "body": safe_body, "headers": safe_headers},
                    "response": {
                        "status": "mixed",
                        "body": f"{details['success_count']} success, {details['duplicate_count']} duplicate",
                    },
                },
                severity="high",
                confidence="likely",
                evidence_type="race_condition_burst",
                evidence_details=details,
            )
            if finding:
                finding.verification_url = verification_url
                finding._verification_url = verification_url
                return [finding]
            return []

        return []

    async def verify_finding(self, finding: Finding) -> bool | None:
        details = getattr(finding, "evidence_details", {}) or {}
        method = details.get("method")
        body = details.get("body", "")
        headers = details.get("headers", {})
        if not method:
            return None
        verify_url = get_verification_url(finding)
        try:
            responses = await self._send_burst(verify_url, method, body, headers, role="verify")
        except Exception:
            return None
        display_url = redact_url(verify_url, drop_userinfo=True)
        classified = self._classify_responses(responses, display_url)
        baseline_ids = tuple(details.get("attempt_ids") or ())
        decision_id = self._record_burst_decision(
            responses, classified, display_url, role="verify", related_sources=baseline_ids
        )
        if decision_id and classified:
            finding.evidence_details["verification_attempt_ids"] = [decision_id]
        return bool(classified)
