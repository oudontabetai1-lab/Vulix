from __future__ import annotations

import asyncio
import hashlib
import posixpath
import secrets
from collections import deque
from urllib.parse import urljoin, urlsplit, urlunsplit

import httpx

from wscan.directory_artifacts import (
    MAX_BODY, ArtifactCandidate, classify_backup, classify_directory_listing,
    control_matches, derive_artifact_candidates, extract_resource_urls,
    normalize_candidate_url, parse_source_map, source_mapping_references,
)
from wscan.scanner_contract import (
    CapabilityState, Carrier, CarrierCapability, CostClass, ExecutionKind,
    PayloadShape, ScannerContract, StateChangeClass, TransportKind, ValueKind,
)
from wscan.url_scope import origin_string, redact_url, same_origin

from .base import BaseScanner, Finding, PageDocumentUnavailable


class DirectoryArtifactsScanner(BaseScanner):
    HAS_PAGE_LEVEL = True
    CHECK_TYPE = "directory_artifacts"
    SEVERITY = "medium"
    CONTRACT = ScannerContract(
        execution_kinds=frozenset({ExecutionKind.PAGE_ANALYSIS}),
        capabilities=tuple(
            CarrierCapability(
                carrier=carrier, state=CapabilityState.SUPPORTED,
                value_kinds=frozenset({ValueKind.STRING}),
                transports=frozenset({TransportKind.HTTPX}),
                payload_shapes=frozenset({PayloadShape.SCALAR}),
            ) if carrier == Carrier.PATH else CarrierCapability(
                carrier=carrier, state=CapabilityState.UNSUPPORTED,
                reason="観測リソース由来の read-only GET 検査でパラメータ注入をしない",
            )
            for carrier in Carrier
        ),
        state_change=StateChangeClass.READ_ONLY,
        cost=CostClass.MEDIUM,
    )
    MAX_CANDIDATES_PER_ORIGIN = 200

    def __init__(self, engine):
        super().__init__(engine)
        self._checked = set()
        self._planned = set()
        self._pending = {}
        self._verification_targets = {}
        self._budget_skipped = set()
        self._counts = {}
        self._controls = {}
        self._lock = asyncio.Lock()
        self._nonce = secrets.token_hex(8)
        self._inline_checked = set()

    async def scan_field(self, url, form_index, field, is_url_param=False) -> list[Finding]:
        return []

    def _allowed(self, url, origin):
        if not normalize_candidate_url(url) or not same_origin(url, origin):
            return False
        excluded = getattr(self.engine, "_is_url_excluded", None)
        if callable(excluded) and excluded(url):
            return False
        allowed = getattr(self.engine, "_is_access_allowed_url", None)
        if callable(allowed):
            return bool(allowed(url))
        return False

    def _note(self, state):
        self._record_scan_note(f"candidate_{state}:{self.CHECK_TYPE}")

    async def _fetch(self, url, origin):
        current = url
        for _ in range(6):
            if not self._allowed(current, origin):
                self._record_scan_note(f"scope_skipped:{self.CHECK_TYPE}:redirect")
                return None
            kwargs = {"timeout": getattr(self.engine, "timeout", 15), "follow_redirects": False}
            configure = getattr(self.engine, "httpx_client_kwargs", None)
            if callable(configure):
                kwargs = configure(**kwargs)
            elif getattr(self.engine, "proxy", ""):
                kwargs["proxy"] = self.engine.proxy
            headers = self.auth_headers_for_url(current, include_cookie=False)
            cookie_provider = getattr(self.engine, "cookie_header_for_url", None)
            if callable(cookie_provider):
                cookies = await cookie_provider(current)
                if cookies is None:
                    raise RuntimeError("cookie jar unavailable")
                if cookies and not any(k.lower() == "cookie" for k in headers):
                    headers["Cookie"] = cookies
            kwargs["headers"] = headers
            await self.log_payload_test("(artifact probe)", "GET", self.CHECK_TYPE, current)
            async with httpx.AsyncClient(**kwargs) as client:
                async with client.stream("GET", current) as response:
                    self._record_probe_status(response)
                    if response.status_code in (408, 429) or response.status_code >= 500:
                        raise RuntimeError(f"temporary HTTP {response.status_code}")
                    if response.status_code in (301, 302, 303, 307, 308):
                        location = response.headers.get("location")
                        if not location:
                            return None
                        current = normalize_candidate_url(urljoin(current, location))
                        continue
                    data = bytearray()
                    async for chunk in response.aiter_bytes():
                        data.extend(chunk)
                        if len(data) > MAX_BODY:
                            raise RuntimeError("artifact response exceeds byte budget")
                    return httpx.Response(
                        response.status_code, headers=response.headers,
                        content=bytes(data), request=httpx.Request("GET", current),
                    )
        self._record_scan_note(f"scope_skipped:{self.CHECK_TYPE}:redirect_limit")
        return None

    def _control_url(self, candidate):
        parts = urlsplit(candidate.url)
        if candidate.kind == "directory":
            parent = parts.path if parts.path.endswith("/") else posixpath.dirname(parts.path) + "/"
            path = parent + "wscan-missing-" + self._nonce + "/"
        else:
            parent = posixpath.dirname(parts.path) + "/"
            suffix = ".map" if candidate.kind == "source_map" else posixpath.splitext(parts.path)[1]
            path = parent + "wscan-missing-" + self._nonce + (suffix or ".txt")
        return urlunsplit(parts._replace(path=path, fragment=""))

    async def _control(self, candidate, origin):
        target = self._control_url(candidate)
        if not self._allowed(target, origin):
            self._record_scan_note(f"control_unavailable:{self.CHECK_TYPE}:scope")
            return None
        if target not in self._controls:
            try:
                response = await self._fetch(target, origin)
                if response is not None and response.status_code in (200, 404, 410):
                    self._controls[target] = response
            except Exception as exc:
                self._record_scan_note(f"probe_error:{self.CHECK_TYPE}:control:{type(exc).__name__}")
                return None
        return self._controls.get(target)

    async def scan_page(self, url):
        return await self._scan(url, {})

    async def scan_page_context(self, page):
        return await self._scan(page.url, getattr(page, "external_scripts", None) or {})

    async def _scan(self, url, external_scripts):
        async with self._lock:
            return await self._scan_serial(url, external_scripts)

    async def _scan_serial(self, url, external_scripts):
        origin = origin_string(url)
        if not self._allowed(url, origin):
            self._note("skipped")
            return []
        findings = []
        failures = []
        queue = deque(candidate for candidate in self._pending.values() if same_origin(candidate.url, origin))
        body_cache = {}
        observed_now = set()

        def enqueue(candidate):
            key = (candidate.url, candidate.kind)
            if key not in self._planned:
                self._planned.add(key)
                self._note("planned")
            self._pending[key] = candidate
            if key in self._checked or key in self._budget_skipped:
                self._pending.pop(key, None)
                return
            if not self._allowed(candidate.url, origin):
                self._checked.add(key)
                self._note("skipped")
                return
            if candidate not in queue:
                queue.append(candidate)

        def observe(target):
            clean = normalize_candidate_url(target)
            if not clean or clean in observed_now:
                return
            observed_now.add(clean)
            for candidate in derive_artifact_candidates(clean):
                enqueue(candidate)

        try:
            response = await self._fetch(url, origin)
            if response is None:
                self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:document_redirect")
                raise PageDocumentUnavailable(f"{self.CHECK_TYPE}: document unavailable")
            body_cache[str(response.url)] = response.text
            observe(url)
            observe(str(response.url))
            if response.status_code == 200:
                findings.extend(await self._references(str(response.url), response.text, origin, enqueue))
                for target in extract_resource_urls(response.text, str(response.url)):
                    observe(target)
            for target in sorted(getattr(self.engine, "reached_urls", None) or ()):
                if self._allowed(target, origin):
                    observe(target)
            browser = getattr(self.engine, "browser", None)
            network = getattr(browser, "network", None)
            for pair in list(getattr(network, "pairs", None) or ()):
                request = pair.get("request") or {}
                target = request.get("url", "")
                if request.get("method") == "GET" and self._allowed(target, origin):
                    observe(target)
                response_data = pair.get("response") or {}
                location = next((v for k, v in (response_data.get("headers") or {}).items() if k.lower() == "location"), "")
                if location and self._allowed(target, origin):
                    observe(urljoin(target, location))
            for target, body in external_scripts.items():
                if self._allowed(target, origin):
                    body_cache[target] = body[:MAX_BODY]
                    observe(target)
        except PageDocumentUnavailable:
            raise
        except Exception as exc:
            self._note("error")
            self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:document:{type(exc).__name__}")
            raise PageDocumentUnavailable(f"{self.CHECK_TYPE}: document unavailable") from exc

        while queue:
            candidate = queue.popleft()
            key = (candidate.url, candidate.kind)
            if key in self._checked or key in self._budget_skipped:
                continue
            if self._counts.get(origin, 0) >= self.MAX_CANDIDATES_PER_ORIGIN and key not in self._counts:
                self._budget_skipped.add(key)
                self._note("skipped")
                self._record_scan_note(f"target_cap:{self.CHECK_TYPE}")
                continue
            if key not in self._counts:
                self._counts[key] = 1
                self._counts[origin] = self._counts.get(origin, 0) + 1
            try:
                if candidate.kind == "resource" and candidate.url in body_cache:
                    body = body_cache[candidate.url]
                    self._note("executed")
                    self._checked.add(key)
                    findings.extend(await self._references(candidate.url, body, origin, enqueue))
                    continue
                response = await self._fetch(candidate.url, origin)
                self._note("executed")
                if response is None:
                    self._note("skipped")
                    self._checked.add(key)
                    continue
                final = str(response.url)
                if candidate.kind == "resource":
                    if response.status_code == 200:
                        findings.extend(await self._references(final, response.text, origin, enqueue))
                    self._checked.add(key)
                    continue
                if response.status_code != 200:
                    self._checked.add(key)
                    continue
                if candidate.kind != "directory" and final != candidate.url:
                    self._record_scan_note(f"redirected_artifact:{self.CHECK_TYPE}")
                    self._checked.add(key)
                    continue
                effective = ArtifactCandidate(final, candidate.kind, candidate.observed_url)
                control = await self._control(effective, origin)
                matched_control = control is not None and control.status_code == 200 and control_matches(response.text, final, control.text, str(control.url))
                if matched_control:
                    self._record_scan_note(f"control_suppressed:{self.CHECK_TYPE}")
                    self._checked.add(key)
                    continue
                if candidate.kind == "directory":
                    observation = classify_directory_listing(response.text, final)
                    if observation.signals and not observation.error_page:
                        finding = await self._record(effective, response, "directory_listing", list(observation.signals), {"family": observation.family, "entry_count": len(observation.entries)}, control is not None)
                        if finding:
                            findings.append(finding)
                        for target in extract_resource_urls(response.text, final):
                            observe(target)
                elif candidate.kind == "backup":
                    signals = classify_backup(response.content, response.headers.get("content-type", ""), final)
                    if signals:
                        finding = await self._record(effective, response, "derived_backup", list(signals), {}, control is not None)
                        if finding:
                            findings.append(finding)
                        findings.extend(await self._handoff(final, response.text))
                else:
                    data = parse_source_map(response.text)
                    if data and data.exposed:
                        finding = await self._record(effective, response, "source_map", ["valid_map", "source_content" if any(data.sources_content) else "internal_paths"], {"source_count": len(data.sources), "internal_path_count": len(data.internal_paths), "sources_content_count": sum(bool(s) for s in data.sources_content)}, control is not None)
                        if finding:
                            findings.append(finding)
                        findings.extend(await self._handoff(final, "\n".join((*data.sources, *data.sources_content))))
                    elif data is None:
                        self._record_scan_note(f"parse_error:{self.CHECK_TYPE}:source_map")
                if control is None:
                    failures.append(key)
                    self._note("error")
                else:
                    self._checked.add(key)
            except Exception as exc:
                self._note("error")
                self._record_scan_note(f"transport_error:{self.CHECK_TYPE}:candidate:{type(exc).__name__}")
                failures.append(key)
        for key in self._checked | self._budget_skipped:
            self._pending.pop(key, None)
        if failures:
            raise PageDocumentUnavailable(f"{self.CHECK_TYPE}: incomplete candidate probes", findings=findings)
        return findings

    async def _references(self, resource_url, body, origin, enqueue):
        findings = []
        for reference in source_mapping_references(body):
            if not reference.startswith("data:"):
                target = normalize_candidate_url(urljoin(resource_url, reference))
                if target:
                    enqueue(ArtifactCandidate(target, "source_map", resource_url))
                continue
            digest = hashlib.sha256(reference.encode()).hexdigest()
            key = (resource_url, digest)
            if key in self._inline_checked:
                continue
            self._inline_checked.add(key)
            self._note("planned")
            self._note("executed")
            data = parse_source_map(reference)
            if data is None:
                self._note("error")
                self._record_scan_note(f"parse_error:{self.CHECK_TYPE}:inline_map")
                continue
            if not data.exposed:
                continue
            fake = httpx.Response(200, content=b"", request=httpx.Request("GET", resource_url))
            candidate = ArtifactCandidate(resource_url, "inline_map", resource_url)
            finding = await self._record(candidate, fake, "inline_source_map", ["inline_map", "source_content" if any(data.sources_content) else "internal_paths"], {"source_count": len(data.sources), "internal_path_count": len(data.internal_paths), "sources_content_count": sum(bool(s) for s in data.sources_content)}, False)
            if finding:
                findings.append(finding)
            findings.extend(await self._handoff(resource_url, "\n".join((*data.sources, *data.sources_content))))
        return findings

    async def _handoff(self, url, body):
        scanner = (getattr(self.engine, "scanners", None) or {}).get("secret_leak")
        if scanner is None:
            return []
        return await scanner._record_body_findings(redact_url(url, drop_userinfo=True), body)

    async def _record(self, candidate, response, evidence_type, signals, details, control_available):
        display = redact_url(candidate.url, drop_userinfo=True)
        if evidence_type == "directory_listing":
            for existing in getattr(self.engine, "all_findings", []):
                if existing.check_type == "info_disclosure" and existing.evidence_type == "info_directory_listing" and existing.url == display:
                    return None
        self._verification_targets[(display, evidence_type)] = candidate.url
        return await self.record_finding(
            url=display, field_name="(" + evidence_type + ")", payload="GET",
            evidence=f"Observed {evidence_type}: {', '.join(signals)}; re-fetch required for confirmation.",
            pair={"request": {"url": display, "method": "GET"}, "response": {"status": response.status_code, "body": "[Artifact body omitted to protect potential secrets]"}},
            screenshot_b64="", confidence="tentative", evidence_type=evidence_type,
            evidence_details={"signals": signals, "control_available": control_available, **details},
            reproduction_steps=[f"GET {display}", "Compare with a nonexistent sibling resource and re-fetch to confirm independent signals.", "Disable autoindex and remove public backup files or private source maps."],
        )

    async def verify_finding(self, finding):
        target = self._verification_targets.get((finding.url, finding.evidence_type), finding.url)
        if "[REDACTED]" in target or "<redacted>" in target:
            self.engine._json_probe_failed = True
            return None
        origin = origin_string(target)
        if not self._allowed(target, origin):
            self._record_scan_note(f"scope_skipped:{self.CHECK_TYPE}:verification")
            self.engine._json_probe_failed = True
            return None
        kind = {"directory_listing": "directory", "derived_backup": "backup", "source_map": "source_map", "inline_source_map": "resource"}.get(finding.evidence_type)
        if not kind:
            return None
        try:
            response = await self._fetch(target, origin)
            if response is None:
                return False
            if response.status_code in (401, 403):
                self.engine._api_auth_failed = True
                return None
            if response.status_code != 200:
                return False
            candidate = ArtifactCandidate(str(response.url), kind, finding.url)
            self._controls.pop(self._control_url(candidate), None)
            control = await self._control(candidate, origin)
            if control is None:
                self.engine._json_probe_failed = True
                return None
            if control.status_code == 200 and control_matches(response.text, str(response.url), control.text, str(control.url)):
                return False
            expected = set((finding.evidence_details or {}).get("signals", []))
            if kind == "directory":
                observation = classify_directory_listing(response.text, str(response.url))
                return observation.composite and bool(expected & set(observation.signals))
            if str(response.url) != target:
                return False
            if kind == "backup":
                signals = set(classify_backup(response.content, response.headers.get("content-type", ""), target))
                return bool(signals & {"archive_signature", "source_code", "sensitive_content"}) and bool(signals & expected)
            if kind == "source_map":
                data = parse_source_map(response.text)
                return bool(data and data.exposed)
            return any(data and data.exposed for data in (parse_source_map(ref) for ref in source_mapping_references(response.text) if ref.startswith("data:")))
        except Exception as exc:
            self._record_scan_note(f"verification_error:{self.CHECK_TYPE}:{type(exc).__name__}")
            self.engine._json_probe_failed = True
            return None
