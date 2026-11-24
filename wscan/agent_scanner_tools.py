"""Guarded scanner actions exposed to the Agent browser-use controller."""
from __future__ import annotations

import asyncio
import hashlib
import json
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from wscan.agent_harness import AgentRole, WorkStatus
from wscan.injection_point import InjectionPoint
from wscan.runtime_scope_guard import ScopePolicy, evaluate_scope
from wscan.url_normalize import endpoint_identity


SUPPORTED_CHECKS = frozenset({"xss", "sqli", "os"})
_SUPPORTED_CARRIERS = frozenset({"form", "query"})


def _verification_consistency_reason(
    record: dict,
    *,
    expected_binding: dict,
    injection_point_id: str,
    check_type: str,
    scanner_evidence: list[dict],
    work_evidence_ids: tuple[str, ...],
) -> str:
    """Checkpoint の outcome・digest・scanner finding evidence を一括検証する。"""
    outcome = record.get("status")
    reproduced = record.get("reproduced")
    deterministic = record.get("deterministic_confirmed")
    expected_flags = {
        "confirmed": (True, True),
        "rejected": (False, False),
        "inconclusive": (False, False),
    }
    if outcome not in expected_flags or (reproduced, deterministic) != expected_flags[outcome]:
        return "outcome fields conflict"

    expected_digest = AgentScannerTools._binding_digest(expected_binding)
    binding = record.get("binding")
    if (
        not isinstance(binding, dict)
        or record.get("binding_digest") != expected_digest
        or AgentScannerTools._binding_digest(binding) != expected_digest
    ):
        return "verification binding does not match the current input point"

    evidence_ids = record.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not all(isinstance(item, str) and item for item in evidence_ids):
        return "evidence IDs are malformed"
    if outcome != "confirmed":
        return "non-confirmed outcome references scanner finding evidence" if evidence_ids else ""
    if not evidence_ids:
        return "confirmed outcome has no scanner finding evidence"

    evidence_by_id = {}
    for item in scanner_evidence:
        if not isinstance(item, dict) or not item.get("evidence_id"):
            continue
        evidence_id = str(item["evidence_id"])
        if evidence_id in evidence_by_id:
            return "scanner finding evidence ID is duplicated"
        evidence_by_id[evidence_id] = item
    if len(set(evidence_ids)) != len(evidence_ids):
        return "verification evidence IDs are duplicated"
    for evidence_id in evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None or evidence_id not in work_evidence_ids:
            return "referenced scanner finding evidence is missing"
        finding = evidence.get("finding")
        if (
            evidence.get("work_id") != record.get("work_id")
            or evidence.get("injection_point_id") != injection_point_id
            or evidence.get("check_type") != check_type
            or evidence.get("binding_digest") != expected_digest
            or not isinstance(finding, dict)
            or finding.get("check_type") != check_type
            or finding.get("source") != "deterministic"
            or finding.get("deterministic_confirmed") is not True
            or finding.get("agent_verified") is not True
        ):
            return "scanner finding evidence is inconsistent with its verification binding"
    return ""


class AgentScannerTools:
    """Expose ID-only scanner actions while keeping transport and secrets server-side."""

    def __init__(self, scanner, harness, *, engine_factory=None):
        self.scanner = scanner
        self.harness = harness
        self.engine_factory = engine_factory or self._new_engine
        self.points: dict[str, dict] = {}
        self.findings: dict[str, object] = {}
        self.work_specs: dict[str, tuple[str, str]] = {}
        self.points_path = Path(harness.output_dir) / "agent_scanner_points.json"
        self._load_points()

    def _load_points(self):
        try:
            data = json.loads(self.points_path.read_text(encoding="utf-8"))
            self.points = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self.points = {}

    def _save_points(self):
        tmp = self.points_path.with_suffix(".tmp")
        from wscan.request_logger import redact_url
        safe = {}
        for point_id, item in self.points.items():
            saved = dict(item)
            for key in ("url", "action"):
                if saved.get(key):
                    redacted = redact_url(str(saved[key]))
                    if redacted != saved[key]:
                        saved["resume_unavailable"] = True
                    saved[key] = redacted
            safe[point_id] = saved
        tmp.write_text(json.dumps(safe, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(self.points_path)
        self.harness.checkpoint()

    @staticmethod
    def _point_id(point: InjectionPoint) -> str:
        identity = json.dumps(point.stable_key_parts(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(identity.encode()).hexdigest()[:20]

    def add_point(self, point: InjectionPoint, field: dict | None = None) -> str:
        point_id = self._point_id(point)
        current = self.points.get(point_id)
        if isinstance(current, dict) and not current.get("resume_unavailable"):
            existing, _ = self._resolve(point_id)
            if existing is not None and existing.stable_key_parts() != point.stable_key_parts():
                raise ValueError("injection point ID collision; rediscover the input point before scheduling")
        if current is None or current.get("resume_unavailable"):
            self.points[point_id] = {
                "location": point.location, "url": point.url, "parameter_id": point.parameter_id,
                "form_index": point.form_index, "field": dict(field or {"name": point.parameter_id}),
                "method": point.method, "action": point.action,
            }
        self._save_points()
        return point_id

    def _resolve(self, point_id: str) -> tuple[InjectionPoint | None, dict | None]:
        item = self.points.get(str(point_id))
        if not isinstance(item, dict):
            return None, None
        if item.get("resume_unavailable"):
            return None, item
        try:
            carrier = "query" if item.get("location") == "url_param" else item.get("location")
            if carrier not in _SUPPORTED_CARRIERS:
                return None, item
            if carrier == "query":
                point = InjectionPoint.for_url_param(item["url"], item["parameter_id"])
            else:
                point = InjectionPoint.for_form(
                    item["url"], item["parameter_id"], int(item.get("form_index", 0)),
                    method=item.get("method", ""), action=item.get("action", ""),
                )
        except (KeyError, TypeError, ValueError):
            return None, item
        if self._point_id(point) != str(point_id):
            return None, item
        return point, item

    def _scope_reason(self, point: InjectionPoint, field_name: str = "") -> str:
        engine_args = self.scanner
        from wscan.llm_agent_browser import _url_is_excluded, security_probe_allowed
        if _url_is_excluded(point.url, engine_args.exclude_urls):
            return "excluded_url"
        if field_name and field_name.lower() in {f.lower() for f in engine_args.exclude_fields}:
            return "excluded_field"
        if not security_probe_allowed(
            point.url, engine_args.target_urls, engine_args.exclude_urls,
            access_urls=engine_args.access_urls, field_name=field_name,
            exclude_fields=engine_args.exclude_fields,
        ):
            return "scope_blocked"
        policy = ScopePolicy(
            target_urls=tuple(engine_args.target_urls), access_urls=tuple(engine_args.access_urls),
            exclude_urls=tuple(engine_args.exclude_urls), login_url=engine_args.login_url,
        )
        decision = evaluate_scope(point.url, policy)
        if not decision.allowed or decision.reason not in {"target_url", "target_url_no_frag", "target_url_no_query"}:
            return "scope_blocked" if decision.reason != "excluded_url" else "excluded_url"
        if point.action:
            from wscan.runtime_scope_guard import _matches_scope_list
            if _url_is_excluded(point.action, engine_args.exclude_urls):
                return "excluded_url"
            if _matches_scope_list(point.action, policy.access_urls):
                return "access_only_url"
            if not security_probe_allowed(
                point.action, engine_args.target_urls, engine_args.exclude_urls,
                access_urls=engine_args.access_urls,
            ):
                return "scope_blocked"
            action_decision = evaluate_scope(point.action, policy)
            if not action_decision.allowed or action_decision.reason not in {"target_url", "target_url_no_frag", "target_url_no_query"}:
                return "scope_blocked" if action_decision.reason != "excluded_url" else "excluded_url"
        return ""

    async def list_scanner_capabilities(self) -> dict:
        """Return discovered injection points and their carrier/check support."""
        await self.observe_page()
        items = []
        gaps = []
        for point_id, raw in sorted(self.points.items()):
            point, metadata = self._resolve(point_id)
            carrier = "query" if raw.get("location") == "url_param" else raw.get("location", "unknown")
            if point is None:
                reason = (
                    "endpoint was redacted in the checkpoint; rediscover this input point"
                    if metadata and metadata.get("resume_unavailable")
                    else "authenticated context not shareable for this carrier"
                )
                items.append({"injection_point_id": point_id, "carrier": carrier, "checks": [], "status": "unsupported", "reason": reason})
                gaps.append(f"unsupported_carrier:{carrier}")
                continue
            reason = self._scope_reason(point, str(metadata.get("parameter_id", "")))
            status = "blocked" if reason else "supported"
            items.append({"injection_point_id": point_id, "carrier": carrier, "checks": sorted(SUPPORTED_CHECKS), "status": status, "reason": reason})
        if gaps:
            self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, *gaps])
        return {"capabilities": items}

    def schedule_scanner(self, injection_point_id: str, check: str) -> dict:
        """Queue an additional scanner work item without sending a request."""
        check = str(check or "").lower()
        point, metadata = self._resolve(injection_point_id)
        if check not in SUPPORTED_CHECKS:
            return {"status": "unsupported", "reason": "check must be one of xss, sqli, os"}
        if point is None or metadata is None:
            return {"status": "unsupported", "reason": "unknown injection point ID"}
        reason = self._scope_reason(point, str(metadata.get("parameter_id", "")))
        if reason:
            self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, f"{reason}:{injection_point_id}"])
            return {"status": "blocked", "reason": reason}
        existing = next((item for item in self.harness.state.work_queue
                         if item.role == AgentRole.PROBE_SPECIALIST
                         and item.target == injection_point_id
                         and item.check_type == check), None)
        work = self.harness.enqueue(AgentRole.PROBE_SPECIALIST, injection_point_id, check_type=check)
        self.work_specs[work.work_id] = (injection_point_id, check)
        return {"work_id": work.work_id, "status": "already_scheduled" if existing else "planned"}

    def schedule_baselines(self, *, point_ids=None) -> int:
        """Deterministically queue every supported point/check pair."""
        count = 0
        for point_id in sorted(point_ids if point_ids is not None else self.points):
            point, metadata = self._resolve(point_id)
            if point is None:
                self.harness.note_coverage(coverage_gaps=[f"unsupported_carrier:{metadata.get('location', 'unknown')}"])
                continue
            for check in sorted(SUPPORTED_CHECKS):
                queued = self.schedule_scanner(point_id, check)
                count += queued.get("status") == "planned"
        return count

    async def run_scanner_work(self, work_id: str) -> dict:
        """Execute a queued item with a fresh, verified handoff session."""
        work = next((item for item in self.harness.state.work_queue if item.work_id == work_id), None)
        if work is None:
            return {"status": "failed", "reason": "unknown work ID; schedule the scanner work first"}
        if work.status not in {WorkStatus.PLANNED, WorkStatus.RUNNING, WorkStatus.INCONCLUSIVE, WorkStatus.TRANSIENT_FAILURE}:
            return {"status": "blocked", "reason": "work is already running or complete; schedule new work to retry"}
        was_claimed = work.status == WorkStatus.RUNNING
        spec = self.work_specs.get(work_id)
        if spec is None:
            try:
                spec = (work.target, work.check_type)
            except Exception:
                spec = None
        if not spec:
            self.harness.finish_work(work_id, WorkStatus.FAILED, rejection_reason="scanner work cannot be resumed; schedule it again")
            return {"status": "failed", "reason": "scanner work metadata is unavailable; schedule it again"}
        point_id, check = spec
        point, metadata = self._resolve(point_id)
        if point is None or check not in SUPPORTED_CHECKS:
            self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="unsupported carrier or check")
            return {"status": "unsupported", "reason": "this carrier or check is not supported"}
        reason = self._scope_reason(point, str(metadata.get("parameter_id", "")))
        if reason:
            self.harness.finish_work(work_id, WorkStatus.SCOPE_BLOCKED, rejection_reason=reason)
            return {"status": "blocked", "reason": reason}
        if self.harness.remaining_steps <= 0:
            self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, f"scanner_budget_exhausted:{point_id}:{check}"])
            self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="scanner work budget exhausted")
            return {"status": "blocked", "reason": "scanner work budget is exhausted; increase the run budget and retry"}
        if self._already_dispatched(work_id):
            self.harness.finish_work(work_id, WorkStatus.INCONCLUSIVE, rejection_reason="prior dispatch outcome is unknown; automatic replay was suppressed")
            return {"status": "inconclusive", "reason": "a prior attempt may have reached the target; automatic replay was suppressed"}
        binding = self._verification_binding(point, metadata, check)
        binding_digest = self._binding_digest(binding)
        try:
            cookies = await self.scanner._capture_cookies(self.scanner._active_session)
        except Exception:
            cookies = None
        if not cookies:
            self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="authentication state unavailable")
            return {"status": "blocked", "reason": "current authentication state is unavailable; re-authenticate and retry"}
        engine = None
        from wscan import url_scope
        secret_registry = getattr(url_scope, "_SECRET_VALUES", None)
        secret_snapshot = dict(secret_registry) if isinstance(secret_registry, dict) else None
        skipped_snapshot = list(getattr(url_scope, "skipped_secret_labels", []))
        try:
            handoff = self._handoff(cookies)
            engine = self.engine_factory(check, handoff)
            from wscan.llm_agent_browser import security_probe_allowed
            if (
                not security_probe_allowed(
                    point.url, engine.target_urls, engine.exclude_urls,
                    access_urls=engine.access_urls, field_name=metadata["parameter_id"],
                    exclude_fields=engine.exclude_fields,
                )
                or not engine._is_attack_target_url(point.url)
                or engine._is_url_excluded(point.url)
                or (point.action and (
                    not security_probe_allowed(
                        point.action, engine.target_urls, engine.exclude_urls,
                        access_urls=engine.access_urls, field_name=metadata["parameter_id"],
                        exclude_fields=engine.exclude_fields,
                    )
                    or not engine._is_attack_target_url(point.action)
                    or engine._is_url_excluded(point.action)
                ))
            ):
                self.harness.finish_work(work_id, WorkStatus.SCOPE_BLOCKED, rejection_reason="engine scope guard rejected injection point")
                return {"status": "blocked", "reason": "engine scope policy rejected the injection point"}
            url_scope.register_secret_values((f"agent_cookie_{i}", c.get("value", "")) for i, c in enumerate(cookies) if isinstance(c, dict))
            await engine._browser.init()
            from wscan.runtime_scope_guard import ScopePolicy
            install_guard = getattr(engine._browser, "install_runtime_scope_guard", None)
            if not callable(install_guard) or not await install_guard(
                ScopePolicy.from_engine(engine), on_block=self._record_scope_block,
            ):
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="runtime scope guard unavailable")
                return {"status": "blocked", "reason": "runtime scope guard could not be enabled; scanner work was not sent"}
            if not await engine._seed_and_verify_handoff_cookies(engine._browser):
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="authentication unverified")
                return {"status": "blocked", "reason": "authentication could not be verified; re-authenticate and retry"}
            if not was_claimed:
                work.transition_to(WorkStatus.RUNNING)
                work.attempts += 1
                self.harness.checkpoint()
            scanner = engine.scanners[check]
            # BaseScanner reroutes selected SPA/API GET query points through HTTPX.
            # Preflight on the guarded WScan browser and fail closed before payload dispatch.
            await engine._browser.navigate(point.url)
            if scanner._should_route_to_api_get(point):
                self.harness.note_coverage(coverage_gaps=[f"unsupported_carrier:query_api_get:{point_id}"])
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="HTTPX API GET carrier unsupported")
                return {"status": "unsupported", "reason": "this query input uses HTTPX transport; only Playwright form and query inputs are supported"}
            self.harness.record_probe_attempt(
                target_url=point.url, check_type=check, work_id=work_id,
                status="dispatching", binding=binding, binding_digest=binding_digest,
            )
            findings = await asyncio.wait_for(
                scanner.scan_field(point.url, point.form_index, metadata["field"], point.legacy_is_url_param()),
                timeout=180,
            )
            verified = []
            verification_inconclusive = False
            for finding in findings:
                verification = await asyncio.wait_for(scanner.verify_finding(finding), timeout=180)
                if verification is True:
                    verified.append(finding)
                elif verification is None:
                    verification_inconclusive = True
            status = WorkStatus.INCONCLUSIVE if verification_inconclusive and not verified else WorkStatus.COMPLETE
            sanitized_findings = self._sanitize_findings(verified)
            evidence_ids = self._persist_scanner_evidence(
                work_id, point_id, check, binding_digest, sanitized_findings,
            )
            self.findings[work_id] = sanitized_findings
            self.harness.record_probe_attempt(
                target_url=point.url, check_type=check, work_id=work_id,
                status="inconclusive" if status == WorkStatus.INCONCLUSIVE else "completed",
                evidence_id=work_id, binding=binding, binding_digest=binding_digest,
            )
            self.harness.finish_work(
                work_id, status,
                summary=f"deterministic scanner work finished: {len(verified)} verified findings",
                evidence_ids=evidence_ids,
            )
            for hypothesis in self.harness.state.hypotheses:
                hypothesis_id = str(hypothesis.get("candidate_id", ""))
                if hypothesis.get("injection_point_id") == point_id and hypothesis.get("check_type") == check:
                    outcome = "confirmed" if verified else "inconclusive" if verification_inconclusive else "rejected"
                    reason = "" if outcome == "confirmed" else (
                        "verify_finding returned None" if outcome == "inconclusive"
                        else "deterministic scanner did not confirm the hypothesis"
                    )
                    self._record_hypothesis_outcome(hypothesis_id, outcome, reason, work_id=work_id)
            return {
                "status": "inconclusive" if status == WorkStatus.INCONCLUSIVE else "completed",
                "verified_count": len(verified), "work_id": work_id,
            }
        except asyncio.TimeoutError:
            work.transition_to(WorkStatus.TRANSIENT_FAILURE, rejection_reason="scanner timed out")
            self.harness.checkpoint()
            self._mark_hypotheses(point_id, check, "inconclusive", "scanner timed out", work_id=work_id)
            return {"status": "timeout", "reason": "scanner timed out; the work remains eligible for resume"}
        except Exception as exc:
            self.harness.finish_work(work_id, WorkStatus.FAILED, rejection_reason=f"scanner error: {type(exc).__name__}")
            self._mark_hypotheses(point_id, check, "inconclusive", f"scanner failed: {type(exc).__name__}", work_id=work_id)
            return {"status": "failed", "reason": "scanner failed; inspect the redacted run log and retry the work"}
        finally:
            if engine is not None and getattr(engine, "_browser", None) is not None:
                try:
                    await engine._browser.close()
                except Exception:
                    pass
            if secret_snapshot is not None:
                secret_registry.clear()
                secret_registry.update(secret_snapshot)
                url_scope.skipped_secret_labels[:] = skipped_snapshot

    async def verify_hypothesis(self, hypothesis_id: str) -> dict:
        """Schedule deterministic verification for a known hypothesis."""
        hypothesis_id = str(hypothesis_id)
        hypothesis = next((item for item in self.harness.state.hypotheses
                           if str(item.get("candidate_id", "")) == hypothesis_id), None)
        if not hypothesis:
            return {"status": "inconclusive", "reason": "unknown hypothesis ID"}
        recorded, ledger_error = self._verification_record(hypothesis_id)
        record_reason = self._verification_consistency_reason(recorded, hypothesis) if recorded is not None else ""
        if recorded is not None and not record_reason:
            self._restore_hypothesis_outcome(hypothesis_id, recorded)
            return self._verification_result(hypothesis_id, recorded)
        unverifiable_checkpoint = bool(
            recorded is not None or ledger_error or self._checkpoint_claims_confirmation(hypothesis)
        )
        if unverifiable_checkpoint:
            self._downgrade_unverifiable(
                hypothesis_id,
                f"inconsistent_verification_record: {record_reason}" if record_reason else None,
            )
        point_id = hypothesis.get("injection_point_id", "")
        check = hypothesis.get("check_type", "")
        scheduled = self.schedule_scanner(point_id, check)
        if scheduled.get("status") not in {"planned", "already_scheduled"}:
            reason = scheduled.get("reason", "verification unavailable")
            if unverifiable_checkpoint:
                reason = f"unverifiable_checkpoint: {reason}"
            self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason)
            return {"status": "inconclusive", "reason": reason}
        self.work_specs[scheduled["work_id"]] = (point_id, check)
        existing = next(item for item in self.harness.state.work_queue if item.work_id == scheduled["work_id"])
        if existing.status == WorkStatus.COMPLETE:
            reason = (
                f"inconsistent_verification_record: {record_reason}; replay was suppressed"
                if record_reason else
                "unverifiable_checkpoint: completed scanner result has no valid deterministic evidence; replay was suppressed"
            )
            self._downgrade_unverifiable(hypothesis_id, reason)
            return {"status": "inconclusive", "reason": reason, "hypothesis_id": hypothesis_id, "work_id": existing.work_id}
        result = await self.run_scanner_work(scheduled["work_id"])
        recorded, ledger_error = self._verification_record(hypothesis_id)
        record_reason = self._verification_consistency_reason(recorded, hypothesis) if recorded is not None else ""
        if recorded is not None and not record_reason:
            self._restore_hypothesis_outcome(hypothesis_id, recorded)
            return {**self._verification_result(hypothesis_id, recorded), "work_id": scheduled["work_id"]}
        if record_reason:
            reason = f"inconsistent_verification_record: {record_reason}; automatic replay was suppressed"
        elif recorded is not None or ledger_error:
            reason = "unverifiable_checkpoint: deterministic verification ledger is unreadable or inconsistent; automatic replay was suppressed"
        else:
            reason = result.get("reason") or "scanner could not complete deterministic verification"
        self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason, work_id=scheduled["work_id"])
        return {"status": "inconclusive", "reason": reason, "hypothesis_id": hypothesis_id, "work_id": scheduled["work_id"]}

    def register_hypothesis(self, hypothesis: dict) -> str:
        safe = dict(hypothesis)
        requested_point_id = str(safe.get("injection_point_id", ""))
        if requested_point_id:
            point, _ = self._resolve(requested_point_id)
            safe["injection_point_id"] = requested_point_id if point is not None else ""
        else:
            matches = [pid for pid, raw in self.points.items()
                       if isinstance(raw, dict) and raw.get("url") == safe.get("url")
                       and raw.get("parameter_id") == safe.get("field_name")
                       and self._resolve(pid)[0] is not None]
            safe["injection_point_id"] = matches[0] if len(matches) == 1 else ""
        hypothesis_id = str(safe.get("candidate_id") or hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()[:20])
        safe["candidate_id"] = hypothesis_id
        self.harness.note_hypotheses([safe])
        return str(safe["injection_point_id"])

    def _record_hypothesis_outcome(
        self, hypothesis_id: str, outcome: str, reason: str, *, work_id: str = "",
        injection_point_id: str = "",
    ) -> None:
        # Checkpoint は信頼されたローカル状態であり、書込み権限者による整合した偽造は防御対象外。
        confirmed = outcome == "confirmed"
        point_id = injection_point_id or next((str(item.get("injection_point_id", ""))
            for item in self.harness.state.hypotheses
            if str(item.get("candidate_id", "")) == hypothesis_id), "")
        head_id = self._current_head_id()
        if confirmed and (not work_id or not point_id or not head_id):
            confirmed = False
            outcome = "inconclusive"
            reason = reason or "unverifiable_checkpoint: verification identifiers are incomplete"
        binding = None
        binding_digest = ""
        point, metadata = self._resolve(point_id) if point_id else (None, None)
        hypothesis = next((item for item in self.harness.state.hypotheses
                           if str(item.get("candidate_id", "")) == hypothesis_id), {})
        if point is not None and metadata is not None:
            binding = self._verification_binding(point, metadata, str(hypothesis.get("check_type", "")))
            binding_digest = self._binding_digest(binding)
        work = next((item for item in self.harness.state.work_queue if item.work_id == work_id), None) if work_id else None
        evidence_ids = tuple(work.evidence_ids) if confirmed and work is not None else ()
        if confirmed and not evidence_ids:
            confirmed = False
            outcome = "inconclusive"
            reason = reason or "inconsistent_verification_record: confirmed outcome has no scanner finding evidence"
        self.harness.record_verification(
            hypothesis_id, reproduced=confirmed, status=outcome,
            method="deterministic", work_id=work_id,
            scan_id=self.harness.state.run_id, head_id=head_id,
            injection_point_id=point_id, evidence_ids=evidence_ids,
            deterministic_confirmed=confirmed, rejection_reason=reason,
            binding=binding, binding_digest=binding_digest,
        )
        self.harness.update_hypothesis(
            hypothesis_id,
            status="deterministic_confirmed" if confirmed else "agent_only",
            verification_outcome=outcome,
            deterministic_confirmed=confirmed,
            source_label="agent_deterministic_confirmed" if confirmed else "agent_unverified",
            rejection_reason=reason,
        )

    def _current_head_id(self) -> str:
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
                stderr=subprocess.DEVNULL, text=True, timeout=2,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _checkpoint_claims_confirmation(hypothesis: dict) -> bool:
        return bool(
            hypothesis.get("deterministic_confirmed")
            or hypothesis.get("verification_outcome") == "confirmed"
            or hypothesis.get("status") in {"confirmed", "deterministic_confirmed", "reproduced"}
            or hypothesis.get("source_label") == "agent_deterministic_confirmed"
        )

    def _downgrade_unverifiable(self, hypothesis_id: str, reason: str | None = None) -> None:
        self.harness.update_hypothesis(
            hypothesis_id, status="agent_only", verification_outcome="inconclusive",
            deterministic_confirmed=False, source_label="agent_unverified",
            rejection_reason=reason or "unverifiable_checkpoint: deterministic ledger evidence is missing or inconsistent",
        )

    def _restore_hypothesis_outcome(self, hypothesis_id: str, record: dict) -> None:
        outcome = str(record.get("status", "inconclusive"))
        confirmed = outcome == "confirmed"
        self.harness.update_hypothesis(
            hypothesis_id,
            status="deterministic_confirmed" if confirmed else "agent_only",
            verification_outcome=outcome,
            deterministic_confirmed=confirmed,
            source_label="agent_deterministic_confirmed" if confirmed else "agent_unverified",
            rejection_reason=str(record.get("rejection_reason", "")),
        )

    def _verification_is_trustworthy(self, record: dict, hypothesis: dict) -> bool:
        return not self._verification_consistency_reason(record, hypothesis)

    def _verification_consistency_reason(self, record: dict, hypothesis: dict) -> str:
        point_id = str(hypothesis.get("injection_point_id", ""))
        point, metadata = self._resolve(point_id)
        if point is None or metadata is None:
            return "unknown injection point"
        if (
            not isinstance(record.get("verification_id"), str) or not record.get("verification_id")
            or not isinstance(record.get("work_id"), str) or not record.get("work_id")
            or record.get("candidate_id") != hypothesis.get("candidate_id")
            or record.get("injection_point_id") != point_id
            or record.get("method") != "deterministic"
        ):
            return "verification identifiers are incomplete or inconsistent"
        if not isinstance(record.get("binding"), dict):
            return "verification binding is missing"
        ledger_binding = dict(record["binding"])
        # Legacy scalar columns remain for reporting; fold them into the single binding hash.
        ledger_binding["scan_id"] = str(record.get("scan_id", ""))
        ledger_binding["code_head"] = str(record.get("head_id", ""))
        record = {**record, "binding": ledger_binding}
        expected_binding = self._verification_binding(point, metadata, str(hypothesis.get("check_type", "")))
        work = next((item for item in self.harness.state.work_queue if item.work_id == record.get("work_id")), None)
        if (
            work is None or work.target != point_id
            or work.check_type != hypothesis.get("check_type")
        ):
            return "scanner work does not match the hypothesis"
        outcome = record.get("status")
        if outcome in {"confirmed", "rejected"} and work.status != WorkStatus.COMPLETE:
            return "scanner work is not complete"
        if outcome == "inconclusive" and work.status not in {WorkStatus.INCONCLUSIVE, WorkStatus.COMPLETE}:
            return "scanner work is not complete"
        consistency_reason = _verification_consistency_reason(
            record,
            expected_binding=expected_binding,
            injection_point_id=point_id,
            check_type=str(hypothesis.get("check_type", "")),
            scanner_evidence=self.harness.state.scanner_evidence,
            work_evidence_ids=tuple(work.evidence_ids),
        )
        if consistency_reason:
            return consistency_reason
        probe_status = "completed" if outcome in {"confirmed", "rejected"} else None
        if not self._probe_evidence_matches(record, outcome=probe_status):
            return "scanner probe evidence is missing or inconsistent"
        return ""

    def _probe_evidence_matches(self, verification: dict, *, outcome: str | None) -> bool:
        path = self.harness.probe_attempts_path
        if not path.exists():
            return False
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                attempt = json.loads(line)
                if (
                    attempt.get("work_id") == verification.get("work_id")
                    and attempt.get("evidence_id") == verification.get("work_id")
                    and (outcome is None or attempt.get("status") == outcome)
                ):
                    point_id = str(next((item.get("injection_point_id") for item in self.harness.state.hypotheses
                                         if item.get("candidate_id") == verification.get("candidate_id")), ""))
                    point, metadata = self._resolve(point_id)
                    if point is None or metadata is None:
                        return False
                    expected = self._verification_binding(
                        point, metadata, str(next((item.get("check_type") for item in self.harness.state.hypotheses
                                                  if item.get("candidate_id") == verification.get("candidate_id")), "")),
                    )
                    # Probe destination is independently observed from the persisted request record.
                    if not isinstance(attempt.get("binding"), dict):
                        return False
                    probe_binding = dict(attempt["binding"])
                    from wscan.request_logger import redact_url
                    probe_binding["endpoint_identity"] = endpoint_identity(redact_url(str(attempt.get("target_url", ""))))
                    probe_binding["check"] = str(attempt.get("check_type", ""))
                    probe_binding["scan_id"] = str(attempt.get("run_id", ""))
                    if (
                        not attempt.get("binding_digest")
                        or self._binding_digest(probe_binding) != attempt.get("binding_digest")
                        or attempt.get("binding_digest") != self._binding_digest(expected)
                        or not self._recorded_target_in_scope(str(attempt.get("target_url", "")))
                    ):
                        return False
                    return True
            return False
        except (OSError, ValueError, AttributeError):
            return False

    @staticmethod
    def _binding_digest(binding: dict) -> str:
        canonical = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _verification_binding(self, point: InjectionPoint, metadata: dict, check: str) -> dict:
        from wscan.request_logger import redact_url
        # Only the endpoint identity is persisted; query secrets are redacted before canonicalization.
        endpoint = endpoint_identity(redact_url(point.url))
        carrier = str(point.carrier.value)
        parameter_identity = {
            "parameter_id": str(metadata.get("parameter_id", point.parameter_id)),
            "form_index": int(point.form_index) if carrier == "form" else None,
            "method": str(point.method or "").upper() if carrier == "form" else "",
            "action_identity": endpoint_identity(redact_url(point.action)) if carrier == "form" and point.action else "",
        }
        return {
            "endpoint_identity": endpoint,
            "carrier": carrier,
            "parameter_identity": parameter_identity,
            "check": str(check),
            "scan_id": str(self.harness.state.run_id),
            "code_head": self._current_head_id(),
        }

    def _recorded_target_in_scope(self, target_url: str) -> bool:
        from wscan.llm_agent_browser import _url_is_excluded, security_probe_allowed
        args = self.scanner
        return bool(
            target_url
            and not _url_is_excluded(target_url, args.exclude_urls)
            and security_probe_allowed(target_url, args.target_urls, args.exclude_urls,
                                       access_urls=args.access_urls)
            and evaluate_scope(target_url, ScopePolicy(
                target_urls=tuple(args.target_urls), access_urls=tuple(args.access_urls),
                exclude_urls=tuple(args.exclude_urls), login_url=args.login_url,
            )).reason in {"target_url", "target_url_no_frag", "target_url_no_query"}
        )

    def _mark_hypotheses(self, point_id: str, check: str, outcome: str, reason: str, *, work_id: str = "") -> None:
        for hypothesis in self.harness.state.hypotheses:
            if hypothesis.get("injection_point_id") == point_id and hypothesis.get("check_type") == check:
                self._record_hypothesis_outcome(str(hypothesis.get("candidate_id", "")), outcome, reason, work_id=work_id)

    def _verification_record(self, candidate_id: str) -> tuple[dict | None, bool]:
        path = self.harness.verification_results_path
        if not path.exists():
            return None, False
        latest = None
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("candidate_id") == candidate_id and record.get("method") == "deterministic":
                    latest = record
            return latest, False
        except (OSError, ValueError, AttributeError):
            return None, True

    @staticmethod
    def _verification_result(candidate_id: str, record: dict) -> dict:
        outcome = str(record.get("status", "inconclusive"))
        result = {"status": outcome, "hypothesis_id": candidate_id}
        if record.get("rejection_reason"):
            result["reason"] = record["rejection_reason"]
        return result

    def _already_dispatched(self, work_id: str) -> bool:
        path = self.harness.probe_attempts_path
        if not path.exists():
            return False
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("work_id") == work_id and record.get("status") in {"dispatching", "sent"}:
                    return True
            return False
        except (OSError, ValueError, AttributeError):
            return True

    def _record_scope_block(self, _url: str, reason: str) -> None:
        gap = f"scanner_network_scope_blocked:{reason}"
        self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, gap])

    def _sanitize_findings(self, findings: list) -> list:
        from wscan.llm_agent_browser import AgentFinding
        from wscan.request_logger import redact_text, redact_url
        result = []
        for finding in findings:
            result.append(AgentFinding(
                check_type=finding.check_type, severity=finding.severity, url=redact_url(finding.url),
                field_name=redact_text(finding.field_name), payload=redact_text(finding.payload),
                evidence=redact_text(finding.evidence), source="deterministic", agent_verified=True,
                deterministic_confirmed=True,
            ))
        return result

    def _persist_scanner_evidence(
        self, work_id: str, point_id: str, check: str, binding_digest: str, findings: list,
    ) -> list[str]:
        evidence_ids = []
        for index, finding in enumerate(findings):
            finding_dict = finding.to_dict()
            canonical = json.dumps(
                {"work_id": work_id, "binding_digest": binding_digest,
                 "index": index, "finding": finding_dict},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            )
            evidence_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
            self.harness.record_scanner_evidence({
                "evidence_id": evidence_id,
                "work_id": work_id,
                "injection_point_id": point_id,
                "check_type": check,
                "binding_digest": binding_digest,
                "finding": finding_dict,
            })
            evidence_ids.append(evidence_id)
        return evidence_ids

    def agent_findings(self) -> list:
        return [finding for findings in self.findings.values() for finding in findings]

    def register_controller_actions(self, controller) -> None:
        controller.action("List server-discovered scanner injection points and capabilities.")(self.list_scanner_capabilities)
        controller.action("Queue deterministic scanner work by injection point ID and check name.")(self.schedule_scanner)
        controller.action("Run queued scanner work by work ID.")(self.run_scanner_work)
        controller.action("Queue deterministic verification for a hypothesis ID.")(self.verify_hypothesis)

    async def observe_page(self, browser=None, current_url: str = "") -> None:
        browser = browser or self.scanner._active_session
        if browser is None or not callable(getattr(browser, "get_current_page", None)):
            return
        try:
            page = await browser.get_current_page()
            if page is None or not callable(getattr(page, "evaluate", None)):
                return
            url = str(current_url or getattr(page, "url", "") or "")
            data = await page.evaluate("""() => [...document.forms].map((f, i) => ({i, action:f.action || location.href, method:(f.method||'GET').toUpperCase(), fields:[...f.elements].filter(e=>e.name).map(e=>({name:e.name,type:e.type||'text'}))}))""")
            parsed = urlsplit(url)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                point = InjectionPoint.for_url_param(url, name)
                point_id = self.add_point(point, {"name": name, "type": "text"})
                self.schedule_baselines(point_ids=(point_id,))
            for form in data or []:
                action = str(form.get("action") or url)
                for field in form.get("fields", []):
                    name = str(field.get("name") or "")
                    if not name:
                        continue
                    point = InjectionPoint.for_form(url, name, int(form.get("i", 0)), method=form.get("method", "GET"), action=action)
                    point_id = self.add_point(point, field)
                    self.schedule_baselines(point_ids=(point_id,))
        except Exception:
            self.harness.note_coverage(coverage_gaps=["injection_point_discovery_failed"])

    def _handoff(self, cookies):
        from wscan.agent_engine import AgentHandoffData
        return AgentHandoffData(cookies=[dict(cookie) for cookie in cookies])

    def _new_engine(self, check, handoff):
        from wscan.engine import ScanEngine
        headers = {
            key: value for key, value in self.scanner.extra_headers.items()
            if str(key).lower() != "cookie"
        }
        return ScanEngine(
            self.scanner.target_url, checks=[check], headless=True, open_report=False,
            output_dir=str(Path(self.harness.output_dir) / "scanner-actions"),
            target_urls=self.scanner.target_urls, access_urls=self.scanner.access_urls,
            exclude_urls=self.scanner.exclude_urls, exclude_fields=self.scanner.exclude_fields,
            handoff_cookies=handoff.cookies, proxy=self.scanner.proxy,
            auth_user=self.scanner.auth_user, auth_pass=self.scanner.auth_pass,
            login_url=self.scanner.login_url, headers=headers,
        )
