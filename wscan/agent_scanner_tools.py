"""Guarded scanner actions exposed to the Agent browser-use controller."""
from __future__ import annotations

import asyncio
import hashlib
import json
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from wscan.agent_harness import AgentRole, WorkStatus
from wscan.injection_point import InjectionPoint
from wscan.runtime_scope_guard import ScopePolicy, evaluate_scope


SUPPORTED_CHECKS = frozenset({"xss", "sqli", "os"})
_SUPPORTED_CARRIERS = frozenset({"form", "query"})


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
                status="dispatching",
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
            self.findings[work_id] = self._sanitize_findings(verified)
            self.harness.record_probe_attempt(
                target_url=point.url, check_type=check, work_id=work_id,
                status="inconclusive" if status == WorkStatus.INCONCLUSIVE else "completed",
                evidence_id=work_id,
            )
            self.harness.finish_work(work_id, status, summary=f"deterministic scanner work finished: {len(verified)} verified findings")
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
        if recorded is not None:
            return self._verification_result(hypothesis_id, recorded)
        if ledger_error:
            reason = "deterministic verification ledger is unreadable; automatic replay was suppressed"
            self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason)
            return {"status": "inconclusive", "reason": reason}
        outcome = str(hypothesis.get("verification_outcome", ""))
        if outcome in {"confirmed", "rejected", "inconclusive"}:
            return self._verification_result(hypothesis_id, hypothesis)
        point_id = hypothesis.get("injection_point_id", "")
        check = hypothesis.get("check_type", "")
        scheduled = self.schedule_scanner(point_id, check)
        if scheduled.get("status") not in {"planned", "already_scheduled"}:
            reason = scheduled.get("reason", "verification unavailable")
            self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason)
            return {"status": "inconclusive", "reason": reason}
        self.work_specs[scheduled["work_id"]] = (point_id, check)
        existing = next(item for item in self.harness.state.work_queue if item.work_id == scheduled["work_id"])
        if existing.status == WorkStatus.COMPLETE:
            reason = "completed scanner result is unavailable after resume; automatic replay was suppressed"
            self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason, work_id=existing.work_id)
            return {"status": "inconclusive", "reason": reason, "hypothesis_id": hypothesis_id, "work_id": existing.work_id}
        result = await self.run_scanner_work(scheduled["work_id"])
        recorded, ledger_error = self._verification_record(hypothesis_id)
        if recorded is not None:
            return {**self._verification_result(hypothesis_id, recorded), "work_id": scheduled["work_id"]}
        if ledger_error:
            reason = "deterministic verification ledger is unreadable; automatic replay was suppressed"
        else:
            reason = result.get("reason") or "scanner could not complete deterministic verification"
        self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason, work_id=scheduled["work_id"])
        return {"status": "inconclusive", "reason": reason, "hypothesis_id": hypothesis_id, "work_id": scheduled["work_id"]}

    def register_hypothesis(self, hypothesis: dict) -> str:
        safe = dict(hypothesis)
        safe["injection_point_id"] = next((pid for pid, raw in self.points.items()
            if raw.get("url") == safe.get("url")
            and raw.get("parameter_id") == safe.get("field_name")), "")
        hypothesis_id = str(safe.get("candidate_id") or hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()[:20])
        safe["candidate_id"] = hypothesis_id
        self.harness.note_hypotheses([safe])
        return str(safe["injection_point_id"])

    def _record_hypothesis_outcome(self, hypothesis_id: str, outcome: str, reason: str, *, work_id: str = "") -> None:
        confirmed = outcome == "confirmed"
        self.harness.record_verification(
            hypothesis_id, reproduced=confirmed, status=outcome,
            method="deterministic", work_id=work_id,
            deterministic_confirmed=confirmed, rejection_reason=reason,
        )
        self.harness.update_hypothesis(
            hypothesis_id,
            status="deterministic_confirmed" if confirmed else "agent_only",
            verification_outcome=outcome,
            deterministic_confirmed=confirmed,
            source_label="agent_deterministic_confirmed" if confirmed else "agent_unverified",
            rejection_reason=reason,
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
        outcome = record.get("status", "inconclusive")
        if record.get("deterministic_confirmed") and record.get("reproduced"):
            outcome = "confirmed"
        elif outcome in {"not_reproduced", "rejected"}:
            outcome = "rejected"
        elif outcome not in {"confirmed", "rejected", "inconclusive"}:
            outcome = "inconclusive"
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
