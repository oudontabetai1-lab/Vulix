from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from wscan.agent_harness import AgentHarness, AgentRole, AgentRunSpec, WorkStatus
from wscan.agent_scanner_tools import AgentScannerTools
from wscan.injection_point import InjectionPoint
from tests.fixtures.agent_lab_app import create_app


class _AgentScanner:
    target_url = "https://target.test/"
    target_urls = ["https://target.test/"]
    access_urls = ["https://target.test/login"]
    exclude_urls = ["https://target.test/private*"]
    exclude_fields = ["ignored"]
    login_url = "https://target.test/login"
    proxy = ""
    _active_session = object()

    def __init__(self, cookies):
        self.cookies = cookies

    async def _capture_cookies(self, _session):
        if isinstance(self.cookies, Exception):
            raise self.cookies
        return list(self.cookies)


class _FakeScanner:
    def __init__(self, *, findings=None, error=None, api_get=False, verify_result=True):
        self.findings = findings or []
        self.error = error
        self.calls = []
        self.api_get = api_get
        self.verify_result = verify_result

    async def scan_field(self, *args):
        self.calls.append(args)
        if self.error:
            raise self.error
        return self.findings

    async def verify_finding(self, _finding):
        return self.verify_result

    def _should_route_to_api_get(self, _point):
        return self.api_get


class _FakeBrowser:
    def __init__(self):
        self.closed = False
        self.scope_policy = None

    async def init(self):
        return None

    async def close(self):
        self.closed = True

    async def navigate(self, _url):
        return True

    async def install_runtime_scope_guard(self, policy, *, on_block=None):
        self.scope_policy = policy
        self.on_block = on_block
        return True


class _PageSession:
    def __init__(self, url):
        self.page = SimpleNamespace(url=url)

    async def get_current_page(self):
        return self.page


class _FakeEngine:
    def __init__(self, check, handoff, finding=None, error=None, auth=True, scanner=None):
        self.handoff = handoff
        self._browser = _FakeBrowser()
        self.headers = {}
        self.scanner = scanner or _FakeScanner(findings=[finding] if finding else [], error=error)
        self.scanners = {check: self.scanner}
        self.auth = auth
        self.target_urls = ["https://target.test/"]
        self.access_urls = ["https://target.test/login"]
        self.exclude_urls = ["https://target.test/private*"]
        self.exclude_fields = ["ignored"]
        self.login_url = "https://target.test/login"
        self.header_scope_enforce = True

    def _is_attack_target_url(self, url):
        from wscan.url_scope import url_matches_any_scope
        return url_matches_any_scope(url, self.target_urls)

    def _is_url_excluded(self, url):
        from wscan.engine import is_url_excluded
        return is_url_excluded(url, self.exclude_urls)

    async def _seed_and_verify_handoff_cookies(self, _browser):
        return self.auth

    def auth_headers(self, extra=None, *, url="", include_cookie=True):
        headers = dict(self.headers)
        from wscan.engine import _effective_synced_token
        from wscan import url_scope
        synced_token = _effective_synced_token(self)
        if url and synced_token:
            captured_origin = synced_token.get("origin", "")
            if captured_origin and url_scope.same_origin(url, captured_origin):
                token_headers = synced_token.get("headers", {})
                for k, v in token_headers.items():
                    if not any(ek.lower() == k.lower() for ek in headers):
                        headers[k] = v
        if extra:
            headers.update(extra)
        return headers


def _harness(path, *, resume=False):
    spec = AgentRunSpec(
        mode="agent", target_url="https://target.test/",
        target_urls=("https://target.test/",), access_urls=("https://target.test/login",),
        exclude_urls=("https://target.test/private*",), exclude_fields=("ignored",),
        checks=("xss", "sqli", "os"), provider="fake", model="fake", max_steps=20,
    )
    return AgentHarness(path, spec, resume=resume)


def test_capability_schema_ids_and_unsupported_carrier_coverage(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        tools = AgentScannerTools(_AgentScanner([]), harness)
        query_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        json_id = tools.add_point(InjectionPoint.for_json_body("POST", "https://target.test/api", "/q"))
        xml_id = tools.add_point(InjectionPoint.for_xml_body("POST", "https://target.test/api/xml", "/root/q"))
        response = await tools.list_scanner_capabilities()
        assert set(response) == {"capabilities"}
        by_id = {item["injection_point_id"]: item for item in response["capabilities"]}
        assert by_id[query_id]["status"] == "supported"
        assert by_id[query_id]["checks"] == ["os", "sqli", "xss"]
        assert by_id[json_id]["status"] == "supported"
        assert by_id[json_id]["checks"] == ["os", "sqli", "xss"]
        assert by_id[xml_id]["status"] == "unsupported"
        assert "xml_body carrier unsupported" in by_id[xml_id]["reason"]
        assert any("unsupported_carrier:xml_body" in gap for gap in harness.state.coverage_gaps)
    asyncio.run(scenario())


def test_redacted_injection_point_checkpoint_is_not_replayed(tmp_path):
    harness = _harness(tmp_path)
    tools = AgentScannerTools(_AgentScanner([]), harness)
    point_id = tools.add_point(InjectionPoint.for_url_param(
        "https://target.test/search?access_token=very-secret-value", "access_token"
    ))
    saved = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
    assert "very-secret-value" not in saved
    resumed = AgentScannerTools(_AgentScanner([]), _harness(tmp_path, resume=True))
    point, metadata = resumed._resolve(point_id)
    assert point is None
    assert metadata["resume_unavailable"] is True


def test_scope_access_only_and_exclusion_are_rejected_before_queue(tmp_path):
    harness = _harness(tmp_path)
    tools = AgentScannerTools(_AgentScanner([]), harness)
    ids = {
        label: tools.add_point(InjectionPoint.for_url_param(url, "q"))
        for label, url in (
            ("outside", "https://outside.test/search?q=1"),
            ("access", "https://target.test/login?q=1"),
            ("excluded", "https://target.test/private/search?q=1"),
        )
    }
    for point_id in ids.values():
        assert tools.schedule_scanner(point_id, "xss")["status"] == "blocked"
    assert harness.state.work_queue == []
    assert any("scope_blocked" in gap or "excluded_url" in gap for gap in harness.state.coverage_gaps)


def test_queue_deduplicates_and_verified_scanner_uses_latest_handoff_without_secrets(tmp_path):
    async def scenario():
        cookie = {"name": "session", "value": "fresh-secret-cookie", "domain": "target.test"}
        harness = _harness(tmp_path)
        scanner = _AgentScanner([cookie])
        finding = SimpleNamespace(
            check_type="xss", severity="high", url="https://target.test/search?q=1",
            field_name="q", payload="rotated-secret-cookie", evidence="rotated-secret-cookie",
        )
        engines = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff, finding=finding)
            engines.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        hypothesis = {
            "candidate_id": "candidate-1", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
        }
        hypothesis["injection_point_id"] = tools.register_hypothesis(hypothesis)
        harness.note_hypotheses([hypothesis])
        assert tools.schedule_baselines(point_ids=(point_id,)) == 3
        assert tools.schedule_baselines(point_ids=(point_id,)) == 0
        work = next(item for item in harness.state.work_queue if item.check_type == "xss")
        scanner.cookies = [{**cookie, "value": "rotated-secret-cookie"}]
        result = await tools.run_scanner_work(work.work_id)
        assert result["status"] == "completed"
        assert result["verified_count"] == 1
        assert engines[0].handoff.cookies[0]["value"] == "rotated-secret-cookie"
        assert engines[0].scanner.calls
        assert engines[0]._browser.closed
        stored_hypothesis = harness.state.hypotheses[0]
        assert stored_hypothesis["deterministic_confirmed"] is True
        assert stored_hypothesis["source_label"] == "agent_deterministic_confirmed"
        serialized = "\n".join(
            path.read_text(encoding="utf-8")
            for path in tmp_path.rglob("*") if path.is_file()
        )
        assert "fresh-secret-cookie" not in serialized
        assert "rotated-secret-cookie" not in serialized
        assert "rotated-secret-cookie" not in json.dumps(result)
    asyncio.run(scenario())


def test_injection_point_hash_collision_is_rejected(tmp_path, monkeypatch):
    monkeypatch.setattr(AgentScannerTools, "_point_id", staticmethod(lambda _point: "same-point-id"))
    tools = AgentScannerTools(_AgentScanner([]), _harness(tmp_path))
    tools.add_point(InjectionPoint.for_url_param("https://target.test/one?q=1", "q"))
    with pytest.raises(ValueError, match="ID collision"):
        tools.add_point(InjectionPoint.for_url_param("https://target.test/two?q=1", "q"))


@pytest.mark.parametrize("check", ["xss", "sqli", "os"])
def test_each_supported_check_runs_through_scanner_queue(tmp_path, check):
    async def scenario():
        harness = _harness(tmp_path / check)
        scanner = _AgentScanner([{"name": "session", "value": "current-cookie-value", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda name, handoff: _FakeEngine(name, handoff))
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, check)["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "completed"
        assert result["verified_count"] == 0
        assert harness.state.work_queue[0].check_type == check
        assert harness.state.work_queue[0].status == WorkStatus.COMPLETE
    asyncio.run(scenario())


def test_unavailable_or_unverified_auth_blocks_probe(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        tools = AgentScannerTools(_AgentScanner([]), harness, engine_factory=lambda *_: pytest.fail("engine must not be created"))
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "blocked"
        assert "re-authenticate" in result["reason"]
        assert harness.state.work_queue[0].status == WorkStatus.BLOCKED

        scanner = _AgentScanner([{ "name": "session", "value": "current-secret", "domain": "target.test" }])
        harness2 = _harness(tmp_path / "unverified")
        engine = _FakeEngine("xss", SimpleNamespace(cookies=[]), auth=False)
        tools2 = AgentScannerTools(scanner, harness2, engine_factory=lambda *_: engine)
        point_id2 = tools2.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id2 = tools2.schedule_scanner(point_id2, "xss")["work_id"]
        result2 = await tools2.run_scanner_work(work_id2)
        assert result2["status"] == "blocked"
        assert not engine.scanner.calls
    asyncio.run(scenario())


def test_engine_scope_gate_blocks_before_browser_or_scanner_send(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "current-cookie-value", "domain": "target.test"}])
        engines = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engine.target_urls = ["https://other.test/"]
            engines.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "blocked"
        assert result["reason"] == "engine scope policy rejected the injection point"
        assert not engines[0].scanner.calls
        assert engines[0]._browser.closed
        assert harness.state.work_queue[0].status == WorkStatus.SCOPE_BLOCKED
    asyncio.run(scenario())


def test_api_get_query_is_supported_and_budget_fails_closed(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "current-cookie-value", "domain": "target.test"}])
        engine = _FakeEngine("xss", SimpleNamespace(cookies=[]), scanner=_FakeScanner(api_get=True))
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/api?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "completed"
        assert engine.scanner.calls != []
        assert harness.state.work_queue[0].status == WorkStatus.COMPLETE

        harness2 = _harness(tmp_path / "budget")
        harness2.state.consumed_steps = harness2.spec.max_steps
        tools2 = AgentScannerTools(scanner, harness2, engine_factory=lambda *_: pytest.fail("budget must block before engine creation"))
        point_id2 = tools2.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id2 = tools2.schedule_scanner(point_id2, "xss")["work_id"]
        result2 = await tools2.run_scanner_work(work_id2)
        assert result2["status"] == "blocked"
        assert harness2.state.work_queue[0].status == WorkStatus.BLOCKED
        assert any("scanner_budget_exhausted" in gap for gap in harness2.state.coverage_gaps)
    asyncio.run(scenario())


def test_playwright_runtime_scope_guard_aborts_outside_and_access_only_routes():
    from wscan.browser import BrowserManager
    from wscan.runtime_scope_guard import ScopePolicy

    class _Context:
        async def route(self, pattern, handler):
            self.pattern = pattern
            self.handler = handler

        async def unroute(self, pattern, handler):
            assert pattern == "**/*"
            assert handler is self.handler
            self.handler = None

    class _Route:
        def __init__(self, url):
            self.request = SimpleNamespace(url=url)
            self.aborted = False
            self.fell_back = False

        async def abort(self):
            self.aborted = True

        async def fallback(self):
            self.fell_back = True

    browser = BrowserManager.__new__(BrowserManager)
    browser._context = _Context()
    browser._runtime_scope_route = None
    browser.request_logger = None
    blocked = []
    policy = ScopePolicy(
        target_urls=("https://target.test/",),
        access_urls=("https://target.test/login",),
    )
    assert asyncio.run(browser.install_runtime_scope_guard(policy, on_block=lambda url, reason: blocked.append(reason)))

    async def scenario():
        target = _Route("https://target.test/search")
        outside = _Route("https://outside.test/collect")
        access = _Route("https://target.test/login")
        await browser._context.handler(target)
        await browser._context.handler(outside)
        await browser._context.handler(access)
        assert target.fell_back and not target.aborted
        assert outside.aborted and access.aborted
        assert blocked == ["out_of_scope_destination", "access_url"]
        await browser.clear_runtime_scope_guard()
        assert browser._context.handler is None
    asyncio.run(scenario())


def test_unknown_outcome_is_not_replayed_after_resume(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{ "name": "session", "value": "fresh-cookie-value", "domain": "target.test" }])
        calls = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff, error=asyncio.TimeoutError())
            calls.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "timeout"
        assert harness.state.work_queue[0].status == WorkStatus.TRANSIENT_FAILURE

        resumed_harness = _harness(tmp_path, resume=True)
        resumed_tools = AgentScannerTools(scanner, resumed_harness, engine_factory=factory)
        result2 = await resumed_tools.run_scanner_work(work_id)
        assert result2["status"] == "inconclusive"
        assert len(calls) == 1
        assert resumed_harness.state.work_queue[0].status == WorkStatus.INCONCLUSIVE
    asyncio.run(scenario())


def test_unreadable_probe_ledger_fails_closed_without_replay(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *_: pytest.fail("ledger failure must suppress replay"))
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        harness.probe_attempts_path.write_text("corrupt ledger record\n", encoding="utf-8")
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "inconclusive"
        assert harness.state.work_queue[0].status == WorkStatus.INCONCLUSIVE
    asyncio.run(scenario())


def test_saved_hypothesis_can_be_verified_once_after_resume(tmp_path):
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        first_harness = _harness(tmp_path)
        first_tools = AgentScannerTools(scanner, first_harness)
        point_id = first_tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        work_id = first_tools.schedule_scanner(point_id, "xss")["work_id"]
        candidate = {
            "candidate_id": "saved-candidate", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
        }
        candidate["injection_point_id"] = first_tools.register_hypothesis(candidate)
        first_harness.note_hypotheses([candidate])

        resumed_harness = _harness(tmp_path, resume=True)
        engines = []
        finding = SimpleNamespace(
            check_type="xss", severity="high", url=candidate["url"],
            field_name="q", payload="marker", evidence="reproduced",
        )

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff, finding=finding)
            engines.append(engine)
            return engine

        resumed_tools = AgentScannerTools(scanner, resumed_harness, engine_factory=factory)
        assert resumed_tools._resolve(point_id)[0] is not None
        assert any(item.work_id == work_id for item in resumed_harness.state.work_queue)
        result = await resumed_tools.verify_hypothesis("saved-candidate")
        assert result["status"] == "confirmed", result
        stored = next(item for item in resumed_harness.state.hypotheses if item["candidate_id"] == "saved-candidate")
        assert stored["verification_outcome"] == "confirmed"
        assert stored["deterministic_confirmed"] is True
        assert stored["source_label"] == "agent_deterministic_confirmed"
        record = json.loads(resumed_harness.verification_results_path.read_text().splitlines()[-1])
        assert record["verification_id"]
        assert record["evidence_ids"]
        assert record["evidence_ids"] != [work_id]
        evidence = next(item for item in resumed_harness.state.scanner_evidence
                        if item["evidence_id"] == record["evidence_ids"][0])
        assert evidence["work_id"] == work_id
        assert evidence["injection_point_id"] == point_id
        assert evidence["check_type"] == "xss"
        assert evidence["binding_digest"] == record["binding_digest"]
        assert record["head_id"] == resumed_tools._current_head_id()
        assert record["scan_id"] == resumed_harness.state.run_id
        assert record["injection_point_id"] == point_id
        first_result = await resumed_tools.verify_hypothesis("saved-candidate")
        assert first_result["status"] == "confirmed"
        assert len(engines) == 1
        assert len(engines[0].scanner.calls) == 1

        reloaded_harness = _harness(tmp_path, resume=True)
        reloaded_tools = AgentScannerTools(scanner, reloaded_harness, engine_factory=lambda *_: pytest.fail("valid ledger should not dispatch again"))
        persisted_result = await reloaded_tools.verify_hypothesis("saved-candidate")
        assert persisted_result["status"] == "confirmed"
        stored_again = reloaded_harness.state.hypotheses[0]
        assert stored_again["status"] == "deterministic_confirmed"
        assert stored_again["source_label"] == "agent_deterministic_confirmed"
    asyncio.run(scenario())


def test_tampered_confirmation_without_ledger_and_invalid_point_is_downgraded(tmp_path):
    scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
    harness = _harness(tmp_path)
    tools = AgentScannerTools(scanner, harness)
    point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
    candidate = {
        "candidate_id": "tampered-candidate", "check_type": "xss",
        "url": "https://target.test/search?q=1", "field_name": "q",
        "injection_point_id": point_id,
    }
    harness.note_hypotheses([candidate])
    saved = harness.state.hypotheses[0]
    saved.update({
        "status": "confirmed", "verification_outcome": "confirmed",
        "deterministic_confirmed": True, "source_label": "agent_deterministic_confirmed",
        "injection_point_id": "not-in-the-point-table",
    })
    harness.checkpoint()
    harness.verification_results_path.unlink(missing_ok=True)

    resumed = _harness(tmp_path, resume=True)
    resumed_tools = AgentScannerTools(scanner, resumed, engine_factory=lambda *_: pytest.fail("invalid point must not reach scanner"))
    result = asyncio.run(resumed_tools.verify_hypothesis("tampered-candidate"))
    assert result["status"] == "inconclusive"
    stored = resumed.state.hypotheses[0]
    assert stored["status"] == "agent_only"
    assert stored["verification_outcome"] == "inconclusive"
    assert stored["deterministic_confirmed"] is False
    assert stored["source_label"] == "agent_unverified"
    assert "unverifiable_checkpoint" in stored["rejection_reason"]
    assert "unknown injection point" in stored["rejection_reason"]


def test_corrupt_verification_ledger_downgrades_checkpoint_claim(tmp_path):
    scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
    harness = _harness(tmp_path)
    tools = AgentScannerTools(scanner, harness)
    point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
    candidate = {
        "candidate_id": "corrupt-ledger-candidate", "check_type": "xss",
        "url": "https://target.test/search?q=1", "field_name": "q",
        "injection_point_id": point_id,
    }
    harness.note_hypotheses([candidate])
    harness.state.hypotheses[0].update({
        "status": "confirmed", "verification_outcome": "confirmed",
        "deterministic_confirmed": True, "source_label": "agent_deterministic_confirmed",
    })
    harness.checkpoint()
    harness.verification_results_path.write_text("{damaged json\n", encoding="utf-8")

    resumed = _harness(tmp_path, resume=True)
    finding = SimpleNamespace(
        check_type="xss", severity="high", url=candidate["url"], field_name="q",
        payload="marker", evidence="reproduced",
    )
    engine = _FakeEngine("xss", SimpleNamespace(cookies=[]), finding=finding)
    resumed_tools = AgentScannerTools(scanner, resumed, engine_factory=lambda *_: engine)
    result = asyncio.run(resumed_tools.verify_hypothesis("corrupt-ledger-candidate"))
    assert result["status"] == "inconclusive"
    assert engine.scanner.calls
    stored = resumed.state.hypotheses[0]
    assert stored["status"] == "agent_only"
    assert stored["verification_outcome"] == "inconclusive"
    assert stored["deterministic_confirmed"] is False
    assert stored["source_label"] == "agent_unverified"
    assert "unverifiable_checkpoint" in stored["rejection_reason"]


def test_verification_from_another_scan_is_not_trusted(tmp_path):
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        harness = _harness(tmp_path)
        tools = AgentScannerTools(scanner, harness)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        candidate = {
            "candidate_id": "cross-scan-candidate", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
            "injection_point_id": point_id,
        }
        harness.note_hypotheses([candidate])
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        finding = SimpleNamespace(
            check_type="xss", severity="high", url=candidate["url"], field_name="q",
            payload="marker", evidence="reproduced",
        )
        engine = _FakeEngine("xss", SimpleNamespace(cookies=[]), finding=finding)
        tools.engine_factory = lambda *_: engine
        assert (await tools.verify_hypothesis("cross-scan-candidate"))["status"] == "confirmed"
        record = json.loads(harness.verification_results_path.read_text().splitlines()[-1])
        record["scan_id"] = "another-scan"
        harness.verification_results_path.write_text(json.dumps(record) + "\n", encoding="utf-8")

        resumed = _harness(tmp_path, resume=True)
        resumed_tools = AgentScannerTools(scanner, resumed, engine_factory=lambda *_: pytest.fail("stale scan record must suppress replay"))
        result = await resumed_tools.verify_hypothesis("cross-scan-candidate")
        assert result["status"] == "inconclusive"
        stored = resumed.state.hypotheses[0]
        assert stored["status"] == "agent_only"
        assert stored["deterministic_confirmed"] is False
        assert stored["source_label"] == "agent_unverified"
        assert "inconsistent_verification_record" in stored["rejection_reason"]
        assert resumed.state.work_queue[0].work_id == work_id
    asyncio.run(scenario())


def test_confirmation_requires_matching_probe_evidence_after_resume(tmp_path):
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        harness = _harness(tmp_path)
        tools = AgentScannerTools(scanner, harness)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        candidate = {
            "candidate_id": "missing-evidence-candidate", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
            "injection_point_id": point_id,
        }
        harness.note_hypotheses([candidate])
        finding = SimpleNamespace(
            check_type="xss", severity="high", url=candidate["url"], field_name="q",
            payload="marker", evidence="reproduced",
        )
        tools.engine_factory = lambda *_: _FakeEngine("xss", SimpleNamespace(cookies=[]), finding=finding)
        assert (await tools.verify_hypothesis("missing-evidence-candidate"))["status"] == "confirmed"
        harness.probe_attempts_path.unlink()

        resumed = _harness(tmp_path, resume=True)
        resumed_tools = AgentScannerTools(scanner, resumed, engine_factory=lambda *_: pytest.fail("missing evidence must not trigger an untracked replay"))
        result = await resumed_tools.verify_hypothesis("missing-evidence-candidate")
        assert result["status"] == "inconclusive"
        stored = resumed.state.hypotheses[0]
        assert stored["verification_outcome"] == "inconclusive"
        assert stored["deterministic_confirmed"] is False
        assert stored["source_label"] == "agent_unverified"
        assert "inconsistent_verification_record" in stored["rejection_reason"]
    asyncio.run(scenario())


@pytest.mark.parametrize("mutation", [
    "target_url", "carrier", "parameter", "check", "scan_id", "verification_scan_id", "digest",
])
def test_tampered_probe_binding_cannot_restore_confirmation(tmp_path, mutation):
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        harness = _harness(tmp_path)
        tools = AgentScannerTools(scanner, harness)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        candidate = {
            "candidate_id": f"tampered-{mutation}", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
            "injection_point_id": point_id,
        }
        harness.note_hypotheses([candidate])
        finding = SimpleNamespace(
            check_type="xss", severity="high", url=candidate["url"], field_name="q",
            payload="marker", evidence="reproduced",
        )
        tools.engine_factory = lambda *_: _FakeEngine("xss", SimpleNamespace(cookies=[]), finding=finding)
        assert (await tools.verify_hypothesis(candidate["candidate_id"]))["status"] == "confirmed"

        attempts = [json.loads(line) for line in harness.probe_attempts_path.read_text().splitlines()]
        attempt = next(item for item in reversed(attempts) if item["status"] == "completed")
        if mutation == "target_url":
            attempt["target_url"] = "https://other.test/forged"
        elif mutation == "carrier":
            attempt["binding"]["carrier"] = "form"
        elif mutation == "parameter":
            attempt["binding"]["parameter_identity"]["parameter_id"] = "other"
        elif mutation == "check":
            attempt["check_type"] = "sqli"
        elif mutation == "scan_id":
            attempt["run_id"] = "another-scan"
        elif mutation == "verification_scan_id":
            verifications = [json.loads(line) for line in harness.verification_results_path.read_text().splitlines()]
            verifications[-1]["scan_id"] = "another-scan"
            harness.verification_results_path.write_text(
                "".join(json.dumps(item) + "\n" for item in verifications), encoding="utf-8",
            )
        elif mutation == "digest":
            attempt["binding_digest"] = "0" * 64
        harness.probe_attempts_path.write_text("".join(json.dumps(item) + "\n" for item in attempts), encoding="utf-8")

        resumed = _harness(tmp_path, resume=True)
        resumed_tools = AgentScannerTools(
            scanner, resumed,
            engine_factory=lambda *_: pytest.fail("tampered evidence must not restore or replay confirmation"),
        )
        result = await resumed_tools.verify_hypothesis(candidate["candidate_id"])
        assert result["status"] == "inconclusive"
        saved = next(item for item in resumed.state.hypotheses if item["candidate_id"] == candidate["candidate_id"])
        assert saved["status"] == "agent_only"
        assert saved["deterministic_confirmed"] is False
        assert "inconsistent_verification_record" in saved["rejection_reason"]
    asyncio.run(scenario())


@pytest.mark.parametrize(("verify_result", "expected"), [(False, "rejected"), (None, "inconclusive")])
def test_resumed_hypothesis_records_rejected_and_inconclusive_labels(tmp_path, verify_result, expected):
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        harness = _harness(tmp_path)
        first_tools = AgentScannerTools(scanner, harness)
        point_id = first_tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        candidate = {
            "candidate_id": f"candidate-{expected}", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
        }
        candidate["injection_point_id"] = first_tools.register_hypothesis(candidate)
        work_id = first_tools.schedule_scanner(point_id, "xss")["work_id"]

        resumed = _harness(tmp_path, resume=True)
        finding = SimpleNamespace(
            check_type="xss", severity="high", url=candidate["url"],
            field_name="q", payload="marker", evidence="candidate evidence",
        )
        engine = _FakeEngine(
            "xss", SimpleNamespace(cookies=[]),
            scanner=_FakeScanner(findings=[finding], verify_result=verify_result),
        )
        tools = AgentScannerTools(scanner, resumed, engine_factory=lambda *_: engine)
        result = await tools.verify_hypothesis(candidate["candidate_id"])
        assert result["status"] == expected
        ledger = [json.loads(line) for line in resumed.verification_results_path.read_text().splitlines()]
        assert ledger[-1]["status"] == expected
        assert ledger[-1]["deterministic_confirmed"] is False
        assert ledger[-1]["evidence_ids"] == []
        stored = next(item for item in resumed.state.hypotheses if item["candidate_id"] == candidate["candidate_id"])
        assert stored["verification_outcome"] == expected
        assert stored["status"] == "agent_only"
        assert stored["source_label"] == "agent_unverified"
        assert stored["deterministic_confirmed"] is False
        assert resumed.state.work_queue[0].work_id == work_id
        if expected == "inconclusive":
            assert resumed.state.work_queue[0].status == WorkStatus.INCONCLUSIVE
    asyncio.run(scenario())


@pytest.mark.parametrize("tampering", [
    "rejected_to_confirmed", "empty_evidence", "missing_evidence", "conflicting_flags",
])
def test_resume_rejects_inconsistent_verification_evidence(tmp_path, tampering):
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session", "domain": "target.test"}])
        harness = _harness(tmp_path)
        tools = AgentScannerTools(scanner, harness)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/search?q=1", "q"))
        candidate = {
            "candidate_id": f"inconsistent-{tampering}", "check_type": "xss",
            "url": "https://target.test/search?q=1", "field_name": "q",
            "injection_point_id": point_id,
        }
        harness.note_hypotheses([candidate])
        if tampering == "rejected_to_confirmed":
            scanner_result = _FakeScanner(findings=[])
            expected = "rejected"
        else:
            finding = SimpleNamespace(
                check_type="xss", severity="high", url=candidate["url"], field_name="q",
                payload="marker", evidence="reproduced",
            )
            scanner_result = _FakeScanner(findings=[finding])
            expected = "confirmed"
        tools.engine_factory = lambda *_: _FakeEngine(
            "xss", SimpleNamespace(cookies=[]), scanner=scanner_result,
        )
        assert (await tools.verify_hypothesis(candidate["candidate_id"]))["status"] == expected

        ledger = [json.loads(line) for line in harness.verification_results_path.read_text().splitlines()]
        record = ledger[-1]
        if tampering == "rejected_to_confirmed":
            record.update(status="confirmed", reproduced=True, deterministic_confirmed=True)
        elif tampering == "empty_evidence":
            record["evidence_ids"] = []
        elif tampering == "missing_evidence":
            record["evidence_ids"] = ["missing-evidence"]
        else:
            record.update(status="confirmed", reproduced=True, deterministic_confirmed=False)
        harness.verification_results_path.write_text(
            "".join(json.dumps(item) + "\n" for item in ledger), encoding="utf-8",
        )

        resumed = _harness(tmp_path, resume=True)
        resumed_tools = AgentScannerTools(
            scanner, resumed,
            engine_factory=lambda *_: pytest.fail("inconsistent evidence must not be replayed or confirmed"),
        )
        result = await resumed_tools.verify_hypothesis(candidate["candidate_id"])
        assert result["status"] == "inconclusive"
        stored = next(item for item in resumed.state.hypotheses if item["candidate_id"] == candidate["candidate_id"])
        assert stored["status"] == "agent_only"
        assert stored["deterministic_confirmed"] is False
        assert "inconsistent_verification_record" in stored["rejection_reason"]
    asyncio.run(scenario())


def test_controller_contract_and_agent_lab_fake_llm_integration(tmp_path):
    class _Controller:
        def __init__(self):
            self.actions = {}

        def action(self, description, **_kwargs):
            def register(function):
                self.actions[function.__name__] = {"description": description, "function": function}
                return function
            return register

    class _LabScanner(_FakeScanner):
        def __init__(self, client):
            super().__init__()
            self.client = client

        async def scan_field(self, url, _form_index, field, is_url_param=False):
            self.calls.append((url, field, is_url_param))
            response = self.client.get("/xss", params={"q": "<script>alert(1)</script>"})
            if "<script>alert(1)</script>" in response.text:
                return [SimpleNamespace(
                    check_type="xss", severity="high", url=url,
                    field_name=field["name"], payload="<script>alert(1)</script>",
                    evidence="raw reflected script",
                )]
            return []

    class _FakeLLM:
        async def use_tools(self, controller, point_id):
            listed = await controller.actions["list_scanner_capabilities"]["function"]()
            assert any(item["injection_point_id"] == point_id for item in listed["capabilities"])
            queued = controller.actions["schedule_scanner"]["function"](point_id, "xss")
            await controller.actions["run_scanner_work"]["function"](queued["work_id"])
            return await controller.actions["verify_hypothesis"]["function"]("lab-hypothesis")

    harness = _harness(tmp_path)
    scanner = _AgentScanner([{"name": "session", "value": "lab-session", "domain": "testserver"}])
    scanner.target_url = "http://testserver/"
    scanner.target_urls = ["http://testserver/"]
    scanner.access_urls = ["http://testserver/access-only"]
    scanner.login_url = ""
    client = TestClient(create_app())
    lab_scanner = _LabScanner(client)

    def factory(check, handoff):
        engine = _FakeEngine(check, handoff, scanner=lab_scanner)
        engine.target_urls = ["http://testserver/"]
        engine.access_urls = ["http://testserver/access-only"]
        engine.login_url = ""
        return engine

    tools = AgentScannerTools(scanner, harness, engine_factory=factory)
    point_id = tools.add_point(InjectionPoint.for_url_param("http://testserver/xss?q=sample", "q"))
    hypothesis = {
        "candidate_id": "lab-hypothesis", "check_type": "xss",
        "url": "http://testserver/xss?q=sample", "field_name": "q",
    }
    hypothesis["injection_point_id"] = tools.register_hypothesis(hypothesis)
    harness.note_hypotheses([hypothesis])
    controller = _Controller()
    tools.register_controller_actions(controller)
    assert set(controller.actions) == {
        "list_scanner_capabilities", "schedule_scanner", "run_scanner_work", "verify_hypothesis",
    }
    from inspect import signature
    assert tuple(signature(controller.actions["schedule_scanner"]["function"]).parameters) == ("injection_point_id", "check")
    assert tuple(signature(controller.actions["run_scanner_work"]["function"]).parameters) == ("work_id",)
    result = asyncio.run(_FakeLLM().use_tools(controller, point_id))
    assert result["status"] == "confirmed"
    assert harness.state.hypotheses[0]["deterministic_confirmed"] is True


def test_httpx_carrier_json_body_and_api_get_confirmed_and_tri_state(tmp_path):
    """JSON body と API GET の送信・確証・tri-state (confirmed / rejected / inconclusive) と
    PR 2 イベント (tool_request, authorization_decision, dispatch_start, executed_scanner_work, dispatch_end) を検証。"""
    async def scenario():
        harness = _harness(tmp_path)
        cookie = {"name": "session", "value": "fresh-session-token", "domain": "target.test"}
        scanner = _AgentScanner([cookie])

        # 1. JSON body finding -> confirmed
        json_finding = SimpleNamespace(
            check_type="sqli", severity="high", url="https://target.test/api/submit",
            field_name="/user/name", payload="' OR 1=1--", evidence="SQL syntax error",
        )
        fake_scanner_json = _FakeScanner(findings=[json_finding], verify_result=True)
        engine_json = _FakeEngine("sqli", SimpleNamespace(cookies=[]), scanner=fake_scanner_json)
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine_json)

        point_json = InjectionPoint.for_json_body(
            "POST", "https://target.test/api/submit", "/user/name",
            template_id="tmpl_json_1",
        )
        point_id_json = tools.add_point(point_json, {"template": {"url": "https://target.test/api/submit", "json_body": {"user": {"name": "test"}}}})
        hyp_json = {
            "candidate_id": "hyp-json-1", "check_type": "sqli",
            "url": "https://target.test/api/submit", "field_name": "/user/name",
        }
        hyp_json["injection_point_id"] = tools.register_hypothesis(hyp_json)
        harness.note_hypotheses([hyp_json])

        sched_json = tools.schedule_scanner(point_id_json, "sqli")
        assert sched_json["status"] == "planned"
        work_id_json = sched_json["work_id"]

        result_json = await tools.run_scanner_work(work_id_json)
        assert result_json["status"] == "completed"
        assert result_json["verified_count"] == 1
        assert engine_json.injection_templates["tmpl_json_1"]["json_body"] == {"user": {"name": "test"}}
        assert engine_json.target_only is True

        # Check hypothesis was confirmed deterministically
        stored_hyp_json = next(h for h in harness.state.hypotheses if h["candidate_id"] == "hyp-json-1")
        assert stored_hyp_json["deterministic_confirmed"] is True
        assert stored_hyp_json["source_label"] == "agent_deterministic_confirmed"

        # 2. API GET finding -> confirmed
        api_finding = SimpleNamespace(
            check_type="xss", severity="high", url="https://target.test/api/search?q=1",
            field_name="q", payload="<script>alert(1)</script>", evidence="reflected script",
        )
        fake_scanner_api = _FakeScanner(findings=[api_finding], api_get=True, verify_result=True)
        engine_api = _FakeEngine("xss", SimpleNamespace(cookies=[]), scanner=fake_scanner_api)
        tools_api = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine_api)

        point_api = InjectionPoint.for_url_param("https://target.test/api/search?q=1", "q")
        point_id_api = tools_api.add_point(point_api)
        hyp_api = {
            "candidate_id": "hyp-api-1", "check_type": "xss",
            "url": "https://target.test/api/search?q=1", "field_name": "q",
        }
        hyp_api["injection_point_id"] = tools_api.register_hypothesis(hyp_api)
        harness.note_hypotheses([hyp_api])

        sched_api = tools_api.schedule_scanner(point_id_api, "xss")
        assert sched_api["status"] == "planned"
        work_id_api = sched_api["work_id"]

        result_api = await tools_api.run_scanner_work(work_id_api)
        assert result_api["status"] == "completed"
        assert result_api["verified_count"] == 1
        stored_hyp_api = next(h for h in harness.state.hypotheses if h["candidate_id"] == "hyp-api-1")
        assert stored_hyp_api["deterministic_confirmed"] is True
        assert stored_hyp_api["source_label"] == "agent_deterministic_confirmed"

        # 3. Verify lifecycle events emitted for both dispatches
        events = harness.state.events
        for wid in (work_id_json, work_id_api):
            wid_events = [e for e in events if e.get("work_id") == wid or e.get("executed_work_id") == wid]
            event_types = [e.get("event_type") for e in wid_events]
            assert "tool_request" in event_types
            assert "authorization_decision" in event_types
            assert "dispatch_start" in event_types
            assert "executed_scanner_work" in event_types
            assert "dispatch_end" in event_types

        # 4. Tri-state: unconfirmed finding preserves hypothesis with deterministic_confirmed=False
        fake_scanner_unconf = _FakeScanner(findings=[json_finding], verify_result=False)
        engine_unconf = _FakeEngine("sqli", SimpleNamespace(cookies=[]), scanner=fake_scanner_unconf)
        tools_unconf = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine_unconf)
        point_unconf = InjectionPoint.for_json_body("POST", "https://target.test/api/unconf", "/user/name")
        point_id_unconf = tools_unconf.add_point(point_unconf)
        hyp_unconf = {
            "candidate_id": "hyp-unconf-1", "check_type": "sqli",
            "url": "https://target.test/api/unconf", "field_name": "/user/name",
        }
        hyp_unconf["injection_point_id"] = tools_unconf.register_hypothesis(hyp_unconf)
        harness.note_hypotheses([hyp_unconf])
        work_unconf = tools_unconf.schedule_scanner(point_id_unconf, "sqli")["work_id"]
        res_unconf = await tools_unconf.run_scanner_work(work_unconf)
        assert res_unconf["status"] == "completed"
        assert res_unconf["verified_count"] == 0
        stored_hyp_unconf = next(h for h in harness.state.hypotheses if h["candidate_id"] == "hyp-unconf-1")
        assert stored_hyp_unconf["deterministic_confirmed"] is False
        assert stored_hyp_unconf["source_label"] == "agent_unverified"

    asyncio.run(scenario())


def test_httpx_carrier_scope_rejections_and_redirect_guard(tmp_path):
    """scope 外、exclusion、access-only、および redirect 先 scope 外・access-only の拒否を検証。"""
    async def scenario():
        harness = _harness(tmp_path)
        cookie = {"name": "session", "value": "test-cookie", "domain": "target.test"}
        scanner = _AgentScanner([cookie])
        tools = AgentScannerTools(scanner, harness)

        # (a) URL scope checks on points
        outside_id = tools.add_point(InjectionPoint.for_json_body("POST", "https://outside.test/api", "/item"))
        excluded_id = tools.add_point(InjectionPoint.for_json_body("POST", "https://target.test/private/api", "/item"))
        access_id = tools.add_point(InjectionPoint.for_json_body("POST", "https://target.test/login", "/item"))
        tmpl_outside_id = tools.add_point(
            InjectionPoint.for_json_body("POST", "https://target.test/api", "/item"),
            {"template": {"url": "https://outside.test/api"}},
        )

        assert tools.schedule_scanner(outside_id, "sqli")["status"] == "blocked"
        assert tools.schedule_scanner(excluded_id, "sqli")["status"] == "blocked"
        assert tools.schedule_scanner(access_id, "sqli")["status"] == "blocked"
        assert tools.schedule_scanner(tmpl_outside_id, "sqli")["status"] == "blocked"
        assert any("scope_blocked" in gap for gap in harness.state.coverage_gaps)
        assert any("excluded_url" in gap for gap in harness.state.coverage_gaps)
        assert any("access_only_url" in gap for gap in harness.state.coverage_gaps)

        # (b) Redirect guard via RuntimeScopeGuardHook with target_only=True
        import httpx
        from wscan.runtime_scope_guard import RuntimeScopeGuardHook, ScopePolicy, OutOfScopeUrlError
        policy = ScopePolicy(
            target_urls=("https://target.test/",),
            access_urls=("https://target.test/login",),
            exclude_urls=("https://target.test/private*",),
        )

        blocks = []
        def _on_block(req, dec):
            blocks.append((str(req.url), dec.reason))

        hook = RuntimeScopeGuardHook(policy, on_block=_on_block, target_only=True)

        # Target url is allowed
        allowed_req = httpx.Request("POST", "https://target.test/api")
        hook(allowed_req)
        assert blocks == []

        # Out-of-scope egress is blocked
        out_req = httpx.Request("GET", "https://outside.test/leak")
        with pytest.raises(OutOfScopeUrlError, match="Out-of-scope egress blocked"):
            hook(out_req)
        assert any(b[0] == "https://outside.test/leak" and b[1] in ("scope_blocked", "out_of_scope_destination") for b in blocks)

        # Access-url egress in target_only mode is blocked
        access_req = httpx.Request("GET", "https://target.test/login")
        with pytest.raises(OutOfScopeUrlError, match="Out-of-scope egress blocked"):
            hook(access_req)
        assert any(b[0] == "https://target.test/login" and b[1] == "access_url" for b in blocks)

        # Excluded egress is blocked
        excl_req = httpx.Request("GET", "https://target.test/private/data")
        with pytest.raises(OutOfScopeUrlError, match="Out-of-scope egress blocked"):
            hook(excl_req)
        assert any(b[0] == "https://target.test/private/data" and b[1] == "excluded_url" for b in blocks)

    asyncio.run(scenario())


def test_httpx_carrier_auth_unavailable_and_unverified_blocks(tmp_path):
    """認証が受け取れないとき、または検証に失敗したときの BLOCKED を検証。"""
    async def scenario():
        harness = _harness(tmp_path)
        # 1. Capture cookies failure
        scanner_no_auth = _AgentScanner([])
        tools_no_auth = AgentScannerTools(scanner_no_auth, harness, engine_factory=lambda *_: pytest.fail("must not create engine"))
        point_id = tools_no_auth.add_point(InjectionPoint.for_json_body("POST", "https://target.test/api", "/data"))
        work_id = tools_no_auth.schedule_scanner(point_id, "sqli")["work_id"]
        res = await tools_no_auth.run_scanner_work(work_id)
        assert res["status"] == "blocked"
        assert "authentication state is unavailable" in res["reason"]
        assert harness.state.work_queue[0].status == WorkStatus.BLOCKED

        # 2. Handoff cookie verification failure
        scanner_auth = _AgentScanner([{"name": "session", "value": "dummy", "domain": "target.test"}])
        engine_unverified = _FakeEngine("sqli", SimpleNamespace(cookies=[]), auth=False)
        tools_unverified = AgentScannerTools(scanner_auth, harness, engine_factory=lambda *_: engine_unverified)
        point_id_2 = tools_unverified.add_point(InjectionPoint.for_json_body("POST", "https://target.test/api/auth2", "/data"))
        work_id_2 = tools_unverified.schedule_scanner(point_id_2, "sqli")["work_id"]
        res_2 = await tools_unverified.run_scanner_work(work_id_2)
        assert res_2["status"] == "blocked"
        assert "authentication could not be verified" in res_2["reason"]
        assert harness.state.work_queue[-1].status == WorkStatus.BLOCKED
    asyncio.run(scenario())


def test_httpx_carrier_duplication_prevention(tmp_path):
    """二重送信の防止（replay suppression）を検証。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "dummy", "domain": "target.test"}])
        engine = _FakeEngine("sqli", SimpleNamespace(cookies=[]))
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine)

        point_id = tools.add_point(InjectionPoint.for_json_body("POST", "https://target.test/api", "/item"))
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]

        # First run succeeds
        res1 = await tools.run_scanner_work(work_id)
        assert res1["status"] == "completed"

        # Simulate work being re-attempted while probe attempt is recorded
        work = next(w for w in harness.state.work_queue if w.work_id == work_id)
        work.status = WorkStatus.PLANNED

        res2 = await tools.run_scanner_work(work_id)
        assert res2["status"] == "inconclusive"
        assert "automatic replay was suppressed" in res2["reason"]
    asyncio.run(scenario())


def test_httpx_carrier_secret_redaction(tmp_path):
    """ツールの入出力とログに秘密が残らないことを検証。"""
    async def scenario():
        secret_token = "super-secret-token-12345"
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "token", "value": secret_token, "domain": "target.test"}])

        finding = SimpleNamespace(
            check_type="sqli", severity="high", url="https://target.test/api?token=query-secret",
            field_name="/user", payload=f"payload-with-{secret_token}", evidence=f"evidence-with-{secret_token}",
        )
        engine = _FakeEngine("sqli", SimpleNamespace(cookies=[]), finding=finding)
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine)

        point = InjectionPoint.for_json_body("POST", f"https://target.test/api?token={secret_token}", "/user")
        point_id = tools.add_point(point)

        # Checkpoint does not persist query secret
        saved_points = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert secret_token not in saved_points

        work_id = tools.schedule_scanner(point_id, "sqli")
        # Since url had query secret, it was marked resume_unavailable
        assert work_id["status"] == "unsupported"

        # Now test with clean URL but secret payload/evidence
        clean_point = InjectionPoint.for_json_body("POST", "https://target.test/api", "/user")
        clean_id = tools.add_point(clean_point)
        work_id_2 = tools.schedule_scanner(clean_id, "sqli")["work_id"]
        res = await tools.run_scanner_work(work_id_2)
        assert res["status"] == "completed"

        # Check sanitized findings have secret redacted
        persisted = "\n".join(p.read_text(encoding="utf-8") for p in tmp_path.rglob("*") if p.is_file())
        assert secret_token not in persisted
    asyncio.run(scenario())


def test_httpx_carrier_unsupported_xml_coverage_gap(tmp_path):
    """UNSUPPORTED のまま残した XML carrier の coverage gap と拒否を検証。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "val", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, harness)

        xml_point = InjectionPoint.for_xml_body("POST", "https://target.test/api/xml", "/root/user/@id")
        xml_id = tools.add_point(xml_point)

        # Capabilities reports unsupported with reason
        caps = await tools.list_scanner_capabilities()
        cap_entry = next(c for c in caps["capabilities"] if c["injection_point_id"] == xml_id)
        assert cap_entry["status"] == "unsupported"
        assert cap_entry["carrier"] == "xml_body"
        assert "xml_body carrier unsupported" in cap_entry["reason"]

        # Baseline scheduling records gap
        tools.schedule_baselines(point_ids=(xml_id,))
        assert any("unsupported_carrier:xml_body" in gap for gap in harness.state.coverage_gaps)

        # Attempting run_scanner_work with unresolved point returns unsupported
        tools.work_specs["work-xml-1"] = (xml_id, "sqli")
        harness.enqueue(AgentRole.PROBE_SPECIALIST, xml_id, check_type="sqli")
        work = harness.state.work_queue[-1]
        res = await tools.run_scanner_work(work.work_id)
        assert res["status"] == "unsupported"
        assert harness.state.work_queue[-1].status == WorkStatus.BLOCKED
    asyncio.run(scenario())


_SECRET_AUTH = "Bearer tpl-auth-secret-AAAA1111"
_SECRET_COOKIE = "sid=tpl-cookie-secret-BBBB2222"
_SECRET_BODY = "tpl-body-secret-CCCC3333"
_SECRET_JWT = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigsigsigsig"


def _all_persisted(path) -> str:
    return "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in path.rglob("*") if p.is_file())


def test_template_auth_headers_are_not_persisted_and_resume_uses_fresh_auth(tmp_path):
    """template の Authorization/Cookie は checkpoint・出力・イベントに残さず、送信は新しい認証状態で行う。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-1", "domain": "target.test"}])
        engines = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engines.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/submit", "/user/name", template_id="tmpl_h")
        template = {
            "url": "https://target.test/api/submit",
            "json_body": {"user": {"name": "test"}},
            "headers": {
                "Authorization": _SECRET_AUTH, "Cookie": _SECRET_COOKIE,
                "X-Custom": f"Bearer {_SECRET_BODY}", "Content-Type": "application/json",
            },
        }
        point_id = tools.add_point(point, {"template": template})
        persisted = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        for secret in (_SECRET_AUTH, _SECRET_COOKIE, _SECRET_BODY, "tpl-auth-secret", "tpl-cookie-secret"):
            assert secret not in persisted
        assert "application/json" in persisted  # 送信に要る非認証ヘッダは残す

        # resume: 保存済み template から復元し、認証は新しいセッションから受け取る
        scanner.cookies = [{"name": "session", "value": "fresh-session-value-2", "domain": "target.test"}]
        fresh_bearer = "fresh-bearer-value-5555"

        async def capture_tokens(_session):
            return [{"storage": "local", "key": "access_token", "value": fresh_bearer}]

        scanner._capture_tokens = capture_tokens
        scanner._active_session = _PageSession("https://target.test/app")
        resumed = AgentScannerTools(scanner, _harness(tmp_path, resume=True), engine_factory=factory)
        work_id = resumed.schedule_scanner(point_id, "sqli")["work_id"]
        outputs = [await resumed.run_scanner_work(work_id), await resumed.list_scanner_capabilities()]
        sent = engines[-1].injection_templates["tmpl_h"]["headers"]
        # 古い template の Bearer は送らず、Agent セッションの新しい Bearer だけを付ける
        assert sent == {"Content-Type": "application/json", "Authorization": f"Bearer {fresh_bearer}"}
        assert not any(_SECRET_AUTH in str(v) or _SECRET_COOKIE in str(v) for v in sent.values())
        assert fresh_bearer not in _all_persisted(tmp_path)
        assert "fresh-session-value-2" in json.dumps(engines[-1].handoff.__dict__, default=str)
        assert "fresh-session-value-1" not in json.dumps(engines[-1].handoff.__dict__, default=str)
        blob = json.dumps(outputs, default=str) + _all_persisted(tmp_path)
        for secret in ("tpl-auth-secret", "tpl-cookie-secret", _SECRET_BODY):
            assert secret not in blob
    asyncio.run(scenario())


def test_template_json_body_secret_is_not_persisted_and_not_replayed(tmp_path):
    """秘密を含む json_body の template はディスクに値を保存せず、取り直せない場合は BLOCKED にする。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-3", "domain": "target.test"}])
        engines = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engines.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/login", "/user/name", template_id="tmpl_s")
        template = {
            "url": "https://target.test/api/login",
            "json_body": {"user": {"name": "test"}, "password": _SECRET_BODY, "session": _SECRET_JWT},
            "headers": {"Authorization": _SECRET_AUTH, "Cookie": _SECRET_COOKIE},
        }
        point_id = tools.add_point(point, {"template": template})
        persisted = _all_persisted(tmp_path)
        for secret in (_SECRET_BODY, _SECRET_JWT, _SECRET_AUTH, _SECRET_COOKIE):
            assert secret not in persisted

        # 永続化された points.json に秘密値が一切現れないことを確認
        points_content = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        for secret in (_SECRET_BODY, _SECRET_JWT, _SECRET_AUTH, _SECRET_COOKIE):
            assert secret not in points_content

        # 新インスタンス（セッションから取り直せない環境）では BLOCKED になる
        resumed_harness = _harness(tmp_path, resume=True)
        resumed_scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-3", "domain": "target.test"}])
        resumed_tools = AgentScannerTools(resumed_scanner, resumed_harness, engine_factory=factory)
        sched = resumed_tools.schedule_scanner(point_id, "sqli")
        assert sched["status"] == "planned"
        res = await resumed_tools.run_scanner_work(sched["work_id"])
        assert res["status"] == "blocked"
        assert engines == []  # 送信されない
        persisted_after = _all_persisted(tmp_path)
        for secret in (_SECRET_BODY, _SECRET_JWT, _SECRET_AUTH, _SECRET_COOKIE):
            assert secret not in persisted_after
    asyncio.run(scenario())


def test_runtime_template_url_gate_blocks_before_send(tmp_path):
    """schedule 後に engine 側 scope が変わり template URL だけ範囲外になった場合、送信前に拒否する。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-4", "domain": "target.test"}])
        engines = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engine.target_urls = ["https://target.test/api/submit"]
            engines.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/submit", "/user/name", template_id="tmpl_u")
        point_id = tools.add_point(point, {"template": {"url": "https://target.test/other/endpoint", "json_body": {"user": {"name": "t"}}}})
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "blocked"
        assert not engines[0].scanner.calls
        assert harness.state.work_queue[0].status == WorkStatus.SCOPE_BLOCKED
    asyncio.run(scenario())


def test_bearer_template_without_session_token_is_blocked_with_reason(tmp_path):
    """Bearer 認証の API で Agent セッションから Bearer を得られなければ、未認証で送らず BLOCKED にする。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-6", "domain": "target.test"}])
        engines = []

        def factory(check, handoff):
            engines.append(_FakeEngine(check, handoff))
            return engines[-1]

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/items", "/q", template_id="tmpl_b")
        point_id = tools.add_point(point, {"template": {
            "url": "https://target.test/api/items", "json_body": {"q": "x"},
            "headers": {"Authorization": _SECRET_AUTH},
        }})
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "blocked" and "bearer" in result["reason"]
        assert engines == []  # engine も scanner も起動せず、要求を送らない
        work = harness.state.work_queue[0]
        assert work.status == WorkStatus.BLOCKED and "bearer" in work.rejection_reason
        assert any(e.get("reason") == "bearer authentication unavailable in the agent session"
                   for e in harness.state.events)

        # operator が Authorization ヘッダを設定していれば、engine 側がそれを付けるので送る
        scanner.extra_headers = {"Authorization": "Bearer operator-configured-7777"}
        tools2 = AgentScannerTools(scanner, _harness(tmp_path / "op"), engine_factory=factory)
        point_id2 = tools2.add_point(point, {"template": {
            "url": "https://target.test/api/items", "json_body": {"q": "x"},
            "headers": {"Authorization": _SECRET_AUTH},
        }})
        result2 = await tools2.run_scanner_work(tools2.schedule_scanner(point_id2, "sqli")["work_id"])
        assert result2["status"] == "completed"
        assert "Authorization" not in engines[-1].injection_templates["tmpl_b"]["headers"]
    asyncio.run(scenario())


@pytest.mark.parametrize("key", [
    "max_tokens", "maxTokens", "max-tokens", "max_output_tokens", "num_tokens", "total_tokens", "token_count",
    "page_token", "pageToken", "next_page_token", "nextPageToken", "next_token", "secretary", "q", "author",
])
def test_ordinary_json_keys_are_not_secret(key):
    from wscan.agent_scanner_tools import _key_is_sensitive, sanitize_template
    assert not _key_is_sensitive(key)
    _, body_secret = sanitize_template({"json_body": {key: 10, "q": "sample"}})
    assert body_secret is False


@pytest.mark.parametrize("key", [
    "password", "newPassword", "password1", "passwd", "pwd", "secret", "clientSecret", "secret_key",
    "token", "access_token", "accessToken", "id_token", "auth_token", "csrf_token", "csrfmiddlewaretoken",
    "XSRF-TOKEN", "authenticity_token", "api_key", "apiKey", "x-api-key", "sessionid", "sessionId",
    "Authorization", "Cookie",
    "tokens", "accessTokens", "refresh_tokens", "auth_tokens", "apiKeys", "api_keys", "session_ids", "sessionIds",
])
def test_credential_keys_stay_secret(key):
    from wscan.agent_scanner_tools import _key_is_sensitive, sanitize_template
    assert _key_is_sensitive(key)
    safe, body_secret = sanitize_template({"json_body": {key: "value-1234"}})
    assert body_secret is True and "value-1234" not in json.dumps(safe)


@pytest.mark.parametrize(("items", "expected"), [
    ([{"key": "access_token", "value": "abcdefgh1234"}], "abcdefgh1234"),
    ([{"key": "auth", "value": json.dumps({"accessToken": "abcdefgh1234", "refreshToken": "zzzzzzzz9999"})}], "abcdefgh1234"),
    ([{"key": "session", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigsigsig"}],
     "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigsigsig"),
    ([{"key": "access_token", "value": "aaaaaaaa1111"}, {"key": "id_token", "value": "bbbbbbbb2222"}], "aaaaaaaa1111"),
    ([{"key": "token_a", "value": "aaaaaaaa1111"}, {"key": "token_b", "value": "bbbbbbbb2222"}], ""),  # 曖昧
    ([{"key": "refresh_token", "value": "zzzzzzzz9999"}, {"key": "csrf_token", "value": "cccccccc3333"}], ""),
    ([{"key": "page_token", "value": "pppppppp4444"}, {"key": "theme", "value": "dark"}], ""),
    # 資格情報を示さないキーの JWT 形の値（同 origin のウィジェット等）は送らない
    ([{"key": "widget_state", "value": "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigsigsig"}], ""),
    ([], ""),
])
def test_select_session_bearer(items, expected):
    from wscan.agent_scanner_tools import select_session_bearer
    assert select_session_bearer(items) == expected


def test_session_bearer_from_another_origin_is_not_forwarded(tmp_path):
    """storage の token は現在ページの origin のもの。送信先と origin が違えば付けずに BLOCKED にする。"""
    async def scenario():
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-8", "domain": "target.test"}])

        async def capture_tokens(_session):
            return [{"storage": "local", "key": "access_token", "value": "other-origin-token-8888"}]

        scanner._capture_tokens = capture_tokens
        engines = []

        def factory(check, handoff):
            engines.append(_FakeEngine(check, handoff))
            return engines[-1]

        template = {"url": "https://target.test/api/items", "json_body": {"q": "x"},
                    "headers": {"Authorization": _SECRET_AUTH}}
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/items", "/q", template_id="tmpl_o")
        for page_url, expected in (("https://idp.example/login", "blocked"), ("https://target.test/app", "completed")):
            scanner._active_session = _PageSession(page_url)
            tools = AgentScannerTools(scanner, _harness(tmp_path / expected), engine_factory=factory)
            point_id = tools.add_point(point, {"template": template})
            result = await tools.run_scanner_work(tools.schedule_scanner(point_id, "sqli")["work_id"])
            assert result["status"] == expected
        assert len(engines) == 1  # 他 origin の token では engine を起動せず送らない
        assert engines[0].injection_templates["tmpl_o"]["headers"]["Authorization"] == "Bearer other-origin-token-8888"
    asyncio.run(scenario())


_REVIEW_TOKEN_KEYS = [
    "oauth_tokens", "oauthTokens", "oauth-tokens", "github_tokens", "githubTokens", "bot_tokens", "app_tokens",
    "jwt_tokens", "jwtTokens", "service_tokens", "serviceTokens", "service-tokens", "private_tokens",
    "device_tokens", "push_tokens", "my_tokens",
]


@pytest.mark.parametrize("key", _REVIEW_TOKEN_KEYS)
def test_plural_token_keys_are_not_persisted_or_output_in_plain_text(tmp_path, key):
    """任意の語 + tokens のキーは値が points.json・ツール出力・イベントに平文で残らない。"""
    async def scenario():
        secret_value = "opaqueVal12345-plural"
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-9", "domain": "target.test"}])
        engines = []
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *a: engines.append(a) or _FakeEngine(*a))
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/x", "/q", template_id="tmpl_p")
        header = "X-" + key.replace("_", "-")
        point_id = tools.add_point(point, {"template": {
            "url": "https://target.test/api/x", "json_body": {"q": "x", key: secret_value},
            "headers": {header: secret_value},
        }})
        saved_text = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert secret_value not in saved_text
        outputs = [tools.schedule_scanner(point_id, "sqli"), await tools.list_scanner_capabilities()]
        assert outputs[0]["status"] == "planned"
        blob = json.dumps(outputs, default=str) + json.dumps(harness.state.events, default=str) + _all_persisted(tmp_path)
        assert secret_value not in blob
    asyncio.run(scenario())


def test_context_keys_with_ordinary_values_are_supported(tmp_path):
    """sort_key/key/session/auth などを含む普通の JSON body は値が保存されず、supported になり取り直して送信できる。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-ctx", "domain": "target.test"}])
        engines = []
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *a: engines.append(_FakeEngine(*a)) or engines[-1])
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/items", "/q", template_id="tmpl_items")
        body = {
            "q": "search-query",
            "sort_key": "asc",
            "key": "title",
            "session": 1,
            "session_name": "active",
            "auth": "local",
        }
        point_id = tools.add_point(point, {"template": {
            "url": "https://target.test/api/items",
            "json_body": body,
        }})
        saved_text = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert "search-query" not in saved_text
        assert "active" not in saved_text
        assert "structure_hash" in saved_text

        sched = tools.schedule_scanner(point_id, "sqli")
        assert sched["status"] == "planned"

        caps = await tools.list_scanner_capabilities()
        cap_entry = next(c for c in caps["capabilities"] if c["injection_point_id"] == point_id)
        assert cap_entry["status"] == "supported"

        res = await tools.run_scanner_work(sched["work_id"])
        assert res["status"] == "completed"
        assert len(engines) == 1
        assert engines[0].injection_templates["tmpl_items"]["json_body"] == body
    asyncio.run(scenario())


@pytest.mark.parametrize(("key", "val"), [
    ("key", "sk-1234567890abcdef1234567890abcdef"),
    ("session", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ4In0.sigsigsigsig"),
    ("session", "4f8a9b2c3d4e5f6a7b8c9d0e1f2a3b4c"),
    ("auth", "Bearer fresh-token-value-12345"),
])
def test_ambiguous_keys_with_secret_values_are_not_persisted(tmp_path, key, val):
    """曖昧なキーでも値は points.json やファイルに一切保存されない。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-sec", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, harness)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/sec", "/q", template_id="tmpl_sec")
        point_id = tools.add_point(point, {"template": {
            "url": "https://target.test/api/sec",
            "json_body": {"q": "x", key: val},
        }})
        saved = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert val not in saved
        persisted = _all_persisted(tmp_path)
        assert val not in persisted
    asyncio.run(scenario())


_REVIEW_REPRO_SECRETS = {
    "cookies": "sid=Q7xk2LmN9pR4",
    "proxyAuthorization": "Basic dXNlcjpwYXNz",
    "private_key": "-----BEGIN PRIVATE KEY----- MIIEvQIBADANBgkqhkiG9w0BAQEFAASC -----END PRIVATE KEY-----",
    "stripe_key": "sk_live_abcdefghijklmnop1234",
    "session": "a1b2c3d4",
}
_REVIEW_REPRO_HDRS = {"X-Auth": "9f8e7d6c5b4a39281706f5e4d3c2b1a0", "X-Session": "Zq81mPx0"}


@pytest.mark.parametrize("k,v", list(_REVIEW_REPRO_SECRETS.items()))
def test_review_repro_body_leaf_not_persisted(tmp_path, k, v):
    """レビューで指摘された 5 種の秘密値が points.json やファイルに一切保存されない。"""
    tools = AgentScannerTools(_AgentScanner([]), _harness(tmp_path))
    tools.add_point(InjectionPoint.for_json_body("POST", "https://target.test/api", "/q", template_id="t"),
                    {"template": {"url": "https://target.test/api", "json_body": {"q": "x", k: v}}})
    points_text = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
    assert v not in points_text
    assert v not in _all_persisted(tmp_path)


@pytest.mark.parametrize("k,v", list(_REVIEW_REPRO_HDRS.items()))
def test_review_repro_header_not_persisted(tmp_path, k, v):
    """レビューで指摘された 2 種のカスタム認証ヘッダ値が points.json やファイルに一切保存されない。"""
    tools = AgentScannerTools(_AgentScanner([]), _harness(tmp_path))
    tools.add_point(InjectionPoint.for_json_body("POST", "https://target.test/api", "/q", template_id="t"),
                    {"template": {"url": "https://target.test/api", "json_body": {"q": "x"}, "headers": {k: v}}})
    points_text = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
    assert v not in points_text
    assert v not in _all_persisted(tmp_path)


def test_missing_live_template_blocks_before_send(tmp_path):
    """resume 時にセッションから live template を取り直せない場合、未認証や壊れた body で送らず BLOCKED にする。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-resume", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, harness)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/items", "/q", template_id="tmpl_missing")
        point_id = tools.add_point(point, {"template": {
            "url": "https://target.test/api/items",
            "json_body": {"q": "search", "sort_key": "asc"},
        }})
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]

        # 新しいインスタンス（セッション上に live template がない状態をシミュレート）
        resumed_harness = _harness(tmp_path, resume=True)
        empty_scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-resume", "domain": "target.test"}])
        engines = []
        resumed_tools = AgentScannerTools(empty_scanner, resumed_harness, engine_factory=lambda *a: engines.append(_FakeEngine(*a)) or engines[-1])
        res = await resumed_tools.run_scanner_work(work_id)
        assert res["status"] == "blocked"
        assert "template" in res["reason"] or "unavailable" in res["reason"]
        assert len(engines) == 0
        assert resumed_harness.state.work_queue[-1].status == WorkStatus.BLOCKED
    asyncio.run(scenario())


def test_tampered_live_template_structure_blocks_before_send(tmp_path):
    """取り直した template の構造ハッシュが注入点と一致しない場合、BLOCKED にする。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-resume", "domain": "target.test"}])
        scanner.captured_templates = {}
        tools = AgentScannerTools(scanner, harness)
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/items", "/q", template_id="tmpl_tamper")
        point_id = tools.add_point(point, {"template": {
            "url": "https://target.test/api/items",
            "json_body": {"q": "search", "sort_key": "asc"},
        }})
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]

        # 登録時のメモリキャッシュを消し、構造が異なる template をセット（sort_key が欠落し別キーがある）
        tools._live_templates.clear()
        scanner.captured_templates.clear()
        scanner.captured_templates[point_id] = {
            "url": "https://target.test/api/items",
            "method": "POST",
            "json_body": {"q": "search", "different_field": 123},
        }
        res = await tools.run_scanner_work(work_id)
        assert res["status"] == "blocked"
        assert "structure" in res["reason"] or "match" in res["reason"]
    asyncio.run(scenario())


def test_real_scan_engine_bearer_origin_scoped_and_scope_enforced(tmp_path, monkeypatch):
    """実際の ScanEngine に対し、Bearer は同一 origin のみに付与され、別 origin の access_urls や
    スコープ外ホストには付与されず、header scope enforcement 無効時は送信が BLOCKED になる。"""
    async def scenario():
        from wscan.engine import ScanEngine
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-val", "domain": "a.test"}])
        scanner.target_url = "https://a.test/"
        scanner.target_urls = ["https://a.test/"]
        scanner.access_urls = ["https://sso.b.test/login"]
        scanner.login_url = "https://a.test/login"
        fresh_bearer = "fresh-bearer-real-engine-1234"

        async def capture_tokens(_session):
            return [{"storage": "local", "key": "access_token", "value": fresh_bearer}]

        scanner._capture_tokens = capture_tokens
        scanner._active_session = _PageSession("https://a.test/app")

        real_engines = []
        def factory(check, handoff):
            engine = ScanEngine(
                "https://a.test/",
                target_urls=["https://a.test/"],
                access_urls=["https://sso.b.test/login"],
                checks=[check],
                headless=True,
                open_report=False,
            )
            engine._browser = _FakeBrowser()
            async def fake_seed(*_):
                return True
            engine._seed_and_verify_handoff_cookies = fake_seed
            engine.scanners[check] = _FakeScanner(findings=[])
            real_engines.append(engine)
            return engine

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)
        point = InjectionPoint.for_url_param("https://a.test/api/search?q=1", "q")
        template = {
            "url": "https://a.test/api/search?q=1",
            "headers": {"Authorization": "Bearer old-expired-token", "Accept": "application/json"},
        }
        point_id = tools.add_point(point, {"template": template})
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "completed"
        assert len(real_engines) == 1
        eng = real_engines[0]

        # 1. Bearer は HeaderManager current には登録されない（全体流出防止）
        assert "Authorization" not in eng.header_manager.current()

        # 2. 同一 origin へのリクエストには Bearer が付与される
        assert eng.auth_headers(url="https://a.test/api/search?q=1").get("Authorization") == f"Bearer {fresh_bearer}"

        # 3. 異なる origin の access_urls (sso.b.test) には Bearer が付与されない
        assert "Authorization" not in eng.auth_headers(url="https://sso.b.test/login")

        # 4. スコープ外のホスト (evil.test) には Bearer が付与されない
        assert "Authorization" not in eng.auth_headers(url="https://evil.test/attack")

        # 5. header scope enforcement が無効な場合 (engine.header_scope_enforce=False または env var)
        # は Bearer の送信が BLOCKED になり、理由が記録される
        blocked_engines = []
        def disabled_factory(check, handoff):
            engine = factory(check, handoff)
            engine.header_scope_enforce = False
            blocked_engines.append(engine)
            return engine

        tools_disabled = AgentScannerTools(scanner, harness, engine_factory=disabled_factory)
        work_id2 = tools_disabled.schedule_scanner(point_id, "sqli")["work_id"]
        res2 = await tools_disabled.run_scanner_work(work_id2)
        assert res2["status"] == "blocked"
        assert res2["reason"] == "header scope enforcement is disabled; bearer token was withheld"

        # env var WSCAN_HEADER_SCOPE_ENFORCE=0 でも同様に BLOCKED
        monkeypatch.setenv("WSCAN_HEADER_SCOPE_ENFORCE", "0")
        tools_env = AgentScannerTools(scanner, harness, engine_factory=factory)
        work_id3 = tools_env.schedule_scanner(point_id, "os")["work_id"]
        res3 = await tools_env.run_scanner_work(work_id3)
        assert res3["status"] == "blocked"
        assert res3["reason"] == "header scope enforcement is disabled; bearer token was withheld"

    asyncio.run(scenario())


def test_api_get_bearer_fresh_token_attached_when_origin_matches(tmp_path):
    """API GET carrier でも、対象と同じ origin のセッションから新しい Bearer を付け直す。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-auth", "domain": "target.test"}])
        fresh_bearer = "fresh-bearer-api-get-9999"

        async def capture_tokens(_session):
            return [{"storage": "local", "key": "access_token", "value": fresh_bearer}]

        scanner._capture_tokens = capture_tokens
        scanner._active_session = _PageSession("https://target.test/app")
        engines = []
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *a: engines.append(_FakeEngine(*a)) or engines[-1])

        # API GET query injection point with template containing old Authorization
        point = InjectionPoint.for_url_param("https://target.test/api/search?q=1", "q")
        template = {
            "url": "https://target.test/api/search?q=1",
            "headers": {"Authorization": _SECRET_AUTH, "Accept": "application/json"},
        }
        point_id = tools.add_point(point, {"template": template})
        persisted = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert _SECRET_AUTH not in persisted
        assert "application/json" in persisted

        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "completed"
        assert len(engines) == 1
        assert "Authorization" not in engines[0].headers
        assert getattr(engines[0], "_synced_token", {}).get("headers", {}).get("Authorization") == f"Bearer {fresh_bearer}"
        assert engines[0].auth_headers(url="https://target.test/api/search?q=1").get("Authorization") == f"Bearer {fresh_bearer}"
        assert fresh_bearer not in _all_persisted(tmp_path)
    asyncio.run(scenario())


def test_template_url_query_values_are_not_persisted_and_reobtained_on_send(tmp_path):
    """Template URL のクエリ値（トークンや通常クエリ値）は永続化されず、キー名と構造ハッシュのみ保持され、
    送信時に live agent session から再取得されて scanner へ渡される。再開時も成功し、構造改ざん時は BLOCKED になる。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-val", "domain": "target.test"}])
        scanner._active_session = _PageSession("https://target.test/app")

        fake_scanner = _FakeScanner(findings=[])
        engines = []
        def factory(check, handoff):
            eng = _FakeEngine(check, handoff, scanner=fake_scanner)
            engines.append(eng)
            return eng

        tools = AgentScannerTools(scanner, harness, engine_factory=factory)

        raw_url = "https://target.test/api/search?q=test&access_token=secret_tok_123&page=2&sort=asc"
        point = InjectionPoint.for_url_param("https://target.test/api/search?q=1", "q")
        template = {
            "url": raw_url,
            "method": "GET",
            "headers": {"Accept": "application/json"},
        }

        point_id = tools.add_point(point, {"template": template})

        # 1. agent_scanner_points.json の検証: クエリ値（secret_tok_123, 2, asc, test）は一切含まれない
        points_text = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert "secret_tok_123" not in points_text
        assert "sort=asc" not in points_text
        assert "page=2" not in points_text
        assert "q=test" not in points_text
        # キー名は残る
        assert "access_token=" in points_text
        assert "sort=" in points_text
        assert "page=" in points_text
        assert "q=" in points_text

        # 2. 送信時: live template からクエリ値が再取得され、scanner.scan_field に渡される
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "completed"
        assert len(fake_scanner.calls) == 1
        called_url = fake_scanner.calls[0][0]
        # 通常クエリ値が scanner に渡されている
        assert "sort=asc" in called_url
        assert "page=2" in called_url
        assert "q=test" in called_url

        # 3. points, state, events, probe_attempts に secret_tok_123 が出現しない
        all_text = _all_persisted(tmp_path)
        assert "secret_tok_123" not in all_text

        # 4. 再開 (resume) の検証: メモリキャッシュを消して disk から再構築し、scanner.captured_templates から再取得して成功
        tools._live_templates.clear()
        tools_resumed = AgentScannerTools(scanner, harness, engine_factory=factory)
        # scanner の captured_templates に live template を設定
        scanner.captured_templates[point_id] = template
        work_id2 = tools_resumed.schedule_scanner(point_id, "sqli")["work_id"]
        res2 = await tools_resumed.run_scanner_work(work_id2)
        assert res2["status"] == "completed"

        # 5. live template が取得できない、またはクエリ構造が不一致（キーが異なる）場合は BLOCKED になる
        tools_resumed._live_templates.clear()
        scanner.captured_templates.clear()
        scanner.captured_templates[point_id] = {
            "url": "https://target.test/api/search?tampered_param=1",
            "method": "GET",
        }
        work_id3 = tools_resumed.schedule_scanner(point_id, "os")["work_id"]
        res3 = await tools_resumed.run_scanner_work(work_id3)
        assert res3["status"] == "blocked"
        assert "structure" in res3["reason"] or "match" in res3["reason"] or "live request template" in res3["reason"]

    asyncio.run(scenario())


def test_api_get_bearer_blocked_when_token_unavailable(tmp_path):
    """API GET carrier で Bearer が得られなければ未認証で送らず BLOCKED にして理由を記録する。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-none", "domain": "target.test"}])
        scanner._active_session = _PageSession("https://target.test/app")
        engines = []
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *a: engines.append(_FakeEngine(*a)) or engines[-1])

        point = InjectionPoint.for_url_param("https://target.test/api/search?q=1", "q")
        template = {
            "url": "https://target.test/api/search?q=1",
            "headers": {"Authorization": _SECRET_AUTH},
        }
        point_id = tools.add_point(point, {"template": template})
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "blocked"
        assert "bearer" in result["reason"]
        assert len(engines) == 0  # 送信せず engine も起動しない
        assert harness.state.work_queue[-1].status == WorkStatus.BLOCKED
        assert "bearer" in harness.state.work_queue[-1].rejection_reason
        assert any(e.get("reason") == "bearer authentication unavailable in the agent session"
                   for e in harness.state.events)
    asyncio.run(scenario())


def test_api_get_bearer_blocked_when_origin_mismatches(tmp_path):
    """API GET carrier で現在のページ origin が送信先と異なれば Bearer を付けずに BLOCKED にする。"""
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-value-diff", "domain": "target.test"}])

        async def capture_tokens(_session):
            return [{"storage": "local", "key": "access_token", "value": "other-token-value"}]

        scanner._capture_tokens = capture_tokens
        scanner._active_session = _PageSession("https://other-origin.example/page")
        engines = []
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *a: engines.append(_FakeEngine(*a)) or engines[-1])

        point = InjectionPoint.for_url_param("https://target.test/api/search?q=1", "q")
        template = {
            "url": "https://target.test/api/search?q=1",
            "headers": {"Authorization": _SECRET_AUTH},
        }
        point_id = tools.add_point(point, {"template": template})
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "blocked"
        assert "bearer" in result["reason"]
        assert len(engines) == 0
    asyncio.run(scenario())


def test_sanitize_template_idempotence_property():
    """sanitize_template は任意の組み合わせ（クエリあり/なし、userinfo あり/なし、JSON/GET）で
    完全に冪等であり、2回目以降の sanitize でも構造ハッシュおよびメタ情報が変化しない。"""
    from wscan.agent_scanner_tools import sanitize_template
    import itertools

    url_variants = [
        "https://target.test/api/items",
        "https://target.test/api/search?q=hello&page=2",
        "https://admin:SecretPass123@target.test:8080/api/items",
        "https://admin:SecretPass123@target.test:8080/api/search?q=hello&access_token=SecretTok99&page=2",
    ]
    body_variants = [
        None,
        {"q": "search", "sort_key": "asc"},
        {"nested": {"items": [1, 2, 3], "flag": True}},
    ]
    header_variants = [
        None,
        {"Authorization": "Bearer secret-token-xyz", "Content-Type": "application/json"},
        {"Accept": "application/json", "X-Custom": "custom-val"},
    ]

    for url, body, headers in itertools.product(url_variants, body_variants, header_variants):
        raw = {"url": url, "method": "POST" if body else "GET"}
        if body is not None:
            raw["json_body"] = body
        if headers is not None:
            raw["headers"] = headers

        t1, _ = sanitize_template(raw)
        t2, _ = sanitize_template(t1)
        t3, _ = sanitize_template(t2)

        # 冪等性: sanitize(sanitize(t)) == sanitize(t)
        assert t1 == t2, f"Idempotence failed between t1 and t2 for {raw}"
        assert t2 == t3, f"Idempotence failed between t2 and t3 for {raw}"
        assert t1.get("structure_hash") == t2.get("structure_hash") == t3.get("structure_hash")
        assert t1["url"] == t2["url"] == t3["url"]

        # 秘密値の除去
        assert "SecretPass123" not in t1["url"]
        assert "admin@" not in t1["url"]
        assert "SecretTok99" not in t1["url"]
        assert "hello" not in t1["url"]


def test_json_template_with_query_url_same_run_and_resume_can_reobtain_and_send(tmp_path):
    """クエリ付き URL を持つ JSON template が、同一実行内でも resume 時でも live セッションから
    再取得されて正常に送信され、live テンプレート構造不一致時は BLOCKED になる。"""
    async def scenario():
        engines = []
        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engines.append(engine)
            return engine

        raw_url = "https://target.test/api/search?q=hello&page=2"
        scanner = _AgentScanner([{"name": "session", "value": "c1", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, _harness(tmp_path), engine_factory=factory)
        tmpl = {"url": raw_url, "method": "POST", "json_body": {"q": "x", "sort_key": "asc"}}
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/search", "/q", template_id="tmpl_jq")
        pid = tools.add_point(point, {"name": "/q", "template": tmpl})

        # 1. 同一実行内での送信: live template から再取得されて completed
        work_id1 = tools.schedule_scanner(pid, "sqli")["work_id"]
        res1 = await tools.run_scanner_work(work_id1)
        assert res1["status"] == "completed"
        sent_tmpl1 = engines[-1].injection_templates["tmpl_jq"]
        assert sent_tmpl1["url"] == raw_url
        assert sent_tmpl1["json_body"] == {"q": "x", "sort_key": "asc"}

        # 2. resume (live ソースなし): テンプレート取得不可のため BLOCKED
        resumed_no_source = AgentScannerTools(
            _AgentScanner([{"name": "session", "value": "c2", "domain": "target.test"}]),
            _harness(tmp_path, resume=True),
            engine_factory=factory,
        )
        work_id2 = resumed_no_source.schedule_scanner(pid, "xss")["work_id"]
        res2 = await resumed_no_source.run_scanner_work(work_id2)
        assert res2["status"] == "blocked"
        assert "live request template is unavailable" in res2["reason"]

        # 3. resume (live ソース一致): captured_templates から再取得されて completed
        scanner_live = _AgentScanner([{"name": "session", "value": "c3", "domain": "target.test"}])
        scanner_live.captured_templates = {pid: dict(tmpl, url="https://target.test/api/search?q=world&page=2")}
        resumed_live = AgentScannerTools(scanner_live, _harness(tmp_path, resume=True), engine_factory=factory)
        work_id3 = resumed_live.schedule_scanner(pid, "os")["work_id"]
        res3 = await resumed_live.run_scanner_work(work_id3)
        assert res3["status"] == "completed"
        sent_tmpl3 = engines[-1].injection_templates["tmpl_jq"]
        assert sent_tmpl3["url"] == "https://target.test/api/search?q=world&page=2"
        assert sent_tmpl3["json_body"] == {"q": "x", "sort_key": "asc"}

        # 4. resume (live ソースのクエリキー構造不一致): BLOCKED
        scanner_mismatch = _AgentScanner([{"name": "session", "value": "c4", "domain": "target.test"}])
        d_mismatch = tmp_path / "mismatch"
        d_mismatch.mkdir()
        tools_m = AgentScannerTools(scanner_mismatch, _harness(d_mismatch), engine_factory=factory)
        pid_m = tools_m.add_point(point, {"name": "/q", "template": tmpl})
        tools_m._live_templates.clear()
        # add_point の後に captured_templates を不一致クエリ (page キー欠落) に書き換える
        scanner_mismatch.captured_templates = {pid_m: dict(tmpl, url="https://target.test/api/search?q=1")}
        work_id4 = tools_m.schedule_scanner(pid_m, "sqli")["work_id"]
        res4 = await tools_m.run_scanner_work(work_id4)
        assert res4["status"] == "blocked"
        assert "structure does not match" in res4["reason"]

    asyncio.run(scenario())


def test_userinfo_credentials_never_appear_in_persisted_files(tmp_path):
    """Template URL の userinfo (ユーザー名・パスワード) は points, state, events, probe_attempts
    のいずれにも一切平文保存されず、送信時は Agent セッションから再取得される。"""
    async def scenario():
        engines = []
        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engine.target_urls = ["https://target.test:8080/"]
            engines.append(engine)
            return engine

        secret_user = "TargetAdminUser77"
        secret_pass = "SuperSecretPassword9988"
        raw_url = f"https://{secret_user}:{secret_pass}@target.test:8080/api/submit?q=1&token=SecretTok771"
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-1", "domain": "target.test"}])
        scanner.target_urls = ["https://target.test:8080/"]
        scanner.target_url = "https://target.test:8080/"
        tools = AgentScannerTools(scanner, _harness(tmp_path), engine_factory=factory)

        tmpl = {"url": raw_url, "method": "POST", "json_body": {"q": "x"}}
        point = InjectionPoint.for_json_body("POST", "https://target.test:8080/api/submit", "/q", template_id="tmpl_uinfo")
        point_id = tools.add_point(point, {"name": "/q", "template": tmpl})

        # 1. agent_scanner_points.json の検査
        points_text = (tmp_path / "agent_scanner_points.json").read_text(encoding="utf-8")
        assert secret_user not in points_text
        assert secret_pass not in points_text
        assert "SecretTok771" not in points_text
        assert "target.test:8080" in points_text

        # 2. スキャン実行
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]
        res = await tools.run_scanner_work(work_id)
        assert res["status"] == "completed"

        # 3. points, state, events, probe_attempts の全ファイル検査
        all_text = _all_persisted(tmp_path)
        assert secret_user not in all_text
        assert secret_pass not in all_text
        assert "SecretTok771" not in all_text

        # 4. 送信時は live template から再取得された URL が使われる
        assert len(engines) == 1
        sent_tmpl = engines[0].injection_templates["tmpl_uinfo"]
        assert sent_tmpl["url"] == raw_url

    asyncio.run(scenario())


def test_probe_attempts_never_contain_header_body_query_or_userinfo_values(tmp_path):
    """probe_attempts.jsonl の全文に、template のヘッダ・body・クエリ・userinfo の値が出ないこと。

    送信 URL（取り直した live template の URL）を probe 記録へ書く退行を検出する。
    """
    values = {
        "user": "ProbeUserinfoName41",
        "pass": "ProbeUserinfoPass42",
        "sig": "ProbeQuerySigValue43",
        "tok": "ProbeQueryTokValue44",
        "body": "ProbeBodyLeafValue45",
        "hdr": "ProbeHeaderValue46",
        "auth": "ProbeAuthHeaderValue47",
    }

    async def scenario():
        engines = []

        def factory(check, handoff):
            engine = _FakeEngine(check, handoff)
            engines.append(engine)
            return engine

        raw_url = (
            f"https://{values['user']}:{values['pass']}@target.test/api/submit"
            f"?sig={values['sig']}&access_token={values['tok']}"
        )
        scanner = _AgentScanner([{"name": "session", "value": "fresh-session-probe", "domain": "target.test"}])
        tools = AgentScannerTools(scanner, _harness(tmp_path), engine_factory=factory)
        tmpl = {
            "url": raw_url,
            "method": "POST",
            "json_body": {"q": "x", "note": values["body"]},
            "headers": {"X-Custom": values["hdr"], "Authorization": f"Basic {values['auth']}"},
        }
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/submit", "/q", template_id="tmpl_probe")
        point_id = tools.add_point(point, {"name": "/q", "template": tmpl})
        work_id = tools.schedule_scanner(point_id, "sqli")["work_id"]
        res = await tools.run_scanner_work(work_id)
        assert res["status"] == "completed"
        # 送信自体は取り直した実 URL を使っている（値は送信にだけ使われる）
        assert engines[0].injection_templates["tmpl_probe"]["url"] == raw_url

    asyncio.run(scenario())
    ledger = (tmp_path / "probe_attempts.jsonl").read_text(encoding="utf-8")
    assert ledger.strip(), "probe attempt must be recorded"
    leaked = [name for name, value in values.items() if value in ledger]
    assert not leaked, leaked


def test_real_scan_engine_json_template_unrecoverable_on_resume_is_blocked_with_reason(tmp_path):
    """本番の AgentBrowserScanner（取り直し元を持たない）と既定の ScanEngine 生成経路で、
    resume 後に JSON template を取り直せないときは送らず BLOCKED とし、理由を記録する。"""
    from wscan.llm_agent_browser import AgentBrowserScanner

    def production_scanner():
        scanner = AgentBrowserScanner(
            target_url="https://target.test/",
            target_urls=["https://target.test/"],
            access_urls=["https://target.test/login"],
            login_url="https://target.test/login",
        )
        # ブラウザだけ差し替える（認証済みセッション）。template の取り直し機能は本番のまま
        scanner._active_session = _PageSession("https://target.test/app")

        async def capture_cookies(_session):
            return [{"name": "session", "value": "fresh-session-prod", "domain": "target.test"}]

        scanner._capture_cookies = capture_cookies
        return scanner

    async def scenario():
        tmpl = {"url": "https://target.test/api/items", "method": "POST", "json_body": {"q": "a", "sort_key": "asc"}}
        point = InjectionPoint.for_json_body("POST", "https://target.test/api/items", "/q", template_id="tmpl_prod")
        first = AgentScannerTools(production_scanner(), _harness(tmp_path))
        point_id = first.add_point(point, {"name": "/q", "template": tmpl})
        work_id = first.schedule_scanner(point_id, "sqli")["work_id"]

        # 別プロセスの resume を模す: メモリ上の template は無く、本番 scanner にも取り直し元が無い
        harness = _harness(tmp_path, resume=True)
        resumed = AgentScannerTools(production_scanner(), harness)
        built = []
        default_factory = resumed.engine_factory  # 既定＝実 ScanEngine を生成する本番経路

        def spy(check, handoff):
            engine = default_factory(check, handoff)
            built.append(engine)
            return engine

        resumed.engine_factory = spy
        res = await resumed.run_scanner_work(work_id)
        return res, harness, built, work_id

    res, harness, built, work_id = asyncio.run(scenario())
    reason = "live request template is unavailable in the current agent session"
    assert res == {"status": "blocked", "reason": reason}
    # 黙って送らない: ScanEngine を生成せず、probe は sent/completed として記録されない
    assert built == []
    ledger_path = tmp_path / "probe_attempts.jsonl"
    ledger = ledger_path.read_text(encoding="utf-8") if ledger_path.exists() else ""
    assert work_id not in ledger
    # 誤って成功扱いにしない: work は BLOCKED で理由付き、dispatch event にも拒否理由が残る
    work = next(item for item in harness.state.work_queue if item.work_id == work_id)
    assert work.status == WorkStatus.BLOCKED
    assert work.rejection_reason == reason
    assert any(
        ev.get("work_id") == work_id and ev.get("allowed") is False and ev.get("reason") == reason
        for ev in harness.state.events
    )
