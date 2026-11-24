from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace

import pytest
from fastapi.testclient import TestClient

from wscan.agent_harness import AgentHarness, AgentRunSpec, WorkStatus
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


class _FakeEngine:
    def __init__(self, check, handoff, finding=None, error=None, auth=True, scanner=None):
        self.handoff = handoff
        self._browser = _FakeBrowser()
        self.scanner = scanner or _FakeScanner(findings=[finding] if finding else [], error=error)
        self.scanners = {check: self.scanner}
        self.auth = auth
        self.target_urls = ["https://target.test/"]
        self.access_urls = ["https://target.test/login"]
        self.exclude_urls = ["https://target.test/private*"]
        self.exclude_fields = ["ignored"]
        self.login_url = "https://target.test/login"

    def _is_attack_target_url(self, url):
        from wscan.url_scope import url_matches_any_scope
        return url_matches_any_scope(url, self.target_urls)

    def _is_url_excluded(self, url):
        from wscan.engine import is_url_excluded
        return is_url_excluded(url, self.exclude_urls)

    async def _seed_and_verify_handoff_cookies(self, _browser):
        return self.auth


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
        response = await tools.list_scanner_capabilities()
        assert set(response) == {"capabilities"}
        by_id = {item["injection_point_id"]: item for item in response["capabilities"]}
        assert by_id[query_id]["status"] == "supported"
        assert by_id[query_id]["checks"] == ["os", "sqli", "xss"]
        assert by_id[json_id]["status"] == "unsupported"
        assert "authenticated context not shareable" in by_id[json_id]["reason"]
        assert any("unsupported_carrier:json_body" in gap for gap in harness.state.coverage_gaps)
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


def test_api_get_query_is_unsupported_before_payload_and_budget_fails_closed(tmp_path):
    async def scenario():
        harness = _harness(tmp_path)
        scanner = _AgentScanner([{"name": "session", "value": "current-cookie-value", "domain": "target.test"}])
        engine = _FakeEngine("xss", SimpleNamespace(cookies=[]), scanner=_FakeScanner(api_get=True))
        tools = AgentScannerTools(scanner, harness, engine_factory=lambda *_: engine)
        point_id = tools.add_point(InjectionPoint.for_url_param("https://target.test/api?q=1", "q"))
        work_id = tools.schedule_scanner(point_id, "xss")["work_id"]
        result = await tools.run_scanner_work(work_id)
        assert result["status"] == "unsupported"
        assert engine.scanner.calls == []
        assert any("unsupported_carrier:query_api_get" in gap for gap in harness.state.coverage_gaps)

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
        assert record["evidence_ids"] == [work_id]
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
        assert "unverifiable_checkpoint" in stored["rejection_reason"]
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
        assert "unverifiable_checkpoint" in stored["rejection_reason"]
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
        stored = next(item for item in resumed.state.hypotheses if item["candidate_id"] == candidate["candidate_id"])
        assert stored["verification_outcome"] == expected
        assert stored["status"] == "agent_only"
        assert stored["source_label"] == "agent_unverified"
        assert stored["deterministic_confirmed"] is False
        assert resumed.state.work_queue[0].work_id == work_id
        if expected == "inconclusive":
            assert resumed.state.work_queue[0].status == WorkStatus.INCONCLUSIVE
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
