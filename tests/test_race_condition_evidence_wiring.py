"""Persisted causal probe evidence for RaceConditionScanner concurrent burst fan-in."""
from __future__ import annotations

import asyncio
import json
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx
import pytest

from wscan.probe_recorder import MANIFEST_FILENAME
from wscan.request_logger import RequestLogger
from wscan.scanners.base import Finding
from wscan.scanners.race_condition import RaceConditionScanner


_ORIGINAL_ASYNC_CLIENT = httpx.AsyncClient
URL = "http://user:pass@target.test/coupon/apply?access_token=query-secret"


class RaceConditionFixture:
    def __init__(
        self,
        *,
        vulnerable: bool = False,
        failure: Exception | None = None,
        failures: dict[int, Exception] | None = None,
        delay_map: dict[int, float] | None = None,
    ):
        self.vulnerable = vulnerable
        self.failure = failure
        self.failures = failures or {}
        self.delay_map = delay_map or {}
        self.requests: list[httpx.Request] = []
        self._lock = asyncio.Lock()
        self._counter = 0

    async def __call__(self, request: httpx.Request) -> httpx.Response:
        async with self._lock:
            idx = self._counter
            self._counter += 1
            self.requests.append(request)

        if idx in self.delay_map:
            await asyncio.sleep(self.delay_map[idx])

        if self.failure:
            raise self.failure

        if idx in self.failures:
            raise self.failures[idx]

        if self.vulnerable:
            return httpx.Response(
                200,
                text="success completed accepted coupon applied",
                headers={"set-cookie": "sid=response-secret"},
                request=request,
            )

        # Safe twin: only the first request succeeds; subsequent requests return duplicate conflict.
        if idx == 0:
            return httpx.Response(
                200,
                text="success completed accepted coupon applied",
                request=request,
            )
        return httpx.Response(
            409,
            text="already redeemed duplicate coupon limit exceeded",
            request=request,
        )


def setup(
    tmp_path,
    monkeypatch,
    fixture,
    *,
    logging: bool | None = True,
    hook=None,
    state_profile: str = "unrestricted",
):
    logger = None if logging is None else RequestLogger(tmp_path, enabled=logging)

    def client_kwargs(**kwargs):
        hooks = {"request": [hook]} if hook else {}
        if logger is not None:
            hooks["request"] = [*hooks.get("request", []), logger.log_httpx_submission]
            hooks["response"] = [logger.log_httpx_response]
        return {**kwargs, "event_hooks": hooks}

    mock_pair = {
        "request": {
            "url": URL,
            "method": "POST",
            "post_data": "coupon=SAVE100&password=secret-pass",
            "headers": {"authorization": "Bearer token123", "cookie": "session=abc"},
        },
        "response": {"status": 200, "headers": {}},
    }

    engine = SimpleNamespace(
        request_logger=logger,
        browser=SimpleNamespace(
            network=SimpleNamespace(
                pairs=[mock_pair],
                latest=lambda: mock_pair,
                latest_for_url=lambda url, match_query=False: mock_pair,
            ),
            screenshot_b64=AsyncMock(return_value=""),
            navigate=AsyncMock(),
            page=SimpleNamespace(
                evaluate=AsyncMock(return_value={
                    "action": "/coupon/apply",
                    "method": "POST",
                    "fields": {"coupon": "SAVE100", "password": "secret-pass"},
                })
            ),
        ),
        monitor=None,
        payload_gen=None,
        timeout=1,
        proxy="",
        wave_errors=[],
        all_findings=[],
        _finding_dedup=set(),
        state_profile=state_profile,
        httpx_client_kwargs=client_kwargs,
        auth_headers_for_url=lambda url: {"authorization": "Bearer token123"},
    )
    scanner = RaceConditionScanner(engine)
    options = []

    def client(**kwargs):
        options.append(dict(kwargs))
        return _ORIGINAL_ASYNC_CLIENT(**{k: v for k, v in kwargs.items() if k != "transport"}, transport=httpx.MockTransport(fixture))

    monkeypatch.setattr("wscan.scanners.race_condition.httpx.AsyncClient", client)
    return engine, scanner, logger, options


def ledger_rows(logger: RequestLogger) -> list[dict]:
    path = logger.probe_ledger.path
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


@pytest.mark.asyncio
async def test_vulnerable_twin_records_fan_in_causal_chain_and_reloads_cleanly(tmp_path, monkeypatch):
    fixture, hook_calls = RaceConditionFixture(vulnerable=True), []

    async def existing_hook(request):
        hook_calls.append(request.method)

    _, scanner, logger, options = setup(tmp_path, monkeypatch, fixture, hook=existing_hook)
    findings = await scanner.scan_page(URL)

    assert len(findings) == 1
    finding = findings[0]
    assert finding.evidence_type == "race_condition_burst"
    assert finding.severity == "high"
    assert len(fixture.requests) == 8
    assert len(hook_calls) == 8

    # Verify physical outgoing requests carry actual credentials unchanged
    for req in fixture.requests:
        assert req.method == "POST"
        assert req.url.params["access_token"] == "query-secret"
        assert req.headers.get("authorization") == "Basic dXNlcjpwYXNz"
        assert "password=secret-pass" in req.content.decode()

    logger.probe_ledger.write_manifest()
    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]
    decisions = [row for row in records if row["record_kind"] == "decision"]

    assert len(requests) == 8
    assert len(observations) == 8
    assert len(decisions) == 1

    decision = decisions[0]
    assert decision["outcome"] == "matched"
    assert decision["decision_rule"] == "race_condition_burst"
    assert decision["role"] == "attack"
    assert len(decision["related_attempt_ids"]) == 8
    assert set(decision["related_attempt_ids"]) == {obs["attempt_id"] for obs in observations}
    assert decision["parent_id"] == observations[0]["attempt_id"]
    assert decision["request_attempt_id"] == requests[0]["attempt_id"]

    # Each observation has exactly 1 parent request
    by_request = {row["attempt_id"]: row for row in requests}
    for obs in observations:
        assert obs["parent_id"] in by_request
        assert obs["request_attempt_id"] == obs["parent_id"]
        assert obs["response"]["status"] == 200

    # Finding links precisely to the decision
    assert finding.evidence_details.get("attempt_ids") == [decision["attempt_id"]]

    # Reload from disk: manifest verification
    restored = RequestLogger(tmp_path)
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert set(restored.probe_ledger.events) == {row["attempt_id"] for row in records}
    assert manifest["logical_requests"] == 8
    assert manifest["evidence_incomplete"] is False
    assert manifest["had_write_error"] is False

    # Redaction: secrets must NOT appear in persisted ledger, manifest, or finding JSON
    persisted = logger.probe_ledger.path.read_text() + (tmp_path / MANIFEST_FILENAME).read_text()
    for secret in ("user:pass", "query-secret", "response-secret", "secret-pass", "token123"):
        assert secret not in persisted

    finding_json = json.dumps(finding.to_dict())
    for secret in ("user:pass", "query-secret", "response-secret", "secret-pass", "token123"):
        assert secret not in finding_json


@pytest.mark.asyncio
async def test_safe_twin_records_no_match_decision_and_no_finding(tmp_path, monkeypatch):
    fixture = RaceConditionFixture(vulnerable=False)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    findings = await scanner.scan_page(URL)
    assert findings == []
    assert len(fixture.requests) == 8

    logger.probe_ledger.write_manifest()
    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]
    decisions = [row for row in records if row["record_kind"] == "decision"]

    assert len(requests) == 8
    assert len(observations) == 8
    assert len(decisions) == 1

    decision = decisions[0]
    assert decision["outcome"] == "no_match"
    assert decision["decision_rule"] == "race_condition_burst"
    assert len(decision["related_attempt_ids"]) == 8

    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert manifest["logical_requests"] == 8
    assert manifest["evidence_incomplete"] is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    "failure_cls,expected_outcome",
    [
        (httpx.ReadTimeout, "timeout"),
        (httpx.ConnectError, "transport_error"),
    ],
)
async def test_all_transport_failure_records_typed_decisions_and_marks_incomplete(
    tmp_path, monkeypatch, failure_cls, expected_outcome
):
    failure = failure_cls("connection failed for race probe")
    fixture = RaceConditionFixture(failure=failure)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    findings = await scanner.scan_page(URL)
    assert findings == []
    assert len(fixture.requests) == 8

    logger.probe_ledger.write_manifest()
    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]
    decisions = [row for row in records if row["record_kind"] == "decision"]

    assert len(requests) == 8
    assert len(observations) == 0
    assert len(decisions) == 8

    for dec in decisions:
        assert dec["outcome"] == expected_outcome
        assert dec["decision_rule"] == "race_condition_burst"
        assert dec["response"] is None

    # Never claim safe negative when all requests failed
    assert not any(d["outcome"] == "no_match" for d in decisions)

    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert manifest["evidence_incomplete"] is True


@pytest.mark.asyncio
async def test_mixed_transport_failure_vulnerable_links_only_consumed_attempts(tmp_path, monkeypatch):
    # 2 requests fail with ReadTimeout, remaining 6 succeed (and are vulnerable)
    failures = {
        1: httpx.ReadTimeout("timeout on probe 1"),
        3: httpx.ReadTimeout("timeout on probe 3"),
    }
    fixture = RaceConditionFixture(vulnerable=True, failures=failures)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    findings = await scanner.scan_page(URL)
    assert len(findings) == 1
    assert len(fixture.requests) == 8

    logger.probe_ledger.write_manifest()
    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]
    decisions = [row for row in records if row["record_kind"] == "decision"]

    assert len(requests) == 8
    assert len(observations) == 6
    # 2 failure decisions + 1 burst decision
    assert len(decisions) == 3

    burst_decision = next(d for d in decisions if d["outcome"] == "matched")
    assert len(burst_decision["related_attempt_ids"]) == 6
    assert set(burst_decision["related_attempt_ids"]) == {obs["attempt_id"] for obs in observations}

    failure_decisions = [d for d in decisions if d["outcome"] == "timeout"]
    assert len(failure_decisions) == 2


@pytest.mark.asyncio
async def test_mixed_transport_failure_safe_avoids_false_safe_negative(tmp_path, monkeypatch):
    # 2 requests fail with ReadTimeout, remaining 6 succeed with non-vulnerable output
    failures = {
        1: httpx.ReadTimeout("timeout on probe 1"),
        3: httpx.ReadTimeout("timeout on probe 3"),
    }
    fixture = RaceConditionFixture(vulnerable=False, failures=failures)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    findings = await scanner.scan_page(URL)
    assert findings == []
    assert len(fixture.requests) == 8

    logger.probe_ledger.write_manifest()
    records = ledger_rows(logger)
    decisions = [row for row in records if row["record_kind"] == "decision"]

    # Must NOT record outcome="no_match" (safe negative) because requests failed
    assert not any(d["outcome"] == "no_match" for d in decisions)
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert manifest["evidence_incomplete"] is True


@pytest.mark.asyncio
async def test_logger_write_failure_preserves_findings_and_marks_manifest_incomplete(tmp_path, monkeypatch):
    fixture = RaceConditionFixture(vulnerable=True)
    engine, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    logger.probe_ledger.append = lambda record: (_ for _ in ()).throw(RuntimeError("disk-write-failure-secret"))
    findings = await scanner.scan_page(URL)

    assert len(findings) == 1
    assert len(fixture.requests) == 8
    assert logger.probe_ledger.evidence_incomplete is True
    assert "disk-write-failure-secret" not in str(logger.probe_ledger.manifest.to_dict())

    logger.probe_ledger.write_manifest()
    manifest = json.loads((tmp_path / MANIFEST_FILENAME).read_text())
    assert manifest["evidence_incomplete"] is True
    assert any("probe_observation_error:RuntimeError" in str(err) for err in manifest["write_errors"])


@pytest.mark.asyncio
@pytest.mark.parametrize("logging", [None, False])
async def test_disabled_and_absent_logger_parity(tmp_path, monkeypatch, logging):
    fixture = RaceConditionFixture(vulnerable=True)
    engine, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture, logging=logging)

    findings = await scanner.scan_page(URL)
    assert len(findings) == 1
    assert len(fixture.requests) == 8
    assert "race_condition_evidence_unavailable" in engine.wave_errors


@pytest.mark.asyncio
async def test_concurrent_isolation_and_out_of_order_responses(tmp_path, monkeypatch):
    # Stagger arrival times of the 8 concurrent responses
    delays = {0: 0.04, 1: 0.01, 2: 0.05, 3: 0.02, 4: 0.06, 5: 0.01, 6: 0.03, 7: 0.02}
    fixture = RaceConditionFixture(vulnerable=True, delay_map=delays)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    findings = await scanner.scan_page(URL)
    assert len(findings) == 1
    assert len(fixture.requests) == 8

    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]

    assert len(requests) == 8
    assert len(observations) == 8

    # Single response observation per actual send: no duplicates
    obs_req_ids = [obs["request_attempt_id"] for obs in observations]
    assert len(set(obs_req_ids)) == 8
    assert set(obs_req_ids) == {req["attempt_id"] for req in requests}


@pytest.mark.asyncio
async def test_scan_field_and_verify_finding_flow(tmp_path, monkeypatch):
    fixture = RaceConditionFixture(vulnerable=True)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    # 1. scan_field caller
    field = {"name": "coupon", "id": "coupon_code"}
    findings = await scanner.scan_field(URL, 0, field)
    assert len(findings) == 1
    finding = findings[0]
    assert finding.field_name == "coupon"
    assert finding.evidence_details["attempt_ids"]

    # 2. verify_finding caller on vulnerable target
    verified = await scanner.verify_finding(finding)
    assert verified is True
    assert "verification_attempt_ids" in finding.evidence_details

    # 3. verify_finding on safe target
    fixture_safe = RaceConditionFixture(vulnerable=False)
    monkeypatch.setattr(
        "wscan.scanners.race_condition.httpx.AsyncClient",
        lambda **kwargs: _ORIGINAL_ASYNC_CLIENT(**{k: v for k, v in kwargs.items() if k != "transport"}, transport=httpx.MockTransport(fixture_safe)),
    )
    verified_safe = await scanner.verify_finding(finding)
    assert verified_safe is False


@pytest.mark.asyncio
async def test_state_gate_prevents_burst_and_records_note(tmp_path, monkeypatch):
    fixture = RaceConditionFixture(vulnerable=True)
    engine, scanner, _, _ = setup(tmp_path, monkeypatch, fixture, state_profile="read-only")

    findings = await scanner.scan_page(URL)
    assert findings == []
    # State gate remains no-send: 0 HTTP requests sent
    assert len(fixture.requests) == 0
    assert "state_change_skipped:race_condition" in engine.wave_errors


def test_select_primary_burst_pair_guarantees_same_task_pairing():
    from wscan.scanners.race_condition import select_primary_burst_pair

    # Standard case: all tasks succeed
    pairs = [("req_0", "obs_0"), ("req_1", "obs_1"), ("req_2", "obs_2")]
    assert select_primary_burst_pair(pairs) == ("obs_0", "req_0")

    # Partial observation: probe 0 missing observation, probe 1 has both
    # In old code: primary_obs was obs_1, but primary_req was req_0 (mismatched!)
    partial_pairs = [("req_0", None), ("req_1", "obs_1"), ("req_2", "obs_2")]
    primary_obs, primary_req = select_primary_burst_pair(partial_pairs)
    assert primary_obs == "obs_1"
    assert primary_req == "req_1"  # Same task pair! Never req_0!

    # Multiple initial gaps
    multi_gap_pairs = [("req_0", None), ("req_1", None), ("req_2", "obs_2")]
    assert select_primary_burst_pair(multi_gap_pairs) == ("obs_2", "req_2")

    # Partial observation where the first observed task lacks request ID
    missing_req_pairs = [("req_0", None), (None, "obs_1"), ("req_2", "obs_2")]
    primary_obs, primary_req = select_primary_burst_pair(missing_req_pairs)
    assert primary_obs == "obs_1"
    assert primary_req == ""  # Treated as missing, not borrowed from req_0!

    # All observations missing
    no_obs_pairs = [("req_0", None), ("req_1", None)]
    assert select_primary_burst_pair(no_obs_pairs) == ("", "")

    # Empty input
    assert select_primary_burst_pair([]) == ("", "")


@pytest.mark.asyncio
async def test_partial_observation_burst_decision_pairs_primary_request_and_observation_to_same_task(
    tmp_path, monkeypatch
):
    fixture = RaceConditionFixture(vulnerable=True)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    orig_observe = logger.observe_request
    call_count = 0

    def mock_observe(context, request_id, pair, transport):
        nonlocal call_count
        call_count += 1
        # Drop observation for the first probe to create a partial observation scenario
        if call_count == 1:
            return None
        return orig_observe(context, request_id, pair, transport)

    monkeypatch.setattr(logger, "observe_request", mock_observe)

    findings = await scanner.scan_page(URL)
    assert len(findings) == 1
    assert len(fixture.requests) == 8

    records = ledger_rows(logger)
    requests = [row for row in records if row["record_kind"] == "request"]
    observations = [row for row in records if row["record_kind"] == "observation"]
    decisions = [row for row in records if row["record_kind"] == "decision"]

    assert len(requests) == 8
    assert len(observations) == 7  # 1st probe dropped observation
    assert len(decisions) == 1

    decision = decisions[0]
    # Primary observation is the first successful observation (probe 2)
    primary_obs = observations[0]
    assert decision["parent_id"] == primary_obs["attempt_id"]
    # Primary request MUST be probe 2's request (same task!), NOT requests[0] (probe 1)
    assert decision["request_attempt_id"] == primary_obs["request_attempt_id"]
    assert decision["request_attempt_id"] != requests[0]["attempt_id"]
    assert decision["request_attempt_id"] == requests[1]["attempt_id"]


def test_url_separation_pure_helpers():
    from wscan.scanners.base import Finding
    from wscan.scanners.race_condition import (
        get_verification_url,
        split_verification_and_display_urls,
    )

    raw_url = "http://user:pass@target.test/coupon/apply?access_token=secret&page=1"
    verify_url, display_url = split_verification_and_display_urls(raw_url)

    # Verification URL preserves full userinfo and secrets
    assert verify_url == raw_url
    assert "user:pass@" in verify_url
    assert "access_token=secret" in verify_url

    # Display / evidence URL redacts userinfo and sensitive query params
    assert display_url == "http://target.test/coupon/apply?access_token=<redacted>&page=1"
    assert "user:pass" not in display_url
    assert "secret" not in display_url

    # Test get_verification_url resolution
    finding_with_attr = Finding(
        check_type="race_condition",
        severity="high",
        url=display_url,
        field_name="coupon",
        payload="8x simultaneous POST requests",
        evidence=f"Race condition probe on {display_url}",
    )
    finding_with_attr.verification_url = verify_url

    assert get_verification_url(finding_with_attr) == verify_url
    assert "user:pass@" in get_verification_url(finding_with_attr)

    # Fallback to finding.url if verification_url is not set
    finding_fallback = Finding(
        check_type="race_condition",
        severity="high",
        url="http://target.test/coupon/apply",
        field_name="coupon",
        payload="8x simultaneous POST requests",
        evidence="evidence",
    )
    assert get_verification_url(finding_fallback) == "http://target.test/coupon/apply"


@pytest.mark.asyncio
async def test_reverification_preserves_userinfo_auth_while_evidence_remains_redacted(
    tmp_path, monkeypatch
):
    fixture = RaceConditionFixture(vulnerable=True)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    findings = await scanner.scan_page(URL)
    assert len(findings) == 1
    finding = findings[0]

    # Verify that finding and evidence strictly redact userinfo and secrets
    assert "user:pass" not in finding.url
    assert "user:pass" not in finding.evidence
    assert "user:pass" not in finding.request.get("url", "")
    assert "query-secret" not in finding.url

    finding_dict = finding.to_dict()
    finding_json = json.dumps(finding_dict)
    assert "user:pass" not in finding_json
    assert "query-secret" not in finding_json

    # Verification URL on finding in-memory retains userinfo authentication
    from wscan.scanners.race_condition import get_verification_url
    assert get_verification_url(finding) == URL
    assert "user:pass@" in get_verification_url(finding)

    # Now run verify_finding and ensure re-verification outgoing requests keep userinfo Basic auth
    fixture.requests.clear()
    verified = await scanner.verify_finding(finding)
    assert verified is True
    assert len(fixture.requests) == 8

    # All outgoing re-verification requests carry the userinfo Basic auth
    for req in fixture.requests:
        assert req.method == "POST"
        assert req.headers.get("authorization") == "Basic dXNlcjpwYXNz"
        assert "user:pass@" in str(req.url)

    # Verification decision in ledger remains redacted
    records = ledger_rows(logger)
    verify_decisions = [
        row for row in records
        if row["record_kind"] == "decision" and row["role"] == "verify"
    ]
    assert len(verify_decisions) == 1
    assert "user:pass" not in str(verify_decisions[0])


@pytest.mark.asyncio
async def test_scan_field_preserves_verification_url_with_userinfo(
    tmp_path, monkeypatch
):
    fixture = RaceConditionFixture(vulnerable=True)
    _, scanner, logger, _ = setup(tmp_path, monkeypatch, fixture)

    field = {"name": "coupon", "id": "coupon_code"}
    findings = await scanner.scan_field(URL, 0, field)
    assert len(findings) == 1
    finding = findings[0]

    # Persistent URL is redacted
    assert "user:pass" not in finding.url
    assert "query-secret" not in finding.url
    assert "user:pass" not in json.dumps(finding.to_dict())

    # Verification URL retains userinfo
    from wscan.scanners.race_condition import get_verification_url
    verify_url = get_verification_url(finding)
    assert "user:pass@" in verify_url
    assert verify_url.startswith("http://user:pass@target.test/coupon/apply")

    fixture.requests.clear()
    verified = await scanner.verify_finding(finding)
    assert verified is True
    assert len(fixture.requests) == 8
    for req in fixture.requests:
        assert req.headers.get("authorization") == "Basic dXNlcjpwYXNz"

