from types import SimpleNamespace

import pytest

from wscan.engine import ScanEngine
from wscan.token_lifecycle import (
    PlannedTokenDependencyAnalyzer, TokenCarrier, TokenLifecycleEvent, TokenTransport,
)


def engine(enabled=False):
    value = ScanEngine.__new__(ScanEngine)
    value.token_lifecycle_manager = enabled
    value.wave_errors = []
    value.request_logger = None
    return value


def event(index=1):
    return TokenLifecycleEvent(str(index), f"evidence-{index}", "xss", TokenCarrier.FORM_URLENCODED,
                               TokenTransport.HTTPX, 1, "stale", 200, "refreshed")


def test_disabled_recorder_preserves_observability():
    actual, untouched = engine(), engine()
    actual.record_token_lifecycle_event(event())
    assert not hasattr(actual, "_token_lifecycle_events")
    assert "token_lifecycle" not in actual._observability_report_data()
    assert actual._observability_report_data() == untouched._observability_report_data()


def test_transport_error_attempt_id_handles_unset_and_foreign_requests():
    import httpx
    from types import SimpleNamespace
    from wscan.scanners.base import BaseScanner
    logger = object()
    error = httpx.ConnectError("x")
    with pytest.raises(RuntimeError):
        _ = error.request
    assert BaseScanner._transport_error_attempt_id(error, logger) is None
    error._request = SimpleNamespace(extensions={"vulix_probe_submission": (logger, "a1")})
    assert BaseScanner._transport_error_attempt_id(error, logger) == "a1"
    error._request = SimpleNamespace(extensions={"vulix_probe_submission": (object(), "a2")})
    assert BaseScanner._transport_error_attempt_id(error, logger) is None


def test_enabled_events_are_serialized_without_sensitive_values():
    value = engine(True)
    value.record_token_lifecycle_event(event())
    value.record_token_lifecycle_event(event(2))
    section = value._observability_report_data()["token_lifecycle"]
    assert section["total"] == 2 and len(section["events"]) == 2
    assert set(section["events"][0]) == set(event().to_dict())
    assert "raw-token" not in repr(section) and "https://secret.example" not in repr(section)


def test_event_list_is_bounded():
    value = engine(True)
    for index in range(150):
        value.record_token_lifecycle_event(event(index))
    section = value._observability_report_data()["token_lifecycle"]
    assert section["total"] == 150 and len(section["events"]) == 100


def test_bad_event_is_swallowed_and_noted():
    value = engine(True)
    value.record_token_lifecycle_event(object())
    assert value.wave_errors == ["token_lifecycle_event_error:TypeError"]


def test_event_validation_and_planned_analyzer():
    with pytest.raises(ValueError):
        TokenLifecycleEvent(None, None, "xss", TokenCarrier.FORM_URLENCODED, TokenTransport.HTTPX, 0, None, None, "unknown")
    with pytest.raises(TypeError):
        TokenLifecycleEvent(None, None, "xss", TokenCarrier.FORM_URLENCODED, TokenTransport.HTTPX, 1, None, "200", "unknown")
    with pytest.raises(NotImplementedError):
        PlannedTokenDependencyAnalyzer().dependencies(injection_point=None, token_sources=[])


@pytest.mark.asyncio
async def test_managed_probe_stale_refresh_retry_records_one_event():
    import json
    import httpx
    from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner

    app = object()
    value = _TestEngine(app, base_url="http://app.test")
    value.token_lifecycle_manager = True
    value._is_access_allowed_url = lambda _url: True
    value._is_url_excluded = lambda _url: False
    scanner = _TestFormScanner(value)
    value._token_lifecycle_events = []
    value.record_token_lifecycle_event = value._token_lifecycle_events.append
    gets = 0
    def handler(request):
        nonlocal gets
        if request.method == "GET":
            gets += 1
            token = "stale" if gets == 1 else "fresh-123"
            return httpx.Response(200, headers={"content-type": "text/html"},
                                  text=f'<form><input type="hidden" name="csrf_token" value="{token}"></form>')
        body = json.loads(request.content or b"{}")
        if body.get("csrf_token") != "fresh-123":
            return httpx.Response(419, text="CSRF token mismatch")
        return httpx.Response(200, text="ok")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler), base_url="http://app.test") as client:
        response, _, _ = await scanner._send_httpx_token_managed(
            client, "POST", "http://app.test/api", {"q": "x", "csrf_token": "stale"}, {}, "json")
    assert response.status_code == 200
    assert len(value._token_lifecycle_events) == 1
    recorded = value._token_lifecycle_events[0]
    assert recorded.attempt_count == 2
    assert recorded.refresh_reason == "stale"
    assert isinstance(recorded.final_status, int)


@pytest.mark.asyncio
async def test_managed_probe_correlates_real_request_logger_ids():
    import json
    import tempfile
    import httpx
    from wscan.engine import ScanEngine
    from wscan.request_logger import RequestLogger
    from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner

    async def run(with_logger):
        value = _TestEngine(object(), base_url="http://app.test")
        value.token_lifecycle_manager = True
        value._is_access_allowed_url = lambda _url: True
        value._is_url_excluded = lambda _url: False
        scanner = _TestFormScanner(value)
        events = []
        value.record_token_lifecycle_event = events.append
        logger = RequestLogger(tempfile.mkdtemp()) if with_logger else None
        value.request_logger = logger
        value.tls_config = type("TLS", (), {"httpx_options": lambda _self: {}})()
        value.proxy = None
        gets = 0

        def handler(request):
            nonlocal gets
            if request.method == "GET":
                gets += 1
                token = "stale" if gets == 1 else "fresh-123"
                return httpx.Response(200, text=f'<form><input type="hidden" name="csrf_token" value="{token}"></form>')
            body = json.loads(request.content or b"{}")
            return httpx.Response(200, text="ok") if body.get("csrf_token") == "fresh-123" else httpx.Response(419, text="CSRF token mismatch")

        kwargs = ScanEngine.httpx_client_kwargs(value, transport=httpx.MockTransport(handler)) if logger else {"transport": httpx.MockTransport(handler)}
        async with httpx.AsyncClient(**kwargs) as client:
            response, _, _ = await scanner._send_httpx_token_managed(
                client, "POST", "http://app.test/api", {"q": "x", "csrf_token": "stale"}, {}, "json")
        assert response.status_code == 200 and len(events) == 1
        expected_attempt = response.request.extensions["vulix_probe_submission"][1] if logger else None
        expected_evidence = response.extensions["vulix_probe_observation"][1] if logger else None
        return events[0], expected_attempt, expected_evidence

    correlated, expected_attempt, expected_evidence = await run(True)
    assert expected_attempt and expected_evidence
    assert correlated.probe_attempt_id == expected_attempt
    assert correlated.evidence_id == expected_evidence
    plain, _, _ = await run(False)
    assert plain.probe_attempt_id is None and plain.evidence_id is None


@pytest.mark.asyncio
async def test_managed_probe_refresh_failed_emits_one_event():
    import httpx
    from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
    value = _TestEngine(object(), base_url="http://app.test")
    value.token_lifecycle_manager = True
    value._is_access_allowed_url = lambda _url: True
    value._is_url_excluded = lambda _url: False
    scanner = _TestFormScanner(value)
    events = []
    value.record_token_lifecycle_event = events.append
    def handler(request):
        if request.method == "GET":
            return httpx.Response(200, text="<form></form>")
        return httpx.Response(419, text="CSRF token mismatch")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        await scanner._send_httpx_token_managed(client, "POST", "http://app.test/api", {"csrf_token": "stale"}, {}, "json")
    assert len(events) == 1 and events[0].refresh_reason == "refresh_failed"


@pytest.mark.asyncio
async def test_managed_transport_error_emits_event_and_reraises():
    import httpx
    from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner
    value = _TestEngine(object(), base_url="http://app.test")
    value.token_lifecycle_manager = True
    value._is_access_allowed_url = lambda _url: True
    value._is_url_excluded = lambda _url: False
    scanner = _TestFormScanner(value)
    value._token_lifecycle_events = []
    value.record_token_lifecycle_event = value._token_lifecycle_events.append
    error = httpx.ConnectError("offline")
    async def handler(_request):
        raise error
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(httpx.ConnectError) as raised:
            await scanner._send_httpx_token_managed(client, "POST", "http://app.test/api", {}, {}, "json")
    assert raised.value is error
    assert len(value._token_lifecycle_events) == 1
    recorded = value._token_lifecycle_events[0]
    assert (recorded.refresh_reason, recorded.final_status, recorded.final_lifecycle_status, recorded.attempt_count) == (
        "transport_error", None, "unknown", 1)
    assert recorded.probe_attempt_id is None


@pytest.mark.asyncio
async def test_managed_retry_transport_error_emits_one_event_and_preserves_response():
    import httpx
    import tempfile
    from wscan.request_logger import RequestLogger
    from tests.test_token_lifecycle_fixtures import _TestEngine, _TestFormScanner

    async def run(recorder):
        value = _TestEngine(object(), base_url="http://app.test")
        value.token_lifecycle_manager = True
        value._is_access_allowed_url = lambda _url: True
        value._is_url_excluded = lambda _url: False
        scanner = _TestFormScanner(value)
        events = []
        value.record_token_lifecycle_event = events.append if recorder else lambda _event: None
        value.request_logger = RequestLogger(tempfile.mkdtemp())
        value.tls_config = type("TLS", (), {"httpx_options": lambda _self: {}})()
        value.proxy = None
        posts = gets = 0
        retry_attempt_id = None
        error = httpx.ConnectError("retry offline")

        def handler(request):
            nonlocal posts, gets, retry_attempt_id
            if request.method == "GET":
                gets += 1
                token = "stale" if gets == 1 else "fresh-123"
                return httpx.Response(200, headers={"content-type": "text/html"},
                                      text=f'<form><input type="hidden" name="csrf_token" value="{token}"></form>')
            posts += 1
            if posts == 1:
                return httpx.Response(419, text="CSRF token mismatch")
            retry_attempt_id = request.extensions["vulix_probe_submission"][1]
            raise error

        from wscan.engine import ScanEngine
        kwargs = ScanEngine.httpx_client_kwargs(value, transport=httpx.MockTransport(handler))
        async with httpx.AsyncClient(**kwargs, base_url="http://app.test") as client:
            try:
                result = await scanner._send_httpx_token_managed(
                    client, "POST", "http://app.test/api", {"q": "x", "csrf_token": "stale"}, {}, "json")
            except Exception as exc:
                return ("raised", type(exc), str(exc)), events
        return ("returned", result[0].status_code), events, retry_attempt_id

    observed, events, retry_attempt_id = await run(True)
    noop_observed, _, _ = await run(False)
    assert observed == noop_observed == ("returned", 419)
    assert len(events) == 1
    recorded = events[0]
    assert (recorded.refresh_reason, recorded.attempt_count, recorded.final_status,
            recorded.final_lifecycle_status) == ("transport_error", 2, None, "unknown")
    assert recorded.probe_attempt_id == retry_attempt_id
    assert recorded.evidence_id is None


@pytest.mark.asyncio
async def test_stale_inconclusive_and_flag_off_are_recorder_independent():
    import httpx
    from tests.fixtures.large_vuln_app import create_app
    from tests.test_token_lifecycle_spa_api import make_scanner

    async def run(enabled, recorder_noop=False):
        app = create_app()
        app.state.json_csrf_force_stale = True
        scanner, value, point = make_scanner(app, "http://large-fixture.test/token-json", enabled)
        if enabled:
            value._token_lifecycle_events = []
            value.record_token_lifecycle_event = value._token_lifecycle_events.append
        if recorder_noop:
            value.record_token_lifecycle_event = lambda _event: None
        async with httpx.AsyncClient(**value.httpx_client_kwargs()) as client:
            response, _, _ = await scanner._send_httpx_token_managed(
                client, "POST", point.url, {"email": "probe", "csrf_token": "stale-token"},
                {"X-CSRF-Token": "stale-token"}, "json")
        return response, value

    response, value = await run(True)
    assert any(n == "token_lifecycle:probe_inconclusive:mail_header" for n in value.wave_errors)
    assert value._token_lifecycle_events[0].refresh_reason in {"stale", "refresh_failed"}
    baseline, _ = await run(True, True)
    assert (response.status_code, response.text) == (baseline.status_code, baseline.text)

    response, value = await run(False)
    baseline, _ = await run(False, True)
    assert not hasattr(value, "_token_lifecycle_events")
    assert not any("token_lifecycle_event_error" in n for n in value.wave_errors)
    assert value.wave_errors == []
    assert (response.status_code, response.text) == (baseline.status_code, baseline.text)


def test_emitted_refresh_reasons_are_accepted_by_event_schema():
    from pathlib import Path
    import re
    from wscan.token_lifecycle import _TOKEN_TELEMETRY_REASONS

    source = Path("wscan/scanners/base.py").read_text()
    body = source.split("async def _send_httpx_token_managed", 1)[1].split("@staticmethod", 1)[0]
    emitted = set(re.findall(r'refresh_reason = "([^"]+)"', body))
    assert emitted <= _TOKEN_TELEMETRY_REASONS


@pytest.mark.asyncio
async def test_managed_probe_swallows_recorder_exception():
    import httpx
    from tests.fixtures.large_vuln_app import create_app
    from tests.test_token_lifecycle_spa_api import make_scanner

    app = create_app()
    scanner, value, point = make_scanner(app, "http://large-fixture.test/token-json")
    value.record_token_lifecycle_event = lambda _event: (_ for _ in ()).throw(RuntimeError("recorder"))
    async with httpx.AsyncClient(**value.httpx_client_kwargs()) as client:
        response, _, _ = await scanner._send_httpx_token_managed(
            client, "POST", point.url, {"email": "probe", "csrf_token": "stale-token"},
            {"X-CSRF-Token": "stale-token"}, "json")
    assert response.status_code == 200
    assert value.wave_errors[-1] == "token_lifecycle_event_error:RuntimeError"
