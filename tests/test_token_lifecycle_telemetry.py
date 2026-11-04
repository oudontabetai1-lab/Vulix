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
