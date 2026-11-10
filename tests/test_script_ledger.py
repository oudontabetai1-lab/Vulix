"""Unit tests for external script subresource scan matrix ledger rows."""
import types
import pytest

from wscan.engine import (
    ScanEngine,
    _SCRIPT_SUBRESOURCE_PAGE_CHECKS,
    _finding_matches_script,
)


def _make_engine():
    engine = ScanEngine.__new__(ScanEngine)
    engine.scan_matrix = []
    return engine


def test_script_subresource_checks_defined():
    assert "secret_leak" in _SCRIPT_SUBRESOURCE_PAGE_CHECKS
    assert "sri" in _SCRIPT_SUBRESOURCE_PAGE_CHECKS
    assert "js_static" in _SCRIPT_SUBRESOURCE_PAGE_CHECKS


def test_finding_matches_script():
    # Direct finding URL
    f1 = types.SimpleNamespace(url="http://test.local/bundle.js", evidence_details=None, field_name="(page)")
    assert _finding_matches_script(f1, "http://test.local/bundle.js")
    assert not _finding_matches_script(f1, "http://test.local/other.js")

    # evidence_details dict resource_url
    f2 = types.SimpleNamespace(
        url="http://test.local/portal",
        evidence_details={"resource_url": "http://test.local/bundle.js"},
        field_name="(page)",
    )
    assert _finding_matches_script(f2, "http://test.local/bundle.js")

    # evidence_details dict src
    f3 = types.SimpleNamespace(
        url="http://test.local/portal",
        evidence_details={"src": "http://test.local/bundle.js"},
        field_name="(page)",
    )
    assert _finding_matches_script(f3, "http://test.local/bundle.js")

    # evidence_details object script attribute
    details_obj = types.SimpleNamespace(script="http://test.local/bundle.js")
    f4 = types.SimpleNamespace(
        url="http://test.local/portal",
        evidence_details=details_obj,
        field_name="(page)",
    )
    assert _finding_matches_script(f4, "http://test.local/bundle.js")

    # field_name contains script URL
    f5 = types.SimpleNamespace(
        url="http://test.local/portal",
        evidence_details=None,
        field_name="(http://test.local/bundle.js) [innerHTML L10]",
    )
    assert _finding_matches_script(f5, "http://test.local/bundle.js")


def test_record_external_script_scan_matrix_tested():
    engine = _make_engine()
    page = types.SimpleNamespace(
        url="http://test.local/portal",
        external_scripts={"http://test.local/clean.js": "const safe = true;"},
    )
    engine._record_external_script_scan_matrix(page, "secret_leak", [])

    assert len(engine.scan_matrix) == 1
    row = engine.scan_matrix[0]
    assert row["url"] == "http://test.local/clean.js"
    assert row["field_name"] == "(page)"
    assert row["check"] == "secret_leak"
    assert row["status"] == "tested"
    assert row["location"] == "page-level"
    assert row["finding_count"] == 0


def test_record_external_script_scan_matrix_finding():
    engine = _make_engine()
    script_url = "http://test.local/vulnerable.js"
    page = types.SimpleNamespace(
        url="http://test.local/portal",
        external_scripts={script_url: "const apiKey = 'AKIAIOSFODNN7EXAMPLE';"},
    )
    finding = types.SimpleNamespace(
        url=script_url,
        severity="high",
        evidence_details={"resource_url": script_url},
        field_name="(response body)",
    )
    engine._record_external_script_scan_matrix(page, "secret_leak", [finding])

    assert len(engine.scan_matrix) == 1
    row = engine.scan_matrix[0]
    assert row["url"] == script_url
    assert row["check"] == "secret_leak"
    assert row["status"] == "finding"
    assert row["severity"] == "high"
    assert row["finding_count"] == 1


def test_fetch_failure_not_recorded_as_tested():
    engine = _make_engine()
    page = types.SimpleNamespace(
        url="http://test.local/portal",
        external_scripts={
            "http://test.local/empty.js": "",
            "http://test.local/whitespace.js": "   \n\t  ",
            "http://test.local/none.js": None,
        },
    )
    engine._record_external_script_scan_matrix(page, "secret_leak", [])

    # None of the un-fetched / empty scripts must be recorded as tested
    assert len(engine.scan_matrix) == 0


def test_record_external_script_scan_matrix_error():
    engine = _make_engine()
    script_url = "http://test.local/app.js"
    page = types.SimpleNamespace(
        url="http://test.local/portal",
        external_scripts={script_url: "console.log('hi');"},
    )
    engine._record_external_script_scan_matrix(
        page, "secret_leak", [], error_note="page-level scan raised: TimeoutError: timed out"
    )

    assert len(engine.scan_matrix) == 1
    row = engine.scan_matrix[0]
    assert row["url"] == script_url
    assert row["status"] == "error"
    assert "TimeoutError" in row["note"]


def test_unrelated_check_does_not_record_script_rows():
    engine = _make_engine()
    page = types.SimpleNamespace(
        url="http://test.local/portal",
        external_scripts={"http://test.local/app.js": "console.log('hi');"},
    )
    engine._record_external_script_scan_matrix(page, "sqli", [])
    assert len(engine.scan_matrix) == 0


def test_duplicate_script_recorded_only_once_per_check():
    engine = _make_engine()
    script_url = "http://test.local/shared.js"
    page1 = types.SimpleNamespace(
        url="http://test.local/page1",
        external_scripts={script_url: "const x = 1;"},
    )
    page2 = types.SimpleNamespace(
        url="http://test.local/page2",
        external_scripts={script_url: "const x = 1;"},
    )
    engine._record_external_script_scan_matrix(page1, "secret_leak", [])
    engine._record_external_script_scan_matrix(page2, "secret_leak", [])

    assert len(engine.scan_matrix) == 1
    assert engine.scan_matrix[0]["url"] == script_url


@pytest.mark.asyncio
async def test_fetch_script_subresource_pure_mock():
    engine = _make_engine()
    engine.timeout = 5.0
    engine.proxy = ""
    engine.auth_headers = lambda url: {}
    engine._is_access_allowed_url = lambda u: "inscope" in u
    engine._is_url_excluded = lambda u: "excluded" in u
    engine.httpx_client_kwargs = lambda **kw: {"timeout": kw.get("timeout", 5.0)}

    # Out of scope -> None
    assert await engine._fetch_script_subresource("http://outofscope.local/a.js") is None

    # Excluded -> None
    assert await engine._fetch_script_subresource("http://inscope.local/excluded/a.js") is None
