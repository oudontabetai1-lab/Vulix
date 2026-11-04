"""Unit and API tests for wscan/traffic_reader.py and traffic endpoints in wscan/monitor.py.

Verifies:
1. Sentinel secret non-leak: recogniseable dummy secrets in URL, userinfo, query,
   Authorization/Cookie headers, Set-Cookie, and post_data must NEVER leak into
   any field of projected traffic entries or previews.
2. Accurate parsing of all 8 input-point kinds (query, form, json, xml, multipart,
   cookie, header, graphql) as booleans and counts without secret values.
3. Length-capped and redacted previews (no wholesale raw bodies).
4. Absent and unreadable log handling: explicit available=False with reason, never
   fake empty success.
5. Pagination and bounds: safe offset/limit clamping and truncated indicator.
6. API tests on MonitorServer (/api/v1/scan/traffic and /api/v1/scans/{id}/traffic).
"""
from __future__ import annotations

import json
from pathlib import Path
import tempfile
import pytest
from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer
from wscan.traffic_reader import (
    MAX_PREVIEW_LENGTH,
    SCHEMA_VERSION,
    parse_input_points,
    parse_traffic_records,
    project_traffic_entry,
    read_traffic_log,
)

# Recognisable sentinel dummy secrets to prove strict non-leak
SENTINEL_USERINFO = "SENTINEL_USERINFO_SECRET_98765"
SENTINEL_QUERY_TOKEN = "SENTINEL_QUERY_TOKEN_54321"
SENTINEL_QUERY_PASSWORD = "SENTINEL_QUERY_PASSWORD_11111"
SENTINEL_AUTH_BEARER = "SENTINEL_AUTH_BEARER_88888"
SENTINEL_COOKIE_VAL = "SENTINEL_COOKIE_SECRET_77777"
SENTINEL_SETCOOKIE_VAL = "SENTINEL_SETCOOKIE_SECRET_66666"
SENTINEL_API_KEY = "SENTINEL_API_KEY_55555"
SENTINEL_POST_PASSWORD = "SENTINEL_POST_PASSWORD_44444"
SENTINEL_JSON_TOKEN = "SENTINEL_JSON_TOKEN_33333"

ALL_SENTINELS = [
    SENTINEL_USERINFO,
    SENTINEL_QUERY_TOKEN,
    SENTINEL_QUERY_PASSWORD,
    SENTINEL_AUTH_BEARER,
    SENTINEL_COOKIE_VAL,
    SENTINEL_SETCOOKIE_VAL,
    SENTINEL_API_KEY,
    SENTINEL_POST_PASSWORD,
    SENTINEL_JSON_TOKEN,
]


def _assert_no_sentinels_in_object(obj: Any) -> None:
    """Recursively verify no sentinel secret exists in any string within obj."""
    serialized = json.dumps(obj)
    for sentinel in ALL_SENTINELS:
        assert sentinel not in serialized, f"Sentinel secret '{sentinel}' leaked in object: {serialized}"


def test_sentinel_dummy_secrets_strict_non_leak():
    """Sentinel dummy secrets in URL, headers, and body must NEVER leak in projected entries."""
    raw_record = {
        "id": "req_secret_test",
        "method": "POST",
        "url": f"https://user:{SENTINEL_USERINFO}@example.com/api/login?token={SENTINEL_QUERY_TOKEN}&password={SENTINEL_QUERY_PASSWORD}&safe_param=hello",
        "request_headers": {
            "Authorization": f"Bearer {SENTINEL_AUTH_BEARER}",
            "Cookie": f"session_id={SENTINEL_COOKIE_VAL}; other=ok",
            "X-Api-Key": SENTINEL_API_KEY,
            "Content-Type": "application/x-www-form-urlencoded",
        },
        "response_headers": {
            "Set-Cookie": f"auth_token={SENTINEL_SETCOOKIE_VAL}; Path=/; HttpOnly",
            "Content-Type": "text/html",
        },
        "post_data": f"username=admin&password={SENTINEL_POST_PASSWORD}&client_token={SENTINEL_JSON_TOKEN}",
        "status": 200,
        "ts": 1700000000.0,
    }

    entry = project_traffic_entry(raw_record, index=0)

    # 1. Check all sentinel values are absent from the entire projected entry
    _assert_no_sentinels_in_object(entry)

    # 2. Check explicit redaction indicators exist
    assert "<redacted>" in entry["url"]
    assert "safe_param=hello" in entry["url"]
    assert entry["request_headers"]["Authorization"] == "<redacted>"
    assert entry["request_headers"]["Cookie"] == "<redacted>"
    assert entry["request_headers"]["X-Api-Key"] == "<redacted>"
    assert entry["response_headers"]["Set-Cookie"] == "<redacted>"
    assert "password=<redacted>" in entry["post_data_preview"]


def test_input_point_kinds_parsed_accurately_as_booleans_and_counts():
    """Verify all 8 input-point kinds (query, form, json, xml, multipart, cookie, header, graphql)."""
    # 1. Query input points
    ip_query = parse_input_points("https://example.com/search?q=test&page=2", {}, None)
    assert ip_query["query"]["present"] is True
    assert ip_query["query"]["count"] == 2
    assert ip_query["form"]["present"] is False
    assert ip_query["json"]["present"] is False
    assert ip_query["xml"]["present"] is False

    # 2. Form input points
    ip_form = parse_input_points(
        "https://example.com/login",
        {"Content-Type": "application/x-www-form-urlencoded"},
        "user=alice&pass=secret&remember=1",
    )
    assert ip_form["form"]["present"] is True
    assert ip_form["form"]["count"] == 3
    assert ip_form["query"]["present"] is False

    # 3. JSON input points
    ip_json = parse_input_points(
        "https://example.com/api/items",
        {"Content-Type": "application/json"},
        '{"item_id": 42, "name": "widget", "active": true}',
    )
    assert ip_json["json"]["present"] is True
    assert ip_json["json"]["count"] == 3

    # 4. XML input points
    ip_xml = parse_input_points(
        "https://example.com/soap",
        {"Content-Type": "text/xml"},
        '<?xml version="1.0"?><Envelope><Body><GetData id="1"/></Body></Envelope>',
    )
    assert ip_xml["xml"]["present"] is True
    assert ip_xml["xml"]["count"] >= 1

    # 5. Multipart input points
    ip_multipart = parse_input_points(
        "https://example.com/upload",
        {"Content-Type": "multipart/form-data; boundary=----WebKitFormBoundary"},
        '------WebKitFormBoundary\r\nContent-Disposition: form-data; name="file"; filename="doc.txt"\r\n\r\nhello\r\n------WebKitFormBoundary\r\nContent-Disposition: form-data; name="title"\r\n\r\nDoc\r\n',
    )
    assert ip_multipart["multipart"]["present"] is True
    assert ip_multipart["multipart"]["count"] == 2

    # 6. Cookie input points
    ip_cookie = parse_input_points("https://example.com/", {"Cookie": "sess=abc; theme=dark; lang=ja"}, None)
    assert ip_cookie["cookie"]["present"] is True
    assert ip_cookie["cookie"]["count"] == 3

    # 7. Header input points
    ip_header = parse_input_points("https://example.com/", {"User-Agent": "Vulix", "X-Custom": "test"}, None)
    assert ip_header["header"]["present"] is True
    assert ip_header["header"]["count"] == 2

    # 8. GraphQL input points (via path, query param, or JSON body)
    ip_gql_path = parse_input_points("https://example.com/graphql", {}, None)
    assert ip_gql_path["graphql"]["present"] is True

    ip_gql_json = parse_input_points(
        "https://example.com/api",
        {"Content-Type": "application/json"},
        '{"query": "{ users { id name } }"}',
    )
    assert ip_gql_json["graphql"]["present"] is True
    assert ip_gql_json["json"]["present"] is True


def test_body_preview_length_capped_and_no_raw_body_wholesale():
    """Verify previews are length-capped and large raw bodies are not returned wholesale."""
    huge_body = "x" * 10000
    record = {
        "method": "POST",
        "url": "https://example.com/submit",
        "post_data": huge_body,
        "response_body": huge_body,
    }

    entry = project_traffic_entry(record, index=0)
    assert "post_data" not in entry  # wholesale raw body NOT returned
    assert "response_body" not in entry

    assert entry["post_data_preview"] is not None
    assert len(entry["post_data_preview"]) <= MAX_PREVIEW_LENGTH + 20
    assert "...<truncated>" in entry["post_data_preview"]

    assert entry["response_preview"] is not None
    assert len(entry["response_preview"]) <= MAX_PREVIEW_LENGTH + 20
    assert "...<truncated>" in entry["response_preview"]


def test_read_traffic_log_absent_and_unreadable(tmp_path: Path):
    """Absent or unreadable logs return available=False with honest reason, never fake empty success."""
    # 1. Nonexistent directory
    res_nonexistent = read_traffic_log(tmp_path / "missing_scan")
    assert res_nonexistent["available"] is False
    assert res_nonexistent["entries"] == []
    assert res_nonexistent["reason"] is not None
    assert "見つかりません" in res_nonexistent["reason"]

    # 2. Existing scan folder but missing http_requests.jsonl
    scan_dir = tmp_path / "scan_no_log"
    scan_dir.mkdir()
    res_missing_file = read_traffic_log(scan_dir)
    assert res_missing_file["available"] is False
    assert res_missing_file["entries"] == []
    assert res_missing_file["reason"] is not None
    assert "http_requests.jsonl" in res_missing_file["reason"]

    # 3. Valid empty log
    empty_scan_dir = tmp_path / "scan_empty_log"
    empty_scan_dir.mkdir()
    (empty_scan_dir / "http_requests.jsonl").write_text("", encoding="utf-8")
    res_empty = read_traffic_log(empty_scan_dir)
    assert res_empty["available"] is True
    assert res_empty["entries"] == []
    assert res_empty["total"] == 0
    assert res_empty["reason"] is None


def test_pagination_and_bounding(tmp_path: Path):
    """Pagination cleanly slices entries and sets truncated=True when remaining exist."""
    scan_dir = tmp_path / "scan_paginated"
    scan_dir.mkdir()
    log_path = scan_dir / "http_requests.jsonl"

    lines = []
    for i in range(25):
        lines.append(json.dumps({
            "method": "GET" if i % 2 == 0 else "POST",
            "url": f"https://example.com/items/{i}",
            "status": 200,
            "ts": 1700000000 + i,
        }))
    log_path.write_text("\n".join(lines), encoding="utf-8")

    # Page 1 (limit 10, offset 0)
    page1 = read_traffic_log(scan_dir, offset=0, limit=10)
    assert page1["available"] is True
    assert page1["total"] == 25
    assert len(page1["entries"]) == 10
    assert page1["truncated"] is True
    assert page1["entries"][0]["url"] == "https://example.com/items/0"
    assert page1["entries"][9]["url"] == "https://example.com/items/9"
    assert page1["counts"]["total"] == 25
    assert page1["counts"]["methods"]["GET"] == 13
    assert page1["counts"]["methods"]["POST"] == 12

    # Page 2 (limit 10, offset 10)
    page2 = read_traffic_log(scan_dir, offset=10, limit=10)
    assert len(page2["entries"]) == 10
    assert page2["truncated"] is True
    assert page2["entries"][0]["url"] == "https://example.com/items/10"

    # Page 3 (limit 10, offset 20)
    page3 = read_traffic_log(scan_dir, offset=20, limit=10)
    assert len(page3["entries"]) == 5
    assert page3["truncated"] is False
    assert page3["entries"][-1]["url"] == "https://example.com/items/24"


def test_monitor_traffic_api_endpoints(tmp_path: Path):
    """Verify /api/v1/scan/traffic and /api/v1/scans/{scan_id}/traffic on MonitorServer."""
    scan_id = "test_traffic_scan_01"
    scan_dir = tmp_path / scan_id
    scan_dir.mkdir()

    # Seed an audit log with dummy secret
    log_file = scan_dir / "http_requests.jsonl"
    log_entries = [
        {
            "method": "GET",
            "url": f"https://example.com/users?token={SENTINEL_QUERY_TOKEN}",
            "request_headers": {"Authorization": f"Bearer {SENTINEL_AUTH_BEARER}"},
            "status": 200,
            "ts": 1700000001.0,
        },
        {
            "method": "POST",
            "url": "https://example.com/login",
            "request_headers": {"Content-Type": "application/x-www-form-urlencoded"},
            "post_data": f"user=test&password={SENTINEL_POST_PASSWORD}",
            "status": 302,
            "ts": 1700000002.0,
        },
    ]
    log_file.write_text("\n".join(json.dumps(e) for e in log_entries), encoding="utf-8")

    server = MonitorServer(output_dir=scan_dir)
    client = TestClient(server.app)

    # 1. GET /api/v1/scan/traffic (active scan)
    resp = client.get("/api/v1/scan/traffic")
    assert resp.status_code == 200
    data = resp.json()
    assert data["schema_version"] == SCHEMA_VERSION
    assert data["available"] is True
    assert data["total"] == 2
    assert len(data["entries"]) == 2
    _assert_no_sentinels_in_object(data)

    # 2. GET /api/v1/scans/{scan_id}/traffic (specific scan ID via output_dir lookup)
    resp2 = client.get(f"/api/v1/scans/{scan_id}/traffic")
    assert resp2.status_code == 200
    data2 = resp2.json()
    assert data2["available"] is True
    assert data2["total"] == 2
    _assert_no_sentinels_in_object(data2)

    # 3. Missing scan ID returns 404 with available=False and reason
    resp_missing = client.get("/api/v1/scans/nonexistent_scan_id/traffic")
    assert resp_missing.status_code == 404
    data_missing = resp_missing.json()
    assert data_missing["available"] is False
    assert "見つかりません" in data_missing["reason"]
