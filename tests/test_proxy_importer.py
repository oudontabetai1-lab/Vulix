import json

import pytest

from wscan import url_scope
from wscan.proxy_importer import MAX_IMPORT_BYTES, parse_burp_xml, parse_zap_json


def test_zap_har_seed_scope_and_secrets():
    seed = parse_zap_json({"log": {"entries": [
        {"request": {"url": "https://example.test/api/users?token=private", "method": "POST",
                      "headers": [{"name": "X-Version", "value": "v1"}, {"name": "Authorization", "value": "private"}],
                      "postData": {"mimeType": "application/json", "text": '{"name":"demo","password":"private"}'}}},
        {"request": {"url": "https://outside.test/private", "method": "GET"}},
    ]}}, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/users?token=%3Credacted%3E"]
    assert seed.headers == {"X-Version": "v1", "Authorization": "<redacted>"}
    assert seed.requests[0].method == "POST"
    assert seed.requests[0].json_body == {"name": "demo"}
    assert seed.rejected_scope_count == 1
    assert "private" not in repr(seed) + repr(seed.requests)


def test_burp_save_items_xml_parses_json_template_without_auth():
    request = "POST /api/items HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nCookie: private\r\nX-Session-Token: session-sample-001\r\nX-Version: v2\r\n\r\n" + json.dumps({"title": "demo", "sessionToken": "private"})
    data = ("<items><item><host>example.test</host><protocol>https</protocol><request><![CDATA[" + request + "]]></request></item></items>").encode()
    seed = parse_burp_xml(data, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/items"]
    assert seed.requests[0].json_body == {"title": "demo"}
    assert seed.headers == {
        "Content-Type": "application/json",
        "Cookie": "<redacted>",
        "X-Session-Token": "<redacted>",
        "X-Version": "v2",
    }
    assert "private" not in repr(seed)


@pytest.mark.parametrize("payload", [b"<items>", b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><items>&e;</items>"])
def test_burp_rejects_broken_and_xxe(payload):
    with pytest.raises(ValueError):
        parse_burp_xml(payload, target_urls=["https://example.test/"])


def test_burp_rejects_oversized_input():
    with pytest.raises(ValueError, match="サイズ上限"):
        parse_burp_xml(b" " * (MAX_IMPORT_BYTES + 1), target_urls=["https://example.test/"])


@pytest.mark.parametrize("encoding", ["utf-16", "utf-16le"])
def test_burp_rejects_utf16_dtd_with_bom_and_encoding_declaration(encoding):
    xml = ('<?xml version="1.0" encoding="UTF-16"?>'
           '<!DOCTYPE items [<!ENTITY h "example.test">]>'
           '<items><item><host>&h;</host><protocol>https</protocol>'
           '<request><![CDATA[GET / HTTP/1.1&#13;&#10;Host: example.test]]></request>'
           '</item></items>')
    encoded = xml.encode(encoding)
    payload = encoded if encoding == "utf-16" else b"\xff\xfe" + encoded
    with pytest.raises(ValueError, match="解析できません"):
        parse_burp_xml(payload, target_urls=["https://example.test/"])


def test_zap_sensitive_header_aliases_and_registered_credentials_are_redacted():
    url_scope.clear_secret_values()
    url_scope.register_secret_values([("configured_header", "config-sample-005")])
    try:
        seed = parse_zap_json({"requests": [{
            "url": "https://example.test/api",
            "headers": [
                {"name": "X-Session-Token", "value": "session-sample-001"},
                {"name": "X-Auth-Token", "value": "auth-sample-002"},
                {"name": "X-CSRF-Token", "value": "csrf-sample-003"},
                {"name": "X-Company-Session", "value": "company-session-sample-004"},
                {"name": "X-Trace", "value": "config-sample-005"},
            ],
        }]}, target_urls=["https://example.test/"])
    finally:
        url_scope.clear_secret_values()
    assert seed.headers == {
        "X-Session-Token": "<redacted>",
        "X-Auth-Token": "<redacted>",
        "X-CSRF-Token": "<redacted>",
        "X-Company-Session": "<redacted>",
        "X-Trace": "[REDACTED:configured_header]",
    }
    assert "sample-" not in repr(seed)


def test_zap_bad_port_drops_only_invalid_item_and_records_reason():
    seed = parse_zap_json({"requests": [
        {"url": "https://example.test:bad/api"},
        {"url": "https://example.test/api/ok"},
    ]}, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/ok"]
    assert seed.rejected_scope_reasons == {"invalid_url": 1}


def test_zap_deep_json_body_drops_only_invalid_item():
    nested_json = '{"x":' * 1500 + '0' + '}' * 1500
    seed = parse_zap_json({"log": {"entries": [
        {"request": {"url": "https://example.test/api/deep", "method": "POST",
                      "postData": {"mimeType": "application/json", "text": nested_json}}},
        {"request": {"url": "https://example.test/api/ok", "method": "GET"}},
    ]}}, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/ok"]
    assert seed.rejected_scope_reasons == {"json_depth_exceeded": 1}


def test_zap_requires_scope():
    with pytest.raises(ValueError, match="明示的"):
        parse_zap_json({"requests": []}, target_urls=[])


def test_zap_report_instances_become_url_seeds():
    seed = parse_zap_json({"site": [{"alerts": [{"instances": [
        {"uri": "https://example.test/api/health", "method": "GET"}
    ]}]}]}, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/health"]
