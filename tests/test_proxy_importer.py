import json

import pytest

from wscan.proxy_importer import MAX_IMPORT_BYTES, parse_burp_xml, parse_zap_json


def test_zap_har_seed_scope_and_secrets():
    seed = parse_zap_json({"log": {"entries": [
        {"request": {"url": "https://example.test/api/users?token=private", "method": "POST",
                      "headers": [{"name": "X-Version", "value": "v1"}, {"name": "Authorization", "value": "private"}],
                      "postData": {"mimeType": "application/json", "text": '{"name":"demo","password":"private"}'}}},
        {"request": {"url": "https://outside.test/private", "method": "GET"}},
    ]}}, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/users?token=%3Credacted%3E"]
    assert seed.headers == {"X-Version": "v1"}
    assert seed.requests[0].method == "POST"
    assert seed.requests[0].json_body == {"name": "demo"}
    assert seed.rejected_scope_count == 1
    assert "private" not in repr(seed) + repr(seed.requests)


def test_burp_save_items_xml_parses_json_template_without_auth():
    request = "POST /api/items HTTP/1.1\r\nHost: example.test\r\nContent-Type: application/json\r\nCookie: private\r\nX-Version: v2\r\n\r\n" + json.dumps({"title": "demo", "sessionToken": "private"})
    data = ("<items><item><host>example.test</host><protocol>https</protocol><request><![CDATA[" + request + "]]></request></item></items>").encode()
    seed = parse_burp_xml(data, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/items"]
    assert seed.requests[0].json_body == {"title": "demo"}
    assert seed.headers == {"Content-Type": "application/json", "X-Version": "v2"}
    assert "private" not in repr(seed)


@pytest.mark.parametrize("payload", [b"<items>", b"<!DOCTYPE x [<!ENTITY e SYSTEM 'file:///etc/passwd'>]><items>&e;</items>"])
def test_burp_rejects_broken_and_xxe(payload):
    with pytest.raises(ValueError):
        parse_burp_xml(payload, target_urls=["https://example.test/"])


def test_burp_rejects_oversized_input():
    with pytest.raises(ValueError, match="サイズ上限"):
        parse_burp_xml(b" " * (MAX_IMPORT_BYTES + 1), target_urls=["https://example.test/"])


def test_zap_requires_scope():
    with pytest.raises(ValueError, match="明示的"):
        parse_zap_json({"requests": []}, target_urls=[])


def test_zap_report_instances_become_url_seeds():
    seed = parse_zap_json({"site": [{"alerts": [{"instances": [
        {"uri": "https://example.test/api/health", "method": "GET"}
    ]}]}]}, target_urls=["https://example.test/"])
    assert seed.urls == ["https://example.test/api/health"]
