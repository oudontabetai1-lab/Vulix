"""ZAP JSON/HAR と Burp Save items XML の安全な seed parser。

純粋な dict/bytes 解析を中心とし、入力 URL は明示された scope に照合する。
ネットワーク送信やリクエスト再生は行わない。
"""
from __future__ import annotations

import base64
import json
import re
import xml.etree.ElementTree as ET
from collections import Counter
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from .api_spec_importer import ApiSeedData, RequestTemplate
from .runtime_scope_guard import ScopePolicy, evaluate_scope

MAX_IMPORT_BYTES = 10 * 1024 * 1024
MAX_ITEMS = 20_000
_SECRET_KEY = re.compile(r"(?:authorization|cookie|token|secret|password|passwd|session|api[-_]?key|credential)", re.I)
_SECRET_HEADERS = frozenset({"authorization", "proxy-authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "x-access-token"})


def _safe_url(url: str) -> str:
    """URL userinfo と認証らしい query 値を落とす。"""
    p = urlsplit(url.strip())
    if p.scheme.lower() not in {"http", "https"} or not p.hostname:
        return ""
    host = p.hostname
    if p.port:
        host += f":{p.port}"
    query = [(k, "<redacted>" if _SECRET_KEY.search(k) else v) for k, v in parse_qsl(p.query, keep_blank_values=True)]
    return urlunsplit((p.scheme.lower(), host, p.path or "/", urlencode(query), ""))


def _safe_headers(headers: Any) -> dict[str, str]:
    out: dict[str, str] = {}
    if isinstance(headers, dict):
        headers = [{"name": k, "value": v} for k, v in headers.items()]
    for h in headers if isinstance(headers, list) else []:
        if not isinstance(h, dict):
            continue
        name = str(h.get("name", h.get("key", ""))).strip()
        value = str(h.get("value", ""))
        if name and name.lower() not in _SECRET_HEADERS and name.lower() not in {"host", "content-length"}:
            out[name] = value
    return out


def _safe_body(value: Any) -> Any:
    if isinstance(value, dict):
        return {k: _safe_body(v) for k, v in value.items() if not _SECRET_KEY.search(str(k))}
    if isinstance(value, list):
        return [_safe_body(v) for v in value]
    return value


def _make_seed(items: list[dict], target_urls: list[str], access_urls: list[str], exclude_urls: list[str]) -> ApiSeedData:
    seed = ApiSeedData()
    policy = ScopePolicy(target_urls=tuple(target_urls), access_urls=tuple(access_urls), exclude_urls=tuple(exclude_urls))
    if not policy.is_configured:
        raise ValueError("明示的な target_urls または access_urls が必要です")
    seen: set[str] = set()
    rejected: Counter[str] = Counter()
    for item in items[:MAX_ITEMS]:
        url = _safe_url(str(item.get("url", "")))
        if not url:
            rejected["invalid_url"] += 1
            continue
        decision = evaluate_scope(url, policy)
        if not decision.allowed:
            rejected[decision.reason] += 1
            continue
        if url not in seen:
            seen.add(url)
            seed.urls.append(url)
        headers = _safe_headers(item.get("headers", []))
        seed.headers.update(headers)
        method = str(item.get("method", "GET")).upper()
        body = item.get("body")
        if method in {"POST", "PUT", "PATCH", "DELETE"} and isinstance(body, dict):
            seed.requests.append(RequestTemplate(method=method, url=url, headers=headers, json_body=_safe_body(body)))
    seed.rejected_scope_count = sum(rejected.values())
    seed.rejected_scope_reasons = dict(rejected)
    return seed


def parse_zap_json(data: dict, *, target_urls: list[str], access_urls: list[str] | None = None, exclude_urls: list[str] | None = None) -> ApiSeedData:
    """ZAP の alerts/sites または HAR log.entries を共通 seed に変換する。"""
    if not isinstance(data, dict):
        raise ValueError("ZAP JSON のルートは object である必要があります")
    try:
        if len(json.dumps(data, ensure_ascii=False).encode("utf-8")) > MAX_IMPORT_BYTES:
            raise ValueError("ZAP JSON がサイズ上限を超えています")
    except (TypeError, ValueError) as exc:
        if isinstance(exc, ValueError) and "サイズ上限" in str(exc):
            raise
        raise ValueError("ZAP JSON に未対応の値が含まれています") from exc
    entries = data.get("log", {}).get("entries", []) if isinstance(data.get("log"), dict) else []
    if not entries:
        entries = data.get("requests", data.get("site", data.get("sites", [])))
    # ZAP の標準 JSON report は site → alerts → instances の URI を持つ。
    if isinstance(entries, list) and entries and all(isinstance(s, dict) and "alerts" in s for s in entries):
        extracted = []
        for site in entries:
            for alert in site.get("alerts", []) if isinstance(site.get("alerts", []), list) else []:
                for instance in alert.get("instances", []) if isinstance(alert, dict) and isinstance(alert.get("instances", []), list) else []:
                    if isinstance(instance, dict) and instance.get("uri"):
                        extracted.append({"url": instance["uri"], "method": instance.get("method", "GET")})
        entries = extracted
    if not isinstance(entries, list) or len(entries) > MAX_ITEMS:
        raise ValueError("ZAP JSON の item 数が上限を超えています")
    items = []
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        req = entry.get("request", entry)
        if not isinstance(req, dict):
            continue
        url = req.get("url", req.get("uri", ""))
        method = req.get("method", "GET")
        body = req.get("json_body")
        if body is None and isinstance(req.get("postData"), dict):
            pd = req["postData"]
            text = pd.get("text", "")
            if "json" in str(pd.get("mimeType", "")).lower() and isinstance(text, str):
                try:
                    parsed = json.loads(text)
                    body = parsed if isinstance(parsed, dict) else None
                except json.JSONDecodeError:
                    pass
        items.append({"url": url, "method": method, "headers": req.get("headers", []), "body": body})
    return _make_seed(items, target_urls, access_urls or [], exclude_urls or [])


def parse_burp_xml(data: bytes | str, *, target_urls: list[str], access_urls: list[str] | None = None, exclude_urls: list[str] | None = None) -> ApiSeedData:
    """Burp の XML Save items を安全に読み込む。DTD/entity 宣言は拒否する。"""
    raw = data.encode() if isinstance(data, str) else data
    if len(raw) > MAX_IMPORT_BYTES:
        raise ValueError("Burp XML がサイズ上限を超えています")
    if re.search(br"<!\s*(?:DOCTYPE|ENTITY)", raw, re.I):
        raise ValueError("DTD/entity 宣言を含む XML は受け付けません")
    try:
        root = ET.fromstring(raw)
    except (ET.ParseError, ValueError) as exc:
        raise ValueError("Burp XML を解析できません") from exc
    items = []
    for node in root.findall(".//item")[:MAX_ITEMS]:
        req = node.findtext("request", "")
        if node.find("request").get("base64", "false").lower() == "true" if node.find("request") is not None else False:
            try:
                req = base64.b64decode(req, validate=True).decode("latin-1")
            except (ValueError, UnicodeDecodeError):
                continue
        lines = req.splitlines()
        if not lines:
            continue
        match = re.match(r"([A-Z]+)\s+(\S+)\s+HTTP/", lines[0])
        if not match:
            continue
        headers = []
        for line in lines[1:]:
            if not line:
                break
            if ":" in line:
                key, value = line.split(":", 1)
                headers.append({"name": key.strip(), "value": value.strip()})
        host = node.findtext("host", "")
        protocol = node.findtext("protocol", "https")
        url = match.group(2)
        if url.startswith("/") and host:
            url = f"{protocol}://{host}{url}"
        elif not url.startswith(("http://", "https://")) and host:
            url = f"{protocol}://{host}/{url}"
        body_parts = re.split(r"\r?\n\r?\n", req, maxsplit=1)
        body_text = body_parts[1] if len(body_parts) == 2 else ""
        body = None
        if body_text and any("json" in h["value"].lower() for h in headers if h["name"].lower() == "content-type"):
            try:
                parsed = json.loads(body_text)
                body = parsed if isinstance(parsed, dict) else None
            except json.JSONDecodeError:
                pass
        items.append({"url": url, "method": match.group(1), "headers": headers, "body": body})
    return _make_seed(items, target_urls, access_urls or [], exclude_urls or [])


def load_proxy_export(path: str, *, target_urls: list[str], access_urls: list[str] | None = None, exclude_urls: list[str] | None = None) -> ApiSeedData:
    """サイズ制限付きファイル入口。XML は Burp、JSON は ZAP/HAR として読む。"""
    from pathlib import Path
    p = Path(path)
    if p.stat().st_size > MAX_IMPORT_BYTES:
        raise ValueError("インポートファイルがサイズ上限を超えています")
    raw = p.read_bytes()
    if p.suffix.lower() == ".xml":
        return parse_burp_xml(raw, target_urls=target_urls, access_urls=access_urls, exclude_urls=exclude_urls)
    try:
        data = json.loads(raw)
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError("ZAP JSON を解析できません") from exc
    return parse_zap_json(data, target_urls=target_urls, access_urls=access_urls, exclude_urls=exclude_urls)
