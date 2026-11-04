"""Read-only HTTP traffic reader and projection for Vulix audit logs.

Provides pure-function parsing, redaction, projection, and pagination over the
audit log (http_requests.jsonl) recorded by wscan/request_logger.py.

INVARIANTS:
- Pure functions only: no capture engine, proxy, MITM, replay, or mutation.
- Strict redaction: credentials, Authorization/Cookie/Set-Cookie header values,
  URL userinfo, and query/body secret values are always masked.
- Input-point kinds are parsed and exposed as booleans and counts only — never raw secrets.
- Wholesale raw bodies are never returned; previews are strictly length-capped and redacted.
- Honest status: absent or unreadable logs return available=False with an explicit reason,
  never a fake empty success.
"""
from __future__ import annotations

import datetime
import json
import logging
import os
from pathlib import Path
import re
from typing import Any, Iterable, Mapping, Optional
import urllib.parse

from wscan import url_scope
from wscan.request_logger import is_sensitive_header

logger = logging.getLogger(__name__)

SCHEMA_VERSION: str = "1.0.0"
MAX_PREVIEW_LENGTH: int = 256
DEFAULT_PAGE_LIMIT: int = 100
MAX_PAGE_LIMIT: int = 500

_RE_GRAPHQL_PATH = re.compile(r"(?i)/graphql(?:[/?#]|$)")
_RE_XML_START = re.compile(r"^\s*<(?:\?xml|[A-Za-z_][\w:.-]*)")
_RE_MULTIPART_FIELD = re.compile(r'(?i)\bname="([^"]+)"')


def _mask_sensitive_headers(headers: Any) -> dict[str, str]:
    """Return headers dict with sensitive header values masked.

    Values of Authorization, Cookie, Set-Cookie, API keys, etc. are replaced
    with <redacted>. Other header values are scanned for embedded credentials.
    """
    if not isinstance(headers, Mapping):
        return {}

    sanitized: dict[str, str] = {}
    for k, v in headers.items():
        key_str = str(k).strip()
        val_str = str(v) if v is not None else ""
        if is_sensitive_header(key_str):
            sanitized[key_str] = url_scope.REDACTED
        else:
            sanitized[key_str] = url_scope.redact_kv_values(val_str)
    return sanitized


def _detect_query_input_points(url: str) -> tuple[bool, int]:
    """Detect query parameter input points from URL."""
    if not url or not isinstance(url, str):
        return (False, 0)
    try:
        parts = urllib.parse.urlsplit(url)
        if not parts.query:
            return (False, 0)
        qsl = urllib.parse.parse_qsl(parts.query, keep_blank_values=True)
        return (len(qsl) > 0, len(qsl))
    except Exception:
        return (False, 0)


def _detect_cookie_input_points(headers: Mapping[str, Any]) -> tuple[bool, int]:
    """Detect cookie input points from request headers."""
    if not isinstance(headers, Mapping):
        return (False, 0)
    for k, v in headers.items():
        if str(k).lower() == "cookie" and v:
            parts = [c.strip() for c in str(v).split(";") if c.strip()]
            return (len(parts) > 0, len(parts))
    return (False, 0)


def _detect_header_input_points(headers: Mapping[str, Any]) -> tuple[bool, int]:
    """Detect custom or standard injectable HTTP header input points."""
    if not isinstance(headers, Mapping) or not headers:
        return (False, 0)
    return (len(headers) > 0, len(headers))


def _detect_body_input_points(
    headers: Mapping[str, Any],
    post_data: Any,
    url: str = "",
) -> dict[str, tuple[bool, int]]:
    """Detect form, json, xml, multipart, and graphql input points from request body and headers."""
    results: dict[str, tuple[bool, int]] = {
        "form": (False, 0),
        "json": (False, 0),
        "xml": (False, 0),
        "multipart": (False, 0),
        "graphql": (False, 0),
    }

    content_type = ""
    for k, v in (headers.items() if isinstance(headers, Mapping) else ()):
        if str(k).lower() == "content-type" and v:
            content_type = str(v).lower()
            break

    # 1. GraphQL check (can be GET query param or POST JSON/body)
    is_graphql = bool(_RE_GRAPHQL_PATH.search(url))
    gql_count = 1 if is_graphql else 0

    if not is_graphql and url and ("query=" in url or "mutation=" in url):
        try:
            parts = urllib.parse.urlsplit(url)
            q_dict = dict(urllib.parse.parse_qsl(parts.query, keep_blank_values=True))
            if "query" in q_dict or "mutation" in q_dict:
                is_graphql = True
                gql_count = 1
        except Exception:
            pass

    body_str = ""
    if isinstance(post_data, str):
        body_str = post_data
    elif isinstance(post_data, bytes):
        try:
            body_str = post_data.decode("utf-8", errors="replace")
        except Exception:
            body_str = ""
    elif isinstance(post_data, (dict, list)):
        try:
            body_str = json.dumps(post_data)
        except Exception:
            body_str = ""

    stripped_body = body_str.strip()

    # 2. JSON detection
    is_json_ct = "application/json" in content_type or "+json" in content_type
    if is_json_ct or stripped_body.startswith(("{", "[")):
        try:
            parsed_json = json.loads(stripped_body) if stripped_body else None
            if isinstance(parsed_json, dict):
                count = len(parsed_json)
                results["json"] = (True, count)
                if "query" in parsed_json or "mutation" in parsed_json:
                    is_graphql = True
                    gql_count = max(gql_count, 1)
            elif isinstance(parsed_json, list):
                results["json"] = (True, len(parsed_json))
        except Exception:
            if is_json_ct:
                results["json"] = (True, 1)

    # 3. Form / urlencoded detection
    is_form_ct = "application/x-www-form-urlencoded" in content_type
    if is_form_ct or (not results["json"][0] and stripped_body and "=" in stripped_body and not stripped_body.startswith("<")):
        try:
            qsl = urllib.parse.parse_qsl(stripped_body, keep_blank_values=True)
            if qsl:
                results["form"] = (True, len(qsl))
            elif is_form_ct:
                results["form"] = (True, 1)
        except Exception:
            if is_form_ct:
                results["form"] = (True, 1)

    # 4. XML detection
    is_xml_ct = "text/xml" in content_type or "application/xml" in content_type or "+xml" in content_type
    if is_xml_ct or bool(_RE_XML_START.search(stripped_body)):
        tag_count = len(re.findall(r"<[A-Za-z_][\w:.-]*", stripped_body))
        results["xml"] = (True, max(1, tag_count))

    # 5. Multipart detection
    if "multipart/form-data" in content_type or "multipart/" in content_type:
        fields = _RE_MULTIPART_FIELD.findall(stripped_body)
        count = len(fields) if fields else 1
        results["multipart"] = (True, count)

    # Finalize GraphQL
    if "application/graphql" in content_type:
        is_graphql = True
        gql_count = max(gql_count, 1)

    results["graphql"] = (is_graphql, gql_count)
    return results


def parse_input_points(
    url: str,
    headers: Mapping[str, Any],
    post_data: Any,
) -> dict[str, dict[str, Any]]:
    """Parse all 8 input-point kinds (query, form, json, xml, multipart, cookie, header, graphql).

    Returns a dictionary mapping each kind to {'present': bool, 'count': int}.
    No secret values are included.
    """
    has_query, query_count = _detect_query_input_points(url)
    has_cookie, cookie_count = _detect_cookie_input_points(headers)
    has_header, header_count = _detect_header_input_points(headers)
    body_res = _detect_body_input_points(headers, post_data, url=url)

    return {
        "query": {"present": has_query, "count": query_count},
        "form": {"present": body_res["form"][0], "count": body_res["form"][1]},
        "json": {"present": body_res["json"][0], "count": body_res["json"][1]},
        "xml": {"present": body_res["xml"][0], "count": body_res["xml"][1]},
        "multipart": {"present": body_res["multipart"][0], "count": body_res["multipart"][1]},
        "cookie": {"present": has_cookie, "count": cookie_count},
        "header": {"present": has_header, "count": header_count},
        "graphql": {"present": body_res["graphql"][0], "count": body_res["graphql"][1]},
    }


def _make_preview(text: Any, max_len: int = MAX_PREVIEW_LENGTH) -> Optional[str]:
    """Create a length-capped, strictly redacted preview of body content."""
    if text is None:
        return None
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8", errors="replace")
        except Exception:
            return None
    raw = str(text)
    if not raw.strip():
        return ""
    # Redact sensitive key-values and embedded user credentials
    redacted = url_scope.redact_kv_values(raw)
    redacted = re.sub(r"\b(https?://)[^\s/?#@]+(?::[^\s/?#@]*)?@", r"\1<redacted>@", redacted)
    redacted = re.sub(r"\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*", r"\1<redacted>", redacted, flags=re.IGNORECASE)
    redacted = re.sub(r"\b(Basic\s+)[A-Za-z0-9+/=]+", r"\1<redacted>", redacted, flags=re.IGNORECASE)

    if len(redacted) > max_len:
        return redacted[:max_len] + "...<truncated>"
    return redacted


def project_traffic_entry(raw_record: dict[str, Any], index: int = 0) -> dict[str, Any]:
    """Project a raw JSONL log record into a safe, bounded, redacted traffic entry.

    Pure function: no external dependencies or I/O.
    """
    raw_url = str(raw_record.get("url") or "")
    redacted_url = url_scope.redact_url(raw_url)

    method = str(raw_record.get("method") or "GET").upper()

    status_raw = raw_record.get("status")
    try:
        status: Optional[int] = int(status_raw) if status_raw is not None else None
    except (ValueError, TypeError):
        status = None

    ts_raw = raw_record.get("ts") or raw_record.get("timestamp") or 0.0
    try:
        ts = float(ts_raw)
    except (ValueError, TypeError):
        ts = 0.0

    iso_str = ""
    time_str = ""
    if ts > 0:
        try:
            dt = datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc)
            iso_str = dt.isoformat()
            time_str = dt.strftime("%H:%M:%S")
        except Exception:
            pass

    source = str(
        raw_record.get("source")
        or raw_record.get("actor")
        or raw_record.get("origin")
        or raw_record.get("transport")
        or "browser"
    ).lower()

    req_headers = _mask_sensitive_headers(raw_record.get("request_headers") or raw_record.get("headers") or {})
    resp_headers = _mask_sensitive_headers(raw_record.get("response_headers") or {})

    req_ct = ""
    for k, v in req_headers.items():
        if k.lower() == "content-type":
            req_ct = v
            break

    resp_ct = ""
    for k, v in resp_headers.items():
        if k.lower() == "content-type":
            resp_ct = v
            break

    raw_post = raw_record.get("post_data")
    if raw_post is None and "request" in raw_record and isinstance(raw_record["request"], dict):
        raw_post = raw_record["request"].get("post_data")

    post_preview = _make_preview(raw_post)
    raw_resp_body = raw_record.get("response_body") or raw_record.get("body")
    resp_preview = _make_preview(raw_resp_body)

    # Compute sizes safely
    req_size = 0
    if "content-length" in {k.lower(): v for k, v in req_headers.items()}:
        try:
            cl = int(next(v for k, v in req_headers.items() if k.lower() == "content-length"))
            req_size = max(0, cl)
        except Exception:
            pass
    if req_size == 0 and raw_post:
        req_size = len(str(raw_post).encode("utf-8", errors="replace"))

    resp_size = None
    if "content-length" in {k.lower(): v for k, v in resp_headers.items()}:
        try:
            cl = int(next(v for k, v in resp_headers.items() if k.lower() == "content-length"))
            resp_size = max(0, cl)
        except Exception:
            pass
    if resp_size is None and raw_resp_body is not None:
        resp_size = len(str(raw_resp_body).encode("utf-8", errors="replace"))

    input_points = parse_input_points(redacted_url, req_headers, raw_post)
    input_point_kinds = {k: v["present"] for k, v in input_points.items()}
    input_point_counts = {k: v["count"] for k, v in input_points.items()}

    entry_id = str(raw_record.get("id") or f"traffic_{index}")

    return {
        "id": entry_id,
        "index": index,
        "url": redacted_url,
        "method": method,
        "status": status,
        "timestamp": ts,
        "timestamp_iso": iso_str,
        "time": time_str,
        "source": source,
        "request_content_type": req_ct,
        "request_size": req_size,
        "response_content_type": resp_ct,
        "response_size": resp_size,
        "input_points": input_points,
        "input_point_kinds": input_point_kinds,
        "input_point_counts": input_point_counts,
        "request_headers": req_headers,
        "response_headers": resp_headers,
        "post_data_preview": post_preview,
        "response_preview": resp_preview,
    }


def parse_traffic_records(
    lines_or_records: Iterable[str | dict[str, Any]],
) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    """Parse multiple JSONL lines or record dicts into safe projected entries and summary counts.

    Pure function: returns (projected_entries, summary_counts).
    Corrupt or empty lines are skipped gracefully.
    """
    entries: list[dict[str, Any]] = []
    methods_count: dict[str, int] = {}
    statuses_count: dict[str, int] = {}
    sources_count: dict[str, int] = {}
    ip_counts: dict[str, int] = {
        "query": 0,
        "form": 0,
        "json": 0,
        "xml": 0,
        "multipart": 0,
        "cookie": 0,
        "header": 0,
        "graphql": 0,
    }

    index = 0
    for item in lines_or_records:
        rec: Optional[dict[str, Any]] = None
        if isinstance(item, dict):
            rec = item
        elif isinstance(item, str):
            line = item.strip()
            if not line:
                continue
            try:
                loaded = json.loads(line)
                if isinstance(loaded, dict):
                    rec = loaded
            except Exception:
                continue

        if not rec:
            continue

        entry = project_traffic_entry(rec, index=index)
        entries.append(entry)
        index += 1

        # Aggregate counts
        m = entry["method"]
        methods_count[m] = methods_count.get(m, 0) + 1

        s = str(entry["status"]) if entry["status"] is not None else "unknown"
        statuses_count[s] = statuses_count.get(s, 0) + 1

        src = entry["source"]
        sources_count[src] = sources_count.get(src, 0) + 1

        for kind, val in entry["input_point_kinds"].items():
            if val and kind in ip_counts:
                ip_counts[kind] += 1

    counts = {
        "total": len(entries),
        "methods": methods_count,
        "statuses": statuses_count,
        "sources": sources_count,
        "input_points": ip_counts,
    }

    return entries, counts


def read_traffic_log(
    scan_dir: Path | str,
    *,
    scan_id: str = "",
    offset: int = 0,
    limit: int = DEFAULT_PAGE_LIMIT,
) -> dict[str, Any]:
    """Read and project traffic from a scan's http_requests.jsonl audit log.

    Handles absent and unreadable logs with explicit available=False reason.
    Limits and offsets provide bounded page sizes for 10k+ log lines.
    """
    path = Path(scan_dir)
    target_scan_id = scan_id or path.name

    # Clamp bounds safely
    safe_offset = max(0, int(offset))
    safe_limit = max(1, min(MAX_PAGE_LIMIT, int(limit)))

    empty_counts = {
        "total": 0,
        "methods": {},
        "statuses": {},
        "sources": {},
        "input_points": {
            "query": 0, "form": 0, "json": 0, "xml": 0,
            "multipart": 0, "cookie": 0, "header": 0, "graphql": 0,
        },
    }

    if not path.exists():
        return {
            "schema_version": SCHEMA_VERSION,
            "available": False,
            "reason": f"スキャンディレクトリが見つかりません ({path.name})",
            "scan_id": target_scan_id,
            "entries": [],
            "counts": empty_counts,
            "total": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "truncated": False,
        }

    log_file = path / "http_requests.jsonl" if path.is_dir() else path
    if not log_file.is_file():
        return {
            "schema_version": SCHEMA_VERSION,
            "available": False,
            "reason": f"監査ログ (http_requests.jsonl) が存在しません",
            "scan_id": target_scan_id,
            "entries": [],
            "counts": empty_counts,
            "total": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "truncated": False,
        }

    try:
        # Stream read line by line with replace decoding to avoid choking on partial UTF-8
        with open(log_file, "r", encoding="utf-8", errors="replace") as f:
            all_entries, counts = parse_traffic_records(f)
    except Exception as exc:
        logger.warning("Failed to read traffic log %s: %s", log_file, exc)
        return {
            "schema_version": SCHEMA_VERSION,
            "available": False,
            "reason": f"監査ログの読み取りに失敗しました: {exc}",
            "scan_id": target_scan_id,
            "entries": [],
            "counts": empty_counts,
            "total": 0,
            "offset": safe_offset,
            "limit": safe_limit,
            "truncated": False,
        }

    total = len(all_entries)
    paginated = all_entries[safe_offset : safe_offset + safe_limit]
    is_truncated = (safe_offset + len(paginated)) < total

    return {
        "schema_version": SCHEMA_VERSION,
        "available": True,
        "reason": None,
        "scan_id": target_scan_id,
        "entries": paginated,
        "counts": counts,
        "total": total,
        "offset": safe_offset,
        "limit": safe_limit,
        "truncated": is_truncated,
    }
