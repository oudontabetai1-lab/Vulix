"""Guarded scanner actions exposed to the Agent browser-use controller."""
from __future__ import annotations

import asyncio
import hashlib
import json
import re
import secrets
import subprocess
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from wscan.agent_harness import AgentRole, WorkStatus
from wscan.injection_point import InjectionPoint, parse_pointer
from wscan.runtime_scope_guard import ScopePolicy, evaluate_scope
from wscan.url_normalize import endpoint_identity
from wscan.url_scope import same_origin as url_scope_same_origin


_BODY_SECRET_REASON = "json body contains credentials that are not stored; it cannot be replayed safely"
SUPPORTED_CHECKS = frozenset({"xss", "sqli", "os"})
_SUPPORTED_CARRIERS = frozenset({"form", "query", "json_body", "json"})


def _default_json_body_for_pointer(pointer: str) -> dict | list:
    """Build a minimal empty JSON object/array structure that contains the pointer."""
    try:
        tokens = parse_pointer(pointer)
    except Exception:
        tokens = []
    if not tokens:
        return {}
    current: Any = ""
    for token in reversed(tokens):
        current = {token: current}
    return current


_REDACTED_LEAF = "<redacted>"


# 既定は秘密。資格情報ではないと明らかな「キー名全体」だけを例外にする（迷う語は秘密の側）。
# 照合は語に分けて "_" でつないだ形（maxTokens・max-tokens も max_tokens になる）。
_NON_SECRET_KEYS = frozenset({
    "max_tokens", "max_output_tokens", "max_completion_tokens", "max_new_tokens",
    "num_tokens", "total_tokens", "input_tokens", "output_tokens", "prompt_tokens", "completion_tokens",
    "token_count", "page_token", "next_page_token", "prev_page_token", "next_token", "continuation_token",
    "secretary",
})

# key/sort_key/session/auth など、文脈や値によって秘密にも非秘密にもなる語。
_AMBIGUOUS_CREDENTIAL_WORDS = frozenset({
    "key", "keys", "session", "sessions", "auth", "oauth", "credential", "credentials",
    "bearer", "jwt",
})

# 短い列挙値やソート方向など、明らかに秘密ではない代表的な値。
_KNOWN_NON_SECRET_VALUES = frozenset({
    "asc", "desc", "ascending", "descending", "none", "null", "all", "any", "true", "false",
    "default", "local", "ldap", "saml", "basic", "bearer", "digest", "oauth", "password",
    "user", "admin", "guest", "test", "sample", "text", "json", "xml", "active", "inactive",
    "enabled", "disabled", "created_at", "updated_at", "id", "name", "title", "date",
    "first", "last", "prev", "next", "open", "close", "start", "stop",
})

_API_KEY_PREFIXES = ("sk-", "ghp_", "gho_", "glpat-", "xoxb-", "xoxp-", "AKIA", "AIza")


def summarize_structure(value):
    """JSON 値の型・構造の要約を返す（秘密値は含まない）。"""
    if isinstance(value, dict):
        return {str(k): summarize_structure(v) for k, v in sorted(value.items())}
    if isinstance(value, (list, tuple)):
        return [summarize_structure(v) for v in value]
    if isinstance(value, bool):
        return "bool"
    if isinstance(value, int):
        return "int"
    if isinstance(value, float):
        return "float"
    if isinstance(value, str):
        return "str"
    if value is None:
        return "null"
    return "any"


def _structure_hash(body) -> str:
    """JSON body の構造要約から決定論的ハッシュを生成する。"""
    summary = summarize_structure(body)
    canonical = json.dumps(summary, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]


def _key_words(key: str) -> list[str]:
    """キー名を語に分ける（snake/kebab/camelCase）。末尾の数字は語の一部とみなさない。"""
    import unicodedata
    normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", unicodedata.normalize("NFKC", str(key)))
    return [w.casefold().rstrip("0123456789") for w in re.findall(r"[^\W_]+", normalized)]


def _is_unambiguous_secret_key(key: str) -> bool:
    """明確に資格情報を示すキー名か。多層防御の伏せ字判定に用いる。"""
    from wscan.request_logger import is_sensitive_header
    low = str(key).lower()
    if not low:
        return False
    if is_sensitive_header(low) or low in ("cookie", "cookies", "authorization", "proxyauthorization", "proxy-authorization", "proxy_authorization"):
        return True
    words = _key_words(key)
    if "_".join(words) in _NON_SECRET_KEYS:
        return False
    # クッキー / 認可 / プロキシ認可ヘッダ系
    if any(w in words for w in ("cookie", "cookies", "authorization", "proxyauthorization")):
        return True
    # パスワード系
    if any(p in low for p in ("password", "passwd", "pwd")):
        return True
    # シークレット系
    if "secret" in low or any(w in ("secret", "secrets") for w in words):
        return True
    # トークン系（_NON_SECRET_KEYS 以外）
    if any("token" in w for w in words):
        return True
    # API キー系
    if "api_key" in low or "apikey" in low or "x-api-key" in low or ("api" in words and any(k in words for k in ("key", "keys"))):
        return True
    # セッション ID 系
    if "sessionid" in low or "session_id" in low or ("session" in words and any(k in words for k in ("id", "ids"))):
        return True
    # CSRF / XSRF 系
    if any(c in low for c in ("csrf", "xsrf", "authenticity_token")):
        return True
    return False


def _key_is_sensitive(key: str) -> bool:
    """キー名が明確な資格情報を示すか。多層防御の伏せ字判定に用いる。"""
    low = str(key).lower()
    words = _key_words(key)
    if any(w in words for w in ("auth", "session", "token", "secret", "cookie", "cookies", "credential", "credentials")):
        if "_".join(words) not in _NON_SECRET_KEYS:
            return True
    return _is_unambiguous_secret_key(key)


def _is_ambiguous_credential_key(key: str) -> bool:
    """key/sort_key/session/auth などの文脈によって秘密にも非秘密にもなるキーか。"""
    words = _key_words(key)
    if not words or "_".join(words) in _NON_SECRET_KEYS:
        return False
    if _is_unambiguous_secret_key(key):
        return False
    return any(w in _AMBIGUOUS_CREDENTIAL_WORDS for w in words)


def _shannon_entropy(data: str) -> float:
    import math
    from collections import Counter
    if not data:
        return 0.0
    counts = Counter(data)
    length = len(data)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def _value_looks_like_secret(val: str) -> bool:
    """値が秘密らしいか。PEM 形式、既知プレフィックス、エントロピーを多層防御で検査する。"""
    if not isinstance(val, str) or not val:
        return False
    cleaned = val.strip()
    # PEM 形式の秘密鍵（空白・改行を含む）
    if "BEGIN" in cleaned and "PRIVATE KEY" in cleaned:
        return True
    # Stripe 等の API キープレフィックス
    if re.match(r"^(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}", cleaned):
        return True
    if cleaned.lower() in _KNOWN_NON_SECRET_VALUES:
        return False
    if cleaned.startswith(_API_KEY_PREFIXES):
        return True
    if re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", cleaned):
        return True
    if len(cleaned) < 16:
        return False
    # 空白や複数の単語区切り（snake_case の自然言語語句）は秘密とみなさない
    if " " in cleaned or bool(re.search(r"[a-z]{3,}_[a-z]{3,}", cleaned)):
        return False
    ent = _shannon_entropy(cleaned)
    if re.fullmatch(r"[0-9a-fA-F]{24,}", cleaned) and ent >= 3.0:
        return True
    if re.fullmatch(r"[A-Za-z0-9+/=_-]{20,}", cleaned) and ent >= 3.4:
        has_digits = any(c.isdigit() for c in cleaned)
        has_letters = any(c.isalpha() for c in cleaned)
        if has_digits and has_letters:
            return True
    return False


def _leaf_is_secret(value, key: str = "") -> bool:
    """多層防御: 値が秘密か。伏せ字処理にのみ用いる。"""
    if isinstance(value, bool) or value is None:
        return False
    if isinstance(value, (int, float)):
        return _key_is_sensitive(key)
    if not isinstance(value, str) or not value:
        return False
    if key and _key_is_sensitive(key):
        return True
    from wscan import url_scope
    from wscan.content_provenance import _BEARER_VALUE_PATTERN, _JWT_VALUE_PATTERN
    from wscan.request_logger import redact_text
    if (
        "BEGIN" in value and "PRIVATE KEY" in value
        or re.match(r"^(sk|rk|pk)_(live|test)_[A-Za-z0-9]{8,}", value.strip())
        or bool(_JWT_VALUE_PATTERN.search(value))
        or bool(_BEARER_VALUE_PATTERN.search(value))
        or url_scope.has_secret_marker(value)
        or url_scope.redact_secret_values(value) != value
        or redact_text(value) != value
    ):
        return True
    return _value_looks_like_secret(value)


def _redact_json_leaves(value, key: str = ""):
    """json_body の秘密の葉を伏せた複製と、秘密があったかを返す（構造は保持）。"""
    if isinstance(value, dict):
        out, found = {}, False
        for k, v in value.items():
            safe, hit = _redact_json_leaves(v, str(k))
            out[k] = safe
            found = found or hit
        return out, found
    if isinstance(value, (list, tuple)):
        items, found = [], False
        for v in value:
            safe, hit = _redact_json_leaves(v, key)
            items.append(safe)
            found = found or hit
        return items, found
    if _leaf_is_secret(value, key):
        return _REDACTED_LEAF, True
    return value, False


def sanitize_template(template: dict) -> tuple[dict, bool]:
    """永続化用に template からヘッダ値と body 値を一切除き、識別に必要な構造要約と非秘密メタ情報だけ残す。

    戻り値は (安全な template, body/header に秘密があったかの多層防御フラグ)。
    ヘッダ値と body 値は、秘密かどうかに関係なく、永続化用 template には一切残さない。"""
    if not isinstance(template, dict):
        return {}, False
    safe = {
        "url": str(template.get("url") or ""),
        "method": str(template.get("method") or "POST").upper(),
        "content_type": str(template.get("content_type") or "application/json"),
    }
    auth_scheme = str(template.get("auth_scheme") or "")
    headers = template.get("headers")
    has_secret_header = False
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "authorization" and str(v).strip().lower().startswith("bearer "):
                auth_scheme = "bearer"
            if _key_is_sensitive(str(k)) or _leaf_is_secret(v, str(k)):
                has_secret_header = True
    if auth_scheme:
        safe["auth_scheme"] = auth_scheme

    body_secret = has_secret_header
    if "json_body" in template:
        body = template["json_body"]
        safe["body_structure"] = summarize_structure(body)
        safe["structure_hash"] = _structure_hash(body)
        if isinstance(body, dict):
            safe["body_keys"] = sorted(str(k) for k in body.keys())
            for k, v in body.items():
                if _key_is_sensitive(str(k)) or _leaf_is_secret(v, str(k)):
                    body_secret = True
    elif "structure_hash" in template:
        safe["structure_hash"] = str(template["structure_hash"])
        if "body_structure" in template:
            safe["body_structure"] = template["body_structure"]
        if "body_keys" in template:
            safe["body_keys"] = template["body_keys"]

    return safe, body_secret


_BEARER_VALUE = re.compile(r"[A-Za-z0-9._~+/=-]{8,}")
_BEARER_UNAVAILABLE = "bearer authentication unavailable in the agent session"


def select_session_bearer(items) -> str:
    """Agent セッションの storage 項目から Bearer に使う値を 1 つ選ぶ（純粋）。

    token らしいキーの値（JWT 形でもキーが資格情報を示すもの）だけを候補にし、refresh/CSRF 用は除く。候補が 1 つでなければ、
    access を含むキーが 1 つのときだけそれを選ぶ。曖昧なら空文字（推測で送らない）。"""
    from wscan.content_provenance import _JWT_VALUE_PATTERN
    found: dict[str, list[str]] = {}

    def visit(key: str, value) -> None:
        if isinstance(value, str) and value.lstrip().startswith("{"):
            try:
                obj = json.loads(value)
            except ValueError:
                obj = None
            if isinstance(obj, dict):
                for k, v in obj.items():
                    visit(str(k), v)
                return
        if not isinstance(value, str):
            return
        words = _key_words(key)
        if {"refresh", "csrf", "xsrf"} & set(words):
            return
        val = value.strip()
        if val.lower().startswith("bearer "):
            val = val[7:].strip()
        if not _BEARER_VALUE.fullmatch(val):
            return
        is_cred_key = _is_unambiguous_secret_key(key) or _is_ambiguous_credential_key(key)
        token_key = bool({"jwt", "bearer"} & set(words)) or (
            is_cred_key and any("token" in w for w in words)
        )
        if token_key or (_JWT_VALUE_PATTERN.fullmatch(val) and is_cred_key):
            found.setdefault(val, words)

    for item in items or ():
        if isinstance(item, dict):
            visit(str(item.get("key") or item.get("name") or ""), item.get("value"))
    if len(found) == 1:
        return next(iter(found))
    access = [v for v, words in found.items() if "access" in words]
    return access[0] if len(access) == 1 else ""


def _verification_consistency_reason(
    record: dict,
    *,
    expected_binding: dict,
    injection_point_id: str,
    check_type: str,
    scanner_evidence: list[dict],
    work_evidence_ids: tuple[str, ...],
) -> str:
    """Checkpoint の outcome・digest・scanner finding evidence を一括検証する。"""
    outcome = record.get("status")
    reproduced = record.get("reproduced")
    deterministic = record.get("deterministic_confirmed")
    expected_flags = {
        "confirmed": (True, True),
        "rejected": (False, False),
        "inconclusive": (False, False),
    }
    if outcome not in expected_flags or (reproduced, deterministic) != expected_flags[outcome]:
        return "outcome fields conflict"

    expected_digest = AgentScannerTools._binding_digest(expected_binding)
    binding = record.get("binding")
    if (
        not isinstance(binding, dict)
        or record.get("binding_digest") != expected_digest
        or AgentScannerTools._binding_digest(binding) != expected_digest
    ):
        return "verification binding does not match the current input point"

    evidence_ids = record.get("evidence_ids")
    if not isinstance(evidence_ids, list) or not all(isinstance(item, str) and item for item in evidence_ids):
        return "evidence IDs are malformed"
    if outcome != "confirmed":
        return "non-confirmed outcome references scanner finding evidence" if evidence_ids else ""
    if not evidence_ids:
        return "confirmed outcome has no scanner finding evidence"

    evidence_by_id = {}
    for item in scanner_evidence:
        if not isinstance(item, dict) or not item.get("evidence_id"):
            continue
        evidence_id = str(item["evidence_id"])
        if evidence_id in evidence_by_id:
            return "scanner finding evidence ID is duplicated"
        evidence_by_id[evidence_id] = item
    if len(set(evidence_ids)) != len(evidence_ids):
        return "verification evidence IDs are duplicated"
    for evidence_id in evidence_ids:
        evidence = evidence_by_id.get(evidence_id)
        if evidence is None or evidence_id not in work_evidence_ids:
            return "referenced scanner finding evidence is missing"
        finding = evidence.get("finding")
        if (
            evidence.get("work_id") != record.get("work_id")
            or evidence.get("injection_point_id") != injection_point_id
            or evidence.get("check_type") != check_type
            or evidence.get("binding_digest") != expected_digest
            or not isinstance(finding, dict)
            or finding.get("check_type") != check_type
            or finding.get("source") != "deterministic"
            or finding.get("deterministic_confirmed") is not True
            or finding.get("agent_verified") is not True
        ):
            return "scanner finding evidence is inconsistent with its verification binding"
    return ""


class AgentScannerTools:
    """Expose ID-only scanner actions while keeping transport and secrets server-side."""

    def __init__(self, scanner, harness, *, engine_factory=None):
        self.scanner = scanner
        self.harness = harness
        self.engine_factory = engine_factory or self._new_engine
        self.points: dict[str, dict] = {}
        self.findings: dict[str, object] = {}
        self.work_specs: dict[str, tuple[str, str]] = {}
        self._live_templates: dict[str, dict] = {}
        self.points_path = Path(harness.output_dir) / "agent_scanner_points.json"
        self._load_points()

    def _load_points(self):
        try:
            data = json.loads(self.points_path.read_text(encoding="utf-8"))
            self.points = data if isinstance(data, dict) else {}
        except (OSError, ValueError):
            self.points = {}

    def _save_points(self):
        tmp = self.points_path.with_suffix(".tmp")
        from wscan.request_logger import redact_url
        safe = {}
        for point_id, item in self.points.items():
            saved = dict(item)
            for key in ("url", "action"):
                if saved.get(key):
                    redacted = redact_url(str(saved[key]))
                    if redacted != saved[key]:
                        saved["resume_unavailable"] = True
                    saved[key] = redacted
            tmpl = saved.get("template")
            if isinstance(tmpl, dict):
                if tmpl.get("url") and redact_url(str(tmpl["url"])) != tmpl["url"]:
                    saved["resume_unavailable"] = True
                saved["template"], _ = sanitize_template(tmpl)
            f = saved.get("field")
            if isinstance(f, dict) and isinstance(f.get("template"), dict):
                saved["field"] = dict(f)
                saved["field"]["template"], _ = sanitize_template(f["template"])
            self.points[point_id] = saved
            safe[point_id] = saved
        tmp.write_text(json.dumps(safe, ensure_ascii=False, sort_keys=True), encoding="utf-8")
        tmp.replace(self.points_path)
        self.harness.checkpoint()

    @staticmethod
    def _point_id(point: InjectionPoint) -> str:
        identity = json.dumps(point.stable_key_parts(), sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(identity.encode()).hexdigest()[:20]

    def add_point(self, point: InjectionPoint, field: dict | None = None) -> str:
        point_id = self._point_id(point)
        current = self.points.get(point_id)
        if isinstance(current, dict) and not current.get("resume_unavailable"):
            existing, _ = self._resolve(point_id)
            if existing is not None and existing.stable_key_parts() != point.stable_key_parts():
                raise ValueError("injection point ID collision; rediscover the input point before scheduling")
        template = None
        if isinstance(field, dict) and isinstance(field.get("template"), dict):
            template = dict(field["template"])
        elif getattr(point, "template", None) and isinstance(point.template, dict):
            template = dict(point.template)

        if template:
            if not hasattr(self, "_live_templates"):
                self._live_templates = {}
            self._live_templates[point_id] = dict(template)
            if self.scanner is not None:
                if not hasattr(self.scanner, "captured_templates") or not isinstance(self.scanner.captured_templates, dict):
                    try:
                        self.scanner.captured_templates = {}
                    except Exception:
                        pass
                if isinstance(getattr(self.scanner, "captured_templates", None), dict):
                    self.scanner.captured_templates[point_id] = dict(template)
                    self.scanner.captured_templates[str(template.get("url") or point.url)] = dict(template)

        if current is None or current.get("resume_unavailable"):
            auth_scheme = ""
            if isinstance(field, dict):
                auth_scheme = str(field.get("auth_scheme") or field.get("auth") or "")
            sanitized_template, _ = sanitize_template(template) if template else ({}, False)
            if not auth_scheme and sanitized_template:
                auth_scheme = str(sanitized_template.get("auth_scheme") or "")
            sanitized_field = dict(field or {"name": point.parameter_id})
            if "template" in sanitized_field and isinstance(sanitized_field["template"], dict):
                sanitized_field["template"], _ = sanitize_template(sanitized_field["template"])
            item_data = {
                "location": point.location, "url": point.url, "parameter_id": point.parameter_id,
                "display_name": point.display_name,
                "form_index": point.form_index, "field": sanitized_field,
                "method": point.method, "action": point.action,
                "template_id": point.template_id,
                "template": sanitized_template,
            }
            if auth_scheme:
                item_data["auth_scheme"] = auth_scheme
            self.points[point_id] = item_data
        self._save_points()
        return point_id

    def _resolve(self, point_id: str) -> tuple[InjectionPoint | None, dict | None]:
        item = self.points.get(str(point_id))
        if not isinstance(item, dict):
            return None, None
        if item.get("resume_unavailable"):
            return None, item
        # レガシーな body_secret かつ structure_hash が未記録の古い checkpoint だけ除外する
        if item.get("body_secret") and not (item.get("template") or {}).get("structure_hash"):
            return None, item
        try:
            carrier = "query" if item.get("location") == "url_param" else item.get("location")
            if carrier not in _SUPPORTED_CARRIERS:
                return None, item
            if carrier == "query":
                point = InjectionPoint.for_url_param(item["url"], item["parameter_id"])
            elif carrier in ("json_body", "json"):
                template_id = str(item.get("template_id") or f"tmpl_{str(point_id)[:12]}")
                display_name = str(item.get("display_name") or (item.get("field", {}) or {}).get("name") or "")
                point = InjectionPoint.for_json_body(
                    item.get("method", "POST"),
                    item["url"],
                    item["parameter_id"],
                    display_name=display_name,
                    template_id=template_id,
                )
            else:
                point = InjectionPoint.for_form(
                    item["url"], item["parameter_id"], int(item.get("form_index", 0)),
                    method=item.get("method", ""), action=item.get("action", ""),
                )
        except (KeyError, TypeError, ValueError):
            return None, item
        if self._point_id(point) != str(point_id):
            return None, item
        return point, item

    async def _reobtain_live_template(self, point: InjectionPoint, metadata: dict) -> tuple[dict | None, str]:
        """送信直前に、現在のページや捕捉したリクエスト・セッションから同じ構造の template を取り直す。

        戻り値は (template, reason)。構造ハッシュが一致したときだけ template を返し、
        取り直せない場合や一致しない場合は (None, reason) を返す。
        """
        point_id = self._point_id(point)
        meta_tmpl = metadata.get("template") if isinstance(metadata.get("template"), dict) else {}
        expected_hash = meta_tmpl.get("structure_hash") or ""
        expected_url = str(meta_tmpl.get("url") or point.url)
        expected_endpoint = endpoint_identity(expected_url)
        expected_method = str(meta_tmpl.get("method") or point.method or "POST").upper()

        candidates: list[dict] = []
        if hasattr(self, "_live_templates") and point_id in self._live_templates:
            candidates.append(self._live_templates[point_id])

        scanner = self.scanner
        if scanner is not None:
            for attr in ("_live_templates", "captured_templates", "injection_templates"):
                val = getattr(scanner, attr, None)
                if isinstance(val, dict):
                    if point_id in val and isinstance(val[point_id], dict) and val[point_id] not in candidates:
                        candidates.append(val[point_id])
                    for k, t in val.items():
                        if isinstance(t, dict) and t not in candidates:
                            t_url = str(t.get("url") or "")
                            if t_url and (t_url == expected_url or endpoint_identity(t_url) == expected_endpoint):
                                candidates.append(t)

            captured_reqs = (
                getattr(scanner, "captured_requests", None)
                or getattr(getattr(scanner, "_active_session", None), "captured_requests", None)
                or getattr(scanner, "_captured_requests", None)
            )
            if isinstance(captured_reqs, list):
                for req in reversed(captured_reqs):
                    if not isinstance(req, dict):
                        continue
                    r_url = str(req.get("url") or "")
                    r_method = str(req.get("method") or "POST").upper()
                    if (r_url == expected_url or endpoint_identity(r_url) == expected_endpoint) and r_method == expected_method:
                        body = req.get("json_body")
                        if body is None and req.get("post_data"):
                            try:
                                body = json.loads(req["post_data"])
                            except Exception:
                                body = None
                        if isinstance(body, (dict, list)):
                            candidates.append({
                                "url": r_url,
                                "method": r_method,
                                "json_body": body,
                                "headers": dict(req.get("headers") or {}),
                                "content_type": str(req.get("content_type") or "application/json"),
                            })

            if callable(getattr(scanner, "get_template_for_point", None)):
                try:
                    res = await scanner.get_template_for_point(point_id)
                    if isinstance(res, dict) and res not in candidates:
                        candidates.append(res)
                except Exception:
                    pass
            elif callable(getattr(scanner, "capture_template", None)):
                try:
                    res = await scanner.capture_template(expected_url, point.parameter_id)
                    if isinstance(res, dict) and res not in candidates:
                        candidates.append(res)
                except Exception:
                    pass

        if not candidates:
            if not expected_hash:
                default_body = _default_json_body_for_pointer(point.parameter_id)
                return {
                    "url": expected_url,
                    "method": expected_method,
                    "json_body": default_body,
                    "content_type": "application/json",
                    "headers": {},
                }, ""
            return None, "live request template for json body is unavailable in the current agent session"

        matched = None
        for cand in candidates:
            if not isinstance(cand, dict) or "json_body" not in cand:
                continue
            cand_body = cand["json_body"]
            cand_hash = _structure_hash(cand_body)
            if not expected_hash or cand_hash == expected_hash:
                matched = cand
                break

        if matched is None:
            return None, "live request template structure does not match the registered injection point"

        return matched, ""

    def _scope_reason(self, point: InjectionPoint, field_name: str = "", template: dict | None = None) -> str:
        engine_args = self.scanner
        from wscan.llm_agent_browser import _url_is_excluded, security_probe_allowed
        policy = ScopePolicy(
            target_urls=tuple(engine_args.target_urls), access_urls=tuple(engine_args.access_urls),
            exclude_urls=tuple(engine_args.exclude_urls), login_url=engine_args.login_url,
        )
        from wscan.runtime_scope_guard import _matches_scope_list
        if _url_is_excluded(point.url, engine_args.exclude_urls):
            return "excluded_url"
        if _matches_scope_list(point.url, policy.access_urls):
            return "access_only_url"
        if not security_probe_allowed(
            point.url, engine_args.target_urls, engine_args.exclude_urls,
            access_urls=engine_args.access_urls, field_name=field_name,
            exclude_fields=engine_args.exclude_fields,
        ):
            return "scope_blocked"
        decision = evaluate_scope(point.url, policy)
        if not decision.allowed or decision.reason not in {"target_url", "target_url_no_frag", "target_url_no_query"}:
            if decision.reason == "excluded_url":
                return "excluded_url"
            if decision.reason == "access_url":
                return "access_only_url"
            return "scope_blocked"
        if point.action:
            from wscan.runtime_scope_guard import _matches_scope_list
            if _url_is_excluded(point.action, engine_args.exclude_urls):
                return "excluded_url"
            if _matches_scope_list(point.action, policy.access_urls):
                return "access_only_url"
            if not security_probe_allowed(
                point.action, engine_args.target_urls, engine_args.exclude_urls,
                access_urls=engine_args.access_urls,
            ):
                return "scope_blocked"
            action_decision = evaluate_scope(point.action, policy)
            if not action_decision.allowed or action_decision.reason not in {"target_url", "target_url_no_frag", "target_url_no_query"}:
                return "scope_blocked" if action_decision.reason != "excluded_url" else "excluded_url"
        if isinstance(template, dict) and template.get("url"):
            tmpl_url = str(template["url"])
            if _url_is_excluded(tmpl_url, engine_args.exclude_urls):
                return "excluded_url"
            from wscan.runtime_scope_guard import _matches_scope_list
            if _matches_scope_list(tmpl_url, policy.access_urls):
                return "access_only_url"
            if not security_probe_allowed(
                tmpl_url, engine_args.target_urls, engine_args.exclude_urls,
                access_urls=engine_args.access_urls,
            ):
                return "scope_blocked"
            tmpl_decision = evaluate_scope(tmpl_url, policy)
            if not tmpl_decision.allowed or tmpl_decision.reason not in {"target_url", "target_url_no_frag", "target_url_no_query"}:
                return "scope_blocked" if tmpl_decision.reason != "excluded_url" else "excluded_url"
        return ""

    async def list_scanner_capabilities(self, *, correlation_id: str = "") -> dict:
        """Return discovered injection points and their carrier/check support."""
        corr_id = str(correlation_id or f"corr_cap_{secrets.token_hex(4)}")
        self.harness.record_dispatch_event(
            event_type="tool_request",
            tool_name="list_scanner_capabilities",
            correlation_id=corr_id,
        )
        self.harness.record_dispatch_event(
            event_type="authorization_decision",
            tool_name="list_scanner_capabilities",
            correlation_id=corr_id,
            allowed=True,
            reason="authorized",
        )
        self.harness.record_dispatch_event(
            event_type="dispatch_start",
            tool_name="list_scanner_capabilities",
            correlation_id=corr_id,
        )
        await self.observe_page()
        items = []
        gaps = []
        for point_id, raw in sorted(self.points.items()):
            point, metadata = self._resolve(point_id)
            carrier = "query" if raw.get("location") == "url_param" else raw.get("location", "unknown")
            if point is None:
                if metadata and metadata.get("body_secret"):
                    reason = _BODY_SECRET_REASON
                elif metadata and metadata.get("resume_unavailable"):
                    reason = "endpoint was redacted in the checkpoint; rediscover this input point"
                elif carrier == "xml_body":
                    reason = "xml_body carrier unsupported: XML lacks schema parsing, browser harvesting, and dynamic token binding in agent mode"
                else:
                    reason = "authenticated context not shareable for this carrier"
                items.append({"injection_point_id": point_id, "carrier": carrier, "checks": [], "status": "unsupported", "reason": reason})
                gaps.append(f"unsupported_carrier:{carrier}")
                continue
            reason = self._scope_reason(point, str(metadata.get("parameter_id", "")), metadata.get("template") if isinstance(metadata, dict) else None)
            status = "blocked" if reason else "supported"
            items.append({"injection_point_id": point_id, "carrier": carrier, "checks": sorted(SUPPORTED_CHECKS), "status": status, "reason": reason})
        if gaps:
            self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, *gaps])
        self.harness.record_dispatch_event(
            event_type="dispatch_end",
            tool_name="list_scanner_capabilities",
            correlation_id=corr_id,
            status="completed",
        )
        return {"capabilities": items}

    def schedule_scanner(self, injection_point_id: str, check: str, *, correlation_id: str = "") -> dict:
        """Queue an additional scanner work item without sending a request."""
        corr_id = str(correlation_id or f"corr_sched_{secrets.token_hex(4)}")
        self.harness.record_dispatch_event(
            event_type="tool_request",
            tool_name="schedule_scanner",
            correlation_id=corr_id,
            details={"injection_point_id": injection_point_id, "check": check},
        )
        check = str(check or "").lower()
        point, metadata = self._resolve(injection_point_id)
        if check not in SUPPORTED_CHECKS:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="schedule_scanner",
                correlation_id=corr_id,
                allowed=False,
                reason="check must be one of xss, sqli, os",
            )
            return {"status": "unsupported", "reason": "check must be one of xss, sqli, os"}
        if point is None or metadata is None:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="schedule_scanner",
                correlation_id=corr_id,
                allowed=False,
                reason="unknown injection point ID",
            )
            if isinstance(metadata, dict) and metadata.get("body_secret"):
                self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, f"unsupported_secret_body:{injection_point_id}"])
                return {"status": "unsupported", "reason": _BODY_SECRET_REASON}
            return {"status": "unsupported", "reason": "unknown injection point ID"}
        reason = self._scope_reason(point, str(metadata.get("parameter_id", "")), metadata.get("template") if isinstance(metadata, dict) else None)
        if reason:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="schedule_scanner",
                correlation_id=corr_id,
                allowed=False,
                reason=reason,
            )
            self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, f"{reason}:{injection_point_id}"])
            return {"status": "blocked", "reason": reason}
        self.harness.record_dispatch_event(
            event_type="authorization_decision",
            tool_name="schedule_scanner",
            correlation_id=corr_id,
            allowed=True,
            reason="authorized",
        )
        self.harness.record_dispatch_event(
            event_type="dispatch_start",
            tool_name="schedule_scanner",
            correlation_id=corr_id,
        )
        existing = next((item for item in self.harness.state.work_queue
                         if item.role == AgentRole.PROBE_SPECIALIST
                         and item.target == injection_point_id
                         and item.check_type == check), None)
        work = self.harness.enqueue(AgentRole.PROBE_SPECIALIST, injection_point_id, check_type=check, correlation_id=corr_id)
        self.work_specs[work.work_id] = (injection_point_id, check)
        status = "already_scheduled" if existing else "planned"
        self.harness.record_dispatch_event(
            event_type="dispatch_end",
            tool_name="schedule_scanner",
            correlation_id=corr_id,
            work_id=work.work_id,
            status=status,
        )
        return {"work_id": work.work_id, "status": status}

    def schedule_baselines(self, *, point_ids=None) -> int:
        """Deterministically queue every supported point/check pair."""
        count = 0
        for point_id in sorted(point_ids if point_ids is not None else self.points):
            point, metadata = self._resolve(point_id)
            if point is None:
                self.harness.note_coverage(coverage_gaps=[f"unsupported_carrier:{metadata.get('location', 'unknown')}"])
                continue
            for check in sorted(SUPPORTED_CHECKS):
                queued = self.schedule_scanner(point_id, check)
                count += queued.get("status") == "planned"
        return count

    async def run_scanner_work(self, work_id: str, *, correlation_id: str = "") -> dict:
        """Execute a queued item with a fresh, verified handoff session."""
        work = next((item for item in self.harness.state.work_queue if item.work_id == work_id), None)
        corr_id = str(correlation_id or (getattr(work, "correlation_id", "") if work else "") or f"corr_work_{work_id}_{secrets.token_hex(4)}")
        self.harness.record_dispatch_event(
            event_type="tool_request",
            tool_name="run_scanner_work",
            work_id=work_id,
            correlation_id=corr_id,
        )
        if work is None:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="unknown work ID; schedule the scanner work first",
            )
            return {"status": "failed", "reason": "unknown work ID; schedule the scanner work first"}
        if work.status not in {WorkStatus.PLANNED, WorkStatus.RUNNING, WorkStatus.INCONCLUSIVE, WorkStatus.TRANSIENT_FAILURE}:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="work is already running or complete; schedule new work to retry",
            )
            return {"status": "blocked", "reason": "work is already running or complete; schedule new work to retry"}
        was_claimed = work.status == WorkStatus.RUNNING
        spec = self.work_specs.get(work_id)
        if spec is None:
            try:
                spec = (work.target, work.check_type)
            except Exception:
                spec = None
        if not spec:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="scanner work metadata is unavailable; schedule it again",
            )
            self.harness.finish_work(work_id, WorkStatus.FAILED, rejection_reason="scanner work cannot be resumed; schedule it again")
            return {"status": "failed", "reason": "scanner work metadata is unavailable; schedule it again"}
        point_id, check = spec
        point, metadata = self._resolve(point_id)
        if point is None or check not in SUPPORTED_CHECKS:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="unsupported carrier or check",
            )
            self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="unsupported carrier or check")
            return {"status": "unsupported", "reason": "this carrier or check is not supported"}
        reason = self._scope_reason(point, str(metadata.get("parameter_id", "")), metadata.get("template") if isinstance(metadata, dict) else None)
        if reason:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason=reason,
            )
            self.harness.finish_work(work_id, WorkStatus.SCOPE_BLOCKED, rejection_reason=reason)
            return {"status": "blocked", "reason": reason}
        if self.harness.remaining_steps <= 0:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="scanner work budget exhausted",
            )
            self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, f"scanner_budget_exhausted:{point_id}:{check}"])
            self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="scanner work budget exhausted")
            return {"status": "blocked", "reason": "scanner work budget is exhausted; increase the run budget and retry"}
        if self._already_dispatched(work_id):
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="prior dispatch outcome is unknown; automatic replay was suppressed",
            )
            self.harness.finish_work(work_id, WorkStatus.INCONCLUSIVE, rejection_reason="prior dispatch outcome is unknown; automatic replay was suppressed")
            return {"status": "inconclusive", "reason": "a prior attempt may have reached the target; automatic replay was suppressed"}
        binding = self._verification_binding(point, metadata, check)
        binding_digest = self._binding_digest(binding)
        try:
            cookies = await self.scanner._capture_cookies(self.scanner._active_session)
        except Exception:
            cookies = None
        if not cookies:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=False,
                reason="authentication state unavailable",
            )
            self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="authentication state unavailable")
            return {"status": "blocked", "reason": "current authentication state is unavailable; re-authenticate and retry"}
        bearer = ""
        tmpl_meta = metadata.get("template") if isinstance(metadata.get("template"), dict) else {}
        is_bearer_carrier = (
            (point.location in ("json_body", "json") or point.location in ("url_param", "query"))
            and (
                tmpl_meta.get("auth_scheme") == "bearer"
                or metadata.get("auth_scheme") == "bearer"
                or (metadata.get("field") or {}).get("auth_scheme") == "bearer"
            )
            and not any(str(k).lower() == "authorization" for k in (getattr(self.scanner, "extra_headers", None) or {}))
        )
        if is_bearer_carrier:
            # 保存した template の Bearer は捨てている。Agent セッションから新しい値を得られる場合だけ送る。
            # storage は origin ごとなので、現在のページが送信先と同じ origin のときだけ読む（他 origin の token を送らない）。
            capture = getattr(self.scanner, "_capture_tokens", None)
            send_url = str(tmpl_meta.get("url") or point.url)
            try:
                page_url = await self._current_page_url()
                bearer = (
                    select_session_bearer(await capture(self.scanner._active_session))
                    if callable(capture) and page_url and url_scope_same_origin(page_url, send_url) else ""
                )
            except Exception:
                bearer = ""
            if not bearer:
                self.harness.record_dispatch_event(
                    event_type="authorization_decision",
                    tool_name="run_scanner_work",
                    work_id=work_id,
                    correlation_id=corr_id,
                    allowed=False,
                    reason=_BEARER_UNAVAILABLE,
                )
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason=_BEARER_UNAVAILABLE)
                return {"status": "blocked", "reason": f"{_BEARER_UNAVAILABLE}; sign in through the agent session or set an Authorization header and retry"}
        live_tmpl = None
        if point.location in ("json_body", "json"):
            import inspect
            reobtain_res = self._reobtain_live_template(point, metadata)
            if inspect.isawaitable(reobtain_res):
                live_tmpl, tmpl_reason = await reobtain_res
            else:
                live_tmpl, tmpl_reason = reobtain_res
            if live_tmpl is None:
                self.harness.record_dispatch_event(
                    event_type="authorization_decision",
                    tool_name="run_scanner_work",
                    work_id=work_id,
                    correlation_id=corr_id,
                    allowed=False,
                    reason=tmpl_reason,
                )
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason=tmpl_reason)
                return {"status": "blocked", "reason": tmpl_reason}
        engine = None
        from wscan import url_scope
        secret_registry = getattr(url_scope, "_SECRET_VALUES", None)
        secret_snapshot = dict(secret_registry) if isinstance(secret_registry, dict) else None
        skipped_snapshot = list(getattr(url_scope, "skipped_secret_labels", []))
        try:
            handoff = self._handoff(cookies)
            engine = self.engine_factory(check, handoff)
            engine.target_only = True
            engine._runtime_scope_block_callback = self._record_scope_block
            if point.location in ("json_body", "json"):
                tmpl_data = live_tmpl
                json_body = tmpl_data.get("json_body")
                if json_body is None:
                    json_body = _default_json_body_for_pointer(point.parameter_id)
                clean_headers = {
                    k: v for k, v in (tmpl_data.get("headers") or {}).items()
                    if not _key_is_sensitive(str(k)) and not _leaf_is_secret(v, str(k))
                }
                if tmpl_data.get("content_type"):
                    clean_headers.setdefault("Content-Type", str(tmpl_data.get("content_type")))
                elif "Content-Type" not in clean_headers:
                    clean_headers["Content-Type"] = "application/json"
                if bearer:
                    clean_headers["Authorization"] = f"Bearer {bearer}"
                template_dict = {
                    "method": str(tmpl_data.get("method") or point.method or "POST").upper(),
                    "url": str(tmpl_data.get("url") or point.url),
                    "endpoint": endpoint_identity(str(tmpl_data.get("url") or point.url)),
                    "json_body": json_body,
                    "content_type": str(tmpl_data.get("content_type") or clean_headers.get("Content-Type") or "application/json"),
                    "headers": clean_headers,
                }
                if not hasattr(engine, "injection_templates") or engine.injection_templates is None:
                    engine.injection_templates = {}
                engine.injection_templates[point.template_id] = template_dict
            elif bearer:
                from wscan.engine import _store_synced_token
                send_url = str(tmpl_meta.get("url") or point.url)
                _store_synced_token(engine, send_url, {"Authorization": f"Bearer {bearer}"})
                if hasattr(engine, "header_manager") and hasattr(engine.header_manager, "update"):
                    await engine.header_manager.update({"Authorization": f"Bearer {bearer}"})
                if hasattr(engine, "headers") and isinstance(engine.headers, dict):
                    engine.headers["Authorization"] = f"Bearer {bearer}"
            from wscan.llm_agent_browser import security_probe_allowed
            tmpl_url = (metadata.get("template") or {}).get("url") if isinstance(metadata.get("template"), dict) else ""
            if (
                not security_probe_allowed(
                    point.url, engine.target_urls, engine.exclude_urls,
                    access_urls=engine.access_urls, field_name=metadata["parameter_id"],
                    exclude_fields=engine.exclude_fields,
                )
                or not engine._is_attack_target_url(point.url)
                or engine._is_url_excluded(point.url)
                or (point.action and (
                    not security_probe_allowed(
                        point.action, engine.target_urls, engine.exclude_urls,
                        access_urls=engine.access_urls, field_name=metadata["parameter_id"],
                        exclude_fields=engine.exclude_fields,
                    )
                    or not engine._is_attack_target_url(point.action)
                    or engine._is_url_excluded(point.action)
                ))
                or (tmpl_url and (
                    not security_probe_allowed(
                        tmpl_url, engine.target_urls, engine.exclude_urls,
                        access_urls=engine.access_urls, field_name=metadata["parameter_id"],
                        exclude_fields=engine.exclude_fields,
                    )
                    or not engine._is_attack_target_url(tmpl_url)
                    or engine._is_url_excluded(tmpl_url)
                ))
            ):
                self.harness.record_dispatch_event(
                    event_type="authorization_decision",
                    tool_name="run_scanner_work",
                    work_id=work_id,
                    correlation_id=corr_id,
                    allowed=False,
                    reason="engine scope guard rejected injection point",
                )
                self.harness.finish_work(work_id, WorkStatus.SCOPE_BLOCKED, rejection_reason="engine scope guard rejected injection point")
                return {"status": "blocked", "reason": "engine scope policy rejected the injection point"}
            url_scope.register_secret_values((f"agent_cookie_{i}", c.get("value", "")) for i, c in enumerate(cookies) if isinstance(c, dict))
            if bearer:
                url_scope.register_secret_values([("agent_bearer", bearer)])
            await engine._browser.init()
            from wscan.runtime_scope_guard import ScopePolicy
            install_guard = getattr(engine._browser, "install_runtime_scope_guard", None)
            if not callable(install_guard) or not await install_guard(
                ScopePolicy.from_engine(engine), on_block=self._record_scope_block,
            ):
                self.harness.record_dispatch_event(
                    event_type="authorization_decision",
                    tool_name="run_scanner_work",
                    work_id=work_id,
                    correlation_id=corr_id,
                    allowed=False,
                    reason="runtime scope guard unavailable",
                )
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="runtime scope guard unavailable")
                return {"status": "blocked", "reason": "runtime scope guard could not be enabled; scanner work was not sent"}
            if not await engine._seed_and_verify_handoff_cookies(engine._browser):
                self.harness.record_dispatch_event(
                    event_type="authorization_decision",
                    tool_name="run_scanner_work",
                    work_id=work_id,
                    correlation_id=corr_id,
                    allowed=False,
                    reason="authentication unverified",
                )
                self.harness.finish_work(work_id, WorkStatus.BLOCKED, rejection_reason="authentication unverified")
                return {"status": "blocked", "reason": "authentication could not be verified; re-authenticate and retry"}
            scanner = engine.scanners[check]
            if point.location not in ("json_body", "json"):
                await engine._browser.navigate(point.url)
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                allowed=True,
                reason="authorized",
            )
            self.harness.record_dispatch_event(
                event_type="dispatch_start",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
            )
            if not was_claimed:
                work.transition_to(WorkStatus.RUNNING)
                work.attempts += 1
                self.harness.checkpoint()
            self.harness.record_probe_attempt(
                target_url=point.url, check_type=check, work_id=work_id,
                correlation_id=corr_id,
                status="dispatching", binding=binding, binding_digest=binding_digest,
            )
            if point.location in ("json_body", "json"):
                if callable(getattr(scanner, "scan_injection_point", None)):
                    scan_coro = scanner.scan_injection_point(point, metadata["field"])
                else:
                    scan_coro = scanner.scan_field(point.url, point.form_index, metadata["field"], False)
            else:
                scan_coro = scanner.scan_field(point.url, point.form_index, metadata["field"], point.legacy_is_url_param())
            findings = await asyncio.wait_for(scan_coro, timeout=180)
            verified = []
            verification_inconclusive = False
            for finding in findings:
                verification = await asyncio.wait_for(scanner.verify_finding(finding), timeout=180)
                if verification is True:
                    verified.append(finding)
                elif verification is None:
                    verification_inconclusive = True
            status = WorkStatus.INCONCLUSIVE if verification_inconclusive and not verified else WorkStatus.COMPLETE
            sanitized_findings = self._sanitize_findings(verified)
            evidence_ids = self._persist_scanner_evidence(
                work_id, point_id, check, binding_digest, sanitized_findings,
            )
            self.findings[work_id] = sanitized_findings
            self.harness.record_probe_attempt(
                target_url=point.url, check_type=check, work_id=work_id,
                correlation_id=corr_id,
                status="inconclusive" if status == WorkStatus.INCONCLUSIVE else "completed",
                evidence_id=work_id, binding=binding, binding_digest=binding_digest,
            )
            self.harness.record_dispatch_event(
                event_type="executed_scanner_work",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                executed_work_id=work_id,
            )
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                status="completed" if status == WorkStatus.COMPLETE else status.value,
                executed_work_id=work_id,
            )
            self.harness.finish_work(
                work_id, status,
                summary=f"deterministic scanner work finished: {len(verified)} verified findings",
                evidence_ids=evidence_ids,
            )
            for hypothesis in self.harness.state.hypotheses:
                hypothesis_id = str(hypothesis.get("candidate_id", ""))
                if hypothesis.get("injection_point_id") == point_id and hypothesis.get("check_type") == check:
                    outcome = "confirmed" if verified else "inconclusive" if verification_inconclusive else "rejected"
                    reason = "" if outcome == "confirmed" else (
                        "verify_finding returned None" if outcome == "inconclusive"
                        else "deterministic scanner did not confirm the hypothesis"
                    )
                    self._record_hypothesis_outcome(hypothesis_id, outcome, reason, work_id=work_id)
            return {
                "status": "inconclusive" if status == WorkStatus.INCONCLUSIVE else "completed",
                "verified_count": len(verified), "work_id": work_id,
            }
        except asyncio.TimeoutError:
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                status="timeout",
                reason="scanner timed out",
            )
            work.transition_to(WorkStatus.TRANSIENT_FAILURE, rejection_reason="scanner timed out")
            self.harness.checkpoint()
            self._mark_hypotheses(point_id, check, "inconclusive", "scanner timed out", work_id=work_id)
            return {"status": "timeout", "reason": "scanner timed out; the work remains eligible for resume"}
        except Exception as exc:
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="run_scanner_work",
                work_id=work_id,
                correlation_id=corr_id,
                status="failed",
                reason=f"scanner error: {type(exc).__name__}",
            )
            self.harness.finish_work(work_id, WorkStatus.FAILED, rejection_reason=f"scanner error: {type(exc).__name__}")
            self._mark_hypotheses(point_id, check, "inconclusive", f"scanner failed: {type(exc).__name__}", work_id=work_id)
            return {"status": "failed", "reason": "scanner failed; inspect the redacted run log and retry the work"}
        finally:
            if engine is not None and getattr(engine, "_browser", None) is not None:
                try:
                    await engine._browser.close()
                except Exception:
                    pass
            if secret_snapshot is not None:
                secret_registry.clear()
                secret_registry.update(secret_snapshot)
                url_scope.skipped_secret_labels[:] = skipped_snapshot

    async def verify_hypothesis(self, hypothesis_id: str, *, correlation_id: str = "") -> dict:
        """Schedule deterministic verification for a known hypothesis."""
        corr_id = str(correlation_id or f"corr_ver_{secrets.token_hex(4)}")
        self.harness.record_dispatch_event(
            event_type="tool_request",
            tool_name="verify_hypothesis",
            correlation_id=corr_id,
            details={"hypothesis_id": str(hypothesis_id)},
        )
        hypothesis_id = str(hypothesis_id)
        hypothesis = next((item for item in self.harness.state.hypotheses
                           if str(item.get("candidate_id", "")) == hypothesis_id), None)
        if not hypothesis:
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name="verify_hypothesis",
                correlation_id=corr_id,
                allowed=False,
                reason="unknown hypothesis ID",
            )
            return {"status": "inconclusive", "reason": "unknown hypothesis ID"}
        self.harness.record_dispatch_event(
            event_type="authorization_decision",
            tool_name="verify_hypothesis",
            correlation_id=corr_id,
            allowed=True,
            reason="authorized",
        )
        self.harness.record_dispatch_event(
            event_type="dispatch_start",
            tool_name="verify_hypothesis",
            correlation_id=corr_id,
        )
        recorded, ledger_error = self._verification_record(hypothesis_id)
        record_reason = self._verification_consistency_reason(recorded, hypothesis) if recorded is not None else ""
        if recorded is not None and not record_reason:
            self._restore_hypothesis_outcome(hypothesis_id, recorded)
            res = self._verification_result(hypothesis_id, recorded)
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="verify_hypothesis",
                correlation_id=corr_id,
                status=res.get("status", "inconclusive"),
            )
            return res
        unverifiable_checkpoint = bool(
            recorded is not None or ledger_error or self._checkpoint_claims_confirmation(hypothesis)
        )
        if unverifiable_checkpoint:
            self._downgrade_unverifiable(
                hypothesis_id,
                f"inconsistent_verification_record: {record_reason}" if record_reason else None,
            )
        point_id = hypothesis.get("injection_point_id", "")
        check = hypothesis.get("check_type", "")
        scheduled = self.schedule_scanner(point_id, check, correlation_id=corr_id)
        if scheduled.get("status") not in {"planned", "already_scheduled"}:
            reason = scheduled.get("reason", "verification unavailable")
            if unverifiable_checkpoint:
                reason = f"unverifiable_checkpoint: {reason}"
            self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason)
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="verify_hypothesis",
                correlation_id=corr_id,
                status="inconclusive",
                reason=reason,
            )
            return {"status": "inconclusive", "reason": reason}
        self.work_specs[scheduled["work_id"]] = (point_id, check)
        existing = next(item for item in self.harness.state.work_queue if item.work_id == scheduled["work_id"])
        if existing.status == WorkStatus.COMPLETE:
            reason = (
                f"inconsistent_verification_record: {record_reason}; replay was suppressed"
                if record_reason else
                "unverifiable_checkpoint: completed scanner result has no valid deterministic evidence; replay was suppressed"
            )
            self._downgrade_unverifiable(hypothesis_id, reason)
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="verify_hypothesis",
                correlation_id=corr_id,
                status="inconclusive",
                reason=reason,
            )
            return {"status": "inconclusive", "reason": reason, "hypothesis_id": hypothesis_id, "work_id": existing.work_id}
        result = await self.run_scanner_work(scheduled["work_id"], correlation_id=corr_id)
        recorded, ledger_error = self._verification_record(hypothesis_id)
        record_reason = self._verification_consistency_reason(recorded, hypothesis) if recorded is not None else ""
        if recorded is not None and not record_reason:
            self._restore_hypothesis_outcome(hypothesis_id, recorded)
            res = {**self._verification_result(hypothesis_id, recorded), "work_id": scheduled["work_id"]}
            self.harness.record_dispatch_event(
                event_type="dispatch_end",
                tool_name="verify_hypothesis",
                correlation_id=corr_id,
                status=res.get("status", "inconclusive"),
            )
            return res
        if record_reason:
            reason = f"inconsistent_verification_record: {record_reason}; automatic replay was suppressed"
        elif recorded is not None or ledger_error:
            reason = "unverifiable_checkpoint: deterministic verification ledger is unreadable or inconsistent; automatic replay was suppressed"
        else:
            reason = result.get("reason") or "scanner could not complete deterministic verification"
        self._record_hypothesis_outcome(hypothesis_id, "inconclusive", reason, work_id=scheduled["work_id"])
        self.harness.record_dispatch_event(
            event_type="dispatch_end",
            tool_name="verify_hypothesis",
            correlation_id=corr_id,
            status="inconclusive",
            reason=reason,
        )
        return {"status": "inconclusive", "reason": reason, "hypothesis_id": hypothesis_id, "work_id": scheduled["work_id"]}

    def register_hypothesis(self, hypothesis: dict) -> str:
        safe = dict(hypothesis)
        requested_point_id = str(safe.get("injection_point_id", ""))
        if requested_point_id:
            point, _ = self._resolve(requested_point_id)
            safe["injection_point_id"] = requested_point_id if point is not None else ""
        else:
            matches = [pid for pid, raw in self.points.items()
                       if isinstance(raw, dict) and raw.get("url") == safe.get("url")
                       and raw.get("parameter_id") == safe.get("field_name")
                       and self._resolve(pid)[0] is not None]
            safe["injection_point_id"] = matches[0] if len(matches) == 1 else ""
        hypothesis_id = str(safe.get("candidate_id") or hashlib.sha256(json.dumps(safe, sort_keys=True).encode()).hexdigest()[:20])
        safe["candidate_id"] = hypothesis_id
        self.harness.note_hypotheses([safe])
        return str(safe["injection_point_id"])

    def _record_hypothesis_outcome(
        self, hypothesis_id: str, outcome: str, reason: str, *, work_id: str = "",
        injection_point_id: str = "",
    ) -> None:
        # Checkpoint は信頼されたローカル状態であり、書込み権限者による整合した偽造は防御対象外。
        confirmed = outcome == "confirmed"
        point_id = injection_point_id or next((str(item.get("injection_point_id", ""))
            for item in self.harness.state.hypotheses
            if str(item.get("candidate_id", "")) == hypothesis_id), "")
        head_id = self._current_head_id()
        if confirmed and (not work_id or not point_id or not head_id):
            confirmed = False
            outcome = "inconclusive"
            reason = reason or "unverifiable_checkpoint: verification identifiers are incomplete"
        binding = None
        binding_digest = ""
        point, metadata = self._resolve(point_id) if point_id else (None, None)
        hypothesis = next((item for item in self.harness.state.hypotheses
                           if str(item.get("candidate_id", "")) == hypothesis_id), {})
        if point is not None and metadata is not None:
            binding = self._verification_binding(point, metadata, str(hypothesis.get("check_type", "")))
            binding_digest = self._binding_digest(binding)
        work = next((item for item in self.harness.state.work_queue if item.work_id == work_id), None) if work_id else None
        evidence_ids = tuple(work.evidence_ids) if confirmed and work is not None else ()
        if confirmed and not evidence_ids:
            confirmed = False
            outcome = "inconclusive"
            reason = reason or "inconsistent_verification_record: confirmed outcome has no scanner finding evidence"
        self.harness.record_verification(
            hypothesis_id, reproduced=confirmed, status=outcome,
            method="deterministic", work_id=work_id,
            scan_id=self.harness.state.run_id, head_id=head_id,
            injection_point_id=point_id, evidence_ids=evidence_ids,
            deterministic_confirmed=confirmed, rejection_reason=reason,
            binding=binding, binding_digest=binding_digest,
        )
        self.harness.update_hypothesis(
            hypothesis_id,
            status="deterministic_confirmed" if confirmed else "agent_only",
            verification_outcome=outcome,
            deterministic_confirmed=confirmed,
            source_label="agent_deterministic_confirmed" if confirmed else "agent_unverified",
            rejection_reason=reason,
        )

    def _current_head_id(self) -> str:
        try:
            return subprocess.check_output(
                ["git", "rev-parse", "HEAD"], cwd=Path(__file__).resolve().parents[1],
                stderr=subprocess.DEVNULL, text=True, timeout=2,
            ).strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    @staticmethod
    def _checkpoint_claims_confirmation(hypothesis: dict) -> bool:
        return bool(
            hypothesis.get("deterministic_confirmed")
            or hypothesis.get("verification_outcome") == "confirmed"
            or hypothesis.get("status") in {"confirmed", "deterministic_confirmed", "reproduced"}
            or hypothesis.get("source_label") == "agent_deterministic_confirmed"
        )

    def _downgrade_unverifiable(self, hypothesis_id: str, reason: str | None = None) -> None:
        self.harness.update_hypothesis(
            hypothesis_id, status="agent_only", verification_outcome="inconclusive",
            deterministic_confirmed=False, source_label="agent_unverified",
            rejection_reason=reason or "unverifiable_checkpoint: deterministic ledger evidence is missing or inconsistent",
        )

    def _restore_hypothesis_outcome(self, hypothesis_id: str, record: dict) -> None:
        outcome = str(record.get("status", "inconclusive"))
        confirmed = outcome == "confirmed"
        self.harness.update_hypothesis(
            hypothesis_id,
            status="deterministic_confirmed" if confirmed else "agent_only",
            verification_outcome=outcome,
            deterministic_confirmed=confirmed,
            source_label="agent_deterministic_confirmed" if confirmed else "agent_unverified",
            rejection_reason=str(record.get("rejection_reason", "")),
        )

    def _verification_is_trustworthy(self, record: dict, hypothesis: dict) -> bool:
        return not self._verification_consistency_reason(record, hypothesis)

    def _verification_consistency_reason(self, record: dict, hypothesis: dict) -> str:
        point_id = str(hypothesis.get("injection_point_id", ""))
        point, metadata = self._resolve(point_id)
        if point is None or metadata is None:
            return "unknown injection point"
        if (
            not isinstance(record.get("verification_id"), str) or not record.get("verification_id")
            or not isinstance(record.get("work_id"), str) or not record.get("work_id")
            or record.get("candidate_id") != hypothesis.get("candidate_id")
            or record.get("injection_point_id") != point_id
            or record.get("method") != "deterministic"
        ):
            return "verification identifiers are incomplete or inconsistent"
        if not isinstance(record.get("binding"), dict):
            return "verification binding is missing"
        ledger_binding = dict(record["binding"])
        # Legacy scalar columns remain for reporting; fold them into the single binding hash.
        ledger_binding["scan_id"] = str(record.get("scan_id", ""))
        ledger_binding["code_head"] = str(record.get("head_id", ""))
        record = {**record, "binding": ledger_binding}
        expected_binding = self._verification_binding(point, metadata, str(hypothesis.get("check_type", "")))
        work = next((item for item in self.harness.state.work_queue if item.work_id == record.get("work_id")), None)
        if (
            work is None or work.target != point_id
            or work.check_type != hypothesis.get("check_type")
        ):
            return "scanner work does not match the hypothesis"
        outcome = record.get("status")
        if outcome in {"confirmed", "rejected"} and work.status != WorkStatus.COMPLETE:
            return "scanner work is not complete"
        if outcome == "inconclusive" and work.status not in {WorkStatus.INCONCLUSIVE, WorkStatus.COMPLETE}:
            return "scanner work is not complete"
        consistency_reason = _verification_consistency_reason(
            record,
            expected_binding=expected_binding,
            injection_point_id=point_id,
            check_type=str(hypothesis.get("check_type", "")),
            scanner_evidence=self.harness.state.scanner_evidence,
            work_evidence_ids=tuple(work.evidence_ids),
        )
        if consistency_reason:
            return consistency_reason
        probe_status = "completed" if outcome in {"confirmed", "rejected"} else None
        if not self._probe_evidence_matches(record, outcome=probe_status):
            return "scanner probe evidence is missing or inconsistent"
        return ""

    def _probe_evidence_matches(self, verification: dict, *, outcome: str | None) -> bool:
        path = self.harness.probe_attempts_path
        if not path.exists():
            return False
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                attempt = json.loads(line)
                if (
                    attempt.get("work_id") == verification.get("work_id")
                    and attempt.get("evidence_id") == verification.get("work_id")
                    and (outcome is None or attempt.get("status") == outcome)
                ):
                    point_id = str(next((item.get("injection_point_id") for item in self.harness.state.hypotheses
                                         if item.get("candidate_id") == verification.get("candidate_id")), ""))
                    point, metadata = self._resolve(point_id)
                    if point is None or metadata is None:
                        return False
                    expected = self._verification_binding(
                        point, metadata, str(next((item.get("check_type") for item in self.harness.state.hypotheses
                                                  if item.get("candidate_id") == verification.get("candidate_id")), "")),
                    )
                    # Probe destination is independently observed from the persisted request record.
                    if not isinstance(attempt.get("binding"), dict):
                        return False
                    probe_binding = dict(attempt["binding"])
                    from wscan.request_logger import redact_url
                    probe_binding["endpoint_identity"] = endpoint_identity(redact_url(str(attempt.get("target_url", ""))))
                    probe_binding["check"] = str(attempt.get("check_type", ""))
                    probe_binding["scan_id"] = str(attempt.get("run_id", ""))
                    if (
                        not attempt.get("binding_digest")
                        or self._binding_digest(probe_binding) != attempt.get("binding_digest")
                        or attempt.get("binding_digest") != self._binding_digest(expected)
                        or not self._recorded_target_in_scope(str(attempt.get("target_url", "")))
                    ):
                        return False
                    return True
            return False
        except (OSError, ValueError, AttributeError):
            return False

    @staticmethod
    def _binding_digest(binding: dict) -> str:
        canonical = json.dumps(binding, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def _verification_binding(self, point: InjectionPoint, metadata: dict, check: str) -> dict:
        from wscan.request_logger import redact_url
        # Only the endpoint identity is persisted; query secrets are redacted before canonicalization.
        endpoint = endpoint_identity(redact_url(point.url))
        carrier = str(point.carrier.value)
        parameter_identity = {
            "parameter_id": str(metadata.get("parameter_id", point.parameter_id)),
            "form_index": int(point.form_index) if carrier == "form" else None,
            "method": str(point.method or "").upper() if carrier in ("form", "json") else "",
            "action_identity": endpoint_identity(redact_url(point.action)) if carrier == "form" and point.action else "",
        }
        return {
            "endpoint_identity": endpoint,
            "carrier": carrier,
            "parameter_identity": parameter_identity,
            "check": str(check),
            "scan_id": str(self.harness.state.run_id),
            "code_head": self._current_head_id(),
        }

    def _recorded_target_in_scope(self, target_url: str) -> bool:
        from wscan.llm_agent_browser import _url_is_excluded, security_probe_allowed
        args = self.scanner
        return bool(
            target_url
            and not _url_is_excluded(target_url, args.exclude_urls)
            and security_probe_allowed(target_url, args.target_urls, args.exclude_urls,
                                       access_urls=args.access_urls)
            and evaluate_scope(target_url, ScopePolicy(
                target_urls=tuple(args.target_urls), access_urls=tuple(args.access_urls),
                exclude_urls=tuple(args.exclude_urls), login_url=args.login_url,
            )).reason in {"target_url", "target_url_no_frag", "target_url_no_query"}
        )

    def _mark_hypotheses(self, point_id: str, check: str, outcome: str, reason: str, *, work_id: str = "") -> None:
        for hypothesis in self.harness.state.hypotheses:
            if hypothesis.get("injection_point_id") == point_id and hypothesis.get("check_type") == check:
                self._record_hypothesis_outcome(str(hypothesis.get("candidate_id", "")), outcome, reason, work_id=work_id)

    def _verification_record(self, candidate_id: str) -> tuple[dict | None, bool]:
        path = self.harness.verification_results_path
        if not path.exists():
            return None, False
        latest = None
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("candidate_id") == candidate_id and record.get("method") == "deterministic":
                    latest = record
            return latest, False
        except (OSError, ValueError, AttributeError):
            return None, True

    @staticmethod
    def _verification_result(candidate_id: str, record: dict) -> dict:
        outcome = str(record.get("status", "inconclusive"))
        result = {"status": outcome, "hypothesis_id": candidate_id}
        if record.get("rejection_reason"):
            result["reason"] = record["rejection_reason"]
        return result

    def _already_dispatched(self, work_id: str) -> bool:
        path = self.harness.probe_attempts_path
        if not path.exists():
            return False
        try:
            for line in path.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                record = json.loads(line)
                if record.get("work_id") == work_id and record.get("status") in {"dispatching", "sent"}:
                    return True
            return False
        except (OSError, ValueError, AttributeError):
            return True

    def _record_scope_block(self, _url: str, reason: str) -> None:
        gap = f"scanner_network_scope_blocked:{reason}"
        self.harness.note_coverage(coverage_gaps=[*self.harness.state.coverage_gaps, gap])

    def _sanitize_findings(self, findings: list) -> list:
        from wscan.llm_agent_browser import AgentFinding
        from wscan.request_logger import redact_text, redact_url
        result = []
        for finding in findings:
            result.append(AgentFinding(
                check_type=finding.check_type, severity=finding.severity, url=redact_url(finding.url),
                field_name=redact_text(finding.field_name), payload=redact_text(finding.payload),
                evidence=redact_text(finding.evidence), source="deterministic", agent_verified=True,
                deterministic_confirmed=True,
            ))
        return result

    def _persist_scanner_evidence(
        self, work_id: str, point_id: str, check: str, binding_digest: str, findings: list,
    ) -> list[str]:
        evidence_ids = []
        for index, finding in enumerate(findings):
            finding_dict = finding.to_dict()
            canonical = json.dumps(
                {"work_id": work_id, "binding_digest": binding_digest,
                 "index": index, "finding": finding_dict},
                sort_keys=True, separators=(",", ":"), ensure_ascii=True,
            )
            evidence_id = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
            self.harness.record_scanner_evidence({
                "evidence_id": evidence_id,
                "work_id": work_id,
                "injection_point_id": point_id,
                "check_type": check,
                "binding_digest": binding_digest,
                "finding": finding_dict,
            })
            evidence_ids.append(evidence_id)
        return evidence_ids

    def agent_findings(self) -> list:
        return [finding for findings in self.findings.values() for finding in findings]

    def register_controller_actions(self, controller) -> None:
        async def list_scanner_capabilities() -> dict:
            return await self.list_scanner_capabilities()

        def schedule_scanner(injection_point_id: str, check: str) -> dict:
            return self.schedule_scanner(injection_point_id, check)

        async def run_scanner_work(work_id: str) -> dict:
            return await self.run_scanner_work(work_id)

        async def verify_hypothesis(hypothesis_id: str) -> dict:
            return await self.verify_hypothesis(hypothesis_id)

        controller.action("List server-discovered scanner injection points and capabilities.")(list_scanner_capabilities)
        controller.action("Queue deterministic scanner work by injection point ID and check name.")(schedule_scanner)
        controller.action("Run queued scanner work by work ID.")(run_scanner_work)
        controller.action("Queue deterministic verification for a hypothesis ID.")(verify_hypothesis)

    async def dispatch_tool(self, tool_name: str, **kwargs) -> dict:
        """Route tool invocation through authorization and lifecycle telemetry."""
        corr_id = str(kwargs.get("correlation_id") or f"corr_{secrets.token_hex(4)}")
        if tool_name not in {
            "list_scanner_capabilities",
            "schedule_scanner",
            "run_scanner_work",
            "verify_hypothesis",
        }:
            self.harness.record_dispatch_event(
                event_type="tool_request",
                tool_name=tool_name,
                correlation_id=corr_id,
            )
            self.harness.record_dispatch_event(
                event_type="authorization_decision",
                tool_name=tool_name,
                correlation_id=corr_id,
                allowed=False,
                reason=f"unauthorized tool: {tool_name}",
            )
            return {"status": "blocked", "reason": f"unauthorized tool: {tool_name}"}

        if tool_name == "list_scanner_capabilities":
            return await self.list_scanner_capabilities(correlation_id=corr_id)
        elif tool_name == "schedule_scanner":
            return self.schedule_scanner(
                str(kwargs.get("injection_point_id", "")),
                str(kwargs.get("check", "")),
                correlation_id=corr_id,
            )
        elif tool_name == "run_scanner_work":
            return await self.run_scanner_work(
                str(kwargs.get("work_id", "")),
                correlation_id=corr_id,
            )
        elif tool_name == "verify_hypothesis":
            return await self.verify_hypothesis(
                str(kwargs.get("hypothesis_id", "")),
                correlation_id=corr_id,
            )
        return {"status": "blocked", "reason": "unknown tool"}

    async def observe_page(self, browser=None, current_url: str = "") -> None:
        browser = browser or self.scanner._active_session
        if browser is None or not callable(getattr(browser, "get_current_page", None)):
            return
        try:
            page = await browser.get_current_page()
            if page is None or not callable(getattr(page, "evaluate", None)):
                return
            url = str(current_url or getattr(page, "url", "") or "")
            data = await page.evaluate("""() => [...document.forms].map((f, i) => ({i, action:f.action || location.href, method:(f.method||'GET').toUpperCase(), fields:[...f.elements].filter(e=>e.name).map(e=>({name:e.name,type:e.type||'text'}))}))""")
            parsed = urlsplit(url)
            for name, _ in parse_qsl(parsed.query, keep_blank_values=True):
                point = InjectionPoint.for_url_param(url, name)
                point_id = self.add_point(point, {"name": name, "type": "text"})
                self.schedule_baselines(point_ids=(point_id,))
            for form in data or []:
                action = str(form.get("action") or url)
                for field in form.get("fields", []):
                    name = str(field.get("name") or "")
                    if not name:
                        continue
                    point = InjectionPoint.for_form(url, name, int(form.get("i", 0)), method=form.get("method", "GET"), action=action)
                    point_id = self.add_point(point, field)
                    self.schedule_baselines(point_ids=(point_id,))
        except Exception:
            self.harness.note_coverage(coverage_gaps=["injection_point_discovery_failed"])

    async def _current_page_url(self) -> str:
        """Agent セッションの現在ページの URL（取れなければ空）。"""
        session = self.scanner._active_session
        get_page = getattr(session, "get_current_page", None)
        if not callable(get_page):
            return ""
        page = await get_page()
        return str(getattr(page, "url", "") or "")

    def _handoff(self, cookies):
        from wscan.agent_engine import AgentHandoffData
        return AgentHandoffData(cookies=[dict(cookie) for cookie in cookies])

    def _new_engine(self, check, handoff):
        from wscan.engine import ScanEngine
        extra_headers = getattr(self.scanner, "extra_headers", None) or {}
        headers = {
            key: value for key, value in extra_headers.items()
            if str(key).lower() != "cookie"
        }
        return ScanEngine(
            self.scanner.target_url, checks=[check], headless=True, open_report=False,
            output_dir=str(Path(self.harness.output_dir) / "scanner-actions"),
            target_urls=self.scanner.target_urls, access_urls=self.scanner.access_urls,
            exclude_urls=self.scanner.exclude_urls, exclude_fields=self.scanner.exclude_fields,
            handoff_cookies=handoff.cookies, proxy=self.scanner.proxy,
            auth_user=self.scanner.auth_user, auth_pass=self.scanner.auth_pass,
            login_url=self.scanner.login_url, headers=headers,
        )
