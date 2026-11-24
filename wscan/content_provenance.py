"""Untrusted content provenance and prompt injection guard layer.

This module provides data structures and pure functions for tracking
the provenance and trust level of data ingested from target environments
(DOM, HTTP responses, console logs, web tools) and defending agent
workflows against prompt-injection and control-token spoofing.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from html import escape as escape_html
import json
import re
import unicodedata
from typing import Any
from urllib.parse import unquote_plus, urlsplit, urlunsplit


_PROMPT_URL_PATTERN = re.compile(r"(?i)\b[a-z][a-z0-9+.\-]*://[^\s<>\"']+")
_PROMPT_KEY_VALUE_PATTERN = re.compile(
    r'(?P<key>[^&?=;\s"\'<>]+)=(?P<value>[^&\s]*)'
)
_PROMPT_JSON_FIELD_PATTERN = re.compile(
    r'(?P<prefix>"(?P<key>(?:\\.|[^"\\])*)"\s*:\s*")'
    r'(?P<value>(?:\\.|[^"\\])*)(?P<suffix>")'
)
_UNTRUSTED_CLOSER_PATTERN = re.compile(
    r"<\s*/\s*untrusted_target_data\s*>", re.IGNORECASE
)
_PROMPT_SENSITIVE_KEY_TOKENS = (
    "jwt", "auth", "authorization", "bearer", "sid", "session",
    "apikey", "api_key", "key", "secret", "password", "passwd", "pwd",
    "signature", "sig", "credential", "access", "refresh", "id_token",
    "code", "otp", "token", "api-key", "client_secret", "private_key",
)
_JWT_VALUE_PATTERN = re.compile(r"(?<![A-Za-z0-9_-])eyJ[A-Za-z0-9_-]*\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
_BEARER_VALUE_PATTERN = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]+")

INJECTION_SIGNAL_NAMES = frozenset({
    "ignore_previous_instructions", "stop_scan_directive",
    "false_safe_declaration", "scope_expansion_override",
    "fake_completion_or_nonce_spoof",
})


def sanitize_injection_signal_details(values) -> list[dict[str, int | str]]:
    """Keep only known signal categories and non-negative character offsets."""
    if not isinstance(values, (list, tuple)):
        return []
    clean = []
    for item in values:
        if not isinstance(item, dict):
            continue
        pattern, start, end = item.get("pattern"), item.get("start"), item.get("end")
        if (pattern in INJECTION_SIGNAL_NAMES and type(start) is int and type(end) is int
                and 0 <= start <= end):
            clean.append({"pattern": pattern, "start": start, "end": end})
    return clean


def _is_sensitive_prompt_key(key: str, sensitive_tokens: tuple[str, ...]) -> bool:
    """Match secret names as complete normalized words, including camelCase parts."""
    decoded_key = key
    for _ in range(3):
        decoded = unquote_plus(decoded_key)
        if decoded == decoded_key:
            break
        decoded_key = decoded

    def words_for(value: str) -> list[str]:
        normalized = unicodedata.normalize("NFKC", value)
        normalized = re.sub(r"(?<=[a-z0-9])(?=[A-Z])", "_", normalized)
        return [word.casefold() for word in re.findall(r"[^\W_]+", normalized)]

    words = words_for(decoded_key)
    if words == ["response", "code"]:
        return False
    aliases = [
        words_for(name)
        for name in (*sensitive_tokens, *_PROMPT_SENSITIVE_KEY_TOKENS)
    ]
    return any(
        words[index:index + len(alias)] == alias
        for alias in aliases if alias
        for index in range(len(words) - len(alias) + 1)
    )


def _redact_prompt_origin(origin: str, url_scope) -> str:
    """Keep URL location metadata while discarding all query and fragment values."""
    safe = url_scope.redact_url(origin, drop_userinfo=True)
    parts = urlsplit(safe)
    query = "&".join(
        f"{key}={url_scope.REDACTED}" if separator else key
        for item in parts.query.split("&") if item
        for key, separator, _value in [item.partition("=")]
    )
    fragment = url_scope.REDACTED if parts.fragment else ""
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query, fragment))


def _redact_prompt_observation(text: str, url_scope) -> str:
    """Redact secrets in prompt observations while retaining following diagnostic text."""
    text = url_scope.redact_secret_values(text, encoded_layers=2)
    text = _JWT_VALUE_PATTERN.sub(url_scope.REDACTED, text)
    text = _BEARER_VALUE_PATTERN.sub(f"Bearer {url_scope.REDACTED}", text)
    text = _PROMPT_URL_PATTERN.sub(
        lambda match: _redact_prompt_origin(match.group(0), url_scope), text
    )
    sensitive_tokens = url_scope.SENSITIVE_KEY_TOKENS

    def redact_json_field(match: re.Match[str]) -> str:
        try:
            key = json.loads(f'"{match.group("key")}"')
        except (json.JSONDecodeError, TypeError):
            return match.group(0)
        if not _is_sensitive_prompt_key(key, sensitive_tokens):
            return match.group(0)
        return f"{match.group('prefix')}{url_scope.REDACTED}{match.group('suffix')}"

    text = _PROMPT_JSON_FIELD_PATTERN.sub(redact_json_field, text)

    def redact_key_value(match: re.Match[str]) -> str:
        key, value = match.group("key"), match.group("value")
        if not _is_sensitive_prompt_key(key, sensitive_tokens):
            return match.group(0)
        trailing_semicolons = len(value) - len(value.rstrip(";"))
        return f"{key}={url_scope.REDACTED}{';' * trailing_semicolons}"

    return _PROMPT_KEY_VALUE_PATTERN.sub(redact_key_value, text)


def _escape_nfkc_closers(text: str) -> str:
    """Escape source delimiter characters whenever NFKC could form an envelope closer."""
    normalized_chars: list[str] = []
    source_indices: list[int] = []
    for index, character in enumerate(text):
        compatibility_form = unicodedata.normalize("NFKC", character)
        normalized_chars.extend(compatibility_form)
        source_indices.extend([index] * len(compatibility_form))

    normalized = "".join(normalized_chars)
    delimiter_indices: dict[int, str] = {}
    for match in _UNTRUSTED_CLOSER_PATTERN.finditer(normalized):
        delimiter_indices[source_indices[match.start()]] = "&lt;"
        delimiter_indices[source_indices[match.end() - 1]] = "&gt;"
    if not delimiter_indices:
        return text
    return "".join(delimiter_indices.get(index, character) for index, character in enumerate(text))


class ContentSource(str, Enum):
    """Source origin of content processed by scanner and agent modules."""
    DOM = "dom"
    HTTP = "http"
    WEBMCP = "webmcp"
    CONSOLE = "console"
    USER_CONFIG = "user_config"
    VULIX_POLICY = "vulix_policy"
    WEB = "web"


class TrustLevel(str, Enum):
    """Trust hierarchy levels for input data."""
    SYSTEM = "system"
    OPERATOR = "operator"
    UNTRUSTED_TARGET = "untrusted-target"


class ContentType(str, Enum):
    """Semantic type of content payload."""
    INSTRUCTION = "instruction"
    OBSERVATION = "observation"
    EVIDENCE = "evidence"
    TOOL_OUTPUT = "tool-output"


_CONTROL_COMPLETION_TOKENS: tuple[str, ...] = (
    "AUTH COMPLETE",
    "EXPLORATION COMPLETE",
    "PROBE COMPLETE",
    "VERIFICATION COMPLETE",
    "REVIEW COMPLETE",
)

_IGNORE_PREVIOUS_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\s*/?\s*(?:system|instructions?|assistant|user)\b[^>]*>", re.IGNORECASE),
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier|initial)\s+(?:instructions?|directions?|context|prompts?|rules?|guidelines?)\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s*(?:instructions?|directions?|context|prompts?|rules?|guidelines?)?\b"),
    re.compile(r"(?i)\bforget\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|directions?|context|prompts?|rules?)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an)\b"),
    re.compile(r"(?i)\b(?:system|new)\s+(?:prompt|instructions?)\s*[:\s]"),
    re.compile(r"(?:前|これまでの?|過去の?|以前の?|既存の?)(?:指示|プロンプト|命令|ルール|ガイドライン)(?:を|は)?(?:すべて|全て)?(?:無視|忘れて|破棄|リセット|無効)"),
    re.compile(r"(?:指示|プロンプト|命令)(?:を|は)?(?:すべて|全て)?(?:無視|忘れて|破棄|リセット)"),
)

_STOP_SCAN_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:stop|abort|cancel|terminate|halt|end)\s+(?:the\s+|this\s+|all\s+)?(?:scans?|scanning|tests?|testing|audits?|penetration\s+tests?|probes?|assessments?)\b"),
    re.compile(r"(?i)\bdo\s+not\s+(?:test|scan|attack|probe|audit)\s+(?:this\s+)?(?:site|application|app|host|server|url|target)\b"),
    re.compile(r"(?i)\bcease\s+(?:all\s+)?(?:scans?|scanning|tests?|testing|probing)\b"),
    re.compile(r"(?:スキャン|検査|テスト|診断|ペネトレーションテスト|ペンテスト|侵入テスト)(?:を|は)?(?:直ちに|今すぐ)?(?:停止|中止|終了|やめろ|止めろ|破棄)"),
    re.compile(r"(?:このサイト|本サイト|当サイト|対象)(?:を|は|の)?(?:検査|テスト|スキャン)(?:を)?(?:しないで|するな|止めろ|中止)"),
    re.compile(r"(?:スキャン|検査|テスト)を(?:停止|中止|終了|止めろ)"),
)

_FALSE_SAFE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:this\s+(?:site|application|app|system|target)\s+is\s+(?:completely\s+|totally\s+|100%\s+)?safe|(?:completely|totally|100%)\s+safe)\b"),
    re.compile(r"(?i)\bno\s+vulnerabilit(?:y|ies)\s+(?:exist|exists|found|detected|present|remain|here)\b"),
    re.compile(r"(?i)\bno\s+security\s+(?:vulnerabilit(?:y|ies)|issues?|flaws?|risks?)\b"),
    re.compile(r"(?i)\b(?:zero|0)\s+vulnerabilities\b"),
    re.compile(r"(?i)\ball\s+vulnerabilities\s+resolved\b"),
    re.compile(r"(?:このサイト|本サイト|当サイト|対象)?(?:は)?(?:完全に|全く)?(?:安全|セキュア)(?:です|である)?"),
    re.compile(r"脆弱性(?:は|が)?(?:存在しませ|ありませ|検出されませ|ゼロ|ありません)"),
    re.compile(r"(?:脆弱性|セキュリティ上の問題|バグ)(?:は|が)?(?:一切|全く|全くもって)?(?:ありませ|存在しませ)"),
)

_SCOPE_OVERRIDE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\b(?:expand|broaden|extend|increase|widen)\s+(?:the\s+)?(?:target\s+)?scope\b"),
    re.compile(r"(?i)\bscope\s*(?:を|は)?\s*(?:広げろ|拡大|拡張)\b"),
    re.compile(r"(?i)\bauthorize\s+all\s+domains\b"),
    re.compile(r"(?i)\ballow\s+all\s+domains\b"),
    re.compile(r"(?i)\badd\s+(?:all\s+)?domains?\s+to\s+scope\b"),
    re.compile(r"(?i)\bATTACK\s+TARGETS\s*:"),
    re.compile(r"(?:スコープ|対象範囲|攻撃対象)(?:を|は)?(?:広げろ|拡大|拡張|全許可|全ドメイン)"),
    re.compile(r"(?:全ドメイン|すべてのドメイン|全てのドメイン)(?:を|は)?(?:許可|対象|スコープ)"),
)

_FAKE_COMPLETION_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"(?i)\bVULNERABILITY\s+(?:FOUND|CONFIRMED)\b"),
    re.compile(r"(?i)\bWSCAN-NONCE\s*:"),
    re.compile(r"(?i)\bAUTH\s+COMPLETE\b"),
    re.compile(r"(?i)\bEXPLORATION\s+COMPLETE\b"),
    re.compile(r"(?i)\bPROBE\s+COMPLETE\b"),
    re.compile(r"(?i)\bVERIFICATION\s+COMPLETE\b"),
    re.compile(r"(?i)\bREVIEW\s+COMPLETE\b"),
    re.compile(r"(?i)\b(?:BEGIN|END)_UNTRUSTED(?:_PAGE)?\b"),
)

_PROMPT_INJECTION_NEUTRALIZE_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"<\s*/?\s*(?:system|instructions?|assistant|user)\b[^>]*>", re.IGNORECASE),
    re.compile(r"(?i)\bignore\s+(?:all\s+)?(?:previous|prior|above|earlier|initial)\s+(?:instructions?|directions?|context|prompts?|rules?|guidelines?)\b"),
    re.compile(r"(?i)\bdisregard\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s*(?:instructions?|directions?|context|prompts?|rules?|guidelines?)?\b"),
    re.compile(r"(?i)\bforget\s+(?:all\s+)?(?:the\s+)?(?:previous|prior|above|earlier)\s+(?:instructions?|directions?|context|prompts?|rules?)\b"),
    re.compile(r"(?i)\byou\s+are\s+now\s+(?:a|an)\b"),
    re.compile(r"(?i)\b(?:system|new)\s+(?:prompt|instructions?)\s*[:\s]"),
    re.compile(r"(?i)\bVULNERABILITY\s+(?:FOUND|CONFIRMED)\b"),
    re.compile(r"(?i)\b(?:BEGIN|END)_UNTRUSTED(?:_PAGE)?\b"),
    re.compile(r"(?:前|これまでの?|過去の?|以前の?|既存の?)(?:指示|プロンプト|命令|ルール|ガイドライン)(?:を|は)?(?:すべて|全て)?(?:無視|忘れて|破棄|リセット|無効)"),
    re.compile(r"(?:指示|プロンプト|命令)(?:を|は)?(?:すべて|全て)?(?:無視|忘れて|破棄|リセット)"),
)


def detect_prompt_injection(text: str) -> list[str]:
    """Detect prompt injection and policy override patterns in untrusted text.

    Returns a list of matched signal category IDs:
    - ignore_previous_instructions
    - stop_scan_directive
    - false_safe_declaration
    - scope_expansion_override
    - fake_completion_or_nonce_spoof
    """
    if not text:
        return []

    signals: list[str] = []
    category_checks: list[tuple[str, tuple[re.Pattern[str], ...]]] = [
        ("ignore_previous_instructions", _IGNORE_PREVIOUS_PATTERNS),
        ("stop_scan_directive", _STOP_SCAN_PATTERNS),
        ("false_safe_declaration", _FALSE_SAFE_PATTERNS),
        ("scope_expansion_override", _SCOPE_OVERRIDE_PATTERNS),
        ("fake_completion_or_nonce_spoof", _FAKE_COMPLETION_PATTERNS),
    ]

    for cat_name, patterns in category_checks:
        for pat in patterns:
            if pat.search(text):
                signals.append(cat_name)
                break

    return signals


def detect_injection_signal_details(text: str) -> list[dict[str, int | str]]:
    """Return category and character offsets only; never retain matched text."""
    if not text:
        return []
    checks = (
        ("ignore_previous_instructions", _IGNORE_PREVIOUS_PATTERNS),
        ("stop_scan_directive", _STOP_SCAN_PATTERNS),
        ("false_safe_declaration", _FALSE_SAFE_PATTERNS),
        ("scope_expansion_override", _SCOPE_OVERRIDE_PATTERNS),
        ("fake_completion_or_nonce_spoof", _FAKE_COMPLETION_PATTERNS),
    )
    found = []
    for category, patterns in checks:
        for pattern in patterns:
            match = pattern.search(text)
            if match:
                found.append({"pattern": category, "start": match.start(), "end": match.end()})
                break
    return sanitize_injection_signal_details(found)


@dataclass
class ProvenanceEnvelope:
    """Envelope wrapping content with provenance metadata and injection guards."""
    content: str
    source: str
    origin: str
    trust: str
    content_type: str
    correlation_id: str = ""
    injection_signals: tuple[str, ...] = ()
    injection_signal_details: tuple[dict[str, int | str], ...] = ()
    sanitized_content: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Serialize envelope to dictionary."""
        return {
            "content": self.content,
            "source": self.source,
            "origin": self.origin,
            "trust": self.trust,
            "content_type": self.content_type,
            "correlation_id": self.correlation_id,
            "injection_signals": list(self.injection_signals),
            "injection_signal_details": [dict(item) for item in self.injection_signal_details],
            "sanitized_content": self.sanitized_content,
        }

    def format_tagged_block(self) -> str:
        """Format content into an untrusted target delimiter block with breakout escaping."""
        body = self.sanitized_content if self.sanitized_content != "" else self.content
        escaped_body = _escape_nfkc_closers(body)
        inj_detected = "true" if self.injection_signals else "false"
        attrs = [
            f'source="{escape_html(self.source, quote=True)}"',
            f'origin="{escape_html(self.origin, quote=True)}"',
            f'trust="{escape_html(self.trust, quote=True)}"',
            f'content_type="{escape_html(self.content_type, quote=True)}"',
            f'correlation_id="{escape_html(self.correlation_id, quote=True)}"',
            f'injection_detected="{inj_detected}"',
            f'injection_signals="{escape_html(",".join(self.injection_signals), quote=True)}"',
        ]
        attr_str = " ".join(attrs)
        if escaped_body:
            return f"<untrusted_target_data {attr_str}>\n{escaped_body}\n</untrusted_target_data>"
        return f"<untrusted_target_data {attr_str}></untrusted_target_data>"


def wrap_untrusted_observation(
    content: str,
    *,
    source: str = "http",
    origin: str = "",
    content_type: str = "observation",
    correlation_id: str = "",
    neutralize_control_tokens: bool = True,
    neutralize_injections: bool = True,
    max_len: int | None = None,
) -> ProvenanceEnvelope:
    """Wrap untrusted observation content into a ProvenanceEnvelope with sanitization."""
    source_text = str(content or "")
    signals = detect_prompt_injection(source_text)
    from . import url_scope

    raw_text = _redact_prompt_observation(source_text, url_scope)
    safe_origin = _redact_prompt_origin(str(origin or ""), url_scope)

    # Length truncation (preserve observation up to max_len)
    if max_len is not None and max_len > 0:
        text = raw_text[:max_len]
    else:
        text = raw_text

    # Neutralize code fence breakout attempts
    sanitized = text.replace("```", "'''")

    # Neutralize envelope closing tag breakout attempts
    sanitized = _escape_nfkc_closers(sanitized)

    # Neutralize spoofed nonce tokens: WSCAN-NONCE:... -> WSCAN-CANDIDATE
    sanitized = re.sub(
        r"(?i)WSCAN-NONCE:(?:\s*\S+)?",
        "WSCAN-CANDIDATE",
        sanitized,
    )

    # Neutralize spoofed completion tokens when requested
    if neutralize_control_tokens:
        for token in _CONTROL_COMPLETION_TOKENS:
            sanitized = re.sub(
                rf"(?i)\b{re.escape(token)}\b",
                f"[UNTRUSTED-TEXT: {token}]",
                sanitized,
            )

    # Neutralize prompt injection phrases when requested
    if neutralize_injections:
        for pat in _PROMPT_INJECTION_NEUTRALIZE_PATTERNS:
            sanitized = pat.sub("[REDACTED]", sanitized)

    return ProvenanceEnvelope(
        content=raw_text,
        source=str(source),
        origin=str(safe_origin or ""),
        trust=TrustLevel.UNTRUSTED_TARGET.value,
        content_type=str(content_type),
        correlation_id=str(correlation_id),
        injection_signals=tuple(signals),
        injection_signal_details=tuple(detect_injection_signal_details(source_text)),
        sanitized_content=sanitized,
    )
