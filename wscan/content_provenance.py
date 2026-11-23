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
import re
from typing import Any


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
            "sanitized_content": self.sanitized_content,
        }

    def format_tagged_block(self) -> str:
        """Format content into an untrusted target delimiter block with breakout escaping."""
        body = self.sanitized_content if self.sanitized_content != "" else self.content
        escaped_body = re.sub(
            r"<\s*/\s*untrusted_target_data\s*>",
            "&lt;/untrusted_target_data&gt;",
            body,
            flags=re.IGNORECASE,
        )
        inj_detected = "true" if self.injection_signals else "false"
        attrs = [
            f'source="{escape_html(self.source, quote=True)}"',
            f'origin="{escape_html(self.origin, quote=True)}"',
            f'trust="{escape_html(self.trust, quote=True)}"',
            f'content_type="{escape_html(self.content_type, quote=True)}"',
            f'correlation_id="{escape_html(self.correlation_id, quote=True)}"',
            f'injection_detected="{inj_detected}"',
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
    from .request_logger import redact_text

    raw_text = redact_text(source_text)
    safe_origin = url_scope.redact_url(str(origin or ""), drop_userinfo=True)

    # Length truncation (preserve observation up to max_len)
    if max_len is not None and max_len > 0:
        text = raw_text[:max_len]
    else:
        text = raw_text

    # Neutralize code fence breakout attempts
    sanitized = text.replace("```", "'''")

    # Neutralize envelope closing tag breakout attempts
    sanitized = re.sub(
        r"<\s*/\s*untrusted_target_data\s*>",
        "&lt;/untrusted_target_data&gt;",
        sanitized,
        flags=re.IGNORECASE,
    )

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
        sanitized_content=sanitized,
    )
