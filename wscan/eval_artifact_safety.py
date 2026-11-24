#!/usr/bin/env python3
"""Fail-closed check for the two allowlisted public evaluation artifacts."""
from __future__ import annotations

import re
from pathlib import Path

from wscan import content_provenance, request_logger, url_scope

ALLOWED_NAMES = {"agent_eval_scorecard.json", "agent_eval_summary.md"}
_UNSAFE = (
    ("html_or_dom", re.compile(r"(?is)<\s*/?\s*(?:html|head|body|script|style|iframe|form|input|div|span|p|svg|article)\b|\b(?:outerHTML|innerHTML|document\.querySelector|<\s*\w+\s+[^>]*>)")),
    ("injection_text", re.compile(r"(?i)ignore\s+(?:all\s+)?previous\s+instructions|prompt\s+injection|report\s+this\s+page\s+as\s+safe|<svg\s*/?onload|javascript\s*:")),
    ("authorization_or_cookie", re.compile(r"(?im)\b(?:authorization|proxy-authorization|cookie|set-cookie)\s*[:=]\s*(?!<redacted>)[^\s,;]+")),
    ("credential", re.compile(r"(?i)\b(?:password|passwd|pwd|token|api[_-]?key|client_secret)\s*[:=]\s*(?!<redacted>)[^\s,;]+|\bBearer\s+(?!<redacted>)[A-Za-z0-9._~+/=-]{8,}|\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")),
    ("provider_secret", re.compile(r"\b(?:sk-(?:ant|proj|live)-[A-Za-z0-9_-]{8,}|AIza[A-Za-z0-9_-]{20,})\b")),
    ("absolute_path", re.compile(r"(?<![A-Za-z0-9])(?:/(?:Users|home|private|tmp|var/tmp)/[^\s\"'<>]+|[A-Za-z]:\\Users\\[^\s\"'<>]+)")),
)


def check_artifacts(paths: list[str | Path]) -> None:
    if len(paths) != 2 or {Path(path).name for path in paths} != ALLOWED_NAMES:
        raise ValueError("only the scorecard JSON and summary Markdown are allowed")
    for path in paths:
        candidate = Path(path)
        text = candidate.read_text(encoding="utf-8")
        # Exercise shared redaction entry points; any registered raw secret still fails.
        shared_redacted = request_logger.redact_text(url_scope.redact_secret_values(text, encoded_layers=2))
        if shared_redacted != text:
            raise ValueError(f"registered secret found in {candidate.name}")
        if content_provenance.detect_prompt_injection(text):
            raise ValueError(f"unsafe injection_text found in {candidate.name}")
        for label, pattern in _UNSAFE:
            if pattern.search(text):
                raise ValueError(f"unsafe {label} found in {candidate.name}")
