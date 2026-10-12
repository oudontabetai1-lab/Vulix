"""JSON body 注入（xss / nosql）の判定ロジック。LLM・HTTP・ブラウザ非依存の純粋関数。

通常ツール層（確実性基準）の判定をスキャナ本体から分離し、送信なしでテストできるようにする。
スキャナ側は送信（`_apply_ip`）と Finding 化だけを担い、「陽性か」はここで決める。
"""
from __future__ import annotations

import html
import re
from dataclasses import dataclass
from typing import Mapping, Optional, Sequence

# レスポンスをブラウザが HTML として描画する content-type。application/json や text/plain の
# 反射は DOM シンク（別問題）であって JSON API 単体の XSS ではないので採らない。
_HTML_MEDIA_TYPES = frozenset({"text/html", "application/xhtml+xml"})

# (HTTP status, 本文)。status が不明（transport 失敗等）なら None。
Response = tuple[Optional[int], str]


def boolean_expansion(
    baseline_src: str,
    probe_src: str,
    baseline_src2: str = "",
) -> tuple[bool, dict]:
    """probe 応答が baseline より有意に膨らんだか（baseline 自然揺らぎ・25%・500B で閾値化）。"""
    baseline_len = len(baseline_src or "")
    probe_len = len(probe_src or "")
    baseline_variance = abs(baseline_len - len(baseline_src2 or "")) if baseline_src2 else 0
    delta = probe_len - baseline_len
    min_delta = max(500, int(baseline_len * 0.25), baseline_variance * 4)
    return (
        bool(baseline_len > 0 and delta > min_delta),
        {
            "baseline_length": baseline_len,
            "probe_length": probe_len,
            "delta": delta,
            "baseline_variance": baseline_variance,
            "min_delta": min_delta,
        },
    )


@dataclass(frozen=True)
class NosqlJsonVerdict:
    evidence_type: str  # "nosql_error" | "nosql_boolean"
    evidence: str
    details: dict


def response_of(source: str, pair: Mapping) -> Response:
    """`_apply_ip` の戻り値 (source, pair) を (status, 本文) に正規化する。送信失敗は (None, "")。"""
    resp = (pair or {}).get("response") or {}
    status = resp.get("status")
    body = resp.get("body")
    return (
        status if isinstance(status, int) else None,
        str(body if body is not None else (source or "")),
    )


def _first_match(body: str, patterns: Sequence[str]) -> str:
    for pattern in patterns:
        m = re.search(pattern, body or "", re.IGNORECASE | re.DOTALL)
        if m:
            return m.group(0)[:200]
    return ""


def _is_2xx(status: Optional[int]) -> bool:
    return status is not None and 200 <= status < 300


def nosql_json_verdict(
    baseline: Response,
    baseline2: Response,
    probe: Response,
    error_patterns: Sequence[str],
) -> Optional[NosqlJsonVerdict]:
    """構造化演算子（`{"$ne": ...}`）を JSON 値に差した probe の陽性判定。

    - error: probe にだけ Mongo 系エラー文字列が出る（baseline 2 回のどちらにも無い）。
    - boolean: baseline・probe とも 2xx で、probe が baseline から有意に膨らむ。
      4xx/5xx の長い検証エラー本文を「膨張」と誤認しないため status を必須にする（FP 対策）。
    応答が取れない、または認証に失敗した場合は比較不能なので陰性。
    """
    b_status, b_body = baseline
    b2_status, b2_body = baseline2
    p_status, p_body = probe
    if any(status is None or status in (401, 403) for status in (b_status, b2_status, p_status)):
        return None

    err = _first_match(p_body, error_patterns)
    if err and not _first_match(b_body, error_patterns) and not _first_match(b2_body, error_patterns):
        return NosqlJsonVerdict(
            "nosql_error",
            f"NoSQL injection via JSON operator: MongoDB error '{err[:150]}' "
            "returned when a structured operator replaced the string value.",
            {"matched_error": err[:150]},
        )

    if all(_is_2xx(status) for status in (b_status, b2_status, p_status)):
        expanded, details = boolean_expansion(b_body, p_body, b2_body)
        if expanded:
            return NosqlJsonVerdict(
                "nosql_boolean",
                f"NoSQL injection (boolean-based, JSON operator): response size increased by "
                f"{details['delta']} bytes when a structured operator replaced the string value. "
                "Possible authentication bypass or data exfiltration.",
                details,
            )
    return None


def renderable_html_body(pair: Mapping) -> str:
    """応答が HTML として描画されるときだけ本文を返す（それ以外は空文字）。

    JSON API は入力をそのまま JSON 文字列で返すのが普通で、`<script>` が生で入っていても
    ブラウザは実行しない。反射 XSS として採るのは html / xhtml 応答に限る（FP 対策）。
    """
    resp = (pair or {}).get("response") or {}
    headers = resp.get("headers") or {}
    ctype = ""
    for name, value in headers.items():
        if str(name).lower() == "content-type":
            ctype = str(value or "")
            break
    media = ctype.split(";", 1)[0].strip().lower()
    return str(resp.get("body") or "") if media in _HTML_MEDIA_TYPES else ""


# Markers used to detect reflected payloads
XSS_MARKERS = [
    "<script>",
    "onerror=",
    "onload=",
    "onfocus=",
    "ontoggle=",
    "ontouchstart=",
    "onwheel=",
    "onpointerenter=",
    "onmouseover=",
    "onanimationend=",
    "javascript:",
    "<svg",
    "<img",
    "<iframe",
    "<body",
    "<input",
    "<video",
    "<audio",
    "<details",
    "<marquee",
    "alert(",
]

# Attributes whose value is a URL — a javascript: payload here executes even
# without breaking out of the quotes, so a reflection inside them stays
# dangerous.
_URL_ATTRS = {"href", "src", "action", "formaction", "xlink:href", "data", "poster"}

def analyze_xss_reflection(
    source: str, payload: str, baseline_source: str = ""
) -> dict:
    """
    Return structured reflection evidence.

    Reflection alone is not always executable XSS.  This classifies the
    reflected location so the report can distinguish executable-looking
    contexts from weaker text-node reflections.
    """
    if payload and len(payload) > 5 and payload in source:
        if baseline_source and source.count(payload) <= baseline_source.count(payload):
            return {}
        idx = source.find(payload)
        preceding = source.lower()[max(0, idx - 300):idx]
        if not (preceding.rfind("<!--") > preceding.rfind("-->")):
            context = _classify_reflection_context(source, idx)
            if _reflection_executable(source, idx, payload, payload, baseline_source, context):
                return {
                    "context": context,
                    "match": "full_payload",
                    "snippet": source[max(0, idx - 10):idx + len(payload) + 50],
                    "confidence": _confidence_for_context(context),
                    "raw_payload_present": True,
                    "baseline_marker_delta": None,
                }

    source_lower = source.lower()
    baseline_lower = baseline_source.lower() if baseline_source else ""
    payload_lower = payload.lower()

    for marker in XSS_MARKERS:
        marker_lower = marker.lower()
        if marker_lower not in payload_lower:
            continue
        if marker_lower not in source_lower:
            continue

        # Baseline comparison: skip if marker count did not increase after injection
        if baseline_lower:
            if source_lower.count(marker_lower) <= baseline_lower.count(marker_lower):
                continue  # No new occurrence introduced by the payload

        # Skip if only the HTML-encoded form is present (not the raw marker)
        encoded = html.escape(marker).lower()
        if encoded != marker_lower and encoded in source_lower and marker_lower not in source_lower:
            continue

        # Inspect *every* occurrence of the marker, not just the first. The
        # first one may be an inert escaped reflection (or, on a page whose own
        # UI carries the same handler code, a pre-existing executable handler),
        # while a genuinely injected executable occurrence sits later. Report
        # the first occurrence that is (a) not in a comment, (b) executable in
        # its context, and (c) NOT pre-existing in the baseline — so a page's
        # own handler is never mis-attributed to the payload regardless of
        # where it sits relative to the reflection.
        start = 0
        while True:
            idx = source_lower.find(marker_lower, start)
            if idx == -1:
                break
            start = idx + 1

            # Skip occurrences inside HTML comments (<!-- ... -->)
            preceding = source_lower[max(0, idx - 300):idx]
            if preceding.rfind("<!--") > preceding.rfind("-->"):
                continue

            context = _classify_reflection_context(source, idx)
            if not _reflection_executable(
                source, idx, payload, marker, baseline_source, context
            ):
                continue

            # Per-occurrence baseline newness: skip an occurrence whose
            # surrounding text already appears verbatim in the baseline (a
            # pre-existing page handler, not something the payload introduced).
            if baseline_lower:
                window = source_lower[max(0, idx - 40):idx + len(marker_lower) + 20]
                if window and window in baseline_lower:
                    continue

            delta = None
            if baseline_lower:
                delta = source_lower.count(marker_lower) - baseline_lower.count(marker_lower)
            return {
                "context": context,
                "match": marker,
                "snippet": source[max(0, idx - 20):idx + len(marker) + 50],
                "confidence": _confidence_for_context(context),
                "raw_payload_present": False,
                "baseline_marker_delta": delta,
            }

    return {}

def _reflection_executable(
    source: str,
    idx: int,
    payload: str,
    matched: str,
    baseline_source: str,
    context: str,
) -> bool:
    """Decide whether a reflection at ``idx`` can actually execute.

    Reflection alone is not XSS: a correctly-escaped page echoes the payload
    but neutralises the characters that would let it break out. ``matched``
    is the token confirmed present *raw* at ``idx`` (the whole payload, or a
    single marker), and ``page.content()`` is the browser's serialised DOM,
    so the trustworthy signals are:

    * ``matched`` carries a raw ``<`` — a real tag/element was formed
      (escaped output keeps ``&lt;``, and a serialised text node re-escapes
      ``<``, so a raw ``<`` in the matched token means a live tag);
    * the reflection sits in an inherently executable position — a
      ``<script>`` body, an unquoted ``on*`` handler, or a URL attribute;
    * inside a quoted attribute value, only an ``on*`` handler / URL
      attribute, or the value's delimiting quote actually being broken.

    Bare markers (``alert(``, ``onload=`` …) and quote / backtick characters
    survive ``html.escape`` and even reappear raw inside serialised attribute
    values, so they are treated as data unless one of the signals above
    holds. This is what suppresses ``value="&quot; onmouseover=alert(1)"``
    and ``Hello, &lt;script&gt;alert(1)`` false positives while still
    catching genuinely unescaped reflections.
    """
    if context == "html_comment":
        return False

    raw_tag = "<" in matched  # matched is confirmed present raw at idx

    owner, delim = _owning_quoted_attr(source, idx)
    if owner is not None:
        # idx sits inside a quoted attribute value: the token is data unless
        # the owning attribute itself runs script, the payload broke the
        # delimiting quote, or a real tag was formed. This stops the
        # classifier from mistaking ``value="… onmouseover=alert(1)"`` text
        # for a live event handler.
        if owner.startswith("on") or owner in _URL_ATTRS:
            return True
        if raw_tag:
            return True
        base_l = baseline_source.lower() if baseline_source else ""
        return bool(
            delim
            and delim in payload
            and base_l
            and source.count(delim) > baseline_source.count(delim)
        )

    # Not inside a quoted value: trust the positional classification — an
    # unquoted on*-handler, a <script> body, or a javascript: URL attribute
    # are executable regardless of structural characters.
    if context in ("script", "event_handler_attribute", "url_attribute"):
        return True
    # html_text / bare unquoted attribute: needs a real tag-opening bracket.
    return raw_tag

def _owning_quoted_attr(source: str, idx: int) -> tuple:
    """Resolve the quoted attribute value (if any) that contains ``idx``.

    Returns ``(attribute_name, delimiter_quote)`` when ``idx`` is inside an
    open, quoted attribute value, else ``(None, "")``. The attribute name is
    lower-cased; it is ``""`` when a delimiter is open but no name precedes
    it. Only raw quote characters are tracked, so an escaped ``&quot;`` does
    not look like a delimiter — which is exactly what distinguishes inert
    escaped output from a genuine attribute breakout.
    """
    lt = source.rfind("<", 0, idx)
    gt = source.rfind(">", 0, idx)
    if lt == -1 or (gt != -1 and gt > lt):
        return (None, "")  # not inside a tag
    seg = source[lt:idx]
    quote = None
    open_pos = -1
    for j, c in enumerate(seg):
        if quote:
            if c == quote:
                quote = None
        elif c in ('"', "'"):
            quote = c
            open_pos = j
    if quote is None:
        return (None, "")
    head = seg[:open_pos]
    m = re.search(r'([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*$', head)
    return (m.group(1).lower() if m else "", quote)

def _classify_reflection_context(source: str, idx: int) -> str:
    before = source[max(0, idx - 500):idx].lower()
    after = source[idx:idx + 500].lower()
    last_lt = before.rfind("<")
    last_gt = before.rfind(">")
    in_tag = last_lt > last_gt
    tag_fragment = before[last_lt:] if in_tag else ""

    if before.rfind("<!--") > before.rfind("-->"):
        return "html_comment"
    if "<script" in before and "</script" not in before.split("<script")[-1]:
        return "script"
    if in_tag:
        if re.search(r"\son[a-z]+\s*=\s*['\"]?$", tag_fragment):
            return "event_handler_attribute"
        if re.search(r"\s(?:href|src|action|formaction)\s*=\s*['\"]?$", tag_fragment):
            return "url_attribute"
        return "html_attribute"
    if after.startswith("</script"):
        return "script"
    return "html_text"

def _confidence_for_context(context: str) -> str:
    if context in {"script", "event_handler_attribute", "url_attribute"}:
        return "likely"
    if context in {"html_attribute", "html_text"}:
        return "tentative"
    return "tentative"
