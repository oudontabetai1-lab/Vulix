"""Bounded read-only JIT context builder and structured notes for Agent mode.

Extracts minimal high-signal evidence for the next agent decision with strict
item and character bounds, preserving evidence IDs and provenance wrapping
for untrusted target content. Structured notes (episode summaries and resume notes)
are stored atomically as part of the harness checkpoint.
"""
from __future__ import annotations

import logging
import math
import re
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from wscan.content_provenance import (
    ContentSource,
    ContentType,
    wrap_untrusted_observation,
)
from wscan.request_logger import redact_text, redact_url

logger = logging.getLogger(__name__)

_MAX_PENDING_WORK = 5
_MAX_HYPOTHESES = 5
_MAX_RECENT_RESULTS = 5
_MAX_COVERAGE_GAPS = 5
_MAX_EPISODE_NOTES = 10
_MAX_RESUME_NOTES = 5
_MAX_TOTAL_CHARS = 3500
_MAX_ITEM_SUMMARY_CHARS = 200

# Terminal work statuses that need no further execution
_TERMINAL_WORK_STATUSES = frozenset({
    "reproduced",
    "rejected",
    "inconclusive",
    "scope_blocked",
    "unreachable",
    "cancelled",
    "complete",
    "blocked",
    "failed",
})


def estimate_tokens(text: str) -> int:
    """決定論的な文字数ベースのトークン概算（4文字≒1トークン）。"""
    if not text:
        return 0
    return max(1, math.ceil(len(text) / 4))


def _safe_int(value: Any, default: int = 0) -> int:
    if value is None:
        raise ValueError("int cannot be None")
    try:
        return int(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid int value {value!r}: {exc}") from exc


def _safe_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        raise ValueError("float cannot be None")
    try:
        return float(value)
    except (ValueError, TypeError) as exc:
        raise ValueError(f"invalid float value {value!r}: {exc}") from exc


def bound_sections(title: str, sections: Sequence[tuple[str, Sequence[str]]], max_chars: int) -> str:
    """見出し＋項目を上限 ``max_chars`` 以内で連結する（純粋関数）。

    項目単位で採否を決めるため、項目内の untrusted envelope は常に完結したまま残る。
    収まらない項目は飛ばして後続の小さい項目を試し、落とした件数を末尾マーカーで示す。
    """
    full = title + "".join(
        "\n\n" + heading + "".join("\n" + item for item in items) for heading, items in sections
    )
    if len(full) <= max_chars:
        return full
    marker_tpl = "\n[...JIT context truncated] ({n} item(s) omitted)"
    budget = max(0, max_chars - len(marker_tpl.format(n=10**6)))
    out = title[:budget]
    omitted = 0
    for heading, items in sections:
        head_sep = "\n\n" + heading
        if len(out) + len(head_sep) > budget:
            omitted += len(items)
            continue
        kept: list[str] = []
        size = len(out) + len(head_sep)
        for item in items:
            piece = "\n" + item
            if size + len(piece) > budget:
                omitted += 1
                continue
            kept.append(piece)
            size += len(piece)
        if kept:
            out += head_sep + "".join(kept)
    if omitted:
        out += marker_tpl.format(n=omitted)
    # 上限が marker 長未満の極端な設定でも超えない（ここで切れるのは marker のみ）
    return out[:max_chars]


# reviewer が判断に使う高優先度の行（finding ブロック・gap 宣言・完了主張）。
# 行は対象由来なので線形時間で終わる形にする。旧形 `^\s*(?:…|[A-Z ]+ COMPLETE)` は
# \s* と [A-Z ]+ が空白で重なり、空白の長い行で二乗時間になった。完了主張は
# 「(最後の非空白 whitespace まで)? + [A-Z ]+」に分けて重なりを無くす（受理集合は同じ）。
_PRIORITY_EVIDENCE_RE = re.compile(
    r"^(?:\s*(?:WSCAN-NONCE|WSCAN-CANDIDATE|VULNERABILITY FOUND|Type|Severity|URL|Field|Payload|"
    r"Evidence|COVERAGE GAP|GAP RESOLVED)|(?:\s*[^\S ])?[A-Z ]+ COMPLETE)\b",
    re.IGNORECASE,
)
_FINDING_START_RE = re.compile(
    r"^\s*(?:WSCAN-NONCE|WSCAN-CANDIDATE|VULNERABILITY FOUND)\b",
    re.IGNORECASE,
)
_VULN_FOUND_RE = re.compile(r"^\s*VULNERABILITY FOUND\b", re.IGNORECASE)
_FINDING_FIELD_KEY_RE = re.compile(
    r"^\s*(Type|Severity|URL|Field|Payload|Evidence)\b",
    re.IGNORECASE,
)
_GAP_DECLARATION_RE = re.compile(
    r"^\s*(?:COVERAGE GAP|GAP RESOLVED)\b",
    re.IGNORECASE,
)
_MAX_REVIEWER_EVIDENCE_CHARS = 4000


def select_priority_evidence(texts: Sequence[str], max_chars: int = _MAX_REVIEWER_EVIDENCE_CHARS) -> str:
    """prior episode の出力から reviewer 用の優先証跡だけを上限内で選ぶ（純粋関数）。

    1) finding ブロック（WSCAN-NONCE / WSCAN-CANDIDATE / VULNERABILITY FOUND から始まる連続行の塊）と
       gap 宣言（COVERAGE GAP / GAP RESOLVED）を塊単位で優先して予算（max_chars）に収め、
       後半の雑多な単発 URL 行による押し出しやブロック途中の断裂を防ぐ。
    2) 残りの予算でその他の優先行（単発の完了主張や単発フィールド行）を新しい順に詰める。
    通常ログ行は JIT の ledger で代替するため含めない（12k 末尾切り詰めで発見行を失わない）。
    """
    if max_chars <= 0:
        return ""
    lines = "\n".join(str(t or "") for t in texts).splitlines()
    priority_chunks: list[list[int]] = []
    other_chunks: list[list[int]] = []
    idx = 0
    n = len(lines)
    while idx < n:
        line = lines[idx]
        if not _PRIORITY_EVIDENCE_RE.match(line):
            idx += 1
            continue
        if _FINDING_START_RE.match(line):
            block = [idx]
            idx += 1
            if not _VULN_FOUND_RE.match(line) and idx < n and _VULN_FOUND_RE.match(lines[idx]):
                block.append(idx)
                idx += 1
            seen_fields: set[str] = set()
            while idx < n:
                m_field = _FINDING_FIELD_KEY_RE.match(lines[idx])
                if not m_field:
                    break
                field_key = m_field.group(1).lower()
                if field_key in seen_fields:
                    break
                seen_fields.add(field_key)
                block.append(idx)
                idx += 1
            priority_chunks.append(block)
            continue
        if _GAP_DECLARATION_RE.match(line):
            priority_chunks.append([idx])
            idx += 1
            continue
        other_chunks.append([idx])
        idx += 1

    chosen: list[int] = []
    used = 0
    for group in (priority_chunks, other_chunks):
        for chunk in reversed(group):
            chunk_chars = sum(len(lines[i]) for i in chunk) + (len(chunk) - 1)
            sep = 1 if chosen else 0
            if used + sep + chunk_chars > max_chars:
                continue
            chosen.extend(chunk)
            used += sep + chunk_chars
    return "\n".join(lines[i] for i in sorted(chosen))


@dataclass(frozen=True)
class EpisodeNote:
    """1 episode の実行結果の要約ノート（checkpoint に原子保存）。"""
    episode_id: str
    work_id: str
    role: str
    status: str
    summary: str
    evidence_ids: tuple[str, ...] = ()
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_id": self.episode_id,
            "work_id": self.work_id,
            "role": self.role,
            "status": self.status,
            "summary": self.summary,
            "evidence_ids": list(self.evidence_ids),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "EpisodeNote | None":
        if not isinstance(data, Mapping):
            logger.warning("Discarding invalid episode note: expected mapping, got %s", type(data).__name__)
            return None
        try:
            ev = data.get("evidence_ids", ())
            if not isinstance(ev, (list, tuple)):
                ev = ()
            return cls(
                episode_id=str(data.get("episode_id", "") or ""),
                work_id=str(data.get("work_id", "") or ""),
                role=str(data.get("role", "") or ""),
                status=str(data.get("status", "") or ""),
                summary=str(data.get("summary", "") or ""),
                evidence_ids=tuple(str(x) for x in ev if x is not None),
                timestamp=_safe_float(data.get("timestamp", 0.0)),
            )
        except Exception as exc:
            logger.warning("Discarding corrupt episode note: %s (%r)", exc, data)
            return None


@dataclass(frozen=True)
class ResumeNote:
    """checkpoint から再開する際に再構成される状態要約ノート。"""
    run_id: str
    checkpoint_generation: int
    consumed_steps: int
    remaining_steps: int
    completed_work_count: int
    pending_work_count: int
    confirmed_findings_count: int
    unverified_hypotheses_count: int
    active_gaps: tuple[str, ...] = ()
    timestamp: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "checkpoint_generation": self.checkpoint_generation,
            "consumed_steps": self.consumed_steps,
            "remaining_steps": self.remaining_steps,
            "completed_work_count": self.completed_work_count,
            "pending_work_count": self.pending_work_count,
            "confirmed_findings_count": self.confirmed_findings_count,
            "unverified_hypotheses_count": self.unverified_hypotheses_count,
            "active_gaps": list(self.active_gaps),
            "timestamp": self.timestamp,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "ResumeNote | None":
        if not isinstance(data, Mapping):
            logger.warning("Discarding invalid resume note: expected mapping, got %s", type(data).__name__)
            return None
        try:
            gaps = data.get("active_gaps", ())
            if not isinstance(gaps, (list, tuple)):
                gaps = ()
            return cls(
                run_id=str(data.get("run_id", "") or ""),
                checkpoint_generation=_safe_int(data.get("checkpoint_generation", 0)),
                consumed_steps=_safe_int(data.get("consumed_steps", 0)),
                remaining_steps=_safe_int(data.get("remaining_steps", 0)),
                completed_work_count=_safe_int(data.get("completed_work_count", 0)),
                pending_work_count=_safe_int(data.get("pending_work_count", 0)),
                confirmed_findings_count=_safe_int(data.get("confirmed_findings_count", 0)),
                unverified_hypotheses_count=_safe_int(data.get("unverified_hypotheses_count", 0)),
                active_gaps=tuple(str(x) for x in gaps if x is not None),
                timestamp=_safe_float(data.get("timestamp", 0.0)),
            )
        except Exception as exc:
            logger.warning("Discarding corrupt resume note: %s (%r)", exc, data)
            return None


@dataclass
class AgentStructuredNotes:
    """構造化ノートの集合（checkpoint に含めて原子的に保存・再開）。"""
    episode_notes: list[EpisodeNote] = field(default_factory=list)
    resume_notes: list[ResumeNote] = field(default_factory=list)
    # from_dict で破棄した壊れたノート数（永続化しない。observability 用）
    discarded: int = field(default=0, compare=False)

    def add_episode_note(self, note: EpisodeNote) -> None:
        self.episode_notes.append(note)
        if len(self.episode_notes) > _MAX_EPISODE_NOTES:
            self.episode_notes = self.episode_notes[-_MAX_EPISODE_NOTES:]

    def add_resume_note(self, note: ResumeNote) -> None:
        self.resume_notes.append(note)
        if len(self.resume_notes) > _MAX_RESUME_NOTES:
            self.resume_notes = self.resume_notes[-_MAX_RESUME_NOTES:]

    def to_dict(self) -> dict[str, Any]:
        return {
            "episode_notes": [n.to_dict() for n in self.episode_notes],
            "resume_notes": [n.to_dict() for n in self.resume_notes],
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any] | None) -> "AgentStructuredNotes":
        if not data or not isinstance(data, Mapping):
            return cls()
        discarded = 0

        def _parse(key: str, note_cls: Any) -> list[Any]:
            nonlocal discarded
            raw = data.get(key, [])
            if not isinstance(raw, (list, tuple)):
                logger.warning("Discarding non-list %s: %s", key, type(raw).__name__)
                discarded += 1
                return []
            parsed = []
            for x in raw:
                note = note_cls.from_dict(x)
                if note is None:
                    discarded += 1
                else:
                    parsed.append(note)
            return parsed

        notes = cls(
            episode_notes=_parse("episode_notes", EpisodeNote),
            resume_notes=_parse("resume_notes", ResumeNote),
        )
        notes.discarded = discarded
        return notes


@dataclass(frozen=True)
class JitContextConfig:
    """JIT コンテキストビルダーの上限設定。"""
    max_pending_work: int = _MAX_PENDING_WORK
    max_hypotheses: int = _MAX_HYPOTHESES
    max_recent_results: int = _MAX_RECENT_RESULTS
    max_coverage_gaps: int = _MAX_COVERAGE_GAPS
    max_episode_notes: int = 5
    max_total_chars: int = _MAX_TOTAL_CHARS
    max_item_summary_chars: int = _MAX_ITEM_SUMMARY_CHARS


@dataclass
class JitContextBundle:
    """組み立てられた JIT コンテキスト（読み取り専用成果物）。"""
    pending_work: list[dict[str, Any]] = field(default_factory=list)
    hypotheses: list[dict[str, Any]] = field(default_factory=list)
    recent_results: list[dict[str, Any]] = field(default_factory=list)
    coverage_gaps: list[str] = field(default_factory=list)
    notes_summary: str = ""
    notes_items: list[str] = field(default_factory=list)
    evidence_ids: list[str] = field(default_factory=list)
    formatted_context: str = ""
    estimated_tokens: int = 0


class AgentJitContextBuilder:
    """Agent の次の判断に必要な小さな証拠だけを上限付きで組み立てるビルダー。

    - 読み取り専用（Harness や State の内部状態を変更しない）
    - evidence ID と provenance を保持
    - 対象サイト由来のテキストはすべて wrap_untrusted_observation でラップ
    - 秘密値は redact_text / secret_values で伏字化
    - 厳格な項目数上限と文字数上限を強制
    """

    def __init__(
        self,
        harness_or_state: Any,
        *,
        current_work: Any = None,
        target_url: str = "",
        secret_values: Iterable[str] = (),
        config: JitContextConfig | None = None,
    ) -> None:
        if hasattr(harness_or_state, "state"):
            self._state = harness_or_state.state
            self._harness = harness_or_state
            self._secret_values = getattr(harness_or_state, "_secret_values", ()) or tuple(secret_values)
        else:
            self._state = harness_or_state
            self._harness = None
            self._secret_values = tuple(secret_values)
        self.current_work = current_work
        self.target_url = target_url or getattr(getattr(self._harness, "spec", None), "target_url", "")
        self.config = config or JitContextConfig()

    def _redact_value(self, value: str) -> str:
        text = str(value or "")
        for s in self._secret_values:
            if s:
                text = text.replace(s, "<redacted>")
        return redact_text(text)

    def _wrap_untrusted(
        self,
        text: Any,
        *,
        source: str = ContentSource.HTTP.value,
        origin: str = "",
        content_type: str = ContentType.OBSERVATION.value,
        correlation_id: str = "",
        max_chars: int | None = None,
    ) -> str:
        """ビルダー側の単一チョークポイントとして untrusted テキストをラップする。"""
        raw = self._redact_value(str(text or ""))
        if max_chars is not None and len(raw) > max_chars:
            raw = raw[:max_chars]
        target_origin = origin or self.target_url or "http://target.test/"
        return wrap_untrusted_observation(
            raw,
            source=source,
            origin=target_origin,
            content_type=content_type,
            correlation_id=correlation_id,
        ).format_tagged_block()

    def build_context(self) -> JitContextBundle:
        bundle = JitContextBundle()
        evidence_ids: list[str] = []

        # 1. 構造化ノート（再開ノート ＋ 直近 episode 要約）
        notes_data = getattr(self._state, "notes", {})
        structured_notes = AgentStructuredNotes.from_dict(notes_data)
        notes_lines: list[str] = []
        if structured_notes.resume_notes:
            latest_resume = structured_notes.resume_notes[-1]
            notes_lines.append(
                f"[Resume checkpoint gen {latest_resume.checkpoint_generation}]: "
                f"{latest_resume.completed_work_count} completed, "
                f"{latest_resume.pending_work_count} pending work items, "
                f"{latest_resume.confirmed_findings_count} confirmed findings, "
                f"{latest_resume.unverified_hypotheses_count} unverified hypotheses."
            )
        recent_episodes = structured_notes.episode_notes[-self.config.max_episode_notes:]
        for ep in recent_episodes:
            ev_str = f" [evidence: {', '.join(ep.evidence_ids)}]" if ep.evidence_ids else ""
            wrapped_summary = self._wrap_untrusted(
                ep.summary,
                source=ContentSource.DOM.value,
                origin=self.target_url,
                content_type=ContentType.OBSERVATION.value,
                correlation_id=ep.episode_id,
                max_chars=self.config.max_item_summary_chars,
            )
            notes_lines.append(
                f"- Episode {ep.episode_id} ({ep.role}): status={ep.status}{ev_str}\n  summary: {wrapped_summary}"
            )
            evidence_ids.extend(ep.evidence_ids)
        bundle.notes_items = notes_lines
        bundle.notes_summary = "\n".join(notes_lines)

        # 2. 未完了 work の選定（上限あり、優先順位付け）
        pending_work_raw = [
            w for w in getattr(self._state, "work_queue", [])
            if (w.status.value if hasattr(w.status, "value") else str(w.status)) not in _TERMINAL_WORK_STATUSES
        ]
        curr_role = (
            getattr(self.current_work, "role", None).value
            if hasattr(getattr(self.current_work, "role", None), "value")
            else str(getattr(self.current_work, "role", "") or "")
        )
        curr_target = getattr(self.current_work, "target", "")

        def _work_priority(item):
            item_role = item.role.value if hasattr(item.role, "value") else str(item.role)
            role_match = 0 if item_role == curr_role else 1
            target_match = 0 if curr_target and item.target == curr_target else 1
            return (role_match, target_match, item.attempts, item.work_id)

        pending_work_raw.sort(key=_work_priority)
        selected_work = pending_work_raw[:self.config.max_pending_work]
        for w in selected_work:
            w_role = w.role.value if hasattr(w.role, "value") else str(w.role)
            w_status = w.status.value if hasattr(w.status, "value") else str(w.status)
            w_ev = list(w.evidence_ids) if hasattr(w, "evidence_ids") else []
            wrapped_target = self._wrap_untrusted(
                w.target,
                source=ContentSource.HTTP.value,
                origin=w.target,
                content_type=ContentType.OBSERVATION.value,
                correlation_id=w.work_id,
            )
            bundle.pending_work.append({
                "work_id": w.work_id,
                "role": w_role,
                "target": redact_url(w.target),
                "wrapped_target": wrapped_target,
                "check_type": w.check_type or "-",
                "status": w_status,
                "attempts": w.attempts,
                "evidence_ids": w_ev,
            })
            evidence_ids.extend(w_ev)

        # 3. 関連する仮説（上限あり、確証ラベル保持）
        hypotheses_raw = list(getattr(self._state, "hypotheses", []))

        def _hyp_priority(h):
            cid = str(h.get("candidate_id", ""))
            label = str(h.get("source_label", ""))
            is_confirmed = 0 if "confirmed" in label else 1
            matches_target = 0 if curr_target and curr_target in str(h.get("url", "")) else 1
            return (is_confirmed, matches_target, cid)

        hypotheses_raw.sort(key=_hyp_priority)
        selected_hypotheses = hypotheses_raw[:self.config.max_hypotheses]
        for hyp in selected_hypotheses:
            cid = str(hyp.get("candidate_id", ""))
            ev_list = [str(x) for x in hyp.get("evidence_ids", []) if str(x)]
            label = str(hyp.get("source_label", "agent_unverified"))
            target_url = str(hyp.get("url", "") or self.target_url)
            field_val = str(hyp.get("field_name", "-"))
            wrapped_url = self._wrap_untrusted(
                target_url,
                source=ContentSource.HTTP.value,
                origin=target_url,
                content_type=ContentType.OBSERVATION.value,
                correlation_id=cid,
            )
            wrapped_field = self._wrap_untrusted(
                field_val,
                source=ContentSource.DOM.value,
                origin=target_url,
                content_type=ContentType.OBSERVATION.value,
                correlation_id=cid,
                max_chars=self.config.max_item_summary_chars,
            )
            hyp_entry = {
                "candidate_id": cid,
                "url": redact_url(target_url),
                "wrapped_url": wrapped_url,
                "check_type": str(hyp.get("check_type", "-")),
                "field_name": field_val,
                "wrapped_field": wrapped_field,
                "source_label": label,
                "status": str(hyp.get("status", "proposed")),
                "evidence_ids": ev_list,
            }
            raw_obs = hyp.get("evidence") or hyp.get("payload") or ""
            if raw_obs:
                wrapped_evidence = self._wrap_untrusted(
                    raw_obs,
                    source=ContentSource.DOM.value,
                    origin=target_url,
                    content_type=ContentType.EVIDENCE.value,
                    correlation_id=cid,
                    max_chars=self.config.max_item_summary_chars,
                )
                hyp_entry["wrapped_evidence"] = wrapped_evidence
            bundle.hypotheses.append(hyp_entry)
            if cid:
                evidence_ids.append(cid)
            evidence_ids.extend(ev_list)

        # 4. 直近の確定結果（scanner_evidence）
        scanner_ev_raw = list(getattr(self._state, "scanner_evidence", []))
        selected_results = scanner_ev_raw[-self.config.max_recent_results:]
        for ev in reversed(selected_results):
            ev_id = str(ev.get("evidence_id", ""))
            corr_id = str(ev.get("correlation_id", ev_id))
            target_url = str(ev.get("url", "") or self.target_url)
            field_val = str(ev.get("field_name", "-"))
            wrapped_url = self._wrap_untrusted(
                target_url,
                source=ContentSource.HTTP.value,
                origin=target_url,
                content_type=ContentType.OBSERVATION.value,
                correlation_id=corr_id,
            )
            wrapped_field = self._wrap_untrusted(
                field_val,
                source=ContentSource.DOM.value,
                origin=target_url,
                content_type=ContentType.OBSERVATION.value,
                correlation_id=corr_id,
                max_chars=self.config.max_item_summary_chars,
            )
            res_entry = {
                "evidence_id": ev_id,
                "check_type": str(ev.get("check_type", "-")),
                "field_name": field_val,
                "url": redact_url(target_url),
                "wrapped_url": wrapped_url,
                "wrapped_field": wrapped_field,
                "status": str(ev.get("status", "confirmed")),
            }
            raw_detail = ev.get("details") or ev.get("detail") or ""
            if raw_detail:
                res_entry["wrapped_detail"] = self._wrap_untrusted(
                    raw_detail,
                    source=ContentSource.HTTP.value,
                    origin=target_url,
                    content_type=ContentType.EVIDENCE.value,
                    correlation_id=corr_id,
                    max_chars=self.config.max_item_summary_chars,
                )
            bundle.recent_results.append(res_entry)
            if ev_id:
                evidence_ids.append(ev_id)
            if corr_id:
                evidence_ids.append(corr_id)

        # 5. カバレッジギャップ（上限あり）
        gaps: list[str] = []
        for g in getattr(self._state, "coverage_gaps", []):
            safe_g = self._redact_value(str(g))[:self.config.max_item_summary_chars]
            if safe_g and safe_g not in gaps:
                gaps.append(safe_g)
        for g in getattr(self._state, "reviewer_gaps", []):
            safe_g = self._redact_value(str(g))[:self.config.max_item_summary_chars]
            if safe_g and safe_g not in gaps:
                gaps.append(safe_g)
        bundle.coverage_gaps = gaps[:self.config.max_coverage_gaps]

        # 6. 一意な evidence_ids を記録
        seen_ev = set()
        bundle.evidence_ids = []
        for e in evidence_ids:
            clean_e = str(e).strip()
            if clean_e and clean_e not in seen_ev:
                seen_ev.add(clean_e)
                bundle.evidence_ids.append(clean_e)

        # 7. プロンプト用テキストの整形と総文字数上限の強制
        bundle.formatted_context = self._format_and_bound(bundle)
        bundle.estimated_tokens = estimate_tokens(bundle.formatted_context)
        return bundle

    def _format_and_bound(self, bundle: JitContextBundle) -> str:
        # 各 section は (見出し, 項目リスト)。項目は完結した envelope を含む単位で、
        # 上限超過時は項目単位で落とす（文字列途中で切らない＝タグを壊さない）。
        sections: list[tuple[str, list[str]]] = []

        if bundle.notes_summary:
            sections.append(("### Structured Notes", bundle.notes_items))

        if bundle.pending_work:
            work_lines = [
                f"- work_id: {w['work_id']} | role: {w['role']} | check: {w['check_type']} | "
                f"status: {w['status']} | attempts: {w['attempts']}"
                + (f" [evidence: {', '.join(w['evidence_ids'])}]" if w['evidence_ids'] else "")
                + f"\n  target: {w['wrapped_target']}"
                for w in bundle.pending_work
            ]
            sections.append((f"### Pending Work Ledger ({len(bundle.pending_work)})", work_lines))
        else:
            sections.append(("### Pending Work Ledger", ["- (no pending work items)"]))

        if bundle.hypotheses:
            hyp_lines = []
            for h in bundle.hypotheses:
                line = (
                    f"- candidate_id: {h['candidate_id']} | check: {h['check_type']} | "
                    f"label: {h['source_label']} | status: {h['status']}\n"
                    f"  url: {h['wrapped_url']}\n"
                    f"  field: {h['wrapped_field']}"
                )
                if h.get("wrapped_evidence"):
                    line += "\n  evidence: " + h["wrapped_evidence"]
                hyp_lines.append(line)
            sections.append((f"### Hypotheses & Evidence ({len(bundle.hypotheses)})", hyp_lines))

        if bundle.recent_results:
            res_lines = []
            for r in bundle.recent_results:
                line = (
                    f"- evidence_id: {r['evidence_id']} | check: {r['check_type']} | status: {r['status']}\n"
                    f"  url: {r['wrapped_url']}\n"
                    f"  field: {r['wrapped_field']}"
                )
                if r.get("wrapped_detail"):
                    line += "\n  detail: " + r["wrapped_detail"]
                res_lines.append(line)
            sections.append((f"### Recent Confirmed Results ({len(bundle.recent_results)})", res_lines))

        if bundle.coverage_gaps:
            gap_lines = []
            for idx, g in enumerate(bundle.coverage_gaps):
                wg = self._wrap_untrusted(
                    g,
                    source=ContentSource.HTTP.value,
                    origin=self.target_url,
                    content_type=ContentType.OBSERVATION.value,
                    correlation_id=f"gap-{idx}",
                )
                gap_lines.append(f"- gap:\n  {wg}")
            sections.append((f"### Active Coverage Gaps ({len(bundle.coverage_gaps)})", gap_lines))

        return bound_sections(
            "## Just-In-Time Context & Structured Notes", sections, self.config.max_total_chars
        )

    def build_prompt_block(self) -> str:
        """Agent のタスクプロンプトに挿入可能な整形済みテキストを直接返す。"""
        return self.build_context().formatted_context
