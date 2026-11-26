"""Bounded read-only JIT context builder and structured notes for Agent mode.

Extracts minimal high-signal evidence for the next agent decision with strict
item and character bounds, preserving evidence IDs and provenance wrapping
for untrusted target content. Structured notes (episode summaries and resume notes)
are stored atomically as part of the harness checkpoint.
"""
from __future__ import annotations

import math
import time
from dataclasses import asdict, dataclass, field
from typing import Any, Iterable, Mapping, Sequence

from wscan.content_provenance import (
    ContentType,
    wrap_untrusted_observation,
)
from wscan.request_logger import redact_text, redact_url

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
    def from_dict(cls, data: Mapping[str, Any]) -> "EpisodeNote":
        ev = data.get("evidence_ids", ())
        return cls(
            episode_id=str(data.get("episode_id", "")),
            work_id=str(data.get("work_id", "")),
            role=str(data.get("role", "")),
            status=str(data.get("status", "")),
            summary=str(data.get("summary", "")),
            evidence_ids=tuple(str(x) for x in ev) if isinstance(ev, (list, tuple)) else (),
            timestamp=float(data.get("timestamp", 0.0)),
        )


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
    def from_dict(cls, data: Mapping[str, Any]) -> "ResumeNote":
        gaps = data.get("active_gaps", ())
        return cls(
            run_id=str(data.get("run_id", "")),
            checkpoint_generation=int(data.get("checkpoint_generation", 0)),
            consumed_steps=int(data.get("consumed_steps", 0)),
            remaining_steps=int(data.get("remaining_steps", 0)),
            completed_work_count=int(data.get("completed_work_count", 0)),
            pending_work_count=int(data.get("pending_work_count", 0)),
            confirmed_findings_count=int(data.get("confirmed_findings_count", 0)),
            unverified_hypotheses_count=int(data.get("unverified_hypotheses_count", 0)),
            active_gaps=tuple(str(x) for x in gaps) if isinstance(gaps, (list, tuple)) else (),
            timestamp=float(data.get("timestamp", 0.0)),
        )


@dataclass
class AgentStructuredNotes:
    """構造化ノートの集合（checkpoint に含めて原子的に保存・再開）。"""
    episode_notes: list[EpisodeNote] = field(default_factory=list)
    resume_notes: list[ResumeNote] = field(default_factory=list)

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
        episodes = [EpisodeNote.from_dict(x) for x in data.get("episode_notes", []) if isinstance(x, Mapping)]
        resumes = [ResumeNote.from_dict(x) for x in data.get("resume_notes", []) if isinstance(x, Mapping)]
        return cls(episode_notes=episodes, resume_notes=resumes)


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
    evidence_ids: list[str] = field(default_factory=list)
    formatted_context: str = ""
    estimated_tokens: int = 0


class AgentJitContextBuilder:
    """Agent の次の判断に必要な小さな証拠だけを上限付きで組み立てるビルダー。

    - 読み取り専用（Harness や State の内部状態を変更しない）
    - evidence ID と provenance を保持
    - 対象サイト由来のテキストは wrap_untrusted_observation でラップ
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
            safe_summary = self._redact_value(ep.summary)[:self.config.max_item_summary_chars]
            ev_str = f" [evidence: {', '.join(ep.evidence_ids)}]" if ep.evidence_ids else ""
            notes_lines.append(f"- Episode {ep.episode_id} ({ep.role}): status={ep.status} - {safe_summary}{ev_str}")
            evidence_ids.extend(ep.evidence_ids)
        bundle.notes_summary = "\n".join(notes_lines)

        # 2. 未完了 work の選定（上限あり、優先順位付け）
        pending_work_raw = [
            w for w in getattr(self._state, "work_queue", [])
            if (w.status.value if hasattr(w.status, "value") else str(w.status)) not in _TERMINAL_WORK_STATUSES
        ]
        # 現在の work に合致するものを優先
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
            bundle.pending_work.append({
                "work_id": w.work_id,
                "role": w_role,
                "target": redact_url(w.target),
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
            # 確証済みを優先、次に対象一致
            is_confirmed = 0 if "confirmed" in label else 1
            matches_target = 0 if curr_target and curr_target in str(h.get("url", "")) else 1
            return (is_confirmed, matches_target, cid)

        hypotheses_raw.sort(key=_hyp_priority)
        selected_hypotheses = hypotheses_raw[:self.config.max_hypotheses]
        for hyp in selected_hypotheses:
            cid = str(hyp.get("candidate_id", ""))
            ev_list = [str(x) for x in hyp.get("evidence_ids", []) if str(x)]
            label = str(hyp.get("source_label", "agent_unverified"))
            hyp_entry = {
                "candidate_id": cid,
                "url": redact_url(str(hyp.get("url", ""))),
                "check_type": str(hyp.get("check_type", "-")),
                "field_name": str(hyp.get("field_name", "-")),
                "source_label": label,
                "status": str(hyp.get("status", "proposed")),
                "evidence_ids": ev_list,
            }
            # 対象サイト由来の証拠テキスト（payload/evidence）がある場合は untrusted ラップ
            raw_obs = hyp.get("evidence") or hyp.get("payload") or ""
            if raw_obs:
                safe_obs = self._redact_value(str(raw_obs))[:self.config.max_item_summary_chars]
                wrapped = wrap_untrusted_observation(
                    safe_obs,
                    source="dom",
                    origin=str(hyp.get("url", "") or self.target_url),
                    content_type=ContentType.EVIDENCE.value,
                    correlation_id=cid,
                ).format_tagged_block()
                hyp_entry["wrapped_evidence"] = wrapped
            bundle.hypotheses.append(hyp_entry)
            if cid:
                evidence_ids.append(cid)
            evidence_ids.extend(ev_list)

        # 4. 直近の確定結果（scanner_evidence）
        scanner_ev_raw = list(getattr(self._state, "scanner_evidence", []))
        # 直近のものを優先
        selected_results = scanner_ev_raw[-self.config.max_recent_results:]
        for ev in reversed(selected_results):
            ev_id = str(ev.get("evidence_id", ""))
            corr_id = str(ev.get("correlation_id", ev_id))
            res_entry = {
                "evidence_id": ev_id,
                "check_type": str(ev.get("check_type", "-")),
                "field_name": str(ev.get("field_name", "-")),
                "url": redact_url(str(ev.get("url", ""))),
                "status": str(ev.get("status", "confirmed")),
            }
            raw_detail = ev.get("details") or ev.get("detail") or ""
            if raw_detail:
                safe_detail = self._redact_value(str(raw_detail))[:self.config.max_item_summary_chars]
                res_entry["wrapped_detail"] = wrap_untrusted_observation(
                    safe_detail,
                    source="http",
                    origin=str(ev.get("url", "") or self.target_url),
                    content_type=ContentType.EVIDENCE.value,
                    correlation_id=corr_id,
                ).format_tagged_block()
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
        sections: list[str] = [
            "## Just-In-Time Context & Structured Notes",
        ]

        if bundle.notes_summary:
            sections.append("### Structured Notes\n" + bundle.notes_summary)

        if bundle.pending_work:
            work_lines = [
                f"- work_id: {w['work_id']} | role: {w['role']} | target: {w['target']} | "
                f"check: {w['check_type']} | status: {w['status']} | attempts: {w['attempts']}"
                + (f" [evidence: {', '.join(w['evidence_ids'])}]" if w['evidence_ids'] else "")
                for w in bundle.pending_work
            ]
            sections.append(f"### Pending Work Ledger ({len(bundle.pending_work)})\n" + "\n".join(work_lines))
        else:
            sections.append("### Pending Work Ledger\n- (no pending work items)")

        if bundle.hypotheses:
            hyp_lines = []
            for h in bundle.hypotheses:
                line = (
                    f"- candidate_id: {h['candidate_id']} | check: {h['check_type']} | "
                    f"field: {h['field_name']} | label: {h['source_label']} | status: {h['status']}"
                )
                if h.get("wrapped_evidence"):
                    line += "\n  " + h["wrapped_evidence"]
                hyp_lines.append(line)
            sections.append(f"### Hypotheses & Evidence ({len(bundle.hypotheses)})\n" + "\n".join(hyp_lines))

        if bundle.recent_results:
            res_lines = []
            for r in bundle.recent_results:
                line = (
                    f"- evidence_id: {r['evidence_id']} | check: {r['check_type']} | "
                    f"field: {r['field_name']} | status: {r['status']}"
                )
                if r.get("wrapped_detail"):
                    line += "\n  " + r["wrapped_detail"]
                res_lines.append(line)
            sections.append(f"### Recent Confirmed Results ({len(bundle.recent_results)})\n" + "\n".join(res_lines))

        if bundle.coverage_gaps:
            gap_lines = [f"- {g}" for g in bundle.coverage_gaps]
            sections.append(f"### Active Coverage Gaps ({len(bundle.coverage_gaps)})\n" + "\n".join(gap_lines))

        full_text = "\n\n".join(sections)
        # 上限文字数を厳格に遵守
        if len(full_text) > self.config.max_total_chars:
            marker = "\n[...JIT context truncated]"
            closing_tag = "\n</untrusted_target_data>"
            reserve = len(marker) + len(closing_tag) + 10
            cutoff = max(50, self.config.max_total_chars - reserve)
            truncated = full_text[:cutoff].rstrip()
            # 途中で切れた untrusted_target_data タグを閉じる
            open_tags = truncated.count("<untrusted_target_data")
            close_tags = truncated.count("</untrusted_target_data>")
            if open_tags > close_tags:
                truncated += closing_tag
            truncated += marker
            if len(truncated) > self.config.max_total_chars:
                truncated = truncated[:self.config.max_total_chars]
            return truncated
        return full_text

    def build_prompt_block(self) -> str:
        """Agent のタスクプロンプトに挿入可能な整形済みテキストを直接返す。"""
        return self.build_context().formatted_context
