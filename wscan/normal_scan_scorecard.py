"""通常スキャンの検出非回帰スコアカードとゲート純粋ロジック。

設計方針:
- 「見逃し（false negative）を最小化し、製品目標を0とする」
- 固定 fixture・既知 ground truth に対する recall 100% の要求
- safe twin（安全エンドポイント）における誤検知（FP）ゼロ
- probe ledger（試行台帳）に基づく planned → executed / blocked → 判定の整合性検証
- baseline 比での recall 低下および attempt 数の低下（payload の黙った減少＝偽陰性）の検知と失格
- 測定不能・空虚合格（vacuous pass）の拒絶（None は合格扱いしない）
"""
from __future__ import annotations

import dataclasses
from dataclasses import asdict, dataclass, field
import json
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence
from urllib.parse import urlparse

from wscan.recall_gate import compute_recall


def _normalize_path(url_or_path: str) -> str:
    """URL または path 文字列を先頭スラッシュ付きの path へ正規化する（純粋）。"""
    if not url_or_path:
        return ""
    if url_or_path.startswith("http://") or url_or_path.startswith("https://"):
        p = urlparse(url_or_path).path
    else:
        p = url_or_path
    if p and not p.startswith("/"):
        p = "/" + p
    return p


@dataclass(frozen=True)
class GroundTruthRecall:
    """ground truth（EXPECTED_FINDINGS）に対する検出集計。"""

    expected_total: int
    matched_total: int
    recall: float | None
    missed: tuple[dict[str, str], ...] = ()
    by_check: dict[str, dict[str, Any]] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "expected_total": self.expected_total,
            "matched_total": self.matched_total,
            "recall": self.recall,
            "missed": [dict(m) for m in self.missed],
            "by_check": {k: dict(v) for k, v in self.by_check.items()},
        }


@dataclass(frozen=True)
class SafeTwinPrecision:
    """safe twin（SAFE_ENDPOINTS）に対する非検出集計。"""

    safe_total: int
    fp_total: int
    tn_total: int
    fpr: float | None
    false_positives: tuple[dict[str, Any], ...] = ()

    def to_dict(self) -> dict[str, Any]:
        return {
            "safe_total": self.safe_total,
            "fp_total": self.fp_total,
            "tn_total": self.tn_total,
            "fpr": self.fpr,
            "false_positives": [dict(fp) for fp in self.false_positives],
        }


@dataclass(frozen=True)
class ProbeAccounting:
    """check 単位の planned → executed / blocked / skipped / error の集計。"""

    check: str
    planned: int = 0
    executed: int = 0
    blocked: int = 0
    skipped: int = 0
    errors: int = 0
    outcomes: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "planned": self.planned,
            "executed": self.executed,
            "blocked": self.blocked,
            "skipped": self.skipped,
            "errors": self.errors,
            "outcomes": dict(self.outcomes),
        }


@dataclass(frozen=True)
class LedgerIntegrity:
    """台帳の整合性・完全性状態。"""

    had_write_error: bool = False
    quarantined: bool = False
    count_mismatches: tuple[str, ...] = ()
    gaps: tuple[str, ...] = ()
    unattributed_notes: tuple[str, ...] = ()
    valid: bool = True

    def to_dict(self) -> dict[str, Any]:
        return {
            "had_write_error": self.had_write_error,
            "quarantined": self.quarantined,
            "count_mismatches": list(self.count_mismatches),
            "gaps": list(self.gaps),
            "unattributed_notes": list(self.unattributed_notes),
            "valid": self.valid,
        }


@dataclass(frozen=True)
class NormalScanScorecard:
    """通常スキャンの検出非回帰スコアカード（不変・直列化可能）。"""

    schema_version: int = 1
    mode: str = "normal"
    fixture_id: str = "realistic_site"
    target_checks: tuple[str, ...] = ()
    overall_status: str = "COMPLETE"
    ground_truth_recall: dict[str, Any] = field(default_factory=dict)
    safe_twin_precision: dict[str, Any] = field(default_factory=dict)
    probe_accounting: dict[str, dict[str, Any]] = field(default_factory=dict)
    attempt_counts: dict[str, int] = field(default_factory=dict)
    total_attempts: int = 0
    ledger_integrity: dict[str, Any] = field(default_factory=dict)
    unmeasured_checks: tuple[str, ...] = ()
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "mode": self.mode,
            "fixture_id": self.fixture_id,
            "target_checks": list(self.target_checks),
            "overall_status": self.overall_status,
            "ground_truth_recall": {
                "expected_total": self.ground_truth_recall.get("expected_total", 0),
                "matched_total": self.ground_truth_recall.get("matched_total", 0),
                "recall": self.ground_truth_recall.get("recall"),
                "missed": [dict(m) for m in self.ground_truth_recall.get("missed", ())],
                "by_check": {
                    ch: dict(info)
                    for ch, info in self.ground_truth_recall.get("by_check", {}).items()
                },
            },
            "safe_twin_precision": {
                "safe_total": self.safe_twin_precision.get("safe_total", 0),
                "fp_total": self.safe_twin_precision.get("fp_total", 0),
                "tn_total": self.safe_twin_precision.get("tn_total", 0),
                "fpr": self.safe_twin_precision.get("fpr"),
                "false_positives": [dict(fp) for fp in self.safe_twin_precision.get("false_positives", ())],
            },
            "probe_accounting": {
                ch: {
                    "check": info.get("check", ch),
                    "planned": info.get("planned", 0),
                    "executed": info.get("executed", 0),
                    "blocked": info.get("blocked", 0),
                    "skipped": info.get("skipped", 0),
                    "errors": info.get("errors", 0),
                    "outcomes": dict(info.get("outcomes", {})),
                }
                for ch, info in self.probe_accounting.items()
            },
            "attempt_counts": dict(self.attempt_counts),
            "total_attempts": self.total_attempts,
            "ledger_integrity": {
                "had_write_error": self.ledger_integrity.get("had_write_error", False),
                "quarantined": self.ledger_integrity.get("quarantined", False),
                "count_mismatches": list(self.ledger_integrity.get("count_mismatches", ())),
                "gaps": list(self.ledger_integrity.get("gaps", ())),
                "unattributed_notes": list(self.ledger_integrity.get("unattributed_notes", ())),
                "valid": self.ledger_integrity.get("valid", True),
            },
            "unmeasured_checks": list(self.unmeasured_checks),
            "metadata": dict(self.metadata),
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> NormalScanScorecard:
        raw_gt = data.get("ground_truth_recall", {})
        gt_by_check = {
            ch: dict(info)
            for ch, info in raw_gt.get("by_check", {}).items()
        }
        gt_recall = {
            "expected_total": int(raw_gt.get("expected_total", 0)),
            "matched_total": int(raw_gt.get("matched_total", 0)),
            "recall": float(raw_gt["recall"]) if raw_gt.get("recall") is not None else None,
            "missed": [dict(m) for m in raw_gt.get("missed", ())],
            "by_check": gt_by_check,
        }

        raw_safe = data.get("safe_twin_precision", {})
        safe_prec = {
            "safe_total": int(raw_safe.get("safe_total", 0)),
            "fp_total": int(raw_safe.get("fp_total", 0)),
            "tn_total": int(raw_safe.get("tn_total", 0)),
            "fpr": float(raw_safe["fpr"]) if raw_safe.get("fpr") is not None else None,
            "false_positives": [dict(fp) for fp in raw_safe.get("false_positives", ())],
        }

        raw_accounting = data.get("probe_accounting", {})
        probe_accounting = {
            ch: {
                "check": info.get("check", ch),
                "planned": int(info.get("planned", 0)),
                "executed": int(info.get("executed", 0)),
                "blocked": int(info.get("blocked", 0)),
                "skipped": int(info.get("skipped", 0)),
                "errors": int(info.get("errors", 0)),
                "outcomes": {str(ok): int(ov) for ok, ov in info.get("outcomes", {}).items()},
            }
            for ch, info in raw_accounting.items()
        }

        raw_integrity = data.get("ledger_integrity", {})
        ledger_integrity = {
            "had_write_error": bool(raw_integrity.get("had_write_error", False)),
            "quarantined": bool(raw_integrity.get("quarantined", False)),
            "count_mismatches": tuple(raw_integrity.get("count_mismatches", ())),
            "gaps": tuple(raw_integrity.get("gaps", ())),
            "unattributed_notes": tuple(raw_integrity.get("unattributed_notes", ())),
            "valid": bool(raw_integrity.get("valid", True)),
        }

        return cls(
            schema_version=int(data.get("schema_version", 1)),
            mode=str(data.get("mode", "normal")),
            fixture_id=str(data.get("fixture_id", "realistic_site")),
            target_checks=tuple(data.get("target_checks", ())),
            overall_status=str(data.get("overall_status", "COMPLETE")),
            ground_truth_recall=gt_recall,
            safe_twin_precision=safe_prec,
            probe_accounting=probe_accounting,
            attempt_counts={str(k): int(v) for k, v in data.get("attempt_counts", {}).items()},
            total_attempts=int(data.get("total_attempts", 0)),
            ledger_integrity=ledger_integrity,
            unmeasured_checks=tuple(data.get("unmeasured_checks", ())),
            metadata=dict(data.get("metadata", {})),
        )


@dataclass(frozen=True)
class NormalScanGateVerdict:
    """通常スキャン検出非回帰ゲートの合否判定結果。"""

    passed: bool
    reasons: tuple[str, ...] = ()
    recall: float | None = None
    fpr: float | None = None
    total_attempts: int = 0
    baseline_attempts: int | None = None
    regressed_checks: tuple[str, ...] = ()
    dropped_attempt_checks: tuple[str, ...] = ()
    false_positives: tuple[dict[str, Any], ...] = ()
    ledger_violations: tuple[str, ...] = ()

    def describe(self) -> str:
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            f"Normal Scan Non-Regression Gate: {status}",
            f"  recall={self.recall}, fpr={self.fpr}, total_attempts={self.total_attempts} (baseline={self.baseline_attempts})",
        ]
        if self.regressed_checks:
            lines.append(f"  Regressed checks: {', '.join(self.regressed_checks)}")
        if self.dropped_attempt_checks:
            lines.append(f"  Dropped attempt checks: {', '.join(self.dropped_attempt_checks)}")
        if self.reasons:
            lines.append("  Failure reasons:")
            for r in self.reasons:
                lines.append(f"    - {r}")
        return "\n".join(lines)


def build_normal_scan_scorecard(
    findings: Iterable[Any],
    expected_findings: Sequence[Mapping[str, str]],
    safe_endpoints: Sequence[Mapping[str, str]],
    *,
    target_checks: Optional[Iterable[str]] = None,
    ledger_records: Optional[Iterable[Any]] = None,
    ledger_manifest: Optional[Any] = None,
    wave_errors: Optional[Iterable[str]] = None,
    planned_probes: Optional[Mapping[str, int]] = None,
    fixture_id: str = "realistic_site",
    metadata: Optional[Mapping[str, Any]] = None,
) -> NormalScanScorecard:
    """通常スキャンの結果からスコアカードを構築する純粋関数。

    - findings: スキャンが報告した Finding 群（Finding インスタンスまたは dict）
    - expected_findings: ground truth（check, path, field, note）
    - safe_endpoints: 安全ツイン（path, field, note）
    - ledger_records: probe_attempts.jsonl の行群（ProbeAttemptRecord または dict）
    - ledger_manifest: LedgerManifest または to_dict 出力
    - wave_errors: engine.wave_errors の文字列リスト
    """
    effective_targets = tuple(sorted(set(str(c) for c in target_checks))) if target_checks is not None else None

    # 1. 報告された Finding の正規化
    reported_keys: list[tuple[str, str, str]] = []
    finding_objects: list[dict[str, Any]] = []
    for f in findings:
        check = str(getattr(f, "check_type", None) or (f.get("check_type") if isinstance(f, Mapping) else None) or (f.get("check") if isinstance(f, Mapping) else "") or "")
        url_raw = str(getattr(f, "url", None) or (f.get("url") if isinstance(f, Mapping) else None) or (f.get("path") if isinstance(f, Mapping) else "") or "")
        field_name = str(getattr(f, "field_name", None) or (f.get("field_name") if isinstance(f, Mapping) else None) or (f.get("field") if isinstance(f, Mapping) else "") or "")
        norm_path = _normalize_path(url_raw)
        reported_keys.append((check, norm_path, field_name))
        finding_objects.append({
            "check": check,
            "path": norm_path,
            "field": field_name,
            "verified": bool(getattr(f, "verified", True) if not isinstance(f, Mapping) else f.get("verified", True)),
        })

    # target_checks が未指定なら expected_findings と finding から自動導出
    if effective_targets is None:
        derived = set()
        for exp in expected_findings:
            if exp.get("check"):
                derived.add(str(exp["check"]))
        for rk in reported_keys:
            if rk[0]:
                derived.add(rk[0])
        effective_targets = tuple(sorted(derived))

    # 2. Ground truth recall の集計（recall_gate.compute_recall を利用）
    recall_report = compute_recall(expected_findings, reported_keys, target_checks=effective_targets)
    expected_total = recall_report.expected_total
    matched_total = recall_report.matched_total
    recall_value: float | None = recall_report.recall if expected_total > 0 else None

    by_check_recall: dict[str, dict[str, Any]] = {}
    for ch in effective_targets:
        m, t = recall_report.by_check.get(ch, (0, 0))
        by_check_recall[ch] = {
            "expected": t,
            "matched": m,
            "recall": (m / t) if t > 0 else None,
        }

    # 3. Safe twin precision（誤検知 FP）の集計
    reported_key_set = set(reported_keys)
    false_positives: list[dict[str, Any]] = []
    tn_total = 0
    safe_total = len(safe_endpoints)

    for spec in safe_endpoints:
        safe_path = _normalize_path(str(spec.get("path", "")))
        safe_field = str(spec.get("field", ""))
        safe_check = str(spec.get("check", "")) if spec.get("check") else None

        # 当該安全エンドポイントに一致する Finding を探す
        matched_fps = [
            f for f in finding_objects
            if f["path"] == safe_path and f["field"] == safe_field and (safe_check is None or f["check"] == safe_check)
        ]
        if matched_fps:
            false_positives.append({
                "path": safe_path,
                "field": safe_field,
                "check": safe_check,
                "note": str(spec.get("note", "")),
                "findings": matched_fps,
            })
        else:
            tn_total += 1

    fp_total = len(false_positives)
    fpr_value: float | None = (fp_total / safe_total) if safe_total > 0 else None

    # 4. Probe ledger の集計
    accounting_by_check: dict[str, dict[str, Any]] = {}
    attempt_counts: dict[str, int] = {}
    for ch in effective_targets:
        accounting_by_check[ch] = {
            "check": ch,
            "planned": (planned_probes or {}).get(ch, 0),
            "executed": 0,
            "blocked": 0,
            "skipped": 0,
            "errors": 0,
            "outcomes": {},
        }
        attempt_counts[ch] = 0

    if ledger_records:
        for r in ledger_records:
            ch = str(r.get("check", "") if isinstance(r, Mapping) else getattr(r, "check", ""))
            if effective_targets and ch not in effective_targets:
                continue
            role = str(r.get("role", "") if isinstance(r, Mapping) else getattr(r, "role", ""))
            outcome = str(r.get("outcome", "") if isinstance(r, Mapping) else getattr(r, "outcome", ""))
            record_kind = str(r.get("record_kind", "") if isinstance(r, Mapping) else getattr(r, "record_kind", ""))

            entry = accounting_by_check.setdefault(ch, {
                "check": ch,
                "planned": (planned_probes or {}).get(ch, 0),
                "executed": 0,
                "blocked": 0,
                "skipped": 0,
                "errors": 0,
                "outcomes": {},
            })

            # role が attack の試行を集計
            if role == "attack":
                if record_kind == "request":
                    entry["executed"] += 1
                elif record_kind in ("decision", "graphql_decision", "legacy"):
                    if not entry["executed"]:
                        # request 行が存在しないレガシー/直接 decision の場合のフォールバック
                        pass
                    if outcome:
                        outcomes = entry["outcomes"]
                        outcomes[outcome] = outcomes.get(outcome, 0) + 1
                        if outcome == "blocked":
                            entry["blocked"] += 1
                        elif outcome == "skipped":
                            entry["skipped"] += 1
                        elif outcome in ("transport_error", "timeout", "verification_error", "unexecutable"):
                            entry["errors"] += 1

        for ch, entry in accounting_by_check.items():
            # executed が 0 でも decision があれば decisions 総数を試行数とする
            exec_cnt = entry["executed"]
            if exec_cnt == 0 and entry["outcomes"]:
                exec_cnt = sum(entry["outcomes"].values())
                entry["executed"] = exec_cnt
            attempt_counts[ch] = exec_cnt
            if entry["planned"] == 0:
                entry["planned"] = exec_cnt + entry["skipped"] + entry["blocked"]

    total_attempts = sum(attempt_counts.values())

    # 5. Ledger integrity の検証
    had_write_error = False
    quarantined = False
    gaps: list[str] = []
    count_mismatches: list[str] = []
    unattributed_notes: list[str] = []

    if ledger_manifest is not None:
        if isinstance(ledger_manifest, Mapping):
            had_write_error = bool(ledger_manifest.get("had_write_error", False))
            quarantined = bool(ledger_manifest.get("quarantined", False))
            gaps = [str(e.get("error", "")) for e in ledger_manifest.get("write_errors", []) if e.get("outcome") == "gap"]
        else:
            had_write_error = bool(getattr(ledger_manifest, "had_write_error", False))
            quarantined = bool(getattr(ledger_manifest, "quarantined", False))
            gaps = [str(g) for g in getattr(ledger_manifest, "gaps", [])]

    if wave_errors:
        for err in wave_errors:
            err_str = str(err)
            if "probe_ledger_incomplete:" in err_str:
                count_mismatches.append(err_str)
                if "write_failed" in err_str:
                    had_write_error = True
            elif "count_mismatch" in err_str:
                count_mismatches.append(err_str)
            else:
                unattributed_notes.append(err_str)

    ledger_valid = not had_write_error and not quarantined and not count_mismatches

    # 6. 未計測 check の検出
    unmeasured: list[str] = []
    for ch in effective_targets:
        ch_exp = by_check_recall.get(ch, {}).get("expected", 0)
        ch_att = attempt_counts.get(ch, 0)
        # ground truth に存在するか試行があるべき check で attempt も expected も 0
        if ch_exp == 0 and ch_att == 0:
            unmeasured.append(ch)

    # 7. Overall status
    if not ledger_valid or unmeasured:
        overall_status = "INCOMPLETE"
    elif recall_value is None or fpr_value is None:
        overall_status = "INCOMPLETE"
    elif recall_value < 1.0 or fp_total > 0:
        overall_status = "FAILED"
    else:
        overall_status = "COMPLETE"

    return NormalScanScorecard(
        schema_version=1,
        mode="normal",
        fixture_id=fixture_id,
        target_checks=effective_targets,
        overall_status=overall_status,
        ground_truth_recall={
            "expected_total": expected_total,
            "matched_total": matched_total,
            "recall": recall_value,
            "missed": [dict(m) for m in recall_report.missed],
            "by_check": by_check_recall,
        },
        safe_twin_precision={
            "safe_total": safe_total,
            "fp_total": fp_total,
            "tn_total": tn_total,
            "fpr": fpr_value,
            "false_positives": false_positives,
        },
        probe_accounting=accounting_by_check,
        attempt_counts=attempt_counts,
        total_attempts=total_attempts,
        ledger_integrity={
            "had_write_error": had_write_error,
            "quarantined": quarantined,
            "count_mismatches": tuple(count_mismatches),
            "gaps": tuple(gaps),
            "unattributed_notes": tuple(unattributed_notes),
            "valid": ledger_valid,
        },
        unmeasured_checks=tuple(unmeasured),
        metadata=dict(metadata or {}),
    )


def evaluate_normal_scan_gate(
    current: NormalScanScorecard | Mapping[str, Any],
    baseline: NormalScanScorecard | Mapping[str, Any] | None = None,
    *,
    max_fp: int = 0,
    allow_vacuous: bool = False,
) -> NormalScanGateVerdict:
    """通常スキャンの検出非回帰ゲート判定純粋関数。

    失格（passed=False）条件:
    1) 未計測・空虚合格: expected_total == 0 または recall is None、safe_total == 0、
       または total_attempts == 0（測れないものは None、green として扱わない）。
    2) False Negative（見逃し）: recall < 1.0 または baseline 比での recall 低下。
    3) False Positive（誤検知）: safe twin での検出（fp > max_fp）または baseline 比増加。
    4) Attempt 数の低下: baseline と比較して総 attempt 数または個別 check の attempt 数が低下
       （送るはずの payload が黙って減ること＝偽陰性）。
    5) Probe ledger 不整合: 台帳 write_error、quarantine、または count_mismatch。
    """
    card = current if isinstance(current, NormalScanScorecard) else NormalScanScorecard.from_dict(current)
    base_card = (
        baseline
        if isinstance(baseline, NormalScanScorecard)
        else (NormalScanScorecard.from_dict(baseline) if baseline is not None else None)
    )

    reasons: list[str] = []
    regressed_checks: list[str] = []
    dropped_attempt_checks: list[str] = []
    ledger_violations: list[str] = []

    # 1. 空虚合格・未計測の拒絶
    gt_recall = card.ground_truth_recall
    expected_total = gt_recall.get("expected_total", 0)
    recall = gt_recall.get("recall")

    safe_prec = card.safe_twin_precision
    safe_total = safe_prec.get("safe_total", 0)
    fpr = safe_prec.get("fpr")
    fp_total = safe_prec.get("fp_total", 0)

    if not allow_vacuous:
        if expected_total == 0 or recall is None:
            reasons.append("Empty expected ground truth: recall is None (vacuous pass rejected)")
        if safe_total == 0 or fpr is None:
            reasons.append("Empty safe twin ground truth: fpr is None (safe endpoints not evaluated)")
        if card.total_attempts == 0:
            reasons.append("Zero probe attempts executed: total_attempts == 0")
        if card.unmeasured_checks:
            reasons.append(f"Unmeasured target checks present: {', '.join(card.unmeasured_checks)}")

    # 2. Ground truth recall の検証（見逃し0・非回帰）
    missed = gt_recall.get("missed", [])
    if missed:
        reasons.append(f"False negative regression: {len(missed)} missed vulnerable case(s)")
    elif recall is not None and recall < 1.0:
        reasons.append(f"Recall below target 1.0: {recall:.4f}")

    if base_card is not None:
        b_gt = base_card.ground_truth_recall
        b_recall = b_gt.get("recall")
        if b_recall is not None and recall is not None and recall < b_recall:
            reasons.append(f"Recall dropped vs baseline: {recall:.4f} < {b_recall:.4f}")

        # check 別の recall 比較
        b_by_check = b_gt.get("by_check", {})
        c_by_check = gt_recall.get("by_check", {})
        for ch, b_info in b_by_check.items():
            b_ch_r = b_info.get("recall")
            c_ch_r = c_by_check.get(ch, {}).get("recall")
            if b_ch_r is not None and c_ch_r is not None and c_ch_r < b_ch_r:
                reasons.append(f"Recall dropped for check '{ch}': {c_ch_r:.4f} < {b_ch_r:.4f}")
                regressed_checks.append(ch)

    # 3. Safe twin の FP 検証（安全ツイン誤検知0・非回帰）
    if fp_total > max_fp or (fpr is not None and fpr > 0.0):
        reasons.append(f"False positive on safe twin endpoints: {fp_total} false alarm(s) (FPR={fpr})")

    if base_card is not None:
        b_fp = base_card.safe_twin_precision.get("fp_total", 0)
        if fp_total > b_fp:
            reasons.append(f"Safe twin false positives increased vs baseline: {fp_total} > {b_fp}")

    # 4. Attempt 数の非回帰（payload の黙認減少＝偽陰性）
    baseline_attempts = base_card.total_attempts if base_card is not None else None
    if base_card is not None:
        if card.total_attempts < base_card.total_attempts:
            reasons.append(
                f"Total probe attempt count dropped vs baseline: {card.total_attempts} < {base_card.total_attempts} "
                f"(silent payload reduction = false negative)"
            )

        b_attempts = base_card.attempt_counts
        c_attempts = card.attempt_counts
        for ch, b_cnt in b_attempts.items():
            c_cnt = c_attempts.get(ch, 0)
            if c_cnt < b_cnt:
                reasons.append(
                    f"Attempt count dropped for check '{ch}': {c_cnt} < {b_cnt} "
                    f"(silent payload reduction = false negative)"
                )
                dropped_attempt_checks.append(ch)

    # 5. Probe ledger の整合性検証
    integrity = card.ledger_integrity
    if not integrity.get("valid", True):
        if integrity.get("had_write_error") or integrity.get("quarantined"):
            reasons.append("Probe ledger write error or quarantine detected (evidence incomplete)")
            ledger_violations.append("ledger_write_error_or_quarantined")
        for cm in integrity.get("count_mismatches", ()):
            reasons.append(f"Probe ledger count mismatch: {cm}")
            ledger_violations.append(cm)
        for g in integrity.get("gaps", ()):
            reasons.append(f"Probe ledger gap: {g}")
            ledger_violations.append(g)

    passed = len(reasons) == 0
    return NormalScanGateVerdict(
        passed=passed,
        reasons=tuple(reasons),
        recall=recall,
        fpr=fpr,
        total_attempts=card.total_attempts,
        baseline_attempts=baseline_attempts,
        regressed_checks=tuple(sorted(set(regressed_checks))),
        dropped_attempt_checks=tuple(sorted(set(dropped_attempt_checks))),
        false_positives=tuple(safe_prec.get("false_positives", ())),
        ledger_violations=tuple(ledger_violations),
    )


def load_normal_scorecard_file(path: str | Path) -> NormalScanScorecard:
    """JSON ファイルから NormalScanScorecard を読み込む。"""
    p = Path(path)
    content = p.read_text(encoding="utf-8")
    data = json.loads(content)
    return NormalScanScorecard.from_dict(data)


def save_normal_scorecard_file(scorecard: NormalScanScorecard, path: str | Path) -> None:
    """NormalScanScorecard を JSON ファイルへ保存する。"""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    content = json.dumps(scorecard.to_dict(), ensure_ascii=False, indent=2, sort_keys=True)
    p.write_text(content, encoding="utf-8")
