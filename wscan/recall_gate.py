"""見逃し0（recall）ゲートの純粋ロジック。

設計方針は「見逃し（false negative）最小化・製品目標0」を第一目的とし、固定 ground truth に
対する recall 100% をリリースゲートにすると定めた。本モジュールはその**判定ロジック**を提供する
（enforcement は E2E scan 実走時＝WSCAN_E2E 有効時に blocking。PR CI は browser 不安定のため
非 blocking のままとし、release gate は nightly workflow で定期 blocking 実行する）。
フィクスチャの
`EXPECTED_FINDINGS`（各 spec は `check`/`path`/`field`/`note`）と、実スキャンが報告した
`(check, path, field)` の集合から recall を算出する純粋関数群。

ブラウザ・エンジン非依存＝ユニットテスト可能に保つ（判定ロジックを I/O から分離する規約）。
E2E 側はこの `RecallReport` を使って `recall == 1.0` を単一ゲートとして assert する。

過検知（false positive）はここでは扱わない（recall のみ）。設計方針に沿って過検知低減は
検知後の証拠強化・隔離再現で行い、候補削減で recall を犠牲にしないため、関心を分離する。
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Iterable, Mapping, Optional, Sequence

# spec の一意キー（E2E の突合と同一：check_type × path × field）
FindingKey = tuple[str, str, str]


def spec_key(spec: Mapping[str, str]) -> FindingKey:
    """EXPECTED_FINDINGS の1 spec を突合キーへ（欠損は空文字で正規化）。"""
    return (
        str(spec.get("check", "")),
        str(spec.get("path", "")),
        str(spec.get("field", "")),
    )


@dataclass(frozen=True)
class RecallReport:
    """target check 群に対する recall（見逃し）測定結果。

    frozen dataclass（属性は再束縛不可）。入れ子コレクション（missed/by_check）は構築時に
    呼び出し側入力から**コピー**するため、入力を後から変更しても report は変わらない（snapshot
    分離）。素の dict/tuple/str/int のみで構成し **JSON 直列化可能**（`dataclasses.asdict` 可）。
    ※ 深い不変化（read-only view）は直列化と両立しないため採らない＝内部 dict の直接改変は
    防がない（snapshot 分離で入力汚染は防ぐ）。"""

    expected_total: int
    matched_total: int
    missed: tuple[Mapping[str, str], ...] = ()
    by_check: Mapping[str, tuple[int, int]] = field(default_factory=dict)  # check -> (matched, total)

    @property
    def recall(self) -> float:
        """expected が空なら vacuously 1.0（測る対象が無い＝見逃しも無い）。"""
        if self.expected_total == 0:
            return 1.0
        return self.matched_total / self.expected_total

    @property
    def is_complete(self) -> bool:
        """recall 100%（見逃し0）か。リリースゲートの合否。"""
        return self.matched_total >= self.expected_total

    def describe(self) -> str:
        """ゲート失敗メッセージ／ログ用の人間可読サマリ。"""
        pct = self.recall * 100.0
        lines = [
            f"recall {self.matched_total}/{self.expected_total} = {pct:.1f}%"
            + ("" if self.is_complete else "  ← FALSE NEGATIVE(S)"),
        ]
        for check in sorted(self.by_check):
            m, t = self.by_check[check]
            flag = "" if m >= t else "  ← 見逃し"
            lines.append(f"  {check}: {m}/{t}{flag}")
        for spec in self.missed:
            lines.append(
                f"  MISS [{spec.get('check','')}] {spec.get('path','')} "
                f"(field '{spec.get('field','')}') — {spec.get('note','')}"
            )
        return "\n".join(lines)


def compute_recall(
    expected: Sequence[Mapping[str, str]],
    reported: Iterable[FindingKey],
    target_checks: Optional[Iterable[str]] = None,
) -> RecallReport:
    """expected spec 群と実報告キー集合から recall を算出（純粋）。

    - `target_checks` 指定時は、その check 群の spec だけを分母にする（＝当該スキャンで
      有効化した check だけを recall 対象にする。無効 check の未検出を見逃し扱いしない）。
    - 同一キーの spec は重複排除して分母を数える（note 違いの二重計上を防ぐ）。
    - `reported` に expected 外のキーが混ざっても無視（それは precision の話で recall では無関係）。
    """
    reported_set = {(str(c), str(p), str(f)) for (c, p, f) in reported}
    targets = set(target_checks) if target_checks is not None else None

    seen: set[FindingKey] = set()
    matched_total = 0
    missed: list[Mapping[str, str]] = []
    by_check: dict[str, list[int]] = {}  # check -> [matched, total]

    for spec in expected:
        key = spec_key(spec)
        check = key[0]
        if targets is not None and check not in targets:
            continue
        if key in seen:
            continue  # 重複キーは分母1回だけ
        seen.add(key)

        slot = by_check.setdefault(check, [0, 0])
        slot[1] += 1
        if key in reported_set:
            matched_total += 1
            slot[0] += 1
        else:
            missed.append(spec)

    # snapshot 分離＋シリアライズ可能を両立する: missed は呼び出し側 spec dict を**コピー**して
    # 参照を持たない（呼び出し側が後から expected を変更しても report は不変）。型は素の dict/tuple
    # のままにし JSON 直列化を保つ（MappingProxyType は json.dumps/asdict 不可のため使わない）。
    snapshot_missed = tuple(dict(spec) for spec in missed)
    snapshot_by_check = {c: (m, t) for c, (m, t) in by_check.items()}
    return RecallReport(
        expected_total=len(seen),
        matched_total=matched_total,
        missed=snapshot_missed,
        by_check=snapshot_by_check,
    )


@dataclass(frozen=True)
class DetectionGateVerdict:
    """検出回帰ゲートの合否判定結果。

    frozen dataclass（属性再束縛不可、JSON直列化可能）。
    recall 100%、FPR 0.0（safe twinでの誤検知0）、未計測/ドロップアウト0、
    および baseline からの回帰なしを検証する。
    """

    passed: bool
    reasons: tuple[str, ...] = ()
    recall: float | None = None
    fpr: float | None = None
    expected_total: int = 0
    attempted_cases: int = 0
    incomplete_cases: int = 0
    fn: int = 0
    fp: int = 0
    regressed_cases: tuple[str, ...] = ()
    removed_cases: tuple[str, ...] = ()

    def describe(self) -> str:
        """ゲート合否サマリ文字列。"""
        status = "PASSED" if self.passed else "FAILED"
        lines = [
            f"Detection gate: {status}",
            f"  expected_total={self.expected_total}, attempted_cases={self.attempted_cases}, incomplete_cases={self.incomplete_cases}",
            f"  fn={self.fn}, fp={self.fp}, recall={self.recall}, fpr={self.fpr}",
        ]
        if self.regressed_cases:
            lines.append(f"  regressed_cases: {', '.join(self.regressed_cases)}")
        if self.removed_cases:
            lines.append(f"  removed_cases: {', '.join(self.removed_cases)}")
        if self.reasons:
            lines.append("  Failure reasons:")
            for reason in self.reasons:
                lines.append(f"    - {reason}")
        return "\n".join(lines)


@dataclass(frozen=True)
class NightlyFreshnessVerdict:
    """Nightly 結果の有効期限・完全性判定結果。

    frozen dataclass。main の成功済み Nightly 結果の有効期限と成功状態を判定する。
    """

    ready: bool
    age_seconds: float | None
    reasons: tuple[str, ...] = ()

    def describe(self) -> str:
        status = "READY" if self.ready else "NOT_READY"
        lines = [f"Nightly freshness: {status} (age={self.age_seconds}s)"]
        for r in self.reasons:
            lines.append(f"  - {r}")
        return "\n".join(lines)


def evaluate_nightly_freshness(
    nightly_record: Mapping[str, Any] | None,
    *,
    now_ts: float,
    max_age_seconds: float = 36 * 3600,
    expected_branch: str = "main",
) -> NightlyFreshnessVerdict:
    """Nightly 結果の鮮度・完全性を判定する純粋関数。

    - nightly_record が存在し Mapping であること
    - conclusion == 'success' かつ recall_complete is True かつ attempted_total > 0
    - branch == expected_branch（指定時）
    - completed_at が now_ts に対して有効期限内（max_age_seconds以内、未来日でない）
    """
    reasons: list[str] = []
    if nightly_record is None:
        return NightlyFreshnessVerdict(ready=False, age_seconds=None, reasons=("Nightly record is missing",))
    if not isinstance(nightly_record, Mapping):
        return NightlyFreshnessVerdict(ready=False, age_seconds=None, reasons=("Nightly record must be a mapping",))

    conclusion = nightly_record.get("conclusion")
    if conclusion != "success":
        reasons.append(f"Nightly conclusion is '{conclusion}', expected 'success'")

    recall_complete = nightly_record.get("recall_complete")
    if recall_complete is not True:
        reasons.append(f"Nightly recall_complete is {recall_complete}, expected True")

    attempted_total = nightly_record.get("attempted_total", 0)
    if not isinstance(attempted_total, (int, float)) or attempted_total <= 0:
        reasons.append(f"Nightly attempted_total is {attempted_total}, expected > 0")

    if expected_branch:
        branch = nightly_record.get("branch")
        if branch != expected_branch:
            reasons.append(f"Nightly branch is '{branch}', expected '{expected_branch}'")

    if nightly_record.get("run_error"):
        reasons.append(f"Nightly run error: {nightly_record.get('run_error')}")

    completed_raw = nightly_record.get("completed_at")
    age_seconds: float | None = None
    if completed_raw is None:
        reasons.append("Nightly completed_at is missing")
    else:
        completed_ts: float | None = None
        if isinstance(completed_raw, (int, float)):
            completed_ts = float(completed_raw)
        elif isinstance(completed_raw, str):
            try:
                iso_str = completed_raw.replace("Z", "+00:00") if completed_raw.endswith("Z") else completed_raw
                completed_ts = datetime.fromisoformat(iso_str).timestamp()
            except Exception:
                completed_ts = None
        if completed_ts is None:
            reasons.append(f"Nightly completed_at timestamp could not be parsed: {completed_raw!r}")
        else:
            age = now_ts - completed_ts
            age_seconds = age
            if age < -60.0:
                reasons.append(f"Nightly completed_at is in the future: age={age:.1f}s")
            elif age > max_age_seconds:
                reasons.append(f"Nightly record is stale: age {age:.1f}s exceeds maximum {max_age_seconds:.1f}s")

    ready = len(reasons) == 0
    return NightlyFreshnessVerdict(ready=ready, age_seconds=age_seconds, reasons=tuple(reasons))


def evaluate_detection_gate(
    current: Mapping[str, Any] | RecallReport,
    baseline: Mapping[str, Any] | None = None,
    *,
    safe_twin_report: Mapping[str, Any] | None = None,
    tier: str = "confirmed",
    max_fp: int = 0,
    max_fpr: float = 0.0,
    allow_vacuous: bool = False,
) -> DetectionGateVerdict:
    """厳格な検出回帰ゲートの判定純粋関数。

    以下のいずれかに該当する場合は fail closed（passed=False）とする:
    1) expected_total == 0 または attempted_cases == 0（ゼロ試行・空分母の空虚合格を拒絶）
    2) skipped, timed out, fixture_unavailable, unregistered 等のドロップアウト（incomplete_cases > 0）
    3) False Negative（missed/fn > 0, recall < 1.0）または safe twin での False Positive（fp > baseline/0.0）
    4) baseline との比較における回帰（regressed, removed, recall/precision 低下）
    """
    reasons: list[str] = []
    regressed_cases: tuple[str, ...] = ()
    removed_cases: tuple[str, ...] = ()

    if isinstance(current, RecallReport):
        expected_total = current.expected_total
        matched_total = current.matched_total
        fn = len(current.missed) if current.missed else max(0, expected_total - matched_total)
        recall = current.recall if expected_total > 0 else None
        safe_fp = 0
        safe_tn = 0
        safe_incomplete = 0
        if safe_twin_report is not None and isinstance(safe_twin_report, Mapping):
            safe_fp = int(safe_twin_report.get("fp", 0))
            safe_tn = int(safe_twin_report.get("tn", 0))
            safe_incomplete = int(safe_twin_report.get("incomplete", 0))
            safe_total = int(safe_twin_report.get("total", safe_fp + safe_tn))
        else:
            safe_total = 0
        fp = safe_fp
        attempted_cases = matched_total + fn + safe_total
        incomplete_cases = safe_incomplete
        fpr = (fp / safe_total) if safe_total > 0 else (0.0 if fp == 0 else 1.0)

        if not allow_vacuous:
            if expected_total == 0:
                reasons.append("Empty expected ground truth: expected_total == 0 (vacuous pass rejected)")
            if attempted_cases == 0:
                reasons.append("Zero attempted cases: attempted_cases == 0")
        if incomplete_cases > 0:
            reasons.append(f"Incomplete measurement: {incomplete_cases} case(s) not completed")
        if fn > 0:
            reasons.append(f"False negative regression: {fn} missed vulnerable case(s)")
        elif recall is not None and recall < 1.0:
            reasons.append(f"Recall below target: {recall:.4f} < 1.0")
        if fp > max_fp or (fpr is not None and fpr > max_fpr):
            reasons.append(f"False positive on safe twin endpoints: {fp} false alarm(s) (FPR={fpr})")

    elif isinstance(current, Mapping):
        run_error = current.get("run_error")
        if run_error:
            reasons.append(f"Scorecard execution error: {run_error}")

        overall = current.get("overall_status")
        if overall in ("FAILED", "INCOMPLETE"):
            reasons.append(f"Scorecard overall_status is {overall}")

        cases = current.get("cases") or []
        case_counts = current.get("case_counts") or {}
        planned = int(case_counts.get("planned", len(cases)))
        completed = int(case_counts.get("completed", 0))

        dropouts = [
            str(c.get("case_id", "unknown"))
            for c in cases
            if isinstance(c, Mapping) and c.get("state") not in (None, "completed")
        ]
        incomplete_cases = max(int(case_counts.get("incomplete", 0)), len(dropouts))
        if completed == 0 and cases:
            completed = len([c for c in cases if isinstance(c, Mapping) and c.get("state") == "completed"])

        metrics = current.get("metrics") or {}
        tier_metrics = metrics.get(tier) if isinstance(metrics, Mapping) else None
        if tier_metrics is None and isinstance(metrics, Mapping):
            tier_metrics = metrics.get("confirmed") or metrics.get("candidate") or {}
        if not isinstance(tier_metrics, Mapping):
            tier_metrics = {}

        tp = int(tier_metrics.get("tp", 0))
        fn = int(tier_metrics.get("fn", 0))
        fp = int(tier_metrics.get("fp", 0))
        tn = int(tier_metrics.get("tn", 0))
        recall_denom = tier_metrics.get("recall_denominator")
        if recall_denom is None:
            recall_denom = tp + fn
        expected_total = int(recall_denom)
        recall = tier_metrics.get("recall")

        safe_total = tn + fp
        fpr = (fp / safe_total) if safe_total > 0 else (0.0 if fp == 0 else 1.0)
        attempted_cases = completed if completed > 0 else (tp + fn + tn + fp)

        if not allow_vacuous:
            if expected_total == 0:
                reasons.append("Empty expected ground truth: expected_total == 0 (vacuous pass rejected)")
            if attempted_cases == 0:
                reasons.append("Zero attempted cases: attempted_cases == 0")

        if incomplete_cases > 0:
            drop_details = f": {', '.join(dropouts)}" if dropouts else ""
            reasons.append(f"Incomplete measurement: {incomplete_cases} case(s) not completed{drop_details}")

        if fn > 0:
            reasons.append(f"False negative regression: {fn} missed vulnerable case(s)")
        elif recall is not None and recall < 1.0:
            reasons.append(f"Recall below target: {recall:.4f} < 1.0")

        baseline_fp = 0
        baseline_fpr = 0.0
        if baseline is not None and isinstance(baseline, Mapping):
            b_metrics = baseline.get("metrics") or {}
            b_tier = b_metrics.get(tier) or b_metrics.get("confirmed") or b_metrics.get("candidate") or {}
            baseline_fp = int(b_tier.get("fp", 0))
            b_safe = int(b_tier.get("tn", 0)) + baseline_fp
            baseline_fpr = (baseline_fp / b_safe) if b_safe > 0 else 0.0

        if baseline is None:
            if fp > max_fp or (fpr is not None and fpr > max_fpr):
                reasons.append(f"False positive on safe twin endpoints: {fp} false alarm(s) (FPR={fpr})")
        else:
            if fp > baseline_fp or (fpr is not None and fpr > baseline_fpr):
                reasons.append(f"False positive regression vs baseline: {fp} fp (FPR={fpr}) > baseline {baseline_fp} (FPR={baseline_fpr})")

        if baseline is not None and isinstance(baseline, Mapping):
            from wscan.benchmark_model import compute_baseline_diff

            effective_tier = tier if tier in ("candidate", "confirmed") else "confirmed"
            diff = compute_baseline_diff(current, baseline, tier=effective_tier)
            reg = tuple(diff.get("regressed", []))
            rem = tuple(diff.get("removed", []))
            regressed_cases = reg
            removed_cases = rem
            if reg:
                reasons.append(f"Baseline case regression: {len(reg)} case(s) regressed ({', '.join(reg)})")
            if rem:
                reasons.append(f"Baseline cases removed: {len(rem)} case(s) ({', '.join(rem)})")
            b_metrics = baseline.get("metrics") or {}
            b_tier = b_metrics.get(tier) or b_metrics.get("confirmed") or b_metrics.get("candidate") or {}
            b_recall = b_tier.get("recall")
            if b_recall is not None and recall is not None and recall < b_recall:
                reasons.append(f"Recall dropped vs baseline: {recall:.4f} < {b_recall:.4f}")
            b_prec = b_tier.get("precision")
            cur_prec = tier_metrics.get("precision")
            if b_prec is not None and cur_prec is not None and cur_prec < b_prec:
                reasons.append(f"Precision dropped vs baseline: {cur_prec:.4f} < {b_prec:.4f}")

    else:
        reasons.append(f"Invalid current scorecard type: {type(current).__name__}")
        expected_total = 0
        attempted_cases = 0
        incomplete_cases = 0
        fn = 0
        fp = 0
        recall = None
        fpr = None

    passed = len(reasons) == 0
    return DetectionGateVerdict(
        passed=passed,
        reasons=tuple(reasons),
        recall=recall,
        fpr=fpr,
        expected_total=expected_total,
        attempted_cases=attempted_cases,
        incomplete_cases=incomplete_cases,
        fn=fn,
        fp=fp,
        regressed_cases=regressed_cases,
        removed_cases=removed_cases,
    )
