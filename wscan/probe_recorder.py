"""probe 証跡台帳の recorder（append-only・I/O 分離）。

[probe_ledger](probe_ledger.py) の純粋 schema を使い、実際の試行を **append-only な正本**
`probe_attempts.jsonl` へ記録する recorder を提供する。scan 内で単調増加する attempt_id を
払い出し、outcome/role 別の件数と **書込み失敗** を manifest に残す。

契約:
- **No evidence, no COMPLETE**: 証跡の書込みに失敗したら握りつぶさず manifest に残す。scan 完了
  判定は `evidence_incomplete` を見る。
- **Evidence for every outcome**: matched だけでなく no-match/blocked/skipped/timeout/error も
  記録する（呼び出し側が outcome を付けて append する）。

**durability モデル（簡素化＝単一 source-of-truth）**:
台帳の write 失敗は稀（disk 異常）で、その試行の証跡は失われる。二源（成功=jsonl / 失敗=manifest）を
突合する複雑さを避け、次の単純な規律にする:
- **jsonl が唯一の正本**（成功試行の source of truth）。
- **write 失敗＝即 quarantine**: 以後の append を拒否し、run を evidence-incomplete とする
  （書けない＝EVIDENCE_INCOMPLETE と整合）。部分 tail への追記・継続はしない。
- **resume**: 成功件数は jsonl から再構築（単一 source）。前 run の不完全さ（write 失敗/欠落）は
  **1 個の欠落マーカー**として持ち越し `evidence_incomplete` を維持する（失敗試行の厳密な内訳を
  跨 run で再構成しない＝reconciliation を持たない）。新規 append は許可（disk が回復していれば継続）。
- crash 対策: 末尾の不完全行は parse-aware に修復（完全 JSON は delimiter を補い保持、断片は truncate）。
  manifest は temp+os.replace で原子的に置換。

I/O はここに閉じ、集計は純粋 `LedgerManifest` へ分離する（I/O と判定の分離規約）。全 transport
送信経路への配線は今後行う。
"""
from __future__ import annotations

import json
import os
import threading
from contextlib import contextmanager
from contextvars import ContextVar
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from wscan.probe_ledger import (
    ProbeAttemptRecord,
    ProbeOutcome,
    ProbeRole,
    derive_attempt_id,
    to_jsonl_line,
    sha256_hex,
)

LEDGER_FILENAME = "probe_attempts.jsonl"
MANIFEST_FILENAME = "probe_attempts_manifest.json"
_CURRENT_COMPLETION_UNIT = ContextVar("probe_completion_unit", default=None)


def completion_identity(key: str) -> str:
    """Keep checkpoint identity semantics without persisting URLs or field names."""
    return sha256_hex(key)

_VALID_ROLES = frozenset(r.value for r in ProbeRole)
_VALID_OUTCOMES = frozenset(o.value for o in ProbeOutcome)


def _role_key(role) -> str:
    return role.value if isinstance(role, ProbeRole) else str(role)


def _outcome_key(outcome) -> str:
    if isinstance(outcome, ProbeOutcome):
        return outcome.value
    return str(outcome) if outcome else "unrecorded"


@dataclass
class LedgerManifest:
    """台帳の集計（純粋・I/O 非依存）。件数・欠落・書込み失敗を保持し 0 Finding を安全へ丸めない。"""

    total: int = 0
    by_role: dict = field(default_factory=dict)
    by_outcome: dict = field(default_factory=dict)
    write_errors: list = field(default_factory=list)  # list[dict]: {error, role, outcome}

    def record(self, role, outcome, *, write_ok: bool, error: str = "") -> None:
        """1 試行を集計へ反映する（純粋）。成功/失敗いずれも件数内訳へ加算し、失敗は error も残す。"""
        self.total += 1
        rk = _role_key(role)
        ok = _outcome_key(outcome)
        self.by_role[rk] = self.by_role.get(rk, 0) + 1
        self.by_outcome[ok] = self.by_outcome.get(ok, 0) + 1
        if not write_ok:
            self.write_errors.append({"error": error or "write_failed", "role": rk, "outcome": ok})

    def note_gap(self, reason: str) -> None:
        """resume で検出した欠落（件数内訳は不明）を 1 マーカーとして残す。

        跨 run で失敗試行の厳密な内訳は再構成せず、`had_write_error` を維持する目的（No evidence,
        no COMPLETE のゲートを前 run の不完全さで倒し続ける）。件数（total 等）は動かさない。"""
        self.write_errors.append({"error": reason, "role": "", "outcome": "gap"})

    @property
    def had_write_error(self) -> bool:
        """証跡の欠落/書込み失敗があったか（No evidence, no COMPLETE の判定に使う）。"""
        return bool(self.write_errors)

    def to_dict(self) -> dict:
        return {
            "total": self.total,
            "by_role": dict(self.by_role),
            "by_outcome": dict(self.by_outcome),
            "write_errors": list(self.write_errors),
            "had_write_error": self.had_write_error,
        }


class ProbeLedger:
    """append-only な probe 台帳 writer。scan 単位。thread-safe（並列ワーカー対応）。

    attempt_id は `derive_attempt_id(scan_id, seq)` で決定論的に払い出す（resume 安定）。
    台帳 write に失敗すると **quarantine** し（`quarantined=True`）、以後の append を拒否する。
    `evidence_incomplete` は run が証跡を取り切れなかったか（＝No evidence, no COMPLETE のゲート）。
    """

    def __init__(self, output_dir, scan_id: str, *, enabled: bool = True) -> None:
        self.scan_id = scan_id
        self.enabled = enabled
        self._seq = 0
        self._lock = threading.Lock()
        self.manifest = LedgerManifest()
        self._quarantined = False
        self._manifest_write_failed = False
        self._path: Optional[Path] = None
        self.planned: dict[str, dict] = {}
        self.recorded: dict[str, list[dict]] = {}
        self.events: dict[str, dict] = {}
        if enabled and output_dir:
            self._path = Path(output_dir) / LEDGER_FILENAME
            self._restore_from_existing()

    def expect(self, key: str, check: str, *, rules=(), role="attack", reason="") -> str:
        unit = completion_identity(key)
        with self._lock:
            plan = {"check": check, "rules": list(rules), "role": role,
                    "reason": reason, "executed": False}
            prior = self.planned.setdefault(unit, plan)
            if any(prior[k] != plan[k] for k in ("check", "rules", "role", "reason")):
                self.manifest.note_gap("completion_plan_changed")
        return unit

    @contextmanager
    def unit_scope(self, unit: str):
        """Bind only this task's observations; restore even on cancellation."""
        token = _CURRENT_COMPLETION_UNIT.set((self, unit))
        with self._lock:
            self.planned[unit]["executed"] = False
        self.write_manifest()
        try:
            yield
        except BaseException:
            raise
        else:
            with self._lock:
                self.planned[unit]["executed"] = True
        finally:
            _CURRENT_COMPLETION_UNIT.reset(token)
            self.write_manifest()

    def current_unit(self) -> str:
        context = _CURRENT_COMPLETION_UNIT.get()
        return context[1] if context is not None and context[0] is self else ""

    def _index_completion(self, rec: dict) -> None:
        if rec.get("record_kind", "legacy") != "legacy":
            self.events[rec["attempt_id"]] = rec
        unit = rec.get("completion_unit")
        if unit and (not isinstance(unit, str) or len(unit) != 64
                     or any(c not in "0123456789abcdef" for c in unit)):
            self.manifest.note_gap("invalid_completion_identity")
            return
        if unit:
            rows = self.recorded.setdefault(unit, [])
        if unit and rec.get("outcome"):
            rows.append(rec)

    def _correlated_decisions(self):
        """Validate event causality from persisted rows, including comparison prerequisites."""
        def sequence(row):
            return int(row["attempt_id"].rpartition(":")[2])

        delivered_ids = {r.get("request_attempt_id") for r in self.events.values()
                         if r.get("record_kind") == "observation"
                         and (r.get("response") or {}).get("body_hash")
                         and (r.get("request") or {}).get("sent")
                         and r.get("parent_id") == r.get("request_attempt_id")
                         and all(r.get(k) == self.events.get(r.get("request_attempt_id"), {}).get(k)
                                 for k in ("scan_id", "check", "completion_unit", "injection_key", "role", "wave"))
                         and all((r.get("request") or {}).get(k) ==
                                 (self.events.get(r.get("request_attempt_id"), {}).get("request") or {}).get(k)
                                 for k in ("method", "url", "transport", "body_hash", "body_length"))}
        requests_by_unit = {}
        controls_by_parent = {}
        for event in self.events.values():
            if event.get("record_kind") == "request":
                requests_by_unit.setdefault(event.get("completion_unit"), []).append(event)
                if event.get("role") == "control":
                    controls_by_parent.setdefault(event.get("parent_id"), []).append(event)

        def same_unit(a, b):
            return all(a.get(k) == b.get(k) for k in ("scan_id", "check", "completion_unit", "injection_key"))

        def delivered(request_id, decision):
            request = self.events.get(request_id, {})
            return (request.get("record_kind") == "request" and same_unit(request, decision)
                    and request_id in delivered_ids)

        result = {}
        for unit, rows in self.recorded.items():
            accepted = []
            invalid_decision = False
            for row in rows:
                if row.get("record_kind", "legacy") == "legacy":
                    if row.get("check") not in {"sqli", "xss", "clickjacking", "security_headers"}:
                        accepted.append(row)
                    continue
                if row.get("record_kind") != "decision":
                    continue
                request_id = row.get("request_attempt_id")
                observation = self.events.get(row.get("parent_id"), {})
                baselines = row.get("baseline_attempt_ids", [])
                controls = row.get("control_attempt_ids", [])
                required_controls = {r["attempt_id"] for parent in [request_id, *baselines]
                                     for r in controls_by_parent.get(parent, ()) if same_unit(r, row)}
                if (observation.get("record_kind") != "observation"
                        or observation.get("request_attempt_id") != request_id
                        or not same_unit(row, observation) or not delivered(request_id, row)
                        or observation.get("role") != row.get("role")
                        or observation.get("wave") != row.get("wave")
                        or len(baselines) < (2 if row.get("check") == "sqli" else 1)
                        or len(set(baselines)) != len(baselines)
                        or not baselines or any(not delivered(ref, row) for ref in baselines + controls)
                        or not required_controls.issubset(controls)
                        or sequence(self.events[request_id]) >= sequence(observation)
                        or sequence(observation) >= sequence(row)
                        or any(sequence(self.events[ref]) >= sequence(self.events[request_id]) for ref in baselines)
                        or any(sequence(self.events[ref]) >= sequence(row) for ref in controls)
                        or any(self.events.get(ref, {}).get("role") != "baseline" for ref in baselines)
                        or any(self.events.get(ref, {}).get("role") != "control"
                               or not (self.events[ref].get("parent_id") == request_id
                                       or self.events[ref].get("parent_id") in baselines
                                       and self.events.get(request_id, {}).get("parent_id") == self.events[ref].get("parent_id"))
                               for ref in controls)):
                    invalid_decision = True
                    continue
                accepted.append(row)
            requests = requests_by_unit.get(unit, ())
            decided = {r.get("request_attempt_id") for r in accepted}
            failed = any(r.get("record_kind") == "decision" and not r.get("request_attempt_id") for r in rows)
            if failed or invalid_decision or any(r["attempt_id"] not in delivered_ids or
                             (r.get("role") == "attack" and r["attempt_id"] not in decided)
                             for r in requests):
                accepted = [r for r in accepted if r.get("record_kind", "legacy") == "legacy"]
            result[unit] = accepted
        from .browser_evidence import accepted_decisions
        for unit, decisions in accepted_decisions(self.events).items():
            result[unit] = decisions
        from .passive_evidence import accepted_decisions as passive_decisions
        for unit, decisions in passive_decisions(self.events).items():
            result[unit] = decisions
        return result

    def reconcile_persisted(self) -> None:
        """Re-read the source at completion so missing files/rows cannot pass on memory alone."""
        if self._path is None or not self.enabled:
            return
        restored = ProbeLedger(self._path.parent, self.scan_id)
        with self._lock:
            self.recorded = restored.recorded
            self.events = restored.events
            if restored.evidence_incomplete:
                self.manifest.note_gap("completion_evidence_restore_failed")
            if restored.planned != self.planned:
                self.manifest.note_gap("completion_plan_not_persisted")

    def completion_summary(self, selected, *, execution_success=True) -> dict:
        from .check_coverage import reconcile_evidence
        with self._lock:
            return reconcile_evidence(self.planned, self._correlated_decisions(), selected,
                                      logging_failed=self.evidence_incomplete or not self.enabled or self._path is None,
                                      execution_success=execution_success)

    @property
    def path(self) -> Optional[Path]:
        return self._path

    @property
    def quarantined(self) -> bool:
        """台帳 write に失敗して隔離中か（True の間 append は拒否）。"""
        return self._quarantined

    @property
    def evidence_incomplete(self) -> bool:
        """証跡を取り切れなかったか（write 失敗 or 前 run の欠落 or resume 検出の行欠落 or
        manifest 書出し失敗）。No evidence, no COMPLETE のリリースゲート。"""
        return (self._quarantined or self._manifest_write_failed
                or self.manifest.had_write_error)

    # ── restore ──────────────────────────────────────────────────────────
    def _repair_unterminated_tail(self, data: bytes) -> bool:
        """末尾が改行で終わらない場合、末尾行を parse して完全な object なら delimiter を補い、
        壊れた断片だけ truncate する。修復 I/O に失敗したら False（quarantine 側で扱う）。"""
        if not data or data.endswith(b"\n"):
            return True
        nl = data.rfind(b"\n")
        tail = data[nl + 1:]
        try:
            keep = isinstance(json.loads(tail.decode("utf-8")), dict)
        except (ValueError, UnicodeDecodeError):
            keep = False
        try:
            if keep:
                with open(self._path, "ab") as fh:
                    fh.write(b"\n")
            else:
                with open(self._path, "rb+") as fh:
                    fh.truncate(nl + 1)  # nl==-1 なら 0
                # 実行済み probe の不完全な証跡を捨てた＝欠落として gate を倒す。
                self.manifest.note_gap("ledger_tail_truncated")
        except OSError:
            return False
        return True

    def _valid_row(self, rec) -> bool:
        """復元行が正本レコードとして妥当か（identity と語彙）。破損行を成功に数えないための門番。"""
        if not isinstance(rec, dict):
            return False
        if rec.get("scan_id") != self.scan_id:
            return False  # foreign/missing scan_id＝別ファイル or 破損
        aid = str(rec.get("attempt_id", ""))
        head, sep, seq = aid.rpartition(":")
        # seq は ASCII 数字かつ長さ上限内（`²` 等の非 ASCII 数字や int() 変換上限超の巨大桁を弾く）。
        if (not sep or head != self.scan_id
                or not (seq.isascii() and seq.isdigit()) or len(seq) > 15):
            return False  # attempt_id が `<scan_id>:<seq>` 形でない（foreign prefix/壊れ連番）
        if rec.get("role") not in _VALID_ROLES:
            return False  # 語彙外の role
        outcome = rec.get("outcome")
        if outcome is not None and outcome not in _VALID_OUTCOMES:
            return False  # 語彙外の outcome（null は未記録として許容）
        if rec.get("record_kind", "legacy") not in {"legacy", "payload", "request", "observation", "decision", "browser", "passive_decision"}:
            return False
        if rec.get("record_kind") == "passive_decision":
            if (rec.get("check") not in {"clickjacking", "security_headers"}
                    or rec.get("actor") != "passive_header_oracle"
                    or rec.get("role") not in {"attack", "verify"}
                    or rec.get("browser") is not None
                    or rec.get("decision_version") != "1"
                    or not isinstance(rec.get("decision_rule"), str)
                    or not isinstance(rec.get("request"), dict)
                    or rec.get("response") is not None and not isinstance(rec["response"], dict)):
                return False
            response = rec.get("response")
            if response is not None and (
                    not isinstance(response.get("headers_hash"), str)
                    or type(response.get("headers_length")) is not int or response["headers_length"] < 0
                    or not isinstance(response.get("final_url"), str)
                    or response.get("status") is not None and type(response["status"]) is not int):
                return False
        if rec.get("record_kind") == "browser":
            from .probe_ledger import BrowserEvidence
            import dataclasses
            b = rec.get("browser")
            fields = {f.name for f in dataclasses.fields(BrowserEvidence)}
            if not isinstance(b, dict) or set(b) != fields:
                return False
            if (any(not isinstance(v, str) for k, v in b.items()
                    if k not in {"index", "total", "input_length", "complete", "inputs", "required_inputs"})
                    or any(type(b[k]) is not int or b[k] < 0 for k in ("index", "total", "input_length", "required_inputs"))
                    or type(b["complete"]) is not bool
                    or not isinstance(b["inputs"], list)
                    or any(not isinstance(i, dict) or set(i) != {"source_id", "body_hash", "body_length", "captured"}
                           or not isinstance(i["source_id"], str) or not isinstance(i["body_hash"], str)
                           or type(i["body_length"]) is not int or i["body_length"] < 0
                           or type(i["captured"]) is not bool for i in b["inputs"])
                    or rec.get("request") is not None
                    or rec.get("response") is not None):
                return False
        if rec.get("record_kind", "legacy") != "legacy":
            if any(not isinstance(rec.get(k, ""), str) for k in
                   ("parent_id", "request_attempt_id", "check", "wave", "injection_key")):
                return False
            if any(not isinstance(rec.get(k, []), list) or
                   any(not isinstance(ref, str) for ref in rec.get(k, []))
                   for k in ("baseline_attempt_ids", "control_attempt_ids")):
                return False
            if any(rec.get(k) is not None and not isinstance(rec.get(k), dict) for k in ("request", "response")):
                return False
        return True

    def _restore_from_existing(self) -> None:
        """既存台帳から seq/manifest を復元する（単一 source＝jsonl）。前 run の不完全さは 1 マーカーで継承。"""
        if self._path is None:
            return
        max_seq = 0
        restored_rows = 0
        if self._path.exists():
            try:
                data = self._path.read_bytes()
            except OSError:
                # 既存正本を読めない＝以後の append を止める（ID 再発行/欠落を防ぐ）
                self._quarantined = True
                self.manifest.note_gap("ledger_unreadable_on_resume")
                return
            if not self._repair_unterminated_tail(data):
                self._quarantined = True
                self.manifest.note_gap("ledger_tail_repair_failed")
                return
            skipped = 0
            duplicates = 0
            seen_seqs: set = set()
            try:
                with open(self._path, encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            rec = json.loads(line)
                        except ValueError:
                            skipped += 1
                            continue  # 壊れた行はスキップ（＝正本の破損＝証跡欠落）
                        if not self._valid_row(rec):
                            skipped += 1
                            continue  # schema 不正（非 object/foreign scan_id/壊れ id/語彙外 role）
                        seq = int(str(rec["attempt_id"]).rpartition(":")[2])  # _valid_row 済で安全
                        max_seq = max(max_seq, seq)
                        if seq in seen_seqs:
                            duplicates += 1  # 同一 attempt_id の重複＝正本の破損
                        else:
                            seen_seqs.add(seq)
                        restored_rows += 1
                        self._index_completion(rec)
                        self.manifest.record(rec.get("role", ""), rec.get("outcome"), write_ok=True)
            except (OSError, UnicodeDecodeError):
                # 読取り不能/不正バイト列＝正本を信頼できない。以後の append を止める。
                self._quarantined = True
                self.manifest.note_gap("ledger_read_failed_on_resume")
                return
            if skipped:
                # 破損/非 object 行が正本にある＝証跡欠落。gate を倒す（No evidence, no COMPLETE）。
                self.manifest.note_gap("ledger_rows_skipped_on_resume")
            if duplicates:
                # 同一 attempt_id の重複＝正本の破損（穴を隠しうる）。
                self.manifest.note_gap("ledger_duplicate_attempt_id")
            if max_seq > len(seen_seqs):
                # 連番に穴（例: 並列 worker が id を採番・永続化する前に crash）＝試行の欠落。
                # 重複が穴を隠さないよう **distinct 連番数** と比較する。
                self.manifest.note_gap("ledger_sequence_hole")
        self._seq = max_seq
        # 前 run の manifest から「不完全だった事実」だけを継承する（内訳の再構成はしない）。
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        if self.recorded and not manifest_path.exists():
            self.manifest.note_gap("completion_plan_missing_on_resume")
        if manifest_path.exists():
            try:
                prior = json.loads(manifest_path.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                # 既存 manifest が読めない/壊れている＝欠落状態を復元できない
                self.manifest.note_gap("prior_manifest_unreadable")
                return
            if not isinstance(prior, dict):
                # 非 object の manifest は破損とみなす
                self.manifest.note_gap("prior_manifest_not_object")
                return
            plans = prior.get("planned_units", {})
            if isinstance(plans, dict) and all(
                isinstance(key, str) and len(key) == 64 and all(c in "0123456789abcdef" for c in key)
                and isinstance(plan, dict) and isinstance(plan.get("check"), str)
                and isinstance(plan.get("rules"), list) and all(isinstance(r, str) for r in plan["rules"])
                and plan.get("role") in _VALID_ROLES and type(plan.get("executed")) is bool
                and isinstance(plan.get("reason", ""), str)
                for key, plan in plans.items()
            ):
                self.planned = plans
            else:
                self.manifest.note_gap("prior_completion_plan_invalid")
            if set(self.recorded) - set(self.planned):
                self.manifest.note_gap("completion_units_missing_on_resume")
            # seq は前 run の発行 ID 総数（=max seq）も考慮（trailing failure/stale jsonl 対策）
            try:
                prior_total = int(prior.get("total") or 0)
            except (ValueError, TypeError):
                prior_total = 0
                self.manifest.note_gap("prior_manifest_bad_total")
            self._seq = max(self._seq, prior_total)
            # 前 run が不完全（write 失敗）だった事実を継承（内訳は再構成しない）。
            errs = prior.get("write_errors")
            if errs:  # 非空 list/その他 truthy を「不完全あり」とみなす
                self.manifest.note_gap("prior_run_evidence_incomplete")
            if prior_total > restored_rows:
                # 例: jsonl が外部で削除/truncate されたのに manifest は多い＝行が失われている
                self.manifest.note_gap("ledger_rows_missing_on_resume")

    # ── append / manifest ────────────────────────────────────────────────
    def next_attempt_id(self) -> str:
        """次の attempt_id を払い出す（単調増加・決定論・thread-safe）。"""
        with self._lock:
            self._seq += 1
            return derive_attempt_id(self.scan_id, self._seq)

    def append(self, record: ProbeAttemptRecord) -> bool:
        """試行レコードを台帳へ追記する。成功で True。

        無効（enabled=False / 出力先なし）は no-op で True。quarantine 中（過去の write 失敗）は
        書込まず失敗として記録し False。write 失敗時は quarantine して以後の append を拒否する
        （部分 tail への連結を構造的に防ぐ）。判定・write・集計は同一 critical section で行う。
        """
        if not (self.enabled and self._path is not None):
            return True
        with self._lock:
            if self._quarantined:
                self.manifest.record(record.role, record.outcome, write_ok=False,
                                     error="ledger_quarantined")
                return False
            if record.scan_id != self.scan_id:
                # 別 scan のレコードを誤って渡された＝混入を正本へ書かない（呼び出し側バグ）。
                self.manifest.record(record.role, record.outcome, write_ok=False,
                                     error="foreign_scan_record")
                return False
            try:
                line = to_jsonl_line(record)
                with open(self._path, "a", encoding="utf-8") as fh:
                    fh.write(line + "\n")
            except (OSError, ValueError, UnicodeError) as exc:
                # write/直列化/エンコード失敗（不正 UTF-8・lone surrogate 等）＝証跡は失われた。
                # 以後の append を止める（quarantine）。
                self._quarantined = True
                self.manifest.record(record.role, record.outcome, write_ok=False,
                                     error=f"{type(exc).__name__}: {exc}")
                return False
            self.manifest.record(record.role, record.outcome, write_ok=True)
            self._index_completion(json.loads(line))
            return True

    def write_manifest(self, *, selected=None, execution_success=True) -> bool:
        """manifest を JSON で原子的に書き出す（temp+os.replace）。scan 完了時に件数・欠落を残す。"""
        if not (self.enabled and self._path is not None):
            return False
        manifest_path = self._path.with_name(MANIFEST_FILENAME)
        tmp_path = manifest_path.with_name(MANIFEST_FILENAME + ".tmp")
        try:
            with self._lock:
                # これから書く manifest が回復後の状態を表すよう、snapshot 前に sticky flag を
                # 楽観的に解除する（成功すれば evidence_incomplete は真の gap のみを反映）。失敗したら
                # 下の except で再度立てる。順序を逆にすると回復済みでも incomplete が永続化される。
                self._manifest_write_failed = False
                data = self.manifest.to_dict()
                data["scan_id"] = self.scan_id
                data["logical_requests"] = sum(r.get("record_kind") == "request" for r in self.events.values())
                data["ledger"] = LEDGER_FILENAME
                data["quarantined"] = self._quarantined
                data["evidence_incomplete"] = self.evidence_incomplete
                data["planned_units"] = {key: dict(plan) for key, plan in self.planned.items()}
                from .check_coverage import reconcile_evidence
                data["completion"] = reconcile_evidence(
                    self.planned, self._correlated_decisions(),
                    selected if selected is not None else {p["check"] for p in self.planned.values()},
                    logging_failed=self.evidence_incomplete, execution_success=execution_success,
                )
                tmp_path.write_text(
                    json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True),
                    encoding="utf-8",
                )
                os.replace(tmp_path, manifest_path)
            return True
        except (OSError, UnicodeError):
            # manifest を永続化できない（I/O or lone surrogate 等の encode 失敗）＝完了証跡が残らない。
            # gate を倒す（caller が返り値を見落としても evidence_incomplete で COMPLETE を防ぐ）。
            with self._lock:
                self._manifest_write_failed = True
                if self.planned:
                    self.manifest.note_gap("completion_manifest_write_failed")
            return False
