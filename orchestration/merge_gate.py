"""PR マージ可否ゲート（read-only・決定論・fail closed）。

CLAUDE.md の「通常ツール層＝確実性」と同じ思想で、**判定は決定論的な純粋関数**が握る。
本モジュールは GitHub を**一切変更しない**（merge もコメントも投稿もしない）。ネットワーク
アクセスも行わず、入力 JSON だけを見て `ready` を返す read-only な gate である。

入力は ``gh`` の出力をそのまま流し込める形にしてある（実行は呼び出し側＝本モジュールは
subprocess を起動しない）::

    gh pr view 190 --json number,state,isDraft,mergeable,mergeStateStatus,headRefOid,\\
        statusCheckRollup,reviews \\
      | jq '. + {requiredChecks:["test"], evidence:{...}}' \\
      | python -m orchestration.merge_gate

**fail closed**: 判定に必要な証跡が欠けている場合は「安全側＝not ready」に倒す。
「情報が無い」を「問題が無い」と読み替えない（0 findings＝安全ではない、と同じ規律）。

``ready: true`` には次の**すべて**が必要:

1. PR が open・非 draft・GitHub 上 mergeable（衝突なし）。
2. **現在の head** に対して required CI が全て成功している（古い commit の成功は数えない）。
3. changes-requested なレビューが残っていない（reviewer 毎の最新状態で判定）。
4. 未解決（unresolved）のレビュースレッドが無い。
5. ローカルの独立レビュー・セキュリティレビュー・受入確認の証跡が明示的に ``PASS``。

出力は ``{"ready": bool, "reasons": [...]}``（reasons は決定論的な順序・重複排除済み）。
``ready`` が true のときも「何を根拠に通したか」を ``reasons`` に残す（証跡を空にしない）。
"""
from __future__ import annotations

import argparse
import json
import sys
from typing import Any, Iterable, Mapping, Optional, Sequence

# 必須のローカル証跡キー（この3つが揃って PASS でなければ通さない）
REQUIRED_EVIDENCE = ("independent_review", "security_review", "acceptance")

# mergeStateStatus のうち「マージして安全」と見なす値。列挙にない値は fail closed。
# BLOCKED(必須レビュー未達) / DIRTY(衝突) / BEHIND / UNSTABLE(CI 失敗) / UNKNOWN は通さない。
_SAFE_MERGE_STATE = frozenset({"CLEAN", "HAS_HOOKS"})

# review の state のうち「その reviewer の意思表示」として最新判定に使う値。
# COMMENTED は APPROVED/CHANGES_REQUESTED を上書きしない（GitHub 準拠）。
_DECISIVE_REVIEW_STATES = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})

# CI の合格と見なす結論。fail closed のため SUCCESS のみ（NEUTRAL/SKIPPED は通さない）。
_PASSING_CONCLUSIONS = frozenset({"SUCCESS"})


def _text(value: Any) -> str:
    """スカラを比較用の正規化文字列へ（None/非文字列も安全に潰す）。"""
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value).strip()


def _upper(value: Any) -> str:
    return _text(value).upper()


def _pick(payload: Mapping[str, Any], *names: str, default: Any = None) -> Any:
    """camelCase（gh 由来）と snake_case（手書き JSON）の両方を受ける。"""
    for name in names:
        if name in payload and payload[name] is not None:
            return payload[name]
    return default


def _as_list(value: Any) -> list[Any]:
    """リスト以外（None・単一オブジェクト）を安全にリスト化する。"""
    if value is None:
        return []
    if isinstance(value, Mapping):
        return [value]
    if isinstance(value, (list, tuple)):
        return list(value)
    return []


def _dedupe(reasons: Iterable[str]) -> list[str]:
    """出現順を保ったまま重複排除（決定論的な出力のため）。"""
    seen: set[str] = set()
    out: list[str] = []
    for reason in reasons:
        if reason not in seen:
            seen.add(reason)
            out.append(reason)
    return out


def _short(sha: str) -> str:
    return sha[:7] if sha else "(unknown)"


# --- 個別ゲート（いずれも純粋関数：入力→理由リスト） -----------------------


def check_pr_state(payload: Mapping[str, Any]) -> list[str]:
    """PR 自体がマージ可能な状態か（open・非 draft・衝突なし）。"""
    reasons: list[str] = []

    state = _upper(_pick(payload, "state", default=""))
    if not state:
        reasons.append("pr: state unknown (fail closed)")
    elif state != "OPEN":
        reasons.append(f"pr: state is {state}, expected OPEN")

    if bool(_pick(payload, "isDraft", "is_draft", default=False)):
        reasons.append("pr: draft PRs are not mergeable")

    mergeable = _pick(payload, "mergeable", default=None)
    if mergeable is None:
        reasons.append("pr: mergeable unknown (fail closed)")
    elif isinstance(mergeable, bool):
        # REST API 形式（true/false/null）。
        if not mergeable:
            reasons.append("pr: not mergeable (conflicts)")
    else:
        token = _upper(mergeable)
        if token != "MERGEABLE":
            reasons.append(f"pr: mergeable is {token or '(empty)'}, expected MERGEABLE")

    # mergeStateStatus は任意。与えられたら安全側の値だけを通す。
    merge_state = _upper(_pick(payload, "mergeStateStatus", "merge_state_status", default=""))
    if merge_state and merge_state not in _SAFE_MERGE_STATE:
        reasons.append(f"pr: mergeStateStatus is {merge_state}, not mergeable-clean")

    return reasons


def _rollup_entry(entry: Mapping[str, Any]) -> tuple[str, str, str, str]:
    """statusCheckRollup の 1 件を (name, conclusion, sha, sort_key) へ正規化。

    CheckRun（name/status/conclusion）と StatusContext（context/state）の両形式を吸収する。
    CheckRun は ``status`` が COMPLETED でなければ（queued/in_progress）未完了として扱う。
    """
    name = _text(_pick(entry, "name", "context", default=""))

    if "conclusion" in entry or "status" in entry:
        status = _upper(_pick(entry, "status", default=""))
        conclusion = _upper(_pick(entry, "conclusion", default=""))
        if status and status != "COMPLETED":
            conclusion = status or "PENDING"
        elif not conclusion:
            conclusion = "PENDING"
    else:
        conclusion = _upper(_pick(entry, "state", default="")) or "PENDING"

    commit = _pick(entry, "commit", default=None)
    sha = ""
    if isinstance(commit, Mapping):
        sha = _text(_pick(commit, "oid", "sha", default=""))
    else:
        sha = _text(_pick(entry, "headSha", "head_sha", "sha", default=""))

    # 再実行（同名 check の複数エントリ）は「最後に完了したもの」を採用する。
    sort_key = _text(_pick(entry, "completedAt", "completed_at", "startedAt", "started_at", default=""))
    return name, conclusion, sha, sort_key


def check_ci(payload: Mapping[str, Any]) -> list[str]:
    """**現在の head** に対して required CI が全て成功しているか。

    - head sha が不明なら fail closed（どの commit の CI か確定できない）。
    - required_checks が空なら fail closed（CI 証跡なしで通さない）。
    - エントリが head と違う sha を持つ場合は「古い実行」として無視する
      （＝required check が欠落扱いになり not ready に倒れる）。
    - 同名 check が複数あるときは completedAt が最後のもの（再実行の結果）を採用。
    """
    reasons: list[str] = []
    head = _text(_pick(payload, "headRefOid", "head_sha", "headSha", default=""))
    if not head:
        reasons.append("ci: head sha unknown (fail closed)")

    required = [_text(c) for c in _as_list(_pick(payload, "requiredChecks", "required_checks", default=[]))]
    required = [c for c in required if c]
    if not required:
        reasons.append("ci: no required checks declared (fail closed)")

    # head 上の最新結果だけを畳み込む。
    latest: dict[str, tuple[str, str]] = {}  # name -> (sort_key, conclusion)
    stale: set[str] = set()
    for entry in _as_list(_pick(payload, "statusCheckRollup", "status_check_rollup", "checks", default=[])):
        if not isinstance(entry, Mapping):
            continue
        name, conclusion, sha, sort_key = _rollup_entry(entry)
        if not name:
            continue
        if sha and head and sha != head:
            stale.add(name)
            continue  # 古い commit の実行は現 head の証跡にならない
        prev = latest.get(name)
        if prev is None or sort_key >= prev[0]:
            latest[name] = (sort_key, conclusion)

    for name in sorted(set(required)):
        found = latest.get(name)
        if found is None:
            if name in stale:
                reasons.append(f"ci: required check '{name}' has no run on head {_short(head)} (stale result only)")
            else:
                reasons.append(f"ci: required check '{name}' missing on head {_short(head)}")
            continue
        conclusion = found[1]
        if conclusion not in _PASSING_CONCLUSIONS:
            reasons.append(f"ci: required check '{name}' is {conclusion or 'PENDING'} on head {_short(head)}")

    return reasons


def check_reviews(payload: Mapping[str, Any]) -> list[str]:
    """changes-requested なレビューが残っていないか（reviewer 毎の最新状態）。"""
    reasons: list[str] = []
    latest: dict[str, tuple[str, int, str]] = {}  # login -> (submittedAt, index, state)

    for index, review in enumerate(_as_list(_pick(payload, "reviews", default=[]))):
        if not isinstance(review, Mapping):
            continue
        state = _upper(_pick(review, "state", default=""))
        if state not in _DECISIVE_REVIEW_STATES:
            continue  # COMMENTED 等は意思表示を上書きしない
        author = _pick(review, "author", default=None)
        if isinstance(author, Mapping):
            login = _text(_pick(author, "login", "name", default=""))
        else:
            login = _text(_pick(review, "user", "login", default=""))
        login = login or f"(anonymous#{index})"
        stamp = _text(_pick(review, "submittedAt", "submitted_at", "createdAt", "created_at", default=""))
        prev = latest.get(login)
        if prev is None or (stamp, index) >= (prev[0], prev[1]):
            latest[login] = (stamp, index, state)

    for login in sorted(latest):
        if latest[login][2] == "CHANGES_REQUESTED":
            reasons.append(f"review: changes requested by {login}")

    # reviewDecision が明示的に CHANGES_REQUESTED なら、reviews 配列が無くても拾う。
    decision = _upper(_pick(payload, "reviewDecision", "review_decision", default=""))
    if decision == "CHANGES_REQUESTED" and not reasons:
        reasons.append("review: reviewDecision is CHANGES_REQUESTED")

    return reasons


def check_threads(payload: Mapping[str, Any]) -> list[str]:
    """未解決のレビュースレッドが無いか（outdated でも未解決なら通さない）。"""
    unresolved = 0
    paths: list[str] = []
    for thread in _as_list(_pick(payload, "reviewThreads", "review_threads", default=[])):
        if not isinstance(thread, Mapping):
            continue
        resolved = _pick(thread, "isResolved", "is_resolved", "resolved", default=None)
        if resolved is None:
            # 解決状態が読めないスレッドは未解決とみなす（fail closed）。
            unresolved += 1
            paths.append(_text(_pick(thread, "path", default="")) or "(unknown path)")
            continue
        if not bool(resolved):
            unresolved += 1
            paths.append(_text(_pick(thread, "path", default="")) or "(unknown path)")

    if not unresolved:
        return []
    shown = ", ".join(sorted(set(paths))[:5])
    return [f"threads: {unresolved} unresolved review thread(s) [{shown}]"]


def _evidence_verdict(raw: Any) -> tuple[str, str]:
    """証跡エントリを (verdict, head_sha) へ正規化。文字列形式とオブジェクト形式を許す。"""
    if isinstance(raw, Mapping):
        verdict = _upper(_pick(raw, "verdict", "status", "result", default=""))
        sha = _text(_pick(raw, "head_sha", "headSha", "commit", default=""))
        return verdict, sha
    return _upper(raw), ""


def check_evidence(payload: Mapping[str, Any]) -> list[str]:
    """ローカルの独立レビュー・セキュリティレビュー・受入確認が明示的に PASS か。

    - 3 種すべてが必要。欠落・空・PASS 以外はすべて not ready（fail closed）。
    - オブジェクト形式で ``head_sha`` を添えた場合、現 head と一致しなければ「古い証跡」
      として無効にする（別 commit に対する PASS を流用させない）。
    """
    reasons: list[str] = []
    evidence = _pick(payload, "evidence", default=None)
    if not isinstance(evidence, Mapping):
        return [f"evidence: missing '{key}' (fail closed)" for key in REQUIRED_EVIDENCE]

    head = _text(_pick(payload, "headRefOid", "head_sha", "headSha", default=""))
    for key in REQUIRED_EVIDENCE:
        if key not in evidence or evidence[key] is None:
            reasons.append(f"evidence: missing '{key}' (fail closed)")
            continue
        verdict, sha = _evidence_verdict(evidence[key])
        if verdict != "PASS":
            reasons.append(f"evidence: '{key}' is {verdict or '(empty)'}, expected PASS")
            continue
        if sha and head and sha != head:
            reasons.append(
                f"evidence: '{key}' recorded for {_short(sha)}, not current head {_short(head)}"
            )

    return reasons


# --- 統合判定 -------------------------------------------------------------


def evaluate(payload: Any) -> dict:
    """マージ可否を判定する純粋関数（I/O なし・GitHub を変更しない）。

    返り値は JSON 直列化可能な dict::

        {"ready": bool, "reasons": [...], "pr": <number|null>, "head_sha": "<sha>"}

    ``payload`` が dict でない（空・壊れている）場合も例外を投げず not ready に倒す。
    """
    if not isinstance(payload, Mapping):
        return {
            "ready": False,
            "reasons": ["input: payload is not a JSON object (fail closed)"],
            "pr": None,
            "head_sha": "",
        }

    reasons: list[str] = []
    for gate in (check_pr_state, check_ci, check_reviews, check_threads, check_evidence):
        reasons.extend(gate(payload))
    reasons = _dedupe(reasons)

    number = _pick(payload, "number", "pr", default=None)
    head = _text(_pick(payload, "headRefOid", "head_sha", "headSha", default=""))
    ready = not reasons
    if ready:
        # 通した根拠も残す（証跡を空にしない）。
        reasons = [
            "pr: open, non-draft, mergeable",
            f"ci: all required checks succeeded on head {_short(head)}",
            "review: no changes-requested reviews",
            "threads: no unresolved review threads",
            "evidence: independent-review, security-review, acceptance all PASS",
        ]

    return {
        "ready": ready,
        "reasons": reasons,
        "pr": number if isinstance(number, int) else (_text(number) or None),
        "head_sha": head,
    }


# --- CLI ------------------------------------------------------------------


def _load(source: Optional[str]) -> tuple[Any, Optional[str]]:
    """入力 JSON を読む。(payload, error) を返し、例外は投げない。"""
    try:
        if source in (None, "-"):
            raw = sys.stdin.read()
        else:
            with open(source, "r", encoding="utf-8") as fh:
                raw = fh.read()
    except OSError as exc:
        return None, f"input: cannot read {source!r} ({exc.__class__.__name__})"

    if not raw.strip():
        return None, "input: empty input (fail closed)"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        return None, f"input: invalid JSON ({exc.msg} at line {exc.lineno})"


def main(argv: Optional[Sequence[str]] = None) -> int:
    """read-only な CLI。exit code: 0=ready / 1=not ready / 2=入力エラー。"""
    parser = argparse.ArgumentParser(
        prog="merge_gate",
        description="PR merge readiness gate (read-only, deterministic, fail closed). "
        "Reads evidence JSON from stdin or --input; never merges or mutates GitHub.",
    )
    parser.add_argument("--input", "-i", default="-", help="evidence JSON file ('-' = stdin, default)")
    args = parser.parse_args(list(argv) if argv is not None else None)

    payload, error = _load(args.input)
    if error is not None:
        json.dump({"ready": False, "reasons": [error], "pr": None, "head_sha": ""}, sys.stdout, indent=2)
        sys.stdout.write("\n")
        return 2

    result = evaluate(payload)
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 0 if result["ready"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
