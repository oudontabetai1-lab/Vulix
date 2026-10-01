"""PR マージ可否ゲート（read-only・決定論・fail closed・stdlib のみ）。

入力 JSON だけを見て ``{"ready", "reasons", "pr", "head_sha"}`` を返す純粋評価器＋CLI。
GitHub API は叩かず merge もコメントもしない（subprocess/network を import しない）。

判定材料が欠けていれば通さない（「情報が無い」を「問題が無い」と読み替えない）:
``isDraft``/``mergeStateStatus``/``reviews``/``reviewThreads`` はキー欠落・null で失格。CI は現
head SHA へ厳密 pin された単一エントリの SUCCESS のみ合格（SHA 欠落・stale・同名重複は失格）。
independent/security/acceptance は ``{"verdict":"PASS","head_sha":<現 head>,"ref":<出典>}`` のみ有効
（``ref`` は verdict の出所＝レビュー URL/ID 等。無ければ失格＝手書き PASS を通さない）。
``tier``（A/B/C・欠落/不明は A 扱い）が A のときは ``nightlyRecall.conclusion`` が SUCCESS であることも要求する
（main の nightly recall が赤のまま検出系 PR を通さない）。B/C は検査しない。SUCCESS でも ``nightlyRecall.created_at`` が ``collectedAt``（収集時刻・決定論のため入力から取る）
より 36 時間超古い／どちらかが読めないなら失格（古い成功を今の健全性の証拠にしない）。
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path
from typing import Any, Mapping, Optional, Sequence

REQUIRED_EVIDENCE = ("independent_review", "security_review", "acceptance")
_SAFE_MERGE_STATE = frozenset({"CLEAN", "HAS_HOOKS"})
_DECISIVE = frozenset({"APPROVED", "CHANGES_REQUESTED", "DISMISSED"})
_HEAD_KEYS = ("headRefOid", "head_sha", "headSha")


def _pick(src: Any, *names: str, default: Any = None) -> Any:
    """camelCase(gh 由来)と snake_case(手書き JSON)の両方を受ける。null は未提供扱い。"""
    if isinstance(src, Mapping):
        for n in names:
            if src.get(n) is not None:
                return src[n]
    return default


def _has(src: Any, *names: str) -> bool:
    return isinstance(src, Mapping) and any(src.get(n) is not None for n in names)


def _text(v: Any) -> str:
    if v is None or isinstance(v, (list, tuple, dict)):
        return ""
    return ("true" if v else "false") if isinstance(v, bool) else str(v).strip()


def _upper(src: Any, *names: str) -> str:
    return (_text(_pick(src, *names, default="")) if names else _text(src)).upper()


def _sha(src: Any, *names: str) -> str:
    return _text(_pick(src, *names, default="")).lower()


def _as_list(v: Any) -> list:
    return [v] if isinstance(v, Mapping) else (list(v) if isinstance(v, (list, tuple)) else [])


def _short(sha: str) -> str:
    return sha[:7] if sha else "(unknown)"


def _check_pr(p: Mapping[str, Any], out: list[str]) -> None:
    """open・非 draft・衝突なし・mergeStateStatus が clean 系か。"""
    if (state := _upper(p, "state")) != "OPEN":
        out.append(f"pr: state is {state or 'unknown'}, expected OPEN")
    if not _has(p, "isDraft", "is_draft"):
        out.append("pr: isDraft missing (fail closed)")
    elif not isinstance(_pick(p, "isDraft", "is_draft"), bool):
        out.append("pr: isDraft must be a boolean (fail closed)")
    elif _pick(p, "isDraft", "is_draft"):
        out.append("pr: draft PRs are not mergeable")
    m = _pick(p, "mergeable", default=None)
    if m is None:
        out.append("pr: mergeable unknown (fail closed)")
    elif m is not True and _upper(m) != "MERGEABLE":
        out.append("pr: not mergeable (conflicts)" if m is False
                   else f"pr: mergeable is {_upper(m) or '(empty)'}, expected MERGEABLE")
    if not _has(p, "mergeStateStatus", "merge_state_status"):
        out.append("pr: mergeStateStatus missing (fail closed)")
    elif (ms := _upper(p, "mergeStateStatus", "merge_state_status")) not in _SAFE_MERGE_STATE:
        out.append(f"pr: mergeStateStatus is {ms or '(empty)'}, not mergeable-clean")


def _check_ci(p: Mapping[str, Any], head: str, out: list[str]) -> None:
    """必須 CI が「現 head に厳密 pin された単一エントリの SUCCESS」か。"""
    if not head:
        out.append("ci: head sha unknown (fail closed)")
    required = sorted({_text(c) for c in _as_list(_pick(p, "requiredChecks", "required_checks", default=[])) if _text(c)})
    if not required:
        out.append("ci: no required checks declared (fail closed)")
    pinned: dict[str, str] = {}
    dupes: set[str] = set()
    unpinned: set[str] = set()
    for e in _as_list(_pick(p, "statusCheckRollup", "status_check_rollup", "checks", default=[])):
        if not (name := _text(_pick(e, "name", "context", default=""))):
            continue
        c = _pick(e, "commit", default=None)
        sha = _sha(c, "oid", "sha") if isinstance(c, Mapping) else _sha(e, "headSha", "head_sha", "sha", "commit")
        if not head or sha != head:  # SHA 欠落も stale も現 head の証跡にならない
            unpinned.add(name)
        elif name in pinned:
            dupes.add(name)  # 同名重複はどちらが真か決められない＝曖昧
        else:
            status = _upper(e, "status")
            pinned[name] = status if status and status != "COMPLETED" else (_upper(e, "conclusion", "state") or "PENDING")
    for name in required:
        if name in dupes:
            out.append(f"ci: required check '{name}' has duplicate entries on head {_short(head)} (ambiguous, fail closed)")
        elif name not in pinned:
            out.append(f"ci: required check '{name}' missing on head {_short(head)}"
                       + (" (only unpinned/stale results)" if name in unpinned else ""))
        elif pinned[name] != "SUCCESS":
            out.append(f"ci: required check '{name}' is {pinned[name]} on head {_short(head)}")


def _check_reviews(p: Mapping[str, Any], out: list[str]) -> None:
    """CHANGES_REQUESTED が残っていないか（reviewer 毎の最新の意思表示で判定）。"""
    if not _has(p, "reviews"):
        return out.append("review: reviews missing (fail closed)")
    reviews = _pick(p, "reviews")
    if not isinstance(reviews, list):
        return out.append("review: reviews must be a list (fail closed)")
    latest: dict[str, tuple[str, int, str]] = {}
    for i, r in enumerate(reviews):
        if not isinstance(r, Mapping):
            out.append("review: invalid review entry (fail closed)")
            continue
        if (state := _upper(r, "state")) not in _DECISIVE:
            continue  # COMMENTED 等は意思表示を上書きしない
        a = _pick(r, "author", default=None)
        who = _text(_pick(a, "login", "name", default="")) if isinstance(a, Mapping) else _text(_pick(r, "user", "login", default=""))
        key, stamp = who or f"(anonymous#{i})", _text(_pick(r, "submittedAt", "submitted_at", "createdAt", "created_at", default=""))
        if not stamp:
            out.append("review: submittedAt missing (fail closed)")
            continue
        if (prev := latest.get(key)) is None or (stamp, i) >= (prev[0], prev[1]):
            latest[key] = (stamp, i, state)
    blocked = [f"review: changes requested by {w}" for w in sorted(latest) if latest[w][2] == "CHANGES_REQUESTED"]
    if not blocked and _upper(p, "reviewDecision", "review_decision") == "CHANGES_REQUESTED":
        blocked.append("review: reviewDecision is CHANGES_REQUESTED")
    out.extend(blocked)


def _check_threads(p: Mapping[str, Any], out: list[str]) -> None:
    """未解決スレッドが無いか（解決状態が読めないものは未解決扱い）。"""
    if not _has(p, "reviewThreads", "review_threads"):
        return out.append("threads: reviewThreads missing (fail closed)")
    threads = _pick(p, "reviewThreads", "review_threads")
    if not isinstance(threads, list):
        return out.append("threads: reviewThreads must be a list (fail closed)")
    paths = []
    for thread in threads:
        if not isinstance(thread, Mapping):
            out.append("threads: invalid review thread (fail closed)")
            continue
        resolved = _pick(thread, "isResolved", "is_resolved", "resolved")
        if not isinstance(resolved, bool):
            out.append("threads: isResolved must be a boolean (fail closed)")
        elif not resolved:
            paths.append(_text(_pick(thread, "path", default="")) or "(unknown path)")
    if paths:
        out.append(f"threads: {len(paths)} unresolved review thread(s) [{', '.join(sorted(set(paths))[:5])}]")


def _check_evidence(p: Mapping[str, Any], head: str, out: list[str]) -> None:
    """3 種の証跡が現 head に pin された PASS オブジェクトか（文字列 PASS は不可）。"""
    ev = _pick(p, "evidence", default=None)
    for key in REQUIRED_EVIDENCE:
        item = ev.get(key) if isinstance(ev, Mapping) else None
        if item is None:
            out.append(f"evidence: missing '{key}' (fail closed)")
        elif not isinstance(item, Mapping):
            out.append(f"evidence: '{key}' must be an object with verdict and head_sha (fail closed)")
        elif (v := _upper(item, "verdict", "status", "result")) != "PASS":
            out.append(f"evidence: '{key}' is {v or '(empty)'}, expected PASS")
        elif not _text(item.get("ref")):
            out.append(f"evidence: '{key}' has no ref (provenance required, fail closed)")
        elif not (sha := _sha(item, "head_sha", "headSha", "commit", "sha")):
            out.append(f"evidence: '{key}' has no head_sha (fail closed)")
        elif not head:
            out.append(f"evidence: '{key}' cannot be pinned: head sha unknown (fail closed)")
        elif sha != head:
            out.append(f"evidence: '{key}' recorded for {_short(sha)}, not current head {_short(head)}")


def _tier(p: Mapping[str, Any]) -> str:
    """tier を A/B/C に正規化。欠落・不明は保守側の A。"""
    t = _upper(p, "tier")
    return t if t in ("A", "B", "C") else "A"


RECALL_MAX_AGE_H = 36


def _age_hours(then: str, now: str) -> Optional[float]:
    """ISO8601 の差(時間)。どちらかが読めなければ None（fail closed）。未来時刻は 0 扱いせず None。"""
    try:
        t, n = (datetime.fromisoformat(x.replace("Z", "+00:00")) for x in (then, now))
    except ValueError:
        return None
    if t.tzinfo is None or n.tzinfo is None or t > n:
        return None
    return (n - t).total_seconds() / 3600


def _check_recall(p: Mapping[str, Any], tier: str, out: list[str]) -> None:
    """Tier A は main の nightly recall gate が SUCCESS であること。"""
    if tier != "A":
        return
    nr = _pick(p, "nightlyRecall", "nightly_recall", default=None)
    if not isinstance(nr, Mapping) or not (c := _upper(nr, "conclusion")):
        out.append("recall: nightly recall status missing (Tier A blocked, fail closed)")
    elif c != "SUCCESS":
        out.append(f"recall: nightly recall gate on main is {c} (Tier A blocked)")
    elif (age := _age_hours(_text(nr.get("created_at")), _text(p.get("collectedAt")))) is None:
        out.append("recall: nightly recall freshness unknown (Tier A blocked)")
    elif age > RECALL_MAX_AGE_H:
        out.append(f"recall: nightly recall result is stale ({age:.0f}h old, Tier A blocked)")


def evaluate(payload: Any) -> dict:
    """マージ可否を判定する純粋関数（I/O なし・例外を投げず安全側に倒す）。"""
    if not isinstance(payload, Mapping):
        return {"ready": False, "reasons": ["input: payload is not a JSON object (fail closed)"], "pr": None, "head_sha": ""}
    head, found = _sha(payload, *_HEAD_KEYS), []
    _check_pr(payload, found)
    _check_ci(payload, head, found)
    _check_reviews(payload, found)
    _check_threads(payload, found)
    _check_evidence(payload, head, found)
    tier = _tier(payload)
    _check_recall(payload, tier, found)
    reasons = list(dict.fromkeys(found))  # 出現順を保った重複排除（決定論的出力）
    if not reasons:  # 通した根拠も残す（証跡を空にしない）
        reasons = ["pr: open, non-draft, mergeable", f"ci: all required checks succeeded on head {_short(head)}",
                   "review: no changes-requested reviews", "threads: no unresolved review threads",
                   f"evidence: independent-review, security-review, acceptance all PASS on head {_short(head)}",
                   f"recall: tier {tier}" + (" (nightly recall SUCCESS)" if tier == "A" else " (nightly recall not required)")]
    n = _pick(payload, "number", "pr", default=None)
    return {"ready": not found, "reasons": reasons, "pr": n if isinstance(n, int) else (_text(n) or None), "head_sha": head}


def _load(source: Optional[str]) -> tuple[Any, Optional[str]]:
    """入力 JSON を読む。(payload, error) を返し例外は投げない。"""
    try:
        raw = sys.stdin.read() if source in (None, "-") else Path(source).read_text(encoding="utf-8")
    except OSError as exc:
        return None, f"input: cannot read {source!r} ({exc.__class__.__name__})"
    if not raw.strip():
        return None, "input: empty input (fail closed)"
    try:
        return json.loads(raw), None
    except json.JSONDecodeError as exc:
        return None, f"input: invalid JSON ({exc.msg} at line {exc.lineno})"


def main(argv: Optional[Sequence[str]] = None) -> int:
    """read-only CLI。exit code: 0=ready / 1=not ready / 2=入力エラー。"""
    ap = argparse.ArgumentParser(prog="merge_gate", description="PR merge readiness gate (read-only, deterministic, fail closed).")
    ap.add_argument("--input", "-i", default="-", help="evidence JSON file ('-' = stdin, default)")
    payload, error = _load(ap.parse_args(list(argv) if argv is not None else None).input)
    result = {"ready": False, "reasons": [error], "pr": None, "head_sha": ""} if error else evaluate(payload)
    json.dump(result, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    return 2 if error else (0 if result["ready"] else 1)


if __name__ == "__main__":
    raise SystemExit(main())
