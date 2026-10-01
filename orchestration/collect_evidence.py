"""merge_gate 用 evidence payload を gh の read-only 呼び出しで機械的に収集する（stdout へ JSON）。

使い方: ``python3 -m orchestration.collect_evidence PR --reviewer LOGIN [--tier A|B|C] | python3 -m orchestration.merge_gate``
merge もコメント投稿もしない。head SHA は API の値をそのまま使い、こちらで注入しない。
gh 呼び出しが失敗したフィールドは省略（＝gate が fail closed）し、理由を stderr に出して exit 1。payload は常に出力する。
security_review / acceptance は ``--evidence-file`` の値を素通しするだけで合成しない。
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from urllib.parse import quote
from typing import Any, Callable, Optional, Sequence

REVIEW_REQUESTS = ("@codex review", "@claude review")
_EFFECTIVE = ("APPROVED", "COMMENTED", "CHANGES_REQUESTED")  # DISMISSED/PENDING は意思表示として数えない
RECALL_WORKFLOW = "Nightly recall gate"


def _login(name: Any) -> str:
    n = str(name or "").lower()
    return n[: -len("[bot]")] if n.endswith("[bot]") else n


def independent_review(head: str, head_time: Optional[str], allowed: Sequence[str], reviews: list,
                       review_comments: list, issue_comments: list) -> dict:
    """現 head 上の許可 reviewer の「指摘なし」シグナルだけを PASS にする純粋関数。

    reviews/review_comments/issue_comments は gh api(REST) の素のデータ。issue_comments の各要素には
    ``reactions``（``[{"content","user":{"login"}}]``）を付けて渡す。ISO8601(Z) 同士は文字列比較で足りる。
    head_time は GitHub が記録した head の時刻（committer date は偽装可能なので単独では使わない）。None なら +1 経路は無効（fail closed）。
    """
    ok = {_login(a) for a in allowed}
    head = head.lower()
    commented = {c.get("pull_request_review_id") for c in review_comments}
    mine = sorted((r for r in reviews if _login((r.get("user") or {}).get("login")) in ok
                   and str(r.get("commit_id", "")).lower() == head and r.get("state") in _EFFECTIVE),
                  key=lambda r: r.get("submitted_at") or "")
    latest = mine[-1] if mine else None
    changes = bool(latest) and latest.get("state") == "CHANGES_REQUESTED"
    # 本文だけに指摘が入った COMMENTED は検出できないので clean 扱いしない（PASS は APPROVED かつ inline なしのみ）
    if latest and latest.get("state") == "APPROVED" and latest.get("id") not in commented:
        return {"verdict": "PASS", "head_sha": head, "ref": latest.get("html_url") or str(latest.get("id"))}
    # +1 は head 後、かつ最新 COMMENTED の後に出した再レビュー依頼のものだけ。CHANGES_REQUESTED は上書きしない
    since = (max(head_time or "", latest.get("submitted_at") or "")
             if latest and latest.get("state") == "COMMENTED" else head_time)
    if head_time and not changes:
        for c in issue_comments:
            body = (c.get("body") or "").lower()
            if (any(k in body for k in REVIEW_REQUESTS) and (c.get("created_at") or "") > since
                    and any(r.get("content") == "+1" and _login((r.get("user") or {}).get("login")) in ok
                            for r in c.get("reactions") or [])):
                return {"verdict": "PASS", "head_sha": head, "ref": c.get("html_url") or str(c.get("id"))}
    if latest:
        return {"verdict": "FINDINGS", "head_sha": head, "ref": "",
                "detail": f"latest review by {(latest.get('user') or {}).get('login')} on head is "
                          + (latest.get("state") if latest.get("state") != "APPROVED" else "with inline comments")}
    return {"verdict": "MISSING", "head_sha": head, "ref": "",
            "detail": "no clean review or +1 reaction by an allowed reviewer on the current head"
                      + ("" if head_time else " (head time unavailable: +1 path disabled)")}


def gh(args: Sequence[str]) -> str:
    """read-only gh 呼び出し。失敗は CalledProcessError（呼び側が省略へ倒す）。"""
    return subprocess.run(["gh", *args], capture_output=True, text=True, check=True).stdout


def build_payload(pr: int, repo: str, reviewers: Sequence[str], tier: Optional[str], evidence: Optional[dict],
                  run: Callable[[Sequence[str]], str] = gh) -> tuple[dict, list[str]]:
    """payload と失敗メッセージ一覧を返す。run を差し替えれば gh 無しでテストできる。"""
    errors: list[str] = []

    def call(label: str, args: Sequence[str]) -> Any:
        try:
            return json.loads(run(args) or "null")
        except Exception as exc:  # 失敗は欠落として表面化させる（握りつぶさず stderr へ）
            errors.append(f"{label}: {exc.__class__.__name__}: {exc}")
            return None

    def paged(label: str, path: str) -> Optional[list]:
        """--paginate --slurp はページ配列を返す。各ページ（配列 or dict）を平坦化する。"""
        pages = call(label, ["api", "--paginate", "--slurp", path])
        return None if pages is None else [x for p in pages for x in (p if isinstance(p, list) else [p])]

    out: dict = {}
    view = call("pr view", ["pr", "view", str(pr), "--repo", repo, "--json",
                            "number,state,isDraft,mergeable,mergeStateStatus,headRefOid,baseRefName"])
    if not isinstance(view, dict):
        return out, errors
    base = view.pop("baseRefName", "")
    out.update(view)
    head = str(view.get("headRefOid") or "")
    prot = call("branch protection", ["api", f"repos/{repo}/branches/{quote(base, safe='')}/protection"])
    if ctx := ((prot or {}).get("required_status_checks") or {}).get("contexts"):
        out["requiredChecks"] = ctx
    if pages := paged("check-runs", f"repos/{repo}/commits/{head}/check-runs"):
        out["statusCheckRollup"] = [{"name": r.get("name"), "status": r.get("status"), "conclusion": r.get("conclusion"),
                                     "head_sha": r.get("head_sha")} for p in pages for r in p.get("check_runs", [])]
    sp = paged("commit status", f"repos/{repo}/commits/{head}/status")  # 各ページは combined status の dict
    if sp and len({x.get("sha") for x in sp}) == 1 and sp[0].get("sha"):  # sha 不一致なら足さない
        out.setdefault("statusCheckRollup", []).extend(
            {"name": x.get("context"), "status": "COMPLETED", "conclusion": str(x.get("state", "")).upper(),
             "head_sha": sp[0]["sha"]} for pg in sp for x in pg.get("statuses") or [])
    owner, name = repo.split("/", 1)
    q = ("query($o:String!,$n:String!,$p:Int!,$c:String){repository(owner:$o,name:$n){pullRequest(number:$p)"
         "{reviewThreads(first:100,after:$c){pageInfo{hasNextPage endCursor} nodes{isResolved path}}}}}")
    threads: Optional[list] = []
    cursor = None
    while threads is not None:  # 途中で失敗したら省略（gate が fail closed）
        extra = ["-f", f"c={cursor}"] if cursor else []
        th = call("reviewThreads", ["api", "graphql", "-f", f"query={q}", "-F", f"p={pr}",
                                    "-f", f"o={owner}", "-f", f"n={name}", *extra])
        try:
            conn = th["data"]["repository"]["pullRequest"]["reviewThreads"]
            threads += conn["nodes"]
            if not conn["pageInfo"]["hasNextPage"]:
                break
            cursor = conn["pageInfo"]["endCursor"]
            if not cursor:
                threads = None
        except (TypeError, KeyError):
            threads = None
    if threads is not None:
        out["reviewThreads"] = threads
    reviews = paged("pr reviews", f"repos/{repo}/pulls/{pr}/reviews")
    rcomments = paged("pr review comments", f"repos/{repo}/pulls/{pr}/comments")
    icomments = paged("issue comments", f"repos/{repo}/issues/{pr}/comments")
    commit = call("head commit", ["api", f"repos/{repo}/commits/{head}"])
    commit_date = (((commit or {}).get("commit") or {}).get("committer") or {}).get("date")
    starts = [r["started_at"] for p in pages or [] for r in p.get("check_runs", []) if r.get("started_at")]
    # committer date は偽装可能なので、サーバ記録の check-run 開始時刻が無ければ +1 経路を無効にする
    head_time = max(filter(None, [commit_date, min(starts)])) if starts else None
    if reviews is not None:  # gate の reviews は pr view(先頭100件のみ)でなくページング済み REST から作る
        out["reviews"] = [{"state": r.get("state"), "author": {"login": (r.get("user") or {}).get("login")},
                           "submittedAt": r.get("submitted_at")} for r in reviews if r.get("submitted_at")]
    if reviews is not None and rcomments is not None and icomments is not None:
        for c in icomments:  # reaction は review request コメントにだけ取りに行く
            if any(k in (c.get("body") or "").lower() for k in REVIEW_REQUESTS):
                c["reactions"] = paged("reactions", f"repos/{repo}/issues/comments/{c['id']}/reactions") or []
        out.setdefault("evidence", {})["independent_review"] = independent_review(
            head, head_time, reviewers, reviews, rcomments, icomments)
    if isinstance(evidence, dict):
        for k in ("security_review", "acceptance"):
            if k in evidence:
                out.setdefault("evidence", {})[k] = evidence[k]
    if tier:
        out["tier"] = tier
    runs = call("nightly recall", ["run", "list", "--repo", repo, "--workflow", RECALL_WORKFLOW, "--branch", "main",
                                   "--status", "completed", "--limit", "1", "--json", "conclusion,headSha,createdAt,status"])
    if done := next(iter(runs or []), None):
        out["nightlyRecall"] = {"conclusion": done.get("conclusion"), "head_sha": done.get("headSha"),
                                "created_at": done.get("createdAt")}
    return out, errors


def main(argv: Optional[Sequence[str]] = None) -> int:
    ap = argparse.ArgumentParser(prog="collect_evidence", description="Collect merge_gate evidence via read-only gh calls.")
    ap.add_argument("pr", type=int)
    ap.add_argument("--reviewer", action="append", required=True, help="allowed independent reviewer login (repeatable)")
    ap.add_argument("--tier", choices=["A", "B", "C"], type=str.upper)
    ap.add_argument("--evidence-file", help="JSON object with security_review / acceptance (passed through as-is)")
    ap.add_argument("--repo", help="OWNER/NAME (default: current repo)")
    a = ap.parse_args(argv)
    evidence = None
    if a.evidence_file:
        with open(a.evidence_file, encoding="utf-8") as f:
            evidence = json.load(f)
    repo = a.repo
    if not repo:
        try:
            repo = json.loads(gh(["repo", "view", "--json", "nameWithOwner"]))["nameWithOwner"]
        except Exception as exc:
            print(f"collect_evidence: cannot resolve repo: {exc}", file=sys.stderr)
            return 2
    payload, errors = build_payload(a.pr, repo, a.reviewer, a.tier, evidence)
    json.dump(payload, sys.stdout, indent=2, ensure_ascii=False)
    sys.stdout.write("\n")
    for e in errors:
        print(f"collect_evidence: {e}", file=sys.stderr)
    return 1 if errors else 0


if __name__ == "__main__":
    raise SystemExit(main())
