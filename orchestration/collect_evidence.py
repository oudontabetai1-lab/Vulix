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
from typing import Any, Callable, Optional, Sequence

REVIEW_REQUESTS = ("@codex review", "@claude review")
_EFFECTIVE = ("APPROVED", "COMMENTED", "CHANGES_REQUESTED")  # DISMISSED/PENDING は意思表示として数えない
RECALL_WORKFLOW = "Nightly recall gate"


def _login(name: Any) -> str:
    n = str(name or "").lower()
    return n[: -len("[bot]")] if n.endswith("[bot]") else n


def independent_review(head: str, head_date: Optional[str], allowed: Sequence[str], reviews: list,
                       review_comments: list, issue_comments: list) -> dict:
    """現 head 上の許可 reviewer の「指摘なし」シグナルだけを PASS にする純粋関数。

    reviews/review_comments/issue_comments は gh api(REST) の素のデータ。issue_comments の各要素には
    ``reactions``（``[{"content","user":{"login"}}]``）を付けて渡す。ISO8601(Z) 同士は文字列比較で足りる。
    """
    ok = {_login(a) for a in allowed}
    head = head.lower()
    commented = {c.get("pull_request_review_id") for c in review_comments}
    mine = sorted((r for r in reviews if _login((r.get("user") or {}).get("login")) in ok
                   and str(r.get("commit_id", "")).lower() == head and r.get("state") in _EFFECTIVE),
                  key=lambda r: r.get("submitted_at") or "")
    latest = mine[-1] if mine else None
    changes = bool(latest) and latest.get("state") == "CHANGES_REQUESTED"
    if latest and not changes and latest.get("id") not in commented:
        return {"verdict": "PASS", "head_sha": head, "ref": latest.get("html_url") or str(latest.get("id"))}
    if head_date and not changes:  # 未解消の CHANGES_REQUESTED は +1 で上書きしない
        for c in issue_comments:
            body = (c.get("body") or "").lower()
            if (any(k in body for k in REVIEW_REQUESTS) and (c.get("created_at") or "") > head_date
                    and any(r.get("content") == "+1" and _login((r.get("user") or {}).get("login")) in ok
                            for r in c.get("reactions") or [])):
                return {"verdict": "PASS", "head_sha": head, "ref": c.get("html_url") or str(c.get("id"))}
    if latest:
        return {"verdict": "FINDINGS", "head_sha": head, "ref": "",
                "detail": f"latest review by {(latest.get('user') or {}).get('login')} on head is "
                          + ("CHANGES_REQUESTED" if changes else "with inline comments")}
    return {"verdict": "MISSING", "head_sha": head, "ref": "",
            "detail": "no clean review or +1 reaction by an allowed reviewer on the current head"}


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
                            "number,state,isDraft,mergeable,mergeStateStatus,headRefOid,baseRefName,reviews"])
    if not isinstance(view, dict):
        return out, errors
    base = view.pop("baseRefName", "")
    out.update(view)
    head = str(view.get("headRefOid") or "")
    prot = call("branch protection", ["api", f"repos/{repo}/branches/{base}/protection"])
    if ctx := ((prot or {}).get("required_status_checks") or {}).get("contexts"):
        out["requiredChecks"] = ctx
    if pages := paged("check-runs", f"repos/{repo}/commits/{head}/check-runs"):
        out["statusCheckRollup"] = [{"name": r.get("name"), "status": r.get("status"), "conclusion": r.get("conclusion"),
                                     "head_sha": r.get("head_sha")} for p in pages for r in p.get("check_runs", [])]
    owner, name = repo.split("/", 1)
    q = ("query($o:String!,$n:String!,$p:Int!){repository(owner:$o,name:$n){pullRequest(number:$p)"
         "{reviewThreads(first:100){nodes{isResolved path}}}}}")
    th = call("reviewThreads", ["api", "graphql", "-f", f"query={q}", "-F", f"p={pr}", "-f", f"o={owner}", "-f", f"n={name}"])
    try:
        out["reviewThreads"] = th["data"]["repository"]["pullRequest"]["reviewThreads"]["nodes"]
    except (TypeError, KeyError):
        pass
    reviews = paged("pr reviews", f"repos/{repo}/pulls/{pr}/reviews")
    rcomments = paged("pr review comments", f"repos/{repo}/pulls/{pr}/comments")
    icomments = paged("issue comments", f"repos/{repo}/issues/{pr}/comments")
    commit = call("head commit", ["api", f"repos/{repo}/commits/{head}"])
    head_date = (((commit or {}).get("commit") or {}).get("committer") or {}).get("date")
    if reviews is not None and rcomments is not None and icomments is not None:
        for c in icomments:  # reaction は review request コメントにだけ取りに行く
            if any(k in (c.get("body") or "").lower() for k in REVIEW_REQUESTS):
                c["reactions"] = call("reactions", ["api", f"repos/{repo}/issues/comments/{c['id']}/reactions"]) or []
        out.setdefault("evidence", {})["independent_review"] = independent_review(
            head, head_date, reviewers, reviews, rcomments, icomments)
    if isinstance(evidence, dict):
        for k in ("security_review", "acceptance"):
            if k in evidence:
                out.setdefault("evidence", {})[k] = evidence[k]
    if tier:
        out["tier"] = tier
    runs = call("nightly recall", ["run", "list", "--repo", repo, "--workflow", RECALL_WORKFLOW, "--branch", "main",
                                   "--limit", "5", "--json", "conclusion,headSha,createdAt,status"])
    if done := next((r for r in runs or [] if r.get("status") == "completed"), None):
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
