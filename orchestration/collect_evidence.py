"""merge_gate 用 evidence payload を gh の read-only 呼び出しで機械的に収集する（stdout へ JSON）。

使い方: ``python3 -m orchestration.collect_evidence PR --reviewer LOGIN [--tier A|B|C] | python3 -m orchestration.merge_gate``
merge もコメント投稿もしない。head SHA は API の値をそのまま使い、こちらで注入しない。
gh 呼び出しが失敗したフィールドは省略（＝gate が fail closed）し、理由を stderr に出して exit 1。payload は常に出力する。
security_review / acceptance は ``--evidence-file`` の値を素通しするだけで合成しない。
"""
from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
from datetime import datetime, timezone
from urllib.parse import quote
from typing import Any, Callable, Optional, Sequence

REVIEW_REQUESTS = ("@codex review", "@claude review")
_EFFECTIVE = ("APPROVED", "COMMENTED", "CHANGES_REQUESTED")  # DISMISSED/PENDING は意思表示として数えない
CLEAN_MARKERS = ("didn't find any major issues",)  # reviewer の「指摘なし」コメントの定型句
_REVIEWED_COMMIT = re.compile(r"reviewed commit:?\**\s*`([0-9a-f]{7,40})`", re.I)
RECALL_WORKFLOW = "Nightly recall gate"


def _login(name: Any) -> str:
    n = str(name or "").lower()
    return n[: -len("[bot]")] if n.endswith("[bot]") else n


def independent_review(head: str, head_time: Optional[str], allowed: Sequence[str], reviews: list,
                       review_comments: list, issue_comments: list) -> dict:
    """現 head 上の許可 reviewer の「指摘なし」シグナルだけを PASS にする純粋関数（reviewer 毎に判定）。

    reviews/review_comments/issue_comments は gh api(REST) の素のデータ。issue_comments の各要素には
    ``reactions``（``[{"content","user":{"login"}}]``）を付けて渡す。ISO8601(Z) 同士は文字列比較で足りる。
    head_time は GitHub が記録した head の時刻（committer date は偽装可能）。None なら +1 経路は無効（fail closed）。

    各 reviewer の指摘 = CHANGES_REQUESTED（最新なら上書き不可）/ COMMENTED / inline 付き APPROVED。
    第3の clean シグナル: 許可 reviewer の未編集 issue コメントで、CLEAN_MARKERS と ``Reviewed commit: `<sha>` ``（7桁以上、
    head の先頭一致）を含むもの。SHA に束縛されるので head_time は不要。
    指摘は「同じ reviewer 自身」の後続の clean（inline なし APPROVED、または指摘より後の依頼への +1）でのみ解消する
    （別 reviewer の APPROVED では消えない）。PASS = 未解消の指摘が無く、かつ clean シグナルが 1 つ以上。
    """
    ok = {_login(a) for a in allowed}
    head = head.lower()
    commented = {c.get("pull_request_review_id") for c in review_comments}
    mine: dict[str, list] = {}
    for r in sorted(reviews, key=lambda r: r.get("submitted_at") or ""):
        who = _login((r.get("user") or {}).get("login"))
        if who in ok and str(r.get("commit_id", "")).lower() == head and r.get("state") in _EFFECTIVE:
            mine.setdefault(who, []).append(r)
    if any(rs[-1].get("state") == "CHANGES_REQUESTED" for rs in mine.values()):
        return {"verdict": "FINDINGS", "head_sha": head, "ref": "", "detail": "an allowed reviewer's latest review on head is CHANGES_REQUESTED"}

    def found_at(who: str) -> str:  # reviewer の最後の指摘時刻（無ければ ""）
        return max([r.get("submitted_at") or "" for r in mine.get(who, [])
                    if r["state"] == "COMMENTED" or r.get("id") in commented] or [""])

    signals: list[tuple[str, str, str]] = []  # (時刻, reviewer, ref)
    for who, rs in mine.items():
        signals += [(r.get("submitted_at") or "", who, r["html_url"]) for r in rs
                    if r["state"] == "APPROVED" and r.get("html_url") and r.get("id") not in commented
                    and (r.get("submitted_at") or "") > found_at(who)]
    if head_time:
        for c in issue_comments:
            if not any(k in (c.get("body") or "").lower() for k in REVIEW_REQUESTS):
                continue
            if not c.get("html_url") or c.get("updated_at") not in (None, c.get("created_at")):
                continue  # 編集された依頼コメントは無効（内容/時刻を後から書き換えられる）
            for who in {_login((x.get("user") or {}).get("login")) for x in c.get("reactions") or [] if x.get("content") == "+1"} & ok:
                if (c.get("created_at") or "") > max(head_time, found_at(who)):
                    signals.append((c.get("created_at") or "", who, c["html_url"]))
    for c in issue_comments:
        who, body = _login((c.get("user") or {}).get("login")), c.get("body") or ""
        m = _REVIEWED_COMMIT.search(body)
        if (who in ok and m and head.startswith(m.group(1).lower()) and any(k in body.lower() for k in CLEAN_MARKERS)
                and c.get("html_url") and c.get("updated_at") in (None, c.get("created_at"))
                and (c.get("created_at") or "") > found_at(who)):
            signals.append((c.get("created_at") or "", who, c["html_url"]))
    unresolved = [w for w in mine if found_at(w) and not any(who == w for _, who, _ in signals)]
    if signals and not unresolved:
        return {"verdict": "PASS", "head_sha": head, "ref": max(signals)[2]}
    if mine:
        return {"verdict": "FINDINGS", "head_sha": head, "ref": "",
                "detail": f"unresolved findings on head from {', '.join(sorted(unresolved)) or '(none)'}" if unresolved
                          else "no clean signal after findings on head"}
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

    # 収集失敗はパイプ越しに exit code が消えるので payload に載せる（gate が非空なら失格）
    out: dict = {"collectionErrors": errors, "collectedAt": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}
    view = call("pr view", ["pr", "view", str(pr), "--repo", repo, "--json",
                            "number,state,isDraft,mergeable,mergeStateStatus,headRefOid,baseRefName"])
    if not isinstance(view, dict):
        return out, errors
    base = view.pop("baseRefName", "")
    out.update(view)
    head = str(view.get("headRefOid") or "")
    prot = call("branch protection", ["api", f"repos/{repo}/branches/{quote(base, safe='')}/protection"])
    rsc = (prot or {}).get("required_status_checks") or {}
    # checks[]={context,app_id} 優先、無ければ contexts（app 指定なし）。app_id が null/-1 は「任意の app」
    req = rsc.get("checks") or [{"context": c, "app_id": None} for c in rsc.get("contexts") or []]
    pins = {x["context"]: x.get("app_id") for x in req if x.get("app_id") not in (None, -1)}
    if names := [x["context"] for x in req]:
        out["requiredChecks"] = names
    if pages := paged("check-runs", f"repos/{repo}/commits/{head}/check-runs"):
        out["statusCheckRollup"] = [{"name": r.get("name"), "status": r.get("status"), "conclusion": r.get("conclusion"),
                                     "head_sha": r.get("head_sha"), "app_id": (r.get("app") or {}).get("id")}
                                    for p in pages for r in p.get("check_runs", [])]
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
    # committer date は偽装可能。サーバ記録の check-run 開始のうち「最新」を使う（他所で先にチェック済みの commit は
    # 開始が古いため最早では甘い）。無ければ +1 経路を無効にする（再実行で +1 が無効化されるのは許容＝fail closed）
    head_time = max(filter(None, [commit_date, max(starts)])) if starts else None
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
    # app 固定の必須 context は別 app の同名 check や commit status では満たせない
    if "statusCheckRollup" in out:
        out["statusCheckRollup"] = [e for e in out["statusCheckRollup"]
                                    if e["name"] not in pins or e.get("app_id") == pins[e["name"]]]
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
