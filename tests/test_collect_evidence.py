"""collect_evidence の純粋ロジック（independent_review / build_payload）テスト。gh・ネットワーク非依存。"""
from __future__ import annotations

import json

from orchestration.collect_evidence import build_payload, independent_review
from orchestration.merge_gate import evaluate

HEAD, OLD = "a" * 40, "b" * 40
HEAD_DATE = "2026-01-02T00:00:00Z"
BOT = "chatgpt-codex-connector"


def review(commit=HEAD, login=f"{BOT}[bot]", rid=1, state="APPROVED", at="2026-01-02T01:00:00Z"):
    return {"id": rid, "commit_id": commit, "user": {"login": login}, "state": state, "submitted_at": at,
            "html_url": f"https://example.test/review/{rid}"}


def request(created="2026-01-02T02:00:00Z", plus=True, login=BOT, body="@codex review"):
    return {"id": 9, "body": body, "created_at": created, "html_url": "https://example.test/c/9",
            "reactions": [{"content": "+1" if plus else "eyes", "user": {"login": login}}]}


def judge(reviews=(), comments=(), issues=(), allowed=(BOT,), head_time=HEAD_DATE):
    return independent_review(HEAD, head_time, allowed, list(reviews), list(comments), list(issues))


def test_clean_review_on_head_passes():
    r = judge([review()])
    assert r["verdict"] == "PASS" and r["head_sha"] == HEAD and r["ref"].endswith("/review/1")


def test_review_on_older_commit_is_missing():
    assert judge([review(commit=OLD)])["verdict"] == "MISSING"


def test_review_on_head_with_inline_comments_is_findings():
    r = judge([review(rid=5)], [{"pull_request_review_id": 5}])
    assert r["verdict"] == "FINDINGS" and r["ref"] == ""


def test_changes_requested_on_head_without_comments_is_findings():
    assert judge([review(state="CHANGES_REQUESTED")])["verdict"] == "FINDINGS"
    assert judge([review(state="CHANGES_REQUESTED")], issues=[request()])["verdict"] == "FINDINGS"


def test_dismissed_or_pending_only_is_missing():
    assert judge([review(state="DISMISSED")])["verdict"] == "MISSING"
    assert judge([review(state="PENDING")])["verdict"] == "MISSING"


def test_approved_on_head_without_comments_passes():
    assert judge([review(state="APPROVED")])["verdict"] == "PASS"


def test_commented_review_is_never_clean():
    r = judge([review(state="COMMENTED")])
    assert r["verdict"] == "FINDINGS" and r["ref"] == ""


def test_commented_then_later_request_with_plus_one_passes():
    c = review(state="COMMENTED", at="2026-01-02T01:00:00Z")
    assert judge([c], issues=[request(created="2026-01-02T02:00:00Z")])["verdict"] == "PASS"


def test_plus_one_on_request_before_commented_review_is_findings():
    c = review(state="COMMENTED", at="2026-01-02T03:00:00Z")
    assert judge([c], issues=[request(created="2026-01-02T02:00:00Z")])["verdict"] == "FINDINGS"


def test_plus_one_on_request_after_head_passes():
    assert judge(issues=[request()])["verdict"] == "PASS"


def test_plus_one_disabled_without_head_time():
    r = judge(issues=[request()], head_time=None)
    assert r["verdict"] == "MISSING" and "head time unavailable" in r["detail"]


def test_plus_one_on_request_before_head_is_missing():
    assert judge(issues=[request(created="2026-01-01T00:00:00Z")])["verdict"] == "MISSING"


def test_non_allowed_reviewer_is_missing():
    assert judge([review(login="coordinator")], issues=[request(login="coordinator")])["verdict"] == "MISSING"


def test_bot_suffix_is_normalized_both_ways():
    assert judge([review(login=BOT)], allowed=[f"{BOT}[bot]"])["verdict"] == "PASS"
    assert judge([review(login=f"{BOT.upper()}[bot]")])["verdict"] == "PASS"


def test_error_comment_without_reaction_is_missing():
    err = {"id": 3, "body": "Codex Review: Something went wrong.", "created_at": "2026-01-02T03:00:00Z", "reactions": []}
    assert judge(issues=[err])["verdict"] == "MISSING"
    assert judge(issues=[request(plus=False)])["verdict"] == "MISSING"  # +1 以外の reaction は不可


def make_run(calls=None, **o):
    """gh の fake。o で各応答を差し替える（check_runs/status/threads/nightly/commit_date）。"""
    pr_view = {"number": 7, "state": "OPEN", "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
               "headRefOid": HEAD, "baseRefName": "main",
               "reviews": [{"author": {"login": "a"}, "state": "APPROVED", "submittedAt": "2026-01-02"}]}
    page = {"data": {"repository": {"pullRequest": {"reviewThreads": {
        "pageInfo": {"hasNextPage": False, "endCursor": None}, "nodes": []}}}}}
    cr = [{"check_runs": [{"name": "test", "status": "completed", "conclusion": "success", "head_sha": HEAD,
                           "started_at": "2026-01-02T00:30:00Z"}]}]

    def run(args):
        a = " ".join(args)
        if calls is not None:
            calls.append(a)
        if a.startswith("pr view"):
            return json.dumps(pr_view)
        if "branches/main/protection" in a:
            return json.dumps({"required_status_checks": {"contexts": ["test", "ext/ci"]}})
        if "check-runs" in a:
            return json.dumps(o.get("check_runs", cr))
        if a.endswith("/status"):
            return json.dumps(o.get("status", [{"sha": HEAD, "statuses": [{"context": "ext/ci", "state": "success"}]}]))
        if "graphql" in a:
            r = o["threads"](a) if "threads" in o else page
            if isinstance(r, Exception):
                raise r
            return json.dumps(r)
        if a.endswith("/pulls/7/reviews"):
            return json.dumps([[review()]])
        if a.endswith("/pulls/7/comments") or a.endswith("/issues/7/comments"):
            return "[[]]"
        if a.endswith(f"/commits/{HEAD}"):
            return json.dumps({"commit": {"committer": {"date": o.get("commit_date", HEAD_DATE)}}})
        if a.startswith("run list"):
            return json.dumps([{"status": "completed", "conclusion": "failure", "headSha": "c" * 40, "createdAt": "x"}])
        raise AssertionError(a)
    return run


def test_commit_status_contexts_use_api_sha_and_uppercase_state():
    payload, errors = build_payload(7, "o/r", [BOT], "B", None, make_run())
    assert errors == []
    assert {"name": "ext/ci", "status": "COMPLETED", "conclusion": "SUCCESS", "head_sha": HEAD} in payload["statusCheckRollup"]
    assert not any("ci:" in r for r in evaluate(payload)["reasons"])


def test_review_threads_are_paginated_with_cursor():
    seen = []

    def threads(a):
        seen.append(a)
        first = "c=CUR1" not in a
        return {"data": {"repository": {"pullRequest": {"reviewThreads": {
            "pageInfo": {"hasNextPage": first, "endCursor": "CUR1" if first else None},
            "nodes": [{"isResolved": first, "path": "p%d" % len(seen)}]}}}}}

    payload, errors = build_payload(7, "o/r", [BOT], "B", None, make_run(threads=threads))
    assert len(seen) == 2 and [t["path"] for t in payload["reviewThreads"]] == ["p1", "p2"]


def test_review_threads_pagination_failure_omits_field():
    n = []

    def threads(a):
        n.append(a)
        if len(n) == 1:
            return {"data": {"repository": {"pullRequest": {"reviewThreads": {
                "pageInfo": {"hasNextPage": True, "endCursor": "C"}, "nodes": []}}}}}
        return RuntimeError("boom")

    payload, errors = build_payload(7, "o/r", [BOT], "B", None, make_run(threads=threads))
    assert "reviewThreads" not in payload and errors


def test_commit_status_pages_are_flattened_and_sha_mismatch_skips():
    pages = [{"sha": HEAD, "statuses": [{"context": "ext/ci", "state": "success"}]},
             {"sha": HEAD, "statuses": [{"context": "ext/two", "state": "pending"}]}]
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run(status=pages))
    names = {e["name"]: e["conclusion"] for e in payload["statusCheckRollup"]}
    assert names["ext/ci"] == "SUCCESS" and names["ext/two"] == "PENDING"
    pages[1]["sha"] = OLD
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run(status=pages))
    assert {e["name"] for e in payload["statusCheckRollup"]} == {"test"}


def test_gate_reviews_come_from_rest_and_protection_branch_is_quoted():
    calls = []
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run(calls))
    assert payload["reviews"] == [{"state": "APPROVED", "author": {"login": f"{BOT}[bot]"},
                                   "submittedAt": "2026-01-02T01:00:00Z"}]
    assert not any(c.startswith("pr view") and "reviews" in c.split("--json")[1] for c in calls)

    def run(args):
        calls.append(" ".join(args))
        if args[:2] == ["pr", "view"]:
            return json.dumps({"headRefOid": HEAD, "baseRefName": "feat/x y"})
        if "reviews" in args[-1]:
            raise RuntimeError("boom")
        return "null"
    calls.clear()
    payload, errors = build_payload(7, "o/r", [BOT], "B", None, run)
    assert "reviews" not in payload and errors  # 取得失敗は省略（gate が fail closed）
    assert any("branches/feat%2Fx%20y/protection" in c for c in calls)


def test_nightly_asks_for_latest_completed_run():
    calls = []
    build_payload(7, "o/r", [BOT], "B", None, make_run(calls))
    run_list = next(c for c in calls if c.startswith("run list"))
    assert "--status completed --limit 1" in run_list


def _plus_one_run(commit_date, started_at):
    base = make_run(commit_date=commit_date, check_runs=[{"check_runs": [
        {"name": "test", "status": "completed", "conclusion": "success", "head_sha": HEAD, "started_at": started_at}]}]
        if started_at else [{"check_runs": [{"name": "test", "status": "completed", "conclusion": "success", "head_sha": HEAD}]}])

    def run(args):
        a = " ".join(args)
        if a.endswith("/pulls/7/reviews"):
            return "[[]]"
        if a.endswith("/issues/7/comments"):
            return json.dumps([[{"id": 9, "body": "@codex review", "created_at": "2026-01-02T00:10:00Z"}]])
        if a.endswith("/reactions"):
            return json.dumps([[{"content": "+1", "user": {"login": BOT}}]])
        return base(args)
    return run


def test_backdated_committer_date_cannot_make_old_request_fresh():
    # 請求(00:10)は committer date(偽装: 00:00)より後だが、サーバ記録の check-run 開始(00:30)より前
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, _plus_one_run("2026-01-02T00:00:00Z", "2026-01-02T00:30:00Z"))
    assert payload["evidence"]["independent_review"]["verdict"] == "MISSING"


def test_missing_check_run_time_disables_plus_one():
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, _plus_one_run("2026-01-02T00:00:00Z", None))
    assert payload["evidence"]["independent_review"]["verdict"] == "MISSING"


def test_plus_one_after_both_times_passes():
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, _plus_one_run("2026-01-02T00:00:00Z", "2026-01-02T00:05:00Z"))
    assert payload["evidence"]["independent_review"]["verdict"] == "PASS"


def test_build_payload_with_fake_runner_feeds_the_gate():
    sec = {"verdict": "PASS", "head_sha": HEAD, "ref": "s"}
    payload, errors = build_payload(7, "o/r", [BOT], "A", {"security_review": sec}, make_run())
    assert errors == []
    assert payload["evidence"]["independent_review"]["verdict"] == "PASS"
    assert set(payload["evidence"]) == {"independent_review", "security_review"}  # acceptance は合成しない
    assert payload["nightlyRecall"]["conclusion"] == "failure"
    reasons = evaluate(payload)["reasons"]
    assert any("acceptance" in r for r in reasons) and any("recall" in r and "FAILURE" in r for r in reasons)


def test_gh_failure_omits_fields_and_reports():
    def run(args):
        raise RuntimeError("boom")

    payload, errors = build_payload(7, "o/r", [BOT], None, None, run)
    assert payload == {} and errors
    assert evaluate(payload)["ready"] is False
