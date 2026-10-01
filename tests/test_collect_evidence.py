"""collect_evidence の純粋ロジック（independent_review / build_payload）テスト。gh・ネットワーク非依存。"""
from __future__ import annotations

import json

from orchestration.collect_evidence import build_payload, independent_review
from orchestration.merge_gate import evaluate

HEAD, OLD = "a" * 40, "b" * 40
HEAD_DATE = "2026-01-02T00:00:00Z"
BOT = "chatgpt-codex-connector"


def review(commit=HEAD, login=f"{BOT}[bot]", rid=1, state="COMMENTED", at="2026-01-02T01:00:00Z"):
    return {"id": rid, "commit_id": commit, "user": {"login": login}, "state": state, "submitted_at": at,
            "html_url": f"https://example.test/review/{rid}"}


def request(created="2026-01-02T02:00:00Z", plus=True, login=BOT, body="@codex review"):
    return {"id": 9, "body": body, "created_at": created, "html_url": "https://example.test/c/9",
            "reactions": [{"content": "+1" if plus else "eyes", "user": {"login": login}}]}


def judge(reviews=(), comments=(), issues=(), allowed=(BOT,)):
    return independent_review(HEAD, HEAD_DATE, allowed, list(reviews), list(comments), list(issues))


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


def test_plus_one_on_request_after_head_passes():
    assert judge(issues=[request()])["verdict"] == "PASS"


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


def test_build_payload_with_fake_runner_feeds_the_gate():
    pr_view = {"number": 7, "state": "OPEN", "isDraft": False, "mergeable": "MERGEABLE", "mergeStateStatus": "CLEAN",
               "headRefOid": HEAD, "baseRefName": "main",
               "reviews": [{"author": {"login": "a"}, "state": "APPROVED", "submittedAt": "2026-01-02"}]}
    threads = {"data": {"repository": {"pullRequest": {"reviewThreads": {"nodes": []}}}}}

    def run(args):
        a = " ".join(args)
        if a.startswith("pr view"):
            return json.dumps(pr_view)
        if "branches/main/protection" in a:
            return json.dumps({"required_status_checks": {"contexts": ["test"]}})
        if "check-runs" in a:
            return json.dumps([{"check_runs": [{"name": "test", "status": "completed", "conclusion": "success", "head_sha": HEAD}]}])
        if "graphql" in a:
            return json.dumps(threads)
        if a.endswith("/pulls/7/reviews"):
            return json.dumps([[review()]])
        if a.endswith("/pulls/7/comments") or a.endswith("/issues/7/comments"):
            return "[[]]"
        if a.endswith(f"/commits/{HEAD}"):
            return json.dumps({"commit": {"committer": {"date": HEAD_DATE}}})
        if a.startswith("run list"):
            return json.dumps([{"status": "in_progress", "conclusion": ""},
                               {"status": "completed", "conclusion": "failure", "headSha": "c" * 40, "createdAt": "x"}])
        raise AssertionError(a)

    sec = {"verdict": "PASS", "head_sha": HEAD, "ref": "s"}
    payload, errors = build_payload(7, "o/r", [BOT], "A", {"security_review": sec}, run)
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
