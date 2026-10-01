"""collect_evidence の純粋ロジック（independent_review / build_payload）テスト。gh・ネットワーク非依存。"""
from __future__ import annotations

import json

from orchestration.collect_evidence import build_payload, independent_review
from orchestration.merge_gate import evaluate as _evaluate

HEAD, OLD = "a" * 40, "b" * 40
HEAD_DATE = "2026-01-02T00:00:00Z"
BOT = "chatgpt-codex-connector[bot]"
REAL_CLEAN_BODY = 'Codex Review: Didn\'t find any major issues. Breezy!\n\n**Reviewed commit:** `def0819f0e`\n\n<details> <summary>ℹ️ About Codex in GitHub</summary>\n<br/>\n\n[Your team has set up Codex to review pull requests in this repo](https://chatgpt.com/codex/cloud/settings/general). Reviews are triggered when you\n- Open a pull request for review\n- Mark a draft as ready\n- Comment "@codex review".\n\nIf Codex has suggestions, it will comment; otherwise it will react with 👍.\n\n\n\n\nCodex can also answer questions or update the PR. Try commenting "@codex address that feedback".\n            \n</details>\n'


def evaluate(payload):
    return _evaluate(payload, payload.get("collectedAt", ""))


def review(commit=HEAD, login=BOT, rid=1, state="APPROVED", at="2026-01-02T01:00:00Z"):
    return {"id": rid, "commit_id": commit, "user": {"login": login}, "state": state, "submitted_at": at,
            "html_url": f"https://github.com/o/r/pull/7#pullrequestreview-{rid}"}


def request(created="2026-01-02T02:00:00Z", plus=True, login=BOT, body="@codex review"):
    return {"id": 9, "body": body, "created_at": created, "html_url": "https://github.com/o/r/pull/7#issuecomment-9",
            "reactions": [{"content": "+1" if plus else "eyes", "user": {"login": login}}]}


def judge(reviews=(), comments=(), issues=(), allowed=(BOT,), head_time=HEAD_DATE):
    return independent_review(HEAD, head_time, allowed, list(reviews), list(comments), list(issues))


def test_clean_review_on_head_passes():
    r = judge([review()])
    assert r["verdict"] == "PASS" and r["head_sha"] == HEAD and r["ref"].endswith("#pullrequestreview-1")


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


B = "other-reviewer"


def test_other_reviewers_approval_does_not_hide_a_comment():
    a = review(state="COMMENTED", at="2026-01-02T01:00:00Z")
    b = review(login=B, rid=2, state="APPROVED", at="2026-01-02T02:00:00Z")
    assert judge([a, b], allowed=(BOT, B))["verdict"] == "FINDINGS"


def test_same_reviewer_supersedes_own_comment_with_later_clean_signal():
    a = review(state="COMMENTED", at="2026-01-02T01:00:00Z")
    assert judge([a], issues=[request(created="2026-01-02T02:00:00Z")])["verdict"] == "PASS"
    a2 = review(rid=3, state="APPROVED", at="2026-01-02T02:00:00Z")
    assert judge([a, a2])["verdict"] == "PASS"
    assert judge([a2, a])["verdict"] == "PASS"  # 入力順に依存しない
    # 別 reviewer の +1 では A の指摘は消えない
    assert judge([a], issues=[request(created="2026-01-02T02:00:00Z", login=B)], allowed=(BOT, B))["verdict"] == "FINDINGS"


def test_changes_requested_by_any_reviewer_blocks_other_approvals():
    a = review(state="CHANGES_REQUESTED", at="2026-01-02T01:00:00Z")
    b = review(login=B, rid=2, state="APPROVED", at="2026-01-02T02:00:00Z")
    assert judge([a, b], allowed=(BOT, B))["verdict"] == "FINDINGS"


def test_edited_request_comment_does_not_count():
    edited = dict(request(), updated_at="2026-01-02T05:00:00Z")
    assert judge(issues=[edited])["verdict"] == "MISSING"
    same = dict(request(), updated_at="2026-01-02T02:00:00Z")
    assert judge(issues=[same])["verdict"] == "PASS"


def test_plus_one_on_request_after_head_passes():
    assert judge(issues=[request()])["verdict"] == "PASS"


def clean_comment(sha=HEAD[:10], created="2026-01-02T02:00:00Z", login=BOT, **kw):
    return dict({"id": 11, "user": {"login": login}, "created_at": created,
                 "html_url": "https://github.com/o/r/pull/7#issuecomment-11",
                 "body": f"Codex Review: Didn't find any major issues.\n\n**Reviewed commit:** `{sha}`"}, **kw)


def test_clean_issue_comment_bound_to_head_passes():
    r = judge(issues=[clean_comment()])
    assert r["verdict"] == "PASS" and r["ref"].endswith("#issuecomment-11")
    assert judge(issues=[clean_comment(body="  Codex Review: Didn't find any major issues.\n`Reviewed commit:` `" + HEAD[:10] + "`")])["verdict"] == "MISSING"
    ok = "\n  Codex Review: Didn't find any major issues. Breezy!\n\n**Reviewed commit:** `" + HEAD[:10] + "`\n"
    assert judge(issues=[clean_comment(body=ok)])["verdict"] == "PASS"  # 既知の定型句だけ許容
    assert judge(issues=[clean_comment(body=ok.replace("Breezy!", "P0: auth bypass found"))])["verdict"] == "MISSING"


def test_real_codex_clean_comment_shape():
    real = REAL_CLEAN_BODY.replace("def0819f0e", HEAD[:10])
    assert judge(issues=[clean_comment(body=real)])["verdict"] == "PASS"
    finding = real.replace("Breezy!\n", "Breezy!\nBug: x.py:3 crashes.\n", 1)
    assert judge(issues=[clean_comment(body=finding)])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(body=real.rstrip() + "\nAlso a bug in y.py")])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(body=real + "x </details>")])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(body=real.replace("About Codex", "P0: auth bypass found"))])["verdict"] == "MISSING"


def test_head_change_during_collection_is_a_collection_error():
    base = make_run()
    n = []

    def run(args):
        if args[:2] == ["pr", "view"]:
            n.append(1)
            if len(n) == 2:
                return json.dumps({"headRefOid": "d" * 40})
        return base(args)
    payload, errors = build_payload(7, "o/r", [BOT], "B", None, run)
    assert any("head changed during collection (aaaaaaa -> ddddddd)" in e for e in errors)
    assert payload["collectionErrors"] == errors
    assert build_payload(7, "o/r", [BOT], "B", None, make_run())[1] == []


def test_clean_issue_comment_must_match_head_and_be_valid():
    assert judge(issues=[clean_comment(sha="def0819f0e")])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(sha=HEAD[:9])])["verdict"] == "MISSING"  # 10桁未満
    assert judge(issues=[clean_comment(created="2026-01-01T00:00:00Z")])["verdict"] == "MISSING"  # head_time より前（使い回し）
    assert judge(issues=[clean_comment()], head_time=None)["verdict"] == "MISSING"  # head_time 無しは無効
    mixed = "Found a bug in x.py. Codex Review: Didn't find any major issues.\n**Reviewed commit:** `" + HEAD[:10] + "`"
    assert judge(issues=[clean_comment(body=mixed)])["verdict"] == "MISSING"  # 先頭でない
    assert judge(issues=[clean_comment(body="Codex Review: Something went wrong. `Reviewed commit:` `" + HEAD[:10] + "`")])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(updated_at="2026-01-02T05:00:00Z")])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(html_url=None)])["verdict"] == "MISSING"
    assert judge(issues=[clean_comment(login="coordinator")])["verdict"] == "MISSING"


def test_clean_issue_comment_before_own_finding_is_findings():
    c = review(state="COMMENTED", at="2026-01-02T03:00:00Z")
    assert judge([c], issues=[clean_comment(created="2026-01-02T02:00:00Z")])["verdict"] == "FINDINGS"
    assert judge([c], issues=[clean_comment(created="2026-01-02T04:00:00Z")])["verdict"] == "PASS"


def test_plus_one_disabled_without_head_time():
    r = judge(issues=[request()], head_time=None)
    assert r["verdict"] == "MISSING" and "head time unavailable" in r["detail"]


def test_plus_one_on_request_before_head_is_missing():
    assert judge(issues=[request(created="2026-01-01T00:00:00Z")])["verdict"] == "MISSING"


def test_non_allowed_reviewer_is_missing():
    assert judge([review(login="coordinator")], issues=[request(login="coordinator")])["verdict"] == "MISSING"


def test_reviewer_identity_is_exact_but_case_insensitive():
    assert judge([review(login="foo[bot]")], allowed=["foo[bot]"])["verdict"] == "PASS"
    assert judge([review(login="FOO[BOT]")], allowed=["foo[bot]"])["verdict"] == "PASS"
    assert judge([review(login="foo")], allowed=["foo[bot]"])["verdict"] == "MISSING"
    assert judge([review(login="foo[bot]")], allowed=["foo"])["verdict"] == "MISSING"
    assert judge(issues=[request(login="foo")], allowed=["foo[bot]"])["verdict"] == "MISSING"


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
            return json.dumps(o.get("protection", {"required_status_checks": {"contexts": ["test", "ext/ci"]}}))
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
    assert payload["reviews"] == [{"state": "APPROVED", "author": {"login": BOT},
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


def test_app_pinned_required_check_rejects_other_app_and_statuses():
    def runs(*apps):
        return [{"check_runs": [{"name": "test", "status": "completed", "conclusion": "success", "head_sha": HEAD,
                                 "started_at": "2026-01-02T00:30:00Z", "app": {"id": a}} for a in apps]}]
    prot = {"required_status_checks": {"checks": [{"context": "test", "app_id": 15368}, {"context": "ext/ci", "app_id": -1}]}}
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run(protection=prot, check_runs=runs(999)))
    assert payload["requiredChecks"] == ["test", "ext/ci"]
    names = [e["name"] for e in payload["statusCheckRollup"]]
    assert "test" not in names and "ext/ci" in names  # -1 は任意 app（commit status 可）
    assert any("'test'" in r and "missing" in r for r in evaluate(payload)["reasons"])
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run(protection=prot, check_runs=runs(15368)))
    assert any(e["name"] == "test" and e["app_id"] == 15368 for e in payload["statusCheckRollup"])
    # app 固定の context は commit status では満たせない
    st = [{"sha": HEAD, "statuses": [{"context": "test", "state": "success"}]}]
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run(protection=prot, check_runs=runs(), status=st))
    assert not any(e["name"] == "test" for e in payload.get("statusCheckRollup", []))


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
            return json.dumps([[{"id": 9, "body": "@codex review", "created_at": "2026-01-02T00:10:00Z",
                                     "html_url": "https://github.com/o/r/pull/7#issuecomment-9"}]])
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


def test_latest_check_run_start_is_the_reference():
    # 古い開始(00:05)と新しい開始(00:30)が混在 → 基準は新しい方。請求(00:10)は無効
    run = _plus_one_run("2026-01-02T00:00:00Z", "2026-01-02T00:05:00Z")

    def wrapped(args):
        if "check-runs" in " ".join(args):
            return json.dumps([{"check_runs": [
                {"name": "test", "status": "completed", "conclusion": "success", "head_sha": HEAD, "started_at": t}
                for t in ("2026-01-02T00:05:00Z", "2026-01-02T00:30:00Z")]}])
        return run(args)
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, wrapped)
    assert payload["evidence"]["independent_review"]["verdict"] == "MISSING"


def test_missing_html_url_makes_signal_unusable():
    r = dict(review(), html_url=None)
    assert judge([r])["verdict"] == "FINDINGS"  # clean 扱いされない
    assert judge(issues=[dict(request(), html_url=None)])["verdict"] == "MISSING"


def test_collection_errors_are_in_payload_and_empty_on_success():
    payload, errors = build_payload(7, "o/r", [BOT], "B", None, make_run())
    assert payload["collectionErrors"] == [] and errors == []


def test_collected_at_is_set():
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, make_run())
    assert payload["collectedAt"].endswith("Z")


def test_plus_one_after_both_times_passes():
    payload, _ = build_payload(7, "o/r", [BOT], "B", None, _plus_one_run("2026-01-02T00:00:00Z", "2026-01-02T00:05:00Z"))
    assert payload["evidence"]["independent_review"]["verdict"] == "PASS"


def test_build_payload_with_fake_runner_feeds_the_gate():
    sec = {"verdict": "PASS", "head_sha": HEAD, "ref": "task_0123abcd"}
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
    assert set(payload) == {"collectedAt", "collectionErrors"} and errors and payload["collectionErrors"] == errors
    assert evaluate(payload)["ready"] is False
