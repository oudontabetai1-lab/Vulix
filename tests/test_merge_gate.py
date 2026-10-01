"""merge_gate の fail-closed 判定テスト（小さく・純粋・ブラウザ/ネットワーク非依存）。

成功パス 1 本を基準に、証跡の**欠落**と**stale**（別 commit への pin）が確実に
not ready へ倒れることを確認する。「情報が無い」が「問題が無い」に化けないことが主眼。
"""
from __future__ import annotations

import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from orchestration.merge_gate import REQUIRED_EVIDENCE, evaluate, main

HEAD = "a" * 40
OLD = "b" * 40
MODULE = Path(__file__).resolve().parents[1] / "orchestration" / "merge_gate.py"


def payload(**overrides):
    """全条件を満たす ready な PR。overrides で 1 箇所だけ壊して使う。"""
    base = {
        "number": 190,
        "state": "OPEN",
        "isDraft": False,
        "mergeable": True,
        "mergeStateStatus": "CLEAN",
        "headRefOid": HEAD,
        "requiredChecks": ["test", "lint"],
        "statusCheckRollup": [
            {"name": "test", "status": "COMPLETED", "conclusion": "SUCCESS", "commit": {"oid": HEAD}},
            {"name": "lint", "status": "COMPLETED", "conclusion": "SUCCESS", "commit": {"oid": HEAD}},
        ],
        "reviews": [{"author": {"login": "alice"}, "state": "APPROVED", "submittedAt": "2026-01-02"}],
        "reviewThreads": [{"path": "a.py", "isResolved": True}],
        "evidence": {k: {"verdict": "PASS", "head_sha": HEAD, "ref": f"https://example.test/{k}"} for k in REQUIRED_EVIDENCE},
        "tier": "A",
        "nightlyRecall": {"conclusion": "SUCCESS", "head_sha": "c" * 40},
    }
    base.update(overrides)
    return {k: v for k, v in base.items() if v is not ...}


def blocked(**overrides) -> list[str]:
    """overrides を適用した結果が not ready であることを確認し reasons を返す。"""
    result = evaluate(payload(**overrides))
    assert result["ready"] is False, f"expected not ready, got {result}"
    return result["reasons"]


def test_all_conditions_met_is_ready():
    result = evaluate(payload())
    assert result["ready"] is True, result["reasons"]
    assert result["pr"] == 190 and result["head_sha"] == HEAD
    assert result["reasons"], "ready でも根拠を残す"
    assert json.loads(json.dumps(result)) == result


@pytest.mark.parametrize("key, fragment", [
    ("isDraft", "isDraft missing"),
    ("mergeStateStatus", "mergeStateStatus missing"),
    ("reviews", "reviews missing"),
    ("reviewThreads", "reviewThreads missing"),
    ("mergeable", "mergeable unknown"),
    ("state", "state is unknown"),
    ("headRefOid", "head sha unknown"),
])
def test_missing_required_field_fails_closed(key, fragment):
    """キー欠落（"情報が無い"）を「問題が無い」と読み替えない。"""
    assert any(fragment in r for r in blocked(**{key: ...})), fragment


@pytest.mark.parametrize("key", ["isDraft", "mergeStateStatus", "reviews", "reviewThreads"])
def test_explicit_null_is_treated_as_missing(key):
    """JSON null も未提供として fail closed（空値を合格に化けさせない）。"""
    assert any("missing" in r for r in blocked(**{key: None}))


@pytest.mark.parametrize("bad", [{"state": "CLOSED"}, {"isDraft": True}, {"mergeable": False},
                                 {"mergeStateStatus": "BLOCKED"}, {"mergeStateStatus": "UNKNOWN"}])
def test_pr_state_blocks(bad):
    assert any(r.startswith("pr:") for r in blocked(**bad))


def test_ci_must_be_pinned_to_exact_head():
    """古い commit の成功も SHA 無しの成功も、現 head の証跡にならない。"""
    stale = blocked(statusCheckRollup=[{"name": "test", "conclusion": "SUCCESS", "commit": {"oid": OLD}},
                                       {"name": "lint", "conclusion": "SUCCESS", "commit": {"oid": HEAD}}])
    assert any("'test'" in r and "missing" in r for r in stale)

    unpinned = blocked(statusCheckRollup=[{"name": "test", "conclusion": "SUCCESS"},
                                          {"name": "lint", "conclusion": "SUCCESS", "commit": {"oid": HEAD}}])
    assert any("'test'" in r and "missing" in r for r in unpinned)


@pytest.mark.parametrize("entry, fragment", [
    ({"name": "test", "conclusion": "FAILURE", "commit": {"oid": HEAD}}, "FAILURE"),
    ({"name": "test", "conclusion": "SKIPPED", "commit": {"oid": HEAD}}, "SKIPPED"),
    ({"name": "test", "status": "IN_PROGRESS", "commit": {"oid": HEAD}}, "IN_PROGRESS"),
])
def test_non_success_required_check_blocks(entry, fragment):
    rollup = [entry, {"name": "lint", "conclusion": "SUCCESS", "commit": {"oid": HEAD}}]
    assert any("'test'" in r and fragment in r for r in blocked(statusCheckRollup=rollup))


def test_duplicate_required_check_is_ambiguous_and_blocks():
    rollup = [{"name": "test", "conclusion": "SUCCESS", "commit": {"oid": HEAD}},
              {"name": "test", "conclusion": "FAILURE", "commit": {"oid": HEAD}},
              {"name": "lint", "conclusion": "SUCCESS", "commit": {"oid": HEAD}}]
    assert any("duplicate" in r for r in blocked(statusCheckRollup=rollup))


def test_missing_required_check_and_empty_required_list_block():
    assert any("'lint'" in r and "missing" in r for r in
               blocked(statusCheckRollup=[{"name": "test", "conclusion": "SUCCESS", "commit": {"oid": HEAD}}]))
    assert any("no required checks" in r for r in blocked(requiredChecks=[]))


def test_changes_requested_blocks_and_later_approval_clears():
    reviews = [{"author": {"login": "bob"}, "state": "CHANGES_REQUESTED", "submittedAt": "2026-01-01"}]
    assert any("changes requested by bob" in r for r in blocked(reviews=reviews))

    commented = reviews + [{"author": {"login": "bob"}, "state": "COMMENTED", "submittedAt": "2026-01-03"}]
    assert any("changes requested by bob" in r for r in blocked(reviews=commented)), "COMMENTED は解除しない"

    approved = reviews + [{"author": {"login": "bob"}, "state": "APPROVED", "submittedAt": "2026-01-02"}]
    assert evaluate(payload(reviews=approved))["ready"] is True


def test_unresolved_thread_blocks():
    assert any("unresolved" in r for r in blocked(reviewThreads=[{"path": "x.py", "isResolved": False}]))
    assert any("boolean" in r for r in blocked(reviewThreads=[{"path": "x.py"}])), "解決状態不明は失格"


@pytest.mark.parametrize("value", ["x", True, 0, {"nodes": [{"state": "CHANGES_REQUESTED"}]}, ["x"]])
def test_malformed_reviews_fail_closed(value):
    assert any("review:" in r for r in blocked(reviews=value))


@pytest.mark.parametrize("value", ["x", 0, {"nodes": []}, ["x"]])
def test_malformed_threads_fail_closed(value):
    assert any("threads:" in r for r in blocked(reviewThreads=value))


@pytest.mark.parametrize("value", ["", [], "false", 0])
def test_nonboolean_draft_fails_closed(value):
    assert any("boolean" in r for r in blocked(isDraft=value))


@pytest.mark.parametrize("value", ["false", 0, None])
def test_nonboolean_resolution_fails_closed(value):
    assert any("boolean" in r for r in blocked(reviewThreads=[{"isResolved": value}]))


def test_undated_change_request_cannot_be_cleared():
    reviews = [{"author": {"login": "bob"}, "state": "CHANGES_REQUESTED"},
               {"author": {"login": "bob"}, "state": "APPROVED", "submittedAt": "2026-01-02"}]
    assert any("submittedAt missing" in r for r in blocked(reviews=reviews))


@pytest.mark.parametrize("key", REQUIRED_EVIDENCE)
def test_evidence_missing_stale_or_unpinned_blocks(key):
    """証跡は現 head に pin された PASS オブジェクトだけを有効にする。"""
    for broken, fragment in [
        (None, "missing"),
        ("PASS", "object"),                                   # 文字列形式は不可
        ({"verdict": "FAIL", "head_sha": HEAD, "ref": "r"}, "expected PASS"),
        ({"verdict": "PASS", "ref": "r"}, "no head_sha"),     # pin なし
        ({"verdict": "PASS", "head_sha": OLD, "ref": "r"}, "not current head"),  # 別 commit の流用
        ({"verdict": "PASS", "head_sha": HEAD}, "no ref"),    # 出典なし（手書き PASS）
        ({"verdict": "PASS", "head_sha": HEAD, "ref": "  "}, "no ref"),
    ]:
        evidence = {k: {"verdict": "PASS", "head_sha": HEAD, "ref": "r"} for k in REQUIRED_EVIDENCE}
        evidence[key] = broken
        assert any(f"'{key}'" in r and fragment in r for r in blocked(evidence=evidence)), (key, fragment)

    assert len(blocked(evidence=None)) >= len(REQUIRED_EVIDENCE)


def test_tier_a_requires_nightly_recall_success():
    assert evaluate(payload(tier="a"))["ready"] is True  # 大文字小文字は問わない
    assert any("recall" in r and "FAILURE" in r for r in blocked(nightlyRecall={"conclusion": "failure"}))
    assert any("recall" in r and "missing" in r for r in blocked(nightlyRecall=...))
    assert any("recall" in r and "missing" in r for r in blocked(nightlyRecall={"head_sha": HEAD}))


@pytest.mark.parametrize("tier", [..., None, "", "Z", 1])
def test_missing_or_unknown_tier_is_treated_as_a(tier):
    assert any("recall" in r for r in blocked(tier=tier, nightlyRecall={"conclusion": "FAILURE"}))


@pytest.mark.parametrize("tier", ["B", "c"])
def test_tier_b_c_ignore_nightly_recall(tier):
    assert evaluate(payload(tier=tier, nightlyRecall={"conclusion": "FAILURE"}))["ready"] is True
    assert evaluate(payload(tier=tier, nightlyRecall=...))["ready"] is True


@pytest.mark.parametrize("bad", [None, [], "nope", 42, {}])
def test_degenerate_input_fails_closed_without_raising(bad):
    result = evaluate(bad)
    assert result["ready"] is False and result["reasons"]


def test_reasons_are_deduped_and_deterministic():
    result = evaluate(payload(state="CLOSED", evidence=None))
    assert len(result["reasons"]) == len(set(result["reasons"]))
    assert result["reasons"] == evaluate(payload(state="CLOSED", evidence=None))["reasons"]


@pytest.mark.parametrize("data, code", [(payload(), 0), (payload(isDraft=True), 1)])
def test_cli_exit_codes(tmp_path, capsys, data, code):
    path = tmp_path / "in.json"
    path.write_text(json.dumps(data), encoding="utf-8")
    assert main(["--input", str(path)]) == code
    assert json.loads(capsys.readouterr().out)["ready"] is (code == 0)


@pytest.mark.parametrize("raw", ["not json", "", "   "])
def test_cli_bad_input_exits_two(tmp_path, capsys, raw):
    path = tmp_path / "bad.json"
    path.write_text(raw, encoding="utf-8")
    assert main(["--input", str(path)]) == 2
    assert json.loads(capsys.readouterr().out)["ready"] is False


def test_cli_reads_stdin():
    proc = subprocess.run([sys.executable, "-m", "orchestration.merge_gate"],
                          input=json.dumps(payload()), capture_output=True, text=True,
                          cwd=str(MODULE.parents[1]))
    assert proc.returncode == 0 and json.loads(proc.stdout)["ready"] is True


def test_module_is_read_only_stdlib_only():
    """read-only 不変条件: 散文ではなく実際の import 文（AST）を見る。"""
    banned = {"subprocess", "socket", "http", "urllib", "requests", "httpx", "github", "os"}
    tree = ast.parse(MODULE.read_text(encoding="utf-8"))
    roots = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            roots.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            roots.add(node.module.split(".")[0])
    assert not (roots & banned), roots & banned
    assert roots <= {"argparse", "json", "sys", "pathlib", "typing", "__future__"}, roots
