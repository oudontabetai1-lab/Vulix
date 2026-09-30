"""merge_gate 純粋ロジックのユニットテスト（read-only・fail closed）。

ネットワーク/gh 非依存。「ready=true は全条件が揃ったときだけ」「証跡欠落は not ready」
「古い head の CI 成功は数えない」を固定する。安全ツイン（ready ケース）と危険ケースを
1 対で持ち、過検知（通すべきを止める）と未検知（止めるべきを通す）の両方を守る。
"""
import ast
import json
import subprocess
import sys
from pathlib import Path

import pytest

from orchestration.merge_gate import evaluate, main, REQUIRED_EVIDENCE

HEAD = "a" * 40
OLD = "b" * 40


def _ok_payload(**overrides):
    """全条件を満たす（ready=true になる）基準ペイロード。"""
    payload = {
        "number": 190,
        "state": "OPEN",
        "isDraft": False,
        "mergeable": "MERGEABLE",
        "mergeStateStatus": "CLEAN",
        "headRefOid": HEAD,
        "requiredChecks": ["test"],
        "statusCheckRollup": [
            {
                "__typename": "CheckRun",
                "name": "test",
                "status": "COMPLETED",
                "conclusion": "SUCCESS",
                "completedAt": "2026-09-30T01:00:00Z",
                "commit": {"oid": HEAD},
            }
        ],
        "reviews": [],
        "reviewThreads": [],
        "evidence": {
            "independent_review": "PASS",
            "security_review": "PASS",
            "acceptance": "PASS",
        },
    }
    payload.update(overrides)
    return payload


# --- 安全ツイン: 全条件が揃えば通る ---------------------------------------


def test_all_conditions_met_is_ready():
    result = evaluate(_ok_payload())
    assert result["ready"] is True, result["reasons"]
    assert result["pr"] == 190
    assert result["head_sha"] == HEAD
    assert result["reasons"], "ready でも根拠を空にしない"


def test_result_is_json_serialisable():
    json.dumps(evaluate(_ok_payload()))  # 例外なく直列化できる


# --- PR 状態 ---------------------------------------------------------------


@pytest.mark.parametrize(
    "overrides, fragment",
    [
        ({"state": "CLOSED"}, "expected OPEN"),
        ({"state": "MERGED"}, "expected OPEN"),
        ({"isDraft": True}, "draft"),
        ({"mergeable": "CONFLICTING"}, "expected MERGEABLE"),
        ({"mergeable": "UNKNOWN"}, "expected MERGEABLE"),
        ({"mergeable": False}, "not mergeable"),
        ({"mergeStateStatus": "DIRTY"}, "mergeStateStatus"),
        ({"mergeStateStatus": "BLOCKED"}, "mergeStateStatus"),
        ({"mergeStateStatus": "BEHIND"}, "mergeStateStatus"),
    ],
)
def test_pr_state_blocks(overrides, fragment):
    result = evaluate(_ok_payload(**overrides))
    assert result["ready"] is False
    assert any(fragment in r for r in result["reasons"]), result["reasons"]


def test_missing_mergeable_fails_closed():
    payload = _ok_payload()
    del payload["mergeable"]
    result = evaluate(payload)
    assert result["ready"] is False
    assert any("mergeable unknown" in r for r in result["reasons"])


# --- CI（現 head に対する required check） ---------------------------------


def test_stale_ci_success_on_old_head_does_not_count():
    """古い commit の SUCCESS を現 head の証跡として流用しない。"""
    payload = _ok_payload(
        statusCheckRollup=[
            {"name": "test", "status": "COMPLETED", "conclusion": "SUCCESS", "commit": {"oid": OLD}}
        ]
    )
    result = evaluate(payload)
    assert result["ready"] is False
    assert any("stale" in r for r in result["reasons"]), result["reasons"]


def test_missing_required_check_blocks():
    result = evaluate(_ok_payload(requiredChecks=["test", "e2e-smoke"]))
    assert result["ready"] is False
    assert any("'e2e-smoke' missing" in r for r in result["reasons"])


@pytest.mark.parametrize("conclusion", ["FAILURE", "CANCELLED", "TIMED_OUT", "NEUTRAL", "SKIPPED", ""])
def test_non_success_conclusion_blocks(conclusion):
    payload = _ok_payload(
        statusCheckRollup=[
            {"name": "test", "status": "COMPLETED", "conclusion": conclusion, "commit": {"oid": HEAD}}
        ]
    )
    assert evaluate(payload)["ready"] is False


def test_incomplete_check_run_blocks():
    payload = _ok_payload(
        statusCheckRollup=[
            {"name": "test", "status": "IN_PROGRESS", "conclusion": "", "commit": {"oid": HEAD}}
        ]
    )
    result = evaluate(payload)
    assert result["ready"] is False
    assert any("IN_PROGRESS" in r for r in result["reasons"])


def test_rerun_uses_latest_completion():
    """同名 check の再実行は最後の完了結果（成功）を採用する。"""
    payload = _ok_payload(
        statusCheckRollup=[
            {"name": "test", "status": "COMPLETED", "conclusion": "FAILURE",
             "completedAt": "2026-09-30T01:00:00Z", "commit": {"oid": HEAD}},
            {"name": "test", "status": "COMPLETED", "conclusion": "SUCCESS",
             "completedAt": "2026-09-30T02:00:00Z", "commit": {"oid": HEAD}},
        ]
    )
    assert evaluate(payload)["ready"] is True


def test_no_required_checks_declared_fails_closed():
    result = evaluate(_ok_payload(requiredChecks=[]))
    assert result["ready"] is False
    assert any("no required checks" in r for r in result["reasons"])


def test_status_context_shape_is_supported():
    """StatusContext 形式（context/state）も読める。"""
    payload = _ok_payload(
        requiredChecks=["legacy"],
        statusCheckRollup=[{"context": "legacy", "state": "SUCCESS", "commit": {"oid": HEAD}}],
    )
    assert evaluate(payload)["ready"] is True


# --- レビュー ---------------------------------------------------------------


def test_changes_requested_blocks():
    payload = _ok_payload(
        reviews=[{"state": "CHANGES_REQUESTED", "author": {"login": "alice"},
                  "submittedAt": "2026-09-30T01:00:00Z"}]
    )
    result = evaluate(payload)
    assert result["ready"] is False
    assert any("changes requested by alice" in r for r in result["reasons"])


def test_later_approval_supersedes_changes_requested():
    payload = _ok_payload(
        reviews=[
            {"state": "CHANGES_REQUESTED", "author": {"login": "alice"},
             "submittedAt": "2026-09-30T01:00:00Z"},
            {"state": "APPROVED", "author": {"login": "alice"},
             "submittedAt": "2026-09-30T02:00:00Z"},
        ]
    )
    assert evaluate(payload)["ready"] is True


def test_commented_review_does_not_clear_changes_requested():
    payload = _ok_payload(
        reviews=[
            {"state": "CHANGES_REQUESTED", "author": {"login": "alice"},
             "submittedAt": "2026-09-30T01:00:00Z"},
            {"state": "COMMENTED", "author": {"login": "alice"},
             "submittedAt": "2026-09-30T03:00:00Z"},
        ]
    )
    assert evaluate(payload)["ready"] is False


# --- レビュースレッド -------------------------------------------------------


def test_unresolved_thread_blocks():
    payload = _ok_payload(reviewThreads=[{"isResolved": False, "path": "wscan/engine.py"}])
    result = evaluate(payload)
    assert result["ready"] is False
    assert any("unresolved" in r and "wscan/engine.py" in r for r in result["reasons"])


def test_thread_without_resolution_flag_fails_closed():
    payload = _ok_payload(reviewThreads=[{"path": "wscan/engine.py"}])
    assert evaluate(payload)["ready"] is False


def test_resolved_threads_are_fine():
    payload = _ok_payload(reviewThreads=[{"isResolved": True, "path": "wscan/engine.py"}])
    assert evaluate(payload)["ready"] is True


# --- ローカル証跡 -----------------------------------------------------------


@pytest.mark.parametrize("key", REQUIRED_EVIDENCE)
def test_each_missing_evidence_blocks(key):
    payload = _ok_payload()
    del payload["evidence"][key]
    result = evaluate(payload)
    assert result["ready"] is False
    assert any(f"missing '{key}'" in r for r in result["reasons"])


@pytest.mark.parametrize("key", REQUIRED_EVIDENCE)
@pytest.mark.parametrize("verdict", ["FAIL", "PENDING", "SKIPPED", "", "pass?"])
def test_non_pass_evidence_blocks(key, verdict):
    payload = _ok_payload()
    payload["evidence"][key] = verdict
    assert evaluate(payload)["ready"] is False


def test_evidence_is_case_insensitive_pass():
    payload = _ok_payload()
    payload["evidence"]["acceptance"] = "pass"
    assert evaluate(payload)["ready"] is True


def test_evidence_bound_to_old_head_is_rejected():
    """別 commit に対する PASS を現 head に流用させない。"""
    payload = _ok_payload()
    payload["evidence"]["security_review"] = {"verdict": "PASS", "head_sha": OLD}
    result = evaluate(payload)
    assert result["ready"] is False
    assert any("not current head" in r for r in result["reasons"])


def test_evidence_bound_to_current_head_is_accepted():
    payload = _ok_payload()
    payload["evidence"]["security_review"] = {"verdict": "PASS", "head_sha": HEAD}
    assert evaluate(payload)["ready"] is True


def test_evidence_block_absent_lists_all_three():
    payload = _ok_payload()
    del payload["evidence"]
    result = evaluate(payload)
    assert result["ready"] is False
    for key in REQUIRED_EVIDENCE:
        assert any(f"missing '{key}'" in r for r in result["reasons"])


# --- 境界・壊れた入力 -------------------------------------------------------


@pytest.mark.parametrize("payload", [{}, [], None, "nope", 42])
def test_degenerate_inputs_fail_closed_without_raising(payload):
    result = evaluate(payload)
    assert result["ready"] is False
    assert result["reasons"]


def test_reasons_are_deduped_and_deterministic():
    payload = _ok_payload(state="CLOSED", requiredChecks=["test", "test"])
    first = evaluate(payload)["reasons"]
    second = evaluate(payload)["reasons"]
    assert first == second
    assert len(first) == len(set(first))


# --- CLI（read-only・exit code） -------------------------------------------


def test_cli_ready_exits_zero(tmp_path, capsys):
    path = tmp_path / "ok.json"
    path.write_text(json.dumps(_ok_payload()), encoding="utf-8")
    assert main(["--input", str(path)]) == 0
    assert json.loads(capsys.readouterr().out)["ready"] is True


def test_cli_not_ready_exits_one(tmp_path, capsys):
    path = tmp_path / "ng.json"
    path.write_text(json.dumps(_ok_payload(state="CLOSED")), encoding="utf-8")
    assert main(["--input", str(path)]) == 1
    assert json.loads(capsys.readouterr().out)["ready"] is False


def test_cli_invalid_json_exits_two(tmp_path, capsys):
    path = tmp_path / "bad.json"
    path.write_text("{not json", encoding="utf-8")
    assert main(["--input", str(path)]) == 2
    out = json.loads(capsys.readouterr().out)
    assert out["ready"] is False and "invalid JSON" in out["reasons"][0]


def test_cli_missing_file_exits_two(capsys):
    assert main(["--input", "/nonexistent/merge-gate-input.json"]) == 2
    assert json.loads(capsys.readouterr().out)["ready"] is False


def test_cli_reads_stdin_end_to_end():
    """`python -m orchestration.merge_gate` として実際に動くことを確認する。"""
    repo_root = Path(__file__).resolve().parents[1]
    proc = subprocess.run(
        [sys.executable, "-m", "orchestration.merge_gate"],
        input=json.dumps(_ok_payload()),
        capture_output=True,
        text=True,
        cwd=repo_root,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["ready"] is True


def test_module_never_mutates_github():
    """read-only 不変条件: プロセス起動・ネットワークの import 経路を持たない。

    docstring の散文ではなく **実際の import 文**（AST）だけを見る。
    """
    source = (Path(__file__).resolve().parents[1] / "orchestration" / "merge_gate.py").read_text(
        encoding="utf-8"
    )
    imported: set[str] = set()
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            imported.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            imported.add(node.module.split(".")[0])

    forbidden = {"subprocess", "os", "shutil", "socket", "requests", "httpx", "urllib"}
    assert not (imported & forbidden), f"merge_gate must stay read-only (imports {imported & forbidden})"


def test_module_only_uses_stdlib():
    """stdlib 制約: サードパーティ依存を持ち込まない。"""
    source = (Path(__file__).resolve().parents[1] / "orchestration" / "merge_gate.py").read_text(
        encoding="utf-8"
    )
    allowed = {"argparse", "json", "sys", "typing", "__future__", "dataclasses", "re"}
    for node in ast.walk(ast.parse(source)):
        if isinstance(node, ast.Import):
            for alias in node.names:
                assert alias.name.split(".")[0] in allowed, alias.name
        elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
            assert node.module.split(".")[0] in allowed, node.module
