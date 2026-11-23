"""Agent supervisor harness の状態・証跡・resume契約。"""
from __future__ import annotations

import json

import pytest

from wscan.agent_harness import (
    AgentHarness,
    AgentPhase,
    AgentRole,
    AgentRunSpec,
    AgentRunStatus,
    WorkStatus,
    step_signature,
)


def spec(*, model="exact-model", max_steps=5, auth_context_hash=""):
    return AgentRunSpec(
        mode="agent",
        target_url="http://fixture.test",
        target_urls=("http://fixture.test",),
        access_urls=(),
        exclude_urls=("/logout",),
        exclude_fields=("csrf_token",),
        checks=("xss", "sqli"),
        provider="ollama",
        model=model,
        max_steps=max_steps,
        auth_context_hash=auth_context_hash,
    )


def test_spec_hash_is_stable_and_model_sensitive():
    assert spec().spec_hash == spec().spec_hash
    assert spec().spec_hash != spec(model="other").spec_hash


def test_step_trace_redacts_secrets_and_checkpoints_budget(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    harness.set_phase(AgentPhase.EXECUTING)

    harness.record_step(
        episode_id="episode-1",
        local_step=2,
        url="http://fixture.test/a?access_token=secret-token",
        proposed_actions=[{"input_text": {"text": "password=secret-value"}}],
        executed_actions=[{"click": {"index": 2}}],
    )

    state = json.loads((tmp_path / "agent_state.json").read_text())
    trace = (tmp_path / "agent_steps.jsonl").read_text()
    assert state["consumed_steps"] == 2
    assert harness.remaining_steps == 3
    assert "secret-token" not in trace
    assert "secret-value" not in trace
    assert "<redacted>" in trace


def test_loop_breaker_marks_partial_without_losing_coverage(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=10), repeat_threshold=3)
    for step in range(1, 4):
        harness.record_step(
            episode_id="episode-1",
            local_step=step,
            url="http://fixture.test/search",
            proposed_actions=[{"click": {"index": 1}}],
            executed_actions=[{"click": {"index": 1}}],
        )
    harness.note_coverage(
        visited_urls=["http://fixture.test/search"],
        coverage_gaps=["q:sqli"],
    )

    status = harness.finalize(success=False, coverage_complete=False)

    assert status == AgentRunStatus.PARTIAL
    assert harness.state.stop_reason == "loop_detected"
    assert harness.state.coverage_gaps == ["q:sqli"]
    assert json.loads((tmp_path / "agent_manifest.json").read_text())["status"] == "partial"


def test_resume_preserves_global_budget_and_rejects_spec_drift(tmp_path):
    first = AgentHarness(tmp_path, spec(max_steps=5))
    first.record_step(
        episode_id="episode-1", local_step=3, url="http://fixture.test/a",
        proposed_actions=[], executed_actions=[],
    )

    resumed = AgentHarness(tmp_path, spec(max_steps=5), resume=True)
    assert resumed.remaining_steps == 2
    assert "2 global steps remain" in resumed.resume_context()
    resumed.record_step(
        episode_id="episode-2", local_step=2, url="http://fixture.test/b",
        proposed_actions=[], executed_actions=[],
    )
    assert resumed.remaining_steps == 0

    with pytest.raises(ValueError, match="spec mismatch"):
        AgentHarness(tmp_path, spec(model="different", max_steps=5), resume=True)


def test_resume_rejects_changed_authentication_context(tmp_path):
    original = spec(max_steps=5, auth_context_hash="account-a")
    AgentHarness(tmp_path, original)
    with pytest.raises(ValueError, match="spec mismatch"):
        AgentHarness(
            tmp_path,
            spec(max_steps=5, auth_context_hash="account-b"),
            resume=True,
        )


def test_complete_requires_explicit_coverage_contract(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    assert harness.finalize(success=True, coverage_complete=False) == AgentRunStatus.PARTIAL

    other = AgentHarness(tmp_path / "complete", spec())
    other.note_coverage(visited_urls=["http://fixture.test"])
    assert other.finalize(success=True, coverage_complete=True) == AgentRunStatus.COMPLETE


def test_step_signature_is_deterministic():
    assert step_signature("http://a/", ["click"]) == step_signature("http://a", ["click"])


def test_work_queue_is_persistent_and_requires_every_role_to_complete(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    explore = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test/")
    probe = harness.enqueue(
        AgentRole.PROBE_SPECIALIST,
        "http://fixture.test/search?q=",
        check_type="xss",
    )
    assert harness.enqueue(AgentRole.EXPLORER, "http://fixture.test/").work_id == explore.work_id
    assert harness.next_work().work_id == explore.work_id
    harness.finish_work(explore.work_id, WorkStatus.COMPLETE)
    assert harness.coverage_complete is False

    resumed = AgentHarness(tmp_path, spec(), resume=True)
    assert resumed.next_work().work_id == probe.work_id
    resumed.finish_work(probe.work_id, WorkStatus.COMPLETE)
    assert resumed.coverage_complete is True


def test_inconclusive_verification_prevents_complete(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    verifier = harness.enqueue(AgentRole.VERIFIER, "hypothesis:1", check_type="sqli")
    harness.next_work()
    harness.finish_work(verifier.work_id, WorkStatus.INCONCLUSIVE)
    assert harness.coverage_complete is False


def test_resume_requeues_interrupted_running_work(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=8))
    item = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test")
    assert harness.next_work().status == WorkStatus.RUNNING
    resumed = AgentHarness(tmp_path, spec(max_steps=8), resume=True)
    assert resumed.next_work().work_id == item.work_id


def test_runtime_secret_values_are_removed_from_trace_and_checkpoint(tmp_path):
    harness = AgentHarness(tmp_path, spec(), secret_values=["unlabeled-secret"])
    item = harness.enqueue(AgentRole.AUTHENTICATOR, "http://fixture.test/login")
    harness.next_work()
    harness.record_step(
        episode_id=item.work_id, local_step=1, url="http://fixture.test/login",
        proposed_actions=[{"input_text": {"text": "unlabeled-secret"}}],
        executed_actions=[],
    )
    harness.finish_work(item.work_id, WorkStatus.COMPLETE, summary="echo unlabeled-secret")
    artifacts = (tmp_path / "agent_steps.jsonl").read_text() + (tmp_path / "agent_state.json").read_text()
    assert "unlabeled-secret" not in artifacts
    assert "<redacted>" in artifacts


def test_requeue_role_resets_completed_authentication(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    auth = harness.enqueue(AgentRole.AUTHENTICATOR, "http://fixture.test/login")
    harness.next_work()
    harness.finish_work(auth.work_id, WorkStatus.COMPLETE, summary="AUTH COMPLETE")
    assert harness.requeue_role(AgentRole.AUTHENTICATOR) == 1
    assert harness.next_work().work_id == auth.work_id


def test_requeue_role_resets_completed_verifier_for_resume(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    verifier = harness.enqueue(AgentRole.VERIFIER, "candidate-1", check_type="xss")
    harness.next_work()
    harness.finish_work(verifier.work_id, WorkStatus.COMPLETE)
    assert harness.requeue_role(AgentRole.VERIFIER) == 1
    assert harness.next_work().work_id == verifier.work_id


def test_structured_hypotheses_survive_resume_without_session_nonce(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=8))
    hypothesis = {
        "candidate_id": "candidate-1",
        "check_type": "xss",
        "severity": "high",
        "url": "http://fixture.test/search",
        "field_name": "q",
        "payload": "<svg/onload=alert(1)>",
        "evidence": "dialog observed",
        "dynamic_verified": False,
    }
    harness.note_hypotheses([hypothesis])
    resumed = AgentHarness(tmp_path, spec(max_steps=8), resume=True)
    assert resumed.state.hypotheses == [hypothesis]
    resumed.mark_dynamic_verification("candidate-1", True)
    assert resumed.state.hypotheses[0]["dynamic_verified"] is True


def test_finalize_redacts_runtime_secret_from_persisted_error(tmp_path):
    harness = AgentHarness(tmp_path, spec(), secret_values=["error-secret"])
    harness.finalize(
        success=False, coverage_complete=False,
        error="dependency rejected error-secret",
    )
    state = (tmp_path / "agent_state.json").read_text()
    assert "error-secret" not in state
    assert "<redacted>" in state


def test_note_coverage_redacts_configured_secrets_everywhere(tmp_path):
    harness = AgentHarness(tmp_path, spec(), secret_values=["coverage-secret"])
    harness.note_coverage(
        visited_urls=["http://fixture.test/private/coverage-secret"],
        tested_targets=["field=coverage-secret"],
        coverage_gaps=["retry coverage-secret"],
    )
    artifacts = (tmp_path / "agent_state.json").read_text()
    assert "coverage-secret" not in artifacts
    assert artifacts.count("<redacted>") == 3


@pytest.mark.parametrize("failed_name", ["agent_state.json", "agent_manifest.json"])
def test_finalize_reports_incomplete_when_final_artifact_write_fails(
    tmp_path, monkeypatch, failed_name
):
    harness = AgentHarness(tmp_path, spec())
    original_write = harness._atomic_write_json

    def fail_selected(path, data, force=False):
        if path.name == failed_name:
            return False
        return original_write(path, data, force=force)

    monkeypatch.setattr(harness, "_atomic_write_json", fail_selected)
    status = harness.finalize(success=True, coverage_complete=True)
    assert status == AgentRunStatus.EVIDENCE_INCOMPLETE


def test_real_manifest_failure_downgrades_durable_checkpoint(tmp_path):
    # 実際の manifest 書き込み失敗（_evidence_failed が立つ）後も downgrade checkpoint を永続化し、
    # agent_state.json が complete のまま残らない。
    harness = AgentHarness(tmp_path, spec())
    harness.manifest_path.mkdir()  # os.replace が失敗する（ディレクトリ）
    status = harness.finalize(success=True, coverage_complete=True)
    assert status == AgentRunStatus.EVIDENCE_INCOMPLETE
    assert json.loads(harness.state_path.read_text())["status"] == "evidence_incomplete"


def test_loop_detection_is_scoped_to_each_episode(tmp_path):
    harness = AgentHarness(tmp_path, spec(max_steps=20), repeat_threshold=3)
    for episode in ("A", "B", "C"):
        for step in (1, 2):
            record = harness.record_step(
                episode_id=episode, local_step=step, url="http://fixture.test",
                proposed_actions=[{"done": {}}], executed_actions=[],
            )
            assert not record.repeated
            assert harness.state.stop_reason != "loop_detected"
    record = harness.record_step(
        episode_id="C", local_step=3, url="http://fixture.test",
        proposed_actions=[{"done": {}}], executed_actions=[],
    )
    assert record.repeated
    assert harness.state.stop_reason == "loop_detected"


def test_reviewer_gap_survives_retry_and_checkpoint_until_explicit_resolution(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    work = harness.enqueue(AgentRole.ADVERSARIAL_REVIEWER, "http://fixture.test")
    harness.record_reviewer_gaps(["missing /admin xss", "missing /admin xss"])
    harness.finish_work(work.work_id, WorkStatus.INCONCLUSIVE)
    harness.note_coverage(coverage_gaps=["reviewer:inconclusive"])
    harness.finish_work(work.work_id, WorkStatus.COMPLETE)
    harness.note_coverage(coverage_gaps=[])
    assert harness.state.reviewer_gaps == ["missing /admin xss"]
    assert not harness.coverage_complete

    resumed = AgentHarness(tmp_path, spec(), resume=True)
    assert resumed.state.reviewer_gaps == ["missing /admin xss"]
    assert not resumed.coverage_complete
    resumed.resolve_reviewer_gaps(["", "unrelated gap", "/admin"])
    assert not resumed.coverage_complete
    resumed.resolve_reviewer_gaps([" MISSING  /admin XSS "])
    assert resumed.coverage_complete
    assert AgentHarness(tmp_path, spec(), resume=True).state.reviewer_gaps == []


def test_reviewer_gaps_redacted_capped_and_accumulated(tmp_path):
    harness = AgentHarness(tmp_path, spec(), secret_values=["private-secret"])
    harness.record_reviewer_gaps(["private-secret", "x" * 1500, " "])
    harness.record_reviewer_gaps(["other gap", "private-secret"])
    assert harness.state.reviewer_gaps == ["<redacted>", "x" * 1000, "other gap"]
    assert "private-secret" not in harness.state_path.read_text()
    assert harness.finalize(success=True, coverage_complete=True) == AgentRunStatus.PARTIAL
    assert not json.loads(harness.manifest_path.read_text())["coverage_complete"]


def test_legacy_checkpoint_without_reviewer_gaps(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    data = json.loads(harness.state_path.read_text())
    data.pop("reviewer_gaps")
    harness.state_path.write_text(json.dumps(data))
    assert AgentHarness(tmp_path, spec(), resume=True).state.reviewer_gaps == []


def test_short_secret_preserves_candidate_id_through_resume_and_verification(tmp_path):
    candidate_id = "329fc1e63355d6014a43"
    harness = AgentHarness(tmp_path, spec(), secret_values=["a"])
    hypothesis = {
        "candidate_id": candidate_id,
        "evidence": "a",
        "nested": [{"candidate_id": candidate_id, "evidence": "a"}],
        "dynamic_verified": False,
    }
    safe = harness._sanitize_value(hypothesis)
    assert safe["candidate_id"] == candidate_id
    assert safe["evidence"] == "<redacted>"
    assert safe["nested"] == [{"candidate_id": candidate_id, "evidence": "<redacted>"}]
    harness.note_hypotheses([hypothesis])
    resumed = AgentHarness(tmp_path, spec(), resume=True, secret_values=["a"])
    assert resumed.state.hypotheses[0]["candidate_id"] == candidate_id
    assert resumed.state.hypotheses[0]["evidence"] == "<redacted>"
    resumed.mark_dynamic_verification(candidate_id, True)
    state = json.loads((tmp_path / "agent_state.json").read_text())
    assert state["hypotheses"][0]["dynamic_verified"] is True


def test_redaction_happens_before_truncation(tmp_path):
    # 境界を跨ぐ JSON 秘密の先頭を永続化しない。
    harness = AgentHarness(tmp_path, spec())
    item = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test")
    harness.next_work()
    summary = "x" * 985 + '{"password": "SUPERSECRETVALUE"}'
    harness.finish_work(item.work_id, WorkStatus.COMPLETE, summary=summary)
    assert "SUPERS" not in (tmp_path / "agent_state.json").read_text()


def test_trace_failure_persists_evidence_incomplete_state(tmp_path):
    # trace 等で _evidence_failed が立ち manifest は書ける場合も、最終 state を durable に揃える。
    harness = AgentHarness(tmp_path, spec())
    harness._evidence_failed = True
    harness.state.evidence_errors.append("trace_write:OSError")
    status = harness.finalize(success=True, coverage_complete=True)
    assert status == AgentRunStatus.EVIDENCE_INCOMPLETE
    assert json.loads(harness.state_path.read_text())["status"] == "evidence_incomplete"


def test_loop_detection_considers_page_state(tmp_path):
    # URL 固定でも DOM が進んでいれば loop としない。
    harness = AgentHarness(tmp_path, spec(max_steps=20), repeat_threshold=3)
    for step, state in enumerate(("s1", "s2", "s3", "s4"), start=1):
        record = harness.record_step(
            episode_id="A", local_step=step, url="http://fixture.test/wizard",
            proposed_actions=[{"click": {"index": 3}}], executed_actions=[], page_state=state,
        )
        assert not record.repeated
    assert harness.state.stop_reason != "loop_detected"


def test_phase_transitions_valid_and_invalid(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    assert harness.state.phase == AgentPhase.INITIALIZING

    # 正例シーケンス
    harness.set_phase(AgentPhase.AUTHENTICATING)
    assert harness.state.phase == AgentPhase.AUTHENTICATING
    harness.set_phase(AgentPhase.RECONNING)
    assert harness.state.phase == AgentPhase.RECONNING
    harness.set_phase(AgentPhase.SCHEDULING)
    assert harness.state.phase == AgentPhase.SCHEDULING
    harness.set_phase(AgentPhase.EXECUTING)
    assert harness.state.phase == AgentPhase.EXECUTING
    harness.set_phase(AgentPhase.VERIFYING)
    assert harness.state.phase == AgentPhase.VERIFYING
    harness.set_phase(AgentPhase.CHECKPOINTING)
    assert harness.state.phase == AgentPhase.CHECKPOINTING
    harness.set_phase(AgentPhase.SCHEDULING)
    assert harness.state.phase == AgentPhase.SCHEDULING
    harness.set_phase(AgentPhase.FINALIZING)
    assert harness.state.phase == AgentPhase.FINALIZING

    # 同一フェーズへの再遷移は許容（no-op）
    harness.set_phase(AgentPhase.FINALIZING)
    assert harness.state.phase == AgentPhase.FINALIZING

    # 負例: FINALIZING からの再遷移は不正
    with pytest.raises(ValueError, match="Invalid phase transition"):
        harness.set_phase(AgentPhase.EXECUTING)

    with pytest.raises(ValueError, match="Invalid phase transition"):
        harness.set_phase(AgentPhase.INITIALIZING)


def test_work_status_transitions_valid_and_invalid(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    item = harness.enqueue(AgentRole.PROBE_SPECIALIST, "http://fixture.test/search", check_type="xss")
    assert item.status == WorkStatus.PLANNED

    # 正常な遷移ステップ
    item.transition_to(WorkStatus.RUNNING)
    assert item.status == WorkStatus.RUNNING
    item.transition_to(WorkStatus.CANDIDATE)
    assert item.status == WorkStatus.CANDIDATE
    item.transition_to(WorkStatus.VERIFY_PENDING)
    assert item.status == WorkStatus.VERIFY_PENDING
    item.transition_to(WorkStatus.REPRODUCED)
    assert item.status == WorkStatus.REPRODUCED

    # 不正遷移: 終端状態からの通常遷移は拒否
    with pytest.raises(ValueError, match="Invalid work status transition"):
        item.transition_to(WorkStatus.RUNNING)

    # 不正遷移: PLANNED から直接 REPRODUCED
    item2 = harness.enqueue(AgentRole.PROBE_SPECIALIST, "http://fixture.test/login", check_type="sqli")
    with pytest.raises(ValueError, match="Invalid work status transition"):
        item2.transition_to(WorkStatus.REPRODUCED)

    # 不正遷移: finish_work で非終端ステータスを指定
    with pytest.raises(ValueError, match="requires a terminal work status"):
        harness.finish_work(item2.work_id, WorkStatus.RUNNING)


def test_candidate_ledger_retains_rejected_inconclusive_agent_only_with_evidence(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    harness.note_hypotheses([
        {
            "candidate_id": "cand-xss-1",
            "check_type": "xss",
            "url": "http://fixture.test/reflect",
            "status": "proposed",
        },
        {
            "candidate_id": "cand-sqli-2",
            "check_type": "sqli",
            "url": "http://fixture.test/items",
            "status": "proposed",
        },
    ])

    # 1. 候補を rejected に更新（理由と証拠参照つき、削除しない）
    harness.update_hypothesis(
        "cand-xss-1",
        status="rejected",
        rejection_reason="WAF filter sanitized payload",
        evidence_ids=["evidence-waf-drop"],
    )

    # 2. 候補を inconclusive / agent-only に更新（独自性の保持、削除しない）
    harness.update_hypothesis(
        "cand-sqli-2",
        status="agent_only",
        source_label="agent_unverified",
        evidence_ids=["evidence-timing-heuristic"],
    )

    # 3. mark_dynamic_verification で未再現でも候補は削除されず保持
    harness.mark_dynamic_verification("cand-sqli-2", reproduced=False, rejection_reason="timeout on replay")

    state = json.loads(harness.state_path.read_text())
    hypotheses = {h["candidate_id"]: h for h in state["hypotheses"]}
    assert len(hypotheses) == 2

    xss = hypotheses["cand-xss-1"]
    assert xss["status"] == "rejected"
    assert xss["rejection_reason"] == "WAF filter sanitized payload"
    assert xss["evidence_ids"] == ["evidence-waf-drop"]

    sqli = hypotheses["cand-sqli-2"]
    assert sqli["dynamic_verified"] is False
    assert sqli["rejection_reason"] == "timeout on replay"
    assert sqli["source_label"] == "agent_unverified"
    assert "evidence-timing-heuristic" in sqli["evidence_ids"]

    # manifest にも全件残っていること
    harness.finalize(success=False, coverage_complete=False)
    manifest = json.loads(harness.manifest_path.read_text())
    assert manifest["hypotheses_count"] == 2


def test_correlation_ids_trace_through_step_llm_probe_and_verification(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    item = harness.enqueue(
        AgentRole.PROBE_SPECIALIST,
        "http://fixture.test/comments",
        check_type="xss",
        correlation_id="corr-flow-1",
    )

    # Step 記録
    step = harness.record_step(
        episode_id="ep-1",
        local_step=1,
        url="http://fixture.test/comments",
        proposed_actions=[{"type": "input"}],
        executed_actions=[{"type": "input"}],
        work_id=item.work_id,
        correlation_id="corr-flow-1",
        llm_call_ids=["llm-test-1"],
        probe_attempt_ids=["probe-test-1"],
        hypothesis_ids=["cand-1"],
    )
    assert step.correlation_id == "corr-flow-1"
    assert step.work_id == item.work_id
    assert step.llm_call_ids == ("llm-test-1",)

    # LLM 呼び出し記録
    llm_call = harness.record_llm_call(
        episode_id="ep-1",
        step_id=step.step_id,
        work_id=item.work_id,
        correlation_id="corr-flow-1",
        role="probe_specialist",
        prompt_tokens=120,
        completion_tokens=40,
        status="ok",
    )
    assert llm_call.correlation_id == "corr-flow-1"
    assert llm_call.step_id == step.step_id
    assert (tmp_path / "llm_calls.jsonl").exists()

    # Probe 試行記録
    probe = harness.record_probe_attempt(
        target_url="http://fixture.test/comments",
        check_type="xss",
        payload="<script>alert(1)</script>",
        episode_id="ep-1",
        step_id=step.step_id,
        work_id=item.work_id,
        correlation_id="corr-flow-1",
        status="reflected",
        response_status=200,
        evidence_id="ev-dom-1",
    )
    assert probe.correlation_id == "corr-flow-1"
    assert probe.step_id == step.step_id
    assert (tmp_path / "probe_attempts.jsonl").exists()

    # 仮説台帳登録と検証結果記録
    harness.note_hypotheses([{
        "candidate_id": "cand-1",
        "check_type": "xss",
        "url": "http://fixture.test/comments",
    }])
    verification = harness.record_verification(
        "cand-1",
        reproduced=True,
        method="deterministic",
        deterministic_confirmed=True,
        episode_id="ep-1",
        step_id=step.step_id,
        work_id=item.work_id,
        correlation_id="corr-flow-1",
        evidence_ids=["ev-dom-1"],
    )
    assert verification.correlation_id == "corr-flow-1"
    assert verification.reproduced is True
    assert (tmp_path / "verification_results.jsonl").exists()

    # 候補台帳が同期更新され、決定論確証ラベルが付与されていること
    cand = [h for h in harness.state.hypotheses if h["candidate_id"] == "cand-1"][0]
    assert cand["deterministic_confirmed"] is True
    assert cand["source_label"] == "agent_deterministic_confirmed"


def test_resume_backward_compatibility_with_legacy_and_unknown_keys(tmp_path):
    harness = AgentHarness(tmp_path, spec())
    item = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test/home")
    harness.next_work()
    harness.finish_work(item.work_id, WorkStatus.COMPLETE)

    # 古い形式（新キーがなく、未知のキーが含まれる）の JSON を作成
    data = json.loads(harness.state_path.read_text())
    # 未知キーの挿入
    data["unknown_future_field"] = "unexpected_value"
    data["work_queue"][0]["unknown_worker_flag"] = True
    # 新キーを除去（古い checkpoint を模倣）
    data["work_queue"][0].pop("rejection_reason", None)
    data["work_queue"][0].pop("evidence_ids", None)
    data["work_queue"][0].pop("parent_hypothesis_id", None)
    data["work_queue"][0].pop("correlation_id", None)
    harness.state_path.write_text(json.dumps(data))

    # resume で例外なくロードでき、未知キーを無視して正常起動すること
    resumed = AgentHarness(tmp_path, spec(), resume=True)
    assert not hasattr(resumed.state, "unknown_future_field")
    resumed_item = resumed.state.work_queue[0]
    assert resumed_item.work_id == item.work_id
    assert resumed_item.rejection_reason == ""
    assert resumed_item.evidence_ids == ()


def test_new_contract_fields_redact_secrets_everywhere(tmp_path):
    secret = "secret-token-xyz"
    password = "super-password-123"
    harness = AgentHarness(tmp_path, spec(), secret_values=[secret, password])

    # 1. finish_work の rejection_reason
    item = harness.enqueue(AgentRole.PROBE_SPECIALIST, "http://fixture.test/auth", check_type="sqli")
    harness.next_work()
    harness.finish_work(
        item.work_id,
        WorkStatus.REJECTED,
        summary=f"failed with {password}",
        rejection_reason=f"blocked auth {secret}",
        evidence_ids=[f"ev-{secret}"],
    )

    # 2. record_llm_call の error
    harness.record_llm_call(
        episode_id="ep-1",
        error=f"call failed token={secret}",
    )

    # 3. record_probe_attempt の target_url と payload
    harness.record_probe_attempt(
        target_url=f"http://fixture.test/api?token={secret}",
        payload=f"admin' AND password='{password}'",
    )

    # 4. record_verification の rejection_reason
    harness.note_hypotheses([{"candidate_id": "cand-sec", "url": "http://fixture.test"}])
    harness.record_verification(
        "cand-sec",
        reproduced=False,
        rejection_reason=f"auth leak check {secret}",
    )

    # すべてのアーティファクトで秘密値が平文で保存されていないことを検証
    all_content = (
        (tmp_path / "agent_state.json").read_text()
        + (tmp_path / "llm_calls.jsonl").read_text()
        + (tmp_path / "probe_attempts.jsonl").read_text()
        + (tmp_path / "verification_results.jsonl").read_text()
    )
    assert secret not in all_content
    assert password not in all_content
    assert "<redacted>" in all_content


def test_resume_from_finalized_checkpoint_resets_phase_and_allows_continuation(tmp_path):
    # 終了処理済み (finalize 済み) の checkpoint から resume しても phase がリセットされ再開できる
    harness = AgentHarness(tmp_path, spec(max_steps=10))
    w = harness.enqueue(AgentRole.EXPLORER, "http://fixture.test")
    harness.next_work()
    harness.set_phase(AgentPhase.EXECUTING)
    harness.finish_work(w.work_id, WorkStatus.COMPLETE)
    harness.enqueue(AgentRole.PROBE_SPECIALIST, "http://fixture.test/search", check_type="xss")
    harness.finalize(success=False, coverage_complete=False)

    state_before = json.loads(harness.state_path.read_text())
    assert state_before["phase"] == "finalizing"

    resumed = AgentHarness(tmp_path, spec(max_steps=10), resume=True)
    assert resumed.state.phase == AgentPhase.INITIALIZING
    assert resumed.state.status == AgentRunStatus.RUNNING

    # 再開後の set_phase が正常に成功すること
    resumed.set_phase(AgentPhase.EXECUTING)
    assert resumed.state.phase == AgentPhase.EXECUTING


def test_resume_from_interrupted_executing_checkpoint_resets_phase(tmp_path):
    # 実行中 (EXECUTING) で中断された checkpoint から再開した場合に初期化状態へ戻る
    harness = AgentHarness(tmp_path, spec(max_steps=10))
    w = harness.enqueue(AgentRole.PROBE_SPECIALIST, "http://fixture.test/items", check_type="sqli")
    harness.next_work()
    harness.set_phase(AgentPhase.EXECUTING)
    # 中断保存 (RUNNING のまま checkpoint)
    harness.checkpoint()

    state_before = json.loads(harness.state_path.read_text())
    assert state_before["phase"] == "executing"

    resumed = AgentHarness(tmp_path, spec(max_steps=10), resume=True)
    assert resumed.state.phase == AgentPhase.INITIALIZING
    # 中断されていた work item が PLANNED に戻ること
    assert resumed.state.work_queue[0].status == WorkStatus.PLANNED

    # 再認証への遷移や直接実行への遷移が正常に成功すること
    resumed.set_phase(AgentPhase.AUTHENTICATING)
    assert resumed.state.phase == AgentPhase.AUTHENTICATING


def test_resume_from_budget_exhausted_checkpoint(tmp_path):
    # 1. 予算残ゼロの checkpoint からの resume は拒否される
    harness = AgentHarness(tmp_path, spec(max_steps=2))
    harness.record_step(
        episode_id="ep-1", local_step=2, url="http://fixture.test",
        proposed_actions=[], executed_actions=[],
    )
    harness.finalize(success=False, coverage_complete=False)
    with pytest.raises(ValueError, match="no remaining step budget"):
        AgentHarness(tmp_path, spec(max_steps=2), resume=True)

    # 2. 予算残があり stop_reason で finalize された checkpoint からは stop_reason と phase がクリアされて再開できる
    harness2 = AgentHarness(tmp_path / "sub", spec(max_steps=10))
    harness2.record_step(
        episode_id="ep-1", local_step=2, url="http://fixture.test",
        proposed_actions=[], executed_actions=[],
    )
    harness2.finalize(success=False, coverage_complete=False)
    assert harness2.state.stop_reason == "agent_incomplete"
    assert harness2.state.phase == AgentPhase.FINALIZING

    resumed = AgentHarness(tmp_path / "sub", spec(max_steps=10), resume=True)
    assert resumed.state.stop_reason == ""
    assert resumed.state.phase == AgentPhase.INITIALIZING
    assert resumed.remaining_steps == 8


def test_resume_from_legacy_checkpoint_without_phase_field(tmp_path):
    # phase キーが存在しない古い checkpoint を模倣
    harness = AgentHarness(tmp_path, spec(max_steps=5))
    data = json.loads(harness.state_path.read_text())
    data.pop("phase", None)
    harness.state_path.write_text(json.dumps(data))

    resumed = AgentHarness(tmp_path, spec(max_steps=5), resume=True)
    assert resumed.state.phase == AgentPhase.INITIALIZING
    resumed.set_phase(AgentPhase.RECONNING)
    assert resumed.state.phase == AgentPhase.RECONNING


def test_phase_transitions_allow_dynamic_replan_and_reject_invalid(tmp_path):
    harness = AgentHarness(tmp_path, spec())

    # EXECUTING から再認証 (AUTHENTICATING) や再探索 (RECONNING) へのリプラン遷移が可能
    harness.set_phase(AgentPhase.EXECUTING)
    harness.set_phase(AgentPhase.AUTHENTICATING)
    assert harness.state.phase == AgentPhase.AUTHENTICATING
    harness.set_phase(AgentPhase.RECONNING)
    assert harness.state.phase == AgentPhase.RECONNING
    harness.set_phase(AgentPhase.EXECUTING)
    assert harness.state.phase == AgentPhase.EXECUTING
    harness.set_phase(AgentPhase.RECONNING)
    assert harness.state.phase == AgentPhase.RECONNING

    # 通常実行中の INITIALIZING への逆行は拒否
    with pytest.raises(ValueError, match="Invalid phase transition"):
        harness.set_phase(AgentPhase.INITIALIZING)
