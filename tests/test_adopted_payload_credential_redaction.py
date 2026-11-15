"""Tests for credential redaction in LLM-generated / adopted session payloads.

Verifies:
1. Adopted session credentials embedded in payloads are redacted in:
   - RequestLogger (payloads.jsonl)
   - Finding dictionary serialization (evidence.json, checkpoint.json)
   - Checkpoint candidate snapshots
   - Payload learning persistence
2. Preservation of non-secret payloads and identifiers.
3. Bounded replay policy: secret-bearing candidates in checkpoint are not persisted raw,
   not replayed as masked markers, units are not silently marked completed, and units
   are marked for retry/regeneration (or explicit incomplete if regeneration unavailable).
4. In-flight attack bytes remain unchanged during execution.
"""
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from wscan import url_scope
from wscan.checkpoint import CheckpointState, save_checkpoint, load_checkpoint
from wscan.injection_point import InjectionPoint
from wscan.payload_learning import PayloadLearner
from wscan.request_logger import RequestLogger
from wscan.scanners.base import Finding


@pytest.fixture(autouse=True)
def clean_secrets():
    url_scope.clear_secret_values()
    yield
    url_scope.clear_secret_values()


def test_payload_log_redacts_synthetic_session_secret_and_preserves_clean(tmp_path):
    secret = "synthetic-session-token-987"
    url_scope.register_secret_values([("session_token", secret)])

    logger = RequestLogger(tmp_path)
    # Secret-bearing payload
    secret_payload = f"admin' AND token='{secret}' --"
    logger.log_payload("search", secret_payload, "sqli", "http://127.0.0.1:8000/api")

    # Non-secret attack payload
    clean_payload = "' OR 1=1 --"
    logger.log_payload("query", clean_payload, "sqli", "http://127.0.0.1:8000/search")

    lines = [json.loads(line) for line in (tmp_path / "payloads.jsonl").read_text().splitlines() if line.strip()]
    assert len(lines) == 2

    # Secret-bearing payload is masked
    assert secret not in lines[0]["payload"]
    assert "[REDACTED:session_token]" in lines[0]["payload"]
    assert lines[0]["field"] == "search"
    assert lines[0]["check_type"] == "sqli"

    # Non-secret payload is preserved byte-for-byte
    assert lines[1]["payload"] == clean_payload
    assert lines[1]["field"] == "query"


def test_finding_dict_redacts_synthetic_session_secret_and_preserves_clean():
    secret = "synthetic-cookie-val-456"
    url_scope.register_secret_values([("cookie", secret)])

    secret_finding = {
        "check_type": "sqli",
        "url": "http://127.0.0.1:8000/profile",
        "field_name": "id",
        "payload": f"1 UNION SELECT '{secret}'",
        "evidence": f"Reflected {secret}",
    }
    redacted = url_scope.redact_finding_dict(secret_finding)
    assert secret not in redacted["payload"]
    assert "[REDACTED:cookie]" in redacted["payload"]
    assert secret not in redacted["evidence"]
    assert "[REDACTED:cookie]" in redacted["evidence"]
    assert redacted["field_name"] == "id"

    clean_finding = {
        "check_type": "xss",
        "url": "http://127.0.0.1:8000/search",
        "field_name": "q",
        "payload": "<script>alert(1)</script>",
        "evidence": "<script>alert(1)</script>",
    }
    clean_redacted = url_scope.redact_finding_dict(clean_finding)
    assert clean_redacted["payload"] == "<script>alert(1)</script>"
    assert clean_redacted["evidence"] == "<script>alert(1)</script>"


def test_checkpoint_candidate_redaction_and_bounded_replay_policy(tmp_path):
    secret = "synthetic-auth-secret-321"
    url_scope.register_secret_values([("auth_pass", secret)])

    ip_secret = InjectionPoint(location="form", url="http://127.0.0.1:8000/login", parameter_id="user", form_index=0)
    ip_clean = InjectionPoint(location="form", url="http://127.0.0.1:8000/search", parameter_id="q", form_index=0)

    state = CheckpointState(target_url="http://127.0.0.1:8000/login")

    # In-flight attack bytes returned by save_candidate_snapshot_ip must be preserved
    secret_cands = [f"admin' AND pass='{secret}' --", "' OR 1=1 --"]
    returned_cands = state.save_candidate_snapshot_ip(ip_secret, "sqli", "adaptive", secret_cands, "llm")
    assert returned_cands == secret_cands, "in-flight attack candidates must be preserved during execution"

    clean_cands = ["' OR 1=1 --", "' UNION SELECT null --"]
    clean_returned = state.save_candidate_snapshot_ip(ip_clean, "sqli", "baseline", clean_cands, "payload_gen")
    assert clean_returned == clean_cands

    # Mark both done
    state.mark_done_ip(ip_secret, "sqli")
    state.mark_done_ip(ip_secret, "(adaptive:sqli)")
    state.mark_done_ip(ip_clean, "sqli")

    # Save checkpoint
    cp_path = save_checkpoint(tmp_path, state)
    raw_text = cp_path.read_text(encoding="utf-8")

    # 1. Raw secret must not be persisted
    assert secret not in raw_text

    # 2. Secret-bearing unit must NOT be silently marked completed
    loaded_data = json.loads(raw_text)
    secret_key = state._candidate_unit_key(ip_secret, "sqli")
    clean_key = state._candidate_unit_key(ip_clean, "sqli")
    assert secret_key not in loaded_data.get("completed_units", [])
    assert clean_key in loaded_data.get("completed_units", [])

    # 3. Load checkpoint and verify candidate retrieval
    loaded_state = load_checkpoint(cp_path)
    assert loaded_state is not None

    # Secret-bearing unit: must NOT replay masked markers, must signal regeneration required
    found, cands = loaded_state.get_candidate_snapshot_ip(ip_secret, "sqli", "adaptive")
    assert found is False, "secret-bearing candidate snapshot must not be replayed"
    assert cands is None
    assert loaded_state.is_candidate_regeneration_required_ip(ip_secret, "sqli", "adaptive") is True
    assert loaded_state.is_done_ip(ip_secret, "sqli") is False

    # Clean unit: preserved and reusable
    clean_found, clean_c = loaded_state.get_candidate_snapshot_ip(ip_clean, "sqli", "baseline")
    assert clean_found is True
    assert clean_c == clean_cands
    assert loaded_state.is_candidate_regeneration_required_ip(ip_clean, "sqli", "baseline") is False
    assert loaded_state.is_done_ip(ip_clean, "sqli") is True


def test_payload_learning_excludes_secret_bearing_payloads(tmp_path):
    secret = "synthetic-session-token-777"
    url_scope.register_secret_values([("token", secret)])

    learn_path = tmp_path / "payload_learning.json"
    learner = PayloadLearner(learning_file=str(learn_path))

    # Try recording secret-bearing payload
    secret_payload = f"admin' AND token='{secret}' --"
    learner.record("sqli", secret_payload, success=True, domain="http://127.0.0.1:8000")

    # Try recording masked payload
    masked_payload = "admin' AND token='[REDACTED:token]' --"
    learner.record("sqli", masked_payload, success=True, domain="http://127.0.0.1:8000")

    # Record clean payload
    clean_payload = "' OR 1=1 --"
    learner.record("sqli", clean_payload, success=True, domain="http://127.0.0.1:8000")

    # Verify memory store
    stats = learner.stats("sqli", domain="http://127.0.0.1:8000")
    payloads_in_stats = [row["payload"] for row in stats]
    assert secret_payload not in payloads_in_stats
    assert masked_payload not in payloads_in_stats
    assert clean_payload in payloads_in_stats

    # Save to disk
    learner.save()
    file_text = learn_path.read_text(encoding="utf-8")
    assert secret not in file_text
    assert masked_payload not in file_text
    assert clean_payload in file_text


@pytest.mark.asyncio
async def test_adaptive_round_explicit_incomplete_when_regeneration_unavailable(tmp_path, monkeypatch):
    from wscan.engine import ScanEngine

    secret = "synthetic-adaptive-secret-555"
    url_scope.register_secret_values([("token", secret)])

    ip = InjectionPoint(location="form", url="http://127.0.0.1:8000/form", parameter_id="name", form_index=0)
    state = CheckpointState(target_url="http://127.0.0.1:8000/form")
    state.save_candidate_snapshot_ip(ip, "sqli", "adaptive", [f"test-{secret}"], "llm")
    save_checkpoint(tmp_path, state)

    # Resume engine with LLM unavailable
    engine = ScanEngine("http://127.0.0.1:8000/form", output_dir=str(tmp_path), checks=["sqli"])
    engine._resume_dir = tmp_path
    engine.checkpoint = load_checkpoint(tmp_path / "checkpoint.json")
    engine.adaptive_enabled = True
    engine.scanners = {"sqli": None}  # Dummy scanner entry
    engine._adaptive_llm_available = False

    # Run adaptive attack field round
    result = await engine._adaptive_attack_field(
        "http://127.0.0.1:8000/form",
        form_index=0,
        field={"name": "name", "type": "text"},
        is_url_param=False,
        check_names=["sqli"],
        field_plan=None,
    )

    # Unit must NOT be marked done, and wave_errors must record explicit incomplete
    assert not engine._checkpoint_is_done_ip(ip, "(adaptive:sqli)")
    assert any("secret_candidate_regeneration_unavailable:sqli" in err for err in engine.wave_errors)


@pytest.mark.asyncio
async def test_adaptive_round_regenerates_when_llm_available(tmp_path, monkeypatch):
    from unittest.mock import MagicMock
    from wscan.engine import ScanEngine

    secret = "synthetic-adaptive-secret-888"
    url_scope.register_secret_values([("token", secret)])

    ip = InjectionPoint(location="form", url="http://127.0.0.1:8000/form", parameter_id="name", form_index=0)
    state = CheckpointState(target_url="http://127.0.0.1:8000/form")
    state.save_candidate_snapshot_ip(ip, "sqli", "adaptive", [f"test-{secret}"], "llm")
    save_checkpoint(tmp_path, state)

    # Resume engine with LLM available
    engine = ScanEngine("http://127.0.0.1:8000/form", output_dir=str(tmp_path), checks=["sqli"])
    engine._resume_dir = tmp_path
    engine.checkpoint = load_checkpoint(tmp_path / "checkpoint.json")
    engine.adaptive_enabled = True

    mock_scanner = MagicMock()
    mock_scanner.scan_injection_point = AsyncMock(return_value=[])
    engine.scanners = {"sqli": mock_scanner}
    engine._adaptive_llm_available = True

    mock_browser = MagicMock()
    mock_browser.get_page_source = AsyncMock(return_value="<html><form><input name='name'></form></html>")
    engine._browser = mock_browser

    regenerated = ["' OR 'clean_regenerated'='clean_regenerated"]
    engine.adaptive_engine.generate = AsyncMock(return_value=(regenerated, "ok"))

    result = await engine._adaptive_attack_field(
        "http://127.0.0.1:8000/form",
        form_index=0,
        field={"name": "name", "type": "text"},
        is_url_param=False,
        check_names=["sqli"],
        field_plan=None,
    )

    # Regeneration must have been invoked and completed unit marked done
    assert engine.adaptive_engine.generate.called
    assert engine._checkpoint_is_done_ip(ip, "(adaptive:sqli)")
    assert not any("secret_candidate_regeneration_unavailable" in err for err in engine.wave_errors)
