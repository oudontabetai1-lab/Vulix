"""設定済み資格情報の値が checkpoint.json / evidence.json に平文で残らない（通常層）。

resume は redaction 済みの finding を復元するため、マーカーを実値として再送しないことも守る。
"""
import asyncio
import json

import pytest

from wscan import checkpoint as cp
from wscan import url_scope
from wscan.engine import ScanEngine
from wscan.scanners.base import Finding

USER, PW = "alice.admin@example.test", "Zx9-very-secret"
TRICKY = 'q"u\\ote-pass9'  # JSON エスケープが要る値でも出力 JSON を壊さない


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    eng = ScanEngine(
        "http://127.0.0.1:1", output_dir=str(tmp_path / "out"), auth_user=USER, auth_pass=PW,
        headers={"X-Api-Key": "apikey-value-123"},
    )
    url_scope.register_secret_values([("tricky", TRICKY)])
    yield eng
    url_scope.clear_secret_values()


def _login_finding(**kw) -> Finding:
    base = dict(
        check_type="sqli", severity="high", url="http://t.test/login", field_name="username",
        payload="' OR 1=1 --", evidence="login bypass",
        request={"method": "POST", "url": f"http://t.test/login?next=/a&u={USER}",
                 "headers": {"X-Api-Key": "apikey-value-123"},
                 "post_data": f"username=%27+OR+1%3D1&password={PW}&u={USER}&t={TRICKY}"},
        response={"status": 200}, injection_location="form",
    )
    base.update(kw)
    return Finding(**base)


def _blob(path) -> str:
    return "".join(p.read_text() for p in path.rglob("*.json"))


def test_checkpoint_json_has_no_configured_secret(engine, tmp_path):
    engine.all_findings.append(_login_finding())
    engine._init_checkpoint()
    assert engine._save_checkpoint()
    text = (tmp_path / "out" / "checkpoint.json").read_text()
    for secret in (USER, PW, "apikey-value-123", TRICKY, json.dumps(TRICKY)[1:-1]):
        assert secret not in text
    data = json.loads(text)  # 伏せても JSON は壊れない
    req = data["findings"][0]["request"]
    assert "[REDACTED:auth_password]" in req["post_data"]
    assert data["findings"][0]["payload"] == "' OR 1=1 --"  # スキャンペイロードは伏せない


def test_evidence_json_has_no_configured_secret(engine, tmp_path):
    engine.all_findings.append(_login_finding())
    engine._save_evidence()
    text = (tmp_path / "out" / "evidence.json").read_text()
    for secret in (USER, PW, "apikey-value-123", TRICKY):
        assert secret not in text
    json.loads(text)


def test_resume_restores_findings_and_verify_does_not_resend_marker(engine, tmp_path):
    engine.all_findings.append(_login_finding())
    engine._init_checkpoint()
    engine._save_checkpoint()
    state = cp.load_checkpoint(tmp_path / "out")
    restored = Finding.from_dict(state.findings[0])
    assert "[REDACTED:auth_password]" in restored.request["post_data"]
    # form 注入は provenance（url/field/index）から再構築する＝post_data は再送しない → 検証対象のまま
    assert not engine._finding_has_unsendable_redaction(restored)
    # provenance を持たず request を再送する検証（privesc_action 等）はマーカー入りだと再送不能
    action = _login_finding(check_type="privesc_action", injection_location="",
                            request={"url": "http://t.test/act", "method": "POST",
                                     "body": {"password": "[REDACTED:auth_password]"}})
    assert engine._finding_has_unsendable_redaction(action)
    assert asyncio.run(engine._verify_one(action)) == "assumed"
    # url にマーカーが入った finding は、どの注入経路でも別 URL を叩いてしまうため再送不能
    assert engine._finding_has_unsendable_redaction(
        _login_finding(url="http://t.test/x?k=[REDACTED:auth_password]"))
    # 無関係な [REDACTED:len=N]（トークン寿命の別マーカー）は対象外
    assert not engine._finding_has_unsendable_redaction(
        _login_finding(injection_location="", request={"body": "[REDACTED:len=12]"}))
