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


def _engine(tmp_path, monkeypatch, user, pw):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    return ScanEngine("http://127.0.0.1:1", output_dir=str(tmp_path / "out"), auth_user=user, auth_pass=pw)


def test_common_username_does_not_rewrite_identifiers(tmp_path, monkeypatch):
    """auth_user='admin' でも /admin/ の unit key・finding.url(path)・field_name は不変（resume 一致）。"""
    eng = _engine(tmp_path, monkeypatch, "admin", "Zx9-very-secret")
    try:
        url = "http://t.test/admin/x?who=admin&p=1"
        eng.all_findings.append(_login_finding(
            url=url, field_name="admin_note",
            request={"method": "POST", "url": url, "post_data": "username=admin&p=1"}))
        eng._init_checkpoint()
        eng.checkpoint.mark_done("http://t.test/admin/x", "admin_note", 0, "sqli")
        assert eng._save_checkpoint()
        state = cp.load_checkpoint(tmp_path / "out")
        assert state.is_done("http://t.test/admin/x", "admin_note", 0, "sqli")  # (a) キー一致
        fd = state.findings[0]
        assert fd["url"] == "http://t.test/admin/x?who=[REDACTED:auth_user]&p=1"  # path 不変・query 値のみ
        assert fd["field_name"] == "admin_note" and fd["check_type"] == "sqli"
        assert fd["request"]["post_data"] == "username=[REDACTED:auth_user]&p=1"
        assert fd["request"]["url"] == fd["url"]
        # path 側の admin は伏せ字にならないので、form 注入の再検証は妨げられない
        restored = Finding.from_dict(fd)
        assert ScanEngine._finding_has_unsendable_redaction(restored) is True  # query に伏せ字＝再送不能
        restored.url = "http://t.test/admin/x"
        assert ScanEngine._finding_has_unsendable_redaction(restored) is False
    finally:
        url_scope.clear_secret_values()


@pytest.mark.parametrize("pw", ["true", "null", "1234"])
def test_json_literal_like_password_keeps_checkpoint_loadable(tmp_path, monkeypatch, pw):
    eng = _engine(tmp_path, monkeypatch, "alice-admin", pw)
    try:
        eng.all_findings.append(_login_finding(
            request={"post_data": f"password={pw}", "body": {"password": pw, "remember": True, "n": None}}))
        eng._init_checkpoint()
        assert eng._save_checkpoint()
        state = cp.load_checkpoint(tmp_path / "out")  # (b) 読める
        assert state is not None and len(state.findings) == 1
        req = state.findings[0]["request"]
        assert req["post_data"] == "password=[REDACTED:auth_password]"  # (c) 値は伏せる
        assert req["body"] == {"password": "[REDACTED:auth_password]", "remember": True, "n": None}
    finally:
        url_scope.clear_secret_values()


def test_marker_gate_is_label_agnostic_and_covers_evidence_details():
    """再開側で資格情報が未設定（登録 0 件）でも、保存済みの伏せ字は再送しない。"""
    url_scope.clear_secret_values()
    ws = _login_finding(check_type="websocket", injection_location="", request={},
                        evidence_details={"ws_url": "ws://t.test/ws?token=[REDACTED:header:Authorization]"})
    assert ScanEngine._finding_has_unsendable_redaction(ws)
    other = _login_finding(url="http://t.test/x?k=[REDACTED:account3_password]")
    assert ScanEngine._finding_has_unsendable_redaction(other)
    assert not ScanEngine._finding_has_unsendable_redaction(
        _login_finding(injection_location="", request={"body": "[REDACTED:len=12]"}))
