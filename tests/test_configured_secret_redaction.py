"""設定済み資格情報の値ベース redaction（キー名に依らず永続化出力から伏せる）。"""
import json

import pytest

from wscan import url_scope
from wscan.engine import ScanEngine
from wscan.request_logger import RequestLogger, redact_text, redact_url

USER, PW = "alice.admin@example.test", "Zx9-very-secret"


@pytest.fixture
def engine(tmp_path, monkeypatch):
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    eng = ScanEngine(
        "http://127.0.0.1:1", output_dir=str(tmp_path / "out"), auth_user=USER, auth_pass=PW,
        accounts=[{"username": "bob-the-user", "password": "bob-pass-1234", "role": "user"},
                  {"username": "ab", "password": "x", "role": "user"}],
        cookies="sid=cookie-value-777; short=1", headers={"Authorization": "Bearer tok-abcdef"},
    )
    yield eng
    url_scope.clear_secret_values()


def test_page_js_json_body_username_is_redacted_everywhere(engine, tmp_path):
    rl = engine.request_logger
    req = {"method": "POST", "url": f"http://t.test/api?u={USER}&x=1",
           "headers": {"X-Who": USER, "Content-Type": "application/json"},
           "post_data": json.dumps({"username": USER, "note": f"hi {PW}", "q": "bob-the-user"})}
    rl.log_http({"request": req, "response": {"status": 200, "headers": {"X-Echo": "bob-pass-1234"}}})
    rl.log_payload("q", "' OR 1=1 --", "sqli", f"http://t.test/?u={USER}")
    blob = "".join(p.read_text() for p in (tmp_path / "out").rglob("*.jsonl"))
    for secret in (USER, PW, "bob-the-user", "bob-pass-1234", "cookie-value-777", "tok-abcdef"):
        assert secret not in blob
    assert "[REDACTED:auth_user]" in blob and "[REDACTED:account0_user]" in blob
    assert "' OR 1=1 --" in blob  # スキャンペイロードは伏せない


def test_encoded_forms_and_short_values(engine):
    assert redact_text("username=alice.admin%40example.test") == "username=[REDACTED:auth_user]"
    assert "[REDACTED:auth_user]" in redact_url(f"http://t.test/u/{USER}/profile")
    assert redact_text('{"n": "ab", "v": "x"}') == '{"n": "ab", "v": "x"}'  # 4 文字未満は対象外
    assert any("redaction_skipped_short_secret" in e for e in engine.wave_errors)
