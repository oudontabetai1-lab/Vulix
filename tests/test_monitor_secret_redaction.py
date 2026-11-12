"""設定済み資格情報の値がダッシュボードのライブイベント/履歴/API に平文で出ない（通常層）。"""
import asyncio
import json

import pytest
from fastapi.testclient import TestClient

from wscan import url_scope
from wscan.engine import ScanEngine
from wscan.monitor import MonitorServer
from wscan.scanners.base import Finding

USER, PW = "alice.admin@example.test", "Zx9-very-secret"
SECRETS = (USER, PW, "cookie-value-777")


class _Client:
    def __init__(self):
        self.sent = []

    async def send_text(self, text):
        self.sent.append(text)


@pytest.fixture
def secrets():
    url_scope.clear_secret_values()
    url_scope.register_secret_values([("auth_user", USER), ("auth_password", PW), ("cookie", "cookie-value-777")])
    yield
    url_scope.clear_secret_values()


def _leaked(text: str) -> list[str]:
    return [s for s in SECRETS if s in text]


def _emit_all(mon: MonitorServer):
    async def go():
        await mon.emit_payload_test("password", f"x{PW}", "sqli", f"http://t.test/login?u={USER}&p={PW}")
        await mon.emit_request({"method": "POST", "url": f"http://t.test/login?u={USER}",
                                "headers": {"Cookie": "sid=cookie-value-777"}, "post_data": f"password={PW}"})
        await mon.emit_response({"status": 200, "body_snippet": f"hello {USER}"})
        await mon.emit_status(f"login as {USER} failed")
        await mon.emit_scan_gap("http://t.test/a?token=" + PW, "transport_error", f"{USER} {PW}")
        await mon.emit_finding({"check_type": "sqli", "url": f"http://t.test/l?u={USER}", "payload": "' OR 1=1",
                                "evidence": f"saw {PW}", "request": {"post_data": f"password={PW}"}})
    asyncio.run(go())


def test_events_reach_history_and_clients_without_secrets(secrets):
    mon = MonitorServer()
    client = _Client()
    mon.clients.add(client)
    _emit_all(mon)
    assert mon.event_history and client.sent
    assert _leaked(json.dumps(list(mon.event_history))) == []
    assert _leaked("".join(client.sent)) == []
    # 派生状態（scan_gaps・api_findings・status）も同じ入口で伏せる
    assert _leaked(json.dumps([mon._scan_gaps, mon.api_findings, mon._scan_status_message])) == []
    # 形は保つ: JSON として読め、識別子（payload・URL の path）は不変
    ev = [json.loads(t) for t in client.sent]
    pt = next(e for e in ev if e["type"] == "payload_test")["data"]
    assert pt["check_type"] == "sqli" and pt["url"].startswith("http://t.test/login?")
    assert "[REDACTED:auth_password]" in pt["payload"]
    fnd = next(e for e in ev if e["type"] == "finding")["data"]
    assert fnd["payload"] == "' OR 1=1"


def test_binary_payloads_are_not_touched(secrets):
    mon = MonitorServer()
    img = "iVBOR" + "A" * 50000
    asyncio.run(mon.emit_screenshot(img, "label"))
    asyncio.run(mon.emit("page_graph_update", {"url": "http://t.test/", "screenshot_b64": img}))
    asyncio.run(mon.broadcast_ephemeral("manual_crawl_frame", {"data": img}))
    assert [e["data"].get("image") or e["data"].get("screenshot_b64") for e in mon.event_history] == [img, img]


def test_no_secrets_registered_is_passthrough():
    url_scope.clear_secret_values()
    mon = MonitorServer()
    data = {"message": PW}
    asyncio.run(mon.emit("status", data))
    assert mon.event_history[-1]["data"] == data


def test_stored_scan_findings_api_serves_redacted_evidence(secrets, tmp_path, monkeypatch):
    """終了済みスキャンの findings API は evidence.json を返す。ディスク側が伏せ済みならレスポンスにも出ない。"""
    import wscan.monitor as m
    monkeypatch.setattr(m, "OUTPUT_BASE", tmp_path)
    monkeypatch.setenv("WSCAN_STATE_DIR", str(tmp_path / "state"))
    eng = ScanEngine("http://127.0.0.1:1", output_dir=str(tmp_path / "20261112-000000"),
                     auth_user=USER, auth_pass=PW, cookies="sid=cookie-value-777")
    eng.all_findings.append(Finding(
        check_type="sqli", severity="high", url="http://t.test/login", field_name="username",
        payload="' OR 1=1 --", evidence=f"login bypass {PW}",
        request={"method": "POST", "url": f"http://t.test/login?u={USER}", "post_data": f"password={PW}"},
        response={"status": 200}, injection_location="form"))
    eng._save_evidence()
    res = TestClient(MonitorServer().app).get("/api/v1/scans/20261112-000000/findings")
    assert res.status_code == 200 and res.json()["findings"]
    assert _leaked(res.text) == []
