"""ダッシュボード → engine の往復（URL・識別子）が資格情報値の伏せ字で壊れない回帰テスト（admin/password 環境）。"""
import asyncio, json
import pytest
from wscan import url_scope
from wscan.engine import ScanEngine
from wscan.monitor import MonitorServer
from wscan.attack_planner import PageAttackPlan, FieldAttackPlan

@pytest.fixture
def sec():
    url_scope.clear_secret_values()
    # DVWA-like defaults: admin/password
    url_scope.register_secret_values([("auth_user", "admin"), ("auth_password", "password")])
    yield
    url_scope.clear_secret_values()

class C:
    def __init__(self): self.sent=[]
    async def send_text(self, t): self.sent.append(t)

def _events(mon, typ):
    return [e for e in mon.event_history if e["type"] == typ]

def _ui_confirm(plans_event):
    """templates/dashboard.html confirmPlan() と同じ構築: edits[card.dataset.url][row.dataset.field]"""
    edits = {}
    for page in plans_event["plans"]:
        edits[page["url"]] = {}
        for fp in page["fields"]:
            edits[page["url"]][fp["name"]] = {"risk_score": fp["risk_score"], "priority_checks": fp["priority_checks"],
                                               "custom_payloads": fp["custom_payloads"], "skip": True}
    return edits

def _plans(url, fname, cp=None):
    return {url: PageAttackPlan(url=url, page_purpose="p", planned_by="heuristic",
            fields=[FieldAttackPlan(name=fname, form_index=0, is_url_param=True, risk_score=7,
                                    priority_checks=["sqli"], rationale="r", custom_payloads=cp or {})])}

def _roundtrip(plans):
    mon = MonitorServer()
    ev = ScanEngine.__new__(ScanEngine)
    data = ScanEngine._serialize_plans(ev, plans)
    asyncio.run(mon.emit_plan_review(data))
    shown = _events(mon, "plan_review")[0]["data"]
    edits = _ui_confirm(shown)
    ScanEngine._apply_plan_edits(ev, plans, edits)
    return plans, shown

def test_plan_url_path_has_username_ok(sec):
    plans, _ = _roundtrip(_plans("http://t.test/admin/panel?id=1", "id"))
    assert plans["http://t.test/admin/panel?id=1"].fields[0].risk_score == 0

def test_plan_url_query_value_is_username(sec):
    u = "http://t.test/profile.php?user=admin"
    plans, shown = _roundtrip(_plans(u, "user"))
    print("SHOWN URL:", shown["plans"][0]["url"])
    assert plans[u].fields[0].risk_score == 0, "skip edit lost: URL query value redacted -> plans.get(url) miss"

def test_plan_field_name_equals_password_value(sec):
    u = "http://t.test/login.php"
    plans, shown = _roundtrip(_plans(u, "password"))
    print("SHOWN FIELD:", shown["plans"][0]["fields"][0]["name"])
    assert plans[u].fields[0].risk_score == 0, "skip edit lost: field name 'password' redacted"

def test_plan_custom_payload_with_secret(sec):
    u = "http://t.test/x"
    plans, shown = _roundtrip(_plans(u, "q", {"sqli": ["' OR user='admin'--"]}))
    print("CP back:", plans[u].fields[0].custom_payloads)
    assert plans[u].fields[0].custom_payloads == {"sqli": ["' OR user='admin'--"]}

def test_site_map_parent_vs_url(sec):
    mon = MonitorServer()
    asyncio.run(mon.emit_page_graph_update("http://t.test/admin/panel", parent="", depth=0))
    asyncio.run(mon.emit_page_graph_update("http://t.test/admin/panel/users", parent="http://t.test/admin/panel", depth=1))
    nodes = {e["data"]["url"]: e["data"] for e in _events(mon, "page_graph_update")}
    child = nodes["http://t.test/admin/panel/users"]
    print("parent:", child["parent"], "| node keys:", list(nodes))
    assert child["parent"] in nodes, "UI _smModel: all[p] lookup fails"

def test_crawl_review_form_action_and_fields(sec):
    mon = MonitorServer()
    pages = [{"url": "http://t.test/admin/login", "form_details": [{"action": "http://t.test/admin/login", "method": "post",
             "fields": [{"name": "password", "type": "password"}]}], "param_names": ["user"]}]
    asyncio.run(mon.emit_crawl_review(pages))
    p = _events(mon, "crawl_review")[0]["data"]["pages"][0]
    print(p)
    assert p["form_details"][0]["fields"][0]["name"] == "password"
    assert p["form_details"][0]["action"] == p["url"]

def test_finding_update_matches_and_gaps(sec):
    mon = MonitorServer()
    f = {"url": "http://t.test/p?user=admin", "field_name": "user", "check_type": "sqli", "evidence_type": "e",
         "payload": "' or 'admin'='admin", "verification_state": "assumed"}
    asyncio.run(mon.emit_finding(dict(f)))
    asyncio.run(mon.emit_finding_update({**f, "verification_state": "verified"}))
    assert len(mon.api_findings) == 1 and mon.api_findings[0]["verification_state"] == "verified"
    asyncio.run(mon.emit_url_start("http://t.test/p?user=admin", 1))
    asyncio.run(mon.emit_finding(dict(f, payload="z")))
    assert list(mon._scan_url_statuses.values()) == ["vuln"]

def test_pending_interactive_and_state_snapshot_leak(sec):
    mon = MonitorServer()
    ev = ScanEngine.__new__(ScanEngine)
    plans = _plans("http://t.test/x?token=password", "q", {"sqli": ["password"]})
    asyncio.run(mon.emit_plan_review(ScanEngine._serialize_plans(ev, plans)))
    asyncio.run(mon.emit_crawl_review([{"url": "http://t.test/?a=password"}]))
    txt = json.dumps(mon.pending_interactive)
    print("PENDING:", txt[:300])
    assert "password" not in txt.replace("[REDACTED:auth_password]", "")

def test_api_target_leak(sec):
    mon = MonitorServer()
    asyncio.run(mon.emit_scan_config("http://admin:password@t.test/?k=password", ["sqli"], 1, 1, 1))
    from fastapi.testclient import TestClient
    t = TestClient(mon.app).get("/api/v1/scan/status").text
    print("STATUS:", t[:200])
    assert "password" not in t.replace("[REDACTED:auth_password]", "")


def test_audit_detail_is_redacted(sec, tmp_path, monkeypatch):
    import wscan.monitor as m
    monkeypatch.setattr(m, "OUTPUT_BASE", tmp_path)
    MonitorServer()._audit("scan_start", "127.0.0.1", "http://admin:password@t.test/?k=password")
    assert "password" not in (tmp_path / "management_audit.jsonl").read_text().replace("[REDACTED:auth_password]", "")


def test_plan_edits_apply_to_every_url_with_same_shown_form(sec):
    a, b = "http://t.test/p?u=admin", "http://t.test/p?u=password"
    plans = {**_plans(a, "q"), **_plans(b, "q")}
    # 伏せ後は別 URL（auth_user / auth_password）だが、伏せ後 URL からの引き直しは各々の元 URL に当たる
    _, _ = _roundtrip(plans)
    assert all(p.fields[0].risk_score == 0 for p in plans.values())


def test_url_prefixed_sentence_is_masked_as_free_text(sec):
    mon = MonitorServer()
    asyncio.run(mon.emit_status("http://t.test/ login as admin failed"))
    assert "admin" not in json.dumps(_events(mon, "status")).replace("[REDACTED:auth_user]", "")
