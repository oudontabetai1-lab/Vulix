import asyncio
import json
import socket
import ssl
import sys
from pathlib import Path

import httpx
import pytest

from wscan.preflight import (
    _http_check, _probe_login_page, classify_exception, evaluate_auth_readiness,
    evaluate_live_channel_readiness, exit_code, is_login_url_in_scope, parse_accounts,
    proxy_applied, result, run_preflight, write_result,
)


def test_transport_exception_classification():
    assert classify_exception(socket.gaierror())[0] == "dns_failure"
    assert classify_exception(httpx.ConnectTimeout("timeout"))[0] == "timeout"
    assert classify_exception(httpx.ProxyError("proxy"))[0] == "proxy_error"
    assert classify_exception(ssl.SSLError("bad cert"))[0] == "tls_certificate_error"
    assert classify_exception(httpx.ConnectError("connection refused"))[0] == "connection_refused"


def test_httpx_proxy_is_applied_and_credentials_are_redacted(monkeypatch):
    from types import SimpleNamespace

    class ProxyTransport(httpx.MockTransport):
        def __init__(self, handler):
            super().__init__(handler)
            self._pool = SimpleNamespace(_proxy_url=httpx.URL("http://proxy.example:8080"))

    class Client:
        def __init__(self, **_kwargs):
            self.transport = ProxyTransport(lambda request: httpx.Response(200))
            self._mounts = {httpx._utils.URLPattern("all://"): self.transport}
        def __enter__(self): return self
        def __exit__(self, *_): self.transport.close()
        def get(self, url): return self.transport.handle_request(httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "Client", Client)
    proxy = "http://user:secret@proxy.example:8080"
    rows = _http_check("http://target.example", proxy, False)
    assert rows[2]["reason_code"] == "proxy_applied"
    assert "secret" not in json.dumps(rows)


def test_configured_proxy_without_selected_proxy_transport_fails(monkeypatch):
    class Client:
        def __init__(self, **_kwargs):
            self.transport = httpx.MockTransport(lambda request: httpx.Response(200))
            self._mounts = {}
        def __enter__(self): return self
        def __exit__(self, *_): self.transport.close()
        def get(self, url): return self.transport.handle_request(httpx.Request("GET", url))

    monkeypatch.setattr(httpx, "Client", Client)
    rows = _http_check("http://target.example", "http://proxy.example:8080", False)
    assert rows[2]["status"] == "fail"
    assert rows[2]["reason_code"] == "proxy_not_applied"


def test_http_status_is_warning_and_hard_failure_is_not_success():
    class Client:
        def __init__(self, **_): pass
        def __enter__(self): return self
        def __exit__(self, *_): pass
        def get(self, _url): return httpx.Response(503)

    import wscan.preflight as preflight
    original = httpx.Client
    try:
        httpx.Client = Client
        assert preflight._http_check("http://target.example", "", False)[0]["reason_code"] == "http_error_status"
    finally:
        httpx.Client = original
    assert exit_code(result([{"status": "fail"}])) == 1
    assert exit_code(result([{"status": "warning"}])) == 0


def test_cli_hard_failure_stops_before_scan(monkeypatch, tmp_path):
    import main
    import wscan.preflight as preflight

    monkeypatch.setattr(sys, "argv", ["main.py", "scan", "http://unit.test", "--preflight-only",
                                       "--output", str(tmp_path)])
    async def failed(*_, **__):
        return {"verdict": "fail", "checks": []}

    monkeypatch.setattr(preflight, "run_preflight", failed)
    with pytest.raises(SystemExit, match="1"):
        asyncio.run(main.run_scan(main.parse_args()))


def test_run_reports_unimplemented_checks_and_saves_output(monkeypatch, tmp_path):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))])
    monkeypatch.setattr("wscan.preflight._http_check", lambda *_: (
        {"id": "reachability_direct", "status": "pass", "reason_code": "reachable", "detail": "ok"},
        {"id": "proxy_reachability", "status": "not_applicable", "reason_code": "proxy_not_configured", "detail": "none"},
        {"id": "proxy_applied", "status": "not_applicable", "reason_code": "proxy_not_configured", "detail": "none"},
    ))

    class Browser:
        async def close(self): pass

    class Chromium:
        async def launch(self, **_): return Browser()

    class Playwright:
        chromium = Chromium()
        async def __aenter__(self): return self
        async def __aexit__(self, *_): pass
        def __await__(self):
            async def ready(): return self
            return ready().__await__()

    import sys
    from types import ModuleType
    module = ModuleType("playwright.async_api")
    module.async_playwright = Playwright
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)
    report = asyncio.run(run_preflight("http://target.example", output_dir=tmp_path,
                                       checks=["mass_assignment"], proxy="", verify_tls=False))
    checks_by_id = {row["id"]: row for row in report["checks"]}
    assert checks_by_id["authentication"]["status"] == "not_applicable"
    assert checks_by_id["websocket"]["status"] == "pass"
    assert checks_by_id["oob"]["status"] == "not_applicable"
    assert checks_by_id["agent_transport"]["status"] in ("pass", "warning")
    assert {row["status"] for row in report["checks"] if row["id"] == "scanner:mass_assignment"} == {"warning"}
    write_result(tmp_path, report)
    assert json.loads((Path(tmp_path) / "preflight.json").read_text())["verdict"] == "warning"


def _mock_preflight_deps(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda *_: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", 80))])
    monkeypatch.setattr("wscan.preflight._http_check", lambda *_: (
        {"id": "reachability_direct", "status": "pass", "reason_code": "reachable", "detail": "ok"},
        {"id": "proxy_reachability", "status": "not_applicable", "reason_code": "proxy_not_configured", "detail": "none"},
        {"id": "proxy_applied", "status": "not_applicable", "reason_code": "proxy_not_configured", "detail": "none"},
    ))

    class Browser:
        async def close(self): pass

    class Chromium:
        async def launch(self, **_): return Browser()

    class Playwright:
        chromium = Chromium()
        async def __aenter__(self): return self
        async def __aexit__(self, *_): pass
        def __await__(self):
            async def ready(): return self
            return ready().__await__()

    from types import ModuleType
    module = ModuleType("playwright.async_api")
    module.async_playwright = Playwright
    monkeypatch.setitem(sys.modules, "playwright.async_api", module)


def test_preflight_oob_check(monkeypatch, tmp_path):
    _mock_preflight_deps(monkeypatch)

    report_configured = asyncio.run(run_preflight(
        "http://target.example", output_dir=tmp_path, checks=[], oob_configured=True
    ))
    oob_row = next(r for r in report_configured["checks"] if r["id"] == "oob")
    assert oob_row["status"] == "pass"
    assert oob_row["reason_code"] == "configured"
    assert "out-of-band email sink is configured" in oob_row["detail"]

    report_unconfigured = asyncio.run(run_preflight(
        "http://target.example", output_dir=tmp_path, checks=[], oob_configured=False
    ))
    oob_row_unconf = next(r for r in report_unconfigured["checks"] if r["id"] == "oob")
    assert oob_row_unconf["status"] == "not_applicable"
    assert oob_row_unconf["reason_code"] == "oob_not_configured"
    assert "No out-of-band sink configured" in oob_row_unconf["detail"]


def test_preflight_agent_transport_check(monkeypatch, tmp_path):
    _mock_preflight_deps(monkeypatch)

    monkeypatch.setitem(sys.modules, "browser_use", None)

    report_agent_mode = asyncio.run(run_preflight(
        "http://target.example", output_dir=tmp_path, checks=[], agent_mode=True
    ))
    agent_row = next(r for r in report_agent_mode["checks"] if r["id"] == "agent_transport")
    assert agent_row["status"] == "fail"
    assert agent_row["reason_code"] == "dependency_missing"
    assert "Agent mode is selected but its browser automation backend is not installed." in agent_row["detail"]

    report_no_agent_mode = asyncio.run(run_preflight(
        "http://target.example", output_dir=tmp_path, checks=[], agent_mode=False
    ))
    agent_row_no_agent = next(r for r in report_no_agent_mode["checks"] if r["id"] == "agent_transport")
    assert agent_row_no_agent["status"] == "warning"
    assert agent_row_no_agent["reason_code"] == "dependency_missing"
    assert "only needed for agent mode" in agent_row_no_agent["detail"]

    from types import ModuleType
    monkeypatch.setitem(sys.modules, "browser_use", ModuleType("browser_use"))
    report_available = asyncio.run(run_preflight(
        "http://target.example", output_dir=tmp_path, checks=[]
    ))
    agent_row_avail = next(r for r in report_available["checks"] if r["id"] == "agent_transport")
    assert agent_row_avail["status"] == "pass"
    assert agent_row_avail["reason_code"] == "available"
    assert "backend is importable" in agent_row_avail["detail"]


def test_login_url_in_scope():
    assert is_login_url_in_scope("https://target.example/app", "/login") is True
    assert is_login_url_in_scope("https://target.example/app", "https://target.example/login") is True
    assert is_login_url_in_scope("http://target.example:8080/app", "http://target.example:8080/auth/login") is True
    assert is_login_url_in_scope("https://target.example/app", "https://evil.example/login") is False
    assert is_login_url_in_scope("https://target.example/app", "https://auth.example/login",
                                 scope_urls=["https://auth.example/"]) is True
    assert is_login_url_in_scope("https://target.example/app", "") is False
    assert is_login_url_in_scope("https://target.example/app", "javascript:void(0)") is False
    assert is_login_url_in_scope("https://target.example/app", "ftp://target.example/login") is False


def test_parse_accounts_and_secret_redaction(tmp_path):
    sentinel_pass = "SENTINEL_NEVER_LEAK_SECRET_PASS_999"

    # From list of dicts
    accounts_list = [
        {"username": "admin", "password": sentinel_pass, "role": "admin"},
        {"user": "tester", "password": "other_pass"},
    ]
    parsed = parse_accounts(accounts_list)
    assert len(parsed) == 2
    assert parsed[0] == {"username": "admin"}
    assert parsed[1] == {"username": "tester"}
    assert sentinel_pass not in json.dumps(parsed)

    # From string format
    accounts_str = f"alice:{sentinel_pass},bob:pass2"
    parsed_str = parse_accounts(accounts_str)
    assert len(parsed_str) == 2
    assert parsed_str[0] == {"username": "alice"}
    assert parsed_str[1] == {"username": "bob"}
    assert sentinel_pass not in json.dumps(parsed_str)

    # Fallback to auth_user
    parsed_single = parse_accounts(None, auth_user="single_user", auth_pass=sentinel_pass)
    assert len(parsed_single) == 1
    assert parsed_single[0] == {"username": "single_user"}
    assert sentinel_pass not in json.dumps(parsed_single)

    # From accounts file
    af = tmp_path / "accounts.yaml"
    af.write_text(f"accounts:\n  - username: file_user\n    password: {sentinel_pass}\n", encoding="utf-8")
    parsed_file = parse_accounts(None, accounts_file=str(af))
    assert len(parsed_file) == 1
    assert parsed_file[0] == {"username": "file_user"}
    assert sentinel_pass not in json.dumps(parsed_file)


def test_auth_readiness_not_applicable():
    res = evaluate_auth_readiness("https://target.example")
    assert res["id"] == "authentication"
    assert res["status"] == "not_applicable"
    assert res["reason_code"] == "auth_not_configured"


def test_auth_readiness_missing_login_url():
    res = evaluate_auth_readiness(
        "https://target.example",
        login_url="",
        auth_user="admin",
        auth_pass="pass123",
    )
    assert res["id"] == "authentication"
    assert res["status"] == "fail"
    assert res["reason_code"] == "login_url_missing"


def test_auth_readiness_partial_missing_accounts():
    res = evaluate_auth_readiness(
        "https://target.example",
        login_url="/login",
        accounts=[],
        auth_user="",
    )
    assert res["id"] == "authentication"
    assert res["status"] == "fail"
    assert res["reason_code"] == "account_missing"


def test_auth_readiness_partial_out_of_scope():
    res = evaluate_auth_readiness(
        "https://target.example",
        login_url="https://external-domain.example/login",
        auth_user="admin",
        auth_pass="pass123",
    )
    assert res["id"] == "authentication"
    assert res["status"] == "fail"
    assert res["reason_code"] == "login_url_out_of_scope"


def test_auth_readiness_partial_empty_selectors():
    res = evaluate_auth_readiness(
        "https://target.example",
        login_url="/login",
        auth_user="admin",
        auth_pass="pass123",
        login_user_field="   ",
    )
    assert res["id"] == "authentication"
    assert res["status"] == "fail"
    assert res["reason_code"] == "required_fields_missing"


def test_auth_readiness_partial_probe_failure():
    # Transport error
    res_transport = evaluate_auth_readiness(
        "https://target.example",
        login_url="/login",
        auth_user="admin",
        auth_pass="pass123",
        probe_error=("connection_refused", "Connection refused"),
    )
    assert res_transport["status"] == "fail"
    assert res_transport["reason_code"] == "login_page_unreachable"

    # HTTP error status
    res_http = evaluate_auth_readiness(
        "https://target.example",
        login_url="/login",
        auth_user="admin",
        auth_pass="pass123",
        probe_status_code=500,
    )
    assert res_http["status"] == "fail"
    assert res_http["reason_code"] == "login_page_http_error"


def test_auth_readiness_configured_pass_and_explicit_non_verification():
    res = evaluate_auth_readiness(
        "https://target.example",
        login_url="/login",
        auth_user="admin",
        auth_pass="pass123",
        probe_status_code=200,
        probe_html="<form action='/login' method='post'><input name='username'/><input type='password' name='password'/><button type='submit'>Login</button></form>",
    )
    assert res["id"] == "authentication"
    assert res["status"] == "pass"
    assert res["reason_code"] == "configured"
    # Status is pass for configuration completeness, but explicitly does NOT claim login succeeded
    assert "Preflight does not verify credentials or login success" in res["detail"]
    assert "no credentials submitted" in res["detail"]
    assert "login form detected" in res["detail"]


def test_auth_readiness_secret_non_leak_sentinel():
    sentinel = "EXTREMELY_SECRET_AUTHENTICATION_PASSWORD_XYZ987"
    res = evaluate_auth_readiness(
        "https://target.example",
        login_url="/login",
        auth_user="admin",
        auth_pass=sentinel,
        accounts=[{"username": "user1", "password": sentinel}],
        probe_status_code=200,
    )
    serialized = json.dumps(res)
    assert sentinel not in serialized


def test_auth_readiness_session_token_configured():
    res_cookie = evaluate_auth_readiness(
        "https://target.example",
        cookie="session_id=abc123xyz",
    )
    assert res_cookie["status"] == "pass"
    assert res_cookie["reason_code"] == "session_token_configured"
    assert "Actual session validity is not verified by preflight" in res_cookie["detail"]


def test_live_channel_readiness():
    res_enabled = evaluate_live_channel_readiness(monitor_enabled=True)
    assert res_enabled["id"] == "websocket"
    assert res_enabled["status"] == "pass"
    assert res_enabled["reason_code"] == "available"

    res_disabled = evaluate_live_channel_readiness(monitor_enabled=False)
    assert res_disabled["id"] == "websocket"
    assert res_disabled["status"] == "not_applicable"
    assert res_disabled["reason_code"] == "monitor_disabled"


def test_run_preflight_auth_and_websocket_integration(monkeypatch, tmp_path):
    _mock_preflight_deps(monkeypatch)
    sentinel = "SUPER_SECRET_PREFLIGHT_SENTINEL_456"

    # Mock probe login page to return reachable 200
    monkeypatch.setattr(
        "wscan.preflight._probe_login_page",
        lambda url, proxy, verify: (200, "<html><form><input name='username'/></form></html>", None)
    )

    report = asyncio.run(run_preflight(
        "http://target.example",
        output_dir=tmp_path,
        checks=["privesc"],
        login_url="/login",
        auth_user="admin",
        auth_pass=sentinel,
        accounts=[{"username": "admin", "password": sentinel}, {"username": "user2", "password": sentinel}],
        monitor_enabled=True,
    ))
    checks_by_id = {row["id"]: row for row in report["checks"]}
    assert checks_by_id["authentication"]["status"] == "pass"
    assert checks_by_id["authentication"]["reason_code"] == "configured"
    assert checks_by_id["websocket"]["status"] == "pass"
    assert checks_by_id["websocket"]["reason_code"] == "available"

    # Scanner prerequisite for AUTH_SESSION and MULTI_ACCOUNT should pass
    scanner_rows = [r for r in report["checks"] if r["id"] == "scanner:privesc"]
    assert all(r["status"] == "pass" for r in scanner_rows)

    # Sentinel password must NEVER leak in preflight report
    assert sentinel not in json.dumps(report)


def test_run_preflight_no_monitor_integration(monkeypatch, tmp_path):
    _mock_preflight_deps(monkeypatch)

    report = asyncio.run(run_preflight(
        "http://target.example",
        output_dir=tmp_path,
        checks=[],
        monitor_enabled=False,
    ))
    ws_row = next(r for r in report["checks"] if r["id"] == "websocket")
    assert ws_row["status"] == "not_applicable"
    assert ws_row["reason_code"] == "monitor_disabled"
