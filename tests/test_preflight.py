import asyncio
import json
import socket
import ssl
import sys
from pathlib import Path

import httpx
import pytest

from wscan.preflight import (
    _http_check, classify_exception, exit_code, proxy_applied, result, run_preflight, write_result,
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
    assert all(report["checks"][-4 + i]["status"] == "not_checked" for i in range(4))
    assert {row["status"] for row in report["checks"] if row["id"] == "scanner:mass_assignment"} == {"warning"}
    write_result(tmp_path, report)
    assert json.loads((Path(tmp_path) / "preflight.json").read_text())["verdict"] == "warning"
