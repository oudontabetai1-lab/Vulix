"""End-to-end loopback tests for Runtime Scope Guard HTTP redirect enforcement."""
from __future__ import annotations

import asyncio
import http.server
import socket
import threading
from typing import Generator
import pytest
import httpx

from wscan.engine import ScanEngine
from wscan.runtime_scope_guard import OutOfScopeUrlError


@pytest.fixture(autouse=True)
def scratch_scan_output(tmp_path, monkeypatch):
    """Keep scan artifacts in the test scratch directory."""
    monkeypatch.setattr("wscan.engine.OUTPUT_BASE", tmp_path / "output")


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class LoopbackFixtureServer:
    def __init__(self, port: int, handler_cls):
        self.port = port
        self.httpd = http.server.HTTPServer(("127.0.0.1", port), handler_cls)
        self.thread = threading.Thread(target=self.httpd.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def stop(self):
        self.httpd.shutdown()
        self.httpd.server_close()


@pytest.mark.asyncio
async def test_redirect_to_out_of_scope_loopback_egress_blocked():
    port_a = _find_free_port()
    port_b = _find_free_port()

    server_a_requests: list[str] = []
    server_b_requests: list[str] = []

    class TargetServerHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_a_requests.append(self.path)
            if self.path == "/redirect-out":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_b}/leak?token=secret123")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"target ok")

        def log_message(self, format, *args):
            pass

    class ExternalServerHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_b_requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"external ok")

        def log_message(self, format, *args):
            pass

    srv_a = LoopbackFixtureServer(port_a, TargetServerHandler)
    srv_b = LoopbackFixtureServer(port_b, ExternalServerHandler)
    srv_a.start()
    srv_b.start()

    try:
        engine = ScanEngine(f"http://127.0.0.1:{port_a}")
        client_kwargs = engine.httpx_client_kwargs(follow_redirects=True)

        with pytest.raises(OutOfScopeUrlError) as exc_info:
            async with httpx.AsyncClient(**client_kwargs) as client:
                await client.get(f"http://127.0.0.1:{port_a}/redirect-out")

        assert exc_info.value.reason == "out_of_scope_destination"
        assert f"http://127.0.0.1:{port_b}/leak?token=secret123" in str(exc_info.value)

        # Invariant: Target server received the first hop
        assert len(server_a_requests) == 1
        assert server_a_requests[0] == "/redirect-out"

        # Critical invariant: Out-of-scope external server received ZERO requests!
        assert len(server_b_requests) == 0

        # Audit trail recorded in wave_errors
        blocked_notes = [
            err for err in engine.wave_errors if err.startswith("scope_guard_blocked:")
        ]
        assert len(blocked_notes) == 1
        assert f"http://127.0.0.1:{port_b}/leak?token=<redacted>" in blocked_notes[0]

    finally:
        srv_a.stop()
        srv_b.stop()


@pytest.mark.asyncio
async def test_safe_in_scope_and_relative_redirects_succeed():
    port_a = _find_free_port()
    requests_log: list[str] = []

    class SafeServerHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            requests_log.append(self.path)
            if self.path == "/rel-redir":
                self.send_response(302)
                self.send_header("Location", "/final-destination")
                self.end_headers()
            elif self.path == "/abs-redir":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_a}/final-destination")
                self.end_headers()
            elif self.path == "/final-destination":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"arrived successfully")
            else:
                self.send_response(404)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    srv = LoopbackFixtureServer(port_a, SafeServerHandler)
    srv.start()

    try:
        engine = ScanEngine(f"http://127.0.0.1:{port_a}")
        client_kwargs = engine.httpx_client_kwargs(follow_redirects=True)

        async with httpx.AsyncClient(**client_kwargs) as client:
            resp_rel = await client.get(f"http://127.0.0.1:{port_a}/rel-redir")
            assert resp_rel.status_code == 200
            assert resp_rel.text == "arrived successfully"

            resp_abs = await client.get(f"http://127.0.0.1:{port_a}/abs-redir")
            assert resp_abs.status_code == 200
            assert resp_abs.text == "arrived successfully"

        assert requests_log == [
            "/rel-redir",
            "/final-destination",
            "/abs-redir",
            "/final-destination",
        ]

    finally:
        srv.stop()


@pytest.mark.asyncio
async def test_protocol_relative_redirect_blocked():
    port_a = _find_free_port()
    port_b = _find_free_port()

    server_b_requests: list[str] = []

    class TargetProtoHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/proto-redir":
                self.send_response(302)
                self.send_header("Location", f"//127.0.0.1:{port_b}/proto-leak")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    class ExternalProtoHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_b_requests.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    srv_a = LoopbackFixtureServer(port_a, TargetProtoHandler)
    srv_b = LoopbackFixtureServer(port_b, ExternalProtoHandler)
    srv_a.start()
    srv_b.start()

    try:
        engine = ScanEngine(f"http://127.0.0.1:{port_a}")
        client_kwargs = engine.httpx_client_kwargs(follow_redirects=True)

        with pytest.raises(OutOfScopeUrlError) as exc_info:
            async with httpx.AsyncClient(**client_kwargs) as client:
                await client.get(f"http://127.0.0.1:{port_a}/proto-redir")

        assert exc_info.value.reason == "out_of_scope_destination"
        assert len(server_b_requests) == 0

    finally:
        srv_a.stop()
        srv_b.stop()


@pytest.mark.asyncio
async def test_access_urls_and_exclude_urls_handling():
    port_a = _find_free_port()
    port_c = _find_free_port()

    server_a_requests: list[str] = []
    server_c_requests: list[str] = []

    class MultiServerA(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_a_requests.append(self.path)
            if self.path == "/redir-access":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_c}/allowed-docs")
                self.end_headers()
            elif self.path == "/redir-exclude":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_a}/admin/logout")
                self.end_headers()
            elif self.path == "/admin/logout":
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"logged out")
            else:
                self.send_response(200)
                self.end_headers()

        def log_message(self, format, *args):
            pass

    class PartnerServerC(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_c_requests.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"partner docs ok")

        def log_message(self, format, *args):
            pass

    srv_a = LoopbackFixtureServer(port_a, MultiServerA)
    srv_c = LoopbackFixtureServer(port_c, PartnerServerC)
    srv_a.start()
    srv_c.start()

    try:
        engine = ScanEngine(
            f"http://127.0.0.1:{port_a}",
            access_urls=[f"http://127.0.0.1:{port_c}"],
            exclude_urls=["/admin/logout"],
        )
        client_kwargs = engine.httpx_client_kwargs(follow_redirects=True)

        # 1. Access URLs redirect is permitted
        async with httpx.AsyncClient(**client_kwargs) as client:
            resp = await client.get(f"http://127.0.0.1:{port_a}/redir-access")
            assert resp.status_code == 200
            assert resp.text == "partner docs ok"
            assert len(server_c_requests) == 1

        # 2. Exclude URLs redirect is blocked pre-send
        with pytest.raises(OutOfScopeUrlError) as exc_info:
            async with httpx.AsyncClient(**client_kwargs) as client:
                await client.get(f"http://127.0.0.1:{port_a}/redir-exclude")

        assert exc_info.value.reason == "excluded_url"
        assert "/admin/logout" not in server_a_requests

    finally:
        srv_a.stop()
        srv_c.stop()


@pytest.mark.asyncio
async def test_out_of_scope_error_propagates_to_incomplete_unit_and_not_marked_checkpoint_done():
    """Prove that OutOfScopeUrlError is not silently swallowed and leaves the unit incomplete in checkpoint."""
    from wscan.injection_point import InjectionPoint

    port_a = _find_free_port()
    port_b = _find_free_port()

    server_b_requests: list[str] = []

    class TargetRedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", 0))
            if length:
                self.rfile.read(length)
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port_b}/leak-data")
            self.end_headers()

        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port_b}/leak-data")
            self.end_headers()

        def log_message(self, format, *args):
            pass

    class ExternalReceiverHandler(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            server_b_requests.append(self.path)
            self.send_response(200)
            self.end_headers()

        def do_GET(self):
            server_b_requests.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, format, *args):
            pass

    srv_a = LoopbackFixtureServer(port_a, TargetRedirectHandler)
    srv_b = LoopbackFixtureServer(port_b, ExternalReceiverHandler)
    srv_a.start()
    srv_b.start()

    try:
        engine = ScanEngine(f"http://127.0.0.1:{port_a}", checks=["nosql", "host_header"])
        engine.enable_checkpoint = True

        # Counterexample 1: Field scanner (nosql_injection)
        test_url = f"http://127.0.0.1:{port_a}/api/login"
        field = {"name": "username", "type": "text"}
        ip = InjectionPoint.for_form(test_url, "username", 0)

        # Counterexample 1: Field scanner (nosql_injection via _test_json_body)
        nosql_scanner = engine.scanners["nosql"]
        with pytest.raises(OutOfScopeUrlError):
            await nosql_scanner._test_json_body(test_url, "username", 0)

        # Invariant 1: External server B received ZERO requests
        assert len(server_b_requests) == 0

        # Invariant 2: Audit trail recorded in wave_errors
        assert any(err.startswith("scope_guard_blocked:") for err in engine.wave_errors)

        # Invariant 3: Unit MUST NOT be marked done in checkpoint!
        assert engine._checkpoint_is_done_ip(ip, "nosql") is False

        # Invariant 4: ScanEngine._scan_field propagates OutOfScopeUrlError to status="error" and unit remains incomplete
        from unittest.mock import AsyncMock, MagicMock
        mock_scanner = MagicMock()
        mock_scanner.requires_state_profile_preflight = None
        mock_scanner.may_scan_injection_point = None
        mock_scanner._field_budget_gate = None
        mock_scanner.scan_injection_point = AsyncMock(side_effect=OutOfScopeUrlError(
            f"Blocked destination: http://127.0.0.1:{port_b}/leak-data (out_of_scope_destination)",
            url=f"http://127.0.0.1:{port_b}/leak-data",
            reason="out_of_scope_destination",
        ))
        engine.scanners["nosql"] = mock_scanner

        await engine._scan_field(test_url, 0, field, is_url_param=False)
        assert engine._checkpoint_is_done_ip(ip, "nosql") is False
        nosql_rows = [r for r in getattr(engine, "scan_matrix", []) if r.get("check") == "nosql" or r.get("check_name") == "nosql"]
        assert len(nosql_rows) == 1
        assert nosql_rows[0]["status"] == "error"
        assert "OutOfScopeUrlError" in nosql_rows[0]["note"] or "out_of_scope_destination" in nosql_rows[0]["note"]

        # Counterexample 2: Page scanner (host_header)
        page_url = f"http://127.0.0.1:{port_a}/profile"
        hh_scanner = engine.scanners["host_header"]
        with pytest.raises(OutOfScopeUrlError):
            await hh_scanner.scan_page(page_url)

        # Verify page checkpoint is NOT marked done
        assert engine._checkpoint_is_done(page_url, "(page)", 0, "host_header") is False

    finally:
        srv_a.stop()
        srv_b.stop()



@pytest.mark.asyncio
async def test_real_httpx_field_scanner_probe_failure_keeps_checkpoint_incomplete():
    """Real NoSQL JSON-body scanner must record blocked redirect as incomplete.

    Uses only loopback origins: allowed A redirects to excluded B for the probe;
    a separate allowed relative redirect is the positive transport control.
    """
    from wscan.injection_point import InjectionPoint

    port_a, port_b = _find_free_port(), _find_free_port()
    seen_b: list[str] = []
    class A(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length", 0)))
            self.send_response(302)
            self.send_header("Location", f"http://127.0.0.1:{port_b}/blocked")
            self.end_headers()
        def do_GET(self):
            self.send_response(302 if self.path == "/control" else 200)
            if self.path == "/control": self.send_header("Location", "/ok")
            self.end_headers()
            self.wfile.write(b"ok")
        def log_message(self, *args): pass
    class B(http.server.BaseHTTPRequestHandler):
        def do_POST(self):
            seen_b.append(self.path); self.send_response(200); self.end_headers()
        def log_message(self, *args): pass
    a, b = LoopbackFixtureServer(port_a, A), LoopbackFixtureServer(port_b, B)
    a.start(); b.start()
    try:
        base = f"http://127.0.0.1:{port_a}"
        engine = ScanEngine(base, checks=["nosql"])
        engine.target_urls = [base]
        engine.exclude_urls = [f"http://127.0.0.1:{port_b}"]
        engine.enable_checkpoint = True
        control = engine.httpx_client_kwargs(follow_redirects=True)
        async with httpx.AsyncClient(**control) as client:
            assert (await client.get(base + "/control")).text == "ok"
        ip = InjectionPoint.for_json_body("POST", base + "/api", "/username", template_id="probe")
        engine.injection_templates["probe"] = {"url": ip.url, "method": "POST", "json_body": {"username": "seed"}}
        from wscan.scanners import SCANNERS
        engine.scanners["nosql"] = SCANNERS["nosql"](engine)
        engine.json_injection_points = [ip]
        await engine._run_json_injection_checks()
        assert seen_b == []
        assert engine._checkpoint_is_done_ip(ip, "nosql") is False
        assert any(row.get("status") == "error" for row in engine.scan_matrix), engine.scan_matrix
    finally:
        a.stop(); b.stop()


@pytest.mark.asyncio
async def test_real_httpx_apply_payload_scan_field_keeps_checkpoint_incomplete():
    """Real SQLi scanner exercising _apply_payload in _scan_field must leave checkpoint incomplete."""
    from wscan.engine import _store_synced_token
    from wscan.injection_point import InjectionPoint
    from wscan.scanners import SCANNERS

    port_a, port_b = _find_free_port(), _find_free_port()
    seen_b: list[str] = []

    class A(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path.startswith("/control"):
                self.send_response(302)
                self.send_header("Location", "/ok")
                self.end_headers()
            elif self.path.startswith("/ok"):
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")
            else:
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{port_b}/leak")
                self.end_headers()

        def log_message(self, *args):
            pass

    class B(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen_b.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b"intercepted")

        def log_message(self, *args):
            pass

    srv_a = LoopbackFixtureServer(port_a, A)
    srv_b = LoopbackFixtureServer(port_b, B)
    srv_a.start()
    srv_b.start()

    try:
        base = f"http://127.0.0.1:{port_a}"
        engine = ScanEngine(base, checks=["sqli"])
        engine.target_urls = [base]
        engine.exclude_urls = [f"http://127.0.0.1:{port_b}"]
        engine.enable_checkpoint = True

        # Positive transport control: in-scope relative redirect works
        control = engine.httpx_client_kwargs(follow_redirects=True)
        async with httpx.AsyncClient(**control) as client:
            resp = await client.get(base + "/control")
            assert resp.text == "ok"

        url = f"{base}/api/search"
        engine._spa_harvested_urls.add(url)
        _store_synced_token(engine, base, {"Authorization": "Bearer test-token"})

        sqli_scanner = SCANNERS["sqli"](engine)
        engine.scanners["sqli"] = sqli_scanner
        ip = InjectionPoint.for_url_param(url, "q", source="spa")

        # 1. Direct _apply_payload call swallows transport error and records failure context
        body, pair = await sqli_scanner._apply_payload(url, 0, "q", "' OR '1'='1", True)
        assert body == ""
        assert pair == {}
        assert seen_b == []

        # 2. Real _scan_field call without any mocked scanner exception
        field = {"name": "q", "type": "text"}
        await engine._scan_field(url, 0, field, is_url_param=True)

        # Invariant 1: External server B received ZERO requests
        assert seen_b == []

        # Invariant 2: Checkpoint unit remains uncompleted
        assert engine._checkpoint_is_done_ip(ip, "sqli") is False
        if engine.checkpoint is not None:
            unit_key = engine.checkpoint.unit_key(ip.url, ip.parameter_id, "sqli", "url_param")
            assert unit_key not in engine.checkpoint.done_units

        # Invariant 3: Scan matrix records error with probe incomplete note
        sqli_rows = [r for r in getattr(engine, "scan_matrix", []) if r.get("check") == "sqli"]
        assert len(sqli_rows) >= 1
        assert any(r.get("status") == "error" and "transport_error" in r.get("note", "") for r in sqli_rows)
    finally:
        srv_a.stop()
        srv_b.stop()


@pytest.mark.asyncio
async def test_blocked_redirect_with_userinfo_redacts_credentials_in_logs_and_ledger():
    """Destination userinfo must be stripped before recording in wave_errors or ledger."""
    port_a = _find_free_port()
    port_b = _find_free_port()

    server_b_requests: list[str] = []

    class TargetServerHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/auth-redirect":
                self.send_response(302)
                self.send_header(
                    "Location",
                    f"http://victim_user:super_secret_password@127.0.0.1:{port_b}/private?api_token=very_sensitive_token&other=safe",
                )
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()

        def log_message(self, *args):
            pass

    class ExternalServerHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            server_b_requests.append(self.path)
            self.send_response(200)
            self.end_headers()

        def log_message(self, *args):
            pass

    srv_a = LoopbackFixtureServer(port_a, TargetServerHandler)
    srv_b = LoopbackFixtureServer(port_b, ExternalServerHandler)
    srv_a.start()
    srv_b.start()

    try:
        engine = ScanEngine(f"http://127.0.0.1:{port_a}")
        client_kwargs = engine.httpx_client_kwargs(follow_redirects=True)

        with pytest.raises(OutOfScopeUrlError):
            async with httpx.AsyncClient(**client_kwargs) as client:
                await client.get(f"http://127.0.0.1:{port_a}/auth-redirect")

        assert len(server_b_requests) == 0

        # Invariant 1: Plaintext secret password and userinfo NEVER appear in wave_errors
        assert not any("super_secret_password" in err for err in engine.wave_errors)
        assert not any("victim_user" in err for err in engine.wave_errors)
        assert not any("very_sensitive_token" in err for err in engine.wave_errors)

        # Invariant 2: Userinfo is cleanly dropped from the recorded URL in wave_errors
        blocked_notes = [
            err for err in engine.wave_errors if err.startswith("scope_guard_blocked:")
        ]
        assert len(blocked_notes) == 1
        expected_dest = f"http://127.0.0.1:{port_b}/private?api_token=<redacted>&other=safe"
        assert f":{expected_dest}:out_of_scope_destination" in blocked_notes[0]

        # Invariant 3: Ledger manifest gap note (if logger initialized) also has no credentials
        if getattr(engine, "request_logger", None):
            ledger = getattr(engine.request_logger, "probe_ledger", None)
            if ledger is not None:
                gaps = getattr(ledger.manifest, "gaps", [])
                assert not any("super_secret_password" in g for g in gaps)
                assert not any("victim_user" in g for g in gaps)
    finally:
        srv_a.stop()
        srv_b.stop()
