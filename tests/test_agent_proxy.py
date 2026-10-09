import asyncio
import http.server
import os
import select
import shutil
import socket
import socketserver
import ssl
import subprocess
import sys
import threading
import time
import types
from types import SimpleNamespace
from urllib.parse import urlsplit
from unittest.mock import patch

import pytest

from wscan.agent_engine import AgentEngine
from wscan.llm_agent_browser import AgentBrowserScanner


@pytest.mark.skipif(os.getenv("WSCAN_E2E") != "1", reason="WSCAN_E2E=1 でbrowser-useのloopback proxy回帰を実行")
def test_browser_use_agent_proxy_routes_http_https_and_fails_closed(tmp_path, monkeypatch):
    """Exercise the real profile helper and installed SDK against loopback-only fixtures."""
    monkeypatch.setenv("ANONYMIZED_TELEMETRY", "false")
    monkeypatch.setenv("BROWSER_USE_CLOUD_SYNC", "false")
    monkeypatch.setenv("BROWSER_USE_VERSION_CHECK", "false")
    monkeypatch.setenv("BROWSER_USE_DISABLE_EXTENSIONS", "1")
    monkeypatch.setenv("BROWSER_USE_CONFIG_DIR", str(tmp_path / "browser-use"))
    browser_use = pytest.importorskip("browser_use", reason="browser-use optional dependency is not installed")
    profile_module = pytest.importorskip("browser_use.browser.profile")
    browser_session = getattr(browser_use, "BrowserSession", None)
    if browser_session is None:
        pytest.skip("installed browser-use does not expose BrowserSession")

    class TargetHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            target_events.append((self.server.scheme, f"127.0.0.1:{self.server.server_port}", self.path))
            body = b"loopback proxy fixture"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *_args):
            pass

    class ThreadedHTTPServer(http.server.ThreadingHTTPServer):
        daemon_threads = True

    class ProxyHandler(socketserver.BaseRequestHandler):
        def _deny(self):
            self.request.sendall(b"HTTP/1.1 502 Fixture Denied\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")

        def handle(self):
            data = b""
            self.request.settimeout(3)
            try:
                while b"\r\n\r\n" not in data and len(data) < 65536:
                    chunk = self.request.recv(4096)
                    if not chunk:
                        return
                    data += chunk
            except OSError:
                return
            pieces = data.split(b"\r\n", 1)[0].decode("latin1", "replace").split()
            if len(pieces) < 2:
                return
            method, destination = pieces[:2]
            connect = method.upper() == "CONNECT"
            parsed = urlsplit(destination) if not connect else None
            authority = destination if connect else parsed.netloc
            path = "" if connect else parsed.path + (("?" + parsed.query) if parsed.query else "")
            expected = (
                ("CONNECT", https_authority, https_authority, "") if connect else
                ("GET", f"http://{http_authority}/agent-http?via=fixture", http_authority, "/agent-http?via=fixture")
            )
            received = (method.upper(), destination, authority, path)
            proxy_events.append(received)
            if received != expected or not authority.startswith("127.0.0.1:"):
                self._deny()
                return
            host, port = authority.rsplit(":", 1)
            try:
                upstream = socket.create_connection((host, int(port)), timeout=2)
            except OSError:
                self._deny()
                return
            forwarded_events.append(received)
            if connect:
                self.request.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
                sockets = [self.request, upstream]
                try:
                    while True:
                        readable, _, _ = select.select(sockets, [], [], 1)
                        for current in readable:
                            chunk = current.recv(65536)
                            if not chunk:
                                return
                            (upstream if current is self.request else self.request).sendall(chunk)
                except OSError:
                    return
                finally:
                    upstream.close()
            else:
                remainder = data.split(b"\r\n", 1)[1]
                upstream.sendall(f"{method} {path} {pieces[2]}\r\n".encode() + remainder)
                try:
                    while chunk := upstream.recv(65536):
                        self.request.sendall(chunk)
                except OSError:
                    pass
                finally:
                    upstream.close()

    class ThreadedTCPServer(socketserver.ThreadingTCPServer):
        allow_reuse_address = True
        daemon_threads = True

    def serve(server):
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        return thread

    target_events = []
    proxy_events = []
    forwarded_events = []
    http_server = ThreadedHTTPServer(("127.0.0.1", 0), TargetHandler)
    http_server.scheme = "http"
    https_server = ThreadedHTTPServer(("127.0.0.1", 0), TargetHandler)
    https_server.scheme = "https"
    cert, key = tmp_path / "fixture-cert.pem", tmp_path / "fixture-key.pem"
    openssl = shutil.which("openssl")
    if not openssl:
        pytest.skip("openssl is required to create the local self-signed target certificate")
    subprocess.run(
        [openssl, "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", str(key),
         "-out", str(cert), "-days", "1", "-subj", "/CN=127.0.0.1",
         "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, capture_output=True,
    )
    tls = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    tls.load_cert_chain(cert, key)
    https_server.socket = tls.wrap_socket(https_server.socket, server_side=True)
    http_authority = f"127.0.0.1:{http_server.server_port}"
    https_authority = f"127.0.0.1:{https_server.server_port}"
    proxy_server = ThreadedTCPServer(("127.0.0.1", 0), ProxyHandler)
    proxy_url = f"http://127.0.0.1:{proxy_server.server_address[1]}"
    servers = (http_server, https_server, proxy_server)
    for server in servers:
        serve(server)

    async def navigate(session, url):
        page = await session.must_get_current_page()
        await page.goto(url)
        deadline = time.monotonic() + 5
        current_url = ""
        while time.monotonic() < deadline:
            current_url = await page.get_url()
            if current_url == url:
                return current_url
            await asyncio.sleep(0.05)
        return current_url

    async def exercise():
        scanner = AgentBrowserScanner(f"http://{http_authority}/agent-http?via=fixture", proxy=proxy_url)
        profile = scanner._build_browser_profile(profile_module.BrowserProfile)
        profile.enable_default_extensions = False
        profile.use_cloud = False
        profile.args = list(profile.args or []) + [
            "--disable-background-networking", "--disable-component-update", "--disable-sync",
            "--ignore-certificate-errors",
        ]
        session = browser_session(browser_profile=profile, is_local=True)
        before = len(target_events)
        try:
            await session.start()
            http_url = f"http://{http_authority}/agent-http?via=fixture"
            assert await navigate(session, http_url) == http_url, {
                "proxy_events": proxy_events, "forwarded_events": forwarded_events, "target_events": target_events,
            }
            https_url = f"https://{https_authority}/agent-https?via=fixture"
            assert await navigate(session, https_url) == https_url
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline and len(target_events) < before + 2:
                await asyncio.sleep(0.05)
        finally:
            await asyncio.wait_for(session.kill(), timeout=10)

        assert ("GET", f"http://{http_authority}/agent-http?via=fixture", http_authority, "/agent-http?via=fixture") in forwarded_events
        assert ("CONNECT", https_authority, https_authority, "") in forwarded_events
        assert ("http", http_authority, "/agent-http?via=fixture") in target_events[before:]
        assert ("https", https_authority, "/agent-https?via=fixture") in target_events[before:]

        dead_proxy = AgentBrowserScanner(http_url, proxy="http://127.0.0.1:1")
        dead_profile = dead_proxy._build_browser_profile(profile_module.BrowserProfile)
        dead_profile.enable_default_extensions = False
        dead_profile.use_cloud = False
        dead_profile.args = list(dead_profile.args or []) + ["--disable-background-networking", "--disable-sync"]
        dead_session = browser_session(browser_profile=dead_profile, is_local=True)
        target_count = len(target_events)
        failure_text = ""
        try:
            await dead_session.start()
            page = await dead_session.must_get_current_page()
            try:
                await asyncio.wait_for(page.goto(http_url), timeout=8)
            except Exception as exc:
                failure_text = str(exc)
            try:
                failure_text += " " + await page.evaluate("() => document.body ? document.body.innerText : ''")
            except Exception:
                pass
        finally:
            await asyncio.wait_for(dead_session.kill(), timeout=10)
        assert len(target_events) - target_count == 0
        assert "ERR_PROXY_CONNECTION_FAILED" in failure_text or "chrome-error://" in failure_text

    try:
        asyncio.run(exercise())
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


def _proxy_sdk_modules():
    browser_use = types.ModuleType("browser_use")
    browser_use.__path__ = []
    browser = types.ModuleType("browser_use.browser")
    browser.__path__ = []
    profile = types.ModuleType("browser_use.browser.profile")

    class ProxySettings:
        def __init__(self, *, server, bypass=None):
            self.server = server
            self.bypass = bypass

    profile.ProxySettings = ProxySettings
    return {
        "browser_use": browser_use,
        "browser_use.browser": browser,
        "browser_use.browser.profile": profile,
    }


def test_agent_browser_profile_receives_normalized_proxy_without_sdk_global_config():
    scanner = AgentBrowserScanner("http://fixture.test", proxy="127.0.0.1:8080")
    captured = {}

    class Profile:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    with patch.dict(sys.modules, _proxy_sdk_modules()):
        scanner._build_browser_profile(Profile)

    assert captured["proxy"].server == "http://127.0.0.1:8080"
    assert captured["proxy"].bypass == "<-loopback>"


def test_proxy_profile_rejects_sdk_without_proxy_support():
    scanner = AgentBrowserScanner("http://fixture.test", proxy="http://127.0.0.1:8080")

    class LegacyProfile:
        def __init__(self, *, headless, disable_security, allowed_domains, storage_state):
            pass

    with patch.dict(sys.modules, _proxy_sdk_modules()):
        with pytest.raises(RuntimeError, match="proxy を browser-use profile"):
            scanner._build_browser_profile(LegacyProfile)


def test_agent_browser_profile_keeps_no_proxy_default():
    scanner = AgentBrowserScanner("http://fixture.test")
    captured = {}

    class Profile:
        def __init__(self, **kwargs):
            captured.update(kwargs)

    scanner._build_browser_profile(Profile)

    assert "proxy" not in captured


def test_agent_engine_run_forwards_proxy_to_scanner(tmp_path):
    captured = {}

    class Scanner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def run(self):
            return SimpleNamespace(error="fixture stop", findings=[], preserve_existing_artifacts=True)

    engine = AgentEngine(
        "http://fixture.test", proxy="127.0.0.1:8080", output_dir=str(tmp_path)
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", Scanner):
        result = asyncio.run(engine.run())

    assert result.error == "fixture stop"
    assert captured["proxy"] == "http://127.0.0.1:8080"


@pytest.mark.asyncio
async def test_agent_engine_recon_forwards_proxy_to_scanner(tmp_path):
    captured = {}

    class Scanner:
        def __init__(self, **kwargs):
            captured.update(kwargs)

        async def run(self):
            return SimpleNamespace(error="fixture stop")

    engine = AgentEngine(
        "http://fixture.test", proxy="http://127.0.0.1:8080", output_dir=str(tmp_path)
    )
    with patch("wscan.llm_agent_browser.AgentBrowserScanner", Scanner):
        with pytest.raises(RuntimeError, match="Agent recon failed"):
            await engine.run_recon()

    assert captured["proxy"] == "http://127.0.0.1:8080"
