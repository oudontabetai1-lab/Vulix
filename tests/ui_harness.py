"""Reusable isolated serve/browser test harness for UI v3 verification.

Provides:
- An isolated environment for running `main.py serve --no-open-browser`
- Clean teardown and process management (graceful SIGTERM with timeout and SIGKILL fallback)
- Chromium gating with explicit pytest.skip on missing browser or failed probe
- Deterministic non-secret baseline fixtures for Portal, Monitor, and Setup
- Responsive screenshot capture at 1440/1280/768 with PIL-free PNG IHDR dimension parsing
- Robust layout and console error assertion helpers
"""
from __future__ import annotations

import contextlib
import json
import os
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Generator

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]

# Viewport presets required by UI v3 specifications
VIEWPORT_1440 = {"width": 1440, "height": 900}
VIEWPORT_1280 = {"width": 1280, "height": 800}
VIEWPORT_768 = {"width": 768, "height": 1024}
STANDARD_VIEWPORTS = {
    1440: VIEWPORT_1440,
    1280: VIEWPORT_1280,
    768: VIEWPORT_768,
}


def find_free_port() -> int:
    """Find and return an available TCP port on localhost."""
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        return int(s.getsockname()[1])


def is_chromium_available() -> tuple[bool, str]:
    """Check if Chromium is launchable via Playwright.

    Returns:
        (True, "") if Chromium can be launched.
        (False, reason) if Playwright is missing or Chromium fails to launch.
    """
    if os.environ.get("WSCAN_SKIP_BROWSER", "").strip().lower() in ("1", "true", "yes"):
        return False, "Browser tests explicitly disabled via WSCAN_SKIP_BROWSER"
    if os.environ.get("WSCAN_NO_BROWSER", "").strip().lower() in ("1", "true", "yes"):
        return False, "Browser tests explicitly disabled via WSCAN_NO_BROWSER"
    if os.environ.get("WSCAN_E2E", "").strip().lower() in ("0", "false", "no", "off"):
        return False, "E2E disabled via WSCAN_E2E=0"

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        return False, "playwright package is not installed"
    except Exception as exc:
        return False, f"playwright import error: {exc}"

    result: dict[str, Any] = {}

    def _probe():
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                browser.close()
            result["ok"] = True
        except Exception as exc:
            result["ok"] = False
            result["reason"] = f"Chromium launch failed: {exc}"

    thread = threading.Thread(target=_probe, daemon=True)
    thread.start()
    thread.join(timeout=10.0)

    if thread.is_alive():
        return False, "Chromium launch probe timed out after 10s"
    if result.get("ok"):
        return True, ""
    return False, result.get("reason", "Chromium launch failed")


def require_browser() -> None:
    """Skip the test if Chromium browser is not available in the environment."""
    available, reason = is_chromium_available()
    if not available:
        pytest.skip(reason)


def parse_png_dimensions(data: bytes) -> tuple[int, int]:
    """Extract (width, height) from PNG IHDR chunk without PIL dependency.

    Format:
    - 8 bytes: PNG signature (\\x89PNG\\r\\n\\x1a\\n)
    - 4 bytes: Chunk length (0x0000000D = 13 bytes)
    - 4 bytes: Chunk type (b"IHDR")
    - 4 bytes: Width (big-endian uint32)
    - 4 bytes: Height (big-endian uint32)
    """
    if len(data) < 24:
        raise ValueError(f"Data too short for PNG header: {len(data)} bytes")
    if data[:8] != b"\x89PNG\r\n\x1a\n":
        raise ValueError("Invalid PNG signature")
    if data[12:16] != b"IHDR":
        raise ValueError("Missing IHDR chunk at expected offset")
    width, height = struct.unpack(">II", data[16:24])
    return int(width), int(height)


# -----------------------------------------------------------------------------
# Deterministic Baseline Fixtures
# -----------------------------------------------------------------------------

def seed_baseline_scans(output_dir: Path) -> list[str]:
    """Create deterministic non-secret scan fixtures in the isolated output directory."""
    output_dir.mkdir(parents=True, exist_ok=True)
    scan_ids = []

    # 1. Done scan with multiple findings of diverse severities
    id1 = "20261026_100000"
    scan_ids.append(id1)
    dir1 = output_dir / id1
    dir1.mkdir(parents=True, exist_ok=True)
    (dir1 / "report.html").write_text(
        "<!DOCTYPE html><html><head><title>Report 20261026_100000</title></head><body><h1>Scan Report</h1></body></html>",
        encoding="utf-8",
    )
    (dir1 / "evidence.json").write_text(
        json.dumps({
            "target": "http://store.internal.local",
            "scan_date": "2026-10-26T10:00:00",
            "status": "done",
            "coverage": {"pages_crawled": 12, "forms_tested": 8},
            "findings": [
                {
                    "id": "f_xss_01",
                    "check_type": "xss",
                    "severity": "critical",
                    "url": "http://store.internal.local/search?q=test",
                    "evidence": "Reflected parameter in HTML without sanitization",
                },
                {
                    "id": "f_sqli_01",
                    "check_type": "sqli",
                    "severity": "high",
                    "url": "http://store.internal.local/products?id=1",
                    "evidence": "Boolean equivalence difference observed",
                },
                {
                    "id": "f_cors_01",
                    "check_type": "cors",
                    "severity": "medium",
                    "url": "http://store.internal.local/api/profile",
                    "evidence": "Access-Control-Allow-Origin: * with credentials",
                },
            ],
        }, indent=2),
        encoding="utf-8",
    )

    # 2. Done scan with low severity
    id2 = "20261026_110000"
    scan_ids.append(id2)
    dir2 = output_dir / id2
    dir2.mkdir(parents=True, exist_ok=True)
    (dir2 / "report.html").write_text(
        "<!DOCTYPE html><html><body>Report 20261026_110000</body></html>",
        encoding="utf-8",
    )
    (dir2 / "evidence.json").write_text(
        json.dumps({
            "target": "http://api.internal.local",
            "scan_date": "2026-10-26T11:00:00",
            "status": "done",
            "coverage": {"pages_crawled": 5, "forms_tested": 0},
            "findings": [
                {
                    "id": "f_sec_01",
                    "check_type": "security_headers",
                    "severity": "low",
                    "url": "http://api.internal.local/health",
                    "evidence": "Missing Strict-Transport-Security header",
                },
            ],
        }, indent=2),
        encoding="utf-8",
    )

    # 3. Aborted scan with no findings
    id3 = "20261026_120000"
    scan_ids.append(id3)
    dir3 = output_dir / id3
    dir3.mkdir(parents=True, exist_ok=True)
    (dir3 / "evidence.json").write_text(
        json.dumps({
            "target": "http://admin.internal.local",
            "scan_date": "2026-10-26T12:00:00",
            "status": "aborted",
            "coverage": {"pages_crawled": 1, "forms_tested": 0},
            "findings": [],
        }, indent=2),
        encoding="utf-8",
    )

    return scan_ids


def seed_baseline_audit_log(output_dir: Path) -> Path:
    """Create deterministic non-secret management audit log entries."""
    output_dir.mkdir(parents=True, exist_ok=True)
    audit_path = output_dir / "management_audit.jsonl"
    entries = [
        {
            "ts": "2026-10-26T10:00:00",
            "ip": "127.0.0.1",
            "action": "scan_start",
            "detail": "http://store.internal.local",
        },
        {
            "ts": "2026-10-26T10:15:00",
            "ip": "127.0.0.1",
            "action": "settings_update",
            "detail": "webhook_set=False enabled=False",
        },
        {
            "ts": "2026-10-26T10:30:00",
            "ip": "127.0.0.1",
            "action": "scan_complete",
            "detail": "http://store.internal.local",
        },
        {
            "ts": "2026-10-26T12:00:00",
            "ip": "127.0.0.1",
            "action": "scan_abort",
            "detail": "http://admin.internal.local",
        },
    ]
    audit_path.write_text(
        "\n".join(json.dumps(e) for e in entries) + "\n",
        encoding="utf-8",
    )
    return audit_path


def seed_baseline_settings(output_dir: Path) -> Path:
    """Create deterministic notification and general settings."""
    output_dir.mkdir(parents=True, exist_ok=True)
    settings_path = output_dir / "wscan_settings.json"
    data = {
        "notifications": {
            "enabled": False,
            "webhook_url": "",
            "notify_on_complete": False,
            "min_severity": "high",
        },
        "retention_days": 14,
        "retention_max_scans": 50,
    }
    settings_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return settings_path


def get_baseline_monitor_events() -> list[dict[str, Any]]:
    """Return a sequence of deterministic scan events for populating Live Monitor."""
    server_id = "srv_baseline_test"
    run_id = "run_baseline_101"
    scan_id = "20261026_100000"

    return [
        {
            "type": "scan_started",
            "server_id": server_id,
            "run_id": run_id,
            "scan_id": scan_id,
            "sequence": 1,
            "data": {
                "target": "http://store.internal.local",
                "checks": ["xss", "sqli", "os"],
            },
        },
        {
            "type": "status",
            "server_id": server_id,
            "run_id": run_id,
            "scan_id": scan_id,
            "sequence": 2,
            "data": {
                "message": "Phase: crawl (discovering endpoints)",
                "state": "scanning",
            },
        },
        {
            "type": "url_crawled",
            "server_id": server_id,
            "run_id": run_id,
            "scan_id": scan_id,
            "sequence": 3,
            "data": {
                "url": "http://store.internal.local/products",
                "status_code": 200,
            },
        },
        {
            "type": "sitemap",
            "server_id": server_id,
            "run_id": run_id,
            "scan_id": scan_id,
            "sequence": 4,
            "data": {
                "node": "http://store.internal.local/products",
                "parent": "http://store.internal.local",
                "depth": 1,
                "forms_count": 2,
            },
        },
        {
            "type": "finding",
            "server_id": server_id,
            "run_id": run_id,
            "scan_id": scan_id,
            "sequence": 5,
            "data": {
                "id": "f_live_xss_01",
                "check_type": "xss",
                "severity": "critical",
                "url": "http://store.internal.local/search?q=test",
                "evidence": "Payload rendered unescaped in <div> context",
                "status": "confirmed",
                "verified": True,
            },
        },
        {
            "type": "log",
            "server_id": server_id,
            "run_id": run_id,
            "scan_id": scan_id,
            "sequence": 6,
            "data": {
                "message": "[xss] Confirmed reflected XSS on /search?q=test",
                "level": "info",
            },
        },
    ]


# -----------------------------------------------------------------------------
# Isolated UI Test Harness
# -----------------------------------------------------------------------------

class UIHarness:
    """Isolated serve process and browser session context manager."""

    def __init__(
        self,
        port: int | None = None,
        seed_fixtures: bool = True,
        auth_token: str | None = None,
        repo_root: Path | None = None,
    ) -> None:
        self.port = port or find_free_port()
        self.seed_fixtures = seed_fixtures
        self.auth_token = auth_token
        self.repo_root = repo_root or REPO_ROOT

        self._temp_dir: tempfile.TemporaryDirectory | None = None
        self.output_dir: Path | None = None
        self.server_proc: subprocess.Popen | None = None
        self.server_url: str = f"http://127.0.0.1:{self.port}"

        self._playwright = None
        self._browser = None
        self._contexts: list[Any] = []
        self._page_errors: dict[Any, list[str]] = {}

    def __enter__(self) -> "UIHarness":
        require_browser()
        from playwright.sync_api import sync_playwright

        # 1. Create isolated temporary working directory
        self._temp_dir = tempfile.TemporaryDirectory(prefix="wscan_ui_harness_")
        tmp_path = Path(self._temp_dir.name)
        self.output_dir = tmp_path / "output"
        self.output_dir.mkdir(parents=True, exist_ok=True)

        # 2. Seed baseline fixtures if requested
        if self.seed_fixtures:
            seed_baseline_scans(self.output_dir)
            seed_baseline_audit_log(self.output_dir)
            seed_baseline_settings(self.output_dir)

        # 3. Launch python main.py serve --no-open-browser in isolated cwd
        env = os.environ.copy()
        env["PYTHONPATH"] = str(self.repo_root)

        cmd = [
            sys.executable,
            str(self.repo_root / "main.py"),
            "serve",
            "--host", "127.0.0.1",
            "--port", str(self.port),
            "--no-open-browser",
        ]
        if self.auth_token:
            cmd.extend(["--auth-token", self.auth_token])

        self.server_proc = subprocess.Popen(
            cmd,
            cwd=str(tmp_path),
            env=env,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )

        # 4. Wait for server to come up and answer /health
        self._wait_for_server(timeout=12.0)

        # 5. Initialize Playwright and launch Chromium
        self._playwright = sync_playwright().start()
        self._browser = self._playwright.chromium.launch(headless=True)

        return self

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        # Close all browser contexts and browser
        for ctx in list(self._contexts):
            try:
                ctx.close()
            except Exception:
                pass
        self._contexts.clear()

        if self._browser:
            try:
                self._browser.close()
            except Exception:
                pass
            self._browser = None

        if self._playwright:
            try:
                self._playwright.stop()
            except Exception:
                pass
            self._playwright = None

        # Stop server subprocess
        if self.server_proc:
            try:
                self.server_proc.terminate()
                self.server_proc.wait(timeout=5.0)
            except Exception:
                try:
                    self.server_proc.kill()
                    self.server_proc.wait(timeout=2.0)
                except Exception:
                    pass
            self.server_proc = None

        # Clean up temporary directory
        if self._temp_dir:
            try:
                self._temp_dir.cleanup()
            except Exception:
                pass
            self._temp_dir = None

    def _wait_for_server(self, timeout: float = 10.0) -> None:
        """Poll /health endpoint until it answers 200 or timeout expires."""
        import urllib.request
        deadline = time.time() + timeout
        health_url = f"{self.server_url}/health"

        while time.time() < deadline:
            if self.server_proc and self.server_proc.poll() is not None:
                stdout, stderr = self.server_proc.communicate()
                raise RuntimeError(
                    f"Server process exited unexpectedly with code {self.server_proc.returncode}.\n"
                    f"STDOUT: {stdout.decode('utf-8', errors='replace')}\n"
                    f"STDERR: {stderr.decode('utf-8', errors='replace')}"
                )
            try:
                with urllib.request.urlopen(health_url, timeout=0.5) as resp:
                    if resp.status == 200:
                        return
            except Exception:
                time.sleep(0.1)

        raise TimeoutError(f"Server at {self.server_url} failed to respond to /health within {timeout}s")

    def new_page(self, width: int = 1440, height: int = 900) -> Any:
        """Create a new page with specified viewport and console/pageerror listening."""
        if not self._browser:
            raise RuntimeError("Browser is not initialized")
        viewport = {"width": width, "height": height}
        context = self._browser.new_context(viewport=viewport)
        self._contexts.append(context)

        page = context.new_page()
        errors: list[str] = []
        self._page_errors[page] = errors

        page.on("pageerror", lambda exc: errors.append(f"pageerror: {exc}"))
        page.on(
            "console",
            lambda msg: errors.append(f"console[{msg.type}]: {msg.text}")
            if msg.type == "error"
            else None,
        )

        return page

    def get_errors(self, page: Any) -> list[str]:
        """Return collected console and unhandled page errors for a page."""
        return list(self._page_errors.get(page, []))

    def clear_errors(self, page: Any) -> None:
        """Clear collected errors for a page."""
        if page in self._page_errors:
            self._page_errors[page].clear()

    def assert_no_errors(self, page: Any) -> None:
        """Assert no console.error or uncaught pageerror occurred."""
        errors = self.get_errors(page)
        assert not errors, f"Unexpected page errors encountered: {errors}"

    def assert_no_horizontal_overflow(self, page: Any, max_allowed: int | None = None) -> None:
        """Assert document layout does not overflow horizontally past the allowed width."""
        overflow_info = page.evaluate("""() => {
            const docWidth = document.documentElement.scrollWidth;
            const winWidth = window.innerWidth;
            const bodyWidth = document.body ? document.body.scrollWidth : 0;
            return {
                docWidth: docWidth,
                winWidth: winWidth,
                bodyWidth: bodyWidth,
            };
        }""")
        limit = max_allowed if max_allowed is not None else (overflow_info["winWidth"] + 1)
        assert overflow_info["docWidth"] <= limit, (
            f"Horizontal overflow detected: scrollWidth {overflow_info['docWidth']}px > limit {limit}px "
            f"(window.innerWidth: {overflow_info['winWidth']}px)"
        )

    def capture_screenshot(
        self,
        page: Any,
        name: str,
        width: int,
        dest_dir: Path | None = None,
    ) -> tuple[Path, int, int]:
        """Capture screenshot, verify dimensions via IHDR without PIL, and return (path, w, h)."""
        target_dir = dest_dir or (Path(self._temp_dir.name) / "screenshots")
        target_dir.mkdir(parents=True, exist_ok=True)
        out_path = target_dir / f"{name}_{width}.png"

        png_bytes = page.screenshot(path=str(out_path), full_page=False)
        parsed_w, parsed_h = parse_png_dimensions(png_bytes)
        assert parsed_w == width, f"Screenshot width mismatch: expected {width}, got {parsed_w}"

        return out_path, parsed_w, parsed_h

    def populate_live_monitor(self, page: Any) -> None:
        """Feed deterministic events into dashboard's handleEvent to populate all 3 panes."""
        page.evaluate("""() => {
            if (typeof handleEvent !== "function") return;
            handleEvent({
                type: "scan_snapshot",
                sequence: 6,
                data: {
                    status: "scanning",
                    findings: [
                        {
                            id: "f_live_xss_01",
                            check_type: "xss",
                            severity: "critical",
                            url: "http://store.internal.local/search?q=test",
                            confirmed: true,
                            verified: true
                        }
                    ],
                    findings_count: 1,
                    total_findings_count: 1,
                    confirmed_findings_count: 1,
                    page_count: 4,
                    check_counts: {xss: 1, sqli: 0},
                    url_order: ["http://store.internal.local", "http://store.internal.local/products"],
                    phase: "attack"
                }
            });
            if (typeof addEventLog === "function") {
                addEventLog("status", "Scan started on http://store.internal.local");
                addEventLog("finding", "[xss] Critical XSS verified");
            }
            if (typeof addSiteMapNode === "function") {
                addSiteMapNode("http://store.internal.local", null);
                addSiteMapNode("http://store.internal.local/products", "http://store.internal.local");
            }
        }""")
        page.wait_for_timeout(100)


@pytest.fixture
def ui_harness() -> Generator[UIHarness, None, None]:
    """Pytest fixture providing an isolated UIHarness instance."""
    require_browser()
    with UIHarness() as harness:
        yield harness
