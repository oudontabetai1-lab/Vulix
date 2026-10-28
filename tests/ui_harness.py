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
import logging
import os
import re
import socket
import struct
import subprocess
import sys
import tempfile
import threading
import time
import warnings
from pathlib import Path
from typing import Any, Generator

import pytest

logger = logging.getLogger(__name__)

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


_CHROMIUM_AVAILABLE_CACHE: tuple[bool, str] | None = None


def reset_chromium_cache() -> None:
    """Clear cached Chromium availability result (primarily for testing)."""
    global _CHROMIUM_AVAILABLE_CACHE
    _CHROMIUM_AVAILABLE_CACHE = None


def is_chromium_available(force_refresh: bool = False) -> tuple[bool, str]:
    """Check if Chromium is launchable via Playwright.

    Returns:
        (True, "") if Chromium can be launched.
        (False, reason) if Playwright is missing or Chromium fails to launch.
    """
    global _CHROMIUM_AVAILABLE_CACHE

    if os.environ.get("WSCAN_SKIP_BROWSER", "").strip().lower() in ("1", "true", "yes"):
        return False, "Browser tests explicitly disabled via WSCAN_SKIP_BROWSER"
    if os.environ.get("WSCAN_NO_BROWSER", "").strip().lower() in ("1", "true", "yes"):
        return False, "Browser tests explicitly disabled via WSCAN_NO_BROWSER"
    if os.environ.get("WSCAN_E2E", "").strip().lower() in ("0", "false", "no", "off"):
        return False, "E2E disabled via WSCAN_E2E=0"

    if not force_refresh and _CHROMIUM_AVAILABLE_CACHE is not None:
        return _CHROMIUM_AVAILABLE_CACHE

    try:
        from playwright.sync_api import sync_playwright
    except ImportError:
        res = (False, "playwright package is not installed")
        _CHROMIUM_AVAILABLE_CACHE = res
        return res
    except Exception as exc:
        res = (False, f"playwright import error: {exc}")
        _CHROMIUM_AVAILABLE_CACHE = res
        return res

    result: dict[str, Any] = {}

    def _probe():
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                browser.close()
            result["ok"] = True
        except BaseException as exc:
            result["ok"] = False
            result["reason"] = f"Chromium launch failed: {exc}"

    thread = threading.Thread(target=_probe, daemon=True)
    thread.start()
    thread.join(timeout=10.0)

    if thread.is_alive():
        res = (False, "Chromium launch probe timed out after 10s")
    elif result.get("ok"):
        res = (True, "")
    else:
        res = (False, result.get("reason", "Chromium launch failed"))

    _CHROMIUM_AVAILABLE_CACHE = res
    return res


def require_browser() -> None:
    """Skip the test if Chromium browser is not available in the environment."""
    available, reason = is_chromium_available()
    if not available:
        pytest.skip(reason)


SAFE_PASSTHROUGH_KEYS = frozenset({
    # Execution & paths
    "PATH",
    # Windows system paths
    "SYSTEMROOT",
    "WINDIR",
    "APPDATA",
    "LOCALAPPDATA",
    "USERPROFILE",
    "HOMEPATH",
    "HOMEDRIVE",
    "COMSPEC",
    "PATHEXT",
    # Temporary directories
    "TMPDIR",
    "TEMP",
    "TMP",
    # Locale & encoding
    "LANG",
    "LC_ALL",
    "LC_CTYPE",
    "TZ",
    # Terminal
    "TERM",
    # Python / Conda environment markers
    "VIRTUAL_ENV",
    "CONDA_PREFIX",
    "CONDA_DEFAULT_ENV",
    "PYTHONHOME",
    # TLS / CA certificates if configured
    "SSL_CERT_FILE",
    "SSL_CERT_DIR",
    "REQUESTS_CA_BUNDLE",
    "CURL_CA_BUNDLE",
})

SAFE_EXTRA_ENV_KEYS = frozenset(
    SAFE_PASSTHROUGH_KEYS
    | {
        # Deterministic Python test runtime settings
        "PYTHONPATH",
        "PYTHONUNBUFFERED",
        "PYTHONIOENCODING",
        "PYTHONHASHSEED",
        "PYTHONDONTWRITEBYTECODE",
        "PYTHONDEBUG",
        "PYTHONUTF8",
        # Non-secret test flags & runner markers
        "WSCAN_TEST_MODE",
        "WSCAN_UI_TEST",
        "WSCAN_LOG_LEVEL",
        "WSCAN_ENV",
        "TESTING",
        "CI",
        "PYTEST_CURRENT_TEST",
    }
)


def sanitize_path_output(
    text: str,
    repo_root: Path | None = None,
    temp_dir: Path | None = None,
) -> str:
    """Sanitize absolute filesystem paths from command output and error messages.

    Replaces real absolute paths with safe relative representations or placeholders
    to avoid leaking local environment filesystem paths (e.g., /Users/..., /home/...).
    """
    if not text:
        return text

    sanitized = text

    # 1. Replace temporary working directory path
    if temp_dir is not None:
        t_str = str(temp_dir).rstrip("/\\")
        if t_str:
            sanitized = sanitized.replace(t_str, "<isolated_cwd>")
            if t_str.startswith("/private/var"):
                sanitized = sanitized.replace(t_str[len("/private"):], "<isolated_cwd>")

    # 2. Replace repository root with relative "."
    root = repo_root or REPO_ROOT
    r_str = str(root).rstrip("/\\")
    if r_str:
        sanitized = sanitized.replace(r_str, ".")
        if r_str.startswith("/private/var"):
            sanitized = sanitized.replace(r_str[len("/private"):], ".")

    # 3. Replace user home directory
    try:
        home_str = str(Path.home()).rstrip("/\\")
        if home_str and home_str != "/":
            sanitized = sanitized.replace(home_str, "~")
            if home_str.startswith("/private/var"):
                sanitized = sanitized.replace(home_str[len("/private"):], "~")
    except Exception:
        pass

    # 4. Replace Python virtualenv / conda prefix
    for prefix in (getattr(sys, "prefix", None), getattr(sys, "base_prefix", None)):
        if prefix:
            p_str = str(prefix).rstrip("/\\")
            if len(p_str) > 1 and p_str != "/":
                sanitized = sanitized.replace(p_str, "<python_env>")

    # 5. Regex replacement for any remaining user home absolute paths
    # macOS: /Users/<user>[/...] or /private/Users/...
    sanitized = re.sub(r"/(?:private/)?Users/[^\s/\"':\\()]+", "~", sanitized)
    # Linux: /home/<user>[/...]
    sanitized = re.sub(r"/home/[^\s/\"':\\()]+", "~", sanitized)
    # Windows: [A-Za-z]:\Users\<user>[\...]
    sanitized = re.sub(r"[A-Za-z]:\\+Users\\[^\s/\\\"':()]+", "~", sanitized)

    return sanitized


def build_sanitized_env(
    repo_root: Path | None = None,
    extra_env: dict[str, str] | None = None,
) -> dict[str, str]:
    """Create a minimal sanitized environment for isolated serve subprocess.

    Excludes parent credentials, API keys, tokens, and secrets while retaining
    essential system and runtime variables. Enforces allowlist on extra_env
    so unexpected or sensitive keys cannot bypass isolation.
    """
    env: dict[str, str] = {}
    for key in SAFE_PASSTHROUGH_KEYS:
        val = os.environ.get(key)
        if val is not None:
            env[key] = val

    # Deterministic test settings
    root = repo_root or REPO_ROOT
    env["PYTHONPATH"] = str(root)
    env["PYTHONUNBUFFERED"] = "1"
    env["PYTHONIOENCODING"] = "utf-8"

    # Enforce safe allowlist for extra_env
    if extra_env:
        for key, val in extra_env.items():
            if key in SAFE_EXTRA_ENV_KEYS and val is not None:
                env[key] = str(val)

    return env


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
        extra_env: dict[str, str] | None = None,
    ) -> None:
        self.port = port or find_free_port()
        self.seed_fixtures = seed_fixtures
        self.auth_token = auth_token
        self.repo_root = repo_root or REPO_ROOT
        self.extra_env = extra_env

        self._temp_dir: tempfile.TemporaryDirectory | None = None
        self.output_dir: Path | None = None
        self.server_proc: subprocess.Popen | None = None
        self.server_url: str = f"http://127.0.0.1:{self.port}"

        self._playwright = None
        self._browser = None
        self._contexts: list[Any] = []
        self._page_errors: dict[Any, list[str]] = {}

    @staticmethod
    def _close_process_pipes(proc: subprocess.Popen) -> None:
        """Safely close standard I/O pipe descriptors of a process."""
        for pipe in (
            getattr(proc, "stdout", None),
            getattr(proc, "stderr", None),
            getattr(proc, "stdin", None),
        ):
            if pipe:
                try:
                    pipe.close()
                except Exception:
                    pass

    def _terminate_serve_process(
        self,
        proc: subprocess.Popen,
        timeout_terminate: float = 5.0,
        timeout_kill: float = 3.0,
    ) -> bool:
        """Terminate serve process with SIGKILL escalation and termination verification."""
        try:
            if proc.poll() is not None:
                return True

            # 1. Attempt graceful SIGTERM
            try:
                proc.terminate()
                try:
                    proc.wait(timeout=timeout_terminate)
                except (subprocess.TimeoutExpired, Exception):
                    pass
            except ProcessLookupError:
                return True
            except Exception as exc:
                logger.debug("Failed to send SIGTERM to serve process pid %s: %s", getattr(proc, "pid", None), exc)

            # 2. Escalate to SIGKILL if still running
            if proc.poll() is None:
                try:
                    proc.kill()
                    try:
                        proc.wait(timeout=timeout_kill)
                    except (subprocess.TimeoutExpired, Exception):
                        pass
                except ProcessLookupError:
                    return True
                except Exception as exc:
                    logger.debug("Failed to send SIGKILL to serve process pid %s: %s", getattr(proc, "pid", None), exc)

            # 3. Final verification of process termination via poll() / returncode
            is_terminated = proc.poll() is not None
            if not is_terminated:
                logger.warning(
                    "Serve process pid=%s could not be confirmed terminated after SIGTERM and SIGKILL escalation (poll=None)",
                    getattr(proc, "pid", None),
                )
            return is_terminated
        finally:
            self._close_process_pipes(proc)

    def cleanup(self) -> None:
        """Safely release all allocated resources (contexts, browser, playwright, server, tempdir)."""
        # 1. Close browser contexts
        try:
            for ctx in list(self._contexts):
                try:
                    ctx.close()
                except Exception:
                    pass
            self._contexts.clear()
        except Exception:
            pass

        # 2. Close browser
        try:
            if self._browser:
                try:
                    self._browser.close()
                except Exception:
                    pass
        finally:
            self._browser = None

        # 3. Stop Playwright
        try:
            if self._playwright:
                try:
                    self._playwright.stop()
                except Exception:
                    pass
        finally:
            self._playwright = None

        # 4. Terminate serve process and verify termination before discarding reference
        proc_terminated = True
        try:
            if self.server_proc:
                proc_terminated = self._terminate_serve_process(self.server_proc)
                if proc_terminated:
                    self.server_proc = None
        except Exception:
            proc_terminated = False

        # 5. Clean up temporary directory only if server process termination was confirmed
        try:
            if proc_terminated and self._temp_dir:
                try:
                    self._temp_dir.cleanup()
                except Exception:
                    pass
                self._temp_dir = None
                self.output_dir = None
        finally:
            if not proc_terminated:
                pid = getattr(self.server_proc, "pid", None)
                msg = f"Teardown incomplete: serve process (pid={pid}) termination could not be confirmed"
                logger.warning(msg)
                warnings.warn(msg, RuntimeWarning, stacklevel=2)
                raise RuntimeError(msg)

    def close(self) -> None:
        """Alias for cleanup to support manual lifecycle management."""
        self.cleanup()

    def __enter__(self) -> "UIHarness":
        require_browser()
        try:
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

            # 3. Launch python main.py serve --no-open-browser in isolated cwd with sanitized env
            env = build_sanitized_env(self.repo_root, extra_env=self.extra_env)

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
            from playwright.sync_api import sync_playwright
            try:
                self._playwright = sync_playwright().start()
                self._browser = self._playwright.chromium.launch(headless=True)
            except Exception as exc:
                pytest.skip(f"Chromium launch failed during UI harness setup: {exc}")

            return self
        except BaseException as exc:
            tmp_path = Path(self._temp_dir.name) if self._temp_dir else None
            self.cleanup()
            msg = str(exc)
            sanitized_msg = sanitize_path_output(msg, repo_root=self.repo_root, temp_dir=tmp_path)
            if sanitized_msg != msg:
                try:
                    raise type(exc)(sanitized_msg) from None
                except TypeError:
                    raise RuntimeError(sanitized_msg) from None
            raise

    def __exit__(self, exc_type, exc_val, exc_tb) -> None:
        self.cleanup()

    def _wait_for_server(self, timeout: float = 10.0) -> None:
        """Poll /health endpoint until it answers 200 or timeout expires."""
        import urllib.request
        deadline = time.time() + timeout
        health_url = f"{self.server_url}/health"

        while time.time() < deadline:
            if self.server_proc and self.server_proc.poll() is not None:
                stdout_bytes, stderr_bytes = self.server_proc.communicate()
                stdout_str = stdout_bytes.decode("utf-8", errors="replace")
                stderr_str = stderr_bytes.decode("utf-8", errors="replace")
                tmp_path = Path(self._temp_dir.name) if self._temp_dir else None
                s_stdout = sanitize_path_output(stdout_str, repo_root=self.repo_root, temp_dir=tmp_path)
                s_stderr = sanitize_path_output(stderr_str, repo_root=self.repo_root, temp_dir=tmp_path)
                raise RuntimeError(
                    f"Server process exited unexpectedly with code {self.server_proc.returncode}.\n"
                    f"STDOUT: {s_stdout}\n"
                    f"STDERR: {s_stderr}"
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
    harness = UIHarness()
    try:
        with harness:
            yield harness
    finally:
        harness.cleanup()
