"""Readiness checks that never send scan payloads."""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

import httpx


def classify_exception(exc: BaseException) -> tuple[str, str]:
    """Return stable machine reason and safe detail for transport exceptions."""
    if isinstance(exc, socket.gaierror):
        return "dns_failure", "The target hostname could not be resolved."
    if isinstance(exc, httpx.ProxyError):
        return "proxy_error", "The configured proxy could not be reached or used."
    if isinstance(exc, httpx.ConnectTimeout | httpx.ReadTimeout | httpx.PoolTimeout):
        return "timeout", "The connection timed out."
    if isinstance(exc, ssl.SSLError | httpx.ConnectError) and (
        isinstance(exc, ssl.SSLError) or "CERTIFICATE_VERIFY_FAILED" in str(exc)
    ):
        return "tls_certificate_error", "TLS certificate validation failed."
    if isinstance(exc, httpx.ConnectError) and "refused" in str(exc).lower():
        return "connection_refused", "The target refused the connection."
    if isinstance(exc, (OSError, httpx.TransportError)):
        return "connection_error", "The target could not be reached."
    return "check_error", "The readiness check could not be completed."


def result(checks: list[dict]) -> dict:
    """Build a JSON-safe verdict from check rows."""
    verdict = "fail" if any(c["status"] == "fail" for c in checks) else (
        "warning" if any(c["status"] == "warning" for c in checks) else "pass"
    )
    return {"schema_version": "1.0.0", "verdict": verdict, "checks": checks}


def exit_code(report: dict) -> int:
    return 1 if report.get("verdict") == "fail" else 0


def _check(check_id: str, status: str, reason: str, detail: str) -> dict:
    return {"id": check_id, "status": status, "reason_code": reason, "detail": detail}


def proxy_applied(client: httpx.Client, url: str, configured_proxy: str) -> bool | None:
    """Inspect the transport selected for URL and report whether it uses a proxy."""
    try:
        target = httpx.URL(url)
        matches = [(pattern, transport) for pattern, transport in client._mounts.items()
                   if pattern.matches(target)]
        if not matches:
            return False
        _, transport = max(matches, key=lambda item: item[0].priority)
        proxy_url = transport._pool._proxy_url
        configured = httpx.URL(configured_proxy).copy_with(username="", password="")
        return proxy_url == configured.copy_with(username="", password="") if proxy_url is not None else False
    except (AttributeError, TypeError, ValueError):
        return None


def _http_check(url: str, proxy: str, verify: bool) -> tuple[dict, dict, dict]:
    def request(configured_proxy: str) -> tuple[dict, bool | None]:
        try:
            from types import SimpleNamespace
            from .engine import ScanEngine
            from .tls_config import TLSConfig

            engine = SimpleNamespace(proxy=configured_proxy, tls_config=TLSConfig.from_values())
            options = ScanEngine.httpx_client_kwargs(engine, verify=verify, timeout=10,
                                                     follow_redirects=False, trust_env=False)
            client = httpx.Client(**options)
            applied = proxy_applied(client, url, configured_proxy) if configured_proxy else False
            with client:
                response = client.get(url)
            status = "pass" if response.status_code < 400 else "warning"
            reason = "reachable" if status == "pass" else "http_error_status"
            return (_check("reachability", status, reason,
                           f"HTTP GET returned status {response.status_code}."), applied)
        except Exception as exc:
            reason, detail = classify_exception(exc)
            return _check("reachability", "fail", reason, detail), locals().get("applied")

    direct, _ = request("")
    if proxy:
        proxied, applied = request(proxy)
    else:
        proxied = _check("proxy_reachability", "not_applicable", "proxy_not_configured", "No proxy was configured.")
        applied = False
    proxy_status = "pass" if applied is True else "fail" if applied is False and proxy else "not_checked" if proxy else "not_applicable"
    proxy_reason = "proxy_applied" if applied is True else "proxy_not_applied" if applied is False and proxy else "proxy_application_unknown" if proxy else "proxy_not_configured"
    proxy_check = _check(
        "proxy_applied", proxy_status,
        proxy_reason,
        "The configured proxy is used by the httpx transport for this request." if applied is True
        else "The configured proxy is not used by the httpx transport for this request." if applied is False and proxy
        else "Proxy use could not be determined from the httpx transport." if proxy
        else "No proxy was configured.",
    )
    # Return both transport outcomes; the caller assigns distinct stable IDs.
    direct["id"] = "reachability_direct"
    if proxy:
        proxied["id"] = "reachability_proxy"
        if direct["status"] == "fail" and proxied["status"] != "fail":
            direct.update(status="warning", reason_code="direct_path_unavailable",
                          detail="The direct path failed, but the configured proxy reached the target.")
    return direct, proxied, proxy_check


async def run_preflight(
    url: str, *, proxy: str = "", verify_tls: bool = False,
    ca_cert: str = "", output_dir: str | Path, checks: list[str],
    api_spec: str = "", auth_configured: bool = False, accounts_configured: bool = False,
    oob_configured: bool = False, agent_mode: bool = False,
) -> dict:
    """Run non-invasive DNS, HTTP, browser, output and declared-prerequisite checks."""
    rows: list[dict] = []
    host = urlsplit(url).hostname
    try:
        if not host:
            raise socket.gaierror("missing hostname")
        await asyncio.to_thread(socket.getaddrinfo, host, urlsplit(url).port, 0, socket.SOCK_STREAM)
        rows.append(_check("dns", "pass", "resolved", "The target hostname resolved."))
    except Exception as exc:
        reason, detail = classify_exception(exc)
        rows.append(_check("dns", "warning" if proxy else "fail", reason, detail))

    tls_configuration_error = False
    try:
        from .tls_config import TLSConfig
        tls = TLSConfig.from_values(verify_tls=verify_tls, ca_cert=ca_cert)
        verify = tls.httpx_options()["verify"]
    except Exception:
        verify = verify_tls
        tls_configuration_error = True
    direct, proxied, proxy_row = await asyncio.to_thread(_http_check, url, proxy, verify)
    rows.extend((direct, proxied, proxy_row))
    if urlsplit(url).scheme.lower() == "https":
        scan_path = proxied if proxy else direct
        tls_failed = scan_path["reason_code"] == "tls_certificate_error"
        rows.append(_check(
            "tls_certificate", "fail" if tls_failed else "pass" if verify else "warning",
            "tls_certificate_error" if tls_failed else "certificate_valid" if verify else "verification_disabled",
            "TLS certificate validation failed." if tls_failed else
            "TLS certificate validation succeeded." if verify else
            "TLS certificate validation is disabled by the scan settings.",
        ))
    if tls_configuration_error:
        rows.append(_check("tls_configuration", "fail", "tls_configuration_error",
                           "The configured TLS certificate settings could not be loaded."))

    try:
        from playwright.async_api import async_playwright
        async with await async_playwright() as p:
            browser = await p.chromium.launch(headless=True, proxy={"server": proxy} if proxy else None)
            await browser.close()
        rows.append(_check("playwright", "pass", "available", "Playwright Chromium launched successfully."))
    except ImportError:
        rows.append(_check("playwright", "fail", "dependency_missing", "Playwright is not installed."))
    except Exception as exc:
        reason, detail = classify_exception(exc)
        message = str(exc).lower()
        if "host system is missing dependencies" in message or "unsupported platform" in message:
            reason, detail = "unsupported_platform", "Playwright Chromium is unsupported on this platform."
        elif "executable" in message or "browser_type.launch" in message:
            reason, detail = "dependency_missing", "Playwright Chromium is unavailable."
        elif proxy and "proxy" in message:
            reason, detail = "proxy_error", "The configured proxy could not be used by Chromium."
        rows.append(_check("playwright", "fail", reason, detail))

    try:
        output = Path(output_dir)
        output.mkdir(parents=True, exist_ok=True)
        with tempfile.NamedTemporaryFile(dir=output, prefix=".preflight-"):
            pass
        rows.append(_check("output_directory", "pass", "writable", "The scan output directory is writable."))
    except OSError:
        rows.append(_check("output_directory", "fail", "output_not_writable", "The scan output directory is not writable."))

    from .scanners import SCANNERS
    from .scanner_contract import Prerequisite
    browser_ready = next((r["status"] == "pass" for r in rows if r["id"] == "playwright"), False)
    for check in checks:
        scanner = SCANNERS.get(check)
        if scanner is None:
            rows.append(_check(f"scanner:{check}", "fail", "scanner_unavailable", "No scanner is registered for this check."))
            continue
        for prerequisite in scanner.CONTRACT.prerequisites:
            if prerequisite == Prerequisite.BROWSER:
                rows.append(_check(f"scanner:{check}", "pass" if browser_ready else "fail",
                                   "available" if browser_ready else "prerequisite_missing",
                                   "This check declares a browser prerequisite."))
            elif prerequisite == Prerequisite.API_SPEC:
                present = bool(api_spec and Path(api_spec).is_file())
                rows.append(_check(f"scanner:{check}", "pass" if present else "warning",
                                   "prerequisite_present" if present else "prerequisite_missing",
                                   "This check declares an API specification prerequisite."))
            elif prerequisite == Prerequisite.AUTH_SESSION and not auth_configured:
                rows.append(_check(f"scanner:{check}", "warning", "prerequisite_missing", "This check declares an authenticated session prerequisite."))
            elif prerequisite == Prerequisite.AUTH_SESSION:
                rows.append(_check(f"scanner:{check}", "not_checked", "not_implemented",
                                   "Authentication readiness is not checked in this increment."))
            elif prerequisite == Prerequisite.MULTI_ACCOUNT and not accounts_configured:
                rows.append(_check(f"scanner:{check}", "warning", "prerequisite_missing", "This check declares a multiple-account prerequisite."))
            elif prerequisite == Prerequisite.MULTI_ACCOUNT:
                rows.append(_check(f"scanner:{check}", "not_checked", "not_implemented",
                                   "Multiple-account readiness is not checked in this increment."))
            elif prerequisite == Prerequisite.SECOND_REQUEST:
                rows.append(_check(f"scanner:{check}", "pass", "available",
                                   "This check declares a multiple-request prerequisite."))
            elif prerequisite == Prerequisite.OOB_SINK:
                rows.append(_check(f"scanner:{check}", "not_checked", "not_implemented", "OOB readiness is not checked in this increment."))

    rows.append(_check("authentication", "not_checked", "not_implemented", "This readiness check is not implemented."))

    try:
        import browser_use  # noqa: F401
        rows.append(_check("agent_transport", "pass", "available", "The agent-mode browser automation backend is importable."))
    except ImportError:
        if agent_mode:
            rows.append(_check("agent_transport", "fail", "dependency_missing", "Agent mode is selected but its browser automation backend is not installed."))
        else:
            rows.append(_check("agent_transport", "warning", "dependency_missing", "The agent-mode browser automation backend is not installed (only needed for agent mode)."))

    rows.append(_check("websocket", "not_checked", "not_implemented", "This readiness check is not implemented."))

    if oob_configured:
        rows.append(_check("oob", "pass", "configured", "An out-of-band email sink is configured for blind-vulnerability confirmation."))
    else:
        rows.append(_check("oob", "not_applicable", "oob_not_configured", "No out-of-band sink configured; blind checks fall back to heuristic confirmation."))
    return result(rows)


def write_result(output_dir: str | Path, report: dict) -> None:
    Path(output_dir).mkdir(parents=True, exist_ok=True)
    (Path(output_dir) / "preflight.json").write_text(
        json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
