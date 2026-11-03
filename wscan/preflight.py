"""Readiness checks that never send scan payloads."""
from __future__ import annotations

import asyncio
import json
import socket
import ssl
import tempfile
from pathlib import Path
from urllib.parse import urljoin, urlparse, urlsplit

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


def is_login_url_in_scope(target_url: str, login_url: str, scope_urls: list[str] | None = None) -> bool:
    """ログインURLが対象URLまたは指定スコープ内に収まっているかを判定する純粋関数。"""
    if not (login_url or "").strip():
        return False
    login_str = login_url.strip()
    parsed_login = urlsplit(login_str)
    if parsed_login.scheme and parsed_login.scheme.lower() not in ("http", "https"):
        return False
    # 相対パスは同一対象ホスト内とみなす
    if not parsed_login.netloc:
        return bool(not parsed_login.scheme)
    parsed_target = urlsplit(target_url or "")
    if parsed_target.netloc and parsed_login.netloc.lower() == parsed_target.netloc.lower():
        return True
    from .url_scope import url_in_scope
    for scope in (scope_urls or []):
        if url_in_scope(login_str, scope, host_scope=True):
            return True
    return False


def parse_accounts(
    accounts: list | str | None = None,
    auth_user: str = "",
    auth_pass: str = "",
    accounts_file: str = "",
) -> list[dict]:
    """アカウント設定を純粋に正規化する。秘密情報（パスワード）は一切含めない。"""
    parsed: list[dict] = []
    if isinstance(accounts, list):
        for acc in accounts:
            if isinstance(acc, dict):
                u = acc.get("username") or acc.get("user")
                if u and str(u).strip():
                    parsed.append({"username": str(u).strip()})
            elif isinstance(acc, str) and acc.strip():
                item = acc.strip()
                user = item.split(":", 1)[0].strip() if ":" in item else item
                if user:
                    parsed.append({"username": user})
    elif isinstance(accounts, str) and accounts.strip():
        for pair in accounts.split(","):
            pair = pair.strip()
            if not pair:
                continue
            user = pair.split(":", 1)[0].strip() if ":" in pair else pair
            if user:
                parsed.append({"username": user})

    if not parsed and auth_user and auth_user.strip():
        parsed.append({"username": auth_user.strip()})

    if accounts_file:
        p = Path(accounts_file)
        if p.is_file():
            try:
                import yaml
                data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
                if isinstance(data, dict):
                    acc_list = data.get("accounts") or []
                    for entry in acc_list:
                        if isinstance(entry, dict):
                            u = entry.get("username") or entry.get("user")
                            if u and str(u).strip():
                                parsed.append({"username": str(u).strip()})
            except Exception:
                pass

    return parsed


def evaluate_auth_readiness(
    target_url: str,
    *,
    login_url: str = "",
    auth_user: str = "",
    auth_pass: str = "",
    login_user_field: str = "username",
    login_pass_field: str = "password",
    accounts: list | str | None = None,
    accounts_file: str = "",
    auto_register: bool = False,
    cookie: str = "",
    bearer: str = "",
    headers: list | dict | None = None,
    target_urls: list[str] | None = None,
    access_urls: list[str] | None = None,
    auth_configured: bool = False,
    accounts_configured: bool = False,
    probe_status_code: int | None = None,
    probe_error: tuple[str, str] | None = None,
    probe_html: str = "",
) -> dict:
    """認証準備状態を正直に判定する純粋関数。

    秘密値（パスワード/トークン）は結果・詳細に一切含めない。
    preflight では実際のログイン成否は検証せず、その旨を明示する。
    """
    has_explicit_selectors = bool(
        (login_user_field and login_user_field != "username")
        or (login_pass_field and login_pass_field != "password")
    )
    has_login_settings = bool(
        login_url
        or auth_user
        or auth_pass
        or accounts
        or accounts_file
        or auto_register
        or has_explicit_selectors
    )
    has_session_auth = bool(cookie or bearer or headers)

    if not has_login_settings and not has_session_auth and not auth_configured and not accounts_configured:
        return _check("authentication", "not_applicable", "auth_not_configured", "No authentication configured.")

    if has_session_auth and not has_login_settings:
        return _check(
            "authentication", "pass", "session_token_configured",
            "Session authentication (cookie/bearer/header) is configured. Actual session validity is not verified by preflight.",
        )

    clean_login_url = (login_url or "").strip()
    if not clean_login_url:
        return _check("authentication", "fail", "login_url_missing", "Login settings are configured but login_url is missing.")

    scopes = list(target_urls or []) + list(access_urls or [])
    if not is_login_url_in_scope(target_url, clean_login_url, scopes):
        return _check("authentication", "fail", "login_url_out_of_scope", "The configured login_url is outside the target scope.")

    parsed_accs = parse_accounts(accounts, auth_user=auth_user, auth_pass=auth_pass, accounts_file=accounts_file)
    if not parsed_accs and not auto_register:
        return _check("authentication", "fail", "account_missing", "Login URL is configured but at least one user account credential is required.")

    if not (login_user_field or "").strip() or not (login_pass_field or "").strip():
        return _check("authentication", "fail", "required_fields_missing", "Required login field selectors (user_field or pass_field) are empty.")

    if probe_error is not None:
        _reason, detail = probe_error
        return _check("authentication", "fail", "login_page_unreachable", f"Login page probe failed: {detail}")

    if probe_status_code is not None and probe_status_code >= 400:
        return _check("authentication", "fail", "login_page_http_error", f"Login page probe returned HTTP status {probe_status_code}.")

    surface_detected = False
    if probe_html:
        try:
            from . import login_surface as ls
            surface = ls.classify_surface(probe_html)
            if surface.kind == ls.LOGIN:
                surface_detected = True
        except Exception:
            pass

    if probe_status_code is not None and probe_status_code < 400:
        form_note = " (login form detected)" if surface_detected else ""
        detail = (
            f"Authentication configuration is complete and login page is reachable{form_note}. "
            "Preflight does not verify credentials or login success (no credentials submitted)."
        )
    else:
        detail = (
            "Authentication configuration is complete. "
            "Preflight does not verify credentials or login success (no credentials submitted)."
        )

    return _check("authentication", "pass", "configured", detail)


def evaluate_live_channel_readiness(*, monitor_enabled: bool = True) -> dict:
    """ダッシュボード monitor ライブ通信チャネル（WebSocket）の利用可能性を正直に判定する純粋関数。"""
    if not monitor_enabled:
        return _check(
            "websocket", "not_applicable", "monitor_disabled",
            "Dashboard live channel is disabled for this scan (--no-monitor or batch mode).",
        )
    return _check(
        "websocket", "pass", "available",
        "Dashboard monitor live channel is enabled for real-time progress updates.",
    )


def _probe_login_page(login_url: str, proxy: str, verify: bool) -> tuple[int | None, str, tuple[str, str] | None]:
    """ログインページへの非破壊・副作用なしの GET プローブ（資格情報は一切送信しない）。"""
    try:
        from types import SimpleNamespace
        from .engine import ScanEngine
        from .tls_config import TLSConfig

        engine = SimpleNamespace(proxy=proxy, tls_config=TLSConfig.from_values())
        options = ScanEngine.httpx_client_kwargs(
            engine, verify=verify, timeout=10, follow_redirects=True, trust_env=False
        )
        with httpx.Client(**options) as client:
            resp = client.get(login_url)
        return resp.status_code, resp.text, None
    except Exception as exc:
        reason, detail = classify_exception(exc)
        return None, "", (reason, detail)


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
    login_url: str = "", auth_user: str = "", auth_pass: str = "",
    login_user_field: str = "username", login_pass_field: str = "password",
    accounts: list | str | None = None, accounts_file: str = "",
    auto_register: bool = False, cookie: str = "", bearer: str = "",
    headers: list | dict | None = None, target_urls: list[str] | None = None,
    access_urls: list[str] | None = None, monitor_enabled: bool = True,
    probe_login: bool = True,
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

    # ログインページプローブ（設定が存在しスコープ内の場合のみ）
    probe_status_code = None
    probe_html = ""
    probe_error = None
    clean_login_url = (login_url or "").strip()
    scopes = list(target_urls or []) + list(access_urls or [])
    if probe_login and clean_login_url and is_login_url_in_scope(url, clean_login_url, scopes):
        resolved_login_url = urljoin(url, clean_login_url)
        probe_status_code, probe_html, probe_error = await asyncio.to_thread(
            _probe_login_page, resolved_login_url, proxy, verify
        )

    auth_row = evaluate_auth_readiness(
        url,
        login_url=clean_login_url,
        auth_user=auth_user,
        auth_pass=auth_pass,
        login_user_field=login_user_field,
        login_pass_field=login_pass_field,
        accounts=accounts,
        accounts_file=accounts_file,
        auto_register=auto_register,
        cookie=cookie,
        bearer=bearer,
        headers=headers,
        target_urls=target_urls,
        access_urls=access_urls,
        auth_configured=auth_configured,
        accounts_configured=accounts_configured,
        probe_status_code=probe_status_code,
        probe_error=probe_error,
        probe_html=probe_html,
    )

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
            elif prerequisite == Prerequisite.AUTH_SESSION:
                if not auth_configured and auth_row["status"] == "not_applicable":
                    rows.append(_check(f"scanner:{check}", "warning", "prerequisite_missing", "This check declares an authenticated session prerequisite."))
                elif auth_row["status"] == "fail":
                    rows.append(_check(f"scanner:{check}", "fail", "prerequisite_missing", "This check declares an authenticated session prerequisite."))
                else:
                    rows.append(_check(f"scanner:{check}", "pass", "available", "This check declares an authenticated session prerequisite."))
            elif prerequisite == Prerequisite.MULTI_ACCOUNT:
                acc_count = len(parse_accounts(accounts, auth_user=auth_user, auth_pass=auth_pass, accounts_file=accounts_file))
                if auto_register or acc_count >= 2:
                    rows.append(_check(f"scanner:{check}", "pass", "available", "This check declares a multiple-account prerequisite."))
                else:
                    rows.append(_check(f"scanner:{check}", "warning", "prerequisite_missing", "This check declares a multiple-account prerequisite."))
            elif prerequisite == Prerequisite.SECOND_REQUEST:
                rows.append(_check(f"scanner:{check}", "pass", "available",
                                   "This check declares a multiple-request prerequisite."))
            elif prerequisite == Prerequisite.OOB_SINK:
                rows.append(_check(f"scanner:{check}", "not_checked", "not_implemented", "OOB readiness is not checked in this increment."))

    rows.append(auth_row)

    try:
        import browser_use  # noqa: F401
        rows.append(_check("agent_transport", "pass", "available", "The agent-mode browser automation backend is importable."))
    except ImportError:
        if agent_mode:
            rows.append(_check("agent_transport", "fail", "dependency_missing", "Agent mode is selected but its browser automation backend is not installed."))
        else:
            rows.append(_check("agent_transport", "warning", "dependency_missing", "The agent-mode browser automation backend is not installed (only needed for agent mode)."))

    ws_row = evaluate_live_channel_readiness(monitor_enabled=monitor_enabled)
    rows.append(ws_row)

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
