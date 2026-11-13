"""共有scannerの操作先が呼び出しタスクのworkerと一致することを保証する。"""
import asyncio

from wscan.engine import ScanEngine, _CURRENT_WORKER
from wscan.scanners.xss import XSSScanner


def test_shared_scanner_resolves_worker_and_isolates_browser_override():
    engine = ScanEngine.__new__(ScanEngine)
    engine._browser = object()
    engine.monitor = engine.payload_gen = None
    scanner = XSSScanner(engine)

    async def run():
        entered = 0
        ready = asyncio.Event()

        async def worker():
            nonlocal entered
            browser = object()
            token = _CURRENT_WORKER.set(browser)
            try:
                assert scanner.browser is browser
                override = object()
                scope = scanner._browser_override.set(override)
                entered += 1
                if entered == 3:
                    ready.set()
                await ready.wait()
                assert scanner.browser is override
                scanner._browser_override.reset(scope)
                assert scanner.browser is browser
            finally:
                _CURRENT_WORKER.reset(token)

        await asyncio.gather(*(worker() for _ in range(3)))
        assert scanner.browser is engine._browser
        # 明示的な差替えを使う既存callerの契約も維持する。
        override = object()
        scanner.browser = override
        assert scanner.browser is override

    asyncio.run(run())
    assert scanner.browser is engine._browser


def test_failed_probe_leaves_only_affected_parallel_unit_incomplete(tmp_path):
    from unittest.mock import AsyncMock
    from wscan.injection_point import InjectionPoint

    engine = ScanEngine(
        "http://fixture.test/private", login_url="http://fixture.test/login",
        checks=["xss"], llm_provider="none", output_dir=str(tmp_path),
        open_report=False, enable_ai_analysis=False, enable_waf_detection=False,
        enable_payload_learning=False, enable_adaptive_payloads=False,
    )
    engine._init_checkpoint()
    scanner = engine.scanners["xss"]

    async def send(ip, *args, **kwargs):
        await asyncio.sleep(0)
        return "Authentication required" if ip.url.endswith("/lost") else "Safe", {
            "response": {"status": 401 if ip.url.endswith("/lost") else 200}}

    scanner._send_probe = AsyncMock(side_effect=send)

    async def check(ip, field):
        await scanner._apply_ip(ip, "probe")
        return []

    scanner.scan_injection_point = check

    async def run():
        await asyncio.gather(*(engine._scan_field(
            f"http://fixture.test/{path}", 0, {"name": "q", "type": "text"})
            for path in ("lost", "valid")))

    asyncio.run(run())
    for path, status, done in (("lost", "error", False), ("valid", "tested", True)):
        url = f"http://fixture.test/{path}"
        row = next(r for r in engine.scan_matrix if r["url"] == url)
        assert row["status"] == status
        assert engine.checkpoint.is_done_ip(InjectionPoint.for_form(url, "q", 0), "xss") is done

    scanner._send_probe = AsyncMock(return_value=("Authentication required", {"response": {"status": 401}}))
    asyncio.run(scanner._apply_ip(InjectionPoint.for_form(
        "http://fixture.test/lost?token=dummy-secret", "q", 0), "probe"))
    assert not any("dummy-secret" in note for note in engine.wave_errors)


def test_input_401_checks_same_session_once_and_valid_twin_finishes(tmp_path):
    from unittest.mock import AsyncMock
    from wscan.injection_point import InjectionPoint

    for status, expected in ((200, "tested"), (401, "error"), (503, "error")):
        engine = ScanEngine("http://fixture.test/private", login_url="http://fixture.test/login",
                            checks=["xss"], llm_provider="none", output_dir=str(tmp_path / str(status)),
                            enable_adaptive_payloads=False, enable_payload_learning=False)
        engine._init_checkpoint()
        engine._authentication_probe_url = engine.target_url
        engine._protected_resource_response = AsyncMock(return_value=(status, "Private page", False))
        scanner = engine.scanners["xss"]
        scanner._send_probe = AsyncMock(return_value=("Invalid input", {"response": {"status": 401}}))

        async def scan(ip, field):
            await scanner._apply_ip(ip, "wrong-code")
            return []

        scanner.scan_injection_point = scan
        url = "http://fixture.test/api/token"
        asyncio.run(engine._scan_field(url, 0, {"name": "code", "type": "text"}))
        engine._protected_resource_response.assert_awaited_once_with(engine.target_url, browser=engine.browser)
        assert engine.scan_matrix[-1]["status"] == expected
        assert engine.checkpoint.is_done_ip(InjectionPoint.for_form(url, "code", 0), "xss") is (status == 200)


def test_incomplete_retry_limit_survives_resume_and_keeps_gap(tmp_path):
    from unittest.mock import AsyncMock
    from wscan.injection_point import InjectionPoint

    previous = None
    calls = []
    url = "http://fixture.test/private"
    ip = InjectionPoint.for_form(url, "q", 0)
    for attempt in range(4):
        engine = ScanEngine(url, checks=["xss"], llm_provider="none",
                            output_dir=str(tmp_path / str(attempt)), resume_dir=previous,
                            enable_payload_learning=False, enable_adaptive_payloads=False)
        engine._field_budget_retry_limit = 1
        engine._init_checkpoint()
        scanner = engine.scanners["xss"]

        async def scan(ip, field):
            calls.append(attempt)
            scanner._probe_failure("authentication_lost")
            return []

        scanner.scan_injection_point = scan
        asyncio.run(engine._scan_field(url, 0, {"name": "q", "type": "text"}))
        engine._save_checkpoint()
        previous = engine.output_dir
        assert not engine.checkpoint.is_done_ip(ip, "xss")
        assert engine.scan_matrix[-1]["status"] == "error"
        if attempt >= 1:
            assert "retry limit" in engine.scan_matrix[-1]["note"].lower()
    assert calls == [0, 1]
    assert engine.checkpoint.is_truncation_exhausted_ip(ip, "xss:probe")


def test_bearer_get_input_401_preserves_valid_token_and_confirms_once(tmp_path):
    from unittest.mock import AsyncMock, Mock
    import httpx
    from wscan.engine import _store_synced_token
    from wscan.injection_point import InjectionPoint

    engine = ScanEngine("http://fixture.test/private", checks=["xss"], llm_provider="none",
                        output_dir=str(tmp_path), enable_payload_learning=False)
    engine._authentication_probe_url = engine.target_url
    engine._protected_resource_response = AsyncMock(return_value=(200, "Private page", False))
    engine.clear_synced_token = Mock()
    engine._api_auth_failed = False
    _store_synced_token(engine, engine.target_url, {"Authorization": "Bearer dummy-token"})
    requests = []

    def reject(request):
        requests.append(request)
        return httpx.Response(401, text="Invalid input")

    engine.httpx_client_kwargs = lambda **kw: {**kw, "transport": httpx.MockTransport(reject)}
    scanner = engine.scanners["xss"]
    ip = InjectionPoint.for_url_param("http://fixture.test/api/token?code=1", "code", source="spa")
    source, pair = asyncio.run(scanner._apply_ip(ip, "invalid"))
    assert source == "Invalid input" and pair["response"]["status"] == 401
    assert requests[0].headers["Authorization"] == "Bearer dummy-token"
    assert not engine._api_auth_failed
    engine.clear_synced_token.assert_not_called()
    engine._protected_resource_response.assert_awaited_once_with(engine.target_url, browser=engine.browser)
    assert not pair.get("_authentication_lost")
