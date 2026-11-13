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
