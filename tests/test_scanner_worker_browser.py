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
