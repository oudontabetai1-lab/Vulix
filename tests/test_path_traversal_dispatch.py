"""0035-D1: path_traversal が typed dispatch() 経由でも従来判定と同一であることを守る。"""
import unittest
from unittest.mock import AsyncMock

from wscan.dispatch_result import DispatchResult, DispatchState
from wscan.scanner_contract import Carrier
from wscan.scanners.path_traversal import PathTraversalScanner
from tests.test_baseline_and_timing_guards import _DummyEngine

URL = "http://fixture.test/page?file=a"
HIT = ("root:x:0:0:root:/root:/bin/bash", {"response": {"body": "root:x:0:0"}})
SAFE = ("Documentation for baseline_test_value", {"response": {"body": "doc"}})


def _scanner(payload_side_effect):
    s = PathTraversalScanner(_DummyEngine())
    s.get_payloads = AsyncMock(return_value=["../../etc/passwd"])
    s._apply_payload = AsyncMock(side_effect=payload_side_effect)
    return s


class PathTraversalDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_goes_through_dispatch(self):
        s = _scanner([SAFE, HIT])
        real = s.dispatch
        s.dispatch = AsyncMock(side_effect=real)
        await s.scan_field(URL, 0, {"name": "file"}, is_url_param=True)
        self.assertEqual(s.dispatch.await_count, 2)  # baseline + payload

    async def test_vulnerable_twin_detected(self):
        f = await _scanner([SAFE, HIT]).scan_field(URL, 0, {"name": "file"}, is_url_param=True)
        self.assertEqual(len(f), 1)

    async def test_safe_twin_not_detected(self):
        f = await _scanner([SAFE, SAFE]).scan_field(URL, 0, {"name": "file"}, is_url_param=True)
        self.assertEqual(f, [])

    async def test_transport_exception_still_propagates(self):
        # dispatch は例外を no-match に丸めない（従来の _apply_ip と同じ伝播）。
        s = _scanner([SAFE, RuntimeError("boom")])
        with self.assertRaises(RuntimeError):
            await s.scan_injection_point(_ip(), {"name": "file"})

    async def test_non_sent_body_kept_as_legacy(self):
        # pair 空でも本文があれば TRANSPORT_ERROR 分類で source が保持され、判定に使われる。
        s = _scanner([("Documentation for baseline_test_value", {}), HIT])
        f = await s.scan_field(URL, 0, {"name": "file"}, is_url_param=True)
        self.assertEqual(len(f), 1)

    async def test_blocked_result_is_skipped_not_matched(self):
        # BLOCKED/UNSUPPORTED は ("", {}) 相当＝マッチ無し（finding を出さず送信もしない）。
        s = _scanner([])
        s.dispatch = AsyncMock(
            return_value=DispatchResult(state=DispatchState.BLOCKED, carrier=Carrier.QUERY)
        )
        f = await s.scan_field(URL, 0, {"name": "file"}, is_url_param=True)
        self.assertEqual(f, [])
        s._apply_payload.assert_not_called()


def _ip():
    from wscan.injection_point import InjectionPoint
    return InjectionPoint.for_url_param(URL, "file")
