"""0035-D1: ssti が typed dispatch() 経由でも従来判定と同一であることを守る。"""
import unittest
from unittest.mock import AsyncMock

from wscan.dispatch_result import DispatchResult, DispatchState
from wscan.injection_point import InjectionPoint
from wscan.scanner_contract import Carrier
from wscan.scanners.ssti import SSTIScanner, SSTI_PROBES
from tests.test_baseline_and_timing_guards import _DummyEngine

URL = "http://fixture.test/page?q=a"
_EXP = SSTI_PROBES[0][1]


def _vuln(url, fi, name, payload, is_url):
    if payload == SSTI_PROBES[0][0]:
        return f"result {_EXP}", {"response": {"body": _EXP}}
    return "plain page", {"response": {"body": "plain"}}


def _safe(url, fi, name, payload, is_url):
    return "plain page", {"response": {"body": "plain"}}


def _scanner(fn):
    s = SSTIScanner(_DummyEngine())
    s.get_payloads = AsyncMock(return_value=["; id"])
    s._apply_payload = AsyncMock(side_effect=fn)
    return s


def _ip():
    return InjectionPoint.for_url_param(URL, "q")


class SSTIScannerDispatchTests(unittest.IsolatedAsyncioTestCase):
    async def test_scan_goes_through_dispatch(self):
        s = _scanner(_vuln)
        real = s.dispatch
        s.dispatch = AsyncMock(side_effect=real)
        await s.scan_injection_point(_ip(), {"name": "q"})
        self.assertGreaterEqual(s.dispatch.await_count, 2)  # baseline + payload

    async def test_vulnerable_twin_detected(self):
        f = await _scanner(_vuln).scan_injection_point(_ip(), {"name": "q"})
        self.assertEqual(len(f), 1)

    async def test_safe_twin_not_detected(self):
        f = await _scanner(_safe).scan_injection_point(_ip(), {"name": "q"})
        self.assertEqual(f, [])

    async def test_transport_exception_propagation_unchanged(self):
        def boom(url, fi, name, payload, is_url):
            if payload != "wscan_ssti_baseline":
                raise RuntimeError("boom")
            return "plain", {"response": {"body": "p"}}
        with self.assertRaises(RuntimeError):
            await _scanner(boom).scan_injection_point(_ip(), {"name": "q"})

    async def test_non_sent_body_kept_as_legacy(self):
        # pair 空でも本文があれば source が保持され判定に使われる（baseline 空 pair でも検出）。
        f = await _scanner(lambda *a: (_vuln(*a)[0], {})).scan_injection_point(
            _ip(), {"name": "q"}
        )
        self.assertEqual(len(f), 1)

    async def test_blocked_result_is_no_match(self):
        s = _scanner(_vuln)
        s.dispatch = AsyncMock(
            return_value=DispatchResult(state=DispatchState.BLOCKED, carrier=Carrier.QUERY)
        )
        f = await s.scan_injection_point(_ip(), {"name": "q"})
        self.assertEqual(f, [])
        s._apply_payload.assert_not_called()
