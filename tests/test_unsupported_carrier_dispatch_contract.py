"""未サポート carrier を discrete な coverage レコード（scan note + attempt ledger）として記録し、未実行理由を保持する契約の回帰テスト。

契約:
- scanner が当該 carrier を supported と宣言していない場合（例: OpenRedirectScanner に対する JSON body、
  SSTIScanner / PathTraversalScanner に対する未接続 carrier 等）:
  - typed dispatch() は DispatchState.UNSUPPORTED を返し、_apply_ip / ネットワーク送信を行わない。
  - 理由と対象 InjectionPoint の識別子（parameter_id / carrier）を coverage（wave_errors 観測ノートおよび attempt_ledger）へ記録する。
  - 偽陰性（0 Finding）として黙って握りつぶされず、離散的な coverage 記録（DispatchResult(state=UNSUPPORTED, carrier=carrier, note=reason)）として保持する。
  - supported な query/form twin に対しては正常に probe が送信され、脆弱ツインなら Finding、安全ツインなら 0 Finding となる。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from wscan.attempt_ledger import AttemptLedger
from wscan.dispatch_result import DispatchResult, DispatchState
from wscan.injection_point import InjectionPoint
from wscan.scanner_contract import Carrier, CapabilityState
from wscan.scanners.ssti import SSTIScanner, SSTI_PROBES
from wscan.scanners.path_traversal import PathTraversalScanner
from wscan.scanners.open_redirect import OpenRedirectScanner

URL = "http://fixture.test/app"
_EXP = SSTI_PROBES[0][1]


def _vuln_ssti_apply(url, fi, name, payload, is_url):
    if payload == SSTI_PROBES[0][0]:
        return f"result {_EXP}", {"response": {"status": 200, "body": _EXP}}
    return "plain page", {"response": {"status": 200, "body": "plain"}}


def _safe_ssti_apply(url, fi, name, payload, is_url):
    return "plain page", {"response": {"status": 200, "body": "plain"}}


class _DummyBrowser:
    async def screenshot_b64(self, label=""):
        return ""


def _make_engine():
    return SimpleNamespace(
        browser=_DummyBrowser(),
        monitor=None,
        payload_gen=None,
        state_profile="unrestricted",
        wave_errors=[],
        attempt_ledger=AttemptLedger(),
        all_findings=[],
        _finding_dedup=set(),
    )


class UnsupportedCarrierDispatchContractTests(unittest.IsolatedAsyncioTestCase):
    async def test_unsupported_carrier_records_coverage_and_does_not_send(self):
        """unsupported carrier（OpenRedirectScanner の JSON body、SSTIScanner の未接続 carrier）
        に対して dispatch() は DispatchState.UNSUPPORTED を返し、reason を note に保持し、
        wave_errors 観測ノートと attempt_ledger へ離散記録を残し、送信プリミティブを一切呼ばない。"""
        engine = _make_engine()
        scanner = OpenRedirectScanner(engine)
        json_ip = InjectionPoint.for_json_body("POST", f"{URL}/login", "/redirect_to")
        self.assertEqual(json_ip.carrier, Carrier.JSON)

        # CONTRACT の capability を確認
        cap = scanner.CONTRACT.capability(Carrier.JSON)
        self.assertIsNotNone(cap)
        self.assertNotEqual(cap.state, CapabilityState.SUPPORTED)
        expected_reason = cap.reason

        # dispatch 実行
        result = await scanner.dispatch(json_ip, "http://evil.com")

        self.assertIsInstance(result, DispatchResult)
        self.assertEqual(result.state, DispatchState.UNSUPPORTED)
        self.assertEqual(result.carrier, Carrier.JSON)
        self.assertEqual(result.note, expected_reason)
        self.assertFalse(result.sent)
        self.assertFalse(result.has_response)
        self.assertEqual(result.source, "")
        self.assertEqual(result.pair, {})

        # coverage 記録の検証: wave_errors に記録されている
        notes = [n for n in engine.wave_errors if n.startswith("carrier_unsupported:open_redirect:json")]
        self.assertEqual(len(notes), 1)
        self.assertIn("/redirect_to", notes[0])
        self.assertIn(expected_reason, notes[0])

        # attempt_ledger にも離散記録が残っている
        history = engine.attempt_ledger.history(json_ip.stable_key_parts(), scanner.CHECK_TYPE)
        self.assertEqual(len(history), 1)
        self.assertEqual(history[0].payload, "[unsupported]")
        self.assertTrue(history[0].error)

    async def test_caller_receives_unsupported_result_and_preserves_coverage_accounting(self):
        """実本番 caller（scan_injection_point）経由で unsupported carrier が渡された際、
        送信せずに coverage 記録が残り、誤った Finding を出さないことを実 dispatch 経由で証明する。"""
        engine = _make_engine()
        scanner = SSTIScanner(engine)
        scanner._apply_payload = AsyncMock(side_effect=_vuln_ssti_apply)

        # SSTI に未対応 carrier の InjectionPoint を作成（location='form' で carrier=Carrier.FORM は supported だが、
        # 未接続 carrier をシミュレートするため CONTRACT 上 unsupported/planned な carrier を持つ InjectionPoint を用意）
        dummy_ip = SimpleNamespace(
            carrier=Carrier.XML,
            url=f"{URL}/api",
            parameter_id="template_node",
            display_name="template_node",
            form_index=0,
            location="form",
            stable_key_parts=lambda: (f"{URL}/api", "template_node", "0", "f", ""),
        )

        findings = await scanner.scan_injection_point(dummy_ip, {"name": "template_node"})
        self.assertEqual(findings, [])
        scanner._apply_payload.assert_not_called()

        # wave_errors に carrier_unsupported が記録されている
        notes = [n for n in engine.wave_errors if n.startswith("carrier_unsupported:ssti:xml")]
        self.assertEqual(len(notes), 1)
        self.assertIn("template_node", notes[0])

    async def test_supported_carrier_twins_execute_and_distinguish_vulnerable_and_safe(self):
        """supported な query / form carrier twin は実際に送信され、脆弱ツインを検出し安全ツインを誤検知しない。"""
        query_ip = InjectionPoint.for_url_param(f"{URL}?q=1", "q")
        self.assertEqual(query_ip.carrier, Carrier.QUERY)

        # 脆弱ツイン
        vuln_scanner = SSTIScanner(_make_engine())
        vuln_scanner._apply_payload = AsyncMock(side_effect=_vuln_ssti_apply)
        findings = await vuln_scanner.scan_injection_point(query_ip, {"name": "q"})
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0].field_name, "q")
        self.assertEqual(findings[0].confidence, "confirmed")

        # 安全ツイン
        safe_scanner = SSTIScanner(_make_engine())
        safe_scanner._apply_payload = AsyncMock(side_effect=_safe_ssti_apply)
        safe_findings = await safe_scanner.scan_injection_point(query_ip, {"name": "q"})
        self.assertEqual(safe_findings, [])

    async def test_path_traversal_supported_twin_and_unsupported_coverage(self):
        """PathTraversalScanner において supported query twin と unsupported carrier の coverage 記録を検証。"""
        engine = _make_engine()
        pt_scanner = PathTraversalScanner(engine)
        pt_scanner._apply_payload = AsyncMock(return_value=("root:x:0:0", {"response": {"status": 200}}))

        # GraphQL は非 supported
        graphql_ip = SimpleNamespace(
            carrier=Carrier.GRAPHQL,
            url=URL,
            parameter_id="query_field",
            display_name="query_field",
            stable_key_parts=lambda: (URL, "query_field", "0", "u", ""),
        )
        res = await pt_scanner.dispatch(graphql_ip, "test")
        self.assertEqual(res.state, DispatchState.UNSUPPORTED)
        self.assertEqual(res.carrier, Carrier.GRAPHQL)
        pt_scanner._apply_payload.assert_not_called()

        # wave_errors に記録あり
        notes = [n for n in engine.wave_errors if n.startswith("carrier_unsupported:path_traversal:graphql")]
        self.assertEqual(len(notes), 1)

        # Supported query twin
        query_ip = InjectionPoint.for_url_param(f"{URL}?file=test", "file")
        res_query = await pt_scanner.dispatch(query_ip, "test")
        self.assertEqual(res_query.state, DispatchState.SENT)
        self.assertEqual(res_query.carrier, Carrier.QUERY)
        self.assertEqual(pt_scanner._apply_payload.await_count, 1)
