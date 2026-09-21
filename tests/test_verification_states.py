import unittest

from wscan.engine import ScanEngine
from wscan.scanners.base import Finding


def _finding(field_name="q"):
    return Finding(
        check_type="sqli",
        severity="critical",
        url="http://fixture.test/search?q=value",
        field_name=field_name,
        payload="'",
        evidence="SQL error",
    )


class _ResultScanner:
    def __init__(self, result):
        self.result = result

    async def verify_finding(self, finding):
        return self.result


class _VerifyOneEngine:
    _verify_one = ScanEngine._verify_one

    def __init__(self, scanner=None):
        self.scanners = {} if scanner is None else {"sqli": scanner}


class _PhaseVerifyEngine:
    _phase_verify = ScanEngine._phase_verify
    _profile = ScanEngine._profile  # WSCAN_PROFILE 計測（既定 no-op・F06/0059）
    _VERIFIABLE_CHECKS = {"sqli"}

    def __init__(self, findings, states):
        self.all_findings = findings
        self.states = states
        self.monitor = None
        self.wave_errors = []

    async def _verify_one(self, finding):
        state = self.states[finding.field_name]
        if isinstance(state, Exception):
            raise state
        return state


class VerificationStateTests(unittest.IsolatedAsyncioTestCase):
    async def test_verify_one_returns_assumed_without_scanner(self):
        engine = _VerifyOneEngine()

        self.assertEqual(await engine._verify_one(_finding()), "assumed")

    async def test_verify_one_returns_reproduced_for_scanner_true(self):
        engine = _VerifyOneEngine(_ResultScanner(True))

        self.assertEqual(await engine._verify_one(_finding()), "reproduced")

    async def test_verify_one_returns_unreproduced_for_scanner_false(self):
        engine = _VerifyOneEngine(_ResultScanner(False))

        self.assertEqual(await engine._verify_one(_finding()), "unreproduced")

    async def _run_fallback_engine(self, mode):
        # scanner verify が失効/transport 失敗で None を返しても、_verify_one は既定で
        # フォールバック再送し 401/空応答を評価して "unreproduced" にしてしまう。json の
        # 失効/transport 失敗時は terminal な "assumed"（penalize しない）にする（Codex #99 R6）。
        # ハーネスは**フォールバックが実際に走る**よう browser 等を備え、fix 無しなら
        # unreproduced を返す（＝有効な回帰テスト）。
        import re as _re

        class _FbBrowser:
            async def navigate(self, url, retries=0):
                return None

            def reset_dialog(self):
                pass

        class _FbScanner:
            CHECK_TYPE = "sqli"

            def __init__(self, engine, mode):
                self.engine = engine
                self.mode = mode

            def _fail(self):
                if self.mode == "auth":
                    self.engine._api_auth_failed = True
                    return "login required", {"response": {"status": 401, "body": "login required"}}
                self.engine._json_probe_failed = True
                return "", {}

            async def verify_finding(self, finding):
                self._fail()
                return None

            async def _apply_ip(self, ip, payload):
                return self._fail()

            def check_response_for_patterns(self, body, patterns):
                return any(_re.search(p, body or "", _re.IGNORECASE) for p in patterns)

        class _FbEngine:
            _verify_one = ScanEngine._verify_one

            def __init__(self, mode):
                self.scanners = {"sqli": _FbScanner(self, mode)}
                self.browser = _FbBrowser()
                self._effective_delay = 0
                self.navigation_retries = 0
                self._api_auth_failed = False
                self._json_probe_failed = False

        finding = Finding(
            check_type="sqli", severity="critical", url="http://h/api/login",
            field_name="email", payload="'", evidence="e",
            injection_location="json_body", injection_pointer="/email",
            injection_method="POST", injection_template_id="t",
        )
        return await _FbEngine(mode)._verify_one(finding)

    async def test_verify_one_false_result_with_transport_failure_is_assumed(self):
        # scanner verify が transport 失敗時に False を返す経路（error-based の空 body・
        # boolean の空 baseline 等）でも、flag が立っていれば結果値より前に assumed にする
        # （「検証リクエストが失敗しただけ」で unreproduced に誤格下げしない。Codex #99 R7）。
        class _FalseWithFailScanner:
            def __init__(self, engine):
                self.engine = engine

            async def verify_finding(self, finding):
                self.engine._json_probe_failed = True
                return False

        engine = _VerifyOneEngine()
        engine.scanners = {"sqli": _FalseWithFailScanner(engine)}
        self.assertEqual(await engine._verify_one(_finding()), "assumed")

    async def test_verify_one_json_auth_failure_is_assumed_not_unreproduced(self):
        self.assertEqual(await self._run_fallback_engine("auth"), "assumed")

    async def test_verify_one_json_transport_failure_is_assumed(self):
        self.assertEqual(await self._run_fallback_engine("transport"), "assumed")

    async def test_phase_verify_applies_all_states_without_dropping_findings(self):
        findings = [
            _finding("reproduced"),
            _finding("assumed"),
            _finding("unreproduced"),
            _finding("skipped"),
        ]
        engine = _PhaseVerifyEngine(
            findings,
            {
                "reproduced": "reproduced",
                "assumed": "assumed",
                "unreproduced": "unreproduced",
                "skipped": RuntimeError("simulated verify crash"),
            },
        )

        await engine._phase_verify()

        reproduced, assumed, unreproduced, skipped = findings
        self.assertTrue(reproduced.verified)
        self.assertEqual(reproduced.verification_state, "reproduced")
        self.assertEqual(reproduced.verification_note, "")

        self.assertFalse(assumed.verified)
        self.assertEqual(assumed.verification_state, "assumed")
        self.assertEqual(assumed.verification_note, "")

        self.assertFalse(unreproduced.verified)
        self.assertEqual(unreproduced.verification_state, "unreproduced")
        self.assertIn("再現できませんでした", unreproduced.verification_note)

        self.assertFalse(skipped.verified)
        self.assertEqual(skipped.verification_state, "skipped")
        self.assertIn("要手動確認", skipped.verification_note)
        self.assertEqual(len(engine.all_findings), 4)


    async def test_phase_verify_bounds_hanging_verify_one(self):
        # 1 件の _verify_one が返らなくても verify フェーズは有界時間で完了し、その finding は
        # "skipped"（未検証・要手動確認）として保持される（reproduced に上げない・削除しない）。F06/0059。
        import asyncio
        from unittest.mock import patch
        import wscan.engine as engine_mod

        class _HangEngine:
            _phase_verify = ScanEngine._phase_verify
            _profile = ScanEngine._profile
            _VERIFIABLE_CHECKS = {"sqli"}

            def __init__(self, findings):
                self.all_findings = findings
                self.monitor = None
                self.wave_errors = []

            async def _verify_one(self, finding):
                await asyncio.sleep(10)   # patch した上限より十分長い＝返らない相当
                return "reproduced"

        f = _finding("hang")
        engine = _HangEngine([f])
        with patch.object(engine_mod, "_VERIFY_ONE_TIMEOUT_S", 0.05):
            await engine._phase_verify()

        self.assertFalse(f.verified)
        self.assertEqual(f.verification_state, "skipped")   # timeout→未検証で保持
        self.assertEqual(len(engine.all_findings), 1)       # 削除しない
        self.assertTrue(any("verify:" in e for e in engine.wave_errors))  # 記録は残す


if __name__ == "__main__":
    unittest.main()


class _FakeRecoverBrowser:
    """recover_page 呼び出しを数える最小 browser（Codex #171 P1/P2 検証用）。"""
    def __init__(self, timeout_ms=0):
        self.timeout = timeout_ms
        self.recover_calls = 0
        self._needs_page_recovery = False

    async def recover_page(self):
        self.recover_calls += 1
        self._needs_page_recovery = False
        return True


class PhaseVerifyRecoveryTests(unittest.IsolatedAsyncioTestCase):
    async def test_recover_page_called_after_verify_timeout(self):
        # _verify_one が timeout したら、次 finding の前に共有ページを作り直す（#171 P1）。
        import asyncio
        from unittest.mock import patch
        import wscan.engine as engine_mod

        class _Eng:
            _phase_verify = ScanEngine._phase_verify
            _profile = ScanEngine._profile
            _VERIFIABLE_CHECKS = {"sqli"}
            def __init__(self, findings, browser):
                self.all_findings = findings
                self.monitor = None
                self.wave_errors = []
                self.browser = browser
            async def _verify_one(self, finding):
                await asyncio.sleep(10)   # budget 超過＝返らない相当
                return "reproduced"

        f = _finding("hang")
        browser = _FakeRecoverBrowser(timeout_ms=0)   # req_to=0 → budget=_VERIFY_ONE_TIMEOUT_S
        eng = _Eng([f], browser)
        with patch.object(engine_mod, "_VERIFY_ONE_TIMEOUT_S", 0.05):
            await eng._phase_verify()
        self.assertEqual(f.verification_state, "skipped")
        self.assertGreaterEqual(browser.recover_calls, 1)   # timeout 後に回復

    async def test_verify_budget_derives_from_request_timeout(self):
        # 固定 180s ではなく request timeout ×6 を確保するので、小さく patch した
        # _VERIFY_ONE_TIMEOUT_S を超える所要でも browser.timeout 由来の budget 内なら
        # 完了して skipped にならない（#171 P2）。
        import asyncio
        from unittest.mock import patch
        import wscan.engine as engine_mod

        class _Eng:
            _phase_verify = ScanEngine._phase_verify
            _profile = ScanEngine._profile
            _VERIFIABLE_CHECKS = {"sqli"}
            def __init__(self, findings, browser):
                self.all_findings = findings
                self.monitor = None
                self.wave_errors = []
                self.browser = browser
            async def _verify_one(self, finding):
                await asyncio.sleep(0.1)   # 0.05 は超えるが 600 budget 内
                return "reproduced"

        f = _finding("slow")
        browser = _FakeRecoverBrowser(timeout_ms=100000)  # 100s → budget=max(0.05,600)=600
        eng = _Eng([f], browser)
        with patch.object(engine_mod, "_VERIFY_ONE_TIMEOUT_S", 0.05):
            await eng._phase_verify()
        self.assertEqual(f.verification_state, "reproduced")   # budget 由来で cancel されない
        self.assertEqual(browser.recover_calls, 0)


if __name__ == "__main__":
    unittest.main()
