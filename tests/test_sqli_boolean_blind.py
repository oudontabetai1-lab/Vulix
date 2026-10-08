"""boolean-based blind SQLi 判定 `_boolean_blind_divergence` の回帰テスト。

見逃し（false negative）再現: 実アプリは共有レイアウト（ヘッダ/ナビ/フッタ）を持つため、
真偽で本文が明確に変わっても全体の SequenceMatcher 比率は高止まりする。旧ロジックは
「false の絶対類似度 <=0.80」を必須にしていたため、healthcare フィクスチャ
``/pharmacy/refill`` の boolean-blind（false が 360B 短いのに比率 0.8973）を取りこぼしていた
（E2E の KNOWN_DETECTION_GAPS 記載の high 難度ケース）。

本修正は「true が baseline を追従し false がそれより乖離する」相対ギャップを追加した加算的
変更で、既存の受理集合（<=0.80 の天井）を包含する。検知・検証の双方が同じ純粋関数を通る。

誤検知ガード: 安全ツイン ``/pharmacy/catalog``（パラメータ化）は真偽で長さがほぼ不変で、
長さ乖離の段で落ちる（類似度条件を緩めても陽性化しない）ことを固定する。
"""
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

import httpx

from tests.fixtures.realistic_healthcare import create_app
from wscan.injection_point import InjectionPoint
from wscan.scanners.sqli import (
    SQLiScanner,
    _BOOLEAN_SIM_GAP,
    _boolean_blind_divergence,
)

# ブラウザ/engine 非依存でスキャナの純粋メソッド（_body_similarity/_normalise_body）を使う。
_SIM = SQLiScanner.__new__(SQLiScanner)


class BooleanBlindDivergenceUnitTests(unittest.TestCase):
    """純粋関数単体。実測値（/pharmacy/refill）を回帰アンカーに固定する。"""

    # healthcare /pharmacy/refill の実測: base=2105, true=2105, false=1745, var=0,
    # sim_true=1.0, sim_false=0.8973。
    SHARED_CHROME = dict(
        baseline_len=2105, baseline_variance=0,
        true_len=2105, false_len=1745,
        sim_true_base=1.0, sim_false_base=0.8973,
        baseline_status=200, true_status=200, false_status=200,
    )

    def test_shared_chrome_case_is_detected(self):
        # 本修正の主眼: 共有レイアウトで sim_false が天井(0.80)超でも検知する。
        self.assertTrue(_boolean_blind_divergence(**self.SHARED_CHROME))

    def test_middleware_status_rejects_relative_gap(self):
        for status in (302, 403, 429, 500, 503, None):
            with self.subTest(false_status=status):
                values = {**self.SHARED_CHROME, "false_status": status,
                          "sim_false_base": 0.94}
                self.assertFalse(_boolean_blind_divergence(**values))

    def test_relative_gap_requires_baseline_and_true_status(self):
        for field in ("baseline_status", "true_status"):
            for status in (None, 302, 403, 500):
                with self.subTest(field=field, status=status):
                    self.assertFalse(_boolean_blind_divergence(
                        **{**self.SHARED_CHROME, field: status}))

    def test_legacy_ceiling_accepts_error_status(self):
        self.assertTrue(_boolean_blind_divergence(
            **{**self.SHARED_CHROME, "sim_false_base": 0.75,
               "false_status": 429}))

    def test_old_ceiling_alone_would_have_missed_it(self):
        # 旧ロジック（<=0.80 の天井のみ）はこのケースを veto していた＝見逃しの再現。
        self.assertGreater(self.SHARED_CHROME["sim_false_base"], 0.80)

    def test_legacy_absolute_ceiling_still_accepted(self):
        # 既存の受理集合（false が絶対的に非類似）は引き続き陽性（加算的＝回帰なし）。
        self.assertTrue(_boolean_blind_divergence(
            baseline_len=2000, baseline_variance=0,
            true_len=2000, false_len=1000,
            sim_true_base=0.98, sim_false_base=0.55,
        ))

    def test_parameterized_safe_rejected_by_length_guard(self):
        # 安全/パラメータ化: 真偽で長さがほぼ不変 → 長さ乖離の段で falsy（誤検知なし）。
        self.assertFalse(_boolean_blind_divergence(
            baseline_len=1766, baseline_variance=0,
            true_len=1770, false_len=1768,
            sim_true_base=0.994, sim_false_base=0.994,
        ))

    def test_high_variance_dynamic_content_rejected(self):
        # 自然変動が大きい（広告/タイムスタンプ等）と閾値が上がり、長さ差では陽性化しない。
        self.assertFalse(_boolean_blind_divergence(
            baseline_len=5000, baseline_variance=300,  # min_threshold=1200
            true_len=5000, false_len=4100,            # diff_false=900 < 1200
            sim_true_base=1.0, sim_false_base=0.80,
        ))

    def test_true_not_tracking_baseline_rejected(self):
        # true が baseline に似ていない（<0.85）なら boolean-blind と見なさない。
        self.assertFalse(_boolean_blind_divergence(
            baseline_len=2105, baseline_variance=0,
            true_len=2105, false_len=1745,
            sim_true_base=0.70, sim_false_base=0.50,
        ))

    def test_small_gap_and_high_false_sim_rejected(self):
        # 長さは乖離するが true/false がともに baseline へ同程度に類似（ギャップ小・天井超）
        # なら陽性化しない（真偽の非対称が無い＝別ページ差し替え等の誤検知を避ける）。
        gap = _BOOLEAN_SIM_GAP / 2
        self.assertFalse(_boolean_blind_divergence(
            baseline_len=2000, baseline_variance=0,
            true_len=2000, false_len=1700,
            sim_true_base=0.90, sim_false_base=0.90 - gap,
        ))


class BooleanBlindFixtureIntegrationTests(unittest.IsolatedAsyncioTestCase):
    """実フィクスチャ応答＋スキャナ実 `_body_similarity` で判定を駆動する統合回帰。"""

    async def asyncSetUp(self):
        self.transport = httpx.ASGITransport(app=create_app())
        self.client = httpx.AsyncClient(
            transport=self.transport,
            base_url="http://portal.cedarvalley.test",
            follow_redirects=False,
        )

    async def asyncTearDown(self):
        await self.client.aclose()

    async def _divergence(self, path: str, field: str, true_p: str, false_p: str) -> bool:
        base_response = await self.client.get(path, params={field: "baseline_test"})
        base = base_response.text
        base2 = (await self.client.get(path, params={field: "baseline_test"})).text
        true_response = await self.client.get(path, params={field: true_p})
        false_response = await self.client.get(path, params={field: false_p})
        true_src, false_src = true_response.text, false_response.text
        return _boolean_blind_divergence(
            len(base),
            abs(len(base) - len(base2)),
            len(true_src),
            len(false_src),
            _SIM._body_similarity(true_src, base),
            _SIM._body_similarity(false_src, base),
            base_response.status_code, true_response.status_code, false_response.status_code,
        )

    async def test_vulnerable_refill_is_detected(self):
        # 数値ペア（フィクスチャの真偽評価が確実に分岐する）で検知できること。
        for true_p, false_p in (("1 AND 1=1", "1 AND 1=2"), ("1) AND (1=1", "1) AND (1=2")):
            with self.subTest(pair=(true_p, false_p)):
                self.assertTrue(
                    await self._divergence("/pharmacy/refill", "rx", true_p, false_p),
                    "boolean-blind SQLi /pharmacy/refill を検知できない（見逃し回帰）",
                )

    async def test_safe_catalog_twin_is_not_detected(self):
        for true_p, false_p in (("1 AND 1=1", "1 AND 1=2"), ("1) AND (1=1", "1) AND (1=2")):
            with self.subTest(pair=(true_p, false_p)):
                self.assertFalse(
                    await self._divergence("/pharmacy/catalog", "drug", true_p, false_p),
                    "安全ツイン /pharmacy/catalog を誤検知した（false positive）",
                )

    async def test_safe_billing_history_twin_is_not_detected(self):
        for true_p, false_p in (("1 AND 1=1", "1 AND 1=2"), ("1) AND (1=1", "1) AND (1=2")):
            with self.subTest(pair=(true_p, false_p)):
                self.assertFalse(
                    await self._divergence("/billing/history", "sort", true_p, false_p),
                    "安全ツイン /billing/history を誤検知した（false positive）",
                )


class SQLiDetectionMatrixTests(unittest.IsolatedAsyncioTestCase):
    """通信応答 double で主要3経路×3入力面の検知・Finding・再検証を固定する。"""

    async def test_detection_and_verification_matrix(self):
        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=create_app()), base_url="http://test"
        ) as client:
            bodies = {
                p: (await client.get("/pharmacy/refill", params={"rx": p})).text
                for p in ("baseline_test", "1 AND 1=1", "1 AND 1=2")
            }
        url = "http://test/pharmacy/refill?rx=1"
        points = (
            InjectionPoint.for_url_param(url, "rx"),
            InjectionPoint.for_form(url, "rx", 0),
            InjectionPoint.for_json_body("POST", url, "/rx", template_id="refill"),
        )
        for ip in points:
            for kind, payload in (
                ("boolean", "1 AND 1=1"), ("boolean", "1 AND 1=2"), ("error", "'"), ("time", "1' AND SLEEP(3)--"),
            ):
                for vulnerable in (True, False, "middleware"):
                    with self.subTest(location=ip.location, kind=kind, vulnerable=vulnerable):
                        engine = SimpleNamespace(
                            browser=SimpleNamespace(screenshot_b64=AsyncMock(return_value="")),
                            monitor=None, payload_gen=None, sleep_factor=0,
                            _finding_dedup=set(), all_findings=[],
                            injection_templates={"refill": {"json_body": {"rx": "1"}}},
                        )
                        scanner = SQLiScanner(engine)
                        scanner.get_payloads = AsyncMock(return_value=[payload])
                        scanner.log_payload_test = AsyncMock()
                        scanner.evolved_payloads = AsyncMock(return_value=[])
                        scanner.mutated_payloads = AsyncMock(return_value=[])
                        scanner.run_equivalence_probe = AsyncMock(return_value=None)

                        false_status = 429 if vulnerable == "middleware" else 200

                        async def respond(point, value, **kwargs):
                            self.assertEqual(point.location, ip.location)
                            body = bodies["baseline_test"]
                            elapsed = 0.1
                            if vulnerable:
                                if kind == "boolean":
                                    body = bodies.get(value, body)
                                elif kind == "error" and value == payload:
                                    body = "SQLite error: unrecognized token"
                                elif kind == "time" and value == payload:
                                    elapsed = 3.2
                            return body, {
                                "request": {"timestamp": 1},
                                "response": {"timestamp": 1 + elapsed, "body": body,
                                             "status": false_status if kind == "boolean" and value == "1 AND 1=2" else 200},
                            }

                        scanner._apply_ip = AsyncMock(side_effect=respond)
                        findings = await scanner.scan_injection_point(ip, {"name": "rx"})
                        expected = bool(vulnerable) and not (kind == "boolean" and vulnerable == "middleware")
                        self.assertEqual(len(findings), int(expected))
                        if expected:
                            finding = findings[0]
                            self.assertEqual(finding.evidence_type, "sqli_" + kind)
                            self.assertEqual(finding.injection_location, ip.location)
                            self.assertTrue(await scanner.verify_finding(finding))
                            self.assertIn(finding, engine.all_findings)
                            if kind == "boolean":
                                false_status = 429
                                self.assertFalse(await scanner.verify_finding(finding))
                        self.assertTrue(scanner.log_payload_test.await_count)


if __name__ == "__main__":
    unittest.main()
