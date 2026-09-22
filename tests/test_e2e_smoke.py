"""高速 E2E スモーク（CI ブロッキング）。

full E2E（``test_end_to_end_scan.py``・1スキャン最大 900s）は重く nightly 専用だが、
crawl→plan→attack→verify の実ブラウザ経路が「通しで完走し基本脆弱性を1件検出する」ことは
**PR 毎に**確かめたい（F06/0059 のような通し停止・クラッシュ回帰を検知するため）。

最小フィクスチャ ``vuln_app`` の反射 XSS（``/search?q=``）に対して XSS スキャンを1本走らせ、
tight な上限内に完走し XSS を検出することだけを確認する軽量スモーク。

CI では ``WSCAN_E2E=1`` + Chromium 有りで **ブロッキング** 実行する。Chromium が無い/起動不能な
環境（通常の非E2E CI ステップ・開発者ローカル）では skip し、非E2E スイートを壊さない。
インフラ都合（``playwright install`` の一時 403 等）で Chromium が入らなかった場合も skip に倒し、
コード回帰だけをブロッキング対象にする。
"""
from __future__ import annotations

import asyncio
import contextlib
import os
import socket
import tempfile
import threading
import time
import unittest

import uvicorn

from tests.fixtures.vuln_app import create_app
from wscan.engine import ScanEngine

# 実ブラウザの crawl→attack→verify を通しで縛る上限。tiny fixture なので通常は数十秒で終わる。
# 真の hang（返らない verifier 等）はこの上限超過で **失敗** になり、CI が赤くなる。
SMOKE_TIMEOUT_S = 180
# 上限超過時、engine.run() の finally（verify/browser cleanup）が停止すると wait_for の
# cancel 待ちが返らず、テストが workflow の 20 分 timeout まで走り得る（Codex #175 P2）。
# scan をデーモンスレッドで走らせ join に **cleanup も含めた** hard deadline を与える：
# 内側 wait_for が SMOKE_TIMEOUT_S で graceful cancel を試み、cleanup が停止しても外側 join が
# この猶予後に必ず返って **失敗** させる（leak した daemon スレッドは interpreter 終了で消える）。
CLEANUP_GRACE_S = 30


def _e2e_enabled() -> bool:
    return os.environ.get("WSCAN_E2E", "").strip().lower() in {"1", "true", "yes", "on"}


# Chromium 可用性 probe の上限。probe の launch/close/teardown は同期 API で timeout を持たないため、
# 停止すると collection が worker の hard deadline に到達せず workflow timeout まで走る（Codex #175 P2）。
CHROMIUM_PROBE_TIMEOUT_S = 60


def _chromium_available() -> bool | None:
    """True=起動可 / False=未導入・起動不能（skip）/ None=probe が deadline 超過（hang → 失敗させる）。"""
    try:
        from playwright.sync_api import sync_playwright
    except Exception:
        return False
    result: dict = {}

    def _probe() -> None:
        try:
            with sync_playwright() as pw:
                browser = pw.chromium.launch(headless=True)
                browser.close()
            result["ok"] = True
        except Exception:
            result["ok"] = False

    # probe もデーモンスレッドで hard deadline 下に置く（leak したスレッドは interpreter 終了で消える）。
    t = threading.Thread(target=_probe, daemon=True)
    t.start()
    t.join(CHROMIUM_PROBE_TIMEOUT_S)
    if t.is_alive():
        return None
    return result.get("ok", False)


# 非 E2E 実行では probe 自体を走らせない（無駄な起動と hang リスクを避ける）。
_CHROMIUM_OK = _chromium_available() if _e2e_enabled() else False


def _free_port() -> int:
    with contextlib.closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_for_server(port: int, timeout: float = 10.0) -> None:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with contextlib.closing(socket.create_connection(("127.0.0.1", port), 0.25)):
                return
        except OSError:
            time.sleep(0.05)
    raise RuntimeError(f"smoke fixture server never came up on port {port}")


@unittest.skipUnless(_e2e_enabled(), "set WSCAN_E2E=1 to run the E2E smoke")
@unittest.skipIf(
    _CHROMIUM_OK is False,
    "Playwright Chromium not launchable (run: playwright install chromium)",
)
class E2ESmokeTests(unittest.TestCase):
    """vuln_app に対する最小の通し XSS 検出スモーク。"""

    @classmethod
    def setUpClass(cls):
        if _CHROMIUM_OK is None:
            raise AssertionError(
                f"E2E smoke: Chromium probe が {CHROMIUM_PROBE_TIMEOUT_S}s 内に返らなかった"
                "（launch/close hang の疑い）"
            )
        cls._port = _free_port()
        cls._config = uvicorn.Config(
            create_app(), host="127.0.0.1", port=cls._port, log_level="error"
        )
        cls._server = uvicorn.Server(cls._config)
        cls._thread = threading.Thread(target=cls._server.run, daemon=True)
        cls._thread.start()
        _wait_for_server(cls._port)

        cls._tmp = tempfile.TemporaryDirectory()

        result: dict = {}

        def _worker() -> None:
            engine = ScanEngine(
                f"http://127.0.0.1:{cls._port}/",
                checks=["xss"],
                llm_provider="none",
                headless=True,
                output_dir=cls._tmp.name,
                open_report=False,
                enable_waf_detection=False,
                enable_ai_analysis=False,
                enable_payload_learning=False,
                enable_adaptive_payloads=False,
                enable_sitemap_crawl=False,
                depth=1,
                fast_mode=True,
                max_payloads=6,
                request_delay=0,
                # llm_provider="none" でも AttackPlanner は決定的ヒューリスティックで plan を作る。
                # plan フェーズを実際に通す（Codex #175 P2）。
                use_planner=True,
                sarif=False,
                timeout=8,
                navigation_retries=0,
            )
            # verify フェーズを実際に通す（Codex #175 P2）。fixture の反射 XSS は dialog で確定するため
            # _phase_verify が除外し verifier が一度も走らない。狙った finding(field=q) だけ dialog 確定を
            # 一時的に外して本物の _phase_verify → _verify_one（ブラウザ再注入）を通し、終了後に戻す。
            orig_phase_verify = engine._phase_verify
            orig_verify_one = engine._verify_one
            verify_calls: list = []

            async def _spy_verify_one(f):
                state = await orig_verify_one(f)
                verify_calls.append((getattr(f, "field_name", ""), state))
                return state

            async def _phase_verify_forcing_target():
                flipped = [
                    f for f in engine.all_findings
                    if f.check_type == "xss" and f.field_name == "q" and f.dialog_confirmed
                ]
                for f in flipped:
                    f.dialog_confirmed = False
                try:
                    await orig_phase_verify()
                finally:
                    for f in flipped:
                        f.dialog_confirmed = True

            engine._verify_one = _spy_verify_one
            engine._phase_verify = _phase_verify_forcing_target
            try:
                # 内側 wait_for は responsive な hang を graceful に cancel し findings-so-far を残す。
                asyncio.run(asyncio.wait_for(engine.run(), timeout=SMOKE_TIMEOUT_S))
                result["findings"] = list(engine.all_findings)
                result["plans"] = list(getattr(engine, "attack_plans", []) or [])
                result["verify_calls"] = verify_calls
            except BaseException as exc:  # noqa: BLE001 — テストへ再送出するため全捕捉
                result["error"] = exc

        # 通しで完走することが第一目的。hang したら join が hard deadline で返りテスト失敗。
        worker = threading.Thread(target=_worker, daemon=True)
        worker.start()
        worker.join(SMOKE_TIMEOUT_S + CLEANUP_GRACE_S)
        if worker.is_alive():
            raise AssertionError(
                f"E2E smoke: cancel/cleanup 含め "
                f"{SMOKE_TIMEOUT_S + CLEANUP_GRACE_S}s の hard deadline 超過（通し hang の疑い）"
            )
        if "error" in result:
            raise result["error"]
        cls._findings = result.get("findings", [])
        cls._plans = result.get("plans", [])
        cls._verify_calls = result.get("verify_calls", [])

    @classmethod
    def tearDownClass(cls):
        try:
            cls._server.should_exit = True
            cls._thread.join(timeout=5)
        finally:
            cls._tmp.cleanup()

    def test_scan_completed_and_detected_reflected_xss(self):
        # 完走（setUpClass が hang せず到達）＋ **狙った** 反射 XSS を検出。fixture には別 XSS シンク
        # （/dom の field=next・/feedback の field=message）もあるため、check_type=="xss" だけで通すと
        # /search?q= の crawl/scan が退行しても緑のままになる。search フローの field=q に限定する
        # （field q はこの反射 XSS 固有。finding.url はフォーム掲載ページ / か反射先 /search）（Codex #175 P1）。
        from urllib.parse import urlparse
        self.assertTrue(self._findings, "E2E smoke: スキャンが 0 findings（通し経路の回帰の疑い）")
        target = [
            f for f in self._findings
            if getattr(f, "check_type", "") == "xss"
            and getattr(f, "field_name", "") == "q"
            and urlparse(getattr(f, "url", "")).path in ("/", "/search")
        ]
        self.assertTrue(
            target,
            "E2E smoke: vuln_app の反射 XSS(search フロー・field=q) を検出できなかった。"
            f" 検出 XSS: {[(getattr(f,'url',''), getattr(f,'field_name','')) for f in self._findings if getattr(f,'check_type','')=='xss']}",
        )

    def test_planner_produced_plan(self):
        # plan フェーズが AttackPlanner を実際に呼び plan を生成した（planner クラッシュ/退行の検知）。
        self.assertTrue(self._plans, "E2E smoke: AttackPlanner が plan を1件も生成しなかった")

    def test_verifier_reproduced_target(self):
        # verify フェーズで verifier が狙った finding を実際に再注入し再現した（verifier hang/退行の検知）。
        self.assertIn(
            ("q", "reproduced"),
            self._verify_calls,
            f"E2E smoke: verifier が field=q を reproduced にしなかった: {self._verify_calls}",
        )


if __name__ == "__main__":
    unittest.main()
