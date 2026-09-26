"""F06/0059: フィールド単位 attack 時間ボックス（`_apply_ip` の deadline gate）の回帰テスト。

stored-XSS flood で単一フィールドが以降を starve させる回帰を防ぐため、engine._scan_field が
task-local な ContextVar（_FIELD_ATTACK_DEADLINE 等）に締切を張り、base._apply_ip が超過後の追加
注入を止める。並行ワーカー汚染を避けるため状態は engine 属性でなく ContextVar に持つ。

不変条件:
- deadline 超過後の `_apply_ip` は追加注入を止め ``("", {})`` を返す。
- 脱落は ``field_budget_exceeded:<check>`` として (フィールド×check) ごとに 1 回だけ記録。
- 打ち切った check は _FIELD_BUDGET_TRUNCATED に記録され、engine 側が checkpoint 完了化を抑止する
  （resume で再試行＝見逃し防止）。
- deadline 未設定（None）／未超過では従来どおり注入する（挙動不変・FP 非増加）。
"""
import time
import unittest

import wscan.engine as eng
from wscan.scanners.base import BaseScanner
from wscan.injection_point import InjectionPoint


class _Engine:
    def __init__(self):
        self.browser = None
        self.monitor = None
        self.payload_gen = None
        self.wave_errors: list = []
        self.state_profile = "unrestricted"
        self.attempt_ledger = None


class _RecordingScanner(BaseScanner):
    CHECK_TYPE = "xss"
    ALWAYS_STATE_CHANGING = False

    def __init__(self, engine):
        super().__init__(engine)
        self.applied = 0

    async def scan_field(self, *a, **k):
        return []

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        self.applied += 1
        return "SRC", {"payload": payload}


def _ip():
    return InjectionPoint.for_form("http://t/", "comment", form_index=0, method="GET")


class _Budget:
    """ContextVar を張って/戻すヘルパ（task-local 時間ボックスの設定を模す）。

    ``ident``=(url, field) を渡すと _FIELD_BUDGET_IDENT も張る（note の per-IP スコープ確認用）。
    未指定なら IDENT は張らず、note は check だけの旧形式へフォールバックする（既存テスト互換）。"""
    def __init__(self, deadline, ident=None):
        self.deadline = deadline
        self.ident = ident

    def __enter__(self):
        self._dl = eng._FIELD_ATTACK_DEADLINE.set(self.deadline)
        self._notes = eng._FIELD_BUDGET_NOTES.set(set())
        self._trunc = eng._FIELD_BUDGET_TRUNCATED.set(set())
        self._ident = (
            eng._FIELD_BUDGET_IDENT.set(self.ident) if self.ident is not None else None
        )
        return self

    def __exit__(self, *a):
        eng._FIELD_ATTACK_DEADLINE.reset(self._dl)
        eng._FIELD_BUDGET_NOTES.reset(self._notes)
        eng._FIELD_BUDGET_TRUNCATED.reset(self._trunc)
        if self._ident is not None:
            eng._FIELD_BUDGET_IDENT.reset(self._ident)


class FieldBudgetTimeboxTests(unittest.IsolatedAsyncioTestCase):
    async def test_skips_injection_after_deadline(self):
        engine = _Engine()
        scanner = _RecordingScanner(engine)
        with _Budget(time.monotonic() - 1.0):  # 既に超過
            source, pair = await scanner._apply_ip(_ip(), "<script>alert(1)</script>")
            self.assertEqual((source, pair), ("", {}))     # 追加注入せず短絡
            self.assertEqual(scanner.applied, 0)           # transport に到達しない
            self.assertIn("field_budget_exceeded:xss", engine.wave_errors)
            self.assertIn("xss", eng._FIELD_BUDGET_TRUNCATED.get())  # truncated 記録

    async def test_note_recorded_once_per_field_check(self):
        engine = _Engine()
        scanner = _RecordingScanner(engine)
        with _Budget(time.monotonic() - 1.0):
            for _ in range(5):
                await scanner._apply_ip(_ip(), "x")
            notes = [e for e in engine.wave_errors if e == "field_budget_exceeded:xss"]
            self.assertEqual(len(notes), 1)  # フィールド×check ごとに 1 回だけ

    async def test_injects_when_no_deadline(self):
        engine = _Engine()
        scanner = _RecordingScanner(engine)
        with _Budget(None):  # 時間ボックス無効
            source, pair = await scanner._apply_ip(_ip(), "payload")
            self.assertEqual(scanner.applied, 1)           # 従来どおり注入
            self.assertEqual(source, "SRC")
            self.assertEqual(engine.wave_errors, [])       # budget ノートなし

    async def test_injects_when_deadline_in_future(self):
        engine = _Engine()
        scanner = _RecordingScanner(engine)
        with _Budget(time.monotonic() + 60.0):  # 未到達
            await scanner._apply_ip(_ip(), "payload")
            self.assertEqual(scanner.applied, 1)
            self.assertEqual(engine.wave_errors, [])

    async def test_note_carries_injection_point_when_ident_set(self):
        """R4#2: IDENT が張られていれば note に injection point 情報（<check>:<path>|<field>）を載せ、
        benchmark が per-IP に degradation を絞れるようにする。観測系は先頭 `:` までで category を取る
        ため category は変わらない（field_budget_exceeded）。"""
        engine = _Engine()
        scanner = _RecordingScanner(engine)
        with _Budget(time.monotonic() - 1.0, ident=("http://h/search?q=1", "q")):
            await scanner._apply_ip(_ip(), "x")
            self.assertIn("field_budget_exceeded:xss:/search|q", engine.wave_errors)

    async def test_deadline_is_task_local(self):
        """別タスクで張った deadline は本タスクへ漏れない（並行ワーカー汚染防止）。"""
        import asyncio
        engine = _Engine()
        scanner = _RecordingScanner(engine)

        async def worker_with_expired():
            with _Budget(time.monotonic() - 1.0):
                await asyncio.sleep(0)  # 別タスク内でのみ有効
        await asyncio.create_task(worker_with_expired())
        # 本タスクには deadline が無い（default None）→ 従来どおり注入される。
        source, pair = await scanner._apply_ip(_ip(), "payload")
        self.assertEqual(scanner.applied, 1)


class _FakePage:
    def __init__(self, session_json="", origin=""):
        self.closed = False
        self.wired: list = []
        self.init_scripts: list = []
        self._session_json = session_json
        self._origin = origin

    def set_default_timeout(self, t):
        pass

    def on(self, ev, cb):
        self.wired.append(ev)

    def is_closed(self):
        return self.closed

    async def add_init_script(self, script):
        self.init_scripts.append(script)

    async def evaluate(self, script, *args):
        if "sessionStorage" in script and "stringify" in script:
            return self._session_json
        if "location.origin" in script:
            return self._origin
        return None

    async def close(self):
        self.closed = True


class _WedgedPage(_FakePage):
    """dialog 未解消で wedge した page。evaluate が返らない（例外）状況を模す。"""
    async def evaluate(self, script, *args):
        raise RuntimeError("page is wedged")


class _FakeContext:
    def __init__(self):
        self.created: list = []

    async def new_page(self):
        p = _FakePage()
        self.created.append(p)
        return p


class RecreatePageTests(unittest.IsolatedAsyncioTestCase):
    """F06/0059: stored-XSS flood で wedge した page を作り直す recreate_page の回帰。"""

    def _bm(self):
        from wscan.browser import BrowserManager
        bm = BrowserManager()
        bm._context = _FakeContext()
        bm._use_scoped_headers = False
        return bm

    async def test_recreate_swaps_page_and_resets_dialog(self):
        bm = self._bm()
        old = _FakePage()
        bm.page = old
        bm.dialog_fired = True
        bm.dialog_message = "XSS"
        bm.dialog_total = 9
        bm.dialog_dismiss_failed = True

        ok = await bm.recreate_page()

        self.assertTrue(ok)
        self.assertIsNot(bm.page, old)          # 新しい page に差し替え
        self.assertTrue(old.closed)             # 旧 page は閉じる
        self.assertIn("dialog", bm.page.wired)  # 新 page に dialog ハンドラ再配線
        self.assertFalse(bm.dialog_fired)       # dialog 状態はリセット
        self.assertFalse(bm.dialog_dismiss_failed)
        self.assertEqual(bm.dialog_total, 9)    # 累積カウンタは保持（flood 検知の連続性）

    async def test_recreate_returns_false_when_no_context(self):
        bm = self._bm()
        bm._context = None
        bm.page = _FakePage()
        self.assertFalse(await bm.recreate_page())  # 復旧不能＝安全側 False

    async def test_reset_dialog_keeps_wedge_signal(self):
        """#6: reset_dialog は wedge signal（dialog_dismiss_failed）を消さない。

        XSS 等が payload 毎に reset_dialog を呼ぶため、ここで消すと初回 dismiss 失敗の
        wedge が recover 検査前に消え page が再生成されない。dialog_fired 等は消す。
        """
        bm = self._bm()
        bm.page = _FakePage()
        bm.dialog_fired = True
        bm.dialog_message = "XSS"
        bm.dialog_dismiss_failed = True

        bm.reset_dialog()

        self.assertFalse(bm.dialog_fired)             # 通常の dialog 状態はリセット
        self.assertEqual(bm.dialog_message, "")
        self.assertTrue(bm.dialog_dismiss_failed)     # wedge signal は保持

    async def test_recreate_seeds_session_storage_via_init_script(self):
        """#3: recreate_page は navigate 成功時に控えた最新スナップショットを init script として仕込む。
        wedge した old page（evaluate が返らない）からの読取に依存しない。"""
        bm = self._bm()
        bm._last_session_storage = ("http://t", '{"token":"abc123"}')
        old = _WedgedPage()  # evaluate が例外＝旧 page から読めない状況
        bm.page = old

        ok = await bm.recreate_page()

        self.assertTrue(ok)
        self.assertEqual(len(bm.page.init_scripts), 1)          # 新 page に仕込む
        script = bm.page.init_scripts[0]
        self.assertIn("http://t", script)                      # 該当 origin ガード
        self.assertIn("abc123", script)                        # 控えた値を seed
        self.assertIn("getItem", script)                       # 未設定キーのみ復元

    async def test_seed_init_script_guards_with_sentinel(self):
        """R4#4: init script は sentinel key で「一度 seed 済み」を記録し、以後の document では
        復元しない。無条件復元だと app が消した auth/one-time key が次 navigation で stale 蘇生する。"""
        bm = self._bm()
        bm._last_session_storage = ("http://t", '{"token":"abc123"}')
        bm.page = _WedgedPage()
        ok = await bm.recreate_page()
        self.assertTrue(ok)
        script = bm.page.init_scripts[0]
        self.assertIn("__wscan_seeded__", script)                 # sentinel を使う
        self.assertIn('getItem(S) !== null) return', script)      # seed 済みなら復元しない
        self.assertIn("setItem(S", script)                        # seed 後に sentinel を立てる

    async def test_recreate_skips_init_script_without_snapshot(self):
        """スナップショットが無ければ init script を仕込まない（従来挙動）。"""
        bm = self._bm()
        bm.page = _FakePage(session_json="{}", origin="http://t")
        ok = await bm.recreate_page()
        self.assertTrue(ok)
        self.assertEqual(bm.page.init_scripts, [])

    async def test_snapshot_captures_nonempty_session_storage(self):
        """#3: navigate 成功時の best-effort スナップショットが非空 sessionStorage を控える。"""
        bm = self._bm()
        bm.page = _FakePage(session_json='{"token":"abc"}', origin="http://t")
        await bm._snapshot_session_storage()
        self.assertEqual(bm._last_session_storage, ("http://t", '{"token":"abc"}'))

    async def test_snapshot_keeps_last_nonempty_on_empty_page(self):
        """#3: login redirect 等で空になったページでは直近の非空スナップショットを上書きしない。"""
        bm = self._bm()
        bm._last_session_storage = ("http://t", '{"token":"old"}')
        bm.page = _FakePage(session_json="{}", origin="http://t")
        await bm._snapshot_session_storage()
        self.assertEqual(bm._last_session_storage, ("http://t", '{"token":"old"}'))

    async def test_worker_recreate_reattaches_scoped_headers(self):
        """#5: worker の recreate_page は create_worker と同じ経路で CDP scoped header interception を
        同期的に再 attach する（_use_scoped_headers を持たない worker でも置換 page へ配線）。"""
        from wscan.browser import BrowserManager, WorkerBrowser
        real = BrowserManager()
        real._context = _FakeContext()
        real._header_intercept_mode = "cdp"
        attached: list = []

        async def fake_attach(page):
            attached.append(page)

        real._attach_header_interception = fake_attach
        worker = WorkerBrowser(real, _FakePage())

        ok = await worker.recreate_page()

        self.assertTrue(ok)
        self.assertEqual(attached, [worker.page])   # 置換 page へ同期 attach
        self.assertIn("dialog", worker.page.wired)  # 通常の配線も維持


class _GateEngine(_Engine):
    pass


class _ProbeScanner(BaseScanner):
    """直接 transport（_apply_ip を経由しない）経路の gate 回帰用。"""
    CHECK_TYPE = "sqli"

    def __init__(self, engine):
        super().__init__(engine)
        self.applied = 0

    async def scan_field(self, *a, **k):
        return []

    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        self.applied += 1
        return "SRC", {"response": {"body": ""}}

    async def log_payload_test(self, *a, **k):
        pass


class _MidLoopProbeScanner(_ProbeScanner):
    """最初の送信中に deadline を失効させ、ループ内 gate 再チェックの回帰を作る。"""
    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        self.applied += 1
        # 送信中に期限切れになった状況を模す（同一 context なので次の gate が拾う）。
        eng._FIELD_ATTACK_DEADLINE.set(time.monotonic() - 1.0)
        return "SRC", {"response": {"body": ""}}


class DirectTransportGateTests(unittest.IsolatedAsyncioTestCase):
    """#3: _apply_ip を迂回する送信経路（equivalence probe / evolution probe）も
    フィールド時間ボックスで短絡する。"""

    async def test_equivalence_probe_short_circuits_after_deadline(self):
        engine = _GateEngine()
        scanner = _ProbeScanner(engine)
        with _Budget(time.monotonic() - 1.0):
            result = await scanner.run_equivalence_probe(
                "http://t/", 0, "q", is_url_param=True, context="sql"
            )
            self.assertIsNone(result)                       # 6 発送らず短絡
            self.assertEqual(scanner.applied, 0)            # transport に到達しない
            self.assertIn("sqli", eng._FIELD_BUDGET_TRUNCATED.get())

    async def test_equivalence_probe_runs_without_deadline(self):
        engine = _GateEngine()
        scanner = _ProbeScanner(engine)
        with _Budget(None):
            await scanner.run_equivalence_probe(
                "http://t/", 0, "q", is_url_param=True, context="sql"
            )
            self.assertGreater(scanner.applied, 0)          # 従来どおり投入

    async def test_evolution_probe_short_circuits_after_deadline(self):
        engine = _GateEngine()
        scanner = _ProbeScanner(engine)
        with _Budget(time.monotonic() - 1.0):
            src, surviving, context = await scanner._evolution_probe(
                "http://t/", 0, "q", is_url_param=True
            )
            self.assertEqual((src, surviving, context), ("", set(), {}))
            self.assertIn("sqli", eng._FIELD_BUDGET_TRUNCATED.get())

    async def test_equivalence_probe_stops_when_deadline_expires_mid_loop(self):
        """#2: 入口 gate 通過後（deadline は未来）に最初の送信中に期限切れになっても、各 request 前の
        再チェックで残りの probe を送らない（sql は 6 発 → 1 発だけ送って打ち切る）。"""
        engine = _GateEngine()
        scanner = _MidLoopProbeScanner(engine)
        with _Budget(time.monotonic() + 30.0):  # 入口では有効
            await scanner.run_equivalence_probe(
                "http://t/", 0, "q", is_url_param=True, context="sql"
            )
            self.assertEqual(scanner.applied, 1)   # 1 発送信後に失効→残りを送らない
            self.assertIn("sqli", eng._FIELD_BUDGET_TRUNCATED.get())


class AttackPageRestoreRecoveryTests(unittest.IsolatedAsyncioTestCase):
    """#1(F06/0059): restore navigate 自体が stored-XSS listing で再 flood/wedge しうるため、
    restore の後にも回復し、次 field が健全 page で走るようにする。"""

    async def test_recovers_after_restore_navigate(self):
        import asyncio as _asyncio
        import types
        from unittest.mock import AsyncMock
        from wscan.engine import CrawledPage, ScanEngine

        recover_calls: list = []

        async def _recover(since):
            recover_calls.append(since)
            return 0

        page = CrawledPage(
            url="http://t/list",
            html="",
            forms=[{
                "index": 0, "method": "GET", "action": "/list",
                "inputs": [{"name": "q", "type": "text"}],
            }],
            url_params=[],
            depth=0,
        )
        engine = types.SimpleNamespace(
            _is_url_excluded=lambda url: False,
            max_forms=5,
            skip_registration=False,
            exclude_urls=None,
            _profile=lambda msg: None,
            scanned_forms=set(),
            _scanned_forms_lock=_asyncio.Lock(),
            total_fields=0,
            exclude_fields=set(),
            controller=types.SimpleNamespace(checkpoint=AsyncMock()),
            _scan_field=AsyncMock(),
            browser=types.SimpleNamespace(
                dialog_total=0,
                navigate=AsyncMock(return_value=True),
            ),
            navigation_retries=0,
            _recover_if_dialog_flood=_recover,
            _record_unscannable_url=lambda *a, **k: None,
            _navigation_failure_note=lambda: "",
        )
        engine._attack_page = types.MethodType(ScanEngine._attack_page, engine)

        await engine._attack_page(page, None)

        # 1 フィールドにつき 2 回回復する：scan 直後 + restore navigate 後（新規 #1）。
        self.assertEqual(len(recover_calls), 2)


class _CollapseUntilBrokenScanner(_ProbeScanner):
    """R4#5: baseline+equivalent は collapse（injectable に見える）させるが、broken 対照 probe の
    送信直前に deadline を失効させ broken を送らせない。gate 修正が無いと evaluate が broken 欠如を
    非 collapse と誤解し injectable=True（FP）を返す。"""
    async def _apply_payload(self, url, form_index, field_name, payload, is_url_param):
        self.applied += 1
        # 隣接文字列リテラルが結合＝collapse シグナル（equivalence_probe の想定と同じ模擬）。
        if "' '" in payload and payload.count("'") == 2:
            body = "r:" + payload.replace("' '", "")   # AA' 'BB → AABB(=marker)
        else:
            body = "r:" + payload                        # baseline/broken は verbatim 反射
        # sql probe は 6 発（baseline+4 equivalent+broken）。deadline が有効な run に限り 5 発送信後に
        # 失効させ 6 発目(broken)を止める（deadline 無効の run では全 6 発送る）。
        if self.applied >= 5 and eng._FIELD_ATTACK_DEADLINE.get() is not None:
            eng._FIELD_ATTACK_DEADLINE.set(time.monotonic() - 1.0)
        return body, {"response": {"body": body}}


class EquivalenceControlTruncationTests(unittest.IsolatedAsyncioTestCase):
    """R4#5: broken-quote 対照 probe が揃う前に truncate したら evaluate せず None を返す（FP 防止）。"""

    async def test_no_finding_when_control_truncated(self):
        engine = _GateEngine()
        scanner = _CollapseUntilBrokenScanner(engine)
        with _Budget(time.monotonic() + 30.0):   # 入口では有効
            result = await scanner.run_equivalence_probe(
                "http://t/", 0, "q", is_url_param=True, context="sql"
            )
            self.assertIsNone(result)              # 部分結果で誤検知（injectable）を出さない
            self.assertEqual(scanner.applied, 5)   # broken(6 発目)は送らず打ち切り
            self.assertIn("sqli", eng._FIELD_BUDGET_TRUNCATED.get())

    async def test_finding_when_all_probes_sent(self):
        """対照(broken)まで全 probe 送れば従来どおり judgment する（guard が過剰抑止しない確認）。"""
        engine = _GateEngine()
        scanner = _CollapseUntilBrokenScanner(engine)
        with _Budget(None):                        # 時間ボックス無効＝全 probe 送信
            result = await scanner.run_equivalence_probe(
                "http://t/", 0, "q", is_url_param=True, context="sql"
            )
            self.assertIsNotNone(result)           # collapse 観測＋broken 非 collapse → injectable
            self.assertEqual(scanner.applied, 6)


class DomXssGateTests(unittest.IsolatedAsyncioTestCase):
    """R4#1: DOM-XSS の独自 _apply_payload 直送経路も時間ボックス gate で短絡する。"""

    def _scanner(self):
        from wscan.scanners.dom_xss import DOMXSSScanner
        engine = _Engine()
        engine.browser = object()   # gate 前に触れたら AttributeError で気づける
        sc = DOMXSSScanner(engine)
        sc.applied = 0

        async def _ap(*a, **k):
            sc.applied += 1
            return "", {}

        async def _hook():
            pass

        sc._apply_payload = _ap
        sc._ensure_hook = _hook
        return sc

    async def test_scan_injection_point_short_circuits_after_deadline(self):
        sc = self._scanner()
        ip = InjectionPoint.for_url_param("http://t/", "q")
        with _Budget(time.monotonic() - 1.0):
            out = await sc.scan_injection_point(ip, {"name": "q"})
            self.assertEqual(out, [])
            self.assertEqual(sc.applied, 0)          # 初期 probe すら送らない
            self.assertIn("dom_xss", eng._FIELD_BUDGET_TRUNCATED.get())

    async def test_evolution_probe_override_short_circuits(self):
        sc = self._scanner()
        with _Budget(time.monotonic() - 1.0):
            res = await sc._evolution_probe("http://t/", 0, "q", is_url_param=True)
            self.assertEqual(res, ("", set(), {}))
            self.assertIn("dom_xss", eng._FIELD_BUDGET_TRUNCATED.get())


class MultiParamRecoveryTests(unittest.IsolatedAsyncioTestCase):
    """R4#3: _phase_multi_param は各結合送信の後で dialog flood/wedge を回復する
    （外側 1 回 bracket では最初の組合せが wedge した page で後続組合せが走る）。"""

    async def test_recovers_after_each_combined_submission(self):
        import asyncio as _asyncio
        import types
        from unittest.mock import AsyncMock
        from wscan.engine import CrawledPage, ScanEngine

        recover_calls: list = []

        async def _recover(since):
            recover_calls.append(since)
            return 0

        # 2 フィールドのフォーム 1 つ → xss/sqli の 2 組合せが submit される。
        page = CrawledPage(
            url="http://t/form",
            html="",
            forms=[{
                "index": 0, "method": "POST", "action": "/form",
                "inputs": [
                    {"name": "a", "type": "text"},
                    {"name": "b", "type": "text"},
                ],
            }],
            url_params=[],
            depth=0,
        )

        class _Scanner:
            def may_scan_injection_point(self, ip):
                return True

        class _PG:
            default_payloads = {"xss": ["<x>"], "sqli": ["' or 1=1"], "ssti": ["{{7*7}}"]}

        engine = types.SimpleNamespace(
            max_forms=5,
            exclude_fields=set(),
            scanners={"xss": _Scanner(), "sqli": _Scanner(), "ssti": _Scanner()},
            payload_gen=_PG(),
            controller=types.SimpleNamespace(wait_if_paused_or_abort=AsyncMock()),
            navigation_retries=0,
            _effective_delay=0,
            flag_finder=None,
            _recover_if_dialog_flood=_recover,
            _record_unscannable_url=lambda *a, **k: None,
            _navigation_failure_note=lambda: "",
            _record_finding=lambda *a, **k: None,
            _check_page_for_flags=lambda *a, **k: None,
            browser=types.SimpleNamespace(
                dialog_total=0,
                dialog_fired=False,
                dialog_message="",
                navigate=AsyncMock(return_value=True),
                reset_dialog=lambda: None,
                fill_and_submit_form_multi=AsyncMock(return_value=("", {})),
            ),
        )
        engine._phase_multi_param = types.MethodType(
            ScanEngine._phase_multi_param, engine
        )

        await engine._phase_multi_param(page, None)

        # xss と sqli の 2 組合せそれぞれの後で回復する（ssti は default はあるが field_payloads を
        # 満たすので 3 組合せになりうる）。少なくとも各送信後に呼ばれる＝送信回数と一致。
        self.assertEqual(
            len(recover_calls),
            engine.browser.fill_and_submit_form_multi.await_count,
        )
        self.assertGreaterEqual(len(recover_calls), 2)


if __name__ == "__main__":
    unittest.main()
