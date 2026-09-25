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
    """ContextVar を張って/戻すヘルパ（task-local 時間ボックスの設定を模す）。"""
    def __init__(self, deadline):
        self.deadline = deadline

    def __enter__(self):
        self._dl = eng._FIELD_ATTACK_DEADLINE.set(self.deadline)
        self._notes = eng._FIELD_BUDGET_NOTES.set(set())
        self._trunc = eng._FIELD_BUDGET_TRUNCATED.set(set())
        return self

    def __exit__(self, *a):
        eng._FIELD_ATTACK_DEADLINE.reset(self._dl)
        eng._FIELD_BUDGET_NOTES.reset(self._notes)
        eng._FIELD_BUDGET_TRUNCATED.reset(self._trunc)


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
        """#2: recreate_page は退避 sessionStorage を init script として仕込む
        （navigate 後の evaluate 復元では SPA bootstrap に間に合わないため）。"""
        bm = self._bm()
        old = _FakePage(session_json='{"token":"abc123"}', origin="http://t")
        bm.page = old

        ok = await bm.recreate_page()

        self.assertTrue(ok)
        self.assertIsNone(bm._pending_session_storage)          # 消費済み
        self.assertEqual(len(bm.page.init_scripts), 1)          # 新 page に仕込む
        script = bm.page.init_scripts[0]
        self.assertIn("http://t", script)                      # 該当 origin ガード
        self.assertIn("abc123", script)                        # 退避値を seed
        self.assertIn("getItem", script)                       # 未設定キーのみ復元

    async def test_recreate_skips_init_script_without_snapshot(self):
        """sessionStorage が空なら init script を仕込まない（従来挙動）。"""
        bm = self._bm()
        bm.page = _FakePage(session_json="{}", origin="http://t")
        ok = await bm.recreate_page()
        self.assertTrue(ok)
        self.assertEqual(bm.page.init_scripts, [])


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


if __name__ == "__main__":
    unittest.main()
