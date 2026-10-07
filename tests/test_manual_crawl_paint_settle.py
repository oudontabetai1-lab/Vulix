"""遠隔ブラウザの描画確定待ち（空フレーム抑止）の回帰テスト。

遷移直後に Chromium が送る描画前の真っ白なフレームを、そのままダッシュボードへ
送らないこと（保留→再判定→描画確認後に送る）と、実画面は従来通り送ることを守る。
"""
import asyncio
import base64
import struct
import unittest
from unittest.mock import patch
import zlib

from wscan import manual_crawl
from wscan.manual_crawl import (
    ManualCrawlSession,
    classify_lifecycle_event,
    decide_settle_action,
    png_is_blank,
    thumbnail_clip,
)

# 実 Chromium（Playwright 1.59 headless）の Page.captureScreenshot(clip scale=0.1) 出力。
CHROMIUM_BLANK_WHITE_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAIAAAABQCAIAAABeYuqzAAAAu0lEQVR4nOzRQQ0AMAgAMbLMv2WQcZ/WQv/uDp03pATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExATEBMQExA4AAP//DEhCAgAAAAZJREFUAwAStwOgcZjsxAAAAABJRU5ErkJggg=="
)
CHROMIUM_BLANK_DARK_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAIAAAABQCAIAAABeYuqzAAAAvUlEQVR4nOzRQQ0AMAgAMbJMCf5FIuM+rYX+3R06b0gJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgJiAmICYgdAAAA//8bBKkfAAAABklEQVQDAG5tAQlNUzrIAAAAAElFTkSuQmCC"
)
CHROMIUM_TEXT_PNG = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAIAAAABQCAIAAABeYuqzAAAA5ElEQVR4nOzTQQ2DQAAAwSvpF/8WsIIRNJCQ3LUq2M+Mhc1+11rP89z3ve/74HXbdV3neR7HMeccvO7zP2DQ2QYpAWICxASICRATICZATICYADEBYgLEBIgJEBMgJkBMgJgAMQFiAsQEiAkQEyAmQEyAmAAxAWICxASICRATICZATICYADEBYgLEBIgJEBMgJkBMgJgAMQFiAsQEiAkQEyAmQEyAmAAxAWICxASICRATICZATICYADEBYgLEBIgJEBMgJkBMgJgAMQFiAsQEiAkQEyAmQEyAmAAxAWICxASICRD7AQAA//+VZD8TAAAABklEQVQDALvIFpuY6JoWAAAAAElFTkSuQmCC"
)


def _png(rows, color_type=2, filter_type=0, depth=8, interlace=0):
    """テスト用の最小 PNG を標準ライブラリだけで組み立てる（rows は画素タプルの行）。"""
    height = len(rows)
    width = len(rows[0])
    channels = {0: 1, 2: 3, 4: 2, 6: 4}[color_type]
    stride = width * channels
    raw = bytearray()
    prev = bytearray(stride)
    for row in rows:
        line = bytearray(v for px in row for v in px)
        out = bytearray(stride)
        for i in range(stride):
            left = line[i - channels] if i >= channels else 0
            up = prev[i]
            upleft = prev[i - channels] if i >= channels else 0
            if filter_type == 0:
                pred = 0
            elif filter_type == 1:
                pred = left
            elif filter_type == 2:
                pred = up
            elif filter_type == 3:
                pred = (left + up) >> 1
            else:
                pred = manual_crawl._paeth(left, up, upleft)
            out[i] = (line[i] - pred) & 0xFF
        raw.append(filter_type)
        raw.extend(out)
        prev = line

    def chunk(ctype, data):
        body = ctype + data
        return struct.pack(">I", len(data)) + body + struct.pack(">I", zlib.crc32(body))

    ihdr = struct.pack(">IIBBBBB", width, height, depth, color_type, 0, 0, interlace)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(bytes(raw)))
        + chunk(b"IEND", b"")
    )


def _solid(w, h, px):
    return [[px] * w for _ in range(h)]


class PngIsBlankTests(unittest.TestCase):
    def test_real_chromium_white_prepaint_frame_is_blank(self):
        # 脆弱ケース: 遷移直後の真っ白なフレームは空白と判定され、保留/リトライ対象になる。
        self.assertIs(png_is_blank(CHROMIUM_BLANK_WHITE_PNG), True)

    def test_real_chromium_single_color_frame_is_blank(self):
        self.assertIs(png_is_blank(CHROMIUM_BLANK_DARK_PNG), True)

    def test_real_chromium_painted_frame_is_not_blank(self):
        # 安全ケース: 文字が描画された実画面は空白ではない（そのまま送る）。
        self.assertIs(png_is_blank(CHROMIUM_TEXT_PNG), False)

    def test_all_filter_types_decode_consistently(self):
        rows = _solid(16, 6, (255, 255, 255))
        rows[3][9] = (10, 20, 30)
        for ftype in range(5):
            with self.subTest(filter=ftype):
                self.assertIs(png_is_blank(_png(_solid(16, 6, (240, 240, 240)), filter_type=ftype)), True)
                self.assertIs(png_is_blank(_png(rows, filter_type=ftype)), False)

    def test_single_differing_pixel_anywhere_is_not_blank(self):
        for x, y in [(0, 0), (15, 0), (0, 5), (15, 5)]:
            rows = _solid(16, 6, (255, 255, 255))
            rows[y][x] = (0, 0, 0)
            self.assertIs(png_is_blank(_png(rows, filter_type=4)), False)

    def test_tolerance_absorbs_tiny_noise_only(self):
        rows = _solid(8, 4, (250, 250, 250))
        rows[1][1] = (252, 250, 249)
        self.assertIs(png_is_blank(_png(rows)), True)
        rows[2][2] = (240, 250, 250)
        self.assertIs(png_is_blank(_png(rows)), False)
        self.assertIs(png_is_blank(_png(rows), tolerance=20), True)

    def test_rgba_gray_and_gray_alpha(self):
        self.assertIs(png_is_blank(_png(_solid(4, 4, (1, 2, 3, 255)), color_type=6)), True)
        # alpha の差は無視（スクリーンショットは不透明）。
        rows = _solid(4, 4, (1, 2, 3, 255))
        rows[0][0] = (1, 2, 3, 0)
        self.assertIs(png_is_blank(_png(rows, color_type=6)), True)
        rows[0][1] = (90, 2, 3, 255)
        self.assertIs(png_is_blank(_png(rows, color_type=6)), False)
        self.assertIs(png_is_blank(_png(_solid(4, 4, (128,)), color_type=0)), True)
        gray = _solid(4, 4, (128,))
        gray[3][3] = (0,)
        self.assertIs(png_is_blank(_png(gray, color_type=0)), False)
        self.assertIs(png_is_blank(_png(_solid(4, 4, (7, 255)), color_type=4)), True)

    def test_undecidable_inputs_return_none(self):
        for bad in [b"", b"not a png", None, "str", CHROMIUM_TEXT_PNG[:40],
                    b"\xff\xd8\xff\xe0jpegdata"]:
            with self.subTest(bad=bad if not isinstance(bad, bytes) else bad[:10]):
                self.assertIsNone(png_is_blank(bad))
        self.assertIsNone(png_is_blank(_png(_solid(2, 2, (1, 1, 1)), interlace=1)))
        self.assertIsNone(png_is_blank(_png(_solid(2, 2, (1,)), color_type=0, depth=16)))
        palette = _png(_solid(2, 2, (1, 1, 1))).replace(
            struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0),
            struct.pack(">IIBBBBB", 2, 2, 8, 3, 0, 0, 0),
        )
        self.assertIsNone(png_is_blank(palette))

    def test_compressed_output_larger_than_declared_pixels_is_rejected(self):
        oversized = _png(_solid(64, 64, (255, 255, 255))).replace(
            struct.pack(">IIBBBBB", 64, 64, 8, 2, 0, 0, 0),
            struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0),
        )
        self.assertIsNone(png_is_blank(oversized))

    def test_oversized_dimensions_are_rejected_without_decoding(self):
        huge = _png(_solid(2, 2, (1, 1, 1))).replace(
            struct.pack(">IIBBBBB", 2, 2, 8, 2, 0, 0, 0),
            struct.pack(">IIBBBBB", 50_000, 50_000, 8, 2, 0, 0, 0),
        )
        self.assertIsNone(png_is_blank(huge))


class DecideSettleActionTests(unittest.TestCase):
    def test_blank_frame_retries_until_budget_then_falls_back(self):
        self.assertEqual(decide_settle_action(True, 0, 3), "retry")
        self.assertEqual(decide_settle_action(True, 1, 3), "retry")
        self.assertEqual(decide_settle_action(True, 2, 3), "fallback")
        self.assertEqual(decide_settle_action(True, 0, 1), "fallback")

    def test_painted_or_undecidable_frame_is_forwarded(self):
        self.assertEqual(decide_settle_action(False, 0, 3), "forward")
        self.assertEqual(decide_settle_action(None, 0, 3), "forward")
        self.assertEqual(decide_settle_action(False, 2, 3), "forward")


class ClassifyLifecycleTests(unittest.TestCase):
    def test_main_frame_init_is_navigation(self):
        self.assertEqual(
            classify_lifecycle_event({"frameId": "M", "name": "init", "loaderId": "L2"}, "M", "L1"),
            "navigation",
        )

    def test_paint_events(self):
        for name in ["firstPaint", "firstContentfulPaint", "firstMeaningfulPaint"]:
            self.assertEqual(classify_lifecycle_event({"frameId": "M", "name": name}, "M"), "paint")

    def test_ignored_events(self):
        self.assertIsNone(classify_lifecycle_event({"frameId": "IFRAME", "name": "init"}, "M"))
        self.assertIsNone(classify_lifecycle_event({"frameId": "M", "name": "load"}, "M"))
        self.assertIsNone(classify_lifecycle_event({"frameId": "M", "name": "DOMContentLoaded"}, "M"))
        self.assertIsNone(classify_lifecycle_event({"frameId": "M", "name": "init"}, None))
        self.assertIsNone(classify_lifecycle_event(None, "M"))

    def test_stale_document_paint_is_ignored(self):
        params = {"frameId": "M", "name": "firstPaint", "loaderId": "OLD"}
        self.assertIsNone(classify_lifecycle_event(params, "M", "NEW"))
        self.assertEqual(classify_lifecycle_event(params, "M", "OLD"), "paint")
        self.assertEqual(classify_lifecycle_event(params, "M", None), "paint")


class ThumbnailClipTests(unittest.TestCase):
    def test_uses_scrolled_visual_viewport(self):
        clip = thumbnail_clip(
            {"cssVisualViewport": {"pageX": 0, "pageY": 1499, "clientWidth": 1280, "clientHeight": 800}},
            1280, 800,
        )
        self.assertEqual(clip, {"x": 0.0, "y": 1499.0, "width": 1280.0, "height": 800.0, "scale": 0.1})

    def test_missing_or_invalid_metrics_fall_back_to_viewport(self):
        expected = {"x": 0.0, "y": 0.0, "width": 1280.0, "height": 800.0, "scale": 0.1}
        self.assertEqual(thumbnail_clip(None, 1280, 800), expected)
        self.assertEqual(thumbnail_clip({}, 1280, 800), expected)
        self.assertEqual(
            thumbnail_clip({"cssVisualViewport": {"pageX": "x", "pageY": -5, "clientWidth": 0,
                                                  "clientHeight": float("nan")}}, 1280, 800),
            expected,
        )


class _SettleCdp:
    """captureScreenshot の結果を順に返す偽 CDP。"""

    def __init__(self, thumbs, viewport_jpeg="RECAPTURED"):
        self.thumbs = list(thumbs)
        self.viewport_jpeg = viewport_jpeg
        self.sent = []
        self.handlers = {}

    def on(self, event, callback):
        self.handlers[event] = callback

    async def send(self, method, params=None):
        self.sent.append((method, params))
        if method == "Page.getFrameTree":
            return {"frameTree": {"frame": {"id": "MAIN"}}}
        if method == "Page.getLayoutMetrics":
            return {"cssVisualViewport": {"pageX": 0, "pageY": 0, "clientWidth": 1280, "clientHeight": 800}}
        if method == "Page.captureScreenshot":
            if params and params.get("format") == "png":
                png = self.thumbs.pop(0) if len(self.thumbs) > 1 else self.thumbs[0]
                return {"data": base64.b64encode(png).decode()}
            return {"data": self.viewport_jpeg}
        return {}

    async def detach(self):
        pass

    def thumb_count(self):
        return sum(1 for m, p in self.sent if m == "Page.captureScreenshot" and p.get("format") == "png")


class _Ctx:
    def __init__(self, cdp):
        self.cdp = cdp

    async def new_cdp_session(self, page):
        return self.cdp


class PaintSettleSessionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self._orig_delays = manual_crawl._PAINT_SETTLE_DELAYS
        manual_crawl._PAINT_SETTLE_DELAYS = (0.01, 0.01, 0.01)

    def tearDown(self):
        manual_crawl._PAINT_SETTLE_DELAYS = self._orig_delays

    async def _session(self, cdp):
        sent = []

        async def cb(frame):
            sent.append(frame["data"])

        session = ManualCrawlSession()
        session.running = True
        session.streaming = True
        session._context = _Ctx(cdp)
        session._page = object()
        session._frame_callback = cb
        await session._start_screencast(session._page)
        return session, sent

    async def _settle(self, session):
        task = session._settle_task
        if task is not None:
            await asyncio.wait_for(asyncio.shield(task), 2)
        await asyncio.sleep(0)

    async def test_screencast_enables_lifecycle_events(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, _ = await self._session(cdp)
        methods = [m for m, _ in cdp.sent]
        self.assertIn("Page.setLifecycleEventsEnabled", methods)
        self.assertLess(methods.index("Page.setLifecycleEventsEnabled"), methods.index("Page.startScreencast"))
        self.assertEqual(session._main_frame_id, "MAIN")
        await self._settle(session)

    async def test_blank_prepaint_frame_is_held_and_replaced_after_paint(self):
        # 脆弱ケース: 遷移直後の真っ白なフレームは送らず、描画確認後の画面だけを送る。
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG, CHROMIUM_BLANK_WHITE_PNG, CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        sent.clear()

        cdp.thumbs = [CHROMIUM_BLANK_WHITE_PNG, CHROMIUM_TEXT_PNG]
        cdp.viewport_jpeg = "PAINTED"
        session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": "L1"}, cdp)
        self.assertTrue(session._settling)
        await session._handle_frame({"data": "WHITE_PREPAINT", "sessionId": 1}, cdp)
        self.assertEqual(sent, [])  # 保留中は送らない
        await self._settle(session)
        self.assertNotIn("WHITE_PREPAINT", sent)
        self.assertEqual(sent, ["PAINTED"])
        self.assertGreaterEqual(cdp.thumb_count(), 2)  # 空白→再判定（リトライ）
        self.assertFalse(session._settling)

    async def test_painted_frame_is_forwarded_when_not_settling(self):
        # 安全ケース: 描画確定後の実フレームはそのまま送る。
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        sent.clear()
        await session._handle_frame({"data": "REAL_FRAME", "sessionId": 2}, cdp)
        self.assertEqual(sent, ["REAL_FRAME"])
        self.assertIn(("Page.screencastFrameAck", {"sessionId": 2}), cdp.sent)

    async def test_paint_event_accelerates_probe_but_white_frame_still_retries(self):
        manual_crawl._PAINT_SETTLE_DELAYS = (5.0, 0.01)
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG, CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        session._paint_event.set()
        await self._settle(session)
        sent.clear()
        before = cdp.thumb_count()
        cdp.thumbs = [CHROMIUM_BLANK_WHITE_PNG, CHROMIUM_TEXT_PNG]
        session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": "L9"}, cdp)
        await session._handle_frame({"data": "PREPAINT", "sessionId": 3}, cdp)
        session._on_lifecycle_event({"frameId": "MAIN", "name": "firstPaint", "loaderId": "L9"}, cdp)
        await self._settle(session)
        self.assertEqual(cdp.thumb_count(), before + 2)
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_blank_then_stall_is_shown_after_bounded_retries(self):
        # 描画されないまま止まったページでも、上限後は表示して画面を凍結させない。
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        self.assertEqual(cdp.thumb_count(), len(manual_crawl._PAINT_SETTLE_DELAYS))
        self.assertEqual(sent, ["RECAPTURED"])
        self.assertFalse(session._settling)

    async def test_failed_recapture_emits_held_frame_and_resumes_stream(self):
        # 撮り直し失敗時は ACK 済みの直近保持フレームを送る（静止ページで空画面を残さない）。
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG], viewport_jpeg="")
        session, sent = await self._session(cdp)
        await session._handle_frame({"data": "OLDER", "sessionId": 4}, cdp)
        await session._handle_frame({"data": "HELD", "sessionId": 5}, cdp)
        self.assertEqual(sent, [])
        await self._settle(session)
        self.assertEqual(sent, ["HELD"])
        self.assertFalse(session._settling)
        self.assertEqual(session._held_frame, "")
        await session._handle_frame({"data": "NEXT_REAL", "sessionId": 7}, cdp)
        self.assertEqual(sent, ["HELD", "NEXT_REAL"])

    async def test_failed_recapture_does_not_emit_previous_document_frame(self):
        # 遷移前 document の保持フレームは、遷移後の撮り直し失敗時に送らない。
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        sent.clear()
        manual_crawl._PAINT_SETTLE_DELAYS = (0.05,)
        cdp.thumbs = [CHROMIUM_BLANK_WHITE_PNG]
        cdp.viewport_jpeg = ""
        session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": "A"}, cdp)
        await session._handle_frame({"data": "DOC_A", "sessionId": 8}, cdp)
        session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": "B"}, cdp)
        await self._settle(session)
        self.assertEqual(sent, [])
        self.assertFalse(session._settling)

    async def test_process_swap_refreshes_main_frame_id(self):
        # process swap で置換後のメインフレームに新 ID が付いても保留が効く。
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        sent.clear()
        cdp.thumbs = [CHROMIUM_BLANK_WHITE_PNG, CHROMIUM_TEXT_PNG]
        cdp.viewport_jpeg = "SWAPPED_PAINTED"
        # 新 ID の init は旧 ID と一致せず取りこぼされる。
        session._on_lifecycle_event({"frameId": "MAIN2", "name": "init", "loaderId": "S1"}, cdp)
        self.assertFalse(session._settling)
        cdp.handlers["Page.frameNavigated"]({"frame": {"id": "MAIN2", "loaderId": "S1"}})
        self.assertEqual(session._main_frame_id, "MAIN2")
        self.assertEqual(session._loader_id, "S1")
        self.assertTrue(session._settling)
        await session._handle_frame({"data": "WHITE_AFTER_SWAP", "sessionId": 9}, cdp)
        self.assertEqual(sent, [])
        await self._settle(session)
        self.assertEqual(sent, ["SWAPPED_PAINTED"])
        # 以降の同 ID の遷移は lifecycle init で検知される。
        session._on_lifecycle_event({"frameId": "MAIN2", "name": "init", "loaderId": "S2"}, cdp)
        self.assertTrue(session._settling)
        await self._settle(session)

    async def test_iframe_or_same_main_frame_navigated_does_not_resettle(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        handler = cdp.handlers["Page.frameNavigated"]
        handler({"frame": {"id": "CHILD", "parentId": "MAIN", "loaderId": "C1"}})
        handler({"frame": {"id": "MAIN", "loaderId": "L1"}})
        self.assertEqual(session._main_frame_id, "MAIN")
        self.assertFalse(session._settling)

    async def test_undecidable_probe_forwards_immediately(self):
        cdp = _SettleCdp([b"garbage"])
        session, sent = await self._session(cdp)
        await self._settle(session)
        self.assertEqual(cdp.thumb_count(), 1)
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_rapid_navigations_do_not_extend_retry_budget(self):
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG])
        session, sent = await self._session(cdp)
        first_task = session._settle_task
        for i in range(5):
            session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": f"R{i}"}, cdp)
            self.assertIs(session._settle_task, first_task)
        await self._settle(session)
        self.assertEqual(cdp.thumb_count(), len(manual_crawl._PAINT_SETTLE_DELAYS))
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_iframe_navigation_does_not_hold_frames(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        await self._settle(session)
        sent.clear()
        session._on_lifecycle_event({"frameId": "CHILD", "name": "init"}, cdp)
        self.assertFalse(session._settling)
        await session._handle_frame({"data": "LIVE", "sessionId": 5}, cdp)
        self.assertEqual(sent, ["LIVE"])

    async def test_stop_screencast_cancels_pending_settle(self):
        manual_crawl._PAINT_SETTLE_DELAYS = (5.0,)
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG])
        session, sent = await self._session(cdp)
        task = session._settle_task
        await session._handle_frame({"data": "HELD", "sessionId": 6}, cdp)
        await session._stop_screencast()
        await asyncio.sleep(0)
        self.assertTrue(task.cancelled() or task.done())
        self.assertFalse(session._settling)
        self.assertEqual(sent, [])

    async def test_stale_cdp_lifecycle_event_is_ignored(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, _ = await self._session(cdp)
        await self._settle(session)
        session._on_lifecycle_event({"frameId": "MAIN", "name": "init"}, object())
        self.assertFalse(session._settling)

    async def test_late_white_frame_cannot_overwrite_recaptured_screen(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        original = cdp.send

        async def send(method, params=None):
            if method == "Page.captureScreenshot" and params.get("format") == "jpeg":
                await session._handle_frame({"data": "LATE_WHITE", "sessionId": 10}, cdp)
            return await original(method, params)

        cdp.send = send
        await self._settle(session)
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_white_frame_acknowledged_after_settle_is_not_forwarded(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        ack_started, ack_release = asyncio.Event(), asyncio.Event()
        original = cdp.send

        async def send(method, params=None):
            if method == "Page.screencastFrameAck":
                ack_started.set()
                await ack_release.wait()
            return await original(method, params)

        cdp.send = send
        frame = asyncio.create_task(session._handle_frame({"data": "DELAYED_WHITE", "sessionId": 11}, cdp))
        await ack_started.wait()
        await self._settle(session)
        ack_release.set()
        await frame
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_repeated_paint_events_do_not_consume_retry_delays(self):
        cdp = _SettleCdp([CHROMIUM_BLANK_WHITE_PNG])
        session, sent = await self._session(cdp)
        original_probe, original_sleep = session._probe_blank, asyncio.sleep
        delays = []

        async def probe(cdp):
            session._paint_event.set()  # firstPaint/FCP 等が各判定中に届く。
            return await original_probe(cdp)

        async def sleep(delay):
            delays.append(delay)
            await original_sleep(delay)

        session._probe_blank = probe
        session._paint_event.set()
        with patch("wscan.manual_crawl.asyncio.sleep", side_effect=sleep):
            await self._settle(session)
        self.assertEqual([d for d in delays if d], [0.01, 0.01])
        self.assertEqual(cdp.thumb_count(), 3)
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_new_document_during_probe_requires_another_probe(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        original = session._probe_blank
        calls = []

        async def probe(cdp):
            calls.append(session._loader_id)
            if len(calls) == 1:
                session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": "NEW"}, cdp)
            return await original(cdp)

        session._probe_blank = probe
        await self._settle(session)
        self.assertEqual(calls, [None, "NEW"])
        self.assertEqual(sent, ["RECAPTURED"])

    async def test_navigation_during_recapture_discards_old_screenshot(self):
        cdp = _SettleCdp([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        original = cdp.send
        captures = 0

        async def send(method, params=None):
            nonlocal captures
            if method == "Page.captureScreenshot" and params.get("format") == "jpeg":
                captures += 1
                if captures == 1:
                    session._on_lifecycle_event({"frameId": "MAIN", "name": "init", "loaderId": "NEW"}, cdp)
                    return {"data": "OLD_DOCUMENT"}
            return await original(method, params)

        cdp.send = send
        await asyncio.sleep(.1)
        await self._settle(session)
        self.assertEqual(sent, ["RECAPTURED"])
        self.assertEqual(captures, 2)

    async def test_lifecycle_enable_failure_keeps_streaming(self):
        class _NoLifecycle(_SettleCdp):
            async def send(self, method, params=None):
                if method in ("Page.enable", "Page.setLifecycleEventsEnabled", "Page.getFrameTree"):
                    self.sent.append((method, params))
                    raise RuntimeError("unsupported")
                return await super().send(method, params)

        cdp = _NoLifecycle([CHROMIUM_TEXT_PNG])
        session, sent = await self._session(cdp)
        self.assertIs(session._cdp, cdp)
        self.assertIsNone(session._main_frame_id)
        await self._settle(session)
        await session._handle_frame({"data": "LIVE", "sessionId": 7}, cdp)
        self.assertEqual(sent, ["RECAPTURED", "LIVE"])


if __name__ == "__main__":
    unittest.main()
