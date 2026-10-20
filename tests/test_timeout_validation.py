"""タイムアウト純粋検証関数のテスト。"""
import math
import unittest

from wscan.timeout_validation import (
    validate_positive_timeout,
    validate_scan_timeouts,
)


class TimeoutValidationTests(unittest.TestCase):
    def test_valid_positive_numbers(self):
        self.assertEqual(validate_positive_timeout(10), 10.0)
        self.assertEqual(validate_positive_timeout(0.5), 0.5)
        self.assertEqual(validate_positive_timeout("30"), 30.0)
        self.assertEqual(validate_positive_timeout("12.5"), 12.5)

    def test_reject_zero(self):
        with self.assertRaises(ValueError) as ctx:
            validate_positive_timeout(0, "テストタイムアウト")
        self.assertIn("テストタイムアウト は正の数値である必要があります", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_positive_timeout("0.0")

    def test_reject_negative(self):
        with self.assertRaises(ValueError) as ctx:
            validate_positive_timeout(-1, "HTTPタイムアウト")
        self.assertIn("HTTPタイムアウト は正の数値である必要があります", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_positive_timeout("-5.5")

    def test_reject_nan(self):
        with self.assertRaises(ValueError) as ctx:
            validate_positive_timeout(float("nan"), "LLMタイムアウト")
        self.assertIn("LLMタイムアウト に NaN は指定できません", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_positive_timeout("nan")
        with self.assertRaises(ValueError):
            validate_positive_timeout("NaN")

    def test_reject_inf(self):
        with self.assertRaises(ValueError) as ctx:
            validate_positive_timeout(float("inf"), "ストリームタイムアウト")
        self.assertIn("ストリームタイムアウト に無限大(Inf)は指定できません", str(ctx.exception))

        with self.assertRaises(ValueError):
            validate_positive_timeout("-inf")
        with self.assertRaises(ValueError):
            validate_positive_timeout("Infinity")

    def test_reject_non_numeric(self):
        with self.assertRaises(ValueError) as ctx:
            validate_positive_timeout("abc", "設定値")
        self.assertIn("設定値 は数値である必要があります", str(ctx.exception))

    def test_allow_none_and_default(self):
        self.assertEqual(
            validate_positive_timeout(None, allow_none=True, default=30.0),
            30.0,
        )
        self.assertEqual(
            validate_positive_timeout("", allow_none=True, default=45.0),
            45.0,
        )
        with self.assertRaises(ValueError):
            validate_positive_timeout(None, allow_none=False)

    def test_validate_scan_timeouts_distinguishes_item_names(self):
        # HTTP タイムアウトが不正な場合
        with self.assertRaises(ValueError) as ctx:
            validate_scan_timeouts(timeout=0, llm_timeout=30)
        self.assertIn("HTTP/ページ読み込みタイムアウト", str(ctx.exception))

        # LLM タイムアウトが不正な場合
        with self.assertRaises(ValueError) as ctx:
            validate_scan_timeouts(timeout=30, llm_timeout=-10)
        self.assertIn("LLM タイムアウト", str(ctx.exception))

        # LLM stream タイムアウトが不正な場合
        with self.assertRaises(ValueError) as ctx:
            validate_scan_timeouts(timeout=30, llm_timeout=30, llm_stream_timeout="nan")
        self.assertIn("LLM streaming タイムアウト", str(ctx.exception))

        # 正常ケース
        res = validate_scan_timeouts(timeout=15, llm_timeout="45", llm_stream_timeout=120)
        self.assertEqual(
            res,
            {"timeout": 15.0, "llm_timeout": 45.0, "llm_stream_timeout": 120.0},
        )

    def test_cli_argument_types(self):
        from main import _positive_float, _positive_int_or_float
        import argparse

        self.assertEqual(_positive_float("15.5"), 15.5)
        self.assertEqual(_positive_int_or_float("30"), 30)
        self.assertEqual(_positive_int_or_float("12.5"), 12.5)

        for bad in [0, -1, "nan", "inf", "abc"]:
            with self.assertRaises(argparse.ArgumentTypeError):
                _positive_float(bad)
            with self.assertRaises(argparse.ArgumentTypeError):
                _positive_int_or_float(bad)


if __name__ == "__main__":
    unittest.main()
