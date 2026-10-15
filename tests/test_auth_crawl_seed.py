import unittest
from pathlib import Path


class AuthCrawlSeedTests(unittest.TestCase):
    def test_engine_seeds_auto_login_landing_url(self):
        text = Path("wscan/engine.py").read_text(encoding="utf-8")
        expected = (
            "self.auth_landing_url",
            "last_login_url",
            "ログイン後ページをクロールキューに追加",
            "queue.append((self.auth_landing_url, 0, self.target_url))",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_browser_waits_for_login_navigation_before_polling(self):
        text = Path("wscan/browser.py").read_text(encoding="utf-8")
        expected = (
            "deadline = time.monotonic() + 15",
            "last_login_url",
            # 成否判定は login_surface の純粋関数に集約する。
            "auth_detect",
            "assess_login_state(",
        )

        for marker in expected:
            with self.subTest(marker=marker):
                self.assertIn(marker, text)

    def test_auth_detect_checks_success_indicator_against_url_and_body(self):
        text = Path("wscan/auth_detect.py").read_text(encoding="utf-8")
        # success_indicator は URL・本文の双方に対して照合する。
        self.assertIn("success_indicator in (post_url", text)
        self.assertIn("success_indicator in (body", text)


if __name__ == "__main__":
    unittest.main()
