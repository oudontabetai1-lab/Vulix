import types
import unittest

from wscan.scanners.csrf import CSRFScanner, unprotected_post_forms
from tests.fixtures.realistic_api import create_app


def _scanner():
    async def _shot(label=""):
        return ""

    browser = types.SimpleNamespace(
        network=types.SimpleNamespace(latest_for_url=lambda url, match_query=True: None),
        dialog_screenshot_b64="",
        screenshot_b64=_shot,
        page=None,  # 現在タブ(別ページ)に依存しないことを担保
    )
    engine = types.SimpleNamespace(
        browser=browser, monitor=None, payload_gen=object(),
        _finding_dedup=set(), all_findings=[],
    )
    return CSRFScanner(engine)


class UnprotectedPostFormsTests(unittest.TestCase):
    def test_pure_detection(self):
        vuln = '<form method="post" action="/a"><input name="card"></form>'
        safe = '<form method="POST"><input type="hidden" name="csrf-token"><input name="x"></form>'
        get = '<form action="/s"><input name="q"></form>'
        self.assertEqual([f["index"] for f in unprotected_post_forms(vuln + safe + get)], [0])
        self.assertEqual(unprotected_post_forms(safe), [])
        self.assertEqual(unprotected_post_forms(get), [])
        self.assertEqual(unprotected_post_forms(""), [])


class CsrfScanPageContextTests(unittest.IsolatedAsyncioTestCase):
    async def _html(self, path):
        import httpx
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://t") as c:
            return (await c.get(path)).text

    async def test_fixture_vulnerable_page_detected_and_safe_twin_clean(self):
        for path, expected in (
            ("/console/billing/payment-method", 1),
            ("/console/billing/payment-method-safe", 0),
        ):
            page = types.SimpleNamespace(url="http://t" + path, html=await self._html(path))
            findings = await _scanner().scan_page_context(page)
            self.assertEqual(len(findings), expected, path)


if __name__ == "__main__":
    unittest.main()
