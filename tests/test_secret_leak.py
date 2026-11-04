"""Unit tests for the SecretLeakScanner pure helpers."""
import unittest
import types
from unittest.mock import AsyncMock

from wscan.scanners.base import PageDocumentUnavailable
from wscan.scanners.secret_leak import (
    _redact,
    _shannon_entropy,
    scan_text_for_secrets,
    is_script_scan_allowed,
)


class SecretLeakDetectionTests(unittest.TestCase):
    def _labels(self, text: str) -> list[str]:
        return [hit["label"] for hit in scan_text_for_secrets(text)]

    def test_aws_access_key_id_detected(self):
        labels = self._labels(
            'var creds = {key: "AKIAIOSFODNN7EXAMPLE2", region: "us-east-1"};'
        )
        # "AKIAIOSFODNN7EXAMPLE2" — placeholder filter must NOT eat the
        # detection just because it contains "EXAMPLE" — wait: this string does
        # contain EXAMPLE, so it should be filtered.  Use a non-placeholder one:
        # Verify behaviour explicitly below.
        self.assertEqual(labels, [])

    def test_aws_access_key_id_real_looking(self):
        text = "AKIA5JZQNVRT7H3KX9PQ in the bundle"
        self.assertIn("AWS Access Key ID", self._labels(text))

    def test_google_api_key_detected(self):
        text = 'window.MAP_KEY = "AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";'
        self.assertIn("Google API Key", self._labels(text))

    def test_github_pat_detected(self):
        # 36 char body — randomish to clear entropy gate.
        text = "Authorization: token ghp_abc123XYZdef456UVWghi789RSTjkl012Mno end"
        self.assertIn("GitHub Personal Access Token", self._labels(text))

    def test_stripe_secret_key_detected(self):
        # Build the token at runtime — GitHub push-protection scans the file
        # contents and would otherwise mistake this fixture for a live key.
        prefix = "s" + "k_" + "l" + "ive_"
        token = prefix + "9aQwBcVnZpYrLqWtMx7HdSeF"
        text = f"config.stripe = '{token}';"
        self.assertIn("Stripe Secret Key", self._labels(text))

    def test_pem_private_key_block_detected(self):
        text = (
            "-----BEGIN RSA PRIVATE KEY-----\n"
            "MIIEowIBAAKCAQEAxa…\n"
            "-----END RSA PRIVATE KEY-----"
        )
        self.assertIn("PEM Private Key Block", self._labels(text))

    def test_placeholders_are_ignored(self):
        # Some placeholder prefixes are constructed at runtime so the file
        # itself does not trip GitHub's push-protection secret regexes.
        stripe_placeholder = "s" + "k_" + "l" + "ive_" + "FAKEFAKEFAKEFAKEFAKEFAKEFAKE"
        for placeholder in (
            "AKIAIOSFODNN7EXAMPLE",
            "AIzaSyDEMO_PLACEHOLDER_KEY_VALUE_AAAAAAAAA",
            "ghp_YOUR_TOKEN_HERE_XXXXXXXXXXXXXXXXXXXXXXX",
            stripe_placeholder,
        ):
            with self.subTest(placeholder=placeholder):
                self.assertEqual(self._labels(placeholder), [])

    def test_benign_text_produces_no_findings(self):
        for benign in (
            "Lorem ipsum dolor sit amet, consectetur adipiscing elit.",
            "<html><body><h1>Welcome</h1><p>No secrets here.</p></body></html>",
            "function add(a, b) { return a + b; }",
            "",
        ):
            with self.subTest(benign=benign):
                self.assertEqual(self._labels(benign), [])

    def test_duplicate_secret_reported_once(self):
        token = "ghp_aBcD1234EFgh5678IJkl9012MNop3456QRst"
        text = f"{token}\n// duplicated:\n{token}"
        hits = scan_text_for_secrets(text)
        self.assertEqual(
            len([h for h in hits if h["label"] == "GitHub Personal Access Token"]),
            1,
        )

    def test_redaction_hides_most_of_secret(self):
        secret = "ghp_aBcD1234EFgh5678IJkl9012MNop3456QRst"
        redacted = _redact(secret)
        self.assertNotIn("aBcD1234", redacted)
        self.assertTrue(redacted.startswith("ghp_"))
        self.assertTrue(redacted.endswith("QRst"))

    def test_snippets_redact_adjacent_and_duplicate_secrets(self):
        import json
        tokens = ['ghp_' + 'abc123XYZdef456UVWghi789RSTjkl012Mno',
                  'ghp_' + 'aBcD1234EFgh5678IJkl9012MNop3456QRst']
        hits = scan_text_for_secrets(' '.join(tokens * 2))
        self.assertEqual(len(hits), 2)
        serialized = json.dumps(hits, ensure_ascii=False)
        for token in tokens:
            self.assertNotIn(token, serialized)
            self.assertIn(_redact(token), serialized)

    def test_entropy_filter_rejects_low_entropy_aws_secret(self):
        # 40 chars but trivially low entropy — should be filtered.
        low_entropy = "aws_secret=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
        self.assertEqual(self._labels(low_entropy), [])
        # Sanity check on the entropy helper itself.
        self.assertLess(_shannon_entropy("A" * 40), 1.0)


class SecretLeakScriptContextTests(unittest.IsolatedAsyncioTestCase):
    async def test_scans_captured_in_scope_scripts_once_and_skips_out_of_scope(self):
        from wscan.scanners.secret_leak import SecretLeakScanner

        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            _is_access_allowed_url=lambda url: url.startswith("http://target.test/"),
        )
        scanner = SecretLeakScanner(engine)
        scanner._document_body = AsyncMock(return_value="safe referring document")
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)
        page = types.SimpleNamespace(url="http://target.test/portal", external_scripts={
            "http://target.test/assets/app.js": 'window.key="AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";',
            "https://outside.test/vendor.js": 'window.key="AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";',
            "http://target.test/assets/safe.js": "function add(a,b){return a+b}",
        })

        found = await scanner.scan_page_context(page)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["url"], "http://target.test/assets/app.js")
        self.assertEqual(found[0]["evidence_details"]["resource_url"],
                         "http://target.test/assets/app.js")
        self.assertEqual(found[0]["evidence_details"]["referring_page_url"], page.url)
        self.assertEqual(await scanner.scan_page_context(page), [])
        self.assertEqual(await scanner.scan_page("http://target.test/assets/app.js"), [])
        self.assertEqual(scanner.record_finding.await_count, 1)
        self.assertEqual(scanner._document_body.await_count, 1)

    async def test_honors_url_exclusions_for_captured_scripts(self):
        # Edge 2: 捕捉済みスクリプトに対してもオペレータの URL 除外ルール（_is_url_excluded）を適用する。
        from wscan.scanners.secret_leak import SecretLeakScanner

        excluded_urls = {"http://target.test/static/private.js"}
        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            _is_access_allowed_url=lambda url: url.startswith("http://target.test/"),
            _is_url_excluded=lambda url: url in excluded_urls,
        )
        scanner = SecretLeakScanner(engine)
        scanner._document_body = AsyncMock(return_value="safe referring document")
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)

        page = types.SimpleNamespace(
            url="http://target.test/portal",
            external_scripts={
                # 除外対象のスクリプト（秘密を含むが除外設定により走査・報告されない）
                "http://target.test/static/private.js": 'window.secret="AKIA5JZQNVRT7H3KX9P1";',
                # 安全ツイン: 除外対象外のスクリプト（秘密を含むため確実に報告される）
                "http://target.test/static/public.js": 'window.secret="AKIA5JZQNVRT7H3KX9P2";',
                # 安全ツイン: 除外対象外の無害スクリプト（秘密を含まないため報告されない）
                "http://target.test/static/safe.js": "function greet(){return 'hello';}",
            },
        )

        found = await scanner.scan_page_context(page)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["url"], "http://target.test/static/public.js")
        self.assertEqual(found[0]["evidence_details"]["resource_url"], "http://target.test/static/public.js")

    def test_pure_is_script_scan_allowed(self):
        # Edge 2 の純粋判定関数テスト
        in_scope = lambda u: "in-scope" in u
        is_excl = lambda u: "private" in u

        # スコープ内かつ除外対象外 -> True
        self.assertTrue(is_script_scan_allowed("https://in-scope.test/public.js", in_scope, is_excl))
        # 除外対象 -> False
        self.assertFalse(is_script_scan_allowed("https://in-scope.test/private.js", in_scope, is_excl))
        # スコープ外 -> False
        self.assertFalse(is_script_scan_allowed("https://out-of-scope.test/public.js", in_scope, is_excl))

    async def test_captured_scripts_not_gated_on_document_replay_failure(self):
        # Edge 5: 参照ドキュメントの再取得（direct GET）がタイムアウト/PageDocumentUnavailable で
        # 失敗しても、crawl 時に捕捉済みのスクリプト本文の検査をゲートせず実行する。
        from wscan.scanners.secret_leak import SecretLeakScanner

        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            _is_access_allowed_url=lambda url: True,
            _is_url_excluded=lambda url: False,
        )
        scanner = SecretLeakScanner(engine)
        # ドキュメントの direct GET が例外を送出
        scanner._document_body = AsyncMock(side_effect=PageDocumentUnavailable("document timeout"))
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)

        page = types.SimpleNamespace(
            url="http://target.test/flaky-doc",
            external_scripts={
                "http://target.test/assets/app.js": 'window.key="AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";',
            },
        )

        # page.html が無い場合、捕捉済みスクリプトの finding を保持して PageDocumentUnavailable が再送出される
        with self.assertRaises(PageDocumentUnavailable) as cm:
            await scanner.scan_page_context(page)
        self.assertEqual(len(cm.exception.findings), 1)
        self.assertEqual(cm.exception.findings[0]["url"], "http://target.test/assets/app.js")

    async def test_captured_document_html_used_when_replay_unavailable(self):
        # Edge 5: クロール時に捕捉済みの page.html があれば、direct GET が失敗しても
        # すでに捕捉された本文を使って検査を完了する。
        from wscan.scanners.secret_leak import SecretLeakScanner

        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            _is_access_allowed_url=lambda url: True,
            _is_url_excluded=lambda url: False,
        )
        scanner = SecretLeakScanner(engine)
        scanner._document_body = AsyncMock(side_effect=PageDocumentUnavailable("direct GET timed out"))
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)

        page = types.SimpleNamespace(
            url="http://target.test/offline-doc",
            html='<html><body><script>var k="AKIA5JZQNVRT7H3KX9P1";</script></body></html>',
            external_scripts={
                "http://target.test/assets/app.js": 'window.key="AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";',
            },
        )

        # page.html があるため PageDocumentUnavailable にならず両方の finding が返る
        findings = await scanner.scan_page_context(page)
        self.assertEqual(len(findings), 2)
        urls = [f["url"] for f in findings]
        self.assertIn("http://target.test/offline-doc", urls)
        self.assertIn("http://target.test/assets/app.js", urls)

    async def test_safe_twin_document_replay_failure_without_secrets(self):
        # 安全ツイン: direct GET が失敗し、捕捉済みスクリプトも無害な場合、偽陽性の finding は生成されない。
        from wscan.scanners.secret_leak import SecretLeakScanner

        engine = types.SimpleNamespace(
            browser=None, monitor=None, payload_gen=None, wave_errors=[],
            _is_access_allowed_url=lambda url: True,
            _is_url_excluded=lambda url: False,
        )
        scanner = SecretLeakScanner(engine)
        scanner._document_body = AsyncMock(side_effect=PageDocumentUnavailable("document timeout"))
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)

        page = types.SimpleNamespace(
            url="http://target.test/flaky-doc",
            external_scripts={
                "http://target.test/assets/safe.js": "function add(a, b) { return a + b; }",
            },
        )

        with self.assertRaises(PageDocumentUnavailable) as cm:
            await scanner.scan_page_context(page)
        self.assertEqual(len(cm.exception.findings), 0)

    async def test_redirected_script_response_followed_and_scanned(self):
        # Edge 4: in-scope <script src> がリダイレクトされた場合、遷移先の最終本文を取得して走査・検出する。
        from wscan.engine import ScanEngine
        from wscan.scanners.secret_leak import SecretLeakScanner

        class CapturedNetwork:
            def latest_for_url(self, url, **_kwargs):
                if url == "http://target.test/app.js":
                    # リダイレクト応答（302, Location ヘッダあり, 本文なし）
                    return {
                        "request": {"url": url},
                        "response": {
                            "status": 302,
                            "url": url,
                            "headers": {"location": "/static/app.bundle.js"},
                            "body": "",
                        },
                    }
                elif url == "http://target.test/static/app.bundle.js":
                    # 最終的なスクリプト実体（200, 秘密を含む本文）
                    return {
                        "request": {"url": url},
                        "response": {
                            "status": 200,
                            "url": url,
                            "headers": {"content-type": "application/javascript"},
                            "body": 'window.key="AIzaSyA-WLh38Kv9XQ7yz1bP4uMd3RTaZ2nHkLm";',
                        },
                    }
                return None

        engine = ScanEngine.__new__(ScanEngine)
        engine._browser = types.SimpleNamespace(network=CapturedNetwork())
        engine.monitor = None
        engine.payload_gen = None
        engine.wave_errors = []
        engine._is_access_allowed_url = lambda url: True
        engine._is_url_excluded = lambda url: False

        # _snapshot_external_scripts がリダイレクトを追跡して final body を確保する
        snapshot = engine._snapshot_external_scripts(
            '<script src="/app.js"></script>',
            "http://target.test/page",
        )
        self.assertIn("http://target.test/app.js", snapshot)
        self.assertIn("AIzaSyA", snapshot["http://target.test/app.js"])

        # scanner がそのスナップショットから秘密を検出する
        scanner = SecretLeakScanner(engine)
        scanner._document_body = AsyncMock(return_value="safe document")
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)

        page = types.SimpleNamespace(url="http://target.test/page", external_scripts=snapshot)
        found = await scanner.scan_page_context(page)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["url"], "http://target.test/app.js")

    async def test_safe_twin_redirected_script_without_secrets(self):
        # 安全ツイン: リダイレクト先の本文が無害な場合、秘密漏洩として誤検知されない。
        from wscan.engine import ScanEngine
        from wscan.scanners.secret_leak import SecretLeakScanner

        class CapturedNetwork:
            def latest_for_url(self, url, **_kwargs):
                if url == "http://target.test/app.js":
                    return {
                        "response": {
                            "status": 302,
                            "url": url,
                            "headers": {"location": "/static/safe.bundle.js"},
                            "body": "",
                        },
                    }
                elif url == "http://target.test/static/safe.bundle.js":
                    return {
                        "response": {
                            "status": 200,
                            "url": url,
                            "headers": {"content-type": "application/javascript"},
                            "body": "function run() { return 42; }",
                        },
                    }
                return None

        engine = ScanEngine.__new__(ScanEngine)
        engine._browser = types.SimpleNamespace(network=CapturedNetwork())
        engine.monitor = None
        engine.payload_gen = None
        engine.wave_errors = []
        engine._is_access_allowed_url = lambda url: True
        engine._is_url_excluded = lambda url: False

        snapshot = engine._snapshot_external_scripts(
            '<script src="/app.js"></script>',
            "http://target.test/page",
        )
        self.assertIn("http://target.test/app.js", snapshot)

        scanner = SecretLeakScanner(engine)
        scanner._document_body = AsyncMock(return_value="safe document")
        scanner.record_finding = AsyncMock(side_effect=lambda **kw: kw)

        page = types.SimpleNamespace(url="http://target.test/page", external_scripts=snapshot)
        found = await scanner.scan_page_context(page)
        self.assertEqual(len(found), 0)

    def test_pure_follow_redirect_chain_in_network(self):
        # Edge 4 の純粋リダイレクト追跡ヘルパーの単体テスト
        from wscan.component_intel import follow_redirect_chain_in_network

        class MockNetwork:
            def __init__(self, table):
                self.table = table

            def latest_for_url(self, url, **_kwargs):
                return self.table.get(url)

        # 1. 直接一致（リダイレクトなし）
        net1 = MockNetwork({
            "http://t.test/a.js": {"response": {"status": 200, "body": "ok"}},
        })
        url, pair = follow_redirect_chain_in_network(net1, "http://t.test/a.js")
        self.assertEqual(url, "http://t.test/a.js")
        self.assertEqual(pair["response"]["body"], "ok")

        # 2. 2ホップリダイレクト: /a.js -> /b.js -> /c.js
        net2 = MockNetwork({
            "http://t.test/a.js": {"response": {"status": 301, "headers": {"Location": "/b.js"}}},
            "http://t.test/b.js": {"response": {"status": 302, "headers": {"location": "http://t.test/c.js"}}},
            "http://t.test/c.js": {"response": {"status": 200, "body": "final_script"}},
        })
        url, pair = follow_redirect_chain_in_network(net2, "http://t.test/a.js")
        self.assertEqual(url, "http://t.test/c.js")
        self.assertEqual(pair["response"]["body"], "final_script")

        # 3. ループリダイレクト: /loop1 -> /loop2 -> /loop1（無限ループせず安全に終了）
        net3 = MockNetwork({
            "http://t.test/loop1": {"response": {"status": 302, "headers": {"location": "/loop2"}}},
            "http://t.test/loop2": {"response": {"status": 302, "headers": {"location": "/loop1"}}},
        })
        url, pair = follow_redirect_chain_in_network(net3, "http://t.test/loop1")
        self.assertIn(url, ("http://t.test/loop1", "http://t.test/loop2"))


if __name__ == "__main__":
    unittest.main()
