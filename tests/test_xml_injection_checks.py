"""0035-D3: XML body injection carrier slice unit & contract tests."""
import unittest
import httpx

from tests.test_stage5b1_migration import _Engine
from wscan.injection_point import (
    InjectionPoint,
    mutate_xml_payload,
    enumerate_xml_leaf_paths,
)
from wscan.scanner_contract import Carrier, ValueKind
from wscan.scanners.sqli import SQLiScanner
from wscan.scanners.xss import XSSScanner
from wscan.engine import ScanEngine


class _FakeEngine:
    def __init__(self, templates=None, transport=None):
        self.injection_templates = dict(templates or {})
        self._transport = transport
        self.timeout = 10
        self.target_url = "http://fixture.test"
        self.browser = None
        self.monitor = None
        self.scan_profile = "full"
        self.state_profile = "read-write"
        self.payload_gen = PayloadGenerator()
        self.custom_payloads = {}
        self.sleep_factor = 0.0
        self.active_attack = None
        self._xml_probe_sent = False
        self._xml_probe_failed = False
        self._api_auth_failed = False
        self.wave_errors = []

    def httpx_client_kwargs(self, **kwargs):
        if self._transport is not None:
            kwargs["transport"] = self._transport
        return kwargs

    def _record_scan_note(self, note: str):
        self.wave_errors.append(note)


class XmlInjectionPointTests(unittest.TestCase):
    def test_for_xml_body_properties_and_carrier(self):
        ip = InjectionPoint.for_xml_body(
            "POST",
            "http://fixture.test/api/xml",
            "/root/user/name",
            template_id="tpl-xml-1",
        )
        self.assertEqual(ip.carrier, Carrier.XML)
        self.assertEqual(ip.location, "xml_body")
        self.assertEqual(ip.method, "POST")
        self.assertEqual(ip.url, "http://fixture.test/api/xml")
        self.assertEqual(ip.parameter_id, "/root/user/name")
        self.assertEqual(ip.display_name, "name")
        self.assertEqual(ip.template_id, "tpl-xml-1")
        self.assertEqual(ip.value_kind, ValueKind.STRING)

    def test_for_xml_body_attribute_display_name(self):
        ip = InjectionPoint.for_xml_body(
            "PUT",
            "http://fixture.test/api/xml",
            "/root/item/@id",
        )
        self.assertEqual(ip.carrier, Carrier.XML)
        self.assertEqual(ip.display_name, "id")
        self.assertEqual(ip.parameter_id, "/root/item/@id")

    def test_legacy_is_url_param_raises_on_xml_body(self):
        ip = InjectionPoint.for_xml_body("POST", "http://fixture.test/api", "/root/name")
        with self.assertRaises(ValueError):
            ip.legacy_is_url_param()

    def test_stable_key_parts_for_xml_body(self):
        ip = InjectionPoint.for_xml_body(
            "POST",
            "http://fixture.test/api/xml?token=123",
            "/root/query",
        )
        norm_url, field_name, form_idx, loc_tok, pointer = ip.stable_key_parts()
        self.assertEqual(norm_url, "http://fixture.test/api/xml?token=123")
        self.assertEqual(field_name, "query")
        self.assertEqual(form_idx, "0")
        self.assertEqual(loc_tok, "x:POST")
        self.assertEqual(pointer, "/root/query")


class XmlMutationPureTests(unittest.TestCase):
    def test_mutate_element_text(self):
        xml_in = '<?xml version="1.0"?>\n<root><user><name>Alice</name></user></root>'
        res = mutate_xml_payload(xml_in, "/root/user/name", "Bob' OR '1'='1")
        self.assertIn("<name>Bob' OR '1'='1</name>", res)
        self.assertTrue(res.startswith('<?xml version="1.0"?>'))

    def test_mutate_attribute(self):
        xml_in = '<catalog><book id="bk101"><title>XML Developer</title></book></catalog>'
        res = mutate_xml_payload(xml_in, "/catalog/book/@id", 'bk999"><script>')
        self.assertIn('id="bk999&quot;&gt;&lt;script&gt;"', res)

    def test_mutate_indexed_elements(self):
        xml_in = '<items><item>first</item><item>second</item></items>'
        res0 = mutate_xml_payload(xml_in, "/items/item[0]", "first_mod")
        self.assertIn("<item>first_mod</item><item>second</item>", res0)

        res1 = mutate_xml_payload(xml_in, "/items/item[1]", "second_mod")
        self.assertIn("<item>first</item><item>second_mod</item>", res1)

    def test_enumerate_leaf_paths(self):
        xml_in = '<order id="1"><item name="pen">Blue</item><item name="paper">White</item></order>'
        paths = enumerate_xml_leaf_paths(xml_in)
        expected = [
            "/order/@id",
            "/order/item[0]/@name",
            "/order/item[0]",
            "/order/item[1]/@name",
            "/order/item[1]",
        ]
        self.assertEqual(paths, expected)


class XmlCarrierHttpDetectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_sqli_xml_body_vulnerable_detected_and_safe_twin_negative(self):
        # 脆弱なエンドポイント: SQL エラーを返す
        def vuln_handler(request: httpx.Request):
            body = request.content.decode("utf-8")
            if "'" in body or "--" in body:
                return httpx.Response(500, text="syntax error at or near 'admin' (PostgreSQL error)")
            return httpx.Response(200, text="<response><status>ok</status></response>")

        # 安全なエンドポイント: 適切にエスケープ/パラメータ化
        def safe_handler(request: httpx.Request):
            return httpx.Response(200, text="<response><status>ok</status></response>")

        xml_tpl = "<user><username>admin</username><role>user</role></user>"
        ip = InjectionPoint.for_xml_body("POST", "http://fixture.test/api/profile", "/user/username", template_id="tpl-sqli")

        # 1. 脆弱ハンドラ
        engine_vuln = _Engine(transport=httpx.MockTransport(vuln_handler))
        engine_vuln.injection_templates["tpl-sqli"] = {"method": "POST", "url": ip.url, "xml_body": xml_tpl}
        scanner_vuln = SQLiScanner(engine_vuln)
        findings_vuln = await scanner_vuln.scan_injection_point(ip, {"name": "username"})
        self.assertEqual(len(findings_vuln), 1)
        self.assertEqual(findings_vuln[0].check_type, "sqli")
        self.assertEqual(findings_vuln[0].injection_location, "xml_body")

        # 2. 安全ツイン
        engine_safe = _Engine(transport=httpx.MockTransport(safe_handler))
        engine_safe.injection_templates["tpl-sqli"] = {"method": "POST", "url": ip.url, "xml_body": xml_tpl}
        scanner_safe = SQLiScanner(engine_safe)
        findings_safe = await scanner_safe.scan_injection_point(ip, {"name": "username"})
        self.assertEqual(findings_safe, [])

    async def test_xss_xml_body_vulnerable_detected_and_safe_twin_negative(self):
        # 脆弱なエンドポイント: XML をパースして得たテキストを unescaped で HTML 応答に埋め込む
        def vuln_handler(request: httpx.Request):
            import xml.etree.ElementTree as ET
            root = ET.fromstring(request.content.decode("utf-8"))
            comment_elem = root.find("comment")
            val = comment_elem.text if comment_elem is not None and comment_elem.text else ""
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                text=f"<html><body><h1>Comment preview:</h1><div>{val}</div></body></html>",
            )

        # 安全なエンドポイント: HTML エスケープして埋め込む
        def safe_handler(request: httpx.Request):
            import xml.etree.ElementTree as ET
            import html as h
            root = ET.fromstring(request.content.decode("utf-8"))
            comment_elem = root.find("comment")
            val = h.escape(comment_elem.text if comment_elem is not None and comment_elem.text else "")
            return httpx.Response(
                200,
                headers={"Content-Type": "text/html; charset=utf-8"},
                text=f"<html><body><h1>Comment preview:</h1><div>{val}</div></body></html>",
            )

        xml_tpl = "<review><id>42</id><comment>Nice product</comment></review>"
        ip = InjectionPoint.for_xml_body("POST", "http://fixture.test/api/review", "/review/comment", template_id="tpl-xss")

        class _PG:
            async def generate(self, **_kwargs):
                return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]

        # 1. 脆弱ハンドラ
        engine_vuln = _Engine(transport=httpx.MockTransport(vuln_handler))
        engine_vuln.payload_gen = _PG()
        engine_vuln.injection_templates["tpl-xss"] = {"method": "POST", "url": ip.url, "xml_body": xml_tpl}
        scanner_vuln = XSSScanner(engine_vuln)
        findings_vuln = await scanner_vuln.scan_injection_point(ip, {"name": "comment"})
        self.assertEqual(len(findings_vuln), 1)
        self.assertEqual(findings_vuln[0].check_type, "xss")
        self.assertEqual(findings_vuln[0].injection_location, "xml_body")

        # 2. 安全ツイン
        engine_safe = _Engine(transport=httpx.MockTransport(safe_handler))
        engine_safe.payload_gen = _PG()
        engine_safe.injection_templates["tpl-xss"] = {"method": "POST", "url": ip.url, "xml_body": xml_tpl}
        scanner_safe = XSSScanner(engine_safe)
        findings_safe = await scanner_safe.scan_injection_point(ip, {"name": "comment"})
        self.assertEqual(findings_safe, [])


class EngineXmlInjectionChecksTests(unittest.IsolatedAsyncioTestCase):
    async def test_run_xml_injection_checks_lifecycle(self):
        class _TestScanner:
            SUPPORTS_XML_BODY = True

            def __init__(self):
                self.scanned = []

            async def scan_injection_point(self, ip, field):
                self.scanned.append((ip, field))
                return []

        scanner = _TestScanner()
        engine = ScanEngine("http://fixture.test", headless=True)
        engine.scanners = {"sqli": scanner}
        ip = InjectionPoint.for_xml_body("POST", "http://fixture.test/api/xml", "/root/q", template_id="t1")
        engine.xml_injection_points = [ip]
        engine.injection_templates["t1"] = {"url": ip.url, "xml_body": "<root><q>1</q></root>"}

        # モックして実行
        async def fake_relogin(*args, **kwargs):
            return None
        async def fake_sync(*args, **kwargs):
            return None
        async def fake_expired(*args, **kwargs):
            return False

        engine._maybe_relogin_for_page = fake_relogin
        engine._sync_cookies_from_browser = fake_sync
        engine._api_session_looks_expired = fake_expired
        engine._xml_probe_sent = True

        await engine._run_xml_injection_checks()
        self.assertEqual(len(scanner.scanned), 1)
        self.assertEqual(scanner.scanned[0][0], ip)
