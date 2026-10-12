"""JSON body 注入の xss / nosql 検出。判定の純粋関数と、MockTransport 上の TP / FP ガード。

ブラウザ・実サーバ不要。脆弱応答だけでなく「安全ツイン」（文字列として扱う・エスケープする・
JSON で返す・厳格に 400 を返す）が陰性になることを同時に守る（誤検知ガード）。
"""
import html
import json
import re
import unittest

import httpx

from tests.test_stage5b1_migration import _Engine
from wscan.injection_point import InjectionPoint
from wscan.json_body_detect import (
    analyze_xss_reflection,
    nosql_json_verdict,
    renderable_html_body,
    response_of,
)
from wscan.scanners.nosql_injection import _NOSQL_ERROR_PATTERNS, NoSQLInjectionScanner
from wscan.scanners.xss import XSSScanner

_MEMBERS = [
    {"name": f"member{i}", "dept": "eng" if i % 2 else "ops", "title": "Engineer " * 3, "email": f"m{i}@corp.example"}
    for i in range(10)
]


def _empty(count=0):
    return {"count": count, "members": []}


def _match(dept, condition):
    if isinstance(condition, dict):  # 脆弱: 演算子 object をそのまま照合に使う
        if "$ne" in condition:
            return dept != condition["$ne"]
        if "$gt" in condition:
            return dept > condition["$gt"]
        return False
    return dept == condition


def _nosql_vulnerable(request: httpx.Request) -> httpx.Response:
    dept = json.loads(request.content)["department"]
    hits = [m for m in _MEMBERS if _match(m["dept"], dept)]
    return httpx.Response(200, json={"count": len(hits), "members": hits})


def _nosql_coercing_twin(request: httpx.Request) -> httpx.Response:
    dept = str(json.loads(request.content)["department"])  # 常に文字列比較
    hits = [m for m in _MEMBERS if m["dept"] == dept]
    return httpx.Response(200, json={"count": len(hits), "members": hits})


def _nosql_strict_twin(request: httpx.Request) -> httpx.Response:
    dept = json.loads(request.content)["department"]
    if not isinstance(dept, str):
        # 長い検証エラー本文（>500B）。2xx でないので膨張と誤認してはならない。
        return httpx.Response(400, json={"error": "department must be a string", "detail": "x" * 800})
    return httpx.Response(200, json=_empty())


def _xss_html_vulnerable(request: httpx.Request) -> httpx.Response:
    note = json.loads(request.content)["note"]
    return httpx.Response(200, text=f"<div class='note'>{note}</div>", headers={"content-type": "text/html; charset=utf-8"})


def _xss_html_escaped(request: httpx.Request) -> httpx.Response:
    note = json.loads(request.content)["note"]
    return httpx.Response(200, text=f"<div class='note'>{html.escape(note)}</div>", headers={"content-type": "text/html"})


def _xss_json_echo(request: httpx.Request) -> httpx.Response:
    note = json.loads(request.content)["note"]
    return httpx.Response(200, content=json.dumps({"note": note}), headers={"content-type": "application/json"})


class _PG:
    async def generate(self, **_kwargs):
        return ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>"]


def _scanner(cls, handler, body, key="department"):
    engine = _Engine(transport=httpx.MockTransport(handler))
    engine.payload_gen = _PG()
    engine.injection_templates["t"] = {
        "method": "POST", "url": "https://x.test/api", "json_body": body,
        "content_type": "application/json",
    }
    ip = InjectionPoint.for_json_body("POST", "https://x.test/api", f"/{key}", template_id="t")
    return cls(engine), ip, {"name": key}


class PureJudgementTests(unittest.TestCase):
    P = list(_NOSQL_ERROR_PATTERNS)

    def test_boolean_expansion_on_2xx_is_positive(self):
        v = nosql_json_verdict((200, "x" * 30), (200, "x" * 30), (200, "y" * 900), self.P)
        self.assertEqual(v.evidence_type, "nosql_boolean")

    def test_long_validation_error_is_not_expansion(self):
        self.assertIsNone(nosql_json_verdict((200, "x" * 30), (200, "x" * 30), (400, "y" * 900), self.P))

    def test_new_mongo_error_is_positive_but_preexisting_is_not(self):
        v = nosql_json_verdict((200, "ok"), (200, "ok"), (500, "MongoServerError: bad"), self.P)
        self.assertEqual(v.evidence_type, "nosql_error")
        self.assertIsNone(nosql_json_verdict((500, "MongoServerError"), (500, "MongoServerError"), (500, "MongoServerError"), self.P))

    def test_no_usable_baseline_is_negative(self):
        self.assertIsNone(nosql_json_verdict((None, ""), (None, ""), (200, "y" * 900), self.P))

    def test_failed_second_baseline_or_auth_response_is_negative(self):
        for baseline2, probe in (((None, ""), (200, "y" * 900)),
                                 ((200, "ok"), (401, "MongoServerError")),
                                 ((403, "denied"), (200, "y" * 900))):
            self.assertIsNone(nosql_json_verdict((200, "ok"), baseline2, probe, self.P))

    def test_xss_pure_judgement_excludes_escaped_and_preexisting_content(self):
        payload = "<img src=x onerror=alert(1)>"
        self.assertTrue(analyze_xss_reflection(payload, payload, "hello"))
        for body, baseline in ((html.escape(payload), "hello"), (payload, payload),
                               (f"<!-- {payload} -->", "hello")):
            self.assertEqual(analyze_xss_reflection(body, payload, baseline), {})

    def test_renderable_html_body_only_for_html(self):
        def pair(ctype):
            return {"response": {"headers": {"Content-Type": ctype} if ctype else {}, "body": "<b>"}}
        self.assertEqual(renderable_html_body(pair("text/html; charset=utf-8")), "<b>")
        self.assertEqual(renderable_html_body(pair("application/xhtml+xml")), "<b>")
        for non_html in ("application/json", "text/plain", ""):
            self.assertEqual(renderable_html_body(pair(non_html)), "")
        self.assertEqual(renderable_html_body({}), "")

    def test_response_of_normalises_failure(self):
        self.assertEqual(response_of("", {}), (None, ""))
        self.assertEqual(response_of("", {"response": {"status": 200, "body": "b"}}), (200, "b"))


class NosqlJsonTests(unittest.IsolatedAsyncioTestCase):
    async def test_operator_injection_detected_and_verified(self):
        s, ip, field = _scanner(NoSQLInjectionScanner, _nosql_vulnerable, {"department": "eng"})
        findings = await s.scan_injection_point(ip, field)
        self.assertEqual(len(findings), 1)
        f = findings[0]
        self.assertEqual((f.check_type, f.evidence_type, f.injection_location), ("nosql", "nosql_boolean", "json_body"))
        self.assertIsInstance(json.loads(f.payload), dict)  # 文字列ではなく構造化 JSON
        self.assertTrue(await s.verify_finding(f))

    async def test_safe_twins_are_negative(self):
        for handler in (_nosql_coercing_twin, _nosql_strict_twin):
            with self.subTest(handler=handler.__name__):
                s, ip, field = _scanner(NoSQLInjectionScanner, handler, {"department": "eng"})
                self.assertEqual(await s.scan_injection_point(ip, field), [])

    async def test_verify_is_indeterminate_when_replay_cannot_be_sent(self):
        s, ip, field = _scanner(NoSQLInjectionScanner, _nosql_vulnerable, {"department": "eng"})
        f = (await s.scan_injection_point(ip, field))[0]
        s.engine.injection_templates.clear()  # 再送不能（テンプレ消失）
        self.assertIsNone(await s.verify_finding(f))

    async def test_missing_template_records_no_finding(self):
        s, ip, field = _scanner(NoSQLInjectionScanner, _nosql_vulnerable, {"department": "eng"})
        s.engine.injection_templates.clear()
        self.assertEqual(await s.scan_injection_point(ip, field), [])


class XssJsonTests(unittest.IsolatedAsyncioTestCase):
    async def test_html_reflection_detected_and_verified(self):
        s, ip, field = _scanner(XSSScanner, _xss_html_vulnerable, {"note": "hi"}, key="note")
        findings = await s.scan_injection_point(ip, field)
        self.assertEqual(len(findings), 1)
        self.assertEqual((findings[0].check_type, findings[0].injection_location), ("xss", "json_body"))
        self.assertTrue(await s.verify_finding(findings[0]))

    async def test_safe_twins_are_negative(self):
        for handler in (_xss_html_escaped, _xss_json_echo):
            with self.subTest(handler=handler.__name__):
                s, ip, field = _scanner(XSSScanner, handler, {"note": "hi"}, key="note")
                self.assertEqual(await s.scan_injection_point(ip, field), [])

    async def test_verify_negative_when_reflection_gone(self):
        s, ip, field = _scanner(XSSScanner, _xss_html_vulnerable, {"note": "hi"}, key="note")
        f = (await s.scan_injection_point(ip, field))[0]
        s.engine._transport = httpx.MockTransport(_xss_html_escaped)
        self.assertFalse(await s.verify_finding(f))


class RealisticIntranetFixtureTests(unittest.IsolatedAsyncioTestCase):
    """実フィクスチャ（ASGI）に対する TP / 安全ツイン FP ガード。E2E 前のブラウザ非依存の確認。"""

    async def _scan(self, cls, path, key, body):
        from tests.fixtures.realistic_intranet import create_app

        engine = _Engine(transport=httpx.ASGITransport(app=create_app()))
        engine.payload_gen = _PG()
        engine.injection_templates["t"] = {
            "method": "POST", "url": f"http://testserver{path}", "json_body": body,
            "content_type": "application/json",
        }
        ip = InjectionPoint.for_json_body("POST", f"http://testserver{path}", f"/{key}", template_id="t")
        return await cls(engine).scan_injection_point(ip, {"name": key})

    async def test_vulnerable_endpoints_detected(self):
        nosql = await self._scan(NoSQLInjectionScanner, "/api/directory/search", "department", {"department": "engineering"})
        xss = await self._scan(XSSScanner, "/api/notes/preview", "note", {"note": "meeting at 10"})
        self.assertEqual([f.check_type for f in nosql], ["nosql"])
        self.assertEqual([f.check_type for f in xss], ["xss"])

    async def test_safe_twins_not_flagged(self):
        cases = (
            (NoSQLInjectionScanner, "/api/directory/search-safe", "department", {"department": "engineering"}),
            (XSSScanner, "/api/notes/preview-safe", "note", {"note": "meeting at 10"}),
            (XSSScanner, "/api/notes/echo", "note", {"note": "meeting at 10"}),
        )
        for cls, path, key, body in cases:
            with self.subTest(path=path):
                self.assertEqual(await self._scan(cls, path, key, body), [])


if __name__ == "__main__":
    unittest.main()
