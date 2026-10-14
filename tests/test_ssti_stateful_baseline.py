"""Stored evolution probes must not become template evaluation evidence."""
import html
import unittest
from unittest.mock import AsyncMock, Mock, patch

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse
from jinja2 import Template

from tests.test_baseline_and_timing_guards import _DummyEngine
from wscan.engine import ScanEngine
from wscan.injection_point import InjectionPoint
from wscan.scanners.base import Finding
from wscan.scanners.ssti import SSTIScanner, SSTI_PROBES


class StatefulSSTIBaselineTests(unittest.IsolatedAsyncioTestCase):
    async def _stateful_scan(self, vulnerable=False, prefix="", suffix=""):
        app = FastAPI()
        comments = ["wscanEVO492", "wscanEVO493", "reference49"]

        @app.post("/comments", response_class=HTMLResponse)
        async def comment(request: Request):
            value = (await request.form())["comment"]
            # Model a WAF which rejects strong probes but allows the evolved syntax.
            if vulnerable and value == "{{7*7}}":
                value = Template(prefix + value + suffix).render()
            comments.append(value)
            return "<ul>" + "".join(f"<li>{html.escape(v)}</li>" for v in comments) + "</ul>"

        async with httpx.AsyncClient(
            transport=httpx.ASGITransport(app=app), base_url="http://fixture.test"
        ) as client:
            engine = _DummyEngine()
            engine.sleep_factor = 0
            scanner = SSTIScanner(engine)
            ip = InjectionPoint.for_form("http://fixture.test/comments", "comment", 0)

            async def submit(url, fi, name, payload, is_url):
                response = await client.post("/comments", data={name: payload})
                return response.text, {"response": {"body": response.text, "status": response.status_code}}

            scanner._apply_payload = AsyncMock(side_effect=submit)

            async def evolve(*args, **kwargs):
                # Real evolution makes this extra submission before returning payloads.
                await scanner.dispatch(ip, 'wscanEVO496<>\'"')
                return ["{{7*7}}"]

            scanner.evolved_payloads = AsyncMock(side_effect=evolve)
            findings = await scanner.scan_injection_point(ip, {"name": "comment"})
            if findings and vulnerable:
                self.assertTrue(await scanner.verify_finding(findings[0]))
            self.assertIn('wscanEVO496<>\'"', comments)
            return findings

    async def test_safe_stateful_form_accumulated_markers(self):
        self.assertEqual(await self._stateful_scan(), [])

    async def test_evolved_vulnerable_twin_still_detected_and_verified(self):
        for prefix, suffix in [("", ""), ("prefix", "suffix"), ("123", "456")]:
            with self.subTest(prefix=prefix, suffix=suffix):
                findings = await self._stateful_scan(True, prefix, suffix)
                self.assertEqual(len(findings), 1)
                self.assertEqual(findings[0].evidence_details["expected"], "49")

    def _scanner(self, responses):
        engine = _DummyEngine()
        engine.sleep_factor = 0
        scanner = SSTIScanner(engine)
        scanner._apply_payload = AsyncMock(side_effect=responses)
        return scanner

    def _finding(self, expected="49", payload="{{7*7}}"):
        return Finding(
            check_type="ssti", severity="critical", url="http://fixture.test/?q=x",
            field_name="q", payload=payload, evidence="candidate",
            evidence_details={"expected": expected},
        )

    async def test_missing_baseline_scan_is_explicitly_unverified(self):
        for pair in [{}, {"request": {}}, {"response": {"status": 200, "body": None}}]:
            scanner = self._scanner([("", pair), ("reference49", {})])
            self.assertEqual(await scanner.scan_field(
                "http://fixture.test/?q=x", 0, {"name": "q"}, True
            ), [])
            self.assertIn("baseline_unavailable:ssti", scanner.engine.wave_errors)
            self.assertEqual(scanner._apply_payload.await_count, 1)

    async def test_missing_evolved_baseline_scan_is_unverified(self):
        responses = [("plain", {})] * (len(SSTI_PROBES) + 1) + [("", {})]
        scanner = self._scanner(responses)
        scanner.evolved_payloads = AsyncMock(return_value=["{{7*7}}"])
        self.assertEqual(await scanner.scan_field(
            "http://fixture.test/?q=x", 0, {"name": "q"}, True
        ), [])
        self.assertIn("baseline_unavailable:ssti:evolved", scanner.engine.wave_errors)

    async def test_missing_baseline_verify_returns_unknown(self):
        for expected, payload in [("49", "{{7*7}}"), (SSTI_PROBES[0][1], SSTI_PROBES[0][0])]:
            scanner = self._scanner([("", {}), (expected, {})])
            self.assertIsNone(await scanner.verify_finding(self._finding(expected, payload)))
            self.assertIn("baseline_unavailable:ssti:verify", scanner.engine.wave_errors)
            self.assertEqual(scanner._apply_payload.await_count, 1)

    async def test_successful_empty_baseline_preserves_standard_detection(self):
        payload, expected, _ = SSTI_PROBES[0]
        scanner = self._scanner([("", {"response": {"body": ""}}), (expected, {})])
        findings = await scanner.scan_field("http://fixture.test/?q=x", 0, {"name": "q"}, True)
        self.assertEqual(len(findings), 1)
        scanner._apply_payload.side_effect = [("", {"response": {"body": ""}}), (expected, {})]
        self.assertTrue(await scanner.verify_finding(findings[0]))

    async def test_missing_verify_probe_returns_unknown_not_negative(self):
        scanner = self._scanner([("plain", {}), ("", {})])
        self.assertIsNone(await scanner.verify_finding(self._finding()))
        self.assertIn("transport_error:ssti:verify_no_response", scanner.engine.wave_errors)

    async def test_successful_empty_verify_probe_is_negative(self):
        scanner = self._scanner([("plain", {}), ("", {"response": {"body": ""}})])
        self.assertFalse(await scanner.verify_finding(self._finding()))

    async def test_captured_baseline_body_is_compared_not_assumed_empty(self):
        payload, expected, _ = SSTI_PROBES[0]
        scanner = self._scanner([])
        scanner._apply_payload.side_effect = lambda *args: ("", {"response": {"body": expected}})
        self.assertEqual(await scanner.scan_field("http://fixture.test/?q=x", 0, {"name": "q"}, True), [])
        scanner = self._scanner([("", {"response": {"body": expected}}), (expected, {})])
        self.assertFalse(await scanner.verify_finding(self._finding(expected, payload)))
        scanner = self._scanner([("", {"response": {"body": "plain"}}), ("", {"response": {"body": expected}})])
        self.assertTrue(await scanner.verify_finding(self._finding(expected, payload)))

    async def test_body_retrieval_states_across_typed_carriers(self):
        ips = [
            InjectionPoint.for_url_param("http://fixture.test/?q=x", "q"),
            InjectionPoint.for_form("http://fixture.test/comments", "q", 0),
            InjectionPoint.for_json_body("POST", "http://fixture.test/api", "/q"),
        ]
        payload, expected, _ = SSTI_PROBES[0]
        for ip in ips:
            for body in [None, "missing", ""]:
                with self.subTest(carrier=ip.location, body=body):
                    response = {"headers": {}}
                    if body != "missing":
                        response["body"] = body
                    scanner = self._scanner([("", {"response": response}), (expected, {})])
                    if ip.location == "json_body":
                        scanner._apply_json_payload = scanner._apply_payload
                    findings = await scanner.scan_injection_point(ip, {"name": "q"})
                    self.assertEqual(len(findings), int(body == ""))
                    finding = self._finding(expected, payload)
                    finding.url = ip.url
                    scanner._verify_injection_point = lambda *_: ip
                    scanner._apply_payload.side_effect = [("", {"response": response}), (expected, {})]
                    result = await scanner.verify_finding(finding)
                    self.assertIs(result, True if body == "" else None)
                    scanner._apply_payload.side_effect = [("plain", {}), ("", {"response": response})]
                    result = await scanner.verify_finding(finding)
                    self.assertIs(result, False if body == "" else None)

    def _verification_engine(self, scanner):
        engine = object.__new__(ScanEngine)
        engine.scanners = {"ssti": scanner}
        engine._browser = scanner.browser
        return engine

    async def test_engine_retains_unknown_without_uncontrolled_confirmation(self):
        ips = [
            InjectionPoint.for_url_param("http://fixture.test/?q=x", "q"),
            InjectionPoint.for_form("http://fixture.test/comments", "q", 0),
            InjectionPoint.for_json_body("POST", "http://fixture.test/api", "/q"),
        ]
        for ip in ips:
            for responses in [[("", {})], [("plain", {}), ("", {})]]:
                with self.subTest(carrier=ip.location, responses=responses):
                    scanner = self._scanner(responses + [(SSTI_PROBES[0][1], {})])
                    if ip.location == "json_body":
                        scanner._apply_json_payload = scanner._apply_payload
                    scanner._verify_injection_point = lambda *_: ip
                    finding = self._finding(SSTI_PROBES[0][1], SSTI_PROBES[0][0])
                    finding.url = ip.url
                    result = await self._verification_engine(scanner)._verify_one(finding)
                    self.assertEqual(result, "assumed")
                    self.assertEqual(scanner._apply_payload.await_count, len(responses))

    async def test_engine_preserves_confirmed_actual_evaluation(self):
        expected = Template("{{7*7}}").render()
        scanner = self._scanner([("plain", {}), ("prefix" + expected + "suffix", {})])
        self.assertEqual(await self._verification_engine(scanner)._verify_one(self._finding()), "reproduced")

    async def test_standard_probe_matches_independent_actual_renderer(self):
        rendered = Template("{{2654435761*2654435761}}").render()
        self.assertEqual(rendered, str(2654435761 * 2654435761))
        self.assertEqual(rendered, "7046029209275649121")
        for payload, expected, _ in SSTI_PROBES:
            if "2654435761" in payload:
                self.assertEqual(expected, rendered)
        for vulnerable in [False, True]:
            scanner = self._scanner([])
            async def submit(url, fi, name, payload, is_url):
                source = Template(payload).render() if vulnerable else html.escape(payload)
                return source, {"response": {"body": source}}
            scanner._apply_payload.side_effect = submit
            findings = await scanner.scan_field("http://fixture.test/?q=x", 0, {"name": "q"}, True)
            self.assertEqual(len(findings), int(vulnerable))
            if findings:
                self.assertEqual(findings[0].payload, "{{2654435761*2654435761}}")
                self.assertTrue(await scanner.verify_finding(findings[0]))

    async def test_engine_preserves_valid_url_http_fallback(self):
        payload, expected, _ = SSTI_PROBES[4]
        scanner = self._scanner([("plain", {}), ("browser asset", {})])
        engine = self._verification_engine(scanner)
        engine.timeout = 8
        engine.httpx_client_kwargs = lambda **kwargs: kwargs
        engine.auth_headers = lambda **kwargs: {}
        engine.record_probe_status = Mock()
        client = AsyncMock()
        client.get.side_effect = [
            httpx.Response(200, text="plain", request=httpx.Request("GET", "http://fixture.test/?q=baseline")),
            httpx.Response(200, text=Template(payload).render(), request=httpx.Request("GET", "http://fixture.test/?q=probe")),
        ]
        with patch("httpx.AsyncClient") as factory:
            factory.return_value.__aenter__.return_value = client
            result = await engine._verify_one(self._finding(expected, payload))
        self.assertEqual(result, "reproduced")
        self.assertEqual(client.get.await_count, 2)
