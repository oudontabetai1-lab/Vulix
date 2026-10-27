"""Tests for the server portal: scan history, report serving, downloads,
deletion and scan management endpoints."""
import io
import json
import shutil
import subprocess
import tempfile
import unittest
import zipfile
from pathlib import Path

from fastapi.testclient import TestClient

import wscan.monitor as monitor_mod
from wscan.monitor import MonitorServer


class PortalTestBase(unittest.TestCase):
    SCAN_ID = "20260529_120000"

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="wscan_portal_test_"))
        # Redirect the module-level output base at the temp dir.
        self._orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = self.tmp
        self._make_scan(self.SCAN_ID)
        self.srv = MonitorServer(port=9000, auth_token=self.auth_token())
        self.client = TestClient(self.srv.app)

    def tearDown(self):
        monitor_mod.OUTPUT_BASE = self._orig_base
        shutil.rmtree(self.tmp, ignore_errors=True)

    def auth_token(self):
        return ""

    def _make_scan(self, sid, findings=None):
        d = self.tmp / sid
        d.mkdir()
        (d / "report.html").write_text(
            "<html><body><h1>RPT</h1><a href='evidence.json'>e</a></body></html>",
            encoding="utf-8",
        )
        (d / "evidence.json").write_text(json.dumps({
            "target": "https://target.example.com",
            "scan_date": "2026-05-29T12:00:00",
            "findings": findings if findings is not None else [
                {"severity": "critical"}, {"severity": "high"},
                {"severity": "high"}, {"severity": "low"},
            ],
        }), encoding="utf-8")
        (d / "screenshots").mkdir()
        (d / "screenshots" / "x.txt").write_text("img", encoding="utf-8")
        return d


class PortalEndpointTests(PortalTestBase):
    def test_portal_and_monitor_pages(self):
        r = self.client.get("/")
        self.assertEqual(r.status_code, 200)
        self.assertIn("Server Portal", r.text)
        self.assertEqual(self.client.get("/monitor").status_code, 200)

    def test_list_scans_summary(self):
        scans = self.client.get("/api/v1/scans").json()["scans"]
        self.assertEqual(len(scans), 1)
        s = scans[0]
        self.assertEqual(s["id"], self.SCAN_ID)
        self.assertEqual(s["target"], "https://target.example.com")
        self.assertEqual(s["findings_count"], 4)
        self.assertEqual(s["severity"]["critical"], 1)
        self.assertEqual(s["severity"]["high"], 2)
        self.assertTrue(s["report_available"])
        self.assertEqual(s["status"], "done")

    def test_running_scan_marked_scanning(self):
        self.srv.scan_in_progress = True
        self.srv.current_scan_id = self.SCAN_ID
        s = self.client.get("/api/v1/scans").json()["scans"][0]
        self.assertEqual(s["status"], "scanning")

    def test_serve_report_and_assets(self):
        self.assertIn("RPT", self.client.get(f"/reports/{self.SCAN_ID}/report.html").text)
        self.assertEqual(
            self.client.get(f"/reports/{self.SCAN_ID}/evidence.json").status_code, 200
        )
        # Empty path defaults to report.html
        self.assertIn("RPT", self.client.get(f"/reports/{self.SCAN_ID}/").text)

    def test_report_path_traversal_blocked(self):
        r = self.client.get(f"/reports/{self.SCAN_ID}/../../etc/passwd")
        self.assertIn(r.status_code, (403, 404))

    def test_report_unknown_scan_404(self):
        self.assertEqual(self.client.get("/reports/nope/report.html").status_code, 404)

    def test_zip_download(self):
        r = self.client.get(f"/api/v1/scans/{self.SCAN_ID}/download")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.headers["content-type"], "application/zip")
        zf = zipfile.ZipFile(io.BytesIO(r.content))
        names = zf.namelist()
        self.assertTrue(any("report.html" in n for n in names))
        self.assertTrue(any("evidence.json" in n for n in names))

    def test_delete_scan(self):
        self.assertEqual(
            self.client.delete(f"/api/v1/scans/{self.SCAN_ID}").status_code, 200
        )
        self.assertFalse((self.tmp / self.SCAN_ID).exists())
        self.assertEqual(self.client.get("/api/v1/scans").json()["scans"], [])

    def test_delete_missing_404(self):
        self.assertEqual(self.client.delete("/api/v1/scans/nope").status_code, 404)

    def test_cannot_delete_running_scan(self):
        self.srv.scan_in_progress = True
        self.srv.current_scan_id = self.SCAN_ID
        self.assertEqual(
            self.client.delete(f"/api/v1/scans/{self.SCAN_ID}").status_code, 409
        )

    def test_abort_idle_returns_409(self):
        self.assertEqual(self.client.post("/api/v1/scan/abort").status_code, 409)

    def test_abort_running_queues_command(self):
        self.srv.scan_in_progress = True
        r = self.client.post("/api/v1/scan/abort")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(self.srv.command_queue.get_nowait(), "abort")

    def test_unusual_scan_id_is_listed_and_deletable(self):
        # A scan dir name with a quote (possible from a custom output_dir) must
        # round-trip safely; the portal JS uses data attributes, never inline JS.
        weird = "scan_'oops"
        self._make_scan(weird, findings=[{"severity": "low"}])
        ids = [s["id"] for s in self.client.get("/api/v1/scans").json()["scans"]]
        self.assertIn(weird, ids)
        self.assertEqual(
            self.client.delete(
                "/api/v1/scans/" + __import__("urllib.parse", fromlist=["quote"]).quote(weird, safe="")
            ).status_code,
            200,
        )


class PortalAuthTests(PortalTestBase):
    def auth_token(self):
        return "tok"

    def test_portal_requires_auth(self):
        r = self.client.get("/", headers={"accept": "text/html"}, follow_redirects=False)
        self.assertEqual(r.status_code, 303)
        self.assertEqual(self.client.get("/api/v1/scans").status_code, 401)

    def test_authed_access(self):
        self.client.post("/login", data={"token": "tok"})
        self.assertEqual(self.client.get("/api/v1/scans").status_code, 200)
        self.assertEqual(
            self.client.get(f"/reports/{self.SCAN_ID}/report.html").status_code, 200
        )


class PortalDisplayUrlRedactionTests(unittest.TestCase):
    """Browser-independent tests for display URL redaction parity in portal.html."""

    @unittest.skipUnless(shutil.which("node"), "Node.js is required for portal JS test")
    def test_portal_redact_display_url_matches_dashboard_parity(self):
        portal_html = Path("templates/portal.html").read_text(encoding="utf-8")
        self.assertIn("function redactDisplayUrl(raw)", portal_html)
        self.assertIn("CONFIG_SENSITIVE_URL_KEY", portal_html)

        # Extract script content from portal.html and evaluate in Node.js
        script_eval = """
global.setInterval = () => ({ unref: () => {} });
global.document = { getElementById: () => ({ addEventListener: () => {} }) };
global.window = {};

const fs = require('fs');
const html = fs.readFileSync('templates/portal.html', 'utf8');
const scriptMatch = html.match(/<script>([\\s\\S]*?)<\\/script>/);
if (!scriptMatch) process.exit(1);

const fn = new Function(scriptMatch[1] + '; return { redactDisplayUrl, isSensitiveKey, maskPathSecrets, maskKv, esc };');
const { redactDisplayUrl, esc } = fn();

const canaries = [
  'CANARY_USER_PASS', 'CANARY_QUERY', 'CANARY_FRAG', 'CANARY_NOSCHEME',
  'CANARY_MATRIX', 'CANARY_JSESSION', 'CANARY_ASP', 'CANARY_JS',
  'CANARY_MALFORMED', 'CANARY_ENCODED', 'CANARY_LDAP',
  'CRV_ENCJSESSION', 'CRV_ENCAPSP', 'CAN_NESTED_TOKEN',
];

const targets = {
  'p-valid': 'https://user:CANARY_USER_PASS@example.com/app?token=CANARY_QUERY&safe=ok#access_token=CANARY_FRAG',
  'p-noscheme': 'user:CANARY_NOSCHEME@example.com/path',
  'p-matrix-token': 'http://example.com/path;token=CANARY_MATRIX',
  'p-jsession': 'http://example.com/path;jsessionid=CANARY_JSESSION',
  'p-enc-jsession': 'http://example.com/path;j%65ssionid=CRV_ENCJSESSION',
  'p-asp': 'https://example.com/path/(S(CANARY_ASP))/view',
  'p-enc-asp': 'https://example.com/path/%28S%28CRV_ENCAPSP%29%29/view',
  'p-js': "javascript:alert('CANARY_JS')",
  'p-malformed': 'http://user:CANARY_MALFORMED@[bad-host/path',
  'p-encoded-key': 'https://example.com/app?%74oken=CANARY_ENCODED',
  'p-nested-token': 'https://example.com/app?next=%2Fapp%3Ftoken%3DCAN_NESTED_TOKEN',
  'p-ldap': 'ldap://user:CANARY_LDAP@ldap.example.com/ou=users',
  'p-safe': 'https://example.com/safe/path?q=ok',
};

for (const [name, rawUrl] of Object.entries(targets)) {
  const redacted = redactDisplayUrl(rawUrl);
  // Escaped display text and title attribute
  const displayHtml = esc(redacted);

  for (const canary of canaries) {
    if (redacted.includes(canary)) {
      console.error(`Canary leaked in redacted display for ${name}: ${canary}`);
      process.exit(2);
    }
    if (displayHtml.includes(canary)) {
      console.error(`Canary leaked in escaped display HTML for ${name}: ${canary}`);
      process.exit(3);
    }
  }
}

// Parity checks on specific sanitized outputs
if (redactDisplayUrl(targets['p-valid']) !== 'https://<redacted>@example.com/app?token=<redacted>&safe=ok#access_token=<redacted>') process.exit(4);
if (redactDisplayUrl(targets['p-safe']) !== 'https://example.com/safe/path?q=ok') process.exit(5);
if (redactDisplayUrl(targets['p-js']) !== '（URL非表示）') process.exit(6);
if (redactDisplayUrl(targets['p-malformed']) !== '（URL非表示）') process.exit(7);
if (redactDisplayUrl(targets['p-noscheme']) !== '（URL非表示）') process.exit(8);
if (redactDisplayUrl(targets['p-matrix-token']) !== 'http://example.com/path;token=<redacted>') process.exit(9);
if (redactDisplayUrl(targets['p-jsession']) !== 'http://example.com/path;jsessionid=<redacted>') process.exit(10);
if (redactDisplayUrl(targets['p-enc-jsession']) !== 'http://example.com/path;j%65ssionid=<redacted>') process.exit(11);
if (redactDisplayUrl(targets['p-asp']) !== 'https://example.com/path/(<redacted>)/view') process.exit(12);
if (redactDisplayUrl(targets['p-enc-asp']) !== 'https://example.com/path/(<redacted>)/view') process.exit(13);
if (redactDisplayUrl(targets['p-encoded-key']) !== 'https://example.com/app?%74oken=<redacted>') process.exit(14);
if (redactDisplayUrl(targets['p-nested-token']) !== 'https://example.com/app?next=%2Fapp%3Ftoken%3D<redacted>') process.exit(15);

process.exit(0);
"""
        res = subprocess.run(
            [shutil.which("node"), "-e", script_eval],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(res.returncode, 0, f"Node script failed with: {res.stderr}\nOutput: {res.stdout}")

    def test_portal_api_and_storage_urls_remain_unredacted(self):
        """Confirm backend API responses and disk data retain full unredacted URLs."""
        tmp = Path(tempfile.mkdtemp(prefix="wscan_portal_unredacted_"))
        orig_base = monitor_mod.OUTPUT_BASE
        monitor_mod.OUTPUT_BASE = tmp
        raw_target = "https://user:CANARY_RAW_SECRET@example.com/app?token=CANARY_QUERY_SECRET"

        try:
            sid = "scan_unredacted_test"
            sdir = tmp / sid
            sdir.mkdir()
            (sdir / "evidence.json").write_text(json.dumps({
                "target": raw_target,
                "scan_date": "2026-10-27T12:00:00",
                "findings": [],
            }), encoding="utf-8")

            srv = MonitorServer(port=9000, auth_token="")
            client = TestClient(srv.app)

            # GET /api/v1/scans must return raw target without display redaction
            r = client.get("/api/v1/scans")
            self.assertEqual(r.status_code, 200)
            scans = r.json()["scans"]
            self.assertEqual(len(scans), 1)
            self.assertEqual(scans[0]["target"], raw_target)
            self.assertIn("CANARY_RAW_SECRET", scans[0]["target"])
            self.assertIn("CANARY_QUERY_SECRET", scans[0]["target"])

            # Schedule API must retain submitted raw URL
            r_post = client.post("/api/v1/schedules", json={
                "url": raw_target,
                "interval_hours": 12,
            })
            self.assertEqual(r_post.status_code, 200)
            r_scheds = client.get("/api/v1/schedules")
            self.assertEqual(r_scheds.status_code, 200)
            scheds = r_scheds.json()["schedules"]
            self.assertEqual(len(scheds), 1)
            self.assertEqual(scheds[0]["url"], raw_target)
        finally:
            monitor_mod.OUTPUT_BASE = orig_base
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
