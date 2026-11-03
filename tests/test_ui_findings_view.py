"""Browser-independent tests for /app Findings view module.

Verifies:
- Filter logic as pure functions (severity, check type, verification status, provenance, text).
- Counts calculation as pure functions with explicit partial-data ("N of M loaded (total: T)")
  and unknown-total ("total unknown") labeling.
- Provenance, verification, review state, and severity labeling (Agent findings retained and labeled).
- Deep-link parsing, URL hash building, finding lookup, and explicit not-found states for stale/unknown IDs.
- Redaction of sensitive credentials in URLs and text.
- XSS inertness of evidence (HTML/script tags escaped, never executable).
- Module registration and routing via ModuleRegistry and NavigationDispatcher.
"""
from __future__ import annotations

import json
from pathlib import Path
import subprocess
import unittest

ROOT = Path(__file__).resolve().parents[1]
FINDINGS_MODULE_JS = ROOT / "templates" / "ui" / "findings-module.js"
EVIDENCE_VIEWER_JS = ROOT / "templates" / "ui" / "evidence-viewer-registry.js"
APP_SHELL_JS = ROOT / "templates" / "ui" / "app-shell.js"
API_CLIENT_JS = ROOT / "templates" / "ui" / "api-client.js"


def _run_node(script: str) -> dict:
    """Run JS script passed via stdin to Node.js and return parsed JSON."""
    proc = subprocess.run(
        ["node", "-"],
        input=script,
        capture_output=True,
        text=True,
        check=True,
    )
    return json.loads(proc.stdout)


class FindingsModulePureFunctionsTests(unittest.TestCase):
    def test_filter_logic_is_pure_and_accurate(self):
        script = f"""
        const fs = require('fs');
        const code = fs.readFileSync('{FINDINGS_MODULE_JS}', 'utf-8');
        eval(code);
        const FM = global.VulixFindingsModule;

        const findings = [
          {{ check_type: 'xss', severity: 'high', verification_state: 'reproduced', source: 'scanner', url: 'http://example.com/search', field_name: 'q' }},
          {{ check_type: 'sqli', severity: 'critical', verification_state: 'assumed', source: 'agent', agent_verified: false, url: 'http://example.com/login', field_name: 'user' }},
          {{ check_type: 'os', severity: 'critical', verification_state: 'reproduced', source: 'agent', agent_verified: true, url: 'http://example.com/cmd', field_name: 'c' }},
          {{ check_type: 'csrf', severity: 'medium', verification_state: 'unreproduced', source: 'scanner', url: 'http://example.com/tx', field_name: 'amount' }},
          {{ check_type: 'info_disclosure', severity: 'low', verification_state: 'skipped', source: 'scanner', url: 'http://example.com/.env', field_name: '' }},
        ];

        // 1. Snapshot original to check purity
        const snapshot = JSON.stringify(findings);

        // 2. Default "all" filter retains all findings, including Agent findings
        const allFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'all' }});
        const allRetained = allFiltered.length === 5;

        // 3. Severity filter
        const critFiltered = FM.filterFindings(findings, {{ severity: 'critical', checkType: 'all', verification: 'all', provenance: 'all' }});
        const critCount = critFiltered.length;

        // 4. Check type filter
        const xssFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'xss', verification: 'all', provenance: 'all' }});
        const xssCount = xssFiltered.length;

        // 5. Verification status filter
        const reproFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'all', verification: 'reproduced', provenance: 'all' }});
        const reproCount = reproFiltered.length;

        // 6. Provenance filter
        const agentFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'agent' }});
        const agentCount = agentFiltered.length;
        const agentVerFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'agent_verified' }});
        const agentVerCount = agentVerFiltered.length;
        const scannerFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'scanner' }});
        const scannerCount = scannerFiltered.length;

        // 7. Text search filter
        const searchFiltered = FM.filterFindings(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'all', search: 'login' }});
        const searchCount = searchFiltered.length;

        // 8. Purity check
        const isPure = JSON.stringify(findings) === snapshot;

        console.log(JSON.stringify({{
          allRetained,
          critCount,
          xssCount,
          reproCount,
          agentCount,
          agentVerCount,
          scannerCount,
          searchCount,
          isPure
        }}));
        """
        res = _run_node(script)
        self.assertTrue(res["allRetained"])
        self.assertEqual(res["critCount"], 2)
        self.assertEqual(res["xssCount"], 1)
        self.assertEqual(res["reproCount"], 2)
        self.assertEqual(res["agentCount"], 2)
        self.assertEqual(res["agentVerCount"], 1)
        self.assertEqual(res["scannerCount"], 3)
        self.assertEqual(res["searchCount"], 1)
        self.assertTrue(res["isPure"])

    def test_counts_calculation_and_partial_data_labeling(self):
        script = f"""
        const fs = require('fs');
        const code = fs.readFileSync('{FINDINGS_MODULE_JS}', 'utf-8');
        eval(code);
        const FM = global.VulixFindingsModule;

        const findings = [
          {{ check_type: 'xss', severity: 'high' }},
          {{ check_type: 'sqli', severity: 'critical' }},
          {{ check_type: 'os', severity: 'critical' }},
        ];

        // Case A: Full dataset (loaded == total)
        const countsFull = FM.computeFindingCounts(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'all' }}, {{ total_findings_count: 3 }});
        // Case B: Full dataset with filter
        const countsFiltered = FM.computeFindingCounts(findings, {{ severity: 'critical', checkType: 'all', verification: 'all', provenance: 'all' }}, {{ total_findings_count: 3 }});
        // Case C: Partial / capped dataset (loaded < total)
        const countsPartial = FM.computeFindingCounts(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'all' }}, {{ total_findings_count: 10 }});
        // Case D: Unknown total (total == null)
        const countsUnknown = FM.computeFindingCounts(findings, {{ severity: 'all', checkType: 'all', verification: 'all', provenance: 'all' }}, {{ total_findings_count: null }});

        console.log(JSON.stringify({{
          countsFull,
          countsFiltered,
          countsPartial,
          countsUnknown
        }}));
        """
        res = _run_node(script)

        # Case A: full dataset
        self.assertFalse(res["countsFull"]["isPartial"])
        self.assertEqual(res["countsFull"]["total"], 3)
        self.assertEqual(res["countsFull"]["loaded"], 3)
        self.assertEqual(res["countsFull"]["filtered"], 3)
        self.assertIn("3", res["countsFull"]["label"])

        # Case B: filtered
        self.assertEqual(res["countsFiltered"]["filtered"], 2)
        self.assertIn("2", res["countsFiltered"]["label"])
        self.assertIn("3", res["countsFiltered"]["label"])

        # Case C: partial dataset (3 of 10)
        self.assertTrue(res["countsPartial"]["isPartial"])
        self.assertEqual(res["countsPartial"]["total"], 10)
        self.assertEqual(res["countsPartial"]["loaded"], 3)
        self.assertIn("3", res["countsPartial"]["label"])
        self.assertIn("10", res["countsPartial"]["label"])

        # Case D: unknown total
        self.assertTrue(res["countsUnknown"]["isPartial"])
        self.assertIsNone(res["countsUnknown"]["total"])
        self.assertIn("不明", res["countsUnknown"]["label"])

    def test_provenance_verification_review_severity_labels(self):
        script = f"""
        const fs = require('fs');
        const code = fs.readFileSync('{FINDINGS_MODULE_JS}', 'utf-8');
        eval(code);
        const FM = global.VulixFindingsModule;

        // 1. Agent unconfirmed finding
        const agentUnconfirmed = {{
          check_type: 'sqli',
          severity: 'high',
          verification_state: 'assumed',
          source: 'agent',
          agent_verified: false,
        }};
        const p1 = FM.getProvenanceLabel(agentUnconfirmed);
        const v1 = FM.getVerificationLabel(agentUnconfirmed);
        const s1 = FM.getSeverityLabel(agentUnconfirmed);
        const r1 = FM.getReviewStateLabel(agentUnconfirmed);

        // 2. Agent verified finding
        const agentVerified = {{
          check_type: 'xss',
          severity: 'critical',
          verification_state: 'reproduced',
          source: 'agent',
          agent_verified: true,
          review_state: 'reviewed',
        }};
        const p2 = FM.getProvenanceLabel(agentVerified);
        const v2 = FM.getVerificationLabel(agentVerified);
        const s2 = FM.getSeverityLabel(agentVerified);
        const r2 = FM.getReviewStateLabel(agentVerified);

        // 3. Scanner finding with skipped verification
        const scannerSkipped = {{
          check_type: 'cmd',
          severity: 'medium',
          verification_state: 'skipped',
          source: 'scanner',
          review_state: 'needs_review',
        }};
        const p3 = FM.getProvenanceLabel(scannerSkipped);
        const v3 = FM.getVerificationLabel(scannerSkipped);
        const s3 = FM.getSeverityLabel(scannerSkipped);
        const r3 = FM.getReviewStateLabel(scannerSkipped);

        console.log(JSON.stringify({{
          p1, v1, s1, r1,
          p2, v2, s2, r2,
          p3, v3, s3, r3
        }}));
        """
        res = _run_node(script)

        # Agent unconfirmed
        self.assertTrue(res["p1"]["isAgent"])
        self.assertFalse(res["p1"]["agentVerified"])
        self.assertIn("Agent", res["p1"]["text"])
        self.assertIn("未確証", res["p1"]["text"])
        self.assertEqual(res["v1"]["state"], "assumed")
        self.assertEqual(res["s1"]["value"], "high")
        self.assertEqual(res["r1"]["state"], "unreviewed")

        # Agent verified
        self.assertTrue(res["p2"]["isAgent"])
        self.assertTrue(res["p2"]["agentVerified"])
        self.assertIn("再現確認済", res["p2"]["text"])
        self.assertEqual(res["v2"]["state"], "reproduced")
        self.assertEqual(res["s2"]["value"], "critical")
        self.assertEqual(res["r2"]["state"], "reviewed")

        # Scanner finding
        self.assertFalse(res["p3"]["isAgent"])
        self.assertIn("決定論スキャナ", res["p3"]["text"])
        self.assertEqual(res["v3"]["state"], "skipped")
        self.assertIn("needs review", res["v3"]["text"])
        self.assertEqual(res["r3"]["state"], "needs_review")

    def test_deep_link_parse_and_lookup_and_not_found(self):
        script = f"""
        const fs = require('fs');
        const code = fs.readFileSync('{FINDINGS_MODULE_JS}', 'utf-8');
        eval(code);
        const FM = global.VulixFindingsModule;

        // 1. Deep link parsing
        const dl1 = FM.parseFindingDeepLink('#/findings?scan=20261103-120000&finding=find-xss-1');
        const dl2 = FM.parseFindingDeepLink('#/findings?scan=20261103-120000');
        const dl3 = FM.parseFindingDeepLink('#/findings');

        // 2. Deep link URL building
        const hash1 = FM.buildFindingHash('20261103-120000', 'find-xss-1');
        const hash2 = FM.buildFindingHash('20261103-120000', null);

        // 3. Finding lookup by ID
        const findings = [
          {{ id: 'f-1', check_type: 'xss', url: 'http://a.test' }},
          {{ finding_id: 'f-2', check_type: 'sqli', url: 'http://b.test' }},
          {{ check_type: 'os', url: 'http://c.test', field_name: 'cmd', payload: '; id' }},
        ];

        const match1 = FM.findFindingById(findings, 'f-1');
        const match2 = FM.findFindingById(findings, 'f-2');
        const match3 = FM.findFindingById(findings, '2'); // index fallback
        const notFound = FM.findFindingById(findings, 'unknown-stale-id');

        console.log(JSON.stringify({{
          dl1, dl2, dl3,
          hash1, hash2,
          found1: match1 ? match1.check_type : null,
          found2: match2 ? match2.check_type : null,
          found3: match3 ? match3.check_type : null,
          notFound: notFound === null
        }}));
        """
        res = _run_node(script)
        self.assertEqual(res["dl1"], {"scanId": "20261103-120000", "findingId": "find-xss-1"})
        self.assertEqual(res["dl2"], {"scanId": "20261103-120000", "findingId": None})
        self.assertEqual(res["dl3"], {"scanId": None, "findingId": None})

        self.assertEqual(res["hash1"], "#/findings?scan=20261103-120000&finding=find-xss-1")
        self.assertEqual(res["hash2"], "#/findings?scan=20261103-120000")

        self.assertEqual(res["found1"], "xss")
        self.assertEqual(res["found2"], "sqli")
        self.assertEqual(res["found3"], "os")
        self.assertTrue(res["notFound"])

    def test_redaction_and_xss_inertness_of_evidence(self):
        script = f"""
        const fs = require('fs');
        const evCode = fs.readFileSync('{EVIDENCE_VIEWER_JS}', 'utf-8');
        const fmCode = fs.readFileSync('{FINDINGS_MODULE_JS}', 'utf-8');
        global.window = global;
        eval(evCode);
        eval(fmCode);
        const FM = global.VulixFindingsModule;

        // 1. Redaction of sensitive URL credentials & matrix secrets
        const rawUrl = 'https://alice:secret_password_123@example.test/search?token=SENSITIVE_TOKEN_456&key=API_KEY_789&q=test#auth=AUTH_VAL';
        const safeUrl = FM.redactDisplayUrl(rawUrl);

        // 2. Redaction of sensitive text
        const rawText = 'Authorization: Bearer SECRET_BEARER_TOKEN with password=MY_SECRET_PASS in body';
        const safeText = FM.redactDisplayText(rawText);

        // 3. Evidence rendering through EvidenceViewerRegistry
        const findingWithXss = {{
          check_type: 'xss',
          severity: 'high',
          url: 'http://example.test/?token=SECRET_URL_TOKEN',
          field_name: '<script>alert("xss")</script>',
          payload: '<img src=x onerror=alert("payload")>',
          evidence: '<svg/onload=alert("evidence")>',
          request: {{
            headers: {{ Authorization: 'Bearer SECRET_REQ_TOKEN' }},
            body: {{ password: 'SECRET_PASSWORD' }}
          }}
        }};

        const renderedHtml = FM.renderEvidenceContent(findingWithXss);

        // Check that raw secret tokens are not leaked
        const hasSecretPassword = renderedHtml.includes('SECRET_PASSWORD');
        const hasSecretBearer = renderedHtml.includes('SECRET_REQ_TOKEN');
        const hasRawUrlToken = renderedHtml.includes('SECRET_URL_TOKEN');

        // Check that executable tags are escaped and inert
        const hasExecutableScript = renderedHtml.includes('<script>');
        const hasExecutableImg = renderedHtml.includes('<img src=x');
        const hasExecutableSvg = renderedHtml.includes('<svg/onload');

        console.log(JSON.stringify({{
          safeUrl,
          safeText,
          hasSecretPassword,
          hasSecretBearer,
          hasRawUrlToken,
          hasExecutableScript,
          hasExecutableImg,
          hasExecutableSvg
        }}));
        """
        res = _run_node(script)

        # Sensitive URL is redacted
        self.assertNotIn("secret_password_123", res["safeUrl"])
        self.assertNotIn("SENSITIVE_TOKEN_456", res["safeUrl"])
        self.assertNotIn("API_KEY_789", res["safeUrl"])
        self.assertNotIn("AUTH_VAL", res["safeUrl"])
        self.assertIn("<redacted>@", res["safeUrl"])

        # Sensitive text is redacted
        self.assertNotIn("SECRET_BEARER_TOKEN", res["safeText"])
        self.assertNotIn("MY_SECRET_PASS", res["safeText"])

        # Untrusted markup is NEVER executable
        self.assertFalse(res["hasSecretPassword"])
        self.assertFalse(res["hasSecretBearer"])
        self.assertFalse(res["hasRawUrlToken"])
        self.assertFalse(res["hasExecutableScript"])
        self.assertFalse(res["hasExecutableImg"])
        self.assertFalse(res["hasExecutableSvg"])

    def test_app_shell_and_navigation_integration(self):
        script = f"""
        const fs = require('fs');
        const shellCode = fs.readFileSync('{APP_SHELL_JS}', 'utf-8');
        const fmCode = fs.readFileSync('{FINDINGS_MODULE_JS}', 'utf-8');
        global.window = global;
        eval(shellCode);
        eval(fmCode);

        const {{ ModuleRegistry, NavigationDispatcher }} = global.VulixAppShell;
        const registry = new ModuleRegistry();
        const dispatcher = new NavigationDispatcher(registry);

        // Register findings module
        const mockContainer = {{ replaceChildren: () => {{}} }};
        const mockApi = {{ createScope: () => ({{ get: async () => ({{ ok: true, data: {{ scans: [] }} }}) }}) }};
        const mod = global.VulixFindingsModule.createFindingsModule({{
          api: mockApi,
          surfaceEl: mockContainer,
          titleEl: {{ textContent: '' }},
          contextEl: {{ textContent: '' }},
        }});
        registry.register(mod);

        // Dispatcher route resolution
        const r1 = dispatcher.resolveRoute('#findings');
        const r2 = dispatcher.resolveRoute('#/findings');
        const r3 = dispatcher.resolveRoute('#/findings?scan=20261103&finding=1');

        console.log(JSON.stringify({{
          isRegistered: registry.has('findings'),
          r1ViewId: r1.viewId,
          r2ViewId: r2.viewId,
          r3ViewId: r3.viewId,
        }}));
        """
        res = _run_node(script)
        self.assertTrue(res["isRegistered"])
        self.assertEqual(res["r1ViewId"], "findings")
        self.assertEqual(res["r2ViewId"], "findings")
        self.assertEqual(res["r3ViewId"], "findings")


if __name__ == "__main__":
    unittest.main()
