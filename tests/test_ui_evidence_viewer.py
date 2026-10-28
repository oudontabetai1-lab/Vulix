"""Behavior checks for the Finding evidence viewer in a real served dashboard."""
import shutil
import socket
import subprocess
import threading
import time
import unittest
from pathlib import Path

from wscan.monitor import MonitorServer


ROOT = Path(__file__).parents[1]
REGISTRY = ROOT / "templates" / "ui" / "evidence-viewer-registry.js"
NODE_CHECK = ROOT / "tests" / "ui_evidence_viewer_registry_check.js"


def _chromium_available():
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


class EvidenceViewerRegistryTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "Node.js is not installed")
    def test_registry_builtin_unknown_dummy_and_redaction(self):
        result = subprocess.run(
            [shutil.which("node"), str(NODE_CHECK), str(REGISTRY)],
            cwd=ROOT, capture_output=True, text=True, check=False,
        )
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        self.assertIn("behavior passed", result.stdout)


@unittest.skipUnless(_chromium_available(), "Playwright Chromium is not available")
class EvidenceViewerDashboardTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        import uvicorn

        cls.monitor = MonitorServer(port=0)
        cls.monitor.api_findings = []
        cls.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.listen(64)
        cls.port = cls.sock.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(
            cls.monitor.app, log_level="error", access_log=False, lifespan="off"
        ))
        cls.thread = threading.Thread(
            target=cls.server.run, kwargs={"sockets": [cls.sock]}, daemon=True
        )
        cls.thread.start()
        deadline = time.time() + 10
        while not cls.server.started and time.time() < deadline:
            time.sleep(0.02)
        if not cls.server.started:
            raise RuntimeError("loopback dashboard server did not start")
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        cls.server.should_exit = True
        cls.thread.join(timeout=5)
        cls.sock.close()

    def test_served_dashboard_finding_render_and_explicit_screenshot_at_two_widths(self):
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.set_default_timeout(5000)
            errors = []
            page.on("pageerror", lambda error: errors.append(str(error)))
            page.route_web_socket("**/ws", lambda websocket: None)
            page.goto(self.base_url + "/monitor", wait_until="load")
            self.assertTrue(page.evaluate("Boolean(window.EvidenceViewerRegistry && window.addFinding)"))
            for width in (1440, 768):
                page.set_viewport_size({"width": width, "height": 900})
                seeded = page.evaluate("""() => {
                  document.getElementById('findingsPanel').innerHTML = '';
                  state.findingKeys.clear(); state.findingCards.clear();
                  state.findingCount = 0; state.confirmedCount = 0; state.hypothesisCount = 0;
                  state.urlFindingCounts = {};
                  const canvas = document.createElement('canvas'); canvas.width=1; canvas.height=1;
                  const jpeg = canvas.toDataURL('image/jpeg').split(',')[1];
                  handleEvent({type:'finding', timestamp:1, data:{finding_id:'known-http', url:'https://alice:pw@example.test/a?token=URL_SENTINEL#password=FRAGMENT_SENTINEL', check_type:'sqli', evidence_type:'http_trace_xst', severity:'high', confidence:'confirmed', verified:true, evidence:'response token=EVIDENCE_SENTINEL <img src=x onerror=alert(1)>', payload:'token=PAYLOAD_SENTINEL&password=PAYLOAD_SECRET', request:{method:'GET',url:'https://alice:pw@example.test/?token=REQ_SENTINEL',headers:{Authorization:'AUTH_SENTINEL',Accept:'text/plain'},body:{nested:{api_token:'NESTED_SENTINEL'}}}, response:{status:200,headers:{'Set-Cookie':'COOKIE_SENTINEL'},body:'<svg onload=alert(1)>'}, evidence_details:{context:'DOM_SENTINEL',nested:{access_token:'DETAIL_SENTINEL'}}, screenshot_b64:jpeg, reproduction_steps:['step token=STEP_SENTINEL']}});
                  EvidenceViewerRegistry.register('dummy_kind', ({finding}) => finding.evidence);
                  handleEvent({type:'finding', timestamp:2, data:{finding_id:'unknown-safe', url:'http://example.test/unknown', check_type:'custom', evidence_type:'unknown_signal_rare', verified:false, evidence:'unknown evidence retained'}});
                  handleEvent({type:'finding', timestamp:3, data:{finding_id:'dummy', url:'http://example.test/dummy', check_type:'custom', evidence_type:'dummy_kind', source:'agent', verified:false, evidence:'dummy viewer registered'}});
                  const duplicateAdded = addFinding({url:'https://alice:pw@example.test/a?token=URL_SENTINEL#password=FRAGMENT_SENTINEL', check_type:'sqli', evidence_type:'http_trace_xst', payload:'token=PAYLOAD_SENTINEL&password=PAYLOAD_SECRET'});
                  const panel = document.getElementById('findingsPanel');
                  return {duplicateAdded, labels:[...panel.querySelectorAll('[data-evidence-kind]')].map(node=>node.dataset.evidenceKind)};
                }""")
                self.assertFalse(seeded["duplicateAdded"])
                cards = page.locator("#findingsPanel .finding-card")
                self.assertEqual(cards.count(), 3)
                self.assertEqual(cards.nth(2).get_attribute("data-severity"), "high")
                self.assertEqual(cards.nth(2).get_attribute("data-confidence"), "confirmed")
                self.assertEqual(cards.nth(2).locator(".fc-verify-badge").inner_text(), "reproduced/assumed")
                self.assertEqual(page.evaluate("""() => [state.findingCount,state.confirmedCount,state.hypothesisCount]"""), [3, 1, 2])
                text = page.locator("#findingsPanel").inner_text()
                self.assertIn("unknown evidence retained", text)
                self.assertIn("dummy viewer registered", text)
                self.assertEqual(page.evaluate("""() => [...document.querySelectorAll('#findingsPanel [data-evidence-kind]')].map(node=>node.dataset.evidenceKind)"""), ["dummy_kind", "fallback", "http"])
                self.assertFalse(page.evaluate("""() => addFinding({url:'http://example.test/dummy', check_type:'custom', evidence_type:'dummy_kind', evidence:'duplicate'})"""))
                page.locator('#findingsPanel .finding-card:has([data-evidence-kind="http"]) summary').click()
                self.assertIn("HTTP evidence", page.locator("#findingsPanel").inner_text())
                for secret in ("URL_SENTINEL", "FRAGMENT_SENTINEL", "REQ_SENTINEL", "AUTH_SENTINEL", "NESTED_SENTINEL", "COOKIE_SENTINEL", "DETAIL_SENTINEL", "EVIDENCE_SENTINEL", "PAYLOAD_SENTINEL", "PAYLOAD_SECRET", "STEP_SENTINEL", "alice:pw"):
                    self.assertNotIn(secret, page.locator("body").inner_html())
                    self.assertNotIn(secret, page.locator("body").inner_text())
                self.assertEqual(page.locator("#findingsPanel script, #findingsPanel svg, #findingsPanel iframe, #findingsPanel [onerror], #findingsPanel [href^='javascript:'], #findingsPanel [src^='data:text/html']").count(), 0)
                shot_card = page.locator('#findingsPanel .finding-card:has([data-evidence-kind="http"])')
                image = shot_card.locator("img.fc-screenshot")
                button = shot_card.locator("button.btn-show-shot")
                self.assertTrue(button.is_visible())
                self.assertFalse(image.get_attribute("src"))
                button.click()
                self.assertTrue(image.get_attribute("src").startswith("data:image/jpeg;base64,/9j/"))
                image.wait_for(state="visible")
                image.click()
                self.assertTrue(page.locator("#lightbox").evaluate("el => el.classList.contains('active')"))
                page.locator("#lightbox .lb-close").click()
                self.assertFalse(errors, errors)
            page.evaluate("""() => {
              const panel = document.getElementById('findingsPanel');
              const fragment = document.createDocumentFragment();
              for (let i = 0; i < 300; i++) {
                const card = document.createElement('div');
                card.className = 'finding-card';
                fragment.appendChild(card); findingCardKeys.set(card, `old-${i}`); state.findingCards.set(`old-${i}`, card);
              }
              panel.appendChild(fragment);
              addFinding({url:'http://example.test/cap/new', check_type:'custom', evidence_type:'cap_test', evidence:'newest'});
            }""")
            cap = page.evaluate("""() => ({children:document.getElementById('findingsPanel').children.length, cards:document.querySelectorAll('#findingsPanel .finding-card').length, evicted:!state.findingCards.has('old-299'), newest:document.getElementById('findingsPanel').firstChild.querySelector('.fc-evidence').textContent})""")
            self.assertEqual(cap, {"children": 300, "cards": 300, "evicted": True, "newest": "newest"})
            browser.close()
