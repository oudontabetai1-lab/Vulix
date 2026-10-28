"""Tests for Single EventStream and Cursor Projection (UI v3 U09)."""
import json
import os
from pathlib import Path
import socket
import subprocess
import threading
import unittest

from fastapi.testclient import TestClient
from starlette.requests import Request
import uvicorn

from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value


ROOT = Path(__file__).resolve().parents[1]
EVENT_STREAM_JS = ROOT / "templates" / "ui" / "event-stream.js"
DASHBOARD_HTML = ROOT / "templates" / "dashboard.html"
EVENT_STREAM_FIXTURES = ROOT / "tests" / "fixtures" / "ui_event_stream"


def _run_node_script(script: str) -> dict:
    """Run a small JavaScript snippet via Node.js and return parsed JSON."""
    full_script = f"""
    const {{ CursorProjection, EventStreamClient, validateWireEvent, BACKEND_WIRE_REFS, getSafeReturnUrl, getLoginUrl }} = require('{EVENT_STREAM_JS}');
    {script}
    """
    res = subprocess.run(
        ["node", "-"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
        input=full_script,
    )
    return json.loads(res.stdout)


def _chromium_available() -> bool:
    try:
        from playwright.sync_api import sync_playwright
        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            browser.close()
        return True
    except Exception:
        return False


def _run_projection_fixture(name: str) -> dict:
    """Replay a fixture event stream through CursorProjection and return actions/final state."""
    path = EVENT_STREAM_FIXTURES / name
    fixture = json.loads(path.read_text(encoding="utf-8"))
    script = f"""
    const state = Object.assign({{}}, {json.dumps(fixture["state"])});
    const proj = new CursorProjection(() => state);
    const events = {json.dumps(fixture["events"])};
    const actions = [];
    for (const evt of events) {{
        const evaluation = proj.evaluate(evt);
        actions.push(evaluation.action);
        if (evaluation.action === 'process' || evaluation.action === 'reset_and_process') {{
            proj.applyCursor(evt, evaluation);
        }}
    }}
    console.log(JSON.stringify({{ actions, final: state }}));
    """
    return _run_node_script(script), fixture


class EventStreamNodeUnitTests(unittest.TestCase):
    def test_event_stream_exports(self):
        """Verify templates/ui/event-stream.js exports expected symbols."""
        self.assertTrue(EVENT_STREAM_JS.is_file())
        result = _run_node_script("console.log(JSON.stringify(Object.keys(require('./templates/ui/event-stream.js'))));")
        expected = ["CursorProjection", "EventStreamClient", "validateWireEvent", "BACKEND_WIRE_REFS", "getSafeReturnUrl", "getLoginUrl"]
        for sym in expected:
            self.assertIn(sym, result)

    def test_cursor_projection_ping_and_snapshot(self):
        """Verify ping is ignored and scan_snapshot triggers apply_snapshot."""
        script = """
        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 5 };
        const proj = new CursorProjection(() => state);

        const pingRes = proj.evaluate({ type: 'ping' });
        const snapRes = proj.evaluate({ type: 'scan_snapshot', data: { status: 'scanning' } });

        console.log(JSON.stringify({
            ping: pingRes,
            snapshot: snapRes,
        }));
        """
        data = _run_node_script(script)
        self.assertEqual(data["ping"]["action"], "ignore")
        self.assertEqual(data["snapshot"]["action"], "apply_snapshot")

    def test_wire_ingress_consumes_unknown_ordered_event(self):
        data = _run_node_script("""
        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 5, eventCount: 5 };
        const received = [];
        const client = new EventStreamClient({ stateAccessor: () => state, onEvent: (e) => received.push(e.type) });
        const event = { type: 'future_wire_event', server_id: 'srv-1', run_id: 'run-1', sequence: 6, data: { marker: true } };
        const valid = validateWireEvent(event);
        client.processEvent(event, true);
        console.log(JSON.stringify({ valid, received, state }));
        """)
        self.assertTrue(data["valid"]["valid"])
        self.assertFalse(data["valid"]["known"])
        self.assertEqual(data["received"], ["future_wire_event"])
        self.assertEqual(data["state"]["lastEventSequence"], 6)

    def test_malformed_durable_event_marks_stale_without_advancing_cursor(self):
        data = _run_node_script("""
        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 5, eventCount: 5 };
        const stale = [];
        const received = [];
        const client = new EventStreamClient({ stateAccessor: () => state,
          onEvent: (e) => received.push(e.type), onWireStale: (e) => stale.push(e) });
        client.processEvent({ type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 6, data: { url: 7 } }, true);
        client.processEvent({ type: 'page_end', server_id: 'srv-1', run_id: 'run-1', sequence: 7, data: { url: 'http://ok' } }, true);
        console.log(JSON.stringify({ stale, received, state }));
        """)
        self.assertEqual(data["stale"][0]["reason"], "invalid_known_payload")
        self.assertEqual(data["received"], [])
        self.assertEqual(data["state"]["lastEventSequence"], 5)
        self.assertEqual(data["state"]["eventStreamStale"]["type"], "page_start")

    def test_wire_requires_cursor_on_snapshot_and_rejects_bad_finding(self):
        data = _run_node_script("""
        const snapshot = validateWireEvent({ type: 'scan_snapshot', data: { status: 'idle', findings: [] } }, { requireDurable: true });
        const finding = validateWireEvent({ type: 'finding', server_id: 's', run_id: 'r', sequence: 1, data: {} }, { requireDurable: true });
        console.log(JSON.stringify({ snapshot, finding }));
        """)
        self.assertEqual(data["snapshot"]["reason"], "missing_cursor")
        self.assertEqual(data["finding"]["reason"], "invalid_known_payload")

    def test_unknown_and_malformed_wire_fixtures(self):
        for name in ("unknown_stream.json", "malformed_stream.json"):
            fixture = json.loads((EVENT_STREAM_FIXTURES / name).read_text(encoding="utf-8"))
            script = f"""
            const fixture = {json.dumps(fixture)};
            const state = Object.assign({{}}, fixture.state);
            const received = [];
            const stale = [];
            const client = new EventStreamClient({{
              stateAccessor: () => state,
              onEvent: (event) => received.push(event.type),
              onWireStale: (event) => stale.push(event),
            }});
            for (const event of fixture.events) client.processEvent(event, true);
            console.log(JSON.stringify({{ state, received, stale }}));
            """
            result = _run_node_script(script)
            if name == "unknown_stream.json":
                self.assertEqual(result["received"], fixture["expected_types"])
                self.assertEqual(result["state"]["lastEventSequence"], fixture["expected_sequence"])
                self.assertEqual(result["stale"], [])
            else:
                self.assertEqual(result["stale"][0], fixture["expected_stale"])
                self.assertEqual(result["state"]["lastEventSequence"], fixture["expected_sequence"])
                self.assertEqual(result["received"], [])

    def test_cursor_projection_sequence_validation_and_gap(self):
        """Verify normal advancement, duplicate drop, and gap detection."""
        script = """
        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 10, eventCount: 10 };
        const proj = new CursorProjection(() => state);

        // 1. Normal next sequence (11)
        const nextEvt = { type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 11, data: { url: 'http://a' } };
        const evalNext = proj.evaluate(nextEvt);
        proj.applyCursor(nextEvt, evalNext);

        const stateAfterNext = { ...state };

        // 2. Duplicate sequence (11 again or 10)
        const dupEvt = { type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 11, data: { url: 'http://a' } };
        const evalDup = proj.evaluate(dupEvt);

        // 3. Gap sequence (14 instead of 12)
        const gapEvt = { type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 14, data: { url: 'http://gap' } };
        const evalGap = proj.evaluate(gapEvt);

        console.log(JSON.stringify({
            evalNext: evalNext,
            stateAfterNext: stateAfterNext,
            evalDup: evalDup,
            evalGap: evalGap,
        }));
        """
        data = _run_node_script(script)
        self.assertEqual(data["evalNext"]["action"], "process")
        self.assertEqual(data["stateAfterNext"]["lastEventSequence"], 11)
        self.assertEqual(data["stateAfterNext"]["eventCount"], 11)
        self.assertEqual(data["evalDup"]["action"], "drop")
        self.assertEqual(data["evalDup"]["reason"], "duplicate")
        self.assertEqual(data["evalGap"]["action"], "reconnect_on_gap")
        self.assertEqual(data["evalGap"]["expected"], 12)
        self.assertEqual(data["evalGap"]["actual"], 14)

    def test_cursor_projection_server_mismatch_and_new_run(self):
        """Verify server_instance_mismatch, new run non-started drop, and scan_started reset."""
        script = """
        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 5, eventCount: 5 };
        const proj = new CursorProjection(() => state);

        // 1. Mismatched server instance
        const mismatchEvt = { type: 'page_start', server_id: 'other-srv', run_id: 'run-1', sequence: 6 };
        const evalMismatch = proj.evaluate(mismatchEvt);

        // 2. New run without scan_started
        const staleNewEvt = { type: 'page_start', server_id: 'srv-1', run_id: 'run-2', sequence: 2 };
        const evalStaleNew = proj.evaluate(staleNewEvt);

        // 3. New run with scan_started (sequence 1)
        const startedEvt = { type: 'scan_started', server_id: 'srv-1', run_id: 'run-2', sequence: 1 };
        const evalStarted = proj.evaluate(startedEvt);
        proj.applyCursor(startedEvt, evalStarted);

        const stateAfterStart = { ...state };

        console.log(JSON.stringify({
            evalMismatch: evalMismatch,
            evalStaleNew: evalStaleNew,
            evalStarted: evalStarted,
            stateAfterStart: stateAfterStart,
        }));
        """
        data = _run_node_script(script)
        self.assertEqual(data["evalMismatch"]["action"], "drop")
        self.assertEqual(data["evalMismatch"]["reason"], "server_instance_mismatch")
        self.assertEqual(data["evalStaleNew"]["action"], "drop")
        self.assertEqual(data["evalStaleNew"]["reason"], "new_run_not_started")
        self.assertEqual(data["evalStarted"]["action"], "reset_and_process")
        self.assertEqual(data["stateAfterStart"]["scanRunId"], "run-2")
        self.assertEqual(data["stateAfterStart"]["lastEventSequence"], 1)

    def test_event_stream_mock_websocket_lifecycle_and_batching(self):
        """Verify mock WebSocket message queueing, RAF batching, and send."""
        script = """
        // Mock WebSocket
        class MockWebSocket {
            constructor(url) {
                this.url = url;
                this.readyState = 0; // CONNECTING
                this.sent = [];
                setTimeout(() => {
                    this.readyState = 1; // OPEN
                    if (this.onopen) this.onopen();
                }, 5);
            }
            send(data) {
                this.sent.push(data);
            }
            close(code, reason) {
                this.readyState = 3; // CLOSED
                if (this.onclose) this.onclose({ code: code || 1000, reason: reason || '' });
            }
        }

        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 0 };
        const received = [];

        const client = new EventStreamClient({
            WebSocket: MockWebSocket,
            host: 'test.local',
            stateAccessor: () => state,
            onEvent: (evt) => received.push(evt.type),
        });

        client.connect();

        setTimeout(() => {
            // Enqueue 3 events
            client.enqueueMessage({ type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 1, data: { url: 'http://a/1' } });
            client.enqueueMessage({ type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 2, data: { url: 'http://a/2' } });
            client.enqueueMessage({ type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 3, data: { url: 'http://a/3' } });

            // Send command
            const sendOk = client.send({ action: 'pause' });

            setTimeout(() => {
                const afterBatch = [...received];
                const lastSeq = state.lastEventSequence;
                const sentData = client.ws.sent;

                client.dispose();

                console.log(JSON.stringify({
                    connected: client.connected,
                    received: afterBatch,
                    lastSeq: lastSeq,
                    sendOk: sendOk,
                    sentData: sentData,
                    disposed: client._disposed,
                }));
            }, 50);
        }, 15);
        """
        data = _run_node_script(script)
        self.assertEqual(data["received"], ["page_start", "page_start", "page_start"])
        self.assertEqual(data["lastSeq"], 3)
        self.assertTrue(data["sendOk"])
        self.assertEqual(data["sentData"], [json.dumps({"action": "pause"}, separators=(",", ":"))])
        self.assertTrue(data["disposed"])

    def test_event_stream_close_code_4401_stops_retry_and_notifies(self):
        """Verify close code 4401 halts auto-reconnect and invokes onAuthRequired."""
        script = """
        class MockWebSocket {
            constructor(url) {
                this.readyState = 1;
                setTimeout(() => { if (this.onopen) this.onopen(); }, 5);
            }
            close(code) {
                this.readyState = 3;
                if (this.onclose) this.onclose({ code: code, reason: 'unauthorized' });
            }
        }

        let authNotified = false;
        let reconnectScheduled = false;

        const client = new EventStreamClient({
            WebSocket: MockWebSocket,
            reconnectDelay: 20,
            onAuthRequired: () => { authNotified = true; },
        });

        client.connect();

        setTimeout(() => {
            // Server closes with 4401
            client.ws.close(4401);

            setTimeout(() => {
                console.log(JSON.stringify({
                    authNotified: authNotified,
                    stopped: client._stopped,
                    hasTimer: client._reconnectTimer !== null,
                }));
            }, 60);
        }, 15);
        """
        data = _run_node_script(script)
        self.assertTrue(data["authNotified"])
        self.assertTrue(data["stopped"])
        self.assertFalse(data["hasTimer"])

    def test_event_stream_generation_guard_prevents_stale_callback_race(self):
        """Verify stale callbacks from old WebSocket generations are discarded."""
        script = """
        class MockWebSocket {
            constructor(url) {
                this.readyState = 1;
            }
            close() {
                this.readyState = 3;
            }
        }

        const eventsReceived = [];
        const client = new EventStreamClient({
            WebSocket: MockWebSocket,
            onEvent: (evt) => eventsReceived.push(evt.type),
        });

        client.connect();
        const oldWs = client.ws;
        const oldGen = client._generation;

        // Force reconnect to bump generation
        client.reconnect();
        const newWs = client.ws;
        const newGen = client._generation;

        // Trigger delayed event on oldWs
        if (oldWs.onmessage) {
            oldWs.onmessage({ data: JSON.stringify({ type: 'stale_event' }) });
        }
        // Trigger delayed close on oldWs
        if (oldWs.onclose) {
            oldWs.onclose({ code: 1006 });
        }

        client.dispose();

        console.log(JSON.stringify({
            genAdvanced: newGen > oldGen,
            oldWsDifferent: oldWs !== newWs,
            eventsReceived: eventsReceived,
            reconnectTimer: client._reconnectTimer,
        }));
        """
        data = _run_node_script(script)
        self.assertTrue(data["genAdvanced"])
        self.assertTrue(data["oldWsDifferent"])
        self.assertEqual(data["eventsReceived"], [])
        self.assertIsNone(data["reconnectTimer"])

    def test_safe_return_url_and_login_url_security(self):
        """Verify getSafeReturnUrl enforces relative paths and blocks protocol-relative targets."""
        script = """
        const normal = getSafeReturnUrl({ pathname: '/monitor', search: '?scan_id=1', hash: '#findings' });
        const external = getSafeReturnUrl({ pathname: 'https://evil.com/phish' });
        const protocolRel = getSafeReturnUrl({ pathname: '//evil.com/phish' });
        const empty = getSafeReturnUrl(null);
        const loginUrl = getLoginUrl({ pathname: '/monitor', search: '', hash: '#history' });

        console.log(JSON.stringify({
            normal: normal,
            external: external,
            protocolRel: protocolRel,
            empty: empty,
            loginUrl: loginUrl,
        }));
        """
        data = _run_node_script(script)
        self.assertEqual(data["normal"], "/monitor?scan_id=1#findings")
        self.assertEqual(data["external"], "/monitor")
        self.assertEqual(data["protocolRel"], "/monitor")
        self.assertEqual(data["empty"], "/monitor")
        self.assertEqual(data["loginUrl"], "/login?next=%2Fmonitor%23history")

    def test_projection_fixtures_safe_hostile_and_mixed_twins(self):
        """Replay safe / hostile / mixed event streams; hostile events must not move the cursor."""
        expectations = {
            "safe_stream.json": (4, 5),
            "hostile_stream.json": (2, 3),
            "mixed_stream.json": (5, 5),
        }
        for name, (last_seq, event_count) in expectations.items():
            with self.subTest(fixture=name):
                result, fixture = _run_projection_fixture(name)
                self.assertEqual(result["actions"], fixture["expected_actions"])
                # cursor 契約の4項目だけを突き合わせる (scanId はイベント毎に上書きされる従来挙動)。
                for key in ("serverInstanceId", "scanRunId", "lastEventSequence", "eventCount"):
                    self.assertEqual(result["final"][key], fixture["expected_final"][key])
                # 安全ツイン(safe)と敵性ツイン(hostile)は同じ初期 cursor から出発する。
                self.assertEqual(fixture["state"]["lastEventSequence"], 2)
                self.assertEqual(result["final"]["lastEventSequence"], last_seq)
                self.assertEqual(result["final"]["eventCount"], event_count)
                # 敵性イベントは server/run 文脈を書き換えない（context 混線なし）。
                self.assertEqual(result["final"]["serverInstanceId"], "srv-a")
                self.assertEqual(result["final"]["scanRunId"], "run-1")

    def test_event_stream_dispose_cancels_timer_raf_and_late_callbacks(self):
        """dispose() must cancel the reconnect timer/RAF, clear the queue, and ignore late socket callbacks."""
        script = """
        const instances = [];
        class MockWebSocket {
            constructor(url) {
                this.url = url;
                this.readyState = 1; // OPEN
                instances.push(this);
            }
            close(code) {
                this.readyState = 3;
                if (this.onclose) this.onclose({ code: code || 1000 });
            }
        }

        const state = { connected: true, serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 0 };
        const received = [];
        const client = new EventStreamClient({
            WebSocket: MockWebSocket,
            reconnectDelay: 20,
            stateAccessor: () => state,
            onEvent: (evt) => received.push(evt.type),
        });

        client.connect();
        const oldWs = client.ws;
        state.ws = oldWs;

        // Trigger a network close so a reconnect timer exists, then queue events before the RAF flush.
        oldWs.onclose({ code: 1006 });
        const hadTimer = client._reconnectTimer !== null;
        client.enqueueMessage({ type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 1 });
        const hadRaf = client._rafPending;

        client.dispose();

        // Late callbacks from the disposed socket must be ignored.
        oldWs.onmessage({ data: JSON.stringify({ type: 'stale_event' }) });
        oldWs.onclose({ code: 1006 });
        oldWs.onerror();

        setTimeout(() => {
            console.log(JSON.stringify({
                hadTimer: hadTimer,
                hadRaf: hadRaf,
                instances: instances.length,
                received: received,
                timer: client._reconnectTimer,
                rafPending: client._rafPending,
                queueLength: client._msgQueue.length,
                disposed: client._disposed,
                connected: client.connected,
                stateWs: state.ws,
                stateConnected: state.connected,
            }));
        }, 60);
        """
        data = _run_node_script(script)
        self.assertTrue(data["hadTimer"])
        self.assertTrue(data["hadRaf"])
        self.assertEqual(data["instances"], 1)  # dispose 後に再接続 socket を作らない
        self.assertEqual(data["received"], [])  # late message は dispatch しない
        self.assertIsNone(data["timer"])
        self.assertFalse(data["rafPending"])
        self.assertEqual(data["queueLength"], 0)
        self.assertTrue(data["disposed"])
        self.assertFalse(data["connected"])
        self.assertIsNone(data["stateWs"])
        self.assertFalse(data["stateConnected"])

    def test_event_stream_network_close_reconnects_once_and_ignores_old_socket(self):
        """A normal close schedules exactly one deterministic reconnect; the old socket stays silent."""
        script = """
        const instances = [];
        class MockWebSocket {
            constructor(url) {
                this.url = url;
                this.readyState = 1;
                instances.push(this);
            }
            close(code) {
                this.readyState = 3;
                if (this.onclose) this.onclose({ code: code || 1000 });
            }
        }

        const received = [];
        const client = new EventStreamClient({
            WebSocket: MockWebSocket,
            reconnectDelay: 20,
            onEvent: (evt) => received.push(evt.type),
        });

        client.connect();
        const oldWs = client.ws;
        oldWs.readyState = 3;  // browser: onclose は CLOSED 遷移後に発火する
        oldWs.onclose({ code: 1006 });

        setTimeout(() => {
            const newWs = client.ws;
            // Late traffic from the replaced socket must not be observed twice.
            oldWs.onmessage({ data: JSON.stringify({ type: 'stale_event' }) });
            newWs.onmessage({ data: JSON.stringify({ type: 'fresh_event', server_id: 'srv-1', run_id: 'run-1', sequence: 1, data: {} }) });

            setTimeout(() => {
                console.log(JSON.stringify({
                    instances: instances.length,
                    reconnected: oldWs !== newWs,
                    received: received,
                    defaultDelay: new EventStreamClient({ WebSocket: MockWebSocket }).reconnectDelay,
                }));
            }, 40);
        }, 80);
        """
        data = _run_node_script(script)
        self.assertEqual(data["instances"], 2)
        self.assertTrue(data["reconnected"])
        self.assertEqual(data["received"], ["fresh_event"])
        self.assertEqual(data["defaultDelay"], 3000)

    def test_event_stream_gap_reconnects_once_without_duplicate_socket(self):
        """A sequence gap forces a single reconnect; a late close of the old socket must not add another."""
        script = """
        const instances = [];
        class MockWebSocket {
            constructor(url) {
                this.url = url;
                this.readyState = 1;
                instances.push(this);
            }
            close(code) {
                this.readyState = 3;
                if (this.onclose) this.onclose({ code: code || 1000 });
            }
        }

        const state = { serverInstanceId: 'srv-1', scanRunId: 'run-1', lastEventSequence: 5 };
        const received = [];
        const client = new EventStreamClient({
            WebSocket: MockWebSocket,
            reconnectDelay: 20,
            stateAccessor: () => state,
            onEvent: (evt) => received.push(evt.type),
        });

        client.connect();
        const oldWs = client.ws;
        client.enqueueMessage({ type: 'page_start', server_id: 'srv-1', run_id: 'run-1', sequence: 7 });

        setTimeout(() => {
            const afterGap = instances.length;
            const newWs = client.ws;
            // The replaced socket's close arrives late.
            oldWs.onclose({ code: 1006 });

            setTimeout(() => {
                console.log(JSON.stringify({
                    afterGap: afterGap,
                    finalInstances: instances.length,
                    reconnected: oldWs !== newWs,
                    received: received,
                    lastSeq: state.lastEventSequence,
                }));
            }, 80);
        }, 80);
        """
        data = _run_node_script(script)
        self.assertEqual(data["afterGap"], 2)  # gap で 1 回だけ再接続
        self.assertEqual(data["finalInstances"], 2)  # 旧 socket の遅延 close で追加再接続しない
        self.assertTrue(data["reconnected"])
        self.assertEqual(data["received"], [])  # gap event 自体は dispatch しない
        self.assertEqual(data["lastSeq"], 5)


class EventStreamServerAssetTests(unittest.TestCase):
    def setUp(self):
        self.monitor = MonitorServer(port=0)
        self.client = TestClient(self.monitor.app)

    def test_server_returns_event_stream_asset_with_javascript_mime(self):
        """Verify /ui/event-stream.js is served with proper content-type and text."""
        res = self.client.get("/ui/event-stream.js")
        self.assertEqual(res.status_code, 200)
        self.assertIn("javascript", res.headers.get("content-type", "").lower())
        self.assertIn("class EventStreamClient", res.text)
        self.assertIn("class CursorProjection", res.text)

    def test_server_auth_protects_event_stream_js(self):
        """Verify /ui/event-stream.js requires authentication when auth_token is set."""
        srv = MonitorServer(port=0, auth_token="secret-token")
        client = TestClient(srv.app)

        res_unauth = client.get("/ui/event-stream.js")
        self.assertEqual(res_unauth.status_code, 401)

        # Authenticated via login
        client.post("/login", data={"token": "secret-token"})
        res_auth = client.get("/ui/event-stream.js")
        self.assertEqual(res_auth.status_code, 200)
        self.assertIn("EventStreamClient", res_auth.text)

    def test_dashboard_html_includes_event_stream_js(self):
        """Verify templates/dashboard.html includes /ui/event-stream.js script tag."""
        content = DASHBOARD_HTML.read_text(encoding="utf-8")
        self.assertIn('<script src="/ui/event-stream.js"></script>', content)
        self.assertIn('initEventStream', content)


class EventStreamChromiumIntegrationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if not _chromium_available():
            raise unittest.SkipTest("Chromium not available in this environment")

        cls.monitor = MonitorServer(port=0)
        cls.monitor.api_scan_id = "u09-integration"
        cls.monitor._begin_scan_snapshot()
        cls.monitor.api_scan_status = "scanning"
        cls.monitor.api_target = "http://127.0.0.1:9/u09-target"
        cls.monitor.api_findings = []

        cls.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        cls.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        cls.sock.bind(("127.0.0.1", 0))
        cls.sock.listen(128)
        cls.port = cls.sock.getsockname()[1]
        cls.server = uvicorn.Server(uvicorn.Config(
            cls.monitor.app, log_level="error", access_log=False, lifespan="off"
        ))
        cls.thread = threading.Thread(
            target=cls.server.run, kwargs={"sockets": [cls.sock]}, daemon=True
        )
        cls.thread.start()
        cls.base_url = f"http://127.0.0.1:{cls.port}"

    @classmethod
    def tearDownClass(cls):
        if hasattr(cls, "server"):
            cls.server.should_exit = True
        if hasattr(cls, "thread"):
            cls.thread.join(timeout=3)
        if hasattr(cls, "sock"):
            try:
                cls.sock.close()
            except Exception:
                pass

    def test_browser_event_stream_single_socket_across_navigation(self):
        """Verify single WebSocket across #live, #history, and #audit navigation without duplication."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{self.base_url}/monitor#live", wait_until="domcontentloaded")
            page.wait_for_function("() => window._eventStream && window._eventStream.connected && state.ws")

            # Capture active socket identity
            page.evaluate("() => { window.__initialSocket = state.ws; }")

            # Navigate to #history
            page.evaluate("() => switchMainView('history')")
            page.wait_for_function("() => document.getElementById('viewScanHistory').style.display !== 'none'")
            self.assertTrue(page.evaluate("() => state.ws === window.__initialSocket"))

            # Navigate to #audit
            page.evaluate("() => switchMainView('audit')")
            page.wait_for_function("() => document.getElementById('viewAuditLog').style.display !== 'none'")
            self.assertTrue(page.evaluate("() => state.ws === window.__initialSocket"))

            # Navigate back to #live
            page.evaluate("() => switchMainView('live')")
            page.wait_for_function("() => document.getElementById('viewLiveMonitor').style.display !== 'none'")
            self.assertTrue(page.evaluate("() => state.ws === window.__initialSocket"))

            browser.close()

    def test_browser_4401_auth_expiry_halts_reconnect_and_renders_login_prompt(self):
        """Verify 4401 close halts auto-reconnect and displays login prompt in UI."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            page.wait_for_function("() => window._eventStream && window._eventStream.connected")

            # Simulate backend 4401 closure on active socket
            page.evaluate("() => { state.ws.close(4401, 'unauthorized'); }")

            # Wait for onclose handler
            page.wait_for_function("() => !state.connected && window._eventStream._stopped")

            # Assert wsBadge text and class
            badge_text = page.locator("#wsBadge").inner_text()
            self.assertIn("4401", badge_text)

            # Assert auth banner is rendered with login link
            self.assertTrue(page.locator("#wsAuthErrorBanner").is_visible())
            login_link = page.locator("#wsAuthErrorBanner a").get_attribute("href")
            self.assertIn("/login", login_link)

            # Wait longer than reconnectDelay to verify NO reconnect occurs
            page.wait_for_timeout(350)
            self.assertTrue(page.evaluate("() => window._eventStream._stopped"))
            self.assertFalse(page.evaluate("() => window._eventStream.connected"))

            browser.close()

    def test_browser_malformed_durable_event_is_explicitly_stale(self):
        """Malformed ordered events are visible in Chromium and do not advance the cursor."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            page.wait_for_function("() => window._eventStream && window._eventStream.connected")
            page.evaluate("""() => {
              const client = window._eventStream;
              const socket = client.ws;
              client.ws = null; // Exercise the UI stale callback without changing the live test server.
              client.processEvent({
                type: 'page_start', server_id: state.serverInstanceId,
                run_id: state.scanRunId, sequence: state.lastEventSequence + 1,
                data: { url: 42 },
              }, true);
              client.ws = socket;
            }""")
            self.assertIn("stale event", page.locator("#wsBadge").inner_text())
            self.assertEqual(page.evaluate("() => state.lastEventSequence"), 0)
            browser.close()

    def test_browser_multitab_nonce_correlation_prevents_cross_context_promotion(self):
        """A foreign-tab scan_started/scan_rejected must not promote credentials, clear pending, or set errors."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            page.wait_for_function("() => window._eventStream && window._eventStream.connected")

            result = page.evaluate("""
                () => {
                    state.myScanNonce = 'tab-a';
                    state.pendingScanConfig = {
                        url: 'http://127.0.0.1:9/mine',
                        accounts: [{username: 'u', password: 'SECRET_A'}],
                    };
                    state.lastScanConfig = null;
                    state.lastScanConfigRedacted = false;

                    // 他タブ(tab-b)の scan_started を観測: 自分の pending を昇格せず、秘密も漏らさない。
                    handleEvent({
                        type: 'scan_started',
                        data: {
                            url: 'http://127.0.0.1:9/other',
                            _client_nonce: 'tab-b',
                            accounts: [{username: 'x', password: 'SECRET_B'}],
                        },
                        timestamp: 1,
                    });
                    const foreignStartLeak = JSON.stringify(state.lastScanConfig || {}).includes('SECRET');
                    const pendingAfterForeignStart = !!(state.pendingScanConfig
                        && state.pendingScanConfig.accounts[0].password === 'SECRET_A');

                    // 自分の scan_started: pending のフル設定(秘密含む)を従来どおり昇格する。
                    handleEvent({
                        type: 'scan_started',
                        data: {url: 'http://127.0.0.1:9/mine', _client_nonce: 'tab-a'},
                        timestamp: 2,
                    });
                    const ownPromoted = !!(state.lastScanConfig
                        && state.lastScanConfig.accounts
                        && state.lastScanConfig.accounts[0].password === 'SECRET_A');
                    const pendingAfterOwnStart = state.pendingScanConfig;

                    // 他タブの scan_rejected では自分の pending を破棄しない。
                    state.pendingScanConfig = {
                        url: 'http://127.0.0.1:9/mine2',
                        accounts: [{username: 'u', password: 'SECRET_A'}],
                    };
                    handleEvent({
                        type: 'scan_rejected',
                        data: {_client_nonce: 'tab-b', message: 'other tab rejected'},
                        timestamp: 3,
                    });
                    const pendingAfterForeignReject = !!(state.pendingScanConfig
                        && state.pendingScanConfig.accounts[0].password === 'SECRET_A');

                    // 自分の scan_rejected では pending を破棄する(従来挙動)。
                    handleEvent({
                        type: 'scan_rejected',
                        data: {_client_nonce: 'tab-a', message: 'mine rejected'},
                        timestamp: 4,
                    });
                    const pendingAfterOwnReject = state.pendingScanConfig;

                    return {
                        foreignStartLeak,
                        pendingAfterForeignStart,
                        ownPromoted,
                        pendingAfterOwnStart,
                        pendingAfterForeignReject,
                        pendingAfterOwnReject,
                    };
                }
            """)

            self.assertFalse(result["foreignStartLeak"])
            self.assertTrue(result["pendingAfterForeignStart"])
            self.assertTrue(result["ownPromoted"])
            self.assertIsNone(result["pendingAfterOwnStart"])
            self.assertTrue(result["pendingAfterForeignReject"])
            self.assertIsNone(result["pendingAfterOwnReject"])

            browser.close()

    def test_browser_samews_command_sending(self):
        """Verify _wsSend / eventStream.send sends command through active WebSocket."""
        from playwright.sync_api import sync_playwright

        with sync_playwright() as playwright:
            browser = playwright.chromium.launch(headless=True)
            page = browser.new_page()
            page.goto(f"{self.base_url}/monitor", wait_until="domcontentloaded")
            page.wait_for_function("() => window._eventStream && window._eventStream.connected")

            # Send pause intervention command via existing _wsSend
            ok = page.evaluate("() => _wsSend({ action: 'intervention', command: 'pause' })")
            self.assertTrue(ok)

            browser.close()
