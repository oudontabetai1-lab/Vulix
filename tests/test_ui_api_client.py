"""Tests for shared typed API Client and ScopedApiClient cancellation."""
import json
from pathlib import Path
import socket
import subprocess
import threading
import time

from fastapi.testclient import TestClient
from playwright.sync_api import sync_playwright
import uvicorn

from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value


ROOT = Path(__file__).resolve().parents[1]
API_CLIENT_JS = ROOT / "templates" / "ui" / "api-client.js"
APP_SHELL_JS = ROOT / "templates" / "ui" / "app-shell.js"


def find_free_port():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class UvicornServerThread:
    def __init__(self, srv: MonitorServer, port: int):
        self.srv = srv
        self.port = port
        self.config = uvicorn.Config(srv.app, host="127.0.0.1", port=port, log_level="warning")
        self.server = uvicorn.Server(self.config)
        self.thread = threading.Thread(target=self.server.run, daemon=True)

    def start(self):
        self.thread.start()
        time.sleep(0.5)

    def stop(self):
        self.server.should_exit = True
        self.thread.join(timeout=2)


def _run_node_script(script: str) -> dict:
    """Run a small JavaScript snippet via Node.js and return parsed JSON."""
    full_script = f"""
    const {{ ApiClient, ScopedApiClient, ApiResult, defaultClient }} = require('{API_CLIENT_JS}');
    {script}
    """
    res = subprocess.run(
        ["node", "-e", full_script],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(res.stdout)


def test_api_client_exports_expected_symbols():
    """Verify that templates/ui/api-client.js exists and exports expected interfaces."""
    assert API_CLIENT_JS.is_file()
    result = _run_node_script("console.log(JSON.stringify(Object.keys(require('./templates/ui/api-client.js'))));")
    expected = ["ApiClient", "ScopedApiClient", "ApiResult", "defaultClient", "createScope", "request", "get"]
    assert all(sym in result for sym in expected)


def test_api_result_typed_states():
    """Verify ApiResult constructor and factory methods for typed states."""
    script = """
    const successRes = ApiResult.success({ foo: 'bar' }, 200);
    const unauthRes = ApiResult.unauthorized('Unauthorized');
    const httpErrRes = ApiResult.httpError(500, 'Internal Server Error');
    const netErrRes = ApiResult.networkError(new Error('Connection refused'));
    const decodeErrRes = ApiResult.decodeError(200, 'OK', null, '{bad', new Error('Unexpected token'));
    const abortRes = ApiResult.aborted(new Error('Operation aborted'));

    console.log(JSON.stringify({
        success: {
            ok: successRes.ok,
            kind: successRes.kind,
            status: successRes.status,
            isSuccess: successRes.isSuccess(),
            isUnauthorized: successRes.isUnauthorized(),
            data: successRes.data,
            errorMessage: successRes.errorMessage,
        },
        unauthorized: {
            ok: unauthRes.ok,
            kind: unauthRes.kind,
            status: unauthRes.status,
            isUnauthorized: unauthRes.isUnauthorized(),
            isSuccess: unauthRes.isSuccess(),
            errorMessage: unauthRes.errorMessage,
        },
        httpError: {
            ok: httpErrRes.ok,
            kind: httpErrRes.kind,
            status: httpErrRes.status,
            isHttpError: httpErrRes.isHttpError(),
            errorMessage: httpErrRes.errorMessage,
        },
        networkError: {
            ok: netErrRes.ok,
            kind: netErrRes.kind,
            isNetworkError: netErrRes.isNetworkError(),
            errorMessage: netErrRes.errorMessage,
        },
        decodeError: {
            ok: decodeErrRes.ok,
            kind: decodeErrRes.kind,
            isDecodeError: decodeErrRes.isDecodeError(),
            rawText: decodeErrRes.rawText,
            errorMessage: decodeErrRes.errorMessage,
        },
        aborted: {
            ok: abortRes.ok,
            kind: abortRes.kind,
            isAborted: abortRes.isAborted(),
            errorMessage: abortRes.errorMessage,
        },
    }));
    """
    data = _run_node_script(script)

    assert data["success"]["ok"] is True
    assert data["success"]["kind"] == "success"
    assert data["success"]["isSuccess"] is True
    assert data["success"]["data"] == {"foo": "bar"}
    assert data["success"]["errorMessage"] == ""

    assert data["unauthorized"]["ok"] is False
    assert data["unauthorized"]["kind"] == "unauthorized"
    assert data["unauthorized"]["status"] == 401
    assert data["unauthorized"]["isUnauthorized"] is True
    assert "401" in data["unauthorized"]["errorMessage"]
    assert "認証" in data["unauthorized"]["errorMessage"]

    assert data["httpError"]["ok"] is False
    assert data["httpError"]["kind"] == "http_error"
    assert data["httpError"]["status"] == 500
    assert data["httpError"]["isHttpError"] is True
    assert "500" in data["httpError"]["errorMessage"]

    assert data["networkError"]["ok"] is False
    assert data["networkError"]["kind"] == "network_error"
    assert data["networkError"]["isNetworkError"] is True
    assert "通信エラー" in data["networkError"]["errorMessage"]

    assert data["decodeError"]["ok"] is False
    assert data["decodeError"]["kind"] == "decode_error"
    assert data["decodeError"]["isDecodeError"] is True
    assert data["decodeError"]["rawText"] == "{bad"

    assert data["aborted"]["ok"] is False
    assert data["aborted"]["kind"] == "aborted"
    assert data["aborted"]["isAborted"] is True


def test_api_client_request_flows_with_mock_fetch():
    """Verify ApiClient request processing for 200, 401, 500, network error, and JSON decode error."""
    script = """
    (async () => {
        // Mock fetch generator
        function makeMockFetch(responseHandler) {
            return async (url, options) => {
                if (options.signal && options.signal.aborted) {
                    const err = new Error('Aborted');
                    err.name = 'AbortError';
                    throw err;
                }
                return responseHandler(url, options);
            };
        }

        // 1. Success 200 JSON
        const client1 = new ApiClient({
            fetch: makeMockFetch(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: {},
                text: async () => JSON.stringify({ scans: [{ id: 's1' }] }),
            })),
        });
        const res1 = await client1.get('/api/v1/scans');

        // 2. 401 Unauthorized with hook
        let hookCalled = false;
        const client2 = new ApiClient({
            fetch: makeMockFetch(async () => ({
                ok: false,
                status: 401,
                statusText: 'Unauthorized',
                headers: {},
                text: async () => JSON.stringify({ detail: 'Token required' }),
            })),
            onUnauthorized: () => { hookCalled = true; },
        });
        const res2 = await client2.get('/api/v1/scans');

        // 3. 500 Internal Server Error
        const client3 = new ApiClient({
            fetch: makeMockFetch(async () => ({
                ok: false,
                status: 500,
                statusText: 'Internal Server Error',
                headers: {},
                text: async () => 'Database failure',
            })),
        });
        const res3 = await client3.get('/api/v1/scans');

        // 4. Decode error (invalid JSON on 200)
        const client4 = new ApiClient({
            fetch: makeMockFetch(async () => ({
                ok: true,
                status: 200,
                statusText: 'OK',
                headers: {},
                text: async () => '<not-json>',
            })),
        });
        const res4 = await client4.get('/api/v1/scans');

        // 5. Network error (fetch rejects)
        const client5 = new ApiClient({
            fetch: async () => {
                throw new Error('Failed to fetch');
            },
        });
        const res5 = await client5.get('/api/v1/scans');

        console.log(JSON.stringify({
            res1: { ok: res1.ok, kind: res1.kind, data: res1.data },
            res2: { ok: res2.ok, kind: res2.kind, status: res2.status, hookCalled: hookCalled },
            res3: { ok: res3.ok, kind: res3.kind, status: res3.status },
            res4: { ok: res4.ok, kind: res4.kind, isDecodeError: res4.isDecodeError() },
            res5: { ok: res5.ok, kind: res5.kind, isNetworkError: res5.isNetworkError() },
        }));
    })();
    """
    data = _run_node_script(script)
    assert data["res1"]["ok"] is True
    assert data["res1"]["kind"] == "success"
    assert data["res1"]["data"] == {"scans": [{"id": "s1"}]}

    assert data["res2"]["ok"] is False
    assert data["res2"]["kind"] == "unauthorized"
    assert data["res2"]["status"] == 401
    assert data["res2"]["hookCalled"] is True

    assert data["res3"]["ok"] is False
    assert data["res3"]["kind"] == "http_error"
    assert data["res3"]["status"] == 500

    assert data["res4"]["ok"] is False
    assert data["res4"]["kind"] == "decode_error"
    assert data["res4"]["isDecodeError"] is True

    assert data["res5"]["ok"] is False
    assert data["res5"]["kind"] == "network_error"
    assert data["res5"]["isNetworkError"] is True


def test_scoped_api_client_cancel_all_stale_reads():
    """Verify ScopedApiClient cancels all active in-flight reads on unmount / navigation."""
    script = """
    (async () => {
        let fetchCount = 0;
        let abortCount = 0;

        const delayedFetch = async (url, options) => {
            fetchCount++;
            return new Promise((resolve, reject) => {
                const timer = setTimeout(() => {
                    resolve({
                        ok: true,
                        status: 200,
                        statusText: 'OK',
                        headers: {},
                        text: async () => JSON.stringify({ scans: [] }),
                    });
                }, 500);

                if (options.signal) {
                    options.signal.addEventListener('abort', () => {
                        clearTimeout(timer);
                        abortCount++;
                        const err = new Error('Aborted');
                        err.name = 'AbortError';
                        reject(err);
                    });
                }
            });
        };

        const client = new ApiClient({ fetch: delayedFetch });
        const scope = client.createScope();

        // Launch two slow reads
        const p1 = scope.get('/api/v1/scans?page=1');
        const p2 = scope.get('/api/v1/scans?page=2');

        const activeBeforeCancel = scope.getActiveCount();

        // Unmount / cancel all
        scope.cancelAll('Unmounting view');

        const res1 = await p1;
        const res2 = await p2;

        const activeAfterCancel = scope.getActiveCount();

        // Start a fresh read after cancellation to ensure scope remains reusable
        const p3 = scope.get('/api/v1/scans?fresh=1');
        const res3 = await p3;

        console.log(JSON.stringify({
            activeBeforeCancel: activeBeforeCancel,
            activeAfterCancel: activeAfterCancel,
            res1: { isAborted: res1.isAborted(), kind: res1.kind },
            res2: { isAborted: res2.isAborted(), kind: res2.kind },
            res3: { ok: res3.ok, kind: res3.kind, isAborted: res3.isAborted() },
            fetchCount: fetchCount,
            abortCount: abortCount,
        }));
    })();
    """
    data = _run_node_script(script)
    assert data["activeBeforeCancel"] == 2
    assert data["activeAfterCancel"] == 0
    assert data["res1"]["isAborted"] is True
    assert data["res1"]["kind"] == "aborted"
    assert data["res2"]["isAborted"] is True
    assert data["res2"]["kind"] == "aborted"
    assert data["res3"]["ok"] is True
    assert data["res3"]["kind"] == "success"
    assert data["res3"]["isAborted"] is False
    assert data["fetchCount"] == 3
    assert data["abortCount"] == 2


def test_app_shell_unmount_cancels_scan_history_read():
    """Verify that AppShell navigation transition from history to live triggers cancelScanHistory."""
    script = f"""
    const {{ setupAppShell }} = require('{APP_SHELL_JS}');

    let cancelCalled = false;
    const fakeGlobal = {{
        cancelScanHistory: () => {{
            cancelCalled = true;
        }},
        loadScanHistory: () => {{}},
        location: {{ hash: '#history' }},
        document: {{
            getElementById: () => null,
        }},
    }};

    const shell = setupAppShell({{ global: fakeGlobal }});
    // Currently on #history
    shell.dispatcher.navigateTo('history');
    cancelCalled = false;

    // Transition away to live view -> must invoke history unmount which calls cancelScanHistory
    shell.dispatcher.navigateTo('live');

    console.log(JSON.stringify({{
        cancelCalled: cancelCalled,
        activeView: shell.registry.getActiveId(),
    }}));
    """
    data = _run_node_script(script)
    assert data["cancelCalled"] is True
    assert data["activeView"] == "live"


def test_dashboard_history_unmount_cancels_in_flight_fetch_in_browser(tmp_path, monkeypatch):
    """Playwright browser verification: unmounting history during in-flight fetch cancels stale read."""
    monkeypatch.setattr("wscan.monitor.OUTPUT_BASE", tmp_path)

    srv = MonitorServer()
    port = find_free_port()
    server_thread = UvicornServerThread(srv, port)
    server_thread.start()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True)
            page = browser.new_page()

            # Intercept /api/v1/scans with a delayed fulfill in a background thread
            def delayed_route(route):
                def fulfill_later():
                    time.sleep(0.6)
                    try:
                        route.fulfill(
                            status=200,
                            body=json.dumps({"scans": [{"id": "stale_scan", "target": "http://stale.example.com", "status": "done"}]}),
                            headers={"Content-Type": "application/json"}
                        )
                    except Exception:
                        pass
                threading.Thread(target=fulfill_later, daemon=True).start()

            page.route("**/api/v1/scans", delayed_route)

            page.goto(f"http://127.0.0.1:{port}/monitor")
            assert page.is_visible("#viewLiveMonitor")

            # 1. Switch to Scan History -> triggers loadScanHistory with delayed fetch
            page.click("#navScanHistory")
            assert page.is_visible("#viewScanHistory")
            page.wait_for_selector("#historyLoadingState", state="visible", timeout=3000)

            # 2. Immediately switch back to Live Monitor before fetch finishes (< 200ms)
            page.click("#navLiveMonitor")
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")

            # 3. Wait for delayed response to arrive (800ms)
            time.sleep(0.8)

            # Assert live view remains cleanly displayed and history view was unmounted without DOM contamination
            assert page.is_visible("#viewLiveMonitor")
            assert not page.is_visible("#viewScanHistory")

            # 4. Now remove route interception and switch back to history
            page.unroute("**/api/v1/scans")
            page.click("#navScanHistory")
            page.wait_for_selector("#historyEmptyState", state="visible", timeout=3000)
            assert page.is_visible("#viewScanHistory")

            browser.close()
    finally:
        server_thread.stop()

