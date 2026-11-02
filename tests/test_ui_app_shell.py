"""Acceptance checks for the opt-in /app shell and legacy adapters."""
from __future__ import annotations

import shutil

import pytest
from fastapi.testclient import TestClient

from tests.ui_harness import STANDARD_VIEWPORTS, UIHarness, ui_harness
from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value

UI_ASSETS = ["/ui/app-entry.js", "/ui/app-shell.js", "/ui/api-client.js", "/ui/tokens.css", "/ui/components.css"]


@pytest.mark.parametrize("auth_token", [""])
def test_app_route_and_assets_keep_existing_auth_boundary(auth_token):
    server = MonitorServer(port=0, auth_token=auth_token)
    client = TestClient(server.app)
    assert client.get("/app").status_code == 200
    assert "app-entry.js" in client.get("/app").text
    assert all(client.get(asset).status_code == 200 for asset in UI_ASSETS)
    assert "VulixAppShell" in client.get("/ui/app-entry.js").text
    assert "Server Portal" in client.get("/").text
    assert "scanConfigOverlay" in client.get("/monitor").text


def test_app_route_and_assets_require_existing_auth():
    server = MonitorServer(port=0, auth_token="ui-test-token")
    client = TestClient(server.app)
    assert client.get("/app", headers={"accept": "text/html"}, follow_redirects=False).status_code == 303
    assert all(client.get(asset).status_code == 401 for asset in UI_ASSETS)
    client.cookies.set(SESSION_COOKIE, _session_value("ui-test-token"))
    assert client.get("/app").status_code == 200
    assert all(client.get(asset).status_code == 200 for asset in UI_ASSETS)


@pytest.mark.parametrize("width", [1440, 768])
def test_app_shell_navigation_preserves_legacy_surfaces_and_one_socket(ui_harness: UIHarness, width: int):
    page = ui_harness.new_page(**STANDARD_VIEWPORTS[width])
    sockets = []
    page.on("websocket", lambda socket: sockets.append(socket.url))
    page.goto(f"{ui_harness.server_url}/app", wait_until="domcontentloaded")
    page.wait_for_function("document.querySelector('#portalFrame').contentDocument?.title.includes('Server Portal')")
    assert page.locator("#portalFrame").is_visible()
    ui_harness.assert_no_horizontal_overflow(page, max_allowed=width + 1)
    ui_harness.capture_screenshot(page, "app-portal", width, dest_dir=ui_harness.output_dir / "screenshots")

    page.locator('[data-route="setup"]').click()
    setup = page.frame_locator("#monitorFrame")
    setup.locator("#scanConfigOverlay.active").wait_for()
    setup.locator("#cfgInputUrl").fill("https://safe.example.test")
    setup.locator("#cfgTab-basic #cfgDepth").fill("4")
    ui_harness.capture_screenshot(page, "app-setup", width, dest_dir=ui_harness.output_dir / "screenshots")
    secret_sentinel = "APP_SECRET_SENTINEL_DO_NOT_PERSIST"
    setup.locator(".cfg-tab").filter(has_text="認証・Cookie").click()
    setup.locator("#cfgAuthPass").fill(secret_sentinel)
    page.locator('[data-route="monitor"]').click()
    page.wait_for_function("document.querySelector('[data-route=monitor]').getAttribute('aria-current') === 'page'")
    assert page.locator('[data-route="monitor"]').get_attribute("aria-current") == "page"
    assert page.locator('[data-route="setup"]').get_attribute("aria-current") is None
    page.wait_for_function("() => !document.querySelector('#monitorFrame').contentDocument.querySelector('#scanConfigOverlay').classList.contains('active')")
    assert setup.locator("#cfgInputUrl").input_value() == "https://safe.example.test"
    assert setup.locator("#cfgTab-basic #cfgDepth").input_value() == "4"
    frame = page.frame_locator("#monitorFrame")
    context_data = frame.locator("body").evaluate("() => JSON.stringify(VulixAppBridge.getContext())")
    assert secret_sentinel not in context_data
    assert secret_sentinel not in page.url
    assert secret_sentinel not in page.evaluate("() => JSON.stringify(Object.entries(localStorage))")
    assert secret_sentinel not in page.locator("body").inner_text()
    monitor_frame = next(frame for frame in page.frames if frame.url.endswith("/monitor"))
    ui_harness.populate_live_monitor(monitor_frame)
    ui_harness.capture_screenshot(page, "app-monitor", width, dest_dir=ui_harness.output_dir / "screenshots")

    for route in ["setup", "monitor", "portal", "monitor", "setup"]:
        page.locator(f'[data-route="{route}"]').click()
        page.wait_for_timeout(80)
    assert len(sockets) == 1, f"expected one persistent dashboard socket, saw {len(sockets)}"
    assert page.locator("#portalFrame").get_attribute("src") == "about:blank"
    page.go_back()
    page.wait_for_timeout(80)
    assert page.url.endswith("#/monitor")
    page.go_forward()
    page.wait_for_timeout(80)
    assert page.url.endswith("#/setup")
    page.reload(wait_until="domcontentloaded")
    setup.locator("#scanConfigOverlay.active").wait_for()
    assert page.url.endswith("#/setup")
    page.wait_for_function("""() => {
      const frame = document.querySelector('#monitorFrame')?.contentWindow;
      return frame?.VulixAppBridge && frame?._eventStream?.connected &&
        frame.eval("typeof state.serverInstanceId === 'string' && state.serverInstanceId.length > 0");
    }""")

    frame = page.frame_locator("#monitorFrame")
    frame.locator("#cfgInputUrl").wait_for()
    frame.locator("#cfgInputUrl").fill("https://safe.example.test")
    page.evaluate("() => document.querySelector('#monitorFrame').contentWindow.eval(\"state.serverInstanceId='server-demo'; state.scanRunId='run-demo'; state.scanId='20261026_100000'; state.status='scanning'; publishAppScanContext()\")")
    page.evaluate("() => { location.hash = '#/monitor?scan=20261026_100000'; }")
    page.wait_for_function("() => document.querySelector('#scanContext').textContent.includes('20261026_100000') && !document.querySelector('#monitorFrame').hidden")
    assert "20261026_100000" in page.locator("#scanContext").inner_text()
    keys = frame.locator("body").evaluate("() => Object.keys(VulixAppBridge.getContext()).sort()")
    assert keys == ["run_id", "scan_id", "server_id", "status"]
    assert secret_sentinel not in ui_harness.get_errors(page).__str__()
    page.evaluate("() => { location.hash = '#/portal'; }")
    page.wait_for_function("() => document.querySelector('#scanContext').textContent === ''")
    frame.locator("body").evaluate("() => window.parent.postMessage({type:'vulix:scan-context', context:{scan_id:'stale-id',status:'scanning'}}, window.location.origin)")
    page.wait_for_timeout(50)
    assert page.locator("#scanContext").inner_text() == ""
    page.evaluate("() => { location.hash = '#/monitor?scan=20261026_110000'; }")
    page.get_by_text("snapshot と一致しません", exact=False).wait_for()
    shutil.rmtree(ui_harness.output_dir / "20261026_110000")
    page.evaluate("() => { location.hash = '#/portal'; }")
    page.wait_for_timeout(50)
    page.evaluate("() => { location.hash = '#/monitor?scan=20261026_110000'; }")
    page.get_by_text("指定 scan は見つかりません", exact=False).wait_for()
    page.goto(f"{ui_harness.server_url}/app#/monitor?scan=missing-id", wait_until="domcontentloaded")
    page.get_by_text("指定 scan は見つかりません", exact=False).wait_for()
    page.goto(f"{ui_harness.server_url}/app#/monitor?scan=%2Fbad", wait_until="domcontentloaded")
    page.get_by_text("route または scan identifier が不正", exact=False).wait_for()
    page.goto(f"{ui_harness.server_url}/app#/not-registered", wait_until="domcontentloaded")
    page.get_by_text("route または scan identifier が不正", exact=False).wait_for()
    ui_harness.assert_no_errors(page)


def test_monitor_unmount_cancels_scoped_scan_list_read(ui_harness: UIHarness):
    page = ui_harness.new_page()
    page.add_init_script("""
      (() => {
        const nativeFetch = window.fetch.bind(window);
        window.fetch = (input, options = {}) => {
          const path = typeof input === 'string' ? input : input.url;
          if (window === window.top && path.includes('/api/v1/scans')) {
            window.__scanListStarted = true;
            return new Promise((resolve, reject) => {
              options.signal?.addEventListener('abort', () => {
                window.__scanListAborted = true;
                reject(new DOMException('Aborted', 'AbortError'));
              }, { once: true });
            });
          }
          return nativeFetch(input, options);
        };
      })();
    """)
    page.goto(f"{ui_harness.server_url}/app")
    page.evaluate("() => { location.hash = '#/monitor?scan=20261026_100000'; }")
    page.wait_for_function("window.__scanListStarted === true")
    page.evaluate("() => { location.hash = '#/portal'; }")
    page.wait_for_function("window.__scanListAborted === true")
    assert page.locator("#portalFrame").is_visible()
    assert page.locator("#message").is_hidden()
    ui_harness.assert_no_errors(page)


def test_monitor_reentry_ignores_stale_scan_list_response(ui_harness: UIHarness):
    page = ui_harness.new_page()
    page.add_init_script("""
      (() => {
        const nativeFetch = window.fetch.bind(window);
        let scanListReads = 0;
        window.fetch = (input, options = {}) => {
          const path = typeof input === 'string' ? input : input.url;
          if (window === window.top && path.includes('/api/v1/scans') && ++scanListReads === 1) {
            window.__oldScanListStarted = true;
            return new Promise((resolve) => {
              window.__resolveOldScanList = () => resolve(new Response(
                JSON.stringify({ scans: [] }),
                { status: 200, headers: { 'Content-Type': 'application/json' } }
              ));
            });
          }
          return nativeFetch(input, options);
        };
      })();
    """)
    page.goto(f"{ui_harness.server_url}/app#/monitor?scan=20261026_110000")
    page.wait_for_function("window.__oldScanListStarted === true")
    page.evaluate("() => { location.hash = '#/portal'; }")
    page.wait_for_function("() => document.querySelector('#portalFrame').contentDocument?.title.includes('Server Portal')")
    page.evaluate("() => { location.hash = '#/monitor?scan=20261026_100000'; }")
    page.get_by_text("snapshot と一致しません", exact=False).wait_for()

    page.evaluate("() => window.__resolveOldScanList()")
    page.wait_for_timeout(100)
    assert page.get_by_text("snapshot と一致しません", exact=False).is_visible()
    assert page.get_by_text("指定 scan は見つかりません", exact=False).count() == 0
    ui_harness.assert_no_errors(page)


def test_selected_scan_is_invalidated_when_live_wire_starts_another_scan(ui_harness: UIHarness):
    page = ui_harness.new_page()
    page.goto(f"{ui_harness.server_url}/app#/monitor?scan=20261026_100000", wait_until="domcontentloaded")
    page.get_by_text("snapshot と一致しません", exact=False).wait_for()
    monitor = page.frame_locator("#monitorFrame")
    page.wait_for_function("""() => {
      const frame = document.querySelector('#monitorFrame')?.contentWindow;
      return frame?.VulixAppBridge && frame?._eventStream?.connected &&
        frame.eval("typeof state.serverInstanceId === 'string' && state.serverInstanceId.length > 0");
    }""")

    def deliver_scan_started(run_id, scan_id):
        event = (
            "const ev={type:'scan_started',server_id:state.serverInstanceId,"
            f"run_id:'{run_id}',scan_id:'{scan_id}',sequence:1,"
            "backend_version:_eventStream.backendVersion(),"
            "data:{url:'https://safe.example.test',checks:['xss']}};"
            "state.ws.onmessage({data:JSON.stringify(ev)})"
        )
        page.evaluate(f"() => document.querySelector('#monitorFrame').contentWindow.eval({event!r})")

    deliver_scan_started("run-a", "20261026_100000")
    page.wait_for_function("() => !document.querySelector('#monitorFrame').hidden && document.querySelector('#scanContext').textContent.includes('20261026_100000')")
    deliver_scan_started("run-b", "20261026_110000")
    page.wait_for_function("() => document.querySelector('#monitorFrame').hidden && document.querySelector('#message').textContent.includes('server snapshot と一致しません')")
    assert page.url.endswith("#/monitor?scan=20261026_100000")
    assert page.get_by_text("指定された scan", exact=False).is_visible()

    page.evaluate("() => { location.hash = '#/monitor?scan=20261026_110000'; }")
    page.wait_for_function("() => !document.querySelector('#monitorFrame').hidden && document.querySelector('#scanContext').textContent.includes('20261026_110000') && document.querySelector('#message').hidden")
    assert page.url.endswith("#/monitor?scan=20261026_110000")
    ui_harness.assert_no_errors(page)


def test_selected_scan_pins_complete_live_identity_until_intentional_remount(ui_harness: UIHarness):
    page = ui_harness.new_page()
    selected = "20261026_100000"
    page.goto(f"{ui_harness.server_url}/app#/monitor?scan={selected}", wait_until="domcontentloaded")
    page.get_by_text("snapshot と一致しません", exact=False).wait_for()
    page.wait_for_function("() => document.querySelector('#monitorFrame').contentWindow?._eventStream?.connected")

    def deliver_scan_started(run_id: str, scan_id: str):
        event = (
            "const ev={type:'scan_started',server_id:state.serverInstanceId,"
            f"run_id:'{run_id}',scan_id:'{scan_id}',sequence:1,"
            "backend_version:_eventStream.backendVersion(),"
            "data:{url:'https://safe.example.test',checks:['xss']}};"
            "state.ws.onmessage({data:JSON.stringify(ev)})"
        )
        page.evaluate(f"() => document.querySelector('#monitorFrame').contentWindow.eval({event!r})")

    # An incomplete initial context must not pin the wrong scan; the matching
    # run arriving through the real versioned cursor path can establish identity.
    deliver_scan_started("run-unmatched", "20261026_110000")
    page.wait_for_function("() => document.querySelector('#monitorFrame').contentWindow?.VulixAppBridge?.getContext()?.run_id==='run-unmatched'")
    assert page.locator("#monitorFrame").is_hidden()
    assert page.get_by_text("指定された scan", exact=False).is_visible()

    deliver_scan_started("run-selected-a", selected)
    page.wait_for_function("() => { const f=document.querySelector('#monitorFrame'); const c=f.contentWindow?.VulixAppBridge?.getContext(); return c?.run_id==='run-selected-a' && c?.scan_id==='20261026_100000' && !f.hidden; }")
    deliver_scan_started("run-selected-b", selected)
    page.wait_for_function("() => { const f=document.querySelector('#monitorFrame'); return f.hidden && document.querySelector('#message').textContent.includes('snapshot と一致しません'); }")
    assert page.url.endswith(f"#/monitor?scan={selected}")

    # Explicit navigation remounts against the current validated tuple.
    page.evaluate("() => { location.hash='#/portal'; }")
    page.locator("#portalFrame").wait_for(state="visible")
    page.evaluate(f"() => {{ location.hash='#/monitor?scan={selected}'; }}")
    page.wait_for_function("() => { const f=document.querySelector('#monitorFrame'); const c=f.contentWindow?.VulixAppBridge?.getContext(); return c?.run_id==='run-selected-b' && !f.hidden && document.querySelector('#message').hidden; }")
    before_server_change = page.evaluate("() => document.querySelector('#monitorFrame').contentWindow.VulixAppBridge.getContext()")

    snapshot = (
        "const ev={type:'scan_snapshot',server_id:'server-replacement',"
        f"run_id:'run-selected-b',scan_id:'{selected}',sequence:0,"
        "backend_version:_eventStream.backendVersion(),"
        "data:{status:'scanning',findings:[],findings_count:0,confirmed_findings_count:0,hypothesis_count:0}};"
        "state.ws.onmessage({data:JSON.stringify(ev)})"
    )
    page.evaluate(f"() => document.querySelector('#monitorFrame').contentWindow.eval({snapshot!r})")
    page.wait_for_function("() => { const f=document.querySelector('#monitorFrame'); const c=f.contentWindow?.VulixAppBridge?.getContext(); return c?.server_id==='server-replacement' && f.hidden && document.querySelector('#message').textContent.includes('snapshot と一致しません'); }")
    assert before_server_change["server_id"] != "server-replacement"
    assert page.url.endswith(f"#/monitor?scan={selected}")

    # A deliberate route remount accepts the newly current validated tuple.
    page.evaluate("() => { location.hash='#/portal'; }")
    page.locator("#portalFrame").wait_for(state="visible")
    page.evaluate(f"() => {{ location.hash='#/monitor?scan={selected}'; }}")
    page.wait_for_function("() => { const f=document.querySelector('#monitorFrame'); const c=f.contentWindow?.VulixAppBridge?.getContext(); return c?.server_id==='server-replacement' && !f.hidden && document.querySelector('#message').hidden; }")
    ui_harness.assert_no_errors(page)


def test_stale_monitor_load_after_navigation_does_not_unhide(ui_harness: UIHarness):
    # Finding 1 回帰: monitor iframe の load が、別 route へ遷移した後に発火しても
    # 旧マウントの onReady が surface を開いたり iframe を un-hide してはならない。
    # /monitor の読み込みを保留して load タイミングを制御し、遷移後に解放する。
    page = ui_harness.new_page()
    held: list = []
    page.route("**/monitor", lambda route: held.append(route))
    page.goto(f"{ui_harness.server_url}/app", wait_until="domcontentloaded")
    page.wait_for_function("() => document.querySelector('#portalFrame')?.contentDocument?.title.includes('Server Portal')")

    # setup へ遷移 → monitor iframe が /monitor を要求するが、load は保留される。
    page.evaluate("() => { location.hash = '#/setup'; }")
    for _ in range(200):
        if held:
            break
        page.wait_for_timeout(20)
    assert held, "setup mount did not trigger the held /monitor load"

    # load 発火前に portal へ離脱 → unmount が保留 load を解除し iframe を隠す。
    page.evaluate("() => { location.hash = '#/portal'; }")
    page.wait_for_function(
        "() => document.querySelector('#portalFrame')?.contentDocument?.title.includes('Server Portal')"
        " && document.querySelector('#monitorFrame').hidden"
    )

    # 保留していた /monitor を解放 → stale な load が発火するが、ガードにより無視される。
    held[0].continue_()
    page.wait_for_function("() => document.querySelector('#monitorFrame').contentWindow?.VulixAppBridge")
    page.wait_for_timeout(150)

    assert page.locator("#monitorFrame").is_hidden(), "stale monitor load un-hid the iframe under /portal"
    assert page.locator("#portalFrame").is_visible()
    assert page.locator('[data-route="portal"]').get_attribute("aria-current") == "page"
    overlay_active = page.frame_locator("#monitorFrame").locator("#scanConfigOverlay").evaluate(
        "el => el.classList.contains('active')"
    )
    assert overlay_active is False, "stale load applied the setup surface after navigating away"
    ui_harness.assert_no_errors(page)


def test_existing_root_and_monitor_routes_remain_compatible(ui_harness: UIHarness):
    page = ui_harness.new_page()
    page.goto(f"{ui_harness.server_url}/")
    assert page.title() == "Vulix — Server Portal"
    assert page.locator("#scanRows").count() == 1
    page.goto(f"{ui_harness.server_url}/monitor")
    assert page.locator("#scanConfigOverlay").count() == 1
    assert page.locator("#navLiveMonitor").get_attribute("aria-current") == "page"
    ui_harness.assert_no_errors(page)


def test_missing_legacy_bridge_renders_safe_error(ui_harness: UIHarness):
    page = ui_harness.new_page()
    page.route("**/monitor", lambda route: route.fulfill(status=200, body="<!doctype html><title>legacy surface</title>"))
    page.goto(f"{ui_harness.server_url}/app")
    page.locator('[data-route="setup"]').click()
    page.get_by_text("Monitor bridge を初期化できません", exact=False).wait_for()
    assert page.locator("#message").is_visible()
    ui_harness.assert_no_errors(page)


def test_app_auth_required_message_is_explicit(ui_harness: UIHarness):
    page = ui_harness.new_page()
    page.goto(f"{ui_harness.server_url}/app#/monitor")
    page.locator('[data-route="monitor"]').wait_for()
    page.wait_for_function("document.querySelector('#monitorFrame').contentWindow?.VulixAppBridge")
    page.frame_locator("#monitorFrame").locator("body").evaluate(
        "() => window.parent.postMessage({type:'vulix:auth-required'}, window.location.origin)"
    )
    page.get_by_text("認証セッションの再確認が必要です", exact=False).wait_for()
    assert page.locator("#message a[href='/login']").count() == 1


def test_hidden_monitor_4401_keeps_app_route_and_shows_auth_required(ui_harness: UIHarness):
    page = ui_harness.new_page()
    sockets = []
    post_requests = []
    page.on("websocket", lambda socket: sockets.append(socket.url))
    page.on("request", lambda request: post_requests.append(request.url) if request.method == "POST" else None)
    page.goto(f"{ui_harness.server_url}/app#/monitor")
    page.wait_for_function("() => document.querySelector('#monitorFrame').contentWindow?._eventStream?.connected")
    page.evaluate("() => { location.hash = '#/portal'; }")
    page.wait_for_function("() => document.querySelector('#portalFrame').contentDocument?.title.includes('Server Portal')")

    monitor = page.frame_locator("#monitorFrame")
    monitor.locator("body").evaluate("() => state.ws.close(4401, 'unauthorized')")
    page.get_by_text("認証セッションの再確認が必要です", exact=False).wait_for()
    assert page.url.endswith("#/portal")
    assert page.locator("#message a[href='/login']").count() == 1
    page.wait_for_function("() => document.querySelector('#monitorFrame').contentWindow._eventStream._stopped")
    page.wait_for_timeout(3200)
    assert len(sockets) == 1
    assert post_requests == []
    assert page.locator("#scanContext").inner_text() == ""
    ui_harness.assert_no_errors(page)
