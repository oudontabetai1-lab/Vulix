"""Tests for App Shell navigation registry, dispatcher, and legacy adapter."""
import json
from pathlib import Path
import subprocess

from fastapi.testclient import TestClient

from wscan.monitor import MonitorServer, SESSION_COOKIE, _session_value


ROOT = Path(__file__).resolve().parents[1]
APP_SHELL_JS = ROOT / "templates" / "ui" / "app-shell.js"
DASHBOARD_HTML = ROOT / "templates" / "dashboard.html"


def _run_node_script(script: str) -> dict:
    """Run a small JavaScript snippet via Node.js and return parsed JSON."""
    full_script = f"""
    const {{ ModuleRegistry, NavigationDispatcher, createLegacyViewAdapter, setupAppShell }} = require('{APP_SHELL_JS}');
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


def test_app_shell_js_exists_and_exports_expected_symbols():
    """Verify that templates/ui/app-shell.js exists and exports expected interfaces."""
    assert APP_SHELL_JS.is_file()
    result = _run_node_script("console.log(JSON.stringify(Object.keys(require('./templates/ui/app-shell.js'))));")
    expected = ["ModuleRegistry", "NavigationDispatcher", "createLegacyViewAdapter", "setupAppShell"]
    assert all(sym in result for sym in expected)


def test_module_registry_registration_and_duplicate_rejection():
    """Verify valid registration, retrieval, and duplicate/invalid ID rejection."""
    script = """
    const reg = new ModuleRegistry();
    reg.register({ id: 'live', title: 'Live' });
    reg.register({ id: 'history', title: 'History' });
    reg.register({ id: 'audit', title: 'Audit' });

    let duplicateRejected = false;
    try {
        reg.register({ id: 'live', title: 'Duplicate Live' });
    } catch (e) {
        duplicateRejected = true;
    }

    let emptyIdRejected = false;
    try {
        reg.register({ id: '   ' });
    } catch (e) {
        emptyIdRejected = true;
    }

    console.log(JSON.stringify({
        list: reg.list(),
        hasLive: reg.has('live'),
        hasUnknown: reg.has('unknown'),
        duplicateRejected: duplicateRejected,
        emptyIdRejected: emptyIdRejected,
    }));
    """
    data = _run_node_script(script)
    assert data["list"] == ["live", "history", "audit"]
    assert data["hasLive"] is True
    assert data["hasUnknown"] is False
    assert data["duplicateRejected"] is True
    assert data["emptyIdRejected"] is True


def test_module_registry_lifecycle_transition_and_destroy():
    """Verify lifecycle mount/unmount and destroy invocation order."""
    script = """
    const reg = new ModuleRegistry();
    const trace = [];

    reg.register({
        id: 'viewA',
        mount: () => trace.push('mount:A'),
        unmount: () => trace.push('unmount:A'),
    });
    reg.register({
        id: 'viewB',
        mount: () => trace.push('mount:B'),
        unmount: () => trace.push('unmount:B'),
    });

    reg.transition('viewA');
    reg.transition('viewB');
    reg.destroy();

    console.log(JSON.stringify({
        trace: trace,
        finalActive: reg.getActiveId(),
    }));
    """
    data = _run_node_script(script)
    assert data["trace"] == ["mount:A", "unmount:A", "mount:B", "unmount:B"]
    assert data["finalActive"] is None


def test_navigation_dispatcher_allowlist_and_fallback():
    """Verify resolution of allowlisted hashes (#live, #history, #audit) and safe fallback for unknown."""
    script = """
    const reg = new ModuleRegistry();
    reg.register({ id: 'live', title: 'Live' });
    reg.register({ id: 'history', title: 'History' });
    reg.register({ id: 'audit', title: 'Audit' });

    const disp = new NavigationDispatcher(reg);

    const rLive = disp.resolveRoute('#live');
    const rHist = disp.resolveRoute('#history');
    const rAudit = disp.resolveRoute('#audit');
    const rEmpty = disp.resolveRoute('');
    const rRoot = disp.resolveRoute('#/');
    const rUnknown1 = disp.resolveRoute('#unknown-screen');
    const rUnknown2 = disp.resolveRoute('#/admin/secret');
    const rMalformed = disp.resolveRoute('#../../etc/passwd');

    console.log(JSON.stringify({
        live: rLive,
        hist: rHist,
        audit: rAudit,
        empty: rEmpty,
        root: rRoot,
        unknown1: rUnknown1,
        unknown2: rUnknown2,
        malformed: rMalformed,
    }));
    """
    data = _run_node_script(script)
    assert data["live"] == {"viewId": "live", "isFallback": False, "matchedHash": "#live"}
    assert data["hist"] == {"viewId": "history", "isFallback": False, "matchedHash": "#history"}
    assert data["audit"] == {"viewId": "audit", "isFallback": False, "matchedHash": "#audit"}
    assert data["empty"] == {"viewId": "live", "isFallback": False, "matchedHash": "#live"}
    assert data["root"] == {"viewId": "live", "isFallback": False, "matchedHash": "#live"}
    assert data["unknown1"] == {"viewId": "live", "isFallback": True, "matchedHash": "#live"}
    assert data["unknown2"] == {"viewId": "live", "isFallback": True, "matchedHash": "#live"}
    assert data["malformed"] == {"viewId": "live", "isFallback": True, "matchedHash": "#live"}


def test_legacy_view_adapter_dom_contract():
    """Verify legacy adapter executes DOM state changes and triggers fetch methods without errors."""
    script = """
    // Minimal mock DOM environment
    const elements = {};
    function makeElement(id) {
        return {
            id: id,
            style: { display: '' },
            classList: {
                _classes: new Set(),
                add: function(c) { this._classes.add(c); },
                remove: function(c) { this._classes.delete(c); },
                contains: function(c) { return this._classes.has(c); },
            },
            _attrs: {},
            setAttribute: function(k, v) { this._attrs[k] = v; },
            removeAttribute: function(k) { delete this._attrs[k]; },
            getAttribute: function(k) { return this._attrs[k]; },
            textContent: '',
        };
    }

    [
        'viewLiveMonitor', 'viewScanHistory', 'viewAuditLog',
        'navLiveMonitor', 'navScanHistory', 'navAuditLog',
        'hdrBtnLive', 'hdrBtnHistory', 'hdrBtnAudit',
        'headerTitle'
    ].forEach(id => {
        elements[id] = makeElement(id);
    });

    const mockDoc = {
        getElementById: function(id) {
            return elements[id] || null;
        }
    };

    let historyFetched = false;
    let auditFetched = false;

    const mockGlobal = {
        document: mockDoc,
        loadScanHistory: () => { historyFetched = true; },
        loadAuditLog: () => { auditFetched = true; },
    };

    const adapter = createLegacyViewAdapter({ document: mockDoc });

    // 1. Render history
    adapter.render('history', mockGlobal);
    const histVisible = elements['viewScanHistory'].style.display;
    const liveHidden = elements['viewLiveMonitor'].style.display;
    const histAria = elements['navScanHistory'].getAttribute('aria-current');
    const titleHist = elements['headerTitle'].textContent;

    // 2. Render audit
    adapter.render('audit', mockGlobal);
    const auditVisible = elements['viewAuditLog'].style.display;
    const histNowHidden = elements['viewScanHistory'].style.display;
    const auditAria = elements['navAuditLog'].getAttribute('aria-current');
    const titleAudit = elements['headerTitle'].textContent;

    // 3. Render live
    adapter.render('live', mockGlobal);
    const liveVisible = elements['viewLiveMonitor'].style.display;
    const auditNowHidden = elements['viewAuditLog'].style.display;
    const liveAria = elements['navLiveMonitor'].getAttribute('aria-current');
    const titleLive = elements['headerTitle'].textContent;

    console.log(JSON.stringify({
        histVisible: histVisible,
        liveHidden: liveHidden,
        histAria: histAria,
        titleHist: titleHist,
        historyFetched: historyFetched,
        auditVisible: auditVisible,
        histNowHidden: histNowHidden,
        auditAria: auditAria,
        titleAudit: titleAudit,
        auditFetched: auditFetched,
        liveVisible: liveVisible,
        auditNowHidden: auditNowHidden,
        liveAria: liveAria,
        titleLive: titleLive,
    }));
    """
    data = _run_node_script(script)
    assert data["histVisible"] == "flex"
    assert data["liveHidden"] == "none"
    assert data["histAria"] == "page"
    assert data["titleHist"] == "スキャン履歴"
    assert data["historyFetched"] is True

    assert data["auditVisible"] == "flex"
    assert data["histNowHidden"] == "none"
    assert data["auditAria"] == "page"
    assert data["titleAudit"] == "監査ログ"
    assert data["auditFetched"] is True

    assert data["liveVisible"] == "flex"
    assert data["auditNowHidden"] == "none"
    assert data["liveAria"] == "page"
    assert data["titleLive"] == "ライブモニター"


def test_dashboard_html_includes_app_shell_and_switch_main_view_integration():
    """Verify that templates/dashboard.html loads app-shell.js and wires switchMainView."""
    html = DASHBOARD_HTML.read_text(encoding="utf-8")
    assert '<script src="/ui/app-shell.js"></script>' in html
    assert "VulixAppShell.setupAppShell" in html
    assert "function switchMainView(viewName)" in html

    # Preserve all existing DOM IDs and inline handlers
    assert 'id="navLiveMonitor"' in html
    assert 'id="navScanHistory"' in html
    assert 'id="navAuditLog"' in html
    assert 'onclick="switchMainView(\'live\')"' in html
    assert 'onclick="switchMainView(\'history\')"' in html
    assert 'onclick="switchMainView(\'audit\')"' in html
    assert 'id="viewLiveMonitor"' in html
    assert 'id="viewScanHistory"' in html
    assert 'id="viewAuditLog"' in html


def test_server_returns_app_shell_asset_with_javascript_mime():
    """Verify that MonitorServer serves /ui/app-shell.js with 200 OK and javascript MIME type."""
    srv = MonitorServer(port=9996, auth_token="")
    client = TestClient(srv.app)
    res = client.get("/ui/app-shell.js")
    assert res.status_code == 200
    assert "javascript" in res.headers.get("content-type", "")
    assert "ModuleRegistry" in res.text
    assert "NavigationDispatcher" in res.text


def test_server_auth_protects_app_shell_js():
    """Verify that under enabled auth, unauthenticated requests to /ui/app-shell.js are rejected with 401."""
    srv = MonitorServer(port=9995, auth_token="test-secret-token")
    client = TestClient(srv.app)

    # Without auth: 401
    unauth = client.get("/ui/app-shell.js")
    assert unauth.status_code == 401

    # With session cookie: 200
    client.post("/login", data={"token": "test-secret-token"})
    auth_res = client.get("/ui/app-shell.js")
    assert auth_res.status_code == 200
    assert "ModuleRegistry" in auth_res.text


def test_app_shell_direct_link_initialization():
    """Verify direct-link behavior: initial location.hash selects corresponding view (#history, #audit)."""
    script = """
    function runDirectLinkTest(initialHash) {
        const events = [];
        const listeners = {};
        const elements = {};

        function makeElement(id) {
            return {
                id: id,
                style: { display: '' },
                classList: {
                    _classes: new Set(),
                    add: function(c) { this._classes.add(c); },
                    remove: function(c) { this._classes.delete(c); },
                    contains: function(c) { return this._classes.has(c); },
                },
                _attrs: {},
                setAttribute: function(k, v) { this._attrs[k] = v; },
                removeAttribute: function(k) { delete this._attrs[k]; },
                getAttribute: function(k) { return this._attrs[k]; },
                textContent: '',
            };
        }

        [
            'viewLiveMonitor', 'viewScanHistory', 'viewAuditLog',
            'navLiveMonitor', 'navScanHistory', 'navAuditLog',
            'hdrBtnLive', 'hdrBtnHistory', 'hdrBtnAudit',
            'headerTitle'
        ].forEach(id => {
            elements[id] = makeElement(id);
        });

        const mockDoc = {
            getElementById: function(id) {
                return elements[id] || null;
            }
        };

        const mockWindow = {
            document: mockDoc,
            location: { hash: initialHash },
            addEventListener: function(event, handler) {
                listeners[event] = listeners[event] || [];
                listeners[event].push(handler);
            },
            removeEventListener: function(event, handler) {
                if (listeners[event]) {
                    listeners[event] = listeners[event].filter(h => h !== handler);
                }
            },
            loadScanHistory: () => { events.push('fetch:history'); },
            loadAuditLog: () => { events.push('fetch:audit'); },
        };

        const shell = setupAppShell({ global: mockWindow });

        return {
            activeId: shell.registry.getActiveId(),
            historyDisplay: elements['viewScanHistory'].style.display,
            auditDisplay: elements['viewAuditLog'].style.display,
            liveDisplay: elements['viewLiveMonitor'].style.display,
            historyAria: elements['navScanHistory'].getAttribute('aria-current'),
            auditAria: elements['navAuditLog'].getAttribute('aria-current'),
            liveAria: elements['navLiveMonitor'].getAttribute('aria-current'),
            headerTitle: elements['headerTitle'].textContent,
            events: events,
        };
    }

    console.log(JSON.stringify({
        historyCase: runDirectLinkTest('#history'),
        auditCase: runDirectLinkTest('#audit'),
        defaultCase: runDirectLinkTest(''),
    }));
    """
    data = _run_node_script(script)

    # #history direct link
    hist = data["historyCase"]
    assert hist["activeId"] == "history"
    assert hist["historyDisplay"] == "flex"
    assert hist["liveDisplay"] == "none"
    assert hist["historyAria"] == "page"
    assert hist["headerTitle"] == "スキャン履歴"
    assert hist["events"] == ["fetch:history"]

    # #audit direct link
    audit = data["auditCase"]
    assert audit["activeId"] == "audit"
    assert audit["auditDisplay"] == "flex"
    assert audit["liveDisplay"] == "none"
    assert audit["auditAria"] == "page"
    assert audit["headerTitle"] == "監査ログ"
    assert audit["events"] == ["fetch:audit"]

    # default (empty / #live) direct link
    default = data["defaultCase"]
    assert default["activeId"] is None  # default remains live in DOM if not transitioned or transitions upon user action
    assert default["liveDisplay"] == ""


def test_app_shell_browser_history_back_forward_navigation():
    """Verify back/forward navigation: sequential hashchange events transition views and aria-current correctly.

    Note: Real browser popstate / History API stack traversal is validated in E2E slices (U04/U28).
    This unit test explicitly simulates browser back/forward history transitions via sequence of hashchange
    events (#live -> #history -> #audit -> back to #history -> back to #live) and asserts that view visibility,
    active module state, and navigation element aria-current attributes update accurately at each step.
    """
    script = """
    const listeners = {};
    const elements = {};

    function makeElement(id) {
        return {
            id: id,
            style: { display: '' },
            classList: {
                _classes: new Set(),
                add: function(c) { this._classes.add(c); },
                remove: function(c) { this._classes.delete(c); },
                contains: function(c) { return this._classes.has(c); },
            },
            _attrs: {},
            setAttribute: function(k, v) { this._attrs[k] = v; },
            removeAttribute: function(k) { delete this._attrs[k]; },
            getAttribute: function(k) { return this._attrs[k]; },
            textContent: '',
        };
    }

    [
        'viewLiveMonitor', 'viewScanHistory', 'viewAuditLog',
        'navLiveMonitor', 'navScanHistory', 'navAuditLog',
        'hdrBtnLive', 'hdrBtnHistory', 'hdrBtnAudit',
        'headerTitle'
    ].forEach(id => {
        elements[id] = makeElement(id);
    });

    const mockDoc = {
        getElementById: function(id) {
            return elements[id] || null;
        }
    };

    const mockWindow = {
        document: mockDoc,
        location: { hash: '#live' },
        addEventListener: function(event, handler) {
            listeners[event] = listeners[event] || [];
            listeners[event].push(handler);
        },
        removeEventListener: function(event, handler) {
            if (listeners[event]) {
                listeners[event] = listeners[event].filter(h => h !== handler);
            }
        },
        loadScanHistory: () => {},
        loadAuditLog: () => {},
    };

    const origWindow = global.window;
    global.window = mockWindow;

    const shell = setupAppShell({ global: mockWindow });

    function fireHashChange(newHash) {
        mockWindow.location.hash = newHash;
        if (listeners['hashchange']) {
            listeners['hashchange'].forEach(fn => fn());
        }
    }

    function captureState() {
        return {
            active: shell.registry.getActiveId(),
            title: elements['headerTitle'].textContent,
            liveDisplay: elements['viewLiveMonitor'].style.display,
            historyDisplay: elements['viewScanHistory'].style.display,
            auditDisplay: elements['viewAuditLog'].style.display,
            navLiveAria: elements['navLiveMonitor'].getAttribute('aria-current') || null,
            navHistoryAria: elements['navScanHistory'].getAttribute('aria-current') || null,
            navAuditAria: elements['navAuditLog'].getAttribute('aria-current') || null,
        };
    }

    // Step 0: Initial state before any hashchange navigation
    const step0 = captureState();

    // Step 1: Forward navigation to #history
    fireHashChange('#history');
    const step1 = captureState();

    // Step 2: Forward navigation to #audit
    fireHashChange('#audit');
    const step2 = captureState();

    // Step 3: Back navigation to #history
    fireHashChange('#history');
    const step3 = captureState();

    // Step 4: Back navigation to #live
    fireHashChange('#live');
    const step4 = captureState();

    global.window = origWindow;

    console.log(JSON.stringify({
        step0: step0,
        step1: step1,
        step2: step2,
        step3: step3,
        step4: step4,
    }));
    """
    data = _run_node_script(script)

    # Initial state: #live is not mounted yet by design (contract: initial live DOM left untouched)
    assert data["step0"]["active"] is None

    # Step 1: forward to #history
    assert data["step1"]["active"] == "history"
    assert data["step1"]["title"] == "スキャン履歴"
    assert data["step1"]["historyDisplay"] == "flex"
    assert data["step1"]["liveDisplay"] == "none"
    assert data["step1"]["auditDisplay"] == "none"
    assert data["step1"]["navHistoryAria"] == "page"
    assert data["step1"]["navLiveAria"] is None
    assert data["step1"]["navAuditAria"] is None

    # Step 2: forward to #audit
    assert data["step2"]["active"] == "audit"
    assert data["step2"]["title"] == "監査ログ"
    assert data["step2"]["auditDisplay"] == "flex"
    assert data["step2"]["historyDisplay"] == "none"
    assert data["step2"]["liveDisplay"] == "none"
    assert data["step2"]["navAuditAria"] == "page"
    assert data["step2"]["navHistoryAria"] is None
    assert data["step2"]["navLiveAria"] is None

    # Step 3: back to #history
    assert data["step3"]["active"] == "history"
    assert data["step3"]["title"] == "スキャン履歴"
    assert data["step3"]["historyDisplay"] == "flex"
    assert data["step3"]["auditDisplay"] == "none"
    assert data["step3"]["liveDisplay"] == "none"
    assert data["step3"]["navHistoryAria"] == "page"
    assert data["step3"]["navAuditAria"] is None
    assert data["step3"]["navLiveAria"] is None

    # Step 4: back to #live
    assert data["step4"]["active"] == "live"
    assert data["step4"]["title"] == "ライブモニター"
    assert data["step4"]["liveDisplay"] == "flex"
    assert data["step4"]["historyDisplay"] == "none"
    assert data["step4"]["auditDisplay"] == "none"
    assert data["step4"]["navLiveAria"] == "page"
    assert data["step4"]["navHistoryAria"] is None
    assert data["step4"]["navAuditAria"] is None


def test_app_shell_unknown_hash_fallback_to_live():
    """Verify that unknown or malformed hash fragments safely fall back to live view."""
    script = """
    const listeners = {};
    const elements = {};

    function makeElement(id) {
        return {
            id: id,
            style: { display: '' },
            classList: {
                _classes: new Set(),
                add: function(c) { this._classes.add(c); },
                remove: function(c) { this._classes.delete(c); },
                contains: function(c) { return this._classes.has(c); },
            },
            _attrs: {},
            setAttribute: function(k, v) { this._attrs[k] = v; },
            removeAttribute: function(k) { delete this._attrs[k]; },
            getAttribute: function(k) { return this._attrs[k]; },
            textContent: '',
        };
    }

    [
        'viewLiveMonitor', 'viewScanHistory', 'viewAuditLog',
        'navLiveMonitor', 'navScanHistory', 'navAuditLog',
        'hdrBtnLive', 'hdrBtnHistory', 'hdrBtnAudit',
        'headerTitle'
    ].forEach(id => {
        elements[id] = makeElement(id);
    });

    const mockDoc = {
        getElementById: function(id) {
            return elements[id] || null;
        }
    };

    const mockWindow = {
        document: mockDoc,
        location: { hash: '#audit' },
        addEventListener: function(event, handler) {
            listeners[event] = listeners[event] || [];
            listeners[event].push(handler);
        },
        removeEventListener: function(event, handler) {
            if (listeners[event]) {
                listeners[event] = listeners[event].filter(h => h !== handler);
            }
        },
        loadScanHistory: () => {},
        loadAuditLog: () => {},
    };

    const origWindow = global.window;
    global.window = mockWindow;

    const shell = setupAppShell({ global: mockWindow });
    // Starts at audit
    const initialActive = shell.registry.getActiveId();

    function fireHashChange(newHash) {
        mockWindow.location.hash = newHash;
        if (listeners['hashchange']) {
            listeners['hashchange'].forEach(fn => fn());
        }
    }

    // Transition with unknown hashes
    fireHashChange('#unknown-screen-xyz');
    const fallbackActive1 = shell.registry.getActiveId();
    const fallbackTitle1 = elements['headerTitle'].textContent;

    // Transition back to audit first
    fireHashChange('#audit');
    const backToAudit = shell.registry.getActiveId();

    // Transition with malformed hash
    fireHashChange('#/../../etc/shadow');
    const fallbackActive2 = shell.registry.getActiveId();
    const fallbackTitle2 = elements['headerTitle'].textContent;

    global.window = origWindow;

    console.log(JSON.stringify({
        initialActive: initialActive,
        fallback1: { active: fallbackActive1, title: fallbackTitle1 },
        backToAudit: backToAudit,
        fallback2: { active: fallbackActive2, title: fallbackTitle2 },
    }));
    """
    data = _run_node_script(script)
    assert data["initialActive"] == "audit"
    assert data["fallback1"] == {"active": "live", "title": "ライブモニター"}
    assert data["backToAudit"] == "audit"
    assert data["fallback2"] == {"active": "live", "title": "ライブモニター"}


def test_app_shell_dispatcher_stop_teardown_listener():
    """Verify dispatcher.stop directly removes the hashchange listener and prevents post-stop transitions.

    Note: app-shell.js does not use any timers or intervals (timer teardown is N/A).
    This test verifies that:
    1. dispatcher.start registers window.addEventListener('hashchange', _onHashChange).
    2. dispatcher.stop calls window.removeEventListener('hashchange', _onHashChange), reducing listener count to 0.
    3. Firing subsequent hashchange events after dispatcher.stop() does NOT trigger any view transition
       or callback (listener is reliably unhooked).
    4. registry.destroy() unmounts any currently active module and clears activeId to null.
    """
    script = """
    const listeners = {};
    const unmounted = [];
    const navigationEvents = [];

    const mockWindow = {
        addEventListener: function(event, handler) {
            listeners[event] = listeners[event] || [];
            listeners[event].push(handler);
        },
        removeEventListener: function(event, handler) {
            if (listeners[event]) {
                listeners[event] = listeners[event].filter(h => h !== handler);
            }
        },
        location: { hash: '#live' },
    };

    const reg = new ModuleRegistry();
    reg.register({
        id: 'viewA',
        mount: (ctx) => {},
        unmount: (ctx) => { unmounted.push('viewA'); },
    });
    reg.register({
        id: 'viewB',
        mount: (ctx) => {},
        unmount: (ctx) => { unmounted.push('viewB'); },
    });
    reg.register({
        id: 'history',
        mount: (ctx) => {},
        unmount: (ctx) => { unmounted.push('history'); },
    });

    // In a browser-like global environment:
    const origWindow = global.window;
    global.window = mockWindow;

    const disp = new NavigationDispatcher(reg, {
        onNavigate: (viewId) => { navigationEvents.push(viewId); }
    });
    disp.start();
    const listenerCountStarted = (listeners['hashchange'] || []).length;

    disp.navigateTo('viewA');
    disp.navigateTo('viewB');

    // Active is now viewB
    const activeBeforeStop = reg.getActiveId();

    // Teardown dispatcher (stops listener and removes from window)
    disp.stop();
    const listenerCountStopped = (listeners['hashchange'] || []).length;

    // Direct verification of teardown: firing hashchange event after stop() must NOT trigger navigation
    mockWindow.location.hash = '#history';
    if (listeners['hashchange']) {
        listeners['hashchange'].forEach(fn => fn());
    }
    const activeAfterPostStopHashChange = reg.getActiveId();

    // Teardown registry active module
    reg.destroy();
    const finalActive = reg.getActiveId();

    // Restore global
    global.window = origWindow;

    console.log(JSON.stringify({
        listenerCountStarted: listenerCountStarted,
        listenerCountStopped: listenerCountStopped,
        activeBeforeStop: activeBeforeStop,
        activeAfterPostStopHashChange: activeAfterPostStopHashChange,
        navigationEvents: navigationEvents,
        unmounted: unmounted,
        finalActive: finalActive,
    }));
    """
    data = _run_node_script(script)
    assert data["listenerCountStarted"] == 1
    assert data["listenerCountStopped"] == 0
    assert data["activeBeforeStop"] == "viewB"
    # Verification that post-stop hashchange did NOT transition active module (remains viewB, not changed to history)
    assert data["activeAfterPostStopHashChange"] == "viewB"
    assert data["navigationEvents"] == ["viewA", "viewB"]
    assert data["unmounted"] == ["viewA", "viewB"]
    assert data["finalActive"] is None

