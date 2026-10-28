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
