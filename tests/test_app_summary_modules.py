import json
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parents[1]


def test_app_summary_modules_contracts():
    node = shutil.which("node")
    if not node:
        return
    script = r"""
    const fs = require('fs'), vm = require('vm');
    class Element {
      constructor(tag) { this.tagName = tag; this.children = []; this.events = {}; this.hidden = false; this.value = ''; }
      append(...items) { this.children.push(...items); }
      prepend(item) { this.children.unshift(item); }
      appendChild(item) { this.append(item); return item; }
      replaceChildren(...items) { this.children = items; }
      addEventListener(name, fn) { this.events[name] = fn; }
      set textContent(value) { this._text = String(value); this.children = []; }
      get textContent() { return this._text || this.children.map(x => x.textContent).join(''); }
      set className(value) { this._className = value; }
    }
    global.document = { createElement: tag => new Element(tag) };
    globalThis.confirm = () => true;
    const dashboard = fs.readFileSync('templates/dashboard.html', 'utf8');
    const legacyIpGuard = dashboard.match(/function validateAndSanitizeClientIp\(ipStr\) \{[\s\S]*?\n\}/)[0];
    const legacyIpContext = {};
    vm.runInNewContext(dashboard.match(/const STRICT_IPV4_RE = .*?;\nconst STRICT_IPV6_RE = .*?;/)[0].replace(/const /g, 'var '), legacyIpContext);
    vm.runInNewContext(legacyIpGuard, legacyIpContext);
    legacyIpContext.validateAndSanitizeClientIp = legacyIpContext.validateAndSanitizeClientIp.bind(legacyIpContext);
    vm.runInThisContext(fs.readFileSync('templates/ui/summary-reader.js', 'utf8'));
    vm.runInThisContext(fs.readFileSync('templates/ui/summary-modules.js', 'utf8'));
    const reader = VulixSummaryReader.createSummaryReader({ get: async () => ({ ok: true, data: { scans: [{ findings_count: null }, { findings_count: 0 }], storage: {} } }) });
    const calls = [];
    const api = {
      get: async path => {
        calls.push(['GET', path]);
        if (path === '/api/v1/scans') return { ok: true, data: { scans: [
          { id: 'safe', target: 'https://user:pass@example.test/?return=%3Ftoken%3Dsecret', findings_count: null, report_available: true },
          { id: 'zero', target: 'example.test/a?key=secret', findings_count: 0, report_available: false },
          { id: 'live', target: 'example.test/live', findings_count: 3, partial: true, status: 'scanning', report_available: false }
        ], storage: { total_bytes: 0, retention_days: 3 } } };
        if (path === '/api/v1/audit') return { ok: true, data: { audit: [{ ts: '2026-11-03T00:00:00Z', action: '<img src=x onerror=alert(1)>', ip: '<svg onload=alert(1)>', detail: '<script>alert(1)</script>' }] } };
        if (path === '/api/v1/scan/status') return { ok: true, data: { status: 'idle' } };
        if (path === '/api/v1/schedules') return { ok: true, data: { schedules: [{ id: 'sched1', url: 'example.test', interval_hours: 24, enabled: true }] } };
        if (path.endsWith('/diff')) return { ok: true, data: { new: ['<img src=x>'], fixed: [], persistent: [] } };
        throw Error(path);
      },
      post: async (path, body) => { calls.push(['POST', path, body]); return { ok: true, data: {} }; },
      delete: async path => { calls.push(['DELETE', path]); return { ok: true, data: {} }; },
    };
    const surface = new Element('div'), title = new Element('h1'), context = new Element('span');
    const modules = VulixSummaryModules.createSummaryModules({ api, surfaceEl: surface, titleEl: title, contextEl: context, clearMessage() {}, hideOthers() {} });
    (async () => {
      const counts = await reader.scans(); await modules[0].mount();
      const report = []; const walk = node => { if (node.tagName === 'a') report.push(node.href); for (const child of node.children) walk(child); }; walk(surface);
      const rendered = surface.textContent; const routes = modules.map(m => [m.id, m.route]);
      const ipCases = ['192.168.1.1', '256.1.1.1', '2001:db8::1', '1:2:3:4:5:6:7:8:9', '<svg onload=alert(1)>'];
      const ipParity = ipCases.map(ip => [VulixSummaryModules.validIp(ip), legacyIpContext.validateAndSanitizeClientIp(ip), (ip.match(/:/g) || []).length]);
      const all = []; const collect = node => { all.push(node); for (const child of node.children) collect(child); }; collect(surface);
      const click = async label => { const item = all.find(n => n.tagName === 'button' && n.textContent === label); if (item && item.events.click) await item.events.click(); };
      const scheduleUrl = all.find(n => n.tagName === 'input' && n.placeholder === 'https://example.com'); scheduleUrl.value = 'https://scheduled.example';
      await click('追加'); await click('差分'); await click('停止'); await click('削除'); await click('整理');
      await modules[2].mount(); const auditText = surface.textContent;
      console.log(JSON.stringify({ counts: counts.scans.map(s => s.findings_count), routes,
        urls: [
          VulixSummaryReader.redactDisplayUrl('https://user:pass@example.test/p?token=secret#auth=secret'),
          VulixSummaryReader.redactDisplayUrl('example.test/p?password=secret'),
          VulixSummaryReader.redactDisplayUrl('https://example.test/?next=%3Ftoken%3Dsecret'),
          VulixSummaryReader.redactDisplayUrl('https://example.test/#next=%3Fkey%3Dsecret')
        ], report, rendered, auditText, inert: surface.innerHTML === undefined,
        ipParity, apiReads: calls.map(c => c.slice(0, 2)) }));
    })().catch(e => { console.error(e); process.exitCode = 1; });
    """
    result = subprocess.run([node, "-"], input=script, text=True, capture_output=True, cwd=ROOT, timeout=20)
    assert result.returncode == 0, result.stderr
    data = json.loads(result.stdout)
    assert data["counts"] == [None, 0]
    assert data["routes"] == [["portal", "#/portal"], ["history", "#/history"], ["audit", "#/audit"]]
    assert data["ipParity"] == [["192.168.1.1", "192.168.1.1", 0], ["—", "—", 0], ["2001:db8::1", "2001:db8::1", 3], ["—", "—", 8], ["—", "—", 0]]
    assert "<redacted>@example.test" in data["urls"][0] and "token=<redacted>" in data["urls"][0]
    assert data["urls"][1] == "http://example.test/p?password=<redacted>"
    assert "secret" not in data["urls"][2] and "secret" not in data["urls"][3]
    assert "/reports/safe/report.html" in data["report"]
    assert "未取得" in data["rendered"] and "0" in data["rendered"]
    # /app 履歴も生 status（scanning）ではなく日本語ラベルと途中件数を示す。
    assert "実行中" in data["rendered"] and "件（実行中・途中）" in data["rendered"]
    assert "scanning" not in data["rendered"]
    assert "<img src=x onerror=alert(1)>" not in data["auditText"]
    assert "（詳細非表示）" in data["auditText"] and "—" in data["auditText"]
    assert data["inert"] is True
    requested = {(call[0], call[1]) for call in data["apiReads"]}
    assert ("GET", "/api/v1/scans/safe/diff") in requested
    assert ("POST", "/api/v1/schedules") in requested
    assert ("POST", "/api/v1/schedules/sched1/toggle") in requested
    assert ("DELETE", "/api/v1/schedules/sched1") in requested
    assert ("POST", "/api/v1/scans/prune") in requested


def test_app_routes_keep_legacy_handlers_and_register_summary_routes():
    entry = (ROOT / "templates/ui/app-entry.js").read_text()
    monitor = (ROOT / "wscan/monitor.py").read_text()
    app_html = (ROOT / "templates/app.html").read_text()
    assert "'/history', '/audit'" in entry
    assert "summaryModules.forEach((module) => registry.register(module))" in entry
    assert 'data-route="history"' in app_html and 'data-route="audit"' in app_html
    assert '@app.get("/", response_class=HTMLResponse)' in monitor
    assert '@app.get("/monitor", response_class=HTMLResponse)' in monitor
    assert '@app.get("/api/v1/scans")' in monitor and '@app.get("/api/v1/audit")' in monitor
