/* Opt-in /app router. Existing Portal and Monitor documents remain the owners
   of their controls, polling, and the single live EventStream. */
(function (global) {
  'use strict';

  const { ModuleRegistry } = global.VulixAppShell;
  const { ApiClient } = global.VulixApiClient;
  const registry = new ModuleRegistry();
  const api = new ApiClient();
  const monitor = document.getElementById('monitorFrame');
  const monitorHost = document.getElementById('monitorModule');
  const summarySurface = document.getElementById('summarySurface');
  const findingsSurface = document.getElementById('findingsSurface');
  const settingsSurface = document.getElementById('settingsSurface');
  const crawlSurface = document.getElementById('crawlSurface');
  const trafficSurface = document.getElementById('trafficSurface');
  const message = document.getElementById('message');
  const agentSkillsSurface = document.getElementById('agentSkillsSurface');
  const setupSurface = document.getElementById('setupSurface');
  const title = document.getElementById('viewTitle');
  const context = document.getElementById('scanContext');
  let activeScope = null;
  let contextHandler = null;
  // マウント世代トークン: ナビゲーションごとに加算する。iframe の load 完了コールバックは
  // 自分の世代がまだアクティブかを照合し、別 route / 別 scan へ遷移後に発火した stale な
  // load で hidden/surface/context を書き換えてクロス識別を起こすのを防ぐ。
  let mountToken = 0;
  let pendingMonitorLoad = null; // 未発火の monitor load リスナ（unmount で解除する）

  function unavailable(text) {
    monitor.hidden = true;
    if (monitorHost) monitorHost.hidden = true;
    if (summarySurface) summarySurface.hidden = true;
    if (findingsSurface) findingsSurface.hidden = true;
    if (agentSkillsSurface) agentSkillsSurface.hidden = true;
    if (setupSurface) setupSurface.hidden = true;
    if (settingsSurface) settingsSurface.hidden = true;
    if (crawlSurface) crawlSurface.hidden = true;
    if (trafficSurface) trafficSurface.hidden = true;
    message.hidden = false;
    message.replaceChildren();
    const heading = document.createElement('h2');
    heading.textContent = '画面を表示できません';
    const detail = document.createElement('p');
    detail.textContent = text;
    const link = document.createElement('a');
    link.href = '#/portal';
    link.textContent = 'ポータルへ戻る';
    message.append(heading, detail, link);
  }

  function clearMessage() {
    message.hidden = true;
    message.replaceChildren();
  }

  function cancelPendingMonitorLoad() {
    if (pendingMonitorLoad) {
      monitor.removeEventListener('load', pendingMonitorLoad);
      pendingMonitorLoad = null;
    }
  }

  function ensureMonitor(onReady) {
    const token = mountToken; // このマウントの世代を固定し、発火時に stale 判定する
    if (monitor.dataset.ready === 'true' && monitor.contentWindow && monitor.contentWindow.VulixAppBridge) {
      if (token === mountToken) onReady(monitor.contentWindow.VulixAppBridge);
      return;
    }
    const loaded = () => {
      monitor.removeEventListener('load', loaded);
      if (pendingMonitorLoad === loaded) pendingMonitorLoad = null;
      // 既に別 route / 別 scan へ遷移済みなら stale。hidden/surface/context を一切触らない。
      if (token !== mountToken) return;
      try {
        const bridge = monitor.contentWindow && monitor.contentWindow.VulixAppBridge;
        if (!bridge || typeof bridge.setSurface !== 'function' || typeof bridge.getContext !== 'function') {
          unavailable('Monitor bridge を初期化できませんでした。');
          return;
        }
        monitor.dataset.ready = 'true';
        onReady(bridge);
      } catch (_) {
        unavailable('Monitor bridge を安全に利用できませんでした。');
      }
    };
    pendingMonitorLoad = loaded;
    monitor.addEventListener('load', loaded, { once: true });
    if (!monitor.src || monitor.src === 'about:blank') monitor.src = '/monitor';
  }

  function stopContextSubscription() {
    if (contextHandler) global.removeEventListener('message', contextHandler);
    contextHandler = null;
  }

  function showMonitorSurface(surface, onReady) {
    clearMessage();
    if (findingsSurface) findingsSurface.hidden = true;
    if (agentSkillsSurface) agentSkillsSurface.hidden = true;
    if (setupSurface) setupSurface.hidden = true;
    if (settingsSurface) settingsSurface.hidden = true;
    if (crawlSurface) crawlSurface.hidden = true;
    if (trafficSurface) trafficSurface.hidden = true;
    monitor.hidden = Boolean(onReady);
    ensureMonitor((bridge) => {
      bridge.setSurface(surface);
      monitor.classList.toggle('transport-owner', surface === 'monitor');
      monitor.setAttribute('aria-hidden', String(surface === 'monitor'));
      const current = bridge.getContext();
      context.textContent = `Scan ${current.scan_id || '—'} · ${current.status || 'status unavailable'}`;
      if (onReady) onReady(bridge, current);
      else {
        monitor.hidden = false;
        if (surface === 'monitor') bridge.mountMonitor(monitorHost);
      }
    });
  }

  const summaryModules = global.VulixSummaryModules.createSummaryModules({
    api,
    surfaceEl: summarySurface,
    titleEl: title,
    contextEl: context,
    clearMessage,
    hideOthers() {
      monitor.hidden = true;
      if (monitorHost) monitorHost.hidden = true;
      if (findingsSurface) findingsSurface.hidden = true;
      if (agentSkillsSurface) agentSkillsSurface.hidden = true;
      if (setupSurface) setupSurface.hidden = true;
      if (settingsSurface) settingsSurface.hidden = true;
      if (crawlSurface) crawlSurface.hidden = true;
      if (trafficSurface) trafficSurface.hidden = true;
    },
  });
  summaryModules.forEach((module) => registry.register(module));

  registry.register({ id: 'setup', title: 'Scan Setup', route: '#/setup', mount() {
    title.textContent = 'Scan Setup';
    context.textContent = '';
    clearMessage();
    cancelPendingMonitorLoad();
    stopContextSubscription();
    monitor.hidden = true;
    if (monitorHost) monitorHost.hidden = true;
    if (findingsSurface) findingsSurface.hidden = true;
    if (agentSkillsSurface) agentSkillsSurface.hidden = true;
    if (settingsSurface) settingsSurface.hidden = true;
    if (crawlSurface) crawlSurface.hidden = true;
    if (trafficSurface) trafficSurface.hidden = true;

    if (global.VulixSetupModule && setupSurface) {
      if (setupSurface.childElementCount > 0) {
        clearMessage();
        setupSurface.hidden = false;
        monitor.hidden = true;
        ensureMonitor((bridge) => {
          monitor.classList.add('transport-owner');
          monitor.setAttribute('aria-hidden', 'true');
          const current = bridge.getContext();
          context.textContent = `Scan ${current.scan_id || '—'} · ${current.status || 'status unavailable'}`;
        });
        return;
      }
      const scope = api.createScope();
      activeScope = scope;
      global.VulixSetupModule.loadAndRenderSetup(setupSurface, {
        api: scope,
        onUnavailable: (reason) => {
          if (activeScope !== scope || registry.getActiveId() !== 'setup') return;
          if (setupSurface) setupSurface.hidden = true;
          showMonitorSurface('setup', (bridge) => {
            const frame = monitor.contentWindow;
            if (frame && frame.document) {
              let banner = frame.document.getElementById('setupSchemaUnavailableBanner');
              if (!banner) {
                banner = frame.document.createElement('div');
                banner.id = 'setupSchemaUnavailableBanner';
                banner.className = 'setup-unavailable-banner';
                const body = frame.document.querySelector('.cfg-body') || frame.document.body;
                if (body) body.insertBefore(banner, body.firstChild);
              }
              banner.textContent = `設定宣言が利用できません (${reason || 'unavailable'})。旧Setup画面を表示しています。`;
              banner.style.display = 'block';
            }
          });
        },
        onStartScan: (config) => {
          ensureMonitor((bridge) => {
            if (typeof bridge.startScan === 'function') {
              bridge.startScan(config);
            } else if (monitor.contentWindow && monitor.contentWindow.state && monitor.contentWindow.state.ws) {
              const ws = monitor.contentWindow.state.ws;
              if (typeof monitor.contentWindow._markOwnScan === 'function') {
                monitor.contentWindow._markOwnScan(config);
              }
              if (ws.readyState === 1) {
                ws.send(JSON.stringify({ action: 'start_scan', config }));
              } else if (ws.readyState === 0) {
                ws.addEventListener('open', () => {
                  try {
                    ws.send(JSON.stringify({ action: 'start_scan', config }));
                  } catch (_) {}
                }, { once: true });
              }
            }
            global.location.hash = '#/monitor';
          });
        },
      }).then((ok) => {
        if (activeScope !== scope || registry.getActiveId() !== 'setup') return;
        if (ok && setupSurface) {
          clearMessage();
          setupSurface.hidden = false;
          monitor.hidden = true;
          ensureMonitor((bridge) => {
            monitor.classList.add('transport-owner');
            monitor.setAttribute('aria-hidden', 'true');
            const current = bridge.getContext();
            context.textContent = `Scan ${current.scan_id || '—'} · ${current.status || 'status unavailable'}`;
          });
        }
      });
    } else {
      showMonitorSurface('setup');
    }
  }, unmount() {
    cancelPendingMonitorLoad();
    stopContextSubscription();
    if (activeScope) activeScope.cancelAll('Setup module unmounted');
    activeScope = null;
    if (setupSurface) {
      setupSurface.hidden = true;
    }
    monitor.hidden = true;
  } });

  registry.register({ id: 'monitor', title: 'Monitor', route: '#/monitor', mount(route) {
    title.textContent = 'Monitor';
    if (findingsSurface) findingsSurface.hidden = true;
    if (settingsSurface) settingsSurface.hidden = true;
    if (crawlSurface) crawlSurface.hidden = true;
    if (trafficSurface) trafficSurface.hidden = true;
    let selectedScanVerified = false;
    let selectedIdentity = null;
    const unavailableText = '指定された scan のライブ Monitor は現在の server snapshot と一致しません。過去 scan は履歴から確認してください。';
    const identityFor = (current) => {
      if (!current || !['server_id', 'run_id', 'scan_id'].every((key) =>
        typeof current[key] === 'string' && current[key].length > 0)) return null;
      return { server_id: current.server_id, run_id: current.run_id, scan_id: current.scan_id };
    };
    const sameIdentity = (left, right) => left && right &&
      left.server_id === right.server_id && left.run_id === right.run_id && left.scan_id === right.scan_id;
    const applySelectedContext = (current) => {
      if (!route.scanId || !selectedScanVerified) return;
      const incoming = identityFor(current);
      if (!incoming || incoming.scan_id !== route.scanId) {
        monitor.hidden = true;
        unavailable(unavailableText);
        return;
      }
      if (!selectedIdentity) selectedIdentity = incoming;
      if (!sameIdentity(selectedIdentity, incoming)) {
        monitor.hidden = true;
        unavailable(unavailableText);
        return;
      }
      clearMessage();
      monitor.hidden = false;
      if (monitorHost.hidden && !monitorHost.shadowRoot?.childElementCount) {
        monitor.contentWindow.VulixAppBridge.mountMonitor(monitorHost, route.scanId);
      }
      monitorHost.hidden = false;
    };
    stopContextSubscription();
    contextHandler = (event) => {
      if (event.origin !== global.location.origin || event.source !== monitor.contentWindow) return;
      const data = event.data;
      if (!data || data.type !== 'vulix:scan-context' || !data.context ||
          typeof data.context.status !== 'string') return;
      const current = data.context;
      context.textContent = `Scan ${current.scan_id || '—'} · ${current.status}`;
      applySelectedContext(current);
    };
    global.addEventListener('message', contextHandler);
    if (!route.scanId) {
      showMonitorSurface('monitor');
      return;
    }
    const scope = api.createScope();
    activeScope = scope;
    scope.get('/api/v1/scans').then((result) => {
      if (activeScope !== scope || registry.getActiveId() !== 'monitor') return;
      if (!result.ok || !result.data || !Array.isArray(result.data.scans)) {
        unavailable('スキャン一覧を確認できず、指定 scan の利用可能性を判定できません。');
        return;
      }
      if (!result.data.scans.some((item) => item && item.id === route.scanId)) {
        unavailable('指定 scan は見つかりません。削除済み、または存在しない可能性があります。');
        return;
      }
      selectedScanVerified = true;
      showMonitorSurface('monitor', (_bridge, current) => applySelectedContext(current));
    }).catch(() => {
      if (activeScope === scope && registry.getActiveId() === 'monitor') unavailable('スキャン一覧を確認できません。');
    });
  }, unmount() {
    cancelPendingMonitorLoad();
    stopContextSubscription();
    if (activeScope) activeScope.cancelAll('Monitor module unmounted');
    activeScope = null;
    const bridge = monitor.contentWindow && monitor.contentWindow.VulixAppBridge;
    if (bridge && bridge.unmountMonitor) bridge.unmountMonitor();
    monitorHost.hidden = true;
    monitor.hidden = true;
  } });

  registry.register({ id: 'agent-skills', title: 'Agent Skills', route: '#/agent-skills', mount() {
    title.textContent = 'Agent Skills';
    context.textContent = '';
    clearMessage();
    cancelPendingMonitorLoad();
    stopContextSubscription();
    monitor.hidden = true;
    if (monitorHost) monitorHost.hidden = true;
    if (findingsSurface) findingsSurface.hidden = true;
    if (setupSurface) setupSurface.hidden = true;
    if (settingsSurface) settingsSurface.hidden = true;
    if (crawlSurface) crawlSurface.hidden = true;
    if (trafficSurface) trafficSurface.hidden = true;
    if (agentSkillsSurface) {
      agentSkillsSurface.hidden = false;
      if (global.VulixAgentSkillsModule && typeof global.VulixAgentSkillsModule.loadAndRenderAgentSkills === 'function') {
        global.VulixAgentSkillsModule.loadAndRenderAgentSkills(agentSkillsSurface, { api });
      }
    }
  }, unmount() {
    if (agentSkillsSurface) {
      agentSkillsSurface.hidden = true;
      if (typeof agentSkillsSurface.replaceChildren === 'function') {
        agentSkillsSurface.replaceChildren();
      } else {
        while (agentSkillsSurface.firstChild) agentSkillsSurface.removeChild(agentSkillsSurface.firstChild);
      }
    }
  } });

  if (global.VulixFindingsModule && typeof global.VulixFindingsModule.createFindingsModule === 'function') {
    registry.register(
      global.VulixFindingsModule.createFindingsModule({
        api: api,
        surfaceEl: findingsSurface,
        titleEl: title,
        contextEl: context,
        unavailable: unavailable,
        clearMessage: clearMessage,
        hideOthers: function () {
          monitor.hidden = true;
          if (monitorHost) monitorHost.hidden = true;
          if (agentSkillsSurface) agentSkillsSurface.hidden = true;
          if (setupSurface) setupSurface.hidden = true;
          if (settingsSurface) settingsSurface.hidden = true;
          if (crawlSurface) crawlSurface.hidden = true;
          if (trafficSurface) trafficSurface.hidden = true;
        },
      })
    );
  }

  if (global.VulixSettingsModule && typeof global.VulixSettingsModule.createSettingsModule === 'function') {
    registry.register(
      global.VulixSettingsModule.createSettingsModule({
        api: api,
        surfaceEl: settingsSurface,
        titleEl: title,
        contextEl: context,
        unavailable: unavailable,
        clearMessage: clearMessage,
        hideOthers: function () {
          monitor.hidden = true;
          if (monitorHost) monitorHost.hidden = true;
          if (findingsSurface) findingsSurface.hidden = true;
          if (agentSkillsSurface) agentSkillsSurface.hidden = true;
          if (setupSurface) setupSurface.hidden = true;
          if (crawlSurface) crawlSurface.hidden = true;
          if (trafficSurface) trafficSurface.hidden = true;
        },
      })
    );
  }

  if (global.VulixCrawlModule && typeof global.VulixCrawlModule.createCrawlModule === 'function') {
    registry.register(
      global.VulixCrawlModule.createCrawlModule({
        api: api,
        surfaceEl: crawlSurface,
        titleEl: title,
        contextEl: context,
        unavailable: unavailable,
        clearMessage: clearMessage,
        hideOthers: function () {
          monitor.hidden = true;
          if (monitorHost) monitorHost.hidden = true;
          if (findingsSurface) findingsSurface.hidden = true;
          if (agentSkillsSurface) agentSkillsSurface.hidden = true;
          if (setupSurface) setupSurface.hidden = true;
          if (settingsSurface) settingsSurface.hidden = true;
          if (trafficSurface) trafficSurface.hidden = true;
        },
      })
    );
  }

  if (global.VulixTrafficModule && typeof global.VulixTrafficModule.createTrafficModule === 'function') {
    registry.register(
      global.VulixTrafficModule.createTrafficModule({
        api: api,
        surfaceEl: trafficSurface,
        titleEl: title,
        contextEl: context,
        unavailable: unavailable,
        clearMessage: clearMessage,
        hideOthers: function () {
          monitor.hidden = true;
          if (monitorHost) monitorHost.hidden = true;
          if (summarySurface) summarySurface.hidden = true;
          if (findingsSurface) findingsSurface.hidden = true;
          if (agentSkillsSurface) agentSkillsSurface.hidden = true;
          if (setupSurface) setupSurface.hidden = true;
          if (settingsSurface) settingsSurface.hidden = true;
          if (crawlSurface) crawlSurface.hidden = true;
        },
      })
    );
  }

  registry.setDefaultId('portal');

  function parseRoute(hash) {
    const raw = (hash || '').replace(/^#\/?/, '/');
    const parts = raw.split('?');
    const route = parts[0] || '/portal';
    if (!['/portal', '/history', '/audit', '/setup', '/monitor', '/findings', '/crawl', '/traffic', '/agent-skills', '/settings'].includes(route) || parts.length > 2) return null;
    const params = new URLSearchParams(parts[1] || '');

    const allowed = {
      '/portal': [],
      '/history': [],
      '/audit': [],
      '/setup': [],
      '/monitor': ['scan'],
      '/findings': ['scan', 'finding', 'url', 'search', 'severity', 'checkType', 'verification', 'provenance'],
      '/crawl': ['scan', 'node', 'url', 'mode', 'kind', 'search'],
      '/traffic': ['scan', 'entry', 'url', 'method', 'status', 'source', 'type', 'search'],
      '/agent-skills': [],
      '/settings': [],
    }[route] || [];

    for (const key of params.keys()) {
      if (!allowed.includes(key)) return null;
      if (params.getAll(key).length > 1) return null;
    }

    const scanId = params.get('scan');
    if (scanId !== null && (!scanId || scanId.length > 128 || !/^[A-Za-z0-9._-]+$/.test(scanId))) return null;
    if (scanId !== null && route !== '/monitor' && route !== '/findings' && route !== '/crawl' && route !== '/traffic') return null;

    const findingId = params.get('finding');
    if (findingId !== null && (!findingId || findingId.length > 512)) return null;
    if (findingId !== null && route !== '/findings') return null;

    const entryId = params.get('entry');
    if (entryId !== null && (!entryId || entryId.length > 256)) return null;
    if (entryId !== null && route !== '/traffic') return null;

    const nodeId = params.get('node');
    if (nodeId !== null && (!nodeId || nodeId.length > 256)) return null;
    if (nodeId !== null && route !== '/crawl') return null;

    const url = params.get('url');
    if (url !== null && (!url || url.length > 2048)) return null;
    if (url !== null && route !== '/crawl' && route !== '/findings' && route !== '/traffic') return null;

    const mode = params.get('mode');
    if (mode !== null && !['graph', 'explorer', 'list'].includes(mode)) return null;
    if (mode !== null && route !== '/crawl') return null;

    const kind = params.get('kind');
    if (kind !== null && !['all', 'page', 'form', 'param'].includes(kind)) return null;
    if (kind !== null && route !== '/crawl') return null;

    const severity = params.get('severity');
    if (severity !== null && !['all', 'critical', 'high', 'medium', 'low', 'info'].includes(severity)) return null;
    if (severity !== null && route !== '/findings') return null;

    const checkType = params.get('checkType');
    if (checkType !== null && (!checkType || checkType.length > 64)) return null;
    if (checkType !== null && route !== '/findings') return null;

    const method = params.get('method');
    if (method !== null && (!method || method.length > 32)) return null;
    if (method !== null && route !== '/traffic') return null;

    const status = params.get('status');
    if (status !== null && (!status || status.length > 16)) return null;
    if (status !== null && route !== '/traffic') return null;

    const source = params.get('source');
    if (source !== null && (!source || source.length > 32)) return null;
    if (source !== null && route !== '/traffic') return null;

    const type = params.get('type');
    if (type !== null && (!type || type.length > 32)) return null;
    if (type !== null && route !== '/traffic') return null;

    const verification = params.get('verification');
    if (verification !== null && !['all', 'reproduced', 'assumed', 'unreproduced', 'skipped'].includes(verification)) return null;
    if (verification !== null && route !== '/findings') return null;

    const provenance = params.get('provenance');
    if (provenance !== null && !['all', 'scanner', 'agent', 'agent_verified'].includes(provenance)) return null;
    if (provenance !== null && route !== '/findings') return null;

    const search = params.get('search');
    if (search !== null && search.length > 512) return null;

    const result = { id: route.slice(1), scanId, findingId };
    if (entryId !== null) result.entryId = entryId;
    if (nodeId !== null) result.nodeId = nodeId;
    if (url !== null) result.url = url;
    if (mode !== null) result.mode = mode;
    if (kind !== null) result.kind = kind;
    if (severity !== null) result.severity = severity;
    if (checkType !== null) result.checkType = checkType;
    if (method !== null) result.method = method;
    if (status !== null) result.status = status;
    if (source !== null) result.source = source;
    if (type !== null) result.type = type;
    if (verification !== null) result.verification = verification;
    if (provenance !== null) result.provenance = provenance;
    if (search !== null) result.search = search;
    return result;
  }

  function renderRoute() {
    mountToken += 1; // 遷移ごとに世代を進め、進行中の stale な monitor load を無効化する
    const route = parseRoute(global.location.hash);
    if (!route) {
      registry.destroy();
      unavailable('URL の route または scan identifier が不正です。');
      return;
    }
    const module = registry.get(route.id);
    if (!module) {
      registry.destroy();
      unavailable('この画面は登録されていません。');
      return;
    }
    try {
      if (registry.getActiveId() === route.id) registry.destroy();
      registry.transition(route.id, route);
      document.querySelectorAll('[data-route]').forEach((button) => {
        if (button.dataset.route === route.id) button.setAttribute('aria-current', 'page');
        else button.removeAttribute('aria-current');
      });
    } catch (_) {
      unavailable('画面の初期化に失敗しました。');
    }
  }

  document.querySelectorAll('[data-route]').forEach((button) => {
    button.addEventListener('click', () => { global.location.hash = `/${button.dataset.route}`; });
  });
  global.addEventListener('hashchange', renderRoute);
  global.addEventListener('pagehide', () => {
    global.removeEventListener('hashchange', renderRoute);
    stopContextSubscription();
    registry.destroy();
    if (activeScope) activeScope.cancelAll('App shell unloaded');
  }, { once: true });
  global.addEventListener('message', (event) => {
    if (event.origin !== global.location.origin || event.source !== monitor.contentWindow ||
        !event.data || event.data.type !== 'vulix:auth-required') return;
    registry.destroy();
    unavailable('認証セッションの再確認が必要です。ログイン後に /app を開き直してください。');
    const login = document.createElement('a');
    login.href = '/login';
    login.textContent = 'ログイン';
    message.append(login);
  });

  if (!global.location.hash) global.history.replaceState(null, '', `${global.location.pathname}${global.location.search}#/portal`);
  renderRoute();
})(window);
