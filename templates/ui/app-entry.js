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
  let currentScanStatus = null;

  const ROUTE_GROUP_MAP = {
    portal: { group: 'overview', label: '概要' },
    history: { group: 'overview', label: '概要' },
    setup: { group: 'scan', label: 'スキャン実行' },
    monitor: { group: 'scan', label: 'スキャン実行' },
    findings: { group: 'investigation', label: '結果・調査' },
    crawl: { group: 'investigation', label: '結果・調査' },
    traffic: { group: 'investigation', label: '結果・調査' },
    audit: { group: 'operations', label: '運用・設定' },
    'agent-skills': { group: 'operations', label: '運用・設定' },
    settings: { group: 'operations', label: '運用・設定' },
  };

  function updateNavCount(route, count) {
    const btn = document.querySelector(`button.history-btn[data-route="${route}"]`);
    if (!btn) return;
    const num = Number(count) || 0;
    if (num > 0) {
      btn.setAttribute('data-nav-count', String(num));
    } else {
      btn.removeAttribute('data-nav-count');
    }
    const badge = btn.querySelector('.nav-count-badge') || document.querySelector(`[data-nav-badge="${route}"]`);
    if (badge) {
      badge.textContent = String(num);
      badge.hidden = num <= 0;
    }
  }

  function updateNavCounts(counts) {
    if (!counts) {
      updateNavCount('findings', 0);
      updateNavCount('crawl', 0);
      updateNavCount('traffic', 0);
      return;
    }
    if (counts.findings !== undefined || counts.findings_count !== undefined || counts.findingsCount !== undefined || counts.total_findings !== undefined) {
      const f = counts.findings_count ?? counts.findingsCount ?? counts.total_findings ?? counts.findings;
      updateNavCount('findings', Array.isArray(f) ? f.length : f);
    }
    if (counts.crawl !== undefined || counts.crawl_count !== undefined || counts.crawled_urls_count !== undefined || counts.crawledUrlsCount !== undefined || counts.crawled_count !== undefined || counts.pages_count !== undefined || counts.pages !== undefined) {
      const c = counts.crawl_count ?? counts.crawled_urls_count ?? counts.crawledUrlsCount ?? counts.crawled_count ?? counts.pages_count ?? counts.pages ?? counts.crawl;
      updateNavCount('crawl', Array.isArray(c) ? c.length : c);
    }
    if (counts.traffic !== undefined || counts.traffic_count !== undefined || counts.trafficCount !== undefined || counts.http_count !== undefined || counts.requests_count !== undefined || counts.entries !== undefined) {
      const t = counts.traffic_count ?? counts.trafficCount ?? counts.http_count ?? counts.requests_count ?? counts.entries ?? counts.traffic;
      updateNavCount('traffic', Array.isArray(t) ? t.length : t);
    }
  }

  function activateRoute(routeId) {
    const groupInfo = ROUTE_GROUP_MAP[routeId] || { group: 'overview', label: '概要' };
    const viewGroupBadge = document.getElementById('viewGroupBadge');
    if (viewGroupBadge) {
      viewGroupBadge.textContent = groupInfo.label;
      viewGroupBadge.setAttribute('data-group', groupInfo.group);
    }

    let activeGroupEl = null;
    document.querySelectorAll('[data-route]').forEach((button) => {
      if (button.dataset.route === routeId) {
        button.setAttribute('aria-current', 'page');
        activeGroupEl = button.closest('.nav-group');
      } else {
        button.removeAttribute('aria-current');
      }
    });

    document.querySelectorAll('.nav-group').forEach((groupEl) => {
      const isMatch = (activeGroupEl && groupEl === activeGroupEl) || (groupEl.dataset.navGroup === groupInfo.group);
      if (isMatch) {
        groupEl.setAttribute('data-active', 'true');
        groupEl.classList.add('nav-group-active');
      } else {
        groupEl.removeAttribute('data-active');
        groupEl.classList.remove('nav-group-active');
      }
    });
  }

  function redactDisplayUrl(raw) {
    if (!raw || typeof raw !== 'string') return raw || '';
    const str = raw.trim();
    if (!str) return '';
    let url = str.replace(/\b(https?:\/\/)[^\s/?#@]+(?::[^\s/?#@]*)?@/gi, '$1<redacted>@');
    const sensitive = /(?:^key$|(?:api|access|auth)[_-]?key|password|passwd|pwd|secret|token|auth[_-]?token|cookie|session[_-]?id|csrf|xsrf|credentials?|signature|samlresponse|(?:^|[._-])(?:sid|sessid|jwt|sig|jsessionid|phpsessid|bearer)(?:$|[._-])|(?:^|[._-])(?:auth|authentication|authorization|session|otp|ticket)$)/i;
    url = url.replace(/([?&#])([^=&#]+)=([^&#]*)/g, (match, sep, k, v) => {
      if (sensitive.test(k)) {
        return sep + k + '=<redacted>';
      }
      return match;
    });
    return url;
  }

  function getActiveScanId() {
    const currentRoute = parseRoute(global.location.hash);
    if (currentRoute && currentRoute.scanId && /^[A-Za-z0-9._-]+$/.test(currentRoute.scanId)) {
      return currentRoute.scanId;
    }
    const statusScanId = currentScanStatus && (currentScanStatus.scan_id || currentScanStatus.scanId);
    if (statusScanId && typeof statusScanId === 'string' && statusScanId !== '—' && /^[A-Za-z0-9._-]+$/.test(statusScanId)) {
      return statusScanId;
    }
    return null;
  }

  function formatDuration(secs) {
    if (!Number.isFinite(secs) || secs < 0) return '—';
    if (secs < 60) return Math.round(secs) + '秒';
    const m = Math.floor(secs / 60);
    const s = Math.round(secs % 60).toString().padStart(2, '0');
    if (m < 60) return m + '分' + s + '秒';
    const h = Math.floor(m / 60);
    return h + '時間' + (m % 60) + '分';
  }

  function renderScanStatusBar(state) {
    if (!state || (!state.scan_id && !state.scanId && !state.status)) {
      currentScanStatus = null;
      if (typeof context.replaceChildren === 'function') context.replaceChildren();
      else context.innerHTML = '';
      context.textContent = '';
      updateNavCounts(null);
      return;
    }
    updateNavCounts(state);
    currentScanStatus = Object.assign({}, currentScanStatus || {}, state);
    let scanId = state.scan_id || state.scanId || (currentScanStatus && (currentScanStatus.scan_id || currentScanStatus.scanId)) || '';
    if (scanId === '—' || !/^[A-Za-z0-9._-]+$/.test(scanId)) {
      scanId = '';
      if (currentScanStatus) {
        delete currentScanStatus.scan_id;
        delete currentScanStatus.scanId;
      }
    }
    const rawStatus = (state.status || (currentScanStatus && currentScanStatus.status) || 'idle').toLowerCase();

    // Map execution status: idle | running | paused | done | aborted | error | partial | unknown
    let execState = 'idle';
    if (/running|scanning|active/.test(rawStatus)) execState = 'running';
    else if (/paused/.test(rawStatus)) execState = 'paused';
    else if (/done|completed|success/.test(rawStatus)) execState = 'done';
    else if (/aborted|cancelled|canceled/.test(rawStatus)) execState = 'aborted';
    else if (/error|failed/.test(rawStatus)) execState = 'error';
    else if (/partial/.test(rawStatus)) execState = 'partial';
    else if (/unknown/.test(rawStatus)) execState = 'unknown';
    else if (rawStatus) execState = rawStatus;

    const mode = state.mode || (currentScanStatus && currentScanStatus.mode) || 'normal';
    const rawTarget = state.target || state.target_url || (currentScanStatus && (currentScanStatus.target || currentScanStatus.target_url)) || '';
    const safeTarget = rawTarget ? redactDisplayUrl(rawTarget) : '';
    const phase = state.phase || (currentScanStatus && currentScanStatus.phase) || '';

    // Connection state: connected | reconnecting | disconnected
    let connState = state.connection || 'connected';
    if (monitor && monitor.contentWindow) {
      try {
        const cw = monitor.contentWindow;
        if (cw._eventStream) {
          if (cw._eventStream.connected) connState = 'connected';
          else if (cw._eventStream.connecting) connState = 'reconnecting';
          else connState = 'disconnected';
        } else if (cw.state && cw.state.ws) {
          const rs = cw.state.ws.readyState;
          if (rs === 1) connState = 'connected';
          else if (rs === 0) connState = 'reconnecting';
          else connState = 'disconnected';
        }
      } catch (_) {}
    }

    // Freshness: fresh | stale | snapshot
    let freshness = state.freshness;
    if (!freshness) {
      if (['done', 'aborted', 'error', 'partial'].includes(execState)) {
        freshness = 'snapshot';
      } else if (connState === 'connected') {
        freshness = 'fresh';
      } else {
        freshness = 'stale';
      }
    }

    const freshnessLabel = freshness === 'fresh' ? 'fresh' : (freshness === 'snapshot' ? 'snapshot' : 'stale');

    if (typeof context.replaceChildren === 'function') context.replaceChildren();
    else context.innerHTML = '';

    const bar = document.createElement('span');
    bar.className = 'scan-status-bar';
    bar.setAttribute('data-testid', 'scan-status-bar');

    // Main status text: Scan <id> · <status> (preserves exact substrings for tests)
    const main = document.createElement('span');
    main.className = 'scan-status-main';
    main.textContent = `Scan ${scanId || '—'} · ${rawStatus || 'idle'}`;

    // Meta items
    const meta = document.createElement('span');
    meta.className = 'scan-status-meta';

    // Mode badge
    const modeBadge = document.createElement('span');
    modeBadge.className = 'scan-mode-badge';
    modeBadge.dataset.mode = mode;
    modeBadge.textContent = `[${mode}]`;
    meta.appendChild(modeBadge);

    // Target URL (redacted)
    if (safeTarget) {
      const targetEl = document.createElement('span');
      targetEl.className = 'scan-target-url';
      targetEl.textContent = safeTarget;
      targetEl.title = safeTarget;
      meta.appendChild(targetEl);
    }

    // Phase badge
    if (phase) {
      const phaseBadge = document.createElement('span');
      phaseBadge.className = 'scan-phase-badge';
      phaseBadge.dataset.phase = phase;
      phaseBadge.textContent = `phase: ${phase}`;
      meta.appendChild(phaseBadge);
    }

    // Connection badge
    const connBadge = document.createElement('span');
    connBadge.className = `scan-conn-badge scan-conn-${connState}`;
    connBadge.dataset.conn = connState;
    connBadge.textContent = `● ${connState}`;
    meta.appendChild(connBadge);

    // Freshness badge
    const freshBadge = document.createElement('span');
    freshBadge.className = `scan-freshness-badge scan-freshness-${freshness}`;
    freshBadge.dataset.freshness = freshness;
    freshBadge.textContent = freshnessLabel;
    meta.appendChild(freshBadge);

    // State badge
    const stateBadge = document.createElement('span');
    stateBadge.className = `scan-state-badge scan-state-${execState}`;
    stateBadge.setAttribute('data-testid', 'scan-state-badge');
    stateBadge.setAttribute('data-state', execState);
    const stateIcons = {
      running: '⟳',
      paused: '⏸',
      done: '✓',
      completed: '✓',
      aborted: '⏹',
      error: '✗',
      failed: '✗',
      partial: '⟲',
      stale: '⟲',
      unverified: '?',
      idle: '—',
      unknown: '—'
    };
    const stateGlyph = stateIcons[execState] || '';
    stateBadge.textContent = stateGlyph ? `${stateGlyph} ${execState}` : execState;
    meta.appendChild(stateBadge);

    // Canonical ETA and Progress rendering if present
    const etaData = state.eta || (state.eta_seconds !== undefined ? state : null);
    if (etaData && typeof etaData === 'object') {
      const etaSeconds = etaData.eta_seconds != null ? Number(etaData.eta_seconds) : null;
      const progressPercent = etaData.progress_percent != null ? Number(etaData.progress_percent) : (state.progress && state.progress.percent != null ? Number(state.progress.percent) : null);
      const confidence = etaData.confidence || etaData.eta_confidence || '';
      const statusLabel = etaData.status_label || etaData.eta_status || '';
      const reasonCode = etaData.reason_code || '';
      const range = Array.isArray(etaData.eta_range_seconds) ? etaData.eta_range_seconds : null;

      if (progressPercent != null && Number.isFinite(progressPercent)) {
        const progBadge = document.createElement('span');
        progBadge.className = 'scan-progress-badge';
        progBadge.setAttribute('data-testid', 'scan-progress-badge');
        const dispProg = execState === 'done' ? 100 : Math.min(99.9, progressPercent);
        progBadge.textContent = `${dispProg % 1 === 0 ? dispProg.toFixed(0) : dispProg.toFixed(1)}%`;
        meta.appendChild(progBadge);
      }

      const etaBadge = document.createElement('span');
      etaBadge.className = 'scan-eta-badge';
      etaBadge.setAttribute('data-testid', 'scan-eta-badge');
      if (confidence) etaBadge.setAttribute('data-confidence', confidence);
      if (statusLabel) etaBadge.setAttribute('data-status-label', statusLabel);
      if (reasonCode) etaBadge.setAttribute('data-reason-code', reasonCode);

      let etaText = '';
      if (execState === 'paused' || statusLabel === 'paused') {
        etaText = 'ETA: 一時停止';
      } else if (execState === 'done' || statusLabel === 'completed') {
        etaText = 'ETA: 完了';
      } else if (execState === 'aborted' || statusLabel === 'aborted') {
        etaText = 'ETA: 中断';
      } else if (execState === 'error' || execState === 'failed') {
        etaText = 'ETA: エラー';
      } else if (statusLabel === 'calibrating' || confidence === 'calibrating' || reasonCode === 'insufficient_samples') {
        etaText = 'ETA: 算出中…';
      } else if (statusLabel === 'indeterminate' || confidence === 'indeterminate') {
        etaText = 'ETA: 推定困難';
      } else if (etaSeconds != null && Number.isFinite(etaSeconds) && etaSeconds >= 1) {
        etaText = `ETA: ${formatDuration(etaSeconds)}`;
        if (confidence === 'low' || reasonCode === 'dynamic_queue_growth') {
          etaText += ' (推定困難)';
        }
      }

      if (etaText) {
        etaBadge.textContent = etaText;
        const titleParts = [etaText];
        if (range && range.length === 2) {
          titleParts.push(`範囲: ${formatDuration(range[0])}〜${formatDuration(range[1])}`);
        }
        if (confidence) titleParts.push(`信頼度: ${confidence}`);
        if (reasonCode) titleParts.push(`理由: ${reasonCode}`);
        etaBadge.title = titleParts.join(' | ');
        meta.appendChild(etaBadge);
      }
    }

    // Help button for status_execution_vs_connection
    const checkHelp = global.VulixCheckHelp || (typeof require === 'function' && typeof process !== 'undefined' ? require(process.cwd() + '/templates/ui/check-help.js') : null);
    if (checkHelp && typeof checkHelp.createHelpButton === 'function') {
      const helpBtn = checkHelp.createHelpButton(document, document.body, 'status_execution_vs_connection', 'ja');
      meta.appendChild(helpBtn);
    }

    bar.appendChild(main);
    bar.appendChild(meta);
    context.appendChild(bar);
  }

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
      renderScanStatusBar(current);
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

  registry.register({ id: 'setup', title: 'Scan Setup', route: '#/setup', mount(route) {
    title.textContent = 'Scan Setup';
    if (route && route.scanId) renderScanStatusBar({ scan_id: route.scanId, status: 'idle' });
    else renderScanStatusBar(null);
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

    if (setupSurface) setupSurface._scanStartInFlight = false;
    const getSetupStartBtn = () => setupSurface ? setupSurface.querySelector('#setupStartScanBtn') : null;
    const showSetupError = (text) => {
      let errBox = setupSurface ? setupSurface.querySelector('#setupStartError') : null;
      if (!errBox && setupSurface) {
        errBox = document.createElement('div');
        errBox.id = 'setupStartError';
        errBox.className = 'setup-start-error';
        errBox.setAttribute('role', 'alert');
        errBox.style.cssText = 'background:rgba(226,112,143,0.18);border:1px solid var(--critical);color:var(--critical);padding:10px 14px;border-radius:6px;margin:8px 0 12px;font-size:0.85rem;font-weight:600;';
        const header = setupSurface.querySelector('.setup-header') || setupSurface.firstChild;
        if (header && header.parentNode) {
          header.parentNode.insertBefore(errBox, header.nextSibling);
        } else {
          setupSurface.insertBefore(errBox, setupSurface.firstChild);
        }
      }
      if (errBox) {
        errBox.textContent = text;
        errBox.hidden = false;
      }
    };
    const clearSetupError = () => {
      const errBox = setupSurface ? setupSurface.querySelector('#setupStartError') : null;
      if (errBox) {
        errBox.hidden = true;
        errBox.textContent = '';
      }
    };

    if (global.VulixSetupModule && setupSurface) {
      if (setupSurface.childElementCount > 0) {
        clearMessage();
        clearSetupError();
        setupSurface._scanStartInFlight = false;
        const existingBtn = getSetupStartBtn();
        if (existingBtn) existingBtn.disabled = false;
        setupSurface.hidden = false;
        monitor.hidden = true;
        ensureMonitor((bridge) => {
          monitor.classList.add('transport-owner');
          monitor.setAttribute('aria-hidden', 'true');
          monitor.setAttribute('tabindex', '-1');
          monitor.hidden = true;
          const current = bridge.getContext();
          if (current && current.scan_id) renderScanStatusBar(current);
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
          if (setupSurface && setupSurface._scanStartInFlight) return;
          if (setupSurface) setupSurface._scanStartInFlight = true;
          const startBtn = getSetupStartBtn();
          if (startBtn) startBtn.disabled = true;
          clearSetupError();

          ensureMonitor((bridge) => {
            const resetInFlight = () => {
              if (setupSurface) setupSurface._scanStartInFlight = false;
              const btn = getSetupStartBtn();
              if (btn) btn.disabled = false;
            };

            const callbacks = {
              onAccepted: (scanId) => {
                if (setupSurface) setupSurface._scanStartInFlight = false;
                const btn = getSetupStartBtn();
                if (btn) btn.disabled = false;
                clearSetupError();
                if (scanId) {
                  renderScanStatusBar({ scan_id: scanId, status: 'scanning', freshness: 'fresh' });
                }
                global.location.hash = '#/monitor';
              },
              onRejected: (rejectionMsg) => {
                resetInFlight();
                showSetupError(`スキャン開始が拒否されました: ${rejectionMsg || ''}`);
                context.textContent = `スキャン開始拒否: ${rejectionMsg || ''}`;
              },
              onTimeout: () => {
                resetInFlight();
                showSetupError('スキャン開始リクエストがタイムアウトしました。');
                context.textContent = 'スキャン開始タイムアウト';
              },
            };

            let started = false;
            try {
              if (typeof bridge.startScan === 'function') {
                started = bridge.startScan(config, callbacks);
              } else if (monitor.contentWindow && monitor.contentWindow.state && monitor.contentWindow.state.ws) {
                const ws = monitor.contentWindow.state.ws;
                if (typeof monitor.contentWindow._markOwnScan === 'function') {
                  monitor.contentWindow._markOwnScan(config);
                }
                if (ws.readyState === 1) {
                  ws.send(JSON.stringify({ action: 'start_scan', config }));
                  started = true;
                } else if (ws.readyState === 0) {
                  ws.addEventListener('open', () => {
                    try {
                      ws.send(JSON.stringify({ action: 'start_scan', config }));
                    } catch (_) {}
                  }, { once: true });
                  started = true;
                }
              }
            } catch (_) {
              started = false;
            }

            if (!started) {
              resetInFlight();
              showSetupError('WebSocket未接続。スキャンを開始できませんでした。');
              context.textContent = 'WebSocket未接続';
              return;
            }
          });
        },
      }).then((ok) => {
        if (activeScope !== scope || registry.getActiveId() !== 'setup') return;
        if (ok && setupSurface) {
          clearMessage();
          clearSetupError();
          setupSurface._scanStartInFlight = false;
          setupSurface.hidden = false;
          monitor.hidden = true;
          ensureMonitor((bridge) => {
            monitor.classList.add('transport-owner');
            monitor.setAttribute('aria-hidden', 'true');
            monitor.setAttribute('tabindex', '-1');
            monitor.hidden = true;
            const current = bridge.getContext();
            if (current && current.scan_id) renderScanStatusBar(current);
          });
        }
      });
    } else {
      showMonitorSurface('setup');
    }
  }, unmount() {
    cancelPendingMonitorLoad();
    stopContextSubscription();
    try {
      if (monitor.contentWindow && monitor.contentWindow.VulixAppBridge &&
          typeof monitor.contentWindow.VulixAppBridge.cancelPendingStartScan === 'function') {
        monitor.contentWindow.VulixAppBridge.cancelPendingStartScan();
      }
    } catch (_) {}
    if (activeScope) activeScope.cancelAll('Setup module unmounted');
    activeScope = null;
    if (setupSurface) {
      setupSurface.hidden = true;
    }
    monitor.classList.remove('transport-owner');
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
      renderScanStatusBar(current);
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

  registry.register({ id: 'agent-skills', title: 'Agent Skills', route: '#/agent-skills', mount(route) {
    title.textContent = 'Agent Skills';
    if (route && route.scanId) renderScanStatusBar({ scan_id: route.scanId, status: 'idle' });
    else renderScanStatusBar(null);
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
      '/portal': ['scan'],
      '/history': [],
      '/audit': [],
      '/setup': ['scan'],
      '/monitor': ['scan'],
      '/findings': ['scan', 'finding', 'url', 'search', 'severity', 'checkType', 'verification', 'provenance'],
      '/crawl': ['scan', 'node', 'url', 'mode', 'kind', 'search'],
      '/traffic': ['scan', 'entry', 'url', 'method', 'status', 'source', 'type', 'search'],
      '/agent-skills': ['scan'],
      '/settings': ['scan'],
    }[route] || [];

    for (const key of params.keys()) {
      if (!allowed.includes(key)) return null;
      if (params.getAll(key).length > 1) return null;
    }

    const scanId = params.get('scan');
    if (scanId !== null && (!scanId || scanId.length > 128 || !/^[A-Za-z0-9._-]+$/.test(scanId))) return null;
    if (scanId !== null && !['/monitor', '/findings', '/crawl', '/traffic', '/portal', '/setup', '/settings', '/agent-skills'].includes(route)) return null;

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
      if (route.scanId) {
        renderScanStatusBar(Object.assign({ scan_id: route.scanId, status: 'snapshot', freshness: 'snapshot' }, (currentScanStatus && currentScanStatus.scan_id === route.scanId) ? currentScanStatus : {}));
      } else if (route.id !== 'monitor') {
        renderScanStatusBar(null);
      }
      activateRoute(route.id);
    } catch (_) {
      unavailable('画面の初期化に失敗しました。');
    }
  }

  document.querySelectorAll('[data-route]').forEach((button) => {
    button.addEventListener('click', () => {
      const targetRoute = button.dataset.route;
      const activeScanId = getActiveScanId();
      const scanAllowed = ['portal', 'setup', 'monitor', 'findings', 'crawl', 'traffic', 'agent-skills', 'settings'].includes(targetRoute);
      if (activeScanId && scanAllowed) {
        global.location.hash = `/${targetRoute}?scan=${encodeURIComponent(activeScanId)}`;
      } else {
        global.location.hash = `/${targetRoute}`;
      }
    });
  });
  global.addEventListener('hashchange', renderRoute);
  global.addEventListener('pagehide', () => {
    global.removeEventListener('hashchange', renderRoute);
    stopContextSubscription();
    registry.destroy();
    if (activeScope) activeScope.cancelAll('App shell unloaded');
  }, { once: true });
  global.addEventListener('message', (event) => {
    if (event.origin !== global.location.origin) return;
    if (event.data && event.data.type === 'vulix:scan-counts') {
      updateNavCounts(event.data.counts || event.data);
    }
    if (event.source !== monitor.contentWindow || !event.data || event.data.type !== 'vulix:auth-required') return;
    registry.destroy();
    unavailable('認証セッションの再確認が必要です。ログイン後に /app を開き直してください。');
    const login = document.createElement('a');
    login.href = '/login';
    login.textContent = 'ログイン';
    message.append(login);
  });

  if (global.VulixAppShell) {
    global.VulixAppShell.renderScanStatus = renderScanStatusBar;
    global.VulixAppShell.getScanStatus = () => currentScanStatus;
    global.VulixAppShell.activateRoute = activateRoute;
    global.VulixAppShell.updateNavCounts = updateNavCounts;
    global.VulixAppShell.updateNavCount = updateNavCount;
    global.VulixAppShell.getActiveScanId = getActiveScanId;
    global.VulixAppShell.ROUTE_GROUP_MAP = ROUTE_GROUP_MAP;
  }
  global.VulixAppEntry = {
    renderScanStatusBar,
    getScanStatus: () => currentScanStatus,
    redactDisplayUrl,
    activateRoute,
    updateNavCounts,
    updateNavCount,
    getActiveScanId,
    ROUTE_GROUP_MAP,
  };

  if (!global.location.hash) global.history.replaceState(null, '', `${global.location.pathname}${global.location.search}#/portal`);
  renderRoute();
})(window);
