/**
 * app-shell.js — Navigation & Module Lifecycle Scaffolding
 *
 * Provides a tested, non-visual navigation registry, lifecycle dispatcher,
 * and legacy adapter for dashboard views (live, history, audit).
 *
 * Preserves existing DOM element IDs, inline handlers, aria-current states,
 * and fetch-on-open semantics without introducing visible navigation items,
 * WebSocket changes, or new UI dependencies.
 */
(function (global) {
  'use strict';

  /**
   * ModuleRegistry: manages module definitions and active lifecycle state.
   */
  class ModuleRegistry {
    constructor() {
      this._modules = new Map();
      this._activeId = null;
      this._defaultId = 'live';
    }

    /**
     * Register a module definition.
     * @param {Object} def
     * @param {string} def.id - unique identifier
     * @param {string} [def.title] - title / header text
     * @param {string} [def.route] - hash route (e.g. '#live')
     * @param {Array<string>} [def.capabilities] - required capabilities
     * @param {Function} [def.mount] - lifecycle mount callback: (container, ctx) => void
     * @param {Function} [def.unmount] - lifecycle unmount callback: (container, ctx) => void
     */
    register(def) {
      if (!def || typeof def.id !== 'string' || !def.id.trim()) {
        throw new Error('Module definition must include a valid non-empty string id');
      }
      const id = def.id.trim();
      if (this._modules.has(id)) {
        throw new Error(`Module with id "${id}" is already registered`);
      }
      this._modules.set(id, {
        id: id,
        title: def.title || '',
        route: def.route || '',
        capabilities: Array.isArray(def.capabilities) ? [...def.capabilities] : [],
        mount: typeof def.mount === 'function' ? def.mount : null,
        unmount: typeof def.unmount === 'function' ? def.unmount : null,
      });
      return this;
    }

    /**
     * Get module definition by id.
     * @param {string} id
     */
    get(id) {
      return this._modules.get(id) || null;
    }

    /**
     * Check if a module is registered.
     * @param {string} id
     */
    has(id) {
      return this._modules.has(id);
    }

    /**
     * Return list of all registered module IDs.
     */
    list() {
      return Array.from(this._modules.keys());
    }

    /**
     * Get active module id.
     */
    getActiveId() {
      return this._activeId;
    }

    /**
     * Set default module id.
     * @param {string} id
     */
    setDefaultId(id) {
      if (this.has(id)) {
        this._defaultId = id;
      }
    }

    /**
     * Get default module id.
     */
    getDefaultId() {
      return this._defaultId;
    }

    /**
     * Transition active module from current to target module.
     * Invokes unmount on prior module and mount on target module.
     * @param {string} targetId
     * @param {Object} [ctx]
     */
    transition(targetId, ctx) {
      const target = this.get(targetId);
      if (!target) {
        throw new Error(`Cannot transition to unregistered module "${targetId}"`);
      }
      if (this._activeId === targetId) {
        return target;
      }

      if (this._activeId) {
        const current = this.get(this._activeId);
        if (current && typeof current.unmount === 'function') {
          try {
            current.unmount(ctx);
          } catch (err) {
            console.error(`Error unmounting module "${this._activeId}":`, err);
          }
        }
      }

      this._activeId = targetId;

      if (typeof target.mount === 'function') {
        try {
          target.mount(ctx);
        } catch (err) {
          console.error(`Error mounting module "${targetId}":`, err);
        }
      }

      return target;
    }

    /**
     * Teardown active module without transition.
     * @param {Object} [ctx]
     */
    destroy(ctx) {
      if (this._activeId) {
        const current = this.get(this._activeId);
        if (current && typeof current.unmount === 'function') {
          try {
            current.unmount(ctx);
          } catch (err) {
            console.error(`Error destroying module "${this._activeId}":`, err);
          }
        }
        this._activeId = null;
      }
    }
  }

  /**
   * NavigationDispatcher: handles hash routing, allowlist mapping,
   * safe fallback, direct-link, and back/forward browser history.
   */
  class NavigationDispatcher {
    /**
     * @param {ModuleRegistry} registry
     * @param {Object} [options]
     * @param {Function} [options.onNavigate] - callback (viewId, route, meta) => void
     * @param {Object} [options.routeMap] - mapping from hash to module id
     */
    constructor(registry, options = {}) {
      this.registry = registry;
      this.onNavigate = typeof options.onNavigate === 'function' ? options.onNavigate : null;
      // Allowlisted hash mappings only
      this.routeMap = Object.assign(
        {
          '#live': 'live',
          '#history': 'history',
          '#audit': 'audit',
        },
        options.routeMap || {}
      );
      this._listening = false;
      this._onHashChange = this._handleHashChange.bind(this);
    }

    /**
     * Resolve a hash fragment or route string to a registered view ID.
     * Unknown hash safely falls back to default ID ('live').
     * @param {string} rawHash
     * @returns {{viewId: string, isFallback: boolean, matchedHash: string}}
     */
    resolveRoute(rawHash) {
      const cleanHash = (rawHash || '').trim().split('?')[0];
      if (!cleanHash || cleanHash === '#' || cleanHash === '#/') {
        return {
          viewId: this.registry.getDefaultId(),
          isFallback: false,
          matchedHash: '#live',
        };
      }

      if (Object.prototype.hasOwnProperty.call(this.routeMap, cleanHash)) {
        const mappedId = this.routeMap[cleanHash];
        if (this.registry.has(mappedId)) {
          return {
            viewId: mappedId,
            isFallback: false,
            matchedHash: cleanHash,
          };
        }
      }

      // Safe unknown-route fallback to default
      return {
        viewId: this.registry.getDefaultId(),
        isFallback: true,
        matchedHash: '#live',
      };
    }

    /**
     * Dispatch navigation to a view by viewId or route.
     * @param {string} viewId
     * @param {Object} [options]
     * @param {boolean} [options.updateHash=true]
     * @param {boolean} [options.replace=false]
     * @param {Object} [options.ctx]
     */
    navigateTo(viewId, options = {}) {
      const { updateHash = true, replace = false, ctx = {} } = options;
      let targetId = viewId;

      // If viewId starts with #, resolve it as a route
      if (typeof targetId === 'string' && targetId.startsWith('#')) {
        const resolved = this.resolveRoute(targetId);
        targetId = resolved.viewId;
      }

      // Fallback if not registered
      if (!this.registry.has(targetId)) {
        targetId = this.registry.getDefaultId();
      }

      const mod = this.registry.transition(targetId, ctx);

      if (updateHash && typeof window !== 'undefined' && window.location) {
        const desiredHash = '#' + targetId;
        if (window.location.hash !== desiredHash) {
          if (replace && window.history && window.history.replaceState) {
            window.history.replaceState(null, '', desiredHash);
          } else {
            window.location.hash = desiredHash;
          }
        }
      }

      if (this.onNavigate) {
        try {
          this.onNavigate(targetId, mod ? mod.route : '', {
            title: mod ? mod.title : '',
            activeId: targetId,
          });
        } catch (err) {
          console.error('Error in onNavigate callback:', err);
        }
      }

      return targetId;
    }

    /**
     * Start listening to hashchange events for browser back/forward and direct links.
     */
    start() {
      if (this._listening) return;
      if (typeof window !== 'undefined' && window.addEventListener) {
        window.addEventListener('hashchange', this._onHashChange);
        this._listening = true;
      }
    }

    /**
     * Stop listening to hashchange events.
     */
    stop() {
      if (!this._listening) return;
      if (typeof window !== 'undefined' && window.removeEventListener) {
        window.removeEventListener('hashchange', this._onHashChange);
        this._listening = false;
      }
    }

    _handleHashChange() {
      if (typeof window === 'undefined' || !window.location) return;
      const resolved = this.resolveRoute(window.location.hash);
      // Synchronize view without pushing another history entry
      this.navigateTo(resolved.viewId, { updateHash: false });
    }
  }

  /**
   * createLegacyViewAdapter: encapsulates existing DOM IDs, classes,
   * aria-current attributes, titles, and fetch-on-open behavior.
   *
   * @param {Object} env - DOM / window environment references
   */
  function createLegacyViewAdapter(env) {
    const doc = env && env.document ? env.document : (typeof document !== 'undefined' ? document : null);

    return {
      views: {
        live: {
          containerId: 'viewLiveMonitor',
          navId: 'navLiveMonitor',
          hdrId: 'hdrBtnLive',
          title: 'ライブモニター',
        },
        history: {
          containerId: 'viewScanHistory',
          navId: 'navScanHistory',
          hdrId: 'hdrBtnHistory',
          title: 'スキャン履歴',
          fetchFnName: 'loadScanHistory',
        },
        audit: {
          containerId: 'viewAuditLog',
          navId: 'navAuditLog',
          hdrId: 'hdrBtnAudit',
          title: '監査ログ',
          fetchFnName: 'loadAuditLog',
        },
      },

      /**
       * Apply DOM representation changes for viewName.
       * Exact preservation of existing switchMainView DOM operations.
       * @param {string} viewName
       * @param {Object} [globals] - window/global context for fetchFn invocation
       */
      render(viewName, globals) {
        if (!doc) return;
        const g = globals || (typeof window !== 'undefined' ? window : {});

        const liveEl = doc.getElementById('viewLiveMonitor');
        const histEl = doc.getElementById('viewScanHistory');
        const auditEl = doc.getElementById('viewAuditLog');
        const navLive = doc.getElementById('navLiveMonitor');
        const navHist = doc.getElementById('navScanHistory');
        const navAudit = doc.getElementById('navAuditLog');
        const hdrLive = doc.getElementById('hdrBtnLive');
        const hdrHist = doc.getElementById('hdrBtnHistory');
        const hdrAudit = doc.getElementById('hdrBtnAudit');
        const hdrTitle = doc.getElementById('headerTitle');

        // Hide all views first
        if (liveEl) liveEl.style.display = 'none';
        if (histEl) histEl.style.display = 'none';
        if (auditEl) auditEl.style.display = 'none';

        // Deactivate all nav/hdr buttons
        [navLive, navHist, navAudit].forEach(function (btn) {
          if (btn) {
            btn.classList.remove('active');
            btn.removeAttribute('aria-current');
          }
        });
        [hdrLive, hdrHist, hdrAudit].forEach(function (btn) {
          if (btn) btn.classList.remove('active');
        });

        if (viewName === 'audit') {
          if (auditEl) auditEl.style.display = 'flex';
          if (navAudit) {
            navAudit.classList.add('active');
            navAudit.setAttribute('aria-current', 'page');
          }
          if (hdrAudit) hdrAudit.classList.add('active');
          if (hdrTitle) hdrTitle.textContent = '監査ログ';
          if (typeof g.loadAuditLog === 'function') {
            g.loadAuditLog();
          }
        } else if (viewName === 'history') {
          if (histEl) histEl.style.display = 'flex';
          if (navHist) {
            navHist.classList.add('active');
            navHist.setAttribute('aria-current', 'page');
          }
          if (hdrHist) hdrHist.classList.add('active');
          if (hdrTitle) hdrTitle.textContent = 'スキャン履歴';
          if (typeof g.loadScanHistory === 'function') {
            g.loadScanHistory();
          }
        } else {
          // Default / live
          if (liveEl) liveEl.style.display = 'flex';
          if (navLive) {
            navLive.classList.add('active');
            navLive.setAttribute('aria-current', 'page');
          }
          if (hdrLive) hdrLive.classList.add('active');
          if (hdrTitle) hdrTitle.textContent = 'ライブモニター';
        }
      },
    };
  }

  /**
   * setupAppShell: initializes the registry with existing live/history/audit views,
   * wires the NavigationDispatcher and legacy adapter, and exposes switchMainView
   * on the global object while handling direct-link hash initialization.
   */
  function setupAppShell(options = {}) {
    const targetGlobal = options.global || (typeof window !== 'undefined' ? window : global);
    const registry = new ModuleRegistry();
    const adapter = createLegacyViewAdapter({ document: targetGlobal.document });

    // Register only the currently implemented views
    registry.register({
      id: 'live',
      title: 'ライブモニター',
      route: '#live',
      capabilities: ['live-monitor'],
      mount: function () {
        adapter.render('live', targetGlobal);
      },
    });

    registry.register({
      id: 'history',
      title: 'スキャン履歴',
      route: '#history',
      capabilities: ['scan-history'],
      mount: function () {
        adapter.render('history', targetGlobal);
      },
    });

    registry.register({
      id: 'audit',
      title: '監査ログ',
      route: '#audit',
      capabilities: ['audit-log'],
      mount: function () {
        adapter.render('audit', targetGlobal);
      },
    });

    const dispatcher = new NavigationDispatcher(registry);

    /**
     * Backward-compatible switchMainView function
     */
    function switchMainView(viewName) {
      return dispatcher.navigateTo(viewName, { updateHash: true });
    }

    // Attach to global scope for inline onclick compatibility
    if (targetGlobal) {
      targetGlobal.switchMainView = switchMainView;
      targetGlobal.AppShell = {
        registry: registry,
        dispatcher: dispatcher,
        adapter: adapter,
        switchMainView: switchMainView,
      };
    }

    dispatcher.start();

    // Check initial location hash if present (direct-link)
    if (targetGlobal && targetGlobal.location && targetGlobal.location.hash) {
      const resolved = dispatcher.resolveRoute(targetGlobal.location.hash);
      // If user came with #history or #audit, switch to it, otherwise live
      if (resolved.viewId !== 'live') {
        dispatcher.navigateTo(resolved.viewId, { updateHash: false });
      }
    }

    return {
      registry: registry,
      dispatcher: dispatcher,
      adapter: adapter,
      switchMainView: switchMainView,
    };
  }

  // Export for browser globals or CommonJS/module environments (e.g. Node tests)
  const appShellExport = {
    ModuleRegistry: ModuleRegistry,
    NavigationDispatcher: NavigationDispatcher,
    createLegacyViewAdapter: createLegacyViewAdapter,
    setupAppShell: setupAppShell,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = appShellExport;
  }
  if (global) {
    global.VulixAppShell = appShellExport;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
