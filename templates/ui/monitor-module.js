/* Monitor の表示 root とライフサイクル。WS と scan 状態は既存 owner に一元化する。 */
(function (global) {
  'use strict';

  const sameIdentity = (a, b) => a && b && ['server_id', 'run_id', 'scan_id']
    .every(key => typeof a[key] === 'string' && a[key] && a[key] === b[key]);

  const STORAGE_KEY = 'vulix:monitor-layout:v1';

  const DEFAULT_LAYOUT = Object.freeze({
    version: 1,
    preset: 'standard',
    leftWidth: 320,
    rightWidth: 300,
    collapsed: Object.freeze({ left: false, center: false, right: false }),
    maximized: null,
  });

  const PRESETS = Object.freeze({
    'standard': Object.freeze({
      version: 1,
      preset: 'standard',
      leftWidth: 320,
      rightWidth: 300,
      collapsed: Object.freeze({ left: false, center: false, right: false }),
      maximized: null,
    }),
    'browser-focused': Object.freeze({
      version: 1,
      preset: 'browser-focused',
      leftWidth: 200,
      rightWidth: 260,
      collapsed: Object.freeze({ left: true, center: false, right: false }),
      maximized: null,
    }),
    'log-focused': Object.freeze({
      version: 1,
      preset: 'log-focused',
      leftWidth: 520,
      rightWidth: 260,
      collapsed: Object.freeze({ left: false, center: false, right: true }),
      maximized: null,
    }),
  });

  const LAYOUT_BOUNDS = Object.freeze({
    left: Object.freeze({ min: 160, max: 700 }),
    right: Object.freeze({ min: 160, max: 700 }),
    minCenter: 200,
  });

  function cloneLayout(layout) {
    return {
      version: 1,
      preset: layout.preset || 'standard',
      leftWidth: Number(layout.leftWidth) || 320,
      rightWidth: Number(layout.rightWidth) || 300,
      collapsed: {
        left: Boolean(layout.collapsed && layout.collapsed.left),
        center: Boolean(layout.collapsed && layout.collapsed.center),
        right: Boolean(layout.collapsed && layout.collapsed.right),
      },
      maximized: layout.maximized || null,
    };
  }

  const SECRET_OR_URL_PATTERN = /https?:|\/\/|token|secret|password|bearer|auth|scan_|payload/i;

  function validateLayoutPreferences(obj) {
    if (!obj || typeof obj !== 'object' || Array.isArray(obj)) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    if (obj.version !== 1) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    const allowedKeys = new Set(['version', 'preset', 'leftWidth', 'rightWidth', 'collapsed', 'maximized']);
    const keys = Object.keys(obj);
    if (!keys.every(k => allowedKeys.has(k))) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    const validPresets = new Set(['standard', 'browser-focused', 'log-focused', 'custom']);
    if (typeof obj.preset !== 'string' || !validPresets.has(obj.preset)) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    if (SECRET_OR_URL_PATTERN.test(obj.preset)) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    if (typeof obj.leftWidth !== 'number' || !Number.isFinite(obj.leftWidth) ||
        obj.leftWidth < LAYOUT_BOUNDS.left.min || obj.leftWidth > 1200) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    if (typeof obj.rightWidth !== 'number' || !Number.isFinite(obj.rightWidth) ||
        obj.rightWidth < LAYOUT_BOUNDS.right.min || obj.rightWidth > 1200) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    if (!obj.collapsed || typeof obj.collapsed !== 'object' || Array.isArray(obj.collapsed)) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    const colKeys = Object.keys(obj.collapsed);
    const allowedColKeys = new Set(['left', 'center', 'right']);
    if (!colKeys.every(k => allowedColKeys.has(k))) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    for (const k of colKeys) {
      if (typeof obj.collapsed[k] !== 'boolean') {
        return cloneLayout(DEFAULT_LAYOUT);
      }
    }
    const validMaximized = new Set([null, 'left', 'center', 'right']);
    if (!validMaximized.has(obj.maximized)) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    return cloneLayout(obj);
  }

  function parseLayoutPreferences(raw) {
    if (typeof raw !== 'string' || !raw.trim()) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
    try {
      if (SECRET_OR_URL_PATTERN.test(raw)) {
        return cloneLayout(DEFAULT_LAYOUT);
      }
      const parsed = JSON.parse(raw);
      return validateLayoutPreferences(parsed);
    } catch (_) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
  }

  function loadPreferences(storage, storageKey = STORAGE_KEY) {
    try {
      if (!storage) return cloneLayout(DEFAULT_LAYOUT);
      const raw = storage.getItem(storageKey);
      return parseLayoutPreferences(raw);
    } catch (_) {
      return cloneLayout(DEFAULT_LAYOUT);
    }
  }

  function savePreferences(storage, layout, storageKey = STORAGE_KEY) {
    try {
      if (!storage) return false;
      const validated = validateLayoutPreferences(layout);
      const clean = {
        version: 1,
        preset: validated.preset,
        leftWidth: Math.round(validated.leftWidth),
        rightWidth: Math.round(validated.rightWidth),
        collapsed: {
          left: Boolean(validated.collapsed.left),
          center: Boolean(validated.collapsed.center),
          right: Boolean(validated.collapsed.right),
        },
        maximized: validated.maximized,
      };
      storage.setItem(storageKey, JSON.stringify(clean));
      return true;
    } catch (_) {
      return false;
    }
  }

  function applySeparatorKey(currentValue, key, options = {}) {
    const { min = 160, max = 700, step = 20, invert = false } = options;
    if (typeof currentValue !== 'number' || !Number.isFinite(currentValue)) {
      currentValue = min;
    }
    if (key === 'ArrowLeft') {
      const delta = invert ? step : -step;
      return Math.min(Math.max(currentValue + delta, min), max);
    }
    if (key === 'ArrowRight') {
      const delta = invert ? -step : step;
      return Math.min(Math.max(currentValue + delta, min), max);
    }
    if (key === 'Home') return min;
    if (key === 'End') return max;
    return currentValue;
  }

  function applyPreset(presetName, currentLayout) {
    if (PRESETS[presetName]) {
      return cloneLayout(PRESETS[presetName]);
    }
    return currentLayout ? cloneLayout(currentLayout) : cloneLayout(DEFAULT_LAYOUT);
  }

  function togglePaneCollapse(layout, paneName) {
    if (!['left', 'center', 'right'].includes(paneName)) {
      return cloneLayout(layout || DEFAULT_LAYOUT);
    }
    const next = cloneLayout(layout || DEFAULT_LAYOUT);
    if (next.maximized) next.maximized = null;
    const currentVal = Boolean(next.collapsed[paneName]);
    const nextVal = !currentVal;
    if (nextVal) {
      const allCollapsed = ['left', 'center', 'right']
        .every(p => (p === paneName ? true : Boolean(next.collapsed[p])));
      if (allCollapsed) return next;
    }
    next.collapsed[paneName] = nextVal;
    next.preset = 'custom';
    return next;
  }

  function togglePaneMaximize(layout, paneName) {
    if (!['left', 'center', 'right'].includes(paneName)) {
      return cloneLayout(layout || DEFAULT_LAYOUT);
    }
    const next = cloneLayout(layout || DEFAULT_LAYOUT);
    if (next.maximized === paneName) {
      next.maximized = null;
    } else {
      next.maximized = paneName;
      next.collapsed[paneName] = false;
    }
    next.preset = 'custom';
    return next;
  }

  function computePaneDimensions(layout, containerWidth = 1000, bounds = LAYOUT_BOUNDS) {
    const safeLayout = validateLayoutPreferences(layout);
    const max = safeLayout.maximized;

    if (max) {
      return {
        left: { width: max === 'left' ? containerWidth : 0, collapsed: false, maximized: max === 'left', visible: max === 'left' },
        center: { flex: max === 'center' ? 1 : 0, collapsed: false, maximized: max === 'center', visible: max === 'center' },
        right: { width: max === 'right' ? containerWidth : 0, collapsed: false, maximized: max === 'right', visible: max === 'right' },
        sepLeft: { visible: false, valueNow: safeLayout.leftWidth, valueMin: bounds.left.min, valueMax: bounds.left.max },
        sepRight: { visible: false, valueNow: safeLayout.rightWidth, valueMin: bounds.right.min, valueMax: bounds.right.max },
      };
    }

    const leftCol = Boolean(safeLayout.collapsed.left);
    const centerCol = Boolean(safeLayout.collapsed.center);
    const rightCol = Boolean(safeLayout.collapsed.right);

    const leftW = leftCol ? 36 : Math.min(Math.max(safeLayout.leftWidth, bounds.left.min), bounds.left.max);
    const rightW = rightCol ? 36 : Math.min(Math.max(safeLayout.rightWidth, bounds.right.min), bounds.right.max);

    return {
      left: { width: leftW, collapsed: leftCol, maximized: false, visible: true },
      center: { flex: centerCol ? 0 : 1, width: centerCol ? 36 : null, collapsed: centerCol, maximized: false, visible: true },
      right: { width: rightW, collapsed: rightCol, maximized: false, visible: true },
      sepLeft: { visible: !leftCol && !centerCol, valueNow: Math.round(leftW), valueMin: bounds.left.min, valueMax: bounds.left.max },
      sepRight: { visible: !rightCol && !centerCol, valueNow: Math.round(rightW), valueMin: bounds.right.min, valueMax: bounds.right.max },
    };
  }

  function createMonitorModule(legacyDocument) {
    let root = null;
    let host = null;
    let expected = null;
    let selectedScan = null;
    let context = () => null;
    let hasMounted = false;
    let layoutCleanups = [];
    const homes = [];
    const actions = new Set([
      'sendIntervention', 'confirmAbort', 'toggleManualPayload', 'sendManualPayload',
      'switchCenterTab', 'smOnSearch', 'smSetMode', 'smExpandAll', 'smZoom', 'smResetView',
      'sendCrawlReview', 'openCrawlReviewDetails', 'openManualCrawlFromReview',
      'renderCrawlReviewList', 'confirmPlan', 'filterFindings', 'showNetTab',
      'togglePayloadExpand', 'openLightbox', '_smHidePopover', 'openScenarioBuilder',
      'scnAddStep', 'scnLoadLoginTemplate', 'scnCloseBuilder', 'scnSaveBuilder',
      'scnSetField', 'scnChangeAction', 'scnMoveStep', 'scnDuplicateStep', 'scnDeleteStep',
      'scnPalFill', 'scnPalAddForm', 'scnPalNavigate', 'scnDeleteFlow',
      'rerunLastScan', 'openManualCrawlAfterScan',
    ]);

    // 親 document を検索しない。Monitor root と既存設定 document だけを参照する。
    const scopedDocument = new Proxy(legacyDocument, {
      get(target, key) {
        if (key === 'getElementById') return id => (root && root.getElementById(id)) || target.getElementById(id);
        if (key === 'querySelector') return selector => (root && root.querySelector(selector)) || target.querySelector(selector);
        if (key === 'querySelectorAll') return selector => root
          ? [...root.querySelectorAll(selector), ...target.querySelectorAll(selector)]
          : target.querySelectorAll(selector);
        if (key === 'body' && root) return root;
        const value = Reflect.get(target, key, target);
        return typeof value === 'function' ? value.bind(target) : value;
      },
    });

    function canSend() {
      // legacy /monitor は従来どおり直接操作できる。一度 /app へ移植した後は、
      // unmount 済みの旧要素から操作イベントが発火しても送信しない。
      if (!hasMounted) return true;
      if (!host || host.hidden) return false;
      // scan 指定なしのライブ画面は現行 WS のみを操作する。scan 指定時だけ
      // 選択中の server/run/scan identity を固定して、取り違え送信を防ぐ。
      return !selectedScan || sameIdentity(expected, context());
    }

    // 既存テンプレートの単純な操作式だけを解釈する。別 document で inline JS を実行しない。
    function onAction(event) {
      const attr = 'on' + event.type;
      const element = event.composedPath().find(node => node.getAttribute && node.hasAttribute(attr));
      if (!element || element.getRootNode() !== root) return;
      const expression = element.getAttribute(attr).trim();
      event.stopImmediatePropagation();
      if (event.type === 'click') event.preventDefault();
      if (element.classList.contains('btn-show-shot')) {
        const image = element.nextElementSibling;
        image.src = element.dataset.src;
        image.style.display = 'block';
        element.style.display = 'none';
        return;
      }
      const close = expression.match(/^document\.getElementById\('([\w-]+)'\)\.(style\.display='none'|classList\.remove\('active'\)|remove\(\))$/);
      if (close) {
        const node = root.getElementById(close[1]);
        if (node) {
          if (close[2].startsWith('style')) node.style.display = 'none';
          else if (close[2].startsWith('classList')) node.classList.remove('active');
          else node.remove();
        }
        return;
      }
      if (expression === "this.classList.remove('active')") {
        element.classList.remove('active');
        return;
      }
      if (expression === "document.getElementById('scanConfigOverlay').classList.add('active')") {
        host.ownerDocument.defaultView.location.hash = '/setup';
        return;
      }
      const call = expression.match(/^(\w+)\((.*)\)$/s);
      if (!call || !actions.has(call[1])) return;
      const tokens = call[2].trim() ? call[2].match(/'[^']*'|"[^"]*"|[^,\s]+/g) : [];
      const args = [];
      for (const token of tokens) {
        if (/^(['"]).*\1$/s.test(token)) args.push(token.slice(1, -1));
        else if (/^-?\d+(?:\.\d+)?$/.test(token)) args.push(Number(token));
        else if (token === 'true' || token === 'false') args.push(token === 'true');
        else if (token === 'this') args.push(element);
        else if (token === 'this.value') args.push(element.value);
        else if (token === 'this.src') args.push(element.src);
        else return;
      }
      global[call[1]](...args);
      if (['openManualCrawlFromReview', 'openManualCrawlAfterScan'].includes(call[1])) {
        host.ownerDocument.defaultView.location.hash = '/setup';
      }
    }

    function setupPaneLayout(shadowRoot) {
      const main = shadowRoot.querySelector('.main');
      if (!main) return;
      const panels = main.querySelectorAll(':scope > .panel');
      if (panels.length < 3) return;

      const panelLeft = panels[0];
      const panelCenter = panels[1];
      const panelRight = panels[2];
      const storage = (host && host.ownerDocument && host.ownerDocument.defaultView && host.ownerDocument.defaultView.localStorage) ||
        (typeof localStorage !== 'undefined' ? localStorage : null);

      let currentLayout = loadPreferences(storage);

      // Create separators
      const sepLeft = legacyDocument.createElement('div');
      sepLeft.className = 'pane-separator';
      sepLeft.id = 'sepLeft';
      sepLeft.setAttribute('role', 'separator');
      sepLeft.setAttribute('tabindex', '0');
      sepLeft.setAttribute('aria-orientation', 'vertical');
      sepLeft.setAttribute('aria-label', 'ログペインの幅を調整');

      const sepRight = legacyDocument.createElement('div');
      sepRight.className = 'pane-separator';
      sepRight.id = 'sepRight';
      sepRight.setAttribute('role', 'separator');
      sepRight.setAttribute('tabindex', '0');
      sepRight.setAttribute('aria-orientation', 'vertical');
      sepRight.setAttribute('aria-label', '検出ペインの幅を調整');

      main.insertBefore(sepLeft, panelCenter);
      main.insertBefore(sepRight, panelRight);

      // Create collapsed bars
      function makeCollapsedBar(paneName, titleText) {
        const bar = legacyDocument.createElement('div');
        bar.className = 'pane-collapsed-bar';
        bar.setAttribute('role', 'button');
        bar.setAttribute('tabindex', '0');
        bar.setAttribute('data-pane', paneName);
        bar.setAttribute('aria-label', `${titleText} を展開`);
        bar.setAttribute('title', `${titleText} を展開`);
        bar.innerHTML = `<button type="button" class="pane-header-btn" data-action="expand" data-pane="${paneName}" aria-label="${titleText} を展開" title="展開">▸</button><span class="pane-collapsed-title">${titleText}</span>`;
        return bar;
      }

      const leftBar = makeCollapsedBar('left', 'Event Log');
      const centerBar = makeCollapsedBar('center', 'Scan Workspace');
      const rightBar = makeCollapsedBar('right', 'Findings');

      panelLeft.prepend(leftBar);
      panelCenter.prepend(centerBar);
      panelRight.prepend(rightBar);

      // Create pane header action buttons
      function makeHeaderActions(paneName, titleText) {
        const group = legacyDocument.createElement('div');
        group.className = 'pane-header-actions';
        group.innerHTML = `<button type="button" class="pane-header-btn btn-collapse" data-action="collapse" data-pane="${paneName}" aria-label="${titleText} を折りたたむ" aria-expanded="true" title="折りたたむ">▾</button><button type="button" class="pane-header-btn btn-maximize" data-action="maximize" data-pane="${paneName}" aria-label="${titleText} を最大化" title="最大化">⤢</button>`;
        return group;
      }

      const leftHdr = panelLeft.querySelector('.panel-header');
      const centerHdr = panelCenter.querySelector('.panel-header');
      const rightHdr = panelRight.querySelector('.panel-header');

      const leftActions = makeHeaderActions('left', 'Event Log');
      const centerActions = makeHeaderActions('center', 'Scan Workspace');
      const rightActions = makeHeaderActions('right', 'Findings');

      if (leftHdr) leftHdr.appendChild(leftActions);
      if (centerHdr) centerHdr.appendChild(centerActions);
      if (rightHdr) rightHdr.appendChild(rightActions);

      // Create layout toolbar
      const layoutToolbar = legacyDocument.createElement('div');
      layoutToolbar.className = 'monitor-layout-toolbar';
      layoutToolbar.setAttribute('role', 'toolbar');
      layoutToolbar.setAttribute('aria-label', 'レイアウトプリセット');
      layoutToolbar.innerHTML = '<button type="button" class="layout-preset-btn active" data-preset="standard" title="標準レイアウト">標準</button><button type="button" class="layout-preset-btn" data-preset="browser-focused" title="ブラウザ優先レイアウト">ブラウザ</button><button type="button" class="layout-preset-btn" data-preset="log-focused" title="ログ優先レイアウト">ログ</button>';

      const headerTitle = shadowRoot.querySelector('#headerTitle');
      if (headerTitle && headerTitle.parentNode) {
        headerTitle.parentNode.insertBefore(layoutToolbar, headerTitle.nextSibling);
      }

      function applyLayout(layout) {
        const containerW = (main && main.getBoundingClientRect().width) || 1000;
        const dims = computePaneDimensions(layout, containerW);

        for (const btn of layoutToolbar.querySelectorAll('.layout-preset-btn')) {
          btn.classList.toggle('active', btn.dataset.preset === layout.preset);
        }

        if (dims.left.maximized) {
          panelLeft.style.display = 'flex';
          panelLeft.style.width = '100%';
          panelLeft.style.flex = '1 1 100%';
          panelLeft.classList.remove('is-collapsed');
          panelLeft.classList.add('is-maximized');
        } else if (dims.left.visible) {
          panelLeft.style.display = 'flex';
          if (dims.left.collapsed) {
            panelLeft.style.width = '36px';
            panelLeft.style.flex = '0 0 36px';
            panelLeft.classList.add('is-collapsed');
            panelLeft.classList.remove('is-maximized');
          } else {
            panelLeft.style.width = dims.left.width + 'px';
            panelLeft.style.flex = '0 0 ' + dims.left.width + 'px';
            panelLeft.classList.remove('is-collapsed', 'is-maximized');
          }
        } else {
          panelLeft.style.display = 'none';
        }

        if (dims.center.maximized) {
          panelCenter.style.display = 'flex';
          panelCenter.style.width = '100%';
          panelCenter.style.flex = '1 1 100%';
          panelCenter.classList.remove('is-collapsed');
          panelCenter.classList.add('is-maximized');
        } else if (dims.center.visible) {
          panelCenter.style.display = 'flex';
          if (dims.center.collapsed) {
            panelCenter.style.width = '36px';
            panelCenter.style.flex = '0 0 36px';
            panelCenter.classList.add('is-collapsed');
            panelCenter.classList.remove('is-maximized');
          } else {
            panelCenter.style.width = 'auto';
            panelCenter.style.flex = '1 1 0';
            panelCenter.style.minWidth = '200px';
            panelCenter.classList.remove('is-collapsed', 'is-maximized');
          }
        } else {
          panelCenter.style.display = 'none';
        }

        if (dims.right.maximized) {
          panelRight.style.display = 'grid';
          panelRight.style.width = '100%';
          panelRight.style.flex = '1 1 100%';
          panelRight.classList.remove('is-collapsed');
          panelRight.classList.add('is-maximized');
        } else if (dims.right.visible) {
          if (dims.right.collapsed) {
            panelRight.style.display = 'flex';
            panelRight.style.width = '36px';
            panelRight.style.flex = '0 0 36px';
            panelRight.classList.add('is-collapsed');
            panelRight.classList.remove('is-maximized');
          } else {
            panelRight.style.display = 'grid';
            panelRight.style.width = dims.right.width + 'px';
            panelRight.style.flex = '0 0 ' + dims.right.width + 'px';
            panelRight.classList.remove('is-collapsed', 'is-maximized');
          }
        } else {
          panelRight.style.display = 'none';
        }

        sepLeft.style.display = dims.sepLeft.visible ? 'flex' : 'none';
        sepLeft.setAttribute('aria-valuenow', String(dims.sepLeft.valueNow));
        sepLeft.setAttribute('aria-valuemin', String(dims.sepLeft.valueMin));
        sepLeft.setAttribute('aria-valuemax', String(dims.sepLeft.valueMax));

        sepRight.style.display = dims.sepRight.visible ? 'flex' : 'none';
        sepRight.setAttribute('aria-valuenow', String(dims.sepRight.valueNow));
        sepRight.setAttribute('aria-valuemin', String(dims.sepRight.valueMin));
        sepRight.setAttribute('aria-valuemax', String(dims.sepRight.valueMax));

        const updateBtnStates = (actionsEl, pane, labelText) => {
          if (!actionsEl) return;
          const colBtn = actionsEl.querySelector('.btn-collapse');
          if (colBtn) {
            const isCol = Boolean(layout.collapsed[pane]);
            colBtn.setAttribute('aria-expanded', String(!isCol));
            colBtn.setAttribute('aria-label', isCol ? `${labelText} を展開` : `${labelText} を折りたたむ`);
            colBtn.title = isCol ? '展開' : '折りたたむ';
            colBtn.textContent = isCol ? '▸' : '▾';
          }
          const maxBtn = actionsEl.querySelector('.btn-maximize');
          if (maxBtn) {
            const isMax = layout.maximized === pane;
            maxBtn.classList.toggle('active', isMax);
            maxBtn.setAttribute('aria-label', isMax ? '元に戻す' : `${labelText} を最大化`);
            maxBtn.title = isMax ? '元に戻す' : '最大化';
            maxBtn.textContent = isMax ? '🗗' : '⤢';
          }
        };

        updateBtnStates(leftActions, 'left', 'Event Log');
        updateBtnStates(centerActions, 'center', 'Scan Workspace');
        updateBtnStates(rightActions, 'right', 'Findings');
      }

      function setPreset(name) {
        currentLayout = applyPreset(name, currentLayout);
        if (name === 'browser-focused') {
          const browserTab = shadowRoot.querySelector('#ctab-browser');
          if (browserTab) {
            if (typeof global.switchCenterTab === 'function') {
              global.switchCenterTab('browser', browserTab);
            } else {
              browserTab.click();
            }
          }
        }
        applyLayout(currentLayout);
        savePreferences(storage, currentLayout);
      }

      function toggleCollapse(pane) {
        currentLayout = togglePaneCollapse(currentLayout, pane);
        applyLayout(currentLayout);
        savePreferences(storage, currentLayout);
      }

      function toggleMaximize(pane) {
        currentLayout = togglePaneMaximize(currentLayout, pane);
        applyLayout(currentLayout);
        savePreferences(storage, currentLayout);
      }

      function onToolbarClick(event) {
        const btn = event.target.closest('.layout-preset-btn');
        if (!btn || !btn.dataset.preset) return;
        event.preventDefault();
        setPreset(btn.dataset.preset);
      }
      layoutToolbar.addEventListener('click', onToolbarClick);

      function onPanelHeaderClick(event) {
        const actionBtn = event.target.closest('.pane-header-btn');
        if (!actionBtn) return;
        const action = actionBtn.dataset.action;
        const pane = actionBtn.dataset.pane;
        if (!pane) return;
        event.preventDefault();
        event.stopPropagation();
        if (action === 'collapse' || action === 'expand') {
          toggleCollapse(pane);
        } else if (action === 'maximize') {
          toggleMaximize(pane);
        }
      }
      panelLeft.addEventListener('click', onPanelHeaderClick);
      panelCenter.addEventListener('click', onPanelHeaderClick);
      panelRight.addEventListener('click', onPanelHeaderClick);

      function onCollapsedBarClick(event) {
        const bar = event.currentTarget;
        const pane = bar.dataset.pane;
        if (!pane) return;
        event.preventDefault();
        toggleCollapse(pane);
      }
      function onCollapsedBarKey(event) {
        if (event.key === 'Enter' || event.key === ' ') {
          event.preventDefault();
          const pane = event.currentTarget.dataset.pane;
          if (pane) toggleCollapse(pane);
        }
      }
      for (const bar of [leftBar, centerBar, rightBar]) {
        bar.addEventListener('click', onCollapsedBarClick);
        bar.addEventListener('keydown', onCollapsedBarKey);
      }

      function bindSeparatorDrag(sep, sepIndex) {
        function onPointerDown(e) {
          if (e.button !== 0) return;
          e.preventDefault();
          try { sep.setPointerCapture(e.pointerId); } catch (_) {}
          sep.classList.add('is-active');
          main.classList.add('is-resizing');

          const startX = e.clientX;
          const startLeft = currentLayout.leftWidth;
          const startRight = currentLayout.rightWidth;
          const containerW = (main && main.getBoundingClientRect().width) || 1000;

          function onPointerMove(moveEvent) {
            const delta = moveEvent.clientX - startX;
            if (sepIndex === 0) {
              const maxW = Math.min(LAYOUT_BOUNDS.left.max, Math.max(LAYOUT_BOUNDS.left.min, containerW - LAYOUT_BOUNDS.minCenter - (currentLayout.collapsed.right ? 36 : currentLayout.rightWidth)));
              currentLayout.leftWidth = Math.min(Math.max(startLeft + delta, LAYOUT_BOUNDS.left.min), maxW);
            } else {
              const maxW = Math.min(LAYOUT_BOUNDS.right.max, Math.max(LAYOUT_BOUNDS.right.min, containerW - LAYOUT_BOUNDS.minCenter - (currentLayout.collapsed.left ? 36 : currentLayout.leftWidth)));
              currentLayout.rightWidth = Math.min(Math.max(startRight - delta, LAYOUT_BOUNDS.right.min), maxW);
            }
            currentLayout.preset = 'custom';
            applyLayout(currentLayout);
          }

          function onPointerUp(upEvent) {
            try { sep.releasePointerCapture(upEvent.pointerId); } catch (_) {}
            sep.classList.remove('is-active');
            main.classList.remove('is-resizing');
            sep.removeEventListener('pointermove', onPointerMove);
            sep.removeEventListener('pointerup', onPointerUp);
            sep.removeEventListener('pointercancel', onPointerUp);
            savePreferences(storage, currentLayout);
          }

          sep.addEventListener('pointermove', onPointerMove);
          sep.addEventListener('pointerup', onPointerUp);
          sep.addEventListener('pointercancel', onPointerUp);
        }

        function onKeyDown(e) {
          if (!['ArrowLeft', 'ArrowRight', 'Home', 'End'].includes(e.key)) return;
          e.preventDefault();
          const containerW = (main && main.getBoundingClientRect().width) || 1000;
          if (sepIndex === 0) {
            const maxW = Math.min(LAYOUT_BOUNDS.left.max, Math.max(LAYOUT_BOUNDS.left.min, containerW - LAYOUT_BOUNDS.minCenter - (currentLayout.collapsed.right ? 36 : currentLayout.rightWidth)));
            currentLayout.leftWidth = applySeparatorKey(currentLayout.leftWidth, e.key, {
              min: LAYOUT_BOUNDS.left.min,
              max: maxW,
              step: 20,
              invert: false,
            });
          } else {
            const maxW = Math.min(LAYOUT_BOUNDS.right.max, Math.max(LAYOUT_BOUNDS.right.min, containerW - LAYOUT_BOUNDS.minCenter - (currentLayout.collapsed.left ? 36 : currentLayout.leftWidth)));
            currentLayout.rightWidth = applySeparatorKey(currentLayout.rightWidth, e.key, {
              min: LAYOUT_BOUNDS.right.min,
              max: maxW,
              step: 20,
              invert: true,
            });
          }
          currentLayout.preset = 'custom';
          applyLayout(currentLayout);
          savePreferences(storage, currentLayout);
        }

        sep.addEventListener('pointerdown', onPointerDown);
        sep.addEventListener('keydown', onKeyDown);
      }

      bindSeparatorDrag(sepLeft, 0);
      bindSeparatorDrag(sepRight, 1);

      function onWindowResize() {
        applyLayout(currentLayout);
      }
      const win = host.ownerDocument.defaultView || global;
      if (win && win.addEventListener) {
        win.addEventListener('resize', onWindowResize);
      }

      layoutCleanups.push(() => {
        if (win && win.removeEventListener) {
          win.removeEventListener('resize', onWindowResize);
        }
        sepLeft.remove();
        sepRight.remove();
        leftBar.remove();
        centerBar.remove();
        rightBar.remove();
        leftActions.remove();
        centerActions.remove();
        rightActions.remove();
        layoutToolbar.remove();
        panelLeft.style.width = '';
        panelLeft.style.flex = '';
        panelLeft.style.display = '';
        panelLeft.classList.remove('is-collapsed', 'is-maximized');
        panelCenter.style.width = '';
        panelCenter.style.flex = '';
        panelCenter.style.minWidth = '';
        panelCenter.style.display = '';
        panelCenter.classList.remove('is-collapsed', 'is-maximized');
        panelRight.style.width = '';
        panelRight.style.flex = '';
        panelRight.style.display = '';
        panelRight.classList.remove('is-collapsed', 'is-maximized');
      });

      applyLayout(currentLayout);
    }

    function unmount() {
      if (!host) return;
      for (const cleanup of layoutCleanups) {
        try { cleanup(); } catch (_) {}
      }
      layoutCleanups = [];
      for (const type of ['click', 'input', 'change']) root.removeEventListener(type, onAction, true);
      for (const { node, marker } of homes) marker.replaceWith(node);
      homes.length = 0;
      root.replaceChildren();
      host.hidden = true;
      root = null;
      host = null;
      expected = null;
      selectedScan = null;
    }

    function mount(target, options = {}) {
      unmount();
      host = target;
      hasMounted = true;
      root = target.shadowRoot || target.attachShadow({ mode: 'open' });
      context = options.getContext;
      selectedScan = options.scanId || null;
      expected = context();
      // 同じ DOM を移すので、レビュー編集中の値、カード参照、map のイベント購読を保持する。
      for (const style of legacyDocument.querySelectorAll('head style, head link[rel=stylesheet]')) {
        root.appendChild(style.cloneNode(true));
      }
      const style = legacyDocument.createElement('style');
      style.textContent = `
:host {
  display: flex;
  flex-direction: column;
  height: calc(100vh - 58px);
  font: 13px system-ui;
  color: var(--text);
  overflow: hidden;
}
.hdr-view-toggle { display: none; }
.main {
  display: flex !important;
  flex-direction: row !important;
  flex: 1 1 0 !important;
  min-height: 0 !important;
  overflow: hidden !important;
  position: relative !important;
}
.main.is-resizing {
  user-select: none !important;
}
.panel {
  min-height: 0;
  min-width: 0;
  overflow: hidden;
  position: relative;
  transition: width 0.12s ease, flex 0.12s ease;
}
.main.is-resizing .panel {
  transition: none !important;
}
.panel.is-collapsed {
  width: 36px !important;
  min-width: 36px !important;
  max-width: 36px !important;
  flex: 0 0 36px !important;
  display: flex !important;
  flex-direction: column !important;
}
.panel.is-collapsed > *:not(.pane-collapsed-bar) {
  display: none !important;
}
.pane-collapsed-bar {
  display: none;
  width: 36px;
  height: 100%;
  flex-direction: column;
  align-items: center;
  justify-content: flex-start;
  padding: 10px 4px;
  background: var(--surface);
  border-right: 1px solid var(--border);
  cursor: pointer;
  user-select: none;
  gap: 8px;
  box-sizing: border-box;
}
.panel.is-collapsed .pane-collapsed-bar {
  display: flex !important;
}
.pane-collapsed-bar:hover, .pane-collapsed-bar:focus-visible {
  background: var(--surface2);
}
.pane-collapsed-bar:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -2px;
}
.pane-collapsed-title {
  writing-mode: vertical-rl;
  transform: rotate(180deg);
  font-size: 0.76rem;
  font-weight: 600;
  color: var(--text-muted);
  letter-spacing: 0.05em;
  white-space: nowrap;
  margin-top: 8px;
}
.panel.is-maximized {
  width: 100% !important;
  min-width: 100% !important;
  max-width: 100% !important;
  flex: 1 1 100% !important;
  z-index: 10;
}
.pane-separator {
  width: 6px;
  flex: 0 0 6px;
  background: var(--surface);
  border-left: 1px solid var(--border);
  border-right: 1px solid var(--border);
  cursor: col-resize;
  display: flex;
  align-items: center;
  justify-content: center;
  touch-action: none;
  user-select: none;
  z-index: 5;
  outline: none;
  box-sizing: border-box;
}
.pane-separator::after {
  content: '';
  width: 2px;
  height: 24px;
  border-radius: 1px;
  background: var(--text-muted);
  opacity: 0.4;
}
.pane-separator:hover, .pane-separator:focus-visible, .pane-separator.is-active {
  background: var(--surface2);
}
.pane-separator:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: -1px;
}
.pane-separator:hover::after, .pane-separator:focus-visible::after, .pane-separator.is-active::after {
  background: var(--accent);
  opacity: 1;
}
.pane-header-actions {
  display: inline-flex;
  align-items: center;
  gap: 4px;
  margin-left: auto;
}
.pane-header-btn {
  background: transparent;
  border: 1px solid transparent;
  color: var(--text-muted);
  border-radius: 4px;
  width: 20px;
  height: 20px;
  padding: 0;
  display: inline-flex;
  align-items: center;
  justify-content: center;
  cursor: pointer;
  font-size: 11px;
  line-height: 1;
}
.pane-header-btn:hover {
  background: var(--surface2);
  color: var(--text);
  border-color: var(--border);
}
.pane-header-btn:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}
.pane-header-btn.active {
  color: var(--accent);
  background: var(--surface2);
  border-color: var(--accent);
}
.monitor-layout-toolbar {
  display: inline-flex;
  align-items: center;
  gap: 3px;
  background: var(--surface2);
  border: 1px solid var(--border);
  border-radius: 6px;
  padding: 2px;
  margin-left: 12px;
}
.layout-preset-btn {
  background: transparent;
  border: none;
  color: var(--text-muted);
  border-radius: 4px;
  padding: 3px 8px;
  font-size: 0.72rem;
  font-weight: 600;
  cursor: pointer;
}
.layout-preset-btn:hover {
  color: var(--text);
}
.layout-preset-btn.active {
  background: var(--surface);
  color: var(--text);
  box-shadow: 0 1px 2px rgba(0,0,0,0.25);
}
.layout-preset-btn:focus-visible {
  outline: 2px solid var(--accent);
  outline-offset: 1px;
}
@media (max-width: 767px) {
  .main {
    flex-direction: column !important;
    overflow-y: auto !important;
  }
  .pane-separator {
    display: none !important;
  }
  .panel {
    width: 100% !important;
    min-width: 0 !important;
    max-width: none !important;
    flex: none !important;
    border-right: none !important;
    border-bottom: 1px solid var(--border) !important;
  }
  .panel.is-collapsed {
    display: none !important;
  }
  .panel.is-maximized {
    width: 100% !important;
    min-width: 0 !important;
    flex: none !important;
  }
  .pane-header-actions {
    display: none !important;
  }
  .monitor-layout-toolbar {
    display: none !important;
  }
}
`;
      root.appendChild(style);
      for (const selector of ['.header', '#viewLiveMonitor', '#planModalOverlay', '#crawlReviewOverlay', '#scenarioBuilderOverlay', '#lightbox']) {
        const node = legacyDocument.querySelector(selector);
        if (!node) continue;
        const marker = legacyDocument.createComment('Monitor module');
        node.replaceWith(marker);
        homes.push({ node, marker });
        root.appendChild(node);
      }
      setupPaneLayout(root);
      for (const type of ['click', 'input', 'change']) root.addEventListener(type, onAction, true);
      host.hidden = false;
    }

    function updateContext() {
      if (!host || selectedScan) return;
      expected = context();
    }

    return { document: scopedDocument, mount, unmount, canSend, updateContext };
  }

  const monitorModuleExport = {
    createMonitorModule,
    sameIdentity,
    DEFAULT_LAYOUT,
    PRESETS,
    LAYOUT_BOUNDS,
    STORAGE_KEY,
    validateLayoutPreferences,
    parseLayoutPreferences,
    loadPreferences,
    savePreferences,
    applySeparatorKey,
    applyPreset,
    togglePaneCollapse,
    togglePaneMaximize,
    computePaneDimensions,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = monitorModuleExport;
  }
  if (global) {
    global.VulixMonitorModule = monitorModuleExport;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
