/* Monitor の表示 root とライフサイクル。WS と scan 状態は既存 owner に一元化する。 */
(function (global) {
  'use strict';

  const sameIdentity = (a, b) => a && b && ['server_id', 'run_id', 'scan_id']
    .every(key => typeof a[key] === 'string' && a[key] && a[key] === b[key]);

  function createMonitorModule(legacyDocument) {
    let root = null;
    let host = null;
    let expected = null;
    let selectedScan = null;
    let context = () => null;
    let hasMounted = false;
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
      // U12 の server/run/scan identity を固定して、取り違え送信を防ぐ。
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

    function unmount() {
      if (!host) return;
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
      style.textContent = ':host{display:flex;flex-direction:column;height:calc(100vh - 58px);font:13px system-ui;color:var(--text);overflow:hidden}.hdr-view-toggle{display:none}';
      root.appendChild(style);
      for (const selector of ['.header', '#viewLiveMonitor', '#planModalOverlay', '#crawlReviewOverlay', '#scenarioBuilderOverlay', '#lightbox']) {
        const node = legacyDocument.querySelector(selector);
        if (!node) continue;
        const marker = legacyDocument.createComment('Monitor module');
        node.replaceWith(marker);
        homes.push({ node, marker });
        root.appendChild(node);
      }
      for (const type of ['click', 'input', 'change']) root.addEventListener(type, onAction, true);
      host.hidden = false;
    }

    function updateContext() {
      if (!host || selectedScan) return;
      expected = context();
    }

    return { document: scopedDocument, mount, unmount, canSend, updateContext };
  }

  global.VulixMonitorModule = { createMonitorModule, sameIdentity };
})(window);
