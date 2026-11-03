/**
 * crawl-module.js — Independent Crawl screen module for Vulix /app shell
 *
 * Provides a read-only, reload-safe, scan-selected crawl graph viewer using
 * native SVG (no graphing library) with zoom, search, list, and explorer views.
 *
 * INVARIANTS:
 * - Read-only snapshot projection from API (/api/v1/scan/crawl-graph or /api/v1/scans/{id}/crawl-graph).
 * - Completeness (complete/partial/unknown) is displayed prominently; partial/unknown is never presented as complete.
 * - Missing node references (actions, inputs, findings) are shown as unavailable, never invented.
 * - Links to findings use plain text IDs (or /app findings deep link if present).
 * - All strings rendered via textContent; URLs displayed as returned (already redacted by API).
 * - Legacy sitemap view in / dashboard remains untouched.
 */
(function (global) {
  'use strict';

  const SCHEMA_VERSION = '1.0.0';
  const SVG_NS = 'http://www.w3.org/2000/svg';

  const KIND_LABELS = {
    page: 'ページ',
    form: 'フォーム',
    param: 'パラメータ',
    unknown: '不明',
  };

  const KIND_COLORS = {
    page: '#9184d9',
    form: '#d99a63',
    param: '#8fb9c9',
    unknown: '#9397ab',
  };

  const REASON_LABELS = {
    scan_in_progress: 'スキャン実行中（クロール未完了）',
    scan_aborted: 'スキャン中断',
    scan_error: 'スキャンエラー',
    scan_gaps_present: '未検査ギャップあり（到達不能/除外URL）',
    unscannable_urls_present: '検査不能URLあり',
    truncation_detected: '巡回上限到達による切り詰めあり',
    empty_scan: '巡回ノードなし（空スキャン）',
    scan_idle: 'スキャン未実行',
    scan_completed: 'スキャン完了',
    status_unknown: '状態不明',
  };

  /**
   * Format completeness status and human-readable reasons.
   * Guarantees: partial or unknown is never presented as complete.
   *
   * @param {string} rawCompleteness
   * @param {Array<string>} [rawReasons]
   * @returns {{ completeness: string, isComplete: boolean, badgeText: string, badgeClass: string, reasons: Array<string>, summaryText: string }}
   */
  function formatCompleteness(rawCompleteness, rawReasons) {
    const norm = String(rawCompleteness || '').trim().toLowerCase();
    const isComplete = norm === 'complete';
    const isPartial = norm === 'partial';

    const reasonsList = Array.isArray(rawReasons)
      ? rawReasons.map((r) => String(r || '').trim()).filter((r) => r.length > 0)
      : [];

    const translatedReasons = reasonsList.map((r) => REASON_LABELS[r] || r);

    if (isComplete) {
      return {
        completeness: 'complete',
        isComplete: true,
        badgeText: '完全 (Complete)',
        badgeClass: 'crawl-badge-complete',
        reasons: translatedReasons.length > 0 ? translatedReasons : ['すべての巡回が完了しています'],
        summaryText: 'すべての巡回が完了し、欠落や切り詰めはありません。',
      };
    }

    if (isPartial) {
      return {
        completeness: 'partial',
        isComplete: false,
        badgeText: '一部のみ (Partial)',
        badgeClass: 'crawl-badge-partial',
        reasons: translatedReasons.length > 0 ? translatedReasons : ['巡回が一部のみ完了しています'],
        summaryText: 'スキャンの進行、中断、切り詰め、または未検査ギャップにより、クロール結果は完全ではありません。',
      };
    }

    return {
      completeness: 'unknown',
      isComplete: false,
      badgeText: '未確定 (Unknown)',
      badgeClass: 'crawl-badge-unknown',
      reasons: translatedReasons.length > 0 ? translatedReasons : ['完全性を判定できません'],
      summaryText: 'スキャンが未開始、空、またはステータス不明のため、完全性は判定されていません。',
    };
  }

  /**
   * Normalize and format node details with explicit missing-reference fallbacks.
   * Never synthesizes or invents fake actions, inputs, or findings.
   *
   * @param {Object} rawNode
   * @returns {Object} Normalized node detail structure
   */
  function formatNodeDetail(rawNode) {
    const node = rawNode && typeof rawNode === 'object' ? rawNode : {};
    const id = String(node.id || 'unknown');
    const kind = String(node.kind || 'unknown').toLowerCase();
    const url = String(node.url || '');
    const label = String(node.label || node.url || id);
    const parentId = node.parent_id ? String(node.parent_id) : null;

    const actions = Array.isArray(node.actions) ? node.actions.filter((a) => a && typeof a === 'object') : [];
    const inputs = Array.isArray(node.inputs) ? node.inputs.filter((i) => i && typeof i === 'object') : [];
    const findings = Array.isArray(node.findings) ? node.findings.filter((f) => f && typeof f === 'object') : [];
    const metadata = node.metadata && typeof node.metadata === 'object' ? Object.assign({}, node.metadata) : {};

    return {
      id: id,
      kind: KIND_LABELS[kind] ? kind : 'unknown',
      kindLabel: KIND_LABELS[kind] || kind,
      url: url,
      label: label,
      parentId: parentId,
      actions: actions,
      hasActions: actions.length > 0,
      actionsUnavailableText: '利用可能なアクションなし (unavailable)',
      inputs: inputs,
      hasInputs: inputs.length > 0,
      inputsUnavailableText: '入力/パラメータなし (unavailable)',
      findings: findings,
      hasFindings: findings.length > 0,
      findingsUnavailableText: '関連する検出事項なし (0 findings)',
      metadata: metadata,
    };
  }

  /**
   * Pure search function across nodes.
   *
   * @param {Array<Object>} nodes
   * @param {string} query
   * @returns {Array<Object>}
   */
  function searchNodes(nodes, query) {
    if (!Array.isArray(nodes)) return [];
    const q = String(query || '').trim().toLowerCase();
    if (!q) return [...nodes];

    return nodes.filter((n) => {
      if (!n || typeof n !== 'object') return false;
      const url = String(n.url || '').toLowerCase();
      const label = String(n.label || '').toLowerCase();
      const id = String(n.id || '').toLowerCase();
      const kind = String(n.kind || '').toLowerCase();
      if (url.includes(q) || label.includes(q) || id.includes(q) || kind.includes(q)) return true;

      if (Array.isArray(n.inputs)) {
        for (const input of n.inputs) {
          if (input && String(input.name || '').toLowerCase().includes(q)) return true;
        }
      }
      if (Array.isArray(n.actions)) {
        for (const act of n.actions) {
          if (act && (String(act.action || '').toLowerCase().includes(q) || String(act.method || '').toLowerCase().includes(q))) return true;
        }
      }
      if (Array.isArray(n.findings)) {
        for (const f of n.findings) {
          if (f && (String(f.id || '').toLowerCase().includes(q) || String(f.check_type || '').toLowerCase().includes(q) || String(f.field_name || '').toLowerCase().includes(q))) return true;
        }
      }
      return false;
    });
  }

  /**
   * Pure filter by node kind.
   *
   * @param {Array<Object>} nodes
   * @param {string} kind
   * @returns {Array<Object>}
   */
  function filterNodesByKind(nodes, kind) {
    if (!Array.isArray(nodes)) return [];
    const k = String(kind || '').trim().toLowerCase();
    if (!k || k === 'all') return [...nodes];
    return nodes.filter((n) => n && String(n.kind || '').toLowerCase() === k);
  }

  /**
   * Pure deterministic graph layout function (column-by-depth).
   *
   * @param {Array<Object>} nodes
   * @param {Array<Object>} edges
   * @param {Object} [options]
   * @returns {{ nodes: Array<Object>, edges: Array<Object>, width: number, height: number }}
   */
  function layoutGraph(nodes, edges, options = {}) {
    const safeNodes = Array.isArray(nodes) ? nodes : [];
    const safeEdges = Array.isArray(edges) ? edges : [];

    const colWidth = Number(options.colWidth) || 220;
    const rowHeight = Number(options.rowHeight) || 68;
    const nodeWidth = Number(options.nodeWidth) || 164;
    const nodeHeight = Number(options.nodeHeight) || 42;
    const padX = Number(options.padX) || 40;
    const padY = Number(options.padY) || 40;

    const byId = new Map();
    safeNodes.forEach((n) => {
      if (n && n.id) byId.set(n.id, n);
    });

    // Derive depths
    const depths = new Map();
    function computeDepth(nodeId, visited = new Set()) {
      if (depths.has(nodeId)) return depths.get(nodeId);
      if (visited.has(nodeId)) return 0; // cycle fallback
      visited.add(nodeId);

      const n = byId.get(nodeId);
      if (!n) return 0;

      if (n.metadata && typeof n.metadata.depth === 'number' && n.metadata.depth >= 0) {
        depths.set(nodeId, n.metadata.depth);
        return n.metadata.depth;
      }

      if (n.parent_id && byId.has(n.parent_id)) {
        const d = computeDepth(n.parent_id, visited) + 1;
        depths.set(nodeId, d);
        return d;
      }

      depths.set(nodeId, 0);
      return 0;
    }

    safeNodes.forEach((n) => {
      if (n && n.id) computeDepth(n.id);
    });

    // Group by depth
    const byDepth = new Map();
    safeNodes.forEach((n) => {
      if (!n || !n.id) return;
      const d = depths.get(n.id) || 0;
      if (!byDepth.has(d)) byDepth.set(d, []);
      byDepth.get(d).push(n);
    });

    const sortedDepths = Array.from(byDepth.keys()).sort((a, b) => a - b);
    let maxRows = 0;
    const layoutNodes = [];

    sortedDepths.forEach((d) => {
      const colNodes = byDepth.get(d);
      colNodes.sort((a, b) => {
        const ka = String(a.kind || '');
        const kb = String(b.kind || '');
        if (ka !== kb) return ka.localeCompare(kb);
        return String(a.label || a.url || a.id).localeCompare(String(b.label || b.url || b.id));
      });

      if (colNodes.length > maxRows) maxRows = colNodes.length;

      colNodes.forEach((n, i) => {
        const x = padX + d * colWidth;
        const y = padY + i * rowHeight;
        layoutNodes.push(
          Object.assign({}, n, {
            x: x,
            y: y,
            width: nodeWidth,
            height: nodeHeight,
            depth: d,
          })
        );
      });
    });

    const layoutById = new Map();
    layoutNodes.forEach((n) => layoutById.set(n.id, n));

    const layoutEdges = [];
    safeEdges.forEach((e) => {
      if (!e || !e.source || !e.target) return;
      const src = layoutById.get(e.source);
      const tgt = layoutById.get(e.target);
      if (!src || !tgt) return;

      const x1 = src.x + src.width;
      const y1 = src.y + src.height / 2;
      const x2 = tgt.x;
      const y2 = tgt.y + tgt.height / 2;
      const mx = (x1 + x2) / 2;
      const pathData = `M${x1},${y1} C${mx},${y1} ${mx},${y2} ${x2},${y2}`;

      layoutEdges.push({
        source: e.source,
        target: e.target,
        kind: e.kind || 'link',
        x1: x1,
        y1: y1,
        x2: x2,
        y2: y2,
        mx: mx,
        my: (y1 + y2) / 2,
        pathData: pathData,
      });
    });

    const totalWidth = Math.max(700, padX * 2 + sortedDepths.length * colWidth);
    const totalHeight = Math.max(480, padY * 2 + maxRows * rowHeight);

    return {
      nodes: layoutNodes,
      edges: layoutEdges,
      width: totalWidth,
      height: totalHeight,
    };
  }

  /**
   * Helper to safely create an SVG element.
   * @param {string} tag
   * @param {Object} [attrs]
   * @param {Object} [documentRef]
   */
  function createSvgElement(tag, attrs, documentRef) {
    const doc = documentRef || (typeof document !== 'undefined' ? document : null);
    if (!doc) return null;
    const el = doc.createElementNS(SVG_NS, tag);
    if (attrs) {
      for (const k in attrs) {
        if (Object.prototype.hasOwnProperty.call(attrs, k)) {
          el.setAttribute(k, attrs[k]);
        }
      }
    }
    return el;
  }

  /**
   * Builds the interactive Crawl View inside a container element.
   *
   * @param {HTMLElement} container
   * @param {Object} [options]
   */
  function renderCrawlView(container, options = {}) {
    const doc = options.document || (typeof document !== 'undefined' ? document : null);
    if (!doc || !container) return null;

    if (typeof container.replaceChildren === 'function') {
      container.replaceChildren();
    } else {
      while (container.firstChild) container.removeChild(container.firstChild);
    }

    const api = options.api;
    let initialScanId = options.scanId || null;
    let currentData = null;
    let currentMode = 'graph'; // 'graph' | 'explorer' | 'list'
    let currentKindFilter = 'all';
    let searchQuery = '';
    let selectedNodeId = null;

    let viewScale = 1.0;
    let viewTx = 0;
    let viewTy = 0;
    let isPanning = false;
    let panStartX = 0;
    let panStartY = 0;

    // Outer root wrapper
    const root = doc.createElement('div');
    root.className = 'crawl-module-root';

    // ── 1. Top Bar: Title, Completeness, Scans, View Modes, Zoom, Search ──
    const toolbar = doc.createElement('div');
    toolbar.className = 'crawl-toolbar';

    // Left group: Completeness Badge
    const statusGroup = doc.createElement('div');
    statusGroup.className = 'crawl-toolbar-group';

    const completenessBadge = doc.createElement('span');
    completenessBadge.className = 'crawl-badge crawl-badge-unknown';
    completenessBadge.textContent = '読み込み中...';
    completenessBadge.setAttribute('role', 'status');
    statusGroup.appendChild(completenessBadge);

    const reasonsTooltip = doc.createElement('span');
    reasonsTooltip.className = 'crawl-reasons-text';
    statusGroup.appendChild(reasonsTooltip);

    toolbar.appendChild(statusGroup);

    // Center group: Scan Selector & Refresh
    const scanGroup = doc.createElement('div');
    scanGroup.className = 'crawl-toolbar-group';

    const scanSelectLabel = doc.createElement('label');
    scanSelectLabel.className = 'crawl-label';
    scanSelectLabel.textContent = 'Scan:';
    scanGroup.appendChild(scanSelectLabel);

    const scanSelect = doc.createElement('select');
    scanSelect.className = 'crawl-select';
    scanSelect.setAttribute('aria-label', 'Scan selection');
    const optActive = doc.createElement('option');
    optActive.value = '';
    optActive.textContent = '現在のスキャン (Active)';
    scanSelect.appendChild(optActive);
    scanGroup.appendChild(scanSelect);

    const reloadBtn = doc.createElement('button');
    reloadBtn.type = 'button';
    reloadBtn.className = 'history-btn';
    reloadBtn.textContent = '更新';
    reloadBtn.title = 'クロールグラフを再読み込み';
    scanGroup.appendChild(reloadBtn);

    toolbar.appendChild(scanGroup);

    // Controls group: View Mode Buttons, Kind Filter, Search, Zoom
    const controlsGroup = doc.createElement('div');
    controlsGroup.className = 'crawl-toolbar-group crawl-toolbar-right';

    // Search input
    const searchWrap = doc.createElement('div');
    searchWrap.className = 'crawl-search-wrap';
    const searchInput = doc.createElement('input');
    searchInput.type = 'text';
    searchInput.className = 'crawl-search-input';
    searchInput.placeholder = 'URL, ラベル, パラメータで検索...';
    searchInput.setAttribute('aria-label', 'Crawl search query');
    searchWrap.appendChild(searchInput);
    controlsGroup.appendChild(searchWrap);

    // Kind filter
    const kindSelect = doc.createElement('select');
    kindSelect.className = 'crawl-select';
    kindSelect.setAttribute('aria-label', 'Filter by kind');
    [
      { id: 'all', text: 'すべての種別' },
      { id: 'page', text: 'Page のみ' },
      { id: 'form', text: 'Form のみ' },
      { id: 'param', text: 'Param のみ' },
      { id: 'unknown', text: 'Unknown のみ' },
    ].forEach((k) => {
      const opt = doc.createElement('option');
      opt.value = k.id;
      opt.textContent = k.text;
      kindSelect.appendChild(opt);
    });
    controlsGroup.appendChild(kindSelect);

    // View modes
    const modeBtnGraph = doc.createElement('button');
    modeBtnGraph.type = 'button';
    modeBtnGraph.className = 'history-btn active';
    modeBtnGraph.textContent = 'グラフ';
    modeBtnGraph.dataset.mode = 'graph';

    const modeBtnExplorer = doc.createElement('button');
    modeBtnExplorer.type = 'button';
    modeBtnExplorer.className = 'history-btn';
    modeBtnExplorer.textContent = 'ツリー (Explorer)';
    modeBtnExplorer.dataset.mode = 'explorer';

    const modeBtnList = doc.createElement('button');
    modeBtnList.type = 'button';
    modeBtnList.className = 'history-btn';
    modeBtnList.textContent = 'リスト';
    modeBtnList.dataset.mode = 'list';

    controlsGroup.appendChild(modeBtnGraph);
    controlsGroup.appendChild(modeBtnExplorer);
    controlsGroup.appendChild(modeBtnList);

    // Zoom buttons (for graph view)
    const zoomGroup = doc.createElement('div');
    zoomGroup.className = 'crawl-zoom-group';

    const zoomInBtn = doc.createElement('button');
    zoomInBtn.type = 'button';
    zoomInBtn.className = 'history-btn';
    zoomInBtn.textContent = '+';
    zoomInBtn.title = '拡大';

    const zoomOutBtn = doc.createElement('button');
    zoomOutBtn.type = 'button';
    zoomOutBtn.className = 'history-btn';
    zoomOutBtn.textContent = '−';
    zoomOutBtn.title = '縮小';

    const zoomResetBtn = doc.createElement('button');
    zoomResetBtn.type = 'button';
    zoomResetBtn.className = 'history-btn';
    zoomResetBtn.textContent = '100%';
    zoomResetBtn.title = '表示倍率リセット';

    zoomGroup.appendChild(zoomInBtn);
    zoomGroup.appendChild(zoomOutBtn);
    zoomGroup.appendChild(zoomResetBtn);
    controlsGroup.appendChild(zoomGroup);

    toolbar.appendChild(controlsGroup);
    root.appendChild(toolbar);

    // ── 2. Content Surfaces ──
    const contentArea = doc.createElement('div');
    contentArea.className = 'crawl-content-area';

    // Status / Message banner (empty, error, loading)
    const messageBanner = doc.createElement('div');
    messageBanner.className = 'crawl-message-banner';
    messageBanner.hidden = true;
    contentArea.appendChild(messageBanner);

    // Surface 1: Graph SVG Canvas
    const graphSurface = doc.createElement('div');
    graphSurface.className = 'crawl-graph-surface';

    const svgEl = createSvgElement('svg', {
      class: 'crawl-svg-canvas',
      width: '100%',
      height: '100%',
    }, doc);

    // Defs: markers
    const defs = createSvgElement('defs', {}, doc);
    const marker = createSvgElement('marker', {
      id: 'crawl-arr',
      viewBox: '0 -5 10 10',
      refX: '9',
      markerWidth: '7',
      markerHeight: '7',
      orient: 'auto',
    }, doc);
    const markerPath = createSvgElement('path', {
      d: 'M0,-5L10,0L0,5',
      fill: '#4a5568',
    }, doc);
    marker.appendChild(markerPath);
    defs.appendChild(marker);
    svgEl.appendChild(defs);

    const svgViewport = createSvgElement('g', { id: 'crawlSvgViewport' }, doc);
    svgEl.appendChild(svgViewport);
    graphSurface.appendChild(svgEl);

    // Surface 2: Explorer Surface (Left: Tree, Right: Inspector)
    const explorerSurface = doc.createElement('div');
    explorerSurface.className = 'crawl-explorer-surface';
    explorerSurface.hidden = true;

    const explorerTree = doc.createElement('div');
    explorerTree.className = 'crawl-explorer-tree';
    explorerTree.setAttribute('role', 'tree');
    explorerSurface.appendChild(explorerTree);

    const explorerDetail = doc.createElement('div');
    explorerDetail.className = 'crawl-explorer-detail';
    explorerSurface.appendChild(explorerDetail);

    // Surface 3: List Surface (Table)
    const listSurface = doc.createElement('div');
    listSurface.className = 'crawl-list-surface';
    listSurface.hidden = true;

    // Node Detail Drawer / Popover (for Graph and List modes)
    const detailDrawer = doc.createElement('div');
    detailDrawer.className = 'crawl-detail-drawer';
    detailDrawer.hidden = true;

    contentArea.appendChild(graphSurface);
    contentArea.appendChild(explorerSurface);
    contentArea.appendChild(listSurface);
    contentArea.appendChild(detailDrawer);
    root.appendChild(contentArea);
    container.appendChild(root);

    // ── Helper: Apply View Transform ──
    function applyTransform() {
      if (!svgViewport) return;
      svgViewport.setAttribute('transform', `translate(${viewTx},${viewTy}) scale(${viewScale})`);
    }

    // ── Helper: Switch Mode ──
    function setMode(mode) {
      currentMode = mode;
      [modeBtnGraph, modeBtnExplorer, modeBtnList].forEach((b) => {
        b.classList.toggle('active', b.dataset.mode === mode);
      });

      graphSurface.hidden = mode !== 'graph';
      explorerSurface.hidden = mode !== 'explorer';
      listSurface.hidden = mode !== 'list';
      zoomGroup.style.display = mode === 'graph' ? 'inline-flex' : 'none';

      if (mode === 'explorer') {
        detailDrawer.hidden = true;
      }
      renderActiveMode();
    }

    // ── Helper: Show Error / Empty / Loading ──
    function showBanner(type, message, actionText, onAction) {
      messageBanner.hidden = false;
      if (typeof messageBanner.replaceChildren === 'function') {
        messageBanner.replaceChildren();
      } else {
        while (messageBanner.firstChild) messageBanner.removeChild(messageBanner.firstChild);
      }
      messageBanner.className = `crawl-message-banner banner-${type}`;

      const text = doc.createElement('p');
      text.textContent = message;
      messageBanner.appendChild(text);

      if (actionText && typeof onAction === 'function') {
        const btn = doc.createElement('button');
        btn.type = 'button';
        btn.className = 'history-btn';
        btn.textContent = actionText;
        btn.addEventListener('click', onAction);
        messageBanner.appendChild(btn);
      }
    }

    function hideBanner() {
      messageBanner.hidden = true;
    }

    // ── Helper: Render Node Detail into a Container ──
    function renderNodeDetailContent(targetContainer, node) {
      if (typeof targetContainer.replaceChildren === 'function') {
        targetContainer.replaceChildren();
      } else {
        while (targetContainer.firstChild) targetContainer.removeChild(targetContainer.firstChild);
      }

      if (!node) {
        const emptyMsg = doc.createElement('div');
        emptyMsg.className = 'crawl-detail-empty';
        emptyMsg.textContent = 'ノードを選択してください';
        targetContainer.appendChild(emptyMsg);
        return;
      }

      const formatted = formatNodeDetail(node);

      // Card Header
      const header = doc.createElement('div');
      header.className = 'crawl-detail-header';

      const kindBadge = doc.createElement('span');
      kindBadge.className = `crawl-kind-badge kind-${formatted.kind}`;
      kindBadge.textContent = formatted.kindLabel;
      header.appendChild(kindBadge);

      const title = doc.createElement('h3');
      title.className = 'crawl-detail-title';
      title.textContent = formatted.label;
      header.appendChild(title);

      targetContainer.appendChild(header);

      // URL row
      const urlRow = doc.createElement('div');
      urlRow.className = 'crawl-detail-row';
      const urlLabel = doc.createElement('strong');
      urlLabel.textContent = 'URL: ';
      urlRow.appendChild(urlLabel);

      const urlCode = doc.createElement('code');
      urlCode.className = 'crawl-url-code';
      urlCode.textContent = formatted.url || '(none)';
      urlRow.appendChild(urlCode);

      if (formatted.url && formatted.url.startsWith('http')) {
        const link = doc.createElement('a');
        link.href = formatted.url;
        link.target = '_blank';
        link.rel = 'noopener noreferrer';
        link.className = 'crawl-external-link';
        link.textContent = ' ↗ 開く';
        urlRow.appendChild(link);
      }
      targetContainer.appendChild(urlRow);

      // Parent ID row
      const parentRow = doc.createElement('div');
      parentRow.className = 'crawl-detail-row';
      const parentLabel = doc.createElement('strong');
      parentLabel.textContent = '親ノード: ';
      parentRow.appendChild(parentLabel);
      const parentText = doc.createElement('span');
      parentText.textContent = formatted.parentId ? formatted.parentId : 'なし (起点)';
      parentRow.appendChild(parentText);
      targetContainer.appendChild(parentRow);

      // ── Actions Section ──
      const actionsSec = doc.createElement('div');
      actionsSec.className = 'crawl-detail-section';
      const actionsTitle = doc.createElement('h4');
      actionsTitle.textContent = `アクション (${formatted.actions.length})`;
      actionsSec.appendChild(actionsTitle);

      if (formatted.hasActions) {
        const actList = doc.createElement('ul');
        actList.className = 'crawl-detail-list';
        formatted.actions.forEach((act) => {
          const item = doc.createElement('li');
          const method = doc.createElement('span');
          method.className = 'crawl-method-badge';
          method.textContent = String(act.method || 'GET').toUpperCase();
          item.appendChild(method);

          const actUrl = doc.createElement('span');
          actUrl.textContent = ` ${act.action || ''}`;
          item.appendChild(actUrl);
          actList.appendChild(item);
        });
        actionsSec.appendChild(actList);
      } else {
        const unavail = doc.createElement('div');
        unavail.className = 'crawl-unavailable-text';
        unavail.textContent = formatted.actionsUnavailableText;
        actionsSec.appendChild(unavail);
      }
      targetContainer.appendChild(actionsSec);

      // ── Inputs Section ──
      const inputsSec = doc.createElement('div');
      inputsSec.className = 'crawl-detail-section';
      const inputsTitle = doc.createElement('h4');
      inputsTitle.textContent = `入力 / パラメータ (${formatted.inputs.length})`;
      inputsSec.appendChild(inputsTitle);

      if (formatted.hasInputs) {
        const inpList = doc.createElement('ul');
        inpList.className = 'crawl-detail-list';
        formatted.inputs.forEach((inp) => {
          const item = doc.createElement('li');
          const nameSpan = doc.createElement('strong');
          nameSpan.textContent = String(inp.name || 'unnamed');
          item.appendChild(nameSpan);

          const typeSpan = doc.createElement('span');
          typeSpan.className = 'crawl-input-meta';
          typeSpan.textContent = ` (${inp.type || 'text'}, ${inp.carrier || 'input'})`;
          item.appendChild(typeSpan);
          inpList.appendChild(item);
        });
        inputsSec.appendChild(inpList);
      } else {
        const unavail = doc.createElement('div');
        unavail.className = 'crawl-unavailable-text';
        unavail.textContent = formatted.inputsUnavailableText;
        inputsSec.appendChild(unavail);
      }
      targetContainer.appendChild(inputsSec);

      // ── Linked Findings Section ──
      const findingsSec = doc.createElement('div');
      findingsSec.className = 'crawl-detail-section';
      const findingsTitle = doc.createElement('h4');
      findingsTitle.textContent = `検出事項 (${formatted.findings.length})`;
      findingsSec.appendChild(findingsTitle);

      if (formatted.hasFindings) {
        const fList = doc.createElement('div');
        fList.className = 'crawl-findings-list';
        formatted.findings.forEach((f) => {
          const card = doc.createElement('div');
          card.className = 'crawl-finding-card';

          const sevBadge = doc.createElement('span');
          const sev = String(f.severity || 'info').toLowerCase();
          sevBadge.className = `crawl-sev-badge sev-${sev}`;
          sevBadge.textContent = String(f.severity || 'INFO').toUpperCase();
          card.appendChild(sevBadge);

          const fCheck = doc.createElement('strong');
          fCheck.textContent = ` ${f.check_type || 'finding'}`;
          card.appendChild(fCheck);

          // Plain text ID display (no deep link invented)
          const fId = doc.createElement('div');
          fId.className = 'crawl-finding-id';
          fId.textContent = `ID: ${f.id || 'unknown'}`;
          card.appendChild(fId);

          if (f.field_name) {
            const fField = doc.createElement('div');
            fField.className = 'crawl-finding-field';
            fField.textContent = `対象フィールド: ${f.field_name}`;
            card.appendChild(fField);
          }

          if (f.verified) {
            const fVer = doc.createElement('span');
            fVer.className = 'crawl-verified-pill';
            fVer.textContent = '確証済み (verified)';
            card.appendChild(fVer);
          }
          fList.appendChild(card);
        });
        findingsSec.appendChild(fList);
      } else {
        const unavail = doc.createElement('div');
        unavail.className = 'crawl-unavailable-text';
        unavail.textContent = formatted.findingsUnavailableText;
        findingsSec.appendChild(unavail);
      }
      targetContainer.appendChild(findingsSec);

      // ── Metadata Section (Only if properties exist) ──
      const metaKeys = Object.keys(formatted.metadata);
      if (metaKeys.length > 0) {
        const metaSec = doc.createElement('div');
        metaSec.className = 'crawl-detail-section';
        const metaTitle = doc.createElement('h4');
        metaTitle.textContent = 'メタデータ';
        metaSec.appendChild(metaTitle);

        const metaList = doc.createElement('dl');
        metaList.className = 'crawl-meta-dl';
        metaKeys.forEach((k) => {
          const dt = doc.createElement('dt');
          dt.textContent = k;
          const dd = doc.createElement('dd');
          const val = formatted.metadata[k];
          dd.textContent = typeof val === 'object' ? JSON.stringify(val) : String(val);
          metaList.appendChild(dt);
          metaList.appendChild(dd);
        });
        metaSec.appendChild(metaList);
        targetContainer.appendChild(metaSec);
      }
    }

    // ── Helper: Open Detail Drawer (in Graph & List views) ──
    function openDetail(node) {
      if (!node) {
        detailDrawer.hidden = true;
        return;
      }
      selectedNodeId = node.id;
      detailDrawer.hidden = false;

      // Close button
      const closeBtn = doc.createElement('button');
      closeBtn.type = 'button';
      closeBtn.className = 'crawl-drawer-close';
      closeBtn.textContent = '✕';
      closeBtn.title = '閉じる';
      closeBtn.addEventListener('click', () => {
        detailDrawer.hidden = true;
      });

      renderNodeDetailContent(detailDrawer, node);
      detailDrawer.insertBefore(closeBtn, detailDrawer.firstChild);
    }

    // ── Render 1: Graph SVG ──
    function renderGraphView(filteredNodes, edges) {
      if (typeof svgViewport.replaceChildren === 'function') {
        svgViewport.replaceChildren();
      } else {
        while (svgViewport.firstChild) svgViewport.removeChild(svgViewport.firstChild);
      }

      if (!filteredNodes || filteredNodes.length === 0) {
        return;
      }

      const layout = layoutGraph(filteredNodes, edges);

      // Render edges
      layout.edges.forEach((edge) => {
        const path = createSvgElement('path', {
          d: edge.pathData,
          fill: 'none',
          stroke: '#4a5568',
          'stroke-width': '1.5',
          'marker-end': 'url(#crawl-arr)',
        }, doc);
        svgViewport.appendChild(path);

        // Edge source dot
        const dot = createSvgElement('circle', {
          cx: String(edge.x1),
          cy: String(edge.y1),
          r: '3',
          fill: '#9184d9',
        }, doc);
        svgViewport.appendChild(dot);
      });

      // Render nodes
      layout.nodes.forEach((n) => {
        const g = createSvgElement('g', {
          transform: `translate(${n.x},${n.y})`,
          class: `crawl-svg-node ${selectedNodeId === n.id ? 'selected' : ''}`,
          'data-id': n.id,
        }, doc);
        g.style.cursor = 'pointer';

        const strokeColor = KIND_COLORS[n.kind] || KIND_COLORS.unknown;
        const findingsCount = Array.isArray(n.findings) ? n.findings.length : 0;

        const rect = createSvgElement('rect', {
          width: String(n.width),
          height: String(n.height),
          rx: '6',
          fill: '#1c1e2c',
          stroke: findingsCount > 0 ? '#e2708f' : strokeColor,
          'stroke-width': selectedNodeId === n.id ? '2.5' : '1.5',
        }, doc);
        g.appendChild(rect);

        // Kind dot
        const dot = createSvgElement('circle', {
          cx: '14',
          cy: String(n.height / 2),
          r: '4',
          fill: strokeColor,
        }, doc);
        g.appendChild(dot);

        // Node title
        const textTitle = createSvgElement('text', {
          x: '24',
          y: String(n.height / 2 - 3),
          'font-size': '10.5px',
          fill: '#e9e9ed',
        }, doc);
        const rawLabel = String(n.label || n.url || n.id);
        textTitle.textContent = rawLabel.length > 18 ? rawLabel.slice(0, 17) + '…' : rawLabel;
        g.appendChild(textTitle);

        // Subtitle: inputs / findings
        const textSub = createSvgElement('text', {
          x: '24',
          y: String(n.height / 2 + 10),
          'font-size': '9px',
          fill: '#9397ab',
        }, doc);
        const inCount = Array.isArray(n.inputs) ? n.inputs.length : 0;
        textSub.textContent = findingsCount > 0
          ? `${inCount} in · ${findingsCount} vuln`
          : `${inCount} inputs`;
        g.appendChild(textSub);

        g.addEventListener('click', (ev) => {
          ev.stopPropagation();
          openDetail(n);
          // Highlight node in SVG
          svgViewport.querySelectorAll('.crawl-svg-node').forEach((el) => el.classList.remove('selected'));
          g.classList.add('selected');
        });

        svgViewport.appendChild(g);
      });

      applyTransform();
    }

    // ── Render 2: Explorer (Tree + Detail) ──
    function renderExplorerView(filteredNodes) {
      if (typeof explorerTree.replaceChildren === 'function') {
        explorerTree.replaceChildren();
      } else {
        while (explorerTree.firstChild) explorerTree.removeChild(explorerTree.firstChild);
      }

      if (!filteredNodes || filteredNodes.length === 0) {
        const empty = doc.createElement('div');
        empty.className = 'crawl-detail-empty';
        empty.textContent = '一致するノードがありません';
        explorerTree.appendChild(empty);
        renderNodeDetailContent(explorerDetail, null);
        return;
      }

      const byId = new Map();
      filteredNodes.forEach((n) => byId.set(n.id, n));

      const children = new Map();
      filteredNodes.forEach((n) => {
        if (n.parent_id && byId.has(n.parent_id)) {
          if (!children.has(n.parent_id)) children.set(n.parent_id, []);
          children.get(n.parent_id).push(n.id);
        }
      });

      const roots = filteredNodes.filter((n) => !n.parent_id || !byId.has(n.parent_id));

      function buildTreeNode(nodeId, depth) {
        const n = byId.get(nodeId);
        if (!n) return null;

        const row = doc.createElement('div');
        row.className = `crawl-tree-row ${selectedNodeId === n.id ? 'selected' : ''}`;
        row.style.paddingLeft = `${depth * 16 + 8}px`;

        const dot = doc.createElement('span');
        dot.className = 'crawl-tree-dot';
        dot.style.background = KIND_COLORS[n.kind] || KIND_COLORS.unknown;
        row.appendChild(dot);

        const label = doc.createElement('span');
        label.className = 'crawl-tree-label';
        label.textContent = String(n.label || n.url || n.id);
        row.appendChild(label);

        const fc = Array.isArray(n.findings) ? n.findings.length : 0;
        if (fc > 0) {
          const vulnBadge = doc.createElement('span');
          vulnBadge.className = 'crawl-tree-vuln';
          vulnBadge.textContent = `${fc}`;
          row.appendChild(vulnBadge);
        }

        row.addEventListener('click', () => {
          selectedNodeId = n.id;
          explorerTree.querySelectorAll('.crawl-tree-row').forEach((r) => r.classList.remove('selected'));
          row.classList.add('selected');
          renderNodeDetailContent(explorerDetail, n);
        });

        const wrap = doc.createElement('div');
        wrap.appendChild(row);

        const kids = children.get(nodeId) || [];
        kids.forEach((kId) => {
          const childNode = buildTreeNode(kId, depth + 1);
          if (childNode) wrap.appendChild(childNode);
        });

        return wrap;
      }

      roots.forEach((r) => {
        const item = buildTreeNode(r.id, 0);
        if (item) explorerTree.appendChild(item);
      });

      // Show first selected or first root node detail
      const activeNode = selectedNodeId ? byId.get(selectedNodeId) : roots[0];
      if (activeNode) {
        selectedNodeId = activeNode.id;
        renderNodeDetailContent(explorerDetail, activeNode);
      }
    }

    // ── Render 3: List View (Table) ──
    function renderListView(filteredNodes) {
      if (typeof listSurface.replaceChildren === 'function') {
        listSurface.replaceChildren();
      } else {
        while (listSurface.firstChild) listSurface.removeChild(listSurface.firstChild);
      }

      if (!filteredNodes || filteredNodes.length === 0) {
        const empty = doc.createElement('div');
        empty.className = 'crawl-detail-empty';
        empty.textContent = '一致するノードがありません';
        listSurface.appendChild(empty);
        return;
      }

      const tableWrap = doc.createElement('div');
      tableWrap.className = 'ui-table-wrap';

      const table = doc.createElement('table');
      table.className = 'ui-table';

      const thead = doc.createElement('thead');
      const trH = doc.createElement('tr');
      ['種別', 'ラベル', 'URL', 'アクション', '入力', '検出事項'].forEach((h) => {
        const th = doc.createElement('th');
        th.textContent = h;
        trH.appendChild(th);
      });
      thead.appendChild(trH);
      table.appendChild(thead);

      const tbody = doc.createElement('tbody');
      filteredNodes.forEach((n) => {
        const tr = doc.createElement('tr');
        tr.style.cursor = 'pointer';
        if (selectedNodeId === n.id) tr.className = 'selected-row';

        // Kind
        const tdKind = doc.createElement('td');
        const kBadge = doc.createElement('span');
        kBadge.className = `crawl-kind-badge kind-${n.kind}`;
        kBadge.textContent = KIND_LABELS[n.kind] || n.kind;
        tdKind.appendChild(kBadge);
        tr.appendChild(tdKind);

        // Label
        const tdLabel = doc.createElement('td');
        tdLabel.textContent = String(n.label || n.url || n.id);
        tr.appendChild(tdLabel);

        // URL
        const tdUrl = doc.createElement('td');
        const code = doc.createElement('code');
        code.textContent = String(n.url || '');
        tdUrl.appendChild(code);
        tr.appendChild(tdUrl);

        // Actions count
        const tdAct = doc.createElement('td');
        tdAct.textContent = Array.isArray(n.actions) && n.actions.length > 0 ? `${n.actions.length}` : '—';
        tr.appendChild(tdAct);

        // Inputs count
        const tdIn = doc.createElement('td');
        tdIn.textContent = Array.isArray(n.inputs) && n.inputs.length > 0 ? `${n.inputs.length}` : '—';
        tr.appendChild(tdIn);

        // Findings count
        const tdF = doc.createElement('td');
        const fc = Array.isArray(n.findings) ? n.findings.length : 0;
        if (fc > 0) {
          const badge = doc.createElement('span');
          badge.className = 'crawl-sev-badge sev-critical';
          badge.textContent = `${fc}件`;
          tdF.appendChild(badge);
        } else {
          tdF.textContent = '0件';
        }
        tr.appendChild(tdF);

        tr.addEventListener('click', () => {
          selectedNodeId = n.id;
          tbody.querySelectorAll('tr').forEach((row) => row.classList.remove('selected-row'));
          tr.classList.add('selected-row');
          openDetail(n);
        });

        tbody.appendChild(tr);
      });

      table.appendChild(tbody);
      tableWrap.appendChild(table);
      listSurface.appendChild(tableWrap);
    }

    // ── Helper: Render Active Mode ──
    function renderActiveMode() {
      if (!currentData) return;
      const allNodes = currentData.nodes || [];
      const searched = searchNodes(allNodes, searchQuery);
      const filtered = filterNodesByKind(searched, currentKindFilter);

      if (filtered.length === 0) {
        showBanner('empty', '検索・フィルタ条件に一致するノードがありません。');
      } else {
        hideBanner();
      }

      if (currentMode === 'graph') {
        renderGraphView(filtered, currentData.edges || []);
      } else if (currentMode === 'explorer') {
        renderExplorerView(filtered);
      } else if (currentMode === 'list') {
        renderListView(filtered);
      }
    }

    // ── Data Loader ──
    async function loadCrawlGraph(scanId) {
      initialScanId = scanId || initialScanId;
      hideBanner();
      showBanner('loading', 'クロールグラフを読み込み中...');

      const endpoint = initialScanId
        ? `/api/v1/scans/${encodeURIComponent(initialScanId)}/crawl-graph`
        : '/api/v1/scan/crawl-graph';

      try {
        const result = await api.get(endpoint);
        if (!result.ok || !result.data) {
          showBanner('error', `クロールグラフの取得に失敗しました (${result.errorMessage || 'HTTP ' + result.status})。`, '再試行', () => {
            loadCrawlGraph(initialScanId);
          });
          completenessBadge.className = 'crawl-badge crawl-badge-unknown';
          completenessBadge.textContent = '取得失敗';
          reasonsTooltip.textContent = result.errorMessage || '';
          return false;
        }

        currentData = result.data;
        const completenessInfo = formatCompleteness(currentData.completeness, currentData.completeness_reasons);

        completenessBadge.className = `crawl-badge ${completenessInfo.badgeClass}`;
        completenessBadge.textContent = completenessInfo.badgeText;
        reasonsTooltip.textContent = completenessInfo.reasons.join(' · ');

        // Update context text if options.onContextUpdated is provided
        if (typeof options.onContextUpdated === 'function') {
          options.onContextUpdated(currentData.scan_id || initialScanId || '—', completenessInfo.badgeText);
        }

        if (!currentData.nodes || currentData.nodes.length === 0) {
          showBanner('empty', 'クロール結果のノードが存在しません（スキャン未開始または巡回ページなし）。');
          renderActiveMode();
          return true;
        }

        hideBanner();
        renderActiveMode();
        return true;
      } catch (err) {
        showBanner('error', `通信エラーが発生しました: ${err.message || 'Error'}`, '再試行', () => {
          loadCrawlGraph(initialScanId);
        });
        return false;
      }
    }

    // ── Load scan options into selector dropdown ──
    async function loadScansList() {
      try {
        const result = await api.get('/api/v1/scans');
        if (result.ok && result.data && Array.isArray(result.data.scans)) {
          // Keep the first default option
          while (scanSelect.children.length > 1) {
            scanSelect.removeChild(scanSelect.lastChild);
          }
          result.data.scans.forEach((s) => {
            if (!s || !s.id) return;
            const opt = doc.createElement('option');
            opt.value = s.id;
            opt.textContent = `${s.id} (${s.target || 'target'})`;
            if (s.id === initialScanId) opt.selected = true;
            scanSelect.appendChild(opt);
          });
        }
      } catch (_) {
        // Scans list error is non-fatal
      }
    }

    // ── Event Handlers Wiring ──
    modeBtnGraph.addEventListener('click', () => setMode('graph'));
    modeBtnExplorer.addEventListener('click', () => setMode('explorer'));
    modeBtnList.addEventListener('click', () => setMode('list'));

    kindSelect.addEventListener('change', () => {
      currentKindFilter = kindSelect.value;
      renderActiveMode();
    });

    searchInput.addEventListener('input', () => {
      searchQuery = searchInput.value;
      renderActiveMode();
    });

    scanSelect.addEventListener('change', () => {
      const selectedId = scanSelect.value;
      initialScanId = selectedId || null;
      if (typeof window !== 'undefined' && window.location) {
        if (initialScanId) {
          window.location.hash = `#/crawl?scan=${encodeURIComponent(initialScanId)}`;
        } else {
          window.location.hash = '#/crawl';
        }
      }
      loadCrawlGraph(initialScanId);
    });

    reloadBtn.addEventListener('click', () => {
      loadCrawlGraph(initialScanId);
    });

    // Zoom controls
    zoomInBtn.addEventListener('click', () => {
      viewScale = Math.min(3.0, viewScale * 1.25);
      applyTransform();
    });
    zoomOutBtn.addEventListener('click', () => {
      viewScale = Math.max(0.2, viewScale * 0.8);
      applyTransform();
    });
    zoomResetBtn.addEventListener('click', () => {
      viewScale = 1.0;
      viewTx = 0;
      viewTy = 0;
      applyTransform();
    });

    // Graph Surface Panning & Wheel Zoom
    graphSurface.addEventListener('mousedown', (ev) => {
      if (ev.target.closest('.crawl-svg-node')) return;
      isPanning = true;
      panStartX = ev.clientX - viewTx;
      panStartY = ev.clientY - viewTy;
    });

    if (typeof window !== 'undefined') {
      window.addEventListener('mousemove', (ev) => {
        if (!isPanning) return;
        viewTx = ev.clientX - panStartX;
        viewTy = ev.clientY - panStartY;
        applyTransform();
      });

      window.addEventListener('mouseup', () => {
        isPanning = false;
      });
    }

    graphSurface.addEventListener('wheel', (ev) => {
      ev.preventDefault();
      const zoomFactor = ev.deltaY < 0 ? 1.1 : 0.9;
      viewScale = Math.max(0.2, Math.min(3.0, viewScale * zoomFactor));
      applyTransform();
    });

    // Initial fetch
    loadScansList();
    loadCrawlGraph(initialScanId);

    return {
      root: root,
      loadCrawlGraph: loadCrawlGraph,
      destroy: () => {
        if (typeof container.replaceChildren === 'function') {
          container.replaceChildren();
        } else {
          while (container.firstChild) container.removeChild(container.firstChild);
        }
      },
    };
  }

  /**
   * Factory function to create Crawl module definition for ModuleRegistry.
   *
   * @param {Object} options
   * @returns {Object} Module definition
   */
  function createCrawlModule(options = {}) {
    let activeScope = null;
    let viewInstance = null;

    return {
      id: 'crawl',
      title: 'Crawl',
      route: '#/crawl',
      mount: function (route) {
        if (options.titleEl) {
          options.titleEl.textContent = 'Crawl';
        }
        if (options.contextEl) {
          options.contextEl.textContent = '';
        }
        if (typeof options.clearMessage === 'function') {
          options.clearMessage();
        }
        if (typeof options.hideOthers === 'function') {
          options.hideOthers();
        }

        if (options.surfaceEl) {
          options.surfaceEl.hidden = false;
          activeScope = options.api && typeof options.api.createScope === 'function'
            ? options.api.createScope()
            : options.api;

          viewInstance = renderCrawlView(options.surfaceEl, {
            api: activeScope,
            scanId: route && route.scanId ? route.scanId : null,
            onContextUpdated: (scanId, completeness) => {
              if (options.contextEl) {
                options.contextEl.textContent = `Scan ${scanId || '—'} · ${completeness || 'unknown'}`;
              }
            },
          });
        }
      },
      unmount: function () {
        if (activeScope && typeof activeScope.cancelAll === 'function') {
          activeScope.cancelAll('Crawl module unmounted');
        }
        activeScope = null;
        if (viewInstance && typeof viewInstance.destroy === 'function') {
          viewInstance.destroy();
          viewInstance = null;
        }
        if (options.surfaceEl) {
          options.surfaceEl.hidden = true;
        }
      },
    };
  }

  const exportObj = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    formatCompleteness: formatCompleteness,
    formatNodeDetail: formatNodeDetail,
    searchNodes: searchNodes,
    filterNodesByKind: filterNodesByKind,
    layoutGraph: layoutGraph,
    renderCrawlView: renderCrawlView,
    createCrawlModule: createCrawlModule,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (global) {
    global.VulixCrawlModule = exportObj;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
