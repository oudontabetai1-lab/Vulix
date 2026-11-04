/**
 * traffic-module.js — Safe, Read-Only Traffic view module for Vulix /app shell
 *
 * Provides a read-only HTTP traffic inspector backed by the audit log
 * (output/<scan>/http_requests.jsonl) recorded by Vulix.
 *
 * INVARIANTS:
 * - Read-only view only: no capture engine, proxy, MITM, replay, or mutation.
 * - Action entry points (replay, mutate, send-to-proxy) are shown disabled with
 *   reason 'not available in this version' unless declared by backend capabilities.
 * - Strict redaction: credentials, Authorization/Cookie/Set-Cookie header values,
 *   URL userinfo, and query secrets are masked before rendering in the DOM or export.
 * - Bounded windowed/chunked rendering prevents UI freeze on 10,000+ log lines.
 * - Cross-links to Findings display 'unknown' (never 0) until findings data is loaded.
 * - URL hash retains selection and filters so reload and back/forward navigation restore state.
 */
(function (global) {
  'use strict';

  const SENSITIVE_KEY_REGEX = /(?:^key$|(?:api|access|auth)[_-]?key|password|passwd|pwd|secret|token|cookie|session[_-]?id|csrf|xsrf|credentials?|signature|samlresponse|(?:^|[._-])(?:sid|sessid|jwt|sig|jsessionid|phpsessid|bearer)(?:$|[._-])|(?:^|[._-])(?:auth|authentication|authorization|session|otp|ticket)$)/i;
  const CHUNK_SIZE = 50;

  function escapeHtml(value) {
    if (value == null) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function redactDisplayUrl(raw) {
    if (!raw || typeof raw !== 'string') return raw || '';
    const str = raw.trim();
    if (!str) return '';
    let parsed;
    try {
      parsed = new URL(str);
    } catch (_) {
      return '[redacted-url]';
    }
    if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname) {
      return '[redacted-url]';
    }
    // userinfo: http://user:pass@host -> http://<redacted>@host
    let url = str.replace(/\b(https?:\/\/)[^\s/?#@]+(?::[^\s/?#@]*)?@/gi, '$1<redacted>@');
    // Query / fragment parameter redaction
    url = url.replace(/([?&#;])([^&=?#;\s]+)=([^&#;\s]*)/g, function (match, sep, k, v) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        return sep + k + '=<redacted>';
      }
      return match;
    });
    return url;
  }

  function redactDisplayText(raw) {
    if (!raw || typeof raw !== 'string') return raw || '';
    let text = String(raw).replace(/\b(https?:\/\/)[^\s/?#@]+(?::[^\s/?#@]*)?@/gi, '$1<redacted>@');
    text = text.replace(/([?&;,\s{}"'])([^&=?#;\s{}"']+)=([^&#;\s,"'}]*)/g, function (match, prefix, k, v) {
      if (SENSITIVE_KEY_REGEX.test(k)) {
        return prefix + k + '=<redacted>';
      }
      return match;
    });
    text = text.replace(/\b(Bearer\s+)[A-Za-z0-9._~+/-]+=*/gi, '$1<redacted>');
    text = text.replace(/\b(Basic\s+)[A-Za-z0-9+/=]+/gi, '$1<redacted>');
    return text;
  }

  function formatBytes(bytes) {
    if (bytes == null || isNaN(bytes)) return '—';
    const num = Number(bytes);
    if (num < 1024) return `${num} B`;
    if (num < 1024 * 1024) return `${(num / 1024).toFixed(1)} KB`;
    return `${(num / (1024 * 1024)).toFixed(1)} MB`;
  }

  function formatStatusClass(status) {
    if (!status) return 'traffic-status-unknown';
    const s = Number(status);
    if (s >= 200 && s < 300) return 'traffic-status-2xx';
    if (s >= 300 && s < 400) return 'traffic-status-3xx';
    if (s >= 400 && s < 500) return 'traffic-status-4xx';
    if (s >= 500) return 'traffic-status-5xx';
    return 'traffic-status-other';
  }

  function formatMethodClass(method) {
    const m = String(method || '').toUpperCase();
    if (m === 'GET') return 'traffic-method-get';
    if (m === 'POST') return 'traffic-method-post';
    if (m === 'PUT') return 'traffic-method-put';
    if (m === 'DELETE') return 'traffic-method-delete';
    return 'traffic-method-other';
  }

  function buildTrafficHash(scanId, entryId, filters) {
    const params = new URLSearchParams();
    if (scanId) params.set('scan', scanId);
    if (entryId) params.set('entry', entryId);
    if (filters) {
      if (filters.method && filters.method !== 'all') params.set('method', filters.method);
      if (filters.status && filters.status !== 'all') params.set('status', filters.status);
      if (filters.source && filters.source !== 'all') params.set('source', filters.source);
      if (filters.type && filters.type !== 'all') params.set('type', filters.type);
      if (filters.search) params.set('search', filters.search);
      if (filters.url) params.set('url', filters.url);
    }
    const q = params.toString();
    return q ? `#/traffic?${q}` : '#/traffic';
  }

  function buildCrawlLink(scanId, url) {
    const params = new URLSearchParams();
    if (scanId) params.set('scan', scanId);
    if (url) params.set('url', url);
    const q = params.toString();
    return q ? `#/crawl?${q}` : '#/crawl';
  }

  function buildFindingsLink(scanId, url) {
    const params = new URLSearchParams();
    if (scanId) params.set('scan', scanId);
    if (url) params.set('url', url);
    const q = params.toString();
    return q ? `#/findings?${q}` : '#/findings';
  }

  /**
   * Resolve action entry points for a traffic entry based on backend capabilities.
   * Replay, mutation, and proxy are disabled unless declared by backend.
   */
  function resolveTrafficActions(entry, options) {
    options = options || {};
    const url = entry && entry.url ? String(entry.url).trim() : '';
    const hasValidHttpUrl = Boolean(url && /^https?:\/\//i.test(url));

    const manifest = options.manifest || (global.VulixCapabilityReader && global.VulixCapabilityReader.defaultReader && global.VulixCapabilityReader.defaultReader.manifest) || null;
    const capabilities = (manifest && manifest.capabilities) || {};

    const hasReplayCap = Boolean(capabilities.replay || capabilities.replay_traffic);
    const hasMutateCap = Boolean(capabilities.mutate || capabilities.mutate_traffic);
    const hasProxyCap = Boolean(capabilities.proxy || capabilities.send_to_proxy || capabilities.proxy_traffic);
    const hasOpenBrowserCap = Boolean(capabilities.open_browser !== false);

    return [
      {
        id: 'open_in_browser',
        label: 'ブラウザで開く',
        enabled: hasValidHttpUrl && hasOpenBrowserCap,
        url: hasValidHttpUrl ? url : null,
        reason: hasValidHttpUrl ? (hasOpenBrowserCap ? null : 'not available in this version') : '利用可能なHTTP(S) URLがありません',
      },
      {
        id: 'replay',
        label: 'リプレイ / 再送信',
        enabled: hasReplayCap,
        reason: hasReplayCap ? null : 'not available in this version',
      },
      {
        id: 'mutate',
        label: '改変送信 / Mutation',
        enabled: hasMutateCap,
        reason: hasMutateCap ? null : 'not available in this version',
      },
      {
        id: 'send_to_proxy',
        label: 'プロキシへ送信 (Proxy)',
        enabled: hasProxyCap,
        reason: hasProxyCap ? null : 'not available in this version',
      },
    ];
  }

  function filterTraffic(entries, filters) {
    if (!Array.isArray(entries)) return [];
    filters = filters || {};
    const methodFilter = (filters.method || 'all').toLowerCase();
    const statusFilter = (filters.status || 'all').toLowerCase();
    const sourceFilter = (filters.source || 'all').toLowerCase();
    const typeFilter = (filters.type || 'all').toLowerCase();
    const searchFilter = (filters.search || '').trim().toLowerCase();
    const urlFilter = (filters.url || '').trim().toLowerCase();

    return entries.filter(function (e) {
      if (methodFilter !== 'all' && (e.method || '').toLowerCase() !== methodFilter) {
        return false;
      }

      if (statusFilter !== 'all') {
        const s = e.status != null ? Number(e.status) : null;
        if (statusFilter === '2xx' && (s == null || s < 200 || s >= 300)) return false;
        if (statusFilter === '3xx' && (s == null || s < 300 || s >= 400)) return false;
        if (statusFilter === '4xx' && (s == null || s < 400 || s >= 500)) return false;
        if (statusFilter === '5xx' && (s == null || s < 500)) return false;
        if (!isNaN(statusFilter) && s !== Number(statusFilter)) return false;
      }

      if (sourceFilter !== 'all' && (e.source || '').toLowerCase() !== sourceFilter) {
        return false;
      }

      if (typeFilter !== 'all') {
        const kinds = e.input_point_kinds || {};
        if (['query', 'form', 'json', 'xml', 'multipart', 'cookie', 'header', 'graphql'].includes(typeFilter)) {
          if (!kinds[typeFilter]) return false;
        } else {
          const reqCt = (e.request_content_type || '').toLowerCase();
          const respCt = (e.response_content_type || '').toLowerCase();
          if (!reqCt.includes(typeFilter) && !respCt.includes(typeFilter)) return false;
        }
      }

      if (urlFilter) {
        const eUrl = (e.url || '').toLowerCase();
        if (eUrl !== urlFilter && !eUrl.includes(urlFilter)) return false;
      }

      if (searchFilter) {
        const urlMatch = (e.url || '').toLowerCase().includes(searchFilter);
        const methodMatch = (e.method || '').toLowerCase().includes(searchFilter);
        const postMatch = (e.post_data_preview || '').toLowerCase().includes(searchFilter);
        const respMatch = (e.response_preview || '').toLowerCase().includes(searchFilter);
        if (!urlMatch && !methodMatch && !postMatch && !respMatch) return false;
      }

      return true;
    });
  }

  function computeTrafficCounts(entries, filtered) {
    const total = Array.isArray(entries) ? entries.length : 0;
    const matchCount = Array.isArray(filtered) ? filtered.length : 0;
    return {
      total: total,
      matched: matchCount,
      label: total === matchCount ? `${total.toLocaleString()} 件` : `${total.toLocaleString()} 件中 ${matchCount.toLocaleString()} 件が一致`,
    };
  }

  /**
   * DOM Renderer for the Traffic screen.
   */
  function renderTrafficView(container, options) {
    options = options || {};
    const api = options.api || (global.VulixApiClient && new global.VulixApiClient.ApiClient());
    const scope = api && typeof api.createScope === 'function' ? api.createScope() : null;

    let allScans = [];
    let currentScanId = '';
    let allEntries = [];
    let backendAvailable = true;
    let backendReason = '';
    let isTruncated = false;
    let selectedEntry = null;
    let selectedEntryId = '';
    let findingsByUrl = null; // null => not loaded yet (unknown)

    container.replaceChildren();

    // Toolbar Header
    const toolbar = document.createElement('div');
    toolbar.className = 'traffic-toolbar';

    const scanSelectWrap = document.createElement('div');
    scanSelectWrap.className = 'traffic-scan-select-wrap';
    const scanLabel = document.createElement('label');
    scanLabel.className = 'ui-label';
    scanLabel.textContent = '対象スキャン:';
    const scanSelect = document.createElement('select');
    scanSelect.className = 'ui-select traffic-scan-select';
    scanSelectWrap.append(scanLabel, scanSelect);

    const filterRow = document.createElement('div');
    filterRow.className = 'traffic-filter-row';

    const methodSelect = document.createElement('select');
    methodSelect.className = 'ui-select traffic-filter-select';
    methodSelect.innerHTML = '<option value="all">すべてのメソッド</option><option value="get">GET</option><option value="post">POST</option><option value="put">PUT</option><option value="delete">DELETE</option><option value="patch">PATCH</option><option value="options">OPTIONS</option>';

    const statusSelect = document.createElement('select');
    statusSelect.className = 'ui-select traffic-filter-select';
    statusSelect.innerHTML = '<option value="all">すべてのステータス</option><option value="2xx">2xx (成功)</option><option value="3xx">3xx (リダイレクト)</option><option value="4xx">4xx (クライアントエラー)</option><option value="5xx">5xx (サーバーエラー)</option>';

    const sourceSelect = document.createElement('select');
    sourceSelect.className = 'ui-select traffic-filter-select';
    sourceSelect.innerHTML = '<option value="all">すべての出自 (Source)</option><option value="browser">Browser</option><option value="scanner">Scanner</option><option value="replay">Replay</option>';

    const typeSelect = document.createElement('select');
    typeSelect.className = 'ui-select traffic-filter-select';
    typeSelect.innerHTML = '<option value="all">すべての入力種別 (Type)</option><option value="query">Query</option><option value="form">Form (urlencoded)</option><option value="json">JSON</option><option value="xml">XML</option><option value="multipart">Multipart</option><option value="cookie">Cookie</option><option value="header">Header</option><option value="graphql">GraphQL</option>';

    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.className = 'ui-input traffic-search-input';
    searchInput.placeholder = 'URL または本文プレビューを検索...';

    filterRow.append(methodSelect, statusSelect, sourceSelect, typeSelect, searchInput);
    toolbar.append(scanSelectWrap, filterRow);

    // Count Summary bar
    const summaryBar = document.createElement('div');
    summaryBar.className = 'traffic-summary-bar';
    const countBadge = document.createElement('span');
    countBadge.className = 'traffic-count-badge';
    countBadge.textContent = '読み込み中...';
    summaryBar.appendChild(countBadge);

    // Main Split View
    const splitView = document.createElement('div');
    splitView.className = 'traffic-split-view';

    const listPane = document.createElement('div');
    listPane.className = 'traffic-list-pane';

    const tableWrap = document.createElement('div');
    tableWrap.className = 'ui-table-wrap traffic-table-wrap';
    tableWrap.tabIndex = 0;

    const table = document.createElement('table');
    table.className = 'ui-table traffic-table';
    const thead = document.createElement('thead');
    thead.innerHTML = '<tr><th style="width:70px">Method</th><th>URL</th><th style="width:70px">Status</th><th style="width:80px">Type</th><th style="width:80px">Source</th><th style="width:80px">Size</th><th style="width:80px">Time</th></tr>';
    const tbody = document.createElement('tbody');
    table.append(thead, tbody);
    tableWrap.appendChild(table);
    listPane.appendChild(tableWrap);

    const detailPane = document.createElement('div');
    detailPane.className = 'traffic-detail-pane';

    splitView.append(listPane, detailPane);
    container.append(toolbar, summaryBar, splitView);

    function getFilters() {
      return {
        method: methodSelect.value,
        status: statusSelect.value,
        source: sourceSelect.value,
        type: typeSelect.value,
        search: searchInput.value,
      };
    }

    function renderDetail(entry) {
      detailPane.replaceChildren();
      if (!entry) {
        const placeholder = document.createElement('div');
        placeholder.className = 'traffic-detail-placeholder';
        placeholder.textContent = '左側の一覧からトラフィック項目を選択してください。';
        detailPane.appendChild(placeholder);
        return;
      }

      const hdr = document.createElement('div');
      hdr.className = 'traffic-detail-hdr';

      const methodBadge = document.createElement('span');
      methodBadge.className = `traffic-badge ${formatMethodClass(entry.method)}`;
      methodBadge.textContent = entry.method;

      const statusBadge = document.createElement('span');
      statusBadge.className = `traffic-badge ${formatStatusClass(entry.status)}`;
      statusBadge.textContent = entry.status != null ? String(entry.status) : '—';

      const urlText = document.createElement('div');
      urlText.className = 'traffic-detail-url';
      urlText.textContent = redactDisplayUrl(entry.url);

      hdr.append(methodBadge, statusBadge, urlText);
      detailPane.appendChild(hdr);

      // Actions row (capability-gated entry points)
      const actionsCard = document.createElement('div');
      actionsCard.className = 'traffic-actions-card';
      const actions = resolveTrafficActions(entry);

      actions.forEach(function (act) {
        if (act.enabled) {
          if (act.url) {
            const a = document.createElement('a');
            a.className = 'history-btn traffic-action-btn primary';
            a.href = act.url;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = `↗ ${act.label}`;
            actionsCard.appendChild(a);
          }
        } else {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'history-btn traffic-action-btn disabled';
          btn.disabled = true;
          btn.setAttribute('aria-disabled', 'true');
          btn.title = act.reason || 'not available in this version';

          const labelSpan = document.createElement('span');
          labelSpan.textContent = act.label;
          const reasonSpan = document.createElement('span');
          reasonSpan.className = 'action-disabled-tag';
          reasonSpan.textContent = ` (${act.reason || 'not available in this version'})`;

          btn.append(labelSpan, reasonSpan);
          actionsCard.appendChild(btn);
        }
      });
      detailPane.appendChild(actionsCard);

      // Cross-links Card (Crawl & Findings)
      const crossLinksCard = document.createElement('div');
      crossLinksCard.className = 'traffic-card traffic-cross-links-card';
      const crossTitle = document.createElement('div');
      crossTitle.className = 'traffic-card-title';
      crossTitle.textContent = '関連画面への遷移 (Cross-Links)';
      crossLinksCard.appendChild(crossTitle);

      const crossLinksRow = document.createElement('div');
      crossLinksRow.className = 'traffic-cross-links-row';

      // 1. Crawl Graph Link
      const crawlLink = document.createElement('a');
      crawlLink.className = 'history-btn traffic-cross-link';
      crawlLink.href = buildCrawlLink(currentScanId, entry.url);
      crawlLink.textContent = '🧭 Crawl Graph で表示 →';
      crossLinksRow.appendChild(crawlLink);

      // 2. Findings Link (honest: unknown when not loaded, never 0)
      const findingsLink = document.createElement('a');
      findingsLink.className = 'history-btn traffic-cross-link';
      findingsLink.href = buildFindingsLink(currentScanId, entry.url);

      if (findingsByUrl === null) {
        findingsLink.textContent = '🔍 Findings (unknown / 未読込) →';
      } else {
        const normUrl = (entry.url || '').trim().replace(/\/+$/, '').toLowerCase();
        const count = findingsByUrl[normUrl] || 0;
        findingsLink.textContent = `🔍 Findings (${count} 件) →`;
      }
      crossLinksRow.appendChild(findingsLink);

      crossLinksCard.appendChild(crossLinksRow);
      detailPane.appendChild(crossLinksCard);

      // Input-Point Kinds Card
      const ipCard = document.createElement('div');
      ipCard.className = 'traffic-card';
      const ipTitle = document.createElement('div');
      ipTitle.className = 'traffic-card-title';
      ipTitle.textContent = '検出された入力点種別 (Input-Point Kinds)';
      ipCard.appendChild(ipTitle);

      const ipGrid = document.createElement('div');
      ipGrid.className = 'traffic-ip-grid';
      const kinds = entry.input_points || {};
      const allKinds = ['query', 'form', 'json', 'xml', 'multipart', 'cookie', 'header', 'graphql'];

      allKinds.forEach(function (k) {
        const info = kinds[k] || { present: false, count: 0 };
        const chip = document.createElement('div');
        chip.className = `traffic-ip-chip ${info.present ? 'active' : 'inactive'}`;
        const nameSpan = document.createElement('span');
        nameSpan.className = 'traffic-ip-name';
        nameSpan.textContent = k.toUpperCase();
        const countSpan = document.createElement('span');
        countSpan.className = 'traffic-ip-count';
        countSpan.textContent = info.present ? `(${info.count})` : '—';
        chip.append(nameSpan, countSpan);
        ipGrid.appendChild(chip);
      });
      ipCard.appendChild(ipGrid);
      detailPane.appendChild(ipCard);

      // Request Metadata Card
      const reqCard = document.createElement('div');
      reqCard.className = 'traffic-card';
      const reqTitle = document.createElement('div');
      reqTitle.className = 'traffic-card-title';
      reqTitle.textContent = 'リクエスト詳細 (Request)';
      reqCard.appendChild(reqTitle);

      const reqMeta = document.createElement('div');
      reqMeta.className = 'traffic-meta-line';
      reqMeta.textContent = `Method: ${entry.method} | Size: ${formatBytes(entry.request_size)} | Type: ${escapeHtml(entry.request_content_type || '—')}`;
      reqCard.appendChild(reqMeta);

      if (entry.request_headers && Object.keys(entry.request_headers).length > 0) {
        const hTitle = document.createElement('div');
        hTitle.className = 'traffic-subheading';
        hTitle.textContent = 'Headers:';
        const hTable = document.createElement('table');
        hTable.className = 'ui-table traffic-subtable';
        const hTbody = document.createElement('tbody');
        Object.entries(entry.request_headers).forEach(([hk, hv]) => {
          const tr = document.createElement('tr');
          const tdK = document.createElement('td');
          tdK.className = 'traffic-header-key';
          tdK.textContent = hk;
          const tdV = document.createElement('td');
          tdV.className = 'traffic-header-val';
          tdV.textContent = redactDisplayText(hv);
          tr.append(tdK, tdV);
          hTbody.appendChild(tr);
        });
        hTable.appendChild(hTbody);
        reqCard.append(hTitle, hTable);
      }

      if (entry.post_data_preview) {
        const bTitle = document.createElement('div');
        bTitle.className = 'traffic-subheading';
        bTitle.textContent = 'Body Preview (伏字・上限長):';
        const pre = document.createElement('pre');
        pre.className = 'traffic-body-pre';
        pre.textContent = redactDisplayText(entry.post_data_preview);
        reqCard.append(bTitle, pre);
      }
      detailPane.appendChild(reqCard);

      // Response Metadata Card
      const respCard = document.createElement('div');
      respCard.className = 'traffic-card';
      const respTitle = document.createElement('div');
      respTitle.className = 'traffic-card-title';
      respTitle.textContent = 'レスポンス詳細 (Response)';
      respCard.appendChild(respTitle);

      const respMeta = document.createElement('div');
      respMeta.className = 'traffic-meta-line';
      respMeta.textContent = `Status: ${entry.status != null ? entry.status : '—'} | Size: ${formatBytes(entry.response_size)} | Type: ${escapeHtml(entry.response_content_type || '—')}`;
      respCard.appendChild(respMeta);

      if (entry.response_headers && Object.keys(entry.response_headers).length > 0) {
        const rhTitle = document.createElement('div');
        rhTitle.className = 'traffic-subheading';
        rhTitle.textContent = 'Headers:';
        const rhTable = document.createElement('table');
        rhTable.className = 'ui-table traffic-subtable';
        const rhTbody = document.createElement('tbody');
        Object.entries(entry.response_headers).forEach(([hk, hv]) => {
          const tr = document.createElement('tr');
          const tdK = document.createElement('td');
          tdK.className = 'traffic-header-key';
          tdK.textContent = hk;
          const tdV = document.createElement('td');
          tdV.className = 'traffic-header-val';
          tdV.textContent = redactDisplayText(hv);
          tr.append(tdK, tdV);
          rhTbody.appendChild(tr);
        });
        rhTable.appendChild(rhTbody);
        respCard.append(rhTitle, rhTable);
      }

      if (entry.response_preview) {
        const rbTitle = document.createElement('div');
        rbTitle.className = 'traffic-subheading';
        rbTitle.textContent = 'Body Preview (伏字・上限長):';
        const pre = document.createElement('pre');
        pre.className = 'traffic-body-pre';
        pre.textContent = redactDisplayText(entry.response_preview);
        respCard.append(rbTitle, pre);
      }
      detailPane.appendChild(respCard);
    }

    function renderList() {
      tbody.replaceChildren();

      if (!backendAvailable) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'traffic-unavailable-cell';

        const unavailBox = document.createElement('div');
        unavailBox.className = 'traffic-unavailable-box';
        const heading = document.createElement('div');
        heading.className = 'traffic-unavailable-title';
        heading.textContent = 'トラフィック情報が利用できません (unavailable)';
        const detail = document.createElement('p');
        detail.className = 'traffic-unavailable-reason';
        detail.textContent = backendReason || '監査ログが見つからないか読み取れませんでした。';

        unavailBox.append(heading, detail);
        td.appendChild(unavailBox);
        tr.appendChild(td);
        tbody.appendChild(tr);
        countBadge.textContent = '利用不可 (unavailable)';
        renderDetail(null);
        return;
      }

      const filters = getFilters();
      const filtered = filterTraffic(allEntries, filters);
      const counts = computeTrafficCounts(allEntries, filtered);
      countBadge.textContent = isTruncated ? `${counts.label}（上限による切り詰めあり）` : counts.label;

      if (allEntries.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'ui-table-empty';
        td.textContent = 'このスキャンで記録されたHTTPトラフィックはありません (0 件)。';
        tr.appendChild(td);
        tbody.appendChild(tr);
        renderDetail(null);
        return;
      }

      if (filtered.length === 0) {
        const tr = document.createElement('tr');
        const td = document.createElement('td');
        td.colSpan = 7;
        td.className = 'ui-table-empty';
        td.textContent = 'フィルタ条件に一致するトラフィック項目はありません。';
        tr.appendChild(td);
        tbody.appendChild(tr);
        renderDetail(null);
        return;
      }

      let renderedCount = 0;
      let sentinelTr = null;

      function createRow(e, idx) {
        const tr = document.createElement('tr');
        tr.className = 'traffic-row';
        tr.setAttribute('role', 'button');
        tr.tabIndex = 0;
        tr.dataset.entryId = e.id;

        const isCurrent = (selectedEntryId && e.id === selectedEntryId) ||
          (selectedEntry && (e === selectedEntry || e.id === selectedEntry.id));
        if (isCurrent) {
          tr.classList.add('active');
          tr.setAttribute('aria-selected', 'true');
        }

        // Method cell
        const tdMethod = document.createElement('td');
        const mBadge = document.createElement('span');
        mBadge.className = `traffic-badge ${formatMethodClass(e.method)}`;
        mBadge.textContent = e.method;
        tdMethod.appendChild(mBadge);

        // URL cell
        const tdUrl = document.createElement('td');
        tdUrl.className = 'traffic-url-cell';
        const urlWrap = document.createElement('div');
        urlWrap.className = 'traffic-url-text';
        urlWrap.textContent = redactDisplayUrl(e.url);
        urlWrap.title = redactDisplayUrl(e.url);
        tdUrl.appendChild(urlWrap);

        // Status cell
        const tdStatus = document.createElement('td');
        const sBadge = document.createElement('span');
        sBadge.className = `traffic-badge ${formatStatusClass(e.status)}`;
        sBadge.textContent = e.status != null ? String(e.status) : '—';
        tdStatus.appendChild(sBadge);

        // Type cell
        const tdType = document.createElement('td');
        const activeKinds = Object.entries(e.input_point_kinds || {})
          .filter(([, v]) => Boolean(v))
          .map(([k]) => k.toUpperCase());
        tdType.textContent = activeKinds.length > 0 ? activeKinds.slice(0, 2).join(',') : (e.request_content_type ? 'RAW' : '—');

        // Source cell
        const tdSource = document.createElement('td');
        tdSource.textContent = e.source || 'browser';

        // Size cell
        const tdSize = document.createElement('td');
        tdSize.textContent = formatBytes(e.response_size != null ? e.response_size : e.request_size);

        // Time cell
        const tdTime = document.createElement('td');
        tdTime.textContent = e.time || '—';

        tr.append(tdMethod, tdUrl, tdStatus, tdType, tdSource, tdSize, tdTime);

        function selectThis() {
          selectedEntry = e;
          selectedEntryId = e.id;
          renderDetail(e);

          tbody.querySelectorAll('.traffic-row').forEach(function (r) {
            r.classList.remove('active');
            r.removeAttribute('aria-selected');
          });
          tr.classList.add('active');
          tr.setAttribute('aria-selected', 'true');

          if (global.location && typeof global.location.hash === 'string') {
            const nextHash = buildTrafficHash(currentScanId, e.id, getFilters());
            if (global.location.hash !== nextHash) {
              if (global.history && global.history.replaceState) {
                global.history.replaceState(null, '', nextHash);
              } else {
                global.location.hash = nextHash;
              }
            }
          }
        }

        tr.addEventListener('click', selectThis);
        tr.addEventListener('keydown', function (evt) {
          if (evt.key === 'Enter' || evt.key === ' ') {
            evt.preventDefault();
            selectThis();
          }
        });

        return tr;
      }

      function updateSentinel() {
        if (renderedCount < filtered.length) {
          if (!sentinelTr) {
            sentinelTr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 7;
            td.className = 'traffic-sentinel-cell';
            td.textContent = `${filtered.length.toLocaleString()} 件中 ${renderedCount.toLocaleString()} 件を表示中（スクロールまたはクリックで追加）`;
            sentinelTr.appendChild(td);
            sentinelTr.addEventListener('click', () => renderChunk(CHUNK_SIZE));
          } else {
            sentinelTr.firstChild.textContent = `${filtered.length.toLocaleString()} 件中 ${renderedCount.toLocaleString()} 件を表示中（スクロールまたはクリックで追加）`;
          }
          tbody.appendChild(sentinelTr);
        } else if (sentinelTr && sentinelTr.parentNode) {
          sentinelTr.remove();
          sentinelTr = null;
        }
      }

      function renderChunk(count) {
        if (sentinelTr && sentinelTr.parentNode) {
          sentinelTr.remove();
        }
        const frag = document.createDocumentFragment();
        const target = Math.min(filtered.length, renderedCount + count);
        for (let i = renderedCount; i < target; i++) {
          const row = createRow(filtered[i], i);
          frag.appendChild(row);
        }
        renderedCount = target;
        tbody.appendChild(frag);
        updateSentinel();
      }

      let initialCount = CHUNK_SIZE;
      if (selectedEntryId) {
        const selIdx = filtered.findIndex((e) => e.id === selectedEntryId);
        if (selIdx >= 0) {
          initialCount = Math.max(CHUNK_SIZE, selIdx + 1);
        }
      }

      renderChunk(initialCount);

      // Auto-select first entry if none selected
      if (!selectedEntry && filtered.length > 0) {
        selectedEntry = filtered[0];
        selectedEntryId = filtered[0].id;
        renderDetail(filtered[0]);
        const firstTr = tbody.querySelector('.traffic-row');
        if (firstTr) {
          firstTr.classList.add('active');
          firstTr.setAttribute('aria-selected', 'true');
        }
      } else if (selectedEntry) {
        renderDetail(selectedEntry);
      }
    }

    [methodSelect, statusSelect, sourceSelect, typeSelect].forEach((el) => {
      el.addEventListener('change', () => {
        renderList();
        updateHash();
      });
    });

    searchInput.addEventListener('input', () => {
      renderList();
      updateHash();
    });

    function updateHash() {
      if (global.location && typeof global.location.hash === 'string') {
        const nextHash = buildTrafficHash(currentScanId, selectedEntryId, getFilters());
        if (global.location.hash !== nextHash && global.history && global.history.replaceState) {
          global.history.replaceState(null, '', nextHash);
        }
      }
    }

    scanSelect.addEventListener('change', () => {
      const nextScan = scanSelect.value;
      if (nextScan && nextScan !== currentScanId) {
        currentScanId = nextScan;
        selectedEntry = null;
        selectedEntryId = '';
        findingsByUrl = null;
        updateHash();
        loadTrafficForScan(nextScan);
        loadFindingsForScan(nextScan);
      }
    });

    async function loadFindingsForScan(scanId) {
      if (!scanId || !api) return;
      try {
        const res = await (scope ? scope.request(`/api/v1/scans/${scanId}/findings`) : api.request(`/api/v1/scans/${scanId}/findings`));
        if (res && res.isSuccess() && res.data && Array.isArray(res.data.findings)) {
          const map = {};
          res.data.findings.forEach(function (f) {
            if (f && f.url) {
              const norm = String(f.url).trim().replace(/\/+$/, '').toLowerCase();
              map[norm] = (map[norm] || 0) + 1;
            }
          });
          findingsByUrl = map;
        } else {
          findingsByUrl = {};
        }
      } catch (_) {
        findingsByUrl = {};
      }
      if (selectedEntry) {
        renderDetail(selectedEntry);
      }
    }

    async function loadTrafficForScan(scanId) {
      countBadge.textContent = 'トラフィック読み込み中...';
      const endpoint = scanId ? `/api/v1/scans/${scanId}/traffic?limit=500` : '/api/v1/scan/traffic?limit=500';

      try {
        const res = await (scope ? scope.request(endpoint) : api.request(endpoint));
        if (res && res.isSuccess() && res.data) {
          backendAvailable = res.data.available !== false;
          backendReason = res.data.reason || '';
          allEntries = Array.isArray(res.data.entries) ? res.data.entries : [];
          isTruncated = Boolean(res.data.truncated);
        } else {
          backendAvailable = false;
          backendReason = (res && res.data && res.data.reason) || (res && res.errorMessage) || '監査ログが見つかりません';
          allEntries = [];
        }
      } catch (err) {
        backendAvailable = false;
        backendReason = err && err.message ? err.message : '通信エラーが発生しました';
        allEntries = [];
      }

      renderList();
    }

    async function initScansAndLoad(routeParams) {
      routeParams = routeParams || {};
      try {
        const res = await (scope ? scope.request('/api/v1/scans') : api.request('/api/v1/scans'));
        if (res && res.isSuccess() && res.data) {
          if (Array.isArray(res.data.scans)) {
            allScans = res.data.scans;
          } else if (Array.isArray(res.data)) {
            allScans = res.data;
          }
        } else {
          allScans = [];
        }
      } catch (_) {
        allScans = [];
      }

      scanSelect.replaceChildren();
      allScans.forEach((sc) => {
        const opt = document.createElement('option');
        opt.value = sc.id;
        opt.textContent = sc.name || sc.id;
        scanSelect.appendChild(opt);
      });

      let targetScan = routeParams.scanId || '';
      if (!targetScan && allScans.length > 0) {
        targetScan = allScans[0].id;
      }

      if (targetScan) {
        if (!allScans.some((s) => s.id === targetScan)) {
          const opt = document.createElement('option');
          opt.value = targetScan;
          opt.textContent = targetScan;
          scanSelect.appendChild(opt);
        }
        scanSelect.value = targetScan;
        currentScanId = targetScan;
      }

      if (routeParams.entryId) {
        selectedEntryId = routeParams.entryId;
      }
      if (routeParams.method) methodSelect.value = routeParams.method;
      if (routeParams.status) statusSelect.value = routeParams.status;
      if (routeParams.source) sourceSelect.value = routeParams.source;
      if (routeParams.type) typeSelect.value = routeParams.type;
      if (routeParams.search) searchInput.value = routeParams.search;

      if (currentScanId) {
        await loadTrafficForScan(currentScanId);
        loadFindingsForScan(currentScanId);
      } else {
        await loadTrafficForScan('');
      }
    }

    return {
      initScansAndLoad: initScansAndLoad,
      destroy: function () {
        if (scope) scope.cancelAll('Traffic view destroyed');
        container.replaceChildren();
      },
    };
  }

  /**
   * Module factory conforming to VulixAppShell ModuleRegistry.
   */
  function createTrafficModule(options) {
    options = options || {};
    let viewInstance = null;

    return {
      id: 'traffic',
      title: 'Traffic',
      route: '#/traffic',
      capabilities: ['traffic'],
      mount: function (route) {
        if (typeof options.hideOthers === 'function') {
          options.hideOthers();
        }
        if (typeof options.clearMessage === 'function') {
          options.clearMessage();
        }
        if (options.titleEl) {
          options.titleEl.textContent = 'Traffic';
        }
        if (options.contextEl) {
          options.contextEl.textContent = route && route.scanId ? `Scan ${route.scanId}` : '';
        }
        if (options.surfaceEl) {
          options.surfaceEl.hidden = false;
          viewInstance = renderTrafficView(options.surfaceEl, { api: options.api });
          viewInstance.initScansAndLoad(route);
        }
      },
      unmount: function () {
        if (viewInstance) {
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
    escapeHtml: escapeHtml,
    redactDisplayUrl: redactDisplayUrl,
    redactDisplayText: redactDisplayText,
    formatBytes: formatBytes,
    buildTrafficHash: buildTrafficHash,
    buildCrawlLink: buildCrawlLink,
    buildFindingsLink: buildFindingsLink,
    resolveTrafficActions: resolveTrafficActions,
    filterTraffic: filterTraffic,
    computeTrafficCounts: computeTrafficCounts,
    renderTrafficView: renderTrafficView,
    createTrafficModule: createTrafficModule,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (global) {
    global.VulixTrafficModule = exportObj;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
