/**
 * findings-module.js — Findings view module for Vulix /app shell
 *
 * Provides an independent findings list and detail view with multi-dimensional
 * filtering (severity, check type, verification status, provenance), evidence
 * viewer rendering via EvidenceViewerRegistry, explicit provenance/verification/review
 * badges (color + text), full-dataset counts with partial-data indication, and
 * deep linking support via URL hash.
 *
 * INVARIANTS:
 * - Agent-reported findings are explicitly labeled, retained, never hidden, removed, or downgraded.
 * - Counts derive from the full dataset; capped/partial results explicitly state partiality.
 * - All untrusted markup in evidence/payload is rendered inertly (escaped, redacted).
 * - Stale or unknown IDs display an explicit not-found state without fabricating fake findings.
 */
(function (global) {
  'use strict';

  const SENSITIVE_KEY_REGEX = /(?:^key$|(?:api|access|auth)[_-]?key|password|passwd|pwd|secret|token|cookie|session[_-]?id|csrf|xsrf|credentials?|signature|samlresponse|(?:^|[._-])(?:sid|sessid|jwt|sig|jsessionid|phpsessid|bearer)(?:$|[._-])|(?:^|[._-])(?:auth|authentication|authorization|session|otp|ticket)$)/i;

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

  const findingViewerHelpers = {
    redactUrl: function (value) { return redactDisplayUrl(value); },
    redactText: function (value) { return redactDisplayText(value); },
  };

  /**
   * Deterministic finding key matching legacy dashboard and backend dedup key.
   * @param {Object} d
   * @returns {string}
   */
  function findingKey(d) {
    if (!d || typeof d !== 'object') return '';
    const base = [
      d.url || '',
      d.field_name || '',
      d.check_type || '',
      d.evidence_type || '',
      d.payload || '',
    ];
    if (d.injection_location === 'json_body') {
      base.push(JSON.stringify(d.injection_method ?? null), JSON.stringify(d.injection_pointer ?? null));
    }
    return base.join('||');
  }

  /**
   * Resolve finding ID: uses explicit id/finding_id when present,
   * otherwise falls back to deterministic findingKey or index.
   */
  function getFindingId(finding, index) {
    if (!finding || typeof finding !== 'object') return String(index ?? '');
    if (finding.id != null && String(finding.id).trim()) return String(finding.id).trim();
    if (finding.finding_id != null && String(finding.finding_id).trim()) return String(finding.finding_id).trim();
    const key = findingKey(finding);
    if (key) return key;
    return String(index ?? '');
  }

  /**
   * Compute Severity badge label and class (color + text).
   */
  function getSeverityLabel(finding) {
    const sev = (finding && finding.severity ? String(finding.severity) : 'info').toLowerCase();
    const labelMap = {
      critical: 'CRITICAL',
      high: 'HIGH',
      medium: 'MEDIUM',
      low: 'LOW',
      info: 'INFO',
    };
    const text = labelMap[sev] || sev.toUpperCase();
    return {
      value: sev,
      text: text,
      cls: 'sev-badge sev-' + (labelMap[sev] ? sev : 'info'),
    };
  }

  /**
   * Compute Verification badge label and class (color + text).
   */
  function getVerificationLabel(finding) {
    if (!finding) return { state: 'unreproduced', text: 'not reproduced', cls: 'verify-badge verify-unreproduced' };
    const st = (finding.verification_state || '').toLowerCase();

    if (st === 'reproduced') {
      return { state: 'reproduced', text: 'reproduced', cls: 'verify-badge verify-reproduced' };
    }
    if (st === 'assumed') {
      return { state: 'assumed', text: 'assumed（推定）', cls: 'verify-badge verify-assumed' };
    }
    if (st === 'unreproduced') {
      return { state: 'unreproduced', text: 'not reproduced', cls: 'verify-badge verify-unreproduced' };
    }
    if (st === 'skipped') {
      return { state: 'skipped', text: 'skipped (needs review)', cls: 'verify-badge verify-skipped' };
    }
    if (st === 'not_checked' || st === 'untested' || st === 'not_tested') {
      return { state: 'untested', text: 'not tested（未検査）', cls: 'verify-badge verify-unreproduced' };
    }
    if (st === 'unknown' || st === 'unavailable') {
      return { state: 'unknown', text: 'unknown（未確定）', cls: 'verify-badge verify-unreproduced' };
    }
    if (finding.verified === false) {
      return { state: 'unreproduced', text: 'not reproduced', cls: 'verify-badge verify-unreproduced' };
    }
    if (finding.source === 'agent' && !finding.agent_verified) {
      return { state: 'assumed', text: 'assumed（推定）', cls: 'verify-badge verify-assumed' };
    }
    if (finding.verified === true) {
      return { state: 'reproduced', text: 'reproduced', cls: 'verify-badge verify-reproduced' };
    }
    // 未確証/未判定 (verified 未指定または null): non-pass として扱う
    return { state: 'unreproduced', text: 'not verified（未確証）', cls: 'verify-badge verify-unreproduced' };
  }

  /**
   * Compute Review State badge label and class (color + text).
   */
  function getReviewStateLabel(finding) {
    if (!finding) return { state: 'unreviewed', text: '未設定 (unreviewed)', cls: 'review-badge review-unset' };
    const raw = finding.review_state || finding.review_status;
    if (raw) {
      const state = String(raw).toLowerCase();
      const map = {
        reviewed: { text: 'reviewed（レビュー済）', cls: 'review-badge review-reviewed' },
        in_review: { text: 'in review（レビュー中）', cls: 'review-badge review-in-review' },
        false_positive: { text: 'false positive（誤検知）', cls: 'review-badge review-false-positive' },
        accepted: { text: 'accepted（受容）', cls: 'review-badge review-accepted' },
        needs_review: { text: 'needs review（要レビュー）', cls: 'review-badge review-needs-review' },
      };
      if (map[state]) {
        return { state: state, text: map[state].text, cls: map[state].cls };
      }
      return { state: state, text: String(raw), cls: 'review-badge review-in-review' };
    }
    return { state: 'unreviewed', text: '未設定 (unreviewed)', cls: 'review-badge review-unset' };
  }

  /**
   * Compute Provenance badge label and class (color + text).
   * Agent findings are explicitly identified and never downgraded or hidden.
   */
  function getProvenanceLabel(finding) {
    if (!finding) {
      return { source: 'scanner', isAgent: false, agentVerified: false, text: '決定論スキャナ', cls: 'provenance-badge provenance-scanner' };
    }
    const isAgent = finding.source === 'agent';
    const agentVerified = Boolean(finding.agent_verified);

    if (isAgent) {
      if (agentVerified) {
        return {
          source: 'agent',
          isAgent: true,
          agentVerified: true,
          text: 'Agent発見 (決定論的再現確認済)',
          cls: 'provenance-badge provenance-agent-verified',
        };
      }
      return {
        source: 'agent',
        isAgent: true,
        agentVerified: false,
        text: 'Agent発見 (未確証)',
        cls: 'provenance-badge provenance-agent',
      };
    }

    return {
      source: 'scanner',
      isAgent: false,
      agentVerified: false,
      text: '決定論スキャナ',
      cls: 'provenance-badge provenance-scanner',
    };
  }

  /**
   * Filter findings by severity, check type, verification, provenance, and text search.
   * Pure function: does not mutate inputs.
   */
  function filterFindings(findings, filters) {
    if (!Array.isArray(findings)) return [];
    if (!filters || typeof filters !== 'object') return [...findings];

    const sevFilter = (filters.severity || 'all').toLowerCase();
    const typeFilter = (filters.checkType || 'all').toLowerCase();
    const verifyFilter = (filters.verification || 'all').toLowerCase();
    const provFilter = (filters.provenance || 'all').toLowerCase();
    const searchFilter = (filters.search || '').trim().toLowerCase();
    const urlFilter = (filters.url || '').trim().toLowerCase();

    return findings.filter(function (f) {
      if (!f || typeof f !== 'object') return false;

      // Severity
      if (sevFilter !== 'all') {
        const s = (f.severity || 'info').toLowerCase();
        if (s !== sevFilter) return false;
      }

      // Check type
      if (typeFilter !== 'all') {
        const ct = (f.check_type || '').toLowerCase();
        if (ct !== typeFilter) return false;
      }

      // Verification
      if (verifyFilter !== 'all') {
        const vInfo = getVerificationLabel(f);
        if (vInfo.state !== verifyFilter) return false;
      }

      // Provenance
      if (provFilter !== 'all') {
        const pInfo = getProvenanceLabel(f);
        if (provFilter === 'agent' && !pInfo.isAgent) return false;
        if (provFilter === 'scanner' && pInfo.isAgent) return false;
        if (provFilter === 'agent_verified' && (!pInfo.isAgent || !pInfo.agentVerified)) return false;
      }

      // URL filter
      if (urlFilter) {
        const fUrl = String(f.url || '').toLowerCase();
        const normFUrl = fUrl.replace(/\/$/, '');
        const normFilter = urlFilter.replace(/\/$/, '');
        if (normFUrl !== normFilter && !fUrl.includes(urlFilter) && !urlFilter.includes(normFUrl)) {
          return false;
        }
      }

      // Text search
      if (searchFilter) {
        const target = (
          (f.check_type || '') + ' ' +
          (f.url || '') + ' ' +
          (f.field_name || '') + ' ' +
          (f.payload || '') + ' ' +
          (f.evidence || '')
        ).toLowerCase();
        if (!target.includes(searchFilter)) return false;
      }

      return true;
    });
  }

  /**
   * Pure calculation of dataset counts and partial-dataset indication.
   */
  function computeFindingCounts(findings, filters, meta) {
    const all = Array.isArray(findings) ? findings : [];
    const loaded = all.length;
    const filtered = filterFindings(all, filters).length;

    let total = null;
    if (meta && typeof meta.total_findings_count === 'number') {
      total = meta.total_findings_count;
    } else if (meta && typeof meta.findings_count === 'number') {
      total = meta.findings_count;
    }

    const isPartial = total === null || loaded < total;
    let label = '';

    if (total === null) {
      label = `表示中: ${filtered} 件 (総件数: 不明)`;
    } else if (loaded < total) {
      label = `表示中: ${filtered} / ${loaded} 件 (全 ${total} 件中)`;
    } else {
      if (filtered === total) {
        label = `全 ${total} 件`;
      } else {
        label = `表示中: ${filtered} / ${total} 件`;
      }
    }

    return {
      total: total,
      loaded: loaded,
      filtered: filtered,
      isPartial: isPartial,
      label: label,
    };
  }

  /**
   * Find a finding by its ID (id, finding_id, findingKey, or index).
   */
  function findFindingById(findings, findingId) {
    if (!Array.isArray(findings) || findingId == null || findingId === '') return null;
    const target = String(findingId).trim();

    for (let i = 0; i < findings.length; i++) {
      const f = findings[i];
      if (!f || typeof f !== 'object') continue;
      if (f.id != null && String(f.id).trim() === target) return f;
      if (f.finding_id != null && String(f.finding_id).trim() === target) return f;
      if (findingKey(f) === target) return f;
      if (String(i) === target) return f;
    }
    return null;
  }

  /**
   * Pure function to build a deep link to the Crawl view focused on a URL/node.
   *
   * @param {string} [scanId]
   * @param {string|Object} [findingOrUrl]
   * @param {string} [nodeId]
   * @returns {string} Hash string e.g. '#/crawl?scan=123&url=http%3A%2F%2F...'
   */
  function buildCrawlLink(scanId, findingOrUrl, nodeId) {
    let hash = '#/crawl';
    const params = new URLSearchParams();
    if (scanId) params.set('scan', String(scanId).trim());

    let targetUrl = '';
    let targetNodeId = nodeId ? String(nodeId).trim() : '';

    if (typeof findingOrUrl === 'string') {
      targetUrl = findingOrUrl.trim();
    } else if (findingOrUrl && typeof findingOrUrl === 'object') {
      if (findingOrUrl.url) targetUrl = String(findingOrUrl.url).trim();
      if (!targetNodeId && findingOrUrl.nodeId) targetNodeId = String(findingOrUrl.nodeId).trim();
      if (!targetNodeId && findingOrUrl.node_id) targetNodeId = String(findingOrUrl.node_id).trim();
    }

    if (targetNodeId) params.set('node', targetNodeId);
    if (targetUrl) params.set('url', targetUrl);

    const qs = params.toString();
    if (qs) hash += '?' + qs;
    return hash;
  }

  /**
   * Pure function to resolve action entry points for a finding based on
   * implemented backend capabilities and finding data.
   *
   * @param {Object} finding
   * @param {Object} [options]
   * @returns {Array<{ id: string, label: string, enabled: boolean, reason: string|null, href?: string, url?: string }>}
   */
  function resolveFindingActions(finding, options = {}) {
    const scanId = options.scanId || (finding && finding.scan_id) || null;
    const url = finding && finding.url ? String(finding.url).trim() : '';
    const hasValidHttpUrl = Boolean(url && /^https?:\/\//i.test(url));

    const manifest = options.manifest || null;
    const hasReplayCapability = Boolean(manifest && manifest.capabilities && manifest.capabilities.replay_finding);
    const hasRequestDetailCapability = Boolean(manifest && manifest.capabilities && manifest.capabilities.request_detail);

    return [
      {
        id: 'crawl_graph',
        label: 'クロールグラフで表示',
        enabled: Boolean(scanId && url),
        href: scanId && url ? buildCrawlLink(scanId, url) : null,
        reason: scanId && url ? null : 'スキャンIDまたはURLがありません',
      },
      {
        id: 'open_browser',
        label: 'ブラウザで開く',
        enabled: hasValidHttpUrl,
        url: hasValidHttpUrl ? url : null,
        reason: hasValidHttpUrl ? null : '利用可能なHTTP(S) URLがありません',
      },
      {
        id: 'reproduce',
        label: '再検証 / 再現実行',
        enabled: hasReplayCapability,
        reason: hasReplayCapability ? null : 'not available in this version',
      },
      {
        id: 'request_detail',
        label: 'リクエスト詳細',
        enabled: hasRequestDetailCapability,
        reason: hasRequestDetailCapability ? null : 'not available in this version',
      },
    ];
  }

  /**
   * Parse deep link hash parameters: scan, finding, and filters.
   */
  function parseFindingDeepLink(hash) {
    const raw = (hash || '').replace(/^#\/?/, '/');
    const parts = raw.split('?');
    const params = new URLSearchParams(parts[1] || '');
    const out = {
      scanId: params.get('scan') || null,
      findingId: params.get('finding') || null,
    };
    if (params.get('url')) out.url = params.get('url');
    if (params.get('search')) out.search = params.get('search');
    if (params.get('severity')) out.severity = params.get('severity');
    if (params.get('checkType')) out.checkType = params.get('checkType');
    if (params.get('verification')) out.verification = params.get('verification');
    if (params.get('provenance')) out.provenance = params.get('provenance');
    return out;
  }

  /**
   * Build hash string for deep link with scan, finding, and optional filters.
   */
  function buildFindingHash(scanId, findingId, filters) {
    let hash = '#/findings';
    const params = new URLSearchParams();
    if (scanId) params.set('scan', scanId);
    if (findingId) params.set('finding', findingId);

    if (filters && typeof filters === 'object') {
      if (filters.url) params.set('url', String(filters.url).trim());
      if (filters.search) params.set('search', String(filters.search).trim());
      if (filters.severity && filters.severity !== 'all') params.set('severity', String(filters.severity).trim());
      if (filters.checkType && filters.checkType !== 'all') params.set('checkType', String(filters.checkType).trim());
      if (filters.verification && filters.verification !== 'all') params.set('verification', String(filters.verification).trim());
      if (filters.provenance && filters.provenance !== 'all') params.set('provenance', String(filters.provenance).trim());
    }

    const qs = params.toString();
    if (qs) hash += '?' + qs;
    return hash;
  }

  /**
   * Render evidence block through EvidenceViewerRegistry.
   */
  function renderEvidenceContent(finding) {
    const reg = global.EvidenceViewerRegistry;
    if (reg && typeof reg.render === 'function') {
      try {
        return reg.render(finding, findingViewerHelpers);
      } catch (err) {
        return `<section class="evidence-viewer"><h4>Evidence</h4><div>${escapeHtml(finding.evidence || '')}</div></section>`;
      }
    }
    return `<section class="evidence-viewer"><h4>Evidence</h4><div>${escapeHtml(finding.evidence || '')}</div></section>`;
  }

  /**
   * Builds the DOM layout for the Findings view.
   */
  function buildFindingsDOM(container) {
    container.replaceChildren();

    const root = document.createElement('div');
    root.className = 'findings-container';

    // ── Toolbar ──
    const toolbar = document.createElement('div');
    toolbar.className = 'findings-toolbar ui-card';

    // Row 1: Scan selector & reload
    const row1 = document.createElement('div');
    row1.className = 'findings-toolbar-row';

    const scanGroup = document.createElement('div');
    scanGroup.className = 'findings-form-group';
    const scanLabel = document.createElement('label');
    scanLabel.className = 'ui-label';
    scanLabel.htmlFor = 'findingsScanSelect';
    scanLabel.textContent = '対象スキャン:';
    const scanSelect = document.createElement('select');
    scanSelect.id = 'findingsScanSelect';
    scanSelect.className = 'ui-select';
    scanGroup.append(scanLabel, scanSelect);

    const refreshBtn = document.createElement('button');
    refreshBtn.type = 'button';
    refreshBtn.id = 'refreshFindingsBtn';
    refreshBtn.className = 'history-btn';
    refreshBtn.textContent = '↻ 更新';

    const countSummary = document.createElement('div');
    countSummary.id = 'findingsCountSummary';
    countSummary.className = 'findings-count-summary';
    countSummary.setAttribute('role', 'status');
    countSummary.setAttribute('aria-live', 'polite');

    row1.append(scanGroup, refreshBtn, countSummary);

    // Row 2: Filters & Search
    const row2 = document.createElement('div');
    row2.className = 'findings-toolbar-row';

    // Severity filter
    const sevSelect = document.createElement('select');
    sevSelect.id = 'filterSeverity';
    sevSelect.className = 'history-filter-select';
    sevSelect.setAttribute('aria-label', '重大度フィルタ');
    [
      { v: 'all', l: '重大度: すべて' },
      { v: 'critical', l: 'CRITICAL' },
      { v: 'high', l: 'HIGH' },
      { v: 'medium', l: 'MEDIUM' },
      { v: 'low', l: 'LOW' },
      { v: 'info', l: 'INFO' },
    ].forEach(function (opt) {
      const o = document.createElement('option');
      o.value = opt.v;
      o.textContent = opt.l;
      sevSelect.appendChild(o);
    });

    // Check type filter
    const typeSelect = document.createElement('select');
    typeSelect.id = 'filterCheckType';
    typeSelect.className = 'history-filter-select';
    typeSelect.setAttribute('aria-label', '検査種別フィルタ');
    const optTypeAll = document.createElement('option');
    optTypeAll.value = 'all';
    optTypeAll.textContent = '検査種別: すべて';
    typeSelect.appendChild(optTypeAll);

    // Verification filter
    const verifySelect = document.createElement('select');
    verifySelect.id = 'filterVerification';
    verifySelect.className = 'history-filter-select';
    verifySelect.setAttribute('aria-label', '確証状態フィルタ');
    [
      { v: 'all', l: '確証状態: すべて' },
      { v: 'reproduced', l: 'reproduced (確証)' },
      { v: 'assumed', l: 'assumed (推定)' },
      { v: 'unreproduced', l: 'not reproduced (未再現)' },
      { v: 'skipped', l: 'skipped (スキップ)' },
    ].forEach(function (opt) {
      const o = document.createElement('option');
      o.value = opt.v;
      o.textContent = opt.l;
      verifySelect.appendChild(o);
    });

    // Provenance filter
    const provSelect = document.createElement('select');
    provSelect.id = 'filterProvenance';
    provSelect.className = 'history-filter-select';
    provSelect.setAttribute('aria-label', '出自フィルタ');
    [
      { v: 'all', l: '出自: すべて (Agent含む)' },
      { v: 'scanner', l: '決定論スキャナ' },
      { v: 'agent', l: 'Agent発見 (LLM独自解釈)' },
      { v: 'agent_verified', l: 'Agent発見 (再現確認済)' },
    ].forEach(function (opt) {
      const o = document.createElement('option');
      o.value = opt.v;
      o.textContent = opt.l;
      provSelect.appendChild(o);
    });

    // Search input
    const searchInput = document.createElement('input');
    searchInput.type = 'search';
    searchInput.id = 'findingsSearchInput';
    searchInput.className = 'history-search-input';
    searchInput.placeholder = 'URL / フィールド / ペイロードで検索…';
    searchInput.setAttribute('aria-label', '検出結果の検索');

    const urlChip = document.createElement('span');
    urlChip.id = 'findingsUrlChip';
    urlChip.className = 'crawl-url-filter-badge';
    urlChip.hidden = true;

    row2.append(sevSelect, typeSelect, verifySelect, provSelect, searchInput, urlChip);
    toolbar.append(row1, row2);
    root.appendChild(toolbar);

    // ── Main Body: Split View (List + Detail) ──
    const splitView = document.createElement('div');
    splitView.className = 'findings-split-view';

    // List Pane
    const listPane = document.createElement('div');
    listPane.id = 'findingsListPane';
    listPane.className = 'findings-list-pane ui-card';
    listPane.tabIndex = 0;
    listPane.setAttribute('aria-label', '検出結果一覧');

    const listStatus = document.createElement('div');
    listStatus.id = 'findingsListStatus';
    listStatus.className = 'ui-status loading';
    listStatus.textContent = '検出結果を読み込み中…';
    listPane.appendChild(listStatus);

    const listContent = document.createElement('div');
    listContent.id = 'findingsListContent';
    listContent.className = 'findings-list-content';
    listPane.appendChild(listContent);

    // Detail Pane
    const detailPane = document.createElement('div');
    detailPane.id = 'findingsDetailPane';
    detailPane.className = 'findings-detail-pane ui-card';
    detailPane.tabIndex = 0;
    detailPane.setAttribute('aria-label', '検出結果詳細');

    const detailEmpty = document.createElement('div');
    detailEmpty.id = 'findingsDetailEmpty';
    detailEmpty.className = 'findings-placeholder';
    detailEmpty.textContent = '一覧から検出結果を選択すると、詳細情報と証跡が表示されます。';
    detailPane.appendChild(detailEmpty);

    const detailContent = document.createElement('div');
    detailContent.id = 'findingsDetailContent';
    detailContent.className = 'findings-detail-content';
    detailContent.hidden = true;
    detailPane.appendChild(detailContent);

    splitView.append(listPane, detailPane);
    root.appendChild(splitView);
    container.appendChild(root);

    return {
      root: root,
      scanSelect: scanSelect,
      refreshBtn: refreshBtn,
      countSummary: countSummary,
      sevSelect: sevSelect,
      typeSelect: typeSelect,
      verifySelect: verifySelect,
      provSelect: provSelect,
      searchInput: searchInput,
      urlChip: urlChip,
      listPane: listPane,
      listStatus: listStatus,
      listContent: listContent,
      detailPane: detailPane,
      detailEmpty: detailEmpty,
      detailContent: detailContent,
    };
  }

  /**
   * Initializes and renders Findings view into container.
   */
  function renderFindingsView(container, options) {
    options = options || {};
    const api = options.api;
    if (!api || typeof api.createScope !== 'function') {
      throw new Error('findings-module requires a valid ApiClient instance');
    }

    const scope = api.createScope();
    const dom = buildFindingsDOM(container);

    let allScans = [];
    let currentScanId = null;
    let allFindings = [];
    let backendMeta = null;
    let selectedFinding = null;
    let selectedFindingId = null;
    let activeUrlFilter = null;

    function getFilters() {
      return {
        severity: dom.sevSelect.value,
        checkType: dom.typeSelect.value,
        verification: dom.verifySelect.value,
        provenance: dom.provSelect.value,
        search: dom.searchInput.value,
        url: activeUrlFilter || '',
      };
    }

    function updateTypeFilterOptions(findings) {
      const currentVal = dom.typeSelect.value;
      const types = new Set();
      (findings || []).forEach(function (f) {
        if (f && f.check_type) types.add(f.check_type.toLowerCase());
      });
      dom.typeSelect.replaceChildren();
      const allOpt = document.createElement('option');
      allOpt.value = 'all';
      allOpt.textContent = '検査種別: すべて';
      dom.typeSelect.appendChild(allOpt);

      Array.from(types).sort().forEach(function (t) {
        const o = document.createElement('option');
        o.value = t;
        o.textContent = t.toUpperCase();
        dom.typeSelect.appendChild(o);
      });

      if (Array.from(types).includes(currentVal)) {
        dom.typeSelect.value = currentVal;
      } else {
        dom.typeSelect.value = 'all';
      }
    }

    function renderDetail(finding, notFoundId) {
      dom.detailContent.replaceChildren();

      if (notFoundId) {
        dom.detailEmpty.hidden = true;
        dom.detailContent.hidden = false;

        const errBox = document.createElement('div');
        errBox.className = 'ui-status error';
        const h = document.createElement('h3');
        h.className = 'findings-notfound-title';
        h.textContent = '指定された Finding は見つかりません';
        const p = document.createElement('p');
        p.className = 'findings-notfound-text';
        p.textContent = `ID: "${notFoundId}" は現在のスキャンデータに存在しないか、既に変更された可能性があります。一覧から選択してください。`;
        errBox.append(h, p);
        dom.detailContent.appendChild(errBox);
        return;
      }

      if (!finding) {
        dom.detailEmpty.hidden = false;
        dom.detailContent.hidden = true;
        return;
      }

      dom.detailEmpty.hidden = true;
      dom.detailContent.hidden = false;

      const sev = getSeverityLabel(finding);
      const verify = getVerificationLabel(finding);
      const review = getReviewStateLabel(finding);
      const prov = getProvenanceLabel(finding);

      // Detail header
      const header = document.createElement('div');
      header.className = 'findings-detail-header';

      const titleRow = document.createElement('div');
      titleRow.className = 'findings-detail-title-row';
      const hTitle = document.createElement('h3');
      hTitle.className = 'findings-detail-title';
      hTitle.textContent = `${(finding.check_type || 'finding').toUpperCase()} on ${finding.field_name || 'URL'}`;
      titleRow.appendChild(hTitle);
      header.appendChild(titleRow);

      // Badges row: Severity, Verification, Review, Provenance
      const badgesRow = document.createElement('div');
      badgesRow.className = 'findings-badges-row';

      const bSev = document.createElement('span');
      bSev.className = sev.cls;
      bSev.textContent = sev.text;

      const bVerify = document.createElement('span');
      bVerify.className = verify.cls;
      bVerify.textContent = verify.text;

      const bReview = document.createElement('span');
      bReview.className = review.cls;
      bReview.textContent = review.text;

      const bProv = document.createElement('span');
      bProv.className = prov.cls;
      bProv.textContent = prov.text;

      badgesRow.append(bSev, bVerify, bReview, bProv);
      header.appendChild(badgesRow);

      // Actions row (capability-gated entry points)
      const actionsRow = document.createElement('div');
      actionsRow.className = 'findings-actions-row';

      const actions = resolveFindingActions(finding, { scanId: currentScanId });
      actions.forEach(function (act) {
        if (act.enabled) {
          if (act.href) {
            const a = document.createElement('a');
            a.className = 'history-btn primary findings-action-btn';
            a.href = act.href;
            a.textContent = `🔍 ${act.label} →`;
            actionsRow.appendChild(a);
          } else if (act.url) {
            const a = document.createElement('a');
            a.className = 'history-btn findings-action-btn';
            a.href = act.url;
            a.target = '_blank';
            a.rel = 'noopener noreferrer';
            a.textContent = `↗ ${act.label}`;
            actionsRow.appendChild(a);
          }
        } else {
          const btn = document.createElement('button');
          btn.type = 'button';
          btn.className = 'history-btn findings-action-btn disabled';
          btn.disabled = true;
          btn.setAttribute('aria-disabled', 'true');
          btn.title = act.reason || 'not available in this version';

          const labelSpan = document.createElement('span');
          labelSpan.textContent = act.label;
          const reasonSpan = document.createElement('span');
          reasonSpan.className = 'action-disabled-tag';
          reasonSpan.textContent = ` (${act.reason || 'not available in this version'})`;

          btn.append(labelSpan, reasonSpan);
          actionsRow.appendChild(btn);
        }
      });
      header.appendChild(actionsRow);

      // Agent Callout banner if agent origin
      if (prov.isAgent) {
        const callout = document.createElement('div');
        callout.className = 'agent-finding-callout';
        callout.textContent = prov.agentVerified
          ? '🤖 Agent発見（決定論的再現確認済）: LLM が自律探索中に独自解釈で発見し、決定論スキャナによる再現性も確認された検出結果です。'
          : '🤖 Agent発見（LLM独自解釈・未確証）: LLM が自律探索中に独自解釈で発見した脆弱性仮説です。決定論的スキャナによる再現とは区別して保持されます。';
        header.appendChild(callout);
      }

      dom.detailContent.appendChild(header);

      // Metadata Table
      const metaCard = document.createElement('div');
      metaCard.className = 'findings-meta-table-wrap';
      const metaTable = document.createElement('table');
      metaTable.className = 'ui-table';
      const metaTbody = document.createElement('tbody');

      const rows = [
        { label: 'Check Type', value: (finding.check_type || '—').toUpperCase() },
        { label: 'Target URL', value: redactDisplayUrl(finding.url || '') || '—', isCode: true },
        { label: 'Field Name', value: redactDisplayText(finding.field_name || '') || '—', isCode: true },
        { label: 'Confidence', value: finding.confidence || 'tentative' },
      ];

      if (finding.payload) {
        rows.push({ label: 'Payload', value: redactDisplayText(finding.payload), isCode: true });
      }
      if (finding.cvss_score != null) {
        rows.push({ label: 'CVSS Score', value: `${finding.cvss_score} (${finding.cvss_vector || '—'})` });
      }
      if (finding.verification_note) {
        rows.push({ label: 'Verification Note', value: redactDisplayText(finding.verification_note) });
      }

      rows.forEach(function (r) {
        const tr = document.createElement('tr');
        const th = document.createElement('th');
        th.className = 'findings-detail-th';
        th.textContent = r.label;
        const td = document.createElement('td');
        if (r.isCode) {
          const code = document.createElement('code');
          code.className = 'ui-code';
          code.textContent = r.value;
          td.appendChild(code);
        } else {
          td.textContent = r.value;
        }
        tr.append(th, td);
        metaTbody.appendChild(tr);
      });
      metaTable.appendChild(metaTbody);
      metaCard.appendChild(metaTable);
      dom.detailContent.appendChild(metaCard);

      // Evidence Section
      const evSection = document.createElement('div');
      evSection.className = 'findings-evidence-section';
      const evHeader = document.createElement('h4');
      evHeader.className = 'findings-section-heading';
      evHeader.textContent = '証跡 / エビデンス (Evidence)';
      evSection.appendChild(evHeader);

      const evContainer = document.createElement('div');
      evContainer.className = 'findings-evidence-wrap';
      evContainer.innerHTML = renderEvidenceContent(finding);
      evSection.appendChild(evContainer);

      dom.detailContent.appendChild(evSection);
    }

    const CHUNK_SIZE = 50;

    function renderList() {
      const filters = getFilters();
      const filtered = filterFindings(allFindings, filters);
      const counts = computeFindingCounts(allFindings, filters, backendMeta);

      dom.countSummary.textContent = counts.label;
      dom.listContent.replaceChildren();

      if (allFindings.length === 0) {
        const empty = document.createElement('div');
        empty.className = 'findings-empty-state';
        empty.textContent = 'このスキャンで検出された脆弱性はありません (0 件)。';
        dom.listContent.appendChild(empty);
        renderDetail(null);
        return;
      }

      if (filtered.length === 0) {
        const noMatch = document.createElement('div');
        noMatch.className = 'findings-empty-state';
        noMatch.textContent = 'フィルタ条件に一致する検出結果はありません。';
        dom.listContent.appendChild(noMatch);
        renderDetail(null);
        return;
      }

      let stillSelected = false;
      let renderedCount = 0;
      let sentinelEl = null;

      function createFindingCard(f, idx) {
        const fid = getFindingId(f, idx);
        const card = document.createElement('div');
        card.className = 'findings-list-card';
        card.setAttribute('role', 'button');
        card.tabIndex = 0;
        card.dataset.findingId = fid;

        const isCurrent = (selectedFindingId && fid === selectedFindingId) ||
          (selectedFinding && (f === selectedFinding || fid === getFindingId(selectedFinding)));

        if (isCurrent) {
          card.classList.add('active');
          card.setAttribute('aria-selected', 'true');
          stillSelected = true;
        }

        const sev = getSeverityLabel(f);
        const verify = getVerificationLabel(f);
        const review = getReviewStateLabel(f);
        const prov = getProvenanceLabel(f);

        // Header: check type + badges
        const cardHdr = document.createElement('div');
        cardHdr.className = 'findings-card-hdr';
        const typeSpan = document.createElement('span');
        typeSpan.className = 'findings-card-type';
        typeSpan.textContent = (f.check_type || 'finding').toUpperCase();

        const badgeWrap = document.createElement('div');
        badgeWrap.className = 'findings-card-badges';

        const bSev = document.createElement('span');
        bSev.className = sev.cls;
        bSev.textContent = sev.text;

        const bVerify = document.createElement('span');
        bVerify.className = verify.cls;
        bVerify.textContent = verify.text;

        const bReview = document.createElement('span');
        bReview.className = review.cls;
        bReview.textContent = review.text;

        const bProv = document.createElement('span');
        bProv.className = prov.cls;
        bProv.textContent = prov.text;

        badgeWrap.append(bSev, bVerify, bReview, bProv);
        cardHdr.append(typeSpan, badgeWrap);
        card.appendChild(cardHdr);

        // Meta: Field & URL (redacted)
        const fieldRow = document.createElement('div');
        fieldRow.className = 'findings-card-field';
        fieldRow.textContent = f.field_name ? `Field: ${redactDisplayText(f.field_name)}` : 'URL Parameter / Path';
        card.appendChild(fieldRow);

        const urlRow = document.createElement('div');
        urlRow.className = 'findings-card-url';
        urlRow.textContent = redactDisplayUrl(f.url || '');
        card.appendChild(urlRow);

        // Snippet
        if (f.evidence) {
          const snip = document.createElement('div');
          snip.className = 'findings-card-evidence';
          snip.textContent = redactDisplayText(f.evidence).slice(0, 100);
          card.appendChild(snip);
        }

        // Selection handler
        function selectThis() {
          selectedFinding = f;
          selectedFindingId = fid;
          renderDetail(f);

          dom.listContent.querySelectorAll('.findings-list-card').forEach(function (c) {
            c.classList.remove('active');
            c.removeAttribute('aria-selected');
          });
          card.classList.add('active');
          card.setAttribute('aria-selected', 'true');

          // Update deep link hash without full re-mount
          if (global.location && typeof global.location.hash === 'string') {
            const nextHash = buildFindingHash(currentScanId, fid, getFilters());
            if (global.location.hash !== nextHash) {
              if (global.history && global.history.replaceState) {
                global.history.replaceState(null, '', nextHash);
              } else {
                global.location.hash = nextHash;
              }
            }
          }
        }

        card.addEventListener('click', selectThis);
        card.addEventListener('keydown', function (e) {
          if (e.key === 'Enter' || e.key === ' ') {
            e.preventDefault();
            selectThis();
          }
        });

        return card;
      }

      function updateSentinel() {
        if (renderedCount < filtered.length) {
          if (!sentinelEl) {
            sentinelEl = document.createElement('div');
            sentinelEl.className = 'findings-list-sentinel';
            sentinelEl.style.cssText = 'padding:10px;text-align:center;font-size:0.75rem;color:var(--text-muted);cursor:pointer;';
            sentinelEl.setAttribute('role', 'button');
            sentinelEl.tabIndex = 0;
            const appendMore = () => renderChunk(CHUNK_SIZE);
            sentinelEl.addEventListener('click', appendMore);
            sentinelEl.addEventListener('keydown', (e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault();
                appendMore();
              }
            });
          }
          sentinelEl.textContent = `${filtered.length.toLocaleString()} 件中 ${renderedCount.toLocaleString()} 件を表示中（スクロールまたはクリックで追加）`;
          dom.listContent.appendChild(sentinelEl);
        } else if (sentinelEl && sentinelEl.parentNode) {
          sentinelEl.remove();
          sentinelEl = null;
        }
      }

      function renderChunk(count) {
        if (sentinelEl && sentinelEl.parentNode) {
          sentinelEl.remove();
        }
        const frag = document.createDocumentFragment();
        const target = Math.min(filtered.length, renderedCount + count);
        for (let i = renderedCount; i < target; i++) {
          const card = createFindingCard(filtered[i], i);
          frag.appendChild(card);
        }
        renderedCount = target;
        dom.listContent.appendChild(frag);
        updateSentinel();
      }

      // Initial chunk: if selected finding is within filtered, ensure initial render includes it
      let initialCount = CHUNK_SIZE;
      if (selectedFindingId) {
        const selIdx = filtered.findIndex((f, idx) => getFindingId(f, idx) === selectedFindingId);
        if (selIdx >= 0) {
          initialCount = Math.max(CHUNK_SIZE, selIdx + 1);
        }
      }

      renderChunk(initialCount);

      // Scroll listener on dom.listPane for bounded infinite scroll
      if (!dom.listPane._hasScrollBound) {
        dom.listPane._hasScrollBound = true;
        let scrollRaf = false;
        dom.listPane.addEventListener('scroll', () => {
          if (scrollRaf) return;
          scrollRaf = true;
          requestAnimationFrame(() => {
            scrollRaf = false;
            if (dom._activeRenderChunk && dom.listPane.scrollTop + dom.listPane.clientHeight >= dom.listPane.scrollHeight - 300) {
              dom._activeRenderChunk(CHUNK_SIZE);
            }
          });
        }, { passive: true });
      }
      dom._activeRenderChunk = (count) => {
        if (renderedCount < filtered.length) {
          renderChunk(count);
        }
      };

      if (!stillSelected) {
        if (selectedFindingId) {
          // Check if selectedFindingId exists anywhere in allFindings
          const foundAnywhere = findFindingById(allFindings, selectedFindingId);
          if (foundAnywhere) {
            // Selected finding exists in full dataset but filtered out
            renderDetail(foundAnywhere);
          } else {
            // Stale or unknown ID
            renderDetail(null, selectedFindingId);
          }
        } else if (filtered.length > 0) {
          // Default select first filtered item
          selectedFinding = filtered[0];
          selectedFindingId = getFindingId(filtered[0], 0);
          const firstCard = dom.listContent.querySelector('.findings-list-card');
          if (firstCard) {
            firstCard.classList.add('active');
            firstCard.setAttribute('aria-selected', 'true');
          }
          renderDetail(selectedFinding);
        }
      }
    }

    async function loadFindingsForScan(scanId, targetFindingId) {
      if (!scanId) return;
      currentScanId = scanId;
      dom.listStatus.hidden = false;
      dom.listStatus.className = 'ui-status loading';
      dom.listStatus.textContent = `スキャン (${scanId}) の検出結果を読み込み中…`;
      dom.listContent.replaceChildren();

      try {
        const res = await scope.get(`/api/v1/scans/${encodeURIComponent(scanId)}/findings`);
        dom.listStatus.hidden = true;

        if (!res.ok || !res.data || res.data.findings === null || res.data.findings_available === false) {
          dom.listStatus.hidden = false;
          dom.listStatus.className = 'ui-status unavailable';
          dom.listStatus.textContent = 'このスキャンの検出結果データは利用できません（evidence.json が存在しないか、読み取れません）。';
          allFindings = [];
          backendMeta = null;
          updateTypeFilterOptions([]);
          renderList();
          renderDetail(null);
          return;
        }

        allFindings = Array.isArray(res.data.findings) ? res.data.findings : [];
        backendMeta = res.data;
        updateTypeFilterOptions(allFindings);

        if (targetFindingId) {
          selectedFindingId = targetFindingId;
          selectedFinding = findFindingById(allFindings, targetFindingId);
          if (!selectedFinding) {
            // Stale / unknown ID
            renderList();
            renderDetail(null, targetFindingId);
            return;
          }
        } else if (allFindings.length > 0) {
          selectedFinding = allFindings[0];
          selectedFindingId = getFindingId(allFindings[0], 0);
        } else {
          selectedFinding = null;
          selectedFindingId = null;
        }

        renderList();
        renderDetail(selectedFinding);
      } catch (err) {
        dom.listStatus.hidden = false;
        dom.listStatus.className = 'ui-status error';
        dom.listStatus.textContent = '検出結果エンドポイントとの通信に失敗しました。';
        renderDetail(null);
      }
    }

    async function initScansAndLoad(route) {
      dom.listStatus.hidden = false;
      dom.listStatus.className = 'ui-status loading';
      dom.listStatus.textContent = 'スキャン履歴を確認中…';

      try {
        const res = await scope.get('/api/v1/scans');
        if (!res.ok || !res.data || !Array.isArray(res.data.scans)) {
          dom.listStatus.className = 'ui-status error';
          dom.listStatus.textContent = 'スキャン一覧を取得できませんでした。';
          return;
        }

        allScans = res.data.scans;
        dom.scanSelect.replaceChildren();

        if (allScans.length === 0) {
          dom.listStatus.className = 'ui-status loading';
          dom.listStatus.textContent = 'スキャン履歴がありません。';
          return;
        }

        allScans.forEach(function (s) {
          const opt = document.createElement('option');
          opt.value = s.id;
          const target = s.target ? ` (${redactDisplayUrl(s.target)})` : '';
          const cnt = s.findings_count != null ? ` — ${s.findings_count}件` : ' — 件数不明';
          opt.textContent = `${s.id}${target}${cnt}`;
          dom.scanSelect.appendChild(opt);
        });

        const targetScanId = route && route.scanId ? route.scanId : null;
        const targetFindingId = route && route.findingId ? route.findingId : null;
        const targetUrl = route && route.url ? route.url : null;
        const targetSearch = route && route.search ? route.search : null;

        if (targetUrl) {
          activeUrlFilter = targetUrl;
          dom.searchInput.value = targetUrl;
          if (dom.urlChip) {
            dom.urlChip.hidden = false;
            dom.urlChip.replaceChildren();
            const chipText = document.createElement('span');
            chipText.textContent = `URLフィルタ: ${targetUrl}`;
            const chipClear = document.createElement('button');
            chipClear.type = 'button';
            chipClear.className = 'findings-chip-clear';
            chipClear.textContent = '✕';
            chipClear.title = 'URLフィルタ解除';
            chipClear.addEventListener('click', function () {
              activeUrlFilter = null;
              dom.searchInput.value = '';
              dom.urlChip.hidden = true;
              onFilterChange();
            });
            dom.urlChip.append(chipText, chipClear);
          }
        } else if (targetSearch) {
          dom.searchInput.value = targetSearch;
        }

        if (route && route.severity) dom.sevSelect.value = route.severity;
        if (route && route.checkType) dom.typeSelect.value = route.checkType;
        if (route && route.verification) dom.verifySelect.value = route.verification;
        if (route && route.provenance) dom.provSelect.value = route.provenance;

        if (targetScanId) {
          const foundScan = allScans.some(function (s) { return s.id === targetScanId; });
          if (!foundScan) {
            dom.listStatus.className = 'ui-status unavailable';
            dom.listStatus.textContent = `指定された Scan ID "${targetScanId}" は見つかりません。削除済みまたは存在しない可能性があります。`;
            renderDetail(null);
            return;
          }
          dom.scanSelect.value = targetScanId;
          await loadFindingsForScan(targetScanId, targetFindingId);
        } else {
          const scanWithFindings = allScans.find(function (s) { return s.findings_count > 0; });
          const defaultScanId = (scanWithFindings || allScans[0]).id;
          dom.scanSelect.value = defaultScanId;
          await loadFindingsForScan(defaultScanId, null);
        }
      } catch (err) {
        dom.listStatus.className = 'ui-status error';
        dom.listStatus.textContent = 'スキャン一覧の読み込みに失敗しました。';
      }
    }

    function onFilterChange() {
      renderList();
      if (global.location && typeof global.location.hash === 'string') {
        const nextHash = buildFindingHash(currentScanId, selectedFindingId, getFilters());
        if (global.location.hash !== nextHash) {
          if (global.history && global.history.replaceState) {
            global.history.replaceState(null, '', nextHash);
          } else {
            global.location.hash = nextHash;
          }
        }
      }
    }

    // Attach event listeners
    dom.scanSelect.addEventListener('change', function () {
      const scanId = dom.scanSelect.value;
      const nextHash = buildFindingHash(scanId, null, getFilters());
      if (global.location && global.location.hash !== nextHash) {
        global.location.hash = nextHash;
      } else {
        loadFindingsForScan(scanId, null);
      }
    });

    dom.refreshBtn.addEventListener('click', function () {
      if (currentScanId) loadFindingsForScan(currentScanId, selectedFindingId);
    });

    dom.sevSelect.addEventListener('change', onFilterChange);
    dom.typeSelect.addEventListener('change', onFilterChange);
    dom.verifySelect.addEventListener('change', onFilterChange);
    dom.provSelect.addEventListener('change', onFilterChange);
    dom.searchInput.addEventListener('input', function () {
      if (activeUrlFilter && dom.searchInput.value !== activeUrlFilter) {
        activeUrlFilter = null;
        if (dom.urlChip) dom.urlChip.hidden = true;
      }
      onFilterChange();
    });

    return {
      dom: dom,
      scope: scope,
      initScansAndLoad: initScansAndLoad,
      destroy: function () {
        scope.cancelAll('Findings view destroyed');
        container.replaceChildren();
      },
    };
  }

  /**
   * Module factory conforming to VulixAppShell ModuleRegistry.
   */
  function createFindingsModule(options) {
    options = options || {};
    let viewInstance = null;

    return {
      id: 'findings',
      title: 'Findings',
      route: '#/findings',
      capabilities: ['findings'],
      mount: function (route) {
        if (typeof options.hideOthers === 'function') {
          options.hideOthers();
        }
        if (typeof options.clearMessage === 'function') {
          options.clearMessage();
        }
        if (options.titleEl) {
          options.titleEl.textContent = 'Findings';
        }
        if (options.contextEl) {
          options.contextEl.textContent = route && route.scanId ? `Scan ${route.scanId}` : '';
        }
        if (options.surfaceEl) {
          options.surfaceEl.hidden = false;
          viewInstance = renderFindingsView(options.surfaceEl, { api: options.api });
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
    findingViewerHelpers: findingViewerHelpers,
    findingKey: findingKey,
    getFindingId: getFindingId,
    getSeverityLabel: getSeverityLabel,
    getVerificationLabel: getVerificationLabel,
    getReviewStateLabel: getReviewStateLabel,
    getProvenanceLabel: getProvenanceLabel,
    filterFindings: filterFindings,
    computeFindingCounts: computeFindingCounts,
    findFindingById: findFindingById,
    parseFindingDeepLink: parseFindingDeepLink,
    buildFindingHash: buildFindingHash,
    buildCrawlLink: buildCrawlLink,
    resolveFindingActions: resolveFindingActions,
    renderEvidenceContent: renderEvidenceContent,
    buildFindingsDOM: buildFindingsDOM,
    renderFindingsView: renderFindingsView,
    createFindingsModule: createFindingsModule,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (global) {
    global.VulixFindingsModule = exportObj;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
