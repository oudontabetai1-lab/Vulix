/**
 * settings-module.js — Settings view module for Vulix /app shell
 *
 * Provides notification settings management (Slack/Webhook) and read-only
 * system settings schema & effective configuration reference table.
 *
 * INVARIANTS:
 * - Credentials and webhook secrets stay masked exactly as backend returns them.
 * - Raw secrets or masked hints are never re-sent to backend unless entered by user.
 * - Saving and testing are explicit user actions only (no autosave).
 * - Read-only schema and effective config display explicit unavailable states on error;
 *   never synthesizes or fabricates fake settings values.
 */
(function (global) {
  'use strict';

  function escapeHtml(value) {
    if (value == null) return '';
    return String(value)
      .replace(/&/g, '&amp;')
      .replace(/</g, '&lt;')
      .replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;')
      .replace(/'/g, '&#39;');
  }

  function formatValue(value) {
    if (value === null) return 'null';
    if (typeof value === 'object') {
      try {
        return JSON.stringify(value);
      } catch (_) {
        return String(value);
      }
    }
    return String(value);
  }

  /**
   * Builds the DOM layout for the Settings view.
   * @param {HTMLElement} container
   * @returns {Object} References to key interactive DOM nodes
   */
  function buildSettingsDOM(container) {
    container.replaceChildren();

    const root = document.createElement('div');
    root.className = 'ui-settings-container';

    // ── 1. Notification Settings Card ──
    const notifyCard = document.createElement('div');
    notifyCard.className = 'ui-card';
    notifyCard.id = 'notificationCard';

    const notifyTitle = document.createElement('h3');
    notifyTitle.className = 'ui-card-title';
    notifyTitle.textContent = '通知設定 (Slack / Webhook)';
    notifyCard.appendChild(notifyTitle);

    const notifyLoading = document.createElement('div');
    notifyLoading.className = 'ui-status loading';
    notifyLoading.id = 'notifyLoading';
    notifyLoading.setAttribute('role', 'status');
    notifyLoading.textContent = '通知設定を読み込み中…';
    notifyCard.appendChild(notifyLoading);

    const notifyError = document.createElement('div');
    notifyError.className = 'ui-status error';
    notifyError.id = 'notifyError';
    notifyError.setAttribute('role', 'status');
    notifyError.hidden = true;
    notifyCard.appendChild(notifyError);

    const notifyForm = document.createElement('form');
    notifyForm.className = 'ui-form';
    notifyForm.id = 'notifyForm';
    notifyForm.hidden = true;
    notifyForm.setAttribute('onsubmit', 'return false;');

    // Webhook URL input group
    const urlGroup = document.createElement('div');
    urlGroup.className = 'ui-form-group';
    const urlLabel = document.createElement('label');
    urlLabel.className = 'ui-label';
    urlLabel.htmlFor = 'webhookUrlInput';
    urlLabel.textContent = 'Webhook URL';
    const hintSpan = document.createElement('span');
    hintSpan.className = 'ui-hint';
    hintSpan.id = 'webhookHint';
    urlLabel.appendChild(hintSpan);
    urlGroup.appendChild(urlLabel);

    const urlInput = document.createElement('input');
    urlInput.type = 'url';
    urlInput.id = 'webhookUrlInput';
    urlInput.className = 'ui-input';
    urlInput.placeholder = 'https://hooks.slack.com/services/…';
    urlInput.autocomplete = 'off';
    urlInput.spellcheck = false;
    urlGroup.appendChild(urlInput);
    notifyForm.appendChild(urlGroup);

    // Enabled checkbox
    const enabledRow = document.createElement('div');
    enabledRow.className = 'ui-form-row';
    const enabledLabel = document.createElement('label');
    enabledLabel.className = 'ui-checkbox-label';
    const enabledInput = document.createElement('input');
    enabledInput.type = 'checkbox';
    enabledInput.id = 'notifyEnabled';
    enabledLabel.appendChild(enabledInput);
    enabledLabel.appendChild(document.createTextNode(' 通知を有効にする'));
    enabledRow.appendChild(enabledLabel);
    notifyForm.appendChild(enabledRow);

    // Complete notification checkbox
    const completeRow = document.createElement('div');
    completeRow.className = 'ui-form-row';
    const completeLabel = document.createElement('label');
    completeLabel.className = 'ui-checkbox-label';
    const completeInput = document.createElement('input');
    completeInput.type = 'checkbox';
    completeInput.id = 'notifyComplete';
    completeLabel.appendChild(completeInput);
    completeLabel.appendChild(document.createTextNode(' スキャン完了時にサマリーを送信'));
    completeRow.appendChild(completeLabel);
    notifyForm.appendChild(completeRow);

    // Min severity select
    const sevGroup = document.createElement('div');
    sevGroup.className = 'ui-form-group';
    const sevLabel = document.createElement('label');
    sevLabel.className = 'ui-label';
    sevLabel.htmlFor = 'notifyMinSeverity';
    sevLabel.textContent = '最小重大度（通知閾値）';
    sevGroup.appendChild(sevLabel);

    const sevSelect = document.createElement('select');
    sevSelect.id = 'notifyMinSeverity';
    sevSelect.className = 'ui-select';
    ['critical', 'high', 'medium', 'low'].forEach(function (sev) {
      const opt = document.createElement('option');
      opt.value = sev;
      opt.textContent = sev;
      sevSelect.appendChild(opt);
    });
    sevGroup.appendChild(sevSelect);
    notifyForm.appendChild(sevGroup);

    // Action buttons & status
    const actionRow = document.createElement('div');
    actionRow.className = 'ui-actions';

    const saveBtn = document.createElement('button');
    saveBtn.type = 'button';
    saveBtn.id = 'saveSettingsBtn';
    saveBtn.className = 'history-btn primary';
    saveBtn.textContent = '保存';
    actionRow.appendChild(saveBtn);

    const testBtn = document.createElement('button');
    testBtn.type = 'button';
    testBtn.id = 'testNotificationBtn';
    testBtn.className = 'history-btn';
    testBtn.textContent = 'テスト送信';
    actionRow.appendChild(testBtn);

    const statusSpan = document.createElement('span');
    statusSpan.id = 'notifyStatus';
    statusSpan.className = 'ui-status-text';
    statusSpan.setAttribute('aria-live', 'polite');
    actionRow.appendChild(statusSpan);
    notifyForm.appendChild(actionRow);

    const notifyNote = document.createElement('p');
    notifyNote.className = 'ui-note';
    notifyNote.textContent = '完了通知は各スキャン終了時に送信されます。Webhook URL はサーバー側で安全に保持され、UI は入力された資格情報を保持・再送信しません。';
    notifyForm.appendChild(notifyNote);

    notifyCard.appendChild(notifyForm);
    root.appendChild(notifyCard);

    // ── 2. Settings Declaration & Effective Config Card ──
    const configCard = document.createElement('div');
    configCard.className = 'ui-card';
    configCard.id = 'configCard';

    const configHeader = document.createElement('div');
    configHeader.className = 'ui-card-header';
    const configTitle = document.createElement('h3');
    configTitle.className = 'ui-card-title';
    configTitle.textContent = 'システム設定リファレンス（宣言・実効値）';
    configHeader.appendChild(configTitle);
    configCard.appendChild(configHeader);

    const toolbar = document.createElement('div');
    toolbar.className = 'ui-toolbar';

    const modeLabel = document.createElement('label');
    modeLabel.className = 'ui-label';
    modeLabel.htmlFor = 'configModeSelect';
    modeLabel.textContent = 'モード:';
    const modeSelect = document.createElement('select');
    modeSelect.id = 'configModeSelect';
    modeSelect.className = 'ui-select';
    [
      { id: 'normal', label: 'normal (通常)' },
      { id: 'hybrid', label: 'hybrid (Hybrid)' },
      { id: 'agent', label: 'agent (Agent)' },
    ].forEach(function (m) {
      const opt = document.createElement('option');
      opt.value = m.id;
      opt.textContent = m.label;
      modeSelect.appendChild(opt);
    });
    modeLabel.appendChild(modeSelect);
    toolbar.appendChild(modeLabel);

    const profileLabel = document.createElement('label');
    profileLabel.className = 'ui-label';
    profileLabel.htmlFor = 'configProfileSelect';
    profileLabel.textContent = 'Preset:';
    const profileSelect = document.createElement('select');
    profileSelect.id = 'configProfileSelect';
    profileSelect.className = 'ui-select';
    [
      { id: '', label: '(既定値)' },
      { id: 'triage', label: 'triage (高速トリアージ)' },
      { id: 'standard', label: 'standard (標準Web診断)' },
      { id: 'auth', label: 'auth (認証あり診断)' },
      { id: 'precision', label: 'precision (精度重視診断)' },
      { id: 'ctf', label: 'ctf (CTFフラグ探索)' },
    ].forEach(function (p) {
      const opt = document.createElement('option');
      opt.value = p.id;
      opt.textContent = p.label;
      profileSelect.appendChild(opt);
    });
    profileLabel.appendChild(profileSelect);
    toolbar.appendChild(profileLabel);

    const refreshBtn = document.createElement('button');
    refreshBtn.type = 'button';
    refreshBtn.id = 'refreshConfigBtn';
    refreshBtn.className = 'history-btn';
    refreshBtn.textContent = '↻ 更新';
    toolbar.appendChild(refreshBtn);

    const spacer = document.createElement('span');
    spacer.className = 'spacer';
    toolbar.appendChild(spacer);

    const filterInput = document.createElement('input');
    filterInput.type = 'search';
    filterInput.id = 'configFilterInput';
    filterInput.className = 'history-search-input';
    filterInput.placeholder = '設定キー / ラベルで絞り込み…';
    toolbar.appendChild(filterInput);

    configCard.appendChild(toolbar);

    const configLoading = document.createElement('div');
    configLoading.className = 'ui-status loading';
    configLoading.id = 'configLoading';
    configLoading.setAttribute('role', 'status');
    configLoading.textContent = '設定宣言・実効値を読み込み中…';
    configCard.appendChild(configLoading);

    const configUnavailable = document.createElement('div');
    configUnavailable.className = 'ui-status error';
    configUnavailable.id = 'configUnavailable';
    configUnavailable.setAttribute('role', 'status');
    configUnavailable.hidden = true;
    configCard.appendChild(configUnavailable);

    const tableWrap = document.createElement('div');
    tableWrap.className = 'ui-table-wrap';
    tableWrap.id = 'configTableWrap';
    tableWrap.tabIndex = 0;
    tableWrap.setAttribute('aria-label', '設定リファレンステーブル');
    tableWrap.hidden = true;

    const table = document.createElement('table');
    table.className = 'ui-table';

    const thead = document.createElement('thead');
    const headTr = document.createElement('tr');
    [
      { text: '設定キー (Key)', width: '25%' },
      { text: '項目名 (Label)', width: '23%' },
      { text: '型 (Type)', width: '12%' },
      { text: '適用モード', width: '14%' },
      { text: '実効値 (Effective)', width: '14%' },
      { text: 'プリセット差分', width: '12%' },
    ].forEach(function (h) {
      const th = document.createElement('th');
      th.textContent = h.text;
      if (h.width && th.style) th.style.width = h.width;
      headTr.appendChild(th);
    });
    thead.appendChild(headTr);
    table.appendChild(thead);

    const tbody = document.createElement('tbody');
    tbody.id = 'configTableBody';
    table.appendChild(tbody);
    tableWrap.appendChild(table);
    configCard.appendChild(tableWrap);

    const configNote = document.createElement('p');
    configNote.className = 'ui-note';
    configNote.textContent = '※ 設定リファレンスはサーバーが公開する読取専用の仕様宣言および実効設定です。自由入力欄や秘密値は非公開 [非公開] となり値は開示されません。';
    configCard.appendChild(configNote);

    root.appendChild(configCard);
    container.appendChild(root);

    return {
      root: root,
      notifyLoading: notifyLoading,
      notifyError: notifyError,
      notifyForm: notifyForm,
      webhookInput: urlInput,
      webhookHint: hintSpan,
      notifyEnabled: enabledInput,
      notifyComplete: completeInput,
      notifyMinSeverity: sevSelect,
      saveSettingsBtn: saveBtn,
      testNotificationBtn: testBtn,
      notifyStatus: statusSpan,
      modeSelect: modeSelect,
      profileSelect: profileSelect,
      refreshConfigBtn: refreshBtn,
      filterInput: filterInput,
      configLoading: configLoading,
      configUnavailable: configUnavailable,
      configTableWrap: tableWrap,
      configTableBody: tbody,
    };
  }

  /**
   * Render table rows into tbody.
   */
  function renderConfigRows(tbody, schema, effective, mode, filterText) {
    tbody.replaceChildren();

    const normalizedFilter = (filterText || '').trim().toLowerCase();
    const fields = (schema && Array.isArray(schema.fields) ? schema.fields : []).filter(function (field) {
      if (!field.applicable_modes || !field.applicable_modes.includes(mode)) return false;
      if (!normalizedFilter) return true;
      return (
        (field.key && field.key.toLowerCase().includes(normalizedFilter)) ||
        (field.label && field.label.toLowerCase().includes(normalizedFilter))
      );
    });

    if (fields.length === 0) {
      const tr = document.createElement('tr');
      const td = document.createElement('td');
      td.colSpan = 6;
      td.className = 'ui-table-empty';
      td.textContent = normalizedFilter ? '一致する設定項目がありません。' : '設定項目がありません。';
      tr.appendChild(td);
      tbody.appendChild(tr);
      return;
    }

    const values = (effective && effective.values) || {};
    const diff = (effective && effective.diff) || {};
    const redactedKeys = new Set((effective && effective.redacted_keys) || []);

    fields.forEach(function (field) {
      const tr = document.createElement('tr');

      // Key
      const tdKey = document.createElement('td');
      const codeKey = document.createElement('code');
      codeKey.className = 'ui-code';
      codeKey.textContent = field.key;
      tdKey.appendChild(codeKey);
      tr.appendChild(tdKey);

      // Label
      const tdLabel = document.createElement('td');
      tdLabel.textContent = field.label || field.key;
      tr.appendChild(tdLabel);

      // Type
      const tdType = document.createElement('td');
      const badgeType = document.createElement('span');
      badgeType.className = 'ui-badge type';
      badgeType.textContent = field.type;
      tdType.appendChild(badgeType);
      tr.appendChild(tdType);

      // Modes
      const tdModes = document.createElement('td');
      (field.applicable_modes || []).forEach(function (m) {
        const b = document.createElement('span');
        b.className = 'ui-badge mode';
        b.textContent = m;
        tdModes.appendChild(b);
      });
      tr.appendChild(tdModes);

      // Effective value
      const tdVal = document.createElement('td');
      const isRedacted = Boolean(field.redacted) || redactedKeys.has(field.key);
      if (isRedacted) {
        const b = document.createElement('span');
        b.className = 'ui-badge redacted';
        b.textContent = '[非公開]';
        tdVal.appendChild(b);
      } else {
        const val = values[field.key];
        const codeVal = document.createElement('code');
        codeVal.className = 'ui-code';
        codeVal.textContent = formatValue(val);
        tdVal.appendChild(codeVal);
      }
      tr.appendChild(tdVal);

      // Diff
      const tdDiff = document.createElement('td');
      if (diff && Object.prototype.hasOwnProperty.call(diff, field.key)) {
        const d = diff[field.key];
        const spanDiff = document.createElement('span');
        spanDiff.className = 'ui-badge diff';
        spanDiff.textContent = `${formatValue(d.before)} → ${formatValue(d.after)}`;
        tdDiff.appendChild(spanDiff);
      } else {
        const spanNone = document.createElement('span');
        spanNone.className = 'ui-muted';
        spanNone.textContent = '—';
        tdDiff.appendChild(spanNone);
      }
      tr.appendChild(tdDiff);

      tbody.appendChild(tr);
    });
  }

  /**
   * Initializes and renders Settings view into container.
   *
   * @param {HTMLElement} container
   * @param {Object} options
   * @param {Object} options.api - ApiClient instance
   * @returns {Object} { destroy: Function, reload: Function }
   */
  function renderSettingsView(container, options) {
    options = options || {};
    const api = options.api;
    if (!api || typeof api.createScope !== 'function') {
      throw new Error('settings-module requires a valid ApiClient instance');
    }

    const scope = api.createScope();
    const dom = buildSettingsDOM(container);

    let cachedSchema = null;
    let cachedEffective = null;

    async function loadNotifications() {
      dom.notifyLoading.hidden = false;
      dom.notifyError.hidden = true;
      dom.notifyForm.hidden = true;

      try {
        const res = await scope.get('/api/v1/settings');
        if (scope.getActiveCount() === 0 && !res.ok && res.isAborted && res.isAborted()) return;

        dom.notifyLoading.hidden = true;
        if (!res.ok || !res.data || !res.data.notifications) {
          dom.notifyError.textContent = '通知設定を取得できません（利用不可）。';
          dom.notifyError.hidden = false;
          return;
        }

        const n = res.data.notifications;
        dom.notifyForm.hidden = false;
        dom.webhookInput.value = '';
        dom.webhookInput.placeholder = n.webhook_set
          ? '設定済み（変更時のみ入力）'
          : 'https://hooks.slack.com/services/…';
        dom.webhookHint.textContent = n.webhook_set
          ? `現在: ${n.webhook_hint || ''}`
          : '未設定';
        dom.notifyEnabled.checked = Boolean(n.enabled);
        dom.notifyComplete.checked = Boolean(n.notify_complete);
        dom.notifyMinSeverity.value = n.min_severity || 'high';
      } catch (err) {
        dom.notifyLoading.hidden = true;
        dom.notifyError.textContent = '通知設定を取得できません（利用不可）。';
        dom.notifyError.hidden = false;
      }
    }

    async function saveNotifications() {
      dom.notifyStatus.textContent = '保存中…';
      const url = dom.webhookInput.value.trim();
      const payload = {
        notifications: {
          enabled: Boolean(dom.notifyEnabled.checked),
          notify_complete: Boolean(dom.notifyComplete.checked),
          min_severity: dom.notifyMinSeverity.value || 'high',
        },
      };
      // Only include webhook_url if user explicitly entered a new string
      if (url) {
        payload.notifications.webhook_url = url;
      }

      try {
        const res = await scope.post('/api/v1/settings', payload);
        if (!res.ok) {
          const err = (res.data && res.data.error) || res.errorMessage || '保存に失敗しました';
          dom.notifyStatus.textContent = err;
          return;
        }

        dom.notifyStatus.textContent = '通知設定を保存しました';
        dom.webhookInput.value = '';
        await loadNotifications();
      } catch (err) {
        dom.notifyStatus.textContent = '保存に失敗しました';
      }
    }

    async function testNotifications() {
      dom.notifyStatus.textContent = 'テスト送信中…';
      try {
        const res = await scope.post('/api/v1/settings/test');
        if (!res.ok) {
          const err = (res.data && res.data.error) || res.errorMessage || 'テスト送信に失敗しました';
          dom.notifyStatus.textContent = err;
          return;
        }
        dom.notifyStatus.textContent = 'テスト通知を送信しました';
      } catch (err) {
        dom.notifyStatus.textContent = 'テスト送信に失敗しました';
      }
    }

    async function loadConfigData() {
      const mode = dom.modeSelect.value || 'normal';
      const profile = mode === 'agent' ? '' : (dom.profileSelect.value || '');

      dom.configLoading.hidden = false;
      dom.configUnavailable.hidden = true;
      dom.configTableWrap.hidden = true;

      try {
        const effPath =
          '/api/v1/settings/effective?mode=' +
          encodeURIComponent(mode) +
          (profile ? '&profile=' + encodeURIComponent(profile) : '');

        const [schemaRes, effRes] = await Promise.all([
          scope.get('/api/v1/settings/schema'),
          scope.get(effPath),
        ]);

        if (scope.getActiveCount() === 0 && (!schemaRes.ok || !effRes.ok)) {
          if (schemaRes.isAborted && schemaRes.isAborted()) return;
        }

        dom.configLoading.hidden = true;

        if (!schemaRes.ok || !schemaRes.data || !effRes.ok || !effRes.data) {
          dom.configUnavailable.textContent = '設定情報エンドポイントが利用できません（利用不可）。';
          dom.configUnavailable.hidden = false;
          return;
        }

        cachedSchema = schemaRes.data;
        cachedEffective = effRes.data;

        dom.configTableWrap.hidden = false;
        renderConfigRows(
          dom.configTableBody,
          cachedSchema,
          cachedEffective,
          mode,
          dom.filterInput.value
        );
      } catch (err) {
        dom.configLoading.hidden = true;
        dom.configUnavailable.textContent = '設定情報エンドポイントが利用できません（利用不可）。';
        dom.configUnavailable.hidden = false;
      }
    }

    // Attach listeners
    dom.saveSettingsBtn.addEventListener('click', saveNotifications);
    dom.testNotificationBtn.addEventListener('click', testNotifications);

    dom.modeSelect.addEventListener('change', function () {
      const mode = dom.modeSelect.value;
      if (mode === 'agent') {
        dom.profileSelect.disabled = true;
        dom.profileSelect.value = '';
      } else {
        dom.profileSelect.disabled = false;
      }
      loadConfigData();
    });

    dom.profileSelect.addEventListener('change', function () {
      loadConfigData();
    });

    dom.refreshConfigBtn.addEventListener('click', function () {
      loadConfigData();
    });

    dom.filterInput.addEventListener('input', function () {
      if (cachedSchema && cachedEffective) {
        renderConfigRows(
          dom.configTableBody,
          cachedSchema,
          cachedEffective,
          dom.modeSelect.value || 'normal',
          dom.filterInput.value
        );
      }
    });

    // Initial load
    loadNotifications();
    loadConfigData();

    return {
      dom: dom,
      scope: scope,
      destroy: function () {
        scope.cancelAll('Settings view destroyed');
        container.replaceChildren();
      },
      reload: function () {
        loadNotifications();
        loadConfigData();
      },
    };
  }

  /**
   * Creates a module definition conforming to ModuleRegistry.
   *
   * @param {Object} options
   * @param {Object} options.api
   * @param {HTMLElement} options.surfaceEl
   * @param {HTMLElement} [options.titleEl]
   * @param {HTMLElement} [options.contextEl]
   * @param {Function} [options.clearMessage]
   * @param {Function} [options.hideOthers]
   */
  function createSettingsModule(options) {
    options = options || {};
    let viewInstance = null;

    return {
      id: 'settings',
      title: 'Settings',
      route: '#/settings',
      capabilities: ['settings'],
      mount: function () {
        if (typeof options.hideOthers === 'function') {
          options.hideOthers();
        }
        if (typeof options.clearMessage === 'function') {
          options.clearMessage();
        }
        if (options.titleEl) {
          options.titleEl.textContent = 'Settings';
        }
        if (options.contextEl) {
          options.contextEl.textContent = '';
        }
        if (options.surfaceEl) {
          options.surfaceEl.hidden = false;
          viewInstance = renderSettingsView(options.surfaceEl, { api: options.api });
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
    buildSettingsDOM: buildSettingsDOM,
    renderConfigRows: renderConfigRows,
    renderSettingsView: renderSettingsView,
    createSettingsModule: createSettingsModule,
    escapeHtml: escapeHtml,
    formatValue: formatValue,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (global) {
    global.VulixSettingsModule = exportObj;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
