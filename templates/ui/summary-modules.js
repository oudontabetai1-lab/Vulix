/* Portal, scan history, and audit views for the opt-in application shell. */
(function (global) {
  'use strict';

  const el = (tag, text, cls) => { const node = document.createElement(tag); if (text !== undefined) node.textContent = text; if (cls) node.className = cls; return node; };
  const button = (text, action) => { const node = el('button', text, 'history-btn'); node.type = 'button'; node.addEventListener('click', action); return node; };
  const cell = (row, value, cls) => row.appendChild(el('td', value, cls));
  const knownCount = (value) => typeof value === 'number' && Number.isFinite(value) ? String(value) : '未取得';
  const timestamp = (value) => { if (typeof value !== 'string' || !/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/.test(value)) return '不明'; const date = new Date(value); return Number.isFinite(date.getTime()) ? date.toLocaleString('ja-JP', { year: 'numeric', month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false }) : '不明'; };
  const validIp = (value) => {
    if (typeof value !== 'string') return '—';
    const ip = value.trim();
    if (/^(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])(?:\.(?:25[0-5]|2[0-4][0-9]|1[0-9]{2}|[1-9]?[0-9])){3}$/.test(ip)) return ip;
    if (ip.includes(':') && /^[0-9a-fA-F:]{2,39}$/.test(ip)) {
      const colons = (ip.match(/:/g) || []).length;
      if (colons >= 2 && colons <= 7) return ip;
    }
    return '—';
  };
  const auditActions = { scan_start: 'スキャン開始', scan_abort: 'スキャン中断', scan_delete: 'スキャン削除', scans_prune: '履歴手動整理', schedule_add: '定期追加', schedule_toggle: '定期切替', schedule_delete: '定期削除', upload: 'ファイル配置', settings_update: '設定変更' };

  function createSummaryModules({ api, surfaceEl, titleEl, contextEl, hideOthers, clearMessage }) {
    const reader = global.VulixSummaryReader.createSummaryReader(api);
    let generation = 0;
    const show = (title) => { hideOthers(); clearMessage(); surfaceEl.hidden = false; surfaceEl.replaceChildren(); titleEl.textContent = title; contextEl.textContent = ''; };
    function addScanRows(tableBody, scans) {
      if (!scans || !scans.length) { const row = el('tr'); const td = el('td', scans ? 'スキャン履歴はまだありません。' : 'スキャン履歴を取得できません。'); td.colSpan = 5; row.append(td); tableBody.append(row); return; }
      for (const scan of scans) {
        if (!scan || typeof scan !== 'object') continue;
        const row = el('tr');
        cell(row, `${scan.id || '—'} · ${timestamp(scan.started_at)}`);
        const target = el('td', scan.target ? reader.redactDisplayUrl(scan.target) : '—', 'crawl-detail-url'); target.title = target.textContent; row.append(target);
        cell(row, knownCount(scan.findings_count));
        cell(row, scan.status || '不明');
        const actions = el('td');
        if (scan.report_available && scan.id) { const report = el('a', 'レポート', 'history-btn'); report.href = `/reports/${encodeURIComponent(scan.id)}/report.html`; report.target = '_blank'; report.rel = 'noopener noreferrer'; actions.append(report); }
        if (scan.id) { const zip = el('a', 'ZIP', 'history-btn'); zip.href = `/api/v1/scans/${encodeURIComponent(scan.id)}/download`; actions.append(zip); }
        if (scan.id) actions.append(button('差分', () => showDiff(scan.id)));
        row.append(actions); tableBody.append(row);
      }
    }
    async function showDiff(id) {
      const result = await api.get(`/api/v1/scans/${encodeURIComponent(id)}/diff`);
      const modal = el('section'); modal.className = 'findings-detail-pane'; modal.append(el('h2', '前回スキャンとの差分'));
      if (result.ok && result.data) for (const key of ['new', 'fixed', 'persistent']) {
        const items = Array.isArray(result.data[key]) ? result.data[key] : [];
        modal.append(el('h3', `${key}: ${items.length}`));
        for (const item of items) modal.append(el('p', typeof item === 'string' ? item : [item.check_type, item.field_name, reader.redactDisplayUrl(item.url || '')].filter(Boolean).join(' · ')));
      } else modal.append(el('p', '比較対象を取得できません。'));
      const close = button('閉じる', () => modal.remove()); modal.prepend(close); surfaceEl.append(modal);
    }
    const portal = {
      id: 'portal', title: 'ポータル', route: '#/portal',
      async mount() {
        const current = ++generation; show('ポータル');
        const summary = el('div'); summary.className = 'findings-container'; surfaceEl.append(summary);
        const status = await reader.status();
        if (current !== generation) return;
        const statusCard = el('section', undefined, 'findings-detail-pane');
        statusCard.append(el('h2', '現在のスキャン'), el('p', status ? `${status.status || '不明'} · ${status.scan_id || '—'}` : '状態を取得できません。'));
        const target = el('p', status && status.target ? reader.redactDisplayUrl(status.target) : ''); statusCard.append(target);
        const controls = el('div'); const start = el('a', '新規スキャン', 'history-btn'); start.href = '#/setup'; controls.append(start);
        const monitor = el('a', 'Monitor', 'history-btn'); monitor.href = '#/monitor'; controls.append(monitor);
        if (status && status.status === 'scanning') controls.append(button('停止', async () => { if (global.confirm('実行中のスキャンを停止しますか？現在までの結果で部分レポートが保存されます。')) await api.post('/api/v1/scan/abort'); }));
        statusCard.append(controls); summary.append(statusCard);
        const historyCard = el('section', undefined, 'findings-detail-pane'); historyCard.append(el('h2', 'スキャン履歴'));
        const storage = el('p', 'ストレージ情報を取得できません。'); historyCard.append(storage);
        const table = el('table'); const head = el('thead'); const hr = el('tr');
        for (const label of ['ID / 日時', '対象', '検出', '状態', '操作']) hr.append(el('th', label)); head.append(hr); table.append(head);
        const body = el('tbody'); table.append(body); historyCard.append(table); summary.append(historyCard);
        const data = await reader.scans(); if (current !== generation) return;
        storage.textContent = data && data.storage && typeof data.storage.total_bytes === 'number' ? `使用量 ${data.storage.total_bytes} B` : 'ストレージ情報を取得できません。';
        const prune = button('整理', async () => { if (global.confirm('保持ポリシーを適用して古いスキャンを削除しますか？')) { await api.post('/api/v1/scans/prune', {}); portal.mount(); } });
        prune.hidden = !(data && data.storage && (data.storage.retention_days || data.storage.retention_max_scans)); historyCard.append(prune);
        addScanRows(body, data && data.scans);
        const sched = el('section', undefined, 'findings-detail-pane'); sched.append(el('h2', '定期スキャン'));
        const url = el('input'); url.placeholder = 'https://example.com';
        const checks = el('input'); checks.placeholder = '検査 (空欄で既定)';
        const depth = el('input'); depth.type = 'number'; depth.min = '1'; depth.max = '10'; depth.value = '2';
        const interval = el('input'); interval.type = 'number'; interval.min = '0.1'; interval.step = '0.5'; interval.value = '24';
        const add = button('追加', async () => { const target = url.value.trim(); if (!target) { global.alert('URL を入力してください'); return; } const body = { url: target, depth: parseInt(depth.value, 10) || 2, interval_hours: parseFloat(interval.value) || 24 }; if (checks.value.trim()) body.checks = checks.value.trim(); await api.post('/api/v1/schedules', body); portal.mount(); });
        sched.append(url, checks, depth, interval, add); const list = el('div'); sched.append(list); summary.append(sched);
        const schedules = await reader.schedules(); if (current !== generation) return;
        if (!schedules || !schedules.length) list.append(el('p', schedules ? '登録された定期スキャンはありません。' : '定期スキャンを取得できません。'));
        for (const item of schedules || []) { const line = el('p', `${reader.redactDisplayUrl(item.url || '')} · ${item.interval_hours}h · ${item.enabled ? '有効' : '停止中'}`); line.append(button(item.enabled ? '停止' : '再開', async () => { await api.post(`/api/v1/schedules/${encodeURIComponent(item.id)}/toggle`); portal.mount(); }), button('削除', async () => { if (global.confirm('この定期スキャンを削除しますか？')) { await api.delete(`/api/v1/schedules/${encodeURIComponent(item.id)}`); portal.mount(); } })); list.append(line); }
      }, unmount() { generation++; surfaceEl.hidden = true; surfaceEl.replaceChildren(); },
    };
    const history = {
      id: 'history', title: 'スキャン履歴', route: '#/history',
      async mount() { const current = ++generation; show('スキャン履歴'); const card = el('section', undefined, 'findings-detail-pane'); const search = el('input'); search.type = 'search'; search.placeholder = '対象 / ID'; const refresh = button('更新', () => history.mount()); card.append(search, refresh); const table = el('table'); const body = el('tbody'); table.append(body); card.append(table); surfaceEl.append(card); const data = await reader.scans(); if (current !== generation) return; const scans = data && data.scans || []; search.addEventListener('input', () => { body.replaceChildren(); addScanRows(body, scans.filter((s) => `${s.id || ''} ${reader.redactDisplayUrl(s.target || '')}`.toLowerCase().includes(search.value.toLowerCase()))); }); addScanRows(body, data && data.scans); },
      unmount() { generation++; surfaceEl.hidden = true; surfaceEl.replaceChildren(); },
    };
    const audit = {
      id: 'audit', title: '監査ログ', route: '#/audit',
      async mount() { const current = ++generation; show('監査ログ'); const card = el('section', undefined, 'findings-detail-pane'); const refresh = button('更新', () => audit.mount()); card.append(refresh); const table = el('table'); const body = el('tbody'); table.append(body); card.append(table); surfaceEl.append(card); const entries = await reader.audit(); if (current !== generation) return; if (!entries || !entries.length) { card.append(el('p', entries ? '記録された管理操作はありません。' : '監査ログを取得できません。')); return; } for (const entry of entries) { const row = el('tr'); cell(row, timestamp(entry.ts)); cell(row, auditActions[entry.action] || 'その他操作'); cell(row, validIp(entry.ip)); cell(row, entry.detail ? (typeof entry.detail === 'string' ? '（詳細非表示）' : '（詳細なし）') : '（詳細なし）'); body.append(row); } },
      unmount() { generation++; surfaceEl.hidden = true; surfaceEl.replaceChildren(); },
    };
    return [portal, history, audit];
  }
  global.VulixSummaryModules = { createSummaryModules, knownCount, validIp };
})(typeof window !== 'undefined' ? window : globalThis);
