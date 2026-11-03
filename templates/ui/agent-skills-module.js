/**
 * agent-skills-module.js — Agent Capabilities ("skills") Display Module
 *
 * Read-only display module for declared Agent capabilities.
 * Strictly display-only: no skill/plugin loading, no code execution,
 * and no mutation of agent behavior or reported findings.
 * All backend strings are rendered exclusively via textContent.
 */
(function (global) {
  'use strict';

  const SCHEMA_VERSION = '1.0.0';
  const MANIFEST_KIND = 'scanner_capability_manifest';

  const MODE_LABELS = {
    normal: '通常',
    agent: 'Agent',
    hybrid: 'Hybrid',
  };

  /**
   * Format display label for an applicable mode.
   * Unknown modes are formatted safely using the raw string or fallback.
   * @param {string} mode
   * @returns {string}
   */
  function formatMode(mode) {
    if (typeof mode !== 'string') return 'unknown';
    const trimmed = mode.trim();
    if (!trimmed) return 'unknown';
    const lower = trimmed.toLowerCase();
    return MODE_LABELS[lower] || trimmed;
  }

  /**
   * Normalize an agent capability object.
   * Fallback safely for any missing, absent, or malformed fields.
   * Never invent synthetic values.
   * @param {any} raw
   * @returns {{id: string, name: string, description: string, applicableModes: Array<string>, available: boolean|null, availableLabel: string}}
   */
  function normalizeCapability(raw) {
    if (!raw || typeof raw !== 'object') {
      return {
        id: 'unknown',
        name: 'unknown',
        description: 'unknown',
        applicableModes: ['unknown'],
        available: null,
        availableLabel: 'unavailable',
      };
    }

    const id = typeof raw.id === 'string' && raw.id.trim() ? raw.id.trim() : 'unknown';
    const name = typeof raw.name === 'string' && raw.name.trim() ? raw.name.trim() : 'unknown';
    const description = typeof raw.description === 'string' && raw.description.trim() ? raw.description.trim() : 'unknown';

    let applicableModes = [];
    if (Array.isArray(raw.applicable_modes)) {
      applicableModes = raw.applicable_modes
        .map((m) => (typeof m === 'string' && m.trim() ? m.trim() : 'unknown'))
        .filter((m) => m.length > 0);
    }
    if (applicableModes.length === 0) {
      applicableModes = ['unknown'];
    }

    let available = null;
    let availableLabel = 'unavailable';
    if (typeof raw.available === 'boolean') {
      available = raw.available;
      availableLabel = raw.available ? '利用可能' : '利用不可';
    }

    return {
      id: id,
      name: name,
      description: description,
      applicableModes: applicableModes,
      available: available,
      availableLabel: availableLabel,
    };
  }

  /**
   * Render capability table strictly using DOM textContent.
   * @param {HTMLElement} container
   * @param {Array<any>} capabilities
   * @param {Object} [documentRef]
   */
  function renderSkillsTable(container, capabilities, documentRef) {
    const doc = documentRef || (typeof document !== 'undefined' ? document : null);
    if (!doc || !container) return;

    if (typeof container.replaceChildren === 'function') {
      container.replaceChildren();
    } else {
      while (container.firstChild) container.removeChild(container.firstChild);
    }

    const header = doc.createElement('div');
    header.className = 'agent-skills-header';
    const title = doc.createElement('h2');
    title.textContent = 'Agent 機能 (Skills)';
    const desc = doc.createElement('p');
    desc.textContent = 'Agentモードおよびハイブリッドモードで自律探索・推論を行う各機能の宣言情報です（表示専用）。';
    header.appendChild(title);
    header.appendChild(desc);
    container.appendChild(header);

    if (!Array.isArray(capabilities) || capabilities.length === 0) {
      const empty = doc.createElement('div');
      empty.className = 'agent-skills-empty';
      empty.textContent = '宣言された Agent 機能がありません (unavailable)';
      container.appendChild(empty);
      return;
    }

    const card = doc.createElement('div');
    card.className = 'agent-skills-table-card';

    const scroll = doc.createElement('div');
    scroll.className = 'agent-skills-table-scroll';

    const table = doc.createElement('table');
    table.className = 'agent-skills-table';

    const thead = doc.createElement('thead');
    const headerRow = doc.createElement('tr');
    ['機能名', '説明', '適用モード', '状態'].forEach((colTitle) => {
      const th = doc.createElement('th');
      th.textContent = colTitle;
      headerRow.appendChild(th);
    });
    thead.appendChild(headerRow);
    table.appendChild(thead);

    const tbody = doc.createElement('tbody');
    capabilities.forEach((raw) => {
      const cap = normalizeCapability(raw);
      const tr = doc.createElement('tr');

      // 1. Name & ID
      const tdName = doc.createElement('td');
      const nameDiv = doc.createElement('div');
      nameDiv.className = 'agent-skill-name';
      nameDiv.textContent = cap.name;
      const idSpan = doc.createElement('span');
      idSpan.className = 'agent-skill-id';
      idSpan.textContent = cap.id;
      tdName.appendChild(nameDiv);
      tdName.appendChild(idSpan);

      // 2. Description
      const tdDesc = doc.createElement('td');
      tdDesc.className = 'agent-skill-desc';
      tdDesc.textContent = cap.description;

      // 3. Applicable Modes
      const tdModes = doc.createElement('td');
      tdModes.className = 'agent-skill-modes';
      cap.applicableModes.forEach((mode) => {
        const badge = doc.createElement('span');
        const cleanMode = String(mode).toLowerCase();
        badge.className = 'agent-skill-mode-badge' + (cleanMode === 'agent' ? ' mode-agent' : cleanMode === 'hybrid' ? ' mode-hybrid' : '');
        badge.textContent = formatMode(mode);
        tdModes.appendChild(badge);
      });

      // 4. Availability
      const tdStatus = doc.createElement('td');
      const statusBadge = doc.createElement('span');
      const statusClass = cap.available === true
        ? 'status-available'
        : (cap.available === false ? 'status-unavailable' : 'status-unknown');
      statusBadge.className = 'agent-skill-status ' + statusClass;
      statusBadge.textContent = cap.availableLabel;
      tdStatus.appendChild(statusBadge);

      tr.appendChild(tdName);
      tr.appendChild(tdDesc);
      tr.appendChild(tdModes);
      tr.appendChild(tdStatus);
      tbody.appendChild(tr);
    });

    table.appendChild(tbody);
    scroll.appendChild(table);
    card.appendChild(scroll);
    container.appendChild(card);
  }

  /**
   * Render error / fallback state.
   * @param {HTMLElement} container
   * @param {string} [message]
   * @param {Object} [documentRef]
   */
  function renderSkillsError(container, message, documentRef) {
    const doc = documentRef || (typeof document !== 'undefined' ? document : null);
    if (!doc || !container) return;

    if (typeof container.replaceChildren === 'function') {
      container.replaceChildren();
    } else {
      while (container.firstChild) container.removeChild(container.firstChild);
    }

    const errorBox = doc.createElement('div');
    errorBox.className = 'agent-skills-error';
    const h3 = doc.createElement('h3');
    h3.textContent = '機能情報を読み込めませんでした';
    const p = doc.createElement('p');
    p.textContent = message || '機能情報が利用できません (unavailable)';
    errorBox.appendChild(h3);
    errorBox.appendChild(p);
    container.appendChild(errorBox);
  }

  /**
   * Fetch capability manifest and render agent skills.
   * @param {HTMLElement} container
   * @param {Object} [options]
   */
  async function loadAndRenderAgentSkills(container, options = {}) {
    const doc = options.document || (typeof document !== 'undefined' ? document : null);
    if (!doc || !container) return;

    if (typeof container.replaceChildren === 'function') {
      container.replaceChildren();
    } else {
      while (container.firstChild) container.removeChild(container.firstChild);
    }

    const loading = doc.createElement('div');
    loading.className = 'agent-skills-loading';
    loading.textContent = '機能情報を読み込み中...';
    container.appendChild(loading);

    try {
      let data = null;
      if (options.manifest) {
        data = options.manifest;
      } else if (options.api && typeof options.api.get === 'function') {
        const resp = await options.api.get(options.endpoint || '/api/capability-manifest');
        if (!resp || !resp.ok || !resp.data) {
          renderSkillsError(container, '機能情報が利用できません (unavailable)', doc);
          return;
        }
        data = resp.data;
      } else if (typeof fetch === 'function') {
        const resp = await fetch(options.endpoint || '/api/capability-manifest');
        if (!resp.ok) {
          renderSkillsError(container, '機能情報が利用できません (unavailable)', doc);
          return;
        }
        data = await resp.json();
      } else {
        renderSkillsError(container, '機能情報が利用できません (unavailable)', doc);
        return;
      }

      if (!data || typeof data !== 'object') {
        renderSkillsError(container, '機能情報が利用できません (unavailable)', doc);
        return;
      }

      // Schema version check: fallback safely on unsupported version or manifest kind
      if (data.schema_version !== SCHEMA_VERSION || data.manifest_kind !== MANIFEST_KIND) {
        renderSkillsError(container, '機能情報が利用できません (unavailable)', doc);
        return;
      }

      const caps = Array.isArray(data.agent_capabilities) ? data.agent_capabilities : [];
      if (caps.length === 0) {
        renderSkillsError(container, '宣言された Agent 機能がありません (unavailable)', doc);
        return;
      }

      renderSkillsTable(container, caps, doc);
    } catch (_) {
      renderSkillsError(container, '機能情報が利用できません (unavailable)', doc);
    }
  }

  /**
   * Create an app-shell compliant module definition.
   * @param {Object} [options]
   * @returns {Object}
   */
  function createAgentSkillsModule(options = {}) {
    return {
      id: 'agent-skills',
      title: 'Agent Skills',
      route: '#/agent-skills',
      capabilities: ['agent-skills'],
      mount(ctx) {
        const doc = options.document || (typeof document !== 'undefined' ? document : null);
        const container = options.container || (doc ? doc.getElementById('agentSkillsSurface') : null);
        if (container) {
          container.hidden = false;
          loadAndRenderAgentSkills(container, Object.assign({}, options, { document: doc }));
        }
      },
      unmount(ctx) {
        const doc = options.document || (typeof document !== 'undefined' ? document : null);
        const container = options.container || (doc ? doc.getElementById('agentSkillsSurface') : null);
        if (container) {
          container.hidden = true;
          if (typeof container.replaceChildren === 'function') {
            container.replaceChildren();
          } else {
            while (container.firstChild) container.removeChild(container.firstChild);
          }
        }
      },
    };
  }

  /**
   * Register Agent Skills view into a ModuleRegistry.
   * @param {Object} registry
   * @param {Object} [options]
   */
  function registerAgentSkillsModule(registry, options = {}) {
    if (!registry || typeof registry.register !== 'function') {
      throw new Error('Valid ModuleRegistry instance required');
    }
    const def = createAgentSkillsModule(options);
    registry.register(def);
    return def;
  }

  const exportObj = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    MANIFEST_KIND: MANIFEST_KIND,
    formatMode: formatMode,
    normalizeCapability: normalizeCapability,
    renderSkillsTable: renderSkillsTable,
    renderSkillsError: renderSkillsError,
    loadAndRenderAgentSkills: loadAndRenderAgentSkills,
    createAgentSkillsModule: createAgentSkillsModule,
    registerAgentSkillsModule: registerAgentSkillsModule,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = exportObj;
  }
  if (global) {
    global.VulixAgentSkillsModule = exportObj;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
