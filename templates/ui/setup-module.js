/**
 * setup-module.js — 5-Tab Setup View Module for Vulix /app shell
 *
 * Backed strictly by the server's settings schema declaration (/api/v1/settings/schema).
 *
 * INVARIANTS:
 * - Field labels, applicable modes, and defaults come from server declaration.
 * - No second client-side schema or duplicate defaults.
 * - When declaration endpoint is unavailable, shows explicit unavailable state
 *   and falls back to legacy-compatible setup surface.
 * - Scan start payloads for normal, Agent, and Hybrid are byte-for-byte equivalent
 *   to what the legacy form sends for the same inputs.
 * - Full roving tabindex and arrow-key navigation across the five tabs.
 * - Explicit field-level validation errors for numbers and constraints.
 */
(function (global) {
  'use strict';

  const SCHEMA_VERSION = '1.0.0';
  const MANIFEST_KIND = 'settings_schema';

  const MODE_LABELS = {
    normal: '通常',
    agent: 'Agent',
    hybrid: 'Hybrid',
  };

  function formatValue(v) {
    if (v === null || v === undefined) return '(なし)';
    if (typeof v === 'boolean') return v ? 'true' : 'false';
    if (Array.isArray(v)) return `[${v.join(', ')}]`;
    if (typeof v === 'object') return JSON.stringify(v);
    return String(v);
  }

  const TAB_DEFINITIONS = [
    { id: 'crawl', label: 'クロール・スコープ' },
    { id: 'checks', label: '検査項目・ペイロード' },
    { id: 'auth', label: '認証・ネットワーク' },
    { id: 'ai', label: 'AI・自律探索' },
    { id: 'advanced', label: '高度な設定・フロー' },
  ];

  const FIELD_TAB_MAP = {
    // Tab 1: crawl
    'depth': 'crawl',
    'timeout': 'crawl',
    'max_forms': 'crawl',
    'request_delay': 'crawl',
    'navigation_retries': 'crawl',
    'target_urls': 'crawl',
    'access_urls': 'crawl',
    'exclude_urls': 'crawl',
    'exclude_fields': 'crawl',
    'manual_crawl_file': 'crawl',
    'toggles.enable_sitemap_crawl': 'crawl',
    'toggles.spa_crawl': 'crawl',
    'toggles.auto_spa_crawl': 'crawl',
    'toggles.interactive_crawl_review': 'crawl',

    // Tab 2: checks
    'checks': 'checks',
    'max_payloads': 'checks',
    'payloads_file': 'checks',
    'toggles.fast_mode': 'checks',
    'state_profile': 'checks',
    'toggles.allow_state_changing_probes': 'checks',
    'toggles.community_payloads': 'checks',
    'toggles.component_intel': 'checks',
    'toggles.tls_scan': 'checks',
    'toggles.ctf_mode': 'checks',
    'ctf_flag_pattern': 'checks',

    // Tab 3: auth
    'auth_user': 'auth',
    'auth_pass': 'auth',
    'login_url': 'auth',
    'login_user_field': 'auth',
    'login_pass_field': 'auth',
    'login_success_indicator': 'auth',
    'cookies': 'auth',
    'low_priv_cookies': 'auth',
    'bearer': 'auth',
    'headers': 'auth',
    'accounts': 'auth',
    'toggles.auto_register': 'auth',
    'auto_register_count': 'auth',
    'toggles.skip_registration': 'auth',
    'mfa_type': 'auth',
    'mfa_field': 'auth',
    'mfa_selector': 'auth',
    'mfa_email_account': 'auth',
    'mfa_email_address': 'auth',
    'mfa_email_imap_host': 'auth',
    'mfa_email_imap_port': 'auth',
    'mfa_email_imap_user': 'auth',
    'mfa_email_imap_password': 'auth',
    'mfa_email_imap_ssl': 'auth',
    'mfa_totp_uri': 'auth',
    'mfa_totp_secret': 'auth',
    'mfa_totp_qr': 'auth',
    'mfa_totp_digits': 'auth',
    'mfa_totp_period': 'auth',
    'mfa_totp_algorithm': 'auth',
    'proxy': 'auth',
    'tls_client_cert': 'auth',
    'tls_client_key': 'auth',
    'tls_client_pfx': 'auth',
    'tls_client_cert_password': 'auth',
    'tls_ca_cert': 'auth',
    'tls_verify': 'auth',
    'toggles.tls_verify': 'auth',
    'header_scope_enforce': 'auth',
    'popup_header_intercept': 'auth',
    'allowed_hours': 'auth',
    'forbidden_hours': 'auth',

    // Tab 4: ai
    'llm': 'ai',
    'ollama_model': 'ai',
    'openai_model': 'ai',
    'gemini_model': 'ai',
    'claude_model': 'ai',
    'openai_base_url': 'ai',
    'role_models': 'ai',
    'llm_timeout_seconds': 'ai',
    'llm_stream_timeout_seconds': 'ai',
    'llm_max_retries': 'ai',
    'toggles.use_planner': 'ai',
    'toggles.interactive_plan': 'ai',
    'toggles.enable_ai_analysis': 'ai',
    'toggles.enable_waf_detection': 'ai',
    'toggles.enable_payload_learning': 'ai',
    'toggles.enable_llm_web_browsing': 'ai',
    'agent_model': 'ai',
    'agent_ollama_url': 'ai',
    'agent_max_steps': 'ai',
    'hybrid_llm': 'ai',
    'hybrid_model': 'ai',
    'hybrid_ollama_url': 'ai',
    'hybrid_max_steps': 'ai',

    // Tab 5: advanced
    'flows': 'advanced',
    'concurrency': 'advanced',
    'toggles.headless': 'advanced',
    'toggles.open_report': 'advanced',
    'report_lang': 'advanced',
    'output_dir': 'advanced',
  };

  const ADVANCED_FIELDS = new Set([
    // Crawl tab advanced
    'request_delay', 'navigation_retries', 'target_urls', 'access_urls',
    'exclude_urls', 'exclude_fields', 'manual_crawl_file',
    'toggles.enable_sitemap_crawl', 'toggles.spa_crawl',
    'toggles.auto_spa_crawl', 'toggles.interactive_crawl_review',

    // Checks tab advanced
    'state_profile', 'allow_state_changing_probes', 'toggles.allow_state_changing_probes',
    'community_payloads', 'toggles.community_payloads',
    'component_intel', 'toggles.component_intel',
    'tls_scan', 'toggles.tls_scan',
    'ctf_mode', 'toggles.ctf_mode', 'ctf_flag_pattern', 'payloads_file',

    // Auth tab advanced
    'login_user_field', 'login_pass_field', 'login_success_indicator',
    'low_priv_cookies', 'headers', 'accounts',
    'toggles.auto_register', 'auto_register_count', 'toggles.skip_registration',
    'mfa_type', 'mfa_field', 'mfa_selector', 'mfa_email_account',
    'mfa_email_address', 'mfa_email_imap_host', 'mfa_email_imap_port',
    'mfa_email_imap_user', 'mfa_email_imap_password', 'mfa_email_imap_ssl',
    'mfa_totp_uri', 'mfa_totp_secret', 'mfa_totp_qr', 'mfa_totp_digits',
    'mfa_totp_period', 'mfa_totp_algorithm',
    'proxy', 'tls_client_cert', 'tls_client_key', 'tls_client_pfx',
    'tls_client_cert_password', 'tls_ca_cert', 'tls_verify', 'toggles.tls_verify',
    'header_scope_enforce', 'popup_header_intercept',
    'allowed_hours', 'forbidden_hours',

    // AI tab advanced
    'role_models', 'openai_base_url', 'llm_timeout_seconds', 'llm_stream_timeout_seconds',
    'llm_max_retries', 'toggles.use_planner', 'toggles.interactive_plan',
    'toggles.enable_ai_analysis', 'toggles.enable_waf_detection',
    'toggles.enable_payload_learning', 'toggles.enable_llm_web_browsing',
    'agent_ollama_url', 'agent_max_steps', 'hybrid_ollama_url', 'hybrid_max_steps',

    // Advanced tab advanced
    'concurrency', 'output_dir', 'flows',
  ]);

  const KEY_TO_ID_MAP = {
    'url': 'cfgInputUrl',
    'depth': 'cfgDepth',
    'timeout': 'cfgTimeoutInput',
    'report_lang': 'cfgReportLang',
    'llm_timeout_seconds': 'cfgLlmTimeoutInput',
    'llm_stream_timeout_seconds': 'cfgLlmStreamTimeoutInput',
    'max_forms': 'cfgMaxForms',
    'concurrency': 'cfgConcurrency',
    'proxy': 'cfgProxy',
    'tls_client_cert': 'cfgTlsClientCert',
    'tls_client_key': 'cfgTlsClientKey',
    'tls_client_pfx': 'cfgTlsClientPfx',
    'tls_client_cert_password': 'cfgTlsClientCertPassword',
    'tls_ca_cert': 'cfgTlsCaCert',
    'tls_verify': 'cfgTlsVerify',
    'header_scope_enforce': 'cfgHeaderScopeEnforce',
    'popup_header_intercept': 'cfgPopupHeaderIntercept',
    'llm': 'cfgLlm',
    'ollama_model': 'cfgOllamaModel',
    'openai_model': 'cfgOpenaiModel',
    'gemini_model': 'cfgGeminiModel',
    'claude_model': 'cfgClaudeModel',
    'openai_base_url': 'cfgLlmBaseUrl',
    'llm_max_retries': 'cfgLlmMaxRetries',
    'auth_user': 'cfgAuthUser',
    'auth_pass': 'cfgAuthPass',
    'login_url': 'cfgLoginUrl',
    'login_user_field': 'cfgLoginUserField',
    'login_pass_field': 'cfgLoginPassField',
    'login_success_indicator': 'cfgLoginSuccess',
    'mfa_type': 'cfgMfaType',
    'mfa_field': 'cfgMfaField',
    'mfa_selector': 'cfgMfaSelector',
    'mfa_email_account': 'cfgMfaEmailAccount',
    'mfa_email_address': 'cfgMfaEmailAddress',
    'mfa_email_imap_host': 'cfgMfaEmailImapHost',
    'mfa_email_imap_port': 'cfgMfaEmailImapPort',
    'mfa_email_imap_user': 'cfgMfaEmailImapUser',
    'mfa_email_imap_password': 'cfgMfaEmailImapPassword',
    'mfa_email_imap_ssl': 'cfgMfaEmailImapSsl',
    'mfa_totp_uri': 'cfgMfaTotpUri',
    'mfa_totp_secret': 'cfgMfaTotpSecret',
    'mfa_totp_qr': 'cfgMfaTotpQr',
    'mfa_totp_digits': 'cfgMfaTotpDigits',
    'mfa_totp_period': 'cfgMfaTotpPeriod',
    'mfa_totp_algorithm': 'cfgMfaTotpAlgorithm',
    'cookies': 'cfgCookies',
    'low_priv_cookies': 'cfgLowPrivCookies',
    'max_payloads': 'cfgMaxPayloads',
    'request_delay': 'cfgDelay',
    'navigation_retries': 'cfgNavigationRetries',
    'output_dir': 'cfgOutputDir',
    'payloads_file': 'cfgPayloadsFile',
    'manual_crawl_file': 'cfgManualCrawlFile',
    'auto_register_count': 'cfgAutoRegisterCount',
    'exclude_fields': 'cfgExcludeFields',
    'exclude_urls': 'cfgExcludeUrls',
    'target_urls': 'cfgTargetUrls',
    'access_urls': 'cfgAccessUrls',
    'bearer': 'cfgBearer',
    'headers': 'cfgHeaders',
    'allowed_hours': 'cfgAllowedHours',
    'forbidden_hours': 'cfgForbiddenHours',
    'state_profile': 'cfgStateProfile',
    'ctf_flag_pattern': 'cfgCtfFlagPattern',
    'agent_model': 'agentModel',
    'agent_ollama_url': 'agentOllamaUrl',
    'agent_max_steps': 'agentMaxSteps',
    'hybrid_llm': 'hybridLlm',
    'hybrid_model': 'hybridModel',
    'hybrid_max_steps': 'hybridMaxSteps',
    'hybrid_ollama_url': 'hybridOllamaUrl',
  };

  /**
   * Helper: Parse multi-line "Name: Value" headers.
   */
  function parseHeaderText(text) {
    const out = {};
    (text || '').split('\n').forEach((line) => {
      const idx = line.indexOf(':');
      if (idx > 0) {
        const k = line.slice(0, idx).trim();
        const v = line.slice(idx + 1).trim();
        if (k) out[k] = v;
      }
    });
    return out;
  }

  /**
   * Helper: Collect auth headers matching legacy authHeaderFields.
   */
  function buildAuthHeaderFields(getVal) {
    const bearer = getVal('cfgBearer').trim();
    const headers = parseHeaderText(getVal('cfgHeaders'));
    const out = {};
    if (bearer) out.bearer = bearer;
    if (Object.keys(headers).length) out.headers = headers;
    return out;
  }

  /**
   * Helper: Collect time window fields matching legacy timeWindowFields.
   */
  function buildTimeWindowFields(getVal) {
    const toList = (val) => (val || '').split('\n').map((s) => s.trim()).filter(Boolean);
    const out = {};
    const a = toList(getVal('cfgAllowedHours'));
    if (a.length) out.allowed_hours = a;
    const f = toList(getVal('cfgForbiddenHours'));
    if (f.length) out.forbidden_hours = f;
    return out;
  }

  /**
   * Helper: Collect native TOTP fields matching legacy mfaTotpFields.
   */
  function buildMfaTotpFields(getVal) {
    return {
      mfa_selector: getVal('cfgMfaSelector').trim(),
      mfa_totp_uri: getVal('cfgMfaTotpUri').trim(),
      mfa_totp_secret: getVal('cfgMfaTotpSecret').trim(),
      mfa_totp_qr: getVal('cfgMfaTotpQr').trim(),
      mfa_totp_digits: getVal('cfgMfaTotpDigits').trim(),
      mfa_totp_period: getVal('cfgMfaTotpPeriod').trim(),
      mfa_totp_algorithm: getVal('cfgMfaTotpAlgorithm').trim(),
    };
  }

  /**
   * Helper: Collect MFA IMAP fields matching legacy mfaImapFields.
   */
  function buildMfaImapFields(getVal) {
    return {
      mfa_email_address: getVal('cfgMfaEmailAddress').trim(),
      mfa_email_imap_host: getVal('cfgMfaEmailImapHost').trim(),
      mfa_email_imap_port: getVal('cfgMfaEmailImapPort').trim(),
      mfa_email_imap_user: getVal('cfgMfaEmailImapUser').trim(),
      mfa_email_imap_ssl: getVal('cfgMfaEmailImapSsl').trim(),
    };
  }

  /**
   * Helper: Collect MFA IMAP password matching legacy mfaImapPassword.
   */
  function buildMfaImapPassword(getVal) {
    const v = getVal('cfgMfaEmailImapPassword').trim();
    return v ? { mfa_email_imap_password: v } : {};
  }

  /**
   * Pure Scan Payload Builder.
   * Produces byte-for-byte equivalent payloads to the legacy form
   * (submitScanConfig, submitAgentScan, submitHybridScan).
   *
   * @param {'normal'|'agent'|'hybrid'} mode
   * @param {Object} [env]
   * @returns {Object}
   */
  function buildScanPayload(mode, env = {}) {
    const doc = env.document || (typeof document !== 'undefined' ? document : null);
    const getVal = (id) => {
      if (env.values && typeof env.values[id] !== 'undefined') {
        const v = env.values[id];
        return v == null ? '' : String(v);
      }
      if (doc && typeof doc.getElementById === 'function') {
        const el = doc.getElementById(id);
        if (el) return el.value != null ? String(el.value) : '';
      }
      return '';
    };

    const getToggles = () => {
      if (env.toggles && typeof env.toggles === 'object') return env.toggles;
      if (typeof cfgToggles !== 'undefined') return cfgToggles;
      // Derive from checkboxes in doc
      const toggles = {};
      if (doc && typeof doc.querySelectorAll === 'function') {
        const cbs = doc.querySelectorAll('input[type="checkbox"][data-toggle]');
        cbs.forEach((cb) => {
          toggles[cb.dataset.toggle] = cb.checked;
        });
      }
      return toggles;
    };

    const getChecks = (forMode) => {
      if (Array.isArray(env.checks)) return [...env.checks];
      if (doc && typeof doc.querySelectorAll === 'function') {
        if (forMode === 'agent') {
          const cbs = doc.querySelectorAll('#agentChecks input[type=checkbox]:checked, .setup-agent-check:checked');
          if (cbs.length) return Array.from(cbs).map((cb) => cb.value);
        }
        const checked = doc.querySelectorAll('.cfg-check-item.checked, input[type=checkbox][data-check]:checked');
        if (checked.length) {
          return Array.from(checked).map((el) => el.dataset.check || el.value);
        }
      }
      return [];
    };

    const getAccounts = () => {
      if (Array.isArray(env.accounts)) return env.accounts;
      if (doc && typeof doc.querySelectorAll === 'function') {
        const items = doc.querySelectorAll('#accountsList > div');
        if (items.length) {
          return Array.from(items).map((div) => ({
            username: (div.querySelector('.acc-user')?.value || '').trim(),
            password: div.querySelector('.acc-pass')?.value || '',
            role: div.querySelector('.acc-role')?.value || 'user',
          })).filter((a) => a.username);
        }
      }
      return [];
    };

    const getFlows = () => {
      if (Array.isArray(env.flows)) return env.flows;
      if (typeof cfgFlows !== 'undefined' && Array.isArray(cfgFlows)) {
        return cfgFlows
          .filter((f) => Array.isArray(f.steps) && f.steps.length)
          .map((f) => ({ name: f.name, steps: f.steps.map((s) => Object.assign({}, s)) }));
      }
      return [];
    };

    const getRoleModels = () => {
      if (env.role_models && typeof env.role_models === 'object') return env.role_models;
      const fields = {
        planner: 'cfgPlannerModel',
        payload: 'cfgPayloadModel',
        adaptive: 'cfgAdaptiveModel',
        triage: 'cfgTriageModel',
      };
      const models = {};
      for (const [role, id] of Object.entries(fields)) {
        const val = getVal(id).trim();
        if (val) models[role] = val;
      }
      return models;
    };

    const url = getVal('cfgInputUrl').trim();

    if (mode === 'agent') {
      const agentChecks = getChecks('agent');
      return {
        url: url,
        agent_mode: true,
        report_lang: getVal('cfgReportLang') || 'ja',
        llm: getVal('agentLlm') || getVal('cfgLlm') || 'ollama',
        agent_model: getVal('agentModel').trim(),
        agent_max_steps: parseInt(getVal('agentMaxSteps'), 10) || 50,
        agent_ollama_url: getVal('agentOllamaUrl').trim() || 'http://localhost:11434',
        llm_timeout_seconds: parseFloat(getVal('agentLlmTimeout') || getVal('cfgLlmTimeoutInput')) || 30,
        checks: agentChecks.length ? agentChecks : ['xss', 'sqli', 'ssti', 'os', 'path_traversal', 'ssrf'],
        login_url: getVal('agentLoginUrl').trim(),
        auth_user: getVal('agentAuthUser').trim(),
        auth_pass: getVal('agentAuthPass'),
        ...buildAuthHeaderFields(getVal),
        ...buildTimeWindowFields(getVal),
        headless: true,
        open_report: true,
      };
    }

    if (mode === 'hybrid') {
      const selectedChecks = getChecks('hybrid');
      const checks = selectedChecks.length ? selectedChecks : ['sqli', 'xss', 'os'];
      const toggles = getToggles();
      return {
        url: url,
        hybrid_mode: true,
        hybrid_llm: getVal('hybridLlm') || 'claude',
        hybrid_model: getVal('hybridModel').trim(),
        hybrid_max_steps: parseInt(getVal('hybridMaxSteps'), 10) || 30,
        hybrid_ollama_url: getVal('hybridOllamaUrl').trim() || 'http://localhost:11434',
        checks: checks,
        headless: Boolean(toggles.headless),
        depth: parseInt(getVal('cfgDepth'), 10) || 2,
        timeout: parseInt(getVal('cfgTimeoutInput'), 10) || 30,
        report_lang: getVal('cfgReportLang') || 'ja',
        llm_timeout_seconds: parseFloat(getVal('cfgLlmTimeoutInput')) || 30,
        llm_stream_timeout_seconds: parseFloat(getVal('cfgLlmStreamTimeoutInput')) || 90,
        concurrency: parseInt(getVal('cfgConcurrency'), 10) || 1,
        auth_user: getVal('cfgAuthUser').trim(),
        auth_pass: getVal('cfgAuthPass'),
        login_url: getVal('cfgLoginUrl').trim(),
        mfa_type: getVal('cfgMfaType').trim(),
        mfa_field: getVal('cfgMfaField').trim(),
        mfa_email_account: getVal('cfgMfaEmailAccount').trim(),
        ...buildMfaImapFields(getVal),
        ...buildMfaTotpFields(getVal),
        ...buildAuthHeaderFields(getVal),
        ...buildTimeWindowFields(getVal),
        ...buildMfaImapPassword(getVal),
        cookies: getVal('cfgCookies').trim(),
        llm: getVal('cfgLlm') || 'none',
        ollama_model: getVal('cfgOllamaModel').trim() || 'llama3',
        openai_model: getVal('cfgOpenaiModel').trim() || 'gpt-4o-mini',
        gemini_model: getVal('cfgGeminiModel').trim() || 'gemini-2.0-flash',
        claude_model: getVal('cfgClaudeModel').trim() || 'claude-haiku-4-5-20251001',
        openai_base_url: (getVal('cfgLlm') === 'openai_compatible' ? getVal('cfgLlmBaseUrl').trim() : ''),
        role_models: getRoleModels(),
        manual_crawl_file: getVal('cfgManualCrawlFile').trim(),
        target_urls: getVal('cfgTargetUrls').split('\n').map((s) => s.trim()).filter(Boolean),
        access_urls: getVal('cfgAccessUrls').split('\n').map((s) => s.trim()).filter(Boolean),
        fast_mode: Boolean(toggles.fast_mode),
        enable_community_payloads: Boolean(toggles.community_payloads),
        enable_component_intel: Boolean(toggles.component_intel),
        enable_tls_scan: Boolean(toggles.tls_scan),
        max_payloads: parseInt(getVal('cfgMaxPayloads'), 10) || 0,
      };
    }

    // Default: normal mode
    const excludeFieldsRaw = getVal('cfgExcludeFields');
    const excludeUrlsRaw = getVal('cfgExcludeUrls');
    const targetUrlsRaw = getVal('cfgTargetUrls');
    const accessUrlsRaw = getVal('cfgAccessUrls');
    const selectedChecks = getChecks('normal');
    const toggles = getToggles();

    const config = {
      url: url,
      depth: parseInt(getVal('cfgDepth'), 10) || 2,
      timeout: parseInt(getVal('cfgTimeoutInput'), 10) || 30,
      report_lang: getVal('cfgReportLang') || 'ja',
      llm_timeout_seconds: parseFloat(getVal('cfgLlmTimeoutInput')) || 30,
      llm_stream_timeout_seconds: parseFloat(getVal('cfgLlmStreamTimeoutInput')) || 90,
      max_forms: parseInt(getVal('cfgMaxForms'), 10) || 50,
      concurrency: parseInt(getVal('cfgConcurrency'), 10) || 1,
      proxy: getVal('cfgProxy').trim(),
      tls_client_cert: getVal('cfgTlsClientCert').trim(),
      tls_client_key: getVal('cfgTlsClientKey').trim(),
      tls_client_pfx: getVal('cfgTlsClientPfx').trim(),
      tls_client_cert_password: getVal('cfgTlsClientCertPassword'),
      tls_ca_cert: getVal('cfgTlsCaCert').trim(),
      tls_verify: Boolean(toggles.tls_verify),
      headless: Boolean(toggles.headless),
      skip_registration: Boolean(toggles.skip_registration),
      open_report: Boolean(toggles.open_report),
      use_planner: Boolean(toggles.use_planner),
      enable_ai_analysis: Boolean(toggles.enable_ai_analysis),
      enable_waf_detection: Boolean(toggles.enable_waf_detection),
      enable_payload_learning: Boolean(toggles.enable_payload_learning),
      enable_community_payloads: Boolean(toggles.community_payloads),
      enable_component_intel: Boolean(toggles.component_intel),
      enable_tls_scan: Boolean(toggles.tls_scan),
      enable_sitemap_crawl: Boolean(toggles.enable_sitemap_crawl),
      state_profile: getVal('cfgStateProfile') || 'unrestricted',
      enable_llm_web_browsing: Boolean(toggles.enable_llm_web_browsing),
      ctf_mode: Boolean(toggles.ctf_mode),
      ctf_flag_pattern: getVal('cfgCtfFlagPattern').trim(),
      checks: selectedChecks.length ? selectedChecks : ['sqli', 'xss', 'os'],
      llm: getVal('cfgLlm') || 'ollama',
      ollama_model: getVal('cfgOllamaModel').trim() || 'llama3',
      openai_model: getVal('cfgOpenaiModel').trim() || 'gpt-4o-mini',
      gemini_model: getVal('cfgGeminiModel').trim() || 'gemini-2.0-flash',
      claude_model: getVal('cfgClaudeModel').trim() || 'claude-haiku-4-5-20251001',
      openai_base_url: (getVal('cfgLlm') === 'openai_compatible' ? getVal('cfgLlmBaseUrl').trim() : ''),
      role_models: getRoleModels(),
      auth_user: getVal('cfgAuthUser').trim(),
      auth_pass: getVal('cfgAuthPass'),
      login_url: getVal('cfgLoginUrl').trim(),
      login_user_field: getVal('cfgLoginUserField').trim() || 'username',
      login_pass_field: getVal('cfgLoginPassField').trim() || 'password',
      login_success_indicator: getVal('cfgLoginSuccess').trim(),
      mfa_type: getVal('cfgMfaType').trim(),
      mfa_field: getVal('cfgMfaField').trim(),
      mfa_email_account: getVal('cfgMfaEmailAccount').trim(),
      ...buildMfaImapFields(getVal),
      ...buildMfaTotpFields(getVal),
      ...buildAuthHeaderFields(getVal),
      ...buildTimeWindowFields(getVal),
      ...buildMfaImapPassword(getVal),
      cookies: getVal('cfgCookies').trim(),
      low_priv_cookies: getVal('cfgLowPrivCookies').trim(),
      interactive_plan: Boolean(toggles.interactive_plan),
      interactive_crawl_review: Boolean(toggles.interactive_crawl_review),
      allow_state_changing_probes: Boolean(toggles.allow_state_changing_probes),
      spa_crawl: Boolean(toggles.spa_crawl),
      auto_spa_crawl: Boolean(toggles.auto_spa_crawl),
      fast_mode: Boolean(toggles.fast_mode),
      max_payloads: parseInt(getVal('cfgMaxPayloads'), 10) || 0,
      request_delay: parseFloat(getVal('cfgDelay')) || 0,
      navigation_retries: parseInt(getVal('cfgNavigationRetries'), 10) || 0,
      output_dir: getVal('cfgOutputDir').trim(),
      payloads_file: getVal('cfgPayloadsFile').trim(),
      manual_crawl_file: getVal('cfgManualCrawlFile').trim(),
      accounts: getAccounts(),
      auto_register: Boolean(toggles.auto_register),
      auto_register_count: parseInt(getVal('cfgAutoRegisterCount'), 10) || 2,
      exclude_fields: excludeFieldsRaw ? excludeFieldsRaw.split(',').map((s) => s.trim()).filter(Boolean) : [],
      exclude_urls: excludeUrlsRaw ? excludeUrlsRaw.split('\n').map((s) => s.trim()).filter(Boolean) : [],
      target_urls: targetUrlsRaw ? targetUrlsRaw.split('\n').map((s) => s.trim()).filter(Boolean) : [],
      access_urls: accessUrlsRaw ? accessUrlsRaw.split('\n').map((s) => s.trim()).filter(Boolean) : [],
      flows: getFlows(),
    };

    if (!config.checks.length) {
      config.checks = ['sqli', 'xss', 'os'];
    }

    return config;
  }

  /**
   * Validate a numeric field value against declaration constraints.
   * Returns error message string or null if valid.
   */
  function validateFieldConstraint(value, field) {
    if (value === '' || value == null) return null; // handled by default
    const num = Number(value);
    if (isNaN(num) || !isFinite(num)) {
      return '有効な数値を入力してください';
    }
    if (field.type === 'integer' && !Number.isInteger(num)) {
      return '整数を入力してください';
    }
    const c = field.constraints || {};
    if (typeof c.minimum === 'number' && num < c.minimum) {
      return `最小値は ${c.minimum} です`;
    }
    if (typeof c.exclusiveMinimum === 'number' && num <= c.exclusiveMinimum) {
      return `${c.exclusiveMinimum} より大きい値を入力してください`;
    }
    return null;
  }

  /**
   * Render the 5-Tab Setup View into container using the server schema declaration.
   */
  function renderSetupView(container, schema, options = {}) {
    const doc = options.document || (typeof document !== 'undefined' ? document : null);
    if (!doc || !container) return null;

    if (typeof container.replaceChildren === 'function') {
      container.replaceChildren();
    } else {
      while (container.firstChild) container.removeChild(container.firstChild);
    }

    let currentMode = 'normal';
    const fieldMap = {};
    const fieldWrappers = [];
    const fieldsByKey = {};
    for (const f of (schema.fields || [])) {
      fieldsByKey[f.key] = f;
    }

    // Outer root wrapper
    const root = doc.createElement('div');
    root.className = 'setup-view-root';

    // Top persistent header (Target URL, Presets, Mode Selector, Start Button)
    const header = doc.createElement('div');
    header.className = 'setup-persistent-header';

    // Target URL Row
    const urlRow = doc.createElement('div');
    urlRow.className = 'setup-url-row';
    const urlLabel = doc.createElement('label');
    urlLabel.setAttribute('for', 'cfgInputUrl');
    urlLabel.textContent = fieldsByKey['url']?.label || '対象 URL (Target URL)';
    const urlInput = doc.createElement('input');
    urlInput.type = 'text';
    urlInput.id = 'cfgInputUrl';
    urlInput.className = 'setup-url-input';
    urlInput.placeholder = 'https://example.com';
    urlInput.autocomplete = 'url';
    urlInput.spellcheck = false;
    const urlError = doc.createElement('span');
    urlError.id = 'cfgInputUrlError';
    urlError.className = 'setup-field-error';
    urlError.setAttribute('role', 'alert');
    urlError.hidden = true;
    urlRow.appendChild(urlLabel);
    urlRow.appendChild(urlInput);
    urlRow.appendChild(urlError);
    header.appendChild(urlRow);

    // Mode Selector & Presets row
    const controlsRow = doc.createElement('div');
    controlsRow.className = 'setup-controls-row';

    // Mode selector
    const modeSection = doc.createElement('div');
    modeSection.className = 'setup-mode-section';
    const modeTitle = doc.createElement('span');
    modeTitle.className = 'setup-section-label';
    modeTitle.textContent = 'スキャンモード:';
    const modeGroup = doc.createElement('div');
    modeGroup.className = 'setup-mode-group';
    modeGroup.setAttribute('role', 'radiogroup');
    modeGroup.setAttribute('aria-label', 'スキャンモード');

    const modeButtons = {};
    const modes = [
      { id: 'normal', label: '通常' },
      { id: 'agent', label: 'Agent' },
      { id: 'hybrid', label: 'Hybrid' },
    ];

    modes.forEach((m) => {
      const btn = doc.createElement('button');
      btn.type = 'button';
      btn.className = 'setup-mode-btn' + (m.id === 'normal' ? ' active' : '');
      btn.setAttribute('role', 'radio');
      btn.setAttribute('aria-checked', m.id === 'normal' ? 'true' : 'false');
      btn.textContent = m.label;
      btn.dataset.mode = m.id;
      modeButtons[m.id] = btn;
      modeGroup.appendChild(btn);
    });
    modeSection.appendChild(modeTitle);
    modeSection.appendChild(modeGroup);
    controlsRow.appendChild(modeSection);

    // Presets Row
    const presetsSection = doc.createElement('div');
    presetsSection.className = 'setup-presets-section';
    const presetsTitle = doc.createElement('span');
    presetsTitle.className = 'setup-section-label';
    presetsTitle.textContent = 'Scan Profile:';
    const presetsList = doc.createElement('div');
    presetsList.className = 'setup-presets-list';

    const presetButtons = {};
    const profiles = schema.profiles || {};
    for (const [profId, profData] of Object.entries(profiles)) {
      const pBtn = doc.createElement('button');
      pBtn.type = 'button';
      pBtn.className = 'setup-preset-btn';
      pBtn.dataset.profile = profId;
      pBtn.textContent = profData.label || profId;
      presetButtons[profId] = pBtn;
      presetsList.appendChild(pBtn);
    }
    const presetNote = doc.createElement('span');
    presetNote.className = 'setup-preset-note';
    presetsSection.appendChild(presetsTitle);
    presetsSection.appendChild(presetsList);
    presetsSection.appendChild(presetNote);
    controlsRow.appendChild(presetsSection);

    // Start Scan Button
    const startSection = doc.createElement('div');
    startSection.className = 'setup-start-section';
    const startBtn = doc.createElement('button');
    startBtn.type = 'button';
    startBtn.id = 'setupStartScanBtn';
    startBtn.className = 'setup-start-btn';
    startBtn.textContent = '▶ スキャン開始';
    startSection.appendChild(startBtn);
    controlsRow.appendChild(startSection);

    header.appendChild(controlsRow);

    // Search row (filters fields across all five tabs by key or label)
    const searchRow = doc.createElement('div');
    searchRow.className = 'setup-search-row';
    const searchInput = doc.createElement('input');
    searchInput.type = 'search';
    searchInput.id = 'setupSearchInput';
    searchInput.className = 'setup-search-input';
    searchInput.placeholder = '設定項目を検索 (キー・ラベル)...';
    searchInput.setAttribute('aria-label', '設定項目検索');
    const searchCount = doc.createElement('span');
    searchCount.id = 'setupSearchCount';
    searchCount.className = 'setup-search-count';
    searchCount.hidden = true;
    searchRow.appendChild(searchInput);
    searchRow.appendChild(searchCount);
    header.appendChild(searchRow);

    // Preset Diff & Effective Config Section
    const effectiveSection = doc.createElement('div');
    effectiveSection.id = 'setupEffectiveSection';
    effectiveSection.className = 'setup-effective-section';
    effectiveSection.hidden = true;
    header.appendChild(effectiveSection);

    root.appendChild(header);

    // ─── Tab Bar (WAI-ARIA Tablist with roving tabindex) ─────────
    const tabBar = doc.createElement('div');
    tabBar.className = 'setup-tabs-bar';
    tabBar.setAttribute('role', 'tablist');
    tabBar.setAttribute('aria-label', '設定タブ');

    const tabButtons = [];
    const tabPanels = [];
    const panelContainers = {};

    TAB_DEFINITIONS.forEach((tabDef, idx) => {
      const tabBtn = doc.createElement('button');
      tabBtn.type = 'button';
      tabBtn.className = 'setup-tab' + (idx === 0 ? ' active' : '');
      tabBtn.id = `setupTab-${tabDef.id}`;
      tabBtn.setAttribute('role', 'tab');
      tabBtn.setAttribute('aria-controls', `setupPanel-${tabDef.id}`);
      tabBtn.setAttribute('aria-selected', idx === 0 ? 'true' : 'false');
      tabBtn.setAttribute('tabindex', idx === 0 ? '0' : '-1');
      tabBtn.textContent = tabDef.label;
      tabButtons.push(tabBtn);
      tabBar.appendChild(tabBtn);

      const panel = doc.createElement('div');
      panel.className = 'setup-panel' + (idx === 0 ? ' active' : '');
      panel.id = `setupPanel-${tabDef.id}`;
      panel.setAttribute('role', 'tabpanel');
      panel.setAttribute('aria-labelledby', `setupTab-${tabDef.id}`);
      panel.setAttribute('tabindex', '0');
      if (idx !== 0) panel.hidden = true;

      // Basic fields grid
      const basicGrid = doc.createElement('div');
      basicGrid.className = 'setup-grid setup-basic-grid';
      panel.appendChild(basicGrid);

      // Advanced disclosure
      const details = doc.createElement('details');
      details.className = 'setup-disclosure';
      const summary = doc.createElement('summary');
      summary.className = 'setup-disclosure-summary';
      summary.textContent = '高度な設定 (詳細設定)';
      const advancedGrid = doc.createElement('div');
      advancedGrid.className = 'setup-grid setup-advanced-grid';
      details.appendChild(summary);
      details.appendChild(advancedGrid);
      panel.appendChild(details);

      panelContainers[tabDef.id] = { basic: basicGrid, advanced: advancedGrid };
      tabPanels.push(panel);
    });

    root.appendChild(tabBar);
    tabPanels.forEach((p) => root.appendChild(p));

    function switchTab(targetIndex) {
      const idx = Math.max(0, Math.min(tabButtons.length - 1, targetIndex));
      tabButtons.forEach((btn, i) => {
        const isCurrent = i === idx;
        btn.classList.toggle('active', isCurrent);
        btn.setAttribute('aria-selected', isCurrent ? 'true' : 'false');
        btn.setAttribute('tabindex', isCurrent ? '0' : '-1');
        tabPanels[i].hidden = !isCurrent;
        tabPanels[i].classList.toggle('active', isCurrent);
      });
      tabButtons[idx].focus();
    }

    // Keyboard navigation between tabs (roving tabindex, arrow keys)
    tabBar.addEventListener('keydown', (e) => {
      const activeIdx = tabButtons.findIndex((b) => b.getAttribute('aria-selected') === 'true');
      if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
        e.preventDefault();
        switchTab((activeIdx + 1) % tabButtons.length);
      } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
        e.preventDefault();
        switchTab((activeIdx - 1 + tabButtons.length) % tabButtons.length);
      } else if (e.key === 'Home') {
        e.preventDefault();
        switchTab(0);
      } else if (e.key === 'End') {
        e.preventDefault();
        switchTab(tabButtons.length - 1);
      }
    });

    tabButtons.forEach((btn, idx) => {
      btn.addEventListener('click', () => switchTab(idx));
    });

    // ─── Render Each Declared Setting Field ─────────────────────
    (schema.fields || []).forEach((field) => {
      const key = field.key;
      // Skip top-level persistently placed fields
      if (key === 'url' || key === 'agent_mode' || key === 'hybrid_mode') return;

      const tabId = FIELD_TAB_MAP[key] || 'advanced';
      const targetGrid = ADVANCED_FIELDS.has(key)
        ? panelContainers[tabId].advanced
        : panelContainers[tabId].basic;

      const fieldWrapper = doc.createElement('div');
      fieldWrapper.className = 'setup-field';
      fieldWrapper.dataset.fieldKey = key;
      fieldWrapper.dataset.modes = JSON.stringify(field.applicable_modes || []);
      fieldWrappers.push(fieldWrapper);

      const elementId = KEY_TO_ID_MAP[key] || ('field_' + key.replace(/\./g, '_'));

      if (field.type === 'boolean') {
        const checkLabel = doc.createElement('label');
        checkLabel.className = 'setup-checkbox-label';
        const checkbox = doc.createElement('input');
        checkbox.type = 'checkbox';
        checkbox.id = elementId;
        checkbox.dataset.fieldKey = key;
        if (key.startsWith('toggles.')) {
          checkbox.dataset.toggle = key.slice(8);
        }
        checkbox.checked = Boolean(field.default);
        const textSpan = doc.createElement('span');
        textSpan.textContent = field.label || key;
        checkLabel.appendChild(checkbox);
        checkLabel.appendChild(textSpan);
        fieldWrapper.appendChild(checkLabel);
        fieldMap[key] = checkbox;
      } else if (key === 'checks') {
        // Scanner check boxes
        const groupTitle = doc.createElement('label');
        groupTitle.className = 'setup-field-title';
        groupTitle.textContent = field.label || '検査項目';
        fieldWrapper.appendChild(groupTitle);

        const checkList = doc.createElement('div');
        checkList.className = 'setup-checks-list';
        checkList.id = 'setupChecks';

        const defaultChecks = Array.isArray(field.default) ? field.default : ['sqli', 'xss', 'os'];
        const allChecks = [
          'sqli', 'xss', 'dom_xss', 'stored_xss', 'os', 'ssti', 'path_traversal',
          'csrf', 'header_injection', 'open_redirect', 'session', 'privesc',
          'cors', 'security_headers', 'info_disclosure', 'ssrf', 'graphql',
          'jwt', 'clickjacking',
        ];

        allChecks.forEach((checkId) => {
          const item = doc.createElement('label');
          item.className = 'setup-check-item';
          const cb = doc.createElement('input');
          cb.type = 'checkbox';
          cb.value = checkId;
          cb.dataset.check = checkId;
          cb.checked = defaultChecks.includes(checkId);
          const nameSpan = doc.createElement('span');
          nameSpan.textContent = checkId;
          item.appendChild(cb);
          item.appendChild(nameSpan);
          checkList.appendChild(item);
        });
        fieldWrapper.appendChild(checkList);
        fieldMap[key] = checkList;
      } else if (key === 'role_models') {
        const groupTitle = doc.createElement('label');
        groupTitle.className = 'setup-field-title';
        groupTitle.textContent = field.label || 'ロール別モデル';
        fieldWrapper.appendChild(groupTitle);

        const grid = doc.createElement('div');
        grid.className = 'setup-subgrid';
        grid.id = 'cfgRoleModelsGrid';
        ['planner', 'payload', 'adaptive', 'triage'].forEach((role) => {
          const row = doc.createElement('div');
          row.className = 'setup-subfield';
          const lbl = doc.createElement('label');
          lbl.textContent = role;
          const inp = doc.createElement('input');
          inp.type = 'text';
          inp.id = 'cfg' + role.charAt(0).toUpperCase() + role.slice(1) + 'Model';
          inp.placeholder = '空=全体設定';
          row.appendChild(lbl);
          row.appendChild(inp);
          grid.appendChild(row);
        });
        fieldWrapper.appendChild(grid);
        fieldMap[key] = grid;
      } else if (key === 'accounts') {
        const groupTitle = doc.createElement('label');
        groupTitle.className = 'setup-field-title';
        groupTitle.textContent = field.label || '複数アカウント';
        fieldWrapper.appendChild(groupTitle);

        const list = doc.createElement('div');
        list.id = 'accountsList';
        list.className = 'setup-accounts-list';
        fieldWrapper.appendChild(list);
        fieldMap[key] = list;
      } else if (key === 'flows') {
        const groupTitle = doc.createElement('label');
        groupTitle.className = 'setup-field-title';
        groupTitle.textContent = field.label || '複数ステップフロー';
        fieldWrapper.appendChild(groupTitle);

        const flowsContainer = doc.createElement('div');
        flowsContainer.id = 'cfgFlowsList';
        flowsContainer.className = 'setup-flows-container';
        fieldWrapper.appendChild(flowsContainer);
        fieldMap[key] = flowsContainer;
      } else {
        // Standard text, textarea, select, or number input
        const label = doc.createElement('label');
        label.setAttribute('for', elementId);
        label.textContent = field.label || key;
        fieldWrapper.appendChild(label);

        const isMultiline = [
          'target_urls', 'access_urls', 'exclude_urls', 'headers',
          'allowed_hours', 'forbidden_hours',
        ].includes(key);

        let input;
        if (field.constraints && Array.isArray(field.constraints.enum)) {
          input = doc.createElement('select');
          input.id = elementId;
          field.constraints.enum.forEach((optVal) => {
            const opt = doc.createElement('option');
            opt.value = optVal;
            opt.textContent = optVal;
            if (field.default === optVal) opt.selected = true;
            input.appendChild(opt);
          });
        } else if (isMultiline) {
          input = doc.createElement('textarea');
          input.id = elementId;
          input.rows = 3;
          input.value = field.default ? String(field.default) : '';
        } else {
          input = doc.createElement('input');
          input.id = elementId;
          if (field.type === 'integer' || field.type === 'number') {
            input.type = 'number';
            if (typeof field.constraints?.minimum === 'number') {
              input.min = String(field.constraints.minimum);
            }
            if (field.type === 'integer') {
              input.step = '1';
            } else {
              input.step = 'any';
            }
            input.value = field.default != null ? String(field.default) : '';
          } else if (key.includes('pass') || key.includes('secret')) {
            input.type = 'password';
            input.value = field.default ? String(field.default) : '';
          } else {
            input.type = 'text';
            input.value = field.default ? String(field.default) : '';
          }
        }

        input.dataset.fieldKey = key;
        fieldWrapper.appendChild(input);

        // Error message placeholder for validation errors
        const errorMsg = doc.createElement('span');
        errorMsg.className = 'setup-field-error';
        errorMsg.setAttribute('role', 'alert');
        errorMsg.hidden = true;
        fieldWrapper.appendChild(errorMsg);

        // Validation listener for numbers
        if (field.type === 'integer' || field.type === 'number') {
          const validate = () => {
            const err = validateFieldConstraint(input.value, field);
            if (err) {
              errorMsg.textContent = err;
              errorMsg.hidden = false;
              input.setAttribute('aria-invalid', 'true');
            } else {
              errorMsg.textContent = '';
              errorMsg.hidden = true;
              input.removeAttribute('aria-invalid');
            }
          };
          input.addEventListener('input', validate);
          input.addEventListener('blur', validate);
        }

        fieldMap[key] = input;
      }

      targetGrid.appendChild(fieldWrapper);
    });

    // ─── Search Filtering Logic ──────────────────────────────────
    function filterFields(query) {
      const q = (query || '').trim().toLowerCase();
      let matchCount = 0;
      let totalFields = 0;

      fieldWrappers.forEach((wrapper) => {
        const key = wrapper.dataset.fieldKey || '';
        const field = fieldsByKey[key];
        const label = (field && field.label ? field.label : '').toLowerCase();
        const matches = !q || key.toLowerCase().includes(q) || label.includes(q);

        totalFields++;
        if (matches) {
          matchCount++;
          wrapper.style.display = '';
          delete wrapper.dataset.searchFiltered;
        } else {
          wrapper.style.display = 'none';
          wrapper.dataset.searchFiltered = 'true';
        }
      });

      if (q) {
        searchCount.textContent = `${matchCount} / ${totalFields} 件一致`;
        searchCount.hidden = false;
        tabPanels.forEach((panel) => {
          const details = (panel.querySelector ? panel.querySelector('details') : null) ||
            Array.from(panel.children || []).find((c) => c && c.tagName === 'details');
          if (details) {
            const children = Array.from(details.children || []);
            const hasMatch = children.some((c) => {
              if (c && c.classList && (typeof c.classList.contains === 'function' ? c.classList.contains('setup-grid') : c.className?.includes('setup-grid'))) {
                const subChildren = Array.from(c.children || []);
                return subChildren.some((w) => w && w.dataset && !w.dataset.searchFiltered);
              }
              return c && c.dataset && !c.dataset.searchFiltered;
            });
            if (hasMatch) details.open = true;
          }
        });
      } else {
        searchCount.hidden = true;
        searchCount.textContent = '';
      }
      return matchCount;
    }

    searchInput.addEventListener('input', () => {
      filterFields(searchInput.value);
    });

    // ─── Preset Diff & Effective Config Display ──────────────────
    let currentPreset = null;

    function renderEffectiveUnavailable(reason) {
      if (typeof effectiveSection.replaceChildren === 'function') {
        effectiveSection.replaceChildren();
      } else {
        while (effectiveSection.firstChild) effectiveSection.removeChild(effectiveSection.firstChild);
      }
      effectiveSection.hidden = false;

      const unavail = doc.createElement('div');
      unavail.className = 'setup-effective-unavailable';
      unavail.setAttribute('role', 'alert');
      unavail.id = 'setupEffectiveUnavailable';
      unavail.textContent = `実効設定・プロファイル差分を取得できませんでした (${reason || 'unavailable'})`;
      effectiveSection.appendChild(unavail);
    }

    function renderEffectiveDiff(effectiveData, profile) {
      if (typeof effectiveSection.replaceChildren === 'function') {
        effectiveSection.replaceChildren();
      } else {
        while (effectiveSection.firstChild) effectiveSection.removeChild(effectiveSection.firstChild);
      }
      effectiveSection.hidden = false;

      const diff = (effectiveData && effectiveData.diff) || {};
      const diffKeys = Object.keys(diff);
      const profLabel = (profile && profile.label) || (effectiveData && effectiveData.profile) || 'プロファイル';

      const secHeader = doc.createElement('div');
      secHeader.className = 'setup-effective-header';
      const titleSpan = doc.createElement('span');
      titleSpan.className = 'setup-effective-title';
      titleSpan.textContent = `プロファイル変更差分: ${profLabel}`;
      const badgeSpan = doc.createElement('span');
      badgeSpan.className = 'setup-effective-badge';
      badgeSpan.textContent = `${diffKeys.length} 項目変更`;
      secHeader.appendChild(titleSpan);
      secHeader.appendChild(badgeSpan);
      effectiveSection.appendChild(secHeader);

      if (Array.isArray(effectiveData.invalid_keys) && effectiveData.invalid_keys.length > 0) {
        const incompNote = doc.createElement('div');
        incompNote.className = 'setup-incompatible-note';
        incompNote.textContent = `※ 宣言の制約に適合しない現在設定 (${effectiveData.invalid_keys.length} 件: ${effectiveData.invalid_keys.join(', ')}) は宣言既定値に置き換えて解決しました`;
        effectiveSection.appendChild(incompNote);
      }

      const diffList = doc.createElement('div');
      diffList.id = 'setupEffectiveDiffList';
      diffList.className = 'setup-effective-diff-list';

      if (diffKeys.length === 0) {
        const empty = doc.createElement('div');
        empty.className = 'setup-effective-empty';
        empty.textContent = '既定値からの変更項目はありません';
        diffList.appendChild(empty);
      } else {
        diffKeys.forEach((key) => {
          const item = diff[key] || {};
          const field = fieldsByKey[key];
          const label = field && field.label ? field.label : key;

          const row = doc.createElement('div');
          row.className = 'setup-effective-diff-item';
          row.dataset.fieldKey = key;

          const keyEl = doc.createElement('span');
          keyEl.className = 'setup-diff-key';
          keyEl.textContent = `${label} (${key}):`;

          const beforeEl = doc.createElement('span');
          beforeEl.className = 'setup-diff-before';
          beforeEl.textContent = formatValue(item.before);

          const arrowEl = doc.createElement('span');
          arrowEl.className = 'setup-diff-arrow';
          arrowEl.textContent = ' → ';

          const afterEl = doc.createElement('span');
          afterEl.className = 'setup-diff-after';
          afterEl.textContent = formatValue(item.after);

          row.appendChild(keyEl);
          row.appendChild(beforeEl);
          row.appendChild(arrowEl);
          row.appendChild(afterEl);
          diffList.appendChild(row);
        });
      }
      effectiveSection.appendChild(diffList);

      const values = (effectiveData && effectiveData.values) || {};
      const valKeys = Object.keys(values);
      if (valKeys.length > 0) {
        const details = doc.createElement('details');
        details.className = 'setup-effective-config-details';
        const summary = doc.createElement('summary');
        summary.textContent = `実効設定値 (${valKeys.length} 項目)`;
        const grid = doc.createElement('div');
        grid.className = 'setup-effective-config-grid';

        valKeys.forEach((k) => {
          const v = values[k];
          const field = fieldsByKey[k];
          const label = field && field.label ? field.label : k;

          const valItem = doc.createElement('div');
          valItem.className = 'setup-effective-val-item';
          valItem.dataset.fieldKey = k;
          valItem.textContent = `${label}: ${formatValue(v)}`;
          grid.appendChild(valItem);
        });

        details.appendChild(summary);
        details.appendChild(grid);
        effectiveSection.appendChild(details);
      }
    }

    async function applyPreset(profId, updateFields = true) {
      if (currentMode === 'agent') return false;
      const profile = profiles[profId];
      if (!profile) return false;
      currentPreset = profId;

      Object.entries(presetButtons).forEach(([id, b]) => {
        if (typeof b.classList?.toggle === 'function') {
          b.classList.toggle('active', id === profId);
        }
      });

      if (updateFields && profile.overrides) {
        for (const [key, value] of Object.entries(profile.overrides)) {
          if (key.startsWith('toggles.')) {
            const toggleKey = key.slice(8);
            const cb = (typeof doc.querySelector === 'function') ? doc.querySelector(`input[data-toggle="${toggleKey}"]`) : null;
            if (cb) cb.checked = Boolean(value);
          } else if (key === 'checks') {
            const cbs = (typeof doc.querySelectorAll === 'function') ? doc.querySelectorAll('#setupChecks input[type=checkbox]') : [];
            cbs.forEach((cb) => {
              cb.checked = Array.isArray(value) && value.includes(cb.value);
            });
          } else {
            const elId = KEY_TO_ID_MAP[key];
            const el = (elId && typeof doc.getElementById === 'function') ? doc.getElementById(elId) : null;
            if (el) el.value = value != null ? String(value) : '';
          }
        }
      }

      presetNote.textContent = `適用中: ${profile.label || profId}`;

      try {
        let data = null;
        if (options.effectiveConfig && options.effectiveConfig.profile === profId && options.effectiveConfig.mode === currentMode) {
          data = options.effectiveConfig;
        } else if (typeof options.fetchEffectiveConfig === 'function') {
          data = await options.fetchEffectiveConfig(currentMode, profId);
        } else if (options.api && typeof options.api.get === 'function') {
          const endpoint = options.effectiveEndpoint || '/api/v1/settings/effective';
          const params = `mode=${encodeURIComponent(currentMode)}&profile=${encodeURIComponent(profId)}&schema_version=${encodeURIComponent(SCHEMA_VERSION)}`;
          const res = await options.api.get(`${endpoint}?${params}`);
          if (!res || !res.ok || !res.data) {
            throw new Error(res && res.error ? res.error : 'unavailable');
          }
          data = res.data;
        } else if (typeof fetch === 'function') {
          const endpoint = options.effectiveEndpoint || '/api/v1/settings/effective';
          const params = `mode=${encodeURIComponent(currentMode)}&profile=${encodeURIComponent(profId)}&schema_version=${encodeURIComponent(SCHEMA_VERSION)}`;
          const res = await fetch(`${endpoint}?${params}`);
          if (!res.ok) {
            throw new Error(`HTTP ${res.status}`);
          }
          data = await res.json();
        } else {
          throw new Error('API client unavailable');
        }

        if (!data || typeof data !== 'object' ||
            data.schema_version !== SCHEMA_VERSION || data.manifest_kind !== 'effective_config' ||
            data.mode !== currentMode || data.profile !== profId ||
            !data.values || typeof data.values !== 'object' || Array.isArray(data.values) ||
            !data.diff || typeof data.diff !== 'object' || Array.isArray(data.diff)) {
          throw new Error('設定宣言と一致しない応答です');
        }

        renderEffectiveDiff(data, profile);
        presetNote.textContent = `適用済み: ${profile.label || profId}`;
        return true;
      } catch (err) {
        renderEffectiveUnavailable(err ? (err.message || String(err)) : 'unavailable');
        presetNote.textContent = `適用失敗: ${profile.label || profId}`;
        return false;
      }
    }

    // ─── Mode Switching Logic ────────────────────────────────────
    function applyMode(mode) {
      currentMode = mode;
      modes.forEach((m) => {
        const btn = modeButtons[m.id];
        const isSelected = m.id === mode;
        if (typeof btn.classList?.toggle === 'function') {
          btn.classList.toggle('active', isSelected);
        }
        btn.setAttribute('aria-checked', isSelected ? 'true' : 'false');
      });

      const isAgent = mode === 'agent';
      Object.entries(presetButtons).forEach(([profId, btn]) => {
        btn.disabled = isAgent;
        if (isAgent && typeof btn.classList?.remove === 'function') {
          btn.classList.remove('active');
        }
      });

      if (isAgent) {
        currentPreset = null;
        effectiveSection.hidden = true;
        presetNote.textContent = '※ Agent モードではプロファイルは指定できません';
      } else {
        presetNote.textContent = currentPreset ? `適用済み: ${profiles[currentPreset]?.label || currentPreset}` : '';
        if (currentPreset) {
          applyPreset(currentPreset, false);
        }
      }

      // Start scan button label
      if (mode === 'agent') {
        startBtn.textContent = '▶ Agent スキャン開始';
      } else if (mode === 'hybrid') {
        startBtn.textContent = '▶ ハイブリッドスキャン開始';
      } else {
        startBtn.textContent = '▶ スキャン開始';
      }

      // Mode applicability: fields not applicable to the selected mode
      // are shown as not applicable with the reason from the declaration.
      fieldWrappers.forEach((wrapper) => {
        const key = wrapper.dataset.fieldKey;
        const field = fieldsByKey[key];
        let fieldModes = [];
        try {
          fieldModes = JSON.parse(wrapper.dataset.modes || '[]');
        } catch (_) {
          fieldModes = field && Array.isArray(field.applicable_modes) ? field.applicable_modes : [];
        }
        const isApplicable = !fieldModes.length || fieldModes.includes(mode);

        let naBadge = (typeof wrapper.querySelector === 'function' ? wrapper.querySelector('.setup-na-badge') : null) ||
          (Array.isArray(wrapper.children) ? wrapper.children.find((c) => c && c.className && c.className.includes('setup-na-badge')) : null);

        if (!isApplicable) {
          if (typeof wrapper.classList?.add === 'function') wrapper.classList.add('not-applicable');
          wrapper.dataset.notApplicable = 'true';
          if (!naBadge) {
            naBadge = doc.createElement('span');
            naBadge.className = 'setup-na-badge';
            naBadge.setAttribute('role', 'note');
            wrapper.appendChild(naBadge);
          }
          const modeName = MODE_LABELS[mode] || mode;
          const allowedNames = fieldModes.map((m) => MODE_LABELS[m] || m).join('・');
          naBadge.textContent = `${modeName}非対応（適用対象: ${allowedNames}）`;
          naBadge.dataset.reason = `${modeName}非対応（適用対象: ${allowedNames}）`;
          naBadge.hidden = false;

          const control = fieldMap[key];
          if (control) {
            if (control.disabled !== undefined) {
              control.disabled = true;
              if (typeof control.setAttribute === 'function') control.setAttribute('aria-disabled', 'true');
            } else if (Array.isArray(control.children)) {
              control.children.forEach((c) => {
                const sub = (c.children && c.children[0]) || c;
                if (sub && sub.disabled !== undefined) {
                  sub.disabled = true;
                  if (typeof sub.setAttribute === 'function') sub.setAttribute('aria-disabled', 'true');
                }
              });
            }
          }
        } else {
          if (typeof wrapper.classList?.remove === 'function') wrapper.classList.remove('not-applicable');
          delete wrapper.dataset.notApplicable;
          if (naBadge) {
            naBadge.hidden = true;
          }

          const control = fieldMap[key];
          if (control) {
            if (control.disabled !== undefined) {
              control.disabled = false;
              if (typeof control.removeAttribute === 'function') control.removeAttribute('aria-disabled');
            } else if (Array.isArray(control.children)) {
              control.children.forEach((c) => {
                const sub = (c.children && c.children[0]) || c;
                if (sub && sub.disabled !== undefined) {
                  sub.disabled = false;
                  if (typeof sub.removeAttribute === 'function') sub.removeAttribute('aria-disabled');
                }
              });
            }
          }
        }
      });
    }

    Object.keys(modeButtons).forEach((m) => {
      modeButtons[m].addEventListener('click', () => applyMode(m));
    });

    // ─── Preset Application Logic ────────────────────────────────
    Object.entries(presetButtons).forEach(([profId, btn]) => {
      btn.addEventListener('click', () => {
        applyPreset(profId);
      });
    });

    // ─── Start Scan Click Validation & Submission ────────────────
    startBtn.addEventListener('click', () => {
      urlError.hidden = true;
      urlError.textContent = '';
      urlInput.removeAttribute('aria-invalid');

      const url = urlInput.value.trim();
      if (!url || !url.startsWith('http')) {
        urlInput.setAttribute('aria-invalid', 'true');
        urlError.textContent = '有効な URL を入力してください (例: https://example.com)';
        urlError.hidden = false;
        urlInput.focus();
        return;
      }

      // Validate all number inputs in the view
      let hasError = false;
      let firstInvalidInput = null;
      for (const field of (schema.fields || [])) {
        if (field.type === 'integer' || field.type === 'number') {
          const elId = KEY_TO_ID_MAP[field.key];
          const input = (elId && typeof doc.getElementById === 'function') ? doc.getElementById(elId) : null;
          if (input) {
            const err = validateFieldConstraint(input.value, field);
            const errorElem = input.parentElement?.querySelector('.setup-field-error');
            if (err) {
              hasError = true;
              input.setAttribute('aria-invalid', 'true');
              if (errorElem) {
                errorElem.textContent = err;
                errorElem.hidden = false;
              }
              if (!firstInvalidInput) firstInvalidInput = input;
            } else {
              input.removeAttribute('aria-invalid');
              if (errorElem) errorElem.hidden = true;
            }
          }
        }
      }

      if (hasError && firstInvalidInput) {
        // Switch to the tab containing the invalid input
        const parentPanel = firstInvalidInput.closest('.setup-panel');
        if (parentPanel) {
          const tabIdx = tabPanels.indexOf(parentPanel);
          if (tabIdx >= 0) switchTab(tabIdx);
        }
        firstInvalidInput.focus();
        return;
      }

      // Build byte-for-byte equivalent payload
      const payload = buildScanPayload(currentMode, { document: doc });

      if (typeof options.onStartScan === 'function') {
        options.onStartScan(payload);
      }
    });

    container.appendChild(root);
    applyMode('normal');

    return {
      root: root,
      switchTab: switchTab,
      applyMode: applyMode,
      applyPreset: applyPreset,
      filterFields: filterFields,
      getMode: () => currentMode,
      buildPayload: () => buildScanPayload(currentMode, { document: doc }),
      effectiveSection: effectiveSection,
    };
  }

  /**
   * Load schema declaration and render Setup View.
   * On failure or invalid declaration, calls onUnavailable and returns false.
   */
  async function loadAndRenderSetup(container, options = {}) {
    const doc = options.document || (typeof document !== 'undefined' ? document : null);
    if (!doc || !container) return false;

    let schema = null;
    try {
      if (options.schema) {
        schema = options.schema;
      } else if (options.api && typeof options.api.get === 'function') {
        const resp = await options.api.get(options.endpoint || '/api/v1/settings/schema');
        if (!resp || !resp.ok || !resp.data) {
          if (typeof options.onUnavailable === 'function') {
            options.onUnavailable('設定宣言を取得できませんでした');
          }
          return false;
        }
        schema = resp.data;
      } else if (typeof fetch === 'function') {
        const resp = await fetch(options.endpoint || '/api/v1/settings/schema');
        if (!resp.ok) {
          if (typeof options.onUnavailable === 'function') {
            options.onUnavailable('設定宣言を取得できませんでした');
          }
          return false;
        }
        schema = await resp.json();
      } else {
        if (typeof options.onUnavailable === 'function') {
          options.onUnavailable('設定宣言クライアントが初期化されていません');
        }
        return false;
      }

      // Version and kind check
      if (!schema || typeof schema !== 'object' ||
          schema.schema_version !== SCHEMA_VERSION ||
          schema.manifest_kind !== MANIFEST_KIND ||
          !Array.isArray(schema.fields) || schema.fields.length === 0) {
        if (typeof options.onUnavailable === 'function') {
          options.onUnavailable('設定宣言のバージョンまたは形式が一致しません');
        }
        return false;
      }

      renderSetupView(container, schema, options);
      return true;
    } catch (err) {
      if (typeof options.onUnavailable === 'function') {
        options.onUnavailable(err && err.message ? err.message : '設定宣言の読み込みに失敗しました');
      }
      return false;
    }
  }

  /**
   * App shell module factory.
   */
  function createSetupModule(options = {}) {
    let currentInstance = null;
    return {
      id: 'setup',
      title: 'Scan Setup',
      route: '#/setup',
      capabilities: ['scan-setup'],
      mount(route) {
        const doc = options.document || (typeof document !== 'undefined' ? document : null);
        const container = options.container || (doc ? doc.getElementById('setupSurface') : null);
        if (container) {
          container.hidden = false;
          loadAndRenderSetup(container, Object.assign({}, options, {
            document: doc,
            onUnavailable: (reason) => {
              container.hidden = true;
              if (typeof options.onUnavailable === 'function') {
                options.onUnavailable(reason);
              }
            },
          })).then((ok) => {
            if (!ok && container) container.hidden = true;
          });
        }
      },
      unmount() {
        const doc = options.document || (typeof document !== 'undefined' ? document : null);
        const container = options.container || (doc ? doc.getElementById('setupSurface') : null);
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

  const setupExport = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    MANIFEST_KIND: MANIFEST_KIND,
    TAB_DEFINITIONS: TAB_DEFINITIONS,
    FIELD_TAB_MAP: FIELD_TAB_MAP,
    ADVANCED_FIELDS: ADVANCED_FIELDS,
    KEY_TO_ID_MAP: KEY_TO_ID_MAP,
    buildScanPayload: buildScanPayload,
    validateFieldConstraint: validateFieldConstraint,
    renderSetupView: renderSetupView,
    loadAndRenderSetup: loadAndRenderSetup,
    createSetupModule: createSetupModule,
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = setupExport;
  }
  if (global) {
    global.VulixSetupModule = setupExport;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
