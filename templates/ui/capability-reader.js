/**
 * capability-reader.js — Capability Manifest Reader for Vulix UI
 *
 * Sourced from versioned backend capability manifest (/api/capability-manifest).
 * Eliminates duplicate scanner ID maintenance in UI code while preserving
 * exact SCANNERS equality, defaults ('sqli', 'os', 'xss'), safe unavailable
 * states (401, network, decode, missing fields, version mismatch), and mode/permission
 * gating.
 *
 * INVARIANT: Declaration != Runtime Execution Coverage
 * Downstream readers must never manufacture runtime execution coverage or pass/fail
 * claims from static declarations.
 */
(function (global) {
  'use strict';

  const SCHEMA_VERSION = '1.0.0';
  const MANIFEST_KIND = 'scanner_capability_manifest';
  const DEFAULT_CHECKS = ['sqli', 'os', 'xss'];

  // Known Japanese display labels for known scanner IDs.
  // Note: This is purely a display mapping; scanners NOT present in this map
  // are dynamically supported and formatted via class name or id.
  const KNOWN_LABELS = {
    sqli: 'SQLi',
    os: 'OSインジェクション',
    nosql: 'NoSQLi',
    ssti: 'SSTI',
    deserialization: '逆シリアル化',
    graphql: 'GraphQL',
    ldap: 'LDAPインジェクション',
    mass_assignment: 'Mass Assignment',
    prototype_pollution: 'Prototype Pollution',
    xss: 'XSS',
    stored_xss: 'Stored XSS',
    dom_xss: 'DOM XSS',
    js_static: 'JavaScript静的解析',
    csrf: 'CSRF',
    session: 'セッション管理',
    privesc: '権限昇格',
    race_condition: '競合状態',
    header_injection: 'ヘッダインジェクション',
    mail_header: 'メールヘッダインジェクション',
    open_redirect: 'オープンリダイレクト',
    path_traversal: 'パストラバーサル',
    host_header: 'Hostヘッダ攻撃',
    xxe: 'XXE',
    cors: 'CORS',
    security_headers: 'セキュリティヘッダ',
    http_methods: 'HTTPメソッド設定',
    request_smuggling: 'リクエストスマグリング',
    info_disclosure: '情報漏えい',
    directory_artifacts: '一覧・バックアップ・ソースマップ',
    ssrf: 'SSRF',
    websocket: 'WebSocket設定',
    secret_leak: 'シークレット漏えい',
    sri: 'Subresource Integrity',
    tls_scan: 'TLS設定',
    transport_security: '通信セキュリティ',
    jwt: 'JWT',
    clickjacking: 'クリックジャッキング',
    file_upload: 'ファイルアップロード',
    cms: 'CMS',
    outdated_components: '古いコンポーネント',
    cache_poisoning: 'キャッシュポイズニング',
  };

  // Known UI category group mappings for known scanner IDs.
  // Unknown scanners will be automatically categorized via heuristic or fallback to 'file'.
  const KNOWN_GROUP_MAPPING = {
    sqli: 'injection',
    os: 'injection',
    nosql: 'injection',
    ssti: 'injection',
    deserialization: 'injection',
    graphql: 'injection',
    ldap: 'injection',
    mass_assignment: 'injection',
    prototype_pollution: 'injection',
    xss: 'xss',
    stored_xss: 'xss',
    dom_xss: 'xss',
    js_static: 'xss',
    csrf: 'access',
    session: 'access',
    privesc: 'access',
    race_condition: 'access',
    header_injection: 'header',
    mail_header: 'header',
    open_redirect: 'header',
    path_traversal: 'header',
    host_header: 'header',
    xxe: 'header',
    cors: 'proto',
    security_headers: 'proto',
    http_methods: 'proto',
    request_smuggling: 'proto',
    info_disclosure: 'proto',
    directory_artifacts: 'proto',
    ssrf: 'proto',
    websocket: 'proto',
    secret_leak: 'proto',
    sri: 'proto',
    tls_scan: 'proto',
    transport_security: 'proto',
    jwt: 'proto',
    clickjacking: 'file',
    file_upload: 'file',
    cms: 'file',
    outdated_components: 'file',
    cache_poisoning: 'file',
  };

  const ALLOWED_TOP_LEVEL_FIELDS = new Set([
    'schema_version',
    'manifest_kind',
    'declaration_only',
    'execution_coverage_claimed',
    'declaration_disclaimer',
    'default_checks',
    'scanner_count',
    'scanner_ids',
    'scanners',
  ]);

  const ALLOWED_SCANNER_FIELDS = new Set([
    'id',
    'name',
    'check_type',
    'severity',
    'cvss',
    'is_default',
    'applicable_modes',
    'state_change',
    'cost',
    'prerequisites',
    'execution_kinds',
    'has_page_level',
    'supports_json_body',
    'supports_xml_body',
    'always_state_changing',
    'declared_carriers',
    'declaration_only',
  ]);

  const FORBIDDEN_COVERAGE_KEYWORDS = [
    'coverage',
    'tested',
    'passed',
    'verified',
    'runtime_coverage',
    'execution_count',
    'test_passed',
  ];

  class CapabilityReader {
    /**
     * @param {Object} [options]
     * @param {Object} [options.apiClient] - VulixApiClient instance
     * @param {string} [options.schemaVersion='1.0.0']
     * @param {string} [options.manifestKind='scanner_capability_manifest']
     * @param {string} [options.endpoint='/api/capability-manifest']
     */
    constructor(options = {}) {
      this.apiClient = options.apiClient || (global.VulixApiClient && global.VulixApiClient.defaultClient) || null;
      this.schemaVersion = options.schemaVersion || SCHEMA_VERSION;
      this.manifestKind = options.manifestKind || MANIFEST_KIND;
      this.endpoint = options.endpoint || '/api/capability-manifest';

      this.status = 'idle'; // 'idle' | 'loading' | 'ready' | 'unavailable'
      this.manifest = null;
      this.error = null;
      this.errorReason = null; // 'network_error' | 'unauthorized' | 'http_error' | 'decode_error' | 'version_mismatch' | 'invalid_manifest' | 'aborted'
      this.errorMessage = '';
      this._listeners = new Set();
    }

    addListener(fn) {
      if (typeof fn === 'function') {
        this._listeners.add(fn);
      }
    }

    removeListener(fn) {
      this._listeners.delete(fn);
    }

    _notifyListeners() {
      for (const listener of this._listeners) {
        try {
          listener(this);
        } catch (err) {
          console.error('Error in CapabilityReader listener:', err);
        }
      }
    }

    isReady() {
      return this.status === 'ready' && Boolean(this.manifest);
    }

    isUnavailable() {
      return this.status === 'unavailable';
    }

    isLoading() {
      return this.status === 'loading';
    }

    /**
     * Validate manifest structure according to the strict schema.
     * Pure function returning a list of validation error strings.
     * @param {any} data
     * @returns {string[]}
     */
    validateManifest(data) {
      const errors = [];
      if (!data || typeof data !== 'object') {
        return ['Manifest must be a non-null JSON object'];
      }

      if (data.schema_version !== this.schemaVersion) {
        errors.push(`Schema version mismatch: expected '${this.schemaVersion}', got '${data.schema_version}'`);
      }
      if (data.manifest_kind !== this.manifestKind) {
        errors.push(`Manifest kind mismatch: expected '${this.manifestKind}', got '${data.manifest_kind}'`);
      }
      if (data.declaration_only !== true) {
        errors.push("Invariant violation: 'declaration_only' must be true");
      }
      if (data.execution_coverage_claimed !== false) {
        errors.push("Invariant violation: 'execution_coverage_claimed' must be false (declaration-only schema strictly prohibits coverage/tested assertions)");
      }
      if (!Array.isArray(data.default_checks)) {
        errors.push("Field 'default_checks' must be a list of strings");
      }
      if (typeof data.scanner_count !== 'number') {
        errors.push("Field 'scanner_count' must be an integer");
      }
      if (!Array.isArray(data.scanner_ids)) {
        errors.push("Field 'scanner_ids' must be a list of strings");
      }
      if (!data.scanners || typeof data.scanners !== 'object') {
        errors.push("Field 'scanners' must be an object map");
        return errors;
      }

      // Check top-level extra or forbidden fields
      for (const key of Object.keys(data)) {
        if (!ALLOWED_TOP_LEVEL_FIELDS.has(key)) {
          const lowerKey = key.toLowerCase();
          if (FORBIDDEN_COVERAGE_KEYWORDS.some(kw => lowerKey.includes(kw))) {
            errors.push(`Manifest contains forbidden runtime execution/coverage claim field '${key}'`);
          } else {
            errors.push(`Manifest contains unexpected extra top-level field '${key}'`);
          }
        }
      }

      // Check scanner entries
      const scKeys = Object.keys(data.scanners);
      if (scKeys.length !== data.scanner_count) {
        errors.push(`Field 'scanner_count' (${data.scanner_count}) does not match scanners count (${scKeys.length})`);
      }

      for (const [id, sc] of Object.entries(data.scanners)) {
        if (!sc || typeof sc !== 'object') {
          errors.push(`Scanner entry '${id}' must be an object`);
          continue;
        }
        if (sc.id !== id) {
          errors.push(`Scanner entry id '${sc.id}' does not match key '${id}'`);
        }
        if (!sc.name) {
          errors.push(`Scanner '${id}' missing required field 'name'`);
        }
        if (!sc.check_type) {
          errors.push(`Scanner '${id}' missing required field 'check_type'`);
        }
        if (sc.declaration_only !== true) {
          errors.push(`Scanner '${id}' declaration_only must be true`);
        }
        for (const key of Object.keys(sc)) {
          if (!ALLOWED_SCANNER_FIELDS.has(key)) {
            const lowerKey = key.toLowerCase();
            if (FORBIDDEN_COVERAGE_KEYWORDS.some(kw => lowerKey.includes(kw))) {
              errors.push(`Scanner '${id}' contains forbidden coverage field '${key}'`);
            } else {
              errors.push(`Scanner '${id}' contains unexpected extra field '${key}'`);
            }
          }
        }
      }

      return errors;
    }

    /**
     * Load capability manifest from server.
     * Transitions status to 'ready' on success or 'unavailable' on failure.
     * @param {Object} [options]
     * @param {AbortSignal} [options.signal]
     * @param {boolean} [options.force=false]
     * @returns {Promise<Object|null>}
     */
    async loadCapabilities(options = {}) {
      if (this.status === 'ready' && !options.force && this.manifest) {
        return this.manifest;
      }

      this.status = 'loading';
      this.error = null;
      this.errorReason = null;
      this.errorMessage = '';
      this._notifyListeners();

      const client = options.apiClient || this.apiClient || (global.VulixApiClient && global.VulixApiClient.defaultClient);
      if (!client) {
        this.status = 'unavailable';
        this.errorReason = 'network_error';
        this.errorMessage = 'API client is not available';
        this._notifyListeners();
        return null;
      }

      let res;
      try {
        res = await client.get(this.endpoint, { signal: options.signal });
      } catch (err) {
        this.status = 'unavailable';
        this.error = err;
        this.errorReason = 'network_error';
        this.errorMessage = err && err.message ? err.message : '通信エラーが発生しました';
        this._notifyListeners();
        return null;
      }

      if (res.isUnauthorized()) {
        this.status = 'unavailable';
        this.errorReason = 'unauthorized';
        this.errorMessage = res.errorMessage || '認証が必要です (HTTP 401 Unauthorized)';
        this._notifyListeners();
        return null;
      }

      if (res.isNetworkError()) {
        this.status = 'unavailable';
        this.errorReason = 'network_error';
        this.errorMessage = res.errorMessage || '通信エラーが発生しました';
        this._notifyListeners();
        return null;
      }

      if (res.isDecodeError()) {
        this.status = 'unavailable';
        this.errorReason = 'decode_error';
        this.errorMessage = res.errorMessage || 'レスポンスのJSON解析に失敗しました';
        this._notifyListeners();
        return null;
      }

      if (res.isHttpError()) {
        this.status = 'unavailable';
        this.errorReason = 'http_error';
        this.errorMessage = res.errorMessage || `HTTP ${res.status}: ${res.statusText || 'Error'}`;
        this._notifyListeners();
        return null;
      }

      if (res.isAborted()) {
        this.status = 'unavailable';
        this.errorReason = 'aborted';
        this.errorMessage = 'リクエストが中断されました';
        this._notifyListeners();
        return null;
      }

      const data = res.data;
      const errors = this.validateManifest(data);
      if (errors.length > 0) {
        this.status = 'unavailable';
        this.manifest = null;
        if (data && data.schema_version && data.schema_version !== this.schemaVersion) {
          this.errorReason = 'version_mismatch';
          this.errorMessage = `スキーマバージョン不一致: 期待 '${this.schemaVersion}', 実際 '${data.schema_version}'`;
        } else {
          this.errorReason = 'invalid_manifest';
          this.errorMessage = `機能マニフェストが不正です (${errors.length}件のエラー): ${errors[0]}`;
        }
        this._notifyListeners();
        return null;
      }

      this.status = 'ready';
      this.manifest = data;
      this.error = null;
      this.errorReason = null;
      this.errorMessage = '';
      this._notifyListeners();
      return this.manifest;
    }

    /**
     * Get sorted list of all scanner IDs.
     * Guaranteed exact equality with backend SCANNERS registry keys when ready.
     * Returns empty array if unavailable.
     * @returns {string[]}
     */
    getScannerIds() {
      if (this.status !== 'ready' || !this.manifest || !this.manifest.scanners) {
        return [];
      }
      return Object.keys(this.manifest.scanners).sort();
    }

    /**
     * Get default check IDs (sqli, os, xss).
     * @returns {string[]}
     */
    getDefaultChecks() {
      if (this.status === 'ready' && this.manifest && Array.isArray(this.manifest.default_checks)) {
        return [...this.manifest.default_checks];
      }
      return [...DEFAULT_CHECKS];
    }

    /**
     * Check if a scanner is applicable under the given scan mode and permissions.
     *
     * INVARIANT: Never guess capability when missing or unavailable.
     * If reader is unavailable, returns false.
     *
     * @param {string} scannerId
     * @param {string} [mode='normal'] - 'normal' | 'agent' | 'hybrid'
     * @param {Object} [permissions]
     * @returns {boolean}
     */
    isScannerApplicable(scannerId, mode = 'normal', permissions = null) {
      if (this.status !== 'ready' || !this.manifest || !this.manifest.scanners) {
        return false;
      }
      const sc = this.manifest.scanners[scannerId];
      if (!sc) {
        return false;
      }

      const normalizedMode = String(mode || 'normal').toLowerCase();
      const applicableModes = Array.isArray(sc.applicable_modes)
        ? sc.applicable_modes.map(m => String(m).toLowerCase())
        : [];

      if (!applicableModes.includes(normalizedMode)) {
        return false;
      }

      if (permissions && typeof permissions === 'object') {
        if (permissions.allow_state_changing === false && sc.always_state_changing) {
          return false;
        }
      }

      return true;
    }

    /**
     * Return user-friendly reason if scanner is not applicable.
     * @param {string} scannerId
     * @param {string} [mode='normal']
     * @param {Object} [permissions]
     * @returns {string}
     */
    getGatedReason(scannerId, mode = 'normal', permissions = null) {
      if (this.status !== 'ready' || !this.manifest || !this.manifest.scanners) {
        return '機能情報が利用できません (unavailable)';
      }
      const sc = this.manifest.scanners[scannerId];
      if (!sc) {
        return `未登録のスキャナです (${scannerId})`;
      }

      const normalizedMode = String(mode || 'normal').toLowerCase();
      const applicableModes = Array.isArray(sc.applicable_modes)
        ? sc.applicable_modes.map(m => String(m).toLowerCase())
        : [];

      if (!applicableModes.includes(normalizedMode)) {
        const modeLabel = normalizedMode === 'agent'
          ? 'Agent Browser'
          : normalizedMode === 'hybrid'
          ? 'ハイブリッド'
          : normalizedMode === 'normal'
          ? '通常'
          : normalizedMode;
        return `${modeLabel}モード非対応 (適用可能: ${applicableModes.join(', ') || 'なし'})`;
      }

      if (permissions && typeof permissions === 'object') {
        if (permissions.allow_state_changing === false && sc.always_state_changing) {
          return '状態変更プローブが不許可のため実行不可';
        }
      }

      return '';
    }

    /**
     * Group scanners into UI presentation categories.
     * Handles unknown/new scanners automatically without requiring UI code ID changes.
     *
     * @param {string} [mode='normal']
     * @param {Object} [permissions]
     * @returns {Object<string, Array<Object>>}
     */
    getGroupedScanners(mode = 'normal', permissions = null) {
      const groups = {
        injection: [],
        xss: [],
        access: [],
        header: [],
        proto: [],
        file: [],
      };

      if (this.status !== 'ready' || !this.manifest || !this.manifest.scanners) {
        return groups;
      }

      const defaultChecks = new Set(this.getDefaultChecks());
      const scannerIds = Object.keys(this.manifest.scanners).sort();

      for (const id of scannerIds) {
        const sc = this.manifest.scanners[id];
        const groupName = KNOWN_GROUP_MAPPING[id] || this._inferGroup(id, sc);
        const targetGroup = groups[groupName] || groups.file;

        const label = KNOWN_LABELS[id] || this._formatLabel(id, sc);
        const isDef = defaultChecks.has(id);
        const applicable = this.isScannerApplicable(id, mode, permissions);
        const gatedReason = applicable ? '' : this.getGatedReason(id, mode, permissions);

        targetGroup.push({
          id: id,
          name: sc.name || id,
          label: label,
          def: isDef,
          severity: sc.severity || 'medium',
          cvss: sc.cvss || null,
          applicable: applicable,
          reason: gatedReason,
          cost: sc.cost || 'medium',
          state_change: sc.state_change || 'conditional',
          applicable_modes: sc.applicable_modes || [],
        });
      }

      return groups;
    }

    _inferGroup(id, sc) {
      const ct = String(sc.check_type || id).toLowerCase();
      const nm = String(sc.name || '').toLowerCase();
      if (ct.includes('inject') || ct.includes('sql') || ct.includes('os') || ct.includes('ssti') || ct.includes('ldap') || ct.includes('graphql') || ct.includes('pollution')) {
        return 'injection';
      }
      if (ct.includes('xss') || ct.includes('script')) {
        return 'xss';
      }
      if (ct.includes('auth') || ct.includes('session') || ct.includes('csrf') || ct.includes('priv') || ct.includes('race')) {
        return 'access';
      }
      if (ct.includes('header') || ct.includes('redirect') || ct.includes('traversal') || ct.includes('xxe')) {
        return 'header';
      }
      if (ct.includes('http') || ct.includes('cors') || ct.includes('tls') || ct.includes('proto') || ct.includes('smuggl') || ct.includes('ssrf') || ct.includes('jwt') || ct.includes('websocket') || ct.includes('secret')) {
        return 'proto';
      }
      return 'file';
    }

    _formatLabel(id, sc) {
      if (sc.name && sc.name !== id) {
        return sc.name.replace(/Scanner$/, '');
      }
      return id.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase());
    }
  }

  const defaultReader = new CapabilityReader();

  const readerModuleExport = {
    SCHEMA_VERSION: SCHEMA_VERSION,
    MANIFEST_KIND: MANIFEST_KIND,
    DEFAULT_CHECKS: DEFAULT_CHECKS,
    KNOWN_LABELS: KNOWN_LABELS,
    KNOWN_GROUP_MAPPING: KNOWN_GROUP_MAPPING,
    CapabilityReader: CapabilityReader,
    defaultReader: defaultReader,
    loadCapabilities: function (options) {
      return defaultReader.loadCapabilities(options);
    },
    isReady: function () {
      return defaultReader.isReady();
    },
    isUnavailable: function () {
      return defaultReader.isUnavailable();
    },
    getScannerIds: function () {
      return defaultReader.getScannerIds();
    },
    getDefaultChecks: function () {
      return defaultReader.getDefaultChecks();
    },
    isScannerApplicable: function (scannerId, mode, permissions) {
      return defaultReader.isScannerApplicable(scannerId, mode, permissions);
    },
    getGroupedScanners: function (mode, permissions) {
      return defaultReader.getGroupedScanners(mode, permissions);
    },
  };

  if (typeof module !== 'undefined' && module.exports) {
    module.exports = readerModuleExport;
  }
  if (global) {
    global.VulixCapabilityReader = readerModuleExport;
  }
})(typeof window !== 'undefined' ? window : (typeof globalThis !== 'undefined' ? globalThis : this));
