/* Shared safe summaries for the opt-in application shell. */
(function (global) {
  'use strict';

  const SECRET_KEY = /(?:^key$|(?:api|access|auth)[_-]?key|password|passwd|pwd|secret|token|session[_-]?id|csrf|xsrf|credentials?|signature|samlresponse|(?:^|[._-])(?:sid|sessid|jwt|sig|jsessionid|phpsessid|bearer)(?:$|[._-])|(?:^|[._-])aspsessionid[a-z]*(?:$|[._-])|(?:^|[._-])(?:auth|authorization|session|otp|ticket)$)/i;
  const hidden = '（URL非表示）';
  const sensitive = (key) => {
    if (!key) return false;
    let decoded = key;
    try { decoded = decodeURIComponent(key); } catch (_) {}
    return SECRET_KEY.test(key) || SECRET_KEY.test(decoded) || /(?:^|[._-])(?:jsessionid|jessionid)(?:$|[._-])/i.test(decoded);
  };
  function maskPath(path) {
    return String(path || '').replace(/(?:%28|\()([A-Z](?:%28|\()[^%()]*?(?:%29|\)))+(?:%29|\))/gi, '(<redacted>)')
      .replace(/;([^/;?#=]+)=([^/;?#]*)/g, (all, key) => sensitive(key) ? `;${key}=<redacted>` : all);
  }
  function unsafePath(path) {
    let decoded = path;
    try { decoded = decodeURIComponent(path); } catch (_) {}
    return /\/\((?:[A-Z]\([^)]*\))+\)(?:\/|$)/i.test(decoded) || decoded.split('/').some((segment) => segment.split(';').slice(1).some((part) => {
      const at = part.indexOf('='); return at >= 0 && part.slice(at + 1) !== '<redacted>' && sensitive(part.slice(0, at));
    }));
  }
  function maskKv(value, depth = 0) {
    return String(value || '').replace(/([^&=?\s]*)=([^&]*)/g, (all, key, val) => {
      if (sensitive(key)) return `${key}=<redacted>`;
      if (depth < 2 && val) {
        try {
          const decoded = /%[0-9a-f]{2}/i.test(val) ? decodeURIComponent(val) : val;
          const masked = maskKv(decoded, depth + 1);
          if (masked !== decoded) return `${key}=${decoded === val ? masked : encodeURIComponent(masked).replace(/%3C/gi, '<').replace(/%3E/gi, '>')}`;
        } catch (_) {}
      }
      return all;
    });
  }
  function redactDisplayUrl(raw) {
    if (typeof raw !== 'string' || !raw.trim()) return '';
    const value = raw.trim();
    const prefix = /^[a-z][a-z\d+.-]*:\/\//i.test(value) ? '' : 'http://';
    let parsed;
    try { parsed = new URL(prefix + value); } catch (_) { return hidden; }
    if (!/^https?:$/.test(parsed.protocol) || !parsed.hostname) return hidden;
    let shown = prefix + value;
    shown = shown.replace(/^(https?:\/\/)([^/?#]*)/i, (_, scheme, auth) =>
      `${scheme}${auth.includes('@') ? '<redacted>@' + auth.slice(auth.lastIndexOf('@') + 1) : auth}`);
    const authorityStart = prefix.length;
    const authorityEnd = ['/', '?', '#'].map((ch) => shown.indexOf(ch, authorityStart)).filter((i) => i >= 0).reduce((a, b) => Math.min(a, b), shown.length);
    const authority = shown.slice(authorityStart, authorityEnd);
    let tail = shown.slice(authorityEnd);
    const hashAt = tail.indexOf('#');
    let fragment = '';
    if (hashAt >= 0) { fragment = tail.slice(hashAt + 1); tail = tail.slice(0, hashAt); }
    const queryAt = tail.indexOf('?');
    let path = queryAt >= 0 ? tail.slice(0, queryAt) : tail;
    const query = queryAt >= 0 ? maskKv(tail.slice(queryAt + 1)) : '';
    path = maskPath(path);
    if (unsafePath(path)) return hidden;
    return shown.slice(0, authorityStart) + authority + path + (queryAt >= 0 ? '?' + query : '') + (fragment ? '#' + maskKv(fragment) : '');
  }
  const resultData = (result, key) => result && result.ok && result.data && Array.isArray(result.data[key]) ? result.data[key] : null;
  function createSummaryReader(api) {
    return {
      async scans() { const result = await api.get('/api/v1/scans'); return resultData(result, 'scans') === null ? null : { scans: result.data.scans, storage: result.data.storage || null }; },
      async audit() { const result = await api.get('/api/v1/audit'); return resultData(result, 'audit'); },
      async status() { const result = await api.get('/api/v1/scan/status'); return result && result.ok && result.data ? result.data : null; },
      async schedules() { const result = await api.get('/api/v1/schedules'); return resultData(result, 'schedules'); },
      redactDisplayUrl,
    };
  }
  global.VulixSummaryReader = { createSummaryReader, redactDisplayUrl };
})(typeof window !== 'undefined' ? window : globalThis);
