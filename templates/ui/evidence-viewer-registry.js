(function (root) {
  'use strict';

  const builtins = new Map();
  const viewers = new Map();
  const sensitiveKey = /(?:^key$|(?:api|access|auth)[_-]?key|password|passwd|pwd|secret|token|cookie|session[_-]?id|csrf|xsrf|credentials?|signature|samlresponse|(?:^|[._-])(?:sid|sessid|jwt|sig|jsessionid|phpsessid|bearer)(?:$|[._-])|(?:^|[._-])(?:auth|authentication|authorization|session|otp|ticket)$)/i;

  function escape(value) {
    return String(value).replace(/&/g, '&amp;').replace(/</g, '&lt;')
      .replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  function clean(value, key, helpers) {
    if (key && sensitiveKey.test(key)) return '[redacted]';
    if (Array.isArray(value)) return value.map(v => clean(v, '', helpers));
    if (value && typeof value === 'object') {
      const out = Object.create(null);
      Object.entries(value).forEach(([k, v]) => {
        out[k] = clean(v, k, helpers);
      });
      return out;
    }
    if (typeof value !== 'string') return value;
    let text = value;
    if (key && /^(?:url|uri|request_url|response_url)$/i.test(key)) {
      text = helpers.redactUrl(text);
    } else {
      text = helpers.redactText(text);
      try {
        const parsed = JSON.parse(text);
        if (parsed && typeof parsed === 'object') return clean(parsed, key, helpers);
      } catch (_) {}
    }
    return text;
  }

  function row(label, value) {
    return `<div><span class="fc-evidence-label">${escape(label)}</span><pre>${escape(JSON.stringify(value, null, 2))}</pre></div>`;
  }

  function register(kind, render) {
    if (typeof kind !== 'string' || !kind || typeof render !== 'function') throw new TypeError('viewer kind and render function required');
    viewers.set(kind, render);
  }

  function evidenceKind(finding) {
    const type = String(finding.evidence_type || finding.check_type || '').toLowerCase();
    if (/(?:dom|html|xss|reflection|dialog|sink)/.test(type)) return 'dom';
    if (/(?:json|graphql|mass_assignment|nosql|api)/.test(type)) return 'json';
    if (/(?:http|request|response|trace|websocket)/.test(type)) return 'http';
    if (finding.injection_location === 'json_body') return 'json';
    if (Object.keys(finding.request || {}).length || Object.keys(finding.response || {}).length) return 'http';
    return 'fallback';
  }

  function render(finding, helpers) {
    const safeFinding = clean(finding, '', helpers);
    delete safeFinding.screenshot_b64;
    const safe = safeFinding.evidence_details || {};
    const context = { finding: safeFinding, safe, escape };
    const type = String(finding.evidence_type || finding.check_type || '').toLowerCase();
    const kind = viewers.has(type) ? type : evidenceKind(finding);
    const custom = viewers.get(kind);
    const renderer = custom || builtins.get(kind) || builtins.get('fallback');
    let html = renderer(context);
    if (custom) html = `<div class="fc-viewer-custom-text">${escape(String(html ?? ''))}</div>`;
    else if (typeof html !== 'string') html = escape(String(html ?? ''));
    const req = finding.request ? row('Request', clean(finding.request, 'request', helpers)) : '';
    const resp = finding.response ? row('Response', clean(finding.response, 'response', helpers)) : '';
    const details = Object.keys(safe).length ? row('Details', safe) : '';
    return `<section class="evidence-viewer" data-evidence-kind="${escape(kind)}">${html}${req}${resp}${details}</section>`;
  }

  function cleanText(value, key, helpers) {
    const safe = clean(value, key || '', helpers);
    return safe && typeof safe === 'object' ? JSON.stringify(safe) : safe;
  }

  function screenshot(value, dialogConfirmed) {
    if (typeof value !== 'string' || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) return '';
    try {
      const bytes = atob(value);
      if (bytes.length < 3 || bytes.charCodeAt(0) !== 0xff || bytes.charCodeAt(1) !== 0xd8 || bytes.charCodeAt(2) !== 0xff) return '';
    } catch (_) { return ''; }
    const border = dialogConfirmed ? 'border:2px solid var(--critical);box-shadow:0 0 8px rgba(226,112,143,0.4);' : '';
    const alert = dialogConfirmed ? '<div style="position:absolute;top:6px;left:6px;background:rgba(220,38,38,0.9);color:white;font-size:0.65rem;font-weight:800;padding:3px 8px;border-radius:4px;letter-spacing:0.05em;">ALERT FIRED</div>' : '';
    return `<div style="position:relative"><button class="btn-show-shot" style="margin-top:6px;padding:4px 10px;font-size:0.75rem;background:var(--surface2);border:1px solid var(--border);border-radius:4px;color:var(--text-muted);cursor:pointer;" onclick="var img=this.nextElementSibling;img.src=this.dataset.src;img.style.display='block';this.style.display='none';" data-src="data:image/jpeg;base64,${value}">📷 Show screenshot</button><img class="fc-screenshot" style="${border}display:none" onclick="openLightbox(this.src)" alt="Screenshot" onload="this.style.display='block'">${alert}</div>`;
  }

  builtins.set('http', ({ finding, escape: esc }) => `<h4>HTTP evidence</h4><div>${esc(finding.evidence || '')}</div>`);
  builtins.set('json', ({ finding, escape: esc }) => `<h4>JSON/API evidence</h4><div>${esc(finding.evidence || '')}</div>`);
  builtins.set('dom', ({ finding, escape: esc }) => `<h4>DOM/text evidence</h4><div>${esc(finding.evidence || '')}</div>`);
  builtins.set('fallback', ({ finding, escape: esc }) => `<h4>Evidence</h4><div>${esc(finding.evidence || '')}</div>`);
  root.EvidenceViewerRegistry = { register, render, evidenceKind, cleanText, screenshot };
})(window);
