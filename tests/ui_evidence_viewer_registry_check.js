const fs = require('fs');
const vm = require('vm');
const assert = require('assert');

const context = { window: {}, atob: value => Buffer.from(value, 'base64').toString('binary') };
vm.runInNewContext(fs.readFileSync(process.argv[2], 'utf8'), context);
const registry = context.window.EvidenceViewerRegistry;
const redactText = value => String(value).replace(/((?:password|token|secret|authorization)=)[^&\s]*/ig, '$1[redacted]');
const redactUrl = value => String(value).replace(/\/\/[^/@]+@/, '//[redacted]@').replace(/([?&#](?:token|secret|password)=)[^&#]*/ig, '$1[redacted]');
const helpers = { redactText, redactUrl };

for (const [type, expected] of [['xss_dialog', 'dom'], ['mass_assignment', 'json'], ['http_trace_xst', 'http'], ['unseen_signal', 'fallback']]) {
  const finding = { evidence_type: type, evidence: '<img src=x onerror=alert(1)>', request: {}, response: {}, evidence_details: { note: '<script>bad()</script>', token: 'SENTINEL' } };
  const html = registry.render(finding, helpers);
  assert(html.includes(`data-evidence-kind="${expected}"`));
  assert(!html.includes('SENTINEL'));
  assert(!html.includes('<script>'));
  assert(html.includes('&lt;img'));
}

registry.register('dummy_kind', ({ finding }) => finding.evidence);
const dummy = registry.render({ evidence_type: 'dummy_kind', evidence: '<svg onload=alert(1)>' }, helpers);
assert(dummy.includes('data-evidence-kind="dummy_kind"'));
assert(dummy.includes('&lt;svg onload=alert(1)&gt;'));
assert(!dummy.includes('<svg'));

const nested = registry.render({
  evidence_type: 'unknown_nested',
  url: 'https://user:pass@example.test/p?token=URL_SENTINEL#secret=FRAGMENT_SENTINEL',
  request: { url: 'https://user:pass@example.test/?password=URL_SENTINEL', headers: { Authorization: 'HEADER_SENTINEL', Accept: 'text/plain' }, body: { nested: { api_token: 'NESTED_SENTINEL' } } },
  response: { status: 200, headers: { 'Set-Cookie': 'COOKIE_SENTINEL' }, body: '<svg onload=alert(1)>' },
  evidence_details: { context: { access_token: 'DETAIL_SENTINEL', markup: '<iframe srcdoc="x">' }, json_body: '{"nested":{"client_secret":"JSON_SENTINEL"}}' },
}, helpers);
for (const secret of ['URL_SENTINEL', 'FRAGMENT_SENTINEL', 'HEADER_SENTINEL', 'NESTED_SENTINEL', 'COOKIE_SENTINEL', 'DETAIL_SENTINEL', 'JSON_SENTINEL', 'user:pass']) assert(!nested.includes(secret), `leaked ${secret}: ${nested}`);
assert(!nested.includes('<svg'));
assert(nested.includes('&lt;svg'));

const screenshot = registry.screenshot('/9j/AA==');
assert(screenshot.includes('class="btn-show-shot"'));
assert(screenshot.includes('data:image/jpeg;base64,/9j/AA=='));
assert(!registry.screenshot(Buffer.from('<svg onload=alert(1)>').toString('base64')));
assert(!registry.screenshot('data:image/svg+xml,<svg>'));
console.log('evidence viewer registry behavior passed');
