/** 共有検査項目カタログと説明ポップオーバー。 */
(function (global) {
  'use strict';
  const cache = {};
  let nextId = 0;

  async function loadCatalog(api, lang) {
    const language = lang === 'en' ? 'en' : 'ja';
    if (!cache[language]) cache[language] = (async () => {
      try {
        const response = api && typeof api.get === 'function'
          ? await api.get(`/api/v1/check-catalog?lang=${language}`)
          : await fetch(`/api/v1/check-catalog?lang=${language}`);
        const data = response && response.data ? response.data : (response && response.ok ? await response.json() : null);
        return data && data.checks && typeof data.checks === 'object' ? data : { checks: {}, lang: language };
      } catch (_) { return { checks: {}, lang: language }; }
    })();
    return cache[language];
  }

  function createButton(doc, host, checkId, catalog, lang) {
    const language = lang === 'en' ? 'en' : 'ja';
    const entry = catalog && catalog[checkId];
    const fallback = language === 'en' ? 'Description not available yet' : '説明準備中';
    const title = entry && entry.title ? entry.title : checkId;
    const info = doc.createElement('button');
    info.type = 'button';
    info.className = 'setup-check-info';
    info.textContent = 'i';
    info.setAttribute('aria-label', `${title} ${language === 'en' ? 'description' : 'の説明'}`);
    info.title = entry && entry.short_description ? entry.short_description : fallback;
    info.addEventListener('click', (event) => {
      event.preventDefault();
      event.stopPropagation();
      const old = host.querySelector('.setup-check-popover');
      if (old) { if (old.closeHelp) old.closeHelp(); old.remove(); }
      const popover = doc.createElement('section');
      popover.className = 'setup-check-popover';
      popover.setAttribute('role', 'dialog');
      const heading = doc.createElement('h3');
      heading.textContent = title;
      heading.id = `check-help-${++nextId}`;
      popover.setAttribute('aria-labelledby', heading.id);
      popover.appendChild(heading);
      const fields = [
        ['what_is_tested', '確認する内容', 'What is tested'],
        ['risk_if_vulnerable', '脆弱な場合のリスク', 'Risk if vulnerable'],
        ['verification_overview', '確認方法', 'Verification'],
        ['remediation_overview', '対処の概要', 'Remediation'],
        ['limitations', '制約', 'Limitations'],
      ];
      if (entry) fields.forEach(([key, ja, en]) => {
        const label = doc.createElement('h4');
        label.textContent = language === 'en' ? en : ja;
        const detail = doc.createElement('p');
        detail.textContent = entry[key] || fallback;
        popover.append(label, detail);
      });
      if (!entry) {
        const detail = doc.createElement('p');
        detail.textContent = fallback;
        popover.appendChild(detail);
      }
      const close = doc.createElement('button');
      close.type = 'button';
      close.className = 'setup-check-popover-close';
      close.textContent = language === 'en' ? 'Close' : '閉じる';
      let removeListeners = () => {};
      const closePopover = () => { popover.remove(); removeListeners(); info.focus(); };
      popover.closeHelp = closePopover;
      close.addEventListener('click', closePopover);
      popover.appendChild(close);
      host.appendChild(popover);
      const anchor = info.getBoundingClientRect();
      const box = popover.getBoundingClientRect();
      const below = global.innerHeight - anchor.bottom - 6;
      const top = below < box.height && anchor.top - box.height - 6 >= 8
        ? anchor.top - box.height - 6
        : Math.min(anchor.bottom + 6, global.innerHeight - box.height - 8);
      popover.style.left = `${Math.max(8, Math.min(anchor.left, global.innerWidth - box.width - 8))}px`;
      popover.style.top = `${Math.max(8, top)}px`;
      close.focus();
      const outside = (e) => { if (!popover.contains(e.target) && e.target !== info) closePopover(); };
      const escape = (e) => { if (e.key === 'Escape') closePopover(); };
      removeListeners = () => { doc.removeEventListener('pointerdown', outside); doc.removeEventListener('keydown', escape); };
      doc.addEventListener('pointerdown', outside);
      doc.addEventListener('keydown', escape);
    });
    return info;
  }

  const exported = { loadCatalog, createButton };
  if (typeof module !== 'undefined' && module.exports) module.exports = exported;
  global.VulixCheckHelp = exported;
})(typeof window !== 'undefined' ? window : globalThis);
