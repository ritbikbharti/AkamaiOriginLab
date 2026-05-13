// Theme toggle with proper SVG icons + localStorage persistence
(function () {
  const KEY = 'demosite-theme';
  const SUN = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg>';
  const MOON = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3a7 7 0 0 0 9.79 9.79z"/></svg>';

  const saved = localStorage.getItem(KEY);
  const prefersDark = window.matchMedia('(prefers-color-scheme: dark)').matches;
  const initial = saved || (prefersDark ? 'dark' : 'light');
  document.documentElement.setAttribute('data-theme', initial);

  function setIcon(btn, theme) {
    btn.innerHTML = theme === 'dark' ? SUN : MOON;
    btn.title = `Switch to ${theme === 'dark' ? 'light' : 'dark'} mode`;
  }

  window.addEventListener('DOMContentLoaded', () => {
    const btn = document.getElementById('themeToggle');
    if (btn) {
      setIcon(btn, initial);
      btn.addEventListener('click', () => {
        const cur = document.documentElement.getAttribute('data-theme') || 'light';
        const next = cur === 'dark' ? 'light' : 'dark';
        document.documentElement.setAttribute('data-theme', next);
        localStorage.setItem(KEY, next);
        setIcon(btn, next);
      });
    }

    // Mark active nav link
    const here = location.pathname.replace(/index\.html$/, '') || '/';
    document.querySelectorAll('nav.primary a').forEach((a) => {
      const href = a.getAttribute('href');
      if (!href) return;
      const norm = href.replace(/index\.html$/, '') || '/';
      if (norm === here) a.classList.add('active');
    });

    // Wrap every <pre> with a copy-to-clipboard button
    document.querySelectorAll('pre').forEach((pre) => {
      if (pre.parentElement && pre.parentElement.classList.contains('pre-wrap')) return;
      const wrap = document.createElement('div');
      wrap.className = 'pre-wrap';
      pre.parentNode.insertBefore(wrap, pre);
      wrap.appendChild(pre);
      const btn = document.createElement('button');
      btn.type = 'button';
      btn.className = 'copy-btn';
      btn.textContent = 'Copy';
      btn.addEventListener('click', async () => {
        try {
          await navigator.clipboard.writeText(pre.textContent || '');
          btn.textContent = 'Copied';
          btn.classList.add('copied');
          setTimeout(() => { btn.textContent = 'Copy'; btn.classList.remove('copied'); }, 1200);
        } catch {
          btn.textContent = 'Failed';
        }
      });
      wrap.appendChild(btn);
    });
  });
})();

window.formatHeaders = function (res) {
  return Array.from(res.headers.entries()).map(([k, v]) => `${k}: ${v}`).join('\n');
};

// Akamai exposes the per-request "GRN" (Global Request Number) on every
// response. The exact header name varies by property configuration — some
// expose it as a plain `grn`, others stick with `X-Akamai-Request-ID`. Try
// each known name in order; first hit wins.
window.AkamaiDebug = {
  GRN_HEADER_CANDIDATES: [
    'grn',
    'x-akamai-request-id',
    'akamai-request-id',
    'x-akamai-edge-request-id'
  ],
  grn(res) {
    if (!res || !res.headers) return null;
    for (const h of this.GRN_HEADER_CANDIDATES) {
      const v = res.headers.get(h);
      if (v) return v;
    }
    return null;
  },
  // Returns a single-line "GRN: <value>" string, or an empty string when the
  // response did not transit an Akamai property.
  grnLine(res) {
    const v = this.grn(res);
    return v ? `GRN: ${v}` : '';
  }
};
