'use strict';

// Shared FortiPlug runtime: feature registry, FortiGate API access and UI helpers.
(() => {
  if (window.FortiPlug) return;
  const FP = (window.FortiPlug = { features: [] });

  /**
   * Register a feature.
   * { id, label, run: async () => {}, isAvailable?: () => bool,
   *   shortcut?: { key, altKey?, shiftKey?, ctrlKey? }, init?: () => {} }
   * Features without `run` don't appear in the menu; `init` is called once the
   * page is recognised as a FortiGate GUI.
   */
  FP.register = (feature) => FP.features.push(feature);
  FP.menuFeatures = () => FP.features.filter((f) => f.run && (!f.isAvailable || f.isAvailable()));

  // --- FortiGate API ---------------------------------------------------------

  // In Firefox, content.fetch runs in the page context, so the GUI's
  // SameSite=Strict session cookies are sent just like the GUI's own requests.
  const pageFetch = (url, opts) =>
    typeof content !== 'undefined' && content.fetch ? content.fetch(url, opts) : fetch(url, opts);

  FP.getCsrfToken = () => {
    const port = location.port || (location.protocol === 'https:' ? '443' : '80');
    const tokens = document.cookie
      .split(';')
      .map((c) => c.trim())
      .filter((c) => /^ccsrf_?token/i.test(c))
      .map((c) => {
        const i = c.indexOf('=');
        return { name: c.slice(0, i), value: decodeURIComponent(c.slice(i + 1)).replace(/^"|"$/g, '') };
      })
      .filter((c) => c.value);
    const best = tokens.find((c) => c.name.includes(`_${port}_`)) || tokens[0];
    return best ? best.value : null;
  };

  FP.getVdom = () => {
    const fromSearch = new URLSearchParams(location.search).get('vdom');
    const fromHash = (location.hash.match(/[?&]vdom=([^&]+)/) || [])[1];
    return fromSearch || (fromHash && decodeURIComponent(fromHash)) || null;
  };

  FP.request = async (path, { method = 'GET', params = {}, body, vdom } = {}) => {
    const url = new URL(path, location.origin);
    for (const [k, v] of Object.entries(params)) url.searchParams.set(k, v);
    if (vdom) url.searchParams.set('vdom', vdom);
    const headers = { Accept: 'application/json, text/plain, */*' };
    const csrf = FP.getCsrfToken();
    if (csrf) headers['X-CSRFTOKEN'] = csrf;
    if (body !== undefined) {
      headers['Content-Type'] = 'application/json';
      body = JSON.stringify(body);
    }
    const res = await pageFetch(url.href, { method, headers, body, credentials: 'same-origin' });
    const text = await res.text();
    if (!res.ok) {
      let detail = '';
      try {
        const j = JSON.parse(text);
        detail = [j.error !== undefined && `error ${j.error}`, j.cli_error, j.message].filter(Boolean).join(', ');
      } catch { /* not JSON */ }
      throw new Error(`${method} ${url.pathname} → HTTP ${res.status}${detail ? ` (${detail})` : ''}`);
    }
    return text;
  };

  FP.requestJson = async (path, opts) => JSON.parse(await FP.request(path, opts));

  // --- Misc helpers ------------------------------------------------------------

  FP.sleep = (ms) => new Promise((r) => setTimeout(r, ms));
  FP.settle = () => new Promise((r) => requestAnimationFrame(() => setTimeout(r, 120)));

  // DOM traversal that also enters open shadow roots and same-origin iframes.
  FP.deepNodes = function* (root, whatToShow = NodeFilter.SHOW_ELEMENT) {
    const doc = root.ownerDocument || root;
    const walker = doc.createTreeWalker(root, NodeFilter.SHOW_ELEMENT | whatToShow);
    for (let n = walker.currentNode; n; n = walker.nextNode()) {
      if (n.nodeType === Node.ELEMENT_NODE) {
        if (whatToShow & NodeFilter.SHOW_ELEMENT && n !== root) yield n;
        if (n.shadowRoot) yield* FP.deepNodes(n.shadowRoot, whatToShow);
        if (n.tagName === 'IFRAME' || n.tagName === 'FRAME') {
          let inner = null;
          try { inner = n.contentDocument?.documentElement; } catch { /* cross-origin */ }
          if (inner) yield* FP.deepNodes(inner, whatToShow);
        }
      } else if (n.nodeType === Node.TEXT_NODE) {
        yield n;
      }
    }
  };
  FP.deepTextNodes = (root) => FP.deepNodes(root, NodeFilter.SHOW_TEXT);
  FP.deepQueryAll = (selector, root = document.documentElement) =>
    [...FP.deepNodes(root)].filter((e) => e.matches(selector));
  // Parent element, crossing shadow root boundaries.
  FP.parentOf = (el) => el.parentElement || el.parentNode?.host || null;

  FP.isVisible = (el) => {
    const r = el.getBoundingClientRect();
    return r.width > 0 && r.height > 0;
  };

  FP.copyText = async (text) => {
    try {
      await navigator.clipboard.writeText(text);
      return true;
    } catch {
      const ta = document.createElement('textarea');
      ta.value = text;
      ta.style.cssText = 'position:fixed;left:-9999px;top:0';
      document.body.appendChild(ta);
      ta.select();
      const ok = document.execCommand('copy');
      ta.remove();
      return ok;
    }
  };

  FP.download = (filename, text) => {
    const a = document.createElement('a');
    a.href = URL.createObjectURL(new Blob([text], { type: 'text/plain' }));
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  };

  // --- UI (isolated in a shadow root so FortiGate CSS can't interfere) ----------

  const CSS = `
    :host { all: initial; }
    * { box-sizing: border-box; font-family: system-ui, -apple-system, "Segoe UI", sans-serif; }
    .launcher { position: fixed; right: 16px; bottom: 16px; width: 36px; height: 36px; border-radius: 50%;
      border: none; background: #c8102e; color: #fff; font-weight: 700; font-size: 13px; cursor: pointer;
      box-shadow: 0 2px 8px rgba(0,0,0,.3); opacity: .75; transition: opacity .15s; }
    .launcher:hover, .launcher.open { opacity: 1; }
    .launcher.busy { animation: pulse 1s infinite; }
    @keyframes pulse { 50% { opacity: .4; } }
    .menu { position: fixed; right: 16px; bottom: 60px; min-width: 260px; background: #fff; color: #222;
      border-radius: 6px; box-shadow: 0 4px 16px rgba(0,0,0,.25); padding: 4px 0; font-size: 13px; }
    .menu-title { padding: 6px 12px; font-size: 11px; color: #888; text-transform: uppercase; letter-spacing: .05em; }
    .menu button { display: flex; justify-content: space-between; gap: 16px; width: 100%; border: none;
      background: none; padding: 8px 12px; text-align: left; font-size: 13px; color: inherit; cursor: pointer; }
    .menu button:hover { background: #f1f3f5; }
    .menu kbd { color: #888; font-size: 11px; font-family: inherit; }
    .toast { position: fixed; right: 60px; bottom: 20px; max-width: 420px; padding: 8px 12px; border-radius: 4px;
      background: #333; color: #fff; font-size: 13px; box-shadow: 0 2px 8px rgba(0,0,0,.3); }
    .toast.error { background: #b00020; }
    .toast.ok { background: #2e7d32; }
    .overlay { position: fixed; inset: 0; background: rgba(0,0,0,.45); display: flex; align-items: center;
      justify-content: center; padding: 16px; }
    .modal { background: #fff; color: #222; border-radius: 8px; width: min(900px, 100%); max-height: 90vh;
      display: flex; flex-direction: column; box-shadow: 0 8px 32px rgba(0,0,0,.35); }
    .modal header { padding: 12px 16px; border-bottom: 1px solid #e5e5e5; font-weight: 600; font-size: 15px; }
    .modal .notes { padding: 8px 16px 0; font-size: 12px; color: #8a5300; }
    .modal .notes div { margin-bottom: 4px; }
    .modal textarea { margin: 12px 16px; flex: 1; min-height: 300px; resize: vertical; border: 1px solid #ccc;
      border-radius: 4px; padding: 8px; font: 12px/1.4 ui-monospace, Consolas, monospace; white-space: pre; }
    .modal footer { padding: 0 16px 12px; display: flex; gap: 8px; justify-content: flex-end; }
    .modal footer button { padding: 6px 14px; border-radius: 4px; border: 1px solid #ccc; background: #fff;
      font-size: 13px; cursor: pointer; }
    .modal footer button.primary { background: #c8102e; border-color: #c8102e; color: #fff; }
    .modal footer button:disabled { opacity: .5; cursor: default; }
    .modal.wide { width: min(1200px, 100%); }
    .modal .body { padding: 12px 16px; overflow: auto; flex: 1; font-size: 13px; }
    .modal .muted { color: #777; }
    .modal .cols { display: grid; grid-template-columns: 1fr 1fr; gap: 16px; margin-bottom: 12px; }
    @media (max-width: 700px) { .modal .cols { grid-template-columns: 1fr; } }
    .modal fieldset { border: 1px solid #ddd; border-radius: 6px; padding: 8px 10px; margin: 0; min-width: 0; }
    .modal legend { font-weight: 600; padding: 0 4px; }
    .modal select, .modal input[type="search"], .modal input[type="text"], .modal input[type="number"] { font: inherit; padding: 4px 6px; border: 1px solid #ccc; border-radius: 4px; }
    .modal .rename-preview input[type="text"] { width: 100%; min-width: 240px; }
    .modal .rename-preview td { overflow-wrap: anywhere; }
    .modal textarea.rename-aliases { margin: 0; width: 100%; min-height: 76px; white-space: pre; }
    .modal .rename-preview label, .modal fieldset > label { display: flex; flex-direction: column; gap: 4px; margin-top: 6px; }
    .modal label.rename-option { display: flex; align-items: center; gap: 6px; margin-top: 8px; }
    .modal .rename-preview details { min-width: 220px; max-width: 400px; }
    .modal .rename-preview summary { cursor: pointer; }
    .modal .policy-detail { white-space: pre-wrap; margin-top: 5px; }
    .modal .picker { margin-top: 6px; }
    .modal .picker input[type="search"] { width: 100%; margin-bottom: 4px; }
    .modal .picker .options { max-height: 160px; overflow: auto; border: 1px solid #eee; border-radius: 4px; }
    .modal .picker label { display: flex; gap: 6px; align-items: center; padding: 3px 6px; cursor: pointer; }
    .modal .picker label:hover { background: #f1f3f5; }
    .modal .picker .kind { color: #999; font-size: 11px; margin-left: auto; }
    .modal .picker label.blocked { color: #aaa; cursor: not-allowed; }
    .modal .picker.off { opacity: .4; pointer-events: none; }
    .modal .chosen { margin-top: 4px; font-size: 12px; color: #555; min-height: 1em; }
    .modal table { width: 100%; border-collapse: collapse; }
    .modal th, .modal td { text-align: left; padding: 4px 6px; border-bottom: 1px solid #eee; vertical-align: top; }
    .modal th { position: sticky; top: 0; background: #fafafa; font-weight: 600; }
    .modal .old { color: #999; text-decoration: line-through; }
    .modal .new { color: #1b5e20; font-weight: 600; }
    .modal .err { color: #b00020; }
    .modal .ok { color: #1b5e20; }
  `;

  let shadow;
  const root = () => {
    if (shadow) return shadow;
    const host = document.createElement('div');
    host.id = 'fortiplug-host';
    host.style.cssText = 'position:fixed;top:0;left:0;width:0;height:0;z-index:2147483647;';
    shadow = host.attachShadow({ mode: 'open' });
    const style = document.createElement('style');
    style.textContent = CSS;
    shadow.appendChild(style);
    document.documentElement.appendChild(host);
    return shadow;
  };

  const el = (tag, props = {}, children = []) => {
    const e = Object.assign(document.createElement(tag), props);
    for (const c of children) e.append(c);
    return e;
  };

  FP.root = root;
  FP.el = el;

  let toastTimer;
  FP.toast = (message, type = '', ms = 4000) => {
    const r = root();
    r.querySelector('.toast')?.remove();
    clearTimeout(toastTimer);
    const t = el('div', { className: `toast ${type}`, textContent: message });
    r.appendChild(t);
    if (ms) toastTimer = setTimeout(() => t.remove(), ms);
  };

  FP.showModal = ({ title, text, notes = [], filename }) => {
    const r = root();
    r.querySelector('.overlay')?.remove();
    const textarea = el('textarea', { value: text, readOnly: true, spellcheck: false });
    const close = () => {
      overlay.remove();
      document.removeEventListener('keydown', onKey, true);
    };
    const onKey = (e) => e.key === 'Escape' && close();
    const copyBtn = el('button', { className: 'primary', textContent: 'Copy' });
    copyBtn.onclick = async () => {
      const ok = await FP.copyText(text);
      copyBtn.textContent = ok ? 'Copied ✓' : 'Copy failed';
      setTimeout(() => (copyBtn.textContent = 'Copy'), 1500);
    };
    const footer = el('footer', {}, [copyBtn]);
    if (filename) {
      const dl = el('button', { textContent: 'Download' });
      dl.onclick = () => FP.download(filename, text);
      footer.append(dl);
    }
    const closeBtn = el('button', { textContent: 'Close' });
    closeBtn.onclick = close;
    footer.append(closeBtn);
    const overlay = el('div', { className: 'overlay' }, [
      el('div', { className: 'modal' }, [
        el('header', { textContent: title }),
        ...(notes.length ? [el('div', { className: 'notes' }, notes.map((n) => el('div', { textContent: `⚠ ${n}` })))] : []),
        textarea,
        footer,
      ]),
    ]);
    overlay.addEventListener('click', (e) => e.target === overlay && close());
    document.addEventListener('keydown', onKey, true);
    r.appendChild(overlay);
  };

  const shortcutLabel = (s) =>
    [s.ctrlKey && 'Ctrl', s.altKey && 'Alt', s.shiftKey && 'Shift', s.key.toUpperCase()].filter(Boolean).join('+');

  let busy = false;
  FP.runFeature = async (feature) => {
    if (busy) return;
    busy = true;
    const launcher = root().querySelector('.launcher');
    launcher?.classList.add('busy');
    try {
      await feature.run();
    } catch (err) {
      console.error('[FortiPlug]', err);
      FP.toast(err.message || String(err), 'error', 8000);
    } finally {
      busy = false;
      launcher?.classList.remove('busy');
    }
  };

  FP.mountLauncher = () => {
    const r = root();
    const launcher = el('button', { className: 'launcher', textContent: 'FP', title: 'FortiPlug' });
    let menu = null;
    const closeMenu = () => {
      menu?.remove();
      menu = null;
      launcher.classList.remove('open');
    };
    launcher.onclick = () => {
      if (menu) return closeMenu();
      const items = FP.menuFeatures();
      menu = el('div', { className: 'menu' }, [el('div', { className: 'menu-title', textContent: 'FortiPlug' })]);
      if (!items.length) menu.append(el('div', { className: 'menu-title', textContent: 'Nothing available on this page' }));
      for (const f of items) {
        const b = el('button', {}, [el('span', { textContent: f.label })]);
        if (f.shortcut) b.append(el('kbd', { textContent: shortcutLabel(f.shortcut) }));
        b.onclick = () => {
          closeMenu();
          FP.runFeature(f);
        };
        menu.append(b);
      }
      r.appendChild(menu);
      launcher.classList.add('open');
    };
    document.addEventListener('click', (e) => menu && !e.composedPath().includes(r.host) && closeMenu());
    r.appendChild(launcher);

    document.addEventListener(
      'keydown',
      (e) => {
        for (const f of FP.features) {
          const s = f.shortcut;
          if (!s || e.key.toLowerCase() !== s.key.toLowerCase()) continue;
          if (!!s.altKey !== e.altKey || !!s.shiftKey !== e.shiftKey || !!s.ctrlKey !== e.ctrlKey) continue;
          if (f.isAvailable && !f.isAvailable()) continue;
          e.preventDefault();
          e.stopPropagation();
          FP.runFeature(f);
          return;
        }
      },
      true
    );
  };
})();
