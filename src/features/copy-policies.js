'use strict';

// Copy the CLI config of every policy currently shown (i.e. after filtering) in a policy list.
(() => {
  const FP = window.FortiPlug;

  // GUI route → CLI table. More specific patterns first.
  const TABLES = [
    [/proxy-policy|proxy\/policy/i, 'firewall proxy-policy'],
    [/local-in/i, 'firewall local-in-policy'],
    [/multicast/i, 'firewall multicast-policy'],
    [/shaping-policy/i, 'firewall shaping-policy'],
    [/policy6/i, 'firewall policy6'],
    [/policy/i, 'firewall policy'],
  ];
  const tableForPage = () => {
    const route = location.pathname + location.hash;
    return (TABLES.find(([re]) => re.test(route)) || [])[1] || null;
  };

  // --- Reading the filtered policy list from the DOM --------------------------
  //
  // Rather than depend on the GUI's internal markup, find the "ID" column header
  // and collect every pure-number text node that sits horizontally inside that
  // column, below the header. The list is virtualised, so scroll it from top to
  // bottom and collect along the way.

  const HEADER_RE = /^(id|policy id)$/i;
  const textOf = (e) => (e.innerText || e.textContent || '').trim().replace(/\s+/g, ' ');

  const ID_COLUMN_RE = /^(policyid|policy-id|id)$/i;
  // FortiOS 7.6+ grid: <div class="header-cell" data-column-id="...">
  const headerCells = () => FP.deepQueryAll('.header-cell[data-column-id]').filter(FP.isVisible);

  const findIdHeaders = () => {
    const cells = headerCells().filter((c) => ID_COLUMN_RE.test(c.dataset.columnId) || HEADER_RE.test(textOf(c)));
    if (cells.length) return cells;
    const headers = FP.deepQueryAll('th, [role="columnheader"]').filter(
      (h) => FP.isVisible(h) && HEADER_RE.test(textOf(h))
    );
    if (headers.length) return headers;
    // Div-based grids without ARIA roles: any visible leaf text "ID".
    const out = [];
    for (const n of FP.deepTextNodes(document.documentElement)) {
      if (HEADER_RE.test(n.data.trim()) && n.parentElement && FP.isVisible(n.parentElement)) out.push(n.parentElement);
    }
    return out;
  };

  // Numbers in badges (e.g. security rating issue counts) are not policy IDs.
  const BADGE_RE = /bubble|badge|rating|notification|count/i;

  // Column id of the nearest cell ancestor, and whether a badge sits in between.
  const cellInfo = (el, stop) => {
    let badge = false;
    for (let a = el; a && a !== stop; a = FP.parentOf(a)) {
      if (BADGE_RE.test(a.getAttribute?.('class') || '')) badge = true;
      if (a.dataset?.columnId) return { column: a.dataset.columnId, badge };
    }
    return { column: null, badge };
  };

  // Returns the elements holding the ID numbers in `container` under `header`.
  const scanColumn = (header, container) => {
    const h = header.getBoundingClientRect();
    const hits = [];
    const range = (container.ownerDocument || document).createRange();
    for (const n of FP.deepTextNodes(container)) {
      if (!/^\s*\d+\s*$/.test(n.data)) continue;
      range.selectNodeContents(n);
      const r = range.getBoundingClientRect();
      if (!r.width || !r.height || r.top < h.bottom - 2) continue;
      const cx = r.left + r.width / 2;
      if (cx < h.left - 2 || cx > h.right + 2) continue;
      const { column, badge } = cellInfo(n.parentElement, container);
      if (badge) continue;
      hits.push({ id: parseInt(n.data.trim(), 10), el: n.parentElement, top: r.top, column });
    }
    // If body cells are tagged with their column, only trust cells of the ID column.
    const col = header.dataset?.columnId;
    return col && hits.some((x) => x.column === col) ? hits.filter((x) => x.column === col) : hits;
  };

  // Smallest ancestor of the header that also contains ID cells.
  const findContainer = (header) => {
    for (let a = FP.parentOf(header); a && a !== header.ownerDocument.documentElement; a = FP.parentOf(a)) {
      if (scanColumn(header, a).length) return a;
    }
    return null;
  };

  const findScroller = (start) => {
    const doc = start.ownerDocument;
    for (let a = start; a && a !== doc.body; a = FP.parentOf(a)) {
      const oy = doc.defaultView.getComputedStyle(a).overflowY;
      if ((oy === 'auto' || oy === 'scroll') && a.scrollHeight > a.clientHeight + 5) return a;
    }
    const se = doc.scrollingElement;
    return se && se.scrollHeight > se.clientHeight + 5 ? se : null;
  };

  const locateGrid = () => {
    const headers = findIdHeaders();
    if (!headers.length) {
      const cols = headerCells().map((c) => textOf(c) || c.dataset.columnId);
      throw new Error('No "ID" column found. Enable the ID column in the policy table (column settings) and try again.' +
        (cols.length ? ` Visible columns: ${cols.join(', ')}` : ''));
    }
    let best = null;
    for (const header of headers) {
      const container = findContainer(header);
      if (!container) continue;
      const count = scanColumn(header, container).length;
      if (!best || count > best.count) best = { header, container, count };
    }
    if (!best) throw new Error('Found the "ID" column but no policy IDs under it. Is the list empty?');
    return best;
  };

  // Row element of each ID hit: the largest ancestor of its cell holding no other ID cell.
  const rowsFor = (hits, container) =>
    hits.map((h) => {
      let row = h.el;
      for (let p = FP.parentOf(row); p && p !== container; p = FP.parentOf(p)) {
        if (hits.some((o) => o !== h && p.contains(o.el))) break;
        row = p;
      }
      return { ...h, row };
    });

  const SELECTED_RE = /(^|\s)(selected|is-selected|row-selected|[\w-]*-selected)(\s|$)/i;
  const isRowSelected = (row) => {
    for (const e of [row, ...[...row.querySelectorAll('*')].slice(0, 200)]) {
      if (e.getAttribute('aria-selected') === 'true' || e.getAttribute('aria-checked') === 'true') return true;
      if (e.matches('input[type="checkbox"]') && e.checked) return true;
      if (SELECTED_RE.test(e.getAttribute('class') || '')) return true;
    }
    return false;
  };

  // All policy IDs in the (filtered) list in GUI order, plus those selected in the GUI.
  const collectList = async () => {
    let { header, container } = locateGrid();
    const first = scanColumn(header, container)[0];
    const scroller = findScroller(first.el);
    const found = new Map(); // id → vertical position in the scrolled content
    const selected = new Set();

    const offset = () => {
      if (!scroller) return 0;
      if (scroller === scroller.ownerDocument.scrollingElement) return scroller.ownerDocument.defaultView.scrollY;
      return scroller.scrollTop - scroller.getBoundingClientRect().top;
    };
    const collect = () => {
      if (!header.isConnected || !container.isConnected) ({ header, container } = locateGrid());
      const off = offset();
      const hits = scanColumn(header, container).filter((h) => h.id > 0); // 0 = implicit deny
      for (const { id, top, row } of rowsFor(hits, container)) {
        if (!found.has(id)) found.set(id, top + off);
        if (isRowSelected(row)) selected.add(String(id));
      }
    };

    // Wait until the rows at the current scroll position have finished rendering:
    // the visible IDs and the content height must be unchanged across two checks.
    const waitStable = async () => {
      let prev = null;
      for (let i = 0; i < 30; i++) {
        await FP.settle();
        if (!header.isConnected || !container.isConnected) continue;
        const ids = scanColumn(header, container).map((h) => h.id).join(',');
        const sig = `${ids}|${scroller ? scroller.scrollHeight : ''}`;
        if (ids && sig === prev) return;
        prev = sig;
      }
    };

    const pass = async () => {
      scroller.scrollTop = 0;
      await waitStable();
      for (let guard = 0; guard < 5000; guard++) {
        collect();
        FP.toast(`Collecting policies… ${found.size}`, '', 0);
        if (scroller.scrollTop + scroller.clientHeight >= scroller.scrollHeight - 2) {
          // At the bottom: wait in case more rows get loaded, then re-check.
          const height = scroller.scrollHeight;
          await waitStable();
          collect();
          if (scroller.scrollHeight === height) break;
          continue;
        }
        const before = scroller.scrollTop;
        // Half a page per step, so consecutive views overlap.
        scroller.scrollTop += Math.max(40, Math.floor(scroller.clientHeight * 0.5));
        await waitStable();
        if (scroller.scrollTop === before) break;
      }
      collect();
    };

    if (!scroller) {
      await waitStable();
      collect();
    } else {
      const startTop = scroller.scrollTop;
      // Repeat until a full pass finds nothing new (max 4 passes).
      for (let i = 0; i < 4; i++) {
        const before = found.size;
        await pass();
        if (i > 0 && found.size === before) break;
      }
      scroller.scrollTop = startTop;
    }
    const ids = [...found.entries()].sort((a, b) => a[1] - b[1]).map(([id]) => String(id));
    return { ids, selected: ids.filter((id) => selected.has(id)) };
  };

  const collectFilteredIds = async () => (await collectList()).ids;

  // --- Fetching config ------------------------------------------------------------

  const looksLikeConfig = (t) => /^#config-version=/m.test(t) || /^\s*config \S/m.test(t);

  // Full config backup; gives the exact output of "show". FortiOS 7.6 uses POST,
  // older releases GET. Try VDOM scope first, then global.
  const fetchBackup = async (vdom) => {
    const path = '/api/v2/monitor/system/config/backup';
    const scopes = vdom ? [{ scope: 'vdom', vdom }, { scope: 'global' }] : [{ scope: 'global' }];
    const errors = [];
    for (const s of scopes) {
      const attempts = [
        () => FP.request(path, { method: 'POST', body: { destination: 'file', ...s } }),
        () => FP.request(path, { params: { destination: 'file', ...s } }),
      ];
      for (const attempt of attempts) {
        try {
          const text = await attempt();
          if (looksLikeConfig(text)) return text;
          errors.push('unexpected response');
        } catch (e) {
          errors.push(e.message);
        }
      }
    }
    throw new Error([...new Set(errors)].join('; '));
  };

  const unquote = (s) => s.trim().replace(/^"(.*)"$/, '$1');

  // Map of edit-key → lines ("    edit N" … "    next") for `config <table>`,
  // limited to `vdom` when the backup contains several VDOMs.
  const extractEdits = (text, table, vdom) => {
    const lines = text.split(/\r?\n/);
    const edits = new Map();
    let curVdom = null;
    let expectVdom = false;
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim();
      if (t === 'config vdom') { expectVdom = true; continue; }
      if (t === 'config global') { curVdom = null; continue; }
      if (expectVdom && t.startsWith('edit ')) { curVdom = unquote(t.slice(5)); expectVdom = false; continue; }
      if (t !== `config ${table}`) continue;
      const ownVdom = !vdom || !curVdom || curVdom === vdom;
      const indent = lines[i].length - lines[i].trimStart().length;
      let key = null, eIndent = 0, buf = [];
      for (i++; i < lines.length; i++) {
        const line = lines[i];
        const li = line.length - line.trimStart().length;
        const lt = line.trim();
        if (li === indent && lt === 'end') break;
        if (key === null && lt.startsWith('edit ')) {
          key = unquote(lt.slice(5));
          eIndent = li;
          buf = [];
        }
        if (key !== null) {
          buf.push('    ' + line.slice(eIndent));
          if (li === eIndent && lt === 'next') {
            if (ownVdom) edits.set(key, buf);
            key = null;
          }
        }
      }
    }
    return edits;
  };

  // Fallback without backup permission: rebuild CLI from REST JSON, dropping
  // values equal to the schema defaults. Close to, but not exactly, "show".
  const QUOTED_TYPES = new Set(['string', 'var-string', 'datasource', 'user']);
  const cliQuote = (s) => `"${s.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"`;
  const cliValue = (s, v) => (QUOTED_TYPES.has(s.type) || s.datasource ? cliQuote(String(v)) : String(v));

  const entryLines = (entry, schema, depth, skipKey) => {
    const pad = ' '.repeat(depth * 4);
    const out = [];
    for (const [k, v] of Object.entries(entry)) {
      if (k === skipKey || k === 'q_origin_key') continue;
      const s = schema.children?.[k];
      if (!s) continue;
      if (s.category === 'table') {
        if (!Array.isArray(v) || !v.length) continue;
        const childKeys = Object.keys(s.children || {});
        const mk = s.mkey || childKeys[0];
        const mkSchema = s.children?.[mk] || { type: 'string' };
        if (childKeys.length <= 1) {
          out.push(`${pad}set ${k} ${v.map((x) => cliValue(mkSchema, x[mk])).join(' ')}`);
        } else {
          out.push(`${pad}config ${k}`);
          for (const item of v) {
            out.push(`${pad}    edit ${cliValue(mkSchema, item[mk])}`);
            out.push(...entryLines(item, s, depth + 2, mk));
            out.push(`${pad}    next`);
          }
          out.push(`${pad}end`);
        }
        continue;
      }
      if (v === null || v === undefined || v === '' || typeof v === 'object') continue;
      if (k === 'uuid' ? /^0{8}-/.test(v) : 'default' in s && String(s.default) === String(v)) continue;
      out.push(`${pad}set ${k} ${cliValue(s, v)}`);
    }
    return out;
  };

  const editsFromApi = async (table, vdom) => {
    const path = `/api/v2/cmdb/${table.replace(' ', '/')}`;
    const [schemaRes, dataRes] = await Promise.all([
      FP.requestJson(path, { params: { action: 'schema' }, vdom }),
      FP.requestJson(path, { vdom }),
    ]);
    const schema = schemaRes.results;
    const mkey = schema.mkey || 'policyid';
    const edits = new Map();
    for (const entry of dataRes.results || []) {
      const key = String(entry[mkey]);
      edits.set(key, [`    edit ${key}`, ...entryLines(entry, schema, 2, mkey), '    next']);
    }
    return edits;
  };

  // Shared with other policy-list features.
  FP.policyList = { tableForPage, locateGrid, scanColumn, rowsFor, collectList };

  // --- Feature -------------------------------------------------------------------

  FP.register({
    id: 'copy-filtered-policies',
    label: 'Copy config of filtered policies',
    description: 'Copies the CLI config of every policy currently shown in the policy list, after search and filters.',
    usage: 'Policy list → FP button or Alt+Shift+C (ID column must be visible)',
    shortcut: { key: 'c', altKey: true, shiftKey: true },
    isAvailable: () => !!tableForPage(),
    run: async () => {
      const table = tableForPage();
      FP.toast('Collecting policies from the list…', '', 0);
      const ids = await collectFilteredIds();
      if (!ids.length) throw new Error('No policies in the current list.');

      FP.toast(`Fetching config for ${ids.length} policies…`, '', 0);
      const vdom = FP.getVdom();
      const notes = [];
      let edits;
      try {
        edits = extractEdits(await fetchBackup(vdom), table, vdom);
      } catch (e) {
        console.warn('[FortiPlug] backup failed, using REST API', e);
        notes.push(`Config backup not available (${e.message}). Generated from the REST API instead, so it may differ slightly from "show".`);
        edits = await editsFromApi(table, vdom);
      }

      const missing = ids.filter((id) => !edits.has(id));
      if (missing.length) notes.push(`No config found for policy ID(s): ${missing.join(', ')}`);
      const found = ids.filter((id) => edits.has(id));
      const text = [`config ${table}`, ...found.flatMap((id) => edits.get(id)), 'end', ''].join('\n');

      const copied = found.length && (await FP.copyText(text));
      FP.toast(copied ? `Copied ${found.length} policies to the clipboard` : 'Could not copy automatically', copied ? 'ok' : 'error');
      FP.showModal({
        title: `${found.length} of ${ids.length} filtered policies — ${table}${vdom ? ` (VDOM ${vdom})` : ''}`,
        text,
        notes,
        filename: `${location.hostname}-${table.replace(/\s+/g, '-')}-${new Date().toISOString().slice(0, 10)}.conf`,
      });
    },
  });

  // Troubleshooting aid: shows what the DOM detection sees.
  FP.register({
    id: 'diagnose-policy-list',
    label: 'Diagnose policy list detection',
    description: 'Shows what FortiPlug detects on the page (columns, policy IDs, last right-click) for troubleshooting.',
    usage: 'Policy list → FP button',
    isAvailable: () => !!tableForPage(),
    run: async () => {
      const info = [`URL: ${location.href}`, `CLI table: ${tableForPage()}`, `VDOM: ${FP.getVdom() ?? '(none)'}`,
        `CSRF token cookie: ${FP.getCsrfToken() ? 'found' : 'NOT found'}`,
        `Last right-click: ${FP.lastContextMenu ? JSON.stringify(FP.lastContextMenu) : '(none recorded)'}`];
      const headers = FP.deepQueryAll('th, [role="columnheader"]').filter(FP.isVisible);
      info.push(`Column headers (${headers.length}): ${headers.map((h) => JSON.stringify(textOf(h))).join(', ')}`);
      const describe = (e) => {
        if (!e) return '';
        const attrs = [...e.attributes].filter((a) => a.name !== 'style').map((a) => `${a.name}="${a.value.slice(0, 80)}"`);
        return `<${e.tagName.toLowerCase()}${attrs.length ? ' ' + attrs.join(' ') : ''}>`;
      };
      const all = [...FP.deepNodes(document.documentElement)];
      info.push(`Elements: ${all.length}, iframes: ${all.filter((e) => /^I?FRAME$/.test(e.tagName)).length}, ` +
        `shadow roots: ${all.filter((e) => e.shadowRoot).length}, canvases: ${all.filter((e) => e.tagName === 'CANVAS').length}`);

      // How do known column titles appear in the DOM?
      const wanted = ['ID', 'Name', 'Source', 'Destination', 'Action', 'Service'];
      const seen = new Set();
      for (const n of FP.deepTextNodes(document.documentElement)) {
        const t = n.data.trim();
        if (!wanted.includes(t) || seen.has(t) || !n.parentElement || !FP.isVisible(n.parentElement)) continue;
        seen.add(t);
        const r = n.parentElement.getBoundingClientRect();
        const chain = [];
        for (let a = n.parentElement, i = 0; a && i < 6; a = FP.parentOf(a), i++) chain.push(describe(a));
        info.push('', `Text "${t}" at x=${Math.round(r.left)}..${Math.round(r.right)} y=${Math.round(r.top)}:`, ...chain.map((c) => `  ${c}`));
      }
      info.push('', `Column titles not found as visible text: ${wanted.filter((w) => !seen.has(w)).join(', ') || '(none)'}`);

      const cells = headerCells();
      info.push('', `Grid header cells (${cells.length}):`, ...cells.map((c) => `  ${c.dataset.columnId}: "${textOf(c)}"`));

      // First body cell under the leftmost header, with its ancestry, to learn the row structure.
      const first = [...cells].sort((a, b) => a.getBoundingClientRect().left - b.getBoundingClientRect().left)[0];
      if (first) {
        const h = first.getBoundingClientRect();
        const range = document.createRange();
        for (const n of FP.deepTextNodes(document.documentElement)) {
          if (!n.data.trim() || !n.parentElement) continue;
          range.selectNodeContents(n);
          const r = range.getBoundingClientRect();
          const cx = r.left + r.width / 2;
          if (!r.width || r.top < h.bottom + 2 || cx < h.left || cx > h.right) continue;
          const chain = [];
          for (let a = n.parentElement, i = 0; a && i < 10; a = FP.parentOf(a), i++) chain.push(describe(a));
          info.push('', `First cell under "${first.dataset.columnId}": "${n.data.trim().slice(0, 40)}"`, ...chain.map((c) => `  ${c}`));
          break;
        }
      }
      info.push('');
      try {
        const { header, container, count } = locateGrid();
        info.push(`ID header: ${describe(header)}`, `Container: ${describe(container)}`, `IDs visible now: ${count}`);
        for (const hit of scanColumn(header, container)) {
          const chain = [];
          for (let a = hit.el, i = 0; a && a !== container && i < 4; a = FP.parentOf(a), i++) chain.push(describe(a));
          info.push(`  ${hit.id} [column ${hit.column ?? '?'}]: ${chain.join(' < ')}`);
        }
        const scroller = findScroller(scanColumn(header, container)[0].el);
        info.push(`Scroller: ${scroller ? `${describe(scroller)} scrollHeight=${scroller.scrollHeight} clientHeight=${scroller.clientHeight}` : '(none)'}`);
        const { ids, selected } = await collectList();
        info.push(`IDs after scrolling (${ids.length}): ${ids.join(', ')}`);
        info.push(`Selected in GUI (${selected.length}): ${selected.join(', ') || '(none detected)'}`);
        const rows = rowsFor(scanColumn(header, container).filter((h) => h.id > 0), container);
        info.push('Row elements:', ...rows.slice(0, 5).map((r) => `  ${r.id}: ${describe(r.row)}`));
      } catch (e) {
        info.push(`Detection error: ${e.message}`);
      }
      FP.showModal({ title: 'FortiPlug diagnostics', text: info.join('\n') });
    },
  });
})();
