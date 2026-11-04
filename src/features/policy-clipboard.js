'use strict';

// Right-click "Copy" / "Paste above" / "Paste below" for policies, done through the
// REST API. The GUI's own paste is unavailable for some policies (e.g. ones with
// multiple interfaces); this works for any policy.
(() => {
  const FP = window.FortiPlug;
  const STORE_KEY = 'policyClipboard';
  const PASTE_DISABLED = true; // pasted copies start disabled so they can be reviewed first
  const NAME_MAX = 35;

  const apiPath = (table) => `/api/v2/cmdb/${table.replace(' ', '/')}`;
  const getClipboard = async () => (await browser.storage.local.get(STORE_KEY))[STORE_KEY] || null;

  // --- Which policy was right-clicked ----------------------------------------------

  // Record of the last right-click, shown by the diagnostics feature.
  FP.lastContextMenu = null;
  const debug = (info) => {
    FP.lastContextMenu = { ...FP.lastContextMenu, ...info };
    console.debug('[FortiPlug] context menu', FP.lastContextMenu);
  };

  let idColumnHintShown = false;

  const policyIdAt = (event) => {
    let grid;
    try {
      grid = FP.policyList.locateGrid();
    } catch (err) {
      if (!idColumnHintShown) {
        idColumnHintShown = true;
        FP.toast('FortiPlug copy/paste needs the ID column. Enable it in the policy table column settings.', 'error', 8000);
      }
      debug({ reason: err.message });
      return null;
    }
    const target = event.composedPath().find((n) => n && n.nodeType === Node.ELEMENT_NODE);
    if (!target) return null;

    // Grid root: smallest ancestor of the body that also holds the header.
    let gridRoot = grid.container;
    while (gridRoot && !gridRoot.contains(grid.header)) gridRoot = FP.parentOf(gridRoot);
    if (!gridRoot || !gridRoot.contains(target)) {
      debug({ reason: 'click outside the policy grid' });
      return null;
    }

    const hits = FP.policyList.scanColumn(grid.header, grid.container).filter((h) => h.id > 0);
    const rows = FP.policyList.rowsFor(hits, grid.container);
    const inRow = rows.find((r) => r.row.contains(target));
    if (inRow) return inRow.id;
    // Split grids (frozen columns): match by the row's vertical extent.
    const y = event.clientY;
    const byBand = rows.find((r) => {
      const b = r.row.getBoundingClientRect();
      return y >= b.top && y <= b.bottom;
    });
    if (!byBand) debug({ reason: `no policy row at y=${y} (${rows.length} rows seen)` });
    return byBand ? byBand.id : null;
  };

  // --- Copy / paste via REST API ----------------------------------------------------

  const copyPolicy = async (table, id) => {
    const vdom = FP.getVdom();
    const res = await FP.requestJson(`${apiPath(table)}/${id}`, { vdom });
    const policy = res.results?.[0];
    if (!policy) throw new Error(`Policy ${id} not found.`);
    await browser.storage.local.set({ [STORE_KEY]: { table, id, host: location.host, vdom, policy, time: Date.now() } });
    FP.toast(`Policy ${id} copied. Right-click a policy to paste it above or below.`, 'ok');
  };

  const uniqueName = (name, taken) => {
    if (!name) return '';
    for (let i = 1; ; i++) {
      const suffix = i === 1 ? '_copy' : `_copy${i}`;
      const candidate = name.slice(0, NAME_MAX - suffix.length) + suffix;
      if (!taken.has(candidate)) return candidate;
    }
  };

  const pastePolicy = async (table, targetId, where) => {
    const clip = await getClipboard();
    if (!clip) throw new Error('Nothing copied yet.');
    if (clip.table !== table) throw new Error(`The copied entry is a ${clip.table}, not a ${table}.`);
    const vdom = FP.getVdom();
    const path = apiPath(table);

    const existing = await FP.requestJson(path, { vdom, params: { format: 'policyid|name' } });
    const taken = new Set((existing.results || []).map((p) => p.name).filter(Boolean));

    const body = structuredClone(clip.policy);
    delete body.policyid;
    delete body.uuid;
    delete body.q_origin_key;
    body.policyid = 0; // let FortiOS assign the next free ID
    body.name = uniqueName(body.name, taken);
    if (PASTE_DISABLED) body.status = 'disable';

    FP.toast(`Pasting policy ${clip.id} ${where} ${targetId}…`, '', 0);
    const created = await FP.requestJson(path, { method: 'POST', vdom, body });
    const newId = created.mkey;
    if (newId === undefined) throw new Error('Policy was created, but FortiOS did not return its ID. Check the list.');
    await FP.request(`${path}/${newId}`, { method: 'PUT', vdom, params: { action: 'move', [where]: targetId } });

    FP.toast(`Created policy ${newId}${body.name ? ` "${body.name}"` : ''} ${where} ${targetId}` +
      `${PASTE_DISABLED ? ' (disabled)' : ''}. Reloading…`, 'ok', 0);
    setTimeout(() => location.reload(), 1500);
  };

  // --- Context menu --------------------------------------------------------------

  const actionsFor = (table, id, clip) => {
    const actions = [{ label: `FortiPlug: Copy policy ${id}`, run: () => copyPolicy(table, id) }];
    if (clip && clip.table === table) {
      actions.push(
        { label: `FortiPlug: Paste ${clip.id} above ${id}`, run: () => pastePolicy(table, id, 'before') },
        { label: `FortiPlug: Paste ${clip.id} below ${id}`, run: () => pastePolicy(table, id, 'after') }
      );
    }
    const bulk = FP.features.find((f) => f.id === 'bulk-interfaces');
    if (bulk && bulk.isAvailable()) actions.push({ label: 'FortiPlug: Bulk edit interfaces…', run: bulk.run });
    return actions;
  };

  const closeGuiMenu = () => {
    for (const type of ['keydown', 'keyup']) {
      document.dispatchEvent(new KeyboardEvent(type, { key: 'Escape', code: 'Escape', keyCode: 27, bubbles: true }));
    }
    for (const type of ['mousedown', 'mouseup', 'click']) {
      document.body.dispatchEvent(new MouseEvent(type, { bubbles: true }));
    }
  };

  // The GUI's context menu item labelled "Copy", near the cursor.
  const findGuiCopyItem = (x, y) => {
    for (const n of FP.deepTextNodes(document.body)) {
      if (n.data.trim() !== 'Copy' || !n.parentElement || !FP.isVisible(n.parentElement)) continue;
      const r = n.parentElement.getBoundingClientRect();
      if (Math.abs(r.left - x) > 500 || Math.abs(r.top - y) > 500) continue;
      for (let a = n.parentElement, i = 0; a && i < 6; a = a.parentElement, i++) {
        const p = a.parentElement;
        if (p && p.children.length >= 3 && [...p.children].some((s) => s !== a && /\b(Paste|Delete|Edit)\b/.test(s.textContent))) {
          return { item: a, label: n };
        }
      }
    }
    return null;
  };

  // Add our entries to the GUI menu by cloning its "Copy" item, so they match its style.
  const injectIntoGuiMenu = (found, actions) => {
    const list = found.item.parentElement;
    list.querySelectorAll(':scope > .fortiplug-item').forEach((e) => e.remove());
    const labelPath = [];
    for (let n = found.label; n !== found.item; n = n.parentNode) labelPath.unshift([...n.parentNode.childNodes].indexOf(n));

    for (const action of actions) {
      const clone = found.item.cloneNode(true);
      clone.classList.add('fortiplug-item');
      for (const e of [clone, ...clone.querySelectorAll('*')]) {
        e.removeAttribute('disabled');
        e.removeAttribute('aria-disabled');
        e.removeAttribute('id');
        [...e.classList].filter((c) => /disabled/i.test(c)).forEach((c) => e.classList.remove(c));
      }
      let label = clone;
      for (const i of labelPath) label = label.childNodes[i];
      label.data = action.label;

      // Keep the GUI's own handlers (possibly delegated) from seeing these clicks.
      for (const type of ['pointerdown', 'mousedown', 'pointerup', 'mouseup']) {
        clone.addEventListener(type, (e) => e.stopPropagation());
      }
      clone.addEventListener('click', (e) => {
        e.preventDefault();
        e.stopPropagation();
        closeGuiMenu();
        FP.runFeature({ run: action.run });
      });
      list.appendChild(clone);
    }
  };

  // Fallback when the GUI menu can't be found: our own small menu at the cursor.
  const showOwnMenu = (x, y, actions) => {
    const r = FP.root();
    r.querySelector('.ctx-menu')?.remove();
    const menu = FP.el('div', { className: 'menu ctx-menu' });
    menu.style.cssText = `left:${x + 4}px;top:${y + 4}px;right:auto;bottom:auto;`;
    const close = () => {
      menu.remove();
      document.removeEventListener('mousedown', onOutside, true);
    };
    const onOutside = (e) => !e.composedPath().includes(menu) && close();
    for (const action of actions) {
      const b = FP.el('button', {}, [FP.el('span', { textContent: action.label })]);
      b.onclick = () => {
        close();
        FP.runFeature({ run: action.run });
      };
      menu.append(b);
    }
    document.addEventListener('mousedown', onOutside, true);
    r.appendChild(menu);
  };

  let lastHandled = 0;
  const onContextMenu = async (event) => {
    if (event.type === 'mousedown' && event.button !== 2) return;
    // A right-click fires both mousedown and contextmenu; handle it once.
    if (event.timeStamp - lastHandled < 500) return;
    lastHandled = event.timeStamp;
    FP.lastContextMenu = { event: event.type, at: new Date().toLocaleTimeString() };
    try {
      const table = FP.policyList.tableForPage();
      if (!table) return debug({ reason: 'not a policy page' });
      const id = policyIdAt(event);
      debug({ policyId: id });
      if (!id) return;
      const { clientX: x, clientY: y } = event;
      const actions = actionsFor(table, id, await getClipboard());
      for (let i = 0; i < 10; i++) {
        await FP.sleep(100);
        const found = findGuiCopyItem(x, y);
        if (found) {
          injectIntoGuiMenu(found, actions);
          return debug({ menu: 'added to GUI menu' });
        }
      }
      showOwnMenu(x, y, actions);
      debug({ menu: 'GUI menu not found, showed own menu' });
    } catch (err) {
      debug({ error: err.message });
      console.error('[FortiPlug]', err);
    }
  };

  FP.register({
    id: 'policy-clipboard',
    label: 'Copy / paste any policy',
    description: 'Copy a policy and paste it above or below another, including policies with multiple interfaces. Pasted copies start disabled.',
    usage: 'Policy list → right-click a policy (ID column must be visible)',
    // Window capture phase runs before any page handler can stop the event.
    init: () => {
      window.addEventListener('mousedown', onContextMenu, true);
      window.addEventListener('contextmenu', onContextMenu, true);
    },
  });
})();
