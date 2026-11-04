'use strict';

// Bulk edit the source / destination interfaces (From / To) of several policies.
(() => {
  const FP = window.FortiPlug;
  const TABLES = new Set(['firewall policy', 'firewall policy6', 'firewall proxy-policy']);
  const SIDES = [
    { key: 'srcintf', label: 'Source interface (From)' },
    { key: 'dstintf', label: 'Destination interface (To)' },
  ];
  const MODES = [
    ['keep', 'Keep unchanged'],
    ['replace', 'Replace with'],
    ['add', 'Add'],
    ['remove', 'Remove'],
  ];

  const apiPath = (table) => `/api/v2/cmdb/${table.replace(' ', '/')}`;
  const names = (list) => (Array.isArray(list) ? list.map((x) => x.name) : []);
  const isAvailable = () => TABLES.has(FP.policyList.tableForPage());

  // Interfaces, zones and SD-WAN zones of this VDOM. Interfaces that are members of
  // an SD-WAN, zone, switch or aggregate can't be used in policies; they get `blocked`.
  const loadInterfaces = async (vdom) => {
    const get = (path, params) => FP.requestJson(path, { vdom, params });
    const [intf, zone, sdwan, vswitch, swIntf] = await Promise.allSettled([
      get('/api/v2/cmdb/system/interface', { format: 'name|vdom|type|member' }),
      get('/api/v2/cmdb/system/zone'),
      get('/api/v2/cmdb/system/sdwan'),
      get('/api/v2/cmdb/system/virtual-switch'),
      get('/api/v2/cmdb/system/switch-interface'),
    ]);
    const results = (r) => (r.status === 'fulfilled' ? r.value.results : null);
    if (intf.status !== 'fulfilled') throw new Error(`Could not read interfaces: ${intf.reason.message}`);

    const memberOf = new Map(); // interface → reason it can't be used
    const mark = (names, reason) => names.forEach((n) => n && !memberOf.has(n) && memberOf.set(n, reason));
    const sd = results(sdwan);
    mark((sd?.members || []).map((m) => m.interface), 'SD-WAN member');
    for (const z of results(zone) || []) mark((z.interface || []).map((i) => i['interface-name']), `member of zone ${z.name}`);
    for (const s of results(vswitch) || []) mark((s.port || []).map((p) => p.name), `port of switch ${s.name}`);
    for (const s of results(swIntf) || []) mark((s.member || []).map((m) => m['interface-name']), `member of switch ${s.name}`);
    for (const i of results(intf) || []) mark((i.member || []).map((m) => m['interface-name']), `member of ${i.name}`);

    const out = [{ name: 'any', kind: 'any' }];
    for (const z of sd?.zone || []) out.push({ name: z.name, kind: 'SD-WAN zone' });
    for (const z of results(zone) || []) out.push({ name: z.name, kind: 'zone' });
    const own = vdom || 'root';
    for (const i of results(intf) || []) {
      if (i.vdom && i.vdom !== own) continue;
      const blocked = memberOf.get(i.name);
      out.push({ name: i.name, kind: blocked || i.type || 'interface', blocked: !!blocked });
    }
    const seen = new Set();
    // Usable entries first, members at the end.
    return out.filter((o) => !seen.has(o.name) && seen.add(o.name)).sort((a, b) => a.blocked - b.blocked);
  };

  const explain = (message) =>
    /entry not found in datasource/i.test(message)
      ? `${message} — an interface isn't usable in policies here (e.g. member of SD-WAN, zone or switch)`
      : message;

  // New interface list for one side of a policy, or { error }.
  const compute = (current, { mode, chosen }) => {
    const picked = [...chosen];
    let next;
    if (mode === 'keep') return { list: current };
    if (!picked.length) return { list: current, error: 'no interfaces chosen' };
    if (mode === 'replace') next = picked;
    if (mode === 'add') next = current.includes('any') ? current : [...current, ...picked.filter((p) => !current.includes(p))];
    if (mode === 'remove') next = current.filter((c) => !chosen.has(c));
    if (next.includes('any') && next.length > 1) {
      return mode === 'add' ? { list: ['any'] } : { list: next, error: '"any" can\'t be combined with other interfaces' };
    }
    if (!next.length) return { list: next, error: 'would leave no interface' };
    return { list: next };
  };

  const sameList = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

  const openDialog = async () => {
    const table = FP.policyList.tableForPage();
    FP.toast('Reading policy list…', '', 0);
    const { ids, selected } = await FP.policyList.collectList();
    if (!ids.length) throw new Error('No policies in the current list.');
    const vdom = FP.getVdom();
    const path = apiPath(table);
    const [polRes, choices] = await Promise.all([
      FP.requestJson(path, { vdom, params: { format: 'policyid|name|srcintf|dstintf' } }),
      loadInterfaces(vdom),
    ]);
    const byId = new Map((polRes.results || []).map((p) => [String(p.policyid), p]));
    const policies = ids
      .filter((id) => byId.has(id))
      .map((id) => {
        const p = byId.get(id);
        return { id, name: p.name || '', srcintf: names(p.srcintf), dstintf: names(p.dstintf), checked: selected.includes(id), status: null };
      });
    FP.toast(`${policies.length} policies loaded`, 'ok', 1500);

    const { el } = FP;
    const state = Object.fromEntries(SIDES.map((s) => [s.key, { mode: 'keep', chosen: new Set() }]));
    let running = false;
    let changesMade = false;

    // --- Interface pickers ---
    const pickers = SIDES.map((side) => {
      const st = state[side.key];
      const mode = el('select');
      for (const [v, t] of MODES) mode.append(el('option', { value: v, textContent: t }));
      const search = el('input', { type: 'search', placeholder: 'Filter interfaces…' });
      const options = el('div', { className: 'options' });
      const chosenInfo = el('div', { className: 'chosen' });
      const picker = el('div', { className: 'picker off' }, [search, options, chosenInfo]);

      const labels = choices.map((c) => {
        const box = el('input', { type: 'checkbox', disabled: !!c.blocked });
        box.onchange = () => {
          box.checked ? st.chosen.add(c.name) : st.chosen.delete(c.name);
          update();
        };
        const label = el('label', {}, [box, el('span', { textContent: c.name }), el('span', { className: 'kind', textContent: c.kind })]);
        if (c.blocked) {
          label.classList.add('blocked');
          label.title = `Can't be used in policies: ${c.kind}`;
        }
        return { c, label };
      });
      options.append(...labels.map((l) => l.label));
      search.oninput = () => {
        const q = search.value.toLowerCase();
        for (const { c, label } of labels) label.style.display = c.name.toLowerCase().includes(q) ? '' : 'none';
      };
      mode.onchange = () => {
        st.mode = mode.value;
        picker.classList.toggle('off', st.mode === 'keep');
        update();
      };
      const refresh = () => {
        chosenInfo.textContent = st.chosen.size ? `Chosen: ${[...st.chosen].join(', ')}` : st.mode === 'keep' ? '' : 'Tick one or more interfaces.';
      };
      return { refresh, node: el('fieldset', {}, [el('legend', { textContent: side.label }), mode, picker]) };
    });

    // --- Policy table ---
    const allBox = el('input', { type: 'checkbox', title: 'Select all' });
    const tbody = el('tbody');
    const table_ = el('table', {}, [
      el('thead', {}, [el('tr', {}, [
        el('th', {}, [allBox]), el('th', { textContent: 'ID' }), el('th', { textContent: 'Name' }),
        el('th', { textContent: 'From' }), el('th', { textContent: 'To' }), el('th', { textContent: 'Status' }),
      ])]),
      tbody,
    ]);
    allBox.onchange = () => {
      for (const p of policies) p.checked = allBox.checked;
      update();
    };

    const planFor = (p) => {
      const plan = { changes: {}, errors: [] };
      for (const side of SIDES) {
        const r = compute(p[side.key], state[side.key]);
        if (r.error && state[side.key].mode !== 'keep') plan.errors.push(`${side.key}: ${r.error}`);
        else if (!sameList(r.list, p[side.key])) plan.changes[side.key] = r.list;
      }
      return plan;
    };

    const ifaceCell = (old, next) => {
      if (!next) return el('td', { textContent: old.join(', ') });
      return el('td', {}, [el('div', { className: 'old', textContent: old.join(', ') || '—' }), el('div', { className: 'new', textContent: next.join(', ') })]);
    };

    const applyBtn = el('button', { className: 'primary' });
    const update = () => {
      pickers.forEach((pk) => pk.refresh());
      tbody.replaceChildren();
      let count = 0;
      for (const p of policies) {
        const plan = planFor(p);
        const changed = Object.keys(plan.changes).length > 0;
        if (p.checked && changed && !plan.errors.length) count++;
        const box = el('input', { type: 'checkbox', checked: p.checked, disabled: running });
        box.onchange = () => {
          p.checked = box.checked;
          update();
        };
        let status = p.status;
        if (!status && p.checked) {
          status = plan.errors.length
            ? { cls: 'err', text: plan.errors.join('; ') }
            : { cls: 'muted', text: changed ? 'will change' : 'no change' };
        }
        tbody.append(el('tr', {}, [
          el('td', {}, [box]),
          el('td', { textContent: p.id }),
          el('td', { textContent: p.name }),
          ifaceCell(p.srcintf, p.checked ? plan.changes.srcintf : null),
          ifaceCell(p.dstintf, p.checked ? plan.changes.dstintf : null),
          el('td', { className: status?.cls || '', textContent: status?.text || '' }),
        ]));
      }
      allBox.checked = policies.every((p) => p.checked);
      applyBtn.textContent = `Apply to ${count} ${count === 1 ? 'policy' : 'policies'}`;
      applyBtn.disabled = running || count === 0;
    };

    applyBtn.onclick = async () => {
      const todo = policies.filter((p) => p.checked).map((p) => ({ p, plan: planFor(p) }))
        .filter(({ plan }) => Object.keys(plan.changes).length && !plan.errors.length);
      if (!todo.length || !confirm(`Change interfaces of ${todo.length} policies on the FortiGate?`)) return;
      running = true;
      let failed = 0;
      for (const { p, plan } of todo) {
        p.status = { cls: 'muted', text: 'saving…' };
        update();
        const body = Object.fromEntries(Object.entries(plan.changes).map(([k, list]) => [k, list.map((name) => ({ name }))]));
        try {
          await FP.request(`${path}/${p.id}`, { method: 'PUT', vdom, body });
          Object.assign(p, plan.changes);
          p.status = { cls: 'ok', text: 'updated ✓' };
        } catch (err) {
          failed++;
          p.status = { cls: 'err', text: explain(err.message) };
        }
      }
      running = false;
      for (const p of policies) if (p.status?.cls === 'ok') p.checked = false;
      update();
      FP.toast(`${todo.length - failed} updated${failed ? `, ${failed} failed` : ''}. Reload the page to see the changes in the list.`,
        failed ? 'error' : 'ok', 8000);
      changesMade = changesMade || todo.length > failed;
    };

    // --- Modal ---
    const r = FP.root();
    r.querySelector('.overlay')?.remove();
    const close = () => {
      if (running) return;
      overlay.remove();
      if (changesMade) location.reload();
    };
    const closeBtn = el('button', { textContent: 'Close' });
    closeBtn.onclick = close;
    const note = selected.length
      ? `${selected.length} of ${policies.length} policies were selected in the GUI and are ticked below.`
      : `No GUI selection detected. Tick the policies to change below (${policies.length} in the current list).`;
    const overlay = el('div', { className: 'overlay' }, [
      el('div', { className: 'modal wide' }, [
        el('header', { textContent: `Bulk edit interfaces — ${table}${vdom ? ` (VDOM ${vdom})` : ''}` }),
        el('div', { className: 'body' }, [
          el('div', { className: 'cols' }, pickers.map((pk) => pk.node)),
          el('p', { className: 'muted', textContent: note }),
          table_,
        ]),
        el('footer', {}, [applyBtn, closeBtn]),
      ]),
    ]);
    overlay.addEventListener('click', (e) => e.target === overlay && close());
    // Keep typing in the dialog away from the GUI's keyboard shortcuts.
    overlay.addEventListener('keydown', (e) => {
      e.stopPropagation();
      if (e.key === 'Escape') close();
    });
    r.appendChild(overlay);
    update();
  };

  FP.register({
    id: 'bulk-interfaces',
    label: 'Bulk edit source / destination interfaces',
    description: 'Replace, add or remove source and destination interfaces (multiple allowed) on several policies at once, with a preview before applying.',
    usage: 'Policy list → select policies, then FP button, right-click or Alt+Shift+I (ID column must be visible)',
    shortcut: { key: 'i', altKey: true, shiftKey: true },
    isAvailable,
    run: openDialog,
  });
})();
