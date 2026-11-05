'use strict';

// Preview and rename selected policies using their interfaces and service names.
(() => {
  const FP = window.FortiPlug;
  const TABLES = new Set(['firewall policy', 'firewall policy6', 'firewall proxy-policy']);
  const N = FP.policyNames;
  const names = (list) => (Array.isArray(list) ? list.map((item) => item.name).filter(Boolean) : []);

  const vipDescription = (vip) => {
    const external = String(vip.extip || '').trim();
    const port = (value) => value && String(value) !== '0' ? String(value) : '';
    const incoming = port(vip.extport);
    const virtualServer = vip.type === 'server-load-balance';
    const allPorts = virtualServer ? vip['server-type'] === 'ip' : vip.portforward !== 'enable';
    const mappings = virtualServer
      ? (vip.realservers || []).map((server) => ({ target: server.ip, port: port(server.port) }))
      : [{
        target: Array.isArray(vip.mappedip)
          ? vip.mappedip.map((ip) => ip.range || ip.name || ip.ip).filter(Boolean).join(', ')
          : vip.mappedip || vip['mapped-addr'],
        port: port(vip.mappedport),
      }];
    const errors = [];
    if (!external || !mappings.length || mappings.some((mapping) => !mapping.target || (!allPorts && (!incoming || !mapping.port)))) {
      errors.push(`VIP ${vip.name}: IP or port mapping is incomplete; edit the preview manually.`);
    }
    return {
      mappings: mappings.map((mapping) => ({ incoming: allPorts ? 'ALL' : incoming || '?', mapped: allPorts ? 'ALL' : mapping.port || '?', external: external || '?', target: String(mapping.target || '?') })),
      errors,
    };
  };

  const openDialog = async () => {
    const table = FP.policyList.tableForPage();
    const vdom = FP.getVdom();
    const path = `/api/v2/cmdb/${table.replace(' ', '/')}`;
    FP.toast('Reading policy list…', '', 0);
    const { ids, selected } = await FP.policyList.collectList();
    if (!ids.length) throw new Error('No policies in the current list.');
    const family = table === 'firewall policy6' ? '6' : '';
    const [response, vipResponse, groupResponse, savedLimit] = await Promise.all([
      FP.requestJson(path, { vdom, params: { format: 'policyid|name|srcintf|dstintf|srcaddr|srcaddr6|srcaddr-negate|dstaddr|dstaddr6|dstaddr-negate|service|action|internet-service-src-name|internet-service-src|internet-service-src-negate|internet-service-name|internet-service|internet-service-negate|utm-status|inspection-mode|ssl-ssh-profile|ips-sensor|webfilter-profile|application-list|comments' } }),
      FP.requestJson(`/api/v2/cmdb/firewall/vip${family}`, { vdom }),
      FP.requestJson(`/api/v2/cmdb/firewall/vipgrp${family}`, { vdom }),
      N.getLimit(),
    ]);
    const vips = new Map((vipResponse.results || []).map((vip) => [vip.name, vip]));
    const groups = new Map((groupResponse.results || []).map((group) => [group.name, group]));
    const describeDestination = (p) => {
      const seen = new Set();
      const mappings = new Map();
      const errors = [];
      const visit = (name) => {
        if (seen.has(name)) return;
        seen.add(name);
        if (vips.has(name)) {
          const description = vipDescription(vips.get(name));
          description.mappings.forEach((mapping) => mappings.set(N.vipLabel(mapping), mapping));
          errors.push(...description.errors);
        } else if (groups.has(name)) {
          names(groups.get(name).member).forEach(visit);
        }
      };
      [...names(p.dstaddr), ...names(p.dstaddr6)].forEach(visit);
      return { mappings: [...mappings.values()], errors };
    };
    const existing = response.results || [];
    const byId = new Map(existing.map((p) => [String(p.policyid), p]));
    const selectedIds = new Set(selected.map(String));
    const policies = ids.filter((id) => byId.has(String(id))).map((id) => ({
      ...byId.get(String(id)), id: String(id), checked: selectedIds.has(String(id)),
      vip: describeDestination(byId.get(String(id))),
      override: null, purposeOverride: null, originalName: byId.get(String(id)).name || '', status: null,
    }));
    if (!policies.length) throw new Error('Could not read the policies in the current list.');
    FP.toast(`${policies.length} policies loaded`, 'ok', 1500);

    const { el } = FP;
    let running = false;
    let changesMade = false;
    const software = el('input', { type: 'text', placeholder: 'Optional common software / purpose' });
    const placeholder = el('input', { type: 'text', value: 'VLXX' });
    const sourcePlaceholder = el('input', { type: 'text', placeholder: 'Source: use default' });
    const destinationPlaceholder = el('input', { type: 'text', placeholder: 'Destination: use default' });
    const aliases = el('textarea', { className: 'rename-aliases', value: 'x8=WAN\nVPN_EX-ADM*=VPN_ADM', spellcheck: false });
    const limit = el('input', { type: 'number', min: 20, max: 40, step: 1, value: String(savedLimit) });
    const reuse = el('input', { type: 'checkbox' });
    const infer = el('input', { type: 'checkbox', checked: true });
    const objectAliases = el('textarea', { className: 'rename-aliases', value: '', placeholder: 'mail.example.com=mail\nH_Server01=Server', spellcheck: false });
    const objectPrefixes = el('input', { type: 'text', value: 'H_, G_' });
    const shortFqdn = el('input', { type: 'checkbox', checked: true });
    for (const [control, label] of [[infer, 'Infer purpose from address objects'], [objectAliases, 'Object aliases'], [objectPrefixes, 'Object prefixes to remove'], [shortFqdn, 'Shorten FQDN object labels']]) control.setAttribute('aria-label', label);
    for (const [control, label] of [[software, 'Common software / purpose'], [placeholder, 'Default multiple-interface placeholder'], [sourcePlaceholder, 'Source multiple-interface placeholder'], [destinationPlaceholder, 'Destination multiple-interface placeholder'], [aliases, 'Interface aliases'], [limit, 'Policy name character limit'], [reuse, 'Reuse existing descriptions']]) control.setAttribute('aria-label', label);
    const limitValue = () => Number(limit.value);
    const parseAliases = () => N.parseAliases(aliases.value, 'Interface');
    const configError = () => !N.validLimit(limitValue()) ? 'Name limit must be a whole number from 20 to 40.'
      : parseAliases().error || N.parseAliases(objectAliases.value).error;
    const interfaceName = (list, side) => {
      const items = names(list);
      const { rules } = parseAliases();
      const translated = items.map((name) => N.aliasFor(name, rules) ?? name);
      if (new Set(translated).size === 1) return translated[0];
      const sidePlaceholder = side === 'srcintf' ? sourcePlaceholder : destinationPlaceholder;
      return items.length > 1 ? sidePlaceholder.value.trim() || placeholder.value.trim() : '';
    };
    const originalPurpose = (p) => N.extractPurpose(p.originalName, [
      `${interfaceName(p.srcintf, 'srcintf')}-${interfaceName(p.dstintf, 'dstintf')}`,
      `${names(p.srcintf).join(', ')}-${names(p.dstintf).join(', ')}`,
    ]);
    const purposeSuggestion = (p) => {
      if (p.purposeOverride !== null) return { value: p.purposeOverride, reason: p.purposeOverride ? 'Manual purpose' : 'Purpose cleared manually', objects: [] };
      if (software.value.trim()) return { value: software.value.trim(), reason: 'Common software / purpose', objects: [] };
      if (reuse.checked && originalPurpose(p)) return { value: originalPurpose(p), reason: 'Existing description', objects: [] };
      if (infer.checked) {
        const sourceIsdb = p['internet-service-src'] === 'enable';
        const destinationIsdb = p['internet-service'] === 'enable';
        const suggestion = N.inferPurpose({
          sources: sourceIsdb ? names(p['internet-service-src-name']) : [...names(p.srcaddr), ...names(p.srcaddr6)],
          destinations: destinationIsdb ? names(p['internet-service-name']) : [...names(p.dstaddr), ...names(p.dstaddr6)],
          sourceInterface: interfaceName(p.srcintf, 'srcintf'),
          destinationInterface: interfaceName(p.dstintf, 'dstintf'),
          sourceNegated: p[sourceIsdb ? 'internet-service-src-negate' : 'srcaddr-negate'] === 'enable',
          destinationNegated: p[destinationIsdb ? 'internet-service-negate' : 'dstaddr-negate'] === 'enable',
        }, { rules: N.parseAliases(objectAliases.value).rules, prefixes: objectPrefixes.value.split(',').map((prefix) => prefix.trim()).filter(Boolean), shortFqdn: shortFqdn.checked });
        if (suggestion.value) return { ...suggestion, reason: `Purpose inferred from ${suggestion.origin}` };
      }
      return { value: '', reason: infer.checked ? 'No specific source or destination; enter the purpose manually.' : 'Address-based purpose disabled; enter the purpose manually.', objects: [] };
    };
    const purposeFor = (p) => purposeSuggestion(p).value;
    const formatted = (p, suffix = '') => N.format({
      route: `${interfaceName(p.srcintf, 'srcintf')}-${interfaceName(p.dstintf, 'dstintf')}`,
      purpose: purposeFor(p), services: names(p.service),
      mappings: p.vip.mappings.map((mapping) => ({ ...mapping, targetLabel: N.aliasFor(mapping.target, N.parseAliases(objectAliases.value).rules) ?? mapping.target })),
      deny: p.action === 'deny',
    }, N.validLimit(limitValue()) ? limitValue() : savedLimit, suffix);
    const proposed = (p) => p.override ?? formatted(p).name;
    const validation = (p, name, owners) => {
      if (!name.trim()) return 'Name must not be empty.';
      if (N.length(name) > limitValue()) return p.override !== null
        ? `Name exceeds ${limitValue()} characters. Shorten the manual name or choose a larger limit.`
        : `Name exceeds ${limitValue()} characters. The complete interface pair is required for generated names: use shorter interface aliases or a larger limit, or edit the name manually.`;
      if (/[\x00-\x1f\x7f"<>]/.test(name)) return 'Name contains unsupported characters.';
      if (p.override === null) {
        const pair = `${interfaceName(p.srcintf, 'srcintf')}-${interfaceName(p.dstintf, 'dstintf')}`;
        if (name !== pair && !name.startsWith(`${pair}_`) && !name.startsWith(`${pair} (`)) return `The complete interface pair ${pair} is required at the start of generated names.`;
        if (!names(p.srcintf).length || !names(p.dstintf).length) return 'Source or destination interface is missing.';
        if (p.vip.errors.length) return p.vip.errors.join('; ');
        if (!p.vip.mappings.length && !names(p.service).length) return 'No services found.';
        if (!interfaceName(p.srcintf, 'srcintf') || !interfaceName(p.dstintf, 'dstintf')) {
          return 'Enter a placeholder for multiple interfaces.';
        }
      }
      // Reserve current names too: sequential saves cannot safely swap names.
      if ([...(owners.get(name) || [])].some((id) => id !== p.id)) return 'Name is already used by another policy.';
      return '';
    };
    const plans = () => {
      const owners = new Map();
      const reserve = (name, id, into = owners) => {
        if (!name) return;
        if (!into.has(name)) into.set(name, new Set());
        into.get(name).add(id);
      };
      for (const p of existing) reserve(p.name, String(p.policyid));
      // Reserve all base suggestions first so colliding generated names each get
      // their own policy ID, independent of their order in the GUI.
      for (const p of policies) if (p.checked) reserve(proposed(p), p.id);
      const allocated = new Map();
      const formats = new Map();
      for (const p of policies.filter((p) => p.checked)) {
        const base = proposed(p);
        let name = base;
        let result = formatted(p);
        if (p.override === null && [...(owners.get(name) || [])].some((id) => id !== p.id)) {
          let attempt = 1;
          do {
            const suffix = `_ID${p.id}${attempt > 1 ? `_${attempt}` : ''}`;
            result = formatted(p, suffix);
            name = result.name;
            attempt++;
          } while ([...(owners.get(name) || [])].some((id) => id !== p.id));
        }
        allocated.set(p.id, name);
        formats.set(p.id, result);
        reserve(name, p.id);
      }
      const finalOwners = new Map();
      for (const p of existing) reserve(p.name, String(p.policyid), finalOwners);
      for (const [id, name] of allocated) reserve(name, id, finalOwners);
      return policies.map((p) => {
        const name = allocated.get(p.id) ?? proposed(p);
        const suffixed = name !== proposed(p);
        return { p, name, suffixed, format: formats.get(p.id) || formatted(p), error: validation(p, name, finalOwners), changed: name !== (p.name || '') };
      });
    };

    const allBox = el('input', { type: 'checkbox', title: 'Select all' });
    const tbody = el('tbody');
    const preview = el('table', { className: 'rename-preview' }, [
      el('thead', {}, [el('tr', {}, [
        el('th', {}, [allBox]), ...['ID', 'Current name / purpose', 'New name (editable)', 'Policy details', 'Status'].map((textContent) => el('th', { textContent })),
      ])]), tbody,
    ]);
    const summary = el('p', { className: 'muted' });
    const applyBtn = el('button', { className: 'primary' });
    const resetBtn = el('button', { textContent: 'Regenerate names' });
    const rows = policies.map((p) => {
      const box = el('input', { type: 'checkbox', checked: p.checked });
      const input = el('input', { type: 'text' });
      input.placeholder = 'New name — manual overrides allowed';
      input.setAttribute('aria-label', `New name for policy ${p.id}`);
      const oldName = el('div', { textContent: p.name || '—' });
      const purpose = el('input', { type: 'text' });
      purpose.setAttribute('aria-label', `Software / purpose for policy ${p.id}`);
      const suggestion = el('div', { className: 'muted' });
      purpose.oninput = () => { p.purposeOverride = purpose.value; p.override = null; p.status = null; update(); };
      const length = el('div', { className: 'muted' });
      const status = el('td');
      const details = el('details', {}, [
        el('summary', { textContent: `${p.action || 'unknown action'} · ${names(p.srcintf).join(', ')} → ${names(p.dstintf).join(', ')}` }),
        ...[
          ['Sources', [...names(p.srcaddr), ...names(p.srcaddr6)].join(', ')],
          ['Source ISDB', names(p['internet-service-src-name']).join(', ')],
          ['Destinations', [...names(p.dstaddr), ...names(p.dstaddr6)].join(', ')],
          ['Destination ISDB', names(p['internet-service-name']).join(', ')],
          ['Services', names(p.service).join(', ')],
          ...['srcaddr-negate', 'dstaddr-negate', 'internet-service-src-negate', 'internet-service-negate'].filter((key) => p[key] === 'enable').map((key) => [key, p[key]]),
          ['VIP mappings (external port → mapped port → WAN IP → target)', p.vip.mappings.map(N.vipLabel).join('\n')],
          ...['utm-status', 'inspection-mode', 'ssl-ssh-profile', 'ips-sensor', 'webfilter-profile', 'application-list', 'comments'].map((key) => [key, p[key]]),
        ].filter(([, value]) => value).map(([label, value]) => el('div', { className: 'policy-detail', textContent: `${label}: ${value}` })),
      ]);
      box.onchange = () => { p.checked = box.checked; p.status = null; update(); };
      input.oninput = () => { p.override = input.value; p.status = null; update(); };
      tbody.append(el('tr', {}, [
        el('td', {}, [box]), el('td', { textContent: p.id }), el('td', {}, [oldName, el('label', {}, [el('span', { textContent: 'Software / purpose' }), purpose]), suggestion]),
        el('td', {}, [input, length]), el('td', {}, [details]), status,
      ]));
      return { box, input, purpose, suggestion, oldName, length, status };
    });

    const update = () => {
      const current = plans();
      let count = 0;
      let errors = 0;
      const settingsError = configError();
      current.forEach(({ p, name, suffixed, format, error, changed }, index) => {
        const row = rows[index];
        row.oldName.textContent = p.name || '—';
        const suggestion = purposeSuggestion(p);
        row.suggestion.textContent = suggestion.reason;
        row.suggestion.title = suggestion.objects.join('\n');
        if (p.checked && changed && !error) count++;
        if (p.checked && error) errors++;
        row.box.checked = p.checked;
        row.box.disabled = running;
        row.input.disabled = running || !p.checked;
        row.purpose.disabled = running || !p.checked;
        if (row.purpose.value !== purposeFor(p)) row.purpose.value = purposeFor(p);
        if (row.input.value !== name) row.input.value = name;
        row.input.title = format.full;
        row.length.textContent = `${N.length(name)}/${limit.value}${p.override !== null ? ' — fixed name' : format.shortened ? ' — automatically shortened' : ''}${p.override === null && format.omitted ? ` — ${format.omitted} entries omitted (+${format.omitted})` : ''}${suffixed ? ' — policy ID added' : ''}`;
        row.status.className = p.status?.cls || (p.checked && error ? 'err' : 'muted');
        row.status.textContent = p.status?.text || (p.checked ? error || (changed ? 'will rename' : 'no change') : '');
      });
      allBox.disabled = running;
      allBox.checked = policies.every((p) => p.checked);
      allBox.indeterminate = policies.some((p) => p.checked) && !allBox.checked;
      for (const control of [software, placeholder, sourcePlaceholder, destinationPlaceholder, aliases, limit, reuse, infer, objectAliases, objectPrefixes, shortFqdn, resetBtn]) control.disabled = running;
      applyBtn.textContent = `Rename ${count} ${count === 1 ? 'policy' : 'policies'}`;
      applyBtn.disabled = running || !count || !!errors || !!settingsError;
      summary.className = errors || settingsError ? 'err' : 'muted';
      summary.textContent = settingsError || (errors ? `Resolve the errors in ${errors} selected policies before applying.` : `${count} policies ready to rename.`);
    };
    allBox.onchange = () => {
      for (const p of policies) { p.checked = allBox.checked; p.status = null; }
      update();
    };
    const refreshConfig = () => {
      for (const p of policies) p.status = null;
      update();
    };
    for (const control of [software, placeholder, sourcePlaceholder, destinationPlaceholder, aliases, limit, objectAliases, objectPrefixes]) control.oninput = refreshConfig;
    for (const control of [reuse, infer, shortFqdn]) control.onchange = refreshConfig;
    limit.onchange = async () => {
      update();
      if (!N.validLimit(limitValue())) return;
      try { await N.setLimit(limitValue()); }
      catch (err) { FP.toast(`Could not save the shared name limit: ${err.message}`, 'error'); }
    };
    resetBtn.onclick = () => {
      for (const p of policies) { p.override = null; p.purposeOverride = null; p.status = null; }
      update();
    };
    applyBtn.onclick = async () => {
      if (running) return;
      if (configError()) return;
      const selectedPlans = plans().filter(({ p }) => p.checked);
      if (selectedPlans.some(({ error }) => error)) return;
      const todo = selectedPlans.filter(({ changed }) => changed);
      if (!todo.length || !confirm(`Rename ${todo.length} policies on the FortiGate using the previewed names?`)) return;
      // Keep every confirmed name stable as earlier policies finish saving.
      for (const { p, name } of todo) p.override = name;
      running = true;
      let failed = 0;
      update();
      try {
        await N.setLimit(limitValue());
        for (const { p, name } of todo) {
          p.status = { cls: 'muted', text: 'saving…' };
          update();
          try {
            await FP.request(`${path}/${p.id}`, { method: 'PUT', vdom, body: { name } });
            p.name = name;
            p.override = name;
            byId.get(p.id).name = name;
            p.checked = false;
            p.status = { cls: 'ok', text: 'renamed ✓' };
            changesMade = true;
          } catch (err) {
            failed++;
            p.status = { cls: 'err', text: err.message };
          }
          update();
        }
      } catch (err) {
        FP.toast(`Could not save the shared name limit: ${err.message}`, 'error');
        return;
      } finally {
        running = false;
        update();
      }
      FP.toast(`${todo.length - failed} renamed${failed ? `, ${failed} failed` : ''}. Close the dialog to reload the list.`, failed ? 'error' : 'ok', 8000);
    };

    const root = FP.root();
    root.querySelector('.overlay')?.remove();
    const close = () => {
      if (running) return;
      overlay.remove();
      if (changesMade) location.reload();
    };
    const closeBtn = el('button', { textContent: 'Close', onclick: close });
    const overlay = el('div', { className: 'overlay' }, [
      el('div', { className: 'modal wide' }, [
        el('header', { textContent: `Bulk rename policies — ${table}${vdom ? ` (VDOM ${vdom})` : ''}` }),
        el('div', { className: 'body' }, [
          el('div', { className: 'cols' }, [
            el('fieldset', {}, [el('legend', { textContent: 'Software / purpose' }), software,
              el('label', { className: 'rename-option' }, [reuse, el('span', { textContent: 'Reuse existing descriptions when available' })]),
              el('label', { className: 'rename-option' }, [infer, el('span', { textContent: 'Infer an empty purpose from address objects' })]),
              el('p', { className: 'muted', textContent: 'Priority: individual purpose, common software, reused description, destination, then source. A short single source can be combined with a short destination. Clearing a purpose keeps it empty until Regenerate names.' })]),
            el('fieldset', {}, [el('legend', { textContent: 'Multiple interfaces' }), placeholder,
              el('label', {}, [el('span', { textContent: 'Source override' }), sourcePlaceholder]),
              el('label', {}, [el('span', { textContent: 'Destination override' }), destinationPlaceholder])]),
            el('fieldset', {}, [el('legend', { textContent: 'Interface aliases / groups' }), aliases,
              el('p', { className: 'muted', textContent: 'One name=alias per line; a trailing * matches an interface group. Interfaces mapping to the same alias use that alias instead of VLXX. Add aliases for opaque interface names such as a once their role is known.' })]),
            el('fieldset', {}, [el('legend', { textContent: 'Address object labels' }), objectAliases,
              el('label', {}, [el('span', { textContent: 'Object prefixes to remove (comma separated)' }), objectPrefixes]),
              el('label', { className: 'rename-option' }, [shortFqdn, el('span', { textContent: 'Shorten FQDN object names to the first hostname label' })]),
              el('p', { className: 'muted', textContent: 'Exact aliases take precedence over wildcard aliases and automatic cleanup. Two short names use A+B, larger sets use +N. For short VIP names, target IP aliases such as 192.168.1.192=DNS01 produce VIP_DNS01_5353. Full object names remain in Policy details. Services are taken from the policy, including ALL.' })]),
            el('fieldset', {}, [el('legend', { textContent: 'Shared name limit' }), limit,
              el('p', { className: 'muted', textContent: '20–40 characters, default 40. Saved across dialogs and shared with copy/paste. Use 35 when required by your FortiGate.' })]),
          ]),
          el('p', { className: 'muted', textContent: 'SRC-DST[_Purpose] (Services), or (VIP_externalPort-mappedPort-WANIP-target). Generated names keep the complete interface pair; manual name edits may override it. Long VIP names prefer VIP_target_mappedPort, using a target IP alias when configured. Deny rules include DENY. Services are shortened before the software / purpose. Shortening uses a single dot (.) and +N for omitted entries, preserving closing parentheses and _ID suffixes. Full IPs keep their normal dots. Hover for the full suggestion; expand policy details for sources, security profiles and every VIP mapping.' }),
          el('p', { className: 'muted', textContent: selected.length ? `${policies.filter((p) => p.checked).length} policies selected from the GUI.` : 'No GUI selection detected. Tick the policies to rename below.' }),
          preview, summary,
        ]),
        el('footer', {}, [resetBtn, applyBtn, closeBtn]),
      ]),
    ]);
    overlay.addEventListener('click', (event) => event.target === overlay && close());
    overlay.addEventListener('keydown', (event) => {
      event.stopPropagation();
      if (event.key === 'Escape') close();
    });
    root.append(overlay);
    update();
  };

  FP.register({
    id: 'bulk-rename',
    label: 'Bulk rename policies',
    description: 'Rename selected policies using interface aliases, software or purposes inferred from address objects, and services or VIP mappings. Editable preview with suggestion origins, automatic policy IDs for duplicates and shortening to 40 characters.',
    usage: 'Policy list → select policies, then FP button or right-click (ID column must be visible)',
    isAvailable: () => TABLES.has(FP.policyList.tableForPage()),
    run: openDialog,
  });
})();
