'use strict';

(() => {
  const FP = window.FortiPlug;
  const SCANNER = 'G_SecurityScanner';
  const BLOCKLIST = 'eworx-IP-Blocklist';
  const THREAT_FAMILIES = ['botnet', 'hosting', 'malicious', 'phishing', 'proxy', 'tor', 'vpn'];
  const threatFamily = (name) => name.toLowerCase().split('-')[0].replace(/^phising$/, 'phishing');
  const isScanner = (name) => /-scanner(?:$|[.-])/i.test(name);
  const names = (refs = []) => (Array.isArray(refs) ? refs : [refs])
    .map((ref) => typeof ref === 'string' ? ref : ref?.name ?? ref?.['interface-name'] ?? ref?.q_origin_key)
    .filter((name) => typeof name === 'string' && name);
  const enabled = (entry) => entry.status !== 'disable';
  const covers = (refs, name) => refs.includes('any') || refs.includes(name);
  const overlaps = (refs, name) => name === 'any' ? refs.length > 0 : covers(refs, name);
  const includesBuiltin = (refs, name) => refs.some((ref) => ref.toLowerCase() === name);
  const isDefaultRoute = (prefix) => /^(0\.0\.0\.0(?:\/0|\/0\.0\.0\.0| 0\.0\.0\.0))$/.test(prefix);

  function defaultMatchVip(version) {
    const [, major, minor, patch] = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version || '') || [];
    return Number(major) > 7 || (Number(major) === 7 &&
      (Number(minor) > 2 || (Number(minor) === 2 && Number(patch) >= 4)));
  }

  function ingressInterfaces({ interfaces, zones, sdwan, staticRoutes, activeRoutes }) {
    const policyInterface = new Map();
    const wan = new Set(interfaces.filter((intf) => intf.role === 'wan').map((intf) => intf.name));
    for (const zone of zones) {
      for (const member of names(zone.interface)) policyInterface.set(member, zone.name);
    }
    if (sdwan?.status === 'enable') {
      for (const member of (sdwan.members || []).filter(enabled)) {
        const zone = member.zone || 'virtual-wan-link';
        policyInterface.set(member.interface, zone);
        wan.add(zone);
      }
    }
    for (const route of staticRoutes.filter(enabled)) {
      if (route.blackhole === 'enable' || names(route.dstaddr).length || route['internet-service'] === 'enable' ||
        names(route['internet-service-name']).length || !isDefaultRoute(route.dst ?? '0.0.0.0 0.0.0.0')) continue;
      for (const intf of [...names(route.device), ...names(route['sdwan-zone'])]) wan.add(intf);
    }
    for (const route of activeRoutes) {
      if (!isDefaultRoute(route.ip_mask ?? route.dst)) continue;
      for (const intf of names(route.interface)) wan.add(intf);
    }
    return {
      wan: [...new Set([...wan].map((intf) => policyInterface.get(intf) || intf))].filter(Boolean).sort(),
      normalize: (intf) => policyInterface.get(intf) || intf,
    };
  }

  function policyChanges(data) {
    const { policies, vips, vipGroups, inventory, groupMembers, isdb, isdbGroups } = data;
    const { wan, normalize } = ingressInterfaces(data);
    const vipNames = new Set(vips.map((vip) => vip.name));
    const groups = new Map(vipGroups.map((group) => [group.name, names(group.member)]));
    const expandVips = (destinations) => new Set(destinations.flatMap((name) => groups.get(name) || name)
      .filter((name) => vipNames.has(name)));
    const expandGroup = (name, ancestors = new Set()) => {
      if (ancestors.has(name)) return [];
      const group = groupMembers.get(name);
      if (!group || group.exclude === 'enable') return [name];
      return [name, ...names(group.member).flatMap((member) => expandGroup(member, new Set([...ancestors, name])))];
    };
    const byId = new Map(isdb.map((entry) => [String(entry['internet-service-id'] ?? entry.id), entry.name]));
    const byGroup = new Map(isdbGroups.map((entry) => [entry.name, names(entry.member)]));
    const catalog = new Set(isdb.filter((entry) => entry.direction !== 'destination')
      .map((entry) => entry.name).filter(Boolean));
    const threatNames = THREAT_FAMILIES.map((family) => [...catalog].filter((name) => threatFamily(name) === family));
    const scannerNames = [...catalog].filter(isScanner);
    const missingFamilies = THREAT_FAMILIES.filter((_, index) => !threatNames[index].length);
    const isThreat = (name) => THREAT_FAMILIES.includes(threatFamily(name));
    const matchVipByDefault = defaultMatchVip(data.policyVersion);

    const rules = policies.map((p, index) => {
      const src = names(p.srcaddr);
      const dst = names(p.dstaddr);
      const srcIsdb = p['internet-service-src'] === 'enable';
      const dstIsdb = p['internet-service'] === 'enable';
      const named = names(p['internet-service-src-name']);
      const ids = (p['internet-service-src-id'] || []).map((ref) => String(ref.id ?? ref));
      const allDestinations = !dstIsdb && includesBuiltin(dst, 'all') && p['dstaddr-negate'] !== 'enable';
      const matchesVip = p['match-vip-only'] === 'enable' || p['match-vip'] === 'enable' ||
        (p.action === 'deny' && p['match-vip'] == null && matchVipByDefault);
      return {
        id: Number(p.policyid), index, srcIsdb, action: p.action, enabled: enabled(p),
        ingress: names(p.srcintf), egress: names(p.dstintf),
        vips: dstIsdb || p['dstaddr-negate'] === 'enable' ? new Set() : expandVips(dst),
        allVips: allDestinations && matchesVip,
        allDestinations,
        always: p.schedule === 'always' && includesBuiltin(names(p.service), 'all') &&
          p['service-negate'] !== 'enable' &&
          p[srcIsdb ? 'internet-service-src-negate' : 'srcaddr-negate'] !== 'enable' &&
          !p.users?.length && !p.groups?.length && !p['fsso-groups']?.length &&
          !p['src-vendor-mac']?.length && p['vlan-filter'] !== 'enable',
        allowScanner: p.action === 'accept' && !srcIsdb && src.length === 1 && src[0] === SCANNER &&
          p['srcaddr-negate'] !== 'enable',
        isdbNames: new Set([...named, ...ids.map((id) => byId.get(id)),
          ...names(p['internet-service-src-group']).flatMap((name) => byGroup.get(name) || [])].filter(Boolean)),
        blocklist: !srcIsdb && src.some((name) => expandGroup(name).includes(BLOCKLIST)),
      };
    });

    // Derive each egress from an enabled publishing policy. A VIP's extintf alone
    // says where traffic arrives, and does not identify the translated host's egress.
    const paths = new Map();
    const unresolved = [];
    const published = new Set();
    for (const vip of vips.filter(enabled)) {
      const bindings = names(vip.extintf).filter((name) => name !== 'any').map(normalize);
      const filters = names(vip['srcintf-filter']).filter((name) => name !== 'any').map(normalize);
      const candidates = wan.filter((name) =>
        (!bindings.length || bindings.includes(name)) && (!filters.length || filters.includes(name)));
      let found = false;
      for (const rule of rules) {
        if (!rule.enabled || rule.action !== 'accept' || !rule.vips.has(vip.name)) continue;
        for (const ingress of candidates.filter((name) => covers(rule.ingress, name))) {
          for (const egress of rule.egress) {
            const key = JSON.stringify([ingress, egress, vip.name]);
            paths.set(key, { ingress, egress, vip: vip.name });
            if (!rule.allowScanner) published.add(key);
            found = true;
          }
        }
      }
      if ((!bindings.length || candidates.length || !wan.length) && !found) unresolved.push(vip.name);
    }

    const notes = [];
    const details = [];
    const planned = new Map();
    if (!wan.length && vips.some(enabled)) notes.push('No WAN policy interface was found. Check WAN roles, SD-WAN, and default routes.');
    if (unresolved.length) {
      details.push('VIPs without a verified inbound policy path', ...unresolved.map((name) => '  ' + name), '');
    }
    if (missingFamilies.length) notes.push('ISDB categories unavailable on this firewall: ' + missingFamilies.join(', ') + '.');
    if (!scannerNames.length) notes.push('No scanner entries were found in the firewall’s ISDB catalog.');

    function plan(kind, path, anchor, sources) {
      const key = JSON.stringify([kind, path.ingress, path.egress, anchor, sources]);
      if (!planned.has(key)) planned.set(key, { kind, ingress: path.ingress, egress: path.egress, anchor, sources, vips: [] });
      planned.get(key).vips.push(path.vip);
    }

    const checks = [...paths].map(([key, path]) => {
      const scoped = rules.filter((rule) =>
        covers(rule.ingress, path.ingress) && overlaps(rule.egress, path.egress));
      const firstAccept = scoped.find((rule) => rule.enabled && rule.action === 'accept' && !rule.allowScanner &&
        (rule.vips.has(path.vip) || rule.allVips));
      const eligible = scoped.filter((rule) => rule.action === 'deny' && rule.always &&
        covers(rule.egress, path.egress) && (!firstAccept || rule.index < firstAccept.index));
      return { key, path, scoped, firstAccept, eligible };
    });
    const repairs = new Map();
    const wildcardCoverage = (rule) => rule.allVips || repairs.get(rule.id)?.enableMatchVip;
    const coverage = (rule, vip) => (rule.enabled || repairs.has(rule.id)) &&
      (rule.vips.has(vip) || wildcardCoverage(rule));
    const planRepair = (rule) => repairs.set(rule.id, {
      id: rule.id,
      enableStatus: !rule.enabled,
      enableMatchVip: rule.allDestinations && !rule.allVips,
    });
    const isdbBaselines = [[threatNames.flat(), isThreat], [scannerNames, isScanner]];
    // Select existing denies first, then evaluate each scanner exception against
    // the resulting policy order, including repairs selected for other VIPs.
    for (const { path, eligible } of checks) {
      const effective = eligible.filter((rule) => coverage(rule, path.vip));
      const candidates = eligible
        .filter((rule) => (rule.allDestinations || rule.vips.has(path.vip)) && !coverage(rule, path.vip))
        .sort((a, b) => Number(b.enabled) - Number(a.enabled));
      if (!effective.some((rule) => rule.blocklist)) {
        const blocklistDeny = candidates.find((rule) => rule.blocklist);
        if (blocklistDeny) planRepair(blocklistDeny);
      }
      for (const [entries, matchesSource] of isdbBaselines) {
        const activeIsdb = eligible.filter((rule) => rule.srcIsdb && coverage(rule, path.vip));
        const hasWildcard = activeIsdb.some((rule) => wildcardCoverage(rule) &&
          [...rule.isdbNames].some(matchesSource));
        if (hasWildcard) continue;
        const uncovered = new Set(entries.filter((name) => !activeIsdb.some((rule) => rule.isdbNames.has(name))));
        for (const rule of candidates) {
          if (!rule.srcIsdb || ![...rule.isdbNames].some((name) => uncovered.has(name))) continue;
          planRepair(rule);
          if (wildcardCoverage(rule)) break;
          for (const name of rule.isdbNames) uncovered.delete(name);
        }
      }
    }
    for (const { id, enableStatus, enableMatchVip } of repairs.values()) {
      const actions = [enableStatus && 're-enable deny', enableMatchVip && 'enable match-vip'].filter(Boolean);
      details.push('Policy #' + id + ' — ' + actions.join(' and ') + '.');
    }
    if (repairs.size) details.push('');

    for (const { key, path, scoped, firstAccept, eligible } of checks) {
      const relevant = scoped.filter((rule) => coverage(rule, path.vip));
      const denies = relevant.filter((rule) => rule.action === 'deny');
      const effective = eligible.filter((rule) => coverage(rule, path.vip));
      const missing = [];
      if (!effective.some((rule) => rule.blocklist)) missing.push(['Blocklist', [BLOCKLIST], inventory.has(BLOCKLIST)]);
      const coveredIsdb = new Set(effective.filter((rule) => rule.srcIsdb).flatMap((rule) => [...rule.isdbNames]));
      const threats = threatNames.flat().filter((name) => !coveredIsdb.has(name)).sort();
      const scanners = scannerNames.filter((name) => !coveredIsdb.has(name)).sort();
      const catalogReview = [];
      for (const [kind, entries, matchesSource] of [
        ['Threats', threats, isThreat],
        ['Scanners', scanners, isScanner],
      ]) {
        if (!entries.length) continue;
        const existing = effective.filter((rule) => wildcardCoverage(rule) && rule.srcIsdb &&
          [...rule.isdbNames].some(matchesSource));
        if (existing.length) {
          catalogReview.push('  ' + kind + ' — existing deny ' + existing.map((rule) => '#' + rule.id).join(', ') +
            ' omits these ISDB entries: ' + entries.join(', '));
        } else {
          missing.push([kind, entries, true]);
        }
      }

      // A new deny before the first publishing accept can also precede an existing
      // scanner exception. Check allow order against both existing and planned denies.
      const denyAnchor = firstAccept?.id;
      const allowAnchor = [denies[0], missing.some(([, , available]) => available) && firstAccept]
        .filter(Boolean).sort((a, b) => a.index - b.index)[0];
      const scannerAllowed = relevant.some((rule) => rule.allowScanner && rule.always &&
        rule.vips.has(path.vip) && covers(rule.egress, path.egress) &&
        (!allowAnchor || rule.index < allowAnchor.index));
      if (!scannerAllowed) missing.unshift(['Allow scanner', [SCANNER], inventory.has(SCANNER) && published.has(key)]);

      if (!missing.length && !catalogReview.length) continue;
      details.push(path.ingress + ' → ' + path.egress + ' / ' + path.vip);
      for (const [kind, sources, available] of missing) {
        details.push('  ' + kind + ' — ' + sources.join(', ') + (available ? '' : ' (requires review)'));
        if (available) plan(kind, path, kind === 'Allow scanner' ? allowAnchor?.id : denyAnchor, sources);
      }
      details.push(...catalogReview);
      details.push('');
    }

    for (const name of [BLOCKLIST, SCANNER]) {
      if (paths.size && !inventory.has(name)) notes.push('Required source object unavailable: ' + name + '.');
    }
    return { changes: [...planned.values()], repairs, details, notes, pathCount: paths.size, unresolvedCount: unresolved.length };
  }

  const quote = (value) => '"' + String(value).replace(/[\\"]/g, '\\$&') + '"';
  const cliList = (values) => values.map(quote).join(' ');

  function renderCli({ changes, repairs }, policies) {
    if (!changes.length && !repairs.size) return '';
    const ids = new Set(policies.map((policy) => Number(policy.policyid)));
    const existingNames = new Set(policies.map((policy) => policy.name));
    const lines = ['config firewall policy'];
    const moves = [];
    let id = 1;
    // When an allow and a deny share an anchor, moving the allow first keeps it above the deny.
    const ordered = [...changes].sort((a, b) => Number(b.kind === 'Allow scanner') - Number(a.kind === 'Allow scanner'));
    for (const rule of ordered) {
      const allow = rule.kind === 'Allow scanner';
      const isdb = rule.kind === 'Threats' || rule.kind === 'Scanners';
      const stem = 'FP-Inbound-' + rule.kind.replace(' ', '-') + '-';
      while (ids.has(id) || existingNames.has(stem + id)) id++;
      lines.push(
        '    edit ' + id,
        '        set name ' + quote(stem + id),
        '        set srcintf ' + quote(rule.ingress),
        '        set dstintf ' + quote(rule.egress),
        '        set action ' + (allow ? 'accept' : 'deny'),
        ...(isdb ? ['        set internet-service-src enable',
          '        set internet-service-src-name ' + cliList(rule.sources)] :
          ['        set srcaddr ' + cliList(rule.sources)]),
        '        set dstaddr ' + cliList(rule.vips),
        '        set schedule "always"',
        '        set service "ALL"',
        allow ? '        set nat disable' : '        set match-vip enable',
        '        set logtraffic all',
        '    next',
      );
      if (rule.anchor !== undefined) moves.push('    move ' + id + ' before ' + rule.anchor);
      id++;
    }
    lines.push(...moves);
    for (const { id, enableStatus, enableMatchVip } of repairs.values()) {
      lines.push('    edit ' + id);
      if (enableMatchVip) lines.push('        set match-vip enable');
      if (enableStatus) lines.push('        set status enable');
      lines.push('    next');
    }
    return [...lines, 'end', ''].join('\n');
  }

  async function readTable(path, vdom, singleton = false) {
    const results = [];
    let start = 0;
    while (true) {
      const response = await FP.requestJson('/api/v2/' + path, { vdom, params: start ? { start } : {} });
      const data = response.results;
      if (response.status !== 'success' || (singleton ? !data || typeof data !== 'object' : !Array.isArray(data))) {
        throw new Error('Unexpected response from ' + path);
      }
      if (singleton) return { data: Array.isArray(data) ? data[0] || {} : data };
      results.push(...data);
      if (!response.limit_reached && !(Number(response.matched_count) > results.length)) {
        return { data: results, version: response.version };
      }
      const next = Number(response.next_idx);
      if (!data.length || !Number.isSafeInteger(next) || next <= start) {
        throw new Error('Incomplete response from ' + path);
      }
      start = next;
    }
  }

  async function run() {
    const vdom = FP.getVdom();
    const title = 'Inbound VIP policy check · ' + (vdom || 'root');
    FP.toast('Checking inbound VIP policies…');
    const requests = [
      ['policies', 'cmdb/firewall/policy'],
      ['vips', 'cmdb/firewall/vip'],
      ['vipGroups', 'cmdb/firewall/vipgrp'],
      ['settings', 'cmdb/system/settings', true],
      ['interfaces', 'cmdb/system/interface'],
      ['zones', 'cmdb/system/zone'],
      ['sdwan', 'cmdb/system/sdwan', true],
      ['staticRoutes', 'cmdb/router/static'],
      ['activeRoutes', 'monitor/router/ipv4'],
      ['addresses', 'cmdb/firewall/address'],
      ['addressGroups', 'cmdb/firewall/addrgrp'],
      ['feeds', 'cmdb/system/external-resource'],
      ['isdb', 'cmdb/firewall/internet-service-name'],
      ['isdbGroups', 'cmdb/firewall/internet-service-group'],
    ];
    const responses = await Promise.allSettled(requests.map(([, path, singleton]) => readTable(path, vdom, singleton)));
    const data = {};
    const failures = new Map();
    for (const [index, [key, path]] of requests.entries()) {
      const response = responses[index];
      data[key] = response.status === 'fulfilled' ? response.value.data : [];
      if (key === 'policies' && response.status === 'fulfilled') data.policyVersion = response.value.version;
      if (response.status === 'rejected') failures.set(key, path);
    }
    const required = ['policies', 'vips', 'vipGroups', 'settings', 'zones', 'sdwan'];
    if (required.some((key) => failures.has(key))) {
      throw new Error('Could not read required configuration — ' + required.filter((key) => failures.has(key))
        .map((key) => failures.get(key)).join(', '));
    }
    if (data.settings['central-nat'] === 'enable' || data.settings['ngfw-mode'] === 'policy-based') {
      FP.showModal({ title, text: 'This check requires the standard IPv4 firewall policy table with policy-based VIPs.' });
      return;
    }
    if (data.policies.some((policy) => !Number.isSafeInteger(Number(policy.policyid)) || Number(policy.policyid) <= 0)) {
      throw new Error('Could not verify the firewall policy IDs.');
    }

    const ownVdom = vdom || 'root';
    data.interfaces = data.interfaces.filter((intf) => !intf.vdom || intf.vdom === ownVdom);
    data.inventory = new Set([
      ...names(data.addresses), ...names(data.addressGroups),
      ...names(data.feeds.filter((feed) => feed.type === 'address')),
      ...data.policies.flatMap((policy) => names(policy.srcaddr)),
    ]);
    data.groupMembers = new Map(data.addressGroups.map((group) => [group.name, group]));
    const report = policyChanges(data);
    const cli = renderCli(report, data.policies);
    const findings = report.details.join('\n');
    const summary = report.pathCount + ' inbound VIP path(s) checked' +
      (report.unresolvedCount ? ', ' + report.unresolvedCount + ' VIP(s) require path review' : '') + '.';
    const notes = [...report.notes];
    if (failures.size) notes.push('Some data could not be read: ' + [...failures.values()].join(', ') + '.');
    const text = cli || findings || (report.pathCount ? 'No missing rules found for the available data.' : 'No inbound VIP paths verified.');
    FP.showModal({
      title: title + ' · ' + (report.changes.length + report.repairs.size) + ' proposed change(s)',
      text,
      notes: [summary, ...notes, ...(cli ? ['Use this CLI in the audited VDOM with the policy order and IDs shown at audit time.'] : [])],
      findings: cli ? findings : undefined,
      filename: cli ? 'fortiplug-inbound-vip-' + ownVdom + '.conf' : undefined,
    });
  }

  FP.register({
    id: 'inbound-policy-check',
    label: 'Check inbound VIP policies',
    description: 'Audit WAN-to-VIP scanner exceptions and block rules and generate FortiOS CLI.',
    usage: 'On Firewall Policy, open FP → Check inbound VIP policies.',
    isAvailable: () => FP.policyList.tableForPage() === 'firewall policy',
    run,
  });
})();
