'use strict';

(() => {
  const FP = window.FortiPlug;
  const SCANNER = 'G_SecurityScanner';
  const BLOCKLIST = 'eworx-IP-Blocklist';
  const SPAM_SERVICE = 'Spam-Spamming.Server';
  const THREAT_FAMILIES = ['botnet', 'hosting', 'malicious', 'phishing', 'proxy', 'tor', 'vpn'];
  const threatFamily = (name) => name.toLowerCase().split('-')[0].replace(/^phising$/, 'phishing');
  const isScanner = (name) => /[.-]scanner(?:$|[.-])/i.test(name);
  const { names, interfaceNames, enabled, covers, overlaps, includesBuiltin, wanInterfaces,
    wirelessVapRequest, policyInterfaceExclusions, quote, cliList, readConfiguration } = FP.policyAudit;
  const pathKey = (ingress, egress, vip) => JSON.stringify([ingress, egress, vip]);
  const pairKey = (ingress, egress) => JSON.stringify([ingress, egress]);

  function defaultMatchVip(version) {
    const [, major, minor, patch] = /^v?(\d+)\.(\d+)\.(\d+)/.exec(version || '') || [];
    return Number(major) > 7 || (Number(major) === 7 &&
      (Number(minor) > 2 || (Number(minor) === 2 && Number(patch) >= 4)));
  }

  function groupDenies(denies, rules, scannerOrder, repairs) {
    const accepts = rules.filter((rule) => rule.enabled && rule.action === 'accept' &&
      (rule.vips.size || rule.allDestinations));
    const groups = new Map();
    const targeted = new Map();

    function canAdvance(scanner, index) {
      const { path, rule } = scanner;
      if (!rule && !scanner.canAdd) return false;
      if (rule && (!rule.onlyVipDestinations || rule.ingress.length !== 1 || rule.egress.length !== 1 ||
        rule.ingress[0] !== path.ingress || rule.egress[0] !== path.egress)) return false;
      const vips = rule?.vips || [path.vip];
      return !rules.some((other) => (other.enabled || repairs.has(other.id)) &&
        other.index >= index && other.index < (rule?.index ?? scanner.index) &&
        covers(other.ingressScope, path.ingress) && overlaps(other.egressScope, path.egress) &&
        (!other.onlyVipDestinations || [...vips].some((vip) => other.vips.has(vip))));
    }

    function combine(proposals) {
      const latest = proposals.reduce((first, rule) => rule.latest.index < first.index ? rule.latest : first, proposals[0].latest);
      const ingress = [...new Set(proposals.flatMap((rule) => rule.ingress))];
      const egress = [...new Set(proposals.flatMap((rule) => rule.egress))];
      const sources = [...new Set(proposals.flatMap((rule) => rule.sources))].sort();
      const pairs = new Set(proposals.flatMap((rule) => [...rule.pairs]));
      if (egress.length > 1 && egress.includes('any')) return null;
      for (const source of ingress) {
        for (const destination of egress) {
          // Combining interface lists can also match the other interface pairs.
          if (!pairs.has(pairKey(source, destination)) && accepts.some((rule) =>
            covers(rule.ingressScope, source) && overlaps(rule.egressScope, destination))) return null;
        }
      }
      const advance = scannerOrder.filter((scanner) => scanner.index > latest.index &&
        ingress.includes(scanner.path.ingress) && overlaps(egress, scanner.path.egress));
      if (advance.some((scanner) => !canAdvance(scanner, latest.index))) return null;
      return { ...proposals[0], ingress, egress, sources, pairs, latest, advance };
    }

    for (const deny of denies) {
      const { ingress, egress, vip } = deny.path;
      const pair = pairKey(ingress, egress);
      const key = deny.kind;
      const proposal = {
        kind: deny.kind, sources: deny.sources, latest: deny.latest,
        ingress: [ingress], egress: [egress], pairs: new Set([pair]),
      };
      const single = combine([proposal]);
      if (!single) {
        const targetKey = JSON.stringify([key, deny.sources, pair, deny.latest.id]);
        if (!targeted.has(targetKey)) targeted.set(targetKey, {
          kind: deny.kind, sources: deny.sources, anchor: deny.latest.id, ingress: [ingress], egress: [egress], vips: [],
        });
        targeted.get(targetKey).vips.push(vip);
        continue;
      }
      if (!groups.has(key)) groups.set(key, []);
      groups.get(key).push(single);
    }

    const merged = [];
    const splitKinds = [];
    for (const group of groups.values()) {
      const combined = combine(group);
      if (combined) {
        merged.push(combined);
        continue;
      }
      const compatible = [];
      for (const rule of group) {
        const index = compatible.findIndex((other, index) => {
          const pair = combine([other, rule]);
          if (!pair) return false;
          compatible[index] = pair;
          return true;
        });
        if (index === -1) compatible.push(rule);
      }
      if (compatible.length > 1) splitKinds.push(group[0].kind);
      merged.push(...compatible);
    }
    const scannerAnchors = new Map();
    const scannerMoves = new Map();
    for (const deny of merged) {
      for (const scanner of deny.advance) {
        const moves = scanner.rule ? scannerMoves : scannerAnchors;
        const key = scanner.rule?.id ?? scanner.key;
        if (!moves.has(key) || moves.get(key).index > deny.latest.index) moves.set(key, deny.latest);
      }
    }
    return {
      wildcard: merged.map((group) => ({ ...group, anchor: group.latest.id, vips: ['all'] })),
      targeted: [...targeted.values()],
      scannerAnchors, scannerMoves, splitKinds,
    };
  }


  function policyChanges(data) {
    const { policies, vips, vipGroups, inventory, groupMembers, isdb, isdbGroups } = data;
    const { wan: detectedWan, normalize, policyInterfaces } = wanInterfaces(data);
    const excluded = new Set(policyInterfaceExclusions(data.wirelessVaps).map(normalize));
    const wan = detectedWan.filter((name) => !excluded.has(name));
    const hasExcludedInterface = [...names(data.interfaces), ...names(data.zones), ...detectedWan,
      ...policies.flatMap((policy) => [...policyInterfaces(policy.srcintf), ...policyInterfaces(policy.dstintf)]),
      ...vips.flatMap((vip) => [...policyInterfaces(vip.extintf), ...policyInterfaces(vip['srcintf-filter'])]),
    ].some((name) => excluded.has(normalize(name)));
    const canChange = (rule) => ![...rule.ingressScope, ...rule.egressScope].some((name) =>
      excluded.has(name) || (name === 'any' && hasExcludedInterface));
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
    const requiredThreats = threatNames.flat();
    if (catalog.has(SPAM_SERVICE)) requiredThreats.push(SPAM_SERVICE);
    else missingFamilies.push('spam');
    const isThreat = (name) => name === SPAM_SERVICE || THREAT_FAMILIES.includes(threatFamily(name));
    const matchVipByDefault = defaultMatchVip(data.policyVersion);

    const rules = policies.map((p, index) => {
      const src = names(p.srcaddr);
      const dst = names(p.dstaddr);
      const srcIsdb = p['internet-service-src'] === 'enable';
      const dstIsdb = p['internet-service'] === 'enable';
      const named = names(p['internet-service-src-name']);
      const ids = (p['internet-service-src-id'] || []).map((ref) => String(ref.id ?? ref));
      const allDestinations = !dstIsdb && includesBuiltin(dst, 'all') && p['dstaddr-negate'] !== 'enable';
      const matchesVip = p['match-vip'] === 'enable' ||
        (p.action === 'deny' && p['match-vip'] == null && matchVipByDefault);
      return {
        id: Number(p.policyid), index, srcIsdb, action: p.action, enabled: enabled(p),
        ingress: interfaceNames(p.srcintf), egress: interfaceNames(p.dstintf),
        ingressScope: policyInterfaces(p.srcintf), egressScope: policyInterfaces(p.dstintf),
        vips: dstIsdb || p['dstaddr-negate'] === 'enable' ? new Set() : expandVips(dst),
        allVips: allDestinations && matchesVip,
        allDestinations,
        onlyVipDestinations: !dstIsdb && p['dstaddr-negate'] !== 'enable' && dst.length > 0 &&
          dst.every((name) => vipNames.has(name) || groups.has(name)),
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
    let wildcardNeedsReview = false;
    const vipBindings = new Map(vips.map((vip) => [
      vip.name, interfaceNames(vip.extintf).filter((name) => name !== 'any').map(normalize),
    ]));
    for (const vip of vips.filter(enabled)) {
      const bindings = vipBindings.get(vip.name);
      const filters = interfaceNames(vip['srcintf-filter']).filter((name) => name !== 'any').map(normalize);
      if ([bindings, filters].some((refs) => refs.length && refs.every((name) => excluded.has(name)))) continue;
      const candidates = wan.filter((name) =>
        (!bindings.length || bindings.includes(name)) && (!filters.length || filters.includes(name)));
      let found = false;
      let skipped = false;
      let hasOtherRule = false;
      for (const rule of rules) {
        if (!rule.enabled || rule.action !== 'accept' || !rule.vips.has(vip.name)) continue;
        if ([rule.ingressScope, rule.egressScope].some((refs) => refs.length && refs.every((name) => excluded.has(name)))) {
          skipped = true;
          continue;
        }
        hasOtherRule = true;
        for (const ingress of candidates.filter((name) => covers(rule.ingressScope, name))) {
          for (const egress of rule.egressScope) {
            if (excluded.has(egress)) continue;
            if (egress === 'any' && hasExcludedInterface) {
              wildcardNeedsReview = true;
              continue;
            }
            const key = pathKey(ingress, egress, vip.name);
            paths.set(key, { ingress, egress, vip: vip.name });
            if (!rule.allowScanner) published.add(key);
            found = true;
          }
        }
      }
      if ((!bindings.length || candidates.length || !wan.length) && !found && (!skipped || hasOtherRule)) unresolved.push(vip.name);
    }

    const notes = [];
    const details = [];
    const scannerAllows = new Map();
    const newDenies = [];
    const scannerOrder = [];
    if (!wan.length && vips.some(enabled)) notes.push('No WAN policy interface was found. Check WAN roles, SD-WAN, and default routes.');
    if (wildcardNeedsReview) notes.push('VIP publishing policies with destination interface any require review when excluded interfaces are present.');
    if (unresolved.length) {
      details.push('VIPs without a verified inbound policy path', ...unresolved.map((name) => '  ' + name), '');
    }
    if (missingFamilies.length) notes.push('ISDB categories unavailable on this firewall: ' + missingFamilies.join(', ') + '.');
    if (!scannerNames.length) notes.push('No scanner entries were found in the firewall’s ISDB catalog.');

    function planScannerAllow(path, anchor) {
      const key = JSON.stringify([path.ingress, path.egress, anchor]);
      if (!scannerAllows.has(key)) scannerAllows.set(key, {
        kind: 'Allow scanner', ingress: [path.ingress], egress: [path.egress], anchor, sources: [SCANNER], vips: [],
      });
      scannerAllows.get(key).vips.push(path.vip);
    }

    const checks = [...paths].map(([key, path]) => {
      const scoped = rules.filter((rule) =>
        covers(rule.ingressScope, path.ingress) && overlaps(rule.egressScope, path.egress));
      const firstAccept = scoped.find((rule) => rule.enabled && rule.action === 'accept' && !rule.allowScanner &&
        (rule.vips.has(path.vip) || rule.allVips));
      const eligible = scoped.filter((rule) => rule.action === 'deny' && rule.always &&
        covers(rule.ingress, path.ingress) && covers(rule.egress, path.egress) &&
        (!firstAccept || rule.index < firstAccept.index));
      return { key, path, scoped, firstAccept, eligible };
    });
    const repairs = new Map();
    const wildcardCoverage = (rule) => rule.allVips || repairs.get(rule.id)?.enableMatchVip;
    const coverage = (rule, vip) => (rule.enabled || repairs.has(rule.id)) &&
      (rule.vips.has(vip) || wildcardCoverage(rule));
    function planRepair(rule) {
      if (!repairs.has(rule.id)) repairs.set(rule.id, {
        id: rule.id,
        enableStatus: !rule.enabled,
        enableMatchVip: rule.allDestinations && !rule.allVips,
        appendIsdb: new Set(),
      });
      return repairs.get(rule.id);
    }
    const isdbBaselines = [[requiredThreats, isThreat], [scannerNames, isScanner]];
    // Select existing denies first, then evaluate each scanner exception against
    // the resulting policy order, including repairs selected for other VIPs.
    for (const { path, eligible } of checks) {
      const effective = eligible.filter((rule) => coverage(rule, path.vip));
      const candidates = eligible
        .filter((rule) => canChange(rule) && (rule.allDestinations || rule.vips.has(path.vip)) && !coverage(rule, path.vip))
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
      const coveredIsdb = new Set(effective.filter((rule) => rule.srcIsdb).flatMap((rule) =>
        [...rule.isdbNames, ...(repairs.get(rule.id)?.appendIsdb || [])]));
      const threats = requiredThreats.filter((name) => !coveredIsdb.has(name)).sort();
      const scanners = scannerNames.filter((name) => !coveredIsdb.has(name)).sort();
      const catalogReview = [];
      for (const [kind, entries, matchesSource] of [
        ['Threats', threats, isThreat],
        ['Scanners', scanners, isScanner],
      ]) {
        if (!entries.length) continue;
        const existing = effective.filter((rule) => wildcardCoverage(rule) && rule.srcIsdb &&
          [...rule.isdbNames].some(matchesSource));
        const appendTo = existing.find((rule) => canChange(rule) && rule.ingress.every((name) => wan.includes(name)));
        if (appendTo) {
          const { appendIsdb } = planRepair(appendTo);
          for (const name of entries) appendIsdb.add(name);
        } else if (existing.length) {
          catalogReview.push('  ' + kind + ' — existing deny ' + existing.map((rule) => '#' + rule.id).join(', ') +
            ' omits these ISDB entries: ' + entries.join(', '));
        } else {
          missing.push([kind, entries, true]);
        }
      }

      // A new deny before the first publishing accept can also precede an existing
      // scanner exception. Check allow order against both existing and planned denies.
      const latest = firstAccept || { index: policies.length };
      const allowAnchor = [denies[0], missing.some(([, , available]) => available) && firstAccept]
        .filter(Boolean).sort((a, b) => a.index - b.index)[0];
      const scannerAllow = relevant.find((rule) => rule.allowScanner && rule.always &&
        rule.vips.has(path.vip) && covers(rule.ingress, path.ingress) && covers(rule.egress, path.egress) &&
        (!allowAnchor || rule.index < allowAnchor.index));
      const canAddScanner = inventory.has(SCANNER) && published.has(key);
      if (!scannerAllow) missing.unshift(['Allow scanner', [SCANNER], canAddScanner]);
      const earliest = scannerAllow ? scannerAllow.index + 1 : canAddScanner ? allowAnchor?.index ?? 0 : latest.index;
      scannerOrder.push({ key, path, index: earliest, rule: scannerAllow, canAdd: canAddScanner, anchor: allowAnchor?.id });

      if (!missing.length && !catalogReview.length) continue;
      details.push(path.ingress + ' → ' + path.egress + ' / ' + path.vip);
      for (const [kind, sources, available] of missing) {
        details.push('  ' + kind + ' — ' + sources.join(', ') + (available ? '' : ' (requires review)'));
        if (!available) continue;
        if (kind !== 'Allow scanner') newDenies.push({ kind, sources, path, latest });
      }
      details.push(...catalogReview);
      details.push('');
    }

    for (const { id, appendIsdb } of repairs.values()) {
      if (appendIsdb.size) details.push('Policy #' + id + ' — append ISDB sources: ' + [...appendIsdb].sort().join(', '));
    }

    for (const name of [BLOCKLIST, SCANNER]) {
      if (paths.size && !inventory.has(name)) notes.push('Required source object unavailable: ' + name + '.');
    }
    const { wildcard, targeted, scannerAnchors, scannerMoves, splitKinds } =
      groupDenies(newDenies, rules, scannerOrder, repairs);
    for (const scanner of scannerOrder) {
      if (!scanner.rule && scanner.canAdd) planScannerAllow(scanner.path, scannerAnchors.get(scanner.key)?.id ?? scanner.anchor);
    }
    for (const [id, anchor] of scannerMoves) details.push('Move scanner exception #' + id + ' above policy #' + anchor.id + '.');
    if (targeted.length) {
      notes.push('Some denies list specific VIPs because an all-destination rule would precede a scanner exception on the same interface pair.');
    }
    if (splitKinds.length) {
      notes.push('Separate denies are needed for ' + splitKinds.join(', ') +
        ' because the interfaces or scanner exceptions prevent a shared policy position.');
    }
    const changes = [...scannerAllows.values(), ...wildcard, ...targeted];
    return { changes, repairs, scannerMoves, details, notes, pathCount: paths.size, unresolvedCount: unresolved.length };
  }

  function renderCli({ changes, repairs, scannerMoves }, policies) {
    if (!changes.length && !repairs.size) return '';
    const ids = new Set(policies.map((policy) => Number(policy.policyid)));
    const existingNames = new Set(policies.map((policy) => policy.name));
    const lines = ['config firewall policy'];
    const moves = [...scannerMoves].map(([id, anchor]) => '    move ' + id + ' before ' + anchor.id);
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
        '        set srcintf ' + cliList(rule.ingress),
        '        set dstintf ' + cliList(rule.egress),
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
    for (const { id, enableStatus, enableMatchVip, appendIsdb } of repairs.values()) {
      lines.push('    edit ' + id);
      if (enableMatchVip) lines.push('        set match-vip enable');
      if (appendIsdb.size) lines.push('        append internet-service-src-name ' + cliList([...appendIsdb].sort()));
      if (enableStatus) lines.push('        set status enable');
      lines.push('    next');
    }
    return [...lines, 'end', ''].join('\n');
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
      wirelessVapRequest,
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
    const { data, failures } = await readConfiguration(requests, vdom);
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
      title: title + ' · ' + (report.changes.length + report.repairs.size + report.scannerMoves.size) + ' proposed change(s)',
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
