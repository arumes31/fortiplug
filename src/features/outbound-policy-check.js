'use strict';

(() => {
  const FP = window.FortiPlug;
  const { names, enabled, covers, includesBuiltin, wanInterfaces, quote, cliList, readConfiguration } = FP.policyAudit;
  const BLOCKLIST = 'eworx-IP-Blocklist';
  const SSL_VPN_INTERFACE = 'ssl.root';
  const BASELINES = [
    { kind: 'SMB', values: ['SMB'] },
    { kind: 'Directory', values: ['LDAP_UDP', 'LDAPS', 'LDAP', 'KERBEROS', 'Kerberos Password'] },
    { kind: 'Threats', values: [
      'Botnet-C&C.Server', 'Phishing-Phishing.Server', 'Proxy-Proxy.Server', 'Spam-Spamming.Server',
      'Tor-Exit.Node', 'Tor-Relay.Node', 'Tor-Tor.Node', 'Malicious-Malicious.Server',
    ] },
    { kind: 'Blocklist', values: [BLOCKLIST] },
  ];
  const serviceKinds = new Set(['SMB', 'Directory']);

  function groupNames(refs, groups, visited = new Set()) {
    return names(refs).flatMap((name) => {
      if (visited.has(name)) return [];
      const group = groups.get(name);
      if (!group || group.exclude === 'enable') return [name];
      return groupNames(group.member, groups, new Set([...visited, name]));
    });
  }

  function internalSources(data, wan, normalize) {
    const memberOf = new Map();
    for (const entry of [...data.interfaces, ...data.softwareSwitches]) {
      for (const member of names(entry.member)) memberOf.set(member, entry.name);
    }
    for (const entry of data.hardwareSwitches) {
      for (const member of names(entry.port)) memberOf.set(member, entry.name);
    }
    const policyName = (name) => name === SSL_VPN_INTERFACE ? undefined : normalize(memberOf.get(name) || name);
    const internal = new Set(data.interfaces.filter((entry) => enabled(entry) &&
      ['lan', 'dmz'].includes(entry.role) && entry['dedicated-to'] !== 'management')
      .map((entry) => policyName(entry.name)));

    // Existing explicit outbound rules also identify internal zones and VLANs
    // whose interfaces have no LAN or DMZ role configured.
    for (const policy of data.policies.filter(enabled)) {
      if (!wan.some((name) => covers(names(policy.dstintf), name))) continue;
      for (const name of names(policy.srcintf)) internal.add(policyName(name));
    }
    return [...internal].filter((name) => name && name !== 'any' && name !== SSL_VPN_INTERFACE && !wan.includes(name)).sort();
  }

  function auditOutbound(data) {
    const { wan: detectedWan, normalize } = wanInterfaces(data, { externalOnly: true });
    const wan = detectedWan.filter((name) => name !== SSL_VPN_INTERFACE);
    const internal = internalSources(data, wan, normalize);
    const serviceGroups = new Map(data.serviceGroups.map((entry) => [entry.name, entry]));
    const addressGroups = new Map(data.addressGroups.map((entry) => [entry.name, entry]));
    const isdbGroups = new Map(data.isdbGroups.map((entry) => [entry.name, entry]));
    const isdb = data.isdb.filter((entry) => !['source', 'src'].includes(entry.direction));
    const isdbNames = new Set(names(isdb));
    const isdbIds = new Map(isdb.map((entry) => [String(entry['internet-service-id'] ?? entry.id), entry.name]));
    const addressNames = new Set([
      ...names(data.addresses), ...names(data.addressGroups),
      ...names(data.feeds.filter((feed) => feed.type === 'address')),
      ...data.policies.filter((policy) => policy['internet-service'] !== 'enable')
        .flatMap((policy) => names(policy.dstaddr)),
    ]);
    const services = new Map();
    for (const name of [...data.policies.flatMap((policy) => names(policy.service)), ...names(data.services)]) {
      services.set(name.toLowerCase(), name);
    }
    const missingObjects = [];
    const baselines = BASELINES.map(({ kind, values }) => ({
      kind,
      values: values.flatMap((name) => {
        const known = serviceKinds.has(kind) ? services.get(name.toLowerCase()) :
          (kind === 'Threats' ? isdbNames : addressNames).has(name) ? name : undefined;
        if (!known) missingObjects.push(name);
        return known ? [known] : [];
      }),
    }));
    const requestedServices = new Set(baselines.filter(({ kind }) => serviceKinds.has(kind)).flatMap(({ values }) => values));
    const requestedThreats = new Set(baselines.find(({ kind }) => kind === 'Threats').values);
    const rules = data.policies.map((policy, index) => {
      const ingress = names(policy.srcintf);
      const egress = names(policy.dstintf);
      const destination = names(policy.dstaddr);
      const service = groupNames(policy.service, serviceGroups);
      const allServices = includesBuiltin(service, 'all');
      const dstIsdb = policy['internet-service'] === 'enable';
      const isdbRefs = [
        ...names(policy['internet-service-name']),
        ...names(policy['internet-service-fortiguard']),
        ...groupNames(policy['internet-service-group'], isdbGroups),
        ...(policy['internet-service-id'] || []).map((ref) => isdbIds.get(String(ref?.id ?? ref))),
      ];
      const wideDeny = policy.action === 'deny' && policy.schedule === 'always' &&
        includesBuiltin(names(policy.srcaddr), 'all') && policy['internet-service-src'] !== 'enable' &&
        policy['srcaddr-negate'] !== 'enable' && !policy.users?.length && !policy.groups?.length &&
        !policy['fsso-groups']?.length && !policy['src-vendor-mac']?.length && !policy['ztna-ems-tag']?.length &&
        policy['vlan-filter'] !== 'enable';
      const allDestination = includesBuiltin(destination, 'all');
      const blockedServices = !dstIsdb && policy['dstaddr-negate'] !== 'enable' && policy['service-negate'] !== 'enable';
      const values = new Map();
      if (wideDeny && blockedServices && allDestination) {
        for (const kind of serviceKinds) {
          values.set(kind, allServices ? requestedServices : new Set(service));
        }
        if (allServices) values.set('Threats', requestedThreats);
      }
      if (wideDeny && blockedServices && allServices &&
        (allDestination || groupNames(destination, addressGroups).includes(BLOCKLIST))) {
        values.set('Blocklist', new Set([BLOCKLIST]));
      }
      if (wideDeny && dstIsdb && policy['internet-service-negate'] !== 'enable') {
        values.set('Threats', new Set(isdbRefs.filter(Boolean)));
      }
      const withinScope = ingress.length > 0 && egress.length > 0 &&
        ingress.every((name) => internal.includes(name)) && egress.every((name) => wan.includes(name));
      // A disabled rule can be restored when all of its selectors belong to the baseline.
      const exactBaseline = dstIsdb ? isdbRefs.length > 0 && isdbRefs.every((name) => requestedThreats.has(name)) &&
        !policy['internet-service-custom']?.length && !policy['internet-service-custom-group']?.length :
        allDestination ? service.length > 0 && service.every((name) => requestedServices.has(name)) :
          destination.length === 1 && destination[0] === BLOCKLIST && allServices;
      return { id: Number(policy.policyid), index, ingress, egress, active: enabled(policy), action: policy.action,
        values, repairable: withinScope && exactBaseline };
    });

    const paths = wan.flatMap((egress) => internal.map((ingress) => {
      const scoped = rules.filter((rule) => covers(rule.ingress, ingress) && covers(rule.egress, egress));
      const anchor = scoped.find((rule) => rule.active && rule.action === 'accept');
      const eligible = scoped.filter((rule) => rule.action === 'deny' && (!anchor || rule.index < anchor.index));
      return { ingress, egress, anchor, eligible };
    }));
    const repairs = new Set();
    const hasCoverage = (path, kind, name) => path.eligible.some((rule) =>
      (rule.active || repairs.has(rule.id)) && rule.values.get(kind)?.has(name));
    for (const path of paths) {
      for (const { kind, values } of baselines) {
        for (const name of values) {
          if (hasCoverage(path, kind, name)) continue;
          const existing = path.eligible.find((rule) => rule.repairable && rule.values.get(kind)?.has(name));
          if (existing) repairs.add(existing.id);
        }
      }
    }

    const details = [...repairs].map((id) => 'Policy #' + id + ' — re-enable outbound deny.');
    const perWan = new Map();
    for (const path of paths) {
      for (const { kind, values } of baselines) {
        const missing = values.filter((name) => !hasCoverage(path, kind, name));
        if (!missing.length) continue;
        details.push(path.ingress + ' → ' + path.egress + ' / ' + kind + ' — ' + missing.join(', '));
        const key = JSON.stringify([path.egress, kind]);
        if (!perWan.has(key)) perWan.set(key, { kind, egress: path.egress, ingress: [], values: new Set() });
        const group = perWan.get(key);
        group.ingress.push(path.ingress);
        for (const name of missing) group.values.add(name);
        if (path.anchor && (!group.anchor || path.anchor.index < group.anchor.index)) group.anchor = path.anchor;
      }
    }

    const changes = new Map();
    for (const group of perWan.values()) {
      const key = JSON.stringify([group.kind, group.ingress]);
      if (!changes.has(key)) changes.set(key, { ...group, egress: [] });
      const combined = changes.get(key);
      combined.egress.push(group.egress);
      for (const name of group.values) combined.values.add(name);
      if (group.anchor && (!combined.anchor || group.anchor.index < combined.anchor.index)) combined.anchor = group.anchor;
    }
    return { changes: [...changes.values()], repairs, details, missingObjects, pathCount: paths.length };
  }

  function renderCli({ changes, repairs }, policies) {
    if (!changes.length && !repairs.size) return '';
    const ids = new Set(policies.map((policy) => Number(policy.policyid)));
    const namesInUse = new Set(policies.map((policy) => policy.name));
    const cli = ['config firewall policy'];
    const moves = [];
    let id = 1;
    for (const rule of changes) {
      const stem = 'FP-Outbound-' + rule.kind + '-';
      while (ids.has(id) || namesInUse.has(stem + id)) id++;
      const values = [...rule.values].sort();
      cli.push(
        '    edit ' + id,
        '        set name ' + quote(stem + id),
        '        set srcintf ' + cliList(rule.ingress),
        '        set dstintf ' + cliList(rule.egress),
        '        set action deny',
        '        set srcaddr "all"',
        ...(rule.kind === 'Threats' ? [
          '        set internet-service enable',
          '        set internet-service-name ' + cliList(values),
        ] : [
          '        set dstaddr ' + cliList(rule.kind === 'Blocklist' ? values : ['all']),
          '        set service ' + cliList(serviceKinds.has(rule.kind) ? values : ['ALL']),
        ]),
        '        set schedule "always"',
        '        set match-vip disable',
        '        set logtraffic all',
        '    next',
      );
      if (rule.anchor) moves.push('    move ' + id + ' before ' + rule.anchor.id);
      id++;
    }
    cli.push(...moves);
    for (const id of repairs) cli.push('    edit ' + id, '        set status enable', '    next');
    return [...cli, 'end', ''].join('\n');
  }

  async function run() {
    const vdom = FP.getVdom();
    const ownVdom = vdom || 'root';
    const title = 'Outbound policy check · ' + ownVdom;
    FP.toast('Checking outbound policies…');
    const { data, failures } = await readConfiguration([
      ['policies', 'cmdb/firewall/policy'],
      ['settings', 'cmdb/system/settings', true],
      ['interfaces', 'cmdb/system/interface'],
      ['zones', 'cmdb/system/zone'],
      ['sdwan', 'cmdb/system/sdwan', true],
      ['staticRoutes', 'cmdb/router/static'],
      ['activeRoutes', 'monitor/router/ipv4'],
      ['hardwareSwitches', 'cmdb/system/virtual-switch'],
      ['softwareSwitches', 'cmdb/system/switch-interface'],
      ['services', 'cmdb/firewall.service/custom'],
      ['serviceGroups', 'cmdb/firewall.service/group'],
      ['addresses', 'cmdb/firewall/address'],
      ['addressGroups', 'cmdb/firewall/addrgrp'],
      ['feeds', 'cmdb/system/external-resource'],
      ['isdb', 'cmdb/firewall/internet-service-name'],
      ['isdbGroups', 'cmdb/firewall/internet-service-group'],
    ], vdom);
    const missing = ['policies', 'settings', 'interfaces', 'zones', 'sdwan'].filter((key) => failures.has(key));
    if (missing.length) throw new Error('Could not read required configuration — ' + missing.map((key) => failures.get(key)).join(', '));
    if (data.settings['ngfw-mode'] === 'policy-based') {
      FP.showModal({ title, text: 'This check requires the standard IPv4 firewall policy table.' });
      return;
    }
    if (data.policies.some((policy) => !Number.isSafeInteger(Number(policy.policyid)) || Number(policy.policyid) <= 0)) {
      throw new Error('Could not verify the firewall policy IDs.');
    }

    data.interfaces = data.interfaces.filter((entry) => !entry.vdom || entry.vdom === ownVdom);
    const report = auditOutbound(data);
    const cli = renderCli(report, data.policies);
    const findings = report.details.join('\n');
    const notes = [report.pathCount + ' internal-to-WAN interface pair(s) checked.'];
    if (report.missingObjects.length) notes.push('Required objects unavailable: ' + report.missingObjects.join(', ') + '.');
    if (failures.size) notes.push('Some data could not be read: ' + [...failures.values()].join(', ') + '.');
    FP.showModal({
      title: title + ' · ' + (report.changes.length + report.repairs.size) + ' proposed change(s)',
      text: cli || findings || (!report.pathCount ? 'No internal-to-WAN paths verified.' :
        report.missingObjects.length || failures.size ? 'No CLI changes available for the objects that could be checked.' :
          'No missing outbound rules found.'),
      notes,
      findings: cli ? findings : undefined,
      filename: cli ? 'fortiplug-outbound-' + ownVdom + '.conf' : undefined,
    });
  }

  FP.register({
    id: 'outbound-policy-check',
    label: 'Check Outbound Policies',
    description: 'Audit internal-to-WAN denies and generate FortiOS CLI for missing rules.',
    usage: 'On Firewall Policy, open FP → Check Outbound Policies.',
    isAvailable: () => FP.policyList.tableForPage() === 'firewall policy',
    run,
  });
})();
