'use strict';

(() => {
  const FP = window.FortiPlug;
  const { names, interfaceNames, enabled, covers, wanInterfaces, quote, readConfiguration } = FP.policyAudit;
  const BASE_THRESHOLDS = {
    tcp_syn_flood: 2000, tcp_port_scan: 200, tcp_src_session: 5000, tcp_dst_session: 5000,
    udp_flood: 5000, udp_scan: 2000, udp_src_session: 5000, udp_dst_session: 5000,
    icmp_flood: 250, icmp_sweep: 100, icmp_src_session: 300, icmp_dst_session: 1000,
    ip_src_session: 5000, ip_dst_session: 5000,
    sctp_flood: 2000, sctp_scan: 1000, sctp_src_session: 5000, sctp_dst_session: 5000,
  };
  const PROFILES = [
    { name: 'DoS - Whitelist SecurityScanner', source: 'G_SecurityScanner' },
    { name: 'DoS - Whitelist MSTeams', source: 'G_MSTeams', expiry: '2m' },
    { name: 'DoS - Default', source: 'all', expiry: '1d' },
  ];
  const BLOCKING = new Set(['tcp_syn_flood', 'tcp_port_scan', 'tcp_src_session']);
  const SESSION_LIMITS = new Set(['tcp_src_session', 'ip_src_session']);
  const DEFAULTS = { status: 'disable', log: 'disable', action: 'pass', quarantine: 'none' };
  const exact = (refs, value) => {
    const selected = names(refs);
    return selected.length === 1 && selected[0].toLowerCase() === value.toLowerCase();
  };

  function supportsSdwanZones(version) {
    const parsed = /^v?(\d+)\.(\d+)\.(\d+)/i.exec(String(version));
    if (!parsed) return null;
    const [, major, minor, patch] = parsed.map(Number);
    return major > 7 || (major === 7 && (minor > 6 || (minor === 6 && patch >= 1)));
  }

  function interfacesForCheck(data, { wan, wanZoneNames, normalize }, zoneSupport) {
    if (data.sdwan.status !== 'enable') return wan;
    const zones = interfaceNames(data.sdwan.zone);
    const members = data.sdwan.members || [];
    if (zoneSupport !== true) {
      const zoneNames = new Set(['virtual-wan-link', ...zones, ...members.flatMap((member) => interfaceNames(member.zone))]);
      const standalone = wan.filter((name) => !zoneNames.has(name) || wanZoneNames.includes(name));
      if (zoneSupport === null) return standalone;
      const devices = new Map(data.interfaces.map((entry) => [entry.name, entry]));
      const uplinks = members.filter(enabled).flatMap((member) => interfaceNames(member.interface)).filter((intf) => {
        const device = devices.get(intf);
        const zone = normalize(intf);
        if (!wan.includes(zone) || wanZoneNames.includes(zone)) return false;
        if (!device) return true;
        const uplinkType = !device.type || ['physical', 'aggregate', 'vlan', 'pppoe'].includes(device.type);
        return enabled(device) && (device.role === 'wan' || (uplinkType && !['lan', 'dmz'].includes(device.role)));
      });
      return [...new Set([...standalone, ...uplinks])].sort();
    }
    const usedZones = members.filter(enabled).map((member) =>
      normalize(interfaceNames(member.interface)[0]) || interfaceNames(member.zone)[0] || 'virtual-wan-link');
    if (usedZones.includes('virtual-wan-link') || (!members.length && (!zones.length || zones.includes('virtual-wan-link')))) {
      return [...new Set(['virtual-wan-link', ...wanZoneNames])];
    }
    return wan.filter((name) => wanZoneNames.includes(name) || usedZones.includes(name) || (!members.length && zones.includes(name)));
  }

  function expiryMinutes(value) {
    const result = /^(?:(\d+)d)?(?:(\d+)h)?(?:(\d+)m)?$/.exec(String(value));
    if (!result || !result[0]) return NaN;
    return Number(result[1] || 0) * 1440 + Number(result[2] || 0) * 60 + Number(result[3] || 0);
  }

  function anomalyEdits(profile, existing) {
    const current = new Map((existing?.anomaly || []).map((item) => [item.name ?? item.q_origin_key, item]));
    const thresholds = new Map(Object.entries(BASE_THRESHOLDS));
    if (!profile.expiry) {
      for (const name of current.keys()) {
        if (/^[a-z0-9_]+$/i.test(name) && !thresholds.has(name)) thresholds.set(name, undefined);
      }
    }
    const edits = [];
    for (const [name, threshold] of thresholds) {
      const monitoring = !!profile.expiry && name !== 'tcp_dst_session';
      const blocking = monitoring && BLOCKING.has(name);
      const quarantine = blocking || (monitoring && name === 'ip_src_session');
      const expected = {
        status: monitoring ? 'enable' : 'disable',
        log: monitoring ? 'enable' : 'disable',
        action: blocking ? 'block' : 'pass',
        quarantine: quarantine ? 'attacker' : 'none',
        ...(quarantine ? { 'quarantine-expiry': profile.expiry, 'quarantine-log': 'disable' } : {}),
        ...(threshold === undefined ? {} : { threshold: monitoring && SESSION_LIMITS.has(name) ? 1000 : threshold }),
      };
      const actual = current.get(name) || {};
      const settings = Object.entries(expected).filter(([key, value]) => {
        if (!existing) return true;
        if (key === 'threshold') return Number(actual[key]) !== value;
        if (key === 'quarantine-expiry') return expiryMinutes(actual[key]) !== expiryMinutes(value);
        return (actual[key] ?? DEFAULTS[key]) !== value;
      });
      if (settings.length) edits.push({ name, settings });
    }
    return edits;
  }

  function plan(data) {
    const topology = wanInterfaces(data, { externalOnly: true });
    const zoneSupport = supportsSdwanZones(data.policyVersion);
    const interfaces = interfacesForCheck(data, topology, zoneSupport);
    const policies = data.policies.map((policy, index) => ({ ...policy, id: Number(policy.policyid), index }));
    const ids = new Set(policies.map((policy) => policy.id));
    const usedNames = new Set(policies.map((policy) => policy.name?.toLowerCase()));
    const inventory = new Set([
      ...names(data.addresses), ...names(data.groups),
      ...policies.flatMap((policy) => names(policy.srcaddr)),
    ]);
    const edits = [];
    const moves = [];
    const details = [];
    let id = 1;

    for (const intf of interfaces) {
      const scoped = policies.filter((policy) => exact(interfaceNames(policy.interface), intf));
      const selected = [];
      for (const profile of PROFILES) {
        const matching = scoped.filter((policy) => exact(policy.srcaddr, profile.source) &&
          exact(policy.dstaddr, 'all') && exact(policy.service, 'ALL'));
        const existing = matching.find(enabled) || matching[0];
        if (!existing && profile.source !== 'all' && !inventory.has(profile.source)) {
          details.push(intf + ' — source object unavailable: ' + profile.source);
          continue;
        }
        const anomaly = anomalyEdits(profile, existing);
        if (existing) {
          selected.push({ id: existing.id, index: existing.index, source: profile.source });
          if (!enabled(existing) || anomaly.length) {
            edits.push({ id: existing.id, enable: !enabled(existing), anomaly });
            details.push(intf + ' — repair policy #' + existing.id + ' (' + profile.name + ').');
          }
          continue;
        }
        while (ids.has(id)) id++;
        if (id > 9999) throw new Error('No free DoS policy ID found in the supported range.');
        let name = profile.name;
        for (let suffix = id; usedNames.has(name.toLowerCase()); suffix++) {
          const tail = ' #' + suffix;
          name = profile.name.slice(0, 35 - tail.length) + tail;
        }
        usedNames.add(name.toLowerCase());
        edits.push({ id, name, intf, source: profile.source, enable: true, anomaly });
        selected.push({ id, index: Infinity, source: profile.source });
        details.push(intf + ' — create policy #' + id + ' (' + profile.name + ').');
        id++;
      }

      const fallback = selected.at(-1);
      const exceptions = selected.slice(0, -1);
      const baselineIds = new Set(selected.map((policy) => policy.id));
      const others = policies.filter((policy) => enabled(policy) && !baselineIds.has(policy.id) &&
        (covers(interfaceNames(policy.interface), intf) || covers(topology.policyInterfaces(policy.interface), intf)));
      const shadow = others.find((policy) => exact(policy.srcaddr, 'all') &&
        exact(policy.dstaddr, 'all') && exact(policy.service, 'ALL') && policy.index < fallback.index);
      if (shadow) moves.push({ id: fallback.id, direction: 'before', anchor: shadow.id });
      else if (fallback.index === Infinity && others.length) {
        moves.push({ id: fallback.id, direction: 'after', anchor: others.at(-1).id });
      }

      const fallbackIndex = shadow?.index ?? fallback.index;
      const prior = others.find((policy) => policy.index < fallbackIndex);
      let anchor = prior?.id ?? fallback.id;
      let anchorIndex = prior?.index ?? fallbackIndex;
      for (const policy of exceptions.reverse()) {
        if (policy.index === Infinity || policy.index >= anchorIndex) {
          moves.push({ id: policy.id, direction: 'before', anchor });
          anchorIndex = Math.min(policy.index, anchorIndex);
        } else {
          anchorIndex = policy.index;
        }
        anchor = policy.id;
      }
    }
    for (const { id, direction, anchor } of moves) details.push('Move policy #' + id + ' ' + direction + ' policy #' + anchor + '.');
    return { interfaces, edits, moves, details, unknownSdwanVersion: data.sdwan.status === 'enable' && zoneSupport === null };
  }

  function renderCli({ edits, moves }) {
    if (!edits.length && !moves.length) return '';
    const lines = ['config firewall DoS-policy'];
    for (const edit of edits) {
      lines.push('    edit ' + edit.id);
      if (edit.name) lines.push(
        '        set name ' + quote(edit.name),
        '        set interface ' + quote(edit.intf),
        '        set srcaddr ' + quote(edit.source),
        '        set dstaddr "all"',
        '        set service "ALL"',
      );
      if (edit.enable) lines.push('        set status enable');
      if (edit.anomaly.length) {
        lines.push('        config anomaly');
        for (const { name, settings } of edit.anomaly) {
          lines.push('            edit ' + quote(name));
          for (const [key, value] of settings) lines.push('                set ' + key + ' ' + value);
          lines.push('            next');
        }
        lines.push('        end');
      }
      lines.push('    next');
    }
    for (const { id, direction, anchor } of moves) lines.push('    move ' + id + ' ' + direction + ' ' + anchor);
    return [...lines, 'end', ''].join('\n');
  }

  async function run() {
    const vdom = FP.getVdom();
    const ownVdom = vdom || 'root';
    const title = 'DoS Policy Check · ' + ownVdom;
    FP.toast('Checking DoS policies…');
    const { data, failures } = await readConfiguration([
      ['policies', 'cmdb/firewall/DoS-policy'],
      ['interfaces', 'cmdb/system/interface'],
      ['zones', 'cmdb/system/zone'],
      ['sdwan', 'cmdb/system/sdwan', true],
      ['staticRoutes', 'cmdb/router/static'],
      ['activeRoutes', 'monitor/router/ipv4'],
      ['addresses', 'cmdb/firewall/address'],
      ['groups', 'cmdb/firewall/addrgrp'],
    ], vdom);
    const missing = ['policies', 'interfaces', 'zones', 'sdwan'].filter((key) => failures.has(key));
    if (missing.length) throw new Error('Could not read required configuration — ' + missing.map((key) => failures.get(key)).join(', '));
    const ids = data.policies.map((policy) => Number(policy.policyid));
    if (ids.some((id) => !Number.isSafeInteger(id) || id <= 0) || new Set(ids).size !== ids.length) {
      throw new Error('Could not verify the DoS policy IDs.');
    }

    data.interfaces = data.interfaces.filter((entry) => !entry.vdom || entry.vdom === ownVdom);
    const report = plan(data);
    const cli = renderCli(report);
    const findings = report.details.join('\n');
    const notes = ['WAN interfaces checked: ' + (report.interfaces.join(', ') || 'none') + '.'];
    if (report.unknownSdwanVersion) notes.push('FortiOS version unavailable. SD-WAN targets require review before generating DoS CLI.');
    if (failures.size) notes.push('Some data could not be read: ' + [...failures.values()].join(', ') + '.');
    FP.showModal({
      title,
      text: cli || findings || (report.interfaces.length ? 'No DoS policy changes found.' : 'No WAN policy interface verified.'),
      notes,
      findings: cli ? findings : undefined,
      filename: cli ? 'fortiplug-dos-' + ownVdom + '.conf' : undefined,
    });
  }

  FP.register({
    id: 'dos-policy-check',
    label: 'DoS Policy Check',
    description: 'Audit per-WAN DoS policies and generate FortiOS CLI.',
    usage: 'On Firewall Policy or DoS Policy, open FP → DoS Policy Check.',
    isAvailable: () => FP.policyList.tableForPage() === 'firewall policy' ||
      /(?:dos-policy|\/policy\/dos)(?![\w-])/i.test(location.pathname + location.hash),
    run,
  });
})();
