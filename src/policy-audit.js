'use strict';

(() => {
  const FP = window.FortiPlug;
  const names = (refs = []) => (Array.isArray(refs) ? refs : [refs])
    .map((ref) => typeof ref === 'string' ? ref : ref?.name ?? ref?.['interface-name'] ?? ref?.q_origin_key)
    .filter((name) => typeof name === 'string' && name);
  const enabled = (entry) => entry.status !== 'disable';
  const covers = (refs, name) => refs.includes('any') || refs.includes(name);
  const overlaps = (refs, name) => name === 'any' ? refs.length > 0 : covers(refs, name);
  const includesBuiltin = (refs, name) => refs.some((ref) => ref.toLowerCase() === name);
  const isDefaultRoute = (prefix) => /^(0\.0\.0\.0(?:\/0|\/0\.0\.0\.0| 0\.0\.0\.0))$/.test(prefix);

  function wanInterfaces({ interfaces, zones, sdwan, staticRoutes, activeRoutes }, { externalOnly = false } = {}) {
    const policyInterface = new Map();
    const wan = new Set(interfaces.filter((intf) => intf.role === 'wan').map((intf) => intf.name));
    const devices = new Map(interfaces.map((intf) => [intf.name, intf]));
    for (const zone of zones) {
      for (const member of names(zone.interface)) policyInterface.set(member, zone.name);
    }
    if (sdwan?.status === 'enable') {
      for (const member of (sdwan.members || []).filter(enabled)) {
        const zone = member.zone || 'virtual-wan-link';
        policyInterface.set(member.interface, zone);
        const device = devices.get(member.interface);
        const uplink = device?.role === 'wan' || (!['lan', 'dmz'].includes(device?.role) &&
          (['physical', 'aggregate', 'vlan', 'pppoe'].includes(device?.type) ||
            (zone === 'virtual-wan-link' && !device?.type)));
        if (!externalOnly || uplink) wan.add(zone);
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

  const quote = (value) => '"' + String(value).replace(/[\\"]/g, '\\$&') + '"';
  const cliList = (values) => values.map(quote).join(' ');

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

  async function readConfiguration(requests, vdom) {
    const responses = await Promise.allSettled(requests.map(([, path, singleton]) => readTable(path, vdom, singleton)));
    const data = {};
    const failures = new Map();
    for (const [index, [key, path]] of requests.entries()) {
      const response = responses[index];
      data[key] = response.status === 'fulfilled' ? response.value.data : [];
      if (key === 'policies' && response.status === 'fulfilled') data.policyVersion = response.value.version;
      if (response.status === 'rejected') failures.set(key, path);
    }
    return { data, failures };
  }

  FP.policyAudit = { names, enabled, covers, overlaps, includesBuiltin, wanInterfaces, quote, cliList, readConfiguration };
})();
