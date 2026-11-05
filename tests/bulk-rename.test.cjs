const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

class Element {
  constructor(tag, props = {}, children = []) {
    this.tag = tag;
    this.children = children;
    this.value = '';
    Object.assign(this, props);
  }
  append(...children) { this.children.push(...children); }
  setAttribute(key, value) { this[key] = value; }
  addEventListener() {}
  querySelector() { return null; }
  remove() { this.removed = true; }
}
const elements = (root, tag) => root.children.flatMap((child) => [
  ...(child.tag === tag ? [child] : []), ...elements(child, tag),
]);
const refs = (list) => list.map((name) => ({ name }));
const policy = (policyid, options = {}) => ({
  policyid, name: `Old ${policyid}`, srcintf: refs(['VL01']),
  dstintf: refs(['WAN']), service: refs(['TCP80', 'TCP443']), action: 'accept', ...options,
});

async function dialog(policies, selected = ['1'], options = {}) {
  const root = new Element('root');
  const writes = [];
  let feature;
  let reloaded = false;
  const storage = { policyNameLimit: options.limit ?? 40 };
  const FP = {
    register: (f) => { feature = f; },
    policyList: {
      tableForPage: () => 'firewall policy',
      collectList: async () => ({ ids: options.ids || policies.map((p) => String(p.policyid)), selected }),
    },
    getVdom: () => 'test-vdom',
    requestJson: async (url, request) => {
      assert.equal(request.vdom, 'test-vdom');
      if (url.includes('/vipgrp')) return { results: structuredClone(options.groups || []) };
      if (url.includes('/vip')) {
        if (options.vipError) throw new Error('VIP read failed');
        return { results: structuredClone(options.vips || []) };
      }
      return { results: structuredClone(policies) };
    },
    request: async (url, request) => {
      writes.push({ url, ...request });
      if (options.save) await options.save(url, request);
    },
    el: (...args) => new Element(...args),
    toast() {},
    root: () => root,
  };
  const context = vm.createContext({
    window: { FortiPlug: FP }, confirm: () => options.confirm !== false,
    location: { reload: () => { reloaded = true; } },
    browser: { storage: { local: {
      get: async () => ({ ...storage }),
      set: async (value) => { Object.assign(storage, value); },
    } } },
  });
  for (const file of ['src/policy-names.js', 'src/features/bulk-rename.js']) {
    vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context);
  }
  await feature.run();
  const inputFor = (label) => elements(root, 'input').find((e) => e['aria-label'] === label);
  const infer = inputFor('Infer purpose from address objects');
  if (options.infer !== undefined) { infer.checked = options.infer; infer.onchange(); }
  const buttons = elements(root, 'button');
  const rows = elements(root, 'tbody')[0].children;
  return {
    root, writes, rows, storage, naming: FP.policyNames,
    software: inputFor('Common software / purpose'), placeholder: inputFor('Default multiple-interface placeholder'),
    sourcePlaceholder: inputFor('Source multiple-interface placeholder'), destinationPlaceholder: inputFor('Destination multiple-interface placeholder'),
    limit: inputFor('Policy name character limit'), reuse: inputFor('Reuse existing descriptions'),
    infer, shortFqdn: inputFor('Shorten FQDN object labels'), prefixes: inputFor('Object prefixes to remove'),
    objectAliases: elements(root, 'textarea').find((e) => e['aria-label'] === 'Object aliases'),
    aliases: elements(root, 'textarea')[0],
    names: elements(root, 'input').filter((e) => e['aria-label']?.startsWith('New name for policy ')),
    purposes: elements(root, 'input').filter((e) => e['aria-label']?.startsWith('Software / purpose for policy ')),
    origins: rows.map((row) => row.children[2].children.at(-1)),
    apply: buttons[1], reset: buttons[0], close: buttons[2],
    reloaded: () => reloaded,
  };
}

test('generates requested format, software suffix and multi-interface placeholder on either side', async () => {
  const d = await dialog([
    policy(1), policy(2, { srcintf: refs(['VL01', 'VL02']), service: refs(['TCP80']) }),
    policy(3, { dstintf: refs(['WAN1', 'WAN2']), service: refs(['HTTPS']) }),
  ], ['1', '2', '3']);
  assert.deepEqual(d.names.map((e) => e.value), [
    'VL01-WAN (TCP80, TCP443)', 'VLXX-WAN (TCP80)', 'VL01-VLXX (HTTPS)',
  ]);
  d.software.value = 'Software';
  d.software.oninput();
  assert.equal(d.names[0].value, 'VL01-WAN_Software (TCP80, TCP443)');
  d.placeholder.value = 'MULTI';
  d.placeholder.oninput();
  assert.equal(d.names[1].value, 'MULTI-WAN_Software (TCP80)');
});

test('automatically shortens previews to 40 characters, keeps full tooltip and permits correction', async () => {
  const d = await dialog([policy(1, { service: refs(['A'.repeat(50)]) })]);
  assert.equal(Array.from(d.names[0].value).length, 40);
  assert.ok(d.names[0].value.endsWith('.)'));
  assert.ok(d.names[0].title.includes('A'.repeat(50)));
  assert.equal(d.apply.disabled, false);
  d.names[0].value = 'B'.repeat(41);
  d.names[0].oninput();
  assert.equal(d.apply.disabled, true);
  d.names[0].value = 'VL01-WAN_Manual';
  d.names[0].oninput();
  assert.equal(d.apply.disabled, false);
  d.software.value = 'Software';
  d.software.oninput();
  assert.equal(d.names[0].value, 'VL01-WAN_Manual');
  d.reset.onclick();
  assert.ok(d.names[0].title.startsWith('VL01-WAN_Software'));
  assert.ok(d.names[0].value.startsWith('VL01-WAN_Software'));
});

test('only selected policies are renamed and only name is sent in the scoped request', async () => {
  const d = await dialog([policy(1), policy(2)]);
  assert.equal(d.names[1].disabled, true);
  await d.apply.onclick();
  assert.equal(d.writes.length, 1);
  assert.equal(d.writes[0].url, '/api/v2/cmdb/firewall/policy/1');
  assert.equal(d.writes[0].vdom, 'test-vdom');
  assert.equal(d.writes[0].method, 'PUT');
  assert.equal(JSON.stringify(d.writes[0].body), JSON.stringify({ name: 'VL01-WAN (TCP80, TCP443)' }));
  assert.equal(d.reloaded(), false);
  d.close.onclick();
  assert.equal(d.reloaded(), true);
});

test('duplicate generated names, including truncation collisions, get policy IDs within 40 characters', async () => {
  const d = await dialog([policy(1), policy(2)], ['1', '2']);
  assert.equal(d.apply.disabled, false);
  assert.equal(d.names[0].value, 'VL01-WAN (TCP80, TCP443)_ID1');
  assert.equal(d.names[1].value, 'VL01-WAN (TCP80, TCP443)_ID2');
  d.names[1].value = 'VL01-WAN_Distinct';
  d.names[1].oninput();
  assert.equal(d.apply.disabled, false);
  const collision = await dialog([
    policy(1, { service: refs(['A'.repeat(50)]) }),
    policy(2, { service: refs(['A'.repeat(49) + 'B']) }),
  ], ['1', '2']);
  assert.notEqual(collision.names[0].value, collision.names[1].value);
  assert.ok(collision.names[0].value.endsWith('_ID1'));
  assert.ok(collision.names[1].value.endsWith('_ID2'));
  assert.equal(collision.names[0].value.length, 40);
  assert.equal(collision.names[1].value.length, 40);
  assert.equal(collision.apply.disabled, false);
});

test('checks names of policies outside the filtered list', async () => {
  const d = await dialog([policy(1), policy(2, { name: 'VL01-WAN (TCP80, TCP443)' })], ['1'], { ids: ['1'] });
  assert.equal(d.apply.disabled, false);
  assert.ok(d.names[0].value.endsWith('_ID1'));
});

test('failed requests remain selected for retry; successful policies are not resubmitted', async () => {
  let fail = true;
  const d = await dialog([policy(1), policy(2, { service: refs(['HTTPS']) })], ['1', '2'], {
    save: async (url) => { if (url.endsWith('/2') && fail) throw new Error('API failure'); },
  });
  await d.apply.onclick();
  assert.equal(d.rows[0].children[0].children[0].checked, false);
  assert.equal(d.rows[1].children.at(-1).textContent, 'API failure');
  fail = false;
  await d.apply.onclick();
  assert.equal(d.writes.length, 3);
  assert.ok(d.writes[2].url.endsWith('/2'));
});

test('requires a selection and respects cancellation', async () => {
  const empty = await dialog([policy(1)], []);
  assert.equal(empty.apply.disabled, true);
  await empty.apply.onclick();
  assert.equal(empty.writes.length, 0);
  const cancelled = await dialog([policy(1)], ['1'], { confirm: false });
  await cancelled.apply.onclick();
  assert.equal(cancelled.writes.length, 0);
});

test('freezes preview controls during requests and saves the exact displayed shortened name', async () => {
  let release;
  let started;
  const requestStarted = new Promise((resolve) => { started = resolve; });
  const wait = new Promise((resolve) => { release = resolve; });
  const d = await dialog([policy(1, { service: refs(['A'.repeat(60)]) })], ['1'], { save: () => { started(); return wait; } });
  const previewed = d.names[0].value;
  const saving = d.apply.onclick();
  assert.equal(d.software.disabled, true);
  assert.equal(d.placeholder.disabled, true);
  assert.equal(d.names[0].disabled, true);
  await requestStarted;
  assert.equal(d.writes[0].body.name, previewed);
  d.close.onclick();
  assert.equal(d.reloaded(), false);
  release();
  await saving;
  assert.equal(d.software.disabled, false);
});

const vip = (options = {}) => ({
  name: 'web-vip', type: 'static-nat', portforward: 'enable',
  extip: '203.0.113.10', extport: '443', mappedport: '8443',
  mappedip: [{ range: '10.0.0.10' }], ...options,
});

test('VIP preview contains ports, WAN IP and target with VIP appearing only once', async () => {
  const d = await dialog([policy(1, { dstaddr: refs(['web-vip']) })], ['1'], { vips: [vip()] });
  const full = 'VL01-WAN_web-vip (VIP_443-8443-203.0.113.10-10.0.0.10)';
  assert.equal(d.names[0].title, full);
  assert.ok(d.names[0].value.length <= 40);
  assert.equal((d.names[0].title.match(/VIP_/g) || []).length, 1);
  assert.equal(d.apply.disabled, false);
  d.software.value = 'App';
  d.software.oninput();
  assert.equal(d.names[0].title, 'VL01-WAN_App (VIP_443-8443-203.0.113.10-10.0.0.10)');
});

test('virtual servers use realserver ports and addresses, with duplicate mappings removed', async () => {
  const d = await dialog([policy(1, { dstaddr: refs(['web-vip']) })], ['1'], {
    vips: [vip({ type: 'server-load-balance', 'server-type': 'https', realservers: [
      { ip: '10.0.0.11', port: 8443 }, { ip: '10.0.0.12', port: 9443 }, { ip: '10.0.0.11', port: 8443 },
    ] })],
  });
  assert.equal(d.names[0].title, 'VL01-WAN_web-vip (VIP_443-8443-203.0.113.10-10.0.0.11, 443-9443-203.0.113.10-10.0.0.12)');
  assert.equal(d.apply.disabled, false);
});

test('VIP groups resolve their members without looping or repeating VIP markers', async () => {
  const d = await dialog([policy(1, { dstaddr: refs(['web-group', 'web-vip']) })], ['1'], {
    vips: [vip()], groups: [{ name: 'web-group', member: refs(['web-vip', 'web-group']) }],
  });
  assert.equal(d.names[0].title, 'VL01-WAN_web-group+web-vip (VIP_443-8443-203.0.113.10-10.0.0.10)');
});

test('VIP without port forwarding uses ALL ports instead of stale configured ports', async () => {
  const d = await dialog([policy(1, { dstaddr: refs(['web-vip']) })], ['1'], {
    vips: [vip({ portforward: 'disable' })],
  });
  assert.equal(d.names[0].title, 'VL01-WAN_web-vip (VIP_ALL-ALL-203.0.113.10-10.0.0.10)');
});

test('incomplete VIP mappings require a manual preview correction', async () => {
  const d = await dialog([policy(1, { dstaddr: refs(['web-vip']) })], ['1'], {
    vips: [vip({ mappedport: '' })],
  });
  assert.equal(d.apply.disabled, true);
  assert.match(d.rows[0].children.at(-1).textContent, /incomplete/);
  d.names[0].value = 'VL01-WAN_Corrected VIP name';
  d.names[0].oninput();
  assert.equal(d.apply.disabled, false);
});

test('VIP read errors stop generation rather than silently using service names', async () => {
  await assert.rejects(dialog([policy(1)], ['1'], { vipError: true }), /VIP read failed/);
});

test('ID suffixes remain unique if an ID-suffixed name is already taken', async () => {
  const d = await dialog([
    policy(1), policy(2, { name: 'VL01-WAN (TCP80, TCP443)' }),
    policy(3, { name: 'VL01-WAN (TCP80, TCP443)_ID1' }),
  ], ['1'], { ids: ['1'] });
  assert.equal(d.names[0].value, 'VL01-WAN (TCP80, TCP443)_ID1_2');
  assert.equal(d.apply.disabled, false);
});

test('manual names can keep the base name while automatic names get IDs', async () => {
  const d = await dialog([policy(1), policy(2)], ['1', '2']);
  d.names[0].value = 'VL01-WAN (TCP80, TCP443)';
  d.names[0].oninput();
  assert.equal(d.apply.disabled, false);
  assert.equal(d.names[1].value, 'VL01-WAN (TCP80, TCP443)_ID2');
  d.names[1].value = d.names[0].value;
  d.names[1].oninput();
  assert.equal(d.apply.disabled, true);
});

test('confirmed collision names stay fixed across partial success and retry', async () => {
  let fail = true;
  let d;
  const observed = [];
  d = await dialog([policy(1), policy(2)], ['1', '2'], {
    save: async (url) => {
      observed.push(d.names.map((e) => e.value));
      if (url.endsWith('/2') && fail) throw new Error('try again');
    },
  });
  const confirmed = d.names.map((e) => e.value);
  await d.apply.onclick();
  assert.deepEqual(d.names.map((e) => e.value), confirmed);
  assert.deepEqual(observed[0], confirmed);
  assert.deepEqual(observed[1], confirmed);
  fail = false;
  await d.apply.onclick();
  assert.equal(d.writes.length, 3);
  assert.equal(d.writes[2].body.name, confirmed[1]);
});

test('interface aliases and VPN groups use friendly names without changing the policy interfaces', async () => {
  const d = await dialog([
    policy(1, { srcintf: refs(['x8']), dstintf: refs(['VL121']) }),
    policy(2, { srcintf: refs(['VPN_EX-ADMHCI', 'VPN_EX-ADMRO']), dstintf: refs(['VL51']) }),
  ], ['1', '2']);
  assert.equal(d.names[0].value, 'WAN-VL121 (TCP80, TCP443)');
  assert.equal(d.names[1].value, 'VPN_ADM-VL51 (TCP80, TCP443)');
  d.aliases.value = 'x8=INTERNET\nVPN_EX-ADM*=ADMIN\nVPN_EX-ADMRO=READONLY';
  d.aliases.oninput();
  assert.equal(d.names[0].value, 'INTERNET-VL121 (TCP80, TCP443)');
  assert.equal(d.names[1].value, 'VLXX-VL51 (TCP80, TCP443)');
  await d.apply.onclick();
  assert.deepEqual(Object.keys(d.writes[0].body), ['name']);
  assert.ok(elements(d.root, 'summary').some((e) => e.textContent.includes('x8')));
});

test('source and destination multiple-interface placeholders can be set separately', async () => {
  const d = await dialog([policy(1, { srcintf: refs(['VL01', 'VL02']), dstintf: refs(['port1', 'port2']) })]);
  d.sourcePlaceholder.value = 'LAN';
  d.destinationPlaceholder.value = 'WAN';
  d.sourcePlaceholder.oninput();
  assert.equal(d.names[0].value, 'LAN-WAN (TCP80, TCP443)');
  d.sourcePlaceholder.value = '';
  d.sourcePlaceholder.oninput();
  assert.equal(d.names[0].value, 'VLXX-WAN (TCP80, TCP443)');
});

test('existing business descriptions are optional and retained per policy with individual overrides', async () => {
  const d = await dialog([
    policy(1, { name: 'WAN-VL121 (BTA-Farm/LoopBack)' }),
    policy(2, { name: 'VL01-WAN (HTTPS/DNS)' }),
    policy(3, { name: 'VL01-WAN_ExistingApp (VIP_443-443-example-target)' }),
  ], ['1', '2', '3']);
  assert.deepEqual(d.purposes.map((e) => e.value), ['', '', '']);
  d.reuse.checked = true;
  d.reuse.onchange();
  assert.equal(d.purposes[0].value, 'BTA-Farm/LoopBack');
  assert.equal(d.purposes[1].value, '');
  assert.equal(d.purposes[2].value, 'ExistingApp');
  d.purposes[0].value = 'RBI';
  d.purposes[0].oninput();
  d.software.value = 'Common';
  d.software.oninput();
  assert.equal(d.purposes[0].value, 'RBI');
  assert.equal(d.purposes[1].value, 'Common');
  assert.equal(d.purposes[2].value, 'Common');
  d.purposes[0].value = '';
  d.purposes[0].oninput();
  assert.equal(d.purposes[0].value, '');
  d.reset.onclick();
  assert.equal(d.purposes[0].value, 'Common');
});

test('deny rules retain DENY and the inferred block purpose when shortened', async () => {
  const d = await dialog([policy(5, {
    name: 'WAN-XXX (Block-Scanner)', srcintf: refs(['x8']), dstintf: refs(['VL01', 'VL02']),
    action: 'deny', service: refs(['ALL']),
  })], ['5']);
  d.reuse.checked = true;
  d.reuse.onchange();
  assert.equal(d.names[0].title, 'WAN-VLXX_Block-Scanner (DENY, ALL)');
  d.limit.value = '25';
  d.limit.oninput();
  assert.ok(d.names[0].value.includes(' (DENY, '));
  assert.ok(d.names[0].value.endsWith(')'));
  assert.ok(d.names[0].value.length <= 25);
});

test('expanded details show sources, ISDB, security profiles and every full VIP mapping', async () => {
  const d = await dialog([policy(1, {
    srcaddr: refs(['G_Whitelist']), dstaddr: refs(['web-vip']),
    'internet-service-src-name': refs(['Microsoft-Office365.Published']),
    'ssl-ssh-profile': 'deep-inspection', 'webfilter-profile': 'site-filter',
    'ips-sensor': 'server-protection', 'application-list': 'block-old-tls',
  })], ['1'], { infer: false, vips: [vip({ type: 'server-load-balance', realservers: [
    { ip: '10.0.0.11', port: 8443 }, { ip: '10.0.0.12', port: 9443 },
  ] })] });
  const text = elements(d.root, 'div').filter((e) => e.className === 'policy-detail').map((e) => e.textContent).join('\n');
  for (const value of ['G_Whitelist', 'Microsoft-Office365.Published', 'deep-inspection', 'site-filter', 'server-protection', 'block-old-tls', '443-8443-203.0.113.10-10.0.0.11', '443-9443-203.0.113.10-10.0.0.12']) {
    assert.ok(text.includes(value), value);
  }
  assert.ok(d.names[0].value.includes('+1)'));
  assert.ok(d.names[0].value.includes('10.0.0.11'));
  assert.ok(d.names[0].value.length <= 40);
});

test('shared limit is loaded, persisted and used by copy/paste formatting', async () => {
  const d = await dialog([policy(1, { service: refs(['A'.repeat(60)]) })], ['1'], { limit: 35 });
  assert.equal(d.limit.value, '35');
  assert.equal(d.names[0].value.length, 35);
  assert.equal(await d.naming.getLimit(), 35);
  const copied = d.naming.copyName('WAN-VL01_BlockSecurityScanner (DENY, ALL)', '_copy', 35);
  assert.ok(copied.length <= 35);
  assert.ok(copied.endsWith(')_copy'));
  assert.ok(copied.includes('DENY, '));
  d.limit.value = '40';
  await d.limit.onchange();
  assert.equal(d.storage.policyNameLimit, 40);
  assert.equal(await d.naming.getLimit(), 40);
  assert.equal(d.names[0].value.length, 40);
});

test('invalid limits and invalid aliases block all writes', async () => {
  const d = await dialog([policy(1)]);
  for (const value of ['', '19', '41', '35.5']) {
    d.limit.value = value;
    d.limit.oninput();
    assert.equal(d.apply.disabled, true);
    await d.apply.onclick();
  }
  d.limit.value = '40';
  for (const value of ['x8', 'x8=', '*x8=WAN', 'x8=WAN\nx8=OTHER']) {
    d.aliases.value = value;
    d.aliases.oninput();
    assert.equal(d.apply.disabled, true);
    await d.apply.onclick();
  }
  assert.equal(d.writes.length, 0);
  d.aliases.value = '';
  d.aliases.oninput();
  assert.equal(d.apply.disabled, false);
});

test('structured shortening preserves parentheses, ID suffixes and reports omitted services', async () => {
  const d = await dialog([policy(1)]);
  for (const limit of [20, 25, 35, 40]) {
    const result = d.naming.format({ route: 'WAN-VL121', purpose: 'Long software description', services: ['HTTPS', 'HTTPS-QUIC', 'TCP9443'] }, limit, '_ID123');
    assert.ok(result.name.length <= limit, result.name);
    assert.ok(result.name.endsWith(')_ID123'));
    assert.ok(result.omitted >= 2);
    assert.ok(result.name.includes(`+${result.omitted})`));
    assert.ok(result.full.includes('Long software description'));
  }
});

test('long software names are preserved by shortening services first', async () => {
  const d = await dialog([policy(1, { service: refs(['HTTPS-QUIC']) })]);
  const software = 'MarketingSuiteEnterprise';
  d.software.value = software;
  d.software.oninput();
  assert.equal(d.names[0].value, `VL01-WAN_${software} (HTT.)`);
  assert.equal(d.names[0].value.length, 40);
  assert.equal(d.names[0].title, `VL01-WAN_${software} (HTTPS-QUIC)`);
  d.purposes[0].value = 'MarketingSuiteEnterpriseXX';
  d.purposes[0].oninput();
  assert.equal(d.names[0].value, 'VL01-WAN_MarketingSuiteEnterpriseXX (H.)');
  d.purposes[0].value = 'S'.repeat(60);
  d.purposes[0].oninput();
  assert.equal(d.names[0].value.length, 40);
  assert.ok(d.names[0].value.endsWith(' (+1)'));
  assert.equal((d.names[0].value.match(/\./g) || []).length, 1);
  assert.ok(d.names[0].title.includes('S'.repeat(60)));
});

test('screenshot policies get descriptive names and preserve their configured services and action', async () => {
  const d = await dialog([
    policy(27, { name: '', srcintf: refs(['lan']), dstintf: refs(['a']), srcaddr: refs(['H_DanielPC']), dstaddr: refs(['mail.example.com']), service: refs(['ALL']) }),
    policy(18, { name: '', srcintf: refs(['lan']), dstintf: refs(['a']), srcaddr: refs(['H_DL', 'H_TROJA']), dstaddr: refs(['all']), action: 'deny', service: refs(['ALL']) }),
    policy(57, { name: '', srcintf: refs(['lan']), dstintf: refs(['a']), srcaddr: refs(['H_RASPIPIB3_STORJ1']), dstaddr: refs(['all']), service: refs(['ALL']) }),
  ], ['27', '18', '57']);
  assert.equal(d.names[0].value, 'lan-a_DanielPC-mail (ALL)');
  assert.equal(d.names[1].value, 'lan-a_DL+TROJA (DENY, ALL)');
  assert.equal(d.names[2].value, 'lan-a_RASPIPIB3_STORJ1 (ALL)');
  assert.equal(d.origins[0].textContent, 'Purpose inferred from source and destination');
  assert.equal(d.origins[1].textContent, 'Purpose inferred from source');
  assert.ok(d.origins[0].title.includes('mail.example.com'));
  d.objectAliases.value = 'H_RASPIPIB3_STORJ1=STORJ1';
  d.objectAliases.oninput();
  assert.equal(d.names[2].value, 'lan-a_STORJ1 (ALL)');
  d.aliases.value += '\na=OUT';
  d.aliases.oninput();
  assert.equal(d.names[0].value, 'lan-OUT_DanielPC-mail (ALL)');
  assert.equal(d.apply.disabled, false);
  await d.apply.onclick();
  assert.equal(d.writes.length, 3);
  for (const request of d.writes) assert.deepEqual(Object.keys(request.body), ['name']);
});

test('purpose priority is individual, common, reused description, destination, source, then fallback', async () => {
  const d = await dialog([policy(1, { name: 'VL01-WAN (Business)', srcaddr: refs(['H_PC']), dstaddr: refs(['G_Targets']) })]);
  assert.equal(d.purposes[0].value, 'PC-Targets');
  d.reuse.checked = true;
  d.reuse.onchange();
  assert.equal(d.purposes[0].value, 'Business');
  assert.equal(d.origins[0].textContent, 'Existing description');
  d.software.value = 'Software';
  d.software.oninput();
  assert.equal(d.purposes[0].value, 'Software');
  assert.equal(d.origins[0].textContent, 'Common software / purpose');
  d.purposes[0].value = 'Manual';
  d.purposes[0].oninput();
  d.software.value = 'Changed';
  d.software.oninput();
  assert.equal(d.purposes[0].value, 'Manual');
  assert.equal(d.origins[0].textContent, 'Manual purpose');
  d.purposes[0].value = '';
  d.purposes[0].oninput();
  assert.equal(d.names[0].value, 'VL01-WAN (TCP80, TCP443)');
  assert.equal(d.origins[0].textContent, 'Purpose cleared manually');
  d.reset.onclick();
  assert.equal(d.purposes[0].value, 'Changed');
});

test('destination labels take priority for larger source sets and large object sets use +N', async () => {
  const d = await dialog([
    policy(1, { srcaddr: refs(['H_PC1', 'H_PC2']), dstaddr: refs(['G_Service']) }),
    policy(2, { srcaddr: refs(['H_A', 'H_B', 'H_C', 'H_D']), dstaddr: refs(['all']) }),
    policy(3, { dstaddr: refs(['H_VeryLongServerName01', 'H_VeryLongServerName02', 'H_VeryLongServerName03']) }),
  ], ['1', '2', '3']);
  assert.deepEqual(d.purposes.map((e) => e.value), ['Service', 'A+B+2', 'VeryLongServerName01+2']);
  assert.equal(d.origins[0].textContent, 'Purpose inferred from destination');
  assert.ok(d.origins[1].title.includes('H_D'));
});

test('aliases precede prefix stripping and FQDN cleanup and exact aliases precede wildcards', async () => {
  const d = await dialog([policy(1, { srcaddr: refs(['all']), dstaddr: refs(['H_mail.example.com']) })]);
  assert.equal(d.purposes[0].value, 'mail');
  d.objectAliases.value = 'H_*=Generic\nH_mail.example.com=ExternalMail';
  d.objectAliases.oninput();
  assert.equal(d.purposes[0].value, 'ExternalMail');
  d.objectAliases.value = 'H_*=Generic\nmail.example.com=ExactName.example';
  d.objectAliases.oninput();
  assert.equal(d.purposes[0].value, 'ExactName.example');
  d.objectAliases.value = '';
  d.shortFqdn.checked = false;
  d.shortFqdn.onchange();
  assert.equal(d.purposes[0].value, 'mail.example.com');
  d.prefixes.value = '';
  d.prefixes.oninput();
  assert.equal(d.purposes[0].value, 'H_mail.example.com');
});

test('generic objects and copied comments never invent a purpose or a service', async () => {
  const d = await dialog([
    policy(1, { name: '(Copy of 25) (Copy of 29)', comments: 'Mail (Copy of 26)', srcaddr: refs(['all']), dstaddr: refs(['all']), service: refs(['ALL']) }),
    policy(2, { srcaddr: refs(['H_PC']), dstaddr: refs(['all', 'H_Ignored']) }),
    policy(3, { name: 'VL01-WAN (ALL, +2)', srcaddr: refs(['all6']), dstaddr: refs(['::/0']) }),
  ], ['1', '2', '3']);
  d.reuse.checked = true;
  d.reuse.onchange();
  assert.equal(d.purposes[0].value, '');
  assert.equal(d.purposes[1].value, 'PC');
  assert.equal(d.purposes[2].value, '');
  assert.equal(d.names[0].value, 'VL01-WAN (ALL)');
  assert.ok(!d.names[0].value.includes('Mail'));
  const p = d.naming.inferPurpose({ sources: ['0.0.0.0/0'], destinations: ['any'] });
  assert.equal(p.value, '');
});

test('IP addresses remain intact and collapsed FQDN labels still indicate multiple objects', async () => {
  const d = await dialog([
    policy(1, { dstaddr: refs(['192.0.2.10']) }),
    policy(2, { dstaddr: refs(['2001:db8::10']) }),
    policy(3, { dstaddr: refs(['mail.example.com', 'mail.example.net']) }),
  ], ['1', '2', '3']);
  assert.deepEqual(d.purposes.map((e) => e.value), ['192.0.2.10', '2001:db8::10', 'mail+1']);
});

test('address-based inference can be disabled and manual edits survive configuration changes', async () => {
  const d = await dialog([policy(1, { srcaddr: refs(['H_PC']), dstaddr: refs(['all']) })]);
  assert.equal(d.purposes[0].value, 'PC');
  d.infer.checked = false;
  d.infer.onchange();
  assert.equal(d.purposes[0].value, '');
  d.names[0].value = 'VL01-WAN_Custom full name';
  d.names[0].oninput();
  d.infer.checked = true;
  d.infer.onchange();
  d.objectAliases.value = 'H_PC=Computer';
  d.objectAliases.oninput();
  assert.equal(d.names[0].value, 'VL01-WAN_Custom full name');
  d.reset.onclick();
  assert.equal(d.names[0].value, 'VL01-WAN_Computer (TCP80, TCP443)');
});

test('meaningful object names avoid IDs and IDs remain available for genuine collisions', async () => {
  const d = await dialog([
    policy(1, { srcaddr: refs(['H_Desktop']), dstaddr: refs(['all']) }),
    policy(2, { srcaddr: refs(['H_Laptop']), dstaddr: refs(['all']) }),
    policy(3, { srcaddr: refs(['H_Laptop']), dstaddr: refs(['all']) }),
  ], ['1', '2', '3']);
  assert.equal(d.names[0].value, 'VL01-WAN_Desktop (TCP80, TCP443)');
  assert.ok(d.names[1].value.endsWith('_ID2'));
  assert.ok(d.names[2].value.endsWith('_ID3'));
  assert.equal(d.apply.disabled, false);
});

test('invalid object aliases block writes and prefix cleanup is configurable', async () => {
  const d = await dialog([policy(1, { srcaddr: refs(['HOST_PC']), dstaddr: refs(['all']) })]);
  d.prefixes.value = 'H_, HOST_';
  d.prefixes.oninput();
  assert.equal(d.purposes[0].value, 'PC');
  for (const text of ['H_PC=', 'H_PC', 'H_PC=A\nH_PC=B', 'H*PC=A']) {
    d.objectAliases.value = text;
    d.objectAliases.oninput();
    assert.equal(d.apply.disabled, true);
    await d.apply.onclick();
  }
  assert.equal(d.writes.length, 0);
});

test('active ISDB selections are used instead of broad address objects and negations are explicit', async () => {
  const d = await dialog([
    policy(1, { srcaddr: refs(['all']), dstaddr: refs(['all']), 'internet-service': 'enable', 'internet-service-name': refs(['Microsoft-Office365']), 'internet-service-negate': 'enable' }),
    policy(2, { srcaddr: refs(['H_Blocked']), dstaddr: refs(['all']), 'srcaddr-negate': 'enable' }),
  ], ['1', '2']);
  assert.equal(d.purposes[0].value, 'NOT_Microsoft-Office365');
  assert.equal(d.purposes[1].value, 'NOT_Blocked');
});

test('shortening produces at most one literal dot marker across all shortened parts', async () => {
  const d = await dialog([policy(1)]);
  const mapping = { incoming: '53', mapped: '53', external: '203.0.113.10', target: '192.168.1.192' };
  for (const limit of [20, 25, 35, 40]) {
    for (const route of ['lan-lan', 'lan-VPN_DP', 'LongSourceInterface-LongDestinationInterface']) {
      for (const purpose of ['UDP53_IP192', 'S'.repeat(60), '']) {
        for (const suffix of ['', '_ID35']) {
          const result = d.naming.format({ route, purpose, mappings: [mapping, { ...mapping, target: '192.168.1.193' }, { ...mapping, target: '192.168.1.194' }] }, limit, suffix);
          if (route.length > limit - 16) assert.ok(result.name.startsWith(route), result.name);
          else assert.ok(result.name.length <= limit, result.name);
          assert.ok(!result.name.includes('…'), result.name);
          assert.ok(!result.name.includes('..'), result.name);
          const withoutIps = result.name.replace(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g, 'IP');
          assert.ok((withoutIps.match(/\./g) || []).length <= 1, result.name);
          assert.ok(result.name.endsWith(`)${suffix}`), result.name);
          assert.ok(result.full.includes('203.0.113.10-192.168.1.192'));
        }
      }
    }
  }
});

test('VIP shortening prefers complete destination addresses and mapped ports', async () => {
  const d = await dialog([policy(1)]);
  const mapping = { incoming: '53', mapped: '5353', external: '203.0.113.10', target: '192.168.1.192' };
  const roomy = d.naming.format({ route: 'lan-lan', mappings: [mapping] }, 40);
  assert.equal(roomy.name, 'lan-lan (VIP_192.168.1.192_5353)');
  const small = d.naming.format({ route: 'lan-VPN_DP', purpose: 'UDP53_IP192', mappings: [mapping, mapping, mapping] }, 40);
  assert.ok(/^lan-VPN_DP_UDP53_IP192 \(VIP_(?:\._5353|5353|\.), \+2\)$/.test(small.name), small.name);
});

test('compact VIP names use configured target IP aliases and keep full mapping details', async () => {
  const d = await dialog([policy(1, { dstaddr: refs(['web-vip']) })], ['1'], { vips: [vip()] });
  d.objectAliases.value = '10.0.0.*=Generic\n10.0.0.10=DNS01';
  d.objectAliases.oninput();
  assert.equal(d.names[0].value, 'VL01-WAN_web-vip (VIP_DNS01_8443)');
  assert.equal(d.names[0].title, 'VL01-WAN_web-vip (VIP_443-8443-203.0.113.10-10.0.0.10)');
  assert.equal(d.apply.disabled, false);
});

test('inferred network labels do not repeat interface names or create multiple shortening groups', async () => {
  const d = await dialog([
    policy(113, { srcintf: refs(['lan']), dstintf: refs(['VLAN_VMs']), srcaddr: refs(['LAN_Walding']), dstaddr: refs(['LAN_VMs']), service: refs(['ALL']) }),
    policy(50, { srcintf: refs(['lan']), dstintf: refs(['VLAN_VMs-DMZ']), srcaddr: refs(['LAN_Walding']), dstaddr: refs(['LAN_VMs_DMZ']), service: refs(['ALL']) }),
  ], ['113', '50']);
  assert.equal(d.names[0].value, 'lan-VLAN_VMs_LAN_Walding (ALL)');
  assert.equal(d.names[1].value, 'lan-VLAN_VMs-DMZ_LAN_Walding (ALL)');
  assert.deepEqual(d.purposes.map((input) => input.value), ['LAN_Walding', 'LAN_Walding']);
  assert.ok(d.origins.every((origin) => origin.textContent === 'Purpose inferred from source'));
  d.purposes[0].value = 'LAN_Walding-LAN_VMs';
  d.purposes[0].oninput();
  assert.equal(d.purposes[0].value, 'LAN_Walding-LAN_VMs');
});

test('generated interface pairs stay complete under every limit while manual edits can replace them', async () => {
  const d = await dialog([policy(1)]);
  for (const limit of [20, 25, 35, 40]) {
    const result = d.naming.format({ route: 'VL01-WAN', purpose: 'S'.repeat(100), services: ['HTTPS', 'DNS'] }, limit, '_ID123');
    assert.ok(result.name.startsWith('VL01-WAN'), result.name);
    assert.ok(result.name.length <= limit, result.name);
    assert.ok(result.name.endsWith(')_ID123'), result.name);
  }
  for (const manual of ['WAN (ALL)', 'VL01-W. (ALL)', 'VL01-WANother (ALL)', 'Software']) {
    d.names[0].value = manual;
    d.names[0].oninput();
    assert.equal(d.apply.disabled, false);
  }
  assert.equal(d.writes.length, 0);
  d.reset.onclick();
  d.aliases.value = 'VL01=VeryLongSourceInterface\nWAN=VeryLongDestinationInterface';
  d.aliases.oninput();
  assert.ok(d.names[0].value.startsWith('VeryLongSourceInterface-VeryLongDestinationInterface'));
  assert.equal(d.apply.disabled, true);
  await d.apply.onclick();
  assert.equal(d.writes.length, 0);
  assert.match(d.rows[0].children.at(-1).textContent, /complete interface pair/);
});

test('manual sdwan names save exactly as edited with length, character and duplicate validation intact', async () => {
  const d = await dialog([
    policy(653, { srcintf: refs(['VL01', 'VL02']), dstintf: refs(['virtual-wan-link']), action: 'deny', service: refs(['SMB']) }),
    policy(703, { srcintf: refs(['VL01', 'VL02']), dstintf: refs(['virtual-wan-link']), action: 'deny', service: refs(['LDAP']) }),
  ], ['653', '703']);
  for (const input of d.names) { input.value = 'VLXX-sdwan (DENY, SMB)'; input.oninput(); }
  assert.equal(d.apply.disabled, true);
  d.names[1].value = 'VLXX-sdwan (DENY, LDAP, +4)';
  d.names[1].oninput();
  assert.equal(d.apply.disabled, false);
  for (const invalid of ['', 'A'.repeat(41), 'Bad"name', 'Bad\nname']) {
    d.names[0].value = invalid;
    d.names[0].oninput();
    assert.equal(d.apply.disabled, true);
    await d.apply.onclick();
  }
  assert.equal(d.writes.length, 0);
  d.names[0].value = 'VLXX-sdwan (DENY, SMB)';
  d.names[0].oninput();
  await d.apply.onclick();
  assert.deepEqual(d.writes.map((request) => request.body.name), ['VLXX-sdwan (DENY, SMB)', 'VLXX-sdwan (DENY, LDAP, +4)']);
  for (const request of d.writes) assert.deepEqual(Object.keys(request.body), ['name']);
});

if (process.env.FORTIPLUG_POLICY_SAMPLE) {
  test('all 43 supplied example policies generate unique, bounded names with purpose reuse', async () => {
    const text = fs.readFileSync(process.env.FORTIPLUG_POLICY_SAMPLE, 'utf8');
    const policies = [...text.matchAll(/^    edit (\d+)\r?\n([\s\S]*?)(?=^    next\s*$)/gm)].map((match) => {
      const p = { policyid: Number(match[1]) };
      for (const field of match[2].matchAll(/^        set ([\w-]+) (.+?)\r?$/gm)) {
        const values = [...field[2].matchAll(/"([^"]*)"|(\S+)/g)].map((value) => value[1] ?? value[2]);
        p[field[1]] = ['srcintf', 'dstintf', 'srcaddr', 'dstaddr', 'service', 'internet-service-src-name'].includes(field[1]) ? refs(values) : values[0];
      }
      return p;
    });
    assert.equal(policies.length, 43);
    const d = await dialog(policies, policies.map((p) => String(p.policyid)));
    d.reuse.checked = true;
    d.reuse.onchange();
    for (const limit of ['35', '40']) {
      d.limit.value = limit;
      d.limit.oninput();
      assert.equal(d.apply.disabled, false);
      const names = d.names.map((input) => input.value);
      assert.equal(new Set(names).size, 43);
      for (const name of names) {
        assert.ok(Array.from(name).length <= Number(limit), name);
        assert.ok(/\)(?:_ID\d+(?:_\d+)?)?$/.test(name), name);
        assert.ok(!name.startsWith('x8-'), name);
      }
    }
  });
}
