'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = ['../src/policy-audit.js', '../src/features/inbound-policy-check.js']
  .map((file) => fs.readFileSync(path.join(__dirname, file), 'utf8')).join('\n');
const refs = (...values) => values.map((name) => ({ name }));
const threats = ['Botnet-C&C.Server', 'Hosting-Bulletproof.Hosting', 'Malicious-Malicious.Server',
  'Phishing-Phishing.Server', 'Proxy-Proxy.Server', 'Spam-Spamming.Server', 'Tor-Exit.Node', 'VPN-Anonymous.VPN'];
const scanners = [
  'BinaryEdge-Scanner', 'Censys-Scanner', 'Palo.Alto.Networks-Cortex.Xpanse.Scanner',
  'Shodan-Scanner', 'Tenable-Tenable.io.Cloud.Scanner',
];
const entry = (policyid, fields = {}) => ({
  policyid, status: 'enable', action: 'accept', srcintf: refs('virtual-wan-link'), dstintf: refs('VL100'),
  dstaddr: refs('web'), srcaddr: refs('all'), schedule: 'always', service: refs('ALL'), ...fields,
});
const block = (policyid, fields) => entry(policyid, {
  action: 'deny', dstaddr: refs('all'), 'match-vip': 'enable', ...fields,
});
const isdbBlock = (policyid, sources, fields) => block(policyid, {
  'internet-service-src': 'enable', 'internet-service-src-name': refs(...sources), ...fields,
});
const exception = (policyid, fields) => entry(policyid, { srcaddr: refs('G_SecurityScanner'), ...fields });

function fixture(overrides = {}) {
  return {
    'cmdb/firewall/policy': [entry(10)],
    'cmdb/firewall/vip': [{ name: 'web', extintf: 'any', type: 'server-load-balance' }],
    'cmdb/firewall/vipgrp': [],
    'cmdb/system/settings': { 'central-nat': 'disable' },
    'cmdb/system/interface': [{ name: 'port7', role: 'lan', vdom: 'branch' }],
    'cmdb/system/zone': [],
    'cmdb/system/sdwan': { status: 'enable', members: [{ interface: 'wan1', zone: 'virtual-wan-link' }] },
    'cmdb/router/static': [],
    'monitor/router/ipv4': [],
    'cmdb/firewall/address': [],
    'cmdb/firewall/addrgrp': [{ name: 'G_SecurityScanner' }],
    'cmdb/system/external-resource': [{ name: 'eworx-IP-Blocklist', type: 'address' }],
    'cmdb/firewall/internet-service-name': [...threats, ...scanners, 'Microsoft-Azure'].map((name, id) => ({
      name, 'internet-service-id': id + 100,
    })),
    'cmdb/firewall/internet-service-group': [],
    ...overrides,
  };
}

async function audit(config = fixture(), version) {
  let feature, modal;
  const calls = [];
  const FP = {
    register: (value) => { feature = value; },
    getVdom: () => 'branch',
    policyList: { tableForPage: () => 'firewall policy' },
    toast: () => {},
    showModal: (value) => { modal = value; },
    requestJson: async (url, options) => {
      const key = url.replace('/api/v2/', '');
      calls.push([key, options]);
      assert.equal(options.vdom, 'branch');
      assert.equal(options.method, undefined);
      assert.equal(options.body, undefined);
      if (config[key] instanceof Error) throw config[key];
      if (typeof config[key] === 'function') return config[key](options.params);
      assert.ok(Object.hasOwn(config, key), key);
      return { status: 'success', results: config[key], version };
    },
  };
  vm.runInNewContext(source, { window: { FortiPlug: FP } });
  assert.ok(feature.isAvailable());
  await feature.run();
  return { ...modal, calls };
}

test('generates four ordered rules for an SD-WAN virtual server and reserves existing IDs', async () => {
  const report = await audit(fixture({ 'cmdb/firewall/policy': [entry(1, { status: 'disable' }), entry(10)] }));
  const cli = report.text;
  assert.match(report.title, /branch.*4 proposed/);
  assert.match(cli, /edit 2\n\s+set name "FP-Inbound-Allow-scanner-2"/);
  assert.match(cli, /set srcintf "virtual-wan-link"/);
  assert.match(cli, /set dstintf "VL100"/);
  assert.match(cli, /set srcaddr "G_SecurityScanner"\n\s+set dstaddr "web"/);
  assert.match(cli, /set srcaddr "eworx-IP-Blocklist"/);
  assert.match(cli, /set internet-service-src-name "Botnet-C&C.Server".*"Spam-Spamming.Server".*"VPN-Anonymous.VPN"/);
  assert.ok(cli.includes('set internet-service-src-name ' + scanners.map((name) => '"' + name + '"').join(' ')));
  assert.equal((cli.match(/set match-vip enable/g) || []).length, 3);
  assert.equal((cli.match(/set dstaddr "all"/g) || []).length, 3);
  assert.doesNotMatch(cli, /set match-vip-only/);
  assert.doesNotMatch(cli, /Microsoft-Azure/);
  assert.match(cli, /move 2 before 10\n\s+move 3 before 10\n\s+move 4 before 10\n\s+move 5 before 10/);
  assert.equal(report.filename, 'fortiplug-inbound-vip-branch.conf');
});

test('accepts existing wildcard VIP denies, ISDB groups and VIP groups in configuration order', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      exception(99, { dstaddr: refs('published') }),
      block(40, { srcaddr: refs('eworx-IP-Blocklist'), dstintf: refs('any') }),
      isdbBlock(30, threats),
      isdbBlock(15, [], { 'internet-service-src-group': refs('FortiGuard scanners') }),
      entry(5, { dstaddr: refs('published') }),
    ],
    'cmdb/firewall/vipgrp': [{ name: 'published', member: refs('web') }],
    'cmdb/firewall/internet-service-group': [{ name: 'FortiGuard scanners', member: refs(...scanners) }],
  }));
  assert.match(report.text, /No missing rules/);
  assert.match(report.title, /0 proposed/);
  assert.equal(report.filename, undefined);
});

test('groups equivalent denies across WAN interfaces, destination interfaces and publish anchors', async () => {
  const wan = refs('port7', 'virtual-wan-link');
  const web = { srcintf: wan, dstintf: refs('VL100'), dstaddr: refs('web') };
  const camera = { srcintf: wan, dstintf: refs('VL900'), dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/system/interface': [{ name: 'port7', role: 'wan', vdom: 'branch' }],
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [exception(66, web), exception(67, camera), entry(10, web), entry(20, camera)],
  }));
  assert.match(report.title, /3 proposed/);
  assert.equal((report.text.match(/set srcintf "port7" "virtual-wan-link"/g) || []).length, 3);
  assert.equal((report.text.match(/set dstintf "VL100" "VL900"/g) || []).length, 3);
  assert.equal((report.text.match(/set dstaddr "all"/g) || []).length, 3);
  assert.equal((report.text.match(/move \d+ before 10/g) || []).length, 3);
});

test('groups VL111 and VL128 by moving a scoped scanner exception before the first publishing rule', async () => {
  const web = { dstintf: refs('VL111') };
  const camera = { dstintf: refs('VL128'), dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [exception(66, web), entry(10, web), exception(67, camera), entry(20, camera)],
  }));
  assert.match(report.title, /4 proposed/);
  assert.equal((report.text.match(/set dstintf "VL111" "VL128"/g) || []).length, 3);
  assert.match(report.text, /move 67 before 10\n\s+move 1 before 10\n\s+move 2 before 10\n\s+move 3 before 10/);
  assert.doesNotMatch(report.text, /set action accept/);
});

test('groups ISDB denies when one interface already has part of the category covered', async () => {
  const camera = { dstintf: refs('VL128'), dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [
      exception(66), exception(67, camera), isdbBlock(90, threats.slice(0, 1), { dstaddr: refs('web') }),
      entry(10), entry(20, camera),
    ],
  }));
  assert.match(report.title, /3 proposed/);
  assert.equal((report.text.match(/set dstintf "VL100" "VL128"/g) || []).length, 3);
  assert.match(report.text, /set internet-service-src-name "Botnet-C&C.Server".*"VPN-Anonymous.VPN"/);
});

test('reports separate denies when a shared anchor would require moving a broader scanner exception', async () => {
  const camera = { dstintf: refs('VL128'), dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [
      exception(66), entry(10), exception(67, { ...camera, srcintf: refs('any') }), entry(20, camera),
    ],
  }));
  assert.match(report.title, /6 proposed/);
  assert.doesNotMatch(report.text, /move 67|set dstintf "VL100" "VL128"/);
  assert.match(report.notes.join(' '), /Separate denies are needed for Blocklist, Threats, Scanners/);
});

test('places a proposed scanner exception above the shared deny anchor', async () => {
  const camera = { dstintf: refs('VL128'), dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [exception(66), entry(10), entry(20, camera)],
  }));
  assert.match(report.title, /4 proposed/);
  assert.equal((report.text.match(/set dstintf "VL100" "VL128"/g) || []).length, 3);
  assert.match(report.text, /set srcaddr "G_SecurityScanner"\n\s+set dstaddr "camera"/);
  assert.match(report.text, /move 1 before 10\n\s+move 2 before 10/);
});

test('keeps denies separate when their interface lists would include a different published VIP path', async () => {
  const web = { srcintf: refs('virtual-wan-link'), dstintf: refs('VL100'), dstaddr: refs('web') };
  const camera = { srcintf: refs('port7'), dstintf: refs('VL900'), dstaddr: refs('camera') };
  const port7Web = { ...web, srcintf: refs('port7') };
  const report = await audit(fixture({
    'cmdb/system/interface': [{ name: 'port7', role: 'wan', vdom: 'branch' }],
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [
      exception(66, web), exception(67, camera), exception(68, port7Web),
      block(90, { ...port7Web, srcaddr: refs('eworx-IP-Blocklist') }),
      isdbBlock(91, threats, port7Web), isdbBlock(92, scanners, port7Web),
      entry(10, web), entry(20, camera), entry(30, port7Web),
    ],
  }));
  assert.match(report.title, /6 proposed/);
  assert.doesNotMatch(report.text, /set srcintf "virtual-wan-link" "port7"|set dstintf "VL100" "VL900"/);
});

test('groups WANs with different VIP bindings because wildcard denies reference no VIP objects', async () => {
  const camera = { srcintf: refs('port7'), dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/system/interface': [{ name: 'port7', role: 'wan', vdom: 'branch' }],
    'cmdb/firewall/vip': [{ name: 'web', extintf: 'virtual-wan-link' }, { name: 'camera', extintf: 'port7' }],
    'cmdb/firewall/policy': [exception(66), exception(67, camera), entry(10), entry(20, camera)],
  }));
  assert.match(report.title, /3 proposed/);
  assert.equal((report.text.match(/set srcintf "virtual-wan-link" "port7"/g) || []).length, 3);
  assert.doesNotMatch(report.text, /set dstaddr "(?:web|camera)"/);
});

test('keeps an early deny VIP-specific when a later scanner exception shares the interface pair', async () => {
  const camera = { dstaddr: refs('camera') };
  const report = await audit(fixture({
    'cmdb/firewall/vip': ['web', 'camera'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [exception(66), entry(10), exception(67, { ...camera, srcintf: refs('any') }), entry(20, camera)],
  }));
  assert.equal((report.text.match(/set dstaddr "web"/g) || []).length, 3);
  assert.equal((report.text.match(/set dstaddr "all"/g) || []).length, 3);
  assert.doesNotMatch(report.text, /set match-vip-only/);
  assert.match(report.notes.join(' '), /precede a scanner exception/);
});

test('recognizes wildcard denies for a new port forward added below them', async () => {
  const future = { dstaddr: refs('new-port-forward') };
  const report = await audit(fixture({
    'cmdb/firewall/vip': ['web', 'new-port-forward'].map((name) => ({ name, extintf: 'any' })),
    'cmdb/firewall/policy': [
      exception(66),
      block(58, { srcaddr: refs('eworx-IP-Blocklist') }),
      isdbBlock(57, scanners),
      isdbBlock(59, threats),
      entry(10),
      entry(11, future),
    ],
  }));
  assert.match(report.title, /1 proposed/);
  assert.match(report.text, /set srcaddr "G_SecurityScanner"\n\s+set dstaddr "new-port-forward"/);
  assert.doesNotMatch(report.text, /set action deny/);
});

test('repairs a late exception and partial, disabled and shadowed denies', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      block(90, { srcaddr: refs('eworx-IP-Blocklist'), 'match-vip': 'disable', service: refs('HTTPS') }),
      isdbBlock(41, [], { dstaddr: refs('web'), 'internet-service-src-id': [{ id: 100 + threats.length }] }),
      isdbBlock(50, scanners, { status: 'disable', service: refs('HTTPS') }),
      entry(20),
      exception(8),
      isdbBlock(12, threats),
    ],
  }));
  assert.match(report.text, /move 1 before 41/);
  assert.match(report.text, /move 2 before 20/);
  assert.ok(report.text.includes('set internet-service-src-name ' + scanners.slice(1).map((name) => '"' + name + '"').join(' ')));
  assert.doesNotMatch(report.text, /BinaryEdge-Scanner/);
});

test('retains wildcard denies and reports catalog additions without creating per-VIP copies', async () => {
  const egress = { dstintf: refs('_default') };
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      exception(66, { ...egress, dstaddr: refs('EX2019_HTTP', 'WEBSHOP-HTTPS') }),
      block(58, { ...egress, 'match-vip': undefined, srcaddr: [{ q_origin_key: 'eworx-IP-Blocklist' }] }),
      isdbBlock(57, scanners.slice(0, 2), egress),
      isdbBlock(59, threats.filter((name) => !name.startsWith('Hosting-') && name !== 'Spam-Spamming.Server'), egress),
      entry(30, { ...egress, dstaddr: refs('EX2019_HTTP') }),
      entry(40, { ...egress, dstaddr: refs('WEBSHOP-HTTPS') }),
    ],
    'cmdb/firewall/vip': ['EX2019_HTTP', 'WEBSHOP-HTTPS'].map((name) => ({ name, extintf: 'any' })),
  }), 'v7.6.5');
  assert.match(report.title, /0 proposed/);
  assert.match(report.text, /existing deny #59 omits these ISDB entries: Hosting-Bulletproof.Hosting, Spam-Spamming.Server/);
  assert.match(report.text, /existing deny #57 omits these ISDB entries: Palo\.Alto\.Networks-Cortex\.Xpanse\.Scanner, Shodan-Scanner, Tenable-Tenable\.io\.Cloud\.Scanner/);
  assert.doesNotMatch(report.text, /Blocklist|config firewall policy/);
  assert.equal(report.filename, undefined);
});

test('enables VIP matching once on policy 58 when it is explicitly disabled or defaults off', async () => {
  for (const [matchVip, version] of [['disable', 'v7.6.5'], [undefined, 'v7.2.3']]) {
    const destinations = refs('web', 'mail');
    const egress = { dstintf: refs('_default') };
    const report = await audit(fixture({
      'cmdb/firewall/policy': [
        exception(66, { ...egress, dstaddr: destinations }),
        block(58, { ...egress, 'match-vip': matchVip, srcaddr: refs('eworx-IP-Blocklist'), 'logtraffic-start': 'enable' }),
        isdbBlock(57, scanners, egress),
        isdbBlock(59, threats, egress),
        entry(30, { ...egress, dstaddr: destinations }),
      ],
      'cmdb/firewall/vip': ['web', 'mail'].map((name) => ({ name, extintf: 'any' })),
    }), version);
    assert.match(report.title, /1 proposed/);
    assert.equal(report.text, 'config firewall policy\n    edit 58\n        set match-vip enable\n    next\nend\n');
    assert.match(report.findings, /Policy #58 — enable match-vip/);
  }
});

test('positions a missing scanner exception before an existing ISDB deny that will get match-vip', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      isdbBlock(57, scanners, { 'match-vip': 'disable' }),
      exception(66),
      block(58, { srcaddr: refs('eworx-IP-Blocklist') }),
      isdbBlock(59, threats),
      entry(30),
    ],
  }));
  assert.match(report.title, /2 proposed/);
  assert.match(report.text, /move 1 before 57\n    edit 57\n        set match-vip enable/);
  assert.doesNotMatch(report.text, /set internet-service-src-name/);
});

test('re-enables the wildcard AXIS threat deny once and enables match-vip when needed', async () => {
  const axes = ['TCP8082-AXIS-CAM', 'TCP8086-AXIS-CAM', 'TCP8087-AXIS-CAM'];
  const egress = { dstintf: refs('VL900') };
  for (const matchVip of ['disable', 'enable']) {
    const report = await audit(fixture({
      'cmdb/firewall/policy': [
        exception(255, { ...egress, dstaddr: refs(...axes) }),
        isdbBlock(129, threats.slice(0, -1), { ...egress, status: 'disable', 'match-vip': matchVip }),
        isdbBlock(128, scanners, egress),
        block(237, { ...egress, srcaddr: refs('eworx-IP-Blocklist') }),
        entry(103, { ...egress, dstaddr: refs(...axes), service: refs('HTTP') }),
      ],
      'cmdb/firewall/vip': axes.map((name) => ({ name, extintf: 'any' })),
    }));
    const matching = matchVip === 'disable' ? '        set match-vip enable\n' : '';
    assert.equal(report.text, 'config firewall policy\n    edit 129\n' + matching + '        set status enable\n    next\nend\n');
    assert.match(report.title, /1 proposed/);
    assert.match(report.findings, /Policy #129 — re-enable deny/);
    assert.match(report.findings, /existing deny #129 omits these ISDB entries: VPN-Anonymous.VPN/);
  }
});

test('re-enables an explicit VIP deny without adding wildcard VIP matching', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      exception(66),
      block(58, { srcaddr: refs('eworx-IP-Blocklist'), dstaddr: refs('web'), status: 'disable', 'match-vip': 'disable' }),
      isdbBlock(57, scanners),
      isdbBlock(59, threats),
      entry(30),
    ],
  }));
  assert.equal(report.text, 'config firewall policy\n    edit 58\n        set status enable\n    next\nend\n');
});

test('creates a deny before publication when enabling match-vip on a later rule would not close the gap', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      exception(66),
      isdbBlock(57, scanners),
      isdbBlock(59, threats),
      entry(30),
      block(58, { status: 'disable', 'match-vip': 'disable', srcaddr: refs('eworx-IP-Blocklist') }),
    ],
  }));
  assert.match(report.title, /1 proposed/);
  assert.match(report.text, /set srcaddr "eworx-IP-Blocklist"/);
  assert.match(report.text, /move 1 before 30/);
  assert.doesNotMatch(report.text, /edit 58/);
});

test('finds a WAN on an arbitrary port via a default route and flags unreferenced VIPs', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [entry(10, { srcintf: refs('any'), dstintf: refs('dmz') })],
    'cmdb/firewall/vip': [{ name: 'web', extintf: 'port7' }, { name: 'unpublished', extintf: 'port7' }],
    'cmdb/system/sdwan': { status: 'disable' },
    'cmdb/router/static': [{ dst: '0.0.0.0 0.0.0.0', device: 'port7' }],
  }));
  assert.match(report.text, /set srcintf "port7"\n\s+set dstintf "dmz"/);
  assert.doesNotMatch(report.text, /unpublished/);
  assert.match(report.findings, /without a verified inbound policy path\n\s+unpublished/);
});

test('uses active default routes and respects VIP source-interface filters', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [entry(10, { srcintf: refs('any') })],
    'cmdb/firewall/vip': [{ name: 'web', extintf: 'any', 'srcintf-filter': refs('port8') }],
    'cmdb/system/sdwan': { status: 'disable' },
    'monitor/router/ipv4': [
      { ip_mask: '0.0.0.0/0', interface: 'port8' },
      { ip_mask: '0.0.0.0/0', interface: 'port9' },
    ],
  }));
  assert.match(report.text, /set srcintf "port8"/);
  assert.doesNotMatch(report.text, /port9/);
});

test('reports unavailable objects and ISDB reads without emitting unknown references', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/addrgrp': [],
    'cmdb/firewall/internet-service-name': new Error('HTTP 403'),
  }));
  assert.match(report.notes.join(' '), /Required source object unavailable: G_SecurityScanner/);
  assert.match(report.notes.join(' '), /ISDB categories unavailable/);
  assert.match(report.text, /set srcaddr "eworx-IP-Blocklist"/);
  assert.doesNotMatch(report.text, /G_SecurityScanner|internet-service-src-name/);
});

test('reads remaining policy pages before reserving IDs and refuses an incomplete sequence', async () => {
  const policies = ({ start }) => start === 1 ?
    { status: 'success', results: [entry(1, { status: 'disable' })], matched_count: 2 } :
    { status: 'success', results: [entry(10)], limit_reached: true, next_idx: 1 };
  const report = await audit(fixture({ 'cmdb/firewall/policy': policies }));
  assert.match(report.text, /edit 2\n/);
  await assert.rejects(audit(fixture({
    'cmdb/firewall/policy': () => ({ status: 'success', results: [entry(10)], limit_reached: true }),
  })), /Could not read required configuration/);
});

test('reports central NAT without generating policy-based VIP commands', async () => {
  const report = await audit(fixture({ 'cmdb/system/settings': { 'central-nat': 'enable' } }));
  assert.match(report.text, /requires the standard IPv4 firewall policy table/);
  assert.equal(report.filename, undefined);
});
