'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = ['../src/policy-audit.js', '../src/features/outbound-policy-check.js']
  .map((file) => fs.readFileSync(path.join(__dirname, file), 'utf8')).join('\n');
const refs = (...names) => names.map((name) => ({ name }));
const directory = ['LDAP_UDP', 'LDAPS', 'LDAP', 'KERBEROS', 'Kerberos Password'];
const threats = [
  'Botnet-C&C.Server', 'Hosting-Bulletproof.Hosting', 'Phishing-Phishing.Server', 'Proxy-Proxy.Server', 'Spam-Spamming.Server',
  'Tor-Exit.Node', 'Tor-Relay.Node', 'Tor-Tor.Node', 'Malicious-Malicious.Server',
];
const blocklist = 'eworx-IP-Blocklist';
const rule = (policyid, fields = {}) => ({
  policyid, action: 'accept', status: 'enable', schedule: 'always', srcintf: refs('VL100'),
  dstintf: refs('virtual-wan-link'), srcaddr: refs('all'), dstaddr: refs('all'), service: refs('ALL'), ...fields,
});
const deny = (policyid, fields = {}) => rule(policyid, { action: 'deny', ...fields });

function fixture(overrides = {}) {
  return {
    'cmdb/firewall/policy': [rule(40)],
    'cmdb/system/settings': { 'ngfw-mode': 'profile-based' },
    'cmdb/system/interface': [{ name: 'VL100', role: 'lan', vdom: 'branch' }],
    'cmdb/wireless-controller/vap': [],
    'cmdb/system/zone': [],
    'cmdb/system/sdwan': { status: 'enable', members: [{ interface: 'x9', zone: 'virtual-wan-link' }] },
    'cmdb/router/static': [],
    'monitor/router/ipv4': [],
    'cmdb/system/virtual-switch': [],
    'cmdb/system/switch-interface': [],
    'cmdb/firewall.service/custom': refs('SMB', ...directory),
    'cmdb/firewall.service/group': [],
    'cmdb/firewall/address': [],
    'cmdb/firewall/addrgrp': [],
    'cmdb/system/external-resource': [{ name: blocklist, type: 'address' }],
    'cmdb/firewall/internet-service-name': [...threats, 'Microsoft-Azure'].map((name, id) => ({
      name, 'internet-service-id': id + 100, direction: 'both',
    })),
    'cmdb/firewall/internet-service-group': [],
    ...overrides,
  };
}

async function audit(config) {
  let feature, modal;
  const FP = {
    register: (value) => { feature = value; },
    getVdom: () => 'branch',
    policyList: { tableForPage: () => 'firewall policy' },
    toast: () => {},
    showModal: (value) => { modal = value; },
    requestJson: async (url, options) => {
      const key = url.replace('/api/v2/', '');
      assert.equal(options.vdom, 'branch');
      assert.equal(options.method, undefined);
      assert.equal(options.body, undefined);
      assert.ok(Object.hasOwn(config, key), key);
      return { status: 'success', results: config[key] };
    },
  };
  vm.runInNewContext(source, { window: { FortiPlug: FP } });
  assert.ok(feature.isAvailable());
  assert.equal(feature.label, 'Check Outbound Policies');
  await feature.run();
  return modal;
}

test('excludes ignored interfaces from outbound discovery and leaves mixed-scope denies alone', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': [{ name: 'VL100', role: 'lan' }, { name: 'LB-EXADM', role: 'dmz' }],
    'cmdb/system/zone': [{ name: 'ADMIN-ZONE', interface: refs('LB-EXADM') }],
    'cmdb/router/static': ['SYSLOG-IF', 'LB-DNS'].map((device) => ({ dst: '0.0.0.0/0', device })),
    'cmdb/firewall/policy': [
      rule(30, { srcintf: refs('SYSLOG-IF', 'ADMIN-ZONE', 'LB-SSLVPN-DNS') }), rule(40),
      deny(41, { srcintf: refs('VL100', 'LB-EXADM'), status: 'disable', service: refs('SMB') }),
    ],
  }));
  assert.match(report.title, /4 proposed/);
  assert.match(report.text, /set srcintf "VL100"/);
  assert.match(report.text, /set dstintf "virtual-wan-link"/);
  assert.doesNotMatch(report.text, /LB-EXADM|SYSLOG-IF|ADMIN-ZONE|LB-SSLVPN-DNS|LB-DNS|edit 41\b|move 41\b/);
});

test('includes tunnel-mode SSIDs in outbound rules and skips bridge and mesh SSIDs', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': ['VL100', 'wifi-bridge', 'wifi-tunnel'].map((name) => ({ name, role: 'lan' })),
    'cmdb/firewall/policy': [rule(40, { srcintf: refs('VL100', 'wifi-mesh') })],
    'cmdb/wireless-controller/vap': [
      { name: 'wifi-bridge', 'local-bridging': 'enable' },
      { name: 'wifi-mesh', 'mesh-backhaul': 'enable' },
      { name: 'wifi-tunnel', 'local-bridging': 'disable', 'mesh-backhaul': 'disable', 'split-tunneling': 'enable' },
    ],
  }));
  assert.equal(report.notes[0], '2 internal-to-WAN interface pair(s) checked.');
  assert.match(report.text, /set srcintf "VL100" "wifi-tunnel"/);
  assert.doesNotMatch(report.text, /wifi-bridge|wifi-mesh/);
});

test('uses the configured WAN and omits runtime PPPoE interface names from outbound CLI', async () => {
  const report = await audit(fixture({
    'cmdb/system/sdwan': { status: 'disable' },
    'cmdb/system/interface': [{ name: 'VL100', role: 'lan' }, { name: 'wan', role: 'wan', mode: 'pppoe' }],
    'cmdb/firewall/policy': [rule(24, { dstintf: refs('wan') })],
    'monitor/router/ipv4': [{ ip_mask: '0.0.0.0/0', interface: 'ppp2' }],
  }));
  assert.equal(report.notes[0], '1 internal-to-WAN interface pair(s) checked.');
  assert.equal((report.text.match(/set dstintf "wan"\n/g) || []).length, 4);
  assert.doesNotMatch(report.text, /ppp2/);
  assert.match(report.text, /move \d+ before 24/);
});

test('generates the four baselines and groups VLANs, zones and WANs into multi-interface rules', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      rule(1, { status: 'disable' }),
      rule(40, { srcintf: refs('VL100', 'guest'), dstintf: refs('virtual-wan-link', 'port7') }),
      rule(41, { srcintf: refs('virtual-wan-link'), dstintf: refs('VL100') }),
    ],
    'cmdb/system/interface': [
      { name: 'VL100', role: 'lan', vdom: 'branch' }, { name: 'VL128', role: 'lan', vdom: 'branch' },
      { name: 'OTHER', role: 'lan', vdom: 'other' }, { name: 'x9', role: 'wan', vdom: 'branch' },
    ],
    'cmdb/system/zone': [{ name: 'servers', interface: [{ 'interface-name': 'VL128' }] }],
    'cmdb/router/static': [{ dst: '0.0.0.0 0.0.0.0', device: 'port7' }],
  }));
  assert.match(report.title, /4 proposed/);
  assert.equal(report.filename, 'fortiplug-outbound-branch.conf');
  assert.equal((report.text.match(/set srcintf "VL100" "guest" "servers"/g) || []).length, 4);
  assert.equal((report.text.match(/set dstintf "port7" "virtual-wan-link"/g) || []).length, 4);
  assert.match(report.text, /set dstaddr "all"\n\s+set service "SMB"/);
  assert.match(report.text, /set service "KERBEROS" "Kerberos Password" "LDAP" "LDAPS" "LDAP_UDP"/);
  assert.match(report.text, /set internet-service enable\n\s+set internet-service-name .*"Hosting-Bulletproof.Hosting".*"Spam-Spamming.Server"/);
  assert.match(report.text, /set dstaddr "eworx-IP-Blocklist"\n\s+set service "ALL"/);
  assert.equal((report.text.match(/"Tor-Relay.Node"/g) || []).length, 1);
  assert.match(report.text, /move 2 before 1\n\s+move 3 before 1\n\s+move 4 before 1\n\s+move 5 before 1/);
  assert.doesNotMatch(report.text, /Microsoft-Azure|internet-service-src|set match-vip|OTHER|x9/);
});

test('counts enabled cover before the accept through service groups, ISDB groups and destination address groups', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      deny(50, { service: refs('DirectoryAndSMB') }),
      deny(51, { 'internet-service': 'enable', 'internet-service-group': refs('ThreatGroup'),
        'internet-service-id': [{ id: 100 }] }),
      deny(52, { dstaddr: refs('Feeds') }),
      rule(40),
    ],
    'cmdb/firewall.service/group': [{ name: 'DirectoryAndSMB', member: refs('SMB', ...directory) }],
    'cmdb/firewall/internet-service-group': [{ name: 'ThreatGroup', member: refs(...threats.slice(1)) }],
    'cmdb/firewall/addrgrp': [{ name: 'Feeds', member: refs(blocklist) }],
  }));
  assert.match(report.title, /0 proposed/);
  assert.equal(report.text, 'No missing outbound rules found.');
});

test('moves and re-enables matching denies and fills remaining coverage before a narrower deny', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      deny(55, { status: 'disable', service: refs('SMB') }),
      deny(56, { srcaddr: refs('LAN_Internal-Server'), dstaddr: refs(blocklist) }),
      deny(57, { 'internet-service': 'enable',
        'internet-service-name': refs(...threats.filter((name) => name !== 'Hosting-Bulletproof.Hosting')) }),
      rule(40),
      deny(58, { status: 'disable', service: refs(...directory) }),
    ],
  }));
  assert.match(report.title, /5 proposed/);
  assert.match(report.text, /edit 55\n\s+set status enable/);
  assert.doesNotMatch(report.text, /FP-Outbound-SMB|FP-Outbound-Directory|edit 56/);
  assert.match(report.text, /set internet-service-name "Hosting-Bulletproof.Hosting"\n/);
  assert.match(report.text, /set dstaddr "eworx-IP-Blocklist"/);
  assert.match(report.text, /move 57 before 56\n\s+move 58 before 56\n\s+move 1 before 56\n\s+move 2 before 56/);
  assert.match(report.text, /edit 58\n\s+set status enable/);
});

test('emits move-only CLI for existing outbound blocks below the first policy on their interface pair', async () => {
  const report = await audit(fixture({
    'cmdb/firewall/policy': [
      rule(70, { srcintf: refs('virtual-wan-link'), dstintf: refs('VL100') }),
      deny(75, { service: refs('SMB'), srcaddr: refs('OneHost') }),
      deny(50, { service: refs('SMB', ...directory) }),
      deny(51, { 'internet-service': 'enable', 'internet-service-name': refs(...threats) }),
      deny(52, { dstaddr: refs(blocklist) }),
      rule(40),
    ],
  }));
  assert.match(report.title, /3 proposed/);
  assert.equal(report.text, 'config firewall policy\n    move 50 before 75\n    move 51 before 75\n    move 52 before 75\nend\n');
});

test('separates WANs with different source gaps to avoid crossing already covered interface pairs', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': refs('VL100', 'VL128').map(({ name }) => ({ name, role: 'lan' })),
    'cmdb/router/static': [{ dst: '0.0.0.0/0', device: 'port7' }],
    'cmdb/firewall/policy': [
      deny(50, { srcintf: refs('VL128'), dstintf: refs('virtual-wan-link') }),
      deny(51, { srcintf: refs('VL100'), dstintf: refs('port7') }),
      rule(40, { srcintf: refs('VL100', 'VL128'), dstintf: refs('port7', 'virtual-wan-link') }),
    ],
  }));
  assert.match(report.title, /8 proposed/);
  assert.equal((report.text.match(/set srcintf "VL128"\n\s+set dstintf "port7"/g) || []).length, 4);
  assert.equal((report.text.match(/set srcintf "VL100"\n\s+set dstintf "virtual-wan-link"/g) || []).length, 4);
});

test('uses the SD-WAN uplink zone and excludes a private tunnel overlay', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': [
      { name: 'VL100', role: 'lan' },
      { name: 'port7', type: 'physical' },
      { name: 'branch-ipsec', type: 'tunnel' },
    ],
    'cmdb/system/sdwan': { status: 'enable', members: [
      { interface: 'port7', zone: 'Internet' },
      { interface: 'branch-ipsec', zone: 'Private' },
    ] },
    'cmdb/firewall/policy': [rule(40, { dstintf: refs('Private') }), rule(41, { dstintf: refs('Internet') })],
  }));
  assert.match(report.title, /4 proposed/);
  assert.equal((report.text.match(/set dstintf "Internet"/g) || []).length, 4);
  assert.equal((report.text.match(/move \d+ before 41/g) || []).length, 4);
  assert.doesNotMatch(report.text, /Private|port7|branch-ipsec/);
});

test('excludes ssl.root even when it has a LAN role and an outbound allow', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': [{ name: 'VL100', role: 'lan' }, { name: 'ssl.root', role: 'lan' }],
    'cmdb/router/static': [{ dst: '0.0.0.0/0', device: 'ssl.root' }],
    'cmdb/firewall/policy': [rule(30, { srcintf: refs('ssl.root') }), rule(40)],
  }));
  assert.match(report.notes.join(' '), /1 internal-to-WAN interface pair/);
  assert.equal((report.text.match(/set srcintf "VL100"/g) || []).length, 4);
  assert.doesNotMatch(report.text + report.findings, /ssl\.root|before 30/);
});

test('groups WAN zone members into one INTERNET destination and uses existing zone rules for ordering', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': [
      { name: 'VL100', role: 'lan' }, { name: 'wan1', role: 'wan' }, { name: 'wan2', role: 'wan' },
    ],
    'cmdb/system/sdwan': { status: 'disable' },
    'cmdb/system/zone': [{ name: 'INTERNET', interface: [
      { name: 'A1', 'interface-name': 'wan1' }, { name: 'A2', 'interface-name': 'wan2' },
    ] }],
    'cmdb/firewall/policy': [rule(40, { dstintf: refs('INTERNET') })],
  }));
  assert.match(report.title, /4 proposed/);
  assert.equal((report.text.match(/set dstintf "INTERNET"/g) || []).length, 4);
  assert.equal((report.text.match(/move \d+ before 40/g) || []).length, 4);
  assert.doesNotMatch(report.text, /set dstintf "wan[12]"/);
});

test('uses zone-only outbound policies even when the input policies still reference member ports', async () => {
  const members = { srcintf: refs('VL100'), dstintf: refs('port7') };
  const report = await audit(fixture({
    'cmdb/system/interface': [],
    'cmdb/system/sdwan': { status: 'disable' },
    'cmdb/router/static': [{ dst: '0.0.0.0/0', device: 'port7' }],
    'cmdb/system/zone': [
      { name: 'INTERNET', interface: refs('port7') }, { name: 'SERVERS', interface: refs('VL100') },
    ],
    'cmdb/firewall/policy': [deny(39, { ...members, service: refs('SMB') }), rule(40, members)],
  }));
  assert.match(report.title, /4 proposed/);
  assert.equal((report.text.match(/set srcintf "SERVERS"\n\s+set dstintf "INTERNET"/g) || []).length, 4);
  assert.doesNotMatch(report.text, /"port7"|"VL100"|edit 39\b/);
});

test('groups a WAN zone with a standalone WAN without including the zone member', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': [
      { name: 'VL100', role: 'lan' }, { name: 'wan1', role: 'wan' }, { name: 'wan2', role: 'wan' },
    ],
    'cmdb/system/sdwan': { status: 'disable' },
    'cmdb/system/zone': [{ name: 'INTERNET', interface: refs('wan1') }],
    'cmdb/firewall/policy': [rule(40, { dstintf: refs('INTERNET', 'wan2') })],
  }));
  assert.equal((report.text.match(/set dstintf "INTERNET" "wan2"/g) || []).length, 4);
  assert.doesNotMatch(report.text, /"wan1"/);
});

test('lists missing service and destination objects and omits unresolved references from CLI', async () => {
  const report = await audit(fixture({
    'cmdb/firewall.service/custom': refs('SMB', ...directory.slice(0, -1)),
    'cmdb/system/external-resource': [],
    'cmdb/firewall/internet-service-name': refs(...threats.slice(1)),
  }));
  assert.match(report.notes.join(' '), /Required objects unavailable: Kerberos Password, Botnet-C&C.Server, eworx-IP-Blocklist/);
  assert.doesNotMatch(report.text, /Kerberos Password|Botnet-C&C.Server|eworx-IP-Blocklist/);
  assert.match(report.text, /set service "SMB"/);
});
