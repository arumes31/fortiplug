'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const source = ['../src/policy-audit.js', '../src/features/dos-policy-check.js']
  .map((file) => fs.readFileSync(path.join(__dirname, file), 'utf8')).join('\n');
const refs = (...values) => values.map((name) => ({ name }));

function fixture(overrides = {}) {
  return {
    'cmdb/firewall/DoS-policy': [],
    'cmdb/system/interface': [{ name: 'wan1', role: 'wan' }, { name: 'wan2', role: 'wan' }],
    'cmdb/system/zone': [],
    'cmdb/system/sdwan': { status: 'disable' },
    'cmdb/router/static': [],
    'monitor/router/ipv4': [],
    'cmdb/firewall/address': [],
    'cmdb/firewall/addrgrp': refs('G_SecurityScanner', 'G_MSTeams'),
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
  assert.equal(feature.label, 'DoS Policy Check');
  await feature.run();
  return modal;
}

// Emulate creation in reverse order, then apply CLI moves as FortiOS list moves.
function replay(cli, original = []) {
  const policies = structuredClone(original);
  const byId = (id) => policies.find((entry) => entry.policyid === Number(id));
  let policy, anomaly, inAnomalies = false;
  for (const raw of cli.split('\n')) {
    const line = raw.trim();
    if (line === 'config anomaly') inAnomalies = true;
    else if (line === 'end') inAnomalies = false;
    else if (line.startsWith('edit ')) {
      const value = line.slice(5).replace(/^"|"$/g, '');
      if (inAnomalies) {
        policy.anomaly ||= [];
        anomaly = policy.anomaly.find((entry) => entry.name === value);
        if (!anomaly) {
          anomaly = { name: value };
          policy.anomaly.push(anomaly);
        }
      } else {
        policy = byId(value);
        if (!policy) {
          policy = { policyid: Number(value) };
          policies.unshift(policy);
        }
      }
    } else if (line.startsWith('set ')) {
      const [, key, value] = /^set (\S+) (.*)$/.exec(line);
      (inAnomalies ? anomaly : policy)[key] = value.replace(/^"|"$/g, '');
    } else if (line.startsWith('move ')) {
      const [, id, direction, anchor] = line.split(' ');
      const moving = byId(id);
      policies.splice(policies.indexOf(moving), 1);
      policies.splice(policies.indexOf(byId(anchor)) + Number(direction === 'after'), 0, moving);
    }
  }
  return policies;
}

test('generates three ordered policies per physical WAN with the requested profiles', async () => {
  const report = await audit(fixture());
  assert.equal(report.filename, 'fortiplug-dos-branch.conf');
  const policies = replay(report.text);
  assert.equal(policies.length, 6);
  for (const intf of ['wan1', 'wan2']) {
    const [scanner, teams, fallback] = policies.filter((policy) => policy.interface === intf);
    assert.deepEqual([scanner.srcaddr, teams.srcaddr, fallback.srcaddr], ['G_SecurityScanner', 'G_MSTeams', 'all']);
    assert.equal(scanner.anomaly.length, 18);
    assert.ok(scanner.anomaly.every((anomaly) => anomaly.status === 'disable' && anomaly.log === 'disable'));
    for (const [policy, expiry] of [[teams, '2m'], [fallback, '1d']]) {
      const byName = new Map(policy.anomaly.map((anomaly) => [anomaly.name, anomaly]));
      assert.equal(byName.get('tcp_syn_flood').action, 'block');
      assert.equal(byName.get('tcp_syn_flood')['quarantine-expiry'], expiry);
      assert.equal(byName.get('tcp_src_session').threshold, '1000');
      assert.equal(byName.get('ip_src_session').action, 'pass');
      assert.equal(byName.get('ip_src_session').quarantine, 'attacker');
      assert.equal(byName.get('udp_flood').threshold, '5000');
      assert.equal(byName.get('udp_flood').action, 'pass');
      assert.equal(byName.get('tcp_dst_session').status, 'disable');
      assert.equal(byName.get('icmp_sweep').threshold, '100');
    }
  }
  assert.equal(new Set(policies.map((policy) => policy.name)).size, 6);
  const repeated = await audit(fixture({ 'cmdb/firewall/DoS-policy': policies }));
  assert.equal(repeated.text, 'No DoS policy changes found.');
});

test('checks only virtual-wan-link with default SD-WAN enabled and fixes a wrongly ordered policy', async () => {
  const config = fixture({
    'cmdb/system/sdwan': { status: 'enable', members: [{ interface: 'wan1', zone: 'virtual-wan-link' }] },
  });
  const initial = await audit(config);
  assert.doesNotMatch(initial.text, /set interface "wan[12]"/);
  const [scanner, teams, fallback] = replay(initial.text);
  scanner.anomaly[0].status = 'enable';
  teams.status = 'disable';
  const wrongOrder = [fallback, teams, scanner];
  const report = await audit({ ...config, 'cmdb/firewall/DoS-policy': wrongOrder });
  assert.doesNotMatch(report.text, /set interface|set name/);
  assert.match(report.text, /set status disable/);
  assert.match(report.text, /set status enable/);
  assert.match(report.text, /move \d+ before \d+/);
  const fixed = replay(report.text, wrongOrder);
  assert.deepEqual(fixed.map((policy) => policy.srcaddr), ['G_SecurityScanner', 'G_MSTeams', 'all']);
  assert.equal((await audit({ ...config, 'cmdb/firewall/DoS-policy': fixed })).text, 'No DoS policy changes found.');
});

test('reports an unavailable scanner object and still creates Teams and Default in order', async () => {
  const report = await audit(fixture({
    'cmdb/system/interface': [{ name: 'wan1', role: 'wan' }],
    'cmdb/firewall/addrgrp': refs('G_MSTeams'),
  }));
  assert.match(report.findings, /source object unavailable: G_SecurityScanner/);
  assert.doesNotMatch(report.text, /G_SecurityScanner/);
  assert.deepEqual(replay(report.text).map((policy) => policy.srcaddr), ['G_MSTeams', 'all']);
});

test('uses the INTERNET zone for its WAN member alongside an unrelated SD-WAN zone', async () => {
  const config = fixture({
    'cmdb/system/zone': [{ name: 'INTERNET', interface: [{ name: 'WAN uplink', 'interface-name': 'wan2' }] }],
    'cmdb/system/sdwan': { status: 'enable', members: [{ interface: 'wan1', zone: 'virtual-wan-link' }] },
  });
  const report = await audit(config);
  const policies = replay(report.text);
  assert.equal(policies.filter((policy) => policy.interface === 'INTERNET').length, 3);
  assert.equal(policies.filter((policy) => policy.interface === 'virtual-wan-link').length, 3);
  assert.doesNotMatch(report.text, /set interface "wan[12]"/);
  assert.equal((await audit({ ...config, 'cmdb/firewall/DoS-policy': policies })).text, 'No DoS policy changes found.');
});

test('does not reuse member-port DoS rules or generate a policy for a disabled SD-WAN member', async () => {
  const report = await audit(fixture({
    'cmdb/system/sdwan': { status: 'enable', members: [
      { interface: 'wan1', zone: 'virtual-wan-link' },
      { interface: 'wan2', zone: 'virtual-wan-link', status: 'disable' },
    ] },
    'cmdb/firewall/DoS-policy': [
      { policyid: 15, interface: 'wan2', srcaddr: refs('all'), dstaddr: refs('all'), service: refs('ALL') },
    ],
  }));
  const policies = replay(report.text);
  assert.equal(policies.length, 3);
  assert.ok(policies.every((policy) => policy.interface === 'virtual-wan-link'));
  assert.doesNotMatch(report.text, /set interface "wan[12]"|edit 15\b/);
});

test('uses a zone for its member and keeps a standalone WAN interface when SD-WAN is disabled', async () => {
  const report = await audit(fixture({
    'cmdb/system/zone': [{ name: 'INTERNET', interface: refs('wan1') }],
  }));
  const interfaces = replay(report.text).map((policy) => policy.interface).sort();
  assert.deepEqual(interfaces, ['INTERNET', 'INTERNET', 'INTERNET', 'wan2', 'wan2', 'wan2']);
});
