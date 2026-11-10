const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const { test } = require('node:test');

const flush = () => new Promise((r) => setImmediate(r));

const load = (context, files) => {
  for (const file of files) vm.runInContext(fs.readFileSync(path.join(__dirname, '..', file), 'utf8'), context);
};

// Minimal DOM stand-ins: enough for the launcher, its menu and the shortcut listener.
class Node {
  constructor(tag = 'div') {
    this.tagName = tag.toUpperCase();
    this.children = [];
    this.classList = { add() {}, remove() {} };
    this.style = {};
  }
  append(...c) { this.children.push(...c); }
  appendChild(c) { this.children.push(c); return c; }
  remove() { this.removed = true; }
  querySelector(selector) {
    const cls = selector.replace(/^\./, '');
    const walk = (n) => n.children.find((c) => c.className === cls) || n.children.map(walk).find(Boolean);
    return walk(this) || null;
  }
}

function coreContext() {
  const listeners = {};
  let shadowMode;
  const document = {
    documentElement: new Node('html'),
    createElement: (tag) => {
      const n = new Node(tag);
      n.attachShadow = ({ mode }) => {
        shadowMode = mode;
        const s = new Node('#shadow');
        s.host = n;
        return s;
      };
      return n;
    },
    addEventListener: (type, fn) => { (listeners[type] ||= []).push(fn); },
  };
  const context = vm.createContext({ window: {}, document, console, location: { origin: 'https://fgt.test' } });
  load(context, ['src/core.js']);
  const FP = context.window.FortiPlug;
  let runs = 0;
  FP.register({ id: 'x', label: 'X', run: async () => { runs++; }, shortcut: { key: 'c', altKey: true, shiftKey: true } });
  FP.mountLauncher();
  const shadow = FP.root();
  return { FP, shadow, listeners, runs: () => runs, shadowMode: () => shadowMode };
}

const key = (isTrusted) => ({
  isTrusted, key: 'C', altKey: true, shiftKey: true, ctrlKey: false, preventDefault() {}, stopPropagation() {},
});

test('UI shadow root is closed to page script', () => {
  assert.equal(coreContext().shadowMode(), 'closed');
});

test('synthetic keyboard shortcuts are ignored, real ones run the feature', async () => {
  const c = coreContext();
  for (const fn of c.listeners.keydown) fn(key(false));
  await flush();
  assert.equal(c.runs(), 0);
  for (const fn of c.listeners.keydown) fn(key(true));
  await flush();
  assert.equal(c.runs(), 1);
});

test('synthetic launcher and menu clicks are ignored', async () => {
  const c = coreContext();
  const launcher = c.shadow.querySelector('.launcher');
  launcher.onclick({ isTrusted: false });
  assert.equal(c.shadow.querySelector('.menu'), null);
  launcher.onclick({ isTrusted: true });
  const item = c.shadow.querySelector('.menu').children.find((b) => b.onclick);
  item.onclick({ isTrusted: false });
  await flush();
  assert.equal(c.runs(), 0);
  item.onclick({ isTrusted: true });
  await flush();
  assert.equal(c.runs(), 1);
});

// --- Policy clipboard ----------------------------------------------------------------

function clipboardContext({ clip, host = 'fgt-a.test', confirmAnswer = false }) {
  const windowListeners = {};
  const requests = [];
  const confirms = [];
  const root = new Node('#shadow');
  const uiHost = new Node('div');
  root.host = uiHost;
  const rootListeners = {};
  const documentListeners = {};
  root.addEventListener = (t, fn) => { rootListeners[t] = fn; };
  root.removeEventListener = (t) => { delete rootListeners[t]; };
  let feature;
  let tableLookups = 0;
  const FP = {
    features: [],
    register: (f) => { feature = f; },
    isTrusted: (e) => !!e && e.isTrusted === true,
    toast() {},
    sleep: async () => {},
    deepTextNodes: () => [],
    el: (tag, props = {}, children = []) => Object.assign(new Node(tag), props, { children: [...children] }),
    root: () => root,
    parentOf: () => null,
    getVdom: () => null,
    runFeature: (f) => f.run(),
    policyNames: { getLimit: async () => 40, copyName: (n, s) => n + s },
    policyList: {
      tableForPage: () => { tableLookups++; return 'firewall policy'; },
      locateGrid: () => ({ container: { contains: () => true }, header: {} }),
      scanColumn: () => [{ id: 7 }],
      rowsFor: (hits) => hits.map((h) => ({ id: h.id, row: { contains: () => true } })),
    },
    requestJson: async (url, opts = {}) => {
      requests.push({ url, method: opts.method || 'GET' });
      return opts.method === 'POST' ? { mkey: 99 } : { results: [] };
    },
    request: async (url, opts = {}) => { requests.push({ url, method: opts.method }); return ''; },
  };
  const context = vm.createContext({
    window: { FortiPlug: FP, addEventListener: (t, fn) => { windowListeners[t] = fn; } },
    document: {
      addEventListener: (t, fn) => { documentListeners[t] = fn; },
      removeEventListener: (t) => { delete documentListeners[t]; },
    },
    console: { debug() {}, error() {} },
    Node: { ELEMENT_NODE: 1 },
    structuredClone,
    setTimeout: () => {},
    confirm: (msg) => { confirms.push(msg); return confirmAnswer; },
    location: { host, reload() {} },
    browser: { storage: { local: { get: async () => ({ policyClipboard: clip }), set: async () => {} } } },
  });
  load(context, ['src/features/policy-clipboard.js']);
  feature.init();
  const rightClick = (isTrusted) =>
    windowListeners.contextmenu({
      isTrusted, type: 'contextmenu', button: 2, timeStamp: Math.random() * 1e9, clientX: 1, clientY: 1,
      composedPath: () => [{ nodeType: 1 }],
    });
  const menuButton = (label) => root.querySelector('menu ctx-menu').children.find((b) => b.children[0].textContent.startsWith(label));
  const menu = () => root.querySelector('menu ctx-menu');
  return { rightClick, menuButton, menu, host: uiHost, rootListeners, documentListeners, requests, confirms, tableLookups: () => tableLookups };
}

const clip = (host) => ({ table: 'firewall policy', id: 3, host, policy: { policyid: 3, name: 'p' }, time: 0 });

test('page-synthesised right-clicks do not open the policy menu', async () => {
  const c = clipboardContext({ clip: null });
  await c.rightClick(false);
  assert.equal(c.tableLookups(), 0);
  await c.rightClick(true);
  assert.equal(c.tableLookups(), 1);
});

test('pasting a policy copied on another host needs confirmation', async () => {
  const c = clipboardContext({ clip: clip('evil.example'), confirmAnswer: false });
  await c.rightClick(true);
  const paste = c.menuButton('FortiPlug: Paste');
  paste.onclick({ isTrusted: false });
  await flush();
  assert.equal(c.confirms.length, 0);
  paste.onclick({ isTrusted: true });
  await flush();
  assert.equal(c.confirms.length, 1);
  assert.match(c.confirms[0], /evil\.example/);
  assert.equal(c.requests.filter((r) => r.method === 'POST').length, 0);
});

test('pasting on the same host proceeds without a prompt', async () => {
  const c = clipboardContext({ clip: clip('fgt-a.test') });
  await c.rightClick(true);
  c.menuButton('FortiPlug: Paste').onclick({ isTrusted: true });
  await flush();
  assert.equal(c.confirms.length, 0);
  assert.equal(c.requests.filter((r) => r.method === 'POST').length, 1);
});

test('fallback menu stays open for presses on its own items inside the closed root', async () => {
  const c = clipboardContext({ clip: null });
  await c.rightClick(true);
  const menu = c.menu();
  // At document level a press inside the closed root is retargeted to the host.
  c.documentListeners.mousedown({ composedPath: () => [c.host] });
  c.rootListeners.mousedown({ composedPath: () => [menu.children[0], menu] });
  assert.ok(!menu.removed);
  c.documentListeners.mousedown({ composedPath: () => [{}] });
  assert.ok(menu.removed);
  assert.equal(c.documentListeners.mousedown, undefined);
  assert.equal(c.rootListeners.mousedown, undefined);
});
