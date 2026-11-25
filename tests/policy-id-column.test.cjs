'use strict';

const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const test = require('node:test');
const vm = require('node:vm');

const script = fs.readFileSync(path.join(__dirname, '../src/features/policy-id-column.js'), 'utf8');

function setup({ hidden = false, method = 'mouse', position = 'late', local = false, mutable = false, dualList = false } = {}) {
  const body = [];
  const scope = { querySelectorAll: () => body };
  let busy = false;
  const liveGrid = {
    getAttribute: (name) => name === 'aria-busy' ? String(busy) : null,
    querySelectorAll(selector) {
      assert.equal(selector, '.table-container .row[row-id] > .row-cell[column-id]');
      return body;
    },
  };
  const header = { children: [], closest: () => scope, contains: (node) => header.children.includes(node) };
  class InputEvent { constructor(type, options) { Object.assign(this, options, { type }); } }
  let resize;
  const view = { MouseEvent: InputEvent, PointerEvent: InputEvent, KeyboardEvent: class {},
    ResizeObserver: class {
      constructor(callback) { resize = callback; }
      observe() {}
      disconnect() {}
    },
  };
  const document = { documentElement: {}, defaultView: view };
  const notices = [];
  let enabled = !hidden;
  let menuOpen = false;
  let order = position === 'before' ? ['ID', 'Policy', 'Source'] :
    position === 'after' ? ['Policy', 'ID', 'Source'] : ['Policy', 'Source', 'ID'];
  const widths = { Policy: local ? 100 : 50, Source: local ? 80 : 50, ID: local ? 30 : 50 };
  const events = [];
  const makeCell = (label, top) => {
    let translate = '';
    return {
      dataset: local ? { columnId: mutable && label === 'ID' ? 'policyid' : label.toLowerCase() } : {},
      style: {
        getPropertyValue: () => translate,
        getPropertyPriority: () => '',
        setProperty: (_name, value) => { translate = value; },
      },
      getBoundingClientRect: () => {
        const left = order.slice(0, order.indexOf(label)).reduce((sum, key) => sum + widths[key], 0) +
          (parseFloat(translate) || 0);
        return { left, right: left + widths[label], width: widths[label], height: 20, top, bottom: top + 20 };
      },
    };
  };
  const makeHeader = (label) => ({
    ...makeCell(label, 0),
    innerText: label, parentElement: header, ownerDocument: document,
    closest: (selector) => mutable && selector === 'nu-mutable' ? liveGrid : null,
    matches: () => true,
    querySelector: (selector) => mutable && label === 'Policy' && selector === 'button[aria-label="Open column settings"]'
      ? { click: () => assert.fail('Header settings opens the filter menu') }
      : null,
    dispatchEvent: (event) => {
      events.push(event.type);
      if (event.type === 'contextmenu') menuOpen = true;
      const dropAfterPolicy = label === 'Policy' && event.clientX % 50 > 25;
      const dropBeforeSource = label === 'Source' && event.clientX % 50 < 25;
      if (event.type === method + 'up' && (dropAfterPolicy || dropBeforeSource)) {
        order = ['Policy', 'ID', 'Source'];
      }
    },
  });
  const policy = makeHeader('Policy');
  const id = makeHeader('ID');
  const source = makeHeader('Source');
  header.children = [policy, source, id];
  let idSelected = false;
  let selectedItem;
  const pickerItems = ['Source', 'ID'].map((name) => ({
    innerText: name,
    click() { selectedItem = this; },
  }));
  const pickerOrder = pickerItems.filter((item) => item.innerText !== 'ID' || enabled);
  const picker = {
    querySelectorAll: (selector) => selector === '.nu-list-1 .column-item'
      ? pickerOrder : pickerItems.filter((item) => !pickerOrder.includes(item)),
    querySelector(selector) {
      if (selector === 'button[aria-label="move all right"]') {
        return { click() { pickerOrder.length = 0; } };
      }
      assert.equal(selector, 'button[aria-label="right to left"]');
      return {
        get disabled() { return !selectedItem; },
        click() { pickerOrder.push(selectedItem); selectedItem = undefined; },
      };
    },
  };
  const cancel = { innerText: 'Cancel', getAttribute: () => null, click() { menuOpen = false; } };
  const idOption = {
    getAttribute: () => 'ID',
    click() {
      idSelected = true;
      if (!mutable) {
        enabled = true;
        menuOpen = false;
      }
    },
  };
  const apply = {
    innerText: 'Apply',
    getAttribute: () => null,
    get disabled() { return dualList ? !pickerOrder.some((item) => item.innerText === 'ID') : !idSelected; },
    click() {
      enabled = !this.disabled;
      if (dualList) order = ['Policy', ...pickerOrder.map((item) => item.innerText)];
      menuOpen = false;
    },
  };
  const portal = {
    querySelectorAll: () => dualList ? [apply, cancel] : [idOption, apply, cancel],
    querySelector: (selector) => dualList && selector === 'nu-transfer-list' ? picker : null,
  };
  const menuScope = { contains: (node) => node === idOption };
  const menu = {
    innerText: 'Select Columns', parentElement: menuScope, ownerDocument: document,
    closest: (selector) => mutable && selector === '.nu-mutable-portal-component' ? portal : null,
  };
  let feature;
  let notify;
  const FP = {
    register: (value) => { feature = value; },
    policyList: { tableForPage: () => 'firewall policy' },
    deepQueryAll: () => enabled ? [policy, id, source] : [policy, source],
    deepTextNodes: function* () {
      if (menuOpen) {
        yield { data: 'Select Columns', parentElement: menu };
        yield { data: 'ID', parentElement: idOption };
      }
    },
    isVisible: () => true,
    settle: async () => {},
    toast: (message) => notices.push(message),
  };
  vm.runInNewContext(script, {
    window: { FortiPlug: FP }, document,
    location: { pathname: '/firewall/policy/policy/standard', hash: '', href: '/firewall/policy/policy/standard' },
    MutationObserver: class {
      constructor(callback) { notify = callback; }
      observe() {}
    },
    requestAnimationFrame: (callback) => setImmediate(callback),
  });
  return {
    feature, notices, events, widths, header, body, makeCell, order: () => order, resize: () => resize(),
    setBusy(value) {
      busy = value;
      notify?.([{ attributeName: 'aria-busy', target: liveGrid }]);
    },
    restoreOrder() {
      order = ['Policy', 'Source', 'ID'];
      notify([{ attributeName: 'style', target: id }]);
    },
  };
}

test('enables a hidden policy ID and moves it immediately after Policy', async () => {
  const grid = setup({ hidden: true });
  await grid.feature.run();
  assert.deepEqual(grid.events, ['contextmenu', 'mousedown', 'mousemove', 'mousemove', 'mouseup']);
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
  assert.deepEqual(grid.notices, ['ID is immediately after Policy.']);
});

test('leaves ID alone when it is already next to Policy', async () => {
  const grid = setup({ position: 'after' });
  await grid.feature.run();
  assert.deepEqual(grid.events, []);
});

test('moves ID right when it is currently before Policy', async () => {
  const grid = setup({ position: 'before' });
  await grid.feature.run();
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
});

test('tries pointer dragging when the mouse drag has no effect', async () => {
  const grid = setup({ method: 'pointer' });
  await grid.feature.run();
  assert.ok(grid.events.includes('mouseup'));
  assert.ok(grid.events.includes('pointerup'));
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
});

test('reports when FortiGate leaves ID in its original position', async () => {
  const grid = setup({ method: 'none' });
  await grid.feature.run();
  assert.match(grid.notices[0], /did not move it immediately after Policy/);
});

test('positions the ID and its data cells after Policy when FortiGate ignores dragging', async () => {
  const grid = setup({ method: 'none', local: true });
  const source = grid.makeCell('Source', 60);
  const id = grid.makeCell('ID', 60);
  const unrelatedId = grid.makeCell('ID', 5);
  grid.body.push(source, id, unrelatedId);
  await grid.feature.run();
  assert.deepEqual(grid.header.children.map((cell) => cell.getBoundingClientRect().left), [0, 130, 100]);
  assert.equal(source.getBoundingClientRect().left, 130);
  assert.equal(id.getBoundingClientRect().left, 100);
  assert.equal(unrelatedId.getBoundingClientRect().left, 180);
  assert.deepEqual(grid.notices, ['ID is immediately after Policy.']);
});

test('aligns newly rendered rows and recalculates offsets without compounding them', async () => {
  const grid = setup({ method: 'none', local: true });
  await grid.feature.run();

  const source = grid.makeCell('Source', 60);
  const id = grid.makeCell('ID', 60);
  grid.body.push(source, id);
  grid.widths.Policy = 140;
  grid.widths.Source = 205;
  grid.widths.ID = 40;
  grid.resize();
  grid.resize();
  assert.equal(source.getBoundingClientRect().left, 180);
  assert.equal(id.getBoundingClientRect().left, 140);
});

test('aligns FortiGate virtual rows whose column keys use column-id instead of data-column-id', async () => {
  const grid = setup({ method: 'none', local: true, mutable: true });
  const addRowCell = (label, key) => {
    const cell = grid.makeCell(label, 60);
    cell.dataset = {};
    cell.getAttribute = (name) => name === 'column-id' ? key : null;
    grid.body.push(cell);
    return cell;
  };
  const source = addRowCell('Source', 'source');
  const id = addRowCell('ID', 'policyid');
  await grid.feature.run();
  assert.equal(id.getBoundingClientRect().left, grid.header.children[2].getBoundingClientRect().left);
  assert.equal(source.getBoundingClientRect().left, grid.header.children[1].getBoundingClientRect().left);
  assert.equal(id.getBoundingClientRect().left, 100);

  const nextId = addRowCell('ID', 'policyid');
  grid.resize();
  assert.equal(nextId.getBoundingClientRect().left, 100);
});

test('automatically waits for the grid to finish loading before trying to drag', async () => {
  const grid = setup({ mutable: true });
  grid.setBusy(true);
  grid.feature.init();
  await new Promise(setImmediate);
  assert.deepEqual(grid.events, []);

  grid.setBusy(false);
  await new Promise(setImmediate);
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
});

test('enables ID through FortiGate’s portal and applies the selection', async () => {
  const grid = setup({ hidden: true, mutable: true });
  await grid.feature.run();
  assert.equal(grid.events[0], 'contextmenu');
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
  assert.deepEqual(grid.notices, ['ID is immediately after Policy.']);
});

test('transfers only ID to the active list and puts it before Source before applying', async () => {
  const grid = setup({ hidden: true, mutable: true, dualList: true, method: 'none' });
  await grid.feature.run();
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
  assert.deepEqual(grid.events, ['contextmenu']);
  assert.deepEqual(grid.notices, ['ID is immediately after Policy.']);
});

test('uses the picker to reorder an already visible ID if header dragging has no effect', async () => {
  const grid = setup({ mutable: true, dualList: true, method: 'none' });
  await grid.feature.run();
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
  assert.deepEqual(grid.notices, ['ID is immediately after Policy.']);
});

test('reapplies the order after FortiGate restores a preference on the same header nodes', async () => {
  const grid = setup();
  grid.feature.init();
  await new Promise(setImmediate);
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);

  grid.restoreOrder();
  await new Promise(setImmediate);
  assert.deepEqual(grid.order(), ['Policy', 'ID', 'Source']);
});
