'use strict';

// Uses FortiGate's header controls, with a local layout fallback for drag-and-drop.
(() => {
  const FP = window.FortiPlug;
  const ID = /^(?:policy[ _-]?)?id$/i;
  const COLUMN_MENU = /^(?:select columns|configure table)$/i;
  const HEADER_SELECTOR = '.header-cell[data-column-id], th, [role="columnheader"]';
  const text = (node) => (node.innerText || node.textContent || '').trim().replace(/\s+/g, ' ');
  const isId = (node) => ID.test(node.dataset?.columnId || '') || ID.test(text(node));
  const isPolicy = (node) => /^policy(?: name)?$/i.test(text(node)) ||
    /^(?:policy|policy-name)$/i.test(node.dataset?.columnId || '');
  const isAvailable = () => FP.policyList.tableForPage() === 'firewall policy' &&
    !/(?:dos-policy|\/policy\/dos)(?![\w-])/i.test(location.pathname + location.hash);

  function columns(row) {
    const headers = (row ? [...row.children].filter((node) => node.matches(HEADER_SELECTOR)) : FP.deepQueryAll(HEADER_SELECTOR))
      .filter((node) => FP.isVisible(node) && text(node));
    const policy = headers.find(isPolicy);
    return policy ? headers.filter((node) => node.parentElement === policy.parentElement)
      .sort((a, b) => a.getBoundingClientRect().left - b.getBoundingClientRect().left) : [];
  }

  function labels(pattern) {
    return [...FP.deepTextNodes(document.documentElement)]
      .filter((node) => pattern.test(node.data.trim()) && node.parentElement && FP.isVisible(node.parentElement))
      .map((node) => node.parentElement);
  }

  function sendMouse(node, type, x, y, buttons = 0) {
    const view = node.ownerDocument.defaultView;
    const Event = type.startsWith('pointer') ? view.PointerEvent : view.MouseEvent;
    node.dispatchEvent(new Event(type, {
      bubbles: true, cancelable: true, composed: true, clientX: x, clientY: y,
      screenX: (view.mozInnerScreenX || 0) + x, screenY: (view.mozInnerScreenY || 0) + y,
      button: type === 'contextmenu' ? 2 : 0, buttons, view,
      pointerId: 1, pointerType: 'mouse', isPrimary: true,
    }));
  }

  async function moveIdInPicker(picker) {
    const active = () => [...picker.querySelectorAll('.nu-list-1 .column-item')].map(text);
    const inactive = () => [...picker.querySelectorAll('.nu-list-2 .column-item')];
    const current = active();
    const names = [...current, ...inactive().map(text)];
    const ids = names.filter((name) => ID.test(name));
    if (ids.length !== 1) return false;
    const desired = [ids[0], ...current.filter((name) => name !== ids[0])];
    if (desired.some((name) => names.indexOf(name) !== names.lastIndexOf(name))) return false;
    if (current[0] === desired[0]) return true;

    // Transfers append to the active list. Rebuild the draft in order and check it before Apply.
    const moveAll = picker.querySelector('button[aria-label="move all right"]');
    const moveOne = picker.querySelector('button[aria-label="right to left"]');
    if (!moveOne || (current.length && (!moveAll || moveAll.disabled))) return false;
    if (current.length) {
      moveAll.click();
      await FP.settle();
      if (!isAvailable() || active().length) return false;
    }
    for (const name of desired) {
      const option = inactive().find((item) => text(item) === name);
      if (!option) return false;
      option.click();
      await FP.settle();
      if (!isAvailable() || moveOne.disabled) return false;
      moveOne.click();
      await FP.settle();
      if (!isAvailable()) return false;
    }
    const result = active();
    return result.length === desired.length && result.every((name, index) => name === desired[index]);
  }

  async function configureId(first, reorderOnly = false) {
    if (labels(COLUMN_MENU).length) return false;
    const { left, top, width, height } = first.getBoundingClientRect();
    sendMouse(first, 'contextmenu', left + width / 2, top + height / 2, 2);
    let menu;
    for (let attempt = 0; attempt < 4 && !menu; attempt++) {
      await FP.settle();
      if (!isAvailable()) return false;
      menu = labels(COLUMN_MENU)[0];
    }
    if (!menu) return false;
    const portal = menu.closest('.nu-mutable-portal-component');
    if (portal) {
      const buttons = [...portal.querySelectorAll('button')].filter(FP.isVisible);
      const apply = buttons.find((button) => /^apply$/i.test(text(button)));
      const cancel = buttons.find((button) => /^cancel$/i.test(text(button)));
      if (!apply) return false;
      const picker = portal.querySelector('nu-transfer-list');
      if (picker) {
        if (!(await moveIdInPicker(picker))) {
          cancel?.click();
          return false;
        }
      } else {
        if (reorderOnly) {
          cancel?.click();
          return false;
        }
        const option = buttons.find((button) => ID.test(button.getAttribute('aria-label') || text(button)));
        if (!option || option.disabled) return false;
        option.click();
        await FP.settle();
      }
      if (!isAvailable() || apply.disabled) return false;
      apply.click();
      const headers = await waitForColumns();
      return reorderOnly ? inPosition(headers) : headers.some(isId);
    }
    if (reorderOnly) return false;
    if (/configure table/i.test(text(menu))) {
      menu.click();
      await FP.settle();
      menu = labels(/^select columns$/i)[0] || menu;
    }
    let scope = menu.parentElement;
    for (let depth = 0; scope && !scope.contains(first) && depth < 5; depth++, scope = scope.parentElement) {
      const id = labels(/^(?:policy )?id$/i).find((node) => scope.contains(node) && !columns().includes(node));
      if (!id) continue;
      id.click();
      await FP.settle();
      if (!columns().some(isId)) {
        const dialog = id.closest('[role="dialog"], dialog');
        const apply = [...(dialog || scope).querySelectorAll('button, [role="button"]')]
          .find((button) => /^apply$/i.test(text(button)) && FP.isVisible(button) && !button.disabled);
        if (apply) {
          apply.click();
          await FP.settle();
        }
      }
      if (menu.isConnected && FP.isVisible(menu)) {
        menu.dispatchEvent(new menu.ownerDocument.defaultView.KeyboardEvent('keydown', {
          key: 'Escape', bubbles: true, cancelable: true,
        }));
      }
      return columns().some(isId);
    }
    return false;
  }

  const inPosition = (headers) => {
    const policy = headers.findIndex(isPolicy);
    return policy >= 0 && (headers[policy + 1] ? isId(headers[policy + 1]) : false);
  };

  function readyColumns() {
    const headers = columns();
    const grid = headers[0]?.closest('nu-mutable');
    if (headers.length < 2 || grid?.getAttribute('aria-busy') === 'true') return [];
    return headers;
  }

  async function waitForColumns() {
    // FortiGate can keep the same header nodes while restoring column preferences.
    let previous = [];
    let previousGeometry = '';
    for (let attempt = 0; attempt < 8 && isAvailable(); attempt++) {
      const headers = readyColumns();
      const geometry = headers.map((header) => {
        const { left, width } = header.getBoundingClientRect();
        return `${left}:${width}`;
      }).join(',');
      if (geometry && geometry === previousGeometry && headers.every((header, index) => header === previous[index])) {
        return headers;
      }
      previous = headers;
      previousGeometry = geometry;
      await FP.settle();
    }
    return [];
  }

  let localLayout;

  function applyLocalOrder() {
    if (!isAvailable()) {
      clearLocalOrder();
      return false;
    }
    const { header, offsets } = localLayout;
    const rect = (node) => {
      const { left, right, top, bottom } = node.getBoundingClientRect();
      const offset = offsets.get(node) || 0;
      return { left: left - offset, right: right - offset, top, bottom };
    };
    const headers = header.parentElement ? columns(header.parentElement).sort((a, b) => rect(a).left - rect(b).left) : [];
    const policyIndex = headers.findIndex(isPolicy);
    const idIndex = headers.indexOf(header);
    if (policyIndex < 0 || idIndex < 0 || inPosition(headers)) {
      clearLocalOrder();
      return false;
    }

    const id = rect(header);
    const movingRight = idIndex < policyIndex;
    const first = movingRight ? idIndex : policyIndex + 1;
    const last = Math.max(policyIndex, idIndex);
    const span = headers.slice(first, last + 1);
    const edge = rect(headers[movingRight ? idIndex + 1 : idIndex - 1]);
    const displacement = movingRight ? id.left - edge.left : id.right - edge.right;
    const target = movingRight ? rect(headers[policyIndex]).right - (id.right - id.left) : rect(span[0]).left;
    const next = new Map(span.map((node) => [node, node === header ? target - id.left : displacement]));

    const keyed = new Map(span.filter((node) => node.dataset?.columnId)
      .map((node) => [node.dataset.columnId, node]));
    const table = header.closest('table');
    const mutable = header.closest('nu-mutable');
    if (table && header.tagName === 'TH') {
      const headerRow = header.parentElement;
      for (const body of table.tBodies) {
        for (const row of body.rows) {
          if (row.cells.length !== headerRow.cells.length || [...row.cells].some((cell) => cell.colSpan !== 1)) continue;
          for (const column of span) next.set(row.cells[column.cellIndex], next.get(column));
        }
      }
    } else if (mutable && keyed.size === span.length) {
      // FortiGate's virtual rows use column-id and share the fixed header's column offsets.
      for (const cell of mutable.querySelectorAll('.table-container .row[row-id] > .row-cell[column-id]')) {
        const column = keyed.get(cell.getAttribute('column-id'));
        if (column) next.set(cell, next.get(column));
      }
    } else if (keyed.size === span.length) {
      // Other grids can reuse column keys in nested controls. Match the original geometry too.
      const rowGroup = header.parentElement;
      const scope = rowGroup.closest('[role="grid"], [role="table"]') || header.getRootNode();
      for (const cell of scope.querySelectorAll('[data-column-id]')) {
        const column = keyed.get(cell.dataset.columnId);
        if (!column || rowGroup.contains(cell)) continue;
        const cellRect = rect(cell);
        const columnRect = rect(column);
        if (cellRect.top >= id.bottom - 2 && cellRect.bottom > cellRect.top &&
            Math.abs(cellRect.left - columnRect.left) <= 3 && Math.abs(cellRect.right - columnRect.right) <= 3) {
          next.set(cell, next.get(column));
        }
      }
    } else {
      clearLocalOrder();
      return false;
    }

    for (const node of offsets.keys()) {
      if (!next.has(node)) restoreTranslate(node);
    }
    for (const [node, offset] of next) {
      if (!localLayout.original.has(node)) {
        localLayout.original.set(node, [node.style.getPropertyValue('translate'), node.style.getPropertyPriority('translate')]);
      }
      if (offsets.get(node) !== offset) node.style.setProperty('translate', `${offset}px`, 'important');
    }
    localLayout.offsets = next;
    return inPosition(columns(header.parentElement));
  }

  function restoreTranslate(node) {
    const [value, priority] = localLayout.original.get(node);
    node.style.setProperty('translate', value, priority);
    localLayout.original.delete(node);
  }

  function clearLocalOrder() {
    if (!localLayout) return;
    localLayout.resize.disconnect();
    for (const node of localLayout.original.keys()) restoreTranslate(node);
    localLayout = undefined;
  }

  function useLocalOrder() {
    const headers = readyColumns();
    const header = headers.find(isId);
    if (!header || (!header.dataset?.columnId && header.tagName !== 'TH')) return false;
    const resize = new header.ownerDocument.defaultView.ResizeObserver(() => {
      if (localLayout?.header === header) applyLocalOrder();
    });
    localLayout = { header, resize, offsets: new Map(), original: new Map() };
    if (!applyLocalOrder()) {
      clearLocalOrder();
      return false;
    }
    for (const column of headers) resize.observe(column);
    return true;
  }

  async function moveIdAfterPolicy(method) {
    const headers = columns();
    if (inPosition(headers)) return true;
    const idIndex = headers.findIndex(isId);
    const policyIndex = headers.findIndex(isPolicy);
    if (idIndex === -1 || policyIndex === -1) return false;
    const id = headers[idIndex];
    const movingRight = idIndex < policyIndex;
    const destination = headers[movingRight ? policyIndex : policyIndex + 1];
    if (!destination) return false;
    const start = id.getBoundingClientRect();
    const end = destination.getBoundingClientRect();
    const x = start.left + start.width / 2;
    const y = start.top + start.height / 2;
    const target = end.left + end.width * (movingRight ? 0.8 : 0.2);
    const view = id.ownerDocument.defaultView;

    if (method === 'native') {
      const handle = id.draggable ? id : id.querySelector('[draggable="true"]');
      if (!handle || !view.DataTransfer || !view.DragEvent) return false;
      const dataTransfer = new view.DataTransfer();
      const drag = (node, type, clientX) => node.dispatchEvent(new view.DragEvent(type, {
        bubbles: true, cancelable: true, composed: true, dataTransfer, clientX, clientY: y,
      }));
      drag(handle, 'dragstart', x);
      drag(destination, 'dragenter', target);
      drag(destination, 'dragover', target);
      drag(destination, 'drop', target);
      drag(handle, 'dragend', target);
    } else {
      if (method === 'pointer' && !view.PointerEvent) return false;
      const handle = id.querySelector('.cdk-drag-handle, [cdkDragHandle]') || id;
      sendMouse(handle, method + 'down', x, y, 1);
      sendMouse(handle, method + 'move', x + (movingRight ? 10 : -10), y, 1);
      sendMouse(destination, method + 'move', target, y, 1);
      await FP.settle();
      sendMouse(destination, method + 'up', target, y);
    }
    await FP.settle();
    return inPosition(columns());
  }

  let pending;
  function prepare() {
    if (pending) return pending;
    pending = (async () => {
      if (!isAvailable()) return 'Open the Firewall Policy table first.';
      const headers = await waitForColumns();
      const first = headers[0];
      if (!first) return 'Policy table not ready.';
      if (inPosition(headers)) return '';
      const alreadyVisible = headers.some(isId);
      if (!alreadyVisible) {
        if (!(await configureId(first))) return 'Could not enable the ID column automatically.';
        if (!(await waitForColumns()).length) return 'Policy table not ready.';
      }
      if (!isAvailable()) return 'Policy table changed during setup.';
      for (const method of ['native', 'mouse', 'pointer']) {
        if (!isAvailable()) return 'Policy table changed during setup.';
        if (await moveIdAfterPolicy(method)) return '';
      }
      if (alreadyVisible && first.closest('nu-mutable') && await configureId(first, true)) return '';
      if (useLocalOrder()) return '';
      return 'ID is visible. FortiGate did not move it immediately after Policy.';
    })().finally(() => { pending = undefined; });
    return pending;
  }

  function init() {
    let route;
    let failed;
    const check = () => {
      if (route !== location.href) {
        route = location.href;
        failed = undefined;
        clearLocalOrder();
      }
      if (localLayout && applyLocalOrder()) return;
      if (pending || !isAvailable()) return;
      const headers = readyColumns();
      if (!headers.length) return;
      if (inPosition(headers)) {
        failed = undefined;
        return;
      }
      if (failed?.length === headers.length && headers.every((header, index) => header === failed[index])) return;
      const attemptRoute = route;
      prepare().then((message) => {
        if (attemptRoute === location.href) failed = message ? headers : undefined;
      }).catch((error) => {
        if (attemptRoute === location.href) failed = headers;
        console.warn('[FortiPlug] ID column setup', error);
      }).finally(scheduleCheck);
    };
    let frame;
    function scheduleCheck() {
      if (frame !== undefined) return;
      frame = requestAnimationFrame(() => {
        frame = undefined;
        check();
      });
    }
    const observer = new MutationObserver((mutations) => {
      if (mutations.some(({ attributeName, target }) => attributeName !== 'style' || target.matches(HEADER_SELECTOR))) {
        scheduleCheck();
      }
    });
    observer.observe(document.documentElement, { childList: true, subtree: true, attributes: true,
      attributeFilter: ['aria-busy', 'data-column-id', 'column-id', 'hidden', 'style'] });
    check();
  }

  FP.register({
    id: 'policy-id-column',
    label: 'Set up policy ID column',
    description: 'Show the ID column immediately after Policy.',
    usage: 'Runs automatically when the Firewall Policy table opens. Use this action to retry.',
    isAvailable,
    init,
    run: async () => {
      const message = await prepare();
      FP.toast(message || 'ID is immediately after Policy.', message ? 'error' : 'ok');
    },
  });
})();
