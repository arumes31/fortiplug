'use strict';

const el = (tag, className, text) => Object.assign(document.createElement(tag), { className, textContent: text ?? '' });

// Catalogue of all features (the feature scripts are loaded into this popup too).
const featureList = document.getElementById('features');
for (const f of window.FortiPlug.features.filter((x) => x.label)) {
  const item = el('div', 'feature');
  item.append(el('div', 'name', f.label));
  if (f.description) item.append(el('div', 'desc', f.description));
  if (f.usage) item.append(el('div', 'usage', f.usage));
  featureList.append(item);
}

// Actions that can run on the current tab.
(async () => {
  const actions = document.getElementById('actions');
  const message = (text) => actions.replaceChildren(el('div', 'msg', text));

  const [tab] = await browser.tabs.query({ active: true, currentWindow: true });
  let res;
  try {
    res = await browser.tabs.sendMessage(tab.id, { type: 'list' });
  } catch {
    return message('Not a FortiGate page. Open the FortiGate GUI (reload the tab if it was open before installing).');
  }
  if (!res?.fortigate) return message('This page does not look like a FortiGate GUI.');
  if (!res.features.length) return message('Nothing to run here. Open a policy list.');

  actions.replaceChildren();
  for (const f of res.features) {
    const b = el('button', '', f.label);
    b.onclick = async () => {
      await browser.tabs.sendMessage(tab.id, { type: 'run', id: f.id });
      window.close();
    };
    actions.append(b);
  }
})();
