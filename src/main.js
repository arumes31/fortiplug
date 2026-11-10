'use strict';

// Runs after all feature scripts have registered. The content script is injected
// everywhere, so only activate on FortiGate GUI pages.
(() => {
  const FP = window.FortiPlug;

  const isFortiGate = () =>
    /forti(gate|os|wifi)/i.test(document.title) ||
    !!document.querySelector('base[href="/static/"]') ||
    location.pathname.startsWith('/ng/');

  const activate = () => {
    if (FP.active || !isFortiGate()) return FP.active;
    FP.active = true;
    FP.mountLauncher();
    for (const f of FP.features) {
      try {
        f.init?.();
      } catch (err) {
        console.error(`[FortiPlug] init of ${f.id} failed`, err);
      }
    }
    return true;
  };

  // The GUI may still be rendering at document_idle; retry for a while.
  if (!activate()) {
    let tries = 0;
    const timer = setInterval(() => (activate() || ++tries > 20) && clearInterval(timer), 500);
  }

  // Toolbar popup: list and run features.
  browser.runtime.onMessage.addListener((msg, sender) => {
    if (sender?.id !== browser.runtime.id) return;
    if (msg?.type === 'list') {
      const fortigate = activate();
      const features = fortigate
        ? FP.menuFeatures().map((f) => ({ id: f.id, label: f.label }))
        : [];
      return Promise.resolve({ fortigate, features });
    }
    if (msg?.type === 'run') {
      const f = activate() && FP.menuFeatures().find((x) => x.id === msg.id);
      if (f) FP.runFeature(f);
      return Promise.resolve(true);
    }
  });
})();
