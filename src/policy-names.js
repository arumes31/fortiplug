'use strict';

// Shared name limit and formatting for bulk rename and copy/paste.
(() => {
  const FP = window.FortiPlug;
  const KEY = 'policyNameLimit';
  const length = (text) => Array.from(text).length;
  const validLimit = (value) => Number.isInteger(value) && value >= 20 && value <= 40;
  const shorten = (text, limit) => {
    if (length(text) <= limit) return text;
    return limit > 0 ? Array.from(text).slice(0, limit - 1).join('') + '.' : '';
  };
  const extractPurpose = (name, routes = []) => {
    // Recognize a purpose after a known route or in a legacy description.
    // Leave free-form names for manual interpretation.
    name = name.replace(/\(Copy of(?:\s+[^()]*)?\)/gi, '').trim();
    const prefix = name.split(' (')[0];
    const route = routes.filter(Boolean).sort((a, b) => b.length - a.length).find((route) => prefix.startsWith(`${route}_`));
    if (route) return prefix.slice(route.length + 1);
    const description = name.match(/\((.*?)(?:\)|$)/)?.[1]?.trim() || '';
    if (/^(?:VIP_|DENY\b)/i.test(description)) return '';
    const tokens = description.split(/[,/\s]+/).filter(Boolean);
    const serviceOnly = tokens.length && tokens.every((token) => /^(?:ALL|ANY|TCP\d+(?:-\d+)?|UDP\d+(?:-\d+)?|HTTP|HTTPS|HTTPS-QUIC|SSH|DNS|LDAPS?|RADIUS|PING|SMTP|SMTPS|RDP|FTP|NTP|SNMP|\+\d+|…|\.)$/i.test(token));
    return serviceOnly ? '' : description;
  };
  const parseAliases = (text, label = 'Object') => {
    const rules = [];
    for (const line of text.split(/\r?\n/).map((line) => line.trim()).filter(Boolean)) {
      const split = line.indexOf('=');
      if (split < 1 || !line.slice(split + 1).trim()) return { rules, error: `${label} aliases need one name=alias per line.` };
      const key = line.slice(0, split).trim();
      if (key.includes('*') && (key.indexOf('*') !== key.length - 1 || key.indexOf('*') !== key.lastIndexOf('*'))) return { rules, error: `Only a trailing * is supported in ${label.toLowerCase()} aliases.` };
      if (rules.some((rule) => rule.key === key)) return { rules, error: `Duplicate ${label.toLowerCase()} alias: ${key}` };
      rules.push({ key, value: line.slice(split + 1).trim() });
    }
    return { rules, error: '' };
  };
  const aliasFor = (name, rules) => rules.find((rule) => rule.key === name)?.value
    ?? rules.find((rule) => rule.key.endsWith('*') && name.startsWith(rule.key.slice(0, -1)))?.value;
  const inferPurpose = ({ sources, destinations, sourceInterface = '', destinationInterface = '', sourceNegated = false, destinationNegated = false }, { rules = [], prefixes = ['H_', 'G_'], shortFqdn = true } = {}) => {
    const specific = (objects) => objects.some((name) => /^(?:all|all6|any|0\.0\.0\.0\/0|::\/0)$/i.test(name)) ? [] : [...new Set(objects)];
    const label = (name) => {
      const prefix = [...prefixes].sort((a, b) => b.length - a.length).find((prefix) => name.toLowerCase().startsWith(prefix.toLowerCase()));
      const clean = prefix ? name.slice(prefix.length) || name : name;
      const alias = rules.find((rule) => rule.key === name)?.value ?? rules.find((rule) => rule.key === clean)?.value
        ?? aliasFor(name, rules) ?? aliasFor(clean, rules);
      if (alias !== undefined) return alias;
      const fqdn = /^[a-z0-9_-]+(?:\.[a-z0-9_-]+)+\.?$/i.test(clean) && !/^[\d.]+$/.test(clean);
      return shortFqdn && fqdn ? clean.split('.')[0] : clean;
    };
    const summarize = (objects) => {
      const labels = objects.map(label);
      const kept = labels.length > 1 && labels[0] !== labels[1] && length(labels[0]) <= 12 && length(labels[1]) <= 12 ? 2 : 1;
      return labels.slice(0, kept).join('+') + (labels.length > kept ? `+${labels.length - kept}` : '');
    };
    const networkLabel = (value) => value.toLowerCase().replace(/^(?:vlan|lan|vl)[_-]/, '').replace(/[-_\s]/g, '');
    const repeatsInterface = (name, iface) => iface && networkLabel(label(name)) === networkLabel(iface);
    const src = specific(sources).filter((name) => sourceNegated || !repeatsInterface(name, sourceInterface));
    const dst = specific(destinations).filter((name) => destinationNegated || !repeatsInterface(name, destinationInterface));
    const mark = (value, negated) => negated ? `NOT_${value}` : value;
    if (dst.length) {
      const target = mark(summarize(dst), destinationNegated);
      if (src.length === 1 && dst.length === 1 && length(label(src[0])) <= 12 && length(target) <= 16) {
        return { value: `${mark(label(src[0]), sourceNegated)}-${target}`, origin: 'source and destination', objects: [...src, ...dst] };
      }
      return { value: target, origin: 'destination', objects: dst };
    }
    if (src.length) return { value: mark(summarize(src), sourceNegated), origin: 'source', objects: src };
    return { value: '', origin: '', objects: [] };
  };
  const vipLabel = (mapping) => [mapping.incoming, mapping.mapped, mapping.external, mapping.target].join('-');
  const compactVip = (mapping, budget) => {
    // Prefer the internal target and mapped port over incoming/WAN details.
    // Only whole fields are kept; the fallback dot never splits a port or IP.
    return [vipLabel(mapping), `${mapping.targetLabel || mapping.target}_${mapping.mapped}`,
      `${mapping.target}_${mapping.mapped}`, `._${mapping.mapped}`, mapping.mapped, '.']
      .find((candidate) => length(candidate) <= budget) || '.';
  };
  const format = ({ route, purpose = '', services = [], mappings = [], deny = false }, limit, suffix = '') => {
    const vip = mappings.length > 0;
    const items = vip ? mappings.map(vipLabel) : services;
    const marker = deny ? 'DENY, ' : '';
    const prefix = vip ? 'VIP_' : '';
    const full = `${route}${purpose ? `_${purpose}` : ''} (${marker}${prefix}${items.join(', ')})${suffix}`;
    const header = `${route}${purpose ? `_${purpose}` : ''}`;
    let kept = items.length;
    const build = (base, detail, omitted) => `${base} (${marker}${prefix}${detail}${omitted ? `, +${omitted}` : ''})${suffix}`;
    const detail = () => items.slice(0, kept).join(', ');
    while (length(build(header, detail(), items.length - kept)) > limit && kept > 1) kept--;
    let omitted = items.length - kept;
    let name = build(header, detail(), omitted);
    if (length(name) > limit) {
      const budget = limit - length(build(header, '', omitted));
      if (budget >= 1) name = build(header, vip ? compactVip(mappings[0], budget) : shorten(detail(), budget), omitted);
      else {
        // If the header itself needs shortening, summarize all detail entries
        // with +N so that the header owns the only shortening dot in the name.
        omitted = items.length;
        const summary = `+${omitted}`;
        const headerBudget = Math.max(1, limit - length(build('', summary, 0)));
        const purposeBudget = headerBudget - length(route) - 1;
        let compactHeader;
        if (!purpose) compactHeader = route;
        else if (purposeBudget >= 1) compactHeader = `${route}_${shorten(purpose, purposeBudget)}`;
        else compactHeader = route;
        name = build(compactHeader, summary, 0);
      }
    }
    return { name, full, shortened: name !== full, omitted };
  };

  FP.policyNames = {
    length, shorten, validLimit, extractPurpose, parseAliases, aliasFor, inferPurpose, format, vipLabel,
    getLimit: async () => {
      const settings = await browser.storage.local.get(KEY);
      return validLimit(settings[KEY]) ? settings[KEY] : 40;
    },
    setLimit: async (value) => {
      if (!validLimit(value)) throw new Error('Name limit must be a whole number from 20 to 40.');
      await browser.storage.local.set({ [KEY]: value });
    },
    copyName: (name, suffix, limit) => {
      const match = name.match(/^(.*?) \((.*)\)(?:_ID\d+(?:_\d+)?)?$/);
      if (!match) return shorten(name, limit - length(suffix)) + suffix;
      // Copies keep arbitrary legacy names, which need not contain an interface
      // pair. Preserve their details and parentheses while reserving the suffix.
      const budget = limit - length(suffix) - length(match[2]) - 3;
      if (budget >= 1) return `${shorten(match[1], budget)} (${match[2]})${suffix}`;
      return `${shorten(match[1], Math.max(1, limit - length(suffix) - 5))} (+1)${suffix}`;
    },
  };
})();
