// {{token}} templating for the story and catalog data. customer.config.json (optional, git-ignored) overrides brand, host and the first user.
// Tokens are filled from one of three vertical packs. A test fails on any token a pack does not define.
// Every person, agent, backend, store container and host in a pack is synthetic: only .example hosts, no real company, tenant or account.
import fs from 'node:fs';
import { scanHosts } from './safety.js';

const TOKEN = /\{\{(\w+)\}\}/g;
const MAX_CAST = 40;
const ID = /^[a-z0-9.-]{1,40}$/;

export const VERTICALS = {
  finance: {
    castBrand: 'Fabrikam Bank', castHost: 'fabrikam', castUser: 'maya.chen', castUser2: 'omar.reyes', castAdmin: 'sam.jones', castAuditor: 'lee.park', castSupport: 'ana.silva',
    castAgent: 'refund-assistant', castT1: 'ledger-api', castT2: 'cards-api', castT3: 'reports-api', castT4: 'partner-gateway',
    castOrg: 'fabrikam-org', castFolder: 'payments', castProject: 'settlement', castFolder2: 'risk', castProject2: 'scoring',
    castKv: 'kv-payments-prod', castKv2: 'kv-risk-prod', castSafe: 'Payments-Prod', castSafe2: 'Risk-Prod', castDelFolder: 'Finance', castDelSub: 'Payments', castAwsPrefix: 'prod/payments', castAwsPrefix2: 'prod/risk',
  },
  health: {
    castBrand: 'Contoso Health', castHost: 'contoso', castUser: 'lena.ortiz', castUser2: 'tariq.hassan', castAdmin: 'noah.becker', castAuditor: 'kofi.mensah', castSupport: 'ella.novak',
    castAgent: 'intake-assistant', castT1: 'claims-api', castT2: 'pharmacy-api', castT3: 'records-api', castT4: 'referral-gateway',
    castOrg: 'contoso-org', castFolder: 'clinical', castProject: 'claims-core', castFolder2: 'research', castProject2: 'trials',
    castKv: 'kv-clinical-prod', castKv2: 'kv-research-prod', castSafe: 'Clinical-Prod', castSafe2: 'Research-Prod', castDelFolder: 'Clinical', castDelSub: 'Claims', castAwsPrefix: 'prod/clinical', castAwsPrefix2: 'prod/research',
  },
  retail: {
    castBrand: 'Northwind Retail', castHost: 'northwind', castUser: 'diego.ruiz', castUser2: 'hana.sato', castAdmin: 'mia.kowalski', castAuditor: 'anna.berg', castSupport: 'tom.fischer',
    castAgent: 'checkout-helper', castT1: 'orders-api', castT2: 'loyalty-api', castT3: 'inventory-api', castT4: 'supplier-gateway',
    castOrg: 'northwind-org', castFolder: 'commerce', castProject: 'checkout', castFolder2: 'supply', castProject2: 'forecasting',
    castKv: 'kv-commerce-prod', castKv2: 'kv-supply-prod', castSafe: 'Commerce-Prod', castSafe2: 'Supply-Prod', castDelFolder: 'Commerce', castDelSub: 'Checkout', castAwsPrefix: 'prod/commerce', castAwsPrefix2: 'prod/supply',
  },
};
export const DEFAULT_VERTICAL = 'finance';
export const DEFAULT_CAST = VERTICALS[DEFAULT_VERTICAL];

export const unfilled = (text, cast) => [...String(text).matchAll(TOKEN)].map((m) => m[1]).filter((k) => !Object.hasOwn(cast, k));
export const fill = (text, cast) => String(text).replace(TOKEN, (m, k) => (Object.hasOwn(cast, k) ? cast[k] : m));
// Iterative, so a deep structure cannot overflow the stack.
export function fillDeep(value, cast) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const outRoot = { v: clone(value) };
  const work = [[value, outRoot, 'v']];
  while (work.length) {
    const [src, dst, key] = work.pop();
    if (typeof src === 'string') { dst[key] = fill(src, cast); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src);
    dst[key] = copy;
    for (const k of Object.keys(src).reverse()) work.push([src[k], copy, k]);
  }
  return outRoot.v;
}

export const verticalFrom = (id) => (typeof id === 'string' && Object.hasOwn(VERTICALS, id) ? id : DEFAULT_VERTICAL);

// Only brand, host and the first user, as short plain strings; anything else in the file is ignored. The user must not collide with another person.
export function loadCast(file, vertical = DEFAULT_VERTICAL) {
  const cast = { ...VERTICALS[verticalFrom(vertical)] };
  if (!file) return cast;
  try {
    const cfg = JSON.parse(fs.readFileSync(file, 'utf8'));
    for (const [short, key] of [['brand', 'castBrand'], ['user', 'castUser'], ['host', 'castHost']]) {
      const v = cfg?.cast?.[short];
      if (typeof v !== 'string' || !v.trim()) continue;
      const clean = v.replace(/[\u0000-\u001f\u007f-\u009f‪-‮⁦-⁩]/g, ' ').trim().slice(0, MAX_CAST);
      if (/:\/\/|@/.test(clean) || scanHosts(clean).length) continue;
      if (short !== 'brand' && !ID.test(clean.toLowerCase())) continue;
      if (short === 'host' && clean.includes('.')) continue;
      const val = short === 'brand' ? clean : clean.toLowerCase();
      if (short === 'user' && Object.entries(cast).some(([k, x]) => k !== 'castUser' && x === val)) continue;
      cast[key] = val;
    }
  } catch { /* no file or not JSON: the defaults */ }
  return cast;
}

// The roster: who can be "signed in". The lab has no sign-in; the visitor picks who acts (the real product takes it from the verified token).
// Roles: user (a person with a vault), admin, auditor, support. No role gives access to anyone else's vault: that is the point.
export const ROLES = ['user', 'admin', 'auditor', 'support'];
export function buildRoster(cast) {
  const p = (id, role) => ({ id, role });
  return [p(cast.castUser, 'user'), p(cast.castUser2, 'user'), p(cast.castAdmin, 'admin'), p(cast.castAuditor, 'auditor'), p(cast.castSupport, 'support')];
}
