// The policy table for secret stores. Default deny. READ and WRITE are SEPARATE grantable actions: a write grant does not let you read the value, a
// read grant does not let you rotate, update or delete. A grant is { principal, scope, actions }; scope is "provider:path" with * (one segment) and
// ** (the rest, last segment only). The matcher is a plain segment walk (no regular expression built from input, so no ReDoS).
// Lab-invented shape behind the deck claim "read and write are separate grantable actions" (UNVERIFIED).
import { PROVIDER_IDS, SEGMENT } from './stores.js';
import { findCredentials } from './credentials.js';

export const ACTIONS = ['read', 'write'];
export const SCOPE_MAX = 140;
export const POLICY_MAX = 100;
const SEG_OR_WILD = (s) => s === '*' || s === '**' || SEGMENT.test(s);

// null when valid, else a fixed reason code (never echoes the scope). A credential-shaped scope is refused like every other typed identifier, so a pasted
// token cannot sit in the policy table.
export function scopeProblem(scope) {
  if (typeof scope !== 'string' || scope.length === 0 || scope.length > SCOPE_MAX) return 'bad_scope';
  const at = scope.indexOf(':');
  if (at < 1) return 'bad_scope';
  const provider = scope.slice(0, at); const path = scope.slice(at + 1);
  if (provider !== '*' && !PROVIDER_IDS.includes(provider)) return 'bad_scope';
  const segs = path.split('/');
  if (segs.length > 10 || !segs.every(SEG_OR_WILD)) return 'bad_scope';
  if (segs.slice(0, -1).includes('**')) return 'bad_scope';
  if (findCredentials(scope).length) return 'credential_shaped_text';
  return null;
}

export function scopeMatches(scope, provider, path) {
  const at = scope.indexOf(':');
  const sp = scope.slice(0, at);
  if (sp !== '*' && sp !== provider) return false;
  const pat = scope.slice(at + 1).split('/'); const segs = path.split('/');
  for (let i = 0; i < pat.length; i++) {
    if (pat[i] === '**') return true;
    if (i >= segs.length) return false;
    if (pat[i] !== '*' && pat[i] !== segs[i]) return false;
  }
  return pat.length === segs.length;
}

export function allowed(policies, principal, action, provider, path) {
  return policies.some((g) => g.principal === principal && g.actions.includes(action) && scopeMatches(g.scope, provider, path));
}

// The grants the lab starts with (names from the cast). The admin can write (rotate) the Payments estate but not read it: separation, on purpose.
export function defaultGrants(c) {
  const g = (principal, scope, actions) => ({ principal, scope, actions });
  return [
    g(c.castUser, `aws:${c.castAwsPrefix}/**`, ['read']),
    g(c.castUser, `azure:${c.castKv}/**`, ['read', 'write']),
    g(c.castUser, `gcp:${c.castOrg}/${c.castFolder}/**`, ['read']),
    g(c.castUser2, `delinea:${c.castDelFolder}/**`, ['read']),
    g(c.castUser2, `cyberark:${c.castSafe}/*`, ['write']),
    g(c.castAdmin, `aws:**`, ['write']),
    g(c.castAdmin, `cyberark:**`, ['write']),
    g(c.castAdmin, `delinea:**`, ['write']),
  ];
}
