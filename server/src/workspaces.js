// Rule 13: a workspace id keeps one visitor's state apart from another's. Server state per workspace is one Engine per vertical
// (vault, inventory, providers, audit, clock). Bounded in count and age; a new workspace is REFUSED at the cap instead of evicting another's.
// The browser sends its id in X-Workspace (default "default"). Reset clears the current workspace only.
import { Engine } from './engine.js';
import { findCredentials } from './credentials.js';

export const WORKSPACE_RE = /^[a-z0-9-]{1,40}$/;
export const DEFAULT_WORKSPACE = 'default';

// A workspace id is echoed in the `workspace` field and in the hop headers, so one that LOOKS like a credential is refused (400 bad_workspace, never echoed).
// Refused: no letter at all (the page always makes ids with a letter), a run of 24 or more hex digits, a credential-word prefix (sk-, pw-, token-, ...), and
// anything the credential detectors find, read as typed and with its hyphens read as spaces ("password-hunter2xyz" is "password hunter2xyz"). A bare word
// with no keyword ("hunter2xyz") cannot be told from a name and is accepted; the page says masking is a heuristic.
const HEX_RUN = /[0-9a-f]{24,}/;
const KEY_PREFIX = /^(?:sk|pk|rk|pw|pwd|pass|passwd|password|tok|token|secret|apikey|bearer|ghp|gho|ghu|ghs|ghr|github|glpat|xox[abprs]|akia|asia|eyj|ya29)(?:-|$)/;
export function credentialLookingId(id) {
  return !/[a-z]/.test(id) || HEX_RUN.test(id) || KEY_PREFIX.test(id) || findCredentials(id).length > 0 || findCredentials(id.replace(/-/g, ' ')).length > 0;
}

export function workspaceFrom(req) {
  const raw = req.headers['x-workspace'];
  if (raw === undefined) return DEFAULT_WORKSPACE;
  return typeof raw === 'string' && WORKSPACE_RE.test(raw) && !credentialLookingId(raw) ? raw : null;
}

export function createWorkspaces({ max = 500, ttlMs = 60 * 60 * 1000, now = Date.now } = {}) {
  const map = new Map(); // id -> { engines: Map(vertical -> Engine), at }
  const sweep = () => { const t = now(); for (const [id, v] of map) { if (t - v.at > ttlMs) map.delete(id); else break; } };
  const touch = (id) => { sweep(); const v = map.get(id) || { engines: new Map(), at: 0 }; v.at = now(); map.delete(id); map.set(id, v); return v; };
  return {
    // null when a NEW workspace would exceed the cap (the caller answers 503 workspace_cap); an existing one is always served.
    engine(id, vertical, cast) {
      sweep();
      if (!map.has(id) && map.size >= max) return null;
      const v = touch(id);
      if (!v.engines.has(vertical)) v.engines.set(vertical, new Engine(cast));
      return v.engines.get(vertical);
    },
    peek(id, vertical) { sweep(); return map.get(id)?.engines.get(vertical) || null; },
    reset(id) { map.delete(id); },
    size() { return map.size; },
  };
}
