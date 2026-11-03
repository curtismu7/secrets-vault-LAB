// Rule 13: a workspace id keeps one visitor's state apart from another's. Server state per workspace is one Engine per vertical
// (vault, inventory, providers, audit, clock). Bounded in count and age; a new workspace is REFUSED at the cap instead of evicting another's.
// The browser sends its id in X-Workspace (default "default"). Reset clears the current workspace only.
import { Engine } from './engine.js';
import { isCredentialId } from './mask.js';

// 1 to 40 lower-case letters, digits and hyphens, with at least one letter (the page always makes ids with a letter; an all-digit id could be a PIN or a card number).
export const WORKSPACE_RE = /^(?=[a-z0-9-]*[a-z])[a-z0-9-]{1,40}$/;
export const DEFAULT_WORKSPACE = 'default';

// A workspace id is echoed in the `workspace` field and in the hop headers, so one that LOOKS like a credential is refused (400 bad_workspace, never echoed).
// The shared masker decides (isCredentialId): 24 or more hex digits, a credential-word prefix (sk-, pw-, token-, ...), a run of 24 or more letters and digits with a
// digit, and anything its detectors find, also with hyphens read as spaces. A bare word with no keyword ("hunter2xyz") cannot be told from a name and is
// accepted; the page says masking is a heuristic. The old name is kept for the callers.
export const credentialLookingId = isCredentialId;

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
