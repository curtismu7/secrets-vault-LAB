// The glue between the HTTP layer and the engine: Mock reads tables, Live drives the workspace's engine. Every action gets one W3C
// trace and a list of hops (the raw request and response panes), with anything credential-shaped masked.
import { Engine } from './engine.js';
import { perform, KEYS } from './actions.js';
import { cleanFree } from './credentials.js';
import { newTrace, formatTraceparent } from './trace.js';
import { buildRoster } from './cast.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const SECRET_KEYS = new Set(['secret', 'fields', 'value', 'values']);

// A copy of the visitor's parameters that is safe to show: strings cleaned and masked, anything under a secret-carrying key replaced by a
// write-only marker. Iterative-ish and depth-limited.
// The key names the lab knows. A key that is not on this list is NEVER shown (it could be a credential): the pane says "(unrecognised key N)" instead, at every depth.
const KNOWN = new Set([...Object.values(KEYS).flat(), ...Object.keys(KEYS), 'id', 'mode', 'vertical']);

// A copy of the visitor's parameters that is safe to show: strings cleaned and masked, key names shown only when allow-listed, anything under a
// secret-carrying key replaced by a write-only marker. Depth- and width-limited.
// A shown string is masked FIRST and cut to 300 characters afterwards; when it is cut the pane says so (nothing is silently dropped from view).
const CUT = ' ... (cut for display)';
const shownString = (value) => { const c = cleanFree(value, 301); return c.length > 300 ? `${c.slice(0, 300)}${CUT}` : c; };
export function scrub(value, depth = 0, secret = false) {
  if (secret) return typeof value === 'string' ? `(write-only, ${Buffer.byteLength(value)} bytes)` : isObj(value) || Array.isArray(value) ? '(write-only)' : typeof value === 'number' || typeof value === 'boolean' || value === null ? value : undefined;
  if (typeof value === 'string') return shownString(value);
  if (Array.isArray(value)) return depth > 4 ? '(too deep to show)' : [...value.slice(0, 10).map((v) => scrub(v, depth + 1)), ...(value.length > 10 ? [`(${value.length - 10} more not shown)`] : [])];
  if (isObj(value)) {
    if (depth > 4) return '(too deep to show)';
    let unknown = 0;
    const keys = Object.keys(value);
    const entries = keys.slice(0, 20).map((k) => [KNOWN.has(k) ? k : `(unrecognised key ${++unknown})`, scrub(value[k], depth + 1, SECRET_KEYS.has(k))]);
    if (keys.length > 20) entries.push(['(more keys)', `${keys.length - 20} not shown`]);
    return Object.fromEntries(entries);
  }
  return typeof value === 'number' || typeof value === 'boolean' || value === null ? value : undefined;
}

export function mockState(table, vertical, scenarioId) {
  const v = table.verticals[vertical];
  const sc = (typeof scenarioId === 'string' && v.scenarios.find((s) => s.id === scenarioId)) || v.scenarios[0];
  return { state: sc.state, scenario: { id: sc.id, title: sc.title, say: sc.say, actor: sc.actor, steps: sc.steps }, scenarios: v.scenarios.map((s) => ({ id: s.id, title: s.title, say: s.say })) };
}

export function liveState(ws, workspaces, vertical, cast, actorId) {
  const e = workspaces.peek(ws, vertical) || new Engine(cast);
  const actor = e.actor(actorId) || e.actor(Object.keys(e.s.vault)[0]);
  return e.snapshot(actor);
}

// True when the caller is on the lab roster. Checked BEFORE any workspace is created or any state is built, so an unidentified caller costs nothing.
export const onRoster = (cast, actorId) => typeof actorId === 'string' && buildRoster(cast).some((p) => p.id === actorId);

// Runs one engine action for a workspace with a trace. Returns { outcome, hops, traceparent, state }, or null when the workspace cap refuses a new workspace.
// A caller who is not on the roster gets a 401 outcome with NO state and NO workspace (a refusal for an unidentified caller carries no one's vault).
export function runAction({ ws, workspaces, vertical, cast, op, actorId, params, traceparent, route }) {
  const known = onRoster(cast, actorId);
  const e = known ? workspaces.engine(ws, vertical, cast) : null;
  if (known && !e) return null;
  const actor = known ? e.actor(actorId) : null;
  const t = newTrace(traceparent);
  const root = t.span();
  let outcome;
  if (e) { e.trace = { traceId: t.traceId, span: t.span }; e.hops = []; e.hopsTruncated = false; }
  try { outcome = actor ? perform(e, op, actor, params) : { ok: false, status: 401, code: 'unknown_actor', detail: 'the caller is not on the lab roster' }; } finally { if (e) e.trace = null; }
  const first = { n: 1, label: 'browser to the lab API', request: { method: route.method, url: route.url, headers: { traceparent: formatTraceparent(t.traceId, root), 'x-workspace': ws, 'x-lab-actor': actor ? actor.id : 'unknown' }, body: scrub(params) }, response: { status: outcome.ok ? 200 : outcome.status, body: outcome.ok ? { ok: true } : { error: outcome.code } } };
  const hops = [first, ...(e ? e.hops : []).map((h, i) => ({ ...h, n: i + 2 }))];
  const truncated = e ? e.hopsTruncated : false; if (e) e.hops = [];
  return { outcome, hops, hopsTruncated: truncated, traceparent: formatTraceparent(t.traceId, root), traceId: t.traceId, ...(actor ? { state: e.snapshot(actor) } : {}) };
}
