// The glue between the HTTP layer and the engine: Mock reads tables, Live drives the workspace's engine. Every action gets one W3C
// trace and a list of hops (the raw request and response panes), with anything credential-shaped masked.
import { Engine } from './engine.js';
import { perform } from './actions.js';
import { cleanFree } from './credentials.js';
import { newTrace, formatTraceparent } from './trace.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const SECRET_KEYS = new Set(['secret', 'fields', 'value', 'values']);

// A copy of the visitor's parameters that is safe to show: strings cleaned and masked, anything under a secret-carrying key replaced by a
// write-only marker. Iterative-ish and depth-limited.
export function scrub(value, depth = 0, secret = false) {
  if (secret) return typeof value === 'string' ? `(write-only, ${Buffer.byteLength(value)} bytes)` : isObj(value) || Array.isArray(value) ? '(write-only)' : typeof value === 'number' || typeof value === 'boolean' || value === null ? value : undefined;
  if (typeof value === 'string') return cleanFree(value, 300);
  if (Array.isArray(value)) return depth > 4 ? [] : value.slice(0, 10).map((v) => scrub(v, depth + 1));
  if (isObj(value)) return depth > 4 ? {} : Object.fromEntries(Object.keys(value).slice(0, 20).map((k) => { const ck = cleanFree(k, 40); return [ck, scrub(value[k], depth + 1, SECRET_KEYS.has(k))]; }));
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

// Runs one engine action for a workspace with a trace. Returns { outcome, hops, traceparent, state }, or null when the workspace cap refuses a new workspace.
export function runAction({ ws, workspaces, vertical, cast, op, actorId, params, traceparent, route }) {
  const e = workspaces.engine(ws, vertical, cast);
  if (!e) return null;
  const actor = e.actor(actorId);
  const t = newTrace(traceparent);
  const root = t.span();
  e.trace = { traceId: t.traceId, span: t.span }; e.hops = []; e.hopsTruncated = false;
  let outcome;
  try { outcome = actor ? perform(e, op, actor, params) : { ok: false, status: 401, code: 'unknown_actor', detail: 'the caller is not on the lab roster' }; } finally { e.trace = null; }
  const first = { n: 1, label: 'browser to the lab API', request: { method: route.method, url: route.url, headers: { traceparent: formatTraceparent(t.traceId, root), 'x-workspace': ws, 'x-lab-actor': actor ? actor.id : 'unknown' }, body: scrub(params) }, response: { status: outcome.ok ? 200 : outcome.status, body: outcome.ok ? { ok: true } : { error: outcome.code } } };
  const hops = [first, ...e.hops.map((h, i) => ({ ...h, n: i + 2 }))];
  const truncated = e.hopsTruncated; e.hops = [];
  return { outcome, hops, hopsTruncated: truncated, traceparent: formatTraceparent(t.traceId, root), traceId: t.traceId, state: e.snapshot(actor || e.actor(Object.keys(e.s.vault)[0]), { fullProof: false }) };
}
