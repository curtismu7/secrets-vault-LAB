// One dispatch for everything that changes an engine, used by the API, the scripted scenarios and the tests, so they cannot drift apart.
// A refusal from the engine is data ({ ok: false, code, detail }), never an exception; anything else is a bug and propagates.
// Every body is strict: it may carry only the listed keys, and the error never says which key was unexpected (it could be a credential).
// NOTHING here takes an owner, a user or a vault id to act on: the caller is the only vault there is.
import { InputError } from './errors.js';

const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
export function onlyKeys(obj, allowed) { return isObj(obj) && Object.keys(obj).every((k) => allowed.includes(k)); }
export const KEYS = {
  entry: ['name', 'targetId', 'shape', 'headerName', 'notes', 'secret', 'generate'],
  entryPatch: ['name', 'targetId', 'shape', 'headerName', 'notes', 'secret'],
  call: ['targetId', 'as', 'entryId', 'operation'],
  key: ['configured', 'reachable'],
  target: ['id', 'accepts', 'protocol'],
  secret: ['provider', 'path', 'template', 'tags', 'fields'],
  read: ['ref', 'consumer'],
  update: ['ref', 'fields', 'tags'],
  ref: ['ref'],
  change: ['provider', 'op', 'ref', 'newPath', 'path'],
  grant: ['principal', 'scope', 'actions'],
  clock: ['minutes'],
};
const strict = (obj, name) => { if (!onlyKeys(obj, KEYS[name])) throw new InputError('unknown_field', 'the body carries a field the lab does not take'); return obj; };
const idOf = (p) => (typeof p?.id === 'string' ? p.id : '');

const OPS = {
  vaultCreate: (e, a, p) => e.vaultCreate(a, strict(p.entry, 'entry')),
  vaultUpdate: (e, a, p) => e.vaultUpdate(a, idOf(p), strict(p.entry, 'entryPatch')),
  vaultDelete: (e, a, p) => e.vaultDelete(a, idOf(p)),
  vaultRestore: (e, a, p) => e.vaultRestore(a, idOf(p)),
  gatewayCall: (e, a, p) => e.gatewayCall(a, strict(p.call, 'call')),
  restartKeys: (e, a, p) => e.restartKeys(a, strict(p.key, 'key')),
  addTarget: (e, a, p) => e.addTarget(a, strict(p.target, 'target')),
  removeTarget: (e, a, p) => e.removeTarget(a, { id: idOf(p) }),
  storeCreate: (e, a, p) => e.storeCreate(a, strict(p.secret, 'secret')),
  storeRead: (e, a, p) => e.storeRead(a, strict(p.read, 'read')),
  storeUpdate: (e, a, p) => e.storeUpdate(a, strict(p.update, 'update')),
  storeRotate: (e, a, p) => e.storeRotate(a, strict(p, 'ref')),
  storeDelete: (e, a, p) => e.storeDelete(a, strict(p, 'ref')),
  storeRecover: (e, a, p) => e.storeRecover(a, strict(p, 'ref')),
  storePurge: (e, a, p) => e.storePurge(a, strict(p, 'ref')),
  connectProvider: (e, a, p) => e.connectProvider(a, { provider: p?.provider }),
  providerChange: (e, a, p) => e.providerChange(a, strict(p.change, 'change')),
  resync: (e, a) => e.resyncNow(a),
  grant: (e, a, p) => e.grant(a, strict(p.grant, 'grant')),
  revoke: (e, a, p) => e.revoke(a, { id: idOf(p) }),
  advance: (e, a, p) => { e.begin(a); return e.advance(strict(p.clock, 'clock')); },
};
export const OP_NAMES = Object.keys(OPS);

export function perform(engine, op, actor, params) {
  if (!Object.hasOwn(OPS, op)) throw new Error(`unknown op ${op}`);
  try { return { ok: true, result: OPS[op](engine, actor, isObj(params) ? params : {}) }; }
  catch (e) { if (e instanceof InputError) return { ok: false, status: e.status, code: e.code, detail: e.message }; throw e; }
}
