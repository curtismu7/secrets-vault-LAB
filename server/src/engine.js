// The vault engine: (1) a per-user credential vault, strictly self-service, sealed with real AES-256-GCM, injected at request time by a simulated gateway,
// and (2) secret store management over five mock providers with a policy table, an audit trail, a nightly re-sync and a no-copy inventory.
// One Engine per workspace and vertical. No I/O, no network. Randomness (keys, nonces, mock values) comes from an injectable source, so tests can
// prove nonce handling; nothing random reaches a Mock table (only counts, sizes and ids do), so the tables regenerate identically.
// Every product claim behind it is a Ping release claim, UNVERIFIED on our tenant; the shapes below are the lab's and are tagged in data.js.
import { createHmac, randomBytes } from 'node:crypto';
import { buildRoster, DEFAULT_CAST, ROLES } from './cast.js';
import { findCredentials, cleanFree } from './credentials.js';
import { refuse } from './errors.js';
import { formatTraceparent } from './trace.js';
import { aadFor, CONFIGURED, KEY_PROVIDERS, makeKeyMaterial, NONCE_BYTES, openBytes, resolveKey, sealBytes, SealError } from './crypto.js';
import { headersFor, headerNameProblem, maskedHeader, SHAPES, SimBackend } from './gateway.js';
import { allowed, defaultGrants, POLICY_MAX, scopeMatches, scopeProblem, ACTIONS } from './policy.js';
import { buildIndex, drain, leafScan, scanText, selfTest, WINDOW } from './proof.js';
import { callShape, mockValue, PATH_MAX, PROVIDER_IDS, PROVIDERS, SEGMENT, seedProviders, DELINEA_TEMPLATES } from './stores.js';

export const MIN = 60_000; export const HOUR = 60 * MIN; export const DAY = 24 * HOUR;
export const CLOCK_START = Date.parse('2026-11-02T09:00:00.000Z');
export const PURGE_AFTER_MS = 24 * HOUR;
export const NIGHTLY_HOUR_UTC = 2; // lab-invented: when connected stores re-synchronise on the lab clock
export const ADVANCE_MAX_MIN = 10080;
export const LIMITS = {
  entriesPerUser: 500, credentialBytes: 65536, targets: 20, audit: 2000, backendLog: 300, gatewayLog: 300, inventory: 400, policies: POLICY_MAX, reports: 30, hops: 40,
  name: 80, notes: 200, tags: 5, headers: 5, deliveries: 100, proofQuickUnits: 600, workspaceSecretBytes: 4 * 1024 * 1024,
};
const CONSUMERS = ['simulated-gateway', 'simulated-agent-tool'];
const PROTOCOLS = ['mcp', 'a2a'];
const iso = (ms) => new Date(ms).toISOString();
const bytes = (s) => Buffer.byteLength(String(s), 'utf8');
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const isStr = (v, max = 200) => typeof v === 'string' && v.length > 0 && v.length <= max;
const MASK = '••••••••';
const TAG = /^[a-z0-9][a-z0-9-]{0,23}$/;
const TARGET_ID = /^[a-z][a-z0-9-]{1,31}$/;
const ENTRY_ID = /^vcr-\d{4,}$/;
export const nightlyIndex = (ms) => Math.floor((ms - NIGHTLY_HOUR_UTC * HOUR) / DAY);

// A visitor-typed name: cleaned, and REFUSED if it looks like a credential (never echoed, never kept).
function typedName(v, max, code = 'bad_name') {
  if (!isStr(v, max * 3)) throw refuse(code, 'a name is required (plain text, at most the length the lab allows)');
  if (findCredentials(v).length) throw refuse('credential_shaped_text', 'that text looks like a credential, so the lab refuses to keep it as a name');
  const c = cleanFree(v, max);
  if (!c || c.length > max) throw refuse(code, 'a name is required (plain text, at most the length the lab allows)');
  return c;
}
const notesOf = (v) => (v === undefined || v === null ? '' : typeof v === 'string' ? cleanFree(v, LIMITS.notes) : (() => { throw refuse('bad_notes', 'notes must be text'); })());

export class Engine {
  #keys; #material; #shared; #connections; #providers; #rand;
  constructor(cast = DEFAULT_CAST, { rand = randomBytes } = {}) {
    this.cast = cast; this.#rand = rand;
    this.roster = new Map(buildRoster(cast).map((p) => [p.id, p]));
    this.trace = null; this.hops = []; this.hopsTruncated = false;
    this.#material = makeKeyMaterial(rand);
    this.keyConfig = { configured: 'aws', reachable: true };
    this.#keys = { ...resolveKey(this.#material, 'aws', true), version: 1 };
    this.nonces = new Set(); // hex of every nonce used under the active key (a reused nonce is refused)
    this.backend = new SimBackend(rand, 5000);
    const seeded = seedProviders(cast, rand);
    this.#providers = seeded.providers; this.pidSeq = seeded.pidSeq;
    this.#shared = {}; this.#connections = {};
    this.consumers = Object.fromEntries(CONSUMERS.map((c) => [c, { key: rand(32), last: null }]));
    this.s = this.fresh();
    this.version = 0; this.proofCache = null; this.proofJob = null; this.proofSlices = 0;
    this.seedTargets();
    this.seedConnections();
    this.seedInventory();
  }

  fresh() {
    return {
      clock: CLOCK_START, seq: { entry: 0, audit: 0, policy: 0, report: 0, delivery: 0, call: 0 },
      vault: Object.fromEntries([...this.roster.values()].map((p) => [p.id, []])),
      targets: [], policies: [], audit: [], inventory: [], reports: [], gatewayLog: [], deliveries: [], connections: {}, counters: { sealed: 0, purged: 0, cleaned: 0 },
      lastNightly: nightlyIndex(CLOCK_START),
    };
  }

  // ---- plumbing --------------------------------------------------------------------------------------------------------------------------------
  hop(label, request, response) {
    if (!this.trace) return;
    if (this.hops.length >= LIMITS.hops) { this.hopsTruncated = true; return; }
    this.hops.push({ n: this.hops.length + 1, label, request: { ...request, headers: { traceparent: formatTraceparent(this.trace.traceId, this.trace.span()), ...(request.headers || {}) } }, response });
  }
  now() { return this.s.clock; }
  actor(id) { return typeof id === 'string' && this.roster.has(id) ? this.roster.get(id) : null; }
  need(actor) { if (!actor || !this.actor(actor.id)) throw refuse('unknown_actor', 'the caller is not on the lab roster', 401); return this.roster.get(actor.id); }
  requireRole(actor, role) { if (actor.role !== role) throw refuse('forbidden_role', `this action is for the ${role} role`, 403); }
  audit(actor, domain, action, resource, outcome, code = '') {
    this.version += 1;
    this.s.audit.push({ id: `aud-${String(++this.s.seq.audit).padStart(5, '0')}`, at: iso(this.now()), actor: actor === 'system' ? 'system' : actor === 'provider-console' ? 'provider-console' : actor.id, role: typeof actor === 'string' ? actor : actor.role, domain, action, resource, outcome, ...(code ? { code } : {}) });
  }
  room(n = 6) { if (this.s.audit.length + n > LIMITS.audit) throw refuse('workspace_full', 'the audit trail of this workspace is full: Reset to start again', 409); }
  begin(actorIn) { const a = this.need(actorIn); this.sweep(); this.room(); return a; }
  freshNonce() {
    for (let i = 0; i < 8; i++) { const n = this.#rand(NONCE_BYTES); const h = n.toString('hex'); if (!this.nonces.has(h)) { this.nonces.add(h); return n; } }
    throw refuse('nonce_exhausted', 'could not draw an unused nonce', 500);
  }

  // ---- seeding ---------------------------------------------------------------------------------------------------------------------------------
  seedTargets() {
    const c = this.cast;
    this.s.targets = [
      { id: c.castT1, host: `${c.castT1}.example`, protocol: 'mcp', accepts: 'bearer', operations: ['read_summary', 'list_items'] },
      { id: c.castT2, host: `${c.castT2}.example`, protocol: 'a2a', accepts: 'api-key', apiKeyHeader: 'X-Api-Key', operations: ['read_summary', 'list_items'] },
      { id: c.castT3, host: `${c.castT3}.example`, protocol: 'mcp', accepts: 'basic', operations: ['read_summary', 'list_items'] },
      { id: c.castT4, host: `${c.castT4}.example`, protocol: 'a2a', accepts: 'headers', requiredHeaders: ['X-Partner-Id', 'X-Partner-Key'], operations: ['read_summary', 'list_items'] },
    ];
    for (const t of this.s.targets) this.makeShared(t);
  }
  payloadFor(shape, label, headerNames) {
    const m = (k) => mockValue(this.#rand, k);
    if (shape === 'bearer') return { token: m('bearer') };
    if (shape === 'api-key') return { key: m('apikey') };
    if (shape === 'basic') return { username: `mock-${label}`, password: m('basic') };
    return { headers: Object.fromEntries((headerNames || ['X-Partner-Id', 'X-Partner-Key']).map((h) => [h, m('header')])) };
  }
  makeShared(t) {
    const p = this.payloadFor(t.accepts, `svc-${t.id}`, t.requiredHeaders);
    this.#shared[t.id] = p;
    this.backend.register(t.id, headersFor(t.accepts, p, t.apiKeyHeader), `svc-${t.id}`);
  }
  seedConnections() {
    for (const id of PROVIDER_IDS) this.connectProviderNow(id, mockValue(this.#rand, `conn-${id}`));
  }
  connectProviderNow(id, credential) {
    this.#providers[id].acceptCredential(credential);
    this.s.connections[id] = { sealed: sealBytes(this.#keys.key, Buffer.from(credential, 'utf8'), `svl1|provider-credential|${id}`, this.freshNonce()), bytes: bytes(credential), version: (this.s.connections[id]?.version || 0) + 1, changedAt: iso(this.now()) };
  }
  seedInventory() {
    for (const id of PROVIDER_IDS) for (const m of this.#providers[id].list()) this.s.inventory.push(this.invRow(id, m));
    this.s.policies = defaultGrants(this.cast).map((g) => ({ id: `pol-${String(++this.s.seq.policy).padStart(4, '0')}`, ...g, by: 'seed', at: iso(this.now()) }));
  }
  invRow(provider, m) { return { ref: `${provider}:${m.path}`, provider, path: m.path, pid: m.pid, template: m.template, tags: m.tags, state: m.state, versions: m.versions, currentVersion: m.currentVersion, rotationCount: m.rotationCount, fields: m.fields, syncedAt: iso(this.now()) }; }

  // ---- the clock, purging and cleanup ------------------------------------------------------------------------------------------------------------
  // Forward only. Staged deletions purge when now >= purgeAt (exactly 24 h after staging); a target removed earlier has had its entries cleaned;
  // every 02:00 the clock crosses runs the nightly re-sync of the connected stores.
  advance({ minutes } = {}) {
    this.room(8 + 8);
    if (!Number.isInteger(minutes) || minutes < 1 || minutes > ADVANCE_MAX_MIN) throw refuse('bad_minutes', 'minutes must be a whole number from 1 to 10080 (the clock only moves forward)');
    const old = this.now(); const to = old + minutes * MIN;
    const crossings = nightlyIndex(to) - nightlyIndex(old);
    this.s.clock = to;
    const swept = this.sweep();
    let nightly = 0;
    for (let i = 1; i <= crossings; i++) { this.resync('nightly', (nightlyIndex(old) + i) * DAY + NIGHTLY_HOUR_UTC * HOUR); nightly += 1; }
    this.s.lastNightly = nightlyIndex(to);
    this.audit('system', 'system', 'clock.advance', '-', 'allowed');
    return { clock: iso(to), purged: swept.purged, cleaned: swept.cleaned, nightlyRuns: nightly };
  }
  sweep() {
    let purged = 0; let cleaned = 0;
    const live = new Set(this.s.targets.map((t) => t.id));
    for (const [user, list] of Object.entries(this.s.vault)) {
      for (let i = list.length - 1; i >= 0; i--) {
        const e = list[i];
        if (!live.has(e.targetId)) { list.splice(i, 1); cleaned += 1; this.s.counters.cleaned += 1; this.audit('system', 'vault', 'vault.cleanup', e.id, 'allowed', 'target_removed'); }
        else if (e.status === 'staged-delete' && this.now() >= e.purgeAt) { list.splice(i, 1); purged += 1; this.s.counters.purged += 1; this.audit('system', 'vault', 'vault.purge', e.id, 'allowed', 'staged_24h'); }
      }
      void user;
    }
    return { purged, cleaned };
  }

  // ---- the user vault: strictly self-service -----------------------------------------------------------------------------------------------------
  // Every function here takes the CALLER and touches only the caller's own list. There is no owner parameter and no role that widens it.
  mine(actor) { return Object.hasOwn(this.s.vault, actor.id) ? this.s.vault[actor.id] : null; }
  needVault(actor) { return this.mine(actor); }
  entryOf(actor, id) {
    const l = this.needVault(actor);
    const e = typeof id === 'string' && ENTRY_ID.test(id) ? l.find((x) => x.id === id) : null;
    if (!e) throw refuse('not_found', 'there is no such entry in your vault', 404);
    return e;
  }
  entryView(e) {
    const now = this.now();
    const secret = { present: true, bytes: e.secretBytes, version: e.version, lastChanged: iso(e.secretChangedAt), masked: MASK, nonce: Buffer.from(e.sealed.n, 'base64').toString('hex').slice(0, 8) };
    return {
      id: e.id, name: e.name, targetId: e.targetId, shape: e.shape, ...(e.shape === 'api-key' ? { headerName: e.headerName } : {}), ...(e.shape === 'headers' ? { headerNames: e.headerNames } : {}),
      notes: e.notes, status: e.status, createdAt: iso(e.createdAt), updatedAt: iso(e.updatedAt), secret,
      ...(e.status === 'staged-delete' ? { stagedAt: iso(e.stagedAt), purgeAt: iso(e.purgeAt), purgesInMin: Math.max(0, Math.ceil((e.purgeAt - now) / MIN)) } : {}),
    };
  }
  sealedTotal() { return Object.values(this.s.vault).reduce((n, l) => n + l.reduce((m, e) => m + e.secretBytes, 0), 0); }
  vaultList(actor) { const a = this.need(actor); return this.mine(a).map((e) => this.entryView(e)); }
  vaultGet(actor, id) { const a = this.need(actor); return this.entryView(this.entryOf(a, id)); }

  checkPayload(shape, payload, { partial = false } = {}) {
    const strs = (o, keys) => keys.every((k) => Object.hasOwn(o, k) && typeof o[k] === 'string' && o[k].length > 0 && !/[\r\n\0]/.test(o[k]));
    if (!isObj(payload) || (partial && Object.keys(payload).length === 0)) throw refuse('bad_secret', 'the secret must be an object for this credential shape, with at least one field when merging');
    const allowedKeys = { bearer: ['token'], 'api-key': ['key'], basic: ['username', 'password'], headers: ['headers'] }[shape];
    if (!Object.keys(payload).every((k) => allowedKeys.includes(k))) throw refuse('bad_secret', 'the secret carries a field this credential shape does not have');
    if (!partial) {
      if (shape === 'headers' ? !isObj(payload.headers) : !strs(payload, allowedKeys)) throw refuse('bad_secret', 'a secret field is missing, empty or contains a line break');
    } else for (const k of Object.keys(payload)) if (k !== 'headers' && (typeof payload[k] !== 'string' || payload[k].length === 0 || /[\r\n\0]/.test(payload[k]))) throw refuse('bad_secret', 'a secret field must be a non-empty string without line breaks');
    if (shape === 'basic' && typeof payload.username === 'string' && payload.username.includes(':')) throw refuse('bad_secret', 'an HTTP Basic user name cannot contain a colon');
    if (shape === 'headers' && payload.headers !== undefined) {
      if (!isObj(payload.headers)) throw refuse('bad_secret', 'headers must be an object of name to value');
      for (const [k, v] of Object.entries(payload.headers)) {
        if (headerNameProblem(k)) throw refuse('bad_header_name', 'a header name is not allowed');
        if (!(v === null && partial) && (typeof v !== 'string' || v.length === 0 || /[\r\n\0]/.test(v))) throw refuse('bad_secret', 'a header value must be a non-empty string without line breaks');
      }
    }
  }
  secretBytesOf(shape, p) { return shape === 'bearer' ? bytes(p.token) : shape === 'api-key' ? bytes(p.key) : shape === 'basic' ? bytes(p.username) + bytes(p.password) : Object.values(p.headers).reduce((n, v) => n + bytes(v), 0); }
  mergePayload(shape, old, patch) {
    if (shape !== 'headers') return { ...(old || {}), ...patch };
    const headers = { ...(old?.headers || {}) };
    for (const [k, v] of Object.entries(patch.headers || {})) { if (v === null) delete headers[k]; else headers[k] = v; }
    return { headers };
  }
  checkFinal(shape, payload) {
    this.checkPayload(shape, payload);
    if (shape === 'headers') { const n = Object.keys(payload.headers).length; if (n < 1 || n > LIMITS.headers) throw refuse('bad_secret', 'a custom header credential has 1 to 5 header pairs'); }
    if (this.secretBytesOf(shape, payload) > LIMITS.credentialBytes) throw refuse('credential_too_large', 'a credential is at most 64 KB (65536 bytes); this one is larger, so nothing was stored', 413);
  }
  seal(userId, entryId, payload) { return sealBytes(this.#keys.key, Buffer.from(JSON.stringify(payload), 'utf8'), aadFor(userId, entryId), this.freshNonce()); }
  open(userId, entry) {
    try { return JSON.parse(openBytes(this.#keys.key, entry.sealed, aadFor(userId, entry.id)).toString('utf8')); }
    catch (e) { if (e instanceof SealError) { this.audit(this.roster.get(userId) || 'system', 'vault', 'vault.integrity', entry.id, 'denied', 'sealed_value_rejected'); throw refuse('sealed_value_rejected', 'the stored value failed its integrity check and was not used', 409); } throw e; }
  }
  register(entry, payload) { this.backend.register(entry.targetId, headersFor(entry.shape, payload, entry.headerName), entry.owner); }
  headerNamesOf(shape, payload) { return shape === 'headers' ? Object.keys(payload.headers).sort() : undefined; }

  vaultCreate(actorIn, input) {
    const a = this.begin(actorIn); const l = this.needVault(a);
    if (!this.backend.hasRoom()) throw refuse('workspace_full', 'the backend registry is full: Reset to start again', 409);
    if (l.length >= LIMITS.entriesPerUser) throw refuse('vault_full', 'a vault holds at most 500 entries (entries staged for deletion count until they are purged), so nothing was stored', 409);
    const t = this.targetOf(input.targetId);
    if (!SHAPES.includes(input.shape)) throw refuse('bad_shape', 'the credential shape must be bearer, api-key, basic or headers');
    const name = typedName(input.name, LIMITS.name);
    const notes = notesOf(input.notes);
    let headerName; if (input.shape === 'api-key') { headerName = input.headerName === undefined ? (t.apiKeyHeader || 'X-Api-Key') : input.headerName; if (headerNameProblem(headerName)) throw refuse('bad_header_name', 'a header name is not allowed'); }
    else if (input.headerName !== undefined) throw refuse('bad_shape', 'only an API key credential has a header name of its own');
    if ((input.secret === undefined) === (input.generate !== true)) throw refuse('bad_secret', 'give a secret, or ask for a generated mock credential (generate: true), not both and not neither');
    const payload = input.generate === true ? this.payloadFor(input.shape, a.id, undefined) : input.secret;
    this.checkFinal(input.shape, payload);
    if (this.sealedTotal() + this.secretBytesOf(input.shape, payload) > LIMITS.workspaceSecretBytes) throw refuse('workspace_secret_bytes_full', 'this workspace holds at most 4 MB of sealed credentials (a lab safety limit, not a deck claim): delete and purge some, or Reset', 409);
    const id = `vcr-${String(++this.s.seq.entry).padStart(4, '0')}`;
    const e = { id, owner: a.id, name, targetId: t.id, shape: input.shape, ...(headerName ? { headerName } : {}), ...(input.shape === 'headers' ? { headerNames: this.headerNamesOf('headers', payload) } : {}), notes, status: 'active', createdAt: this.now(), updatedAt: this.now(), secretChangedAt: this.now(), version: 1, secretBytes: this.secretBytesOf(input.shape, payload), sealed: this.seal(a.id, id, payload) };
    l.push(e); this.s.counters.sealed += 1;
    this.register(e, payload);
    this.hop('vault: seal (AES-256-GCM, fresh 12-byte nonce, AAD = user id + entry id)', { method: 'PUT', url: `vault://${a.id}/entries/${id}`, body: { shape: e.shape, secret: `${MASK} (write-only, ${e.secretBytes} bytes)` } }, { status: 201, body: { sealedBytes: e.secretBytes, keyProvider: this.#keys.provider, nonce: Buffer.from(e.sealed.n, 'base64').toString('hex').slice(0, 8) } });
    this.audit(a, 'vault', 'vault.create', id, 'allowed');
    return { entryId: id, entry: this.entryView(e) };
  }
  targetOf(id) { const t = typeof id === 'string' ? this.s.targets.find((x) => x.id === id) : null; if (!t) throw refuse('unknown_target', 'there is no such target system', 400); return t; }

  // Merge, never replace: omitted fields keep their stored value, and omitting the secret keeps the sealed value byte for byte.
  vaultUpdate(actorIn, id, patch) {
    const a = this.begin(actorIn); const e = this.entryOf(a, id);
    if (e.status !== 'active') throw refuse('entry_staged_for_delete', 'restore the entry before editing it', 409);
    const next = { ...e };
    if (patch.name !== undefined) next.name = typedName(patch.name, LIMITS.name);
    if (patch.notes !== undefined) next.notes = notesOf(patch.notes);
    if (patch.targetId !== undefined) next.targetId = this.targetOf(patch.targetId).id;
    const shape = patch.shape === undefined ? e.shape : patch.shape;
    if (!SHAPES.includes(shape)) throw refuse('bad_shape', 'the credential shape must be bearer, api-key, basic or headers');
    const shapeChanged = shape !== e.shape;
    next.shape = shape;
    if (shape === 'api-key') { const hn = patch.headerName !== undefined ? patch.headerName : (shapeChanged ? (this.targetOf(next.targetId).apiKeyHeader || 'X-Api-Key') : e.headerName); if (headerNameProblem(hn)) throw refuse('bad_header_name', 'a header name is not allowed'); next.headerName = hn; }
    else { if (patch.headerName !== undefined) throw refuse('bad_shape', 'only an API key credential has a header name of its own'); delete next.headerName; }
    if (shapeChanged && patch.secret === undefined) throw refuse('secret_required', 'changing the credential shape needs a complete new secret', 400);
    let payload = null;
    if (patch.secret !== undefined) {
      this.checkPayload(shape, patch.secret, { partial: !shapeChanged });
      payload = shapeChanged ? patch.secret : this.mergePayload(shape, this.open(a.id, e), patch.secret);
      this.checkFinal(shape, payload);
      if (this.sealedTotal() - e.secretBytes + this.secretBytesOf(shape, payload) > LIMITS.workspaceSecretBytes) throw refuse('workspace_secret_bytes_full', 'this workspace holds at most 4 MB of sealed credentials (a lab safety limit, not a deck claim): delete and purge some, or Reset', 409);
      if (!this.backend.hasRoom()) throw refuse('workspace_full', 'the backend registry is full: Reset to start again', 409);
    }
    // all checks passed: commit
    if (payload) {
      next.sealed = this.seal(a.id, e.id, payload); next.secretBytes = this.secretBytesOf(shape, payload); next.version = e.version + 1; next.secretChangedAt = this.now();
      if (shape === 'headers') next.headerNames = this.headerNamesOf(shape, payload); else delete next.headerNames;
      this.s.counters.sealed += 1;
    } else if (next.headerNames === undefined && shape === 'headers') next.headerNames = e.headerNames;
    next.updatedAt = this.now();
    Object.assign(e, next);
    if (payload) this.register(e, payload);
    this.hop(payload ? 'vault: merge, then re-seal (fresh nonce)' : 'vault: metadata only (the sealed value is not touched)', { method: 'PATCH', url: `vault://${a.id}/entries/${e.id}`, body: { changed: Object.keys(patch).filter((k) => k !== 'secret'), secret: patch.secret === undefined ? 'omitted: the stored value is kept' : `${MASK} (write-only)` } }, { status: 200, body: { secretVersion: e.version, sealedChanged: !!payload } });
    this.audit(a, 'vault', 'vault.update', e.id, 'allowed', payload ? 'secret_changed' : 'metadata_only');
    return { entryId: e.id, secretChanged: !!payload, entry: this.entryView(e) };
  }

  vaultDelete(actorIn, id) {
    const a = this.begin(actorIn); const e = this.entryOf(a, id);
    if (e.status === 'staged-delete') throw refuse('already_staged', 'this entry is already staged for deletion', 409);
    e.status = 'staged-delete'; e.stagedAt = this.now(); e.purgeAt = this.now() + PURGE_AFTER_MS; e.updatedAt = this.now();
    this.audit(a, 'vault', 'vault.delete', e.id, 'allowed', 'staged');
    return { entryId: e.id, purgeAt: iso(e.purgeAt), entry: this.entryView(e) };
  }
  vaultRestore(actorIn, id) {
    const a = this.begin(actorIn); const e = this.entryOf(a, id);
    if (e.status !== 'staged-delete') throw refuse('not_staged', 'this entry is not staged for deletion', 409);
    e.status = 'active'; delete e.stagedAt; delete e.purgeAt; e.updatedAt = this.now();
    this.audit(a, 'vault', 'vault.restore', e.id, 'allowed');
    return { entryId: e.id, entry: this.entryView(e) };
  }

  // ---- key provider ------------------------------------------------------------------------------------------------------------------------------
  // "Restart" the vault service with a key source. The data key is resolved again; because everything runs in one process the lab re-seals every
  // sealed value under the new key (fresh nonces) so the demo continues. A real deployment that came up with a different key could not open its old
  // values: that part is lab-invented and said so on the page.
  restartKeys(actorIn, { configured, reachable } = {}) {
    const a = this.begin(actorIn); this.requireRole(a, 'admin');
    if (!CONFIGURED.includes(configured) || typeof reachable !== 'boolean') throw refuse('bad_key_config', 'configured must be aws, vault or none, and reachable true or false');
    const next = resolveKey(this.#material, configured, reachable);
    const old = this.#keys;
    const opened = [];
    for (const [user, list] of Object.entries(this.s.vault)) for (const e of list) opened.push([e, this.open(user, e)]);
    const conns = Object.keys(this.s.connections).map((id) => [id, openBytes(old.key, this.s.connections[id].sealed, `svl1|provider-credential|${id}`)]);
    this.#keys = { ...next, version: old.version + 1 }; this.nonces = new Set(); this.keyConfig = { configured, reachable };
    for (const [e, p] of opened) { e.sealed = this.seal(e.owner, e.id, p); this.s.counters.sealed += 1; }
    for (const [id, c] of conns) this.s.connections[id].sealed = sealBytes(this.#keys.key, c, `svl1|provider-credential|${id}`, this.freshNonce());
    this.hop(`key provider: ${next.provider}`, { method: 'RESOLVE', url: `key://${next.provider}`, body: { configured, reachable } }, { status: 200, body: { active: next.provider, reason: next.reason, steps: next.steps, valuesResealed: opened.length } });
    this.audit(a, 'vault', 'vault.keys', next.provider, 'allowed', next.reason.replace(/ /g, '_'));
    return { provider: next.provider, warning: next.warning, resealed: opened.length + conns.length, keyVersion: this.#keys.version };
  }
  keyView() {
    const k = this.#keys;
    return { configured: this.keyConfig.configured, reachable: this.keyConfig.reachable, active: k.provider, label: KEY_PROVIDERS[k.provider].label, keyRef: k.keyRef, warning: k.warning, reason: k.reason, steps: k.steps, keyVersion: k.version,
      algorithm: 'AES-256-GCM', nonceBytes: NONCE_BYTES, aad: 'user id + entry id', providers: Object.values(KEY_PROVIDERS).map((p) => ({ id: p.id, label: p.label })) };
  }

  // ---- targets ----------------------------------------------------------------------------------------------------------------------------------
  addTarget(actorIn, input) {
    const a = this.begin(actorIn); this.requireRole(a, 'admin');
    if (this.s.targets.length >= LIMITS.targets) throw refuse('targets_full', 'a workspace has at most 20 target systems', 409);
    if (typeof input.id !== 'string' || !TARGET_ID.test(input.id) || findCredentials(input.id).length) throw refuse('bad_target', 'a target id is lowercase letters, digits and dashes, 2 to 32 characters');
    if (this.s.targets.some((t) => t.id === input.id)) throw refuse('target_exists', 'that target already exists', 409);
    if (!SHAPES.includes(input.accepts) || !PROTOCOLS.includes(input.protocol)) throw refuse('bad_target', 'accepts must be a credential shape and protocol mcp or a2a');
    if (!this.backend.hasRoom()) throw refuse('workspace_full', 'the backend registry is full: Reset to start again', 409);
    const t = { id: input.id, host: `${input.id}.example`, protocol: input.protocol, accepts: input.accepts, ...(input.accepts === 'api-key' ? { apiKeyHeader: 'X-Api-Key' } : {}), ...(input.accepts === 'headers' ? { requiredHeaders: ['X-Partner-Id', 'X-Partner-Key'] } : {}), operations: ['read_summary', 'list_items'] };
    this.s.targets.push(t); this.makeShared(t);
    this.audit(a, 'vault', 'target.add', t.id, 'allowed');
    return { targetId: t.id };
  }
  removeTarget(actorIn, input) {
    const a = this.begin(actorIn); this.requireRole(a, 'admin');
    const t = this.targetOf(input.id);
    this.s.targets = this.s.targets.filter((x) => x.id !== t.id); delete this.#shared[t.id];
    const before = this.s.counters.cleaned;
    const swept = this.sweep(); // automatic clean-up of entries whose target system is gone (the admin never reads them)
    this.audit(a, 'vault', 'target.remove', t.id, 'allowed', `entries_cleaned_${this.s.counters.cleaned - before}`);
    return { targetId: t.id, entriesCleaned: swept.cleaned };
  }

  // ---- the simulated gateway ---------------------------------------------------------------------------------------------------------------------
  // The agent asks for an operation on a target. The gateway builds the credential from the CALLER's own vault entry (per-user), or from the
  // application's shared service account (shown for contrast), injects it, and the backend answers and logs who acted. The agent never holds it.
  gatewayCall(actorIn, { targetId, as, entryId, operation } = {}) {
    const a = this.begin(actorIn);
    const t = this.targetOf(targetId);
    if (!['per-user', 'shared'].includes(as)) throw refuse('bad_mode', 'as must be per-user or shared');
    if (typeof operation !== 'string' || !t.operations.includes(operation)) throw refuse('bad_operation', 'that operation is not offered by this target');
    if (this.s.gatewayLog.length >= LIMITS.gatewayLog) this.s.gatewayLog.shift();
    let headers; let lookedIn; let entry = null;
    this.hop('agent to gateway (no credential)', { method: 'POST', url: `https://gateway.example/${t.protocol}/${t.id}`, body: { tool: operation, onBehalfOf: a.id, credential: 'none: the agent never holds one' } }, { status: 202, body: { note: 'the gateway adds the credential' } });
    if (as === 'per-user') {
      if (entryId === undefined) {
        // no entry named: use the caller's one live entry for this target. If there is none the call is REFUSED: it never falls back to a shared account.
        const live = this.mine(a).filter((x) => x.targetId === t.id && x.status === 'active');
        if (live.length === 0) throw refuse('no_credential_for_target', 'you have no credential in your vault for this target, and the gateway does not fall back to a shared account', 409);
        if (live.length > 1) throw refuse('entry_required', 'you have more than one entry for this target: name the one to use', 409);
        entry = live[0];
      } else entry = this.entryOf(a, entryId);
      if (entry.status !== 'active') throw refuse('entry_staged_for_delete', 'a staged entry cannot be used', 409);
      if (entry.targetId !== t.id) throw refuse('entry_target_mismatch', 'that entry belongs to a different target system', 409);
      const payload = this.open(a.id, entry);
      headers = headersFor(entry.shape, payload, entry.headerName);
      lookedIn = `the vault of ${a.id} (the caller's own; no other vault can be named)`;
      this.hop('gateway: the caller\'s own vault, unseal (AES-256-GCM, AAD = user + entry)', { method: 'GET', url: `vault://${a.id}/entries/${entry.id}` }, { status: 200, body: { shape: entry.shape, unsealed: true, bytes: entry.secretBytes } });
    } else {
      headers = headersFor(t.accepts, this.#shared[t.id], t.apiKeyHeader);
      lookedIn = `the application's shared service account for ${t.id} (one credential for every caller)`;
      this.hop('gateway: the shared service account', { method: 'GET', url: `gateway://apps/${t.id}/service-account` }, { status: 200, body: { sharedByEveryone: true } });
    }
    const injected = headers.map(maskedHeader);
    const r = this.backend.handle(t, headers, operation, iso(this.now()), LIMITS.backendLog);
    this.hop(`gateway to ${t.id} (credential injected)`, { method: 'POST', url: `https://${t.host}/${t.protocol}`, headers: Object.fromEntries(injected.map((i) => [i.header, i.shown])), body: { tool: operation } }, { status: r.status, body: { principal: r.principal, result: r.status === 200 ? 'ok' : r.outcome } });
    const n = ++this.s.seq.call;
    this.s.gatewayLog.push({ n, at: iso(this.now()), actor: a.id, targetId: t.id, as, entryId: entry?.id || null, status: r.status });
    this.audit(a, 'vault', 'gateway.call', entry?.id || `shared:${t.id}`, r.status === 200 ? 'allowed' : 'denied', r.status === 200 ? as : 'backend_rejected');
    return {
      callNumber: n, status: r.status,
      agentView: { asked: `${operation} on ${t.id}`, holdsCredential: false, sees: r.status === 200 ? 'the answer only' : 'a refusal only', answer: { status: r.status, result: r.status === 200 ? 'ok' : r.outcome } },
      gatewayView: { as, lookedIn, shape: entry?.shape || t.accepts, injected },
      backendView: { target: t.id, receivedFromGateway: true, principal: r.principal, status: r.status, outcome: r.outcome, logLine: `${iso(this.now())} ${t.id} ${operation} principal=${r.principal === null ? 'unknown' : r.principal} status=${r.status}` },
    };
  }

  // ---- secret stores -----------------------------------------------------------------------------------------------------------------------------
  provider(id) { if (typeof id !== 'string' || !Object.hasOwn(this.#providers, id)) throw refuse('unknown_provider', 'there is no such secret store provider', 400); return this.#providers[id]; }
  invOf(ref) { return typeof ref === 'string' && ref.length <= 160 ? this.s.inventory.find((r) => r.ref === ref) || null : null; }
  // A caller that has no grant at all on a path is told "not found" (existence is not revealed); one with some grant but not this action is told no.
  gate(actor, row, action, op = action) {
    const any = ACTIONS.some((x) => allowed(this.s.policies, actor.id, x, row.provider, row.path));
    if (!any) { this.audit(actor, 'store', `store.${op}`, row ? row.ref : '-', 'denied', 'no_grant'); throw refuse('not_found', 'there is no such secret in the inventory', 404); }
    if (!allowed(this.s.policies, actor.id, action === 'read' ? 'read' : 'write', row.provider, row.path)) {
      this.audit(actor, 'store', `store.${op}`, row.ref, 'denied', `${action === 'read' ? 'read' : 'write'}_not_granted`);
      this.hop('policy engine: denied', { method: 'CHECK', url: `policy://${row.provider}`, body: { actor: actor.id, action: action === 'read' ? 'read' : 'write' } }, { status: 403, body: { allowed: false, reason: `${action === 'read' ? 'read' : 'write'} is a separate grant` } });
      throw refuse('access_denied', `you hold a grant on this secret, but not ${action === 'read' ? 'read' : 'write'}: read and write are separate grants`, 403);
    }
    this.hop('policy engine: allowed', { method: 'CHECK', url: `policy://${row.provider}`, body: { actor: actor.id, action: action === 'read' ? 'read' : 'write' } }, { status: 200, body: { allowed: true } });
  }
  // Authenticate to the provider with the connection credential, decrypted only for this call.
  connect(id, op, path) {
    const p = this.provider(id);
    let cred;
    try { cred = openBytes(this.#keys.key, this.s.connections[id].sealed, `svl1|provider-credential|${id}`).toString('utf8'); } catch { throw refuse('provider_credential_rejected', 'the stored provider connection failed its integrity check', 409); }
    if (!p.authenticate(cred)) throw refuse('provider_credential_rejected', 'the provider did not accept the stored connection', 409);
    const shape = callShape(id, path, op);
    return { p, shape };
  }
  providerHop(id, op, path, conn, resp) {
    this.hop(`${PROVIDERS[id].name} (simulated, ${op})`, { method: conn.shape.method, url: conn.shape.url, headers: { authorization: 'the provider connection is sealed at rest and never shown' } }, resp);
  }

  rowFor(actor, ref) { const row = this.invOf(ref); if (!row) { this.audit(actor, 'store', 'store.lookup', '-', 'denied', 'not_found'); throw refuse('not_found', 'there is no such secret in the inventory', 404); } return row; }
  refreshRow(row) { const m = this.#providers[row.provider].list().find((x) => x.pid === row.pid); Object.assign(row, this.invRow(row.provider, m)); }
  canOf(actor, row) { return { read: allowed(this.s.policies, actor.id, 'read', row.provider, row.path), write: allowed(this.s.policies, actor.id, 'write', row.provider, row.path) }; }
  visibleInventory(actor) { return this.s.inventory.map((r) => ({ r, can: this.canOf(actor, r) })).filter((x) => x.can.read || x.can.write); }

  tagsOf(v) {
    if (v === undefined) return [];
    if (!Array.isArray(v) || v.length > LIMITS.tags || !v.every((t) => typeof t === 'string' && TAG.test(t) && !findCredentials(t).length)) throw refuse('bad_tags', 'tags are up to 5 short lowercase words (letters, digits, dashes)');
    return [...new Set(v)];
  }
  fieldMap(v) { if (v === undefined) return null; if (!isObj(v) || Object.keys(v).length > 8) throw refuse('bad_field_value', 'fields must be an object of field name to value'); return v; }

  storeCreate(actorIn, input) {
    const a = this.begin(actorIn);
    const p = this.provider(input.provider);
    if (typeof input.path !== 'string' || input.path.length > PATH_MAX || findCredentials(input.path).length) throw refuse('bad_path', 'that path is not valid for this provider');
    if (!allowed(this.s.policies, a.id, 'write', p.id, input.path)) { this.audit(a, 'store', 'store.create', `${p.id}:-`, 'denied', 'write_not_granted'); throw refuse('access_denied', 'you do not hold the write grant for that location', 403); }
    const template = p.id === 'delinea' ? (input.template === undefined ? 'Password' : input.template) : null;
    if (p.id !== 'delinea' && input.template !== undefined) throw refuse('bad_template', 'only Delinea Secret Server has templates');
    if (p.id === 'delinea' && (typeof template !== 'string' || !Object.hasOwn(DELINEA_TEMPLATES, template))) throw refuse('bad_template', 'the template must be Password or Secure-File');
    const problem = p.pathProblem(input.path); if (problem) throw refuse(problem, problem === 'already_exists' ? 'a secret already exists at that path' : problem === 'parent_not_found' ? 'the folder, vault, safe or project does not exist at the provider' : 'that path is not valid for this provider', problem === 'already_exists' ? 409 : 400);
    const tags = this.tagsOf(input.tags); const given = this.fieldMap(input.fields);
    if (this.s.inventory.length >= LIMITS.inventory) throw refuse('inventory_full', 'the inventory is full at 400 secrets, so Reset to start again', 409);
    const conn = this.connect(p.id, 'create', input.path);
    p.fieldsFrom(template, given); // validate before creating
    const pid = p.create({ path: input.path, template, tags, given, now: this.now() });
    const row = this.invRow(p.id, p.list().find((x) => x.pid === pid)); this.s.inventory.push(row);
    this.providerHop(p.id, 'create', input.path, conn, { status: 201, body: { created: true, versions: 1 } });
    this.audit(a, 'store', 'store.create', row.ref, 'allowed');
    return { ref: row.ref, item: this.itemView(a, row) };
  }

  // The value is fetched LIVE from the provider and delivered to a simulated consumer. No API response carries it.
  storeRead(actorIn, { ref, consumer } = {}) {
    const a = this.begin(actorIn);
    if (!CONSUMERS.includes(consumer)) throw refuse('bad_consumer', 'the consumer must be one of the lab\'s simulated consumers');
    const row = this.rowFor(a, ref); this.gate(a, row, 'read');
    if (row.state !== 'active') throw refuse('soft_deleted', 'soft-deleted at the provider: recover it first', 409);
    const conn = this.connect(row.provider, 'read', row.path);
    const fields = conn.p.read(row.pid);
    if (!fields) throw refuse('not_found_at_provider', 'the provider no longer has this secret, so re-synchronise the inventory', 409);
    this.providerHop(row.provider, 'read', row.path, conn, { status: 200, body: { fields: Object.keys(fields), values: 'returned to the gateway only, never to this API' } });
    const total = Object.values(fields).reduce((n, f) => n + bytes(f.value), 0);
    this.consumers[consumer].last = { ref: row.ref, provider: row.provider, pid: row.pid, bytes: total, at: iso(this.now()), digest: this.consumerDigest(consumer, fields) };
    if (this.s.deliveries.length >= LIMITS.deliveries) this.s.deliveries.shift();
    const n = ++this.s.seq.delivery;
    this.s.deliveries.push({ n, at: iso(this.now()), actor: a.id, ref: row.ref, consumer, bytes: total, fields: Object.keys(fields) });
    this.hop(`${consumer} (simulated)`, { method: 'DELIVER', url: `consumer://${consumer}`, body: { ref: row.ref, value: `${MASK} (${total} bytes)` } }, { status: 200, body: { received: true, bytes: total } });
    this.audit(a, 'store', 'store.read', row.ref, 'allowed', consumer);
    return { delivered: true, consumer, ref: row.ref, bytes: total, fields: Object.entries(fields).map(([name, f]) => ({ name, type: f.type, bytes: bytes(f.value), shown: MASK })), note: 'value delivered to the consumer (masked)' };
  }

  consumerDigest(consumer, fields) { return createHmac('sha256', this.consumers[consumer].key).update(JSON.stringify(fields)).digest('hex'); }
  // What each simulated consumer last received, compared NOW against a fresh read of the provider (a rotation or an edit made since makes it stale). Never a constant.
  consumerStates() {
    return CONSUMERS.map((name) => {
      const last = this.consumers[name].last;
      if (!last) return { name, last: null, currentWithProvider: null, reason: 'nothing delivered yet' };
      const fresh = this.#providers[last.provider].read(last.pid);
      if (!fresh) return { name, last: { ref: last.ref, bytes: last.bytes, at: last.at }, currentWithProvider: null, reason: 'the secret is gone or soft-deleted at the provider' };
      const same = this.consumerDigest(name, fresh) === last.digest;
      return { name, last: { ref: last.ref, bytes: last.bytes, at: last.at }, currentWithProvider: same, reason: same ? 'what the consumer holds equals a fresh read of the provider' : 'the provider value changed after the delivery: the consumer holds an old copy' };
    });
  }

  storeUpdate(actorIn, { ref, fields, tags } = {}) {
    const a = this.begin(actorIn);
    const row = this.rowFor(a, ref); this.gate(a, row, 'write', 'update');
    if (row.state !== 'active') throw refuse('soft_deleted', 'soft-deleted at the provider: recover it first', 409);
    if (fields === undefined && tags === undefined) throw refuse('nothing_to_update', 'give fields, tags, or both (an omitted field keeps its stored value)', 400);
    const given = this.fieldMap(fields); const newTags = tags === undefined ? undefined : this.tagsOf(tags);
    const conn = this.connect(row.provider, 'update', row.path);
    conn.p.fieldsFrom(row.template, given, conn.p.current(row.pid)); // validate whole patch first
    conn.p.update(row.pid, { given, tags: newTags, now: this.now() });
    this.refreshRow(row);
    this.providerHop(row.provider, 'update', row.path, conn, { status: 200, body: { currentVersion: row.currentVersion, merged: true } });
    this.audit(a, 'store', 'store.update', row.ref, 'allowed', given ? 'value_changed' : 'tags_only');
    return { ref: row.ref, item: this.itemView(a, row) };
  }
  storeRotate(actorIn, { ref } = {}) {
    const a = this.begin(actorIn);
    const row = this.rowFor(a, ref); this.gate(a, row, 'write', 'rotate');
    if (row.state !== 'active') throw refuse('soft_deleted', 'soft-deleted at the provider: recover it first', 409);
    const conn = this.connect(row.provider, 'rotate', row.path);
    conn.p.rotate(row.pid, this.now()); this.refreshRow(row);
    this.providerHop(row.provider, 'rotate', row.path, conn, { status: 200, body: { currentVersion: row.currentVersion, rotationCount: row.rotationCount } });
    this.audit(a, 'store', 'store.rotate', row.ref, 'allowed');
    return { ref: row.ref, item: this.itemView(a, row) };
  }
  storeDelete(actorIn, { ref } = {}) {
    const a = this.begin(actorIn);
    const row = this.rowFor(a, ref); this.gate(a, row, 'write', 'delete');
    if (row.state === 'soft-deleted') throw refuse('already_deleted', 'already soft-deleted', 409);
    const conn = this.connect(row.provider, 'delete', row.path);
    const how = conn.p.remove(row.pid, this.now());
    if (how === 'hard') this.s.inventory = this.s.inventory.filter((r) => r !== row); else this.refreshRow(row);
    this.providerHop(row.provider, 'delete', row.path, conn, { status: 200, body: { deleted: how === 'hard' ? 'permanently' : 'soft-deleted: recoverable until purged' } });
    this.audit(a, 'store', 'store.delete', row.ref, 'allowed', how);
    return { ref: row.ref, deleted: how === 'hard' ? 'permanently' : 'soft', ...(how === 'soft' ? { item: this.itemView(a, row) } : {}) };
  }
  storeRecover(actorIn, { ref } = {}) {
    const a = this.begin(actorIn);
    const row = this.rowFor(a, ref); this.gate(a, row, 'write', 'recover');
    if (!PROVIDERS[row.provider].softDelete) throw refuse('unsupported_operation', `${PROVIDERS[row.provider].name} has no soft-delete in this lab (the deck lists soft-delete and purge for Azure)`, 409);
    if (row.state !== 'soft-deleted') throw refuse('not_soft_deleted', 'not soft-deleted', 409);
    const conn = this.connect(row.provider, 'recover', row.path);
    conn.p.recover(row.pid); this.refreshRow(row);
    this.providerHop(row.provider, 'recover', row.path, conn, { status: 200, body: { recovered: true } });
    this.audit(a, 'store', 'store.recover', row.ref, 'allowed');
    return { ref: row.ref, item: this.itemView(a, row) };
  }
  storePurge(actorIn, { ref } = {}) {
    const a = this.begin(actorIn);
    const row = this.rowFor(a, ref); this.gate(a, row, 'write', 'purge');
    if (!PROVIDERS[row.provider].purge) throw refuse('unsupported_operation', `${PROVIDERS[row.provider].name} has no purge in this lab (the deck lists soft-delete and purge for Azure)`, 409);
    if (row.state !== 'soft-deleted') throw refuse('not_soft_deleted', 'only a soft-deleted secret can be purged', 409);
    const conn = this.connect(row.provider, 'purge', row.path);
    conn.p.purge(row.pid); this.s.inventory = this.s.inventory.filter((r) => r !== row);
    this.providerHop(row.provider, 'purge', row.path, conn, { status: 200, body: { purged: true } });
    this.audit(a, 'store', 'store.purge', row.ref, 'allowed');
    return { ref: row.ref, purged: true };
  }
  connectProvider(actorIn, { provider } = {}) {
    const a = this.begin(actorIn); this.requireRole(a, 'admin');
    const p = this.provider(provider);
    this.connectProviderNow(p.id, mockValue(this.#rand, `conn-${p.id}`));
    this.audit(a, 'store', 'store.connection', p.id, 'allowed', 'credential_replaced');
    return { provider: p.id, connection: this.connectionView(p.id) };
  }
  connectionView(id) { const c = this.s.connections[id]; return { present: true, bytes: c.bytes, version: c.version, changedAt: c.changedAt, sealed: 'AES-256-GCM, never shown' }; }

  // A change made at the PROVIDER by someone else (a lab helper: the real world does this without telling Privilege). The inventory does not know until a re-sync.
  providerChange(actorIn, { provider, op, ref, newPath, path } = {}) {
    const a = this.begin(actorIn);
    const p = this.provider(provider);
    if (!['rename', 'delete', 'create', 'rotate'].includes(op)) throw refuse('bad_change', 'op must be rename, delete, create or rotate');
    if (op === 'create') {
      if (typeof path !== 'string' || findCredentials(path).length) throw refuse('bad_path', 'that path is not valid for this provider');
      const problem = p.pathProblem(path); if (problem) throw refuse(problem, 'that path is not valid for this provider, or its container does not exist', problem === 'already_exists' ? 409 : 400);
      p.create({ path, template: p.id === 'delinea' ? 'Password' : null, tags: ['by-hand'], given: null, now: this.now() });
    } else {
      const row = this.invOf(ref);
      if (!row || row.provider !== p.id || !p.secrets.has(row.pid)) throw refuse('not_found', 'there is no such secret in the inventory', 404);
      if (op === 'rename') {
        if (typeof newPath !== 'string' || findCredentials(newPath).length) throw refuse('bad_path', 'that path is not valid for this provider');
        const problem = p.pathProblem(newPath); if (problem) throw refuse(problem, 'that path is not valid for this provider, or its container does not exist', problem === 'already_exists' ? 409 : 400);
        p.rename(row.pid, newPath);
      } else if (op === 'delete') p.remove(row.pid, this.now());
      else { if (p.secrets.get(row.pid).state !== 'active') throw refuse('soft_deleted', 'soft-deleted at the provider', 409); p.rotate(row.pid, this.now()); }
    }
    this.hop(`${PROVIDERS[p.id].name}: changed by hand (simulated; Privilege is not told)`, { method: 'LAB', url: `provider://${p.id}`, body: { op } }, { status: 200, body: { inventoryUpdated: false } });
    this.audit('provider-console', 'provider', `provider.${op}`, p.id, 'allowed', 'by_hand');
    return { provider: p.id, op, inventoryUpdated: false };
  }

  // Re-synchronise: ask each provider for METADATA only, and bring the inventory in line (new, renamed, deleted, changed). A value is never asked for.
  resync(kind = 'manual', atMs = this.now(), actorIn = null) {
    if (actorIn) this.begin(actorIn);
    const items = []; const by = {}; let skippedFull = 0;
    for (const id of PROVIDER_IDS) {
      const list = this.#providers[id].list(); const byPid = new Map(list.map((m) => [m.pid, m]));
      const c = { new: 0, renamed: 0, deleted: 0, changed: 0, unchanged: 0 }; by[id] = c;
      for (const row of [...this.s.inventory.filter((r) => r.provider === id)]) {
        const cur = byPid.get(row.pid);
        if (!cur) { this.s.inventory = this.s.inventory.filter((r) => r !== row); items.push({ provider: id, change: 'deleted', ref: row.ref }); c.deleted += 1; continue; }
        const oldRef = row.ref;
        const renamed = cur.path !== row.path;
        const changed = cur.state !== row.state || cur.currentVersion !== row.currentVersion || JSON.stringify(cur.tags) !== JSON.stringify(row.tags);
        if (renamed) {
          const lost = this.s.policies.filter((g) => scopeMatches(g.scope, id, row.path) && !scopeMatches(g.scope, id, cur.path)).length;
          const gained = this.s.policies.filter((g) => !scopeMatches(g.scope, id, row.path) && scopeMatches(g.scope, id, cur.path)).length;
          items.push({ provider: id, change: 'renamed', from: oldRef, ref: `${id}:${cur.path}`, grantsLost: lost, grantsGained: gained }); c.renamed += 1;
        } else if (changed) { items.push({ provider: id, change: 'changed', ref: oldRef, what: [cur.state !== row.state ? 'state' : null, cur.currentVersion !== row.currentVersion ? 'version' : null, JSON.stringify(cur.tags) !== JSON.stringify(row.tags) ? 'tags' : null].filter(Boolean) }); c.changed += 1; } else c.unchanged += 1;
        Object.assign(row, this.invRow(id, cur));
      }
      const known = new Set(this.s.inventory.filter((r) => r.provider === id).map((r) => r.pid));
      for (const m of list) if (!known.has(m.pid)) {
        if (this.s.inventory.length >= LIMITS.inventory) { skippedFull += 1; continue; }
        this.s.inventory.push(this.invRow(id, m)); items.push({ provider: id, change: 'new', ref: `${id}:${m.path}` }); c.new += 1;
      }
    }
    const proof = this.proofSync({ scope: 'stores', withSnapshots: false });
    const report = { id: `sync-${String(++this.s.seq.report).padStart(4, '0')}`, at: iso(atMs), kind, byProvider: by, items: items.slice(0, 200), itemsTotal: items.length, skippedFull, valuesFoundInInventoryAfter: proof.valuesFound };
    this.s.reports.push(report); if (this.s.reports.length > LIMITS.reports) this.s.reports.shift();
    this.hop('re-sync: metadata only from every provider', { method: 'LIST', url: 'providers://*/secrets?metadata=only' }, { status: 200, body: { changes: items.length, valuesRequested: 0 } });
    this.audit('system', 'store', `store.resync.${kind}`, '-', 'allowed', `changes_${items.length}`);
    return { report: report.id, changes: items.length, items: report.items };
  }
  resyncNow(actorIn) { return this.resync('manual', this.now(), actorIn); }

  // ---- policy ------------------------------------------------------------------------------------------------------------------------------------
  grant(actorIn, input) {
    const a = this.begin(actorIn); this.requireRole(a, 'admin');
    if (typeof input.principal !== 'string' || !this.roster.has(input.principal)) throw refuse('bad_grant', 'the principal must be someone on the roster');
    const sp = scopeProblem(input.scope); if (sp) throw refuse('bad_scope', 'a scope is "provider:path" using a provider id (or *) and segments, with * for one segment and ** for the rest');
    if (!Array.isArray(input.actions) || input.actions.length < 1 || input.actions.length > 2 || !input.actions.every((x) => ACTIONS.includes(x)) || new Set(input.actions).size !== input.actions.length) throw refuse('bad_grant', 'actions must be read, write, or both');
    if (this.s.policies.length >= LIMITS.policies) throw refuse('policies_full', 'a workspace has at most 100 grants', 409);
    const g = { id: `pol-${String(++this.s.seq.policy).padStart(4, '0')}`, principal: input.principal, scope: input.scope, actions: [...input.actions].sort(), by: a.id, at: iso(this.now()) };
    this.s.policies.push(g);
    this.audit(a, 'policy', 'policy.grant', g.id, 'allowed');
    return { grantId: g.id };
  }
  revoke(actorIn, { id } = {}) {
    const a = this.begin(actorIn); this.requireRole(a, 'admin');
    const g = typeof id === 'string' ? this.s.policies.find((x) => x.id === id) : null;
    if (!g) throw refuse('not_found', 'there is no such grant', 404);
    this.s.policies = this.s.policies.filter((x) => x !== g);
    this.audit(a, 'policy', 'policy.revoke', g.id, 'allowed');
    return { grantId: g.id };
  }

  // ---- the no-copy proof ---------------------------------------------------------------------------------------------------------------------------
  // Serialises everything the Privilege side keeps (inventory, grants, audit, reports, deliveries, sealed vault values with their ciphertext bodies counted
  // but not searched, sealed connections, the logs, and the state every roster member would be shown) and searches it for every value the providers hold
  // (all versions), every provider connection credential, every vault plaintext and the shared service accounts (see proof.js for the forms and the method).
  // It is a generator that yields at checkpoints: proofSync drains it at once (small workspaces, tests, the re-sync report), proofAsync runs it in slices of a
  // few milliseconds so a large workspace never holds the event loop. A result is cached against the state version; a stale cache is never shown as current.
  sealedView() {
    const out = {};
    for (const [u, list] of Object.entries(this.s.vault)) out[u] = list.map((e) => ({ ...e, sealed: { n: e.sealed.n, ct: `[${e.sealed.ct.length} base64 characters of AES-GCM output, counted not searched]`, t: e.sealed.t } }));
    return out;
  }
  *proofGen({ scope = 'all', withSnapshots = true } = {}) {
    const values = [];
    const add = (label, v) => { if (typeof v === 'string') values.push({ label, value: v }); };
    const creds = (p) => [p.token, p.key, p.username, p.password, ...(p.headers ? Object.values(p.headers) : [])];
    for (const id of PROVIDER_IDS) for (const v of this.#providers[id].allValues()) add('store value', v);
    for (const id of PROVIDER_IDS) { try { add('provider connection', openBytes(this.#keys.key, this.s.connections[id].sealed, `svl1|provider-credential|${id}`).toString('utf8')); } catch { /* the connection fails closed elsewhere */ } }
    yield;
    if (scope === 'all') {
      let n = 0;
      for (const [user, list] of Object.entries(this.s.vault)) for (const e of list) { try { for (const v of creds(JSON.parse(openBytes(this.#keys.key, e.sealed, aadFor(user, e.id)).toString('utf8')))) add('vault credential', v); } catch { /* integrity failures are reported by the vault */ } if (++n % 8 === 0) yield; }
      for (const t of Object.values(this.#shared)) for (const v of creds(t)) add('shared service account', v);
    }
    const areas = { inventory: this.s.inventory, grants: this.s.policies, audit: this.s.audit, 'sync reports': this.s.reports, deliveries: this.s.deliveries, 'sealed vault values': this.sealedView(), 'sealed connections': this.s.connections, 'gateway log': this.s.gatewayLog, 'backend log': this.backend.log };
    yield;
    if (withSnapshots) for (const p of this.roster.values()) { areas[`state shown to ${p.id} (${p.role})`] = this.snapshotCore(p); yield; }
    const index = buildIndex(values);
    const found = []; const sizes = [];
    for (const [area, obj] of Object.entries(areas)) {
      const text = JSON.stringify(obj); sizes.push({ name: area, bytes: text.length });
      yield* scanText(text, index, area, found); yield* leafScan(obj, index, area, found); yield;
    }
    const uniq = [...new Map(found.map((f) => [`${f.label}|${f.area}|${f.kind}`, f])).values()];
    return { valuesChecked: index.checked, shortChecked: index.shortChecked, skippedTiny: index.skippedTiny, valuesFound: uniq.length, found: uniq.slice(0, 20), areas: sizes, bytesScanned: sizes.reduce((n, a) => n + a.bytes, 0), encodings: ['plain', 'json-escaped', 'base64', 'hex'], windowChars: WINDOW, selfTest: selfTest(), computedAtVersion: this.version, clock: iso(this.now()) };
  }
  proofSync(opts) { return drain(this.proofGen(opts)); }
  noCopyProof(withSnapshots = true, { scope = 'all' } = {}) { return this.proofSync({ scope, withSnapshots }); }
  // Time-sliced: yields to the event loop whenever `sliceMs` has passed (0 = at every checkpoint). One run at a time per engine; `onSlice` counts the yields.
  proofAsync({ sliceMs = 8, onSlice = null } = {}) {
    if (this.proofJob) return this.proofJob;
    const version = this.version;
    this.proofJob = (async () => {
      try {
        const gen = this.proofGen({}); let t0 = performance.now();
        for (;;) {
          const r = gen.next();
          if (r.done) { const result = r.value; if (version === this.version) this.proofCache = { version, result }; return version === this.version ? result : { ...result, stale: true }; }
          if (performance.now() - t0 >= sliceMs) { this.proofSlices += 1; if (onSlice) onSlice(); await new Promise((res) => setImmediate(res)); t0 = performance.now(); }
        }
      } finally { this.proofJob = null; }
    })();
    return this.proofJob;
  }
  // What a state read shows: the cached proof when it is current, a quick computation for a small workspace, else an honest "run it" placeholder (never a pass).
  proofView() {
    const c = this.proofCache;
    if (c && c.version === this.version) return c.result;
    const units = Object.values(this.s.vault).reduce((n, l) => n + l.length, 0) * 6 + this.s.inventory.length + Math.ceil(this.s.audit.length / 2) + this.s.reports.length * 2;
    if (units <= LIMITS.proofQuickUnits) { const result = this.proofSync({}); this.proofCache = { version: this.version, result }; return result; }
    return { skipped: true, reason: 'this workspace is large, so the search is not run on every read or write: press "Run the proof now" (it runs in short slices and never blocks the lab)', units, last: c ? { valuesFound: c.result.valuesFound, valuesChecked: c.result.valuesChecked, version: c.version, current: false } : null };
  }

  // ---- views ------------------------------------------------------------------------------------------------------------------------------------
  itemView(actor, r) {
    return { ref: r.ref, provider: r.provider, path: r.path, template: r.template, tags: r.tags, state: r.state, currentVersion: r.currentVersion, versions: r.versions.length, rotationCount: r.rotationCount, fields: r.fields, can: this.canOf(actor, r), syncedAt: r.syncedAt };
  }
  structureView(actor) {
    const rows = this.visibleInventory(actor).map((x) => x.r);
    return PROVIDER_IDS.map((id) => {
      const cfg = PROVIDERS[id]; const nodes = this.#providers[id].structure();
      return { id, name: cfg.name, structure: cfg.structure, softDelete: cfg.softDelete, purge: cfg.purge, fileFields: cfg.fileFields, templates: id === 'delinea' ? Object.keys(DELINEA_TEMPLATES) : undefined, connection: this.connectionView(id), nodes: nodes.map((n) => ({ ...n, secrets: rows.filter((r) => r.provider === id && (r.path === n.path || r.path.startsWith(`${n.path}/`))).length })) };
    });
  }
  snapshotCore(actorIn) {
    const a = this.need(actorIn); const all = a.role === 'admin' || a.role === 'auditor';
    const mine = this.mine(a);
    const entries = mine.map((e) => this.entryView(e));
    const nonceList = mine.map((e) => e.sealed.n);
    return {
      clock: iso(this.now()), actor: { id: a.id, role: a.role }, roster: [...this.roster.values()],
      limits: { entriesPerUser: LIMITS.entriesPerUser, credentialBytes: LIMITS.credentialBytes, purgeAfterHours: 24, nightlyHourUtc: NIGHTLY_HOUR_UTC },
      vault: { entries, count: entries.length, staged: entries.filter((e) => e.status === 'staged-delete').length, sealedValues: nonceList.length, distinctNonces: new Set(nonceList).size, key: this.keyView(), counters: { ...this.s.counters } },
      targets: this.s.targets.map((t) => ({ ...t })),
      gatewayLog: this.s.gatewayLog.filter((g) => all || g.actor === a.id).slice(-20),
      backendLog: this.backend.log.filter((b) => all || b.principal === a.id || (typeof b.principal === 'string' && b.principal.startsWith('svc-'))).slice(-20),
      stores: { providers: this.structureView(a), items: this.visibleInventory(a).map((x) => this.itemView(a, x.r)), inventoryTotal: this.s.inventory.length },
      governance: {
        policies: this.s.policies.filter((g) => all || g.principal === a.id), policiesTotal: this.s.policies.length, canEditPolicy: a.role === 'admin',
        audit: this.s.audit.filter((x) => all || x.actor === a.id).slice(-60).reverse(), auditTotal: this.s.audit.length, canSeeAllAudit: all,
        consumerStates: this.consumerStates(), reports: this.s.reports.slice(-8).reverse(), deliveries: this.s.deliveries.filter((d) => all || d.actor === a.id).slice(-10).reverse(), consumers: CONSUMERS,
      },
    };
  }
  snapshot(actorIn) { const s = this.snapshotCore(actorIn); return { ...s, proof: this.proofView() }; }

  // Everything the Privilege side holds, for tests that search it. Never holds a plaintext value; the providers' own stores are NOT in it.
  dump() { return JSON.stringify({ s: this.s, backendLog: this.backend.log }); }
  providerValues() { return PROVIDER_IDS.flatMap((id) => this.#providers[id].allValues()); }
  // Test hooks that stand in for an attacker with write access to the store: they change sealed bytes, nothing else.
  get roleNames() { return ROLES; }
}
