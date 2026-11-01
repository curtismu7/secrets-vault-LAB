// One Express app. /api = health, info, story, diagram, state, a few actor-scoped reads, and the action endpoints (vault entries, gateway calls, key provider,
// targets, secret stores, grants, clock, reset). Server state per workspace id (X-Workspace) is one engine per vertical.
// The caller is named by X-Lab-Actor (a lab stand-in for the verified token). NO route takes an owner, a user or a vault id to act on: the caller is the
// only vault there is, and a query or body that names one is refused. Mock reads generated tables and refuses every write; Live drives the engine.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import express from 'express';
import { hostCheck, sameOriginWrites } from './safety.js';
import { createHealth } from './health.js';
import { buildRoster, loadCast, verticalFrom, VERTICALS } from './cast.js';
import { defaultMode, modeOf } from './config.js';
import { buildStory } from './story.js';
import { DIAGRAM_NAMES, buildDiagram } from './diagramData.js';
import { InputError } from './errors.js';
import { MOCK_TABLE } from './mockTable.js';
import { createWorkspaces, workspaceFrom } from './workspaces.js';
import { Engine } from './engine.js';
import { liveState, mockState, runAction } from './service.js';
import { maskDeep } from './mask.js';

const HERE = path.dirname(fileURLToPath(import.meta.url));
const WEB_DIST = process.env.WEB_DIST || path.resolve(HERE, '../../web/dist');
const CONFIG = process.env.CUSTOMER_CONFIG || path.resolve(HERE, '../../customer.config.json');
const isObj = (v) => v !== null && typeof v === 'object' && !Array.isArray(v);
const QUERY_OK = ['mode', 'vertical', 'scenario', 'name'];

export function createApp({ health = createHealth(), configFile = CONFIG, workspaces = createWorkspaces(), table = MOCK_TABLE, webDist = WEB_DIST } = {}) {
  const app = express();
  app.disable('x-powered-by');
  app.use(hostCheck);
  app.use(sameOriginWrites);
  app.use((_req, res, next) => { res.set('X-Content-Type-Options', 'nosniff'); next(); });

  const api = express.Router();
  api.use(express.json({ limit: '200kb' }));
  // Defence in depth: every JSON answer is masked for credential-shaped values, whatever path produced it.
  api.use((_req, res, next) => { const send = res.json.bind(res); res.json = (b) => send(maskDeep(b)); next(); });
  api.use('/health', health.router);
  const verticalOf = (req) => verticalFrom(req.body?.vertical ?? req.query.vertical);
  // An unknown vertical is refused (400), never silently replaced by the default one. Fixed text, the value is never echoed.
  const verticalOk = (req, res) => {
    const raw = req.body?.vertical ?? req.query.vertical;
    if (raw === undefined || (typeof raw === 'string' && Object.hasOwn(VERTICALS, raw))) return true;
    res.status(400).json({ error: 'bad_vertical', detail: 'vertical must be one of the lab\'s packs' }); return false;
  };
  const castFor = (req) => loadCast(configFile, verticalOf(req));
  const noStore = (res) => res.set('Cache-Control', 'no-store');
  const ws = (req, res) => { const id = workspaceFrom(req); if (!id) res.status(400).json({ error: 'bad_workspace' }); return id; };
  const bodyOf = (req) => (isObj(req.body) ? req.body : {});
  const actorId = (req) => (typeof req.headers['x-lab-actor'] === 'string' ? req.headers['x-lab-actor'] : null);
  // Query strings are strict too: a parameter that names an owner or user is refused, never ignored and never echoed.
  const queryOk = (req, res) => { if (Object.keys(req.query).every((k) => QUERY_OK.includes(k))) return true; res.status(400).json({ error: 'unknown_field', detail: 'the query carries a parameter the lab does not take' }); return false; };

  api.get('/story', (req, res) => { noStore(res); if (!queryOk(req, res) || !verticalOk(req, res)) return; res.json(buildStory(castFor(req), verticalOf(req))); });
  api.get('/diagram', (req, res) => {
    noStore(res); if (!queryOk(req, res) || !verticalOk(req, res)) return;
    const name = req.query.name === undefined ? DIAGRAM_NAMES[0] : req.query.name;
    if (typeof name !== 'string' || !DIAGRAM_NAMES.includes(name)) return res.status(404).json({ error: 'unknown_diagram' });
    return res.json(buildDiagram(castFor(req), name));
  });
  api.get('/info', (_req, res) => { noStore(res); res.json({ mode: defaultMode(), modes: ['mock', 'live'], simulated: true, release: '2026-11-02', unverified: true }); });

  // The engine for a read: the workspace's own, or a fresh one that is never stored.
  const readEngine = (req, res) => {
    const id = ws(req, res); if (!id) return null;
    noStore(res);
    if (!queryOk(req, res) || !verticalOk(req, res)) return null;
    const vertical = verticalOf(req);
    const e = workspaces.peek(id, vertical) || new Engine(castFor(req));
    const actor = e.actor(actorId(req));
    if (!actor) { res.status(401).json({ error: actorId(req) === null ? 'actor_required' : 'unknown_actor' }); return null; }
    return { e, actor, id, vertical };
  };

  api.get('/state', (req, res) => {
    const id = ws(req, res); if (!id) return;
    noStore(res);
    if (!queryOk(req, res) || !verticalOk(req, res)) return;
    const mode = modeOf(req.query.mode); if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
    const vertical = verticalOf(req);
    if (mode === 'mock') {
      const sc = req.query.scenario;
      if (sc !== undefined && (typeof sc !== 'string' || !table.verticals[vertical].scenarios.some((s) => s.id === sc))) return res.status(404).json({ error: 'unknown_scenario' });
      return res.json({ mode, vertical, workspace: id, ...mockState(table, vertical, sc) });
    }
    if (!buildRoster(castFor(req)).some((p) => p.id === actorId(req))) return res.status(401).json({ error: actorId(req) === null ? 'actor_required' : 'unknown_actor' });
    return res.json({ mode, vertical, workspace: id, state: liveState(id, workspaces, vertical, castFor(req), actorId(req)) });
  });

  // Actor-scoped reads. None takes an owner; the vault read is always the caller's own.
  api.get('/vault/entries', (req, res) => { const r = readEngine(req, res); if (r) res.json({ entries: r.e.vaultList(r.actor) }); });
  api.get('/vault/entries/:id', (req, res) => {
    const r = readEngine(req, res); if (!r) return;
    try { return res.json({ entry: r.e.vaultGet(r.actor, req.params.id) }); } catch (e) { if (e instanceof InputError) return res.status(e.status).json({ error: e.code }); throw e; }
  });
  api.get('/stores/secrets', (req, res) => { const r = readEngine(req, res); if (r) res.json({ items: r.e.snapshotCore(r.actor).stores.items }); });
  api.get('/governance', (req, res) => { const r = readEngine(req, res); if (r) { const g = r.e.snapshotCore(r.actor).governance; res.json({ policies: g.policies, audit: g.audit }); } });

  // Every write: Live only, strict top-level keys, one trace, hops, and the whole fresh state back.
  const write = (method, route, { op, keys, params }) => {
    api[method](route, (req, res, next) => {
      const id = ws(req, res); if (!id) return;
      noStore(res);
      try {
        if (!isObj(req.body)) return res.status(400).json({ error: 'bad_request' });
        const mode = modeOf(req.body.mode);
        if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
        if (mode === 'mock') return res.status(409).json({ error: 'mock_is_read_only', detail: 'Mock mode only reads tables: switch to Live to act' });
        if (!Object.keys(req.body).every((k) => ['mode', 'vertical', ...keys].includes(k))) return res.status(400).json({ error: 'unknown_field', detail: 'the body carries a field the lab does not take' });
        if (!verticalOk(req, res)) return;
        const vertical = verticalOf(req);
        const r = runAction({ ws: id, workspaces, vertical, cast: castFor(req), op, actorId: actorId(req), params: params(req), traceparent: req.headers.traceparent, route: { method: method.toUpperCase(), url: `/api${route}` } });
        if (!r) return res.status(503).json({ error: 'workspace_cap', detail: 'too many workspaces on this lab: try again later' });
        res.set('traceparent', r.traceparent);
        const common = { workspace: id, mode, vertical, hops: r.hops, hopsTruncated: r.hopsTruncated, traceId: r.traceId, state: r.state };
        if (r.outcome.ok) return res.json({ ok: true, result: r.outcome.result, ...common });
        // A refusal is a real HTTP status (400, 401, 403, 404, 409, 413, 503) with the same JSON body: the page reads that body as data, and the
        // browser logs the 4xx as a console line. Nothing is hidden behind a 200.
        return res.status(r.outcome.status || 400).json({ ok: false, error: r.outcome.code, detail: r.outcome.detail, ...common });
      } catch (e) { return next(e); }
    });
  };
  const idParam = (req) => (typeof req.params.id === 'string' ? req.params.id : '');
  const o = (v) => (isObj(v) ? v : { __bad: 1 });
  write('post', '/vault/entries', { op: 'vaultCreate', keys: ['entry'], params: (req) => ({ entry: o(req.body.entry) }) });
  write('put', '/vault/entries/:id', { op: 'vaultUpdate', keys: ['entry'], params: (req) => ({ id: idParam(req), entry: o(req.body.entry) }) });
  write('post', '/vault/entries/:id/delete', { op: 'vaultDelete', keys: [], params: (req) => ({ id: idParam(req) }) });
  write('post', '/vault/entries/:id/restore', { op: 'vaultRestore', keys: [], params: (req) => ({ id: idParam(req) }) });
  write('post', '/gateway/call', { op: 'gatewayCall', keys: ['call'], params: (req) => ({ call: o(req.body.call) }) });
  write('post', '/vault/keys', { op: 'restartKeys', keys: ['key'], params: (req) => ({ key: o(req.body.key) }) });
  write('post', '/targets', { op: 'addTarget', keys: ['target'], params: (req) => ({ target: o(req.body.target) }) });
  write('post', '/targets/:id/remove', { op: 'removeTarget', keys: [], params: (req) => ({ id: idParam(req) }) });
  write('post', '/stores/secrets', { op: 'storeCreate', keys: ['secret'], params: (req) => ({ secret: o(req.body.secret) }) });
  write('post', '/stores/read', { op: 'storeRead', keys: ['read'], params: (req) => ({ read: o(req.body.read) }) });
  write('post', '/stores/update', { op: 'storeUpdate', keys: ['update'], params: (req) => ({ update: o(req.body.update) }) });
  for (const op of ['rotate', 'delete', 'recover', 'purge']) write('post', `/stores/${op}`, { op: `store${op[0].toUpperCase()}${op.slice(1)}`, keys: ['ref'], params: (req) => ({ ref: req.body.ref }) });
  write('post', '/stores/connection', { op: 'connectProvider', keys: ['provider'], params: (req) => ({ provider: req.body.provider }) });
  write('post', '/stores/provider-change', { op: 'providerChange', keys: ['change'], params: (req) => ({ change: o(req.body.change) }) });
  write('post', '/stores/resync', { op: 'resync', keys: [], params: () => ({}) });
  write('post', '/policies', { op: 'grant', keys: ['grant'], params: (req) => ({ grant: o(req.body.grant) }) });
  write('post', '/policies/:id/revoke', { op: 'revoke', keys: [], params: (req) => ({ id: idParam(req) }) });
  write('post', '/clock', { op: 'advance', keys: ['clock'], params: (req) => ({ clock: o(req.body.clock) }) });

  // The no-copy proof on demand, in short slices (it yields to the event loop every few milliseconds, so a large workspace never blocks health or anyone else).
  api.post('/proof/run', async (req, res, next) => {
    try {
      const id = ws(req, res); if (!id) return;
      noStore(res);
      if (!isObj(req.body)) return res.status(400).json({ error: 'bad_request' });
      const mode = modeOf(req.body.mode);
      if (!mode) return res.status(400).json({ error: 'bad_mode', detail: 'mode must be mock or live' });
      if (mode === 'mock') return res.status(409).json({ error: 'mock_is_read_only', detail: 'Mock mode only reads tables: switch to Live to run it' });
      if (!Object.keys(req.body).every((k) => ['mode', 'vertical'].includes(k))) return res.status(400).json({ error: 'unknown_field', detail: 'the body carries a field the lab does not take' });
      if (!verticalOk(req, res)) return;
      const e = workspaces.engine(id, verticalOf(req), castFor(req));
      if (!e) return res.status(503).json({ error: 'workspace_cap', detail: 'too many workspaces on this lab: try again later' });
      if (!e.actor(actorId(req))) return res.status(401).json({ error: actorId(req) === null ? 'actor_required' : 'unknown_actor' });
      return res.json({ ok: true, proof: await e.proofAsync() });
    } catch (err) { return next(err); }
  });

  // Reset clears this workspace's engines (vault, inventory, providers, audit, the clock) and nothing else.
  api.post('/reset', (req, res) => { const id = ws(req, res); if (!id) return; noStore(res); workspaces.reset(id); return res.json({ reset: 'ok', workspace: id }); });
  api.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  app.use('/api', api);

  if (fs.existsSync(path.join(webDist, 'index.html'))) {
    app.use(express.static(webDist));
    app.get(/^\/(?!api\/).*/, (_req, res) => res.sendFile(path.join(webDist, 'index.html')));
  }
  // The last two handlers catch everything that is left, for every method and every path: Express's default answers would echo the path the
  // visitor typed, which may be a token. Fixed JSON, no path.
  app.use((_req, res) => res.status(404).json({ error: 'not_found' }));
  // eslint-disable-next-line no-unused-vars
  app.use((err, _req, res, _next) => {
    const status = Number(err?.status || err?.statusCode);
    if (err instanceof InputError) return res.status(err.status).json({ error: err.code });
    if (status === 413) return res.status(413).json({ error: 'payload_too_large' });
    if (status >= 400 && status < 500) return res.status(status).json({ error: 'bad_request' });
    return res.status(500).json({ error: 'internal_error' });
  });
  return app;
}

export function startHttpServer({ port, host, app = createApp() } = {}) {
  return new Promise((resolve, reject) => {
    const server = app.listen(port, host, () => resolve({ server, url: `http://${host}:${server.address().port}/` }));
    // A busy client reusing a keep-alive socket the server had just closed was the source of rare ECONNRESETs: keep idle sockets longer than a load balancer would.
    server.keepAliveTimeout = 61_000; server.headersTimeout = 65_000;
    server.once('error', reject);
  });
}
