import http from 'node:http';
import { createHash } from 'node:crypto';
import { createApp, startHttpServer } from '../src/app.js';
import { createHealth } from '../src/health.js';
import { createWorkspaces } from '../src/workspaces.js';
import { Engine } from '../src/engine.js';
import { VERTICALS } from '../src/cast.js';
import { perform } from '../src/actions.js';

export const C = VERTICALS.finance;
// A deterministic random source for tests that need to count or compare (never used in the app itself).
export function seqRand(tag = 't') { let i = 0; return (n) => { const out = Buffer.alloc(n); let at = 0; while (at < n) { createHash('sha256').update(`${tag}${i++}`).digest().copy(out, at, 0, Math.min(32, n - at)); at += 32; } return out; }; }
export const newEngine = (cast = C, o = {}) => new Engine(cast, o);
export const who = (e, id) => e.roster.get(id);
export const U1 = C.castUser; export const U2 = C.castUser2; export const ADMIN = C.castAdmin; export const AUD = C.castAuditor; export const SUP = C.castSupport;
export const ALL = [U1, U2, ADMIN, AUD, SUP];
// run an op through the same dispatch the API uses
export const run = (e, op, actorId, params) => perform(e, op, e.roster.get(actorId), params);
export const code = (r) => (r.ok ? 'ok' : r.code);
export const mk = (e, actorId, o = {}) => { const r = run(e, 'vaultCreate', actorId, { entry: { name: 'Ledger bearer', targetId: C.castT1, shape: 'bearer', generate: true, ...o } }); if (!r.ok) throw new Error(`create failed: ${r.code}`); return r.result.entryId; };

export async function withServer(fn, { configFile = '/nonexistent/customer.config.json', workspaces = createWorkspaces(), webDist } = {}) {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  await health.ready;
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health, configFile, workspaces, ...(webDist ? { webDist } : {}) }) });
  try { await fn(url.replace(/\/$/, ''), { workspaces }); } finally { health.stop(); await new Promise((res) => server.close(res)); }
}
const hdr = (url, actor, extra = {}) => ({ 'content-type': 'application/json', origin: url, ...(actor ? { 'x-lab-actor': actor } : {}), ...extra });
export const post = (url, path, body, actor = U1, headers = {}) => fetch(`${url}${path}`, { method: 'POST', headers: hdr(url, actor, headers), body: JSON.stringify(body) });
export const put = (url, path, body, actor = U1, headers = {}) => fetch(`${url}${path}`, { method: 'PUT', headers: hdr(url, actor, headers), body: JSON.stringify(body) });
export const get = (url, path, actor = U1, headers = {}) => fetch(`${url}${path}`, { headers: { ...(actor ? { 'x-lab-actor': actor } : {}), ...headers } });
export const live = (extra = {}) => ({ mode: 'live', vertical: 'finance', ...extra });

// fetch cannot set Host; node:http can. The sweeps open thousands of short connections while other test files run in parallel, so a connection that is
// reset or refused BEFORE any answer is retried (these requests change no state: they probe paths and answer fixed errors); an answer is never retried.
export function rawHttp(url, { method = 'GET', headers = {}, body } = {}, tries = 6) {
  const once = () => new Promise((resolve, reject) => {
    const u = new URL(url);
    const req = http.request({ host: u.hostname, port: u.port, path: u.pathname + u.search, method, headers, agent: false }, (res) => {
      let data = ''; res.on('data', (c) => { data += c; }); res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, text: data }));
      res.on('error', reject);
    });
    req.on('error', reject); if (body) req.write(body); req.end();
  });
  return (async () => { for (let i = 0; ; i++) { try { return await once(); } catch (e) { if (i + 1 >= tries || !['ECONNRESET', 'ECONNREFUSED', 'EPIPE'].includes(e.code)) throw e; await new Promise((r) => setTimeout(r, 50 * (i + 1))); } } })();
}
