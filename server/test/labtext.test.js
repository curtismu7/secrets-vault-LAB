// False-positive guard for the shared masker (1.4.0 adoption): nothing the LAB writes itself may come back masked. Every scripted step of every scenario of every vertical
// is replayed through the HTTP API, then the state, governance, vault and store reads, the story, the diagram and the Mock state are read; none of the answers may hold a mark.
import test from 'node:test';
import assert from 'node:assert/strict';
import { VERTICALS } from '../src/cast.js';
import { scenarioList } from '../src/scenarios.js';
import { withServer, live } from './helpers.js';
const routes = {
    vaultCreate: ['POST', () => '/api/vault/entries', (p) => p], vaultUpdate: ['PUT', (p) => `/api/vault/entries/${p.id}`, (p) => ({ entry: p.entry })],
    vaultDelete: ['POST', (p) => `/api/vault/entries/${p.id}/delete`, () => ({})], vaultRestore: ['POST', (p) => `/api/vault/entries/${p.id}/restore`, () => ({})],
    gatewayCall: ['POST', () => '/api/gateway/call', (p) => p], advance: ['POST', () => '/api/clock', (p) => p], storeCreate: ['POST', () => '/api/stores/secrets', (p) => p],
    storeRead: ['POST', () => '/api/stores/read', (p) => p], storeRotate: ['POST', () => '/api/stores/rotate', (p) => p], storeDelete: ['POST', () => '/api/stores/delete', (p) => p],
    storeRecover: ['POST', () => '/api/stores/recover', (p) => p], storePurge: ['POST', () => '/api/stores/purge', (p) => p], grant: ['POST', () => '/api/policies', (p) => p],
    providerChange: ['POST', () => '/api/stores/provider-change', (p) => p],
};
test('the lab\'s own answers (hops, views, tables, story, diagrams, Mock state) are never masked, in every scenario of every vertical', async () => {
  const seen = new Map(); let steps = 0;
  const note = (where, text) => { for (const m of text.matchAll(/.{60}\[masked:[a-z-]+\].{30}/g)) { const k = m[0].replace(/[0-9]+/g, 'N'); if (!seen.has(k)) seen.set(k, where); } };
  await withServer(async (url) => {
    for (const [vname, cast] of Object.entries(VERTICALS)) for (const sc of scenarioList(cast)) {
      const ws = `probe-${vname}-${sc.id}`.slice(0, 38);
      for (const st of sc.steps) { steps += 1; const [m, path, body] = routes[st.op]; const r = await fetch(`${url}${path(st.params)}`, { method: m, headers: { 'content-type': 'application/json', origin: url, 'x-workspace': ws, 'x-lab-actor': st.actor }, body: JSON.stringify(live({ ...body(st.params), vertical: vname })) }); note(`${vname}/${sc.id}/${st.op}`, await r.text()); }
      for (const p of ['/api/state?mode=live', '/api/governance', '/api/vault/entries', '/api/stores/secrets']) { const r = await fetch(`${url}${p}&vertical=${vname}`.replace('?&','?'), { headers: { 'x-workspace': ws, 'x-lab-actor': sc.actor } }); note(`${vname}/${sc.id}${p}`, await r.text()); }
    }
    for (const v of Object.keys(VERTICALS)) for (const p of [`/api/story?vertical=${v}`, `/api/diagram?vertical=${v}`, `/api/state?mode=mock&vertical=${v}`]) note(p, await (await fetch(url + p, { headers: { 'x-lab-actor': VERTICALS[v].castUser } })).text());
  });
  assert.deepEqual([...seen].map(([k, w]) => `${w} :: ${k}`), []);
  assert.equal(steps, 147, 'scripted steps replayed');
});
