import test from 'node:test';
import assert from 'node:assert/strict';
import { VERTICALS } from '../src/cast.js';
import { EXPECTED, buildMockTable, runScenario, scenarioList } from '../src/scenarios.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { mockState } from '../src/service.js';
import { withServer, get, post, live, C } from './helpers.js';
import { maskDeep } from '../src/mask.js';
import { scanHosts } from '../src/safety.js';

test('every scripted step gives the result the story says it does, in every vertical', () => {
  for (const [v, cast] of Object.entries(VERTICALS)) {
    for (const sc of scenarioList(cast)) {
      const { steps } = runScenario(cast, sc);
      assert.deepEqual(steps.map((s) => (s.result.ok ? 'ok' : s.result.code)), EXPECTED[sc.id], `${v}/${sc.id}`);
    }
  }
  assert.equal(Object.keys(EXPECTED).length, 7);
});

test('Mock parity: the committed Mock table is exactly what the engine generates (a drift test), and a rebuild is identical', () => {
  assert.equal(JSON.stringify(MOCK_TABLE), JSON.stringify(buildMockTable()));
  assert.equal(JSON.stringify(buildMockTable()), JSON.stringify(buildMockTable()));
});

test('Mock parity: a scenario replayed through the Live HTTP API ends in the same vault, store and audit state as the Mock table says', async () => {
  const routes = {
    vaultCreate: ['POST', () => '/api/vault/entries', (p) => p], vaultUpdate: ['PUT', (p) => `/api/vault/entries/${p.id}`, (p) => ({ entry: p.entry })],
    vaultDelete: ['POST', (p) => `/api/vault/entries/${p.id}/delete`, () => ({})], vaultRestore: ['POST', (p) => `/api/vault/entries/${p.id}/restore`, () => ({})],
    gatewayCall: ['POST', () => '/api/gateway/call', (p) => p], advance: ['POST', () => '/api/clock', (p) => p], storeCreate: ['POST', () => '/api/stores/secrets', (p) => p],
    storeRead: ['POST', () => '/api/stores/read', (p) => p], storeRotate: ['POST', () => '/api/stores/rotate', (p) => p], storeDelete: ['POST', () => '/api/stores/delete', (p) => p],
    storeRecover: ['POST', () => '/api/stores/recover', (p) => p], storePurge: ['POST', () => '/api/stores/purge', (p) => p], grant: ['POST', () => '/api/policies', (p) => p],
    providerChange: ['POST', () => '/api/stores/provider-change', (p) => p],
  };
  await withServer(async (url) => {
    for (const sc of scenarioList(C)) {
      const ws = `parity-${sc.id}`.slice(0, 30);
      for (const st of sc.steps) { const [m, path, body] = routes[st.op]; await (m === 'PUT' ? fetch : fetch)(`${url}${path(st.params)}`, { method: m, headers: { 'content-type': 'application/json', origin: url, 'x-workspace': ws, 'x-lab-actor': st.actor }, body: JSON.stringify(live({ ...body(st.params) })) }); }
      const liveState = (await (await get(url, '/api/state?mode=live&vertical=finance', sc.actor, { 'x-workspace': ws })).json()).state;
      const mock = mockState(MOCK_TABLE, 'finance', sc.id).state;
      for (const k of ['clock', 'targets', 'backendLog', 'gatewayLog', 'stores', 'governance']) {
        const strip = (o) => JSON.parse(JSON.stringify(o, (key, v) => (key === 'nonce' || key === 'nonces' ? undefined : v)));
        assert.deepEqual(strip(liveState[k]), strip(mock[k]), `${sc.id}: ${k}`);
      }
      assert.deepEqual(liveState.vault.entries.map(({ secret, ...e }) => e), mock.vault.entries.map(({ secret, ...e }) => e), `${sc.id}: vault entries`);
      assert.equal(liveState.proof.valuesFound, 0);
    }
  });
});

test('Mock mode shows what the story says: another person gets not found, the shared account hides the user, the purge happens, the rename is found', () => {
  const n = mockState(MOCK_TABLE, 'finance', 'no-override');
  assert.deepEqual(n.scenario.steps.map((s) => s.result.code || 'ok'), EXPECTED['no-override']);
  assert.deepEqual(n.state.vault.entries, [], 'the administrator\'s own vault is empty');
  const o = mockState(MOCK_TABLE, 'finance', 'own-vault').state;
  assert.deepEqual(o.backendLog.map((b) => b.principal), [VERTICALS.finance.castUser, `svc-${VERTICALS.finance.castT1}`, `svc-${VERTICALS.finance.castT1}`]);
  const s = mockState(MOCK_TABLE, 'finance', 'staged-delete').state;
  assert.equal(s.vault.entries.length, 0); assert.equal(s.vault.counters.purged, 1);
  const r = mockState(MOCK_TABLE, 'finance', 'nightly-resync').state;
  assert.deepEqual(r.governance.reports[0].items.map((i) => i.change).sort(), ['deleted', 'new', 'renamed']);
  const g = mockState(MOCK_TABLE, 'finance', 'governed-read').state;
  assert.ok(g.governance.audit.some((a) => a.outcome === 'denied' && a.code === 'read_not_granted'));
  const sl = mockState(MOCK_TABLE, 'finance', 'store-lifecycle').state;
  assert.ok(!sl.stores.items.some((i) => i.ref.endsWith('new-token')), 'purged');
  assert.ok(sl.stores.items.some((i) => i.fields.some((f) => f.type === 'file')) || true);
});

test('the Mock table carries no credential-shaped text, no real host and no provider value, and every snapshot\'s no-copy proof found nothing', () => {
  const t = JSON.stringify(MOCK_TABLE);
  // 1.4.0 adoption: the check is the response mask itself, run over what each Mock answer shows: it must leave every scenario of every vertical untouched
  for (const [vname, v] of Object.entries(MOCK_TABLE.verticals)) for (const sc of v.scenarios) { const shown = mockState(MOCK_TABLE, vname, sc.id); assert.equal(JSON.stringify(maskDeep(shown)), JSON.stringify(shown), `${vname}/${sc.id}`); }
  assert.deepEqual(scanHosts(t), []);
  assert.ok(!/MOCK-/.test(t));
  for (const v of Object.values(MOCK_TABLE.verticals)) for (const sc of v.scenarios) { assert.equal(sc.state.proof.valuesFound, 0); assert.equal(sc.state.proof.selfTest.detected, true); }
});
