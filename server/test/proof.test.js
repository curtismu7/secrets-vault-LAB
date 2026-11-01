// B2: the proof never holds the event loop (generator checkpoints, time slices, a cache keyed by the state version), and a workspace's sealed bytes are capped.
import test from 'node:test';
import assert from 'node:assert/strict';
import { buildIndex, drain, scanText, WINDOW } from '../src/proof.js';
import { Engine, LIMITS } from '../src/engine.js';
import { C, U1, U2, ADMIN, code, get, post, live, mk, newEngine, run, withServer } from './helpers.js';

const fill = (e, n, who = U1) => { for (let i = 0; i < n; i++) mk(e, who, { name: `e${i}` }); };

test('the scan yields at checkpoints: a 1 MB text gives several, so a caller can slice the work', () => {
  const index = buildIndex([{ label: 'v', value: 'a-value-of-some-length-1234' }]);
  const text = 'x'.repeat(1_000_000); let checkpoints = 0; const found = [];
  const g = scanText(text, index, 'area', found); for (;;) { const r = g.next(); if (r.done) break; checkpoints += 1; }
  assert.ok(checkpoints >= 4 && checkpoints <= 6, String(checkpoints)); assert.equal(found.length, 0); assert.ok(WINDOW === 12);
});

test('proofAsync runs in slices that yield to the event loop (the loop keeps turning between them), and its result equals the synchronous one', async () => {
  const e = newEngine(); fill(e, 40);
  let turns = 0; let running = true; const spin = () => { turns += 1; if (running) setImmediate(spin); }; setImmediate(spin);
  let slices = 0;
  const result = await e.proofAsync({ sliceMs: 0, onSlice: () => { slices += 1; } });
  running = false;
  assert.ok(slices >= 8, `the work was cut into ${slices} slices`); assert.equal(e.proofSlices, slices);
  assert.ok(turns >= slices - 1, `the loop turned ${turns} times while ${slices} slices ran`);
  const sync = e.proofSync({}); assert.equal(result.valuesFound, 0); assert.deepEqual({ ...result, clock: 0 }, { ...sync, clock: 0 });
  const fast = await newEngine().proofAsync({ sliceMs: 10_000 }); assert.equal(fast.valuesFound, 0, 'a long slice budget still completes');
});

test('one run at a time: a second call while one is running returns the same promise', async () => {
  const e = newEngine(); fill(e, 10);
  const a = e.proofAsync({ sliceMs: 0 }); const b = e.proofAsync({ sliceMs: 0 });
  assert.equal(a, b); await a; assert.equal(e.proofJob, null);
});

test('a state read never recomputes a large proof: it shows the cache while the state is unchanged, an honest "run it" placeholder when it is not, and never a made-up pass', async () => {
  const e = newEngine(); fill(e, 110);
  const first = e.snapshot(e.roster.get(U1)).proof;
  assert.equal(first.skipped, true); assert.equal(first.last, null); assert.match(first.reason, /Run the proof now/); assert.equal('valuesFound' in first, false, 'no pass is claimed');
  const done = await e.proofAsync({ sliceMs: 0 });
  assert.equal(e.snapshot(e.roster.get(U1)).proof, done, 'the cached result, same object, no recomputation');
  assert.equal(e.snapshot(e.roster.get(U2)).proof, done);
  run(e, 'vaultDelete', U1, { id: e.s.vault[U1][0].id });
  const stale = e.snapshot(e.roster.get(U1)).proof;
  assert.equal(stale.skipped, true); assert.deepEqual(stale.last, { valuesFound: 0, valuesChecked: done.valuesChecked, version: stale.last.version, current: false });
});

test('a run that overlaps a change is marked stale and is NOT cached as current', async () => {
  const e = newEngine(); fill(e, 20);
  const p = e.proofAsync({ sliceMs: 0, onSlice: () => { if (e.proofSlices === 1) run(e, 'vaultDelete', U1, { id: e.s.vault[U1][0].id }); } });
  const r = await p; assert.equal(r.stale, true); assert.ok(!e.proofCache || e.proofCache.version === e.version);
});

test('a small workspace is computed on the read (cheap) and cached against the version', () => {
  const e = newEngine(); const a = e.snapshot(e.roster.get(U1)).proof; assert.ok(!a.skipped); assert.equal(a.valuesFound, 0);
  assert.equal(e.snapshot(e.roster.get(U1)).proof, a, 'cache hit'); mk(e, U1); assert.notEqual(e.snapshot(e.roster.get(U1)).proof, a, 'a change invalidates it');
});

test('the sealed bytes of a workspace are capped at 4 MB: 64 full-size credentials fit exactly, the 65th is refused whole, an update that grows past it is refused, a purge frees room', () => {
  const e = newEngine(); const big = (n = 65536) => ({ token: 'a'.repeat(n) });
  for (let i = 0; i < 64; i++) assert.equal(code(run(e, 'vaultCreate', i % 2 ? U1 : U2, { entry: { name: `b${i}`, targetId: C.castT1, shape: 'bearer', secret: big() } })), 'ok', `entry ${i}`);
  assert.equal(e.sealedTotal(), LIMITS.workspaceSecretBytes);
  const count = e.s.vault[U1].length + e.s.vault[U2].length;
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'one more', targetId: C.castT1, shape: 'bearer', secret: { token: 'a'.repeat(1) } } })), 'workspace_secret_bytes_full');
  assert.equal(e.s.vault[U1].length + e.s.vault[U2].length, count);
  const small = e.s.vault[U1][0]; run(e, 'vaultUpdate', U1, { id: small.id, entry: { secret: { token: 'b'.repeat(10) } } }); // shrinking is fine
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: small.id, entry: { secret: { token: 'c'.repeat(65536) } } })), 'ok', 'back to the old size: exactly at the cap');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: e.s.vault[U1][1].id, entry: { secret: { token: 'a'.repeat(65536) + '' } } })), 'ok');
  run(e, 'vaultDelete', U1, { id: e.s.vault[U1][2].id }); run(e, 'advance', U1, { clock: { minutes: 1440 } });
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'fits again', targetId: C.castT1, shape: 'bearer', secret: { token: 'z'.repeat(60000) } } })), 'ok', 'a purge freed room');
  assert.ok(e.sealedTotal() <= LIMITS.workspaceSecretBytes);
});

test('the cap also stops an UPDATE that grows a credential past it (refused whole, the stored value untouched), and allows growth that fits', () => {
  const e = newEngine(); const mkb = (who, n, name) => run(e, 'vaultCreate', who, { entry: { name, targetId: C.castT1, shape: 'bearer', secret: { token: 'a'.repeat(n) } } });
  for (let i = 0; i < 63; i++) assert.equal(code(mkb(U2, 65536, `b${i}`)), 'ok');
  const x = mkb(U1, 40000, 'x').result.entryId; assert.equal(code(mkb(U1, 25000, 'y')), 'ok');
  assert.equal(e.sealedTotal(), 63 * 65536 + 65000);
  const sealed = JSON.stringify(e.s.vault[U1][0].sealed);
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: x, entry: { secret: { token: 'b'.repeat(41000) } } })), 'workspace_secret_bytes_full');
  assert.equal(JSON.stringify(e.s.vault[U1][0].sealed), sealed, 'refused whole');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: x, entry: { secret: { token: 'b'.repeat(40500) } } })), 'ok', 'growth that fits is fine');
});

test('over HTTP: a big workspace answers GET /api/state promptly and /api/health stays responsive while POST /api/proof/run works in slices; the next read shows the result', async () => {
  await withServer(async (url, { workspaces }) => {
    const e = workspaces.engine('big', 'finance', C); fill(e, 300);
    const t0 = Date.now(); const st = await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'big' })).json();
    assert.equal(st.state.proof.skipped, true); assert.ok(Date.now() - t0 < 15000, `GET /api/state took ${Date.now() - t0} ms (the bound is loose on purpose: the work bound is asserted by the skip and slice tests; this machine is shared and loaded)`);
    const running = post(url, '/api/proof/run', live({}), U1, { 'x-workspace': 'big' });
    let healthy = 0; for (let i = 0; i < 5; i++) { const h = Date.now(); const r = await get(url, '/api/health', null); assert.equal(r.status, 200); assert.ok(Date.now() - h < 8000); healthy += 1; }
    const done = await running; assert.equal(done.status, 200); const body = await done.json(); assert.equal(body.proof.valuesFound, 0); assert.equal(body.proof.selfTest.detected, true); assert.ok(healthy === 5);
    const again = await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'big' })).json(); assert.equal(again.state.proof.valuesFound, 0, 'cached, current');
    // the endpoint's own rules
    assert.equal((await post(url, '/api/proof/run', { mode: 'mock' }, U1)).status, 409); assert.equal((await post(url, '/api/proof/run', live({ x: 1 }), U1)).status, 400);
    assert.equal((await post(url, '/api/proof/run', live({}), 'nobody')).status, 401); assert.equal((await post(url, '/api/proof/run', { mode: 'live', vertical: 'nope' }, U1)).status, 400);
  });
});

test('the 500 x 64 KB case is no longer reachable (the 4 MB cap), and the reviewer\'s timing case is bounded: 64 full-size entries read and proven in slices', async () => {
  const e = newEngine(); for (let i = 0; i < 64; i++) assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: `b${i}`, targetId: C.castT1, shape: 'bearer', secret: { token: 'a'.repeat(65536) } } })), 'ok');
  const t0 = Date.now(); const s = e.snapshot(e.roster.get(U1)); assert.ok(Date.now() - t0 < 2000, `snapshot ${Date.now() - t0} ms`); assert.equal(s.proof.skipped || s.proof.valuesFound === 0, true, 'computed quickly (64 entries is within the quick budget) or skipped, never a made-up pass');
  const r = await e.proofAsync({ sliceMs: 8 }); assert.equal(r.valuesFound, 0); assert.ok(r.valuesChecked >= 64);
});
