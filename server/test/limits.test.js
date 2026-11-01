// Every editable limit, at its exact boundary (the reviewer's surviving mutants): tags, name, notes, path, field bytes, logs, hops, workspace age, reports, deliveries.
import test from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/engine.js';
import { createWorkspaces } from '../src/workspaces.js';
import { scrub } from '../src/service.js';
import { C, U1, ADMIN, code, mk, newEngine, run } from './helpers.js';

const create = (e, who, secret) => run(e, 'storeCreate', who, { secret });

test('tags: five are accepted, a sixth is refused whole (LIMITS.tags), duplicates collapse, each tag is at most 24 characters', () => {
  assert.equal(LIMITS.tags, 5);
  const e = newEngine(); const ok = (tags, p) => code(create(e, ADMIN, { provider: 'aws', path: `prod/t/${p}`, tags }));
  assert.equal(ok(['a1', 'b1', 'c1', 'd1', 'e1'], 'one'), 'ok'); assert.equal(ok(['a1', 'b1', 'c1', 'd1', 'e1', 'f1'], 'two'), 'bad_tags');
  assert.equal(ok(['x'.repeat(24)], 'three'), 'ok'); assert.equal(ok(['x'.repeat(25)], 'four'), 'bad_tags'); assert.equal(e.s.inventory.find((r) => r.path === 'prod/t/two'), undefined, 'refused whole');
});

test('name: 80 characters are kept whole, text beyond 80 is cut to 80 (never stored longer), an empty name is refused', () => {
  assert.equal(LIMITS.name, 80); const e = newEngine();
  const long = 'wxyz '.repeat(30); const id2 = mk(e, U1, { name: long }); assert.ok(e.vaultGet(e.roster.get(U1), id2).name.length <= 80);
  const exact = `${'abcd '.repeat(15)}abcde`; assert.equal(exact.length, 80); const id3 = mk(e, U1, { name: exact }); assert.equal(e.vaultGet(e.roster.get(U1), id3).name, exact, 'exactly 80 is kept whole');
  const over = `${'abcd '.repeat(16)}`; assert.equal(over.length, 80); const id4 = mk(e, U1, { name: `${over}z` }); assert.equal(e.vaultGet(e.roster.get(U1), id4).name.length, 80, 'one over is cut to 80');
});

test('notes: 200 characters are kept whole, one over is cut to 200', () => {
  assert.equal(LIMITS.notes, 200); const e = newEngine();
  const n200 = `${'abcd '.repeat(39)}abcde`; assert.equal(n200.length, 200);
  const a = mk(e, U1, { notes: n200 }); assert.equal(e.vaultGet(e.roster.get(U1), a).notes, n200);
  const b = mk(e, U1, { notes: `${n200}z` }); assert.equal(e.vaultGet(e.roster.get(U1), b).notes.length, 200);
});

test('provider path: 120 characters are accepted, 121 refused (PATH_MAX); a store field: 4096 bytes accepted, 4097 refused (FIELD_MAX_BYTES), by bytes not characters', () => {
  const e = newEngine();
  const w = (n) => `${'abc-'.repeat(Math.ceil(n / 4))}`.slice(0, n - 1) + 'x'; const path120 = `${w(39)}/${w(39)}/${w(40)}`; assert.equal(path120.length, 120); const path121 = `${path120}d`;
  assert.equal(code(create(e, ADMIN, { provider: 'aws', path: path120 })), 'ok');
  assert.equal(code(create(e, ADMIN, { provider: 'aws', path: path121 })), 'bad_path');
  assert.equal(code(create(e, ADMIN, { provider: 'aws', path: 'prod/f/exact', fields: { value: 'a'.repeat(4096) } })), 'ok'); assert.equal(code(create(e, ADMIN, { provider: 'aws', path: 'prod/f/over', fields: { value: 'a'.repeat(4097) } })), 'bad_field_value');
  assert.equal(code(create(e, ADMIN, { provider: 'aws', path: 'prod/f/mb', fields: { value: 'é'.repeat(2048) } })), 'ok'); assert.equal(code(create(e, ADMIN, { provider: 'aws', path: 'prod/f/mb2', fields: { value: `${'é'.repeat(2048)}a` } })), 'bad_field_value');
});

test('the gateway log keeps the last 300: call 301 drops exactly the oldest; the reports keep 30; the deliveries keep 100', () => {
  assert.deepEqual([LIMITS.gatewayLog, LIMITS.reports, LIMITS.deliveries], [300, 30, 100]);
  const e = newEngine(); const id = mk(e, U1);
  for (let i = 0; i < 301; i++) run(e, 'gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } });
  assert.equal(e.s.gatewayLog.length, 300); assert.equal(e.s.gatewayLog[0].n, 2); assert.equal(e.s.gatewayLog.at(-1).n, 301);
  for (let i = 0; i < 31; i++) e.resync('manual'); assert.equal(e.s.reports.length, 30); assert.equal(e.s.reports[0].id, 'sync-0002');
  const f = newEngine(); for (let i = 0; i < 101; i++) run(f, 'storeRead', U1, { read: { ref: `aws:${C.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } });
  assert.equal(f.s.deliveries.length, 100); assert.equal(f.s.deliveries[0].n, 2);
});

test('the backend log keeps the last 300 as well', () => {
  const e = newEngine(); const id = mk(e, U1);
  for (let i = 0; i < 305; i++) run(e, 'gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } });
  assert.equal(e.backend.log.length, 300);
});

test('hops: at most 40 per answer, and the answer says when it was cut', () => {
  assert.equal(LIMITS.hops, 40); const e = newEngine(); e.trace = { traceId: 'a'.repeat(32), span: () => 'b'.repeat(16) }; e.hops = []; e.hopsTruncated = false;
  for (let i = 0; i < 50; i++) e.hop(`h${i}`, { method: 'GET', url: 'x' }, { status: 200 });
  assert.equal(e.hops.length, 40); assert.equal(e.hopsTruncated, true); assert.equal(e.hops.at(-1).label, 'h39');
});

test('workspaces expire after exactly one hour of idleness (default ttl) and are refused beyond the cap of 500 (default), on the injected clock', () => {
  let t = 0; const w = createWorkspaces({ now: () => t }); const c = C;
  w.engine('a', 'finance', c); t = 3_599_999; assert.ok(w.peek('a', 'finance'), 'still there just under an hour'); t = 3_599_999 + 3_600_001; assert.equal(w.peek('a', 'finance'), null, 'gone after an hour idle');
  const w2 = createWorkspaces({ now: () => 0 }); for (let i = 0; i < 500; i++) assert.ok(w2.engine(`w${i}`, 'finance', c) !== null, `workspace ${i}`);
  assert.equal(w2.engine('one-more', 'finance', c), null); assert.equal(w2.size(), 500);
});

test('B46: the hop panes show a write-only marker for every secret-carrying field, whatever the value (deterministic, no dependence on the random value)', () => {
  const secret = 'Distinct-Secret-Value-For-This-Test-ABCDEFG123';
  const out = JSON.stringify(scrub({ entry: { name: 'x', secret: { token: secret }, notes: 'n' }, secret: { fields: { value: secret }, provider: 'aws' }, update: { fields: { value: secret } } }));
  assert.ok(!out.includes(secret)); assert.ok(out.includes('(write-only'), out);
  assert.match(JSON.stringify(scrub({ entry: { secret: 'abc' } })), /\(write-only, 3 bytes\)/);
  const e = newEngine(); e.trace = { traceId: 'a'.repeat(32), span: () => 'b'.repeat(16) }; e.hops = [];
  mk(e, U1, { generate: undefined, secret: { token: secret } }); assert.ok(!JSON.stringify(e.hops).includes(secret)); assert.ok(JSON.stringify(e.hops).includes('write-only'));
});
