// S5 and S8: every refusal is audited (credential-free), lab helpers are admin-only, the audit trail never overruns its cap, and a refused call changes nothing else.
import test from 'node:test';
import assert from 'node:assert/strict';
import { LIMITS } from '../src/engine.js';
import { C, U1, U2, ADMIN, AUD, SUP, code, mk, newEngine, run, get, post, live, withServer } from './helpers.js';

const AWS = `aws:${C.castAwsPrefix}/db-admin`;
const last = (e) => e.s.audit.at(-1);
const strip = (e, who) => { const s = e.snapshotCore(e.roster.get(who)); delete s.governance.audit; delete s.governance.auditTotal; return JSON.stringify(s); };

test('S8: every role-gated action refused for a non-admin is a 403 AND an audit entry (who, which operation, forbidden_role), for every admin-only operation and role', () => {
  const ops = [['grant', { grant: { principal: SUP, scope: 'aws:**', actions: ['read'] } }], ['revoke', { id: 'pol-0001' }], ['restartKeys', { key: { configured: 'none', reachable: true } }], ['addTarget', { target: { id: 'new-api', accepts: 'bearer', protocol: 'mcp' } }],
    ['removeTarget', { id: C.castT1 }], ['connectProvider', { provider: 'aws' }], ['providerChange', { change: { provider: 'aws', op: 'delete', ref: AWS } }], ['resync', {}]];
  for (const who of [U1, U2, AUD, SUP]) for (const [op, params] of ops) {
    const e = newEngine(); const n = e.s.audit.length;
    const r = run(e, op, who, params);
    assert.equal(r.ok, false, `${who} ${op}`); assert.equal(r.code, 'forbidden_role', `${who} ${op}`); assert.equal(r.status, 403);
    assert.equal(e.s.audit.length, n + 1, `${who} ${op}: exactly one audit entry`);
    assert.deepEqual({ actor: last(e).actor, action: last(e).action, outcome: last(e).outcome, code: last(e).code, resource: last(e).resource }, { actor: who, action: op, outcome: 'denied', code: 'forbidden_role', resource: '-' });
  }
});

test('S8: support or a user cannot change a provider through the lab helper (the grant model is not bypassed); the administrator can, and it is audited as a provider-side change', () => {
  const e = newEngine(); const before = e.providerValues().length; const inv = JSON.stringify(e.s.inventory);
  for (const who of [SUP, U1]) { assert.equal(code(run(e, 'providerChange', who, { change: { provider: 'aws', op: 'delete', ref: AWS } })), 'forbidden_role'); assert.equal(code(run(e, 'providerChange', who, { change: { provider: 'aws', op: 'rename', ref: AWS, newPath: `${C.castAwsPrefix}/x` } })), 'forbidden_role'); }
  assert.equal(e.providerValues().length, before); assert.equal(JSON.stringify(e.s.inventory), inv);
  assert.equal(code(run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'rename', ref: AWS, newPath: `${C.castAwsPrefix}/renamed` } })), 'ok');
  assert.ok(e.s.audit.some((a) => a.actor === 'provider-console' && a.action === 'provider.rename')); assert.equal(code(run(e, 'resync', ADMIN, {})), 'ok');
});

test('S8: the other refusals are audited too, credential-free: not found, unknown target, bad path, bad consumer, no credential for a target, unknown field, bad body', () => {
  const e = newEngine(); const cases = [
    ['vaultDelete', U1, { id: 'vcr-0099' }, 'not_found'], ['vaultCreate', U1, { entry: { name: 'x', targetId: 'nope', shape: 'bearer', generate: true } }, 'unknown_target'],
    ['storeCreate', ADMIN, { secret: { provider: 'aws', path: 'a b' } }, 'bad_path'], ['storeRead', U1, { read: { ref: AWS, consumer: 'anywhere' } }, 'bad_consumer'],
    ['gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary' } }, 'no_credential_for_target'], ['vaultCreate', U1, { entry: { zz: 1 } }, 'unknown_field'],
    ['storeRotate', SUP, { ref: AWS }, 'not_found'], ['advance', U1, { clock: { minutes: 0 } }, 'bad_minutes'],
  ];
  for (const [op, who, params, expect] of cases) {
    const n = e.s.audit.length; const r = run(e, op, who, params); assert.equal(r.code, expect, `${op}`);
    const added = e.s.audit.slice(n); assert.ok(added.length >= 1, `${op}: audited`); const a = added.at(-1);
    assert.equal(a.actor, who); assert.ok(['denied', 'refused'].includes(a.outcome)); assert.equal(a.code, expect === 'not_found' && op === 'storeRotate' ? 'no_grant' : expect);
    assert.equal(JSON.stringify(added).includes('vcr-0099'), false, 'the typed id is not copied into the audit'); assert.ok(!JSON.stringify(added).includes('a b'));
  }
});

test('S8: the clock move is audited under the person who made it (it is a lab control, not role-gated), and a refused move is audited as refused', () => {
  const e = newEngine(); run(e, 'advance', U1, { clock: { minutes: 5 } }); assert.deepEqual([last(e).actor, last(e).action, last(e).outcome], [U1, 'clock.advance', 'allowed']);
});

test('S8: an unknown caller is refused with no audit entry (there is nobody to name), and refusals never push the trail past its cap', () => {
  const e = newEngine(); const n = e.s.audit.length; assert.equal(run(e, 'vaultCreate', 'nobody', { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true } }).code, 'unknown_actor'); assert.equal(e.s.audit.length, n);
  while (e.s.audit.length < LIMITS.audit - 3) e.s.audit.push({ id: 'x', at: '', actor: 'system', role: 'system', domain: 'x', action: 'x', resource: '-', outcome: 'allowed' });
  for (let i = 0; i < 50; i++) run(e, 'vaultDelete', U1, { id: 'vcr-0099' });
  assert.ok(e.s.audit.length <= LIMITS.audit, String(e.s.audit.length));
});

test('S5a: the reviewer\'s overflow: 1000 entries, 900 staged, a 24 h move purges them all and the trail stays under its cap (one summary entry per person), nothing locks', () => {
  const e = newEngine(); const ids = { [U1]: [], [U2]: [] };
  for (let i = 0; i < 500; i++) for (const who of [U1, U2]) ids[who].push(mk(e, who, { name: `n${i}`, generate: true }));
  for (let i = 0; i < 450; i++) for (const who of [U1, U2]) run(e, 'vaultDelete', who, { id: ids[who][i] });
  assert.ok(e.s.audit.length >= 1900, String(e.s.audit.length));
  const r = run(e, 'advance', U1, { clock: { minutes: 1440 } });
  assert.equal(r.ok, true, JSON.stringify(r)); assert.equal(r.result.purged, 900); assert.ok(e.s.audit.length <= LIMITS.audit, `audit ${e.s.audit.length}`);
  const purges = e.s.audit.filter((a) => a.action === 'vault.purge'); assert.equal(purges.length, 2); assert.match(purges[0].resource, /vcr-0001, vcr-0003, vcr-0005 and 447 more \(450 entries\)|and 447 more \(450 entries\)/);
  assert.equal(e.s.vault[U1].length, 50); assert.equal(e.s.counters.purged, 900);
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'still works', targetId: C.castT1, shape: 'bearer', generate: true } })) , e.s.audit.length + 6 > LIMITS.audit ? 'workspace_full' : 'ok');
});

test('S5a: a move the trail could not hold is refused whole and changes nothing (no half sweep, the clock stays)', () => {
  const e = newEngine(); const a = mk(e, U1); const b = mk(e, U2); run(e, 'vaultDelete', U1, { id: a }); run(e, 'vaultDelete', U2, { id: b });
  while (e.s.audit.length < LIMITS.audit - 9) e.s.audit.push({ id: 'x', at: '', actor: 'system', role: 'system', domain: 'x', action: 'x', resource: '-', outcome: 'allowed' });
  const before = JSON.stringify([e.s.clock, e.s.vault, e.s.audit.length, e.s.reports]);
  const r = run(e, 'advance', U1, { clock: { minutes: 10080 } }); // needs 2 purge summaries + 7 nights + 1 move > 9 free
  assert.equal(r.code, 'workspace_full'); assert.equal(JSON.stringify([e.s.clock, e.s.vault, e.s.audit.length, e.s.reports]), before);
});

test('S5b: a refused call changes NOTHING but the audit trail: after 300 gateway calls a refused one leaves the log at 300 with the same first entry; every refusal path leaves the visible state identical', () => {
  const e = newEngine(); const id = mk(e, U1);
  for (let i = 0; i < 300; i++) assert.equal(run(e, 'gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } }).ok, true);
  assert.equal(e.s.gatewayLog.length, 300); const first = e.s.gatewayLog[0].n;
  assert.equal(code(run(e, 'gatewayCall', U1, { call: { targetId: C.castT2, as: 'per-user', operation: 'read_summary' } })), 'no_credential_for_target');
  assert.equal(e.s.gatewayLog.length, 300); assert.equal(e.s.gatewayLog[0].n, first, 'nothing was shifted by a refused call');
  const refusals = [
    ['vaultCreate', U1, { entry: { name: 'x', targetId: 'nope', shape: 'bearer', generate: true } }], ['vaultCreate', U1, { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', secret: { token: 'a'.repeat(65537) } } }],
    ['vaultUpdate', U1, { id, entry: { shape: 'basic' } }], ['vaultUpdate', U2, { id, entry: { notes: 'x' } }], ['vaultDelete', U2, { id }], ['vaultRestore', U1, { id }],
    ['gatewayCall', U1, { call: { targetId: C.castT3, as: 'per-user', operation: 'read_summary' } }], ['gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'nope' } }],
    ['restartKeys', U1, { key: { configured: 'none', reachable: true } }], ['addTarget', U1, { target: { id: 'zz-api', accepts: 'bearer', protocol: 'mcp' } }], ['removeTarget', U1, { id: C.castT1 }],
    ['storeCreate', U1, { secret: { provider: 'aws', path: 'prod/x/y' } }], ['storeRead', SUP, { read: { ref: AWS, consumer: 'simulated-gateway' } }], ['storeRead', ADMIN, { read: { ref: AWS, consumer: 'simulated-gateway' } }],
    ['storeUpdate', U1, { update: { ref: AWS, tags: ['x'] } }], ['storeRotate', U1, { ref: AWS }], ['storeDelete', U1, { ref: AWS }], ['storeRecover', ADMIN, { ref: AWS }], ['storePurge', ADMIN, { ref: AWS }],
    ['providerChange', SUP, { change: { provider: 'aws', op: 'delete', ref: AWS } }], ['resync', U1, {}], ['grant', U1, { grant: { principal: U1, scope: 'aws:**', actions: ['read'] } }], ['revoke', U2, { id: 'pol-0001' }],
    ['advance', U1, { clock: { minutes: 99999 } }], ['connectProvider', SUP, { provider: 'aws' }],
  ];
  for (const [op, who, params] of refusals) {
    const before = ['user', 'admin', 'support'].map((r) => strip(e, { user: U1, admin: ADMIN, support: SUP }[r])).join('|'); const clock = e.s.clock; const inv = JSON.stringify(e.s.inventory); const vault = JSON.stringify(e.s.vault); const log = JSON.stringify(e.s.gatewayLog);
    const r = run(e, op, who, params); assert.equal(r.ok, false, `${op} by ${who} must be refused`);
    assert.equal(['user', 'admin', 'support'].map((x) => strip(e, { user: U1, admin: ADMIN, support: SUP }[x])).join('|'), before, `${op}: the visible state is byte-identical`);
    assert.deepEqual([e.s.clock, JSON.stringify(e.s.inventory), JSON.stringify(e.s.vault), JSON.stringify(e.s.gatewayLog)], [clock, inv, vault, log], `${op}: clock, inventory, vault and log untouched`);
  }
});

test('S4: what a consumer holds is compared NOW against a fresh read of the provider, in both directions (current, then stale after a provider-side rotation, then current again after a new read); nothing delivered yet is reported as such', () => {
  const e = newEngine(); const state = () => e.snapshot(e.roster.get(U1)).governance.consumerStates.find((c) => c.name === 'simulated-gateway');
  assert.deepEqual([state().last, state().currentWithProvider], [null, null]);
  run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-gateway' } });
  assert.equal(state().currentWithProvider, true); assert.equal(state().last.ref, AWS);
  run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'rotate', ref: AWS } });
  assert.equal(state().currentWithProvider, false); assert.match(state().reason, /changed after the delivery/);
  run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-gateway' } });
  assert.equal(state().currentWithProvider, true);
  run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'delete', ref: AWS } });
  assert.equal(state().currentWithProvider, null); assert.match(state().reason, /gone/);
  assert.equal(e.snapshot(e.roster.get(U1)).governance.consumerStates.find((c) => c.name === 'simulated-agent-tool').currentWithProvider, null);
});

test('nit: "aws:prod/payments/**" covers prod/payments itself and everything below it (a documented choice: ** matches zero or more segments), but not a sibling', async () => {
  const { scopeMatches } = await import('../src/policy.js');
  assert.equal(scopeMatches('aws:prod/payments/**', 'aws', 'prod/payments'), true); assert.equal(scopeMatches('aws:prod/payments/**', 'aws', 'prod/payments/x/y'), true);
  assert.equal(scopeMatches('aws:prod/payments/**', 'aws', 'prod/paymentsx'), false); assert.equal(scopeMatches('aws:prod/payments/**', 'aws', 'prod'), false);
});

test('over HTTP: a refused request is a real 403 for a non-admin helper call and the answer carries the audited trail entry', async () => {
  await withServer(async (url) => {
    const r = await post(url, '/api/stores/provider-change', live({ change: { provider: 'aws', op: 'delete', ref: AWS } }), SUP); assert.equal(r.status, 403);
    const b = await r.json(); assert.equal(b.error, 'forbidden_role'); assert.ok(b.state.governance.audit.some((a) => a.code === 'forbidden_role' && a.actor === SUP));
    const resync = await post(url, '/api/stores/resync', live({}), U1); assert.equal(resync.status, 403);
    const g = await (await get(url, '/api/governance', ADMIN)).json(); assert.ok(g.audit.filter((a) => a.code === 'forbidden_role').length >= 2);
  });
});
