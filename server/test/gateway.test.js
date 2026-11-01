import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, U2, ADMIN, code, mk, newEngine, run } from './helpers.js';

const call = (e, who, o) => run(e, 'gatewayCall', who, { call: { operation: 'read_summary', as: 'per-user', ...o } });
const SHAPE_TARGET = [['bearer', C.castT1, { token: 'bearer-secret-value-AAAA1111' }, 'Authorization', /^Bearer /], ['api-key', C.castT2, { key: 'apikey-secret-value-BBBB2222' }, 'X-Api-Key', /^•+$/], ['basic', C.castT3, { username: 'maya', password: 'basic-pass-value-CCCC3333' }, 'Authorization', /^Basic /], ['headers', C.castT4, { headers: { 'X-Partner-Id': 'partner-id-value-DDDD4444', 'X-Partner-Key': 'partner-key-value-EEEE5555' } }, 'X-Partner-Id', /^•+$/]];

test('all four credential shapes are injected, the backend identifies the caller from the credential, and no value is in the answer', () => {
  const e = newEngine();
  for (const [shape, target, secret, header, shown] of SHAPE_TARGET) {
    const id = mk(e, U1, { name: shape, targetId: target, shape, generate: undefined, secret });
    const r = call(e, U1, { targetId: target, entryId: id });
    assert.equal(r.ok, true, shape);
    assert.equal(r.result.status, 200); assert.equal(r.result.backendView.principal, U1, shape);
    const inj = r.result.gatewayView.injected.find((i) => i.header === header);
    assert.ok(inj && shown.test(inj.shown), `${shape}: ${JSON.stringify(r.result.gatewayView.injected)}`);
    const text = JSON.stringify(r) + e.dump();
    for (const v of JSON.stringify(secret).match(/[a-z]+-[a-z]+-value-[A-Z0-9]+|[a-z]+-pass-value-[A-Z0-9]+/g)) assert.ok(!text.includes(v), `${shape}: ${v} must not appear`);
  }
});

test('the agent never sees the credential: the agent view has none, says so, and shows only the answer; the gateway view is masked', () => {
  const e = newEngine(); const id = mk(e, U1);
  const r = call(e, U1, { targetId: C.castT1, entryId: id }).result;
  assert.equal(r.agentView.holdsCredential, false);
  assert.deepEqual(Object.keys(r.agentView).sort(), ['answer', 'asked', 'holdsCredential', 'sees']);
  assert.match(r.gatewayView.injected[0].shown, /^Bearer •{8}$/);
  assert.ok(r.gatewayView.injected[0].bytes > 10);
  assert.match(r.gatewayView.lookedIn, /own; no other vault/);
});

test('a shared service account gives the backend the SAME identity for every caller; per-user gives each caller their own', () => {
  const e = newEngine(); const a = mk(e, U1); const b = mk(e, U2);
  const s1 = call(e, U1, { targetId: C.castT1, as: 'shared' }).result.backendView.principal;
  const s2 = call(e, U2, { targetId: C.castT1, as: 'shared' }).result.backendView.principal;
  assert.equal(s1, `svc-${C.castT1}`); assert.equal(s1, s2);
  assert.equal(call(e, U1, { targetId: C.castT1, entryId: a }).result.backendView.principal, U1);
  assert.equal(call(e, U2, { targetId: C.castT1, entryId: b }).result.backendView.principal, U2);
  const log = e.backend.log.map((x) => x.principal);
  assert.deepEqual(log, [s1, s1, U1, U2]);
});

test('no fallback: with no entry for the target the call is refused (not served by the shared account); two entries need one named', () => {
  const e = newEngine();
  assert.equal(code(call(e, U1, { targetId: C.castT1 })), 'no_credential_for_target');
  assert.equal(e.backend.log.length, 0, 'the backend was never called');
  mk(e, U1); mk(e, U1, { name: 'second' });
  assert.equal(code(call(e, U1, { targetId: C.castT1 })), 'entry_required');
  assert.equal(code(call(e, U1, { targetId: C.castT1, entryId: 'vcr-9999' })), 'not_found');
});

test('a call with the wrong entry for the target, a bad mode, an unknown target or an unknown operation is refused', () => {
  const e = newEngine(); const id = mk(e, U1);
  assert.equal(code(call(e, U1, { targetId: C.castT2, entryId: id })), 'entry_target_mismatch');
  assert.equal(code(call(e, U1, { targetId: C.castT1, entryId: id, as: 'admin' })), 'bad_as');
  assert.equal(code(call(e, U1, { targetId: 'nope', entryId: id })), 'unknown_target');
  assert.equal(code(call(e, U1, { targetId: C.castT1, entryId: id, operation: 'drop_tables' })), 'bad_operation');
});

test('the backend rejects the wrong kind of credential and an unknown one, and the refusal is logged without a principal', () => {
  const e = newEngine();
  const id = mk(e, U1, { name: 'wrong', targetId: C.castT1, shape: 'api-key' }); // an API key sent to a bearer-only target
  const r = call(e, U1, { targetId: C.castT1, entryId: id });
  assert.equal(r.result.status, 401); assert.match(r.result.backendView.outcome, /wrong kind/);
  const typed = mk(e, U1, { name: 'typed', targetId: C.castT3, shape: 'basic', generate: undefined, secret: { username: 'u', password: 'p-typed-by-the-visitor' } });
  assert.equal(call(e, U1, { targetId: C.castT3, entryId: typed }).result.status, 200, 'a credential the visitor typed is registered for them');
  assert.equal(e.backend.log.at(-1).principal, U1);
  assert.equal(e.backend.log[0].principal, null);
});

test('the first registration of a credential wins: pasting someone else\'s credential does not make it yours at the backend', () => {
  const e = newEngine(); const same = { token: 'shared-pasted-token-12345' };
  const a = mk(e, U1, { generate: undefined, secret: same }); const b = mk(e, U2, { generate: undefined, secret: same });
  assert.equal(call(e, U1, { targetId: C.castT1, entryId: a }).result.backendView.principal, U1);
  assert.equal(call(e, U2, { targetId: C.castT1, entryId: b }).result.backendView.principal, U1, 'the backend knows whose credential it is');
});

test('a gateway call is audited (allowed and rejected), kept in the gateway log with the real caller, and deleting a vault entry does not revoke it at the target', () => {
  const e = newEngine(); const id = mk(e, U1);
  call(e, U1, { targetId: C.castT1, entryId: id }); call(e, U1, { targetId: C.castT1, as: 'shared' });
  assert.deepEqual(e.s.gatewayLog.map((g) => [g.actor, g.as, g.status]), [[U1, 'per-user', 200], [U1, 'shared', 200]], 'the gateway knows who called even when the backend does not');
  assert.equal(e.s.audit.filter((a) => a.action === 'gateway.call').length, 2);
  const before = e.backend.registry.size; run(e, 'vaultDelete', U1, { id }); run(e, 'advance', U1, { clock: { minutes: 1440 } });
  assert.equal(e.backend.registry.size, before);
});

test('the hop panes show the masked injected header and a traceparent on every hop, and never the secret', () => {
  const e = newEngine(); const id = mk(e, U1, { generate: undefined, secret: { token: 'hop-pane-secret-ZZZZ9999' } });
  e.trace = { traceId: 'a'.repeat(32), span: () => 'b'.repeat(16) }; e.hops = [];
  call(e, U1, { targetId: C.castT1, entryId: id });
  const text = JSON.stringify(e.hops);
  assert.ok(e.hops.length >= 3); assert.ok(e.hops.every((h) => /^00-[0-9a-f]{32}-[0-9a-f]{16}-01$/.test(h.request.headers.traceparent)));
  assert.ok(!text.includes('hop-pane-secret')); assert.ok(text.includes('Bearer •'));
});

test('a staged entry cannot be used at the gateway, and the backend is never called for it', () => {
  const e = newEngine(); const id = mk(e, U1); run(e, 'vaultDelete', U1, { id });
  assert.equal(code(call(e, U1, { targetId: C.castT1, entryId: id })), 'entry_staged_for_delete');
  assert.equal(code(call(e, U1, { targetId: C.castT1 })), 'no_credential_for_target', 'with no entry named, a staged one is not picked either');
  assert.equal(e.backend.log.length, 0);
});

test('another role calling with someone else\'s entry id is refused before anything is injected', () => {
  const e = newEngine(); const id = mk(e, U1);
  assert.equal(code(call(e, ADMIN, { targetId: C.castT1, entryId: id })), 'not_found');
  assert.equal(e.backend.log.length, 0);
});
