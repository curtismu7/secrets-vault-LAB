import test from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { aadFor, devKey, makeKeyMaterial, openBytes, resolveKey, sealBytes, SealError } from '../src/crypto.js';
import { C, U1, U2, ADMIN, code, mk, newEngine, run, seqRand } from './helpers.js';

const key = Buffer.alloc(32, 7);
const flip = (b64, i = 0) => { const b = Buffer.from(b64, 'base64'); b[i] ^= 1; return b.toString('base64'); };

test('AES-256-GCM round trip, 12-byte nonce, 16-byte tag, and the ciphertext is not the plaintext', () => {
  const nonce = Buffer.alloc(12, 1);
  const s = sealBytes(key, Buffer.from('hello world 123'), 'aad', nonce);
  assert.equal(Buffer.from(s.n, 'base64').length, 12); assert.equal(Buffer.from(s.t, 'base64').length, 16);
  assert.notEqual(Buffer.from(s.ct, 'base64').toString(), 'hello world 123');
  assert.equal(openBytes(key, s, 'aad').toString(), 'hello world 123');
});

test('tampering with the ciphertext, the tag, the nonce or the AAD is detected', () => {
  const s = sealBytes(key, Buffer.from('payload-bytes'), 'aad', Buffer.alloc(12, 2));
  for (const bad of [{ ...s, ct: flip(s.ct) }, { ...s, t: flip(s.t) }, { ...s, n: flip(s.n) }]) assert.throws(() => openBytes(key, bad, 'aad'), SealError);
  assert.throws(() => openBytes(key, s, 'aad2'), SealError);
  assert.throws(() => openBytes(Buffer.alloc(32, 8), s, 'aad'), SealError);
  assert.throws(() => openBytes(key, { ...s, n: Buffer.alloc(11).toString('base64') }, 'aad'), SealError);
});

test('a fresh random nonce for every value: 300 sealed entries have 300 distinct nonces, and the same secret seals differently each time', () => {
  const e = newEngine();
  const ids = Array.from({ length: 300 }, () => mk(e, U1));
  const snap = e.snapshot(e.roster.get(U1));
  assert.equal(snap.vault.sealedValues, 300); assert.equal(snap.vault.distinctNonces, 300);
  const sec = { token: 'same-secret-value-123' };
  const a = run(e, 'vaultCreate', U1, { entry: { name: 'a', targetId: C.castT1, shape: 'bearer', secret: sec } });
  const b = run(e, 'vaultCreate', U1, { entry: { name: 'b', targetId: C.castT1, shape: 'bearer', secret: sec } });
  const list = e.s.vault[U1];
  const ea = list.find((x) => x.id === a.result.entryId); const eb = list.find((x) => x.id === b.result.entryId);
  assert.notEqual(ea.sealed.n, eb.sealed.n); assert.notEqual(ea.sealed.ct, eb.sealed.ct);
  assert.equal(ids.length, 300);
});

test('a nonce that was already used is never used again (the engine draws again), and a source that only repeats is refused', () => {
  const base = seqRand('n'); const mode = { v: 'real', fixed: Buffer.alloc(12, 9), calls: 0 };
  const e = newEngine(C, { rand: (n) => { if (n === 12 && mode.v === 'dup') { mode.calls += 1; return mode.calls <= 2 ? mode.fixed : base(n); } if (n === 12 && mode.v === 'stuck') return mode.fixed; return base(n); } });
  mode.v = 'dup'; mode.calls = 0;
  mk(e, U1); // draws the fixed nonce for the first time
  const used = e.nonces.size;
  mk(e, U1); // the next draw repeats it: the engine must draw again
  assert.equal(e.nonces.size, used + 1);
  assert.equal(new Set([...e.nonces]).size, e.nonces.size);
  mode.v = 'stuck'; // now every draw repeats a nonce that is already in use
  e.nonces.add(mode.fixed.toString('hex'));
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true } })), 'nonce_exhausted');
  assert.equal(e.s.vault[U1].length, 2, 'nothing was stored');
});

test('the user id is in the AAD: a sealed value moved to another user\'s entry, or another entry of the same user, does not open', () => {
  const e = newEngine();
  const a = mk(e, U1); const b = mk(e, U2); const a2 = mk(e, U1);
  const ea = e.s.vault[U1].find((x) => x.id === a); const eb = e.s.vault[U2].find((x) => x.id === b); const ea2 = e.s.vault[U1].find((x) => x.id === a2);
  eb.sealed = { ...ea.sealed }; // copy user 1's ciphertext into user 2's entry
  assert.equal(code(run(e, 'gatewayCall', U2, { call: { targetId: C.castT1, as: 'per-user', entryId: b, operation: 'read_summary' } })), 'sealed_value_rejected');
  ea2.sealed = { ...ea.sealed }; // another entry of the same user
  assert.equal(code(run(e, 'gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: a2, operation: 'read_summary' } })), 'sealed_value_rejected');
  assert.ok(e.s.audit.some((x) => x.action === 'vault.integrity' && x.outcome === 'denied'));
  assert.notEqual(aadFor(U1, 'vcr-0001'), aadFor(U2, 'vcr-0001'));
});

test('a tampered stored value is refused by the gateway, not used (ciphertext, tag, nonce)', () => {
  for (const field of ['ct', 't', 'n']) {
    const e = newEngine(); const id = mk(e, U1);
    const en = e.s.vault[U1][0]; en.sealed = { ...en.sealed, [field]: flip(en.sealed[field]) };
    assert.equal(code(run(e, 'gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } })), 'sealed_value_rejected', field);
  }
});

test('the three key providers: aws (envelope), vault, and the development key as the fallback with a loud warning', () => {
  const m = makeKeyMaterial(seqRand('k'));
  const aws = resolveKey(m, 'aws', true); const vault = resolveKey(m, 'vault', true);
  assert.equal(aws.provider, 'aws'); assert.equal(vault.provider, 'vault'); assert.equal(aws.warning, null); assert.equal(vault.warning, null);
  assert.notDeepEqual(aws.key, vault.key);
  assert.ok(aws.steps.join(' ').includes('kms:Decrypt'));
  for (const [c, r] of [['none', true], ['aws', false], ['vault', false]]) { const d = resolveKey(m, c, r); assert.equal(d.provider, 'dev'); assert.match(d.warning, /^DEVELOPMENT KEY/); }
  assert.deepEqual(devKey(), createHash('sha256').update('secrets-vault-LAB development key: public, not a secret').digest());
});

test('under the development key anyone with the source can open a value, under aws they cannot: that is why the warning is loud', () => {
  const e = newEngine(); const id = mk(e, U1, { generate: undefined, secret: { token: 'dev-key-test-token-1' } });
  const en = e.s.vault[U1][0];
  assert.throws(() => openBytes(devKey(), en.sealed, aadFor(U1, id)), SealError);
  assert.equal(code(run(e, 'restartKeys', ADMIN, { key: { configured: 'none', reachable: true } })), 'ok');
  assert.equal(JSON.parse(openBytes(devKey(), e.s.vault[U1][0].sealed, aadFor(U1, id)).toString()).token, 'dev-key-test-token-1');
  const snap = e.snapshot(e.roster.get(U1));
  assert.equal(snap.vault.key.active, 'dev'); assert.match(snap.vault.key.warning, /DEVELOPMENT KEY/);
});

test('a key restart re-seals every value under the new key with fresh nonces; entries still work; only an admin may restart', () => {
  const e = newEngine(); const id = mk(e, U1); mk(e, U2);
  const before = e.s.vault[U1][0].sealed;
  assert.equal(code(run(e, 'restartKeys', U1, { key: { configured: 'vault', reachable: true } })), 'forbidden_role');
  assert.equal(e.s.vault[U1][0].sealed, before);
  const r = run(e, 'restartKeys', ADMIN, { key: { configured: 'vault', reachable: true } });
  assert.equal(r.result.provider, 'vault'); assert.ok(r.result.resealed >= 2);
  assert.notEqual(e.s.vault[U1][0].sealed.n, before.n); assert.notEqual(e.s.vault[U1][0].sealed.ct, before.ct);
  assert.equal(run(e, 'gatewayCall', U1, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } }).result.status, 200);
  assert.equal(code(run(e, 'restartKeys', ADMIN, { key: { configured: 'bogus', reachable: true } })), 'bad_key_config');
  assert.equal(code(run(e, 'restartKeys', ADMIN, { key: { configured: 'aws', reachable: 'yes' } })), 'bad_key_config');
});
