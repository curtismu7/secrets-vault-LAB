import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, U2, ADMIN, AUD, SUP, ALL, code, mk, newEngine, run } from './helpers.js';

const OTHERS = [U2, ADMIN, AUD, SUP];
const call = (e, who, entryId, o = {}) => run(e, 'gatewayCall', who, { call: { targetId: C.castT1, as: 'per-user', entryId, operation: 'read_summary', ...o } });

test('self-service: every role, on every vault path, is forced to its OWN vault: another user\'s entry is "not found" for all four others', () => {
  const e = newEngine(); const id = mk(e, U1);
  const before = JSON.stringify(e.s.vault[U1]);
  for (const who of OTHERS) {
    assert.equal(code(run(e, 'vaultUpdate', who, { id, entry: { notes: 'x' } })), 'not_found', `${who} update`);
    assert.equal(code(run(e, 'vaultDelete', who, { id })), 'not_found', `${who} delete`);
    assert.equal(code(run(e, 'vaultRestore', who, { id })), 'not_found', `${who} restore`);
    assert.equal(code(call(e, who, id)), 'not_found', `${who} use`);
    assert.throws(() => e.vaultGet(e.roster.get(who), id), /no such entry/);
    assert.deepEqual(e.vaultList(e.roster.get(who)), [], `${who} list`);
    assert.equal(e.snapshot(e.roster.get(who)).vault.entries.length, 0, `${who} snapshot`);
  }
  assert.equal(JSON.stringify(e.s.vault[U1]), before, 'nothing about the entry changed');
});

test('there is no administrator override: no body or call field names an owner, and an administrator\'s own vault is separate and works the same', () => {
  const e = newEngine(); const id = mk(e, U1);
  for (const k of ['owner', 'user', 'userId', 'vault', 'onBehalfOf', 'asUser', 'admin', 'override']) {
    assert.equal(code(run(e, 'gatewayCall', ADMIN, { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary', [k]: U1 } })), 'unknown_field', k);
    assert.equal(code(run(e, 'vaultCreate', ADMIN, { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true, [k]: U1 } })), 'unknown_field', k);
    assert.equal(code(run(e, 'vaultUpdate', ADMIN, { id, entry: { [k]: U1 } })), 'unknown_field', k);
  }
  const mine = mk(e, ADMIN);
  assert.equal(e.s.vault[ADMIN].length, 1);
  assert.equal(call(e, ADMIN, mine).result.backendView.principal, ADMIN, 'the backend logs the administrator for the administrator\'s own entry');
  assert.equal(e.s.vault[U1].length, 1);
});

test('snapshots never carry another person\'s entries, nonces or entry ids, for any role', () => {
  const e = newEngine(); const id = mk(e, U1, { name: 'private ledger' });
  const nonce = e.s.vault[U1][0].sealed.n;
  for (const who of OTHERS) {
    const text = JSON.stringify(e.snapshot(e.roster.get(who)));
    assert.ok(!text.includes('private ledger'), `${who}: name`);
    assert.ok(!text.includes(nonce), `${who}: nonce`);
    assert.ok(!text.includes(`"${id}"`) || who === ADMIN || who === AUD, `${who}: entry id appears only in audit for the oversight roles`);
  }
});

test('merge-edit: omitting the secret keeps the sealed value byte for byte; metadata changes; the version does not move', () => {
  const e = newEngine(); const id = mk(e, U1, { notes: 'one' });
  const sealed = JSON.stringify(e.s.vault[U1][0].sealed);
  const r = run(e, 'vaultUpdate', U1, { id, entry: { notes: 'two', name: 'Renamed' } });
  assert.equal(r.result.secretChanged, false);
  assert.equal(JSON.stringify(e.s.vault[U1][0].sealed), sealed);
  assert.equal(e.vaultGet(e.roster.get(U1), id).notes, 'two'); assert.equal(e.vaultGet(e.roster.get(U1), id).name, 'Renamed');
  assert.equal(e.vaultGet(e.roster.get(U1), id).secret.version, 1);
  assert.equal(call(e, U1, id).result.status, 200, 'the kept secret still works');
});

test('merge-edit: a secret change re-seals with a fresh nonce and bumps the version; a partial Basic secret merges field by field; headers merge by name, null removes', () => {
  const e = newEngine();
  const b = mk(e, U1, { name: 'reports', targetId: C.castT3, shape: 'basic', generate: undefined, secret: { username: 'maya', password: 'pw-one-aaaaaaa' } });
  const n1 = e.s.vault[U1][0].sealed.n;
  run(e, 'vaultUpdate', U1, { id: b, entry: { secret: { password: 'pw-two-bbbbbbb' } } });
  assert.notEqual(e.s.vault[U1][0].sealed.n, n1);
  assert.equal(e.vaultGet(e.roster.get(U1), b).secret.version, 2);
  const open = () => JSON.parse(Buffer.from('e30=', 'base64')); void open;
  const used = run(e, 'gatewayCall', U1, { call: { targetId: C.castT3, as: 'per-user', entryId: b, operation: 'list_items' } });
  assert.equal(used.result.backendView.principal, U1);
  const h = mk(e, U1, { name: 'pair', targetId: C.castT4, shape: 'headers', generate: undefined, secret: { headers: { 'X-Partner-Id': 'id-value-1', 'X-Partner-Key': 'key-value-1', 'X-Extra': 'extra-1' } } });
  run(e, 'vaultUpdate', U1, { id: h, entry: { secret: { headers: { 'X-Extra': null, 'X-Partner-Key': 'key-value-2' } } } });
  assert.deepEqual(e.vaultGet(e.roster.get(U1), h).headerNames, ['X-Partner-Id', 'X-Partner-Key']);
  assert.equal(run(e, 'gatewayCall', U1, { call: { targetId: C.castT4, as: 'per-user', entryId: h, operation: 'list_items' } }).result.status, 200);
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: h, entry: { secret: { headers: { 'X-Partner-Id': null, 'X-Partner-Key': null } } } })), 'bad_secret', 'a credential cannot be emptied by merge');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: b, entry: { secret: {} } })), 'bad_secret');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: b, entry: { shape: 'bearer' } })), 'secret_required');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: b, entry: { secret: { password: '' } } })), 'bad_secret');
});

test('a refused edit changes nothing at all (whole request refused)', () => {
  const e = newEngine(); const id = mk(e, U1, { notes: 'keep' });
  const before = JSON.stringify(e.s.vault[U1]);
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { notes: 'changed', targetId: 'no-such-target' } })), 'unknown_target');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { notes: 'changed', secret: { token: 'a'.repeat(65537) } } })), 'credential_too_large');
  assert.equal(JSON.stringify(e.s.vault[U1]), before);
});

test('staged delete: purge at exactly 24 hours (23:59 still there and restorable, 24:00 gone), and restore only inside the window', () => {
  const e = newEngine(); const id = mk(e, U1);
  run(e, 'vaultDelete', U1, { id });
  assert.equal(e.vaultGet(e.roster.get(U1), id).status, 'staged-delete');
  assert.equal(e.vaultGet(e.roster.get(U1), id).purgesInMin, 1440);
  run(e, 'advance', U1, { clock: { minutes: 1439 } });
  assert.equal(e.vaultGet(e.roster.get(U1), id).status, 'staged-delete', '23:59: still staged');
  assert.equal(e.vaultGet(e.roster.get(U1), id).purgesInMin, 1);
  assert.equal(code(run(e, 'vaultRestore', U1, { id })), 'ok', '23:59: restore works');
  run(e, 'vaultDelete', U1, { id });
  run(e, 'advance', U1, { clock: { minutes: 1439 } });
  assert.equal(e.s.vault[U1].length, 1);
  const r = run(e, 'advance', U1, { clock: { minutes: 1 } });
  assert.equal(r.result.purged, 1, '24:00: purged');
  assert.equal(e.s.vault[U1].length, 0);
  assert.equal(code(run(e, 'vaultRestore', U1, { id })), 'not_found');
  assert.ok(e.s.audit.some((a) => a.action === 'vault.purge' && a.actor === 'system'));
});

test('a staged entry cannot be edited, used or deleted again; restore of an active entry is refused; the purge time is fixed at staging', () => {
  const e = newEngine(); const id = mk(e, U1);
  assert.equal(code(run(e, 'vaultRestore', U1, { id })), 'not_staged');
  run(e, 'vaultDelete', U1, { id });
  const purgeAt = e.vaultGet(e.roster.get(U1), id).purgeAt;
  assert.equal(code(run(e, 'vaultDelete', U1, { id })), 'already_staged');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { notes: 'x' } })), 'entry_staged_for_delete');
  assert.equal(code(call(e, U1, id)), 'entry_staged_for_delete');
  run(e, 'advance', U1, { clock: { minutes: 600 } });
  assert.equal(e.vaultGet(e.roster.get(U1), id).purgeAt, purgeAt);
});

test('a single clock move past the boundary purges once; a move of 10081 minutes, 0, a fraction or a string is refused and the clock only moves forward', () => {
  const e = newEngine(); const id = mk(e, U1); run(e, 'vaultDelete', U1, { id });
  const t0 = e.s.clock;
  for (const m of [0, -5, 1.5, '60', 10081, null, NaN]) { assert.equal(code(run(e, 'advance', U1, { clock: { minutes: m } })), 'bad_minutes', String(m)); }
  assert.equal(e.s.clock, t0);
  assert.equal(run(e, 'advance', U1, { clock: { minutes: 10080 } }).result.purged, 1);
});

test('limits: exactly 500 entries per user, the 501st is refused whole; staged entries still count; purge frees a slot; other users have their own 500', () => {
  const e = newEngine();
  for (let i = 0; i < 500; i++) mk(e, U1, { name: `e${i}` });
  assert.equal(e.s.vault[U1].length, 500);
  const before = e.s.seq.entry;
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'one too many', targetId: C.castT1, shape: 'bearer', generate: true } })), 'vault_full');
  assert.equal(e.s.vault[U1].length, 500); assert.equal(e.s.seq.entry, before);
  run(e, 'vaultDelete', U1, { id: e.s.vault[U1][0].id });
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'still full', targetId: C.castT1, shape: 'bearer', generate: true } })), 'vault_full', 'a staged entry still counts');
  run(e, 'advance', U1, { clock: { minutes: 1440 } });
  assert.equal(e.s.vault[U1].length, 499);
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'fits now', targetId: C.castT1, shape: 'bearer', generate: true } })), 'ok');
  assert.equal(code(run(e, 'vaultCreate', U2, { entry: { name: 'mine', targetId: C.castT1, shape: 'bearer', generate: true } })), 'ok');
});

test('limits: a credential of exactly 65536 bytes is accepted and 65537 is refused whole, for every shape; bytes (not characters) are counted', () => {
  const e = newEngine(); const big = (n) => 'a'.repeat(n);
  const mkSecret = (shape, n) => (shape === 'bearer' ? { token: big(n) } : shape === 'api-key' ? { key: big(n) } : shape === 'basic' ? { username: 'u', password: big(n - 1) } : { headers: { 'X-One': big(n - 10), 'X-Two': big(10) } });
  const target = { bearer: C.castT1, 'api-key': C.castT2, basic: C.castT3, headers: C.castT4 };
  for (const shape of ['bearer', 'api-key', 'basic', 'headers']) {
    const ok = run(e, 'vaultCreate', U1, { entry: { name: shape, targetId: target[shape], shape, secret: mkSecret(shape, 65536) } });
    assert.equal(ok.ok, true, `${shape} at the limit`);
    assert.equal(e.vaultGet(e.roster.get(U1), ok.result.entryId).secret.bytes, 65536);
    const count = e.s.vault[U1].length;
    assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: shape, targetId: target[shape], shape, secret: mkSecret(shape, 65537) } })), 'credential_too_large', `${shape} one byte over`);
    assert.equal(e.s.vault[U1].length, count);
  }
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'multi', targetId: C.castT1, shape: 'bearer', secret: { token: 'é'.repeat(32768) } } })), 'ok', '32768 two-byte characters = 65536 bytes');
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'multi', targetId: C.castT1, shape: 'bearer', secret: { token: `${'é'.repeat(32768)}a` } } })), 'credential_too_large');
});

test('a merge that would push a credential over 64 KB is refused whole and the stored value is untouched', () => {
  const e = newEngine();
  const id = mk(e, U1, { name: 'pair', targetId: C.castT4, shape: 'headers', generate: undefined, secret: { headers: { 'X-Partner-Id': 'a'.repeat(60000), 'X-Partner-Key': 'k' } } });
  const sealed = JSON.stringify(e.s.vault[U1][0].sealed);
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { secret: { headers: { 'X-More': 'b'.repeat(6000) } } } })), 'credential_too_large');
  assert.equal(JSON.stringify(e.s.vault[U1][0].sealed), sealed);
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { secret: { headers: Object.fromEntries(Array.from({ length: 5 }, (_, i) => [`X-H${i}`, 'v'])) } } })), 'bad_secret', 'at most 5 header pairs');
});

test('removing a target system cleans up its entries automatically (not staged), only an administrator may remove it, and other targets are untouched', () => {
  const e = newEngine(); mk(e, U1); mk(e, U2); mk(e, U1, { name: 'cards', targetId: C.castT2, shape: 'api-key' });
  assert.equal(code(run(e, 'removeTarget', U1, { id: C.castT1 })), 'forbidden_role');
  assert.equal(e.s.vault[U1].length, 2);
  const r = run(e, 'removeTarget', ADMIN, { id: C.castT1 });
  assert.equal(r.result.entriesCleaned, 2);
  assert.deepEqual(e.s.vault[U1].map((x) => x.targetId), [C.castT2]); assert.equal(e.s.vault[U2].length, 0);
  assert.ok(e.s.audit.some((a) => a.action === 'vault.cleanup' && a.code === 'target_removed'));
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true } })), 'unknown_target');
  assert.equal(code(run(e, 'removeTarget', ADMIN, { id: C.castT1 })), 'unknown_target');
  // the administrator never read anything: the audit names counts, and the administrator's snapshot has no entries
  assert.equal(e.snapshot(e.roster.get(ADMIN)).vault.entries.length, 0);
});

test('targets can be added (admin only, id rules, cap of 20) and an entry may then use them', () => {
  const e = newEngine();
  assert.equal(code(run(e, 'addTarget', U1, { target: { id: 'new-api', accepts: 'bearer', protocol: 'mcp' } })), 'forbidden_role');
  assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'New API', accepts: 'bearer', protocol: 'mcp' } })), 'bad_target');
  assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'new-api', accepts: 'nope', protocol: 'mcp' } })), 'bad_target');
  assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'new-api', accepts: 'bearer', protocol: 'mcp' } })), 'ok');
  assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'new-api', accepts: 'bearer', protocol: 'mcp' } })), 'target_exists');
  for (let i = 0; i < 15; i++) assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: `more-${i}a`, accepts: 'basic', protocol: 'a2a' } })), 'ok');
  assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'one-more', accepts: 'basic', protocol: 'a2a' } })), 'targets_full');
});

test('input rules: shapes, header names, line breaks, colons, empty values, exclusive secret/generate, no header name on non-api-key', () => {
  const e = newEngine(); const mkc = (o) => code(run(e, 'vaultCreate', U1, { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', secret: { token: 'abcdefgh123' }, ...o } }));
  assert.equal(mkc({}), 'ok');
  assert.equal(mkc({ shape: 'pigeon' }), 'bad_shape');
  assert.equal(mkc({ secret: { token: '' } }), 'bad_secret');
  assert.equal(mkc({ secret: { token: 'line\r\nbreak' } }), 'bad_secret');
  assert.equal(mkc({ secret: { token: 'x', extra: 'y' } }), 'bad_secret');
  assert.equal(mkc({ secret: 'plain string' }), 'bad_secret');
  assert.equal(mkc({ generate: true }), 'bad_secret', 'both given');
  assert.equal(mkc({ secret: undefined, generate: undefined }), 'bad_secret', 'neither given');
  assert.equal(mkc({ headerName: 'X-Api-Key' }), 'bad_shape');
  assert.equal(mkc({ shape: 'basic', secret: { username: 'a:b', password: 'pw' } }), 'bad_secret');
  assert.equal(mkc({ shape: 'api-key', secret: { key: 'k1234567' }, headerName: 'Host' }), 'bad_header_name');
  assert.equal(mkc({ shape: 'api-key', secret: { key: 'k1234567' }, headerName: 'X-Api-Key' }), 'ok');
  assert.equal(mkc({ shape: 'headers', secret: { headers: { Authorization: 'v' } } }), 'bad_header_name');
  assert.equal(mkc({ shape: 'headers', secret: { headers: { 'X-A': 'bad\nvalue' } } }), 'bad_secret');
  assert.equal(mkc({ shape: 'headers', secret: { headers: {} } }), 'bad_secret');
  assert.equal(mkc({ targetId: 5 }), 'unknown_target');
  assert.equal(mkc({ name: '' }), 'bad_name');
  assert.equal(mkc({ name: 'ab '.repeat(30) }), 'ok', '80 characters is the most a name keeps (longer text is cut to 80)');
  assert.equal(mkc({ name: 'a'.repeat(81) }), 'credential_shaped_text', 'a long unbroken run looks like a key and is refused, never echoed');
  assert.equal(mkc({ notes: 42 }), 'bad_notes');
});

test('every actor shape: an unknown or missing caller is refused, a forged role is ignored', () => {
  const e = newEngine();
  assert.throws(() => e.vaultList({ id: 'nobody', role: 'admin' }), /not on the lab roster/);
  const forged = { id: U2, role: 'admin' };
  assert.throws(() => e.restartKeys(forged, { configured: 'none', reachable: true }), /admin role/);
  assert.equal(e.snapshot(forged).actor.role, 'user', 'the role comes from the roster, not from the caller');
});
