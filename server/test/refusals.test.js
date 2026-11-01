// Second review: an unidentified caller gets a state-free 401 and no workspace; a scope is credential-checked like every other typed identifier;
// the plain-language credential words work with a space; over-long names and notes are refused whole (never cut); and the editable fields and limits
// that survived mutation are pinned (key reachable, target protocol, header pairs, scope depth, versions kept).
import test from 'node:test';
import assert from 'node:assert/strict';
import { findCredentials, cleanFree } from '../src/credentials.js';
import { createWorkspaces } from '../src/workspaces.js';
import { LIMITS } from '../src/engine.js';
import { C, U1, U2, ADMIN, code, get, live, mk, newEngine, post, run, withServer } from './helpers.js';

const entry = (o = {}) => ({ name: 'prod ledger', targetId: C.castT1, shape: 'bearer', generate: true, ...o });

test('an unidentified caller (no actor, or one off the roster) gets a 401 with no vault state in it, and creates no workspace', async () => {
  await withServer(async (url, { workspaces }) => {
    assert.equal((await post(url, '/api/vault/entries', live({ entry: entry() }), U1, { 'x-workspace': 'unk1' })).status, 200);
    const sizeBefore = workspaces.size();
    for (const actor of [null, 'nobody']) {
      const r = await post(url, '/api/vault/entries', live({ entry: entry() }), actor, { 'x-workspace': 'unk1' });
      const text = await r.text(); const b = JSON.parse(text);
      assert.equal(r.status, 401); assert.equal(b.error, 'unknown_actor');
      assert.equal(b.state, undefined, 'no state in a refusal for an unknown caller'); assert.ok(!text.includes('vcr-0001') && !text.includes(U1) && !text.includes('"nonce"'), text.slice(0, 200));
      // a brand-new workspace id: still no state, and the workspace is not created
      const fresh = await post(url, '/api/clock', live({ clock: { minutes: 1 } }), actor, { 'x-workspace': `fresh-${actor || 'none'}` });
      assert.equal(fresh.status, 401); assert.equal((await fresh.json()).state, undefined);
      const proof = await post(url, '/api/proof/run', live({}), actor, { 'x-workspace': `fresh-p-${actor || 'none'}` });
      assert.equal(proof.status, 401);
    }
    assert.equal(workspaces.size(), sizeBefore, 'no workspace was created by an unidentified caller');
  });
});

test('unidentified callers cannot fill the workspace cap: the next real visitor on a new id is served', async () => {
  const workspaces = createWorkspaces({ max: 3 });
  await withServer(async (url) => {
    for (let i = 0; i < 6; i++) assert.equal((await post(url, '/api/clock', live({ clock: { minutes: 1 } }), i % 2 ? null : 'nobody', { 'x-workspace': `junk-${i}` })).status, 401);
    assert.equal(workspaces.size(), 0);
    const r = await post(url, '/api/vault/entries', live({ entry: entry() }), U1, { 'x-workspace': 'real-visitor' });
    assert.equal(r.status, 200, 'a legitimate new visitor is not refused with workspace_cap');
  }, { workspaces });
});

test('the cap still refuses a NEW workspace for a real caller with 503 and a state-free body (nothing evicted)', async () => {
  const workspaces = createWorkspaces({ max: 1 });
  await withServer(async (url) => {
    assert.equal((await post(url, '/api/vault/entries', live({ entry: entry() }), U1, { 'x-workspace': 'one' })).status, 200);
    const r = await post(url, '/api/vault/entries', live({ entry: entry() }), U1, { 'x-workspace': 'two' });
    assert.equal(r.status, 503); assert.equal((await r.json()).error, 'workspace_cap'); assert.ok(workspaces.peek('one', 'finance'));
  }, { workspaces });
});

test('a scope that looks like a credential is refused like every other typed identifier, and nothing is stored', () => {
  const e = newEngine();
  const before = e.s.policies.length;
  for (const scope of ['aws:abcdefghijklmnopqrstuvwxyz0123456789ABCD', 'aws:prod/payments/Zk9fQ2mLp7Zt3Wd8xY1v', 'aws:prod/ZZZZ1111222233334444555566667777']) {
    const r = run(e, 'grant', ADMIN, { grant: { principal: U2, scope, actions: ['read'] } });
    assert.equal(code(r), 'credential_shaped_text', scope);
    assert.ok(!JSON.stringify(r).includes(scope.slice(8)), 'never echoed');
  }
  assert.equal(e.s.policies.length, before);
  // ordinary scopes still work, including long lowercase paths and the default cast scopes
  for (const scope of ['aws:prod/payments/**', 'aws:**', '*:**', `azure:${C.castKv}/*`, 'aws:prod/payments/db-admin']) assert.equal(code(run(e, 'grant', ADMIN, { grant: { principal: U2, scope, actions: ['read'] } })), 'ok', scope);
});

test('a scope has at most 10 segments: 10 accepted, 11 refused (bad_scope)', () => {
  const e = newEngine(); const path = (n) => Array.from({ length: n }, (_, i) => `s${i}`).join('/');
  assert.equal(code(run(e, 'grant', ADMIN, { grant: { principal: U2, scope: `aws:${path(10)}`, actions: ['read'] } })), 'ok');
  assert.equal(code(run(e, 'grant', ADMIN, { grant: { principal: U2, scope: `aws:${path(11)}`, actions: ['read'] } })), 'bad_scope');
});

test('credential words written with a space are found, as the detector\'s own comment promises (api key, private key, access key, account key, secret key, cred, passcode)', () => {
  const v = 'hunter2xyzQ';
  const phrases = [`my api key is ${v}`, `api key: ${v}`, `access key is ${v}`, `private key: ${v}`, `the secret key = ${v}`, `account key: ${v}`, `API KEY: ${v}`, `cred: ${v}`, `passcode: ${v}`, `api-key: ${v}`, `api_key=${v}`, `password: ${v}`, `pass=${v}`];
  for (const p of phrases) { assert.ok(findCredentials(p).length > 0, p); assert.ok(!cleanFree(p).includes(v), p); }
  // ordinary prose with the same words but no value after a separator is left alone
  for (const p of ['the api key rotates every night', 'a private key never leaves the vault', 'secret keys stay in the vault']) assert.equal(cleanFree(p), p);
});

test('over HTTP: notes written in plain language never come back', async () => {
  await withServer(async (url) => {
    for (const notes of ['my api key is hunter2xyzQ', 'access key is hunter2xyzQ', 'private key: hunter2xyzQ', 'the secret key = hunter2xyzQ']) {
      const r = await post(url, '/api/vault/entries', live({ entry: entry({ notes }) }), U1, { 'x-workspace': 'plain' });
      assert.equal(r.status, 200); const t = await r.text(); assert.ok(!t.includes('hunter2xyzQ'), notes);
    }
    assert.ok(!(await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'plain' })).text()).includes('hunter2xyzQ'));
  });
});

test('names: 80 characters accepted, 81 refused whole (bad_name), never cut; the same through HTTP and for an edit', async () => {
  assert.equal(LIMITS.name, 80); const e = newEngine();
  const n80 = `${'abcd '.repeat(15)}abcde`; assert.equal(n80.length, 80);
  const id = mk(e, U1, { name: n80 }); assert.equal(e.vaultGet(e.roster.get(U1), id).name, n80);
  const before = e.s.vault[U1].length;
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: entry({ name: `${n80}z` }) })), 'bad_name');
  assert.equal(e.s.vault[U1].length, before, 'nothing stored');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { name: `${n80}z` } })), 'bad_name'); assert.equal(e.vaultGet(e.roster.get(U1), id).name, n80, 'edit refused whole');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { name: `${n80.slice(0, 79)}` } })), 'ok');
  await withServer(async (url) => {
    const long = 'ab '.repeat(40).trim(); assert.equal(long.length, 119);
    const r = await post(url, '/api/vault/entries', live({ entry: entry({ name: long }) }), U1, { 'x-workspace': 'longname' });
    assert.equal(r.status, 400); assert.equal((await r.json()).error, 'bad_name');
  });
});

test('notes: 200 characters accepted, 201 refused whole (bad_notes), never cut; the same through HTTP and for an edit', async () => {
  assert.equal(LIMITS.notes, 200); const e = newEngine();
  const n200 = `${'abcd '.repeat(39)}abcde`; assert.equal(n200.length, 200);
  const id = mk(e, U1, { notes: n200 }); assert.equal(e.vaultGet(e.roster.get(U1), id).notes, n200);
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: entry({ notes: `${n200}z` }) })), 'bad_notes');
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { notes: `${n200}z` } })), 'bad_notes'); assert.equal(e.vaultGet(e.roster.get(U1), id).notes, n200);
  await withServer(async (url) => {
    const r = await post(url, '/api/vault/entries', live({ entry: entry({ notes: 'word '.repeat(60) }) }), U1, { 'x-workspace': 'longnote' });
    assert.equal(r.status, 400); assert.equal((await r.json()).error, 'bad_notes');
  });
});

test('key provider: reachable:false makes aws and vault fall back to the development key with a warning; reachable:true does not', () => {
  const e = newEngine();
  for (const configured of ['aws', 'vault']) {
    const down = run(e, 'restartKeys', ADMIN, { key: { configured, reachable: false } });
    assert.equal(down.ok, true); assert.equal(down.result.provider, 'dev', `${configured} unreachable`); assert.ok(down.result.warning, 'a warning says the development key is in use');
    const up = run(e, 'restartKeys', ADMIN, { key: { configured, reachable: true } });
    assert.equal(up.result.provider, configured); assert.equal(up.result.warning, null);
  }
});

test('a target protocol must be mcp or a2a: anything else is refused (bad_target) and nothing is added', () => {
  const e = newEngine(); const n = e.s.targets.length;
  for (const protocol of ['ftp', undefined, 'MCP', '', 5]) assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'new-target', accepts: 'bearer', protocol } })), 'bad_target', String(protocol));
  assert.equal(e.s.targets.length, n);
  assert.equal(code(run(e, 'addTarget', ADMIN, { target: { id: 'new-target', accepts: 'bearer', protocol: 'a2a' } })), 'ok');
});

test('a custom header credential has 1 to 5 pairs: 5 accepted, 6 refused (bad_secret), through create and through an edit that grows it', () => {
  assert.equal(LIMITS.headers, 5); const e = newEngine();
  const pairs = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`X-Partner-${i}`, `v${i}`]));
  const mkh = (n) => run(e, 'vaultCreate', U1, { entry: { name: `h${n}`, targetId: C.castT4, shape: 'headers', secret: { headers: pairs(n) } } });
  assert.equal(code(mkh(5)), 'ok'); assert.equal(code(mkh(6)), 'bad_secret'); assert.equal(code(mkh(1)), 'ok');
  const id = mkh(5).result.entryId;
  assert.equal(code(run(e, 'vaultUpdate', U1, { id, entry: { secret: { headers: { 'X-Extra': 'x' } } } })), 'bad_secret', 'a sixth pair added by an edit is refused whole');
  const one = mkh(1).result.entryId;
  assert.equal(code(run(e, 'vaultUpdate', U1, { id: one, entry: { secret: { headers: { 'X-Partner-0': null } } } })), 'bad_secret', 'removing the last pair is refused whole (at least 1)');
});

test('a secret keeps its last 10 versions: the 11th write drops the oldest, so a record never holds 11', () => {
  const e = newEngine(); const ref = `aws:${C.castAwsPrefix}/db-admin`;
  const versions = () => e.snapshot(e.roster.get(ADMIN)).stores.items.find((r) => r.ref === ref).versions;
  const start = versions();
  for (let i = start; i < 10; i++) assert.equal(code(run(e, 'storeRotate', ADMIN, { ref })), 'ok');
  assert.equal(versions(), 10);
  assert.equal(code(run(e, 'storeRotate', ADMIN, { ref })), 'ok'); assert.equal(versions(), 10, 'the 11th version pushed the oldest out');
});
