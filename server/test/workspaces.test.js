import test from 'node:test';
import assert from 'node:assert/strict';
import { WORKSPACE_RE, createWorkspaces, workspaceFrom } from '../src/workspaces.js';
import { VERTICALS } from '../src/cast.js';

const C = VERTICALS.finance;
test('workspaceFrom defaults, accepts a good id and refuses a bad one', () => {
  assert.equal(workspaceFrom({ headers: {} }), 'default');
  assert.equal(workspaceFrom({ headers: { 'x-workspace': 'abc-1' } }), 'abc-1');
  for (const bad of ['', 'A', 'a b', 'a/b', 'x'.repeat(41), ['a'], '__proto__']) assert.equal(workspaceFrom({ headers: { 'x-workspace': bad } }), null);
  assert.ok(WORKSPACE_RE.test('a'));
});

test('engines are per workspace and per vertical, created on first use, and reset clears the workspace only', () => {
  const w = createWorkspaces();
  const a = w.engine('a', 'finance', C); const a2 = w.engine('a', 'finance', C); const ah = w.engine('a', 'health', VERTICALS.health); const b = w.engine('b', 'finance', C);
  assert.equal(a, a2); assert.notEqual(a, ah); assert.notEqual(a, b);
  assert.equal(w.peek('a', 'finance'), a); assert.equal(w.peek('zzz', 'finance'), null); assert.equal(w.peek('a', 'retail'), null);
  assert.equal(w.size(), 2, 'a peek never creates a workspace');
  w.reset('a');
  assert.equal(w.peek('a', 'finance'), null); assert.equal(w.peek('b', 'finance'), b);
});

test('the store expires old workspaces; at the cap a NEW workspace is refused (null) instead of evicting another visitor, and an existing one is still served', () => {
  let t = 0;
  const w = createWorkspaces({ max: 3, ttlMs: 100, now: () => t });
  for (const id of ['a', 'b', 'c']) assert.ok(w.engine(id, 'finance', C));
  assert.equal(w.engine('d', 'finance', C), null);
  assert.equal(w.size(), 3); assert.ok(w.peek('a', 'finance'), 'nobody was evicted');
  assert.ok(w.engine('a', 'finance', C));
  t = 500;
  assert.equal(w.peek('a', 'finance'), null); assert.ok(w.engine('d', 'finance', C), 'expired workspaces free room');
});

// ---------- credential-looking ids (sweep class F) ----------
import { credentialLookingId } from '../src/workspaces.js';
import { U1, get, post, live, withServer } from './helpers.js';

test('F: credential-looking workspace ids are refused: a run of 24 hex digits, a credential-word prefix, a keyword read with hyphens as spaces, no letter at all', () => {
  const j = (...p) => p.join('-'); // assembled at run time: no credential-looking literal sits in the repository
  const refused = [j('pw', 'hunter2xyz'), j('sk', 'abcdefghijklmnop1234'), j('password', 'hunter2xyz'), j('token', 'abcdef1234'), j('api', 'key', 'hunter2xyz'), j('secret', 'hunter2xyz'), j('ghp', 'abcdef123456'), 'akia-abcdef', 'eyj-abc', '0123456789abcdef01234567', 'w-0123456789abcdef01234567',
    `x-${'a'.repeat(24)}`, '123456789', '0', 'pw', 'pass-1', j('xoxb', '1234'), j('glpat', 'abcdef12'), j('ya29', 'abcdefgh'), j('bearer', 'hunter2xyz'), 'ab-cd-ef-gh-ij-kl-mn-op-1'];
  for (const id of refused) assert.equal(workspaceFrom({ headers: { 'x-workspace': id } }), null, id);
  const accepted = ['default', 'abc-1', 'lab-7', 'w-0123456789abcdef', `w${'a'.repeat(23)}`, 'hid200b', 'echo-ghp-x', 'my-workspace', 'a', 'pwa-1', 'skate-park-2', 'tokens-r-us', 'passenger-7'];
  for (const id of accepted) assert.equal(workspaceFrom({ headers: { 'x-workspace': id } }), id, id);
  assert.equal(credentialLookingId('a'.repeat(23)), false); assert.equal(credentialLookingId('a'.repeat(24)), true, 'exactly 24 hex digits is refused, 23 is not');
});

test('F: over HTTP a credential-looking id is a 400 bad_workspace on every read and write, never echoed, and it creates no workspace', async () => {
  const bad = [['pw', 'hunter2xyz'].join('-'), ['sk', 'abcdefghijklmnop1234'].join('-'), '0123456789abcdef01234567', ['password', 'hunter2xyz'].join('-'), '123456789012'];
  await withServer(async (url, { workspaces }) => {
    for (const id of bad) {
      const h = { 'x-workspace': id };
      for (const r of [await get(url, '/api/state?mode=live', U1, h), await get(url, '/api/vault/entries', U1, h), await get(url, '/api/governance', U1, h), await post(url, '/api/clock', live({ clock: { minutes: 1 } }), U1, h), await post(url, '/api/reset', {}, U1, h), await post(url, '/api/proof/run', live({}), U1, h)]) {
        const t = await r.text();
        assert.equal(r.status, 400, id); assert.equal(t, '{"error":"bad_workspace"}'); assert.ok(!t.includes(id) && !t.includes('hunter2xyz'));
      }
    }
    assert.equal(workspaces.size(), 0, 'a refused id creates nothing');
    const ok = await post(url, '/api/clock', live({ clock: { minutes: 1 } }), U1, { 'x-workspace': 'w-0123456789abcdef' });
    assert.equal(ok.status, 200); assert.equal((await ok.json()).workspace, 'w-0123456789abcdef');
  });
});
