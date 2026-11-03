// The named sweep leaks, each with its own test: U+1680 in entry.name; "login: bob / x" and "password - x" in entry fields, path ids and the hop panes; the
// entry-id counter; vault secret values stay unechoed. Credential words are assembled at run time. Expected strings are LITERALS.
import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, U2, ADMIN, get, post, put, live, withServer } from './helpers.js';
import { sweepAll } from './sweep.js';
import { cleanFree, findCredentials } from '../src/credentials.js';

const PW = ['pass', 'word'].join(''); const OGHAM = ' '; const V1 = ['hunter', '2xyz'].join('');
const SHORT1 = `${PW} - x`; const SHORT2 = 'login: bob / x';
const TARGET = C.castT1;
const create = (url, entry, ws = 'leak-a') => post(url, '/api/vault/entries', live({ entry: { targetId: TARGET, shape: 'bearer', generate: true, ...entry } }), U1, { 'x-workspace': ws });
const capture = () => {
  const out = []; const wo = process.stdout.write.bind(process.stdout); const we = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c, ...a) => { out.push(String(c)); return wo(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return we(c, ...a); };
  return { out, stop: () => { process.stdout.write = wo; process.stderr.write = we; } };
};

test('U+1680 (Ogham space mark) between the words of a credential phrase in entry.name: the name is refused, never echoed, never stored; as notes it is masked', async () => {
  const forms = [`${PW}${OGHAM}${V1}`, `${PW.slice(0, 4)}${OGHAM}${PW.slice(4)} = ${V1}`, `my${OGHAM}${PW}${OGHAM}is${OGHAM}${V1}`, `${PW}${OGHAM}-${OGHAM}x`, `login:${OGHAM}bob${OGHAM}/${OGHAM}x`, `token${OGHAM}:${OGHAM}x`, `${OGHAM}${PW}${OGHAM}${OGHAM}:${OGHAM}${OGHAM}x`];
  assert.equal(forms.length, 7);
  const cap = capture();
  try {
    await withServer(async (url) => {
      for (const [i, f] of forms.entries()) {
        const ws = `ogham-${i}`;
        const r = await create(url, { name: f }, ws); const t = await r.text();
        assert.equal(r.status, 400, JSON.stringify(f)); assert.ok(t.includes('"credential_shaped_text"'), t.slice(0, 100));
        assert.ok(!t.includes(V1) && !t.includes('bob') && !t.includes(OGHAM) && !/"notes":"[^"]*x/.test(t), `name refused without an echo: ${JSON.stringify(f)}`);
        const n = await create(url, { name: 'ok name', notes: f }, ws); const nb = await n.json();
        assert.equal(n.status, 200, JSON.stringify(f));
        assert.ok(nb.result.entry.notes.includes('[masked:'), `notes masked: ${JSON.stringify(f)} -> ${nb.result.entry.notes}`);
        const all = JSON.stringify(nb) + await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': ws })).text() + await (await get(url, '/api/governance', ADMIN, { 'x-workspace': ws })).text();
        assert.ok(!all.includes(V1) && !all.includes('bob') && !all.includes(OGHAM), `absent from the answer, the hops, the state and the audit: ${JSON.stringify(f)}`);
        const u = await put(url, `/api/vault/entries/${nb.result.entryId}`, live({ entry: { name: f } }), U1, { 'x-workspace': ws });
        assert.equal(u.status, 400); assert.ok(!(await u.text()).includes(V1));
      }
      // plain U+1680 between ordinary words is just a space
      const ok = await create(url, { name: `Ledger${OGHAM}bearer`, notes: `rotate${OGHAM}quarterly` }, 'ogham-ok'); const okb = await ok.json();
      assert.equal(ok.status, 200); assert.equal(okb.result.entry.name, 'Ledger bearer'); assert.equal(okb.result.entry.notes, 'rotate quarterly');
    });
  } finally { cap.stop(); }
  assert.ok(!cap.out.join('').includes(V1), 'nothing was logged');
});

test('a one-letter password after a separator (a login pair, a word plus dash) is refused as a name and masked as notes, with the exact mark', async () => {
  assert.equal(cleanFree(SHORT1), '[masked:short-value]'); assert.equal(cleanFree(SHORT2), '[masked:short-value]');
  assert.equal(cleanFree(`rotate: ${SHORT1} soon`), 'rotate: [masked:short-value] soon'); assert.equal(cleanFree(`see ${SHORT2} now`), 'see [masked:short-value] now');
  assert.equal(findCredentials(SHORT1).length, 1); assert.equal(findCredentials(SHORT2).length, 1);
  for (const [t, form] of [[`${PW}: x`, 'colon'], [`${PW} = y`, 'equals'], [`${PW} – z`, 'en dash'], [`pw | q`, 'bar'], [`Token - a`, 'capital'], [`user: bob | k`, 'user pair'], [`account = bob / m`, 'account pair']]) assert.equal(cleanFree(t).includes('[masked:'), true, form);
  await withServer(async (url) => {
    for (const probe of [SHORT1, SHORT2]) {
      const r = await create(url, { name: probe }, 'short-a'); const t = await r.text();
      assert.equal(r.status, 400); assert.ok(t.includes('"credential_shaped_text"') && !t.includes(probe) && !t.includes('bob'), t.slice(0, 120));
      const n = await create(url, { name: 'ok', notes: probe }, 'short-b'); const nb = await n.json();
      assert.equal(n.status, 200); assert.equal(nb.result.entry.notes, '[masked:short-value]');
      assert.equal(nb.hops[0].request.body.entry.notes, '[masked:short-value]', 'the hop pane shows the masked text');
      const everything = JSON.stringify(nb) + await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'short-b' })).text() + await (await get(url, '/api/governance', ADMIN, { 'x-workspace': 'short-b' })).text();
      assert.ok(!everything.includes(probe) && !everything.includes('bob / x') && !everything.includes(`${PW} - x`), `absent: ${probe}`);
    }
  });
});

test('the two one-letter-password forms typed into every input of every endpoint (also with U+1680 and percent-encoded) come back in no answer, no follow-up state and no process output', async () => {
  const cap = capture();
  try {
    await withServer(async (url) => {
      const id = (await (await create(url, { name: 'seed' }, 'default')).json()).result.entryId;
      let n = 0;
      for (const base of [SHORT1, SHORT2]) for (const typed of [base, base.replaceAll(' ', OGHAM), encodeURIComponent(base), encodeURIComponent(encodeURIComponent(base))]) {
        n += 1;
        const texts = await sweepAll(url, typed, id);
        const hit = texts.filter((t) => t.includes(typed) || t.includes(base) || t.includes('bob / x') || t.includes('bob / x'));
        assert.deepEqual(hit.map((t) => t.slice(0, 160)), [], `${JSON.stringify(typed)} came back`);
        for (const who of [U1, ADMIN]) for (const p of ['/api/state?mode=live', '/api/governance', '/api/vault/entries', '/api/stores/secrets']) { const t = await (await get(url, p, who)).text(); assert.ok(!t.includes('bob / x') && !t.includes(`${PW} - x`), `${p} as ${who}`); }
      }
      assert.equal(n, 8);
    });
  } finally { cap.stop(); }
  const logged = cap.out.join(''); for (const n of ['bob / x', `${PW} - x`]) { const i = logged.indexOf(n); assert.ok(i < 0, JSON.stringify(logged.slice(Math.max(0, i - 200), i + 100))); }
});

test('path ids: a typed id on every entry, target and grant route is refused with a fixed code and shown MASKED in the hop pane, whatever its shape', async () => {
  await withServer(async (url) => {
    for (const probe of [SHORT1, SHORT2, `${PW}${OGHAM}${V1}`]) {
      const seg = encodeURIComponent(probe);
      const calls = [
        ['PUT', `/api/vault/entries/${seg}`, live({ entry: { notes: 'x' } }), U1], ['POST', `/api/vault/entries/${seg}/delete`, live({}), U1], ['POST', `/api/vault/entries/${seg}/restore`, live({}), U1],
        ['POST', `/api/targets/${seg}/remove`, live({}), ADMIN], ['POST', `/api/policies/${seg}/revoke`, live({}), ADMIN],
      ];
      for (const [m, p, b, who] of calls) {
        const r = await (m === 'PUT' ? put : post)(url, p, b, who, { 'x-workspace': 'pathid' }); const t = await r.text();
        assert.ok(r.status >= 400 && r.status < 500, `${m} ${p.slice(0, 30)}: ${r.status}`);
        assert.ok(!t.includes(probe) && !t.includes('bob / x') && !t.includes(`${PW} - x`) && !t.includes(V1) && !t.includes(OGHAM), `${m} ${probe}: ${t.slice(0, 160)}`);
        assert.ok(t.includes('"id":"[masked:'), `the hop pane shows the id masked: ${t.slice(0, 200)}`);
      }
      const g = await get(url, `/api/vault/entries/${seg}`, U1, { 'x-workspace': 'pathid' }); const gt = await g.text();
      assert.equal(g.status, 404); assert.ok(!gt.includes(probe) && !gt.includes('bob / x'), gt);
      const after = await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'pathid' })).text() + await (await get(url, '/api/governance', ADMIN, { 'x-workspace': 'pathid' })).text();
      assert.ok(!after.includes('bob / x') && !after.includes(`${PW} - x`) && !after.includes(V1), 'state afterwards');
    }
  });
});

test('entry ids: vcr-NNNN comes from ONE counter per workspace and vertical (all roster users of a workspace share it); a new workspace starts again at vcr-0001, another vertical too', async () => {
  await withServer(async (url) => {
    const id = async (ws, who, vertical = 'finance') => (await (await post(url, '/api/vault/entries', live({ vertical, entry: { name: 'n', targetId: TARGET, shape: 'bearer', generate: true } }), who, { 'x-workspace': ws })).json()).result?.entryId;
    assert.equal(await id('count-a', U1), 'vcr-0001'); assert.equal(await id('count-a', U1), 'vcr-0002');
    assert.equal(await id('count-a', U2), 'vcr-0003', 'the counter is shared by the users of one workspace');
    assert.equal(await id('count-b', U1), 'vcr-0001', 'another workspace starts again'); assert.equal(await id('count-b', U2), 'vcr-0002');
    assert.equal(await id('count-c', U1), 'vcr-0001');
    const health = await post(url, '/api/vault/entries', live({ vertical: 'health', entry: { name: 'n', targetId: C.castT1, shape: 'bearer', generate: true } }), U1, { 'x-workspace': 'count-a' });
    assert.notEqual(health.status, 500); // the health pack has its own cast: a finance target id is refused there, and no id is spent
  });
});

test('vault secret values stay unechoed: a value typed into a secret field is write-only in the answer, the hop panes, the state, the audit and the log', async () => {
  const cap = capture(); const VAL = ['zeta-', 'bearer-', 'value-4471'].join('');
  try {
    await withServer(async (url) => {
      const r = await post(url, '/api/vault/entries', live({ entry: { name: 'v', targetId: TARGET, shape: 'bearer', secret: { token: VAL } } }), U1, { 'x-workspace': 'wo' });
      const t = await r.text(); assert.equal(r.status, 200); assert.ok(!t.includes(VAL) && t.includes('(write-only, 22 bytes)'), t.slice(0, 200));
      const id = JSON.parse(t).result.entryId;
      const all = [t, await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'wo' })).text(), await (await get(url, `/api/vault/entries/${id}`, U1, { 'x-workspace': 'wo' })).text(), await (await get(url, '/api/governance', ADMIN, { 'x-workspace': 'wo' })).text()].join('');
      assert.ok(!all.includes(VAL));
      const bad = await post(url, '/api/vault/entries', live({ entry: { name: 'v', targetId: TARGET, shape: 'bearer', secret: { token: VAL, extra: VAL } } }), U1, { 'x-workspace': 'wo' });
      assert.ok(!(await bad.text()).includes(VAL), 'a refused request does not echo the value either');
    });
  } finally { cap.stop(); }
  assert.ok(!cap.out.join('').includes(VAL), 'nothing was logged');
});
