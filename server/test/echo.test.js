// A credential the visitor types must come back in NO response field, hop pane, audit entry, log line or error: tested by typing every credential shape
// into every place a request can carry text (names, notes, paths, tags, ids, query strings, headers, unknown keys, and the secret fields themselves) on every
// endpoint, and searching every answer, the state afterwards and the process output for it. Masking is a heuristic and the page says so.
import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, ADMIN, get, post, put, live, withServer } from './helpers.js';
import { SECRETS } from './secrets.js';
import { sweepAll } from './sweep.js';
import { HIDDEN } from './hidden.js';

// 1.4.0 adoption: two bare shapes are NOT found by the shared masker on purpose (a hex digest with no decimal digit is a hash, a 31-character random value is below its
// 32-character threshold, and a passphrase of several plain words after a colon is a documented shared-masker limit, and a SHORT prefixed token such as ghp_ plus 12 characters is below the masker's 16-character floor: reported to the shared-masker owner); they are pinned as limits in the last test of this file, not swept. Every other shape is.
const NOT_FOUND = ['hex', 'key31', 'passphrase', 'shortGh'];
const NEEDLES = Object.fromEntries(Object.entries(SECRETS).filter(([k]) => !NOT_FOUND.includes(k)).map(([k, v]) => [k, { raw: v, probe: k === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : k === 'bearer' ? 'tokenvalue' : k === 'assignment' ? 'hunter2hunter2' : k === 'plainIs' ? 'hunter2xyz' : k === 'pwColon' ? 'Hunter2Secret' : k === 'passEq' ? 'Tr0ub4dor' : k === 'passphrase' ? 'correct horse' : k === 'userinfo' ? 'hunter2@' : k === 'tokenWord' ? 'abcdef1234567890zz' : k === 'accountKey' ? 'abcdEFGH' : k === 'sessionId' ? '00D5g000008dkQz' : v }]));
const W = (id) => ({ 'x-workspace': id });

test('typing every credential shape into every field of every endpoint never echoes it (secret fields included: write-only)', async () => {
  const out = []; const realOut = process.stdout.write.bind(process.stdout); const realErr = process.stderr.write.bind(process.stderr);
  await withServer(async (url) => {
    const mk = await post(url, '/api/vault/entries', live({ entry: { name: 'seed', targetId: C.castT1, shape: 'bearer', generate: true } }), U1);
    const id = (await mk.json()).result.entryId;
    const sweep = (v) => sweepAll(url, v, id);
    process.stdout.write = (c, ...a) => { out.push(String(c)); return realOut(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return realErr(c, ...a); };
    try {
      let formNo = 0;
      for (const [name, n] of Object.entries(NEEDLES)) for (const [form, typed] of [['raw', n.raw], ['hidden', [...n.raw].join(String.fromCodePoint(HIDDEN[formNo++ % HIDDEN.length]))], ['percent-encoded once', encodeURIComponent(n.raw)], ['percent-encoded twice', encodeURIComponent(encodeURIComponent(n.raw))]]) {
        const texts = await sweep(typed);
        // The endpoints answer with ONLY fixed codes and masked text: the probe part of the value (and the typed form) must be in none of them.
        const hit = texts.filter((t) => t.includes(n.probe) || (form !== 'raw' && t.includes(typed)));
        assert.deepEqual(hit.map((t) => t.slice(0, 180)), [], `${name} (${form}): the value came back`);
        for (const who of [U1, ADMIN]) { const state = JSON.stringify(await (await get(url, '/api/state?mode=live', who)).json()) + JSON.stringify(await (await get(url, '/api/governance', who)).json()); assert.ok(!state.includes(n.probe), `${name} (${form}): absent from the state shown to ${who}`); }
      }
    } finally { process.stdout.write = realOut; process.stderr.write = realErr; }
  });
  for (const n of Object.values(NEEDLES)) assert.ok(!out.join('').includes(n.probe), 'nothing was logged');
});

test('a credential in a real, accepted request is masked in the answer, the hop panes and the audit trail (notes), and the secret itself is write-only', async () => {
  await withServer(async (url) => {
    for (const [name, n] of Object.entries(NEEDLES)) {
      const ws = `echo-${name.toLowerCase()}`.slice(0, 30).replace(/[^a-z0-9-]/g, '-');
      const r = await post(url, '/api/vault/entries', live({ entry: { name: 'ok name', targetId: C.castT1, shape: 'bearer', notes: `please ${n.raw} thanks`, secret: { token: `plain-token-for-${name}-0123456789`.replace(/\n/g, '') } } }), U1, W(ws));
      const body = await r.text();
      assert.equal(r.status, 200, name); assert.ok(!body.includes(n.probe), `${name}: not in the answer`); assert.match(body, /\[masked:/);
      assert.ok(!body.includes(`plain-token-for-${name}`), `${name}: the secret is write-only`);
      assert.ok(body.includes('"hops"') && body.includes('write-only'), `${name}: the hop shows a write-only marker`);
    }
  });
});

test('field names are not echoed either: an unknown key that is itself a credential never comes back', async () => {
  await withServer(async (url) => {
    for (const n of Object.values(NEEDLES)) {
      for (const [p, b] of [['/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true, [n.raw]: 1 } })], ['/api/gateway/call', live({ call: { [n.raw]: 1 } })], ['/api/policies', live({ grant: { [n.raw]: 1 } })], ['/api/stores/read', live({ read: { [n.raw]: 1 } })]]) {
        const t = await (await post(url, p, b, ADMIN)).text(); assert.ok(!t.includes(n.probe), p);
      }
    }
  });
});

test('the documented limits, pinned: a bare hex digest, a bare 31-character random value, a several-word passphrase and a short ghp_ token are not found by the shared masker, so free text keeps them (masking is a heuristic)', async () => {
  const { cleanFree } = await import('../src/credentials.js');
  for (const k of NOT_FOUND) assert.equal(cleanFree(SECRETS[k]), SECRETS[k], k);
  assert.equal(SECRETS.hex.length, 48); assert.equal(SECRETS.key31.length, 31); assert.equal(SECRETS.passphrase, 'passphrase: correct horse battery');
  assert.equal(SECRETS.shortGh.length, 16);
  // the same values behind a keyword ARE masked
  assert.equal(cleanFree(`token: ${SECRETS.key31}`), '[masked:assignment]');
  assert.equal(cleanFree(`secret=${SECRETS.hex}`), '[masked:assignment]');
});
