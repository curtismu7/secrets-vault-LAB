// A credential the visitor types must come back in NO response field, hop pane, audit entry, log line or error: tested by typing every credential shape
// into every place a request can carry text (names, notes, paths, tags, ids, query strings, headers, unknown keys, and the secret fields themselves) on every
// endpoint, and searching every answer, the state afterwards and the process output for it. Masking is a heuristic and the page says so.
import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, ADMIN, get, post, put, live, withServer } from './helpers.js';
import { SECRETS } from './secrets.js';
import { HIDDEN } from './hidden.js';

const NEEDLES = Object.fromEntries(Object.entries(SECRETS).map(([k, v]) => [k, { raw: v, probe: k === 'pem' ? 'MIIEvQIBADANBgkqhkiG9w0BAQEFAASC' : k === 'bearer' ? 'tokenvalue' : k === 'assignment' ? 'hunter2hunter2' : k === 'plainIs' ? 'hunter2xyz' : k === 'pwColon' ? 'Hunter2Secret' : k === 'passEq' ? 'Tr0ub4dor' : k === 'passphrase' ? 'correct horse' : k === 'userinfo' ? 'hunter2@' : k === 'tokenWord' ? 'abcdef1234567890zz' : k === 'accountKey' ? 'abcdEFGH' : k === 'sessionId' ? '00D5g000008dkQz' : v }]));
const W = (id) => ({ 'x-workspace': id });
const AWS = `aws:${C.castAwsPrefix}/db-admin`;

test('typing every credential shape into every field of every endpoint never echoes it (secret fields included: write-only)', async () => {
  const out = []; const realOut = process.stdout.write.bind(process.stdout); const realErr = process.stderr.write.bind(process.stderr);
  await withServer(async (url) => {
    const mk = await post(url, '/api/vault/entries', live({ entry: { name: 'seed', targetId: C.castT1, shape: 'bearer', generate: true } }), U1);
    const id = (await mk.json()).result.entryId;
    const sweep = async (v) => {
      const bodies = [
        [U1, 'POST', '/api/vault/entries', live({ entry: { name: v, targetId: v, shape: v, notes: v, headerName: v, secret: v } })],
        [U1, 'POST', '/api/vault/entries', live({ entry: { name: `n ${v}`, targetId: C.castT1, shape: 'bearer', notes: `see ${v} here`, secret: { token: v } } })],
        [U1, 'POST', '/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT3, shape: 'basic', secret: { username: v, password: v } } })],
        [U1, 'POST', '/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT4, shape: 'headers', secret: { headers: { [v]: v, 'X-Ok': v } } } })],
        [U1, 'POST', '/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true, [v]: v } })],
        [U1, 'PUT', `/api/vault/entries/${id}`, live({ entry: { name: v, notes: v, secret: { token: v }, [v]: v } })],
        [U1, 'PUT', `/api/vault/entries/${encodeURIComponent(v)}`, live({ entry: { notes: v } })],
        [U1, 'POST', `/api/vault/entries/${encodeURIComponent(v)}/delete`, live({})], [U1, 'POST', `/api/vault/entries/${encodeURIComponent(v)}/restore`, live({ [v]: v })],
        [U1, 'POST', '/api/gateway/call', live({ call: { targetId: v, as: v, entryId: v, operation: v, [v]: v } })],
        [U1, 'POST', '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: v } })],
        [ADMIN, 'POST', '/api/vault/keys', live({ key: { configured: v, reachable: v, [v]: v } })],
        [ADMIN, 'POST', '/api/targets', live({ target: { id: v, accepts: v, protocol: v, [v]: v } })],
        [ADMIN, 'POST', `/api/targets/${encodeURIComponent(v)}/remove`, live({})],
        [U1, 'POST', '/api/stores/secrets', live({ secret: { provider: v, path: v, template: v, tags: [v], fields: { [v]: v, value: v } } })],
        [ADMIN, 'POST', '/api/stores/secrets', live({ secret: { provider: 'aws', path: `prod/x/${v}`, tags: [v], fields: { value: v } } })],
        [ADMIN, 'POST', '/api/stores/secrets', live({ secret: { provider: 'aws', path: 'prod/echo/one', fields: { value: v } } })],
        [U1, 'POST', '/api/stores/read', live({ read: { ref: v, consumer: v, [v]: v } })], [U1, 'POST', '/api/stores/read', live({ read: { ref: AWS, consumer: v } })],
        [U1, 'POST', '/api/stores/update', live({ update: { ref: v, fields: { [v]: v }, tags: [v] } })], [ADMIN, 'POST', '/api/stores/update', live({ update: { ref: 'aws:prod/echo/one', fields: { value: v }, tags: [v] } })],
        [U1, 'POST', '/api/stores/rotate', live({ ref: v })], [U1, 'POST', '/api/stores/delete', live({ ref: v })], [U1, 'POST', '/api/stores/recover', live({ ref: v })], [U1, 'POST', '/api/stores/purge', live({ ref: v })],
        [ADMIN, 'POST', '/api/stores/connection', live({ provider: v })],
        [ADMIN, 'POST', '/api/stores/provider-change', live({ change: { provider: v, op: v, ref: v, newPath: v, path: v } })],
        [ADMIN, 'POST', '/api/stores/provider-change', live({ change: { provider: 'aws', op: 'create', path: v } })],
        [ADMIN, 'POST', '/api/stores/resync', live({ [v]: v })],
        [ADMIN, 'POST', '/api/policies', live({ grant: { principal: v, scope: v, actions: [v], [v]: v } })], [ADMIN, 'POST', `/api/policies/${encodeURIComponent(v)}/revoke`, live({})],
        [U1, 'POST', '/api/clock', live({ clock: { minutes: v, [v]: v } })],
        [U1, 'POST', '/api/reset', { [v]: v }],
      ];
      const gets = [`/api/state?mode=${encodeURIComponent(v)}`, `/api/state?mode=live&vertical=${encodeURIComponent(v)}&scenario=${encodeURIComponent(v)}`, `/api/state?mode=mock&scenario=${encodeURIComponent(v)}`, `/api/state?mode=live&${encodeURIComponent(v)}=${encodeURIComponent(v)}`, `/api/story?vertical=${encodeURIComponent(v)}`, `/api/diagram?name=${encodeURIComponent(v)}&vertical=${encodeURIComponent(v)}`, `/api/vault/entries/${encodeURIComponent(v)}`, `/api/vault/entries?owner=${encodeURIComponent(v)}`, `/api/stores/secrets?x=${encodeURIComponent(v)}`, `/api/${encodeURIComponent(v)}`, `/api/health?x=${encodeURIComponent(v)}`];
      const texts = [];
      for (const [who, m, p, b] of bodies) { const r = await (m === 'PUT' ? put : post)(url, p, b, who); texts.push(`${m} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
      for (const g of gets) { const r = await get(url, g, U1); texts.push(`GET ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
      for (const hv of [v, `a ${v}`]) { const clean = hv.slice(0, 40).replace(/[^\x20-\x7e]/g, '?'); for (const h of [{ 'x-workspace': clean }, { 'x-lab-actor': clean }]) { const r = await get(url, '/api/state?mode=live', h['x-lab-actor'] ? clean : U1, h['x-workspace'] ? h : {}); texts.push(`H ${r.status} ${await r.text()}`); } }
      return texts;
    };
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
