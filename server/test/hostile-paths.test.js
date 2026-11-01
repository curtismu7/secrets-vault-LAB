// A credential typed into a URL path must never come back, whatever the method, whether or not the web build exists, and whatever the answer.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { rawHttp, withServer, get, post } from './helpers.js';
import { SECRETS } from './secrets.js';

const PATHS = (v) => [`/${v}`, `/api/${v}`, `/api/vault/entries/${v}`, `/api/vault/entries/${v}/delete`, `/${v}/x/${v}`, `/static/${v}.js`, `/api/policies/${v}/revoke`, `/api/targets/${v}/remove`];
const METHODS = ['GET', 'POST', 'PUT', 'DELETE', 'PATCH', 'HEAD', 'OPTIONS'];

async function sweep(url) {
  const host = new URL(url).host;
  for (const [name, v] of Object.entries(SECRETS)) {
    if (/\s|\n|[?#]/.test(v)) continue; // a path segment cannot carry a space, a newline or a query separator
    const seg = encodeURIComponent(v);
    for (const method of METHODS) for (const p of PATHS(seg)) {
      const r = await rawHttp(`${url}${p}`, { method, headers: { host, origin: url, 'content-type': 'application/json' }, body: ['POST', 'PUT', 'PATCH'].includes(method) ? '{}' : undefined });
      const needle = v.length > 12 ? v.slice(4, 16) : v;
      assert.ok(!r.text.includes(needle) && !r.text.includes(seg.slice(4, 16)), `${name} ${method} ${p.slice(0, 30)}: the path came back: ${r.text.slice(0, 80)}`);
      assert.ok(!/Cannot (GET|POST|PUT|DELETE|PATCH)|<pre>|node_modules|at .*\(/.test(r.text), `${name} ${method}: a default Express page: ${r.text.slice(0, 80)}`);
    }
  }
}

test('S2: no method on any token-shaped path echoes it, with the web build present (the fallback serves the page, everything else is JSON)', async () => {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'svl-dist-')); fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>x</title>');
  try { await withServer(sweep, { webDist: dist }); } finally { fs.rmSync(dist, { recursive: true, force: true }); }
});

test('S2: ...and with no web build at all (a fresh clone before npm run build)', async () => {
  await withServer(sweep, { webDist: '/nonexistent/dist' });
});

test('S2: a non-API path answers fixed JSON 404 for every method but GET (GET serves the page when it exists)', async () => {
  const dist = fs.mkdtempSync(path.join(os.tmpdir(), 'svl-dist-')); fs.writeFileSync(path.join(dist, 'index.html'), '<!doctype html><title>x</title>');
  try {
    await withServer(async (url) => {
      const host = new URL(url).host;
      for (const m of ['POST', 'PUT', 'DELETE', 'PATCH']) { const r = await rawHttp(`${url}/anything/at/all`, { method: m, headers: { host, origin: url } }); assert.equal(r.status, 404); assert.deepEqual(JSON.parse(r.text), { error: 'not_found' }, m); }
      assert.equal((await rawHttp(`${url}/anything`, { headers: { host } })).status, 200);
    }, { webDist: dist });
  } finally { fs.rmSync(dist, { recursive: true, force: true }); }
  await withServer(async (url) => { const r = await rawHttp(`${url}/anything`, { headers: { host: new URL(url).host } }); assert.equal(r.status, 404); assert.deepEqual(JSON.parse(r.text), { error: 'not_found' }); }, { webDist: '/nonexistent/dist' });
});

test('S2: a workspace id that looks like a credential is refused, never echoed in the answer or in a hop header', async () => {
  await withServer(async (url) => {
    const hex40 = 'a3f9c2e17b4d58a6f0c1e9d27b3a45c8e6f1d097';
    for (const id of [hex40, hex40.slice(0, 32), `w-${hex40}`.slice(0, 40), ['glpat', '-abcdefghijklmnop1234'].join(''), ['sk', '-abcdefghijklmnop1234'].join('')]) {
      const r = await get(url, '/api/state?mode=live', undefined, { 'x-workspace': id }); const t = await r.text();
      assert.equal(r.status, 400, id); assert.ok(!t.includes(id.slice(0, 20)), id);
      const w = await post(url, '/api/vault/entries', { mode: 'live', entry: { name: 'x', targetId: 'ledger-api', shape: 'bearer', generate: true } }, undefined, { 'x-workspace': id });
      assert.equal(w.status, 400); assert.ok(!(await w.text()).includes(id.slice(0, 20)));
    }
    // the ids the page makes itself, and ordinary names, still work and are echoed
    for (const id of ['w-0123456789abcdef', 'default', 'ws-a', 'parity-warehouse-role']) {
      const r = await post(url, '/api/vault/entries', { mode: 'live', entry: { name: 'x', targetId: 'ledger-api', shape: 'bearer', generate: true } }, 'maya.chen', { 'x-workspace': id });
      assert.equal(r.status, 200, id); const b = await r.json(); assert.equal(b.workspace, id); assert.equal(b.hops[0].request.headers['x-workspace'], id);
    }
  });
});

test('S9: an unknown key name at ANY depth is never shown in the hop pane: it is replaced by "(unrecognised key N)", known keys stay', async () => {
  const { scrub } = await import('../src/service.js');
  const odd = 'Zq81xkZq81xkQ9';
  const out = scrub({ entry: { name: 'x', [odd]: 'v', deeper: { [odd + '2']: { [odd + '3']: 1 } } }, [odd + '4']: 1, call: { targetId: 'a', [odd + '5']: 2 } });
  const t = JSON.stringify(out);
  assert.ok(!t.includes('Zq81xk'), t); assert.ok(t.includes('(unrecognised key 1)') && t.includes('"name":"x"') && t.includes('"targetId":"a"'));
  assert.deepEqual(Object.keys(scrub({ a1: 1, b2: 2 })), ['(unrecognised key 1)', '(unrecognised key 2)']);
  await withServer(async (url) => {
    const r = await post(url, '/api/vault/entries', { mode: 'live', vertical: 'finance', entry: { name: 'x', targetId: 'ledger-api', shape: 'bearer', generate: true, [odd]: 1 } });
    const text = await r.text(); assert.equal(r.status, 400); assert.ok(!text.includes('Zq81xk'), text.slice(0, 300)); assert.ok(text.includes('(unrecognised key 1)'));
  });
});
