// Static files and methods: a missing file is a JSON 404 (never the app shell with a 200), the page fallback serves only extension-less non-dotfile GETs, Express's
// default HTML answers ("Cannot POST /<path>", which echoes the path) never appear, and a wrong method on a known route is a 405 with Allow.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { U1, get, post, live, rawHttp, withServer } from './helpers.js';

function webDist() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'svl-web-'));
  fs.mkdirSync(path.join(dir, 'assets'));
  fs.writeFileSync(path.join(dir, 'index.html'), '<!doctype html><title>shell</title><div id="root"></div>');
  fs.writeFileSync(path.join(dir, 'assets', 'app.js'), 'console.log(1)');
  fs.writeFileSync(path.join(dir, '.secret'), 'dotfile');
  return dir;
}
const isJson404 = async (r, label) => {
  const t = await r.text();
  assert.equal(r.status, 404, `${label}: ${r.status}`); assert.match(r.headers.get('content-type'), /^application\/json/, label); assert.equal(t, '{"error":"not_found"}', label);
};

test('E: a missing file is a JSON 404, never a 200 text/html page', async () => {
  const dist = webDist();
  try {
    await withServer(async (url) => {
      for (const p of ['/assets/missing.js', '/favicon.ico', '/robots.txt', '/foo.map', '/foo.svg', '/sitemap.xml', '/assets/', '/assets', '/assets/missing', '/Assets/missing', '/.env', '/.git/config', '/.secret', '/a/.hidden/b', '/foo%2Ejs', '/foo%2Emap', '/a.b/c.d', '/index.html.bak', '/assets/app.js/extra']) {
        await isJson404(await rawHttp(`${url}${p}`).then((r) => new Response(r.text, { status: r.status, headers: { 'content-type': r.headers['content-type'] } })), `GET ${p}`);
      }
      const head = await fetch(`${url}/favicon.ico`, { method: 'HEAD' }); assert.equal(head.status, 404);
    }, { webDist: dist });
  } finally { fs.rmSync(dist, { recursive: true, force: true }); }
});

test('E: the page shell answers only extension-less non-dotfile GET paths; real files are served as files', async () => {
  const dist = webDist();
  try {
    await withServer(async (url) => {
      for (const p of ['/', '/vault', '/stores/secrets', '/a/b/c', '/vault/']) {
        // 1.4.0 adoption: the page shell goes to a client that ACCEPTS text/html (a browser); the old test sent no Accept header
        const r = await fetch(`${url}${p}`, { headers: { accept: 'text/html' } }); const t = await r.text();
        assert.equal(r.status, 200, p); assert.match(r.headers.get('content-type'), /^text\/html/); assert.ok(t.includes('<title>shell</title>'));
      }
      for (const p of ['/', '/vault']) await isJson404(await fetch(`${url}${p}`, { headers: { accept: 'application/json' } }), `GET ${p} without text/html`);
      assert.equal((await fetch(`${url}/vault`, { method: 'HEAD', headers: { accept: 'text/html' } })).status, 200, 'HEAD too');
      const js = await fetch(`${url}/assets/app.js`); assert.equal(js.status, 200); assert.match(js.headers.get('content-type'), /javascript/); assert.equal(await js.text(), 'console.log(1)');
      const idx = await fetch(`${url}/index.html`); assert.equal(idx.status, 200);
    }, { webDist: dist });
  } finally { fs.rmSync(dist, { recursive: true, force: true }); }
});

test('E: without a built page, every non-API path is a JSON 404 too', async () => {
  await withServer(async (url) => {
    for (const p of ['/', '/vault', '/favicon.ico', '/assets/x.js']) await isJson404(await fetch(`${url}${p}`), p);
  }, { webDist: path.join(os.tmpdir(), 'svl-no-such-web-dist') });
});

test('E: a malformed escape, an invalid JSON body and an oversized body are fixed JSON, never Express\'s HTML', async () => {
  const dist = webDist();
  try {
    await withServer(async (url) => {
      for (const p of ['/%E0%A4%A', '/api/%E0%A4%A', '/api/vault/entries/%E0%A4%A', '/assets/%E0%A4%A']) {
        const r = await rawHttp(`${url}${p}`); assert.match(r.headers['content-type'], /^application\/json/, p); assert.ok(r.status >= 400 && r.status < 500, `${p}: ${r.status}`); assert.ok(!r.text.includes('<'), p); assert.ok(!r.text.includes('Cannot') && !r.text.includes('%E0'), p);
      }
      const bad = await fetch(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url, 'x-lab-actor': U1 }, body: '{"clock": hunter2xyz' });
      assert.equal(bad.status, 400); assert.equal(await bad.text(), '{"error":"bad_request"}');
      const big = await fetch(`${url}/api/clock`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url, 'x-lab-actor': U1 }, body: JSON.stringify({ pad: 'x'.repeat(300_000) }) });
      assert.equal(big.status, 413); assert.equal(await big.text(), '{"error":"payload_too_large"}');
    }, { webDist: dist });
  } finally { fs.rmSync(dist, { recursive: true, force: true }); }
});

test('E: an unknown method or path never gets the default "Cannot POST /path" page, and the path is never echoed', async () => {
  const dist = webDist();
  try {
    await withServer(async (url) => {
      const probe = 'hunter2xyz-not-a-route';
      for (const [m, p] of [['POST', `/${probe}`], ['PUT', `/${probe}/x`], ['DELETE', `/${probe}`], ['PATCH', '/vault'], ['POST', '/vault/entries'], ['OPTIONS', `/${probe}`], ['POST', `/api/${probe}`], ['DELETE', `/api/${probe}/x/y`], ['TRACE', '/vault']]) {
        const r = await rawHttp(`${url}${p}`, { method: m, headers: { 'content-type': 'application/json', origin: url } });
        assert.ok([404, 405].includes(r.status), `${m} ${p}: ${r.status}`); assert.match(r.headers['content-type'] || '', /^application\/json/, `${m} ${p}`);
        assert.ok(!r.text.includes(probe) && !r.text.includes('Cannot') && !r.text.includes('<'), `${m} ${p}: ${r.text}`);
      }
    }, { webDist: dist });
  } finally { fs.rmSync(dist, { recursive: true, force: true }); }
});

const ROUTES = [
  // [method used wrongly, path, Allow]
  ['POST', '/api/story', 'GET, HEAD'], ['POST', '/api/diagram', 'GET, HEAD'], ['POST', '/api/info', 'GET, HEAD'], ['POST', '/api/state', 'GET, HEAD'], ['DELETE', '/api/state', 'GET, HEAD'],
  ['POST', '/api/vault/entries/vcr-0001', 'GET, HEAD, PUT'], ['DELETE', '/api/vault/entries/vcr-0001', 'GET, HEAD, PUT'], ['PUT', '/api/vault/entries', 'GET, HEAD, POST'], ['PATCH', '/api/vault/entries', 'GET, HEAD, POST'],
  ['GET', '/api/vault/entries/vcr-0001/delete', 'POST'], ['GET', '/api/vault/entries/vcr-0001/restore', 'POST'], ['PUT', '/api/vault/entries/vcr-0001/delete', 'POST'],
  ['GET', '/api/gateway/call', 'POST'], ['GET', '/api/vault/keys', 'POST'], ['GET', '/api/targets', 'POST'], ['GET', '/api/targets/x-y/remove', 'POST'],
  ['POST', '/api/stores/secrets', null], ['PUT', '/api/stores/secrets', 'GET, HEAD, POST'], ['GET', '/api/stores/read', 'POST'], ['GET', '/api/stores/update', 'POST'],
  ['GET', '/api/stores/rotate', 'POST'], ['GET', '/api/stores/delete', 'POST'], ['GET', '/api/stores/recover', 'POST'], ['GET', '/api/stores/purge', 'POST'],
  ['GET', '/api/stores/connection', 'POST'], ['GET', '/api/stores/provider-change', 'POST'], ['GET', '/api/stores/resync', 'POST'], ['GET', '/api/policies', 'POST'], ['GET', '/api/policies/x/revoke', 'POST'],
  ['GET', '/api/clock', 'POST'], ['GET', '/api/proof/run', 'POST'], ['GET', '/api/reset', 'POST'], ['PUT', '/api/governance', 'GET, HEAD'], ['DELETE', '/api/health', 'GET, HEAD'], // 1.4.0 adoption: the route table adds HEAD wherever GET is (was 'GET')
 
];
test('E: a wrong method on a known API route is a 405 with Allow (literal table of 34 routes); a right method is not', async () => {
  assert.equal(ROUTES.length, 34);
  await withServer(async (url) => {
    for (const [m, p, allow] of ROUTES) {
      if (allow === null) continue; // POST /api/stores/secrets is a real route (checked below)
      const r = await fetch(`${url}${p}`, { method: m, headers: { 'content-type': 'application/json', origin: url, 'x-lab-actor': U1 }, ...(m === 'GET' || m === 'HEAD' ? {} : { body: '{}' }) });
      const t = await r.text();
      assert.equal(r.status, 405, `${m} ${p}: ${r.status} ${t}`); assert.equal(r.headers.get('allow'), allow, `${m} ${p}`); assert.equal(t, p.startsWith('/api/health') ? '{"error":"method_not_allowed"}' : '{"error":"method_not_allowed"}');
    }
    assert.notEqual((await post(url, '/api/stores/secrets', live({ secret: {} }), U1)).status, 405);
    assert.notEqual((await get(url, '/api/state?mode=mock', U1)).status, 405);
    assert.deepEqual(await (await get(url, '/api/not-a-route', U1)).json(), { error: 'not_found' });
    assert.equal((await fetch(`${url}/api/state/extra`, { headers: { 'x-lab-actor': U1 } })).status, 404, 'a longer path is not the known route');
  });
});

test('E: with the page built, POST / is a 405 with Allow GET, HEAD', async () => {
  const dist = webDist();
  try {
    await withServer(async (url) => {
      const r = await fetch(`${url}/`, { method: 'POST', headers: { origin: url }, body: '{}' });
      assert.equal(r.status, 405); assert.equal(r.headers.get('allow'), 'GET, HEAD'); assert.equal(await r.text(), '{"error":"method_not_allowed"}');
    }, { webDist: dist });
  } finally { fs.rmSync(dist, { recursive: true, force: true }); }
});
