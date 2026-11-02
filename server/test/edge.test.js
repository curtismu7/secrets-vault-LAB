// The HTTP edge (step B of the shared-masker 1.4.0 adoption, docs/EXPRESS-RECIPE.md): 415 for a charset problem with a fixed body and nothing logged, the final JSON 404
// and the catch-all error handler that never echo what was typed, 405 with Allow from the route table, the page shell only for page addresses, the workspace-id middleware
// that refuses a credential-looking id before any slot exists. Expected strings and counts are LITERALS.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { U1, ADMIN, get, post, live, rawHttp, withServer } from './helpers.js';

const hunter = ['hunter', '2xyz'].join('');
const capture = () => {
  const out = []; const wo = process.stdout.write.bind(process.stdout); const we = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c, ...a) => { out.push(String(c)); return wo(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return we(c, ...a); };
  return { out, stop: () => { process.stdout.write = wo; process.stderr.write = we; } };
};
const dist = () => { const d = fs.mkdtempSync(path.join(os.tmpdir(), 'svl-edge-')); fs.mkdirSync(path.join(d, 'assets')); fs.writeFileSync(path.join(d, 'index.html'), '<!doctype html><title>shell</title>'); fs.writeFileSync(path.join(d, 'assets', 'a.js'), 'x'); return d; };

test('a charset other than utf-8 is a 415 with the fixed body {"error":"unsupported_charset"} on every route and method, the value is never echoed or logged', async () => {
  const cap = capture(); const bad = [`application/json; charset=utf-16`, `application/json; charset=${hunter}`, `application/json; charset="latin1"`, `text/plain;charset=iso-8859-1`, `application/json; charset=utf-8; charset=utf-16`, `application/json; charset`];
  try {
    await withServer(async (url) => {
      let n = 0;
      for (const ct of bad) for (const [m, p] of [['POST', '/api/clock'], ['GET', '/api/state?mode=live'], ['GET', '/api/health'], ['POST', '/api/reset'], ['PUT', '/api/vault/entries/vcr-0001'], ['GET', '/anything'], ['DELETE', '/api/nope']]) {
        const r = await rawHttp(`${url}${p}`, { method: m, headers: { host: new URL(url).host, origin: url, 'content-type': ct, 'x-lab-actor': U1 }, body: m === 'GET' || m === 'DELETE' ? undefined : '{}' });
        n += 1;
        assert.equal(r.status, 415, `${m} ${p} ${ct}`); assert.equal(r.text, '{"error":"unsupported_charset"}', `${m} ${p}`); assert.match(r.headers['content-type'], /^application\/json/);
      }
      assert.equal(n, 42);
      // utf-8 in any case and quoting is fine
      for (const ct of ['application/json; charset=utf-8', 'application/json; charset=UTF-8', 'application/json; charset="utf-8"', 'application/json']) {
        const r = await rawHttp(`${url}/api/clock`, { method: 'POST', headers: { host: new URL(url).host, origin: url, 'content-type': ct, 'x-lab-actor': U1 }, body: JSON.stringify(live({ clock: { minutes: 1 } })) });
        assert.equal(r.status, 200, ct);
      }
    });
  } finally { cap.stop(); }
  assert.ok(!cap.out.join('').includes(hunter) && !cap.out.join('').includes('utf-16'), 'nothing typed was logged');
});

test('the final JSON 404 and the catch-all error handler echo nothing: an unknown path, a bad body and an oversized body give fixed codes and print nothing', async () => {
  const cap = capture(); const d = dist();
  try {
    await withServer(async (url) => {
      const host = new URL(url).host;
      for (const p of [`/api/${hunter}`, `/api/vault/${hunter}`, `/api/vault/entries/${hunter}/nope`, `/${hunter}.js`, `/assets/${hunter}`, '/assets', '/assets/', '/api/state/x', '/%zz', '/api/%zz']) {
        const r = await rawHttp(`${url}${p}`, { headers: { host, accept: 'text/html' } });
        assert.equal(r.status, 404, p); assert.equal(r.text, '{"error":"not_found"}', p);
      }
      const bad = await rawHttp(`${url}/api/clock`, { method: 'POST', headers: { host, origin: url, 'content-type': 'application/json' }, body: `{"clock": ${hunter}` });
      assert.equal(bad.status, 400); assert.equal(bad.text, '{"error":"bad_request"}');
      const big = await rawHttp(`${url}/api/clock`, { method: 'POST', headers: { host, origin: url, 'content-type': 'application/json' }, body: JSON.stringify({ pad: 'x'.repeat(300_000) }) });
      assert.equal(big.status, 413); assert.equal(big.text, '{"error":"payload_too_large"}');
    }, { webDist: d });
  } finally { cap.stop(); fs.rmSync(d, { recursive: true, force: true }); }
  assert.ok(!cap.out.join('').includes(hunter), 'nothing typed was logged');
});

test('the page shell is for page addresses only: /assets and /assets/ are JSON 404, a dotfile or an extension is, and a client that does not accept text/html gets JSON', async () => {
  const d = dist();
  try {
    await withServer(async (url) => {
      const host = new URL(url).host; const html = { host, accept: 'text/html,application/xhtml+xml' };
      for (const p of ['/', '/vault', '/vault/', '/stores/secrets', '/a/b/c']) { const r = await rawHttp(`${url}${p}`, { headers: html }); assert.equal(r.status, 200, p); assert.ok(r.text.includes('<title>shell</title>'), p); }
      for (const p of ['/assets', '/assets/', '/ASSETS/', '/assets/missing', '/static/x', '/api', '/favicon.ico', '/robots.txt', '/x.map', '/.env', '/.git/config', '/a//b', '/%2541']) { const r = await rawHttp(`${url}${p}`, { headers: html }); assert.equal(r.status, 404, p); assert.equal(r.text, '{"error":"not_found"}', p); }
      assert.equal((await rawHttp(`${url}/vault`, { headers: { host, accept: 'application/json' } })).status, 404);
      assert.equal((await rawHttp(`${url}/vault`, { headers: { host } })).status, 404, 'no Accept header at all');
      assert.equal((await rawHttp(`${url}/assets/a.js`, { headers: { host } })).status, 200, 'a real file is served as a file');
      const post1 = await rawHttp(`${url}/vault`, { method: 'POST', headers: { ...html, origin: url }, body: '{}' }); assert.equal(post1.status, 404);
    }, { webDist: d });
  } finally { fs.rmSync(d, { recursive: true, force: true }); }
});

test('the workspace-id middleware refuses a credential-looking id with 400 bad_workspace on EVERY route that takes a workspace, before any slot exists; info routes take none', async () => {
  const ids = [['pw', hunter].join('-'), ['sk', 'abcdefghijklmnop1234'].join('-'), 'deadbeef'.repeat(4), '123456789012', 'UPPER-case', 'has space', 'a'.repeat(41), ['xoxb', '1234'].join('-')];
  await withServer(async (url, { workspaces }) => {
    let n = 0;
    for (const id of ids) {
      const h = { 'x-workspace': id };
      const reads = ['/api/state?mode=live', '/api/vault/entries', '/api/vault/entries/vcr-0001', '/api/stores/secrets', '/api/governance'];
      const writes = [['/api/vault/entries', live({ entry: { name: 'x', targetId: 'ledger-api', shape: 'bearer', generate: true } })], ['/api/gateway/call', live({ call: {} })], ['/api/clock', live({ clock: { minutes: 1 } })], ['/api/reset', {}], ['/api/proof/run', live({})], ['/api/policies', live({ grant: {} })], ['/api/stores/resync', live({})]];
      for (const p of reads) { const r = await get(url, p, ADMIN, h); n += 1; assert.equal(r.status, 400, `${p} ${id.slice(0, 6)}`); assert.equal(await r.text(), '{"error":"bad_workspace"}'); }
      for (const [p, b] of writes) { const r = await post(url, p, b, ADMIN, h); n += 1; assert.equal(r.status, 400, `${p} ${id.slice(0, 6)}`); assert.equal(await r.text(), '{"error":"bad_workspace"}'); }
    }
    assert.equal(n, 96);
    assert.equal(workspaces.size(), 0, 'no refused id took a slot');
    for (const p of ['/api/health', '/api/info', '/api/story', '/api/diagram']) assert.equal((await get(url, p, ADMIN, { 'x-workspace': ids[0] })).status, 200, `${p} takes no workspace`);
    assert.equal(workspaces.size(), 0, 'info routes took no slot either');
    assert.equal((await get(url, '/api/nope', ADMIN, { 'x-workspace': ids[0] })).status, 404, 'an unknown route is a 404, not a workspace error');
  });
});
