import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, U2, ADMIN, AUD, SUP, ALL, get, post, put, live, rawHttp, withServer } from './helpers.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { installNetguard } from '../src/netguard.js';

// The parallel tests send `connection: close`, so no request can race a keep-alive socket the server just closed (the cause of the one ECONNRESET seen at load 145).
// Nothing is retried: a retried POST could double-create, and an assertion is never retried.
const withRetry = (fn) => fn();
const CLOSE = { connection: 'close' };

const guard = installNetguard(); // installed for the whole file: every test here runs under it

const W = (id) => ({ 'x-workspace': id });
const entry = (o = {}) => ({ name: 'Ledger bearer', targetId: C.castT1, shape: 'bearer', generate: true, ...o });
const mk = async (url, who = U1, ws = 'default', o = {}) => (await (await post(url, '/api/vault/entries', live({ entry: entry(o) }), who, W(ws))).json());

test('health answers demo-health/1, GET only, with no detail; info says simulated and unverified', async () => {
  await withServer(async (url) => {
    const h = await (await get(url, '/api/health', null)).json();
    assert.equal(h.schema, 'demo-health/1'); assert.equal(h.state, 'ready'); assert.equal(h.demo.id, 'secrets-vault-lab'); assert.ok(JSON.stringify(h).length < 400);
    assert.equal((await post(url, '/api/health', {}, null)).status, 405);
    const i = await (await get(url, '/api/info', null)).json(); assert.equal(i.unverified, true); assert.equal(i.simulated, true);
  });
});

test('the caller must be named: a missing or unknown X-Lab-Actor is 401 on state, reads and writes (never defaulted to someone)', async () => {
  await withServer(async (url) => {
    for (const a of [null, 'nobody', '__proto__', 'x'.repeat(300)]) {
      for (const p of ['/api/state?mode=live', '/api/vault/entries', '/api/stores/secrets', '/api/governance']) { const r = await get(url, p, a); assert.equal(r.status, 401, `${a} ${p}`); }
      const w = await post(url, '/api/vault/entries', live({ entry: entry() }), a); assert.equal(w.status, 401, 'a real 401');
      assert.equal((await w.json()).error, 'unknown_actor');
    }
    assert.equal((await get(url, '/api/state?mode=mock', null)).status, 200, 'the recorded Mock tables need no caller');
  });
});

test('every vault path, as every other role, is forced to the caller\'s own vault over HTTP; naming an owner (query, body or call) is refused, never ignored', async () => {
  await withServer(async (url) => {
    const id = (await mk(url)).result.entryId;
    for (const who of [U2, ADMIN, AUD, SUP]) {
      const g = await get(url, `/api/vault/entries/${id}`, who); assert.equal(g.status, 404); assert.deepEqual(await g.json(), { error: 'not_found' });
      const l = await (await get(url, '/api/vault/entries', who)).json(); assert.deepEqual(l.entries, []);
      for (const [m, p, b] of [['PUT', `/api/vault/entries/${id}`, { entry: { notes: 'x' } }], ['POST', `/api/vault/entries/${id}/delete`, {}], ['POST', `/api/vault/entries/${id}/restore`, {}], ['POST', '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } }]]) {
        const r = await (m === 'PUT' ? put : post)(url, p, live(b), who); assert.equal(r.status, 404, `${who} ${p}`); assert.equal((await r.json()).error, 'not_found');
      }
      for (const k of ['owner', 'user', 'userId', 'vault', 'asUser']) {
        assert.equal((await get(url, `/api/vault/entries/${id}?${k}=${U1}`, who)).status, 400, `${who} ?${k}`);
        assert.equal((await get(url, `/api/vault/entries?${k}=${U1}`, who)).status, 400);
        assert.equal((await get(url, `/api/state?mode=live&${k}=${U1}`, who)).status, 400);
        assert.equal((await post(url, '/api/vault/entries', live({ entry: entry(), [k]: U1 }), who)).status, 400, 'a top-level owner is refused');
        assert.equal((await post(url, '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary', [k]: U1 } }), who)).status, 400, 'an owner in the call is refused');
      }
      assert.ok(!JSON.stringify((await (await get(url, '/api/state?mode=live', who)).json()).state.vault).includes(id));
    }
    assert.equal((await get(url, `/api/vault/entries/${id}`, U1)).status, 200, 'the owner still reads their own');
  });
});

test('"not found" for another user\'s entry and for an entry that never existed are the same answer (no oracle)', async () => {
  await withServer(async (url) => {
    const id = (await mk(url)).result.entryId;
    const a = await get(url, `/api/vault/entries/${id}`, ADMIN); const b = await get(url, '/api/vault/entries/vcr-9999', ADMIN); const c = await get(url, '/api/vault/entries/anything', ADMIN);
    assert.deepEqual([a.status, await a.text()], [b.status, await b.text()]); assert.equal(c.status, 404);
  });
});

test('Mock mode is read-only: every write is 409, state comes from the recorded tables, a scenario is chosen by id, an unknown one falls back', async () => {
  await withServer(async (url) => {
    for (const [p, b] of [['/api/vault/entries', { entry: entry() }], ['/api/clock', { clock: { minutes: 5 } }], ['/api/stores/resync', {}], ['/api/policies', { grant: {} }], ['/api/vault/keys', { key: {} }]]) assert.equal((await post(url, p, { mode: 'mock', vertical: 'finance', ...b })).status, 409, p);
    const s = await (await get(url, '/api/state?mode=mock&vertical=finance&scenario=staged-delete', null)).json();
    assert.equal(s.mode, 'mock'); assert.equal(s.scenario.id, 'staged-delete'); assert.equal(s.scenarios.length, 7);
    for (const bad of ['__proto__', 'constructor', 'nope']) { const r = await get(url, `/api/state?mode=mock&scenario=${bad}`, null); assert.equal(r.status, 404, bad); assert.deepEqual(await r.json(), { error: 'unknown_scenario' }); }
    assert.equal((await (await get(url, '/api/state?mode=mock', null)).json()).scenario.id, MOCK_TABLE.verticals.finance.scenarios[0].id, 'no scenario named: the first');
    assert.equal((await get(url, '/api/state?mode=prod', null)).status, 400);
    assert.equal((await post(url, '/api/clock', { mode: 'prod', clock: { minutes: 5 } })).status, 400);
  });
});

test('Live writes: every refusal is a real HTTP status with the same JSON body (never a 200), a body with an unknown top-level field is 400', async () => {
  await withServer(async (url) => {
    const bad = await post(url, '/api/vault/entries', live({ entry: entry({ targetId: 'nope' }) })); assert.equal(bad.status, 400);
    const j = await bad.json(); assert.equal(j.ok, false); assert.equal(j.error, 'unknown_target'); assert.ok(j.state && j.hops.length, 'the refusal body still carries the fresh state and the hops, for the page to read as data');
    const flag = await post(url, '/api/vault/entries', live({ entry: entry(), refusalsAs200: true })); assert.equal(flag.status, 400, 'the old refusalsAs200 flag no longer exists: it is an unknown field'); assert.equal((await flag.json()).error, 'unknown_field');
    assert.equal((await post(url, '/api/vault/keys', live({ key: { configured: 'none', reachable: true } }), U1)).status, 403);
    assert.equal((await post(url, '/api/vault/entries', live({ entry: entry(), extra: 1 }))).status, 400);
    assert.equal((await post(url, '/api/vault/entries', live({ entry: 'x' }))).status, 400);
    assert.equal((await post(url, '/api/vault/entries', live({ entry: { ...entry(), extra: 1 } }))).status, 400);
    const r = await fetch(`${url}/api/vault/entries`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url, 'x-lab-actor': U1 }, body: '[1]' }); assert.equal(r.status, 400);
    const m = await fetch(`${url}/api/vault/entries`, { method: 'POST', headers: { 'content-type': 'application/json', origin: url, 'x-lab-actor': U1 }, body: '{bad' }); assert.equal(m.status, 400);
  });
});

test('the 64 KB bound over HTTP: exactly 65536 bytes is stored, 65537 is refused whole (413) and nothing was kept', async () => {
  await withServer(async (url) => {
    const ok = await post(url, '/api/vault/entries', live({ entry: entry({ generate: undefined, secret: { token: 'a'.repeat(65536) } }) })); assert.equal(ok.status, 200);
    const over = await post(url, '/api/vault/entries', live({ entry: entry({ generate: undefined, secret: { token: 'a'.repeat(65537) } }) })); assert.equal(over.status, 413); assert.equal((await over.json()).error, 'credential_too_large');
    const st = (await (await get(url, '/api/state?mode=live', U1)).json()).state; assert.equal(st.vault.count, 1);
    const huge = await post(url, '/api/vault/entries', live({ entry: entry({ generate: undefined, secret: { token: 'a'.repeat(250000) } }) })); assert.equal(huge.status, 413); assert.deepEqual(await huge.json(), { error: 'payload_too_large' });
  });
});

test('the 500-entry bound over HTTP, under 600 creates in parallel waves: exactly 500 succeed, 100 are refused, nothing is dropped or duplicated', async () => {
  await withServer(async (url) => {
    const bodies = []; const statuses = [];
    for (let wave = 0; wave < 6; wave++) { // six waves of 100 truly parallel requests (one wave of 600 sockets overruns the listen backlog on a loaded machine)
      const rs = await Promise.all(Array.from({ length: 100 }, (_, i) => withRetry(() => post(url, '/api/vault/entries', live({ entry: entry({ name: `e${wave}-${i}` }) }), U1, { ...W('cap'), ...CLOSE }))));
      statuses.push(...rs.map((r) => r.status)); bodies.push(...await Promise.all(rs.map((r) => r.json())));
    }
    assert.equal(statuses.filter((s) => s === 200).length, 500); assert.equal(statuses.filter((s) => s === 409).length, 100, 'the 501st and later are a real 409');
    assert.ok(bodies.filter((b) => !b.ok).every((b) => b.error === 'vault_full'));
    const st = (await (await get(url, '/api/state?mode=live', U1, W('cap'))).json()).state; assert.equal(st.vault.count, 500);
    assert.equal(new Set(bodies.filter((b) => b.ok).map((b) => b.result.entryId)).size, 500);
    assert.equal(st.vault.distinctNonces, 500);
  });
});

test('parallel deletes and restores of one entry end in one consistent state (double staging refused), and parallel store reads are each audited', async () => {
  await withServer(async (url) => {
    const id = (await mk(url, U1, 'par')).result.entryId;
    const rs = await Promise.all(Array.from({ length: 10 }, () => withRetry(() => post(url, `/api/vault/entries/${id}/delete`, live({}), U1, { ...W('par'), ...CLOSE }))));
    const b = await Promise.all(rs.map((r) => r.json())); assert.equal(rs.filter((r) => r.status === 200).length, 1); assert.equal(rs.filter((r) => r.status === 409).length, 9);
    assert.equal(b.filter((x) => x.ok).length, 1); assert.equal(b.filter((x) => x.error === 'already_staged').length, 9);
    const reads = await Promise.all(Array.from({ length: 8 }, () => post(url, '/api/stores/read', live({ read: { ref: `aws:${C.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } }), U1, { ...W('par'), ...CLOSE })));
    assert.ok(reads.every((r) => r.status === 200));
    const gov = await (await get(url, '/api/governance', AUD, W('par'))).json(); assert.equal(gov.audit.filter((a) => a.action === 'store.read').length, 8);
  });
});

test('workspaces are isolated, Reset clears only the current one, and the cap on workspaces answers 503 for a new one', async () => {
  await withServer(async (url) => {
    await mk(url, U1, 'ws-a'); await mk(url, U1, 'ws-b');
    assert.equal((await post(url, '/api/reset', {}, U1, W('ws-a'))).status, 200);
    assert.equal((await (await get(url, '/api/state?mode=live', U1, W('ws-a'))).json()).state.vault.count, 0);
    assert.equal((await (await get(url, '/api/state?mode=live', U1, W('ws-b'))).json()).state.vault.count, 1);
    assert.equal((await get(url, '/api/state?mode=live', U1, W('BAD ID'))).status, 400);
  });
  const { createWorkspaces } = await import('../src/workspaces.js');
  await withServer(async (url) => {
    assert.equal((await post(url, '/api/vault/entries', live({ entry: entry() }), U1, W('one'))).status, 200);
    const r = await post(url, '/api/vault/entries', live({ entry: entry() }), U1, W('two')); assert.equal(r.status, 503); assert.equal((await r.json()).error, 'workspace_cap');
    assert.equal((await post(url, '/api/vault/entries', live({ entry: entry() }), U1, W('one'))).status, 200, 'the existing workspace is still served');
  }, { workspaces: createWorkspaces({ max: 1 }) });
});

test('a W3C traceparent continues across every hop; the first hop shows the route pattern, never the path, and the actor; hops are capped', async () => {
  await withServer(async (url) => {
    const id = (await mk(url)).result.entryId;
    const tp = `00-${'1'.repeat(32)}-${'2'.repeat(16)}-01`;
    const r = await post(url, '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } }), U1, { traceparent: tp });
    assert.match(r.headers.get('traceparent'), new RegExp(`^00-${'1'.repeat(32)}-[0-9a-f]{16}-01$`));
    const b = await r.json(); assert.equal(b.traceId, '1'.repeat(32)); assert.ok(b.hops.length >= 4 && b.hops.length <= 40);
    assert.ok(b.hops.every((h) => h.request.headers.traceparent.startsWith(`00-${'1'.repeat(32)}-`)));
    assert.equal(b.hops[0].request.url, '/api/gateway/call'); assert.equal(b.hops[0].request.headers['x-lab-actor'], U1);
    const d = await post(url, `/api/vault/entries/${id}/delete`, live({}), U1); assert.equal((await d.json()).hops[0].request.url, '/api/vault/entries/:id/delete');
  });
});

test('Host and same-origin rules: a non-loopback Host is 403, a cross-origin or cross-site write is 403, and nothing is written', async () => {
  await withServer(async (url, { workspaces }) => {
    const host = new URL(url).host;
    assert.equal((await rawHttp(`${url}/api/health`, { headers: { host: 'evil.example:80' } })).status, 403);
    for (const h of [{ origin: 'http://evil.example' }, { 'sec-fetch-site': 'cross-site' }]) {
      const r = await rawHttp(`${url}/api/vault/entries`, { method: 'POST', headers: { host, 'content-type': 'application/json', 'x-lab-actor': U1, ...h }, body: JSON.stringify(live({ entry: entry() })) });
      assert.equal(r.status, 403);
    }
    assert.equal(workspaces.size(), 0);
  });
});

test('no value ever leaves in a response: a full flow of mock values (vault and stores) is searched in every answer', async () => {
  await withServer(async (url) => {
    const secrets = ['typed-bearer-value-123456789', 'typed-store-value-987654321', 'typed-user-name-5555'];
    const texts = [];
    const take = async (r) => { const t = await r.text(); texts.push(t); return JSON.parse(t); };
    const e = await take(await post(url, '/api/vault/entries', live({ entry: entry({ generate: undefined, secret: { token: secrets[0] } }) }), U1, W('flow')));
    const id = e.result.entryId;
    texts.push(JSON.stringify(await (await get(url, `/api/vault/entries/${id}`, U1, W('flow'))).json()));
    await take(await put(url, `/api/vault/entries/${id}`, live({ entry: { notes: 'edit', secret: { token: `${secrets[0]}-v2` } } }), U1, W('flow')));
    await take(await post(url, '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } }), U1, W('flow')));
    await take(await post(url, '/api/stores/secrets', live({ secret: { provider: 'azure', path: `${C.castKv}/flow`, fields: { value: secrets[1] } } }), U1, W('flow')));
    const rd = await take(await post(url, '/api/stores/read', live({ read: { ref: `azure:${C.castKv}/flow`, consumer: 'simulated-gateway' } }), U1, W('flow')));
    assert.equal(rd.result.note, 'value delivered to the consumer (masked)');
    await take(await post(url, '/api/stores/rotate', live({ ref: `azure:${C.castKv}/flow` }), U1, W('flow')));
    await take(await post(url, '/api/vault/keys', live({ key: { configured: 'none', reachable: true } }), ADMIN, W('flow')));
    for (const who of ALL) texts.push(await (await get(url, '/api/state?mode=live', who, W('flow'))).text(), await (await get(url, '/api/governance', who, W('flow'))).text());
    const all = texts.join('\n');
    for (const s of [secrets[0], secrets[1], `${secrets[0]}-v2`]) assert.ok(!all.includes(s), `${s} leaked`);
    assert.ok(!/MOCK-(aws|gcp|azure|delinea|cyberark|conn|bearer|apikey|basic|header|file)-/.test(all), 'no provider or generated value either');
  });
});

test('every fixed refusal message passes the response mask unchanged (a message must never look like a credential and be masked)', async () => {
  const fs = await import('node:fs'); const { maskDeep } = await import('../src/mask.js');
  const src = ['engine.js', 'stores.js', 'actions.js'].map((f) => fs.readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8')).join('\n');
  const msgs = [...src.matchAll(/refuse\('[a-z_]+', (?:'((?:[^'\\]|\\.)*)'|`((?:[^`\\]|\\.)*)`)/g)].map((m) => (m[1] ?? m[2]).replace(/\\'/g, "'").replace(/\$\{[^}]*\}/g, 'x'));
  assert.ok(msgs.length > 60, `found ${msgs.length}`);
  for (const m of msgs) assert.equal(maskDeep(m), m, m);
});

test('unknown API paths and wrong methods are fixed JSON 404s; the static fallback never serves the API', async () => {
  await withServer(async (url) => {
    assert.deepEqual(await (await get(url, '/api/nope', U1)).json(), { error: 'not_found' });
    assert.deepEqual(await (await post(url, '/api/nope', {}, U1)).json(), { error: 'not_found' });
    assert.equal((await post(url, '/api/vault/entries/vcr-0001', live({}), U1)).status, 404, 'POST on a PUT route');
  });
});

test('zero outbound network attempts across the whole API in both modes (the guard records any attempt, and there are none)', async () => {
  const before = guard.attempts.length;
  await withServer(async (url) => {
    for (const mode of ['mock', 'live']) {
      await get(url, `/api/state?mode=${mode}`, U1);
      await post(url, '/api/vault/entries', { mode, vertical: 'finance', entry: entry() }, U1);
    }
    const id = (await mk(url, U1, 'net')).result.entryId;
    await post(url, '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } }), U1, W('net'));
    await post(url, '/api/stores/read', live({ read: { ref: `aws:${C.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } }), U1, W('net'));
    await post(url, '/api/stores/connection', live({ provider: 'aws' }), ADMIN, W('net'));
    await post(url, '/api/clock', live({ clock: { minutes: 10080 } }), U1, W('net'));
    await post(url, '/api/stores/resync', live({}), U1, W('net'));
  });
  assert.deepEqual(guard.attempts.slice(before), []);
});

test('the server writes no file and spawns nothing: no worker thread or child process modules in the source', async () => {
  const fs = await import('node:fs');
  for (const f of fs.readdirSync(new URL('../src/', import.meta.url)).filter((x) => x.endsWith('.js'))) {
    const t = fs.readFileSync(new URL(`../src/${f}`, import.meta.url), 'utf8');
    assert.ok(!/child_process|worker_threads|cluster/.test(t), f);
  }
});

test('an unknown vertical is a 400 and an unknown diagram a 404 on every route that takes one (never a silent fallback); the value is never echoed', async () => {
  await withServer(async (url) => {
    for (const bad of ['nope', '__proto__', 'constructor', 'Finance']) {
      for (const p of [`/api/story?vertical=${bad}`, `/api/diagram?vertical=${bad}`, `/api/state?mode=mock&vertical=${bad}`, `/api/state?mode=live&vertical=${bad}`, `/api/vault/entries?vertical=${bad}`]) {
        const r = await get(url, p, U1); assert.equal(r.status, 400, p); const t = await r.text(); assert.deepEqual(JSON.parse(t).error, 'bad_vertical'); assert.ok(!t.includes(bad) || bad === 'Finance' && false, 'not echoed');
      }
      const w = await post(url, '/api/vault/entries', { mode: 'live', vertical: bad, entry: entry() }, U1); assert.equal(w.status, 400); assert.equal((await w.json()).error, 'bad_vertical');
    }
    for (const bad of ['nope', '__proto__', 'constructor']) { const r = await get(url, `/api/diagram?name=${bad}`, U1); assert.equal(r.status, 404); assert.deepEqual(await r.json(), { error: 'unknown_diagram' }); }
    assert.equal((await get(url, '/api/diagram', U1)).status, 200); assert.equal((await get(url, '/api/diagram?name=secret-store-no-copy&vertical=health', U1)).status, 200);
  });
});
