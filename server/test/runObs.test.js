// Rule 27: the lab's half of the run-observability panel (runObs.js, the route, the table events). The vendored collector has its own tests in the shared folder.
// Real is tested against an in-process fake Privilege gateway on loopback only; the shared settings file is pointed at a file that does not exist.
import test from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { VERTICALS } from '../src/cast.js';
import { MOCK_TABLE } from '../src/mockTable.js';
import { runScenario, scenarioList } from '../src/scenarios.js';
import { assertRunObservability, classify, layerMatchers, createMasker, LAYERS } from '../src/runObservability.js';
import { createRunLog, decisionLine, KEEP_RUNS, lineValue, mockRecord, realRecord, replyOf } from '../src/runObs.js';
import { maskDeep } from '../src/mask.js';
import { C, U1, U2, ADMIN, SUP, get, post, live, withServer } from './helpers.js';

const NO_ENV = '/nonexistent/none.env'; // the shared settings file is read live by gatewayReal.js: never the owner's
const W = (id) => ({ 'x-workspace': id });
const WORDS = /refused|denied|rejected|forbidden|failed|invalid|expired|mismatch|token|audience|scope|served|unauthorized|insufficient|not allowed/i;
const LINE = /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z secrets-vault-lab decision step=[A-Za-z0-9._:/@-]+ layer=[a-z]+ actor=[A-Za-z0-9._:/@-]+ result=(?:passed|stopped|unclear|no-reply) cause=[A-Za-z0-9._:/@-]+(?: labtime=[A-Za-z0-9._:/@-]+)? run=[A-Za-z0-9._:/@-]+$/;
const PRODUCTS = [...new Set(layerMatchers.map((m) => m.product))];
const fragments = (...p) => p.join('');
const KEY = fragments('fake-agent-key-', 'qqqqqqqqqq', '-end');
const rows = (rec) => rec.rows.filter((r) => r.origin !== 'not-logged');
const noMatcherReads = (line) => { for (const product of PRODUCTS) { const at = line.split(' ')[0]; assert.equal(classify({ product, message: line, at: Date.parse(at), atExact: at }, []), null, `${product}: ${line}`); } };

// ---- A fake Privilege gateway on loopback: the MCP calls the lab's client makes, answered by a script ------------------------------------------
async function fakeGateway() {
  const g = { script: { list: null, call: null }, seen: [], url: '', port: 0 };
  const json = (res, obj, status = 200, headers = {}) => { res.writeHead(status, { 'content-type': 'application/json', ...headers }); res.end(JSON.stringify(obj)); };
  const server = http.createServer((req, res) => {
    let body = ''; req.on('data', (c) => { body += c; });
    req.on('end', () => {
      if (req.method === 'DELETE') { res.writeHead(200); return res.end(); }
      let m; try { m = JSON.parse(body); } catch { res.writeHead(400); return res.end(); }
      g.seen.push({ method: m.method, auth: req.headers.authorization });
      if (m.method === 'initialize') return json(res, { jsonrpc: '2.0', id: m.id, result: { protocolVersion: '2025-06-18', serverInfo: { name: 'fake-gateway' }, capabilities: {} } }, 200, { 'mcp-session-id': 's1' });
      if (m.method === 'notifications/initialized') { res.writeHead(202); return res.end(); }
      const step = m.method === 'tools/list' ? g.script.list : g.script.call;
      return step({ m, res, req, json: (o, s, h) => json(res, o, s, h) });
    });
  });
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  g.port = server.address().port; g.url = `http://127.0.0.1:${g.port}`;
  g.close = () => new Promise((r) => { server.closeAllConnections(); server.close(r); });
  return g;
}
const tools = (n) => ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result: { tools: Array.from({ length: n }, (_x, i) => ({ name: `tool_${i}`, description: 'a tool' })) } });
const status = (code, text = 'nope') => ({ json }) => json({ message: text }, code);
const rpcResult = (result) => ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result });
const rpcError = (message) => ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, error: { code: -32000, message } });
const drop = ({ req }) => req.socket.destroy();
const rawText = ({ res }) => { res.writeHead(200, { 'content-type': 'application/json' }); res.end('<html>not json</html>'); };

async function withGateway(fn, { runLog } = {}) {
  const gw = await fakeGateway();
  const env = { STANDALONE_ENV: NO_ENV, SVL_GW_URL: gw.url, SVL_GW_APPS: 'door-a', SVL_GW_KEY_LAB_AGENT: KEY };
  try { await withServer(async (url, ctx) => fn(url, gw, ctx), { env, runLog }); } finally { await gw.close(); }
}
const toReal = (url) => post(url, '/api/mode', { source: 'real' }, null);
const toMock = (url) => post(url, '/api/mode', { source: 'mock' }, null);
const check = async (url) => (await post(url, '/api/gateway-check', {}, null)).json();
const record = async (url, q = '') => (await (await get(url, `/api/run-observability${q}`, null)).json());

// ---- Mock: the recorded scenarios -------------------------------------------------------------------------------------------------------------
test('every recorded scenario of every vertical has a Mock record that passes the shared contract, is all simulated, and comes through the response mask unchanged', async () => {
  await withServer(async (url) => {
    for (const [v, vv] of Object.entries(MOCK_TABLE.verticals)) {
      for (const sc of vv.scenarios) {
        const res = await get(url, `/api/run-observability?vertical=${v}&scenario=${sc.id}`, null);
        assert.equal(res.status, 200, `${v}/${sc.id}`);
        const { record: rec } = await res.json();
        assert.deepEqual(assertRunObservability(rec), [], `${v}/${sc.id}`);
        assert.equal(rec.source, 'mock'); assert.equal(rec.runId, `table-${v}-${sc.id}`);
        assert.ok(rows(rec).every((r) => r.origin === 'simulated' && !r.basis && !r.matchedBy), 'no row is presented as read from a log');
        assert.deepEqual(Object.keys(rec.coverage).sort(), [...LAYERS].sort());
        assert.equal(rec.coverage.authorize, 'not-logged');
        // the route's answer is exactly the record the lab built: the response mask changed no word of it
        assert.deepEqual(rec, JSON.parse(JSON.stringify(await mockRecord(MOCK_TABLE, v, sc.id))));
        assert.deepEqual(maskDeep({ record: rec }), { record: rec });
        assert.equal(rec.rows.length, rows(rec).length + Object.values(rec.coverage).filter((c) => c === 'not-logged').length);
      }
    }
    // no scenario named: the first one
    assert.equal((await record(url)).record.runId, `table-finance-${MOCK_TABLE.verticals.finance.scenarios[0].id}`);
  });
});

test('own-vault: each call is person, agent, gateway, then the backend, in that order; the injection is information, the backend logs who acted', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'own-vault');
  assert.deepEqual(rec.rows.filter((r) => r.origin !== 'not-logged').map((r) => r.layer), ['person', 'agent', 'gateway', 'resource', 'person', 'agent', 'gateway', 'resource', 'person', 'agent', 'gateway', 'resource']);
  const [, , inj, back] = rows(rec);
  assert.equal(inj.outcome, 'info'); assert.match(inj.message, /not a decision/); assert.deepEqual(inj.detail.headers, ['Authorization']);
  assert.equal(back.outcome, 'allowed'); assert.match(back.message, new RegExp(`logged who actually acted: ${U1}`)); assert.equal(back.detail.principal, U1);
  const shared = rows(rec).filter((r) => r.layer === 'resource').map((r) => r.detail.principal);
  assert.deepEqual(shared, [U1, `svc-${C.castT1}`, `svc-${C.castT1}`], 'a shared service account logs the same identity for every caller');
  assert.deepEqual(rec.summary, { allowed: 3, refused: 0, blocked: 0, info: 9, unverified: 0 }, 'an injection, a person and an agent line are information, never a pass');
  assert.equal(rec.coverage.privilege, 'not-logged'); assert.match(rec.reasons.privilege, /no grant check/);
  // the lab clock does not move inside one scenario step, so the times tie; the order the engine wrote them in is kept
  assert.deepEqual(rows(rec).map((r) => r.detail.eventSeq), [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]);
  assert.deepEqual(rows(rec).map((r) => r.id), rows(rec).map((_r, i) => `r${i + 1}`));
});

test('a call the gateway turns away is refused, never a plain allow, and never reaches the backend', async () => {
  const injection = await mockRecord(MOCK_TABLE, 'finance', 'injection-shapes');
  const last = rows(injection).slice(-2);
  assert.deepEqual(last.map((r) => [r.layer, r.outcome]), [['person', 'info'], ['gateway', 'refused']]);
  assert.match(last[1].message, /never falls back to a shared account/);
  assert.equal(rows(injection).filter((r) => r.layer === 'resource').length, 4, 'four calls reached the backend; the fifth did not');
  const staged = await mockRecord(MOCK_TABLE, 'finance', 'staged-delete');
  assert.deepEqual(rows(staged).map((r) => [r.layer, r.outcome]), [['person', 'info'], ['gateway', 'refused']]);
  assert.match(rows(staged)[1].message, /staged for deletion cannot be used/);
  const override = await mockRecord(MOCK_TABLE, 'finance', 'no-override');
  assert.deepEqual(rows(override).filter((r) => r.layer === 'gateway').map((r) => r.outcome), ['refused', 'refused'], 'another person\'s entry is not found, and naming an owner is not a field');
  assert.equal(rows(override).filter((r) => r.layer === 'resource').length, 0);
});

test('governed-read: the grant table allows, refuses (read and write are separate, default deny) and says so; an edit of the table is information', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'governed-read');
  const g = rows(rec);
  assert.deepEqual(g.map((r) => r.layer), Array(7).fill('privilege'));
  assert.deepEqual(g.map((r) => r.outcome), ['allowed', 'refused', 'refused', 'allowed', 'refused', 'info', 'allowed']);
  assert.match(g[1].message, /not the write grant.*separate grants/s);
  assert.match(g[2].message, /not the read grant/);
  assert.match(g[4].message, /no grant for .*default deny/s);
  assert.match(g[5].message, /added grant pol-0009.*not a decision/s);
  assert.equal(rec.coverage.privilege, 'simulated'); assert.equal(rec.coverage.person, 'not-logged'); assert.equal(rec.coverage.gateway, 'not-logged');
  assert.deepEqual(rec.summary, { allowed: 3, refused: 3, blocked: 0, info: 1, unverified: 0 });
});

test('a scenario whose steps are no decision of these layers has no rows, and every layer says why', async () => {
  const rec = await mockRecord(MOCK_TABLE, 'finance', 'nightly-resync');
  assert.equal(rec.rows.length, 6); assert.ok(rec.rows.every((r) => r.origin === 'not-logged' && r.at === null));
  assert.deepEqual(rec.summary, { allowed: 0, refused: 0, blocked: 0, info: 0, unverified: 0 });
  assert.deepEqual(assertRunObservability(rec), []);
  for (const l of LAYERS) assert.ok(rec.reasons[l].length > 20, l);
});

test('the Mock events are the audit trail\'s: a call is four events, a turned-away call two, a grant check one, each pointing at an audit entry of the same time', () => {
  for (const [v, cast] of Object.entries(VERTICALS)) {
    for (const sc of scenarioList(cast)) {
      const run = runScenario(cast, sc);
      const audit = new Map(run.engine.s.audit.map((a) => [a.id, a]));
      const byAudit = Map.groupBy(run.events, (e) => e.detail.audit);
      for (const [id, evs] of byAudit) {
        const a = audit.get(id); assert.ok(a, `${v}/${sc.id}: ${id} is in the audit trail`);
        assert.ok(evs.every((e) => e.at === a.at), 'the time is the audit entry\'s');
        if (a.action === 'gateway.call') assert.deepEqual(evs.map((e) => e.layer), ['person', 'agent', 'gateway', 'resource'], `${v}/${sc.id}/${id}`);
        else if (a.action === 'gatewayCall') assert.deepEqual(evs.map((e) => [e.layer, e.outcome]), [['person', 'info'], ['gateway', 'refused']], `${v}/${sc.id}/${id}`);
        else assert.equal(evs.length, 1, `${v}/${sc.id}/${id}`);
      }
      const calls = [...audit.values()].filter((a) => a.action === 'gateway.call').length;
      assert.equal(run.events.filter((e) => e.layer === 'resource').length, calls, `${v}/${sc.id}: one backend event per call the backend answered`);
      assert.deepEqual(MOCK_TABLE.verticals[v].scenarios.find((s) => s.id === sc.id).events.map((e) => e.seq), run.events.map((_e, i) => i + 1));
    }
  }
});

test('no credential, provider value or sealed byte is in any Mock event (the table is public)', () => {
  for (const [v, cast] of Object.entries(VERTICALS)) {
    for (const sc of scenarioList(cast)) {
      const run = runScenario(cast, sc); const e = run.engine;
      const secrets = [...e.providerValues()];
      for (const [user, list] of Object.entries(e.s.vault)) for (const entry of list) {
        const p = e.open(user, entry); secrets.push(...[p.token, p.key, p.username, p.password, ...(p.headers ? Object.values(p.headers) : [])].filter(Boolean));
        secrets.push(entry.sealed.ct, entry.sealed.n, entry.sealed.t);
      }
      const text = JSON.stringify(run.events);
      for (const s of secrets.filter((x) => x.length >= 8)) assert.ok(!text.includes(s), `${v}/${sc.id}: a value is in an event`);
    }
  }
});

// ---- The route ------------------------------------------------------------------------------------------------------------------------------
test('the route answers errors as {error, message} JSON and takes only its own parameters', async () => {
  await withServer(async (url) => {
    const cases = [['?bogus=1', 400, 'unknown_field'], ['?scenario=nope', 404, 'unknown_scenario'], ['?vertical=nope', 400, 'bad_vertical']];
    for (const [q, st, code] of cases) {
      const r = await get(url, `/api/run-observability${q}`, null); const b = await r.json();
      assert.equal(r.status, st, q); assert.equal(b.error, code);
      if (code !== 'bad_vertical') assert.equal(typeof b.message, 'string');
    }
    for (const [m, st] of [['POST', 405], ['PUT', 405], ['DELETE', 405]]) {
      const r = await fetch(`${url}/api/run-observability`, { method: m, headers: { origin: url, 'content-type': 'application/json' }, body: m === 'DELETE' ? undefined : '{}' });
      assert.equal(r.status, st, m); assert.match(r.headers.get('allow'), /GET/);
    }
    assert.equal((await get(url, '/api/run-observability', null)).headers.get('cache-control'), 'no-store');
  });
});

// ---- Live: one stdout line per decision --------------------------------------------------------------------------------------------------------
const act = (url, ws, who, route, body) => post(url, route, live(body), who, W(ws));
async function liveSession(url, ws) {
  const entry = { name: 'Ledger bearer', targetId: C.castT1, shape: 'bearer', generate: true };
  await act(url, ws, U1, '/api/vault/entries', { entry });
  await act(url, ws, U1, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary' } });
  await act(url, ws, U1, '/api/gateway/call', { call: { targetId: C.castT1, as: 'shared', operation: 'read_summary' } });
  await act(url, ws, U2, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary' } });
  await act(url, ws, U1, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary', owner: ADMIN } });
  await act(url, ws, U1, '/api/stores/read', { read: { ref: `aws:${C.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } });
  await act(url, ws, U1, '/api/stores/rotate', { ref: `aws:${C.castAwsPrefix}/db-admin` });
  await act(url, ws, SUP, '/api/stores/read', { read: { ref: `aws:${C.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } });
  await act(url, ws, ADMIN, '/api/policies', { grant: { principal: SUP, scope: `aws:${C.castAwsPrefix}/**`, actions: ['read'] } });
  await act(url, ws, ADMIN, '/api/clock', { clock: { minutes: 5 } });
}

test('Live: each decision the engine makes is one stdout line, one run id per action, no word a shared matcher reads, and no shared matcher reads any line', async () => {
  const lines = [];
  await withServer(async (url) => {
    await liveSession(url, 'obs-live');
    assert.equal(lines.length, 16, 'four lines for each of two calls, two for each of two turned away, one for each of four grant checks and edits');
    const steps = new Set();
    for (const l of lines) {
      assert.match(l, LINE); assert.ok(!WORDS.test(l.replace(/ actor=\S+/, '')), l);
      noMatcherReads(l);
      steps.add(/ step=(\S+)/.exec(l)[1]);
    }
    for (const s of ['caller', 'agent-ask', 'injection', 'backend', 'call-turned-away', 'grant-check', 'grant-edit']) assert.ok(steps.has(s), `${s} was written`);
    // one run id per action; a call writes four lines under one id; ids are unique across the session
    const byRun = Map.groupBy(lines, (l) => / run=(\S+)$/.exec(l)[1]);
    assert.ok([...byRun.values()].every((v) => v.length === 4 || v.length === 2 || v.length === 1));
    // a refusal is a result, not a pass, and an injection is `unclear`, never `passed`
    assert.ok(lines.some((l) => / step=grant-check .* result=stopped /.test(l)));
    assert.ok(lines.filter((l) => / step=injection /.test(l)).every((l) => / result=unclear /.test(l)));
    assert.ok(lines.filter((l) => / step=call-turned-away /.test(l)).every((l) => / result=stopped /.test(l)));
    // the lab clock is in the line as labtime (the time of the audit entry), the line's own time is the wall clock
    assert.ok(lines.every((l) => !/labtime=/.test(l) || /labtime=2026-11-02T09:/.test(l)));
    // nothing is written for a read, for a Mock table or for a caller the roster does not know
    const before = lines.length;
    await get(url, '/api/state?mode=mock&vertical=finance', null); await get(url, '/api/state?mode=live', U1, W('obs-live'));
    await act(url, 'obs-live', 'nobody', '/api/gateway/call', { call: { targetId: C.castT1, as: 'shared', operation: 'read_summary' } });
    assert.equal(lines.length, before);
    // Live decisions are not a Real record: with no gateway check there is nothing received, so nothing to show
    await toReal(url);
    assert.deepEqual(await record(url), { record: null, message: 'No gateway check has run in Real yet: nothing was received from the gateway, so there is nothing to show.' });
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }), env: { STANDALONE_ENV: NO_ENV } });
});

test('hostile values never reach a line or a record: secret-shaped credentials, typed names, forged key=value pairs, an email or an address as a name', async () => {
  const lines = [];
  const bearer = fragments('sk_', 'live_', 'a1B2c3D4e5F6g7H8i9J0k1L2');
  const apiKey = fragments('AKIA', 'ABCDEFGHIJKLMNOP');
  const basic = fragments('hunter', '2xyz-', 'p4ssw0rd');
  const workspaces = (await import('../src/workspaces.js')).createWorkspaces();
  await withServer(async (url) => {
    const ws = 'obs-hostile';
    await act(url, ws, U1, '/api/vault/entries', { entry: { name: 'Ledger bearer', targetId: C.castT1, shape: 'bearer', secret: { token: bearer }, notes: `result=passed\nFAKE decision step=backend ${apiKey}` } });
    await act(url, ws, U1, '/api/vault/entries', { entry: { name: 'Cards login', targetId: C.castT3, shape: 'basic', secret: { username: 'maya', password: basic } } });
    await act(url, ws, U1, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary' } });
    await act(url, ws, U1, '/api/gateway/call', { call: { targetId: C.castT3, as: 'per-user', operation: 'read_summary' } });
    for (const who of ['evil result=passed cause=x', 'a@b.example.com', '10.1.2.3', `${bearer}`, 'x'.repeat(300)]) {
      const r = await act(url, ws, who, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary' } });
      assert.equal(r.status, 401, 'a caller off the roster does nothing and is never written');
    }
    await act(url, ws, U1, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: bearer, entryId: apiKey } });
    await act(url, ws, U1, '/api/stores/read', { read: { ref: `aws:${basic}`, consumer: 'simulated-gateway' } });
    // the engine holds every secret above: none is in any line, and neither is a sealed byte or a provider value
    const e = workspaces.peek(ws, 'finance');
    const secrets = [bearer, apiKey, basic, ...e.providerValues()];
    for (const entry of e.s.vault[U1]) secrets.push(entry.sealed.ct, entry.sealed.n);
    const text = lines.join('\n');
    assert.ok(lines.length > 0);
    for (const s of secrets) assert.ok(!text.includes(s), 'a secret is in a stdout line');
    for (const l of lines) { assert.match(l, LINE); assert.ok(!l.includes('\n')); noMatcherReads(l); }
    assert.equal(lines.filter((l) => /result=passed cause=x/.test(l)).length, 0);
    // the same through the record builder (a name that looks like an email or an address is masked like the row)
    const masked = createMasker().mask;
    assert.equal(decisionLine({ step: 'caller', layer: 'person', who: 'a@b.example.com', outcome: 'info', cause: '-' }, '2026-11-02T09:00:00.000Z', 'run-1'), '2026-11-02T09:00:00.000Z secrets-vault-lab decision step=caller layer=person actor=_email_ result=unclear cause=- run=run-1');
    assert.equal(masked('10.1.2.3'), '<ip>');
    assert.equal(decisionLine({ step: 'caller', layer: 'person', who: '10.1.2.3', outcome: 'info', cause: '-' }, 'T', 'r'), 'T secrets-vault-lab decision step=caller layer=person actor=_ip_ result=unclear cause=- run=r');
    assert.equal(decisionLine({ step: 'caller', layer: 'person', who: 'a b\nresult=passed run=x', outcome: 'info', cause: '-' }, 'T', 'r').split(' ').filter((p) => p.startsWith('result=')).length, 1, 'a typed name cannot add a second result');
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }), env: { STANDALONE_ENV: NO_ENV }, workspaces });
  assert.equal(lineValue('a b\nc=d'), 'a_b_c_d'); assert.equal(lineValue(''), '-'); assert.equal(lineValue(undefined), '-');
});

test('every step and cause the lab can write passes the shared matchers: each way a call is turned away, each grant refusal, every reply kind', () => {
  const at = '2026-11-02T09:00:00.000Z';
  const evs = [];
  for (const [step, cause, outcome] of [['call-turned-away', 'no-entry', 'refused'], ['call-turned-away', 'entry-unnamed', 'refused'], ['call-turned-away', 'not-in-vault', 'refused'], ['call-turned-away', 'staged-entry', 'refused'], ['call-turned-away', 'other-target', 'refused'], ['call-turned-away', 'bad-request', 'refused'],
    ['grant-check', 'granted', 'allowed'], ['grant-check', 'no-grant', 'refused'], ['grant-check', 'read-not-granted', 'refused'], ['grant-check', 'write-not-granted', 'refused'], ['grant-edit', '-', 'info'],
    ['backend', 'caller-identity', 'allowed'], ['backend', 'shared-identity', 'allowed'], ['backend', 'wrong-kind', 'refused'], ['backend', 'not-recognised', 'refused'], ['backend', 'other', 'refused'], ['injection', 'own-vault', 'info'], ['injection', 'shared-account', 'info']]) evs.push({ step, cause, outcome, layer: 'gateway', who: 'maya.chen', labtime: at });
  const replies = [
    ['tools/list', { ok: true, tools: [{}] }], ['tools/list', { ok: true, tools: [] }], ['tools/list', { ok: false, refusal: { status: 401 } }], ['tools/list', { ok: false, refusal: { status: 403 } }], ['tools/list', { ok: false, refusal: { status: 500 } }],
    ['probe', { ok: true, isError: true, text: 'x' }], ['probe', { ok: true, isError: false, text: 'x' }], ['probe', { ok: true, isError: false, text: '' }], ['probe', { ok: false, refusal: { status: null, message: 'boom' } }],
    ['probe', { ok: false, refusal: { status: null, message: 'reply is not JSON' } }], ['probe', { ok: false, refusal: { status: 403 } }],
  ];
  for (const [step, r] of replies) evs.push({ ...replyOf(step, r), step: step === 'probe' ? 'gateway-probe' : 'gateway-list', layer: 'gateway', who: 'lab-agent' });
  evs.push({ step: 'gateway-list', layer: 'gateway', who: 'lab-agent', noReply: true, cause: 'no-reply' });
  assert.equal(evs.length, 18 + 11 + 1);
  for (const ev of evs) {
    const line = decisionLine(ev, at, 'run-1');
    assert.match(line, LINE); assert.ok(!WORDS.test(line.replace(/ actor=\S+/, '')), line); noMatcherReads(line);
    noMatcherReads(`[${at}] INFO: ${line.split(' ').slice(1).join(' ')}`);
  }
  assert.match(decisionLine(evs.at(-1), at, 'r'), / result=no-reply cause=no-reply run=r$/);
});

// ---- Real: what the lab received from the Privilege gateway ---------------------------------------------------------------------------------------
test('Real: a gateway check is one stdout line and one `response` row per reply, at the time the lab had the reply; the key and the gateway address are in neither', async () => {
  const lines = [];
  let t = Date.UTC(2026, 10, 22, 12, 0, 0);
  const runLog = createRunLog({ write: (l) => lines.push(l), clock: () => { t += 250; return t; } });
  await withGateway(async (url, gw) => {
    const echo = ({ json }) => json({ message: `denied for ${KEY} at ${gw.url}` }, 403);
    gw.script.list = ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: `tool-${KEY}`, description: `see ${gw.url}` }, { name: 'b', description: 'c' }] } });
    gw.script.call = echo;
    // Mock first: the check is refused, and the record route answers a Mock record
    assert.equal((await post(url, '/api/gateway-check', {}, null)).status, 409);
    assert.equal((await record(url)).record.source, 'mock');
    await toReal(url);
    const out = await check(url);
    assert.equal(out.listing.ok, true); assert.equal(out.refusal.ok, false); assert.match(out.runId, /^gw-[0-9a-f]{6}-\d+$/);
    const { record: rec } = await record(url, `?runId=${out.runId}`);
    assert.deepEqual(assertRunObservability(rec), []);
    assert.equal(rec.source, 'real'); assert.equal(rec.runId, out.runId);
    assert.deepEqual(rows(rec).map((r) => [r.layer, r.outcome, r.origin]), [['gateway', 'allowed', 'response'], ['gateway', 'refused', 'response']]);
    assert.ok(rec.rows.every((r) => r.origin !== 'logged' && r.origin !== 'simulated' && !r.basis && !r.matchedBy));
    assert.deepEqual(rec.coverage, { person: 'not-logged', agent: 'not-logged', authorize: 'not-logged', privilege: 'not-logged', gateway: 'response', resource: 'not-logged' });
    assert.match(rec.reasons.privilege, /stay in the lab's own engine in Real too/);
    assert.match(rows(rec)[0].message, /2 tools/); assert.match(rows(rec)[1].message, /HTTP 403.*what the probe expects/);
    assert.match(rows(rec)[0].message, /reply the lab received, not a gateway log line/);
    // the key and the address of the gateway are nowhere in the record, the lines or the answer's run id
    const everything = JSON.stringify(rec) + lines.join('\n');
    assert.ok(!everything.includes(KEY) && !everything.includes('127.0.0.1') && !everything.includes(`:${gw.port}`), 'no key and no gateway address');
    assert.equal(gw.seen.find((s) => s.method === 'tools/list').auth, `Bearer ${KEY}`, 'the lab did send the key to the gateway');
    // two lines, one per row, with the row's own time
    assert.equal(lines.length, 2); lines.forEach((l) => { assert.match(l, LINE); noMatcherReads(l); assert.ok(!WORDS.test(l.replace(/ actor=\S+/, '')), l); });
    assert.deepEqual(lines.map((l) => l.split(' ')[0]), rows(rec).map((r) => r.atExact));
    assert.match(lines[0], / step=gateway-list layer=gateway actor=\S+ result=passed cause=tools-listed run=gw-/);
    assert.match(lines[1], / step=gateway-probe .* result=stopped cause=status-403 run=gw-/);
  }, { runLog });
});

test('Real: how each kind of reply is read (401 and 403 refused, a usable 200 allowed, a JSON-RPC error or isError refused, an unparsed body or another status information)', async () => {
  const cases = [
    { name: 'list 401', list: status(401), want: [['refused', 'status-401']], probeSent: false },
    { name: 'list 403', list: status(403), want: [['refused', 'status-403']], probeSent: false },
    { name: 'list 500', list: status(500), want: [['info', 'status-500']], probeSent: false },
    { name: 'list not JSON', list: rawText, want: [['info', 'unreadable']], probeSent: false },
    { name: 'list JSON-RPC error', list: rpcError('no'), want: [['refused', 'jsonrpc-error']], probeSent: false },
    { name: 'list empty', list: tools(0), call: status(403), want: [['info', 'empty-list'], ['refused', 'status-403']] },
    { name: 'probe 401', list: tools(2), call: status(401), want: [['allowed', 'tools-listed'], ['refused', 'status-401']] },
    { name: 'probe isError', list: tools(2), call: rpcResult({ isError: true, content: [{ type: 'text', text: 'no' }] }), want: [['allowed', 'tools-listed'], ['refused', 'tool-error']] },
    { name: 'probe JSON-RPC error', list: tools(2), call: rpcError('policy says no'), want: [['allowed', 'tools-listed'], ['refused', 'jsonrpc-error']] },
    { name: 'probe 200 with a result', list: tools(2), call: rpcResult({ content: [{ type: 'text', text: 'ok' }] }), want: [['allowed', 'tools-listed'], ['allowed', 'tool-ran']] },
    { name: 'probe 200 with nothing to read', list: tools(2), call: rpcResult({ content: [] }), want: [['allowed', 'tools-listed'], ['info', 'no-content']] },
    { name: 'probe 502', list: tools(2), call: status(502), want: [['allowed', 'tools-listed'], ['info', 'status-502']] },
    { name: 'probe not JSON', list: tools(2), call: rawText, want: [['allowed', 'tools-listed'], ['info', 'unreadable']] },
  ];
  for (const c of cases) {
    const lines = [];
    await withGateway(async (url, gw) => {
      gw.script.list = c.list; gw.script.call = c.call || status(418, 'the probe must not be sent');
      await toReal(url);
      const out = await check(url);
      const { record: rec } = await record(url, `?runId=${out.runId}`);
      assert.deepEqual(assertRunObservability(rec), [], c.name);
      assert.deepEqual(rows(rec).map((r) => r.outcome), c.want.map((w) => w[0]), c.name);
      assert.deepEqual(lines.map((l) => /cause=(\S+)/.exec(l)[1]), c.want.map((w) => w[1]), c.name);
      if (c.probeSent === false) {
        assert.ok(!gw.seen.some((s) => s.method === 'tools/call'), c.name);
        assert.match(rec.reasons.gateway, /only sent after tools\/list is answered with a tool list/, c.name);
      }
      assert.ok(rows(rec).every((r) => r.origin === 'response'));
    }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
  }
});

test('Real: a call that got no reply is no row and no pass: a no-reply line, and the layer says why', async () => {
  const lines = [];
  await withGateway(async (url, gw) => {
    await toReal(url);
    gw.script.list = drop; gw.script.call = status(403);
    let out = await check(url);
    assert.equal(out.listing.ok, false);
    let { record: rec } = await record(url, `?runId=${out.runId}`);
    assert.equal(rows(rec).length, 0); assert.equal(rec.coverage.gateway, 'not-logged'); assert.match(rec.reasons.gateway, /tools\/list call got no reply/);
    assert.deepEqual(assertRunObservability(rec), []);
    assert.match(lines.at(-1), / step=gateway-list .* result=no-reply cause=no-reply run=gw-/);
    // the list answered, the probe was dropped: one row, the other named in the layer's reason; the earlier answer is not borrowed for it
    gw.script.list = tools(3); gw.script.call = drop;
    out = await check(url);
    ({ record: rec } = await record(url, `?runId=${out.runId}`));
    assert.deepEqual(rows(rec).map((r) => r.outcome), ['allowed']);
    assert.equal(rec.coverage.gateway, 'response'); assert.match(rec.reasons.gateway, /refusal probe got no reply/);
    assert.match(lines.at(-1), / step=gateway-probe .* result=no-reply /);
    assert.deepEqual(assertRunObservability(rec), []);
  }, { runLog: createRunLog({ write: (l) => lines.push(l) }) });
});

test('the mode is stored on the run: a Real run is never answered in Mock and a Mock record never in Real; an attempt that began no run does not change the answer', async () => {
  await withGateway(async (url, gw) => {
    gw.script.list = tools(2); gw.script.call = status(403);
    await toReal(url);
    assert.equal((await record(url)).record, null, 'before any check: no run, and the message says so');
    const first = await check(url);
    assert.equal((await record(url)).record.runId, first.runId, 'the newest run');
    // attempts that never reach the gateway make no run and change nothing
    assert.equal((await post(url, '/api/gateway-check', { app: 'no-such-door' }, null)).status, 400);
    assert.equal((await post(url, '/api/gateway-check', { bogus: 1 }, null)).status, 400);
    assert.equal((await record(url)).record.runId, first.runId);
    // back to Mock: the same run id gets a Mock record (never the Real run), and Real comes back with the Real run again
    await toMock(url);
    const m = await record(url, `?runId=${first.runId}&vertical=finance&scenario=own-vault`);
    assert.equal(m.record.source, 'mock'); assert.notEqual(m.record.runId, first.runId);
    assert.equal((await post(url, '/api/gateway-check', {}, null)).status, 409);
    await toReal(url);
    assert.equal((await record(url, `?runId=${first.runId}`)).record.source, 'real');
    assert.deepEqual(await record(url, '?runId=gw-000000-1'), { record: null, message: 'That gateway check is no longer kept (the lab keeps the last few).' });
    assert.equal((await get(url, '/api/run-observability?runId=a&runId=b', null)).status, 400);
  });
});

test('Real runs are kept in a bounded list, newest last, with ids that never repeat; the id is unique across checks and Live actions', async () => {
  await withGateway(async (url, gw) => {
    gw.script.list = tools(1); gw.script.call = status(403);
    await toReal(url);
    const ids = [];
    for (let i = 0; i < KEEP_RUNS + 3; i += 1) ids.push((await check(url)).runId);
    assert.equal(new Set(ids).size, ids.length);
    assert.equal((await record(url)).record.runId, ids.at(-1));
    assert.equal((await record(url, `?runId=${ids.at(-KEEP_RUNS)}`)).record.runId, ids.at(-KEEP_RUNS), 'the oldest kept run is still there');
    assert.equal((await record(url, `?runId=${ids[0]}`)).record, null, 'an evicted run says so');
    const live1 = []; const log = createRunLog({ write: (l) => live1.push(l) });
    const a = log.beginCheck('lab-agent'); const b = log.beginCheck('lab-agent'); a.end(); b.end();
    log.live([{ step: 'caller', layer: 'person', who: U1, outcome: 'info', cause: '-' }]);
    const all = [a.id, b.id, / run=(\S+)$/.exec(live1[0])[1]];
    assert.equal(new Set(all).size, 3);
    // an open run is never in the list, so it can never be evicted by others finishing
    const open = log.beginCheck('lab-agent'); for (let i = 0; i < KEEP_RUNS + 2; i += 1) log.beginCheck('x').end();
    assert.equal(log.get(open.id), null); open.end(); assert.equal(log.get(open.id).id, open.id);
  });
});

test('a recorder that throws never breaks the run or the audit: the lab answers as before and says why on stderr', async () => {
  const boom = () => { throw Object.assign(new Error('recorder is broken'), { code: 'E_BOOM' }); };
  const runLog = { live: boom, beginCheck: boom, get: boom };
  const written = []; const realWrite = process.stderr.write;
  process.stderr.write = (s, ...rest) => { written.push(String(s)); return typeof rest.at(-1) === 'function' ? rest.at(-1)() : true; };
  try {
    await withGateway(async (url, gw, { workspaces }) => {
      gw.script.list = tools(1); gw.script.call = status(403);
      const r = await act(url, 'obs-boom', U1, '/api/vault/entries', { entry: { name: 'Ledger bearer', targetId: C.castT1, shape: 'bearer', generate: true } });
      assert.equal(r.status, 200); assert.equal((await r.json()).ok, true);
      const call = await act(url, 'obs-boom', U1, '/api/gateway/call', { call: { targetId: C.castT1, as: 'per-user', operation: 'read_summary' } });
      assert.equal(call.status, 200); assert.equal((await call.json()).result.backendView.principal, U1);
      assert.ok(workspaces.peek('obs-boom', 'finance').s.audit.some((a) => a.action === 'gateway.call'), 'the audit trail has the call');
      await toReal(url);
      const out = await check(url);
      assert.equal(out.listing.ok, true); assert.equal(out.runId, undefined, 'no run was kept, and the answer says nothing about one');
      const rec = await get(url, '/api/run-observability', null);
      assert.equal(rec.status, 500); assert.deepEqual(Object.keys(await rec.json()).sort(), ['error', 'message']);
    }, { runLog });
  } finally { process.stderr.write = realWrite; }
  const text = written.join('');
  assert.match(text, /run observability: live-decisions E_BOOM recorder is broken/);
  assert.match(text, /run observability: begin-check E_BOOM/);
  assert.match(text, /run observability: record E_BOOM/);
});

test('the lab keeps the key and the gateway address out of the record when a reply carries them in every field it could', async () => {
  const text = {};
  await withGateway(async (url, gw) => {
    const dirty = (code) => ({ json }) => json({ jsonrpc: '2.0', id: 1, error: { code, message: `${KEY} ${gw.url} Bearer ${KEY}` }, message: `${KEY} ${gw.url}` }, code === 200 ? 200 : 403);
    gw.script.list = ({ m, json }) => json({ jsonrpc: '2.0', id: m.id, result: { tools: [{ name: KEY, description: gw.url }] } });
    for (const call of [dirty(403), rpcResult({ isError: true, content: [{ type: 'text', text: `${KEY} ${gw.url}` }] }), rpcError(`${KEY} ${gw.url}`)]) {
      gw.script.call = call;
      await toReal(url);
      const out = await check(url);
      text[out.runId] = JSON.stringify((await record(url, `?runId=${out.runId}`)).record);
    }
  });
  assert.equal(Object.keys(text).length, 3);
  for (const t of Object.values(text)) assert.ok(!t.includes(KEY) && !t.includes('127.0.0.1') && !/Bearer \w/.test(t));
});

test('a Real record is built from the lab\'s own events alone and keeps no word of the gateway\'s', async () => {
  const run = { id: 'gw-abcdef-1', source: 'real', caller: 'lab_agent', startedAt: '2026-11-22T12:00:00.000Z', endedAt: '2026-11-22T12:00:01.000Z', notes: [], events: [{ ...replyOf('tools/list', { ok: true, tools: [{ name: 'x' }], ms: 5 }), at: '2026-11-22T12:00:00.500Z', layer: 'gateway', product: 'Privilege gateway reply', who: 'lab_agent' }] };
  const rec = await realRecord(run);
  assert.deepEqual(assertRunObservability(rec), []);
  assert.deepEqual(rows(rec).map((r) => r.detail), [{ step: 'tools/list', tools: 1, ms: 5, eventSeq: 0 }]);
  assert.equal(replyOf('probe', null), null); assert.equal(replyOf('probe', 'text'), null);
});
