// The masking sweep, pinned: control characters inside a keyword (A), a keyword and a plain space (B), user info without a scheme (C), a JSON-quoted assignment (D),
// each typed into every field of every endpoint, with the probe absent from every answer, the follow-up state and the process output. Expected strings and
// limits are LITERALS, never imported constants.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanFree, findCredentials, maskResponseText, maskText } from '../src/credentials.js';
import { scrub } from '../src/service.js';
import { maskDeep } from '../src/mask.js';
import { C, U1, U2, ADMIN, get, post, put, live, withServer } from './helpers.js';
import { sweepAll } from './sweep.js';

const V1 = 'hunter2xyz';
const V2 = ['abcdefghijklmnop', '1234'].join(''); // assembled at run time: no key-shaped string sits in the repository
const PROBES = [V1, V2];
const PW = ['pass', 'word'].join('');
const TOK = ['tok', 'abc12345'].join('-'); // a plain mock value, assembled at run time
const U = (...c) => String.fromCharCode(...c);

// the sweep's exact repros
const CLASS_A = [
  `p${U(1)}a${U(1)}s${U(1)}s${U(1)}w${U(1)}o${U(1)}r${U(1)}d: ${V1}`, `${PW.slice(0, 4)}${U(0)}${PW.slice(4)}=${V1}`, `${PW.slice(0, 4)}${U(0x85)}${PW.slice(4)}=${V1}`, `${PW.slice(0, 4)}${U(0x7f)}${PW.slice(4)}=${V1}`,
  `my pa${U(0)}ss${U(0)}word is ${V1}`, `tok${U(1)}en ${V1}`, `Bea${U(1)}rer ${V1}`, `s${U(1)}k-${V2}`,
];
const CLASS_B = [`${PW} ${V1}`, `pw ${V1}`, `token ${V1}`, `secret ${V1}`, `api key ${V1}`, `the key is ${V1}`];
const CLASS_C = [`bob:${V1}@host.example`, `//bob:${V1}@host.example`, `https://bob:${V1}@host.example`, `https://${V1}@host.example`];
const CLASS_D = [`{"${PW}":"${V1}"}`];
const ALL = [...CLASS_A, ...CLASS_B, ...CLASS_C, ...CLASS_D];
const has = (t) => PROBES.some((p) => t.includes(p));

test('A: every sweep payload with a control character inside the keyword is masked by the cleaner, the name test and the response mask', () => {
  assert.equal(CLASS_A.length, 8);
  for (const p of CLASS_A) {
    assert.ok(!has(cleanFree(p)) && cleanFree(p).includes('[masked:'), JSON.stringify(p));
    assert.ok(findCredentials(p).length > 0, `seen by the name test: ${JSON.stringify(p)}`);
    assert.ok(!has(maskResponseText(p)), `response mask: ${JSON.stringify(p)}`);
  }
  assert.equal(cleanFree(`${PW.slice(0, 4)}${U(0)}${PW.slice(4)}=${V1}`), '[masked:assignment]');
  assert.equal(cleanFree(`my pa${U(0)}ss${U(0)}word is ${V1}`), 'my [masked:phrase]');
  assert.equal(cleanFree(`tok${U(1)}en ${V1}`), '[masked:shape]');
});

test('A: all 62 C0/C1 controls (not tab, LF, CR) are DELETED: none can split the keyword or the value, and none turns into a space', () => {
  const controls = [];
  for (let c = 0; c < 0xa0; c += 1) if ((c < 0x20 || c >= 0x7f) && ![9, 10, 13].includes(c)) controls.push(c);
  assert.equal(controls.length, 62);
  for (const c of controls) {
    const ch = String.fromCharCode(c);
    assert.equal(cleanFree(`pass${ch}word=${V1}`), '[masked:assignment]', `U+${c.toString(16)} inside the keyword`);
    assert.equal(cleanFree(`password=hunter${ch}2xyz`), '[masked:assignment]', `U+${c.toString(16)} inside the value`);
    // 1.4.0 adoption: the shared masker does not rewrite ordinary text, so a control character in a harmless name stays as typed (it is not a secret and is
    // never turned into a space). It used to be deleted by the app's own cleaner.
    assert.equal(cleanFree(`a${ch}b`), /\s/.test(ch) ? 'a b' : `a${ch}b`, `U+${c.toString(16)} stays as typed (white space is collapsed to one space, as for any text)`);
    assert.ok(!has(maskResponseText(`tok${ch}en ${V1}`)), `response mask, U+${c.toString(16)}`);
  }
  // a control character that a percent-escape PRODUCES is deleted as well
  assert.equal(cleanFree(`pass%00word=${V1}`), '[masked:assignment]');
  assert.equal(cleanFree(`pass%2500word=${V1}`), '[masked:assignment]');
  assert.equal(cleanFree(`pass%C2%85word=${V1}`), '[masked:assignment]', 'a UTF-8 escaped C1 control (U+0085)');
  assert.equal(cleanFree(`pass%E2%80%8Bword=${V1}`), '[masked:assignment]', 'a UTF-8 escaped zero-width space');
  assert.equal(cleanFree(`pass%C2%85word=${V1}`.replace('%C2%85', '%25C2%2585')), '[masked:assignment]', 'and escaped twice');
});

test('A: tab, newline, carriage return, U+2028 and U+2029 are separators, yet cannot split a keyword; a plain multi-line text stays readable', () => {
  for (const sep of ['\t', '\n', '\r', ' ', ' ']) {
    assert.equal(cleanFree(`pass${sep}word=${V1}`), '[masked:assignment]', JSON.stringify(sep));
    assert.equal(cleanFree(`to${sep}ken ${V1}`), '[masked:shape]', JSON.stringify(sep));
    assert.equal(cleanFree(`one${sep}two`), 'one two');
  }
  assert.equal(cleanFree('line one\nline two\tcol end\r\nlast'), 'line one line two col end last');
  assert.equal(cleanFree(`rack 4\n${PW}=${V1}\nnext line`), 'rack 4 [masked:assignment] next line');
});

test('B: a credential word, plain whitespace and a 6+ character value with a digit is masked', () => {
  for (const k of [PW, 'pw', 'token', 'secret', 'api key', 'api-key', 'apikey', 'pwd', 'passwd', 'passphrase', 'credentials', 'private key', 'access key', 'session id', 'Passwords', 'TOKENS']) {
    assert.equal(cleanFree(`${k} ${V1}`), '[masked:shape]', k);
    assert.equal(cleanFree(`my ${k}    ${V1} and more`), 'my [masked:shape] and more', `${k} with several spaces and text after`);
    assert.equal(cleanFree(`${k}\t${V1}`), '[masked:shape]', `${k} then a tab`);
  }
  assert.equal(cleanFree(`the key is ${V1}`), '[masked:phrase]');
  assert.equal(cleanFree(`key=${V1}`), '[masked:assignment]');
  assert.equal(cleanFree(`Bearer ${V1}`), '[masked:bearer]');
  assert.equal(cleanFree(`${PW} "${V1}"`), '[masked:shape]');
});

test('B: the false-positive trade-off, pinned both ways: a word with no digit after the keyword stays readable, and a short or digit-free value is NOT found', () => {
  for (const ok of [
    'password reset', 'the password policy is in the handbook', 'rotate the tokens on the first of the month', 'the token requirements', 'secret santa', 'a secret garden', 'pw rotation',
    'api key rotation', 'the key point', 'monkey: 3', 'turkey is fine', 'keyboard 12345678', 'secretary 12345678', 'tokenizer settings', 'Bearer tokens', 'pass the salt', 'the key is held by the provider',
    'meeting 12:30 in room 4', 'contact mailto:ops@corp.example', 'passing the review needs sign-off', 'Snowflake role ANALYST_RO on main.payments_gold', 'req-0001 on gh-repo-core until 2026-11-02T10:00:00Z',
  ]) assert.equal(cleanFree(ok), ok, ok);
  assert.equal(cleanFree('password policy: see wiki'), 'password policy: see wiki', 'no digit, no separator after the first word');
  // what the heuristic still misses (README "What masking still misses"): no digit after a bare space, fewer than 6 characters, and a bare word
  assert.equal(cleanFree('password correcthorse'), 'password correcthorse');
  assert.equal(cleanFree('pw a1b2'), 'pw a1b2');
  assert.equal(cleanFree('hunter2xyz'), 'hunter2xyz');
  // the documented false positive: a value-like word WITH a digit after the keyword is masked
  assert.equal(cleanFree('password reset99 now'), '[masked:shape] now');
  // 1.4.0 adoption: 'the token 2026rotation is due' is no longer masked (the shared masker needs a value shape after the keyword); it used to be a documented false positive.
  assert.equal(cleanFree('the token 2026rotation is due'), 'the token 2026rotation is due');
});

test('C: user info without a scheme, after a bare //, and with a scheme (also a token alone before the @) is masked', () => {
  assert.equal(cleanFree(`bob:${V1}@host.example`), '[masked:userinfo]host.example');
  assert.equal(cleanFree(`//bob:${V1}@host.example`), '//[masked:userinfo]host.example');
  assert.equal(cleanFree(`login bob:${V1}@10.0.0.5:8080/x`), '[masked:shape]');
  assert.match(cleanFree(`https://bob:${V1}@host.example/x`), /^https:\/\/\[masked:url-userinfo\]host\.example\/x$/);
  assert.match(cleanFree(`https://${V1}@host.example/x`), /^https:\/\/\[masked:url-userinfo\]host\.example\/x$/);
  for (const ok of ['contact mailto:ops@corp.example', 'write to ops@corp.example', 'at 12:30 in the hall', 'a:b', 'user@host.example', 'https://host.example/path']) assert.equal(cleanFree(ok), ok, ok);
});

test('D: a JSON-quoted assignment typed as text is masked, in any quoting', () => {
  for (const t of [`{"${PW}":"${V1}"}`, `{"${PW}": "${V1}"}`, `{'${PW}': '${V1}'}`, `{"apiKey":"${V1}"}`, `{"a":1,"token":"${V1}"}`, `{"outer":{"${PW}":"${V1}"}}`]) {
    assert.ok(!has(cleanFree(t)), t); assert.ok(!has(maskResponseText(t)), `response ${t}`); assert.ok(findCredentials(t).length > 0, `name test ${t}`);
  }
  assert.equal(cleanFree(`{"${PW}":"${V1}"}`), '{[masked:assignment]}');
});

test('the same payloads survive percent-encoding once, twice and three times, and fullwidth letters', () => {
  for (const p of ALL.filter((x) => !/[\u0000-\u001f\u007f-\u009f]/.test(x))) {
    for (const enc of [(x) => x, encodeURIComponent, (x) => encodeURIComponent(encodeURIComponent(x)), (x) => encodeURIComponent(encodeURIComponent(encodeURIComponent(x)))]) {
      assert.ok(!has(cleanFree(enc(p))), `${p} -> ${cleanFree(enc(p))}`);
      assert.ok(!has(maskResponseText(enc(p))), `response ${p}`);
    }
  }
  assert.ok(!has(cleanFree(`ｐａｓｓｗｏｒｄ ${V1}`)));
  assert.ok(!has(maskText(`${PW}%0A${V1}`)), 'an escaped line break between the keyword and the value');
});

test('adversarial inputs are bounded by work: the new detectors are linear (a generous 60 s bound only separates linear from quadratic)', () => {
  const N = 20000;
  const inputs = ['pw '.repeat(N / 3), `${PW}${' '.repeat(N)}`, 'a:'.repeat(N / 2), `${'a'.repeat(N)}@`, `ab:${'c'.repeat(N)}`, 'key is '.repeat(N / 7), 'token\t'.repeat(N / 6), `pw ${'x'.repeat(N)}`, `pw ${'x'.repeat(N - 10)}1`, '//a:b@'.repeat(N / 6), 'a:b@'.repeat(N / 4), 'Bearer '.repeat(N / 7), 'password '.repeat(N / 9), `${'p\u0001w '.repeat(N / 4)}`, 'secret   "'.repeat(N / 10)];
  const t0 = Date.now();
  for (const s of inputs) { cleanFree(s); maskResponseText(s); findCredentials(s); }
  assert.ok(Date.now() - t0 < 60_000);
});

test('maskDeep masks object KEYS too, keeps colliding keys apart, and sets an own "__proto__" key as data', () => {
  const out = maskDeep({ [`${PW} ${V1}`]: 1, [`${PW}  ${V1}`]: 2, plain: { [`token ${V1}`]: [`bob:${V1}@host.example`] } });
  const t = JSON.stringify(out);
  assert.ok(!has(t), t);
  assert.equal(Object.keys(out).length, 3, 'two keys that mask to the same text are not merged');
  const evil = JSON.parse('{"__proto__":{"polluted":"x"},"a":1}');
  const masked = maskDeep(evil);
  assert.equal(Object.getPrototypeOf(masked), Object.prototype); assert.equal(masked.polluted, undefined); assert.deepEqual(Object.keys(masked), ['__proto__', 'a']);
  assert.deepEqual(maskDeep({ id: 'x', list: [1, 'y', null] }), { id: 'x', list: [1, 'y', null] }, 'a clean value is returned unchanged');
});

// ---------- through the API, mode live ----------
const capture = () => {
  const out = []; const wo = process.stdout.write.bind(process.stdout); const we = process.stderr.write.bind(process.stderr);
  process.stdout.write = (c, ...a) => { out.push(String(c)); return wo(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return we(c, ...a); };
  return { out, stop: () => { process.stdout.write = wo; process.stderr.write = we; } };
};

test('the sweep payloads typed into every field, key name, path segment, query, header and error path of every endpoint come back in no answer, no follow-up state and no process output', async () => {
  const cap = capture();
  try {
    await withServer(async (url) => {
      const seed = await post(url, '/api/vault/entries', live({ entry: { name: 'seed', targetId: C.castT1, shape: 'bearer', generate: true } }), U1);
      const id = (await seed.json()).result.entryId;
      let n = 0;
      for (const payload of ALL) for (const typed of [payload, encodeURIComponent(payload)]) {
        n += 1;
        const texts = await sweepAll(url, typed, id);
        const hit = texts.filter((t) => has(t));
        assert.deepEqual(hit.map((t) => t.slice(0, 200)), [], `${JSON.stringify(payload)}: the probe came back`);
        for (const who of [U1, ADMIN]) {
          for (const p of ['/api/state?mode=live', '/api/governance', '/api/vault/entries', '/api/stores/secrets']) {
            const t = await (await get(url, p, who)).text();
            assert.ok(!has(t), `${JSON.stringify(payload)}: absent from ${p} as ${who}`);
          }
        }
      }
      assert.equal(n, 38, '19 payloads, raw and percent-encoded');
    });
  } finally { cap.stop(); }
  assert.ok(!has(cap.out.join('')), 'nothing was logged');
});

test('the finding: the entry name, the notes and an update carrying the payloads are refused or masked, in the answer, the hop panes, the state and the list', async () => {
  await withServer(async (url) => {
    for (const [i, p] of ALL.entries()) {
      const ws = { 'x-workspace': `fin${i}` };
      const r = await post(url, '/api/vault/entries', live({ entry: { targetId: 'ledger-api', shape: 'bearer', name: p, secret: { token: TOK } } }), U1, ws);
      const body = await r.text();
      assert.equal(r.status, 400, JSON.stringify(p)); assert.ok(body.includes('"credential_shaped_text"'), body.slice(0, 120)); assert.ok(!has(body), `name refused: ${JSON.stringify(p)}`);
      const n = await post(url, '/api/vault/entries', live({ entry: { targetId: 'ledger-api', shape: 'bearer', name: 'ok name', notes: p, secret: { token: TOK } } }), U1, ws);
      const nb = await n.text();
      assert.equal(n.status, 200, JSON.stringify(p)); assert.ok(!has(nb) && nb.includes('[masked:'), `notes masked: ${JSON.stringify(p)} ${nb.slice(0, 200)}`);
      const entryId = JSON.parse(nb).result.entryId;
      const u = await put(url, `/api/vault/entries/${entryId}`, live({ entry: { name: p, notes: p } }), U1, ws);
      const ub = await u.text(); assert.equal(u.status, 400); assert.ok(!has(ub), 'update refused');
      const u2 = await put(url, `/api/vault/entries/${entryId}`, live({ entry: { notes: p } }), U1, ws);
      const u2b = await u2.text(); assert.equal(u2.status, 200); assert.ok(!has(u2b), 'update masked');
      for (const path of ['/api/state?mode=live', '/api/vault/entries', '/api/governance']) assert.ok(!has(await (await get(url, path, U1, ws)).text()), path);
    }
  });
});

test('hop panes: every field of the request echo is shown MASKED, including path ids, unknown keys and key names (hops[].request.body)', async () => {
  await withServer(async (url) => {
    const probe = (b) => JSON.stringify(b);
    for (const [i, p] of ALL.entries()) {
      const ws = { 'x-workspace': `hop${i}` };
      const calls = [
        [ADMIN, 'POST', '/api/stores/rotate', live({ ref: p })],
        [U1, 'POST', '/api/gateway/call', live({ call: { targetId: p, as: p, entryId: p, operation: p } })],
        [U1, 'POST', '/api/vault/entries', live({ entry: { targetId: p, shape: p, headerName: p, name: 'n', notes: p, secret: { token: TOK } } })],
        [U1, 'POST', '/api/stores/read', live({ read: { ref: p, consumer: p } })],
        [ADMIN, 'POST', '/api/stores/connection', live({ provider: p })],
        [ADMIN, 'POST', '/api/stores/provider-change', live({ change: { provider: p, op: p, ref: p, newPath: p, path: p } })],
        [ADMIN, 'POST', '/api/policies', live({ grant: { principal: p, scope: p, actions: [p] } })],
        [U1, 'POST', `/api/vault/entries/${encodeURIComponent(p)}/delete`, live({})],
        [ADMIN, 'POST', `/api/targets/${encodeURIComponent(p)}/remove`, live({})],
        [ADMIN, 'POST', `/api/policies/${encodeURIComponent(p)}/revoke`, live({})],
        [ADMIN, 'POST', '/api/policies', live({ grant: { [p]: 1 } })],
      ];
      for (const [who, m, path, b] of calls) {
        const r = await (m === 'PUT' ? put : post)(url, path, b, who, ws); const j = await r.json();
        assert.ok(Array.isArray(j.hops) && j.hops.length >= 1, `${path}: hops present`);
        assert.ok(!has(probe(j.hops)), `${path} ${JSON.stringify(p)}: hops`);
        assert.ok(!has(JSON.stringify(j)), `${path} ${JSON.stringify(p)}: answer`);
      }
    }
  });
});

test('refused whole, masked before cut: a name of 80 characters is kept, 81 refused; notes of 200 kept, 201 refused; a credential near the end is masked, never half shown or silently cut', async () => {
  await withServer(async (url) => {
    const create = (entry, ws) => post(url, '/api/vault/entries', live({ entry: { targetId: 'ledger-api', shape: 'bearer', generate: true, ...entry } }), U1, { 'x-workspace': ws });
    const n80 = `${'abcd '.repeat(15)}abcde`; assert.equal(n80.length, 80);
    assert.equal((await create({ name: n80 }, 'len-a')).status, 200); assert.equal((await create({ name: `${n80}z` }, 'len-b')).status, 400);
    const notes200 = `${'abcd '.repeat(39)}abcde`; assert.equal(notes200.length, 200);
    assert.equal((await create({ name: 'n', notes: notes200 }, 'len-c')).status, 200); assert.equal((await create({ name: 'n', notes: `${notes200}z` }, 'len-d')).status, 400);
    // 180 characters of filler, then a 20-character token: 200 characters as typed, but 201 once masked ("[masked:prefix-token]" is 21), so it is refused WHOLE (nothing stored) and never shown
    const filler = `${'abcd '.repeat(36)}`; assert.equal(filler.length, 180);
    const tok20 = ['gh', 'p_a1B2c3D4e5F6g7H8'].join('');
    const edge = `${filler}${tok20}`; assert.equal(edge.length, 200);
    const r = await create({ name: 'n', notes: edge }, 'len-e'); const t = await r.text();
    assert.equal(r.status, 400); assert.ok(t.includes('"bad_notes"') && !has(t) && !t.includes('a1B2c3D4e5'));
    const st = JSON.stringify((await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': 'len-e' })).json()));
    assert.ok(!st.includes('abcd abcd abcd') && !has(st), 'nothing was stored');
    // a short note with the same credential is kept, masked
    const ok = await create({ name: 'n', notes: `rotate: ${PW} ${V1} soon` }, 'len-f'); const okb = await ok.json();
    assert.equal(ok.status, 200); assert.equal(okb.result.entry.notes, 'rotate: [masked:shape] soon');
    // the hop pane cuts a long display string at 300 characters and SAYS so
    const long = await post(url, '/api/stores/rotate', live({ ref: 'abc '.repeat(100) }), ADMIN, { 'x-workspace': 'len-g' }); const lj = await long.json();
    assert.match(lj.hops[0].request.body.ref, / \.\.\. \(cut for display\)$/); assert.equal(lj.hops[0].request.body.ref.indexOf(' ...'), 300);
    const exact = await post(url, '/api/stores/rotate', live({ ref: `${'abc '.repeat(74)}abcd` }), ADMIN, { 'x-workspace': 'len-h' }); assert.equal((await exact.json()).hops[0].request.body.ref, `${'abc '.repeat(74)}abcd`, 'exactly 300 characters are shown whole');
  });
});

test('vault secret VALUES (token, key, username, password, header values) never come back in any answer, state, list, audit or log, through create, update, gateway call and every read', async () => {
  const cap = capture(); const VALUES = ['zeta-bearer-value-4471', 'zeta-apikey-value-5582', 'zeta-user-name-6693', 'zeta-pass-phrase-7704', 'zeta-hdr-one-8815', 'zeta-hdr-two-9926', 'zeta-updated-1137'];
  const all = [];
  try {
    await withServer(async (url) => {
      const ws = { 'x-workspace': 'values-a' };
      const seen = async (r) => { const t = `${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`; all.push(t); return t; };
      for (const [target, shape, secret] of [[C.castT1, 'bearer', { token: VALUES[0] }], [C.castT2, 'api-key', { key: VALUES[1] }], [C.castT3, 'basic', { username: VALUES[2], password: VALUES[3] }], [C.castT4, 'headers', { headers: { 'X-Partner-Id': VALUES[4], 'X-Partner-Key': VALUES[5] } }]]) {
        const r = await post(url, '/api/vault/entries', live({ entry: { name: `v ${shape}`, targetId: target, shape, secret } }), U1, ws);
        const status = r.status; const t = await seen(r); assert.equal(status, 200, t.slice(0, 200));
      }
      const list = await (await get(url, '/api/vault/entries', U1, ws)).json();
      for (const e of list.entries) {
        await seen(await put(url, `/api/vault/entries/${e.id}`, live({ entry: e.shape === 'bearer' ? { secret: { token: VALUES[6] } } : { notes: 'touched' } }), U1, ws));
        await seen(await get(url, `/api/vault/entries/${e.id}`, U1, ws));
        await seen(await post(url, '/api/gateway/call', live({ call: { targetId: e.targetId, as: 'per-user', entryId: e.id, operation: 'read_summary' } }), U1, ws));
      }
      await seen(await post(url, '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'shared', operation: 'read_summary' } }), U1, ws));
      for (const who of [U1, U2, ADMIN]) for (const p of ['/api/state?mode=live', '/api/governance', '/api/vault/entries', '/api/stores/secrets']) await seen(await get(url, p, who, ws));
      await seen(await post(url, '/api/proof/run', live({}), U1, ws));
      assert.equal(list.entries.length, 4);
    });
  } finally { cap.stop(); }
  const text = all.join('\n') + cap.out.join('');
  assert.equal(all.length, 30);
  for (const v of VALUES) assert.ok(!text.includes(v), `${v} came back`);
});

test('Bearer or Basic with a short value: 6 or more characters with a digit is masked, a plain word is not; the response mask leaves long ids and hashes alone', () => {
  assert.equal(cleanFree('Bearer abc123'), '[masked:bearer]'); assert.equal(cleanFree('Basic zx9y8w'), '[masked:bearer]');
  assert.equal(cleanFree('Bearer abcde'), 'Bearer abcde', 'five characters'); assert.equal(cleanFree('Bearer tokens'), 'Bearer tokens'); assert.equal(cleanFree('Bearer abcdefgh'), 'Bearer abcdefgh', 'eight letters, no digit, under 10');
  // 1.4.0 adoption: ten letters with no digit are no longer masked after "Bearer" (the old cleaner masked them; the shared masker needs a digit or a longer value shape)
  assert.equal(cleanFree('Bearer abcdefghij'), 'Bearer abcdefghij', 'ten letters, no digit');
  // 1.4.0 adoption: the response mask no longer skips the long-run detectors. A long opaque run under a name the LAB writes (hash) is kept (opaqueKeys); the same run
  // anywhere else is masked, in an answer as in input. A 64-digit hex run with no decimal digit is not found at all (documented limit).
  const id = `req-${'a1b2c3d4'.repeat(5)}`; const hash = 'deadbeef'.repeat(8); const digest = 'a1b2c3d4'.repeat(8);
  assert.equal(maskResponseText(id), '[masked:opaque]'); assert.equal(maskResponseText(hash), hash);
  assert.equal(maskDeep({ hash: digest }).hash, digest, 'a field named hash is opaque'); assert.equal(maskDeep({ note: digest }).note, '[masked:opaque]');
  assert.equal(cleanFree(digest), '[masked:opaque]', 'a long opaque run is masked in input');
});

test('hop pane overflow is marked: 10 list items and 20 keys are shown whole, one more is counted, never silently dropped', () => {
  const list = (n) => Array.from({ length: n }, (_, i) => `item ${i}`);
  assert.equal(scrub({ tags: list(10) }).tags.length, 10);
  const eleven = scrub({ tags: list(11) }).tags; assert.equal(eleven.length, 11); assert.equal(eleven[10], '(1 more not shown)');
  assert.equal(scrub({ tags: list(25) }).tags.at(-1), '(15 more not shown)');
  const keys = (n) => Object.fromEntries(Array.from({ length: n }, (_, i) => [`k${i}`, i]));
  assert.equal(Object.keys(scrub(keys(20))).length, 20);
  const more = scrub(keys(21)); assert.equal(Object.keys(more).length, 21); assert.equal(more['(more keys)'], '1 not shown');
  assert.equal(scrub({ entry: { entry: { entry: { entry: { entry: { entry: 1 } } } } } }).entry.entry.entry.entry.entry, '(too deep to show)');
});
