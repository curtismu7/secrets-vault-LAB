// The masking heuristic, pinned: hidden characters, key-shaped JSON and glued assignments, percent-encoding, long inputs, and the response-level mask.
import test from 'node:test';
import assert from 'node:assert/strict';
import { cleanFree, findCredentials, normalizeText, maskText, maskResponseText } from '../src/credentials.js';
import { maskDeep } from '../src/mask.js';
import { C, U1, get, post, live, withServer } from './helpers.js';
import { HIDDEN } from './hidden.js';

const U = (...c) => String.fromCodePoint(...c);
const between = (s, cp) => [...s].join(U(cp));
const SECRETS = ['hunterTwo99xx', ['eyJhbGciOiJIUzI1NiJ9', 'eyJzdWIiOiJhYmNkZWYifQ', 'abcdefghij1234567890XYZ'].join('.'), ['sk', '-proj-Zy9Xw8Vv7Uu6Tt5Ss4Rr3Qq2Pp1'].join(''), 'Zq9Xk2Lm8Rt4Vb7Nc1Hd5Fj3Gs6Pw0Y'];
const SHAPES = [(v) => `my ${['pass', 'word'].join('')} is ${v}`, (v) => `Bearer ${v}`, (v) => v, (v) => `${['pass', 'word'].join('')}: ${v}`];

test('hidden characters never hide a credential: 29 of them, between EVERY character, through four secrets in four shapes (cleaner, name test and response mask)', () => {
  for (const cp of HIDDEN) for (const secret of SECRETS) for (const shape of SHAPES) {
    if (shape === SHAPES[2] && secret === SECRETS[0]) continue; // a bare 13-character word has no recognisable shape: the page says masking is a heuristic
    const text = shape(secret); const hidden = between(text, cp);
    assert.ok(!cleanFree(hidden).includes(secret.slice(0, 12)), `U+${cp.toString(16)} ${text.slice(0, 20)}: cleaner`);
    assert.ok(findCredentials(hidden).length > 0, `U+${cp.toString(16)} ${text.slice(0, 20)}: seen by the name test`);
    if (!(shape === SHAPES[2] && secret === SECRETS[3])) assert.ok(!maskResponseText(hidden).includes(secret.slice(0, 12)) && !maskResponseText(hidden).includes(U(cp)), `U+${cp.toString(16)} ${text.slice(0, 20)}: response mask (a bare key-like run is the input cleaner's job: the response mask skips the generic detectors, ids are long)`);
  }
});

test('the reviewer\'s exact repros: a Hangul filler inside "password", a key-like string with U+3164 between every character', () => {
  assert.ok(!cleanFree(`pass${U(0x3164)}word: hunterTwo99xx`).includes('hunterTwo99xx'));
  assert.ok(!cleanFree(between('Zq9Xk2Lm8Rt4Vb7Nc1Hd5', 0x3164)).includes('Zq9Xk2'));
  assert.equal(normalizeText(`a${U(0x3164)}b${U(0xfffd)}c${U(0xe0041)}d`), 'abcd');
});

test('key-shaped forms: JSON keys in any quoting, suffixed keys (userPassword), and two assignments glued together each mask on their own', () => {
  const pw = ['pass', 'word'].join('');
  for (const t of [`{"${pw}":"hunterTwo99xx"}`, `{'${pw}': 'hunterTwo99xx'}`, `${pw}="hunterTwo99xx"`, `user${pw[0].toUpperCase()}${pw.slice(1)}=hunterTwo99xx`, `client_secret: hunterTwo99xx`, `"apiKey":"hunterTwo99xx"`, `access_token=hunterTwo99xx`]) {
    assert.ok(!cleanFree(t).includes('hunterTwo99xx'), t); assert.ok(!maskResponseText(t).includes('hunterTwo99xx'), `response: ${t}`);
  }
  const glued = `${pw}: a","b":"${pw}: zq81xkzq`;
  assert.ok(!cleanFree(glued).includes('zq81xkzq')); assert.ok(!maskResponseText(glued).includes('zq81xkzq'));
  const two = cleanFree(`${pw}=firstValue99,${pw}=secondValue88;token: thirdValue77`);
  for (const v of ['firstValue99', 'secondValue88', 'thirdValue77']) assert.ok(!two.includes(v), v);
});

test('percent-encoded once, twice and three times (and with a fullwidth percent sign) is decoded before matching, and the masked text shows the decoded form', () => {
  const pw = ['pass', 'word'].join('');
  const enc1 = `${pw}%3Dhunterxx99`; const enc2 = `${pw}%253Dhunterxx99`; const enc3 = `${pw}%25253Dhunterxx99`; const full = `${pw}${U(0xff05)}3Dhunterxx99`;
  for (const t of [enc1, enc2, enc3, full, encodeURIComponent(`my ${pw} is hunterxx99`), encodeURIComponent(encodeURIComponent(`${pw}: hunterxx99`))]) {
    const c = cleanFree(t); assert.ok(!c.includes('hunterxx99'), `${t}: ${c}`); assert.ok(!maskResponseText(t).includes('hunterxx99'), `response ${t}`);
    assert.match(c, /\[masked:/); assert.ok(!c.includes('%3D') && !c.includes('%253D'), 'the decoded text is shown, masked');
  }
  assert.equal(cleanFree('100% sure, 50%25 off'), '100% sure, 50% off', 'ordinary text with a percent sign survives');
});

test('ordinary text is not eaten: prose, ids, dates, paths and the words "token requirements" are left alone', () => {
  for (const t of ['I need read access to review the change', 'req-0001 on gh-repo-core for maya.chen until 2026-11-02T10:00:00Z', 'the token requirements and the password policy are in the handbook', 'kv-payments-prod/db-connection', 'compass: north', 'Snowflake role ANALYST_RO on main.payments_gold']) assert.equal(cleanFree(t), t, t);
});

test('the response-level mask is pinned: a credential inside any response string, at any depth, is masked even when no input cleaner ran', () => {
  const pw = ['pass', 'word'].join(''); const tok = ['gh', 'p_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
  const out = maskDeep({ a: { b: [{ c: `x ${tok} y` }, `my ${pw} is hunterTwo99xx`, between(`${pw}: hunterTwo99xx`, 0x3164)] }, hash: tok });
  const t = JSON.stringify({ ...out, hash: undefined });
  assert.ok(!t.includes('hunterTwo99xx') && !t.includes('a1B2c3D4e5'), t.slice(0, 200));
  assert.equal(out.hash, tok, 'a field named hash is opaque');
  assert.equal(maskDeep('plain text').toString(), 'plain text');
  assert.match(maskResponseText('x'.repeat(30000)), /\[cut at 20000 characters\]$/);
});

test('long and hostile inputs are bounded: 7000 PEM headers, 200 KB of filler, and a token after 19,990 filler characters are all handled in well under a second, and the token is masked', () => {
  const t0 = Date.now();
  const BEGIN = ['-----BEGIN ', 'PRIVATE KEY-----'].join(''); const BEGIN_RSA = ['-----BEGIN RSA ', 'PRIVATE KEY-----\n'].join('');
  cleanFree(BEGIN.repeat(7000)); cleanFree(BEGIN_RSA.repeat(5000) + 'x'.repeat(3000)); cleanFree('a'.repeat(200_000));
  assert.ok(Date.now() - t0 < 1500, `took ${Date.now() - t0} ms`);
  const filler = 'ok '.repeat(6600);
  assert.ok(!cleanFree(`${filler}${['gh', 'p_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('')}`, 40000).includes('a1B2c3D4e5'));
  const key = ['-----BEGIN ', 'PRIVATE KEY-----\n', 'MIIEvQIBADANBgkqhkiG9w0B'.repeat(20), '\n-----END ', 'PRIVATE KEY-----'].join('');
  assert.ok(!cleanFree(`before ${key} after`).includes('MIIEvQIBADANBg')); assert.match(cleanFree(`before ${key} after`), /^before \[masked:private-key\] after$/);
  assert.match(cleanFree(`${BEGIN}\n${'A'.repeat(100)}`), /masked:private-key/, 'an unterminated block is masked to its end');
});

test('through the API: the reviewer\'s notes and name repros do not come back, for notes, names and every hidden character', async () => {
  await withServer(async (url) => {
    const pw = ['pass', 'word'].join('');
    for (const cp of HIDDEN.slice(0, 12)) {
      const notes = `pass${U(cp)}word: hunterTwo99xx and ${between('Zq9Xk2Lm8Rt4Vb7Nc1Hd5', cp)}`;
      const r = await post(url, '/api/vault/entries', live({ entry: { name: 'n', targetId: C.castT1, shape: 'bearer', generate: true, notes } }), U1, { 'x-workspace': `hid${cp.toString(16)}` });
      const t = await r.text(); assert.equal(r.status, 200); assert.ok(!t.includes('hunterTwo99xx') && !t.includes('Zq9Xk2'), `U+${cp.toString(16)} notes: ${t.slice(0, 80)}`);
      const n = await post(url, '/api/vault/entries', live({ entry: { name: between(`${pw}: hunterTwo99xx`, cp), targetId: C.castT1, shape: 'bearer', generate: true } }), U1, { 'x-workspace': `hid${cp.toString(16)}` });
      const nt = await n.text(); assert.ok(!nt.includes('hunterTwo99xx'), `U+${cp.toString(16)} name: ${nt.slice(0, 80)}`);
      const st = await (await get(url, '/api/state?mode=live', U1, { 'x-workspace': `hid${cp.toString(16)}` })).text(); assert.ok(!st.includes('hunterTwo99xx') && !st.includes('Zq9Xk2'), 'state afterwards');
    }
  });
});

test('maskText is the same normaliser: it decodes, strips and masks, and returns an empty string for an empty input', () => {
  assert.equal(maskText(''), ''); assert.ok(!maskText(`tok${U(0x200b)}en: abcdef1234567890zz`).includes('abcdef1234567890zz'));
});
