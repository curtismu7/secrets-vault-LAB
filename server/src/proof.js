// The no-copy proof's search. It looks for stored values in everything the Privilege side keeps, in four forms (plain, JSON-escaped, base64, hex), with
//   * a 12-character window index: every area's text is scanned ONCE, however many values there are (cost grows with the text, not with values x text);
//   * partial probes: a long value is searched by up to three 63-character slices (start, middle, end), so a truncated leak is found and a 64 KB value costs the same as a short one;
//   * exact-field matching for SHORT values (4 to 11 bytes): they are found only as a whole string field (a short string appears in ordinary words), values under 4 bytes are skipped and counted;
//   * generators that yield at checkpoints, so the caller can slice the work and never hold the event loop for more than a few milliseconds at a time;
//   * a self-test computed from the same functions: hard canaries (quotes, backslashes, non-ASCII, a newline, a short value) are planted and must all be found, and a clean copy must give none.
import { Buffer } from 'node:buffer';

export const WINDOW = 12;
export const SHORT_MIN = 4;
export const PROBE = 63; // a multiple of 3, so a base64 form of a slice taken at a multiple of 3 embeds in the base64 of the whole value
const STEP = 200_000;
const b64 = (s) => Buffer.from(s, 'utf8').toString('base64');
const hex = (s) => Buffer.from(s, 'utf8').toString('hex');
const jesc = (s) => JSON.stringify(s).slice(1, -1);
const ascii = (s) => /^[\x00-\x7f]*$/.test(s);

export function probesOf(v) {
  if (v.length <= PROBE) return [{ text: v, offset: 0 }];
  const last = Math.floor((v.length - PROBE) / 3) * 3;
  const mid = Math.floor(last / 2 / 3) * 3;
  return [{ text: v.slice(0, PROBE), offset: 0 }, { text: v.slice(mid, mid + PROBE), offset: mid }, { text: v.slice(last, last + PROBE), offset: last }];
}

// values: [{ label, value }]. Returns the index the scans use.
export function buildIndex(values) {
  const map = new Map(); const exact = new Map(); let checked = 0; let shortChecked = 0; let skippedTiny = 0;
  const addForm = (form, label, kind) => { if (form.length < WINDOW) return; const k = form.slice(0, WINDOW); (map.get(k) || map.set(k, []).get(k)).push({ form, label, kind }); };
  for (const { label, value } of values) {
    if (typeof value !== 'string') continue;
    const n = Buffer.byteLength(value, 'utf8');
    if (n < SHORT_MIN) { skippedTiny += 1; continue; }
    if (n < WINDOW) { for (const [form, kind] of [[value, 'exact'], [b64(value), 'exact-base64'], [hex(value), 'exact-hex']]) exact.set(form, { label, kind }); shortChecked += 1; continue; }
    checked += 1;
    for (const p of probesOf(value)) {
      addForm(p.text, label, 'plain');
      const j = jesc(p.text); if (j !== p.text) addForm(j, label, 'json-escaped');
      addForm(hex(p.text), label, 'hex');
      if (p.offset === 0) { const buf = Buffer.from(p.text, 'utf8'); addForm((p.text === value ? buf : buf.subarray(0, buf.length - (buf.length % 3))).toString('base64'), label, 'base64'); } // a leading slice embeds in the base64 of the whole value when cut at a multiple of 3 bytes
      else if (ascii(value) && p.offset % 3 === 0) addForm(b64(p.text), label, 'base64');
    }
  }
  return { map, exact, checked, shortChecked, skippedTiny };
}

export function* scanText(text, index, area, found) {
  const n = text.length - WINDOW + 1;
  for (let i = 0; i < n; i++) {
    const hits = index.map.get(text.substr(i, WINDOW));
    if (hits) for (const h of hits) if (text.startsWith(h.form, i)) found.push({ label: h.label, area, kind: h.kind });
    if (i % STEP === STEP - 1) yield;
  }
}

// Iterative walk over the string fields (and keys are NOT searched): a short value matches only when a whole field equals it.
export function* leafScan(root, index, area, found) {
  if (index.exact.size === 0) return;
  const stack = [root]; let seen = 0;
  while (stack.length) {
    const x = stack.pop();
    if (typeof x === 'string') { const h = index.exact.get(x); if (h) found.push({ label: h.label, area, kind: h.kind }); } else if (x && typeof x === 'object') for (const k of Object.keys(x)) stack.push(x[k]);
    if (++seen % 50_000 === 0) yield;
  }
}

const drain = (gen) => { for (;;) { const r = gen.next(); if (r.done) return r.value; } };

// Computed, never a constant: plants hard canaries and a clean control, runs the SAME scans, and reports what they found.
export function selfTest(scan = scanText, leaf = leafScan) {
  const C = ['has"quote-and\\back-1234567', 'unicode-ü漢字-value-12345', 'line1\nline2\tTAB-value-12345', 'MOCK-selftest-0001-abcdef12', 'abcd9'];
  const index = buildIndex(C.map((value, i) => ({ label: `canary ${i}`, value })));
  const planted = [{ leak: C[0] }, { leak: C[1] }, { leak: C[2] }, { leak: C[3] }, { b: b64(C[3]) }, { h: hex(C[1]) }, { short: C[4] }];
  const want = new Set(['canary 0:json-escaped', 'canary 1:plain', 'canary 2:json-escaped', 'canary 3:plain', 'canary 3:base64', 'canary 1:hex', 'canary 4:exact']);
  const found = []; drain(scan(JSON.stringify(planted), index, 'self-test', found)); drain(leaf(planted, index, 'self-test', found));
  const got = new Set(found.map((f) => `${f.label}:${f.kind}`));
  const clean = []; drain(scan(JSON.stringify([{ row: 'a clean copy', note: 'nothing planted here' }]), index, 'self-test', clean)); drain(leaf([{ row: 'a clean copy' }], index, 'self-test', clean));
  const missing = [...want].filter((w) => !got.has(w));
  return { detected: missing.length === 0 && clean.length === 0, planted: want.size, found: [...want].filter((w) => got.has(w)).length, falsePositives: clean.length, howTested: 'five hard values (a quote, a backslash, non-ASCII, a newline and tab, a short value) planted as plain text, JSON-escaped, base64 and hex into a copy of the data, plus a clean control; the same scans as the real search' };
}
export { drain };
