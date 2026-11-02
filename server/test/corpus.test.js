// The shared-masker corpora (test/corpus/leaks.json, ordinary.json, copied unchanged from shared-masker 9bc664a) run through THIS app's adapters:
// every leak probe must come out without its secret, every ordinary string must come out unchanged. Probes are stored as arrays of short fragments (gitleaks safety)
// and joined here at run time. Counts are literals.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { maskText, maskResponseText, findCredentials, cleanFree } from '../src/credentials.js';
import { maskDeep } from '../src/mask.js';

const read = (name) => JSON.parse(readFileSync(new URL(`./corpus/${name}.json`, import.meta.url), 'utf8'));
const leaks = read('leaks'); const ordinary = read('ordinary');
const join = (a) => a.join('');
const expand = (row) => `${row.fillBefore ? `${'a'.repeat(row.fillBefore)} ` : ''}${join(row.input)}${row.fillAfter ? ` ${'a'.repeat(row.fillAfter)}` : ''}`;
const isDeep = (row) => row.api === 'deep';

test('corpus sizes are pinned: 3754 leak probes (the shared corpus at 9bc664a) and 1926 ordinary strings', () => {
  assert.equal(leaks.length, 3754); assert.equal(ordinary.length, 1926);
  assert.equal(leaks.filter(isDeep).length, 338); assert.equal(ordinary.filter(isDeep).length, 109);
  for (const row of [...leaks, ...ordinary]) for (const f of [...row.input, ...(row.secret || [])]) assert.ok(Array.from(f).length <= 4, row.id);
});

test('leaks.json through the app adapters: the secret never survives maskText, maskResponseText or cleanFree, findCredentials sees it, and masking is idempotent', () => {
  const failures = []; let n = 0;
  for (const row of leaks) {
    if (isDeep(row)) continue;
    n += 1;
    const input = expand(row); const secret = join(row.secret);
    const out = maskText(input);
    if (out.includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: maskText`);
    else if (findCredentials(input).length === 0) failures.push(`${row.id} ${row.family}/${row.enc}: findCredentials empty`);
    if (maskText(out) !== out) failures.push(`${row.id} ${row.family}/${row.enc}: not idempotent`);
    if (maskResponseText(input).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: maskResponseText`);
    if (cleanFree(input, 100000).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}: cleanFree`);
  }
  assert.equal(n, 3416);
  assert.deepEqual(failures, [], `${failures.length} failed:\n${failures.slice(0, 40).join('\n')}`);
});

test('leaks.json structured probes through the app maskDeep: the secret is gone, the input is not mutated, the result is stable', () => {
  const failures = []; let n = 0;
  for (const row of leaks.filter(isDeep)) {
    n += 1;
    const value = JSON.parse(join(row.input)); const secret = join(row.secret); const snapshot = JSON.stringify(value);
    const out = maskDeep(value);
    if (JSON.stringify(value) !== snapshot) failures.push(`${row.id} input mutated`);
    if (JSON.stringify(out).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}`);
    else if (JSON.stringify(maskDeep(out)) !== JSON.stringify(out)) failures.push(`${row.id} ${row.family}/${row.enc} (not stable)`);
  }
  assert.equal(n, 338);
  assert.deepEqual(failures, [], failures.slice(0, 40).join('\n'));
});

test('leaks.json: the secret does not survive as a maskDeep value or key either', () => {
  const failures = []; let n = 0;
  for (const row of leaks.slice(0, 400)) {
    if (isDeep(row)) continue;
    const input = expand(row); if (input.length > 5000) continue;
    n += 1;
    const secret = join(row.secret);
    if (JSON.stringify(maskDeep({ note: input, list: [input] })).includes(secret) || JSON.stringify(maskDeep({ [input]: 1 })).includes(secret)) failures.push(`${row.id} ${row.family}/${row.enc}`);
  }
  assert.ok(n > 300);
  assert.deepEqual(failures, [], failures.slice(0, 20).join('\n'));
});

test('ordinary.json through the app adapters: every string stays unchanged (maskText, maskResponseText, findCredentials) and every structured value stays equal under maskDeep', () => {
  const changed = []; let text = 0; let deep = 0;
  for (const row of ordinary) {
    const input = join(row.input);
    if (isDeep(row)) { deep += 1; const value = JSON.parse(input); if (JSON.stringify(maskDeep(value)) !== JSON.stringify(value)) changed.push(`${row.id} deep ${input.slice(0, 80)}`); continue; }
    text += 1;
    const out = maskText(input);
    if (out !== input) changed.push(`${row.id} ${JSON.stringify(input.slice(0, 80))} -> ${JSON.stringify(out.slice(0, 80))}`);
    if (maskResponseText(input) !== input) changed.push(`${row.id} response`);
    if (findCredentials(input).length !== 0) changed.push(`${row.id} findCredentials`);
  }
  assert.equal(text, 1817); assert.equal(deep, 109);
  assert.deepEqual(changed, [], `${changed.length} of ${ordinary.length} changed:\n${changed.slice(0, 40).join('\n')}`);
});
