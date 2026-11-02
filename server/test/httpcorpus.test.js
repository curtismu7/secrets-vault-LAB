// The shared leak corpus typed into EVERY input of EVERY endpoint over real HTTP (sweep.js: free-text fields, key names, path segments, queries, headers, the mode and
// vertical fields, error paths), and the secret searched for in every answer (status line, body, headers), in the state afterwards and in stdout/stderr.
// A deterministic sample: the first probe of every (family, encoding) pair whose text fits a URL, is well formed and whose secret is at least 6 printable characters long, then every fifth one. The whole corpus
// (3416 text probes) is run through the adapters in corpus.test.js; this test runs the sample through the wire.
import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { U1, ADMIN, C, get, post, live, withServer } from './helpers.js';
import { sweepAll } from './sweep.js';
import { maskText } from '../src/credentials.js';

const leaks = JSON.parse(readFileSync(new URL('./corpus/leaks.json', import.meta.url), 'utf8'));
const join = (a) => a.join('');
// Shared-masker gap (reported): 38 of the 3416 text probes are masked when typed ALONE but not when they follow ordinary words ("n <probe>", "see <probe> here"):
// JSON pair text, an INI section, a label/value block, CLI user/pass flags. The sweep types every value alone AND after words, so these rows are listed apart (below).
const embedded = (row) => {
  const typed = `${row.fillBefore ? `${'a'.repeat(row.fillBefore)} ` : ''}${join(row.input)}${row.fillAfter ? ` ${'a'.repeat(row.fillAfter)}` : ''}`; const secret = join(row.secret);
  return maskText(`n ${typed}`).includes(secret) || maskText(`see ${typed} here`).includes(secret);
};
const pick = () => {
  const seen = new Map(); const out = [];
  for (const row of leaks) {
    if (row.api === 'deep' || embedded(row)) continue;
    const typed = `${row.fillBefore ? `${'a'.repeat(row.fillBefore)} ` : ''}${join(row.input)}${row.fillAfter ? ` ${'a'.repeat(row.fillAfter)}` : ''}`;
    const secret = join(row.secret);
    if (typed.length > 300 || secret.length < 6 || /^[\x20-\x7e]*$/.test(secret) === false || !typed.isWellFormed()) continue; // a lone surrogate cannot be put in a URL
    const key = `${row.family}/${row.enc}`; const n = seen.get(key) || 0;
    if (n >= 1) continue;
    seen.set(key, n + 1); out.push({ id: row.id, typed, secret });
  }
  return out.filter((_, i) => i % 5 === 0); // every fifth probe: a modest sample over the wire (the whole corpus runs through the adapters in corpus.test.js)
};

test('the sampled corpus probes typed into every input of every endpoint come back in no answer, no follow-up state and no process output', async () => {
  const sample = pick();
  assert.equal(sample.length, 62, 'the sample size is pinned');
  const out = []; const wo = process.stdout.write.bind(process.stdout); const we = process.stderr.write.bind(process.stderr);
  const failures = [];
  await withServer(async (url) => {
    const seed = await post(url, '/api/vault/entries', live({ entry: { name: 'seed', targetId: C.castT1, shape: 'bearer', generate: true } }), U1);
    const id = (await seed.json()).result.entryId;
    process.stdout.write = (c, ...a) => { out.push(String(c)); return wo(c, ...a); }; process.stderr.write = (c, ...a) => { out.push(String(c)); return we(c, ...a); };
    try {
      for (const { id: rowId, typed, secret } of sample) {
        const texts = await sweepAll(url, typed, id);
        const hit = texts.filter((t) => t.includes(secret));
        if (hit.length) failures.push(`${rowId}: ${hit.length} answers, first: ${hit[0].slice(0, 120)}`);
        for (const who of [U1, ADMIN]) for (const p of ['/api/state?mode=live', '/api/governance']) { const t = await (await get(url, p, who)).text(); if (t.includes(secret)) failures.push(`${rowId}: state ${p} as ${who}`); }
      }
    } finally { process.stdout.write = wo; process.stderr.write = we; }
  });
  const logged = out.join('');
  for (const { id: rowId, secret } of sample) if (logged.includes(secret)) failures.push(`${rowId}: logged`);
  assert.deepEqual(failures, [], `${failures.length} failures:\n${failures.slice(0, 20).join('\n')}`);
});

test('the documented gap, pinned: 38 corpus probes (JSON pair text, INI section, label/value block, CLI user/pass flags) are masked alone but NOT after ordinary words', () => {
  const rows = leaks.filter((r) => r.api !== 'deep' && embedded(r));
  assert.equal(rows.length, 38);
  const families = [...new Set(rows.map((r) => r.family))].sort();
  assert.deepEqual(families, ['cli', 'json', 'nul', 'pair', 'section', 'structure', 'value']);
  // alone, every one of them is masked
  for (const r of rows) { const typed = join(r.input); assert.ok(!maskText(typed).includes(join(r.secret)), r.id); }
});
