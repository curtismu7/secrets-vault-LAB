import test from 'node:test';
import assert from 'node:assert/strict';
import { post, withServer } from './helpers.js';

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
