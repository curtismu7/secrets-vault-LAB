// Defence in depth: every API response passes through maskDeep, so a credential-shaped value can never leave in any field even if a code path
// forgot to clean its input. Iterative: a deep structure cannot overflow the stack. The generic long-blob detector is NOT applied here
// (ids, hashes and trace ids are long and legitimate); the specific token, key, bearer and assignment detectors are, on the SAME normalised text
// the input cleaner uses (hidden characters deleted, percent-escapes decoded). Visitor text is already fully cleaned on the way in by cleanFree.
import { maskResponseText } from './credentials.js';

const OPAQUE = new Set(['hash', 'traceparent', 'traceId']);
export { maskResponseText };

// Object KEYS are masked too (a key can carry what a visitor typed); two keys that mask to the same text are kept apart with a suffix, and a key such as
// "__proto__" is set as an own property, never as a prototype.
export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const put = (obj, key, v) => Object.defineProperty(obj, key, { value: v, enumerable: true, writable: true, configurable: true });
  const keyCache = new Map();
  const maskKey = (k) => { let m = keyCache.get(k); if (m === undefined) { m = maskResponseText(k); keyCache.set(k, m); } return m; };
  const root = { v: clone(value) };
  const work = [[value, root, 'v', false]];
  while (work.length) {
    const [src, dst, key, opaque] = work.pop();
    if (typeof src === 'string') { put(dst, key, opaque ? src : maskResponseText(src)); continue; }
    if (src === null || typeof src !== 'object') { put(dst, key, src); continue; }
    const copy = clone(src); put(dst, key, copy);
    const isArr = Array.isArray(src);
    const used = new Set();
    for (const k of Object.keys(src).reverse()) {
      let nk = isArr ? k : maskKey(k);
      for (let n = 2; used.has(nk); n += 1) nk = `${maskKey(k)}~${n}`;
      used.add(nk);
      work.push([src[k], copy, nk, OPAQUE.has(k)]);
    }
  }
  return root.v;
}
