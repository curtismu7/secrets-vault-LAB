// Defence in depth: every API response passes through maskDeep, so a credential-shaped value can never leave in any field even if a code path
// forgot to clean its input. Iterative: a deep structure cannot overflow the stack. The generic long-blob detector is NOT applied here
// (ids, hashes and trace ids are long and legitimate); the specific token, key, bearer and assignment detectors are, on the SAME normalised text
// the input cleaner uses (hidden characters deleted, percent-escapes decoded). Visitor text is already fully cleaned on the way in by cleanFree.
import { maskResponseText } from './credentials.js';

const OPAQUE = new Set(['hash', 'traceparent', 'traceId']);
export { maskResponseText };

export function maskDeep(value) {
  const clone = (x) => (Array.isArray(x) ? [] : x && typeof x === 'object' ? {} : x);
  const root = { v: clone(value) };
  const work = [[value, root, 'v', false]];
  while (work.length) {
    const [src, dst, key, opaque] = work.pop();
    if (typeof src === 'string') { dst[key] = opaque ? src : maskResponseText(src); continue; }
    if (src === null || typeof src !== 'object') { dst[key] = src; continue; }
    const copy = clone(src); dst[key] = copy;
    for (const k of Object.keys(src).reverse()) work.push([src[k], copy, k, OPAQUE.has(k)]);
  }
  return root.v;
}
