// W3C Trace Context helpers (Rule 14 family standard): one trace id per evaluation, a new span id per hop. A valid
// incoming `traceparent` header continues its trace; anything else starts a new one. Nothing is sent anywhere —
// values are random, mock, and carry no meaning outside the app. Family shared service (owner, 2026-11-13):
// vendor it, never edit a lab's copy. (Token-redaction tracing stays lab-specific; only the traceparent half is shared.)
import { randomBytes } from 'node:crypto';

const TP = /^00-([0-9a-f]{32})-([0-9a-f]{16})-([0-9a-f]{2})$/;
const ZERO32 = '0'.repeat(32);
const ZERO16 = '0'.repeat(16);

export function parseTraceparent(v) {
  if (typeof v !== 'string' || v.length !== 55) return null;
  const m = TP.exec(v);
  return m && m[1] !== ZERO32 && m[2] !== ZERO16 ? { traceId: m[1], parentId: m[2], flags: m[3] } : null;
}
export const formatTraceparent = (traceId, spanId, flags = '01') => `00-${traceId}-${spanId}-${flags}`;

export function newTrace(incoming, rand = randomBytes) {
  const p = parseTraceparent(incoming);
  const span = () => rand(8).toString('hex').replace(/^0{16}$/, '0000000000000001');
  return { traceId: p ? p.traceId : rand(16).toString('hex').replace(/^0{32}$/, `${'0'.repeat(31)}1`), parentId: p ? p.parentId : null, span };
}
