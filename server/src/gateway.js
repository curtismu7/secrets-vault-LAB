// The simulated gateway's view of a call, and the simulated BACKEND that logs who actually acted. The backend identifies the caller from the
// credential it receives (it keeps only an HMAC of each credential it issued, never the value), so "who acted" is the credential's owner, not
// something the gateway announces. A shared service account is one credential for everyone, so the backend logs the same identity every time.
// All of this is lab-invented behaviour behind the deck claim "the backend sees who actually acted" (UNVERIFIED).
import { createHmac } from 'node:crypto';
import { findCredentials } from './credentials.js';

export const SHAPES = ['bearer', 'api-key', 'basic', 'headers'];
export const SHAPE_TEXT = {
  bearer: 'Bearer token, sent in the Authorization header with the word Bearer',
  'api-key': 'API key (one header, default X-Api-Key, carries the key)',
  basic: 'Username and password as HTTP Basic: sent in the Authorization header with the word Basic',
  headers: 'Custom header pairs: 1 to 5 header names, each with its own value',
};
export const HEADER_NAME = /^[A-Za-z][A-Za-z0-9-]{0,39}$/;
const FORBIDDEN_HEADERS = new Set(['host', 'content-length', 'transfer-encoding', 'connection', 'cookie', 'set-cookie', 'authorization']);
// A header name is metadata the page shows, so a name that looks like a credential is refused (it would be echoed in the entry's header list).
export const headerNameProblem = (n) => (typeof n !== 'string' || !HEADER_NAME.test(n) || FORBIDDEN_HEADERS.has(n.toLowerCase()) || findCredentials(n).length ? 'bad_header_name' : null);

// The headers the gateway injects for a shape and a decrypted payload (the only place the plaintext is turned into wire form).
export function headersFor(shape, payload, headerName) {
  if (shape === 'bearer') return [['Authorization', `Bearer ${payload.token}`]];
  if (shape === 'api-key') return [[headerName || 'X-Api-Key', payload.key]];
  if (shape === 'basic') return [['Authorization', `Basic ${Buffer.from(`${payload.username}:${payload.password}`, 'utf8').toString('base64')}`]];
  return Object.keys(payload.headers).sort().map((k) => [k, payload.headers[k]]);
}

// What may be shown about an injected header: its name and the scheme word, never the value.
export function maskedHeader([name, value]) {
  const scheme = /^(Bearer|Basic) /.exec(value)?.[1];
  const n = Buffer.byteLength(value, 'utf8');
  return { header: name, shown: `${scheme ? `${scheme} ` : ''}••••••••`, bytes: scheme ? n - scheme.length - 1 : n };
}

export class SimBackend {
  constructor(rand, cap = 5000) { this.key = rand(32); this.registry = new Map(); this.log = []; this.seq = 0; this.cap = cap; }
  tag(targetId, headers) { return createHmac('sha256', this.key).update(`${targetId}\n${headers.map(([k, v]) => `${k.toLowerCase()}: ${v}`).join('\n')}`).digest('hex'); }
  // The target issued this credential to this principal (first registration wins: pasting someone else's credential does not make it yours).
  register(targetId, headers, principal) { const t = this.tag(targetId, headers); if (!this.registry.has(t)) this.registry.set(t, principal); return this.registry.get(t); }
  hasRoom(n = 2) { return this.registry.size + n <= this.cap; }

  // The target's check: does the request carry the right kind of credential, and whose is it?
  handle(target, headers, operation, at, logCap) {
    const lower = new Map(headers.map(([k, v]) => [k.toLowerCase(), v]));
    let status = 200; let principal = null; let outcome = 'served';
    const has = (n) => lower.has(n.toLowerCase());
    const kindOk = target.accepts === 'bearer' ? /^Bearer /.test(lower.get('authorization') || '')
      : target.accepts === 'basic' ? /^Basic /.test(lower.get('authorization') || '')
        : target.accepts === 'api-key' ? has(target.apiKeyHeader || 'X-Api-Key')
          : (target.requiredHeaders || []).every(has);
    if (!kindOk) { status = 401; outcome = 'rejected: wrong kind of credential for this target'; }
    else {
      principal = this.registry.get(this.tag(target.id, headers)) || null;
      if (!principal) { status = 401; outcome = 'rejected: credential not recognised'; }
    }
    const entry = { n: ++this.seq, at, target: target.id, protocol: target.protocol, operation, principal: status === 200 ? principal : null, status, outcome };
    this.log.push(entry); if (this.log.length > logCap) this.log.shift();
    return { status, principal: entry.principal, outcome, entry };
  }
}
