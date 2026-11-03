// Copied unchanged from the canonical shared-masker, commit 9bc664a, version 1.4.0 (below this line). Do not edit here: fixes go to shared-masker, then re-copy.
// shared-masker/hygiene.js - small pure helpers for the HTTP edge of the standalone demo apps. No dependencies, no I/O, never throws on malformed input.
// Pair with mask.js. docs/EXPRESS-RECIPE.md shows the wiring.
import { isCredentialId, maskText, createStats } from './mask.js';

export const CHARSET_UNSUPPORTED = 'unsupported_charset';
export const RESERVED_PREFIXES = Object.freeze(['assets', 'static', 'api']);

// isPageAddress(path[, { reserved }]) -> boolean. True only for a path an app may answer with its single-page HTML shell:
//   - a string starting with a single "/" (the query string and fragment, if any, are ignored);
//   - percent-decodable (so "/%" and "/%zz" are not), and not double-encoded (a valid %XX left after one decode is refused);
//   - no backslash, no control character, no empty segment other than the trailing slash;
//   - no segment that is "." or ".." or starts with a dot (dotfiles: /.git/config, /.well-known/x);
//   - no extension in the LAST segment (/favicon.ico, /robots.txt, /foo.map, /sitemap.xml);
//   - the first segment is not reserved (default: assets, static, api), so "/assets" and "/assets/" are static or API territory, not pages.
export function isPageAddress(path, opts) {
  try {
    if (typeof path !== 'string' || path.length === 0 || path.length > 2048) return false;
    let p = path;
    const cut = p.search(/[?#]/);
    if (cut >= 0) p = p.slice(0, cut);
    if (p[0] !== '/') return false;
    let d;
    try { d = decodeURIComponent(p); } catch { return false; }
    if (/%[0-9a-fA-F]{2}/.test(d)) return false;
    if (d.includes('\\') || /[\x00-\x1f\x7f-\x9f]/.test(d)) return false;
    if (d === '/') return true;
    const segs = d.slice(1).split('/');
    if (segs[segs.length - 1] === '') segs.pop();
    const reserved = opts && Array.isArray(opts.reserved) ? opts.reserved : RESERVED_PREFIXES;
    for (let i = 0; i < segs.length; i += 1) {
      const s = segs[i];
      if (s === '' || s.startsWith('.')) return false;
      if (i === 0 && reserved.includes(s.toLowerCase())) return false;
    }
    if (segs.length === 0) return false;
    if (segs[segs.length - 1].includes('.')) return false;
    return true;
  } catch {
    return false;
  }
}

// charsetProblem(contentType) -> null | 'unsupported_charset'. null when there is no content type, no charset parameter, or the charset is utf-8 / utf8
// (any case, optional quotes). Anything else returns the FIXED code; the offending value is never part of the answer, so a caller can answer 415 and log
// nothing the visitor typed.
// Parameters are split on ';' outside double quotes (a quoted-string may hold ';' and 'charset=' text and backslash-escaped quotes), as RFC 9110 reads them.
function splitParams(ct) {
  const parts = [];
  let cur = '';
  let q = false;
  for (let i = 0; i < ct.length; i += 1) {
    const ch = ct[i];
    if (q) {
      cur += ch;
      if (ch === '\\' && i + 1 < ct.length) { i += 1; cur += ct[i]; } else if (ch === '"') q = false;
    } else if (ch === '"') { q = true; cur += ch; } else if (ch === ';') { parts.push(cur); cur = ''; } else cur += ch;
  }
  parts.push(cur);
  return q ? null : parts; // an unterminated quoted string is a malformed header
}
export function charsetProblem(contentType) {
  try {
    if (contentType === undefined || contentType === null || contentType === '') return null;
    if (typeof contentType !== 'string') return CHARSET_UNSUPPORTED;
    if (contentType.length > 1024) return CHARSET_UNSUPPORTED;
    const parts = splitParams(contentType);
    if (parts === null) return CHARSET_UNSUPPORTED;
    let seen = 0;
    for (let i = 1; i < parts.length; i += 1) {
      const eq = parts[i].indexOf('=');
      const name = (eq < 0 ? parts[i] : parts[i].slice(0, eq)).trim().toLowerCase();
      if (name !== 'charset') continue;
      seen += 1;
      if (eq < 0) return CHARSET_UNSUPPORTED;
      let v = parts[i].slice(eq + 1).trim();
      if (v.length >= 2 && v[0] === '"' && v[v.length - 1] === '"') v = v.slice(1, -1);
      v = v.toLowerCase();
      if (v !== 'utf-8' && v !== 'utf8') return CHARSET_UNSUPPORTED;
    }
    return seen > 1 ? CHARSET_UNSUPPORTED : null;
  } catch {
    return CHARSET_UNSUPPORTED;
  }
}

// Method tables. routes is { "/api/thing": ["GET", "POST"], "/api/workspaces/:id": ["GET"] }.
// Lookup normalises case (paths and methods) and ONE trailing slash; ":name" matches exactly one segment. HEAD is allowed wherever GET is.
const normPath = (p) => {
  let s = String(p).toLowerCase();
  if (s.length > 1 && s.endsWith('/')) s = s.slice(0, -1);
  return s;
};
// Express routes neither an empty segment nor a double slash ("/api/w//", "//"), so they are not in any table: a 404, not a 405.
const hasEmptySegment = (p) => p.includes('//');
export function buildMethodTable(routes) {
  const exact = new Map();
  const params = [];
  if (routes && typeof routes === 'object') {
    for (const key of Object.keys(routes)) {
      const list = Array.isArray(routes[key]) ? routes[key] : [routes[key]];
      const set = new Set();
      for (const m of list) if (typeof m === 'string' && m) set.add(m.toUpperCase());
      if (set.has('GET')) set.add('HEAD');
      const allow = [...set].sort();
      const path = normPath(key);
      if (path.includes(':')) params.push({ segs: path.split('/'), allow });
      else exact.set(path, allow);
    }
  }
  return { exact, params };
}
// allowFor(table, path) -> { allow: [...] } | null (null: the path is not in the table, so it is a 404 not a 405). `table` may be the result of buildMethodTable
// or the plain routes object itself (it is compiled once and cached).
const compiled = new WeakMap();
function asTable(t) {
  if (!t || typeof t !== 'object') return null;
  if (t.exact instanceof Map) return t;
  let c = compiled.get(t);
  if (!c) { c = buildMethodTable(t); compiled.set(t, c); }
  return c;
}
export function allowFor(routes, path) {
  try {
    const table = asTable(routes);
    if (typeof path !== 'string' || !table) return null;
    const raw = path.split(/[?#]/, 1)[0];
    if (hasEmptySegment(raw)) return null;
    const p = normPath(raw);
    const hit = table.exact.get(p);
    if (hit) return { allow: [...hit] };
    const segs = p.split('/');
    for (const r of table.params) {
      if (r.segs.length !== segs.length) continue;
      let ok = true;
      for (let i = 0; i < segs.length && ok; i += 1) if (!r.segs[i].startsWith(':') && r.segs[i] !== segs[i]) ok = false;
      if (ok) return { allow: [...r.allow] };
    }
    return null;
  } catch {
    return null;
  }
}
// methodNotAllowed(table, method, path) -> { allow } when the path is known and the method is not allowed (answer 405 with an Allow header), else null.
export function methodNotAllowed(table, method, path) {
  const hit = allowFor(table, path);
  if (!hit) return null;
  const m = typeof method === 'string' ? method.toUpperCase() : '';
  return hit.allow.includes(m) ? null : hit;
}

// safeWorkspaceId(id) -> the id when it is safe to use as a workspace key, else null. Refuses anything isCredentialId flags. The allowed pattern is "w-" followed
// by 2 to 60 letters, digits or hyphens that include a letter, or a date / run-number id (digits and hyphens only, at most 12 digits: w-20261101-1530,
// w-2026-11-01-1530, w-1530). A credential word may be part of a lab name (w-password-reset, w-token-exchange, w-pw); it is refused only when a
// 3+ character segment with a digit follows it (w-password-abc123), which is what a typed secret looks like. Never echo a refused id.
const KEYWORD_SEGMENTS = new Set(['password', 'passwd', 'passphrase', 'passcode', 'pwd', 'pw', 'secret', 'token', 'bearer', 'credential', 'credentials', 'apikey', 'privatekey']);
// Names of weaker credential words: a segment after one of these is refused only when it mixes letters and digits (w-key-rotation-2 and w-session-2026 stay).
const WEAK_KEYWORD_SEGMENTS = new Set(['key', 'auth', 'authorization', 'session', 'cookie', 'login', 'sid', 'jwt', 'psk', 'pin', 'otp', 'sig', 'signature', 'secrets', 'tokens', 'passwords', 'creds', 'cred']);
const GLUED_KEYWORDS = ['password', 'passwd', 'passphrase', 'passcode', 'secret', 'token', 'bearer', 'credential', 'apikey', 'privatekey'];
const WS_ID_LETTER = /^w-(?=[A-Za-z0-9-]*[A-Za-z])[A-Za-z0-9-]{2,60}$/;
// digit runs separated by single hyphens (at most 6 runs, an optional trailing hyphen is refused below). Written without a nested quantifier: the form (?:\d+-?){1,6}
// backtracks catastrophically on a long digit run that then fails to match (w-111...1!).
const WS_ID_DIGITS = /^w-\d+(?:-\d+){0,5}-?$/;
// A lab name made only of lower-case words and short numbers (w-password-reset-2, w-secret-handling-4, w-token-bucket-demo) may hold a credential word. When the
// masker flags such a name it is only because a keyword is followed by a word and a digit; any other detector (a prefix token, an opaque run, a JWT ...) still refuses it.
const LAB_NAME = /^w(?:-(?:[a-z]{2,20}|\d{1,4})){1,12}$/;
function onlyKeywordShapes(id) {
  const st = createStats();
  maskText(id, { stats: st });
  const ids = Object.keys(st.byDetector);
  return ids.length > 0 && ids.every((k) => k === 'shape' || k === 'phrase' || k === 'assignment');
}
export function safeWorkspaceId(id) {
  try {
    if (typeof id !== 'string' || id.length > 64) return null;
    const digitsOnly = WS_ID_DIGITS.test(id) && !id.endsWith('-') && (id.match(/\d/g) || []).length <= 12 && !id.includes('--');
    if (!WS_ID_LETTER.test(id) && !digitsOnly) return null;
    if (isCredentialId(id) && !(LAB_NAME.test(id) && onlyKeywordShapes(id))) return null;
    const segs = id.toLowerCase().split('-');
    for (let i = 0; i < segs.length; i += 1) {
      const strong = KEYWORD_SEGMENTS.has(segs[i]);
      const weak = !strong && WEAK_KEYWORD_SEGMENTS.has(segs[i]);
      if (strong || weak) {
        let j = i + 1;
        while (j < segs.length && segs[j] === '') j += 1; // "w-password--hunter2xyz": an empty segment does not hide the one after it
        const next = j < segs.length ? segs[j] : '';
        if (next.length >= 3 && /\d/.test(next) && (strong || /[a-z]/.test(next))) return null;
      }
      // a keyword glued to the secret: w-passwordhunter2xyz, w-secrethunter2xyz, w-hunter2xyzpassword
      for (const kw of GLUED_KEYWORDS) {
        if (segs[i].length > kw.length + 2 && segs[i].startsWith(kw) && /\d/.test(segs[i].slice(kw.length))) return null;
        if (segs[i].length > kw.length + 2 && segs[i].endsWith(kw) && /\d/.test(segs[i].slice(0, -kw.length))) return null;
      }
    }
    return id;
  } catch {
    return null;
  }
}

// createHttpHygiene({ routes, pageHandler, onError, workspaceId }) -> { handle(req, res, next) }: the whole edge of a plain node:http server (no Express), in the order of
// docs/NODE-HTTP-RECIPE.md. For every request, in this order:
//   1. charset: a Content-Type charset other than utf-8 is answered 415 {"error":"unsupported_charset"}; the header value is never read into the answer or the log;
//   2. method: a path in the route table with a method the table does not list is answered 405 {"error":"method_not_allowed"} with Allow (case and ONE trailing slash are
//      normalised; HEAD is allowed wherever GET is);
//   3. a path in the table with an allowed method is the app's own: the workspace id is checked first (workspaceId(req), default the x-workspace header; one that
//      isCredentialId flags is answered 400 {"error":"bad_workspace"}, before any slot exists and without echoing it), then next(req, res) is called. Without `next`,
//      handle() returns false and the caller routes the request itself;
//   4. any other GET / HEAD for a page address (isPageAddress) from a client that accepts text/html goes to pageHandler(req, res): the single-page-app fallback and nothing
//      else. /assets and /assets/ are not page addresses;
//   5. everything else is answered 404 {"error":"not_found"} (JSON, the path is never echoed).
// A handler (pageHandler or next) that throws or returns a rejected promise gets the catch-all answer: status 400, 413 or 415 when the error carries exactly that
// status, else 500, with the fixed codes bad_request, too_large, unsupported_charset, internal. err.message and err.stack are never read. onError({ status, code }) is called
// with those two fixed values only (a logger can print them); a throwing onError is ignored. handle() never throws and returns true when it answered or delegated.
const FIXED = Object.freeze({
  unsupported_charset: [415, '{"error":"unsupported_charset"}'],
  method_not_allowed: [405, '{"error":"method_not_allowed"}'],
  bad_workspace: [400, '{"error":"bad_workspace"}'],
  not_found: [404, '{"error":"not_found"}'],
  bad_request: [400, '{"error":"bad_request"}'],
  too_large: [413, '{"error":"too_large"}'],
  internal: [500, '{"error":"internal"}'],
});
const ERROR_CODE = Object.freeze({ 400: 'bad_request', 413: 'too_large', 415: 'unsupported_charset' });
export function createHttpHygiene(options) {
  const { routes, pageHandler, onError, workspaceId } = options || {};
  if (pageHandler !== undefined && typeof pageHandler !== 'function') throw new TypeError('pageHandler must be a function (req, res)');
  if (onError !== undefined && typeof onError !== 'function') throw new TypeError('onError must be a function ({ status, code })');
  if (workspaceId !== undefined && typeof workspaceId !== 'function') throw new TypeError('workspaceId must be a function (req) => string | undefined');
  const table = asTable(routes || {});
  const note = (status, code) => { if (onError) { try { onError({ status, code }); } catch { /* a logger that fails must not break the answer */ } } };
  const send = (res, code, headers) => {
    const [status, body] = FIXED[code];
    note(status, code);
    try {
      if (res.headersSent || res.writableEnded) { if (!res.writableEnded) res.end(); return; }
      res.writeHead(status, { 'content-type': 'application/json; charset=utf-8', 'x-content-type-options': 'nosniff', 'cache-control': 'no-store', ...headers });
      res.end(body);
    } catch { try { res.destroy(); } catch { /* nothing left to do */ } }
  };
  const fail = (res, err) => {
    let status = 500;
    try { if (err && (err.status === 400 || err.status === 413 || err.status === 415)) status = err.status; } catch { /* a hostile err object is a 500 */ }
    send(res, ERROR_CODE[status] || 'internal');
  };
  const run = (fn, req, res) => {
    try {
      const r = fn(req, res);
      if (r && typeof r.then === 'function') r.then(undefined, (err) => fail(res, err));
    } catch (err) {
      fail(res, err);
    }
  };
  const header = (req, name) => { const v = req && req.headers ? req.headers[name] : undefined; return typeof v === 'string' ? v : undefined; };
  function handle(req, res, next) {
    try {
      const url = req && typeof req.url === 'string' ? req.url : '/';
      const pathname = url.split(/[?#]/, 1)[0];
      if (charsetProblem(req.headers ? req.headers['content-type'] : undefined)) { send(res, 'unsupported_charset'); return true; }
      const method = typeof req.method === 'string' ? req.method.toUpperCase() : 'GET';
      const miss = methodNotAllowed(table, method, pathname);
      if (miss) { send(res, 'method_not_allowed', { allow: miss.allow.join(', ') }); return true; }
      if (allowFor(table, pathname)) {
        const raw = workspaceId ? workspaceId(req) : header(req, 'x-workspace');
        if (raw !== undefined && raw !== '' && (typeof raw !== 'string' || isCredentialId(raw))) { send(res, 'bad_workspace'); return true; }
        if (typeof next !== 'function') return false;
        run(next, req, res);
        return true;
      }
      if (pageHandler && (method === 'GET' || method === 'HEAD') && (header(req, 'accept') || '').includes('text/html') && isPageAddress(pathname)) { run(pageHandler, req, res); return true; }
      send(res, 'not_found');
      return true;
    } catch (err) {
      fail(res, err);
      return true;
    }
  }
  return Object.freeze({ handle });
}
