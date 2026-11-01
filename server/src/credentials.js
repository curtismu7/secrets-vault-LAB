// Credential-shaped text. Anything a visitor types that looks like a token, a key, a password or key material is masked on the way IN
// (reason, comment) so the raw value never enters state, a receipt, an outbox entry, a hop pane, a log line or an error.
// Lab-written detectors; linear patterns only (no nested quantifiers), run on input capped at MAX_FREE characters.
export const MAX_FREE = 400;

// ONE normaliser for everything that decides whether text looks like a credential: the input cleaner, the name and id refusals, and the response mask.
//   1. NFKC (fullwidth look-alikes, including the fullwidth percent sign, become the ASCII they imitate)
//   2. every default-ignorable code point, every format character (Cf) and U+FFFD is DELETED, so nothing can be interleaved to hide a token:
//      U+3164 U+FFA0 U+115F U+1160 U+034F U+180E U+FE00-FE0F U+E0000-E007F U+061C U+206A-206F U+17B4 U+0600-0605 U+06DD U+070F and the zero-width and bidi ones
//   3. ASCII percent-escapes decoded, up to three rounds (a value that was percent-encoded once or twice is matched in its decoded form)
// Returns the normalised text; matching and masking run on it (so a masked answer shows the decoded, masked text).
const HIDDEN = /[\p{Default_Ignorable_Code_Point}\p{Cf}�]/gu;
const PCT = /%([0-9a-fA-F]{2})/g;
const pctRound = (t) => t.replace(PCT, (m, h) => { const c = parseInt(h, 16); return c < 0x80 ? String.fromCharCode(c) : m; });
export function normalizeText(input, limit = MAX_SCAN) {
  let t = String(input ?? '').slice(0, limit);
  for (let round = 0; round < 4; round++) {
    const n = pctRound(t.normalize('NFKC').replace(HIDDEN, ''));
    if (n === t) break;
    t = n;
  }
  return t;
}

const D = (id, re) => ({ id, re });
// Lab-written, heuristic detectors: they catch the common shapes, plain-language passwords and keys of 20 characters or more. Not every secret has a
// recognisable shape (a short random password with no keyword before it is not found), and the page says so.
export const DETECTORS = [
  // custom scanner (linear): a BEGIN line, then up to 4000 characters to the END line or the end of the text
  { id: 'private-key', scan: (t) => {
    const out = []; const head = /-----BEGIN [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/g; let m;
    while ((m = head.exec(t)) !== null) {
      const from = m.index + m[0].length; const win = t.slice(from, from + 4000); const e = win.indexOf('-----END');
      let end = e === -1 ? from + win.length : from + e;
      if (e !== -1) { const tail = /^-----END [A-Z0-9 ]{0,40}PRIVATE KEY(?: BLOCK)?-----/.exec(win.slice(e)); end = from + e + (tail ? tail[0].length : 8); }
      out.push({ start: m.index, end, id: 'private-key' }); head.lastIndex = Math.max(end, m.index + 1);
    }
    return out;
  } },
  D('url-userinfo', /\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:\/\/[^/\s:@]{1,100}:[^@\s]{1,200}@/g),
  D('github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{6,}|github_pat_[A-Za-z0-9_]{6,})/g),
  D('gitlab-token', /\bglpat-[A-Za-z0-9_-]{6,}/g),
  D('slack-token', /\bxox[abprs]-[A-Za-z0-9-]{6,}/g),
  D('aws-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g),
  D('google-token', /\b(?:ya29\.[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{20,})/g),
  D('api-key', /\bsk-[A-Za-z0-9_-]{8,}/g),
  D('jwt', /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g),
  D('bearer', /\b(?:Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{10,}/gi),
  // "token abcdef1234567890" (an Authorization header): the word needs a digit, so "token requirements" is left alone
  D('token-word', /\btoken\s+(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{12,}/gi),
  // a passphrase is several words: take the next four
  D('passphrase', /\bpassphrase\s*(?:[:=]|\bis\b)\s*[^\s"',;{}]+(?:[ \t]+[^\s"',;{}]+){0,3}/gi),
  // key-aware: a credential word as a key or label, with the quote (if any) between it and the separator, and the value in any quoting.
  // The value stops at a quote, comma, semicolon, brace or space, so two assignments glued together each match on their own.
  // Credential words: password, passwd, pwd, passphrase, secret, token, api key, private key, access key, account key, secret key (each with a space, hyphen or underscore), cred, credential, passcode, session id (a word before them
  // is allowed, so userPassword and client_secret count), and the short words pw and pass on their own.
  D('assignment', /(?:[A-Za-z0-9_]{0,30}(?:password|passwd|pwd|passphrase|secret|token|api[_ -]?key|apikey|private[_ -]?key|access[_ -]?key|account[_ -]?key|secret[_ -]?key|cred|credential|passcode|session[_-]?id|sessionid)|\bpw|\bpass)s?["']?\s*(?:[:=]|\bis\b)\s*["']?[^\s"',;{}]{3,}/gi),
  // A long run of key characters. Two detectors, both checked in code rather than with a look-ahead (to stay linear): a run of 20 or more of
  // letters, digits, _ and - that has both a letter and a digit (or is 32 or more and is not just lowercase words joined by hyphens), and a run of 32 or
  // more that also uses + / = (base64) unless it is a lowercase path such as a URL path.
  { id: 'key-like', generic: true, re: /[A-Za-z0-9_-]{20,}/g, accept: (m) => (/\d/.test(m) && /[A-Za-z]/.test(m)) || (m.length >= 32 && !/^[a-z]+(?:-[a-z]+)+$/.test(m)) },
  { id: 'long-blob', generic: true, re: /[A-Za-z0-9+/_=-]{32,}/g, accept: (m) => !/^[a-z0-9._-]+(?:\/[a-z0-9._-]+)+$/.test(m) && !/^[a-z]+(?:-[a-z]+)+$/.test(m) },
];

export const MAX_SCAN = 20000;
// Spans { start, end, id } over the NORMALISED text (see normalizeText). Pass already-normalised text with { normalised: true }.
export function findCredentials(text, { normalised = false, generic = true, limit = MAX_SCAN } = {}) {
  const t = normalised ? String(text).slice(0, limit) : normalizeText(text, limit);
  const spans = [];
  for (const d of DETECTORS) {
    if (d.generic && !generic) continue;
    if (d.scan) { spans.push(...d.scan(t)); continue; }
    d.re.lastIndex = 0;
    for (const m of t.matchAll(d.re)) if (!d.accept || d.accept(m[0])) spans.push({ start: m.index, end: m.index + m[0].length, id: d.id });
  }
  return spans;
}

export function maskSpans(text, spans) {
  const sorted = spans.filter((s) => s.end > s.start).sort((a, b) => a.start - b.start || b.end - a.end);
  let out = ''; let at = 0;
  for (const s of sorted) { if (s.start < at) { at = Math.max(at, s.end); continue; } out += `${text.slice(at, s.start)}[masked:${s.id}]`; at = s.end; }
  return out + text.slice(at);
}

export function maskText(input) {
  const t = normalizeText(input);
  return t ? maskSpans(t, findCredentials(t, { normalised: true })) : t;
}

// The same, for a RESPONSE string: only the specific detectors (ids, hashes and trace ids are long and legitimate). A string with nothing in it is
// returned exactly as it came; one with a credential is returned in its decoded, masked form.
export function maskResponseText(text) {
  // A response string is never legitimately longer than this; anything longer is cut (and says so) rather than left half-scanned.
  if (text.length > MAX_SCAN) return `${maskResponseText(text.slice(0, MAX_SCAN))}[cut at ${MAX_SCAN} characters]`;
  const t = normalizeText(text);
  const spans = findCredentials(t, { normalised: true, generic: false });
  return spans.length ? maskSpans(t, spans) : text;
}

// Free text from the visitor: normalised (hidden characters deleted, percent-escapes decoded), other control characters turned into spaces, credential-shaped
// runs masked, and only THEN cut to length (a token that straddles the cut is masked, not half shown). Only the first max + 5000 characters are scanned:
// every detector matches at most 4000 characters from where it starts, so a token that begins inside the kept text is masked whole.
export function cleanFree(value, max = MAX_FREE) {
  const flat = normalizeText(value, max + 5000).replace(/[\u0000-\u001f\u007f-\u009f]/g, ' ');
  return maskSpans(flat, findCredentials(flat, { normalised: true })).replace(/\s+/g, ' ').trim().slice(0, max);
}
