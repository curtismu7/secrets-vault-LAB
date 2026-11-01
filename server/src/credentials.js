// Credential-shaped text. Anything a visitor types that looks like a token, a key, a password or key material is masked on the way IN
// (reason, comment) so the raw value never enters state, a receipt, an outbox entry, a hop pane, a log line or an error.
// Lab-written detectors; linear patterns only (no nested quantifiers), run on input capped at MAX_FREE characters.
export const MAX_FREE = 400;

// ONE normaliser for everything that decides whether text looks like a credential: the input cleaner, the name and id refusals, and the response mask.
//   1. NFKC (fullwidth look-alikes, including the fullwidth percent sign, become the ASCII they imitate)
//   2. every default-ignorable code point, every format character (Cf) and U+FFFD is DELETED, so nothing can be interleaved to hide a token:
//      U+3164 U+FFA0 U+115F U+1160 U+034F U+180E U+FE00-FE0F U+E0000-E007F U+061C U+206A-206F U+17B4 U+0600-0605 U+06DD U+070F and the zero-width and bidi ones
//   3. every C0 and C1 control character EXCEPT tab, line feed and carriage return is DELETED too, never turned into a space ("p<U+0001>a<U+0001>ss" is
//      "pass"). Tab, LF, CR, U+2028 and U+2029 stay: they are separators, handled by the second look below.
//   4. ASCII percent-escapes decoded, up to four rounds (a value percent-encoded up to four times is matched in its decoded form); every round is followed
//      by steps 1-3 again, so a control character that a decode produces is deleted as well.
// Returns the normalised text; matching and masking run on it (so a masked answer shows the decoded, masked text).
const HIDDEN = /[\p{Default_Ignorable_Code_Point}\p{Cf}�]/gu;
const CONTROLS = /[\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F]/g; // C0 and C1 except tab (09), line feed (0A) and carriage return (0D)
const PCT = /%([0-9a-fA-F]{2})/g;
const PCT_RUN = /(?:%[0-9a-fA-F]{2})+/g;
const asciiOnly = (run) => run.replace(PCT, (m, h) => { const c = parseInt(h, 16); return c < 0x80 ? String.fromCharCode(c) : m; });
// A run of escapes is decoded as UTF-8 (so %C2%85, a C1 control, and %E2%80%8B, a zero-width space, become the characters tidy() deletes); a run that is not valid
// UTF-8 falls back to its ASCII escapes only.
const pctRound = (t) => t.replace(PCT_RUN, (run) => { try { return decodeURIComponent(run); } catch { return asciiOnly(run); } });
const tidy = (t) => t.normalize('NFKC').replace(HIDDEN, '').replace(CONTROLS, '');
export function normalizeText(input, limit = MAX_SCAN) {
  let t = tidy(String(input ?? '').slice(0, limit));
  for (let round = 0; round < 4; round++) {
    const n = tidy(pctRound(t));
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
  // user info that is only a token (https://TOKEN@host); a plain user name before the @ is over-masked on purpose
  D('url-userinfo', /\b[a-zA-Z][a-zA-Z0-9+.-]{1,20}:\/\/[^\s/?#@]{1,200}@(?=[A-Za-z0-9[])/g),
  // user:password@host WITHOUT a scheme, also after a bare "//" ("bob:pw@host.example"). The look-behind starts a match only at the beginning of a run of name
  // characters, so this stays linear; "mailto:" and a time such as 12:30 followed by something other than a host are left alone.
  D('userinfo-bare', /(?<![A-Za-z0-9._%+-])(?!mailto:)[A-Za-z0-9._%+-]{1,100}:[^\s/?#@:]{1,200}(?=@[A-Za-z0-9[])/gi),
  D('github-token', /\b(?:gh[pousr]_[A-Za-z0-9]{6,}|github_pat_[A-Za-z0-9_]{6,})/g),
  D('gitlab-token', /\bglpat-[A-Za-z0-9_-]{6,}/g),
  D('slack-token', /\bxox[abprs]-[A-Za-z0-9-]{6,}/g),
  D('aws-key', /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g),
  D('google-token', /\b(?:ya29\.[A-Za-z0-9_-]{8,}|AIza[0-9A-Za-z_-]{20,})/g),
  D('api-key', /\bsk-[A-Za-z0-9_-]{8,}/g),
  D('jwt', /\beyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}/g),
  // Bearer/Basic and a value: 10 or more characters, or 6 or more when it contains a digit ("Bearer hunter2xyz"; "Bearer tokens" stays readable)
  D('bearer', /\b(?:Bearer|Basic)\s+(?:[A-Za-z0-9._~+/=-]{10,}|(?=[A-Za-z0-9._~+/=-]*\d)[A-Za-z0-9._~+/=-]{6,})/gi),
  // A credential word, then only whitespace (no ":" or "="), then a value of 6 or more characters that contains a digit: "password hunter2xyz", "pw hunter2xyz",
  // "api key hunter2xyz", "token abcdef1234". The digit requirement is the false-positive trade-off: "password reset" and "the token requirements" stay readable,
  // while "password reset99" is masked. A value without a digit after a bare space ("password correcthorse") is NOT found (the page says so).
  D('keyword-space', /(?<![A-Za-z0-9])(?:password|passwd|passphrase|pwd|pw|secret|token|api[_ -]?key|apikey|credentials?|private[_ -]?key|access[_ -]?key|session[_ -]?id)s?\s{1,20}["']?(?=[^\s"',;{}]*\d)[^\s"',;{}]{6,}/gi),
  // a bare "key" needs a separator or "is" ("the key is <value>", "key=<value>"), and a digit in the value, so "the key is held by the provider" is left alone
  D('key-is', /(?<![A-Za-z0-9])keys?["']?\s*(?:[:=]|\bis\b|\bwas\b)\s*["']?(?=[^\s"',;{}]*\d)[^\s"',;{}]{3,}/gi),
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
function spansOf(t, generic) {
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

// Tab, line feed, carriage return, U+2028 and U+2029 are separators: a multi-line label stays readable, but a keyword cannot be split by one either. So every
// scan runs twice: on the text as typed and, when that text holds a separator, on the first result with every separator DELETED ("pass<TAB>word=x" is
// "password=x"). The second look only ever adds masking to what the first produced; when it finds nothing the first result stands, so ordinary multi-line
// text is not glued together.
const HAS_SEPARATOR = /[\t\n\r\u2028\u2029]/;
const SEPARATORS = /[\t\n\r\u2028\u2029]/g;
// -> { text, spans }: the text the spans refer to (the normalised text, or the first result with its separators deleted) and the spans to mask in it.
export function inspect(text, { normalised = false, generic = true, limit = MAX_SCAN } = {}) {
  const t = normalised ? String(text).slice(0, limit) : normalizeText(text, limit);
  const first = spansOf(t, generic);
  if (HAS_SEPARATOR.test(t)) {
    const joined = maskSpans(t, first).replace(SEPARATORS, '');
    const second = spansOf(joined, generic);
    if (second.length) return { text: joined, spans: second };
  }
  return { text: t, spans: first };
}
// Spans { start, end, id } over the NORMALISED text (see normalizeText), or over the separator-free text of the second look (see inspect). Callers that only ask
// "is there a credential here" use the length; callers that mask use inspect() so text and spans stay together.
export function findCredentials(text, opts = {}) { return inspect(text, opts).spans; }

export function maskText(input) {
  const { text, spans } = inspect(input);
  return text ? maskSpans(text, spans) : text;
}

// The same, for a RESPONSE string: only the specific detectors (ids, hashes and trace ids are long and legitimate). A string with nothing in it is
// returned exactly as it came; one with a credential is returned in its decoded, masked form.
export function maskResponseText(text) {
  // A response string is never legitimately longer than this; anything longer is cut (and says so) rather than left half-scanned.
  if (text.length > MAX_SCAN) return `${maskResponseText(text.slice(0, MAX_SCAN))}[cut at ${MAX_SCAN} characters]`;
  const { text: t, spans } = inspect(text, { generic: false });
  return spans.length ? maskSpans(t, spans) : text;
}

// Free text from the visitor: normalised (hidden characters and control characters deleted, percent-escapes decoded), credential-shaped runs masked, white
// space collapsed, and only THEN cut to length (a token that straddles the cut is masked, not half shown). Only the first max + 5000 characters are scanned:
// every detector matches at most 4000 characters from where it starts, so a token that begins inside the kept text is masked whole.
export function cleanFree(value, max = MAX_FREE) {
  const { text, spans } = inspect(value, { limit: max + 5000 });
  return maskSpans(text, spans).replace(/\s+/g, ' ').trim().slice(0, max);
}
