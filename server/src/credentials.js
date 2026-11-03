// Credential-shaped text: the app's names (cleanFree, findCredentials, maskText, maskResponseText) over the one shared masker (see mask.js).
// Detection, decoding, hidden-character deletion and look-alike folding all live in the shared module; the only detection kept here is the small guard below.
// Masking is a heuristic: it catches the common shapes and plain-language secrets listed in the README, not every secret.
import { maskText as sharedMaskText } from './mask.js';

// Visitor free text is cut to this many characters AFTER it is masked.
export const MAX_FREE = 400;
// A response string is never legitimately longer than this: maskResponseText cuts a longer one (after masking it) and says so.
export const MAX_SCAN = 20000;


// APP GUARD for one documented limit of the shared masker (reported to its owner; delete this block when the masker covers it): a credential WORD, a separator and a
// ONE-LETTER value is not found there ("password - x", "password: x"), nor is the short password of a "login: name / x" pair. The two shapes below are masked
// here, linear patterns only (white space and separators are disjoint classes). Everything else is the shared masker's.
//   1. word, optional blanks (any white space but a line break, so U+1680 and the other Unicode spaces count), a separator ( : = - en dash em dash | / > ), optional spaces, a value that is a single letter and ends the token (a digit, a symbol or two letters are NOT taken: "Password: at least 8", "token: 3 days", "password = $1" stay readable)
//   2. login / user / username / account, a separator, a name, a slash or bar, a single letter ("login: bob / x")
// Matching is done on a view with percent-escapes decoded (three rounds), NFKC applied and the invisible and format characters removed, so a zero-width space or U+1680 cannot split the word; when nothing matches the
// text is returned exactly as the shared masker left it. The trade-off is in the README: "token - a" is masked too, and a password of one digit or two characters after a bare separator is NOT found.
const GUARD_SHORT = /(?<![\p{L}\p{N}])(?:password|passwd|passphrase|passcode|pwd|pw|secret|token|api[ _-]?key|apikey|credentials?|creds?)s?[^\S\r\n]*[:=\-\u2013\u2014|/>]+[^\S\r\n]*\p{L}(?![^\s])/giu;
const GUARD_PAIR = /(?<![\p{L}\p{N}])(?:login|user|username|account)[^\S\r\n]*[:=\-\u2013\u2014|>]+[^\S\r\n]*[^\s/|]{1,64}[^\S\r\n]*[/|][^\S\r\n]*\p{L}(?![^\s])/giu;
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Cc}]/gu;
const GUARD_TEST = /(?:password|passwd|passphrase|passcode|pwd|pw|secret|token|key|credential|cred|login|user|account)/i;
// Percent-escapes are decoded (up to three rounds, as the shared masker does for its own shapes) so "password%20-%20x" is read as "password - x".
const PCT_RUN = /(?:%[0-9a-fA-F]{2})+/g;
const unescapeRuns = (t) => t.replace(PCT_RUN, (run) => { try { return decodeURIComponent(run); } catch { return run; } });
function guard(text) {
  if (text.length === 0 || text.length > MAX_GUARDED) return text;
  let view = text;
  for (let round = 0; round < 3 && view.includes('%'); round += 1) { const next = unescapeRuns(view); if (next === view) break; view = next; }
  view = view.normalize('NFKC').replace(INVISIBLE, (c) => (/[\t\n\r]/.test(c) ? c : ''));
  if (!GUARD_TEST.test(view)) return text;
  const out = view.replace(GUARD_SHORT, '[masked:short-value]').replace(GUARD_PAIR, '[masked:short-value]');
  return out === view ? text : out;
}
const MAX_GUARDED = 250_000;

// Masked text: the shared masker, then the guard above.
export function maskText(input) {
  return guard(sharedMaskText(input == null ? '' : String(input)));
}

// Masked text for a RESPONSE string: masked whole first, then cut to MAX_SCAN with the cut said in the text.
export function maskResponseText(text) {
  const masked = maskText(text);
  return masked.length > MAX_SCAN ? `${masked.slice(0, MAX_SCAN)}[cut at ${MAX_SCAN} characters]` : masked;
}

// "Is there a credential in this text": a list with one whole-text span when there is, else an empty list. Every caller only asks whether it is empty.
export function findCredentials(text) {
  const s = text === undefined || text === null ? '' : String(text);
  return s.length > 0 && maskText(s) !== s ? [{ start: 0, end: s.length, id: 'credential' }] : [];
}

// Free text from the visitor: masked first, then white space collapsed and the result cut to `max` characters (code points), so a secret that
// straddles the cut is masked, never half shown.
export function cleanFree(value, max = MAX_FREE) {
  return Array.from(maskText(value).replace(/\s+/g, ' ').trim()).slice(0, max).join('');
}
