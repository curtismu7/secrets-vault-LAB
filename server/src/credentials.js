// Credential-shaped text: the app's names (cleanFree, findCredentials, maskText, maskResponseText) over the one shared masker (see mask.js).
// Detection, decoding, hidden-character deletion and look-alike folding all live in the shared module; nothing is detected here.
// Masking is a heuristic: it catches the common shapes and plain-language secrets listed in the README, not every secret.
import { maskText, looksLikeCredential } from './mask.js';

// Visitor free text is cut to this many characters AFTER it is masked.
export const MAX_FREE = 400;
// A response string is never legitimately longer than this: maskResponseText cuts a longer one (after masking it) and says so.
export const MAX_SCAN = 20000;

export { maskText };

// Masked text for a RESPONSE string: masked whole first, then cut to MAX_SCAN with the cut said in the text.
export function maskResponseText(text) {
  const masked = maskText(text);
  return masked.length > MAX_SCAN ? `${masked.slice(0, MAX_SCAN)}[cut at ${MAX_SCAN} characters]` : masked;
}

// "Is there a credential in this text": a list with one whole-text span when there is, else an empty list. Every caller only asks whether it is empty.
export function findCredentials(text) {
  const s = text === undefined || text === null ? '' : String(text);
  return s.length > 0 && looksLikeCredential(s) ? [{ start: 0, end: s.length, id: 'credential' }] : [];
}

// Free text from the visitor: masked first, then white space collapsed and the result cut to `max` characters (code points), so a secret that
// straddles the cut is masked, never half shown.
export function cleanFree(value, max = MAX_FREE) {
  return Array.from(maskText(value).replace(/\s+/g, ' ').trim()).slice(0, max).join('');
}
