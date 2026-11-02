// Copied unchanged from the canonical shared-masker, commit 9bc664a, version 1.4.0 (below this line). Do not edit here: fixes go to shared-masker, then re-copy.
// shared-masker/mask.js - the canonical masker for the Ping standalone demo family.
//
// Dependency-free ES module (Node 26; also bundleable for the browser: it uses only String.prototype.normalize, RegExp with \p{..}, Map, Set, WeakSet).
// Masking is a HEURISTIC. It catches the common shapes and plain-language passwords listed in README.md, not every secret: a short random value with no
// keyword in front of it is not found. See README.md "Known limits" and "False-positive trade-offs".
//
// Pipeline (see README.md for the long form):
//   1. NFKC (after a few single-character rewrites that NFKC would otherwise turn into a different letter).
//   2. Delete Default_Ignorable_Code_Point, Cf, Co (private use), Cn (unassigned), noncharacters, U+FFFC, U+2800, U+FFFD, lone surrogates, U+0300-U+036F
//      combining marks and all C0/C1 controls EXCEPT tab, LF, CR, U+2028 and U+2029 (VT, FF, NUL, DEL, U+0085 are deleted). Every other combining mark (Mn,
//      Mc, Me) that sits on a Latin, Greek, Cyrillic, symbol or punctuation base is deleted too. Runs of 33+ combining marks are removed BEFORE NFKC
//      (canonical reordering is quadratic).
//   3. Whitespace views. Every White_Space character (Zs, Zl, Zp, U+1680, NBSP, tab, LF, CR ...) reads as one plain space for value scanning (view F), and
//      the keyword finder tolerates up to three such separators between any two letters of a keyword (CRLF is two), so ordinary multi-line prose stays readable. Header-line
//      detectors run on the text with real line breaks (view B). All views are index-for-index the same length, so spans need no mapping; the masked UNION
//      is rendered once.
//   4. Look-alike letters (Cyrillic, Greek, small capitals, accented Latin and Cyrillic/Greek, ...) are folded to ASCII for matching only, one UTF-16 unit
//      for one unit. The same table folds look-alike separators (colons, arrows, bullets, dashes, quotes) to their ASCII form.
//   5. Percent-encoding (UTF-8 where valid, byte-wise otherwise), %uXXXX, HTML numeric entities (any number of leading zeros, semicolon optional),
//      backslash-u / u{..} / U / x escapes and short CSS escapes typed as text are decoded repeatedly until the text stops changing (at most MAX_ROUNDS rounds,
//      MAX_GROWTH x the input size and a total scan budget). If it still changes after a bound the WHOLE value is masked as [masked:undecodable]. Every
//      round is masked in turn on top of the previous round's result, so a credential visible in an early round and one hidden under an encoding are both
//      masked and ONE result is returned.
//   6. MASK BEFORE ANY TRUNCATION: callers must call maskText first and cut the result afterwards (a secret after 19,990 filler characters, or one that
//      straddles the cut, must never be half shown). Input over opts.maxChars is masked WHOLE as [masked:oversize]; this module never cuts silently.
//
// All scans are linear or bounded: no regular expression nests an unbounded quantifier in another, keyword hits are consumed so a hit is never rescanned,
// value ends come from one precomputed break table, values are judged on a bounded sample, and trimming is done by index loops. `stats.work` counts the
// units of work so tests can assert a bound that does not depend on the clock (the tests also bound CPU time).

export class MaskUsageError extends TypeError {
  constructor(message) {
    super(message);
    this.name = 'MaskUsageError';
    this.code = 'ERR_MASK_USAGE';
  }
}

export const LIMITS = Object.freeze({
  MAX_CHARS: 1_000_000, // default opts.maxChars: longer input is masked whole
  HARD_MAX_CHARS: 4_000_000, // opts.maxChars may not exceed this
  MAX_ROUNDS: 10, // decode rounds
  MAX_GROWTH: 5, // a decode round may not exceed this multiple of the input size
  SCAN_FACTOR: 4, // total characters scanned over all decode rounds may not exceed SCAN_FACTOR x the input + SCAN_FLOOR
  SCAN_FLOOR: 65536,
  MAX_DEPTH: 32, // maskDeep default opts.maxDepth
  MAX_NODES: 20000, // maskDeep default opts.maxNodes
  MAX_TOTAL_CHARS: 1_000_000, // maskDeep default opts.maxTotalChars: characters of keys and values analysed in one call
  KEY_SCAN: 1000, // longest quoted value looked for after a keyword
  SAMPLE: 256, // a value is judged on its first SAMPLE characters
});

export const DETECTOR_IDS = Object.freeze([
  'assignment', 'phrase', 'shape', 'pair', 'prefix-token', 'jwt', 'pem', 'ssh-key', 'url-userinfo', 'userinfo', 'header', 'bearer', 'opaque', 'cli', 'sql', 'url-param', 'table',
  'wifi', 'block', 'undecodable', 'oversize', 'non-string', 'error', 'too-deep', 'too-large', 'cycle', 'unreadable', 'unsupported',
]);

const defaultMark = (id) => `[masked:${id}]`;
const MARK_AT = /\[masked(?:[:\]]|$)/; // a mark of either style: [masked:rule] or the plain [masked] (createMasker markStyle 'plain')
const MARK_START = /^\[masked(?:[:\]]|$)/;
const OPT_KEYS = new Set(['maxChars', 'maxDepth', 'maxNodes', 'maxTotalChars', 'mark', 'stats']);
const DEFAULT_OPTS = Object.freeze({ maxChars: LIMITS.MAX_CHARS, maxDepth: LIMITS.MAX_DEPTH, maxNodes: LIMITS.MAX_NODES, maxTotalChars: LIMITS.MAX_TOTAL_CHARS, mark: defaultMark, stats: null });

// Not API: the tables and view helpers the tests sweep. Names and shapes may change without notice.
export const _internal = { get FOLD() { return FOLD; }, get SMP_FOLD() { return SMP_FOLD; }, get ND_ZEROS_BMP() { return ND_ZEROS_BMP; }, get ND_ZEROS_SMP() { return ND_ZEROS_SMP; }, cleanView: (t) => cleanView(identity(t), t.length), cleanChunk: (t) => cleanChunk(t), decodeText: (t) => decodeOnce(identity(t), t.length).t, fold: (t) => fold(t), classifyKey: (k) => classifyKey(k), camelWords: (k) => camelWords(k), weakSecretish: (v) => weakSecretish(v), isNameish: (v) => isNameish(v), isDirLike: (v) => isDirLike(v) };

export function createStats() {
  return { calls: 0, inputChars: 0, changed: 0, spans: 0, byDetector: Object.create(null), maxRounds: 0, undecodable: 0, oversize: 0, nonString: 0, errors: 0, work: 0, nodes: 0 };
}

function readOpts(opts) {
  if (opts === undefined || opts === null) return DEFAULT_OPTS;
  if (typeof opts !== 'object' || Array.isArray(opts)) throw new MaskUsageError('opts must be an object');
  for (const k of Object.keys(opts)) if (!OPT_KEYS.has(k)) throw new MaskUsageError(`unknown option: ${k.slice(0, 40).replace(/[^\w.-]/g, '?')}`);
  const out = { ...DEFAULT_OPTS };
  if (opts.maxChars !== undefined) {
    if (!Number.isInteger(opts.maxChars) || opts.maxChars < 1 || opts.maxChars > LIMITS.HARD_MAX_CHARS) throw new MaskUsageError(`opts.maxChars must be an integer from 1 to ${LIMITS.HARD_MAX_CHARS}`);
    out.maxChars = opts.maxChars;
  }
  if (opts.maxDepth !== undefined) {
    if (!Number.isInteger(opts.maxDepth) || opts.maxDepth < 1 || opts.maxDepth > 200) throw new MaskUsageError('opts.maxDepth must be an integer from 1 to 200');
    out.maxDepth = opts.maxDepth;
  }
  if (opts.maxNodes !== undefined) {
    if (!Number.isInteger(opts.maxNodes) || opts.maxNodes < 1 || opts.maxNodes > 1_000_000) throw new MaskUsageError('opts.maxNodes must be an integer from 1 to 1000000');
    out.maxNodes = opts.maxNodes;
  }
  if (opts.maxTotalChars !== undefined) {
    if (!Number.isInteger(opts.maxTotalChars) || opts.maxTotalChars < 1 || opts.maxTotalChars > 64_000_000) throw new MaskUsageError('opts.maxTotalChars must be an integer from 1 to 64000000');
    out.maxTotalChars = opts.maxTotalChars;
  }
  if (opts.mark !== undefined) {
    if (typeof opts.mark !== 'function') throw new MaskUsageError('opts.mark must be a function (id) => string');
    out.mark = opts.mark;
  }
  if (opts.stats !== undefined && opts.stats !== null) {
    if (typeof opts.stats !== 'object' || !opts.stats.byDetector) throw new MaskUsageError('opts.stats must come from createStats()');
    out.stats = opts.stats;
  }
  return out;
}

const SCRATCH_STATS = () => createStats();
// A mark function supplied by the caller may itself throw; the error paths must still not throw.
function safeMark(o, id) {
  try { return String(o.mark(id)); } catch { return defaultMark(id); }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Character helpers (code units; every character that matters here is in the BMP).
const isDigitC = (c) => c >= 48 && c <= 57;
const isUpperC = (c) => c >= 65 && c <= 90;
const isLowerC = (c) => c >= 97 && c <= 122;
const isLetterC = (c) => isUpperC(c) || isLowerC(c);
const isAlnumC = (c) => isDigitC(c) || isLetterC(c);

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Steps 1-2: normalise and delete.
// A VIEW is a string plus, for every character of it, the range of the ORIGINAL input it came from: { t, lo, hi } (lo / hi are Int32Arrays, hi exclusive; both
// null means the view is index-for-index the original). Findings are made on views and mapped back, so the masked result is the ORIGINAL text with the found
// ranges replaced: nothing that was merely encoded, invisible or look-alike is ever rewritten into something readable.
const loOf = (v, i) => (v.lo ? v.lo[i] : i);
const hiOf = (v, i) => (v.hi ? v.hi[i] : i + 1);
class MapBuf {
  constructor(n) {
    this.lo = new Int32Array(Math.max(32, n));
    this.hi = new Int32Array(Math.max(32, n));
    this.n = 0;
  }

  grow(extra) {
    if (this.n + extra <= this.lo.length) return;
    const cap = Math.max(this.lo.length * 2, this.n + extra);
    const lo = new Int32Array(cap);
    const hi = new Int32Array(cap);
    lo.set(this.lo.subarray(0, this.n));
    hi.set(this.hi.subarray(0, this.n));
    this.lo = lo;
    this.hi = hi;
  }

  copy(v, a, b) { // characters a..b of view v, one for one
    this.grow(b - a);
    if (v.lo) {
      this.lo.set(v.lo.subarray(a, b), this.n);
      this.hi.set(v.hi.subarray(a, b), this.n);
    } else {
      for (let i = a; i < b; i += 1) { this.lo[this.n + i - a] = i; this.hi[this.n + i - a] = i + 1; }
    }
    this.n += b - a;
  }

  fill(count, lo, hi) { // `count` new characters that all came from the original range lo..hi
    this.grow(count);
    this.lo.fill(lo, this.n, this.n + count);
    this.hi.fill(hi, this.n, this.n + count);
    this.n += count;
  }

  view(t, rawLen) {
    if (this.n !== t.length) return { t, lo: new Int32Array(t.length), hi: new Int32Array(t.length).fill(rawLen) }; // cannot happen; fail closed (everything maps to the whole input)
    return { t, lo: this.lo.subarray(0, this.n), hi: this.hi.subarray(0, this.n) };
  }
}
const identity = (t) => ({ t, lo: null, hi: null });
// A view of characters a..b of view v (the map is cut the same way).
function sliceView(v, a, b) {
  const n = b - a;
  const lo = new Int32Array(n);
  const hi = new Int32Array(n);
  for (let i = 0; i < n; i += 1) { lo[i] = loOf(v, a + i); hi[i] = hiOf(v, a + i); }
  return { t: v.t.slice(a, b), lo, hi };
}
// The merged neighbourhoods [a, b) of up to `cap` matches of the global regexp re: `before` characters in front of a match and `after` behind it.
function windows(t, re, before, after, cap, runChar) {
  const out = [];
  re.lastIndex = 0;
  let m;
  for (let n = 0; n < cap && (m = re.exec(t)) !== null; n += 1) {
    if (m[0].length === 0) { re.lastIndex += 1; continue; }
    let a0 = m.index;
    while (runChar && a0 > 0 && t.charCodeAt(a0 - 1) === runChar) a0 -= 1; // the whole run of backslashes, then `before` characters
    const a = Math.max(0, a0 - before);
    const b = Math.min(t.length, m.index + m[0].length + after);
    if (out.length && a <= out[out.length - 1][1]) out[out.length - 1][1] = Math.max(out[out.length - 1][1], b); else out.push([a, b]);
  }
  return out;
}
// The original-text range of a span [s, e) of a view.
function rawRange(v, s, e) {
  if (e <= s) return null;
  const a = loOf(v, s);
  const b = hiOf(v, e - 1);
  return b > a ? [a, b] : [a, a + 1];
}
// Replace every match of the global regexp `re` in view v by fn(match) (a string); the characters of a replacement map to the whole range they replace.
function replaceMapped(v, re, fn, rawLen) {
  const t = v.t;
  re.lastIndex = 0;
  let m = re.exec(t);
  if (m === null) return v;
  let out = '';
  let at = 0;
  let changed = false;
  const mb = new MapBuf(t.length + 16);
  while (m !== null) {
    if (m[0].length === 0) { re.lastIndex += 1; m = re.exec(t); continue; }
    const rep = fn(m);
    const end = m.index + m[0].length;
    if (rep !== m[0]) {
      changed = true;
      out += t.slice(at, m.index);
      mb.copy(v, at, m.index);
      out += rep;
      if (rep.length) mb.fill(rep.length, loOf(v, m.index), hiOf(v, end - 1));
      at = end;
    }
    m = re.exec(t);
  }
  if (!changed) return v;
  out += t.slice(at);
  mb.copy(v, at, t.length);
  return mb.view(out, rawLen);
}

const MARK_RUN = /\p{M}{33,}/gu; // zalgo: NFKC canonical reordering is quadratic in the length of a run of combining marks
// Characters that NFKC turns into a different letter, or does not map at all, but that read as an ASCII letter: lunate sigma (NFKC: final sigma), the numero
// sign and vulgar fractions (NFKC: "No", "1/2"), parenthesized / negative circled / negative squared letters and regional indicators (NFKC: "(a)" or nothing),
// and the supplementary-plane look-alikes in CONF_SMP.
// CONF_BMP / CONF_SMP: Unicode confusables (UTS #39 'MA' skeleton) that are ONE ASCII letter or separator, plus characters whose name says which letter they are
// ("LATIN SMALL LETTER P WITH STROKE", "CYRILLIC SMALL LETTER NARROW O"); generated by scripts/gen-fold.py. The first character of each entry is the ASCII
// target, the rest are hex code points. Characters NFKC already maps, and accented letters (folded by their decomposition) are left out.
const CONF_BMP = `'2b9,2bb,2bc,2bd,2be,2c8,2ca,2cb,2f4,55a,55d,5d9,5f3,7f4,7f5,144a,16cc,2018,2019,201b,2032,2035,a78c ,60d,66b,201a,a4f9 -2d7,6d4,2010,2012,2013,2043,2212,2796,2cba /1735,2041,2044,2215,2571,27cb,29f8,2cc6,3033,30ce,31d3,4e3f :2d0,2f8,589,5c3,703,704,16ec,1803,1809,205a,2236,a4fd,a789 =1400,2e40,30a0,a4ff A23a,391,410,4d0,4d2,13aa,15c5,a4ee B181,182,243,392,412,13f4,15f7,a4d0,a796,a7b4 C187,23b,421,13df,2ca4,a4da,a792,a7c4 D110,18a,18b,13a0,15de,15ea,a4d3,a7c7 E246,395,415,4ec,13ac,22ff,2d39,a4f0 F191,3dc,15b4,a4dd,a798 G193,1e4,50c,13c0,13f3,a4d6,a7a0 H126,397,41d,13bb,157c,2c67,2c8e,a4e7,a7aa I197,40d,4e2,4e4,a7ae J248,37f,408,13ab,148d,a4d9,a7b2 K198,39a,41a,13e6,16d5,2c69,2c94,a4d7,a740,a742,a744,a7a2 L141,23d,13de,14aa,2c60,2c62,2cd0,a4e1,a748,a7ad M39c,3fa,41c,13b7,15f0,16d6,2c6e,2c98,a4df N19d,220,39d,2c9a,a4e0,a790,a7a4 Od8,19f,1fe,39f,41e,4e6,555,7c0,9e6,b20,b66,12d0,2c9e,2d54,3007,a4f3,a668,a66c,a74a,a74c Pde,1a4,3a1,420,13e2,146d,2c63,2ca2,a4d1,a750,a752,a754 Q2d55,a756,a758 R1a6,24c,13a1,13d2,1587,2c64,a4e3,a7a6 S405,54f,13d5,13da,2c7e,a4e2,a7a8,a7c5,a7c9 T166,1ac,1ae,23e,3a4,422,13a2,22a4,27d9,2ca6,a4d4 U4ee,4f0,4f2,54d,1200,144c,222a,22c3,a4f4,a7b8 V1b2,474,667,6f7,13d9,142f,2d38,a4e6,a6df,a75e W51c,13b3,13d4,2c72,a4ea X3a7,425,166d,16b7,2573,2cac,2d5d,a4eb,a7b3 Y1b3,24e,3a5,423,4ae,13a9,13bd,1efe,2ca8,a4ec Z1b5,224,396,13c3,2c6b,2c7f,a4dc,a7c6 a251,3b1,430,4d1,4d3,1d00,1d8f,237a,2c65 b180,183,184,253,299,42c,13cf,1472,15af,1d6c,1d80,a797 c188,23c,255,441,1c83,1d04,2ca5,a793,a794,abaf d111,18c,221,256,257,501,13e7,146f,1d05,1d6d,1d81,1d91,a4d2,a7c8 e247,435,4bd,4ed,1d07,1d92,212e,2c78,ab32,ab34 f192,584,1d6e,1d82,1e9d,a730,a799,ab35 g18d,1e5,260,261,262,29b,581,1d83,a7a1 h127,266,29c,4bb,570,13c2,2c68,a795 i131,268,269,26a,3b9,456,45d,4cf,4e3,4e5,13a5,1d96,2373,a647,ab75 j249,29d,3f3,458,1d0a k199,1d0b,1d84,2c6a,a741,a743,a745,a7a3 l142,196,19a,1c0,234,26b,26c,26d,29f,399,406,4c0,5c0,5d5,5df,627,661,6f1,7ca,16c1,1d0c,1d85,2223,23fd,2c61,2c92,2d4f,a4f2,a749,a78e,ab37,ab38,ab39 m271,1d0d,1d6f,1d86,a7fa,ab3a n19e,235,272,273,274,578,57c,1d70,1d87,a791,a7a5,ab3b of8,1ff,3bf,3c3,43e,4e7,585,5e1,647,665,6be,6c1,6d5,6f5,966,a66,ae6,be6,c66,ce6,d20,d66,e50,ed0,101d,1040,10ff,1c82,1d0f,1d11,2c7a,2c9f,a669,a66d,a74b,a74d,ab3d pfe,1a5,3c1,440,1d18,1d71,1d7d,1d88,2374,2ca3,a751,a753,a755 q24b,2a0,51b,563,566,a757,a759,a7af r24d,27c,27d,27e,280,433,1d26,1d72,1d73,1d89,2c85,a7a7,ab46,ab47,ab48,ab49,ab81 s1bd,23f,282,455,1d74,1d8a,a731,a7a9,a7ca,abaa t167,1ab,1ad,236,288,1d1b,1d75,2c66 u28b,3c5,4ef,4f1,4f3,57d,1d1c,1d99,a79f,a7b9,ab4e,ab52 v3bd,475,5d8,1d20,2228,22c1,2c71,2c74,a75f,aba9 w26f,461,51d,561,1d21,2c73,ab83 xd7,445,1541,157d,166e,1d8d,292b,292c,2a2f,ab56,ab57,ab58,ab59 y1b4,24f,263,28f,3b3,443,4af,10e7,1d8c,1eff,ab5a z1b6,225,240,290,291,1d22,1d76,1d8e,2c6c,ab93 n3b7,43f,3c0,14b N41f,3a0 k138 e454,25b r491,a785 ta787 aab64 u3bc :2d1,703,704,705,706,707,708,709,1366,205d,2360,2982,2af6,a6f4,2237,2025,2a6e,29e3 =224c,2251,2256,2257,225b,225c,225d,225f,229c,22cd,2338,2a6f,2a70,2a75,2a76,2243,2245,2246,224a,2971,29e4,2a66,2a73,2a77,2aae,2b40,2bf9`;
const CONF_SMP = `:1da8a,12471,12472,12473,12474,10781,10782 =1f7f0 /1d23a A102a0,16f40 B10282,102a1,10301 C102a2,10302,10415,1051c,118e9,118f2,1f74c E10286,118a6,118ae F10287,102a5,10525,118a2,118c2,1d213 H102cf K10518 L1041b,10526,118a3,118b2,16f16,1d22a M102b0,10311 N10513 O10292,102ab,10404,104c2,10516,114d0,118b5,118e0 P10295 R104b4,16f35,1d216 S10296,10420,16f3a T10297,102b1,10315,118bc,16f0a,1f768 U104ce,118b8,16f42 V1051d,118a0,16f08,1d20d W118e6,118ef X10290,102b4,10317,10322,10527,118ec Y102b2,118a4,16f43 Z102f5,118a9,118e5 c1043d i118c3 l1028a,10309,10320,16f28,1e8c7 o1042c,104ea,118c8,118d7 s10448,118c1 u104f6,118d8 v11706,118c0 w1170a,1170e,1170f y118dc z118c4`;
// Decimal digits of other scripts read as ASCII digits ("password\u0662="): the code point of each block's zero, BMP then supplementary.
const ND_ZEROS_BMP = [0x660, 0x6f0, 0x7c0, 0x966, 0x9e6, 0xa66, 0xae6, 0xb66, 0xbe6, 0xc66, 0xce6, 0xd66, 0xde6, 0xe50, 0xed0, 0xf20, 0x1040, 0x1090, 0x17e0, 0x1810, 0x1946, 0x19d0, 0x1a80, 0x1a90, 0x1b50, 0x1bb0, 0x1c40, 0x1c50,
  0xa620, 0xa8d0, 0xa900, 0xa9d0, 0xa9f0, 0xaa50, 0xabf0];
const ND_ZEROS_SMP = [0x104a0, 0x10d30, 0x10d40, 0x116d0, 0x116da, 0x11bf0, 0x11de0, 0x11f50, 0x16130, 0x16d70, 0x1ccf0, 0x1e4f0, 0x1e5f1, 0x11066, 0x110f0, 0x11136, 0x111d0, 0x112f0, 0x11450, 0x114d0, 0x11650, 0x116c0, 0x11730, 0x118e0, 0x11950, 0x11c50, 0x11d50, 0x11da0, 0x16a60, 0x16ac0, 0x16b50, 0x1e140, 0x1e2f0, 0x1e950];
function parseConf(table, fn) {
  for (const entry of table.split(' ')) {
    const to = entry[0];
    for (const h of entry.slice(1).split(',')) fn(parseInt(h, 16), to);
  }
}
const SMP_FOLD = new Map();
parseConf(CONF_SMP, (cp, to) => SMP_FOLD.set(cp, to));
for (const z of ND_ZEROS_SMP) for (let d = 0; d < 10; d += 1) SMP_FOLD.set(z + d, String(d));
function PRE_BASE_CLASS(map) {
  const base = '\\ufe30\\u03f2\\u03f9\\u2116\\u00bc-\\u00be\\u2150-\\u215f\\u2189\\u249c-\\u24b5\\u{1f110}-\\u{1f129}\\u{1f150}-\\u{1f169}\\u{1f170}-\\u{1f189}\\u{1f1e6}-\\u{1f1ff}';
  return base + [...map.keys()].map((cp) => `\\u{${cp.toString(16)}}`).join('');
}
const PRE_CLASS = PRE_BASE_CLASS(SMP_FOLD);
const PRE_RE = new RegExp(`[${PRE_CLASS}]`, 'gu');
const PRE_TEST = new RegExp(`[${PRE_CLASS}]`, 'u');
function preMap(ch) {
  const cp = ch.codePointAt(0);
  if (SMP_FOLD.has(cp)) return SMP_FOLD.get(cp);
  if (cp === 0xfe30) return ':';
  if (cp === 0x3f2) return 'c';
  if (cp === 0x3f9) return 'C';
  if (cp === 0x2116 || (cp >= 0xbc && cp <= 0xbe) || (cp >= 0x2150 && cp <= 0x215f) || cp === 0x2189) return 'n';
  let base;
  if (cp >= 0x249c && cp <= 0x24b5) base = cp - 0x249c;
  else if (cp >= 0x1f110 && cp <= 0x1f129) base = cp - 0x1f110;
  else if (cp >= 0x1f150 && cp <= 0x1f169) base = cp - 0x1f150;
  else if (cp >= 0x1f170 && cp <= 0x1f189) base = cp - 0x1f170;
  else base = cp - 0x1f1e6;
  return String.fromCharCode(97 + base);
}
const STRIP = /[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Co}\p{Cn}\u{fffc}\u{2800}\u{fffd}\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u{300}-\u{36f}\u{d800}-\u{dfff}]/gu;
const MARKS_RE = /\p{M}+/gu;
// A character that is deleted (NUL, any other control, an invisible one) typed between the two halves of an astral character splits it into two lone surrogates, which
// are then deleted too: "p" (U+1D429) + NUL in the middle would vanish with its letter. The deleted characters between the halves go first, so the pair is whole again.
const SPLIT_PAIR = /(?<=[\ud800-\udbff])[\p{Default_Ignorable_Code_Point}\p{Cf}\p{Co}\p{Cn}\u{fffc}\u{2800}\u{fffd}\u0000-\u0008\u000B\u000C\u000E-\u001F\u007F-\u009F\u{300}-\u{36f}]+(?=[\udc00-\udfff])/gu;
const SPLIT_TEST = /[\ud800-\udbff][^\ud800-\udfff]/;
const joinPairs = (s) => (SPLIT_TEST.test(s) ? s.replace(SPLIT_PAIR, '') : s);
// Combining marks (Mn, Mc, Me) are deleted when their base is a Latin, Greek, Cyrillic, symbol or punctuation character (anything an attacker can use inside
// an ASCII keyword) or when there is no base. Marks on Hebrew, Arabic, Indic, South-East Asian, CJK and other scripts are part of those words and stay.
function dropMarks(s) {
  if (!/\p{M}/u.test(s)) return s;
  let out = '';
  let at = 0;
  for (const m of s.matchAll(MARKS_RE)) {
    const i = m.index;
    let drop = i === 0;
    if (!drop) {
      let cp = s.charCodeAt(i - 1);
      if (cp >= 0xdc00 && cp <= 0xdfff && i >= 2) cp = s.codePointAt(i - 2);
      drop = cp < 0x590 || (cp >= 0x1d00 && cp < 0x3000) || (cp >= 0xff00 && cp < 0x10000);
    }
    if (drop) { out += s.slice(at, i); at = i + m[0].length; }
  }
  return at === 0 ? s : out + s.slice(at);
}
// One chunk of text that holds no plain printable ASCII break: invisible characters are deleted BEFORE normalisation (so decomposed pieces separated by a
// zero-width character recompose: Hangul jamo, kana + voiced mark) and again after it (NFKC can produce more of them).
function cleanChunk(s) {
  s = joinPairs(s);
  if (s.length > 32 && /\p{M}/u.test(s)) s = s.replace(MARK_RUN, '');
  if (PRE_TEST.test(s)) s = s.replace(PRE_RE, preMap);
  return dropMarks(s.replace(STRIP, '').normalize('NFKC').replace(STRIP, ''));
}
const clean = cleanChunk;
const SPECIAL = /[^\x20-\x7e\t\n\r]+/g; // everything but plain printable ASCII and the three line/tab white-space characters
const SPECIAL_TEST = /[^\x20-\x7e\t\n\r]/;
// A string as the structure rules read it: invisible and control characters (NUL ...) deleted, NFKC. A name or a separator typed with a NUL inside is still that name or separator.
const cs = (s) => (typeof s === 'string' && SPECIAL_TEST.test(s) ? cleanChunk(s) : s);
// Normalise and delete, keeping the map. Plain ASCII text between special runs is copied one for one; each special run is cleaned as a chunk and its result maps to the
// whole chunk. (Nothing composes with a plain ASCII character that survives the pre-NFKC deletion: the marks that do, U+0300 to U+036F, are deleted first.)
function cleanView(v, rawLen) {
  const t = v.t;
  if (!SPECIAL_TEST.test(t)) return v;
  const mb = new MapBuf(t.length + 16);
  let out = '';
  let at = 0;
  SPECIAL.lastIndex = 0;
  let m = SPECIAL.exec(t);
  while (m !== null) {
    const a = m.index;
    const b = a + m[0].length;
    if (a > at) { out += t.slice(at, a); mb.copy(v, at, a); }
    const c = cleanChunk(t.slice(a, b));
    if (c.length) { out += c; mb.fill(c.length, loOf(v, a), hiOf(v, b - 1)); }
    at = b;
    m = SPECIAL.exec(t);
  }
  if (at < t.length) { out += t.slice(at); mb.copy(v, at, t.length); }
  return mb.view(out, rawLen);
}

// Step 4: fold look-alikes to ASCII, one UTF-16 unit for one unit (all of these are in the BMP), so every index stays valid.
const FOLD = new Map();
{
  const pairs = [
    // Cyrillic
    ['\u{430}', 'a'], ['\u{432}', 'b'], ['\u{435}', 'e'], ['\u{43a}', 'k'], ['\u{43c}', 'm'], ['\u{43d}', 'h'], ['\u{43e}', 'o'], ['\u{440}', 'p'], ['\u{441}', 'c'], ['\u{442}', 't'],
    ['\u{443}', 'y'], ['\u{445}', 'x'], ['\u{456}', 'i'], ['\u{458}', 'j'], ['\u{455}', 's'], ['\u{501}', 'd'], ['\u{4bb}', 'h'], ['\u{51b}', 'q'], ['\u{51d}', 'w'], ['\u{4cf}', 'l'],
    ['\u{451}', 'e'], ['\u{461}', 'w'], ['\u{410}', 'A'], ['\u{412}', 'B'], ['\u{415}', 'E'], ['\u{41a}', 'K'], ['\u{41c}', 'M'], ['\u{41d}', 'H'], ['\u{41e}', 'O'], ['\u{420}', 'P'],
    ['\u{421}', 'C'], ['\u{422}', 'T'], ['\u{425}', 'X'], ['\u{423}', 'Y'], ['\u{406}', 'I'], ['\u{408}', 'J'], ['\u{405}', 'S'], ['\u{51a}', 'Q'], ['\u{51c}', 'W'], ['\u{4c0}', 'I'],
    // Greek
    ['\u{3b1}', 'a'], ['\u{3b5}', 'e'], ['\u{3b9}', 'i'], ['\u{3ba}', 'k'], ['\u{3bd}', 'v'], ['\u{3bf}', 'o'], ['\u{3c1}', 'p'], ['\u{3c4}', 't'], ['\u{3c5}', 'u'], ['\u{3c7}', 'x'],
    ['\u{3c9}', 'w'], ['\u{3b3}', 'y'], ['\u{3c2}', 's'], ['\u{3f2}', 'c'], ['\u{3f3}', 'j'], ['\u{391}', 'A'], ['\u{392}', 'B'], ['\u{395}', 'E'], ['\u{396}', 'Z'], ['\u{397}', 'H'],
    ['\u{399}', 'I'], ['\u{39a}', 'K'], ['\u{39c}', 'M'], ['\u{39d}', 'N'], ['\u{39f}', 'O'], ['\u{3a1}', 'P'], ['\u{3a4}', 'T'], ['\u{3a5}', 'Y'], ['\u{3a7}', 'X'], ['\u{3f9}', 'C'],
    // Latin small capitals and other look-alikes
    ['\u{1d00}', 'a'], ['\u{299}', 'b'], ['\u{1d04}', 'c'], ['\u{1d05}', 'd'], ['\u{1d07}', 'e'], ['\u{a730}', 'f'], ['\u{262}', 'g'], ['\u{29c}', 'h'], ['\u{26a}', 'i'], ['\u{1d0a}', 'j'],
    ['\u{1d0b}', 'k'], ['\u{29f}', 'l'], ['\u{1d0d}', 'm'], ['\u{274}', 'n'], ['\u{1d0f}', 'o'], ['\u{1d18}', 'p'], ['\u{280}', 'r'], ['\u{a731}', 's'], ['\u{1d1b}', 't'], ['\u{1d1c}', 'u'],
    ['\u{1d20}', 'v'], ['\u{1d21}', 'w'], ['\u{28f}', 'y'], ['\u{1d22}', 'z'], ['\u{131}', 'i'], ['\u{251}', 'a'], ['\u{261}', 'g'], ['\u{269}', 'i'], ['\u{f8}', 'o'], ['\u{d8}', 'O'],
    ['\u{111}', 'd'], ['\u{110}', 'D'], ['\u{142}', 'l'], ['\u{141}', 'L'], ['\u{127}', 'h'], ['\u{126}', 'H'], ['\u{585}', 'o'],
    // Look-alike separators, for the keyword -> value link: colons -> ':', equals -> '=', arrows and bullets -> '>', hyphens and dashes -> '-', slashes, pipes, commas
    ['\u{2236}', ':'], ['\u{a789}', ':'], ['\u{205a}', ':'], ['\u{2d0}', ':'], ['\u{2f8}', ':'], ['\u{589}', ':'], ['\u{1365}', ':'], ['\u{1804}', ':'], ['\u{fe30}', ':'], ['\u{fe13}', ':'],
    ['\u{2254}', '='], ['\u{2255}', '='], ['\u{2550}', '='], ['\u{2248}', '='], ['\u{2261}', '='], ['\u{30a0}', '='], ['\u{a78a}', '='], ['\u{2a74}', '='],
    ['\u{2022}', '>'], ['\u{b7}', '>'], ['\u{2219}', '>'], ['\u{22c5}', '>'], ['\u{30fb}', '>'], ['\u{2027}', '>'], ['\u{2043}', '>'], ['\u{25cf}', '>'], ['\u{25cb}', '>'], ['\u{25aa}', '>'], ['\u{25a0}', '>'], ['\u{2023}', '>'],
    ['\u{2010}', '-'], ['\u{2011}', '-'], ['\u{2012}', '-'], ['\u{2013}', '-'], ['\u{2014}', '-'], ['\u{2015}', '-'], ['\u{2212}', '-'], ['\u{fe58}', '-'], ['\u{fe63}', '-'], ['\u{2e3a}', '-'], ['\u{2e3b}', '-'],
    ['\u{2044}', '/'], ['\u{2215}', '/'], ['\u{29f8}', '/'], ['\u{2502}', '|'], ['\u{1c0}', '|'], ['\u{2223}', '|'], ['\u{2551}', '|'], ['\u{60c}', ','], ['\u{3001}', ','], ['\u{61b}', ';'],
    // Typographic quotes open and close a quoted phrase like the ASCII ones
    ['\u{201c}', '"'], ['\u{201d}', '"'], ['\u{275d}', '"'], ['\u{275e}', '"'], ['\u{275b}', "'"], ['\u{275c}', "'"], ['\u{201e}', '"'], ['\u{201f}', '"'], ['\u{ab}', '"'], ['\u{bb}', '"'], ['\u{300c}', '"'], ['\u{300d}', '"'], ['\u{300e}', '"'], ['\u{300f}', '"'],
    ['\u{301d}', '"'], ['\u{301e}', '"'], ['\u{301f}', '"'], ['\u{2018}', "'"], ['\u{2019}', "'"], ['\u{201a}', "'"], ['\u{201b}', "'"], ['\u{2039}', "'"], ['\u{203a}', "'"],
  ];
  for (const [from, to] of pairs) FOLD.set(from, to);
  // Arrows (right and left, so a reversed layout reads the same).
  for (const [lo, hi] of [[0x2190, 0x21ff], [0x2794, 0x27be], [0x27f0, 0x27ff], [0x2900, 0x297f]]) for (let cp = lo; cp <= hi; cp += 1) FOLD.set(String.fromCharCode(cp), '>');
  // Accented letters: take the base letter of the canonical decomposition (one unit in, one unit out). Latin, Greek and Cyrillic, polytonic Greek included.
  const addRange = (lo, hi) => {
    for (let cp = lo; cp <= hi; cp += 1) {
      const ch = String.fromCharCode(cp);
      if (FOLD.has(ch)) continue;
      const d = ch.normalize('NFD');
      if (d.length < 2 || !/^\p{M}+$/u.test(d.slice(1))) continue;
      const to = /^[A-Za-z]$/.test(d[0]) ? d[0] : FOLD.get(d[0]);
      if (to) FOLD.set(ch, to);
    }
  };
  addRange(0xc0, 0x24f);
  addRange(0x370, 0x52f);
  addRange(0x1e00, 0x1fff);
  // generated confusables and other-script digits; an entry above always wins
  parseConf(CONF_BMP, (cp, to) => { const ch = String.fromCharCode(cp); if (!FOLD.has(ch)) FOLD.set(ch, to); });
  for (const z of ND_ZEROS_BMP) for (let d = 0; d < 10; d += 1) FOLD.set(String.fromCharCode(z + d), String(d));
}
const FOLD_RE = new RegExp(`[${[...FOLD.keys()].join('')}]`, 'g');
const fold = (s) => (/[^\u0000-\u007f]/.test(s) ? s.replace(FOLD_RE, (c) => FOLD.get(c)) : s);
// A decimal digit of another script that also looks like a letter (Lao zero and "o", Devanagari zero and "o"): the fold reads it as the digit; ALT_FOLD reads it as
// the letter, in a second view of the same text.
const ALT_FOLD = new Map();
{
  const letters = new Map();
  parseConf(CONF_BMP, (cp, to) => { if (/[A-Za-z]/.test(to)) letters.set(String.fromCharCode(cp), to); });
  for (const [ch, to] of FOLD) if (/[0-9]/.test(to) && letters.has(ch)) ALT_FOLD.set(ch, letters.get(ch));
}
const ALT_RE = new RegExp(`[${[...ALT_FOLD.keys()].join('')}]`, 'g');
const ALT_TEST = new RegExp(`[${[...ALT_FOLD.keys()].join('')}]`);
const foldAlt = (s) => fold(s.replace(ALT_RE, (c) => ALT_FOLD.get(c)));

// Every White_Space character except none: all become one plain space. Same length, so every index is valid in both views.
const WS_RE = /[\t\n\r\u{a0}\u{1680}\u{2000}-\u{200a}\u{2028}\u{2029}\u{202f}\u{205f}\u{3000}]/gu;
const flatten = (s) => s.replace(WS_RE, ' ');

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Step 5: decoding typed-as-text encodings.
const ENC_TEST = /%[uU]?[0-9a-fA-F]{2}|&#[xX]?[0-9a-fA-F]|&[A-Za-z][A-Za-z0-9]{1,31}[;A-Za-z]|\\[uUxXNn0-9a-fA-F]/;
const PCT = /(?:%[0-9a-fA-F]{2})+/g;
const PCTU = /%[uU]([0-9a-fA-F]{4})/g;
const HTMLNUM = /&#(?:[xX]0*([0-9a-fA-F]{1,6})|0*([0-9]{1,7}));?/g;
const HTMLNAMED = /&([A-Za-z][A-Za-z0-9]{1,31})(;)?/g;
const BSLX = /(?:\\x[0-9a-fA-F]{2})+/g;
// \u{..}  \uXXXX  \UXXXXXXXX  octal \NNN (a first digit of 1-3 is octal; a leading 0 followed by white space is a CSS escape like \070 )  \N{CHARACTER NAME}
const BSL = /\\u\{0*([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\(?:([1-3][0-7]{2})(?![0-7])|(0[0-7]{2})(?![0-7 \t\n\r\f]))|\\N\{([A-Za-z0-9 -]{1,40})\}/g;
const CSSESC = /\\([0-9a-fA-F]{2,6})[ \t\n\r\f]?/g;
const QP_SOFT = /=\r?\n/g; // quoted-printable soft line break: "pass=\nword". Its own view (mode 'qp'), read with a stricter value rule: "DB_PASSWORD=<newline>HOST=localhost" is an empty value, not a soft break.
const QP_SOFT_TEST = /=\r?\n/;
const cpToStr = (cp) => (cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff) ? '\u{fffd}' : String.fromCodePoint(cp));
// Named character references that are ASCII or white space or invisible (the rest of the 2,000 HTML names cannot spell a keyword or a separator).
const NAMED_ENT = new Map(Object.entries({
  quot: '"', QUOT: '"', amp: '&', AMP: '&', lt: '<', LT: '<', gt: '>', GT: '>', apos: "'", nbsp: '\u00a0', NonBreakingSpace: '\u00a0', equals: '=', colon: ':', semi: ';', comma: ',', period: '.', excl: '!', quest: '?',
  lpar: '(', rpar: ')', lsqb: '[', rsqb: ']', lbrack: '[', rbrack: ']', lcub: '{', rcub: '}', lbrace: '{', rbrace: '}', num: '#', dollar: '$', percnt: '%', ast: '*', midast: '*', plus: '+', sol: '/', bsol: '\\',
  commat: '@', lowbar: '_', UnderBar: '_', grave: '`', DiacriticalGrave: '`', verbar: '|', vert: '|', VerticalLine: '|', Hat: '^', hyphen: '\u2010', dash: '\u2010', Tab: '\t', NewLine: '\n', shy: '\u00ad', zwj: '\u200d', zwnj: '\u200c',
  ZeroWidthSpace: '\u200b', NoBreak: '\u2060', ensp: '\u2002', emsp: '\u2003', emsp13: '\u2004', emsp14: '\u2005', numsp: '\u2007', puncsp: '\u2008', thinsp: '\u2009', ThinSpace: '\u2009', hairsp: '\u200a',
  ndash: '\u2013', mdash: '\u2014', horbar: '\u2015', lsquo: '\u2018', rsquo: '\u2019', rsquor: '\u2019', ldquo: '\u201c', rdquo: '\u201d', laquo: '\u00ab', raquo: '\u00bb', lsaquo: '\u2039', rsaquo: '\u203a',
  thorn: '\u00fe', THORN: '\u00de', imath: '\u0131', inodot: '\u0131', hellip: '\u2026', bull: '\u2022', middot: '\u00b7', centerdot: '\u00b7', rarr: '\u2192', larr: '\u2190', rArr: '\u21d2', lArr: '\u21d0', harr: '\u2194', hArr: '\u21d4',
}));
// Legacy names decode without the closing semicolon, as browsers read them, and by the longest prefix (&quotpassword is a quote and "password").
// A letter with an accent, as named references spell it (&aacute; &egrave; &ccedil; &ouml; &aring; &oslash; &scaron; ...): the base letter is all the matcher needs.
const ACCENT_ENT = /^([A-Za-z])(?:acute|grave|circ|tilde|uml|ring|cedil|caron|breve|macron|ogon|dot|dblac|strok|slash)$/;
const LEGACY_ORDER = ['nbsp', 'quot', 'QUOT', 'amp', 'AMP', 'lt', 'LT', 'gt', 'GT']; // these decode without the closing semicolon, as browsers read them
// Names for \N{...}: every printable ASCII character, by its Unicode name.
const ASCII_NAMES = new Map();
{
  const punct = ['SPACE', 'EXCLAMATION MARK', 'QUOTATION MARK', 'NUMBER SIGN', 'DOLLAR SIGN', 'PERCENT SIGN', 'AMPERSAND', 'APOSTROPHE', 'LEFT PARENTHESIS', 'RIGHT PARENTHESIS', 'ASTERISK', 'PLUS SIGN', 'COMMA', 'HYPHEN-MINUS',
    'FULL STOP', 'SOLIDUS', 'DIGIT ZERO', 'DIGIT ONE', 'DIGIT TWO', 'DIGIT THREE', 'DIGIT FOUR', 'DIGIT FIVE', 'DIGIT SIX', 'DIGIT SEVEN', 'DIGIT EIGHT', 'DIGIT NINE', 'COLON', 'SEMICOLON', 'LESS-THAN SIGN', 'EQUALS SIGN',
    'GREATER-THAN SIGN', 'QUESTION MARK', 'COMMERCIAL AT'];
  punct.forEach((name, i) => ASCII_NAMES.set(name, String.fromCharCode(0x20 + i)));
  for (let i = 0; i < 26; i += 1) {
    ASCII_NAMES.set(`LATIN CAPITAL LETTER ${String.fromCharCode(65 + i)}`, String.fromCharCode(65 + i));
    ASCII_NAMES.set(`LATIN SMALL LETTER ${String.fromCharCode(65 + i)}`, String.fromCharCode(97 + i));
  }
  ['LEFT SQUARE BRACKET', 'REVERSE SOLIDUS', 'RIGHT SQUARE BRACKET', 'CIRCUMFLEX ACCENT', 'LOW LINE', 'GRAVE ACCENT'].forEach((name, i) => ASCII_NAMES.set(name, String.fromCharCode(0x5b + i)));
  ['LEFT CURLY BRACKET', 'VERTICAL LINE', 'RIGHT CURLY BRACKET', 'TILDE'].forEach((name, i) => ASCII_NAMES.set(name, String.fromCharCode(0x7b + i)));
}
// Lenient UTF-8: well-formed sequences become their code point; every other byte is read as one Latin-1 character (A0-BF, the symbols and NBSP, are dropped),
// so one stray byte never changes how the valid sequences around it are read.
function utf8Lenient(bytes) {
  let out = '';
  const n = bytes.length;
  for (let i = 0; i < n;) {
    const b = bytes[i];
    if (b < 0x80) { out += String.fromCharCode(b); i += 1; continue; }
    let need = 0;
    let cp = 0;
    let min = 0;
    if (b >= 0xc2 && b <= 0xdf) { need = 1; cp = b & 0x1f; min = 0x80; } else if (b >= 0xe0 && b <= 0xef) { need = 2; cp = b & 0x0f; min = 0x800; } else if (b >= 0xf0 && b <= 0xf4) { need = 3; cp = b & 0x07; min = 0x10000; }
    let ok = need > 0 && i + need < n;
    for (let k = 1; ok && k <= need; k += 1) {
      const cb = bytes[i + k];
      if ((cb & 0xc0) !== 0x80) ok = false; else cp = (cp << 6) | (cb & 0x3f);
    }
    if (ok && (cp < min || cp > 0x10ffff || (cp >= 0xd800 && cp <= 0xdfff))) ok = false;
    if (ok) { out += String.fromCodePoint(cp); i += need + 1; } else { if (b < 0xa0 || b > 0xbf) out += String.fromCharCode(b); i += 1; } // a stray Latin-1 symbol or NBSP byte (A0-BF) is dropped: it can only separate
  }
  return out;
}
function hexBytes(run, step, skip) {
  const bytes = [];
  for (let i = 0; i + skip + 1 < run.length + 0; i += step) bytes.push(parseInt(run.slice(i + skip, i + skip + 2), 16));
  return bytes;
}
// One decode pass over a view (percent, %u, numeric and named character references, \x, \u, \U, octal, \N{..}, CSS escapes, quoted-printable soft breaks).
function decodeOnce(v, rawLen) {
  let cur = v;
  if (cur.t.includes('%')) {
    cur = replaceMapped(cur, PCT, (m) => utf8Lenient(hexBytes(m[0], 3, 1)), rawLen);
    if (cur.t.includes('%u') || cur.t.includes('%U')) cur = replaceMapped(cur, PCTU, (m) => String.fromCharCode(parseInt(m[1], 16)), rawLen);
  }
  if (cur.t.includes('&')) {
    if (cur.t.includes('&#')) cur = replaceMapped(cur, HTMLNUM, (m) => cpToStr(m[1] !== undefined ? parseInt(m[1], 16) : parseInt(m[2], 10)), rawLen);
    cur = replaceMapped(cur, HTMLNAMED, (m) => {
      const ch = NAMED_ENT.get(m[1]);
      if (ch !== undefined && m[2] !== undefined) return ch;
      if (m[2] === undefined) {
        for (const name of LEGACY_ORDER) if (m[1].startsWith(name)) return NAMED_ENT.get(name) + m[1].slice(name.length);
      } else {
        const am = ACCENT_ENT.exec(m[1]); // &aacute; &Ccedil; &ouml;: an accented letter reads as its base letter (the mark is ignored for matching anyway)
        if (am) return am[1];
      }
      return m[0];
    }, rawLen);
  }
  if (cur.t.includes('\\')) {
    cur = replaceMapped(cur, BSLX, (m) => utf8Lenient(hexBytes(m[0], 4, 2)), rawLen);
    cur = replaceMapped(cur, BSL, (m) => {
      if (m[1] !== undefined) return cpToStr(parseInt(m[1], 16));
      if (m[2] !== undefined) return String.fromCharCode(parseInt(m[2], 16));
      if (m[3] !== undefined) return cpToStr(parseInt(m[3], 16));
      if (m[4] !== undefined) return String.fromCharCode(parseInt(m[4], 8));
      if (m[5] !== undefined) return String.fromCharCode(parseInt(m[5], 8));
      const named = ASCII_NAMES.get(m[6].toUpperCase());
      return named === undefined ? m[0] : named;
    }, rawLen);
    cur = replaceMapped(cur, CSSESC, (m) => { const cp = parseInt(m[1], 16); return cp >= 0x20 && cp <= 0x10ffff && !(cp >= 0xd800 && cp <= 0xdfff) ? String.fromCodePoint(cp) : m[0]; }, rawLen);
  }
  return cur;
}
// The ALTERNATE decode order (a second chain per root). The standard pass reads a reference without its semicolon the way a browser does and decodes
// entities before escapes, which turns "&#1&#48;1;" into U+0001 + "0" + "1;" and "&#101\x3B" into "e" + ";". The alternate pass reads the layers inside out:
// backslash escapes first (an octal escape is always three digits at most, so "\1622" is "\162" + "2", and "\072 " keeps its space), then percent, then only
// TERMINATED entities; when none of that changes anything it falls back to the standard pass for this round (so an unterminated outer reference is read once
// its inner references are gone).
const HTMLNUM_STRICT = /&#(?:[xX]0*([0-9a-fA-F]{1,6})|0*([0-9]{1,7}));/g;
const HTMLNAMED_STRICT = /&([A-Za-z][A-Za-z0-9]{1,31});/g;
const BSL_ALT = /\\u\{0*([0-9a-fA-F]{1,6})\}|\\u([0-9a-fA-F]{4})|\\U([0-9a-fA-F]{8})|\\([0-3][0-7]{2})|\\N\{([A-Za-z0-9 -]{1,40})\}/g;
function decodeAlt(v, rawLen) {
  let cur = v;
  if (cur.t.includes('\\')) {
    cur = replaceMapped(cur, BSLX, (m) => utf8Lenient(hexBytes(m[0], 4, 2)), rawLen);
    cur = replaceMapped(cur, BSL_ALT, (m) => {
      if (m[1] !== undefined) return cpToStr(parseInt(m[1], 16));
      if (m[2] !== undefined) return String.fromCharCode(parseInt(m[2], 16));
      if (m[3] !== undefined) return cpToStr(parseInt(m[3], 16));
      if (m[4] !== undefined) return String.fromCharCode(parseInt(m[4], 8));
      const named = ASCII_NAMES.get(m[5].toUpperCase());
      return named === undefined ? m[0] : named;
    }, rawLen);
  }
  if (cur.t.includes('%')) {
    cur = replaceMapped(cur, PCT, (m) => utf8Lenient(hexBytes(m[0], 3, 1)), rawLen);
    if (cur.t.includes('%u') || cur.t.includes('%U')) cur = replaceMapped(cur, PCTU, (m) => String.fromCharCode(parseInt(m[1], 16)), rawLen);
  }
  if (cur.t.includes('&')) {
    if (cur.t.includes('&#')) cur = replaceMapped(cur, HTMLNUM_STRICT, (m) => cpToStr(m[1] !== undefined ? parseInt(m[1], 16) : parseInt(m[2], 10)), rawLen);
    cur = replaceMapped(cur, HTMLNAMED_STRICT, (m) => {
      const ch = NAMED_ENT.get(m[1]);
      if (ch !== undefined) return ch;
      const am = ACCENT_ENT.exec(m[1]);
      return am ? am[1] : m[0];
    }, rawLen);
  }
  return cur.t !== v.t ? cur : decodeOnce(v, rawLen);
}
// Alternative views of the same text. Findings in any of them are mapped back and masked together.
const VT_FF_NEL_TEST = /[\u000b\u000c\u0085]/;
const VT_FF_NEL = /[\u000b\u000c\u0085]/g; // White_Space that the main view deletes (so it can sit inside a keyword): here it reads as a plain space
const TAG_CHAR_TEST = /[\u{e0020}-\u{e007e}]/u;
const TAG_CHARS = /[\u{e0020}-\u{e007e}]/gu; // Unicode tag characters spell ASCII invisibly ("ASCII smuggling"): here they read as the letters they stand for
const MARKUP_TEST = /<[A-Za-z/!]/;
const MARKUP = /<!--(?:(?!-->)[^]){0,400}-->|<\/?[A-Za-z][A-Za-z0-9:_-]{0,24}(?:[ \t\r\n][^<>]{0,200})?\/?>/g; // tags and comments, deleted: pass<b></b>word
const BS_RUN = /\\+/g;
const BS_RUN2 = /\\{2,}/g; // a view with every run of two or more backslashes deleted (a log line escaped five times): between a keyword and its separator or quote
const BS_RUN2_TEST = /\\\\["'`:=]/; // two backslashes before a quote or a separator (the last two of a run: a pattern with \\{2,} here would be quadratic on a long run)
const BS_RUN2_G = /\\\\["'`:=]/g;
// a numeric reference cut by a backslash escape or another reference ("&#10\\x31;", "&#1&#48;1;"), an octal escape followed by a digit or a leading-zero one followed by a space
const ALT_TRIGGER_G = /&#[xX]?[0-9a-fA-F]*[\\&]|\\[0-3][0-7]{2}[0-7]|\\0[0-7]{2}[ ]|%(?:u00)?(?:26|23|5[cC])/g;
const ALT_TRIGGER_T = /&#[xX]?[0-9a-fA-F]*[\\&]|\\[0-3][0-7]{2}[0-7]|\\0[0-7]{2}[ ]|%(?:u00)?(?:26|23|5[cC])/; // (the last: a percent layer that makes the "&#" or the backslash)
// A tag is deleted from the markup view when it is a known HTML element, carries a namespace or attributes, or is a comment: pass<b></b>word. <your-token> and <password>
// after an equals sign are placeholders, not markup, and stay.
const HTML_TAGS = new Set(('a abbr b bdi bdo big blockquote body br button caption center cite code col colgroup dd del details dfn div dl dt em fieldset figcaption figure font footer form h1 h2 h3 h4 h5 h6 head header hr html i iframe img input ins kbd label legend li link ' +
  'main mark meta nav noscript object ol optgroup option p pre q s samp section select small span strike strong style sub summary sup table tbody td textarea tfoot th thead title tr tt u ul var wbr xml x y z').split(' '));
const markupGone = (m) => {
  const t = m[0];
  if (t.startsWith('<!')) return '';
  const nm = /^<\/?([A-Za-z][A-Za-z0-9:_-]*)/.exec(t);
  return nm && (HTML_TAGS.has(nm[1].toLowerCase()) || nm[1].includes(':') || /[ \t\r\n]/.test(t)) ? '' : t;
};
const TAB_NL = /[\t\n\r]+/g; // WHATWG URL parsing strips tab and newline anywhere in a URL

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Value shapes.
const SAFE_SUFFIX = new Set(('type types endpoint url uri policy policies reset length count expiry expires expiration ttl bucket rotation age min max strength field hint label ' +
  'placeholder required enabled disabled manager store vault name ref path file header scheme prefix limit lifetime status kind format rules rule validation complexity ' +
  'history attempts page form input mode algorithm alg method location source ' +
  'id ids kid last4 lastfour issuer audience aud claims use usage scope scopes details server servers methods supported timeout domain provider samesite maxage interval ' +
  'duration idle changed updated last set valid configured present verified confirmed time at days minutes seconds hours flow flows exchange basic post jwt ' +
  'js ts jsx tsx mjs cjs json yaml yml md txt py go rs java rb sh css html xml toml ini cfg conf log lock ' +
  'state bytes byte dir dirs directory param params parameter title sock socket fingerprint fingerprints size bits backend driver engine require requires allow allows reuse score entropy cost rotate ' +
  'cache caching storage description desc stored saved digit digits uppercase lowercase symbol symbols special numeric minimum maximum ' +
  'validator generator checker meter authentication authenticator encryption rounds iterations hasher hashers algo auth shell arn arns').split(' '));

const COMMON = new Set(('a an the and or of to for in on at by as if is was are were be been being not no yes with without from into onto this that these those it its can could will ' +
  'would must should may might has have had does do did done but so than then when where which who whom whose how what why too very more most less least also only just still ' +
  'already always never now here there out up down over under again once all any each every some such own same other another few many much both either neither one two three ' +
  'four five required invalid valid correct incorrect wrong right expired missing empty blank set unset stored hashed salted encrypted secure insecure strong weak accepted ' +
  'rejected denied granted ok okay fine good bad fresh new old current temporary permanent reset changed unchanged updated verified unverified checked locked unlocked ' +
  'disabled enabled optional mandatory hidden shown visible masked redacted default unknown null none undefined true false sent received issued revoked rotated managed shared ' +
  'private public safe unsafe long short simple complex common unique different identical matching mismatched needed used ready available unavailable supported allowed ' +
  'forbidden refused failed successful pending active inactive stale case least about after before between during per via using within again ' +
  'your my our their his her dynamic static manual automatic absent internal external ephemeral overridden random generated custom important necessary essential critical crucial vital useful helpful sensitive confidential personal individual standard typical normal regular special specific ' +
  'general main basic key main primary secondary additional extra final initial first last next previous recent early late easy hard difficult impossible possible ' +
  'likely unlikely certain sure clear obvious visible invisible readable unreadable reasonable acceptable unacceptable appropriate suitable sufficient insufficient ' +
  'min minimum max maximum click tap press see visit go open use enter choose select follow contact ask type check read learn hover sign log below above up down ' +
  'must needs need na tbd todo tba shown displayed prompted sent emailed texted entered typed pasted ' +
  'kept found given known chosen taken made written seen gone held left lost paid put saved provided stated listed noted shown').split(' '));
const SUFFIX_COMMON = /(?:able|ible|ous|ful|less|ive|ant|ent|ary|ory|tial|cial|ity|ness|ment)$/;
const isCommonWord = (w) => COMMON.has(w) || (w.length >= 5 && /^[a-z]+(?:ed|ly|ing)$/.test(w)) || (w.length >= 7 && SUFFIX_COMMON.test(w));

// Descriptive technical and configuration words that follow a keyword in documentation ("Token: JWT", "Private key: PEM", "credentials: 'include'").
const TECH_WORDS = new Set(('jwt jws jwe jwk jwks dpop opaque header body query cookie pem der pfx p12 jks rsa ec ecdsa eddsa ed25519 x25519 hmac aes hs256 hs384 hs512 rs256 rs384 rs512 ' +
  'es256 es384 es512 ps256 ps384 ps512 sha1 sha-1 sha256 sha-256 sha384 sha-384 sha512 sha-512 md5 bcrypt scrypt argon2 argon2id pbkdf2 iam oauth oauth2 oidc saml mtls tls ssl ' +
  'bearer basic digest negotiate none mock-issued write-only read-only mock mocked simulated sample demo example placeholder redacted ' +
  'await async new function require import return this self props state req res args process env config os getenv ' +
  'base64 base64url hex utf8 utf-8 ascii plaintext plain json xml yaml url aws4 aws gcm cbc ctr sha224 sha-224 sha3 blake2 hs rs es ps sid sessionid jsessionid phpsessid connect.sid').split(' '));
const CONFIG_WORDS = new Set(['include', 'omit', 'same-origin', 'same-site', 'strict', 'lax']);
const LABEL_WORDS = new Set(['required', 'optional', 'invalid', 'incorrect', 'expired', 'missing', 'empty', 'hidden', 'masked', 'redacted', 'none', 'null', 'unknown', 'valid', 'correct', 'wrong', 'changed', 'reset', 'set', 'unset', 'ok']);
// Hint and label words of the languages the keywords cover (a localized UI: "Passwort: mindestens 8 Zeichen", "Mot de passe : requis", "\u5bc6\u7801\uff1a\u672a\u8bbe\u7f6e"). They are folded the way the
// matcher folds the text, so accents and look-alike Cyrillic letters compare equal. The CJK and Hangul entries match as prefixes (those scripts have no spaces).
const HINT_WORDS = new Set(('mindestens nicht kein keine erforderlich pflicht pflichtfeld ung\u00fcltig falsch richtig leer gesetzt festgelegt optional n\u00f6tig notwendig ' +
  'obligatoria obligatorio requerida requerido m\u00ednimo m\u00ednima minimo no sin inv\u00e1lida vac\u00eda opcional definida necesaria ' +
  'requis requise obligatoire minimum non invalide vide facultatif optionnel d\u00e9fini d\u00e9finie ' +
  'obrigat\u00f3ria obrigat\u00f3rio n\u00e3o inv\u00e1lido vazia vazio ' +
  'obbligatoria obbligatorio minimo impostata vuota facoltativa richiesta ' +
  '\u043e\u0431\u044f\u0437\u0430\u0442\u0435\u043b\u044c\u043d\u043e \u043c\u0438\u043d\u0438\u043c\u0443\u043c \u043d\u0435 \u043f\u0443\u0441\u0442\u043e\u0439 \u043f\u0443\u0441\u0442\u043e \u043d\u0435\u043e\u0431\u0445\u043e\u0434\u0438\u043c \u0442\u0440\u0435\u0431\u0443\u0435\u0442\u0441\u044f \u043d\u0435\u0442 \u0441\u043a\u0440\u044b\u0442 \u0437\u0430\u0434\u0430\u043d').split(' ').map((w) => fold(w.toLowerCase())));
const CJK_HINTS = ['\u672a\u8bbe\u7f6e', '\u672a\u8a2d\u7f6e', '\u672a\u8bbe\u5b9a', '\u672a\u8a2d\u5b9a', '\u81f3\u5c11', '\u5fc5\u586b', '\u5fc5\u987b', '\u5fc5\u9808', '\u4e0d\u80fd\u4e3a\u7a7a', '\u4e0d\u53ef\u4e3a\u7a7a', '\u7a7a', '\u65e0', '\u7121', '\u6682\u65e0', '\u5df2\u8bbe\u7f6e', '\u5df2\u8a2d\u5b9a',
  '\u8a2d\u5b9a\u3055\u308c', '\u8a2d\u5b9a\u306a\u3057', '\u672a\u5165\u529b', '\u5165\u529b\u5fc5\u9808', '\u5fc5\u8981', '\ud544\uc218', '\uc124\uc815', '\ube44\uc5b4', '\ucd5c\uc18c', '\uc785\ub825', '\uc5c6\uc74c'];
const isHint = (w) => HINT_WORDS.has(w) || (w.charCodeAt(0) > 0x2e80 && CJK_HINTS.some((h) => w.startsWith(h)));
const NA_RE = /^(?:n\/a|n\.a\.?|n\/d|tbd|tba|nil|-{1,3}|\?{1,3}|\(none\)|\(not set\))$/i;
// Names made only of credential and plumbing vocabulary are names of things, not secrets: auth_token, JWT_SECRET, x-api-key, process.env.JWT_SECRET.
const NAME_VOCAB = new Set(('password passwd passphrase passcode pwd pw pass secret secrets token tokens key keys auth authorization bearer basic cookie session sessions sid login user username id name field header param api access refresh ' +
  'client csrf xsrf jwt app db env config value data store storage local cache account credential credentials cred creds private public signing encryption master service ssh sig signature xsrf-token').split(' '));
const CODE_ROOTS = /^(?:process\.env|os\.environ|os\.getenv|os\.Getenv|System\.getenv|import\.meta\.env|ENV|env|config|settings|options|opts|props|state|this|self|req|request|res|args|params|ctx|vars|secrets|credentials|user|data|body|var|local|locals|module|each|Rails|Settings|Secrets|Credentials)(?:[.[(]|$)/;
const CALL_CHAIN = /^[A-Za-z_$][\w$]*(?:\.[A-Za-z_$][\w$]*)*\([^()]{0,40}\)(?:\.[A-Za-z_$][\w$]*(?:\([^()]{0,40}\))?)*[;,]?$/; // z.string().min(8)
const CODE_KW = new Set(['await', 'async', 'new', 'function', 'require', 'import', 'return', 'this', 'self', 'props', 'state', 'req', 'res', 'args', 'process', 'env', 'config', 'os', 'getenv', 'null', 'nil', 'none', 'undefined', 'input', 'prompt', 'getpass', 'readline', 'fetch']);
const PERM_VERBS = new Set(['read', 'write', 'delete', 'create', 'list', 'rotate', 'revoke', 'verify', 'update', 'get', 'put', 'post', 'admin', 'manage', 'view', 'edit', 'issue', 'refresh', 'validate', 'use', 'all', 'full', 'readonly', 'rw', 'ro', 'reset', 'expire', 'exchange', 'introspect', 'mint', 'sign', 'decrypt', 'encrypt', 'unlock', 'lock']);
function nameLike(cv) {
  if (cv.length > 80) return false;
  const parts = cv.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase().split(/[^a-z0-9]+/).filter(Boolean);
  return parts.length >= 2 && parts.every((p) => NAME_VOCAB.has(p) || TECH_WORDS.has(p));
}
const FILE_RE = /^[\w@./-]*\.(?:txt|csv|json|ya?ml|md|log|conf|cfg|ini|env|js|ts|py|sh|pem|key|crt|cer|p12|pfx|jks|xml|toml|properties|list|db|sql|html|css|go|rs|java|rb|php|lock|tsv|pub|asc|gpg|enc|bak)$/i;
const REGEX_LIT = /^\/(?!\/)[^\n]{2,}\/[gimsuy]*;?$/;
function isCodeExpr(cv) {
  if (cv.startsWith('...') && /^\.\.\.[A-Za-z_$]/.test(cv)) return true;
  if (REGEX_LIT.test(cv) && /\(\?|\\[dwsb]|\.[*+]|\[|\^|\$/.test(cv)) return true;
  if (CODE_ROOTS.test(cv) && cv.length > 4) return true;
  if (CALL_CHAIN.test(cv) && !/^["']/.test(cv)) return true;
  return false;
}
const isSoftWord = (w) => LABEL_WORDS.has(w) || TECH_WORDS.has(w) || CONFIG_WORDS.has(w) || isHint(w) || NA_RE.test(w) || FILE_RE.test(w) || nameLike(w) || /^urn:[a-z0-9._:-]+$/.test(w);

const DASH = '[-\\u2010-\\u2015\\u2212]';
const DATE_RE = new RegExp(`^\\d{4}${DASH}\\d{2}${DASH}\\d{2}(?:[Tt ]\\d{2}:\\d{2}(?::\\d{2}(?:\\.\\d{1,9})?)?(?:[Zz]|[+-]\\d{2}:?\\d{2})?)?$`);
const DATE2_RE = /^(?:\d{4}[/.]\d{1,2}[/.]\d{1,2}|\d{1,2}[/.]\d{1,2}[/.]\d{2,4}|\d{4}\u5e74\d{1,2}\u6708(?:\d{1,2}\u65e5)?|\d{4}\ub144\d{1,2}\uc6d4(?:\d{1,2}\uc77c)?)$/;
const VERSION_RE = new RegExp(`^(?:[~^<>=]{1,2}[ ]?)?[vV]?\\d{1,4}(?:\\.(?:\\d{1,4}|[xX*])){1,3}(?:[-+][0-9A-Za-z.${'\\u2010-\\u2015\\u2212'}-]{1,30})?$`);
const FIGURE_RE = /^(?:[A-Z]{1,6}-\d{1,6}|\d{1,3}\/\d{1,3}|(?:GPIO|IO)\d{1,3}|\d{1,2}:\d{2}(?::\d{2})?[-\u2013]\d{1,2}:\d{2}(?::\d{2})?|[$\u20ac\u00a3\u00a5\u20b9]\d{1,9}(?:[.,]\d{1,3})*[kKmM]?|\d{1,3}(?:[,.]\d{3})+(?:\.\d+)?|\d{1,9}(?:\.\d+)?%|\d{1,4}[-\u2013]\d{1,4}|S-1-\d+(?:-\d+){1,8}|[~^]?\d+(?:\.\d+){0,2}\.[xX*]|latest|workspace:\*|npm:[@\w./-]+|[@\w./-]+@[~^]?\d+(?:\.\d+){0,3}(?:-[\w.]+)?)$/;
const TIME_RE = /^\d{1,6}:\d{1,6}(?::\d{1,6})?$/;
const isDateOrVersion = (c) => c.length <= 64 && (DATE_RE.test(c) || DATE2_RE.test(c) || VERSION_RE.test(c) || TIME_RE.test(c) || FIGURE_RE.test(c)); // dates, versions and everyday figures (1,024  $99  8-64  ^9.0.2  S-1-5-21-1)

// Strip wrapping quotes/brackets and trailing sentence punctuation by index loops (an `x+$` regex would be quadratic on long punctuation runs).
const isOpenWrap = (c) => c === 34 || c === 39 || c === 96 || c === 40 || c === 91 || c === 123 || c === 60;
const isTrailWrap = (c) => c === 34 || c === 39 || c === 96 || c === 41 || c === 93 || c === 125 || c === 62 || c === 46 || c === 44 || c === 59 || c === 58 || c === 33 || c === 63;
function core(v) {
  let a = 0;
  let b = v.length;
  while (a < b && isOpenWrap(v.charCodeAt(a))) a += 1;
  while (b > a && isTrailWrap(v.charCodeAt(b - 1))) b -= 1;
  return a === 0 && b === v.length ? v : v.slice(a, b);
}

// Has a digit, a symbol, or an inner capital (a capital after position 0 in a word that also holds a lowercase letter).
function shapeOf(v) {
  let digit = false;
  let sym = false;
  let upper = false;
  let lower = false;
  let innerCap = false;
  for (let i = 0; i < v.length; i += 1) {
    const c = v.charCodeAt(i);
    if (isDigitC(c)) digit = true;
    else if (isUpperC(c)) { upper = true; if (i > 0 && (isLowerC(v.charCodeAt(i - 1)) || isDigitC(v.charCodeAt(i - 1)))) innerCap = true; } else if (isLowerC(c)) lower = true;
    else if (c < 128 && c !== 32) sym = true;
  }
  return { digit, sym, innerCap: innerCap && lower, upper, lower };
}
const PLAIN_HYPHEN = /^[A-Za-z][a-z]{0,29}(?:[-_'][A-Za-z][a-z]{0,29})?$/;
const HOSTLIKE = /^[a-z0-9][a-z0-9-]{0,40}(?:\.[a-z0-9-]{1,40}){1,5}$/;
const PATHISH = /^[\w.@-]+(?:\/[\w.@-]+){1,}\/?$/; // kubernetes.io/serviceaccount/token  a path is not a secret
const NAMESPACED_KEY = /^[a-z][a-z0-9_-]{1,30}(?::[A-Za-z0-9_-]{1,30}){1,4}$/; // cache keys: users:123  cache:user:42:profile
const PAIRLIKE = /^[A-Za-z_][A-Za-z0-9_-]{0,30}=/;
const COMPOUND_ADJ = /^[A-Za-z0-9]{1,15}-(?:encoded|based|bound|safe|only|free|less|like|aware|ready|related|specific|scoped|signed|hashed|encrypted|protected|compatible|compliant|style|level|side|type|wide|first|driven|backed|managed|issued|bearing|owned|stored|enabled|disabled|sensitive)$/i;
const ARTICLES = new Set(['the', 'a', 'an', 'my', 'your', 'our', 'his', 'her', 'their', 'this', 'that', 'these', 'those', 'its']);
function wordAt(Fm, n, i) {
  while (i < n && (Fm.charCodeAt(i) === 32 || Fm.charCodeAt(i) === 58 || Fm.charCodeAt(i) === 61)) i += 1;
  let r = i;
  while (r < n && r < i + 8 && isLetterC(Fm.charCodeAt(r))) r += 1;
  return Fm.slice(i, r).toLowerCase();
}
const GAP_LEAD = /^(?:for|of|to|on|in|at|from)[ ]/i;
const COOKIE_ATTR_START = /^;[ ]*(?:max-age|expires|path|domain|samesite|secure|httponly|partitioned|priority)\b/i;
const NEXT_KEY_COLON = /[ \t]*(?:-[ \t]+)?[A-Za-z_][\w.-]{0,60}[ \t]*:/y;
const NEXT_KEY_EQ = /[ \t]*(?:export[ \t]+)?(?:[A-Z][A-Z0-9_]{1,60}|[a-z][a-z0-9_.-]{1,60})[ \t]*=(?!=)/y;
const DEGREES = new Set(['phd', 'md', 'msc', 'bsc', 'mba', 'ba', 'bs', 'ma', 'ms', 'dds', 'dvm', 'jd', 'llb', 'llm', 'rn', 'cpa', 'pmp', 'cissp', 'cfa', 'cfp', 'dpt', 'mfa', 'mph', 'msw', 'bba', 'beng', 'meng', 'btech', 'mtech', 'ba/bs', 'cism', 'ccna', 'ccnp', 'aws', 'itil']);
const CHAIN_START = /^[ ]*(?:is|are|was|were|be|equals?|set[ ]to|to|as|becomes?|stays?|remains?|reads?|says?)\b/i;
const IDENT_PUNCT = /^[A-Za-z_$]+(?:\.[A-Za-z_$][\w$]*)*[\])}(;,]+$/;
const CALLLIKE = /^[A-Za-z_$][A-Za-z_$.]{0,40}\([^)'"]{0,30}\)?;?$/;
// 6+ chars (or minLen) holding a digit, an inner capital or a symbol; plain words, dates and versions stay readable.
// A value that reads as a typed secret rather than as a path or a phrase: a digit, an inner capital or one of ! @ # $ % ^ & * + = ? ~
const STRONG_SYM = /[!@#$%^&*+=?~]/;
function strongShape(cv, minLen) {
  return shapeOK(cv, minLen) && (STRONG_SYM.test(cv) || /\d/.test(cv) || shapeOf(cv).innerCap);
}
function shapeOK(cv, minLen) {
  if (cv.length < minLen) return false;
  if (cv.length <= 64 && isDateOrVersion(cv)) return false;
  const s = shapeOf(cv);
  if (!(s.digit || s.sym || s.innerCap)) return false;
  if (!s.digit && !s.innerCap && cv.length <= 62 && PLAIN_HYPHEN.test(cv)) return false;
  return true;
}
// Values of the "named key" keyword class (key, sig, signature, jwt, pin ...): 6+ characters with a digit, no brackets or slashes, not a date or version.
function kOK(cv, minLen) {
  if (cv.length < minLen || cv.length > 4096) return false;
  if (NAMESPACED_KEY.test(cv)) return false;
  if (cv.length <= 40 && isDateOrVersion(cv)) return false;
  const lim = Math.min(cv.length, 256);
  let digit = false;
  for (let i = 0; i < lim; i += 1) {
    const c = cv.charCodeAt(i);
    if (isDigitC(c)) digit = true;
    else if (c === 40 || c === 41 || c === 123 || c === 125 || c === 91 || c === 93 || c === 47 || c === 92 || c === 32) return false;
  }
  return digit;
}
const PLACEHOLDER = /(?:<[A-Za-z][A-Za-z _-]{0,30}>|0{8}-0{4}-0{4}-0{4}-0{12}|CHANGE_?ME|REPLACE_?ME|\{\{|\$\{|\$\(|<%|%\(|\[masked[:\]]|\[redacted|\[REDACTED|\*{3,}|<redacted|<your|<password|<secret|<token|\$[A-Z_][A-Z0-9_]{2,}\b|x{6,}\b|YOUR_|your[_-]|\$\d{1,3}(?![A-Za-z0-9])|\?(?![A-Za-z0-9_?])|%[sd](?![A-Za-z0-9])|:[a-z][a-z_]{1,30}(?![A-Za-z0-9_])|\$[a-z_][a-z_]{2,30}(?![A-Za-z0-9_]))/y;

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Keyword finder. Letters of a keyword may be separated by up to three White_Space characters (the "separators inside a keyword" view);
// the words of a two-word keyword may also be separated by up to three spaces, underscores, dots or hyphens.
const WCLS = '[ \\t\\n\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const WNS = '[\\t\\n\\r\\u00a0\\u1680\\u2000-\\u200a\\u2028\\u2029\\u202f\\u205f\\u3000]';
const T = (w, cls = WCLS) => w.split('').join(`${cls}{0,3}`); // up to three separators between two letters (CRLF is two)
const SEPW = `(?:[ _.-]|${WCLS}){0,3}`;
const KW2 = (a, b) => `${T(a)}${SEPW}${T(b)}`;
const KW3 = (a, b, c) => `${T(a)}${SEPW}${T(b)}${SEPW}${T(c)}`;
const KEYQ = '(?:signing|encryption|master|ssh|license|storage|service|deploy|app|hmac|wifi|devops|shared|webhook|symmetric|subscription|functions|auth|client|session|rsa|aes|tls|serial|product|registration|activation|recovery|backup|cipher|wpa[23]?|wep)';
const CODEQ = '(?:recovery|verification|backup|security|activation|confirmation|authentication|auth|reset|access|invite|invitation|login|signin|sms|2fa|mfa|totp|hotp|otp|pin|unlock|door|gate|alarm|entry|garage|authorization)';
const SEEDQ = '(?:totp|hotp|otp|mfa|2fa|authenticator|wallet|bip39)';
// name -> [class, spaceOK]. P: password family; S: secret/token family; W: weak words that need a digit/symbol/capital in the value; K: named-key words that
// need a separator AND a value of 6+ with a digit.
const KWINFO = {
  password: ['P', true], passphrase: ['P', true], passcode: ['P', true], passwd: ['P', true], pwd: ['P', true], pw: ['P', true],
  psw: ['P', true], pswd: ['P', true], pword: ['P', true], passw: ['P', true], passwrd: ['P', true], passwort: ['P', true], kennwort: ['P', true], contrasena: ['P', true],
  motdepasse: ['P', true], senha: ['P', true], identifiedby: ['P', true],
  '\u5bc6\u7801': ['P', true], '\u5bc6\u78bc': ['P', true], '\u53e3\u4ee4': ['P', true], '\u30d1\u30b9\u30ef\u30fc\u30c9': ['P', true], '\ube44\ubc00\ubc88\ud638': ['P', true], '\uc554\ud638': ['P', true],
  requirepass: ['P', true], masterauth: ['P', true], pat: ['W', true], webhook: ['W', true], webhookurl: ['W', true],
  'pa\u00dfwort': ['P', true], '\ud328\uc2a4\uc6cc\ub4dc': ['P', true], storepass: ['P', true], keypass: ['P', true], truststorepass: ['P', true], dsn: ['K', false], hotp: ['K', false],
  seedphrase: ['S', true], recoveryphrase: ['S', true], mnemonic: ['S', true], connectionstring: ['S', true], secretword: ['S', true], authorizationcode: ['S', true], phpsessid: ['S', true], sessid: ['S', true],
  secretkey: ['S', true], secret: ['S', true], apikey: ['S', true], accesskey: ['S', true], privatekey: ['S', true], accountkey: ['S', true], credential: ['S', true], cred: ['S', true], creds: ['S', true],
  token: ['S', true], accesstoken: ['S', true], refreshtoken: ['S', true], authtoken: ['S', true], apitoken: ['S', true], idtoken: ['S', true], bearertoken: ['S', true],
  sessiontoken: ['S', true], csrftoken: ['S', true], xsrftoken: ['S', true], clientsecret: ['S', true], psk: ['S', false], clientassertion: ['S', true], codeverifier: ['S', true],
  authorization: ['W', true], bearer: ['W', true], jsessionid: ['S', true], sessionid: ['S', true],
  pass: ['W', true], passkey: ['W', false], pin: ['W', true], sid: ['W', true], login: ['W', true], auth: ['K', false, 8], basic: ['K', false, 8], cookie: ['K', false, 8], session: ['K', false, 8],
  key: ['K', false], sig: ['K', false], signature: ['K', false], jwt: ['K', false], otp: ['K', false], totp: ['K', false],
};
// The Russian word for password, in the forms the matcher sees: folded from lower case, from capitals (the capital soft sign folds to a Latin letter, the small one
// does not) and from mixed case. The key is the lower-cased folded form.
const CYR_PASSWORD = '\u043f\u0430\u0440\u043e\u043b\u044c';
const CYR_VARIANTS = [...new Set([fold(CYR_PASSWORD), fold(CYR_PASSWORD.toUpperCase())])];
for (const v of CYR_VARIANTS) KWINFO[v.toLowerCase()] = ['P', true];
const KEYQ_NAME = new RegExp(`^${KEYQ}key$`);
const CODE_NAME = new RegExp(`^(?:${CODEQ.slice(3, -1)}|onetime)codes?$|^${SEEDQ}(?:seed|secret|key)$`);
const infoFor = (name) => (Object.hasOwn(KWINFO, name) ? KWINFO[name] : undefined) || (KEYQ_NAME.test(name) || CODE_NAME.test(name) || name.startsWith('aspsessionid') ? ['S', true] : undefined);
const KW_ALTS = [
  `${T('identified')}(?:[ ]+with[ ]+[A-Za-z0-9_]{1,40})?${SEPW}${T('by')}`, KW3('mot', 'de', 'passe'), T('contrasena'), T('kennwort'), T('passwort'), T('senha'),
  T('storepass'), T('keypass'), T('truststorepass'), KW2('pass', 'phrase'), KW2('pass', 'code'), KW2('pass', 'word'), T('passwd'), T('passwrd'), KW2('pass', 'key'), T('passw'), T('pswd'), T('psw'), T('pword'), T('pwd'), T('pw'), T('pass'),
  T('accesstoken'), T('refreshtoken'), T('authtoken'), T('apitoken'), T('idtoken'), T('bearertoken'), T('sessiontoken'), T('csrftoken'), T('xsrftoken'), T('clientsecret'),
  KW2('client', 'assertion'), KW2('code', 'verifier'),
  `${SEEDQ}${SEPW}(?:seed|secret|key)`, `(?:${CODEQ.slice(3, -1)}|one${SEPW}time)${SEPW}codes?`, T('requirepass'), T('masterauth'), KW2('webhook', 'url'), T('webhook'), T('pat'),
  KW2('seed', 'phrase'), KW2('recovery', 'phrase'), T('mnemonic'), KW2('connection', 'string'), KW2('secret', 'word'), `${T('aspsessionid')}[A-Za-z]{0,12}`, T('phpsessid'), T('sessid'),
  KW2('secret', 'key'), T('secret'), KW2('api', 'key'), KW2('access', 'key'), KW2('private', 'key'), KW2('account', 'key'), T('credential'), T('creds'), T('cred'), T('token'),
  T('authorization'), T('bearer'), T('jsessionid'), KW2('session', 'id'),
  `${KEYQ}[ _.-]?key`,
  T('signature', WNS), T('sig', WNS), T('psk', WNS), T('jwt', WNS), T('totp', WNS), T('hotp', WNS), T('otp', WNS), T('pin', WNS), T('key', WNS), T('dsn', WNS),
  T('auth'), T('basic'), T('cookie'), T('session'), T('sid', WNS), T('login', WNS),
  ...CYR_VARIANTS.map((v) => T(v)), T('\u5bc6\u7801'), T('\u5bc6\u78bc'), T('\u53e3\u4ee4'), T('\u30d1\u30b9\u30ef\u30fc\u30c9'), T('\ube44\ubc00\ubc88\ud638'), T('\uc554\ud638'), T('\ud328\uc2a4\uc6cc\ub4dc'),
  `${T('pa')}${WCLS}{0,3}[\u00df\u1e9e]${WCLS}{0,3}${T('wort')}`,
];
const KW = new RegExp(`(?:${KW_ALTS.join('|')})`, 'gi');
const kwName = (m) => { const n = m.toLowerCase().replace(/[\s_.-]/g, ''); return n.startsWith('identified') ? 'identifiedby' : n; };

const SHORT_NAMES = new Set(['pat', 'pw', 'pwd', 'pass', 'passwd', 'psw', 'pswd', 'pword', 'passkey', 'sid', 'login', 'auth', 'basic', 'cookie', 'session', 'bearer', 'key', 'sig', 'psk', 'jwt', 'otp', 'totp', 'pin', 'cred', 'creds']);
// A password abbreviation glued to one of these prefix words is a name (dbpass, rootpw, SSHPASS, storepass); glued to anything else it is an ordinary word
// (compass, bypass, impasse).
const PASS_PREFIXES = ['db', 'sql', 'mysql', 'pg', 'postgres', 'mongo', 'redis', 'root', 'admin', 'user', 'usr', 'ssh', 'ftp', 'sftp', 'smtp', 'imap', 'pop', 'ldap', 'bind', 'wifi', 'wlan',
  'proxy', 'store', 'trust', 'truststore', 'keystore', 'key', 'app', 'api', 'sys', 'sa', 'master', 'service', 'svc', 'client', 'server', 'host', 'vpn', 'smb', 'rdp', 'oracle', 'mq', 'amqp', 'kafka',
  'sudo', 'su', 'enable', 'unlock', 'backup', 'docker', 'registry', 'git', 'npm', 'admin', 'guest', 'test', 'demo', 'gh', 'github', 'gitlab'];
const KEY_DENY = new Set(['public', 'primary', 'foreign', 'sort', 'partition', 'cache', 'idempotency', 'translation', 'lookup', 'composite', 'unique', 'natural', 'surrogate', 'row', 'map',
  'object', 'group', 'order', 'shard', 'search', 'react', 'i18n', 'hot', 'short', 'api', 'item', 'list', 'array', 'dict', 'hash', 'index', 'join', 'sorting', 'ssh-public']);
const FLAG_PREFIX = new Set(['num', 'number', 'total', 'count', 'has', 'is', 'show', 'hide', 'no', 'toggle', 'can', 'forgot', 'remember', 'needs', 'require', 'requires', 'required', 'missing', 'enable', 'disable', 'allow', 'with', 'without', 'existing', 'your']);
function prevWord(M, s) {
  // the identifier word right before position s, when glued by _ . - or a camelCase boundary; '' otherwise
  if (s === 0) return '';
  const pc = M.charCodeAt(s - 1);
  let e = s;
  let camel = false;
  if (pc === 95 || pc === 46 || pc === 45) e = s - 1;
  else if (isLowerC(pc) && isUpperC(M.charCodeAt(s))) camel = true;
  else return '';
  let b = e;
  while (b > 0 && b > e - 14 && isLetterC(M.charCodeAt(b - 1))) b -= 1;
  let w = M.slice(b, e);
  if (camel) { const m = /[A-Z]?[a-z]+$/.exec(w); if (m) w = m[0]; }
  return w.toLowerCase();
}
const SCHEMES = new Set(['bearer', 'basic', 'token', 'digest', 'negotiate', 'bot', 'oauth', 'apikey']);

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// The value that follows a keyword. Fm is the whitespace-flattened text (same length as M).
const ROMAN_NUM = /^[IVX]{1,4}(?![A-Za-z0-9])/;
const LIST_MARK = /\d{1,3}[.)](?=[ ])/y;
const isLeader = (c) => c === 46 || c === 95 || c === 45 || c === 126; // . _ - ~
// A run of leader characters (. _ - ~) that is a separator and not decoration: two dots, three underscores (or two when a value follows at once or a space comes before). __TOKEN__ closes a
// placeholder and is not a separator; "pw: ..." (after a colon or equals sign) is not asked at all. Returns the length of the run, 0 when it is not a separator.
function leaderRun(Fm, q, c) {
  let r = q;
  while (isLeader(Fm.charCodeAt(r)) && r < q + 64) r += 1;
  const len = r - q;
  if (c === 46) return len >= 2 && !(len === 3 && Fm.charCodeAt(q - 1) !== 32) ? len : 0; // "pass..." is an ellipsis; "Password ........" and "password.." are leaders
  return len >= 3 || (len === 2 && (isAlnumC(Fm.charCodeAt(r)) || Fm.charCodeAt(q - 1) === 32)) ? len : 0; // ("x __ y" and "x__y" separate; "__TOKEN__" closes a placeholder)
}
function suffixEnd(Fm, n, p) {
  let q = p;
  for (let g = 0; g < 4; g += 1) {
    const c = Fm.charCodeAt(q);
    if (g === 0 && (c === 73 || c === 86 || c === 88) && ROMAN_NUM.test(Fm.slice(q, q + 6))) { // password\u2161=x reads password + II
      q += ROMAN_NUM.exec(Fm.slice(q, q + 6))[0].length;
    } else if ((c === 95 || c === 46 || c === 45) && isAlnumC(Fm.charCodeAt(q + 1))) {
      let r = q + 1;
      const lim = q + 26;
      while (r < n && r < lim && isAlnumC(Fm.charCodeAt(r))) r += 1;
      if (r < n && isAlnumC(Fm.charCodeAt(r))) break; // too long to be a name part: it is a value
      if (SAFE_SUFFIX.has(Fm.slice(q + 1, r).toLowerCase())) return { p: q, safe: true };
      q = r;
    } else if (isUpperC(c) && isLowerC(Fm.charCodeAt(q - 1))) {
      let r = q + 1;
      const lim = q + 26;
      while (r < n && r < lim && (isLowerC(Fm.charCodeAt(r)) || isDigitC(Fm.charCodeAt(r)))) r += 1;
      if (r < n && isAlnumC(Fm.charCodeAt(r)) && !isUpperC(Fm.charCodeAt(r))) break;
      if (SAFE_SUFFIX.has(Fm.slice(q, r).toLowerCase())) return { p: q, safe: true };
      q = r;
    } else if (isDigitC(c) && g === 0) {
      let r = q;
      while (r < n && r < q + 3 && isDigitC(Fm.charCodeAt(r))) r += 1;
      q = r;
    } else break;
  }
  return { p: q, safe: false };
}

// "is", "has been set to", "should be", "equals", "changed to", "as": a short chain of verb words ending in a binding word. Returns { t, strong } or null.
// Strong binders (is are was were be equals become) allow any plain word as the value; weak binders (to, as) need a value that looks like a secret.
const CHAIN_WORDS = new Set(['is', 'are', 'was', 'were', 'be', 'been', 'being', 'has', 'have', 'had', 'will', 'would', 'should', 'shall', 'must', 'can', 'could', 'may', 'might', 'now', 'currently',
  'still', 'just', 'actually', 'simply', 'literally', 'set', 'changed', 'reset', 'updated', 'equals', 'equal', 'to', 'as', 'become', 'becomes', 'became', 'gets', 'got', 'not',
  'stays', 'stay', 'remains', 'remain', 'reads', 'read', 'says', 'shows', 'looks', 'follows', 'following', 'lautet', 'also', 'really', 'always', 'finally', 'honestly', 'today', 'for',
  'es', 'ist', 'sind', 'est', 'sont', 'son', 'sao', 'esta', 'e']); // the last row: Spanish, German, French, Portuguese
const BIND_STRONG = new Set(['following', 'is', 'are', 'was', 'were', 'be', 'been', 'equals', 'equal', 'become', 'becomes', 'became', 'stays', 'stay', 'remains', 'remain', 'read', 'reads', 'says', 'shows', 'follows', 'lautet', 'es', 'ist', 'sind', 'est', 'sont', 'son', 'sao', 'esta', 'e']);
const BIND_WEAK = new Set(['to', 'as']);
const TRAIL_FILLER = new Set(['now', 'currently', 'still', 'just', 'actually', 'simply', 'literally', 'also', 'really', 'always', 'finally', 'honestly', 'today']);
function matchChain(Fm, n, q) {
  let t = q;
  let words = 0;
  let strong = false;
  let weak = false;
  let endBind = -1;
  for (let k = 0; k < 6; k += 1) {
    let u = t;
    while (u < n && (Fm.charCodeAt(u) === 32 || (k > 0 && (Fm.charCodeAt(u) === 58 || Fm.charCodeAt(u) === 61 || Fm.charCodeAt(u) === 44 || Fm.charCodeAt(u) === 45)))) u += 1;
    let r = u;
    while (r < n && r < u + 12 && isLetterC(Fm.charCodeAt(r))) r += 1;
    if (r === u || r - u > 10 || isLetterC(Fm.charCodeAt(r))) break;
    const w = Fm.slice(u, r).toLowerCase();
    if (!CHAIN_WORDS.has(w)) break;
    if (w === 'for' && !/^for[ ]+(?:now|today)\b/i.test(Fm.slice(u, u + 10))) break; // "is, for now, x" - but not "password for the database is x" (the gap rule reads that one)
    words += 1;
    if (BIND_STRONG.has(w)) { strong = true; endBind = r; } else if (BIND_WEAK.has(w)) { weak = true; endBind = r; }
    t = r;
    if (TRAIL_FILLER.has(w) && endBind >= 0) endBind = r;
  }
  if (words === 0 || endBind < 0 || !(strong || weak)) return null;
  return { t: endBind, strong };
}

const FOR_USER = /for[ ]+(?:['"`][^'"`\s]{1,64}['"`]|[A-Za-z0-9_.-]{1,64})(?:@(?:['"`][^'"`\s]{1,64}['"`]|[A-Za-z0-9_.%-]{1,64}))?[ ]*=[ ]*/iy;
const PW_FUNC = /(?:old_)?password[ ]*\([ ]*/iy;
const DECOR = /[ ]*(?:[*?!_~.$]+|#\d{0,3}|\([^()\n]{0,24}\)|\[[^\]\n]{0,24}\]|\])(?=[ ]*[:=*?!~(#[])/y;
const EMPH_BEFORE = /(?:<\/[A-Za-z][A-Za-z0-9]{0,9}>|[*_~`])+(?=[ ]*[:=|])/y; // <strong>Password</strong>: x   **Password**: x
const EMPH_AFTER = /(?:(?:<\/[A-Za-z][A-Za-z0-9]{0,9}>|[*_~`])[ ]*)+/y; // **Password:** x   <b>Password:</b> x
const TAG_REST = /(?:[ ][^<>]{0,160})?>[ ]*/y; // <wsse:Password Type="x">value</wsse:Password>
const TAG_TEXT = /[^<>]{0,200}>[ ]*(?:<[A-Za-z][A-Za-z0-9:_-]{0,20}(?:[ ][^<>]{0,60})?>[ ]*){0,2}/y; // <property name="password">value</property>
const VOID_TAGS = new Set(['input', 'img', 'br', 'hr', 'meta', 'link', 'area', 'base', 'col', 'embed', 'source', 'track', 'wbr']);
const ATTR_VALUE_ALL = /\bvalue[ ]*=[ ]*(?:"([^"]*)"|'([^']*)'|([^\s>"'/]+))/gi;
const QUAL = /[ ]+(?:used|field|value|text|input|entry|box|entered|given|provided|again|confirmation|confirm|repeat|retype|verify)(?=[ ]*[:=])/iy;
const HTML_CELL = /(?:<\/[A-Za-z][A-Za-z0-9]{0,9}>[ ]*){1,2}<([A-Za-z][A-Za-z0-9]{0,9})((?:[ ]+[^<>]{0,160})?)\/?>[ ]*/dy;
const ATTR_VALUE = /\bvalue[ ]*=[ ]*(?:"([^"]*)"|'([^']*)'|([^\s>"']+))/id;
const VALUEFIELD = /["'`\\]*[ ]*[,;]?[ ]*(?:[A-Za-z_:-]{1,16}[ ]*=[ ]*(?:"[^"]{0,60}"|'[^']{0,60}'|[^\s"'<>]{1,60})[ ]+){0,3}(?:[A-Za-z_]{1,24}:[ ]+[^\s:"'{]{1,60}[ ]+){0,3}["'`]?(?:value|val|v|text|data|content|contents|secret|string|default|defaultvalue)["'`]?[ ]*[:=][ ]*/iy;
const LABEL_LEFT = /(?<![A-Za-z0-9_])(?:name|key|id|label|field|header|param|parameter|var|variable|setting|property|prop|attr|attribute|column|env|option|arg|argument|k|n)\\*["'`]?[ ]*[:=][ ]*\\*["'`]?$/i;
const TYPE_ANN = /[&*]*[A-Za-z_][\w.<>[\]|?]{0,30}[ ]*=(?!=)[ ]*/y;
const ARROW = /[ ]*(?:-+>|=+>|>>?)[ ]+(?=\S)/y;
const TAG_START = /^<[/!]?[A-Za-z][A-Za-z0-9-]{0,15}[ />]/;
const AMP_PAIR = /^&(?:#|[A-Za-z]{2,8};|[A-Za-z0-9_.-]{1,40}=)/;

function isAttrEq(Fm, i) {
  // i is the index of an opening quote; true when "name=" precedes it (an attribute in a tag)
  let j = i - 1;
  while (j >= 0 && Fm.charCodeAt(j) === 32) j -= 1;
  if (j < 0 || Fm.charCodeAt(j) !== 61) return false;
  j -= 1;
  while (j >= 0 && Fm.charCodeAt(j) === 32) j -= 1;
  const c = Fm.charCodeAt(j);
  return j >= 0 && (isAlnumC(c) || c === 95 || c === 45 || c === 58);
}

function getBrk(ctx) {
  if (ctx.brk) return ctx.brk;
  const { Fm, n } = ctx;
  const brk = new Int32Array(n + 2);
  brk[n] = n;
  brk[n + 1] = n;
  for (let i = n - 1; i >= 0; i -= 1) {
    const c = Fm.charCodeAt(i);
    brk[i] = c === 32 || c === 34 || c === 38 || c === 60 ? i : brk[i + 1];
  }
  ctx.st.work += n;
  ctx.brk = brk;
  return brk;
}
// End of an unquoted value starting at vs: a space or a double quote ends it, '&' and '<' end it only when they start an entity, a "name=" pair or a tag, and
// a double quote followed by a letter or digit is part of the value.
function valueEnd(ctx, vs) {
  const { Fm, n } = ctx;
  const brk = getBrk(ctx);
  let ve = brk[vs];
  for (let hops = 0; ve < n && hops < 64; hops += 1) {
    const d = Fm.charCodeAt(ve);
    if (d === 38) {
      if (AMP_PAIR.test(Fm.slice(ve, ve + 46))) break;
      ve = brk[ve + 1];
    } else if (d === 60) {
      if (TAG_START.test(Fm.slice(ve, ve + 20))) break;
      ve = brk[ve + 1];
    } else if (d === 34) {
      if (isAlnumC(Fm.charCodeAt(ve + 1)) && ve > vs && isAlnumC(Fm.charCodeAt(ve - 1))) ve = brk[ve + 1]; else break;
    } else break;
  }
  return ve;
}

// <input value="x" type="password">: the value attribute sits BEFORE the attribute that names it. quotePos is the opening quote of the naming attribute's value.
function leftAttrValue(Fm, quotePos) {
  const ts = Fm.lastIndexOf('<', quotePos);
  if (ts < 0 || quotePos - ts > 400) return null;
  const gt = Fm.indexOf('>', ts);
  if (gt !== -1 && gt < quotePos) return null;
  const text = Fm.slice(ts, quotePos);
  let last = null;
  for (const m of text.matchAll(ATTR_VALUE_ALL)) last = m;
  if (!last) return null;
  const g = last[1] !== undefined ? last[1] : last[2] !== undefined ? last[2] : last[3];
  const quoted = last[3] === undefined;
  const cv = core(g);
  PLACEHOLDER.lastIndex = 0;
  if (cv.length < 3 || PLACEHOLDER.test(g) || isSoftWord(cv.toLowerCase())) return null;
  const end = ts + last.index + last[0].length;
  return { a: end - g.length - (quoted ? 2 : 0), b: end, id: 'assignment' };
}

// A literal wrapped in a conversion or constructor call: []byte("x")  Buffer.from("x")  String("x")  new SecureString("x")  b'x'. Returns the length of the wrapper.
const WRAP_CALL = /(?:new[ ]+)?(?:\[\][a-z0-9]{2,8}|Buffer\.from|String::from|bytes|bytearray|str|String|string|SecureString|Secret|Password|Text|text|unicode|utf8|char\[\]|Some|Just|Ok|Optional\.of(?:Nullable)?|Option::Some|std::make_optional|Maybe\.of|Right|Left)\([ ]*(?=["'`])|(?:string|str)\(\d{1,6}\)[ ]+(?=["'])|[bBrRuU]{1,2}(?=["'])/y;
function wrapLen(Fm, q) {
  const c = Fm.charCodeAt(q);
  if (c !== 91 && c !== 66 && c !== 98 && c !== 78 && c !== 110 && !isLetterC(c)) return 0;
  WRAP_CALL.lastIndex = q;
  const m = WRAP_CALL.exec(Fm);
  return m ? m[0].length : 0;
}

// True when the rest of the line after position `at` is blank and the next line starts a new key (a .env example, a YAML mapping that continues below).
function emptyValueAt(ctx, at) {
  const M0 = ctx.M;
  let x = at;
  while (x < ctx.n && (M0.charCodeAt(x) === 32 || M0.charCodeAt(x) === 9)) x += 1;
  if (M0.charCodeAt(x) !== 10 && M0.charCodeAt(x) !== 13) return false;
  let y = x;
  if (M0.charCodeAt(y) === 13) y += 1;
  if (M0.charCodeAt(y) === 10) y += 1;
  NEXT_KEY_COLON.lastIndex = y;
  NEXT_KEY_EQ.lastIndex = y;
  return NEXT_KEY_COLON.test(M0) || NEXT_KEY_EQ.test(M0);
}
// returns { a, b, id } or null. a: start of the whole name; kwStart: start of the keyword text; p0: index just after the keyword (and its plural s / name suffix).
function valueAfter(ctx, a0, kwStart, p0, info, glued, xml, plural, name) {
  const { Fm, n, st } = ctx;
  st.work += 1;
  const [cls, spaceOK] = info;
  if (name === 'pwd') { // the working directory ($(pwd):/app, PWD=/home/alice) is a path, not a password
    let u = p0;
    let sep = false;
    while (u < p0 + 6 && ' :=)}"\''.includes(Fm[u] || '#')) { if (Fm[u] !== ' ') sep = true; u += 1; }
    if (sep && (Fm.charCodeAt(u) === 47 || Fm.charCodeAt(u) === 126 || /^[A-Za-z]:[\\/]/.test(Fm.slice(u, u + 3)))) {
      let e = u;
      while (e < n && e < u + 200 && Fm.charCodeAt(e) > 32 && Fm.charCodeAt(e) !== 34 && Fm.charCodeAt(e) !== 39) e += 1;
      if (isDirLike(Fm.slice(u, e).replace(/[);:,]+$/, ''))) return null;
    }
  }
  let q = p0;
  if (Fm.charCodeAt(q) === 32 && a0 > 0) { // {"password ": ...}  "password\t" = "x": white space between the name and its closing quote
    let r = q;
    while (r < n && r - q < 16 && Fm.charCodeAt(r) === 32) r += 1;
    let r2 = r;
    while (Fm.charCodeAt(r2) === 92 && r2 < r + 16) r2 += 1;
    const d = Fm.charCodeAt(r2);
    if ((d === 34 || d === 39 || d === 96) && Fm.charCodeAt(a0 - 1) === d) q = r;
  }
  let c = Fm.charCodeAt(q);
  let closeQuote = 0;
  if (c === 34 || c === 39 || c === 93 || c === 41 || c === 125 || c === 96) { closeQuote = c; q += 1; } else if (c === 92) { // \" inside an escaped JSON string, any number of backslashes
    let r = q;
    while (Fm.charCodeAt(r) === 92 && r < q + 16) r += 1;
    const d = Fm.charCodeAt(r);
    if (d === 34 || d === 39) { closeQuote = d; q = r + 1; }
  }
  if ((closeQuote === 34 || closeQuote === 39 || closeQuote === 96) && a0 > 0 && Fm.charCodeAt(a0 - 1) === 32) { // {" password": ...}: spaces between an opening quote and the name belong to the name
    let l = a0;
    while (l > 0 && a0 - l < 16 && Fm.charCodeAt(l - 1) === 32) l -= 1;
    if (l > 0 && Fm.charCodeAt(l - 1) === closeQuote) a0 = l;
  }
  if (!closeQuote) { // **Password**: x   <strong>Password</strong>: x   __password__: x
    EMPH_BEFORE.lastIndex = q;
    const em = EMPH_BEFORE.exec(Fm);
    if (em) q += em[0].length;
  }
  const quotedName = (closeQuote === 34 || closeQuote === 39 || closeQuote === 96) && a0 > 0 && Fm.charCodeAt(a0 - 1) === closeQuote;
  let fieldMode = false;
  let attrMode = false;
  let fieldStart = quotedName ? a0 - 1 : a0;
  if (quotedName && isAttrEq(Fm, a0 - 1)) {
    fieldMode = true; // <input name="password" value="x">: only the value attribute is the secret
    attrMode = true;
  } else {
    const wl = Fm.charCodeAt(Math.max(0, fieldStart - 1));
    if (wl === 58 || wl === 61 || wl === 34 || wl === 39 || wl === 32 || wl === 96) {
      if (LABEL_LEFT.test(Fm.slice(Math.max(0, fieldStart - 40), fieldStart))) fieldMode = true; // "name": "password", "value": "x"
    }
    if (fieldMode && !closeQuote) { // --env=DB_PASSWORD=x   $env:DB_PASSWORD = x   -var=password=x: the label word is part of the command, the keyword is the name of the assignment
      let r = q;
      while (Fm.charCodeAt(r) === 32 && r < q + 16) r += 1;
      const d = Fm.charCodeAt(r);
      if (d === 58 || d === 61) fieldMode = false;
    }
  }
  let strong = false;
  let eq = false;
  let soft = false;
  let ws = false;
  let open = 0;
  let viaColon = false;
  let sepAt = -1; // just after the first : or = of the separator
  let colonSpace = true;
  let forUser = false;
  let cellDone = false;
  let vs0 = -1;
  if (fieldMode) {
    VALUEFIELD.lastIndex = q;
    const m = VALUEFIELD.exec(Fm);
    if (m) {
      const sepEnd = q + m[0].length - /[:=][ ]*$/.exec(m[0])[0].length + 1;
      q += m[0].length;
      if (emptyValueAt(ctx, sepEnd)) return null; // name: creds / secret:<newline>  secretName: x
    } else {
      if (!attrMode) return null;
      const left = leftAttrValue(Fm, a0 - 1); // <input value="x" type="password">
      if (left) return left;
      const ts = Fm.lastIndexOf('<', a0);
      if (ts < 0 || a0 - ts > 400) return null;
      const tm = /^<([A-Za-z][A-Za-z0-9:_-]*)/.exec(Fm.slice(ts, ts + 40));
      if (!tm || VOID_TAGS.has(tm[1].toLowerCase())) return null;
      TAG_TEXT.lastIndex = q; // <property name="password">x</property>   <setting name="Password"><value>x</value></setting>
      const tt = TAG_TEXT.exec(Fm);
      if (!tt || Fm.charCodeAt(q + tt[0].indexOf('>') - 1) === 47) return null;
      q += tt[0].length;
      vs0 = q;
      let e = Fm.indexOf('<', q);
      if (e < 0 || e > q + 200) e = Math.min(n, q + 200);
      ctx.cellEnd = e;
    }
    strong = true;
    cellDone = true;
  } else if (Fm.charCodeAt(q) === 60 && Fm.charCodeAt(q + 1) === 47) {
    // <td>Password</td><td>x</td>  <dt>Password</dt><dd>x</dd>  <label>Password</label><input value="x">
    HTML_CELL.lastIndex = q;
    const m = HTML_CELL.exec(Fm);
    if (!m) return null;
    const attrs = m[2] || '';
    const av = attrs ? ATTR_VALUE.exec(attrs) : null;
    if (av) {
      const gi = av[1] !== undefined ? 1 : av[2] !== undefined ? 2 : 3;
      q = m.indices[2][0] + av.indices[gi][0];
      vs0 = q;
      strong = true;
      cellDone = true;
      ctx.cellEnd = q + av[gi].length;
    } else {
      q += m[0].length;
      strong = true;
      cellDone = true;
      vs0 = q;
      let e = Fm.indexOf('<', q);
      if (e < 0 || e > q + 200) e = Math.min(n, q + 200);
      ctx.cellEnd = e;
    }
  }
  if (!cellDone && xml && Fm.charCodeAt(q) === 32) { // <wsse:Password Type="x">value</wsse:Password>
    TAG_REST.lastIndex = q;
    const tr = TAG_REST.exec(Fm);
    if (tr) {
      q += tr[0].length;
      strong = true;
      cellDone = true;
      vs0 = q;
      let e = Fm.indexOf('<', q);
      if (e < 0 || e > q + 200) e = Math.min(n, q + 200);
      ctx.cellEnd = e;
    }
  }
  if (!cellDone) {
    for (let k = 0; k < 4; k += 1) { // Password (again): x   Password *: x   password field: x   password used: x   password[]: x
      DECOR.lastIndex = q;
      let m = DECOR.exec(Fm);
      if (m) { q += m[0].length; continue; }
      QUAL.lastIndex = q;
      m = QUAL.exec(Fm);
      if (m) { q += m[0].length; continue; }
      break;
    }
    let wl = 0;
    let lr = 0;
    let marks = 0; // separator characters other than white space; a run of white space of any length is skipped (it is consumed, so it is never rescanned)
    while (q < n && marks < 16) {
      c = Fm.charCodeAt(q);
      if (c === 32 || c === 43) { ws = true; q += 1; continue; }
      marks += 1;
      if (xml && marks === 1 && c === 62) { strong = true; q += 1; } else if (c === 0x662f || c === 0x306f || c === 0xb294 || c === 0xc740 || c === 0xc774 || c === 0x4e3a || c === 0xac00 || c === 0x304c) { strong = true; q += 1; } /* \u662f \u306f \ub294 \uc740 \uc774 \u4e3a: 'is' */ else if (strong && (wl = wrapLen(Fm, q)) > 0) { q += wl; break; } else if (c === 58 || c === 61) { strong = true; if (c === 61) eq = true; else viaColon = true; if (sepAt < 0) { sepAt = q + 1; colonSpace = Fm.charCodeAt(q + 1) === 32 || c === 61; } q += 1; } else if (c === 44 || c === 59 || c === 124 || c === 47 || c === 62 || c === 126 || c === 45) { soft = true; q += 1; } else if ((c === 46 || c === 95) && !strong && (lr = leaderRun(Fm, q, c)) > 0) { soft = true; q += lr; /* a dot / underscore leader: Password ........ x   password_-_x   password__x */ } else if (c === 60 && (Fm.charCodeAt(q + 1) === 45 || (Fm.charCodeAt(q + 1) === 60 && Fm.charCodeAt(q + 2) === 45))) { strong = true; eq = true; q += Fm.charCodeAt(q + 1) === 45 ? 2 : 3; /* R: password <- "x"   password <<- "x" */ } else if (strong && isDigitC(c) && (LIST_MARK.lastIndex = q, LIST_MARK.test(Fm))) { q = LIST_MARK.lastIndex; /* 1. x   2) x */ } else if (c === 34 || c === 39 || c === 96 || c === 91 || c === 40 || c === 123 || c === 60) { open = c; q += 1; break; } else break;
    }
    if (!(strong || soft || ws) && closeQuote && closeQuote !== 93 && closeQuote !== 41 && closeQuote !== 125 && !fieldMode) {
      let inside = 0; // an odd number of the same quote before the keyword means this quote CLOSES a string that holds the keyword ('#password')
      for (let i = Math.max(0, a0 - 80); i < a0; i += 1) if (Fm.charCodeAt(i) === closeQuote) inside += 1;
      if (inside % 2 === 1) return null;
      open = closeQuote; closeQuote = 0; soft = true;
    } // password\u00bbvalue: a quote right after the keyword opens the value
    if (strong && sepAt >= 0 && Fm.charCodeAt(sepAt) === 59 && COOKIE_ATTR_START.test(Fm.slice(sepAt, sepAt + 20))) return null; // sessionid=; Max-Age=0: a cookie that clears itself
    if (strong && sepAt >= 0 && emptyValueAt(ctx, sepAt)) return null; // DB_PASSWORD=<newline>HOST=localhost: an empty value is not the next line
    if (!(strong || soft || ws)) return null;
    if (glued && !strong) return null;
    if (!strong && a0 > 0 && (Fm.charCodeAt(a0 - 1) === 36 || (Fm.charCodeAt(a0 - 1) === 123 && Fm.charCodeAt(a0 - 2) === 36))) return null; // "Bearer $TOKEN" ${token}: a variable reference, not an assignment
    if (strong && !open) { // **Password:** x   <b>Password:</b> x
      EMPH_AFTER.lastIndex = q;
      const ea = EMPH_AFTER.exec(Fm);
      if (ea && ea[0].endsWith(' ')) q += ea[0].length; // **Password:** x  (closing emphasis, then a space); ***REMOVED*** is a value
    }
  }
  if (!strong && !soft && !spaceOK && !(cls === 'P')) { /* no plain-space form for this keyword, except "my otp is x" */ if (!open && !CHAIN_START.test(Fm.slice(q, q + 24))) return null; }
  let isShape = false;
  let gap = false;
  let weakBind = false;
  if (!cellDone && !strong && !soft && !open) {
    FOR_USER.lastIndex = q;
    const fu = FOR_USER.exec(Fm);
    if (fu && cls === 'P') {
      q += fu[0].length;
      strong = true;
      eq = true;
      forUser = true;
    } else {
      let ch = null;
      let t = q;
      for (let k = 0; k < 6 && !ch; k += 1) { // "the password for the database is X", "password to the drive has been changed to X": up to five plain words, then the verb chain
        const cand = matchChain(Fm, n, t);
        if (cand && !ARTICLES.has(wordAt(Fm, n, cand.t))) { ch = cand; gap = k > 0; break; }
        let r = t;
        while (r < n && r < t + 16 && (isAlnumC(Fm.charCodeAt(r)) || Fm.charCodeAt(r) === 39)) r += 1;
        if (r === t || r - t >= 16 || SAFE_SUFFIX.has(Fm.slice(t, r).toLowerCase())) break;
        t = r;
        while (t < n && Fm.charCodeAt(t) === 32) t += 1;
        const sc = Fm.charCodeAt(t);
        if ((sc === 58 || sc === 61) && (sc === 61 || Fm.charCodeAt(t + 1) === 32) && (cls === 'P' || cls === 'S') && GAP_LEAD.test(Fm.slice(q, q + 5))) { gap = true; strong = true; eq = sc === 61; q = t + 1; break; }
      }
      if (ch) {
        isShape = true;
        weakBind = !ch.strong;
        q = ch.t;
        while (q < n && (Fm.charCodeAt(q) === 32 || Fm.charCodeAt(q) === 58 || Fm.charCodeAt(q) === 61 || Fm.charCodeAt(q) === 44 || Fm.charCodeAt(q) === 45)) q += 1;
        c = Fm.charCodeAt(q);
        if (c === 34 || c === 39 || c === 96) { open = c; q += 1; }
      }
    }
  }
  if (!cellDone) {
    if (strong && forUser) { PW_FUNC.lastIndex = q; const f = PW_FUNC.exec(Fm); if (f) q += f[0].length; }
    // YAML tag and a type annotation between the name and the value
    if (strong) {
      while (q < n && Fm.charCodeAt(q) === 32) q += 1;
      for (let k = 0; k < 3; k += 1) { // password: now X   password: is X   password: set to X
        const ch = matchChain(Fm, n, q);
        if (ch) { q = ch.t; while (q < n && (Fm.charCodeAt(q) === 32 || Fm.charCodeAt(q) === 58 || Fm.charCodeAt(q) === 61)) q += 1; continue; }
        let r = q;
        while (r < n && r < q + 10 && isLetterC(Fm.charCodeAt(r))) r += 1;
        if (r > q && r - q < 10 && Fm.charCodeAt(r) === 32 && TRAIL_FILLER.has(Fm.slice(q, r).toLowerCase())) { q = r; while (Fm.charCodeAt(q) === 32) q += 1; continue; }
        break;
      }
      if (Fm.charCodeAt(q) === 33) { let r = q + 1; while (r < n && r < q + 40 && Fm.charCodeAt(r) > 32 && Fm.charCodeAt(r) !== 34 && Fm.charCodeAt(r) !== 39) r += 1; if (Fm.charCodeAt(r) === 32) { q = r; while (Fm.charCodeAt(q) === 32) q += 1; } }
      if (viaColon) { TYPE_ANN.lastIndex = q; const ta = TYPE_ANN.exec(Fm); if (ta && !/^(?:true|false)\b/i.test(ta[0])) q += ta[0].length; }
    }
  }
  if (!strong && !isShape && !spaceOK && !cellDone) return null; // a soft separator or plain space after a keyword that takes neither: rejected before the value is looked at
  // the value
  let quote = 0;
  let viaEsc = false; // the value was opened by an escaped quote (\" inside an escaped JSON string): it closes the same way, backslashes are not escapes
  if (open === 34 || open === 39 || open === 96) quote = open;
  else if (!open) {
    c = Fm.charCodeAt(q);
    if (c === 92) { let r = q; while (Fm.charCodeAt(r) === 92 && r < q + 16) r += 1; if (Fm.charCodeAt(r) === 34 || Fm.charCodeAt(r) === 39) { q = r; viaEsc = true; } }
    c = Fm.charCodeAt(q);
    if (c === 34 || c === 39 || c === 96) { quote = c; q += 1; }
  }
  let vs = vs0 >= 0 ? vs0 : q;
  PLACEHOLDER.lastIndex = vs; // a quoted or cell value that is a template, an environment reference or one of our own marks
  if (PLACEHOLDER.test(Fm)) return null;
  if (open && !quote) { PLACEHOLDER.lastIndex = vs - 1; if (PLACEHOLDER.test(Fm)) return null; } // [masked:x] after a keyword: the bracket was taken as an opening bracket
  if (open === 123 && eq && !quote && (cls === 'P' || cls === 'S')) quote = 125; // Password={a;b c};Server=h (ODBC): the value runs to the closing brace
  if ((open === 91 || open === 123) && strong && viaColon && !quote && (cls === 'P' || cls === 'S')) { // password: [a, x]   password: {a: x}
    let depth = 1;
    let i = q;
    const stop = Math.min(n, q + 400);
    while (i < stop && depth > 0) {
      const d = Fm.charCodeAt(i);
      if (d === 91 || d === 123) depth += 1; else if (d === 93 || d === 125) depth -= 1;
      i += 1;
    }
    if (depth === 0 && Fm.slice(q, i - 1).split(/[\s,:;]+/).some((tok) => tok && shapeOK(core(tok), 4) && !isSoftWord(core(tok).toLowerCase()))) {
      let fa = a0;
      if (closeQuote && fa > 0 && Fm.charCodeAt(fa - 1) === closeQuote && (closeQuote === 34 || closeQuote === 39 || closeQuote === 96)) { fa -= 1; while (fa > 0 && Fm.charCodeAt(fa - 1) === 92) fa -= 1; }
      return { a: fa, b: i, id: 'assignment' };
    }
  }
  let ve = q;
  let spanEnd;
  if (quote) {
    const stop = Math.min(n, q + LIMITS.KEY_SCAN);
    let i = q;
    while (i < stop) {
      const d = Fm.charCodeAt(i);
      if (d === quote) {
        if (!viaEsc && quote !== 96 && Fm.charCodeAt(i + 1) === quote) { i += 2; continue; } // doubled quote inside the value: "a""b"  'it''s'  {a}}b}
        break;
      }
      if (!viaEsc && d === 92 && quote !== 125) {
        i += quote === 39 && Fm.charCodeAt(i + 1) === 39 && Fm.charCodeAt(i + 2) === 39 ? 3 : 2; // \"  and the shell idiom '\''
        continue;
      }
      i += 1;
    }
    if (i > stop) i = stop;
    st.work += i - q;
    if (i < stop && Fm.charCodeAt(i) === quote) { ve = i; spanEnd = i + 1; } else { quote = 0; while (vs < n && Fm.charCodeAt(vs) === 32) vs += 1; }
  }
  let second = -1; // start of the word after a scheme word ("Bearer abc")
  if (!quote) {
    ve = cellDone && ctx.cellEnd !== undefined ? ctx.cellEnd : valueEnd(ctx, vs);
    ctx.cellEnd = undefined;
    if (ve > vs && (info[0] === 'S' || name === 'authorization' || name === 'bearer') && ve - vs <= 10 && Fm.charCodeAt(ve) === 32 && SCHEMES.has(Fm.slice(vs, ve).toLowerCase())) {
      const w = valueEnd(ctx, ve + 1);
      if (w > ve + 1) {
        PLACEHOLDER.lastIndex = ve + 1; // Bearer $TOKEN  Bearer ${token}
        if (PLACEHOLDER.test(Fm)) return null;
        second = ve + 1;
        ve = w;
      }
    }
    spanEnd = ve;
  }
  const sampleEnd = Math.min(ve, vs + LIMITS.SAMPLE);
  st.work += 1 + ((sampleEnd - vs) >> 3); // slicing the sample is a memory copy: one unit per eight characters
  const v = Fm.slice(second >= 0 ? second : vs, sampleEnd);
  let cv = core(v);
  if (cv === '' || MARK_AT.test(cv)) return null; // a value that already holds a mark was masked by an earlier pass
  const lower = cv.toLowerCase();
  if (name.startsWith('credential') && DEGREES.has(lower)) return null; // Credentials: PhD, MD
  if (quote === 96 && (/^--?[A-Za-z]/.test(cv) || /<[A-Za-z _-]{1,30}>/.test(cv))) return null; // Pass `--token <TOKEN>` to authenticate
  if (viaColon && !colonSpace && PERM_VERBS.has(lower)) return null; // tokens:write  secrets:rotate (a permission name)
  let ok = false;
  let id = 'assignment';
  const soften = isSoftWord(lower) || CALLLIKE.test(cv);
  { // self.password = password   this.token = token;   const x = process.env.JWT_SECRET   /^(?=.*\d).{8,}$/: code that names a value, not a value
    const flat = lower.replace(/[^a-z0-9]/g, '');
    if (flat === name && (cls === 'P' || cls === 'S' || cls === 'W')) return null;
    if (!quote && NAME_VOCAB.has(lower) && /[,;)}\]]$/.test(v)) return null; // { token, }  f(token)  key: token;  a property shorthand or an argument, not a value
    if (!quote && (isCodeExpr(vs > 0 && Fm.charCodeAt(vs - 1) === 47 ? `/${cv}` : cv) || isCodeExpr(v))) return null; // (a '/' right after the separator was read as a soft separator)
  }
  if (strong) {
    if (cls === 'P') {
      if (forUser || eq) ok = !CALLLIKE.test(cv) && !(TECH_WORDS.has(lower) && !eq) && !(CODE_KW.has(lower) && !quote);
      else if (quote !== 0) ok = true;
      else ok = cv.length >= 3 && !soften && !isCommonWord(lower) && !isDateOrVersion(cv) && !/^\d{1,2}$/.test(cv);
      if (ok && cellDone) ok = cv.length >= 3 && !soften && !isCommonWord(lower);
    } else if (cls === 'S') {
      ok = !isDateOrVersion(cv) && !soften && !(!quote && isCommonWord(lower)) && !(plural && /^\d{1,9}$/.test(cv)) && !CONFIG_WORDS.has(lower) && !/^\d{1,4}$/.test(cv) && (cv.length >= 3 || quote !== 0);
      if (ok && cellDone) ok = cv.length >= 3;
    } else if (cls === 'K') ok = kOK(cv, info[2] || 6) && !soften;
    else ok = shapeOK(cv, 3) && !soften;
    if (ok && ctx.strict && !quote && !shapeOK(cv, 4)) ok = false; // a soft-break view needs a value that looks like a secret
  } else if (isShape) {
    id = 'phrase';
    if (COMPOUND_ADJ.test(cv)) ok = false;
    else if (weakBind) ok = cls === 'K' ? kOK(cv, info[2] || 6) && !soften : (shapeOK(cv, 4) || (quote !== 0 && cv.length >= 3 && (cls === 'P' || cls === 'S'))) && !soften && !PRODUCTISH.test(cv);
    else if (gap) ok = (cls === 'P' && cv.length >= 3 && !soften && !isCommonWord(lower) && !isDateOrVersion(cv) && !/^\d{1,3}$/.test(cv)) || ((cls === 'S' || spaceOK) && cls !== 'P' && shapeOK(cv, 3) && !/^\d+$/.test(cv));
    else if (cls === 'P') ok = cv.length >= 3 && !isDateOrVersion(cv) && !isCommonWord(lower) && !soften;
    else if (cls === 'K') ok = kOK(cv, info[2] || 6) && !soften; // my otp is 482913   the cookie is x1y2z3
    else ok = shapeOK(cv, 3) && !isDateOrVersion(cv);
  } else {
    id = 'shape';
    ok = spaceOK && shapeOK(cv, 6) && !soften && !(PAIRLIKE.test(cv) && !shapeOK(cv.slice(cv.indexOf('=') + 1), 6)) && !IDENT_PUNCT.test(v) && Fm.charCodeAt(ve - 1) !== 58 && !(cls === 'W' && HOSTLIKE.test(cv)) && !PATHISH.test(cv) && !(vs > 2 && Fm.charCodeAt(vs - 1) === 45 && Fm.charCodeAt(vs - 2) === 45 && Fm.charCodeAt(vs - 3) === 32); // (secret --from-file=./x: the value follows a --flag; password--x is a separator)
  }
  if (!ok) return null;
  // the span starts at the beginning of the whole name (DB_PASSWORD, accessToken) and at the opening quote of a JSON key; in a name/value pair
  // (<input name="password" value="x">, {"name":"password","value":"x"}, <td>Password</td><td>x</td>) only the value is the span
  let a = a0;
  if (fieldMode || cellDone) return { a: quote ? vs - 1 : vs, b: spanEnd, id };
  if (closeQuote && a > 0 && Fm.charCodeAt(a - 1) === closeQuote && (closeQuote === 34 || closeQuote === 39 || closeQuote === 96)) { a -= 1; while (a > 0 && Fm.charCodeAt(a - 1) === 92) a -= 1; }
  // "old -> new": a changed password lists both
  if (strong || isShape) {
    ARROW.lastIndex = spanEnd;
    const am = ARROW.exec(Fm);
    if (am) {
      const w0 = spanEnd + am[0].length;
      const w1 = valueEnd(ctx, w0);
      if (w1 - w0 >= 3 && w1 - w0 <= 200) { const w = core(Fm.slice(w0, w1)); if (w.length >= 3 && !isCommonWord(w.toLowerCase()) && !isSoftWord(w.toLowerCase())) spanEnd = w1; }
    }
  }
  return { a, b: spanEnd, id };
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Left-hand and instruction forms: "<value> is my password", "use <value> as the password", "<value> (password)", "when asked for the password, type <value>".
const REV_PREP = /(?:as|for|into|in|to)[ ]+(?:(?:the|my|your|our|a|an)[ ]+)?$/;
const REV_IS = /(?:is|was)[ ]+(?:(?:my|the|your|our|his|her|their|a|an|another|the same)[ ]+)(?:[a-z][a-z0-9-]{0,15}[ ]+){0,2}$/;
const REV_MARK = /(?:\(|#+|\/\/|\[|<)[ ]*(?:the |my |your )?$/;
const USE_VERB = /(?:^|[ ,;:(])(?:use|enter|type|typed|paste|pasted|input|supply|provide|try|submit|send|set|put|write|wrote|say|key in|log in with|login with|sign in with)[ ]+$/;
const NEG_USE = /(?:never|avoid|don't|dont|do not|should not|shouldn't|must not|can't|cannot|not|stop|without)[ ]+(?:ever[ ]+)?(?:use|using|enter|type|choose|pick|set|try|put)[ ]+$/;
const INSTRUCT = /[ ,:;.)-]*(?:then |please |just |simply )?(?:type|enter|use|input|paste|say|answer|reply with|reply|respond with|put|key in|supply|provide|submit|send)[ ]+(["'`]?)([^\s"'`]{3,200})/iy;
const deMd = (t) => t.replace(/^[*_~`]+|[*_~`]+$/g, ''); // markdown emphasis around a word is formatting, not a symbol of the value
function leftValue(ctx, s) {
  const { Fm } = ctx;
  if (s < 8) return null;
  const tail = Fm.slice(Math.max(0, s - 40), s).toLowerCase();
  const valueBefore = (end) => { // the space-free run that ends at `end`
    let e = end;
    while (e > 0 && Fm.charCodeAt(e - 1) === 32) e -= 1;
    let b = e;
    while (b > 0 && b > e - 201 && Fm.charCodeAt(b - 1) !== 32) b -= 1;
    return [b, e];
  };
  // 1. <value> is/was my/the password
  const mi = REV_IS.exec(tail);
  if (mi) {
    const [b, e] = valueBefore(s - (tail.length - mi.index));
    if (e - b >= 6 && e - b <= 200 && (b === 0 || !isAlnumC(Fm.charCodeAt(b - 1))) && shapeOK(core(deMd(Fm.slice(b, e))), 6)) return { a: b, b: e, id: 'phrase' };
    return null;
  }
  // 2. use/enter/type <value> as/for/into the password
  const mp = REV_PREP.exec(tail);
  if (mp) {
    let e = s - (tail.length - mp.index);
    while (e > 0 && Fm.charCodeAt(e - 1) === 32) e -= 1;
    const outerEnd = e;
    const qc = Fm.charCodeAt(e - 1);
    const quoted = qc === 34 || qc === 39 || qc === 96;
    if (quoted) e -= 1;
    let b = e;
    while (b > 0 && b > e - 201 && Fm.charCodeAt(b - 1) !== 32 && !(quoted && Fm.charCodeAt(b - 1) === qc)) b -= 1;
    const outerStart = quoted && Fm.charCodeAt(b - 1) === qc ? b - 1 : b;
    const preUse = Fm.slice(Math.max(0, outerStart - 40), outerStart).toLowerCase();
    if (e - b >= 4 && USE_VERB.test(preUse) && !NEG_USE.test(preUse) && shapeOK(core(deMd(Fm.slice(b, e))), 6)) return { a: outerStart, b: outerEnd, id: 'phrase' };
    return null;
  }
  // 3. <value> (password)  <value> # password
  const mm = REV_MARK.exec(tail);
  if (mm) {
    const markAt = s - (tail.length - mm.index);
    if (Fm.charCodeAt(markAt) === 40 && markAt > 0 && Fm.charCodeAt(markAt - 1) !== 32) return null; // bcrypt.hash(password, 10): a call, not "<value> (password)"
    const [b, e] = valueBefore(markAt);
    if (e - b >= 6 && e - b <= 200 && shapeOK(core(deMd(Fm.slice(b, e))), 6) && !/[('"`{[=:<>]/.test(Fm.slice(b, e))) return { a: b, b: e, id: 'phrase' }; // (not code: cy.get('#password'))
  }
  return null;
}
function instructValue(ctx, e) {
  INSTRUCT.lastIndex = e;
  const m = INSTRUCT.exec(ctx.Fm);
  if (!m) return null;
  const cv = core(m[2]);
  if (!shapeOK(cv, 4)) return null;
  const vs = e + m[0].length - m[2].length - m[1].length;
  return { a: vs, b: e + m[0].length, id: 'phrase' };
}

function scanKeywords(ctx, spans) {
  const { M, Fm, n, st, decoded } = ctx;
  KW.lastIndex = 0;
  let m;
  while ((m = KW.exec(M)) !== null) {
    st.work += 1;
    const s = m.index;
    const e = s + m[0].length;
    if (e === s) { KW.lastIndex = s + 1; continue; }
    const name = kwName(m[0]);
    const info = infoFor(name);
    if (!info) { KW.lastIndex = e; continue; }
    let glued = false;
    if (s > 0) {
      const pc = M.charCodeAt(s - 1);
      if (isAlnumC(pc) && !(isLowerC(pc) && isUpperC(M.charCodeAt(s))) && !decoded && !((pc === 111 || pc === 79) && name.startsWith('auth') && !isAlnumC(M.charCodeAt(s - 2)))) { // ("oauth token" is a word, not a glued name) // in a decoded round a keyword glued to a letter counts as if it stood alone (an encoded letter can be glued to it on purpose)
        if (SHORT_NAMES.has(name)) {
          const before = M.slice(Math.max(0, s - 14), s).toLowerCase().replace(/[^a-z]/g, '');
          if (!PASS_PREFIXES.some((p) => before.endsWith(p))) { KW.lastIndex = s + 1; continue; }
        }
        glued = true; // dbpassword=x: a long keyword glued to letters still counts when an explicit = or : follows
      }
    }
    if (s > 0 && M.charCodeAt(s - 1) === 60 && M.charCodeAt(e) === 62 && /[ `'",.)]/.test(M[e + 1] || '')) { KW.lastIndex = e; continue; } // <TOKEN> in a sentence: a placeholder
    if (s > 0 && M.charCodeAt(s - 1) === 47 && !/^[ ]*[:=]/.test(M.slice(e, e + 3))) { KW.lastIndex = e; continue; } // a path segment: auth/approle/login role_id=...
    let p = e;
    let plural = false;
    const c0 = M.charCodeAt(p);
    if (isLetterC(c0)) {
      if ((c0 === 115 || c0 === 83) && !isLowerC(M.charCodeAt(p + 1))) { p += 1; plural = true; } else if ((name === 'passwort' || name === 'kennwort') && /^(?:er|e|n)(?![A-Za-z])/i.test(M.slice(p, p + 3))) { p += M.slice(p, p + 3).toLowerCase().startsWith('er') ? 2 : 1; plural = true; } else if (isUpperC(c0) && isLowerC(M.charCodeAt(p - 1))) { /* camelCase suffix, handled below */ } else { KW.lastIndex = e; continue; }
    }
    // the whole name (DB_PASSWORD, accessToken) starts here
    let a = s;
    const floor = Math.max(0, s - 40);
    while (a > floor) {
      const d = Fm.charCodeAt(a - 1);
      if (isAlnumC(d) || d === 95 || d === 46 || d === 45) a -= 1; else break;
    }
    if (info[0] === 'K' || SHORT_NAMES.has(name) || name === 'password' || name === 'token' || name === 'secret') {
      const pw = prevWord(M, s);
      if (pw && ((info[0] === 'K' && KEY_DENY.has(pw) && !(name === 'auth' && pw === 'api')) || FLAG_PREFIX.has(pw))) { KW.lastIndex = e; continue; }
    }
    const suf = suffixEnd(Fm, n, p);
    if (suf.safe) { KW.lastIndex = e; continue; }
    if (info[0] === 'P' && /^[_.-]?[Kk]ey(?:s)?(?![a-z])/.test(M.slice(p, p + 6))) { KW.lastIndex = e; continue; } // passwordKey: the name of a key, not a password
    const xml = s > 0 && (M.charCodeAt(s - 1) === 60 || /<[A-Za-z][A-Za-z0-9_-]{0,20}:$/.test(M.slice(Math.max(0, s - 24), s)));
    if (plural && /\b(?:common|popular|weak|worst|typical|leaked|banned|forbidden|bad|default|top)\b/i.test(M.slice(Math.max(0, s - 40), s))) { KW.lastIndex = e; continue; } // "the most common passwords are 123456"
    let r = null;
    if (suf.p !== p) r = valueAfter(ctx, a, s, suf.p, info, glued, xml, plural, name);
    if (!r) r = valueAfter(ctx, a, s, p, info, glued, xml, plural, name);
    if (!r && (info[0] === 'P' || info[0] === 'S') && !glued) {
      r = leftValue(ctx, a);
      if (!r) r = instructValue(ctx, suf.p !== p ? suf.p : p);
    }
    if (r) { spans.push({ s: r.a, e: r.b, id: r.id }); KW.lastIndex = Math.max(r.b, e); } else KW.lastIndex = e;
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Other detectors.
const B = '(?<![A-Za-z0-9])';
const PREFIX_TOKEN = new RegExp(`${B}(?:` + [
  'sk-[A-Za-z0-9_-]{12,}',
  '[sprm]k_(?:live|test)_[A-Za-z0-9]{8,}',
  'gh[pousr]_[A-Za-z0-9]{16,}',
  'github_pat_[A-Za-z0-9_]{16,}',
  'glpat-[A-Za-z0-9_-]{12,}',
  'gl(?:rt|dt|soat|cbt|ptt|ft|imt|agent)-[A-Za-z0-9_-]{16,}',
  'xox[a-z]-[A-Za-z0-9-]{8,}',
  'sq0(?:atp|csp|idp)-[A-Za-z0-9_-]{16,}',
  '(?:AKIA|ASIA)[0-9A-Z]{16}',
  'AIza[0-9A-Za-z_-]{20,}',
  'SG\\.[A-Za-z0-9_-]{12,}\\.[A-Za-z0-9_-]{12,}',
  'hf_[A-Za-z0-9]{16,}',
  'npm_[A-Za-z0-9]{16,}',
  'shp(?:at|ca|pa|ss)_[A-Fa-f0-9]{16,}',
  'dop_v1_[a-f0-9]{16,}',
  'pypi-[A-Za-z0-9_-]{16,}',
  'ya29\\.[A-Za-z0-9_-]{16,}',
  'fw_[A-Za-z0-9]{20,}',
  'NR(?:JS|AK|II|AA|SP|IQ)-[A-Za-z0-9]{16,}',
  'GR1348941[A-Za-z0-9_-]{12,}',
  'gsk_[A-Za-z0-9]{20,}',
  '(?:pplx|xai|tvly)-[A-Za-z0-9-]{16,}',
  'whsec_[A-Za-z0-9]{16,}',
  'hv[sb]\\.[A-Za-z0-9_-]{20,}',
  'dckr_pat_[A-Za-z0-9_-]{16,}',
  'gl(?:c|sa)_[A-Za-z0-9+/=_-]{24,}',
  'lsv2_(?:pt|sk)_[A-Za-z0-9_]{16,}',
  'lin_api_[A-Za-z0-9]{24,}',
  'ntn_[A-Za-z0-9]{24,}',
  'figd_[A-Za-z0-9_-]{24,}',
  'rubygems_[a-f0-9]{24,}',
  'dapi[a-f0-9]{32}',
  'pat-(?:na|eu)1-[a-f0-9-]{30,}',
  'ATATT3[A-Za-z0-9_=-]{24,}',
  'r8_[A-Za-z0-9]{24,}',
  'xapp-[0-9]-[A-Za-z0-9-]{16,}',
  'key-[0-9a-f]{32}',
].join('|') + ')', 'g');
// Vault service / batch / recovery tokens (s.<24>) and Discord bot tokens (<id>.<time>.<hmac>): no fixed prefix, but a distinctive shape.
const VAULT_TOKEN = /(?<![A-Za-z0-9.])[sbr]\.[A-Za-z0-9]{24}(?![A-Za-z0-9])/g;
const DISCORD_TOKEN = /(?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{23,27}\.[A-Za-z0-9_-]{6,7}\.[A-Za-z0-9_-]{27,40}(?![A-Za-z0-9_-])/g;
const IMAP_LOGIN = /(?<![A-Za-z0-9])[A-Za-z0-9]{1,8}[ ]+LOGIN[ ]+(?:"[^"]{1,64}"|[^\s"]{1,64})[ ]+("?)([^\s"]{3,200})\1/gd; // a001 LOGIN bob "x"
const WIFI_QR = /\bWIFI:[^\r\n]{0,600}/gi;
// Credentials as positional arguments: requests.get(u, auth=('bob', 'x'))  HTTPBasicAuth('bob','x')  db.auth("bob","x")  new NetworkCredential("bob", "x")
const AUTH_ARGS = /(?<![A-Za-z0-9])(?:auth|authenticate|login|log_in|logIn|signin|sign_in|signIn|logon|bind|BasicAuth|HTTPBasicAuth|HTTPDigestAuth|NetworkCredential|PasswordAuthentication|PasswordCredential|UsernamePasswordCredentials|Credentials)[ ]*[=:(][ ]*(?:\([ ]*)?(["'`])[^"'`\s]{1,64}\1[ ]*,[ ]*(["'`])([^"'`\s]{3,200})\2/gdi;
// "password changed from old to new": both values are listed.
const CHANGED_FROM = /(?<![A-Za-z0-9])(?:password|passwd|passphrase|passcode|pwd|pw|secret|token|api[ _-]?key)s?[ ]+(?:(?:was|has been|got|is|will be)[ ]+)?(?:changed|updated|reset|set|rotated|replaced|switched)[ ]+from[ ]+(["']?)([^\s"']{3,200})\1[ ]+to[ ]+(["']?)([^\s"']{3,200})\3/gdi;
const SSH_KEY = /(?<![A-Za-z0-9-])(?:ssh-(?:rsa|ed25519|dss)|ecdsa-sha2-nistp(?:256|384|521))[ ]+AAAA[A-Za-z0-9+/=]{16,}/g;
const URL_USERINFO = /(?<![A-Za-z0-9+.-])[A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/((?:[^\s/?#]{1,4096}|[^\s/?#:@]{1,128}:[ ]{1,3}[^\s/?#]{1,128}))@/g;
const URL_USERINFO_SLASH = /[A-Za-z][A-Za-z0-9+.-]{1,20}:\/\/([^\s@/?#:]{1,128}:(?!\d{1,5}(?:[/?#@]|$))[^\s@]{1,200})@(?=[A-Za-z0-9[])/g;
const MAIL_LIKE = new Set(['mailto', 'email', 'e-mail', 'mail', 'from', 'to', 'cc', 'bcc', 'contact', 'sender', 'reply-to', 'author', 'xmpp', 'sip', 'sips', 'tel', 'sms',
  'owner', 'owners', 'assignee', 'reviewer', 'maintainer', 'maintainers', 'approver', 'reporter', 'creator', 'committer', 'by', 'requester', 'lead', 'manager', 'sponsor',
  'cc\'d', 'authors', 'signed-off-by', 'co-authored-by', 'reviewed-by', 'acked-by', 'tested-by', 'reported-by', 'suggested-by']);
const SSH_SCHEMES = new Set(['ssh', 'git', 'git+ssh', 'sftp', 'scp', 'rsync', 'svn+ssh']);
const BEARER = new RegExp(`${B}(?:bearer|basic)[ ]+([A-Za-z0-9._~+/=-]{6,})`, 'gi');
const HEADER = /(?<![A-Za-z0-9_-])(?:proxy-authorization|authorization|set-cookie|cookie|x-api-key|x-auth-token|x-amz-security-token)[ \t]{0,8}:[ \t]{0,8}[^\r\n\u{2028}\u{2029}]+/giu;
const OPAQUE = /(?<![A-Za-z0-9+/_=-])[A-Za-z0-9+/_=-]{32,}/g;
const USER_PAIR = /(?<![A-Za-z0-9])(?:login|log[ -]?in|sign[ -]?in|user(?:name|id)?|usr|uname|uid|u|credentials?|creds?|account)(?:[ ]{0,2}[:=][ ]{0,2}|[ ]+(?:is|are|was)[ ]+)["']?[^\s"'|/,;&]{1,64}["']?[ ]{0,4}(?:[|/,;&]|and )[ ]{0,4}["']?([^\s"']{3,200})/gi;
const PAIR_WORDS = /(?<![A-Za-z0-9])(?:log[ ]?in|login|logon|sign[ ]?in|signin|credentials?|creds?)[ ]+(?:(?:is|are|with|as|using|for)[ ]+)?["']?([A-Za-z0-9_.@-]{1,64})["']?(?:[ ]+and[ ]+|[ ]*[/|&,+][ ]*|[ ]+)["']?([^\s"']{3,200})/gid;
const PAIR_NAMED = /(?<![A-Za-z0-9])(?:account|user(?:name)?|id)[ ]+["']?([A-Za-z0-9_.@-]{1,64})["']?(?:[ ]+and[ ]+|[ ]*[/|&,+][ ]*)["']?([^\s"']{3,200})/gid;
const CONNECT_USING = /(?<![A-Za-z0-9])(?:connect(?:ing|ed)?|log(?:ging|ged)?[ ]?in|sign(?:ing|ed)?[ ]?in|authenticat(?:e|ed|ing)|auth(?:orized)?|login|use|using|with|via)[ ]+(?:(?:using|with|as|via|to|the credentials|credentials|user)[ ]+)?([A-Za-z][A-Za-z0-9._@-]{0,63}):([^\s:"'/][^\s:"']{4,199})/gid;
const TUPLE_LABEL = /\(([^()\s,]{1,64}),[ ]*([^()\s,]{3,200})\)[ ]*=[ ]*\([ ]*(?:user(?:name)?|login|u)[ ]*,[ ]*(?:pass(?:word)?|pwd|pw|secret|p)[ ]*\)/gid;
const NOT_USER = new Set(['extends', 'implements', 'class', 'function', 'const', 'let', 'var', 'return', 'import', 'from', 'export', 'default', 'new', 'async', 'await', 'static', 'public', 'private', 'interface', 'type', 'file', 'path', 'name', 'page', 'form', 'screen', 'flow', 'service', 'provider', 'manager', 'handler', 'store', 'cache', 'config']);
const IMAGE_NAMES = new Set(['node', 'python', 'ubuntu', 'debian', 'alpine', 'nginx', 'redis', 'postgres', 'mysql', 'mongo', 'golang', 'ruby', 'java', 'openjdk', 'php', 'httpd', 'busybox', 'centos', 'fedora', 'rust', 'maven', 'gradle', 'docker', 'dotnet', 'localhost', 'http', 'https', 'ftp', 'jdbc', 'redis', 'amqp', 'tcp', 'udp']);
const LABEL_PAIR = /(?<![A-Za-z0-9])(?:user(?:name|id)?|usr|login|account|uid|u)[ ]{0,2}(?:[/&,|+]|and)[ ]{0,2}(?:pass(?:word|wd|code)?|pwd|pw|secret|p)[ ]{0,2}[:=][ ]{0,2}["']?[^\s"'|/,;&]{1,64}["']?[ ]{0,4}(?:[/&,|;+]|and )[ ]{0,4}["']?([^\s"']{3,200})/gi;
const LOGIN_WITH = /(?<![A-Za-z0-9])(?:log(?:ged|s|ging)?[ ]?in|sign(?:ed|s|ing)?[ ]?in|login|signin|logon|log(?:ged|ging)?[ ]?on|authenticat(?:e|ed|es|ing))[ ]+(?:(?:in|on)[ ]+)?(?:with|as|using)[ ]+["']?[^\s"'/,|&]{1,64}["']?(?:[ ]+(?:and|with)[ ]+|[ ]{0,2}[/|&,:][ ]{0,2})["']?([^\s"']{3,200})/gi;
const BASIC_PAIR = /(?<![A-Za-z0-9])basic(?:[ ]+auth(?:entication)?)?[ ]+[^\s:/|,]{1,64}(?::|[ ]{0,2}[/|,][ ]{0,2})([^\s]{3,200})/gi;
const UP_SHORT = /(?<![A-Za-z0-9])u[ ]{0,2}[:=][ ]{0,2}[^\s]{1,64}[ ]{1,3}p[ ]{0,2}[:=][ ]{0,2}[^\s]{1,200}/gi;
const UP_SLASH = /(?<![A-Za-z0-9])u\/p[ ]{0,2}[:=][ ]{0,2}[^\s/]{1,64}\/[^\s]{1,200}/gi;
const CLI_USER = /(?<![A-Za-z0-9-])(?:-u|--user|--proxy-user|-U)(?:[ ]*|=)([^\s:-][^\s:]{0,63}):([^\s]{3,200})/g;
const KEY_IS = /(?<![A-Za-z0-9])(?:my|the|your|our|his|her|their|this)[ ]+(?:(?:secret|api|access|private|master|encryption)[ ]+)?key[ ]+(?:is|are|was)[ ]+(?:set to[ ]+)?(["']?[^\s"']{3,200})/gi;
const LOGIN_NEXT_LINE = /(?<![A-Za-z0-9])(?:login|log[ ]?in|user(?:name|id)?|usr|uname|account)[ ]{0,2}[:=][ ]{0,2}[^\s]{1,64}[ \t]*\r?\n[ \t]*([^\s]{4,200})[ \t]*(?:\r?\n|$)/gi;
const URL_PARAM = /[?&;]([A-Za-z][A-Za-z0-9_.-]{0,40})=([^&#\s"'<>]{1,500})/g;
const URL_PATH_TOKEN = /\/[A-Za-z0-9_-]{0,30}(?:reset|verif|confirm|activat|invit|recover|magic|unsubscribe|forgot|redeem|claim|accept|passw|secret)[A-Za-z0-9_-]{0,30}\/([^/?#\s"'<>]{8,200})/gi;
const QP_STRONG = new Set(['sig', 'signature', 'x-amz-signature', 'x-amz-security-token', 'x-goog-signature', 'x-amz-credential']);
const QP_WEAK = new Set(['code', 't', 'tk', 'k', 'otp', 'pin', 'ticket', 'jwt', 'assertion', 'sv', 'magic', 'invite', 'invitation', 'license', 'licence', 'activation', 'activate', 'verify', 'reset', 'confirm', 'recovery', 'redeem', 'claim', 'unlock', 'nonce', 'magic_link', 'magiclink', 'invite_code', 'invitation_code']);


// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Round-4 detectors: shapes of prose, code and commands that name a credential without a plain "keyword: value".
const PRODUCTISH = /^(?:[A-Z][a-z]+(?:[A-Z][a-z0-9]+)+|[A-Z]{2,}[a-z]+[A-Za-z]*)$/; // PingOne GitHub LinkedIn: a product name, not a typed secret
const digitOrSym = (cv) => /[0-9!@#$%^&*+=?~]/.test(cv);
const BEARER_CONCAT = /(?<![A-Za-z0-9])(?:bearer|basic|token)[ ]*(["'`])[ ]*(?:\+[ ]*|\.concat\([ ]*)(["'`])([^"'`\n]{4,200})\2/gid; // 'Bearer ' + 'x'
const FLAG_QUOTED = /(?<![\w-])--(?:password|passwd|pass|passphrase|pwd|pw|token|secret|api-?key|auth-?token|access-?token|client-?secret|private-?key|otp|credentials?)(?:[ ]+|=)(["'])((?:(?!\1)[^\\\n]){1,200})\1/gid;
const DETAILS = /(?<![A-Za-z0-9])(?:(?:login|log[ ]?in|sign[ ]?in|account|access|auth(?:entication)?|user)[ ]+(?:details?|info(?:rmation)?|data|credentials?)|credentials?|creds?)(?:[ ]+(?:are|is)(?![A-Za-z]))?[ ]*(?:[:–-][ ]*)?["']?([A-Za-z][A-Za-z0-9_.@-]{0,63})["']?(?:[ ]*[/|,&+:;][ ]*|[ ]+and[ ]+|[ ]+)["']?([^\s"']{3,200})/gid;
const USER_LOGS = /(?<![A-Za-z0-9])(?:logs?|logged|signs?|signed)[ ]?(?:in|on)[ ]+(?:with|using)[ ]+["']?([^\s"']{8,200})/gid; // the user is the word before the verb
const USE_SLASH = /(?<![A-Za-z0-9])(?:use|using|try|enter|type)[ ]+([a-z][a-z-]{1,31})\/([^\s"'/]{8,200})/gdi;
const WIFI_PAIR = /(?<![A-Za-z0-9])(?:wi-?fi|wlan)(?:[ ]+(?:network|name|login|details|credentials?)(?![A-Za-z]))?[ ]*(?:[:–-][ ]*)?["']?([A-Za-z][A-Za-z0-9_.@-]{0,31})["']?(?:[ ]*[/|,&+-][ ]*|[ ]+)["']?([^\s"']{6,64})/gid;
const CONFIRM_LINE = /(?<![A-Za-z0-9])(?:verify|confirm(?:ation)?|repeat|retype|re-?enter|re-?type|again)(?:[ ](?:password|passphrase|pw|pwd|passcode|pin))?[ ]*[:=][ ]*["']?([^\s"']{4,200})/gid;
const AUTH_CMD = /(?<![A-Za-z0-9_.-])AUTH[ ]+(?:[A-Za-z0-9_.-]{1,64}[ ]+)?(["']?)([^\s"']{4,200})\1/gd;
const NET_USE = /\bnet[ ]+use[ ]+(?:\S+[ ]+)?\/user:[^\s]+[ ]+([^\s/"']{3,127})|\bnet[ ]+use[ ]+\S+[ ]+([^\s/"']{3,127})[ ]+\/user:/gid;
const PORT_MAP = /^(?:\[[0-9a-f:]+\]:|[\w.-]+:)?\d{1,5}(?::\d{1,5})?(?:\/\w+)?$/i; // a published port: 8080, 8080:80, 127.0.0.1:8080:80, 8080:80/tcp
const UP_FLAGS = /(?<![\w-])-[uU][ =]+([A-Za-z][\w.@-]{0,63})[ ]+-[pP][ =]+(["']?)([^\s"'-][^\s"']{2,127})\2/gd;
const SP_LOGIN = /\bsp_(addlogin|password|addremotelogin)[ ]+((?:@\w+[ ]*=[ ]*)?(?:'[^'\n]{0,128}'|"[^"\n]{0,128}"|[\w$#@]{1,64})(?:[ ]*,[ ]*(?:@\w+[ ]*=[ ]*)?(?:'[^'\n]{0,128}'|"[^"\n]{0,128}"|[\w$#@]{1,64})){0,5})/gid;
const SETTER_CALL = /(?<![A-Za-z0-9])(?:set_?password|set_?passwd|set_?pwd|set_?passphrase|set_?pass|set_?secret|set_?token|set_?api_?key|set_?credentials?|set_?auth_?token|set_?access_?token|change_?password|reset_?password|update_?password|changepw|setpw)[ ]*\(([^()\n]{1,400})\)/gid;
const QUOTED_LIT = /(["'`])((?:(?!\1)[^\\\n]){3,200})\1/g;
const UI_FILL1 = /(?:password|passwd|pwd|passphrase|secret|token|api-?key)[^;\n]{0,80}?\.(?:fill|type|val|sendKeys|send_keys|setValue|set_value|setText|typeText|input)[ ]*\([ ]*(["'`])([^"'`\n]{3,200})\1/gid;
const UI_FILL2 = /(?:fill|type|setValue|set_value|sendKeys|send_keys|input|enter|write)[ ]*\([ ]*(["'`])[^"'`\n]{0,60}(?:password|passwd|pwd|secret|token)[^"'`\n]{0,60}\1[ ]*,[ ]*(["'`])([^"'`\n]{3,200})\2/gid;
const TYPED_DECL = /(?<![A-Za-z0-9])(?:password|passwd|passphrase|pwd|pw|secret|token|apikey|api_key|credential|passcode)[A-Za-z0-9_]{0,12}(?:[ ]*:[ ]*[&*]?[A-Za-z_][\w<>[\],. ]{0,30}|[ ]+as[ ]+[A-Za-z_][\w.]{0,30}|[ ]+[A-Za-z_][\w.[\]*]{1,20})?[ ]*(?::=|<<?-|=(?!=))[ ]*(["'`])([^"'`\n]{3,200})\1/gid;
const SET_VARIABLE = /\bSet-Variable[ ]+(?:-Name[ ]+)?["']?[A-Za-z_]*(?:password|passwd|pwd|pw|secret|token|passphrase|apikey)[A-Za-z_]*["']?[ ]+-Value[ ]+(["'])([^"'\n]{1,200})\1/gid;
const ARG_DEFAULT = /\b(?:add_argument|addArgument|add_option|addOption|option|argument|flag|String|StringVar|Flag)\([ ]*(["'])-{0,2}([\w-]{1,40})\1[^()\n]{0,120}?\b(?:default|defaultValue|value)[ ]*[:=][ ]*(["'])([^"'\n]{3,200})\3/gid;
const VAR_DEFAULT = /\b(?:variable|var|param|parameter|input|option|setting)[ ]+["']([\w.-]{1,60})["'][ ]*\{[^{}\n]{0,300}?\b(?:default|value)[ ]*[:=][ ]*(["'])([^"'\n]{3,200})\2/gid;
const SLACK_HOOK = /(?<![A-Za-z0-9])hooks\.slack\.com\/services\/[A-Za-z0-9]{1,16}\/[A-Za-z0-9]{1,16}\/[A-Za-z0-9]{6,}/g;
// [function name pattern, index of the password argument, extra index]: positional driver arguments (new PDO($dsn, 'bob', 'x'), mysqli_connect('h', 'bob', 'x', 'db'))
const DRIVER_CALLS = [
  [/\bnew[ ]+PDO[ ]*\(/gi, 2], [/\b(?:mysqli_connect|mysqli_real_connect|mysql_connect|mysql_pconnect|ldap_bind|ldap_bind_ext)[ ]*\(/gi, 2], [/\bnew[ ]+mysqli[ ]*\(/gi, 2],
  [/\b(?:DriverManager\.getConnection|getConnection|createConnection|createPool|pymysql\.connect|psycopg2\.connect)[ ]*\(/g, 2], [/\boci_(?:p?connect|new_connect)[ ]*\(/gi, 1], [/\bnew[ ]+(?:SqlConnection|MongoClient|Client|Pool)[ ]*\(/g, 2],
];
function scanRound4(M, Fm, spans, st) {
  const lit = (a, b, id) => { if (b > a) spans.push({ s: a, e: b, id }); };
  run(BEARER_CONCAT, Fm, spans, st, 'bearer', (m) => { PLACEHOLDER.lastIndex = 0; return PLACEHOLDER.test(m[3]) || isSoftWord(m[3].toLowerCase()) ? null : [m.indices[2][0], m.indices[3][1] + 1]; });
  run(FLAG_QUOTED, Fm, spans, st, 'cli', (m) => { PLACEHOLDER.lastIndex = 0; const v = m[2]; return PLACEHOLDER.test(v) || /^[$<{]/.test(v) ? null : [m.indices[1][0], m.indices[2][1] + 1]; });
  run(DETAILS, Fm, spans, st, 'pair', (m) => {
    const u = m[1].toLowerCase();
    const pw = core(m[2]);
    return !isCommonWord(u) && !isSoftWord(u) && !NOT_USER.has(u) && !/^[${(<{[]/.test(m[2]) && strongShape(pw, 6) && digitOrSym(pw) && !PRODUCTISH.test(pw) && !isDateOrVersion(pw) ? [m.indices[2][0], m.indices[2][1]] : null;
  });
  run(USER_LOGS, Fm, spans, st, 'pair', (m) => {
    const pw = core(m[1]);
    let e = m.index;
    while (e > 0 && Fm.charCodeAt(e - 1) === 32) e -= 1;
    let b = e;
    while (b > 0 && e - b < 64 && /[A-Za-z0-9_.@-]/.test(Fm[b - 1])) b -= 1;
    const user = Fm.slice(b, e);
    return user !== '' && /^[A-Za-z]/.test(user) && !isCommonWord(user.toLowerCase()) && strongShape(pw, 8) && /\d/.test(pw) && /[A-Za-z]/.test(pw) && !PRODUCTISH.test(pw) && !isDateOrVersion(pw) ? [m.indices[1][0], m.indices[1][1]] : null;
  });
  run(USE_SLASH, Fm, spans, st, 'pair', (m) => { const pw = core(m[2]); return strongShape(pw, 8) && /\d/.test(pw) && /[A-Za-z]/.test(pw) && !FILE_RE.test(pw) && !isDateOrVersion(pw) && !isNameish(pw) ? [m.indices[2][0], m.indices[2][1]] : null; });
  run(WIFI_PAIR, Fm, spans, st, 'pair', (m) => {
    const u = m[1].toLowerCase();
    const pw = core(m[2]);
    return !isCommonWord(u) && !isSoftWord(u) && !IMAGE_NAMES.has(u) && strongShape(pw, 6) && digitOrSym(pw) && !/^\d+(?:\.\d+)*[A-Za-z]{0,3}$/.test(pw) && !isDateOrVersion(pw) ? [m.indices[2][0], m.indices[2][1]] : null;
  });
  run(AUTH_CMD, Fm, spans, st, 'cli', (m) => { const pw = core(m[2]); return strongShape(pw, 6) && !isNameish(pw) && !isDateOrVersion(pw) ? [m.indices[2][0], m.indices[2][1]] : null; });
  run(NET_USE, Fm, spans, st, 'cli', (m) => { const g = m[1] !== undefined ? 1 : 2; return MARK_START.test(m[g]) ? null : [m.indices[g][0], m.indices[g][1]]; });
  run(UP_FLAGS, Fm, spans, st, 'cli', (m) => {
    const pw = core(m[3]);
    if (PORT_MAP.test(pw) || PORT_MAP.test(m[3]) || MARK_START.test(pw)) return null; // docker run -u bob -p 8080:80   -p 127.0.0.1:8080:80/tcp
    return shapeOK(pw, 4) ? [m.indices[3][0], m.indices[3][1]] : null;
  });
  run(SP_LOGIN, Fm, spans, st, 'sql', (m) => {
    const kind = m[1].toLowerCase();
    const args = [...m[2].matchAll(/'([^'\n]{1,128})'|"([^"\n]{1,128})"|(?<![@\w])([\w$#]{3,64})(?![\w=])/g)];
    const base = m.indices[2][0];
    args.forEach((a, k) => { if (kind === 'addlogin' ? k >= 1 : true) { const g = a[1] !== undefined ? 1 : a[2] !== undefined ? 2 : 3; if (g === 3 && !/\d/.test(a[3])) return; lit(base + a.index + (g === 3 ? 0 : 1), base + a.index + a[0].length - (g === 3 ? 0 : 1), 'sql'); } });
    return null;
  });
  const setter = (re, valueGroupsFrom) => {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(Fm)) !== null) {
      st.work += 1;
      if (m[0].length === 0) { re.lastIndex += 1; continue; }
      const base = m.indices[valueGroupsFrom][0];
      const body = m[valueGroupsFrom];
      QUOTED_LIT.lastIndex = 0;
      let q;
      while ((q = QUOTED_LIT.exec(body)) !== null) { if (!/^\{[A-Za-z]+\}$/.test(q[2]) && !/^[$<{]/.test(q[2])) lit(base + q.index, base + q.index + q[0].length, 'assignment'); }
    }
  };
  setter(SETTER_CALL, 1);
  run(UI_FILL1, Fm, spans, st, 'assignment', (m) => (/^\{[A-Za-z]+\}$/.test(m[2]) || /^[$<{]/.test(m[2]) ? null : [m.indices[1][0], m.indices[2][1] + 1]));
  run(UI_FILL2, Fm, spans, st, 'assignment', (m) => (/^\{[A-Za-z]+\}$/.test(m[3]) || /^[$<{]/.test(m[3]) ? null : [m.indices[2][0], m.indices[3][1] + 1]));
  run(TYPED_DECL, Fm, spans, st, 'assignment', (m) => { PLACEHOLDER.lastIndex = 0; return PLACEHOLDER.test(m[2]) || /^[$<{]/.test(m[2]) || isSoftWord(m[2].toLowerCase()) ? null : [m.indices[1][0], m.indices[2][1] + 1]; });
  run(SET_VARIABLE, Fm, spans, st, 'assignment', (m) => [m.indices[1][0], m.indices[2][1] + 1]);
  run(ARG_DEFAULT, Fm, spans, st, 'assignment', (m) => (labelClass(m[2]) >= 2 && !/^[$<{]/.test(m[4]) ? [m.indices[3][0], m.indices[4][1] + 1] : null));
  run(VAR_DEFAULT, Fm, spans, st, 'assignment', (m) => (labelClass(m[1]) >= 2 && !/^[$<{]/.test(m[3]) ? [m.indices[2][0], m.indices[3][1] + 1] : null));
  run(SLACK_HOOK, M, spans, st, 'prefix-token');
  for (const [re, idx] of DRIVER_CALLS) {
    re.lastIndex = 0;
    let m;
    while ((m = re.exec(Fm)) !== null) {
      st.work += 1;
      if (m[0].length === 0) { re.lastIndex += 1; continue; }
      const start = m.index + m[0].length;
      const args = splitTop(Fm.slice(start, start + 600));
      if (idx >= args.length) continue;
      const [as, ae] = args[idx];
      const raw = Fm.slice(start + as, start + ae);
      const t = raw.trim();
      if (t.length < 5 || !/^(["'`]).{3,200}\1$/.test(t) || /^["'`][$<{]/.test(t)) continue;
      const lead = raw.length - raw.trimStart().length;
      lit(start + as + lead, start + as + lead + t.length, 'assignment');
    }
  }
}

function run(re, text, spans, st, id, accept) {
  re.lastIndex = 0;
  let m;
  while ((m = re.exec(text)) !== null) {
    st.work += 1;
    if (m[0].length === 0) { re.lastIndex += 1; continue; }
    const r = accept ? accept(m) : [m.index, m.index + m[0].length];
    if (r) spans.push({ s: r[0], e: r[1], id });
  }
}

// A run of 32+ characters that reads as words (kebab-case, a path of words and ids, a UUID, a traceparent, a digest) is not a credential.
const UUID_RE = /^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$/;
const TRACEPARENT_RE = /^[0-9a-f]{2}-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}$/;
const BENIGN_SEG = /^(?:[A-Za-z]{1,30}|\d{1,12}|[A-Za-z]{1,12}[-_]?\d{1,4}|v\d{1,3}|[A-Za-z]{1,12}-[A-Za-z0-9]{1,12})$/;
function pathLike(run32) {
  if (!run32.includes('/')) return false;
  const segs = run32.split('/');
  if (segs.length < 3) return false;
  for (const s of segs) if (s !== '' && !BENIGN_SEG.test(s)) return false;
  return true;
}
function wordlike(run32) {
  let total = 0;
  let lowerChars = 0;
  let seg = 0;
  let segLower = true;
  const flush = () => { if (seg >= 3 && segLower) lowerChars += seg; seg = 0; segLower = true; };
  for (let i = 0; i < run32.length; i += 1) {
    const c = run32.charCodeAt(i);
    total += 1;
    if (c === 45 || c === 95 || c === 47 || c === 43 || c === 61) flush();
    else { seg += 1; if (!isLowerC(c)) segLower = false; }
  }
  flush();
  return lowerChars * 10 >= total * 6;
}
const SID_RE = /^S-1-\d+(?:-\d+){2,9}$/; // a Windows security identifier
const MARK_ONLY = /^\[masked(?::[a-z-]+)?\]$/;
const MARK_ANY_RE = /\[masked(?::[a-z-]+)?\]/g;
// A mark written by an earlier pass is never matched again, and a span that cuts through one (user:[masked:x]@host read as user:password@host) is dropped.
function dropMarkOverlaps(M, spans) {
  if (spans.length === 0 || !MARK_AT.test(M)) return spans;
  const marks = [];
  for (const m of M.matchAll(MARK_ANY_RE)) { marks.push([m.index, m.index + m[0].length]); if (marks.length > 4096) break; }
  if (marks.length === 0) return spans;
  return spans.filter((sp) => {
    if (MARK_ONLY.test(M.slice(sp.s, Math.min(sp.e, sp.s + 40)))) return false;
    let lo = 0;
    let hi = marks.length;
    while (lo < hi) { const mid = (lo + hi) >> 1; if (marks[mid][1] <= sp.s) lo = mid + 1; else hi = mid; }
    for (let i = lo; i < marks.length && marks[i][0] < sp.e; i += 1) {
      const [ms, me] = marks[i];
      if (!(sp.s <= ms && me <= sp.e)) return false; // partial overlap
    }
    return true;
  });
}
const SHELL_VAR = /^"?\$(?:\{|\(|[A-Z_][A-Z0-9_]{2,}\b)/; // $PASS ${PASS} $(cat x): a shell variable or command, not a typed secret
const DIGEST_BEFORE = /(?:sha1|sha224|sha256|sha384|sha512|md5):$/i;

function scanJwt(M, spans, st) {
  const n = M.length;
  let pos = 0;
  for (;;) {
    const i = M.indexOf('eyJ', pos);
    if (i < 0) return;
    st.work += 1;
    if (i > 0 && isAlnumC(M.charCodeAt(i - 1))) { pos = i + 1; continue; }
    const isB64 = (c) => isAlnumC(c) || c === 95 || c === 45;
    let j = i + 3;
    while (j < n && isB64(M.charCodeAt(j))) j += 1;
    st.work += j - i;
    if (j - (i + 3) < 4 || M.charCodeAt(j) !== 46) { pos = Math.max(j, i + 1); continue; }
    let k = j + 1;
    while (k < n && isB64(M.charCodeAt(k))) k += 1;
    st.work += k - j;
    if (k - (j + 1) < 4 || M.charCodeAt(k) !== 46) { pos = Math.max(j, i + 1); continue; }
    let l = k + 1;
    while (l < n && isB64(M.charCodeAt(l))) l += 1;
    st.work += l - k;
    spans.push({ s: i, e: l, id: 'jwt' });
    pos = l;
  }
}

function scanPem(M, spans, st) {
  let from = 0;
  const n = M.length;
  for (;;) {
    const i = M.indexOf('-----BEGIN ', from);
    if (i < 0) return;
    st.work += 1;
    let j = i + 11;
    const lim = Math.min(n, i + 11 + 42);
    while (j < lim && (isUpperC(M.charCodeAt(j)) || isDigitC(M.charCodeAt(j)) || M.charCodeAt(j) === 32)) j += 1;
    if (j === i + 11) { from = i + 11; continue; }
    const k = M.indexOf('-----END ', j);
    let end = n;
    if (k >= 0) {
      const close = M.indexOf('-----', k + 9);
      end = close >= 0 && close - k < 60 ? close + 5 : Math.min(n, k + 9);
    }
    spans.push({ s: i, e: end, id: 'pem' });
    from = Math.max(end, i + 11);
  }
}

// user:password@host without a scheme, by index loops (the equivalent regular expression backtracks about 64 x 200 steps per colon).
const userCh = (c) => isAlnumC(c) || c === 46 || c === 95 || c === 126 || c === 37 || c === 43 || c === 45;
const stopCh = (c) => c <= 32 || c === 64 || c === 47 || c === 58 || c === 63 || c === 35 || c === 34 || c === 39 || c === 60 || c === 62 || c === 0x85 || c === 0xa0 || c === 0x1680 || (c >= 0x2000 && c <= 0x200a) || c === 0x2028 || c === 0x2029 || c === 0x202f || c === 0x205f || c === 0x3000;
const DIGEST_HOST = /^sha(?:1|224|256|384|512)[:-]|^md5[:-]/i;
function scanBareUserinfo(M, spans, st) {
  const n = M.length;
  let i = M.indexOf(':');
  while (i >= 0) {
    st.work += 1;
    let l = i;
    while (l > 0 && l > i - 65 && userCh(M.charCodeAt(l - 1))) l -= 1;
    const ulen = i - l;
    if (ulen >= 1 && ulen <= 64) {
      let r = i + 1;
      const lim = Math.min(n, i + 202);
      while (r < lim && !stopCh(M.charCodeAt(r))) r += 1;
      const plen = r - (i + 1);
      if (plen >= 1 && plen <= 200 && M.charCodeAt(r) === 64 && isLetterC(M.charCodeAt(r + 1))) {
        const user = M.slice(l, i);
        const pw = M.slice(i + 1, r);
        // not a label before an address: "Owner:alice@host.example", "Reporter:john.smith@host.example" (a Capitalised word and a lower-case local part without digits)
        const label = MAIL_LIKE.has(user.toLowerCase()) || (/^[A-Z][a-z]{2,15}$/.test(user) && /^[a-z][a-z._-]*[a-z]$/.test(pw));
        if (!label && !(/^\d+$/.test(user) && /^\d+$/.test(pw)) && !DIGEST_HOST.test(M.slice(r + 1, r + 12))) spans.push({ s: l, e: r + 1, id: 'userinfo' });
      }
    }
    i = M.indexOf(':', i + 1);
  }
}

// A table header or label line that is exactly a password-family or secret-family name (plural and a closing colon allowed).
function isCredName(cell) {
  const t = cell.trim().replace(/^[*_`]+|[*_`]+$/g, '').replace(/:$/, '');
  if (!t || t.length > 40) return false;
  KW.lastIndex = 0;
  const m = KW.exec(t);
  if (!m || m.index !== 0 || !(m[0].length === t.length || (m[0].length === t.length - 1 && /s$/i.test(t)))) return false;
  const info = infoFor(kwName(m[0]));
  return !!info && (info[0] === 'P' || info[0] === 'S' || kwName(m[0]) === 'pass');
}
const LABEL_LINE = /^[A-Za-z][A-Za-z _/-]{0,23}:?$/;
function fieldValueOK(cv) {
  if (cv.length < 3) return false;
  const lower = cv.toLowerCase();
  return !isSoftWord(lower) && !isCommonWord(lower) && !isDateOrVersion(cv) && !SAFE_SUFFIX.has(lower);
}
// Split one CSV / TSV line into [start, end) cells (double quotes protect the delimiter).
function splitCells(raw, delim) {
  const cells = [];
  let start = 0;
  let q = false;
  for (let i = 0; i < raw.length && cells.length < 64; i += 1) {
    const c = raw.charCodeAt(i);
    if (c === 34) q = !q;
    else if (!q && c === delim) { cells.push([start, i]); start = i + 1; }
  }
  cells.push([start, raw.length]);
  return cells;
}
// The part of a cell between its white space and its quotes.
function cellInner(raw, cell) {
  let a = cell[0];
  let b = cell[1];
  while (a < b && (raw.charCodeAt(a) === 32 || raw.charCodeAt(a) === 9)) a += 1;
  while (b > a && (raw.charCodeAt(b - 1) === 32 || raw.charCodeAt(b - 1) === 9 || raw.charCodeAt(b - 1) === 13)) b -= 1;
  if (b - a >= 2 && raw.charCodeAt(a) === 34 && raw.charCodeAt(b - 1) === 34) { a += 1; b -= 1; }
  return [a, b];
}
const YAML_KEY = /^([ \t]*)(?:-[ \t]+)?([A-Za-z_][\w. -]{0,50}?)[ \t]*:[ \t]*(?:([|>])[+-]?\d?)?[ \t]*(?:#.*)?$/;
const DELIMS = [44, 9, 59];
// cells of a space-aligned line: runs of text separated by two or more spaces or a tab; { a: start, t: text }
function alignedCells(raw) {
  const out = [];
  const re = /\S+(?:[ ]\S+)*/g;
  let m;
  while ((m = re.exec(raw)) !== null && out.length < 16) out.push({ a: m.index, t: m[0] });
  return out;
}
function scanLines(M, spans, st) {
  // markdown tables, CSV / TSV, label blocks and YAML blocks. Only runs when a line break exists.
  if (M.indexOf('\n') < 0) return;
  const lines = [];
  let at = 0;
  for (;;) {
    const e = M.indexOf('\n', at);
    if (e < 0) { lines.push([at, M.length]); break; }
    lines.push([at, e]);
    at = e + 1;
  }
  st.work += lines.length;
  const text = (ln) => M.slice(ln[0], ln[1]).replace(/\r$/, '');
  const cover = new Map(); // table column -> last row already scanned (a header repeated inside a table must not rescan its rows)
  for (let i = 0; i < lines.length; i += 1) {
    const raw = text(lines[i]);
    if (raw.length > 400 || raw.length === 0) continue;
    // markdown table: | user | password |  then a separator row, then data rows
    if (raw.includes('|') && i + 1 < lines.length) {
      const cells = raw.split('|');
      let col = -1;
      for (let k = 0; k < cells.length; k += 1) if (isCredName(cells[k])) col = k;
      const nextLine = text(lines[i + 1]);
      const ruled = /^[\s|:-]+$/.test(nextLine) && nextLine.includes('-');
      if (col >= 0 && (ruled || (nextLine.includes('|') && nextLine.split('|').length === cells.length))) { // a rule row is optional: id | name | pass / 1 | bob | x
        const key = `|${col}`;
        const from = Math.max(ruled ? i + 2 : i + 1, (cover.get(key) ?? -1) + 1);
        let j = from;
        for (; j < lines.length && j < from + 2000; j += 1) {
          const r2 = text(lines[j]);
          if (!r2.includes('|')) break;
          const c2 = r2.split('|');
          if (col < c2.length) {
            const cellRaw = c2[col];
            const cellTrim = cellRaw.trim();
            if (fieldValueOK(core(cellTrim))) {
              let off = lines[j][0];
              for (let k = 0; k < col; k += 1) off += c2[k].length + 1;
              const lead = cellRaw.length - cellRaw.trimStart().length;
              spans.push({ s: off + lead, e: off + lead + cellTrim.length, id: 'table' });
            }
          }
        }
        cover.set(key, j - 1);
      }
    }
    // CSV / TSV: username,password,role  then rows
    if (i + 1 < lines.length && !raw.includes('|')) {
      for (const delim of DELIMS) {
        if (raw.indexOf(String.fromCharCode(delim)) < 0) continue;
        const cells = splitCells(raw, delim);
        if (cells.length < 2) continue;
        for (let col = 0; col < cells.length; col += 1) {
          const [a, b] = cellInner(raw, cells[col]);
          if (b <= a || !isCredName(raw.slice(a, b))) continue;
          const key = `${delim}${col}`;
          const from = Math.max(i + 1, (cover.get(key) ?? -1) + 1);
          let j = from;
          for (; j < lines.length && j < from + 2000; j += 1) {
            const r2 = text(lines[j]);
            if (r2.length === 0 || r2.length > 4000) break;
            const c2 = splitCells(r2, delim);
            if (c2.length < 2) break;
            if (col < c2.length) {
              const [ca, cb] = cellInner(r2, c2[col]);
              if (cb > ca && fieldValueOK(core(r2.slice(ca, cb)))) spans.push({ s: lines[j][0] + ca, e: lines[j][0] + cb, id: 'table' });
            }
          }
          cover.set(key, j - 1);
        }
      }
    }
    // space-aligned table: Login      Password / ---------- ---------- / bob        hunter2xyz   (cells are separated by two or more spaces or a tab)
    if (!raw.includes('|') && !raw.includes('\t') && /[ ]{2}/.test(raw) && /^[A-Za-z][A-Za-z _/-]*$/.test(raw.trim())) { // (a tab-separated table is the TSV rule's)
      const hc = alignedCells(raw);
      if (hc.length >= 2 && hc.length <= 8 && hc.every((c) => c.t.length <= 24)) {
        const credCols2 = hc.filter((c) => isCredName(c.t));
        if (credCols2.length) {
          let j = i + 1;
          if (j < lines.length && /^[\s=-]+$/.test(text(lines[j])) && /[=-]/.test(text(lines[j]))) j += 1;
          const key = `a${credCols2.map((c) => c.a).join(',')}`;
          j = Math.max(j, (cover.get(key) ?? -1) + 1);
          const stop = j + 2000;
          for (; j < lines.length && j < stop; j += 1) {
            const r2 = text(lines[j]);
            if (!r2.trim() || r2.length > 400) break;
            const rc = alignedCells(r2);
            if (rc.length < 2 || Math.abs(rc.length - hc.length) > 1) break;
            for (const hcol of credCols2) {
              let best = null;
              for (const c of rc) if (Math.abs(c.a - hcol.a) <= 3 && (!best || Math.abs(c.a - hcol.a) < Math.abs(best.a - hcol.a))) best = c;
              if (!best && rc.length === hc.length) best = rc[hc.indexOf(hcol)];
              if (best && fieldValueOK(core(best.t))) spans.push({ s: lines[j][0] + best.a, e: lines[j][0] + best.a + best.t.length, id: 'table' });
            }
          }
          cover.set(key, j - 1);
        }
      }
    }
    // INI section named after the credential: [passwords] / bob = x
    {
      const sm = /^\[([^\]\n]{1,40})\][ \t]*$/.exec(raw);
      if (sm && (isCredName(sm[1]) || /^(?:auth|login|logins|authentication)$/i.test(sm[1].trim()))) {
        for (let j = i + 1; j < lines.length && j < i + 201; j += 1) {
          const t = text(lines[j]);
          if (/^\[[^\]\n]{1,40}\][ \t]*$/.test(t)) break;
          const km = /^[ \t]*([A-Za-z0-9_.@-]{1,64})[ \t]*[=:][ \t]*([^#;\n][^\n]{0,198}?)[ \t]*$/.exec(t);
          if (!km) continue;
          const cv = core(km[2]);
          if (fieldValueOK(cv)) { const vs = t.lastIndexOf(km[2]); spans.push({ s: lines[j][0] + vs, e: lines[j][0] + vs + km[2].length, id: 'block' }); }
        }
      }
    }
    // YAML: a credential key with a block scalar, a nested mapping or a list under it
    const ym = YAML_KEY.exec(raw);
    if (ym && labelClass(ym[2]) >= 2) {
      const base = ym[1].length + (ym[0].trimStart().startsWith('-') ? 2 : 0);
      const block = [];
      for (let j = i + 1; j < lines.length && j < i + 101; j += 1) {
        const t = text(lines[j]);
        if (t.trim() === '') { if (ym[3]) block.push(j); continue; }
        const indent = t.length - t.trimStart().length;
        if (indent > base || (indent === base && !ym[3] && t.trimStart().startsWith('- '))) block.push(j); else break;
      }
      while (block.length && text(lines[block[block.length - 1]]).trim() === '') block.pop();
      if (block.length) {
        if (ym[3]) { // | and >: the whole block is the value if any word of it looks like a secret
          const first = lines[block[0]];
          const last = lines[block[block.length - 1]];
          const body = M.slice(first[0], last[1]);
          if (body.length <= 4000 && body.split(/\s+/).some((w) => w && shapeOK(core(w), 4) && !isSoftWord(core(w).toLowerCase()))) {
            const lead = text(first).length - text(first).trimStart().length;
            spans.push({ s: first[0] + lead, e: last[0] + text(last).trimEnd().length, id: 'block' });
          }
        } else {
          for (const j of block) {
            const t = text(lines[j]);
            const m = /^([ \t]*)(?:-[ \t]+)?(?:[A-Za-z_][\w. -]{0,50}?[ \t]*:[ \t]+)?([^#\n]+?)[ \t]*(?:#.*)?$/.exec(t);
            if (!m) continue;
            const v = m[2];
            const cv = core(v);
            if (cv.length >= 4 && shapeOK(cv, 4) && !isSoftWord(cv.toLowerCase()) && !isDateOrVersion(cv)) {
              const vs = t.lastIndexOf(v, t.length);
              spans.push({ s: lines[j][0] + vs, e: lines[j][0] + vs + v.length, id: 'block' });
            }
          }
        }
      }
    }
    // label block: username / password / bob / hunter2xyz (as many labels as values, one token per line)
    if (LABEL_LINE.test(raw.trim()) && isCredName(raw)) {
      let b = i;
      while (b > 0 && LABEL_LINE.test(text(lines[b - 1]).trim()) && i - b < 8) b -= 1;
      const tokens = [];
      for (let j = b; j < lines.length && tokens.length < 16; j += 1) {
        const tt = text(lines[j]).trim();
        if (!tt || /\s/.test(tt) || tt.length > 64) break;
        tokens.push(j);
      }
      const k = tokens.length;
      const idx = i - b;
      if (k >= 4 && k % 2 === 0 && idx < k / 2) {
        const vj = tokens[k / 2 + idx];
        const full = text(lines[vj]);
        const vt = full.trim();
        if (shapeOK(core(vt), 6)) spans.push({ s: lines[vj][0] + (full.length - full.trimStart().length), e: lines[vj][0] + full.trimEnd().length, id: 'table' });
      }
    }
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Command lines, SQL and URL parameters.
const CLI_HINT = /\b(?:echo|printf|chpasswd|net|smbclient|rpcclient|mysql\w*|mariadb\w*|sshpass|redis-cli|docker|podman|twine|psql|ldap\w*|vault|gem|aws|az|gcloud|kubectl|curl|wget|sqlcmd|mongo\w*|htpasswd|openssl|keytool|gpg|7z|zip|unzip|unrar|rar|npm|helm|gh|oras|crane|skopeo|sqlplus|sqlldr|rman|expdp|impdp|jdbc|http|https|httpie|xh|psexec\w*|sudo|buildah|nerdctl|convertto-securestring)\b/i;
// [command pattern, flag pattern (its last capture group is the secret), the value must look like a secret (a bare word after "-p" is a database name)]
const CLI_RULES = [
  [/\b(?:mysql\w*|mariadb\w*|mongo\w*)\b/i, /(?<![\w-])-p(?!assword|ort|rotocol)([^\s'"-][^\s'"]{2,127})/g, false],
  [/\b(?:mysql\w*|mariadb\w*|mongo\w*|sshpass|twine|smbclient)\b/i, /(?<![\w-])-p[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, true],
  [/\b(?:docker|podman|az|crane|oras|skopeo|helm|buildah|nerdctl)\b[^\n]{0,60}\blogin\b/i, /(?<![\w-])-p[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\b(?:docker|podman|az|crane|oras|skopeo|helm|buildah|nerdctl)\b[^\n]{0,60}\blogin\b/i, /(?<![\w-])-p(?:(["'])([^"'\s]{3,127})\1|([^\s'"-][^\s'"]{2,127}))/g, false],
  [/\b(?:mysql\w*|mariadb\w*|mongo\w*|sshpass)\b/i, /(?<![\w-])-p(["'])([^"'\n]{3,127})\1/g, false],
  [/psexec\w*/i, /(?<![\w-])-p[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\bopenssl\b/i, /(?<![\w-])-k[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\bgh[ ]+(?:secret[ ]+set|auth[ ]+login)\b/i, /(?<![\w-])(?:--body|-b|--with-token)[ ]+(?:<<<[ ]*)?(["']?)([^\s"'-][^\s"']{2,200})\1/g, false],
  [/\b(?:http|https|httpie|xh)\b/i, /(?<![\w-])(?:-a|--auth)[ ]+(["']?)[^\s:"']{1,64}:([^\s"']{3,200})\1/g, false],
  [/\bhtpasswd\b/i, /-[a-z]*(?:nb|bn)[a-z]*[ ]+[^\s"']+[ ]+([^\s"']{3,127})/g, false],
  [/\bconvertto-securestring\b/i, /ConvertTo-SecureString[ ]+(?:-String[ ]+)?(["']?)([^\s"'-][^\s"']{2,200})\1/gi, false],
  [/\bldap\w*\b/i, /(?<![\w-])-[wW][ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\bpsql\b/i, /(?<![\w-])-W[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, true],
  [/\bsqlcmd\b/i, /(?<![\w-])-P[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\bredis-cli\b/i, /(?<![\w-])-a[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\b(?:docker|podman|oras|crane|skopeo|helm|gh|npm|twine|gem|vault|htpasswd|mc|az|gcloud|aws)\b/i, /(?<![\w-])--(?:password|passwd|pass|passphrase|token|secret|key|api-key|auth-token|client-secret|secret-string|access-key|storepass|keypass|otp|one-time-password)[ =]+(["']?)([^\s"'-][^\s"']{2,200})\1/gi, false],
  [/\bopenssl\b/i, /(?<![\w-])-pass(?:in|out)?[ ]+pass:([^\s]{3,200})/g, false],
  [/\bkeytool\b/i, /(?<![\w-])-(?:storepass|keypass|deststorepass|destkeypass|srcstorepass)[ ]+(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\b(?:gpg|7z|zip|unzip|unrar|rar)\b/i, /(?<![\w-])(?:-P|-p|--passphrase)[ ]*(["']?)([^\s"'-][^\s"']{2,127})\1/g, false],
  [/\bvault[ ]+operator[ ]+unseal\b/i, /\bunseal[ ]+([^\s-][^\s]{5,200})/g, false],
  [/\bvault[ ]+login\b/i, /\blogin[ ]+(?:-[\w-]+(?:=[^\s]+)?[ ]+)*([^\s-=][^\s=]{5,200})(?=[ ]|$)/g, false],
  [/\bvault[ ]+kv[ ]+put\b/i, /(?<=[ ])[A-Za-z0-9_.-]{1,60}=([^\s'"]{4,200})/g, false],
  [/\bnet[ ]+user\b/i, /\buser[ ]+[^\s/]+[ ]+([^\s/'"*]{3,127})/gi, false],
  [/\bhtpasswd\b/i, /-[a-z]*b[a-z]*[ ]+\S+[ ]+\S+[ ]+([^\s"']{3,127})/g, false],
  [/\b(?:smbclient|rpcclient|net[ ]+rpc)\b/i, /-U[ ]*[^\s%]+%([^\s]{3,127})/g, false],
  [/\bkubectl\b/i, /--from-literal=[A-Za-z0-9_.-]{1,60}=(["']?)([^\s"']{3,200})\1/g, false],
  [/\b(?:aws[ ]+ssm[ ]+put-parameter|az[ ]+keyvault[ ]+secret[ ]+set|aws[ ]+secretsmanager)\b/i, /--(?:value|secret-string)[ =]+(["']?)([^\s"'-][^\s"']{2,200})\1/g, false],
];
const PIPE_SECRET = /\b(?:echo|printf)[ ]+(?:-n[ ]+|-e[ ]+)*(["']?)([^\s"'|;][^\s"'|;]{3,200})\1[ ]*\|[ ]*(?:sudo[ ]+-[A-Za-z]*S\b|(?:sudo[ ]+)?(?:docker[ ]+login|podman[ ]+login|gcloud[ ]+secrets|vault[ ]+(?:kv|login)|kubectl[ ]+create[ ]+secret|gh[ ]+(?:secret|auth)|az[ ]|aws[ ]|npm[ ]+login|helm[ ]+registry[ ]+login|htpasswd|chpasswd|passwd|openssl|oras[ ]+login|crane[ ]+auth[ ]+login|skopeo|sshpass|docker[ ]+secret))/gi;
function scanCli(Fm, spans, st) {
  if (!CLI_HINT.test(Fm)) return;
  st.work += 1;
  for (const [cmd, flag, needShape] of CLI_RULES) {
    if (!cmd.test(Fm)) continue;
    flag.lastIndex = 0;
    let m;
    while ((m = flag.exec(Fm)) !== null) {
      st.work += 1;
      if (m[0].length === 0) { flag.lastIndex += 1; continue; }
      const sec = m.slice(1).filter((g) => g !== undefined && g !== '"' && g !== "'").pop(); // the secret is the last capture group
      if (sec === undefined || MARK_START.test(sec) || SHELL_VAR.test(sec)) continue;
      if (needShape && !shapeOK(core(sec), 4)) continue;
      const at = m.index + m[0].lastIndexOf(sec);
      spans.push({ s: at, e: at + sec.length, id: 'cli' });
    }
  }
  PIPE_SECRET.lastIndex = 0;
  let pm;
  while ((pm = PIPE_SECRET.exec(Fm)) !== null) {
    st.work += 1;
    const sec = pm[2];
    if (MARK_START.test(sec) || SHELL_VAR.test(sec)) continue;
    const at = pm.index + pm[0].indexOf(sec);
    if (shapeOK(core(sec), 4) || sec.length >= 6) spans.push({ s: at, e: at + sec.length, id: 'cli' });
  }
}

const SQL_HINT = /\b(?:insert|replace|upsert|merge|identified|sqlplus|sqlldr|jdbc|rman|expdp|impdp|pragma)\b/i;
// INSERT / REPLACE / UPSERT [OR x | IGNORE] INTO t (cols) VALUES (...)   and the MERGE form: ... THEN INSERT (cols) VALUES (...)
const SQL_INSERT = /\b(?:(?:insert|replace|upsert)[ ]+(?:(?:or[ ]+\w+|ignore|low_priority|delayed|high_priority)[ ]+)?into[ ]+[\w."`[\]]{1,80}[ ]*|insert[ ]*)\(([^()]{1,400})\)[ ]*values[ ]*\(/gi;
const SQL_INSERT_NOCOL = /\b(?:insert|replace|upsert)[ ]+(?:(?:or[ ]+\w+|ignore|low_priority|delayed|high_priority)[ ]+)?into[ ]+([\w."`[\]]{1,80})[ ]+values[ ]*\(/gi;
const CRED_TABLE = /user|account|login|cred|auth|admin|member|customer|employee|secret|token|session|owner|operator/i;
const SQL_STRONG_COL = /^(?:password|passwd|pwd|pw|pass|passphrase|secret|token|api_?key|secret_?key|client_?secret|credential|credentials|passcode|hash|password_?hash|salt|access_?token|refresh_?token|auth_?token)$/;
const SQL_WEAK_COL = /^(?:key|pin|otp|session|cookie|auth|sid|jwt|psk|signature|sig|code)$/;
const ORA_USERPASS = /(?:\b(?:sqlplus|sqlldr|rman|expdp|impdp|exp|imp)[ ]+(?:(?:-\w+|target|userid=|auth=)[ ]+)*["']?|jdbc:oracle:thin:)([A-Za-z0-9_$#.-]{1,64})\/(["']?)([^\s@/'"]{3,128})\2(?:@|(?=[ "']|$))/gid;
function splitTop(s) {
  // split a VALUES tuple at top-level commas, respecting single and double quotes; returns [start,end) pairs
  const out = [];
  let start = 0;
  let q = 0;
  let depth = 0;
  for (let i = 0; i < s.length; i += 1) {
    const c = s.charCodeAt(i);
    if (q) { if (c === q) q = 0; continue; }
    if (c === 39 || c === 34 || c === 96) q = c;
    else if (c === 40) depth += 1;
    else if (c === 41) { if (depth === 0) { out.push([start, i]); return out; } depth -= 1; } else if (c === 44 && depth === 0) { out.push([start, i]); start = i + 1; }
  }
  out.push([start, s.length]);
  return out;
}
function sqlTuples(Fm, vstart, visit) {
  // visit(parts, tail, pos) for every tuple of "VALUES (...), (...), ..."
  let pos = vstart;
  for (let t = 0; t < 300; t += 1) {
    const tail = Fm.slice(pos, pos + 800);
    const parts = splitTop(tail);
    visit(parts, tail, pos);
    const end = pos + parts[parts.length - 1][1] + 1;
    const next = /^[ ]*,[ ]*\(/.exec(Fm.slice(end, end + 12));
    if (!next) return;
    pos = end + next[0].length;
  }
}
function scanSql(Fm, spans, st) {
  if (!SQL_HINT.test(Fm)) return;
  st.work += 1;
  SQL_INSERT.lastIndex = 0;
  let m;
  while ((m = SQL_INSERT.exec(Fm)) !== null) {
    st.work += 1;
    const cols = m[1].split(',').map((x) => x.trim().replace(/^[`"[]|[`"\]]$/g, '').toLowerCase());
    const idx = [];
    cols.forEach((cn, k) => { if (SQL_STRONG_COL.test(cn)) idx.push([k, false]); else if (SQL_WEAK_COL.test(cn)) idx.push([k, true]); });
    if (!idx.length) continue;
    sqlTuples(Fm, m.index + m[0].length, (parts, tail, pos) => {
      for (const [k, weak] of idx) {
        if (k >= parts.length) continue;
        const [ps, pe] = parts[k];
        const raw = tail.slice(ps, pe);
        const lead = raw.length - raw.trimStart().length;
        const t = raw.trim();
        const inner = core(t);
        if (inner.length === 0 || /^(?:null|default|\?|\$\d+|:\w+)$/i.test(inner)) continue;
        if (weak && !shapeOK(inner, 6)) continue;
        spans.push({ s: pos + ps + lead, e: pos + ps + lead + t.length, id: 'sql' });
      }
    });
  }
  SQL_INSERT_NOCOL.lastIndex = 0;
  while ((m = SQL_INSERT_NOCOL.exec(Fm)) !== null) { // INSERT INTO users VALUES ('bob', 'x'): no column list, so every string that looks like a secret
    st.work += 1;
    if (!CRED_TABLE.test(m[1])) continue;
    sqlTuples(Fm, m.index + m[0].length, (parts, tail, pos) => {
      for (const [ps, pe] of parts) {
        const raw = tail.slice(ps, pe);
        const lead = raw.length - raw.trimStart().length;
        const t = raw.trim();
        if (!/^(["'`]).*\1$/.test(t)) continue;
        const inner = core(t);
        if (inner.length >= 6 && shapeOK(inner, 6) && !/@/.test(inner) && !isDateOrVersion(inner) && !isNameish(inner)) spans.push({ s: pos + ps + lead, e: pos + ps + lead + t.length, id: 'sql' });
      }
    });
  }
  run(ORA_USERPASS, Fm, spans, st, 'sql', (mm) => (mm[0].endsWith('@') || shapeOK(core(mm[3]), 4) ? [mm.indices[3][0], mm.indices[3][1]] : null)); // sqlplus bob/x@db   sqlplus bob/x   rman target bob/x
}
function scanUrlParams(M, spans, st) {
  if (M.indexOf('=') < 0 && M.indexOf('/') < 0) return;
  run(URL_PARAM, M, spans, st, 'url-param', (m) => {
    const nm = m[1].toLowerCase();
    const cv = core(m[2]);
    const strong = QP_STRONG.has(nm) || (nm === 'sas' || nm === 'sas_token');
    if (strong ? cv.length >= 6 : QP_WEAK.has(nm) && (shapeOK(cv, 6) && !isDateOrVersion(cv))) { const at = m.index + m[0].length - m[2].length; return [at, at + m[2].length]; }
    return null;
  });
  run(URL_PATH_TOKEN, M, spans, st, 'url-param', (m) => (shapeOK(m[1], 8) && (/\d/.test(m[1]) || shapeOf(m[1]).innerCap) && !HOSTLIKE.test(m[1]) ? [m.index + m[0].length - m[1].length, m.index + m[0].length] : null));
}

// "Authorization: required", "Cookie: scopes read write": a documentation line made only of everyday and descriptive words is not a header value.
const DESCR_WORDS = new Set(['scope', 'scopes', 'read', 'write', 'header', 'headers', 'cookie', 'cookies', 'token', 'tokens', 'session', 'sessions', 'value', 'values', 'only', 'optional', 'access', 'granted', 'denied']);
const VARIABLE_VALUE = /^["'`]?(?:(?:bearer|basic|token|digest|bot)[ ]+)?["'`]?(?:\$[A-Za-z_{(]|%[A-Za-z_]+%|\{\{|<[A-Za-z _-]{1,30}>)/i;
const HEADER_NOTHING = /^["'`]?(?:\(none\)|\(empty\)|\(not set\)|none|null|nil|undefined|n\/a|-{1,3}|\?{1,3})["'`]?$/i;
const HEADER_PLACEHOLDER = /^["'`]?(?:YOUR[_ -]|<[^>]{1,40}>|\{[A-Za-z_][\w. -]{0,40}\}|\*{3,}|[xX*#.-]{4,}(?![A-Za-z0-9])|[A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+(?![A-Za-z0-9])|REPLACE|CHANGE_?ME|INSERT|TOKEN_HERE|0{8}-)/;
const COOKIE_ATTRS = new Set(['expires', 'max-age', 'domain', 'path', 'samesite', 'secure', 'httponly', 'partitioned', 'priority']);
// A header with no value, a placeholder instead of a value, or a cookie that only clears itself (every cookie has an empty value) holds nothing to hide.
function emptyHeaderValue(head, v) {
  if (v === '' || HEADER_NOTHING.test(v)) return true;
  if (HEADER_PLACEHOLDER.test(v.replace(/^(?:bearer|basic|token|digest|bot)[ ]+/i, ''))) return true;
  if (head === 'set-cookie' || head === 'cookie') {
    for (const item of v.split(';')) {
      const eq = item.indexOf('=');
      if (eq < 0) continue;
      const name = item.slice(0, eq).trim().toLowerCase();
      if (COOKIE_ATTRS.has(name)) continue;
      if (item.slice(eq + 1).trim() !== '') return false;
    }
    return true;
  }
  return false;
}
function descriptiveHeader(v) {
  if (!/^[A-Za-z0-9][A-Za-z0-9 ,.'-]{0,80}$/.test(v)) return false;
  const words = v.toLowerCase().split(/[ ,.]+/).filter(Boolean);
  if (words.length === 0 || words.length > 8) return false;
  if (SCHEMES.has(words[0]) && words.length > 1) return false;
  if (words.length >= 2) return true; // two or more plain words are a sentence ("Change cookie: click Settings."), not a header value
  return words.every((w) => isCommonWord(w) || isSoftWord(w) || DESCR_WORDS.has(w));
}

function scanUrlUserinfo(M, spans, st) {
  run(URL_USERINFO_SLASH, M, spans, st, 'url-userinfo', (m) => (/[/?#]/.test(m[1]) ? [m.index + m[0].length - m[1].length - 1, m.index + m[0].length] : null)); // a / ? # inside the password: https://bob:pa/ss@host/x
  run(URL_USERINFO, M, spans, st, 'url-userinfo', (m) => {
    const scheme = m[0].slice(0, m[0].indexOf(':')).toLowerCase();
    if (SSH_SCHEMES.has(scheme) && /^[a-z]{1,16}$/.test(m[1])) return null; // ssh://git@host: a user name, not a secret
    return [m.index + m[0].length - m[1].length - 1, m.index + m[0].length];
  });
}

// mode 'url': only the URL user-info detector (used on the view with tab / line breaks deleted); otherwise every detector.
function findSpans(M, st, decoded, mode) {
  if (mode === 'url') {
    const only = [];
    scanUrlUserinfo(M, only, st);
    return dropMarkOverlaps(M, only);
  }
  const Fm = flatten(M);
  const ctx = { M, Fm, n: M.length, st, brk: null, cellEnd: undefined, decoded, strict: mode === 'qp' };
  const spans = [];
  scanKeywords(ctx, spans);
  run(PREFIX_TOKEN, M, spans, st, 'prefix-token');
  scanJwt(M, spans, st);
  run(VAULT_TOKEN, M, spans, st, 'prefix-token', (m) => (/\d/.test(m[0]) && /[A-Za-z]/.test(m[0].slice(2)) ? [m.index, m.index + m[0].length] : null));
  run(DISCORD_TOKEN, M, spans, st, 'prefix-token', (m) => (/\d/.test(m[0]) ? [m.index, m.index + m[0].length] : null));
  run(WIFI_QR, Fm, spans, st, 'wifi', (m) => { // WIFI:T:WPA;S:home;P:secret;;
    const f = /(?:^|;)P:((?:\\.|[^;\\]){1,200})/i.exec(m[0].slice(5));
    if (!f) return null;
    const start = m.index + 5 + f.index + f[0].length - f[1].length;
    return [start, start + f[1].length];
  });
  run(SSH_KEY, Fm, spans, st, 'ssh-key');
  scanPem(M, spans, st);
  scanUrlUserinfo(M, spans, st);
  scanBareUserinfo(M, spans, st);
  run(BEARER, M, spans, st, 'bearer', (m) => {
    const cv = core(m[1]);
    if (HEADER_PLACEHOLDER.test(m[1])) return null; // Authorization: Bearer YOUR_TOKEN
    if (/^[A-Za-z]{2,20}=$/.test(m[1])) return null; // WWW-Authenticate: Bearer realm="x"
    return shapeOK(cv, 6) || cv.length >= 20 ? [m.index, m.index + m[0].length] : null;
  });
  run(HEADER, M, spans, st, 'header', (m) => {
    const t = m[0];
    const colon = t.indexOf(':');
    const v = t.slice(colon + 1).trim();
    const head = t.slice(0, colon).toLowerCase();
    if ((head === 'authorization' || head === 'cookie' || head === 'proxy-authorization') && descriptiveHeader(v)) return null;
    if (VARIABLE_VALUE.test(v)) return null; // curl -H "Authorization: Bearer $TOKEN"  Authorization: `Bearer ${token}`
    if (colon + 1 < t.length && !/[ \t]/.test(t[colon + 1]) && PERM_VERBS.has(v.toLowerCase())) return null; // authorization:read (a permission name)
    if (emptyHeaderValue(head, v)) return null; // Authorization:   X-API-Key: (none)   Set-Cookie: sid=; Max-Age=0   Bearer YOUR_TOKEN
    return [m.index, m.index + t.length];
  });
  run(USER_PAIR, Fm, spans, st, 'pair', (m) => (shapeOK(core(m[1]), 4) ? [m.index, m.index + m[0].length] : null));
  run(LABEL_PAIR, Fm, spans, st, 'pair', (m) => (shapeOK(core(m[1]), 4) ? [m.index, m.index + m[0].length] : null));
  run(LOGIN_WITH, Fm, spans, st, 'pair', (m) => (shapeOK(core(m[1]), 6) ? [m.index, m.index + m[0].length] : null));
  run(BASIC_PAIR, Fm, spans, st, 'pair', (m) => (shapeOK(core(m[1]), 6) ? [m.index, m.index + m[0].length] : null));
  run(LOGIN_NEXT_LINE, M, spans, st, 'pair', (m) => (shapeOK(core(m[1]), 6) ? [m.index, m.index + m[0].length] : null));
  run(PAIR_WORDS, Fm, spans, st, 'pair', (m) => {
    const u = m[1].toLowerCase();
    const pw = core(m[2]);
    return /^[A-Za-z]/.test(m[1]) && !isCommonWord(u) && !isSoftWord(u) && !NOT_USER.has(u) && !/^[${(<{[]/.test(m[2]) && strongShape(pw, 6) && !isDateOrVersion(pw) ? [m.indices[1][0], m.index + m[0].length] : null;
  });
  run(PAIR_NAMED, Fm, spans, st, 'pair', (m) => (/^[A-Za-z]/.test(m[1]) && !NOT_USER.has(m[1].toLowerCase()) && !/^[${(<{[]/.test(m[2]) && strongShape(core(m[2]), 6) && !isDateOrVersion(core(m[2])) ? [m.indices[1][0], m.index + m[0].length] : null));
  run(CONNECT_USING, Fm, spans, st, 'pair', (m) => {
    const u = m[1].toLowerCase();
    const pw = core(m[2]);
    if (IMAGE_NAMES.has(u) || isCommonWord(u) || !strongShape(pw, 6) || isDateOrVersion(pw) || /^[\d.]+(?:-[a-z]+)?$/.test(pw) || FILE_RE.test(pw)) return null; // node:20-alpine  localhost:3000
    return [m.indices[1][0], m.index + m[0].length];
  });
  run(IMAP_LOGIN, Fm, spans, st, 'cli', (m) => [m.indices[2][0], m.indices[2][1]]);
  run(TUPLE_LABEL, Fm, spans, st, 'pair', (m) => [m.indices[2][0], m.indices[2][1]]);
  run(AUTH_ARGS, Fm, spans, st, 'pair', (m) => [m.indices[3][0], m.indices[3][1]]);
  run(CHANGED_FROM, Fm, spans, st, 'phrase', (m) => (shapeOK(core(m[2]), 4) || shapeOK(core(m[4]), 4) ? [m.indices[1][0], m.index + m[0].length] : null));
  run(UP_SHORT, Fm, spans, st, 'pair');
  run(UP_SLASH, Fm, spans, st, 'pair');
  run(CLI_USER, Fm, spans, st, 'pair', (m) => {
    if (/^\d+$/.test(m[1]) && /^\d+$/.test(m[2])) return null; // docker run -u 1000:1000
    if (SHELL_VAR.test(m[1]) || SHELL_VAR.test(m[2])) return null; // curl -u $USER:$PASS
    if (!shapeOK(core(m[2]), 3) && !/\b(?:curl|wget|http)/i.test(Fm.slice(Math.max(0, m.index - 80), m.index))) return null;
    return [m.index, m.index + m[0].length];
  });
  run(KEY_IS, Fm, spans, st, 'phrase', (m) => {
    const cv = core(m[1]);
    if (/^\d+$/.test(cv) && cv.length < 6) return null; // "the key is 256 bits"
    return shapeOK(cv, 3) ? [m.index, m.index + m[0].length] : null;
  });
  scanRound4(M, Fm, spans, st);
  scanCli(Fm, spans, st);
  scanSql(Fm, spans, st);
  scanUrlParams(M, spans, st);
  scanLines(M, spans, st);
  run(CONFIRM_LINE, M, spans.length ? spans : [], st, 'assignment', (m) => { // Password: x / Verify: x
    const cv = core(m[1]);
    const prior = spans.filter((sp) => sp.e <= m.index && m.index - sp.e < 200 && sp.id !== 'opaque' && sp.id !== 'prefix-token');
    if (prior.length === 0) return null;
    return prior.some((sp) => M.slice(sp.s, sp.e).includes(cv)) || shapeOK(cv, 4) ? [m.indices[1][0], m.indices[1][1]] : null;
  });
  run(OPAQUE, M, spans, st, 'opaque', (m) => {
    const t = m[0];
    if (!/\d/.test(t) || wordlike(t) || UUID_RE.test(t) || TRACEPARENT_RE.test(t) || pathLike(t) || SID_RE.test(t)) return null;
    if (DIGEST_BEFORE.test(M.slice(Math.max(0, m.index - 8), m.index))) return null;
    return [m.index, m.index + t.length];
  });
  return dropMarkOverlaps(M, spans);
}

function render(text, spans, o, st) {
  const rank = (id) => (id === 'assignment' || id === 'shape' || id === 'phrase' ? 1 : 0); // on a tie the more specific detector names the mark
  spans.sort((x, y) => x.s - y.s || y.e - x.e || rank(x.id) - rank(y.id));
  let out = '';
  let at = 0;
  for (const sp of spans) {
    if (sp.s < at) { if (sp.e > at) at = sp.e; continue; }
    out += text.slice(at, sp.s) + String(o.mark(sp.id));
    at = sp.e;
    st.spans += 1;
    st.byDetector[sp.id] = (st.byDetector[sp.id] || 0) + 1;
  }
  return out + text.slice(at);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// The pipeline. Returns { text, found }. `text` is the masked text when found, the ORIGINAL input when nothing was found.
// The input is turned into several VIEWS (see "Steps 1-2"): the cleaned text; the text with VT / FF / NEL read as spaces; the text with Unicode tag characters read
// as the letters they stand for; each of those decoded round after round (percent, entities, escapes ...); and, for every one of them, a copy with markup deleted
// (pass<b></b>word) and one with tab / line breaks deleted (WHATWG URL parsing ignores them). Every view is scanned. A finding maps back to a range of the
// ORIGINAL input and the result is the original with the UNION of those ranges masked, so a credential that is visible only before a decode (an entity glued to a
// keyword) or only after it is masked, and nothing that was merely encoded is ever rewritten into plain text.
function analyze(raw, o, st, wantText) {
  st.calls += 1;
  st.inputChars += raw.length;
  if (raw.length === 0) return { text: raw, found: false };
  if (raw.length > o.maxChars) { st.oversize += 1; return { text: String(o.mark('oversize')), found: true }; }
  const rawLen = raw.length;
  const r0 = SPLIT_TEST.test(raw) ? replaceMapped(identity(raw), SPLIT_PAIR, () => '', rawLen) : identity(raw);
  const base = cleanView(r0, rawLen);
  if (base.t.length > o.maxChars * 2) { st.oversize += 1; return { text: String(o.mark('oversize')), found: true }; }
  const cap = Math.max(LIMITS.MAX_GROWTH * raw.length, 64);
  const budget = 2 * (LIMITS.SCAN_FACTOR * raw.length + LIMITS.SCAN_FLOOR);
  const undecodable = () => { st.undecodable += 1; return { text: String(o.mark('undecodable')), found: true }; };
  // 1. the roots, and for each the decode chain: too many rounds, too much growth or too much to scan -> mask the whole value
  const roots = [base];
  if (VT_FF_NEL_TEST.test(r0.t)) roots.push(cleanView(replaceMapped(r0, VT_FF_NEL, () => ' ', rawLen), rawLen));
  if (TAG_CHAR_TEST.test(r0.t)) roots.push(cleanView(replaceMapped(r0, TAG_CHARS, (m) => String.fromCharCode(m[0].codePointAt(0) - 0xe0000), rawLen), rawLen));
  const units = [];
  const seen = { all: new Set(), url: new Set(), qp: new Set() }; // a text that is already a unit is not scanned twice (the standard and the alternate decode chains often agree)
  const addUnit = (v, decoded, mode) => {
    const set = seen[mode];
    if (set.has(v.t)) return;
    set.add(v.t);
    units.push({ v, decoded, mode });
  };
  let scan = 0;
  let altBudget = 200;
  for (const root of roots) {
    scan += root.t.length;
    const chains = [[root]];
    const extra = [];
    if (ENC_TEST.test(root.t)) {
      const std = chains[0];
      let probe = root;
      for (let r = 0; ; r += 1) {
        const next = cleanView(decodeOnce(probe, rawLen), rawLen);
        st.work += probe.t.length;
        if (next.t === probe.t) break;
        if (r >= LIMITS.MAX_ROUNDS || next.t.length > cap) return undecodable();
        probe = next;
        std.push(probe);
        scan += probe.t.length;
        if (scan > budget) return undecodable();
      }
      if (std.length - 1 > st.maxRounds) st.maxRounds = std.length - 1;
      // the inside-out chain (see decodeAlt): only the neighbourhood of a reference cut by another layer is read that way, so the cost stays small on hostile text
      for (let k = 0; k < std.length && altBudget > 0; k += 1) {
        for (const [wa, wb] of windows(std[k].t, ALT_TRIGGER_G, 64, 400, Math.min(altBudget, 64))) {
          altBudget -= 1;
          let ap = sliceView(std[k], wa, wb);
          for (let r = k; ; r += 1) {
            const next = cleanView(decodeAlt(ap, rawLen), rawLen);
            st.work += ap.t.length;
            if (next.t === ap.t) break;
            if (r >= LIMITS.MAX_ROUNDS || next.t.length > cap) return undecodable();
            ap = next;
            scan += ap.t.length;
            if (scan > budget) return undecodable();
            extra.push({ v: ap, r: r + 1 });
          }
        }
      }
    }
    chains.forEach((chain, ci) => chain.forEach((v, r) => {
      addUnit(v, r > 0, 'all');
      if (MARKUP_TEST.test(v.t)) { const sv = replaceMapped(v, MARKUP, markupGone, rawLen); if (sv !== v) addUnit(sv, r > 0, 'all'); }
      if (v.t.includes('://') && /[\t\n\r]/.test(v.t)) { const sv = replaceMapped(v, TAB_NL, () => '', rawLen); if (sv !== v) addUnit(sv, r > 0, 'url'); }
    }));
    for (const e of extra) addUnit(e.v, true, 'all');
    if (QP_SOFT_TEST.test(root.t)) { const qv = replaceMapped(root, QP_SOFT, () => '', rawLen); if (qv !== root) addUnit(qv, true, 'qp'); }
    if (BS_RUN2_TEST.test(root.t)) { // runs of 2+ backslashes deleted around each run: password + 17 backslashes + "x"
      for (const [wa, wb] of windows(root.t, BS_RUN2_G, 64, 400, 64, 92)) {
        const w = sliceView(root, wa, wb);
        const sv = replaceMapped(w, BS_RUN2, () => '', rawLen);
        if (sv !== w) addUnit(sv, false, 'all');
      }
    }
  }
  // 2. scan every view; a finding is mapped back to a range of the original input
  const found = [];
  for (const u of units) {
    const Ms = [fold(u.v.t)];
    if (ALT_TEST.test(u.v.t)) Ms.push(foldAlt(u.v.t)); // digits that look like letters, read as letters
    for (const M of Ms) {
      st.work += M.length;
      const spans = findSpans(M, st, u.decoded, u.mode);
      if (spans.length === 0) continue;
      if (!wantText) return { text: '', found: true };
      for (const sp of spans) {
        const rr = rawRange(u.v, sp.s, sp.e);
        if (rr) found.push({ s: rr[0], e: rr[1], id: sp.id });
      }
    }
  }
  jsonTextSpans(raw, o, st, found);
  if (found.length === 0) return { text: raw, found: false };
  if (!wantText) return { text: '', found: true };
  return { text: render(raw, found, o, st), found: true, spans: found };
}

// A text that is a JSON document gets the structure rules maskDeep has (name/value pairs, columns and rows, header-plus-rows, Secret manifests ...): it is
// parsed, walked like a value, and every string literal of the text that maskDeep replaced as a whole is masked in the text too.
const JSON_TEXT_MAX = 262144;
function jsonTextSpans(raw, o, st, found) {
  const n = raw.length;
  if (n < 2 || n > JSON_TEXT_MAX) return;
  // NUL, other controls and invisible characters anywhere in the text (between tokens, inside a name) make JSON.parse fail, which would switch the structure rules off:
  // they are deleted for the parse, and from every literal before it is compared.
  const dirty = raw.search(STRIP) >= 0;
  const strip = (t) => (dirty ? t.replace(STRIP, '') : t);
  const src = strip(raw);
  let a = 0;
  while (a < n && (raw.charCodeAt(a) <= 32 || (dirty && strip(raw[a]) === ''))) a += 1;
  const c = raw.charCodeAt(a);
  if (c !== 123 && c !== 91) return;
  let hits;
  try {
    const parsed = JSON.parse(src);
    hits = new Set();
    walk(parsed, 0, false, { o, st, nodes: 0, chars: 0, seen: new WeakSet(), keyCache: new Map(), hits });
  } catch { return; }
  if (hits.size === 0) return;
  // string literals of the text that are values (a literal followed by a colon is a key)
  for (let i = raw.indexOf('"', a); i >= 0 && i < n;) {
    let j = i + 1;
    while (j < n) {
      const d = raw.charCodeAt(j);
      if (d === 92) j += 2; else if (d === 34) break; else j += 1;
    }
    if (j >= n) return;
    let k = j + 1;
    while (k < n && raw.charCodeAt(k) <= 32) k += 1;
    if (raw.charCodeAt(k) !== 58) {
      const lit = strip(raw.slice(i + 1, j));
      let value = lit;
      if (lit.includes('\\')) { try { value = JSON.parse(`"${lit}"`); } catch { value = null; } }
      if (value !== null && hits.has(value)) found.push({ s: i, e: j + 1, id: 'assignment' });
    }
    i = raw.indexOf('"', j + 1);
  }
}
function maskString(s, o, st) {
  try {
    const res = analyze(s, o, st, true);
    if (res.found) st.changed += 1;
    return res.text;
  } catch {
    st.errors += 1;
    return safeMark(o, 'error');
  }
}

// maskText(str, opts) -> masked string. Never throws on any value; throws MaskUsageError only for bad opts.
//   null / undefined -> '' ; number, boolean, bigint -> String(value) ; object, function, symbol -> the [masked:non-string] mark.
export function maskText(str, opts) {
  const o = readOpts(opts);
  const st = o.stats || SCRATCH_STATS();
  if (typeof str === 'string') return maskString(str, o, st);
  if (str === undefined || str === null) return '';
  if (typeof str === 'number' || typeof str === 'boolean' || typeof str === 'bigint') return maskString(String(str), o, st);
  st.nonString += 1;
  return String(o.mark('non-string'));
}

// looksLikeCredential(str) -> boolean. True when maskText would change the text (including oversize / undecodable input). Non-strings: false.
export function looksLikeCredential(str, opts) {
  const o = readOpts(opts);
  const st = o.stats || SCRATCH_STATS();
  if (typeof str !== 'string') return false;
  try {
    return analyze(str, o, st, false).found;
  } catch {
    st.errors += 1;
    return true;
  }
}

// isCredentialId(id) -> boolean, for workspace ids and other ids that must never be echoed or used as a key.
const ID_PREFIX = /^(?:sk|pw|token|key|secret|password|bearer|ghp|gho|ghu|ghs|ghr|glpat|xox[a-z]?|akia|asia|pk|rk)[-_]/i;
export function isCredentialId(id) {
  if (typeof id !== 'string') return false;
  if (id.length > 4096) return true;
  if (ID_PREFIX.test(id)) return true;
  let hexRun = 0;
  let hexDigits = 0;
  let alnumRun = 0;
  let alnumDigit = false;
  for (let i = 0; i <= id.length; i += 1) {
    const c = i < id.length ? id.charCodeAt(i) : 0;
    const hexish = isDigitC(c) || (c >= 97 && c <= 102) || (c >= 65 && c <= 70);
    if (hexish || c === 45) { hexRun += 1; if (hexish) hexDigits += 1; } else { if (hexRun >= 24 && hexDigits >= 20) return true; hexRun = 0; hexDigits = 0; }
    if (isAlnumC(c)) { alnumRun += 1; if (isDigitC(c)) alnumDigit = true; } else { if (alnumRun >= 24 && alnumDigit) return true; alnumRun = 0; alnumDigit = false; }
  }
  return looksLikeCredential(id);
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// maskDeep. A key is classified from its words, not by probing it as text. The classes (the force a key puts on its value):
//   strong (2)   password-family and secret/token-family names: every string, number and boolean below it is masked, objects leaf by leaf, and so is an object key that
//                looks like a secret;
//   glued (4)    the same, for names that only END in such a word (jsonwebtoken, dbpassword): a version range ("^9.0.2") is a package dependency and stays;
//   plural (3)   plural "tokens": every STRING below it, in arrays and objects too, that looks like a secret (token counts such as max_tokens: 1024 are numbers);
//   weak (1)     login, session, cookie, sid, pass, auth, basic, bearer, authorization, key, sig, signature, jwt, pin, code, p, k ...: a STRING value (or each string of an
//                array) is masked when it looks like a secret - 6+ characters with a digit, symbol or inner capital that is not a NAME (item-12, ERR_NOT_FOUND, RSA-SHA256).
const KEY_STRONG = new Set(('password passwd passphrase passcode pwd pw psw pswd pword passw passwrd passwort kennwort contrasena senha secret secrets credential credentials cred creds ' +
  'psk token apikey accesstoken refreshtoken authtoken apitoken idtoken bearertoken sessiontoken csrftoken xsrftoken clientsecret clientassertion codeverifier sessionid jsessionid ' +
  'secretkey accesskey privatekey accountkey signingkey encryptionkey masterkey sshkey licensekey storagekey servicekey deploykey appkey hmackey wifikey connectionstring mnemonic ' +
  'passwordhash identifiedby motdepasse privkey phpsessid sessid requirepass masterauth authz plaintext cleartext recoveryphrase seedphrase webhookurl storepass keypass truststorepass').split(' '));
const NON_LATIN_KEYS = ['\u043f\u0430\u0440\u043e\u043b\u044c', '\u5bc6\u7801', '\u53e3\u4ee4', '\u30d1\u30b9\u30ef\u30fc\u30c9', '\ube44\ubc00\ubc88\ud638', '\uc554\ud638', '\u5bc6\u78bc']; // Russian, Chinese x2, Japanese, Korean x2, Chinese (traditional)
NON_LATIN_KEYS.push('\ud328\uc2a4\uc6cc\ub4dc'); // Korean transliteration of "password"
const NON_LATIN_FOLDED = [...new Set(NON_LATIN_KEYS.flatMap((w) => [fold(w).toLowerCase(), fold(w.toUpperCase()).toLowerCase()]))]; // the capital soft sign folds differently from the small one
for (const w of NON_LATIN_FOLDED) KEY_STRONG.add(w);
for (const w of ['pa\u00dfwort', 'passworter', 'kennworter']) KEY_STRONG.add(w);
const KEY_WEAK = new Set('login session sessions cookie cookies sid pass passkey auth authorization basic bearer key sig signature jwt otp totp pin code dsn p k pat sess csrf xsrf'.split(' '));
const KEY_QUALIFIER = new Set(['api', 'access', 'private', 'secret', 'account', 'signing', 'encryption', 'master', 'ssh', 'license', 'storage', 'service', 'deploy', 'app', 'hmac', 'wifi',
  'devops', 'shared', 'webhook', 'symmetric', 'subscription', 'functions', 'auth', 'client', 'session', 'rsa', 'aes', 'tls', 'bearer', 'user', 'db', 'admin', 'root']);
const DEEP_PAIRS = Object.assign(Object.create(null), { client: ['assertion'], code: ['verifier'], connection: ['string'], seed: ['phrase'], recovery: ['code', 'phrase'], access: ['token'], refresh: ['token'], id: ['token'], auth: ['token'], api: ['token'], bearer: ['token'], webhook: ['url'], wallet: ['seed'], secret: ['word'] }); // (no prototype: the key word "constructor" is not a pair)
const KEY_GLUE_LONG = ['password', 'passwd', 'passphrase', 'passcode', 'secret', 'token', 'apikey', 'credential', 'credentials'];
const KEY_GLUE_SHORT = ['pw', 'pwd', 'pass', 'psw', 'pswd'];
const KEY_START_OK = new Set(['hash', 'value', 'confirm', 'confirmation', 'again', 'verify', 'new', 'old', 'current', 'repeat']);
const KEY_FOLLOW_SAFE = new Set([...SAFE_SUFFIX, 'method', 'methods', 'supported', 'endpoint', 'servers', 'request', 'response', 'version', 'bucket', 'in', 'of', 'to', 'issued', 'every', 'challenge', 'ops', 'operations']);
// A name like password_input / secretField holds what the visitor TYPED: not safe, but a value that is a name stays (password_field: "pwd").
const TYPED_WORDS = new Set(['input', 'field', 'form', 'box', 'entry', 'text', 'element', 'control', 'prompt']);
// Values that are placeholders or nothing at all: our own marks, template expressions, shell variables, "(not set)" ...
const PLACEHOLDER_VALUE = /^(?:\[(?:masked|redacted)[^\]]{0,40}\]|\*{3,}|x{4,}|<redacted>|<hidden>|\u2022{3,}|-{3,}|\.{3,}|\$\{\{[^}]{0,80}\}\}|\$\{[^}]{0,80}\}|\{\{[^}]{0,80}\}\}|<[A-Za-z][A-Za-z _-]{0,40}>|\(?(?:not set|unset|none|n\/a|null|empty|blank|hidden|redacted|masked|not configured|missing|required|optional)\)?)$/i;
// Under a credential key, members that describe the credential (a JSON schema, an OpenAPI security scheme, a key's fingerprint) stay unless their value itself looks like a secret.
const META_KEYS = new Set(['type', 'types', 'minlength', 'maxlength', 'minimum', 'maximum', 'pattern', 'required', 'description', 'title', 'format', 'enum', 'in', 'name', 'scheme', 'bearerformat', 'flow', 'flows', 'fingerprint',
  'fingerprints', 'algorithm', 'alg', 'bits', 'length', 'size', 'kind', 'label', 'hint', 'example', 'examples', 'default', 'ref', 'schema', 'minitems', 'maxitems', 'nullable', 'readonly', 'writeonly', 'deprecated', 'placeholder',
  'version', 'versions', 'updated', 'updatedat', 'created', 'createdat', 'modified', 'modifiedat', 'changed', 'changedat', 'lastchanged', 'lastrotated', 'rotated', 'rotatedat', 'rotation', 'expires', 'expiresat', 'expiry', 'expiration', 'ttl', 'set',
  'isset', 'policy', 'policies', 'strength', 'status', 'state', 'enabled', 'disabled', 'count', 'owner', 'tags', 'labels', 'id', 'arn', 'uri', 'url', 'path', 'location', 'reference', 'source', 'provider', 'manager', 'store', 'vault', 'lifetime', 'age', 'score']);
const PLACEHOLDER_ENV = /^(?:\$[A-Z_][A-Z0-9_]{2,40}|%[A-Z_][A-Z0-9_]{2,40}%)$/; // $TOKEN  %TOKEN%: an upper-case variable reference (case-sensitive: $hunter2xyz is a value)
const COLUMN_WORDS = new Set(['id', 'name', 'user', 'username', 'email', 'role', 'status', 'type', 'created', 'updated', 'date', 'time', 'title', 'description', 'group', 'age', 'phone', 'address', 'city', 'country', 'host', 'port']);

// The words of a key as the matcher reads them: NFKC, invisible characters deleted, look-alikes folded, and decoded round after round (%70assword, &#112;assword,
// \u0070assword, tag characters). Every view of the key is classified and the strongest class wins. A key is read at ANY length.
function keyViews(k0) {
  const k = joinPairs(k0);
  const views = [];
  const addView = (t) => { const f = fold(t); views.push(f); if (ALT_TEST.test(t)) views.push(foldAlt(t)); };
  const roots = [k];
  if (TAG_CHAR_TEST.test(k)) roots.push(k.replace(TAG_CHARS, (c) => String.fromCharCode(c.codePointAt(0) - 0xe0000)));
  if (VT_FF_NEL_TEST.test(k)) roots.push(k.replace(VT_FF_NEL, ' '));
  for (const root of roots) {
    const cr = clean(root); // the references are looked for in the cleaned text: "%" + NUL + "70assword" is a reference
    addView(cr);
    if (ENC_TEST.test(cr)) {
      const cap = Math.max(LIMITS.MAX_GROWTH * root.length, 64);
      let triggered = ALT_TRIGGER_T.test(cr); // the inside-out order only where a reference is cut by another layer (see decodeAlt)
      for (const step of [decodeOnce, decodeAlt]) {
        if (step === decodeAlt && !triggered) break;
        let probe = cleanView(identity(root), root.length);
        for (let r = 0; r < LIMITS.MAX_ROUNDS; r += 1) {
          const next = cleanView(step(probe, root.length), root.length);
          if (next.t === probe.t || next.t.length > cap) break;
          probe = next;
          addView(probe.t);
          if (!triggered && ALT_TRIGGER_T.test(probe.t)) triggered = true;
        }
      }
    }
  }
  if (k.includes('\\')) addView(clean(k.replace(BS_RUN, '')));
  return views;
}
// Split a camelCase / PascalCase / ACRONYMWord key into lower-case words. One pass, no backtracking (a run of capitals is NOT a quadratic regular expression).
function camelWords(c) {
  let out = '';
  for (let i = 0; i < c.length; i += 1) {
    const ch = c.charCodeAt(i);
    if (i > 0 && ch >= 65 && ch <= 90) {
      const p = c.charCodeAt(i - 1);
      const n = c.charCodeAt(i + 1);
      if ((p >= 97 && p <= 122) || (p >= 48 && p <= 57) || (p >= 65 && p <= 90 && n >= 97 && n <= 122)) out += ' ';
    }
    out += c[i];
  }
  return out.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean);
}
function wordLists(view) {
  // the camelCase reading (myPassword -> my password) and the plain one (PASSword, pAssword, TOKENs: capitals are not word boundaries); the stronger class wins
  const lists = [camelWords(view)];
  if (/[A-Z]/.test(view)) lists.push(view.toLowerCase().split(/[^\p{L}\p{N}]+/u).filter(Boolean));
  return lists;
}
const keyWords = (k) => camelWords(fold(clean(k)));

// scores: 5 strong (exact word), 4 glued, 3 plural tokens, 1 weak; 0 none
const WEAK_PLURAL_OK = (w) => w.length > 3 && w.endsWith('s') && w !== 'keys' && w !== 'codes';
function wordScore(w0, words, i) {
  let w = w0;
  const dm = /^([a-z]{2,})\d{1,3}$/.exec(w); // password2, key1, pass1, pw2
  if (dm && (dm[1].length >= 3 || KEY_STRONG.has(dm[1]))) w = dm[1];
  else {
    const rm = /^([a-z]{3,}?)(?:ii|iii|iv|vi|vii|viii|ix)$/.exec(w);
    if (rm && (KEY_STRONG.has(rm[1]) || KEY_WEAK.has(rm[1]))) w = rm[1];
  }
  const prev = i > 0 ? words[i - 1] : '';
  const next = words[i + 1];
  if (KEY_STRONG.has(w)) return { cls: 5, end: i };
  if (w === 'tokens') return { cls: 3, end: i };
  if (w.length >= 3 && w.endsWith('s') && KEY_STRONG.has(w.slice(0, -1))) return { cls: w.slice(0, -1).endsWith('token') ? 3 : 5, end: i }; // passwords, pws, apikeys, accesstokens
  if ((w === 'pass' && next === 'word') || (w === 'session' && (next === 'id' || next === 'ids')) || (DEEP_PAIRS[w] !== undefined && DEEP_PAIRS[w].includes(next))) return { cls: 5, end: i + 1 };
  if (w === 'passe' && prev === 'de' && words[i - 2] === 'mot') return { cls: 5, end: i };
  if ((w === 'key' || w === 'keys') && KEY_QUALIFIER.has(prev)) return { cls: 5, end: i };
  if (w === 'key' && i > 0 && KEY_DENY.has(prev)) return { cls: 0, end: i };
  if (w === 'secret' && next === 'key') return { cls: 5, end: i };
  if (KEY_WEAK.has(w)) return { cls: KEY_STRONG.has(prev) || prev === 'key' ? 0 : 1, end: i };
  if (WEAK_PLURAL_OK(w) && KEY_WEAK.has(w.slice(0, -1))) return { cls: KEY_STRONG.has(prev) ? 0 : 1, end: i }; // pins, sigs, auths
  if (w.charCodeAt(0) > 0x2e80 || w.charCodeAt(0) > 0x400) for (const nk of NON_LATIN_FOLDED) if (w.length > nk.length && w.includes(nk)) return { cls: 4, end: i }; // \u7528\u6237\u5bc6\u7801
  // glued names: dbpassword, userpass, xxxxx...password, passwordhash
  for (const g of KEY_GLUE_LONG) if (w.length > g.length && w.endsWith(g)) return { cls: 4, end: i };
  for (const g of KEY_GLUE_SHORT) if (w.length > g.length && w.endsWith(g) && PASS_PREFIXES.some((p) => w.slice(0, -g.length).endsWith(p))) return { cls: 4, end: i };
  for (const g of KEY_GLUE_LONG) if (w.length > g.length && w.startsWith(g) && KEY_START_OK.has(w.slice(g.length))) return { cls: 4, end: i };
  if (w.length > 3 && (w.endsWith('key') || w.endsWith('keys')) && KEY_QUALIFIER.has(w.slice(0, w.endsWith('keys') ? -4 : -3))) return { cls: 4, end: i };
  return { cls: 0, end: i };
}
function classifyWords(words) {
  let best = 0;
  for (let i = 0; i < words.length; i += 1) {
    const { cls, end } = wordScore(words[i], words, i);
    if (!cls) continue;
    const prev = i > 0 ? words[i - 1] : '';
    if (FLAG_PREFIX.has(prev)) continue;
    let safe = '';
    for (let k = end + 1; k <= end + 3 && k < words.length; k += 1) if (KEY_FOLLOW_SAFE.has(words[k])) { safe = words[k]; break; }
    if (safe) {
      if (TYPED_WORDS.has(safe) && best < 1) best = 1; // password_input: not a setting about the password, the typed password itself
      continue;
    }
    if (cls > best) best = cls;
    if (best === 5) return 5;
  }
  return best;
}
// the class of a key: the strongest over all its views (decoded, look-alikes folded, capitals-run variant)
function classifyKey(k) {
  let best = 0;
  for (const view of keyViews(k)) {
    for (const words of wordLists(view)) {
      const c = classifyWords(words);
      if (c > best) best = c;
      if (best === 5) return 5;
    }
  }
  return best;
}
const NAME_FIELDS = new Set(['name', 'key', 'label', 'field', 'header', 'param', 'parameter', 'variable', 'var', 'id', 'setting', 'property', 'prop', 'attr', 'attribute', 'column', 'env', 'option', 'arg', 'argument', 'type', 'k', 'n',
  'parametername', 'parameterkey', 'keyname', 'propertyname', 'fieldname', 'varname', 'paramname', 'settingname', 'variablename', 'envname']);
const VALUE_FIELDS = new Set(['value', 'val', 'v', 'text', 'data', 'content', 'contents', 'secret', 'string', 'default', 'defaultvalue', 'parametervalue', 'sensitivevalue', 'encryptedvalue', 'securevalue', 'plainvalue', 'rawvalue',
  'stringvalue', 'input', 'plaintext', 'cleartext', 'propertyvalue', 'fieldvalue', 'variablevalue', 'envvalue']);
const normField = (k) => k.toLowerCase().replace(/[^a-z0-9]/g, ''); // "@name", "#text", "sensitive_value", "ParameterKey"
function labelClass(s) {
  // a short string that names a credential ("DB_PASSWORD", "Authorization", "--password", "x-api-key"): 2 strong, 1 weak, 0 no
  if (typeof s !== 'string' || s.length === 0 || s.length > 512) return 0;
  const spaced = /\s/.test(s);
  const words = keyWords(s);
  if (words.length === 0 || words.length > (spaced ? 6 : 64)) return 0;
  const c = classifyWords(words);
  return c === 5 || c === 4 ? 2 : c === 3 ? 3 : c;
}
// A string that names a thing - item-12, ERR_NOT_FOUND, auth/invalid-credential, connect.sid, XSRF-TOKEN, RSA-SHA256, bob@example.com, jdoe42 - rather than being a secret:
// every part (split at - _ . : @ /) is a word of at most two case changes, up to four digits, or a word with up to four trailing digits.
function isNameish(cv) {
  if (cv.length > 80) return false;
  const parts = cv.split(/[-_.:@/]+/).filter(Boolean);
  if (parts.length === 0) return false;
  for (const p of parts) {
    if (/^\d{1,4}$/.test(p)) continue;
    const m = /^([A-Za-z]{1,24})\d{0,4}$/.exec(p);
    if (!m) return false;
    let flips = 0;
    for (let i = 1; i < m[1].length; i += 1) if (isLowerC(m[1].charCodeAt(i - 1)) && isUpperC(m[1].charCodeAt(i))) flips += 1;
    if (flips > 2) return false;
  }
  if (parts.length >= 3 && /^[a-z]/.test(parts[0]) && parts.slice(1).some((p) => /^[A-Z][a-z]/.test(p))) return false; // correct-Horse-battery9
  return true;
}
// A string under a weak key: 6+ characters with a digit, symbol or inner capital, no inner white space (surrounding white space is ignored), not a placeholder or a name.
function weakSecretish(v) {
  if (typeof v !== 'string') return false;
  const t = cs(v).trim();
  if (t.length < 6 || /\s/.test(t) || PLACEHOLDER_VALUE.test(t)) return false;
  const cv = core(t);
  return shapeOK(cv, 6) && !isNameish(cv) && !isSoftWord(cv.toLowerCase());
}
// An object key that is itself a secret (a map keyed by token or session id): a digit that is not just a numbering suffix, or a long opaque run.
function keyLooksSecret(k) {
  if (k.length < 6 || k.length > 4096) return false;
  const c = core(k.trim());
  if (c.length < 6 || isDateOrVersion(c) || !/\d/.test(c)) return false;
  return !/^[A-Za-z][A-Za-z_.-]*\d{1,3}$/.test(c); // password2, item12: a numbering suffix, not a secret
}
const PWD_PATH = /^(?:\/|~|\.\/|\.\.\/|[A-Za-z]:[\\/])/;
// A value of a pwd key that is a working directory: /home/alice, /app, C:\Users\bob - not /hunter2xyz (one segment with a digit, capital or symbol)
function isDirLike(v) {
  if (!PWD_PATH.test(v)) return false;
  const segs = v.split(/[\\/]+/).filter(Boolean);
  while (segs.length && (segs[0] === '.' || segs[0] === '..' || /^[A-Za-z]:$/.test(segs[0]))) segs.shift();
  if (segs.length >= 2) return true;
  return segs.length === 0 || /^~?[a-z_-]*$/.test(segs[0]);
}
const VERSIONISH = /^[~^<>=]{0,2}[vV]?\d+(?:\.(?:\d+|[xX*]))*(?:[-+][\w.-]+)?$|^(?:latest|next|workspace:.+|npm:.+|\*)$/;
// credential columns of a header row: Map(index -> 2 | 1)
const HEADER_CELL_KEYS = new Set(['name', 'label', 'title', 'key', 'field', 'id', 'header', 'text', 'column', 'columnname', 'fieldname', 'displayname', 'prop', 'dataindex', 'accessor', 'headername', 'caption']);
function headerCellText(h) {
  if (typeof h === 'string') return h;
  if (h === null || typeof h !== 'object' || Array.isArray(h)) return null;
  try {
    for (const k of Object.keys(h)) if (HEADER_CELL_KEYS.has(normField(k)) && typeof h[k] === 'string') return h[k];
  } catch { /* an unreadable descriptor is not a header */ }
  return null;
}
function credCols(header) {
  const cols = new Map();
  if (!Array.isArray(header)) return cols;
  for (let i = 0; i < header.length && i < LIMITS.MAX_NODES; i += 1) {
    let h;
    try { h = headerCellText(header[i]); } catch { continue; }
    if (typeof h !== 'string') continue;
    const lc = labelClass(h);
    if (lc >= 1) cols.set(i, lc === 1 ? 1 : 2);
  }
  return cols;
}
const HEADER_KEYS = new Set(['columns', 'headers', 'header', 'fields', 'cols', 'colnames', 'columnnames', 'thead', 'head', 'titles', 'headings', 'columndefs', 'columndefinitions']);
const ROWS_KEYS = new Set(['rows', 'data', 'values', 'records', 'items', 'results', 'tbody', 'entries', 'list', 'lines', 'body', 'result', 'tuples', 'cells', 'matrix', 'grid', 'rowdata', 'table']);
// the force a cell of a credential column gets
function cellForce(level, cell) {
  if (cell !== null && typeof cell === 'object') return level === 2 ? 2 : (Array.isArray(cell) ? 1 : 0); // a list or a record in a credential column is the credential
  if (level === 2) return typeof cell === 'number' || (typeof cell === 'string' && fieldValueOK(core(cs(cell).trim()))) ? 2 : 0;
  return 1;
}

function walkRows(rows, cols, depth, ctx) {
  const { o } = ctx;
  const out = [];
  for (let r = 0; r < rows.length; r += 1) {
    if (ctx.nodes >= o.maxNodes) { out.push(safeMark(o, 'too-large')); break; }
    let row;
    try { row = rows[r]; } catch { out.push(safeMark(o, 'unreadable')); continue; }
    if (!Array.isArray(row)) { out.push(walk(row, depth + 1, 0, ctx)); continue; }
    ctx.seen.add(row);
    ctx.nodes += 1;
    ctx.st.nodes += 1;
    try {
      const cells = [];
      for (let c = 0; c < row.length; c += 1) {
        if (ctx.nodes >= o.maxNodes) { cells.push(safeMark(o, 'too-large')); break; }
        let cell;
        try { cell = row[c]; } catch { cells.push(safeMark(o, 'unreadable')); continue; }
        cells.push(walk(cell, depth + 2, cols.has(c) ? cellForce(cols.get(c), cell) : 0, ctx));
      }
      out.push(cells);
    } finally {
      ctx.seen.delete(row);
    }
  }
  return out;
}

const isPermName = (item) => { const i = item.lastIndexOf(':'); return i > 0 && PERM_VERBS.has(item.slice(i + 1).toLowerCase()); }; // secrets:rotate
const SEP_ITEM = /^[\s:=,;|>-]{0,3}$/;
const isSepItem = (item) => item === null || item === undefined || (typeof item === 'string' && SEP_ITEM.test(item));
// One step of the pair rule over a sequence (an array, or an object with keys "0", "1" ...): after an element that names a credential the next element that is not a
// separator ("", null, ":", "=", "=>") is its value, whatever its type. Returns the force for `item` and the new state.
function pairStep(item0, after, seps) {
  const item = cs(item0);
  if (after > 0 && seps < 3 && isSepItem(item)) return { f: 0, after, seps: seps + 1 };
  let f = 0;
  if (after > 0) {
    if (item !== null && typeof item === 'object') f = after === 2 ? 2 : (Array.isArray(item) ? 1 : 0);
    else if (after === 2 && (typeof item === 'number' || (typeof item === 'string' && fieldValueOK(core(item)) && labelClass(item) === 0 && !COLUMN_WORDS.has(item.toLowerCase()) && !PLACEHOLDER_VALUE.test(item) && !isPermName(item)))) f = 2;
    else if (after === 1 && typeof item === 'string' && weakSecretish(item)) f = 2;
  }
  return { f, after: typeof item === 'string' ? labelClass(item) : 0, seps: 0 };
}
// A first row [credential name, a word that is not a column name] is a pair ([["token", "t1"], ["password", "x"]] = Object.entries), not a header, unless a cell under
// the credential column looks like a secret.
function firstRowIsHeader(first, cols, rows) {
  const pairLike = first.length === 2 && typeof first[0] === 'string' && typeof first[1] === 'string' && labelClass(first[0]) > 0 && !COLUMN_WORDS.has(cs(first[1]).toLowerCase()) && !(labelClass(first[1]) > 0 && /^[A-Za-z_][\w.-]{0,30}$/.test(first[1]));
  if (!pairLike) return true;
  for (let r = 1; r < rows.length && r < 50; r += 1) {
    let row;
    try { row = rows[r]; } catch { continue; }
    if (!Array.isArray(row)) continue;
    for (const c of cols.keys()) { let cell; try { cell = row[c]; } catch { continue; } if (typeof cell === 'string' && weakSecretish(cell)) return true; }
  }
  return false;
}
// A command line split into an argv array: the words are joined and read as a command; every word that overlaps a finding is masked whole.
function argvHits(items0, o, st) {
  const items = items0.map(cs);
  if (items.length < 2 || items.length > 64) return null;
  const starts = [];
  let joined = '';
  for (const it of items) { starts.push(joined.length); joined += `${it} `; }
  if (joined.length > 4000 || !CLI_HINT.test(joined)) return null;
  const res = analyze(joined, o, st, true);
  if (!res.found || !res.spans) return null;
  const hit = items.map((it, i) => res.spans.some((sp) => sp.s < starts[i] + it.length && sp.e > starts[i]));
  return hit.some(Boolean) ? hit : null;
}
const SECRET_KINDS = /^(?:sealed)?secret$/i;
const SECRET_DATA_KEYS = new Set(['data', 'stringdata', 'encrypteddata']);
const JWK_PRIVATE = new Set(['d', 'p', 'q', 'dp', 'dq', 'qi', 'k', 'oth']);
// Public JWK parameters that are long base64url values (the RSA modulus, the EC coordinates, the certificate chain and thumbprints) are public data and stay; the short ones
// (kid, use, alg, crv, e) are not masked by anything else, and a short or odd value under one of these names is read by the ordinary rules (an object cannot hide a secret by calling itself a key).
const JWK_PUBLIC = new Set(['n', 'x', 'y', 'x5c', 'x5t', 'x5ts256']);
const B64URL_LONG = /^[A-Za-z0-9_-]{22,1400}$/;
const B64_LONG = /^[A-Za-z0-9+/=]{40,12000}$/;
const jwkPublicOK = (nk, val) => (nk === 'x5c' ? Array.isArray(val) && val.length <= 10 && val.every((c) => typeof c === 'string' && B64_LONG.test(c)) : typeof val === 'string' && B64URL_LONG.test(val));
const KEEP = -1; // the member is public data (a JWK public parameter) and stays as it is
const PAIR_EXEMPT = new Set([...NAME_FIELDS, ...META_KEYS, 'id', 'type', 'kind', 'required', 'sensitive', 'secure', 'masked', 'encrypted', 'hidden', 'readonly', 'disabled', 'enabled', 'order', 'index', 'position', 'group',
  'section', 'version', 'updated', 'created', 'modified', 'source', 'scope', 'owner', 'tags', 'help', 'helptext', 'tooltip', 'autocomplete', 'inputmode', 'icon', 'regex', 'regexp', 'validation', 'validator', 'rule', 'rules', 'policy',
  'format', 'mask', 'min', 'max', 'step', 'width', 'height', 'options', 'choices', 'unit', 'units', 'category', 'description', 'title', 'caption']);
const EXTRA_VALUE_FIELDS = new Set(['answer', 'answers', 'payload', 'current', 'body', 'new', 'old', 'typed', 'response', 'reply', 'result', 'output', 'entered', 'entry', 'newvalue', 'oldvalue', 'currentvalue', 'supplied', 'provided', 'given']);
const isValueField = (nk) => VALUE_FIELDS.has(nk) || EXTRA_VALUE_FIELDS.has(nk) || (nk.length > 5 && nk.endsWith('value'));
const isNameField = (nk) => NAME_FIELDS.has(nk) || nk === 'question' || nk === 'prompt' || (nk.length > 3 && (nk.endsWith('key') || nk.endsWith('label')) && !KEY_STRONG.has(nk));

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// Per-masker configuration (createMasker). cfg = { keyNone, tests, pred, rules }: keyNone - keyMode 'none' applies to this node and below; tests - key-name tests of the
// opaque names; pred - the opaque(key, path, value) predicate; rules - the path rules. The default masker has none of these, so its walk is the walk of 1.3.0.
const NO_CFG = Object.freeze({ keyNone: false, tests: null, pred: null, rules: null });
// Enter the child `key` of the current node: the key goes on the path, the path rules that match the child's dotted path change the configuration for it and below,
// and the child is "opaque" when a rule says so or one of the opaque names / the predicate does. leave() undoes it.
function enter(ctx, cfg, key, val) {
  ctx.path.push(key);
  const saved = ctx.cfg;
  let next = cfg;
  let opaque = false;
  try {
    const path = cfg.rules || cfg.pred || cfg.tests ? ctx.path.join('.') : '';
    // the opaque names of the PARENT's scope judge this member; a rule that matches it changes the scope for its members
    if (cfg.tests) opaque = cfg.tests.some((t) => t(key, path, val) === true);
    if (!opaque && cfg.pred) opaque = cfg.pred(key, path, val) === true;
    if (cfg.rules) {
      for (const r of cfg.rules) {
        if (!r.match.test(path)) continue;
        next = { keyNone: r.keyMode === undefined ? next.keyNone : r.keyMode === 'none', tests: r.test ? [...(next.tests || []), r.test] : next.tests, pred: next.pred, rules: next.rules };
        if (r.all) opaque = true;
      }
    }
  } catch {
    opaque = false; // a rule or predicate that throws masks (fail closed)
  }
  ctx.cfg = next;
  return { cfg: next, opaque, saved };
}
function leave(ctx, scope) {
  ctx.path.pop();
  ctx.cfg = scope.saved;
}
// An opaque value is returned as it is (a copy, so the result shares nothing with the input).
function opaqueCopy(val, ctx) {
  ctx.nodes += 1;
  ctx.st.nodes += 1;
  if (val === null || (typeof val !== 'object' && typeof val !== 'function' && typeof val !== 'symbol')) return val;
  if (typeof val !== 'object') return safeMark(ctx.o, 'non-string');
  try { return structuredClone(val); } catch { return safeMark(ctx.o, 'unsupported'); }
}

function walkObject(v, depth, force, ctx) {
  const { o } = ctx;
  const cfg = ctx.cfg || NO_CFG; // the configuration that applies to THIS node (createMasker: keyMode, opaque names, path rules)
  if (v instanceof Date) { let iso; try { iso = v.toISOString(); } catch { iso = 'invalid-date'; } return maskString(iso, o, ctx.st); }
  if (v instanceof String || v instanceof Number || v instanceof Boolean || (typeof BigInt !== 'undefined' && v instanceof BigInt)) {
    let prim;
    try { prim = v.valueOf(); } catch { return safeMark(o, 'unreadable'); }
    return walk(prim, depth, force, ctx);
  }
  if (ArrayBuffer.isView(v) || v instanceof ArrayBuffer || v instanceof Map || v instanceof Set || v instanceof WeakMap || v instanceof WeakSet || v instanceof Promise) return safeMark(o, 'unsupported');
  if (Array.isArray(v)) {
    const out = [];
    let len = 0;
    try { len = v.length; } catch { return safeMark(o, 'unreadable'); }
    let after = 0; // the previous element names a credential (["password", "x"], ["--password", "x"], [["pass", "x"]])
    let seps = 0;
    let head = null; // [["user", "password"], ["bob", "x"]]: the first row names the columns
    let argv = null; // ["mysql", "-u", "root", "-px"]: a command line
    if (!force && !cfg.keyNone && len >= 2) {
      let first;
      let second;
      try { first = v[0]; second = v[1]; } catch { first = null; }
      if (Array.isArray(first) && Array.isArray(second)) { const c = credCols(first); if (c.size && firstRowIsHeader(first, c, v)) head = c; }
      if (len <= 64) {
        const items = [];
        try { for (let i = 0; i < len; i += 1) { const it = v[i]; if (typeof it !== 'string') break; items.push(it); } } catch { items.length = 0; }
        if (items.length === len) argv = argvHits(items, o, ctx.st);
      }
    }
    for (let i = 0; i < len; i += 1) {
      if (ctx.nodes >= o.maxNodes) { out.push(safeMark(o, 'too-large')); break; }
      let item;
      try { item = v[i]; } catch { item = safeMark(o, 'unreadable'); out.push(item); after = 0; continue; }
      const scope = ctx.scoped ? enter(ctx, cfg, String(i), item) : null;
      try {
        if (scope && scope.opaque && !force) { out.push(opaqueCopy(item, ctx)); after = 0; continue; }
        if (argv && argv[i]) { ctx.nodes += 1; ctx.st.nodes += 1; out.push(safeMark(o, 'cli')); continue; }
        if (head && i > 0 && Array.isArray(item)) { out.push(...walkRows([item], head, depth + 1, ctx)); after = 0; continue; }
        let f = force;
        if (!force && !cfg.keyNone) {
          const step = pairStep(item, after, seps);
          f = step.f;
          after = step.after;
          seps = step.seps;
        }
        out.push(walk(item, depth + 1, f, ctx));
      } finally {
        if (scope) leave(ctx, scope);
      }
    }
    return out;
  }
  let keys;
  try { keys = Object.keys(v); } catch { return safeMark(o, 'unreadable'); }
  // name/value siblings: {"name": "DB_PASSWORD", "value": "x"}, {"key": "password", "val": "x"}, {"header": "X-Api-Key", "value": "x"}, {"ParameterKey": "DBPassword", "ParameterValue": "x"}
  let pairCls = 0;
  let headerCols = null; // {"columns": ["user", "password"], "rows": [["bob", "x"]]}
  let secretKind = ctx.secretKind === true; // set while a Secret manifest's "spec" is walked (SealedSecret: spec.encryptedData)
  let jwk = false;
  const limit = Math.min(keys.length, LIMITS.MAX_NODES);
  if (!force && !cfg.keyNone) {
    for (let i = 0; i < limit; i += 1) {
      const k = keys[i];
      const nk = normField(k);
      if (isNameField(nk)) {
        let nv;
        try { nv = v[k]; } catch { continue; }
        const lc = labelClass(nv);
        if (lc > pairCls) pairCls = lc;
      } else if (headerCols === null && HEADER_KEYS.has(nk)) {
        let hv;
        try { hv = v[k]; } catch { continue; }
        const c = credCols(Array.isArray(hv) && Array.isArray(hv[0]) ? hv[0] : hv);
        if (c.size) headerCols = c;
      } else if (nk === 'kind') {
        let kv;
        try { kv = v[k]; } catch { continue; }
        if (typeof kv === 'string' && SECRET_KINDS.test(cs(kv).trim())) secretKind = true; // a Kubernetes Secret manifest: everything under data / stringData is a value
      } else if (nk === 'kty') {
        let kv;
        try { kv = v[k]; } catch { continue; }
        if (typeof kv === 'string' && /^(?:RSA|EC|OKP|oct)$/.test(cs(kv))) jwk = true; // a JSON Web Key: the public parameters are public
      }
    }
  }
  // an object whose keys are "0", "1", ... is read like an array for the pair rule
  let seqForce = null;
  if (!force && !cfg.keyNone && keys.length >= 2 && keys.length <= 64 && keys.every((k) => /^\d{1,3}$/.test(k))) {
    const order = [...keys].sort((x, y) => Number(x) - Number(y));
    seqForce = new Map();
    let after = 0;
    let seps = 0;
    for (const k of order) {
      let item;
      try { item = v[k]; } catch { item = null; }
      const step = pairStep(item, after, seps);
      seqForce.set(k, step.f);
      after = step.after;
      seps = step.seps;
    }
  }
  const out = {};
  const used = new Set();
  const nextSuffix = new Map();
  for (const k of keys) {
    if (ctx.nodes >= o.maxNodes || ctx.chars >= o.maxTotalChars) { Object.defineProperty(out, 'too-large', { value: safeMark(o, 'too-large'), enumerable: true, writable: true, configurable: true }); break; }
    let val;
    try { val = v[k]; } catch { val = safeMark(o, 'unreadable'); }
    ctx.chars += k.length;
    // under a credential key even an object KEY that looks like a secret is one (a map keyed by token or session id)
    let name = force === 2 || force === 3 || force === 4 ? (keyLooksSecret(k) ? safeMark(o, 'assignment') : maskString(k, o, ctx.st)) : maskString(k, o, ctx.st);
    if (used.has(name)) {
      let i = nextSuffix.get(name) || 2;
      while (used.has(`${name}#${i}`)) i += 1;
      nextSuffix.set(name, i + 1);
      name = `${name}#${i}`;
    }
    used.add(name);
    const scope = ctx.scoped ? enter(ctx, cfg, k, val) : null;
    const cc = scope ? scope.cfg : cfg;
    try {
    if (scope && scope.opaque && !force && name === k) {
      Object.defineProperty(out, name, { value: opaqueCopy(val, ctx), enumerable: true, writable: true, configurable: true });
      continue;
    }
    let sub = force;
    if ((force === 2 || force === 4) && name === k && META_KEYS.has(normField(k))) sub = typeof val === 'string' && weakSecretish(val) ? 2 : 0;
    if (!force && typeof val !== 'undefined') {
      const nk = normField(k);
      if (name !== k) sub = typeof val === 'string' ? 2 : 0; // the key text itself held a credential: the string it labels is one too
      else if (cc.keyNone) sub = 0; // keyMode 'none': a prose subtree, only the text of the values is read
      else if (jwk && JWK_PRIVATE.has(nk)) sub = 2;
      else if (jwk && JWK_PUBLIC.has(nk) && jwkPublicOK(nk, val)) sub = KEEP;
      else {
        sub = keyForce(k, val, ctx);
        if (!sub && secretKind && SECRET_DATA_KEYS.has(nk)) sub = 2;
        if (!sub && seqForce) sub = seqForce.get(k) || 0;
        if (!sub && pairCls > 0 && isValueField(nk)) {
          if (val !== null && typeof val === 'object') sub = pairCls === 2 ? 2 : (Array.isArray(val) ? 1 : 0);
          else if (pairCls === 2) sub = typeof val === 'number' || (typeof val === 'string' && fieldValueOK(core(cs(val).trim())) && !PLACEHOLDER_VALUE.test(cs(val))) ? 2 : 0;
          else sub = weakSecretish(val) ? 2 : 0;
        } else if (!sub && pairCls > 0 && !PAIR_EXEMPT.has(nk) && typeof val === 'string' && weakSecretish(val)) sub = 2; // {"name": "password", "whatever": "x1y2z3Q"}
      }
    }
    if (headerCols && !cc.keyNone && Array.isArray(val) && ROWS_KEYS.has(normField(k))) {
      Object.defineProperty(out, name, { value: walkRows(val, headerCols, depth + 1, ctx), enumerable: true, writable: true, configurable: true });
      continue;
    }
    const wasSecret = ctx.secretKind;
    ctx.secretKind = secretKind && normField(k) === 'spec';
    try {
      Object.defineProperty(out, name, { value: walk(val, depth + 1, sub, ctx), enumerable: true, writable: true, configurable: true });
    } finally {
      ctx.secretKind = wasSecret;
    }
    } finally {
      if (scope) leave(ctx, scope);
    }
  }
  return out;
}

// Does the key force the value? 0 no, 2 everything below it, 4 the same but a version range stays, 3 every secret-looking string below it, 1 a secret-looking string (or array of them).
function keyForce(k, val, ctx) {
  let cls = ctx.keyCache.get(k);
  if (cls === undefined) {
    cls = classifyKey(k);
    ctx.keyCache.set(k, cls);
  }
  if (cls === 0) return 0;
  if (cls === 5) {
    if (typeof val === 'boolean' && /^(?:plain|clear)text$/i.test(k)) return 0; // {"plaintext": false} is a flag
    if (typeof val === 'string') {
      const lk = k.toLowerCase();
      if (lk === 'pwd' && isDirLike(val)) return 0;
      if ((lk === 'credentials' || lk === 'credential') && CONFIG_WORDS.has(val.toLowerCase())) return 0; // fetch(url, { credentials: "include" })
    }
    return 2;
  }
  if (cls === 4) return typeof val === 'string' && VERSIONISH.test(val.trim()) ? 0 : 2;
  if (cls === 3) return 3;
  return 1;
}

function walk(v, depth, force, ctx) {
  const { o } = ctx;
  ctx.nodes += 1;
  ctx.st.nodes += 1;
  const t = typeof v;
  if (force === KEEP) return Array.isArray(v) ? v.map((x) => (typeof x === 'string' ? x : walk(x, depth + 1, 0, ctx))) : (v !== null && typeof v === 'object' ? walk(v, depth, 0, ctx) : v);
  if (t === 'string') {
    if (v === '') return v;
    if (ctx.chars >= o.maxTotalChars) return safeMark(o, 'too-large');
    ctx.chars += v.length;
    if (force === 2 || force === 4) {
      if (PLACEHOLDER_VALUE.test(v) || PLACEHOLDER_ENV.test(v)) return maskString(v, o, ctx.st);
      if (ctx.hits) ctx.hits.add(v);
      return safeMark(o, 'assignment');
    }
    if (force === 1 || force === 3) {
      if (weakSecretish(v)) { if (ctx.hits) ctx.hits.add(v); return safeMark(o, 'assignment'); }
      return maskString(v, o, ctx.st);
    }
    const masked = maskString(v, o, ctx.st);
    if (ctx.hits && masked !== v && /^\s*[{[]/.test(v)) ctx.hits.add(v); // a JSON document inside a string: the whole literal goes in the text too
    return masked;
  }
  if (t === 'number' || t === 'boolean' || t === 'bigint') return force === 2 || force === 4 ? safeMark(o, 'assignment') : v;
  if (t === 'undefined') return v;
  if (t === 'symbol' || t === 'function') return safeMark(o, 'non-string');
  if (v === null) return null;
  if (depth >= o.maxDepth) return safeMark(o, 'too-deep');
  if (ctx.seen.has(v)) return safeMark(o, 'cycle');
  ctx.seen.add(v);
  try {
    return walkObject(v, depth, force === 1 && !Array.isArray(v) ? 0 : force, ctx); // a weak key forces a string or the strings of an array, never the members of an object
  } finally {
    ctx.seen.delete(v);
  }
}

// maskDeep(value, opts) -> a NEW value in which every string value AND every object key is masked (key collisions get #2, #3 ...; "__proto__" is plain data;
// depth, node and total-character counts are bounded; cycles and unsupported objects become marks). A value stored under a credential-named key ("password",
// "token_value", ...) is masked whatever it looks like; a name/value pair ({name: "DB_PASSWORD", value: x}) and an array pair (["--password", x]) too. Boxed
// String / Number / Boolean objects are unwrapped. The input is never mutated.
export function maskDeep(value, opts) {
  return deepWith(value, readOpts(opts), NO_CFG);
}
function deepWith(value, o, cfg) {
  const st = o.stats || SCRATCH_STATS();
  try {
    const ctx = { o, st, nodes: 0, chars: 0, seen: new WeakSet(), keyCache: new Map(), cfg, scoped: Boolean(cfg.tests || cfg.pred || cfg.rules), path: [] };
    if (cfg.rules) { // the path rules also apply to the root (path "")
      for (const r of cfg.rules) {
        if (!r.match.test('')) continue;
        ctx.cfg = { keyNone: r.keyMode === undefined ? ctx.cfg.keyNone : r.keyMode === 'none', tests: r.test ? [...(ctx.cfg.tests || []), r.test] : ctx.cfg.tests, pred: ctx.cfg.pred, rules: cfg.rules };
        if (r.all) return opaqueCopy(value, ctx);
      }
    }
    return walk(value, 0, false, ctx);
  } catch {
    st.errors += 1;
    return safeMark(o, 'error');
  }
}

// ---------------------------------------------------------------------------------------------------------------------------------------------------------
// createMasker(options) -> { maskText, maskDeep, looksLikeCredential, isCredentialId }, configured once for one app. Every option is optional and the defaults give the
// behaviour of the module-level functions (maskText, maskDeep ...) exactly. A bad option throws MaskUsageError at creation, never later.
//   opaqueKeys   Set of key names (compared without regard to case) or a RegExp tested on the key name: the VALUE under such a key is left as it is (hash, traceparent ...).
//   opaque       (key, path, value) => boolean: the same, decided per member; path is dotted ("a.b.0.c", array positions are numbers). A predicate that throws masks.
//   keyMode      'strong' (default) the key name classifies its value (token, password, secret ...); 'none' the key name is never read, only secret-looking TEXT inside
//                the values is masked (stories, prose, notes).
//   markStyle    'named' (default) [masked:rule]; 'plain' exactly [masked].
//   tooLongText  the string that replaces a value over maxLength (default: the mark for 'oversize').
//   maxLength    longest text analysed, default LIMITS.MAX_CHARS (same range as opts.maxChars).
//   pathRules    [{ match: RegExp on the dotted path, keyMode?, opaque? }]: for the node whose path matches and everything below it. opaque: true leaves that node as it is;
//                a Set / RegExp / function applies like opaqueKeys / opaque to the members below it.
//   stats, maxDepth, maxNodes, maxTotalChars   as for maskDeep.
// An opaque member is honoured only where no credential-named ancestor forces the subtree (a token below "password" is still masked), and not for a key that is itself a
// credential as text.
const CREATE_KEYS = new Set(['opaqueKeys', 'opaque', 'keyMode', 'markStyle', 'tooLongText', 'maxLength', 'pathRules', 'stats', 'maxDepth', 'maxNodes', 'maxTotalChars']);
const noFlagsRe = (re) => new RegExp(re.source, re.flags.replace(/[gy]/g, ''));
function keyTest(spec, what) {
  if (spec instanceof Set) {
    const names = new Set();
    for (const x of spec) {
      if (typeof x !== 'string') throw new MaskUsageError(`${what} must hold strings`);
      names.add(x.toLowerCase());
    }
    return (k) => names.has(k.toLowerCase());
  }
  if (spec instanceof RegExp) { const re = noFlagsRe(spec); return (k) => re.test(k); }
  throw new MaskUsageError(`${what} must be a Set of names or a RegExp`);
}
export function createMasker(options) {
  if (options === undefined || options === null) options = {};
  if (typeof options !== 'object' || Array.isArray(options)) throw new MaskUsageError('createMasker options must be an object');
  for (const k of Object.keys(options)) if (!CREATE_KEYS.has(k)) throw new MaskUsageError(`unknown createMasker option: ${/^[A-Za-z]{1,24}$/.test(k) ? k : '?'}`);
  const { opaqueKeys, opaque, keyMode, markStyle, tooLongText, maxLength, pathRules } = options;
  if (keyMode !== undefined && keyMode !== 'strong' && keyMode !== 'none') throw new MaskUsageError("keyMode must be 'strong' or 'none'");
  if (markStyle !== undefined && markStyle !== 'named' && markStyle !== 'plain') throw new MaskUsageError("markStyle must be 'named' or 'plain'");
  if (tooLongText !== undefined && typeof tooLongText !== 'string') throw new MaskUsageError('tooLongText must be a string');
  if (opaque !== undefined && typeof opaque !== 'function') throw new MaskUsageError('opaque must be a function (key, path, value) => boolean');
  const base = markStyle === 'plain' ? () => '[masked]' : defaultMark;
  const mark = tooLongText === undefined ? base : (id) => (id === 'oversize' ? tooLongText : base(id));
  const readIn = { mark };
  for (const k of ['stats', 'maxDepth', 'maxNodes', 'maxTotalChars']) if (options[k] !== undefined) readIn[k] = options[k];
  if (maxLength !== undefined) {
    if (!Number.isInteger(maxLength) || maxLength < 1 || maxLength > LIMITS.HARD_MAX_CHARS) throw new MaskUsageError(`maxLength must be an integer from 1 to ${LIMITS.HARD_MAX_CHARS}`);
    readIn.maxChars = maxLength;
  }
  const o = readOpts(readIn);
  const tests = opaqueKeys === undefined ? null : [keyTest(opaqueKeys, 'opaqueKeys')];
  let rules = null;
  if (pathRules !== undefined) {
    if (!Array.isArray(pathRules)) throw new MaskUsageError('pathRules must be an array');
    rules = pathRules.map((r) => {
      if (r === null || typeof r !== 'object' || !(r.match instanceof RegExp)) throw new MaskUsageError('each pathRule needs a match RegExp');
      for (const k of Object.keys(r)) if (k !== 'match' && k !== 'keyMode' && k !== 'opaque') throw new MaskUsageError('unknown pathRule field');
      if (r.keyMode !== undefined && r.keyMode !== 'strong' && r.keyMode !== 'none') throw new MaskUsageError("pathRule keyMode must be 'strong' or 'none'");
      const out = { match: noFlagsRe(r.match), keyMode: r.keyMode, test: null, all: false };
      if (r.opaque === true) out.all = true;
      else if (typeof r.opaque === 'function') out.test = r.opaque;
      else if (r.opaque !== undefined && r.opaque !== false) out.test = keyTest(r.opaque, 'pathRule opaque');
      return out;
    });
  }
  const cfg = tests === null && opaque === undefined && rules === null && keyMode !== 'none' ? NO_CFG
    : Object.freeze({ keyNone: keyMode === 'none', tests, pred: opaque === undefined ? null : opaque, rules });
  return Object.freeze({
    maskText: (str) => maskText(str, readIn),
    maskDeep: (value) => deepWith(value, o, cfg),
    looksLikeCredential: (str) => looksLikeCredential(str, readIn),
    isCredentialId: (id) => isCredentialId(id),
  });
}
