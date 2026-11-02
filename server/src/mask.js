// The app's masker: ONE shared-masker instance (server/src/shared/mask.js, copied from shared-masker 9bc664a, v1.4.0), configured here and nowhere else.
// credentials.js (text) and the response mask (maskDeep below) are thin adapters over it. Masking is a HEURISTIC: it finds the common shapes and plain-language
// secrets listed in the README, not every secret, and it errs towards masking (a few ordinary words that look like a secret are masked too; README, "Masking").
import { createMasker } from './shared/mask.js';

// Opaque fields: values THIS APP writes itself that look like secrets and are not. Each is written by the lab, never typed by a visitor:
//   hash         the sealed-record / audit hash chain (a hex digest the lab computes)
//   traceparent  the W3C trace header the lab mints for each hop (00-<32 hex>-<16 hex>-01)
//   traceId      the 32-hex trace id of one action
//   templates    the Delinea secret-template NAMES (a constant list of the lab's, engine.js providers view): ["Password", "Secure-File", ...]
// Nothing a visitor can type freely (a name, a note, a value) is listed here.
const OPAQUE_KEYS = new Set(['hash', 'traceparent', 'traceId', 'templates']);

// Longest text analysed. The JSON body limit is 200 kb, so no honest string is longer; a longer one is masked WHOLE (never cut) as [masked:oversize].
export const MAX_ANALYSED = 250_000;

// Two more things the lab writes itself and a visitor cannot make secret:
//   * the write-only marker the hop panes show for a secret field: "(write-only)" or "(write-only, N bytes)" (service.js scrub). It sits under a key named
//     "secret"/"fields"/"value", which the masker would otherwise blank as a secret.
//   * "secrets": a COUNT of inventory secrets under a provider path (a number the engine computes), shown in the stores table.
//   * "holdsCredential": the gateway call view's boolean "the agent holds a credential" (always false, set by the engine).
const WRITE_ONLY = /^\(write-only(?:, \d{1,9} bytes)?\)$/;
const lab = (key, _path, value) => (key === 'secrets' && typeof value === 'number') || (key === 'holdsCredential' && typeof value === 'boolean') || (typeof value === 'string' && WRITE_ONLY.test(value));

// Prose: subtrees the lab itself writes as sentences (the story, the Mock scenario texts, the limits, the shape and provider descriptions). They say "password",
// "token" and "secret" as ordinary words, so the key names are not read as credential names there (keyMode 'none'); credential-shaped TEXT in them is still masked.
// The hop panes (hops[]) are the raw request and response panes the lab itself composes: their KEY names are the lab's ("secret", "credential", "principal", "result"
// ...), and the first hop is the visitor's request already scrubbed (service.js scrub: unknown key names replaced, secret fields replaced by a write-only marker, strings
// masked). Credential-shaped TEXT in a hop is still masked; only the key names are not read as credential names.
const PROSE = /^(?:hops|title|intro|banner|claimLabel|claims|why|notDemonstrated|fieldSources|limitsText|shapes|providers|scenarios|scenario|talkTrack)(?:\.|$)/;

// The entry view's own metadata about a sealed value: { present, bytes, version, lastChanged, masked: "••••••••", nonce: first 8 hex of the public GCM nonce }, built by the
// engine (engine.js entryView), never from visitor input. It sits under a key named "secret", so it is kept by PATH (only at the places the engine puts it).
const SEALED_VIEW = /^(?:state\.vault\.entries\.\d+|result\.entry|entry|entries\.\d+)\.secret$/;

export const masker = createMasker({
  opaqueKeys: OPAQUE_KEYS, opaque: lab, maxLength: MAX_ANALYSED,
  pathRules: [{ match: PROSE, keyMode: 'none' }, { match: SEALED_VIEW, opaque: true }],
});
export const { maskText, maskDeep, looksLikeCredential, isCredentialId } = masker;
