// Builds content-pack.json for the Learning Hub from the story data, so the pack cannot drift from the lab.
//   node scripts/build-content-pack.mjs        (writes content-pack.json)
// The pack uses .invalid placeholders and no documentation URLs.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { DEFAULT_CAST } from '../server/src/cast.js';
import { buildStory } from '../server/src/story.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const { version } = JSON.parse(fs.readFileSync(path.join(ROOT, 'package.json'), 'utf8'));
const UNV = 'Ping release claim, UNVERIFIED on our tenant.';

export function buildPack() {
  const story = buildStory(DEFAULT_CAST, 'finance');
  const sid = (n) => `S${String(n).padStart(2, '0')}`;
  const terms = {
    'own-vault': ['user-vault', 'request-time-injection', 'merge-edit'], 'staged-delete': ['staged-delete', 'lab-clock', 'bounds'], 'no-override': ['self-service', 'user-vault'],
    'injection-shapes': ['request-time-injection', 'credential-shapes'], 'store-lifecycle': ['secret-store-management', 'soft-delete-purge', 'rotation'],
    'governed-read': ['read-write-grants', 'audit-trail', 'no-copy'], 'nightly-resync': ['nightly-resync', 'no-copy', 'lab-clock'],
  };
  const why = (id) => story.talkTrack.find((t) => t.id === id).say;
  return {
    schema: 'demo-content-pack/1',
    id: 'secrets-vault-lab',
    title: 'Secrets Vault LAB',
    version,
    demo: { id: 'secrets-vault-lab', name: 'Secrets Vault LAB', catalog: 'D108', baseUrl: 'http://localhost:7450', doctor: '/api/health', tags: ['user-vault', 'secrets', 'aes-gcm', 'credential-injection', 'secret-stores', 'no-copy', 'simulated'] },
    glossary: [
      { id: 'user-vault', term: 'User Vault', definition: `A private credential store per person, injected into that person's backend calls at request time, so the backend sees who actually acted instead of a shared service account. ${UNV}`, aliases: ['per-user credentials'] },
      { id: 'self-service', term: 'Strictly self-service', definition: `Every operation is forced to the calling user's own vault; there is no administrator override, and no admin, auditor or support role can read another user's credentials through the API. In the lab the caller is the only vault there is: no call takes an owner, another person's entry id is "not found", and naming an owner is refused. ${UNV}`, aliases: ['no administrator override'] },
      { id: 'request-time-injection', term: 'Used at request time', definition: `The MCP and agent-to-agent gateways, when an application is set to per-user credentials, build the credential from the caller's own entry and inject it into the backend call. The agent never holds it; the backend logs who actually acted. The gateway, agent and backend views are lab-invented simulations. ${UNV}`, aliases: ['credential injection', 'backend credential injection'] },
      { id: 'credential-shapes', term: 'Credential shapes', definition: `Bearer tokens, API keys, username and password as HTTP Basic, and custom header pairs (slide 42). The exact wire form, header-name rules and field names are the lab's. ${UNV}`, aliases: ['bearer', 'api key', 'basic', 'header pairs'] },
      { id: 'encrypted-at-rest', term: 'Encrypted at rest', definition: `AES-GCM with a unique nonce per value; the key is resolved at startup from AWS Secrets Manager with KMS envelope decryption or from HashiCorp Vault on premises, with a compiled-in development key only as fallback. The lab seals with real AES-256-GCM and a fresh 12-byte nonce per value, and binds the user id and entry id as additional authenticated data (lab-invented); the three key providers are mocks, and the development key is public on purpose. ${UNV}`, aliases: ['AES-GCM', 'nonce', 'key provider', 'development key'] },
      { id: 'merge-edit', term: 'Safe editing: merge, not replace', definition: `An update merges: omitting the secret keeps the stored value, so metadata can be edited without re-entering credentials. Merging field by field inside a credential is the lab's reading. ${UNV}`, aliases: ['omit the secret'] },
      { id: 'staged-delete', term: 'Staged deletion', definition: `A deletion is staged, then purged after 24 hours. In the lab it can be restored inside the window, is purged exactly at 24 hours (one minute short it is still there), and a staged entry cannot be edited or used. ${UNV}`, aliases: ['purge after 24 hours'] },
      { id: 'bounds', term: 'Bounded vault', definition: `500 entries per user and 64 KB per credential, with entries whose target system is removed cleaned up automatically. The lab counts staged entries until they are purged and counts 64 KB as 65536 bytes over the secret fields; one byte over is refused whole. ${UNV}`, aliases: ['500 entries', '64 KB'] },
      { id: 'secret-store-management', term: 'Secret Store Management', definition: `Discover and control the secrets already in AWS Secrets Manager, GCP Secret Manager, Azure Key Vault, Delinea Secret Server and CyberArk PAM, preserving each store's structure, without becoming another copy of them. The five providers here are in-process mocks. ${UNV}`, aliases: ['five providers', 'secret stores'] },
      { id: 'soft-delete-purge', term: 'Soft-delete and purge', definition: `The deck lists soft-delete and purge for Azure and file fields for Delinea. In the lab only Azure soft-deletes and purges; the other four delete permanently and refuse recover and purge (the lab's reading). ${UNV}`, aliases: ['Azure soft-delete', 'file fields'] },
      { id: 'rotation', term: 'Rotate on demand', definition: `Rotation is triggered from Privilege for every provider. The lab replaces the password-type fields with a new labelled mock value, makes a new version and counts it. ${UNV}`, aliases: ['rotate'] },
      { id: 'read-write-grants', term: 'Read and write as separate grants', definition: `Access runs through the same policy engine as the rest of the platform: read and write are separate grantable actions. The lab's grant shape (principal, "provider:path" scope, actions) is invented; a caller with no grant is told "not found", one holding only the other action is told "denied". ${UNV}`, aliases: ['policy engine', 'default deny'] },
      { id: 'audit-trail', term: 'Audit trail', definition: `Every secret read and mutation is audited, allowed or denied, with actor, role, action, resource and outcome. ${UNV}`, aliases: ['audit'] },
      { id: 'no-copy', term: 'No copy', definition: `Only metadata (name, path, provider, tags and versions) is persisted; the value is excluded and fetched live from the provider at the moment of an authorized read. In the lab the value goes only into a simulated consumer, and a proof panel searches everything Privilege keeps for every value the providers hold (plain, base64, hex), with a planted-copy self-test. The method is lab-invented; provider credentials are sealed at rest. ${UNV}`, aliases: ['metadata only', 'live fetch'] },
      { id: 'nightly-resync', term: 'Nightly re-sync', definition: `Connected stores re-synchronise nightly. The lab runs it when the lab clock crosses 02:00 and reports new, renamed, deleted and changed secrets from metadata only (rename found by the provider's own id); the time and finding kinds are lab-invented. ${UNV}`, aliases: ['re-synchronise'] },
      { id: 'lab-clock', term: 'The lab clock', definition: 'A clock the visitor advances (buttons for 1 minute, 1 hour, 23 hours 59 minutes, 24 hours and 1 day) so the 24-hour purge and the nightly re-sync can be seen. It only moves forward. Lab-invented.', aliases: [] },
    ],
    sources: [
      { id: 'deck-slides', title: 'Ping ID4AI Workforce H2 2026 deck, slides 42, 43 and 36', url: 'https://example.invalid/ping-id4ai-workforce-h2-2026-deck', kind: 'deck', use: 'The User Vault and Secret Store Management release claims, and the backend credential modes they plug into.', status: 'read', checked: '2026-10-31' },
    ],
    cards: [
      ...story.scenarios.map((sc, i) => ({ id: `try-${sc.id}`, label: `Scenario ${i + 1}: ${sc.title}`, description: sc.say, group: 'try-it', action: { type: 'route', href: '/#vault' }, terms: terms[sc.id], story: sid(i + 1) })),
      { id: 'try-isolation', label: 'Try every other role', description: 'Another user, the administrator, the auditor and support each ask for your entry: each is forced into their own empty vault.', group: 'try-it', action: { type: 'route', href: '/#vault' }, terms: ['self-service'] },
      { id: 'try-injection', label: 'Call a backend with and without a shared account', description: 'The gateway injects your credential; the agent sees nothing; the backend logs you. The shared account logs the same identity for everyone.', group: 'try-it', action: { type: 'route', href: '/#injection' }, terms: ['request-time-injection', 'credential-shapes'] },
      { id: 'try-proof', label: 'Run the no-copy proof', description: 'Search everything Privilege keeps for every value the providers hold; a planted copy proves the search works.', group: 'try-it', action: { type: 'route', href: '/#governance' }, terms: ['no-copy'] },
      { id: 'concept-why-user-vault', label: 'Why it matters: User Vault (slide 42)', description: why('why-user-vault'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['user-vault', 'self-service', 'request-time-injection'] },
      { id: 'concept-why-secret-store', label: 'Why it matters: Secret Store Management (slide 43)', description: why('why-secret-store'), group: 'concept', action: { type: 'route', href: '/#talk' }, terms: ['secret-store-management', 'no-copy', 'read-write-grants'] },
      { id: 'concept-diagram', label: 'Diagrams', description: 'Two diagrams: the credential injected at request time; and a governed read with no copy.', group: 'concept', action: { type: 'route', href: '/#diagram' }, terms: ['request-time-injection', 'no-copy'] },
      { id: 'ref-doctor', label: 'Doctor and health', description: 'Preflight checks and the demo-health/1 endpoint.', group: 'setup', action: { type: 'route', href: '/api/health' } },
    ],
    stories: story.scenarios.map((sc, i) => ({ id: sid(i + 1), title: sc.title, say: sc.say })),
  };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  fs.writeFileSync(path.join(ROOT, 'content-pack.json'), `${JSON.stringify(buildPack(), null, 2)}\n`);
  console.log('wrote content-pack.json');
}
