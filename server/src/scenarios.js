// Scripted scenarios: data (with names from the cast) run through the real engine with a deterministic random source, so the Mock tables are
// generated from the engine and regenerate identically (`npm run mock-table`; a doctor check and a test fail on drift).
import { createHash } from 'node:crypto';
import { Engine } from './engine.js';
import { VERTICALS } from './cast.js';
import { perform } from './actions.js';

// A deterministic stand-in for crypto.randomBytes, used ONLY to build the tables. Live always uses the real one.
export function detRand() {
  let i = 0;
  return (n) => { const out = Buffer.alloc(n); let at = 0; while (at < n) { const d = createHash('sha256').update(`svl-table-${i++}`).digest(); d.copy(out, at, 0, Math.min(32, n - at)); at += 32; } return out; };
}

export function scenarioList(c) {
  const S = (actor, say, op, params) => ({ actor, say, op, params });
  const entry = (o) => ({ entry: { generate: true, ...o } });
  const call = (o) => ({ call: { operation: 'read_summary', ...o } });
  return [
    {
      id: 'own-vault', title: 'Store a credential, edit it, use it', actor: c.castUser,
      say: 'A person stores a credential in their own vault, edits its notes without re-entering the secret, and the gateway uses it at request time. The backend logs who actually acted; with a shared service account it logs the same identity for everyone.',
      steps: [
        S(c.castUser, `${c.castUser} stores a bearer token for ${c.castT1} (a mock credential the lab generates).`, 'vaultCreate', entry({ name: 'Ledger bearer', targetId: c.castT1, shape: 'bearer', notes: 'first version' })),
        S(c.castUser, 'The notes are edited. The secret field is left out, so the stored value is kept untouched.', 'vaultUpdate', { id: 'vcr-0001', entry: { notes: 'rotated quarterly' } }),
        S(c.castUser, `The agent asks ${c.castT1} for a summary. The gateway injects ${c.castUser}'s own credential; the agent never sees it.`, 'gatewayCall', call({ targetId: c.castT1, as: 'per-user' })),
        S(c.castUser, 'The same call through a shared service account, for contrast.', 'gatewayCall', call({ targetId: c.castT1, as: 'shared' })),
        S(c.castUser2, `${c.castUser2} makes the same shared-account call: the backend logs the same identity.`, 'gatewayCall', call({ targetId: c.castT1, as: 'shared' })),
      ],
    },
    {
      id: 'staged-delete', title: 'Delete, restore, then purge after 24 hours', actor: c.castUser,
      say: 'A deletion is staged, not immediate. It can be restored inside the window, and it is purged at exactly 24 hours: one minute short and it is still there.',
      steps: [
        S(c.castUser, `${c.castUser} stores a credential for ${c.castT1}.`, 'vaultCreate', entry({ name: 'Ledger bearer', targetId: c.castT1, shape: 'bearer' })),
        S(c.castUser, 'The entry is deleted: staged, with a purge time 24 hours away.', 'vaultDelete', { id: 'vcr-0001' }),
        S(c.castUser, 'Changed their mind: restored, nothing lost.', 'vaultRestore', { id: 'vcr-0001' }),
        S(c.castUser, 'Deleted again.', 'vaultDelete', { id: 'vcr-0001' }),
        S(c.castUser, 'The lab clock moves 23 hours 59 minutes. The entry is still staged.', 'advance', { clock: { minutes: 1439 } }),
        S(c.castUser, 'A staged entry cannot be used.', 'gatewayCall', call({ targetId: c.castT1, as: 'per-user', entryId: 'vcr-0001' })),
        S(c.castUser, 'One more minute: exactly 24 hours. The entry is purged.', 'advance', { clock: { minutes: 1 } }),
        S(c.castUser, 'Restoring is now impossible: it is gone.', 'vaultRestore', { id: 'vcr-0001' }),
      ],
    },
    {
      id: 'no-override', title: 'Nobody else can read it, not even an administrator', actor: c.castAdmin,
      say: `${c.castUser} has an entry. Another user, the administrator, the auditor and support each try to act on it, and each is forced into their own, empty, vault: not found. Naming an owner is refused.`,
      steps: [
        S(c.castUser, `${c.castUser} stores a credential for ${c.castT1}.`, 'vaultCreate', entry({ name: 'Ledger bearer', targetId: c.castT1, shape: 'bearer' })),
        S(c.castUser2, `${c.castUser2} tries to delete ${c.castUser}'s entry by its id.`, 'vaultDelete', { id: 'vcr-0001' }),
        S(c.castAdmin, `${c.castAdmin}, an administrator, tries to edit it.`, 'vaultUpdate', { id: 'vcr-0001', entry: { notes: 'admin was here' } }),
        S(c.castAuditor, `${c.castAuditor}, the auditor, tries to restore it.`, 'vaultRestore', { id: 'vcr-0001' }),
        S(c.castSupport, `${c.castSupport}, support, tries to use it through the gateway.`, 'gatewayCall', call({ targetId: c.castT1, as: 'per-user', entryId: 'vcr-0001' })),
        S(c.castAdmin, 'The administrator names the owner in the call. There is no such parameter: the call is refused.', 'gatewayCall', { call: { targetId: c.castT1, as: 'per-user', entryId: 'vcr-0001', operation: 'read_summary', owner: c.castUser } }),
      ],
    },
    {
      id: 'injection-shapes', title: 'Four credential shapes, injected at request time', actor: c.castUser,
      say: 'Bearer token, API key, HTTP Basic and a custom header pair: the gateway builds each from the caller\'s own entry, the agent sees none of it, and the backend identifies the caller from the credential. With no entry the call is refused: it does not fall back to a shared account.',
      steps: [
        S(c.castUser, 'A bearer token for the ledger.', 'vaultCreate', entry({ name: 'Ledger bearer', targetId: c.castT1, shape: 'bearer' })),
        S(c.castUser, 'An API key for the cards system.', 'vaultCreate', entry({ name: 'Cards key', targetId: c.castT2, shape: 'api-key' })),
        S(c.castUser, 'A user name and password for reports, sent as HTTP Basic.', 'vaultCreate', entry({ name: 'Reports login', targetId: c.castT3, shape: 'basic' })),
        S(c.castUser, 'A pair of custom headers for the partner gateway.', 'vaultCreate', entry({ name: 'Partner pair', targetId: c.castT4, shape: 'headers' })),
        S(c.castUser, 'Call 1: bearer.', 'gatewayCall', call({ targetId: c.castT1, as: 'per-user' })),
        S(c.castUser, 'Call 2: API key.', 'gatewayCall', call({ targetId: c.castT2, as: 'per-user' })),
        S(c.castUser, 'Call 3: Basic.', 'gatewayCall', call({ targetId: c.castT3, as: 'per-user' })),
        S(c.castUser, 'Call 4: custom headers.', 'gatewayCall', call({ targetId: c.castT4, as: 'per-user' })),
        S(c.castUser2, `${c.castUser2} has no entry for ${c.castT1}: the call is refused, with no fallback to the shared account.`, 'gatewayCall', call({ targetId: c.castT1, as: 'per-user' })),
      ],
    },
    {
      id: 'store-lifecycle', title: 'Create, rotate, soft-delete and purge in a secret store', actor: c.castUser,
      say: 'In Azure Key Vault a secret gets created, rotated, soft-deleted, recovered, soft-deleted again and purged. Soft-delete and purge exist only where the deck lists them (Azure): AWS refuses. A Delinea secret with a file field is created too.',
      steps: [
        S(c.castUser, `${c.castUser} creates a secret in ${c.castKv} (the lab generates a mock value).`, 'storeCreate', { secret: { provider: 'azure', path: `${c.castKv}/new-token`, tags: ['prod'] } }),
        S(c.castUser, 'Rotate it on demand: a new version, a rotation counter.', 'storeRotate', { ref: `azure:${c.castKv}/new-token` }),
        S(c.castUser, 'Delete: Azure soft-deletes, so it is recoverable.', 'storeDelete', { ref: `azure:${c.castKv}/new-token` }),
        S(c.castUser, 'Recover it.', 'storeRecover', { ref: `azure:${c.castKv}/new-token` }),
        S(c.castUser, 'Delete again.', 'storeDelete', { ref: `azure:${c.castKv}/new-token` }),
        S(c.castUser, 'Purge: gone for good.', 'storePurge', { ref: `azure:${c.castKv}/new-token` }),
        S(c.castUser, 'On AWS the same user only holds read, so a delete is refused.', 'storeDelete', { ref: `aws:${c.castAwsPrefix}/db-admin` }),
        S(c.castAdmin, 'The administrator holds write on AWS, but AWS has no soft-delete here: refused.', 'storeRecover', { ref: `aws:${c.castAwsPrefix}/db-admin` }),
        S(c.castAdmin, 'A Delinea secret from the Secure-File template, with a file field.', 'storeCreate', { secret: { provider: 'delinea', path: `${c.castDelFolder}/Ops/vpn-config`, template: 'Secure-File', tags: ['ops'] } }),
      ],
    },
    {
      id: 'governed-read', title: 'Read and write are separate grants', actor: c.castAdmin,
      say: 'The user can read an AWS secret but not rotate it; the administrator can rotate it but not read it. A value is delivered only to a simulated consumer, never into an API response. Everything is audited, allowed or denied.',
      steps: [
        S(c.castUser, `${c.castUser} reads the AWS database secret, and the value goes to the simulated gateway, masked here.`, 'storeRead', { read: { ref: `aws:${c.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } }),
        S(c.castUser, `${c.castUser} tries to rotate it: read is granted, write is not.`, 'storeRotate', { ref: `aws:${c.castAwsPrefix}/db-admin` }),
        S(c.castAdmin, `${c.castAdmin} tries to read it: write is granted, read is not.`, 'storeRead', { read: { ref: `aws:${c.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } }),
        S(c.castAdmin, 'The administrator rotates it: allowed.', 'storeRotate', { ref: `aws:${c.castAwsPrefix}/db-admin` }),
        S(c.castSupport, `${c.castSupport} has no grant at all, so the secret does not exist for them.`, 'storeRead', { read: { ref: `aws:${c.castAwsPrefix}/db-admin`, consumer: 'simulated-gateway' } }),
        S(c.castAdmin, `The administrator grants ${c.castSupport} read on the AWS payments secrets.`, 'grant', { grant: { principal: c.castSupport, scope: `aws:${c.castAwsPrefix}/**`, actions: ['read'] } }),
        S(c.castSupport, 'Now the read is allowed, and delivered to the consumer.', 'storeRead', { read: { ref: `aws:${c.castAwsPrefix}/db-admin`, consumer: 'simulated-agent-tool' } }),
      ],
    },
    {
      id: 'nightly-resync', title: 'The nightly re-sync notices what changed at the provider', actor: c.castAdmin,
      say: 'Someone renames one secret, deletes another and adds a third directly at the providers. Privilege is not told. When the lab clock crosses 02:00 the connected stores re-synchronise: metadata only, no value is ever requested.',
      steps: [
        S(c.castAdmin, 'One secret gets renamed in the AWS console.', 'providerChange', { change: { provider: 'aws', op: 'rename', ref: `aws:${c.castAwsPrefix}/db-admin`, newPath: `${c.castAwsPrefix}/db-admin-v2` } }),
        S(c.castAdmin, 'Another is deleted at AWS.', 'providerChange', { change: { provider: 'aws', op: 'delete', ref: `aws:${c.castAwsPrefix}/signing-key` } }),
        S(c.castAdmin, 'A new secret appears in a GCP project.', 'providerChange', { change: { provider: 'gcp', op: 'create', path: `${c.castOrg}/${c.castFolder}/${c.castProject}/new-key` } }),
        S(c.castAdmin, 'The clock moves to 01:59: the nightly re-sync has not run.', 'advance', { clock: { minutes: 1019 } }),
        S(c.castAdmin, 'One more minute: 02:00. The nightly re-sync runs.', 'advance', { clock: { minutes: 1 } }),
      ],
    },
  ];
}

// Expected result of every step (a fixed contract, so a change in the engine is noticed). 'ok' or the refusal code.
export const EXPECTED = {
  'own-vault': ['ok', 'ok', 'ok', 'ok', 'ok'],
  'staged-delete': ['ok', 'ok', 'ok', 'ok', 'ok', 'entry_staged_for_delete', 'ok', 'not_found'],
  'no-override': ['ok', 'not_found', 'not_found', 'not_found', 'not_found', 'unknown_field'],
  'injection-shapes': ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'no_credential_for_target'],
  'store-lifecycle': ['ok', 'ok', 'ok', 'ok', 'ok', 'ok', 'access_denied', 'unsupported_operation', 'ok'],
  'governed-read': ['ok', 'access_denied', 'access_denied', 'ok', 'not_found', 'ok', 'ok'],
  'nightly-resync': ['ok', 'ok', 'ok', 'ok', 'ok'],
};

export function runScenario(cast, sc, rand = detRand()) {
  const e = new Engine(cast, { rand });
  const steps = sc.steps.map((st) => {
    const actor = e.roster.get(st.actor);
    const r = perform(e, st.op, actor, st.params);
    return { say: st.say, actor: st.actor, op: st.op, result: r.ok ? { ok: true } : { ok: false, code: r.code, status: r.status } };
  });
  return { engine: e, steps, state: e.snapshot(e.roster.get(sc.actor)) };
}

export function buildMockTable() {
  const verticals = {};
  for (const [v, cast] of Object.entries(VERTICALS)) {
    verticals[v] = { scenarios: scenarioList(cast).map((sc) => { const run = runScenario(cast, sc); return { id: sc.id, title: sc.title, say: sc.say, actor: sc.actor, steps: run.steps, state: run.state }; }) };
  }
  return { schema: 'svl-mock-table/1', generatedFrom: 'the engine, through scripted scenarios', verticals };
}
