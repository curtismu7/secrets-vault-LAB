import test from 'node:test';
import assert from 'node:assert/strict';
import { scopeMatches, scopeProblem, allowed } from '../src/policy.js';
import { C, U1, U2, ADMIN, AUD, SUP, code, newEngine, run } from './helpers.js';

const AWSP = C.castAwsPrefix; const AWS = `aws:${AWSP}/db-admin`;
const read = (e, who, ref = AWS) => run(e, 'storeRead', who, { read: { ref, consumer: 'simulated-gateway' } });
const snap = (e, who) => e.snapshot(e.roster.get(who));
const grant = (e, principal, scope, actions) => run(e, 'grant', ADMIN, { grant: { principal, scope, actions } });

test('read and write are SEPARATE grants: read-only cannot rotate, update or delete; write-only cannot read; neither is implied by the other', () => {
  const e = newEngine();
  assert.equal(code(read(e, U1)), 'ok');
  for (const op of ['storeRotate', 'storeDelete', 'storeRecover', 'storePurge']) assert.equal(code(run(e, op, U1, { ref: AWS })), 'access_denied', op);
  assert.equal(code(run(e, 'storeUpdate', U1, { update: { ref: AWS, tags: ['x'] } })), 'access_denied');
  assert.equal(code(read(e, ADMIN)), 'access_denied', 'the administrator can write AWS but not read it');
  assert.equal(code(run(e, 'storeRotate', ADMIN, { ref: AWS })), 'ok');
  assert.equal(code(run(e, 'storeCreate', U1, { secret: { provider: 'aws', path: `${AWSP}/mine` } })), 'access_denied');
});

test('default deny: a caller with no grant at all is told the secret does not exist; one with the other action is told denied; every case is audited', () => {
  const e = newEngine();
  assert.equal(code(read(e, SUP)), 'not_found'); assert.equal(code(read(e, AUD)), 'not_found'); assert.equal(code(read(e, U2)), 'not_found');
  assert.equal(code(read(e, ADMIN)), 'access_denied');
  const denied = e.s.audit.filter((a) => a.action === 'store.read' && a.outcome === 'denied');
  assert.deepEqual(denied.map((a) => [a.actor, a.code]), [[SUP, 'no_grant'], [AUD, 'no_grant'], [U2, 'no_grant'], [ADMIN, 'read_not_granted']]);
  assert.deepEqual(snap(e, SUP).stores.items, [], 'metadata is hidden too'); assert.equal(snap(e, SUP).stores.providers[0].nodes.every((n) => n.secrets === 0), true);
});

test('metadata is shown for a path the caller holds any grant on, with what they can do; the inventory never reveals the rest', () => {
  const e = newEngine();
  const items = snap(e, U1).stores.items;
  assert.ok(items.every((i) => /^(aws|azure|gcp):/.test(i.ref)), items.map((i) => i.ref).join());
  assert.ok(items.every((i) => i.can.read || i.can.write));
  assert.deepEqual(items.find((i) => i.ref === AWS).can, { read: true, write: false });
  assert.deepEqual(snap(e, ADMIN).stores.items.find((i) => i.ref === AWS).can, { read: false, write: true });
});

test('every secret read and mutation is audited with actor, role, action, resource and outcome, in lab-clock order', () => {
  const e = newEngine();
  read(e, U1); run(e, 'storeRotate', ADMIN, { ref: AWS }); run(e, 'storeCreate', U1, { secret: { provider: 'azure', path: `${C.castKv}/aud` } });
  run(e, 'storeUpdate', U1, { update: { ref: `azure:${C.castKv}/aud`, tags: ['t'] } }); run(e, 'storeDelete', U1, { ref: `azure:${C.castKv}/aud` });
  run(e, 'storeRecover', U1, { ref: `azure:${C.castKv}/aud` }); run(e, 'storeDelete', U1, { ref: `azure:${C.castKv}/aud` }); run(e, 'storePurge', U1, { ref: `azure:${C.castKv}/aud` });
  const acts = e.s.audit.filter((a) => a.domain === 'store').map((a) => a.action);
  assert.deepEqual(acts, ['store.read', 'store.rotate', 'store.create', 'store.update', 'store.delete', 'store.recover', 'store.delete', 'store.purge']);
  const first = e.s.audit[0]; assert.deepEqual(Object.keys(first).sort(), ['action', 'actor', 'at', 'domain', 'id', 'outcome', 'resource', 'role'].concat(first.code ? ['code'] : []).sort());
  assert.equal(first.role, 'user'); assert.equal(first.resource, AWS); assert.equal(first.outcome, 'allowed');
  const ids = e.s.audit.map((a) => a.id); assert.deepEqual(ids, [...ids].sort());
  run(e, 'advance', U1, { clock: { minutes: 5 } });
  assert.notEqual(e.s.audit.at(-1).at, e.s.audit[0].at);
});

test('the audit is scoped: a person sees their own events; the administrator and the auditor see all (metadata only); support sees only their own', () => {
  const e = newEngine(); read(e, U1); read(e, SUP);
  const actors = (who) => new Set(snap(e, who).governance.audit.map((a) => a.actor));
  assert.deepEqual([...actors(U1)], [U1]); assert.deepEqual([...actors(SUP)], [SUP]); assert.deepEqual([...actors(U2)], []);
  assert.ok(actors(AUD).has(U1) && actors(AUD).has(SUP)); assert.ok(actors(ADMIN).has(U1));
  assert.equal(snap(e, AUD).governance.canSeeAllAudit, true); assert.equal(snap(e, SUP).governance.canSeeAllAudit, false);
});

test('only an administrator edits grants; a grant takes effect at once and a revoke removes it; every editable grant field is honoured (principal, scope, actions)', () => {
  const e = newEngine();
  assert.equal(code(run(e, 'grant', U1, { grant: { principal: SUP, scope: `aws:${AWSP}/**`, actions: ['read'] } })), 'forbidden_role');
  assert.equal(code(read(e, SUP)), 'not_found');
  const g = grant(e, SUP, `aws:${AWSP}/**`, ['read']); assert.equal(g.ok, true);
  assert.equal(code(read(e, SUP)), 'ok');
  assert.equal(code(read(e, SUP, `aws:${C.castAwsPrefix2}/scoring-token`)), 'not_found', 'the scope is honoured: another prefix is not covered');
  assert.equal(code(read(e, U2)), 'not_found', 'the principal is honoured: someone else does not gain it');
  assert.equal(code(run(e, 'storeRotate', SUP, { ref: AWS })), 'access_denied', 'the actions are honoured: read does not give write');
  assert.equal(code(run(e, 'revoke', U1, { id: g.result.grantId })), 'forbidden_role');
  assert.equal(code(run(e, 'revoke', ADMIN, { id: g.result.grantId })), 'ok'); assert.equal(code(read(e, SUP)), 'not_found');
  assert.equal(code(run(e, 'revoke', ADMIN, { id: g.result.grantId })), 'not_found');
  assert.equal(grant(e, SUP, `aws:${AWSP}/**`, ['read', 'write']).ok, true); assert.equal(code(run(e, 'storeRotate', SUP, { ref: AWS })), 'ok');
  assert.ok(e.s.audit.some((a) => a.action === 'policy.grant') && e.s.audit.some((a) => a.action === 'policy.revoke'));
});

test('grant validation: roster principal, scope syntax, one or two distinct valid actions, 100 grants at most', () => {
  const e = newEngine();
  for (const [p, s, a] of [['ghost', `aws:x`, ['read']], [SUP, 'aws', ['read']], [SUP, 'nope:x', ['read']], [SUP, 'aws:a/**/b', ['read']], [SUP, 'aws:a b', ['read']], [SUP, 'aws:x', []], [SUP, 'aws:x', ['admin']], [SUP, 'aws:x', ['read', 'read']], [SUP, 'aws:x', 'read'], [{}, 'aws:x', ['read']], [SUP, 'x'.repeat(200), ['read']]]) {
    assert.equal(run(e, 'grant', ADMIN, { grant: { principal: p, scope: s, actions: a } }).ok, false, JSON.stringify([p, s, a]).slice(0, 60));
  }
  while (e.s.policies.length < 100) assert.equal(grant(e, SUP, `aws:p${e.s.policies.length}/**`, ['read']).ok, true);
  assert.equal(code(grant(e, SUP, 'aws:full/**', ['read'])), 'policies_full');
});

test('the scope matcher: exact, *, **, provider *, and longer or shorter paths; no regular expression is built from input', () => {
  assert.equal(scopeMatches('aws:a/b', 'aws', 'a/b'), true); assert.equal(scopeMatches('aws:a/b', 'aws', 'a/b/c'), false); assert.equal(scopeMatches('aws:a/b/c', 'aws', 'a/b'), false);
  assert.equal(scopeMatches('aws:a/*', 'aws', 'a/x'), true); assert.equal(scopeMatches('aws:a/*', 'aws', 'a/x/y'), false); assert.equal(scopeMatches('aws:a/**', 'aws', 'a/x/y'), true);
  assert.equal(scopeMatches('aws:a/**', 'aws', 'a'), true); assert.equal(scopeMatches('aws:a/**', 'gcp', 'a/x'), false); assert.equal(scopeMatches('*:**', 'gcp', 'any/thing'), true);
  assert.equal(scopeMatches('aws:a.b/c', 'aws', 'aXb/c'), false, 'a dot is a dot, not a wildcard');
  assert.equal(scopeProblem('aws:' + 'a/'.repeat(30)), 'bad_scope'); assert.equal(scopeProblem('aws:(a+)+$'), 'bad_scope');
  assert.equal(allowed([{ principal: 'p', scope: 'aws:**', actions: ['read'] }], 'p', 'write', 'aws', 'x'), false);
});

test('nightly re-sync: the clock crossing 02:00 detects a rename, a deletion and a new secret from metadata only; at 01:59 nothing has run', () => {
  const e = newEngine(); const ref2 = `aws:${AWSP}/signing-key`;
  run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'rename', ref: AWS, newPath: `${AWSP}/db-admin-v2` } });
  run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'delete', ref: ref2 } });
  run(e, 'providerChange', ADMIN, { change: { provider: 'gcp', op: 'create', path: `${C.castOrg}/${C.castFolder}/${C.castProject}/new-key` } });
  assert.ok(e.s.inventory.some((r) => r.ref === AWS) && e.s.inventory.some((r) => r.ref === ref2), 'Privilege has not been told');
  assert.equal(run(e, 'advance', ADMIN, { clock: { minutes: 1019 } }).result.nightlyRuns, 0);
  assert.equal(e.s.reports.length, 0); assert.ok(e.s.inventory.some((r) => r.ref === AWS));
  assert.equal(run(e, 'advance', ADMIN, { clock: { minutes: 1 } }).result.nightlyRuns, 1);
  const rep = e.s.reports.at(-1); assert.equal(rep.kind, 'nightly'); assert.match(rep.at, /T02:00:00/);
  assert.deepEqual(rep.items.map((i) => i.change).sort(), ['deleted', 'new', 'renamed']);
  const ren = rep.items.find((i) => i.change === 'renamed');
  assert.equal(ren.from, AWS); assert.equal(ren.ref, `aws:${AWSP}/db-admin-v2`);
  assert.ok(ren.grantsLost >= 0 && 'grantsGained' in ren);
  assert.ok(e.s.inventory.some((r) => r.ref === `aws:${AWSP}/db-admin-v2`) && !e.s.inventory.some((r) => r.ref === AWS || r.ref === ref2));
  assert.ok(e.s.inventory.some((r) => r.ref === `gcp:${C.castOrg}/${C.castFolder}/${C.castProject}/new-key`));
  assert.equal(rep.valuesFoundInInventoryAfter, 0);
  assert.equal(code(read(e, U1, `aws:${AWSP}/db-admin-v2`)), 'ok', 'the renamed secret is still the same one at the provider');
  assert.equal(run(e, 'advance', ADMIN, { clock: { minutes: 60 } }).result.nightlyRuns, 0, 'no second run on the same night');
  assert.ok(e.s.audit.some((a) => a.actor === 'provider-console' && a.action === 'provider.rename'));
});

test('a move across several nights runs one re-sync per night; a manual re-sync reports changes and detects a rotation or soft-delete made by hand', () => {
  const e = newEngine();
  assert.equal(run(e, 'advance', U1, { clock: { minutes: 10080 } }).result.nightlyRuns, 7);
  const e2 = newEngine();
  run(e2, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'rotate', ref: AWS } });
  run(e2, 'providerChange', ADMIN, { change: { provider: 'azure', op: 'delete', ref: `azure:${C.castKv}/storage-key` } });
  const r = run(e2, 'resync', U2, {}).result;
  assert.equal(r.changes, 2);
  const rep = e2.s.reports.at(-1); assert.equal(rep.kind, 'manual');
  assert.deepEqual(rep.items.map((i) => [i.change, i.what.join()]).sort(), [['changed', 'state'], ['changed', 'version']]);
  assert.equal(e2.s.inventory.find((r2) => r2.ref === `azure:${C.castKv}/storage-key`).state, 'soft-deleted');
  assert.equal(run(e2, 'resync', U2, {}).result.changes, 0);
});

test('a re-sync into a full inventory reports what it could not add instead of dropping it silently', () => {
  const e = newEngine();
  while (e.s.inventory.length < 399) e.s.inventory.push({ ...e.s.inventory[0], ref: `x:${e.s.inventory.length}`, pid: `none-${e.s.inventory.length}`, provider: 'none' });
  run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'create', path: 'prod/a/one' } });
  run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'create', path: 'prod/a/two' } });
  e.resync('manual'); // the unknown-provider rows are not touched by a re-sync (it only walks the five providers)
  assert.equal(e.s.reports.at(-1).skippedFull, 1);
});

test('the no-copy proof is computed: every value the providers hold, in plain, base64 and hex, is searched for in everything Privilege keeps, and none is found', () => {
  const e = newEngine();
  read(e, U1); run(e, 'storeRotate', ADMIN, { ref: AWS });
  run(e, 'storeCreate', ADMIN, { secret: { provider: 'cyberark', path: `${C.castSafe}/typed`, fields: { secret: 'a-value-the-visitor-typed-0001', userName: 'svc-typed-account' } } });
  const p = snap(e, ADMIN).proof;
  assert.ok(p.valuesChecked >= 20, String(p.valuesChecked)); assert.equal(p.valuesFound, 0); assert.deepEqual(p.encodings, ['plain', 'base64', 'hex']);
  assert.ok(p.areas.length >= 14 && p.areas.every((a) => a.bytes > 2)); assert.equal(p.bytesScanned, p.areas.reduce((n, a) => n + a.bytes, 0));
  assert.equal(p.selfTest.detected, true);
  const all = e.dump() + JSON.stringify(e.roster.size ? [...e.roster.keys()].map((id) => snap(e, id)) : '') + JSON.stringify(e.s.audit);
  for (const v of e.providerValues()) { if (v.length >= 12) assert.ok(!all.includes(v) && !all.includes(Buffer.from(v).toString('base64')) && !all.includes(Buffer.from(v).toString('hex')), 'a provider value is in Privilege state'); }
});

test('the proof is not vacuous: if a value IS copied into the inventory it is found (plain, base64 and hex), and short values are counted as skipped', () => {
  for (const form of [(v) => v, (v) => Buffer.from(v).toString('base64'), (v) => Buffer.from(v).toString('hex')]) {
    const e = newEngine(); const v = e.providerValues().find((x) => x.length >= 12);
    e.s.inventory[0].leak = form(v);
    const p = e.noCopyProof(); assert.ok(p.valuesFound >= 1, 'found'); assert.equal(p.found[0].area, 'inventory');
  }
  const e = newEngine(); run(e, 'storeCreate', ADMIN, { secret: { provider: 'aws', path: 'prod/s/short', fields: { value: 'abc12' } } });
  assert.ok(e.noCopyProof().skippedShort >= 1);
});

test('a value that leaks into the AUDIT trail or a sync report is found too (every area is searched)', () => {
  for (const area of ['audit', 'reports', 'deliveries', 'gatewayLog']) {
    const e = newEngine(); read(e, U1); run(e, 'advance', U1, { clock: { minutes: 1020 } });
    const v = e.providerValues().find((x) => x.length >= 12);
    (e.s[area].length ? e.s[area] : e.s[area].push({}) && e.s[area])[0].leak = v;
    const p = e.noCopyProof(); assert.ok(p.valuesFound >= 1, area);
  }
});

test('the state every role is shown, for every vertical, never carries a provider value, a connection credential, a vault secret or a shared service account value', () => {
  for (const v of ['finance', 'health', 'retail']) {
    const e = newEngine(); const c = e.cast; e.trace = null;
    const id = run(e, 'vaultCreate', c.castUser, { entry: { name: 'v', targetId: c.castT1, shape: 'bearer', secret: { token: `typed-token-for-${v}-0123456789` } } }).result.entryId;
    run(e, 'gatewayCall', c.castUser, { call: { targetId: c.castT1, as: 'per-user', entryId: id, operation: 'read_summary' } });
    const text = [...e.roster.keys()].map((who) => JSON.stringify(e.snapshot(e.roster.get(who)))).join('\n') + e.dump();
    assert.ok(!text.includes(`typed-token-for-${v}`)); for (const val of e.providerValues()) assert.ok(!text.includes(val));
    assert.ok(!/MOCK-conn-|MOCK-bearer-|MOCK-apikey-|MOCK-basic-|MOCK-header-/.test(text));
  }
});

test('capacity: a full audit trail refuses new work whole instead of dropping entries', () => {
  const e = newEngine();
  while (e.s.audit.length < 1995) e.s.audit.push({ id: 'x', at: '', actor: 'system', role: 'system', domain: 'x', action: 'x', resource: '-', outcome: 'allowed' });
  const before = JSON.stringify(e.s.vault[U1]);
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true } })), 'workspace_full');
  assert.equal(code(read(e, U1)), 'workspace_full'); assert.equal(JSON.stringify(e.s.vault[U1]), before);
});

test('typed names, paths, tags and notes: credential-shaped text is refused or masked and never kept', () => {
  const e = newEngine(); const tok = ['gh', 'p_', 'a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8'].join('');
  assert.equal(code(run(e, 'vaultCreate', U1, { entry: { name: tok, targetId: C.castT1, shape: 'bearer', generate: true } })), 'credential_shaped_text');
  assert.equal(code(run(e, 'storeCreate', ADMIN, { secret: { provider: 'aws', path: `prod/${tok}` } })), 'bad_path');
  assert.equal(code(run(e, 'storeCreate', ADMIN, { secret: { provider: 'aws', path: 'prod/t/x', tags: [tok.toLowerCase()] } })), 'bad_tags');
  assert.equal(code(run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'create', path: tok } })), 'bad_path');
  const id = run(e, 'vaultCreate', U1, { entry: { name: 'ok', targetId: C.castT1, shape: 'bearer', generate: true, notes: `my ${['pass', 'word'].join('')} is hunter2xyz and ${tok}` } }).result.entryId;
  const notes = e.vaultGet(e.roster.get(U1), id).notes; assert.ok(!notes.includes('hunter2xyz') && !notes.includes(tok)); assert.match(notes, /\[masked:/);
});
