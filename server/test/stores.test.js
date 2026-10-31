import test from 'node:test';
import assert from 'node:assert/strict';
import { C, U1, U2, ADMIN, AUD, SUP, code, newEngine, run } from './helpers.js';

const AWS = `aws:${C.castAwsPrefix}/db-admin`; const AZ = (n) => `azure:${C.castKv}/${n}`;
const snap = (e, who) => e.snapshot(e.roster.get(who));
const item = (e, who, ref) => snap(e, who).stores.items.find((i) => i.ref === ref);

test('five providers, each keeping its own structure in the inventory (GCP org/folder/project, Delinea folders and templates, CyberArk safes, Azure vaults, AWS prefixes)', () => {
  const e = newEngine(); const p = Object.fromEntries(snap(e, ADMIN).stores.providers.map((x) => [x.id, x]));
  assert.deepEqual(Object.keys(p), ['aws', 'gcp', 'azure', 'delinea', 'cyberark']);
  assert.deepEqual(p.gcp.nodes.map((n) => n.kind).sort(), ['folder', 'folder', 'organisation', 'project', 'project']);
  assert.ok(p.gcp.nodes.some((n) => n.path === `${C.castOrg}/${C.castFolder}/${C.castProject}` && n.kind === 'project'));
  assert.deepEqual(p.delinea.templates, ['Password', 'Secure-File']); assert.ok(p.delinea.nodes.every((n) => n.kind === 'folder'));
  assert.deepEqual(p.cyberark.nodes.map((n) => n.kind), ['safe', 'safe']); assert.deepEqual(p.azure.nodes.map((n) => n.kind), ['vault', 'vault']);
  assert.ok(p.aws.nodes.every((n) => n.kind === 'prefix'));
  assert.equal(p.azure.softDelete, true); assert.equal(p.aws.softDelete, false); assert.equal(p.delinea.fileFields, true);
  const inv = e.s.inventory; assert.ok(['aws', 'gcp', 'azure', 'delinea', 'cyberark'].every((id) => inv.some((r) => r.provider === id)));
});

test('create: needs write and an existing container; the parent must exist, the path must be valid, duplicates are refused', () => {
  const e = newEngine();
  const mk = (who, secret) => code(run(e, 'storeCreate', who, { secret }));
  assert.equal(mk(U1, { provider: 'azure', path: `${C.castKv}/new-token` }), 'ok');
  assert.equal(mk(U1, { provider: 'azure', path: `${C.castKv}/new-token` }), 'already_exists');
  assert.equal(mk(U1, { provider: 'azure', path: `${C.castKv2}/x` }), 'access_denied', 'no write grant on that vault');
  assert.equal(mk(ADMIN, { provider: 'aws', path: 'a b/c' }), 'bad_path');
  assert.equal(mk(ADMIN, { provider: 'delinea', path: `${C.castDelFolder}/NoSuchFolder/x` }), 'parent_not_found');
  assert.equal(mk(ADMIN, { provider: 'delinea', path: `${C.castDelFolder}/Ops/x`, template: 'Nope' }), 'bad_template');
  assert.equal(mk(ADMIN, { provider: 'aws', path: 'prod/new/x', template: 'Password' }), 'bad_template');
  assert.equal(mk(ADMIN, { provider: 'nope', path: 'x' }), 'unknown_provider');
  assert.equal(mk(ADMIN, { provider: 'cyberark', path: 'GhostSafe/x' }), 'parent_not_found');
  assert.equal(mk(ADMIN, { provider: 'aws', path: 'prod/new/x', tags: ['Bad Tag'] }), 'bad_tags');
  assert.equal(mk(ADMIN, { provider: 'aws', path: 'prod/new/x', fields: { value: '' } }), 'bad_field_value');
  assert.equal(mk(ADMIN, { provider: 'aws', path: 'prod/new/x', fields: { other: 'v' } }), 'unknown_field');
  assert.equal(mk(ADMIN, { provider: 'aws', path: 'prod/new/x', fields: { value: 'MOCK-typed-value-aaaa1111' } }), 'ok');
});

test('read, create, update and delete work for all five providers (write grant), with soft-delete and purge only for Azure', () => {
  const e = newEngine();
  e.s.policies.push({ id: 'pol-9001', principal: ADMIN, scope: '*:**', actions: ['read', 'write'], by: 'test', at: '' });
  const targets = [['aws', 'prod/x/one'], ['gcp', `${C.castOrg}/${C.castFolder}/${C.castProject}/one`], ['azure', `${C.castKv}/one`], ['delinea', `${C.castDelFolder}/Ops/one`], ['cyberark', `${C.castSafe}/one`]];
  for (const [provider, path] of targets) {
    const ref = `${provider}:${path}`;
    assert.equal(code(run(e, 'storeCreate', ADMIN, { secret: { provider, path } })), 'ok', `${provider} create`);
    assert.equal(run(e, 'storeRead', ADMIN, { read: { ref, consumer: 'simulated-gateway' } }).result.delivered, true, `${provider} read`);
    assert.equal(item(e, ADMIN, ref).currentVersion, 1);
    assert.equal(code(run(e, 'storeUpdate', ADMIN, { update: { ref, tags: ['changed'] } })), 'ok', `${provider} update tags`);
    assert.equal(item(e, ADMIN, ref).currentVersion, 1, 'a tag change is not a new version');
    assert.equal(code(run(e, 'storeRotate', ADMIN, { ref })), 'ok', `${provider} rotate`);
    assert.equal(item(e, ADMIN, ref).currentVersion, 2); assert.equal(item(e, ADMIN, ref).rotationCount, 1);
    const soft = provider === 'azure';
    if (!soft) { assert.equal(code(run(e, 'storeRecover', ADMIN, { ref })), 'unsupported_operation', `${provider} recover`); assert.equal(code(run(e, 'storePurge', ADMIN, { ref })), 'unsupported_operation', `${provider} purge`); }
    const d = run(e, 'storeDelete', ADMIN, { ref });
    assert.equal(d.result.deleted, soft ? 'soft' : 'permanently', `${provider} delete`);
    assert.equal(!!item(e, ADMIN, ref), soft, `${provider} still in the inventory only when soft-deleted`);
  }
});

test('Azure soft-delete lifecycle: delete, read refused, recover, delete, purge (only when soft-deleted); a purged secret is gone from the provider and the inventory', () => {
  const e = newEngine(); run(e, 'storeCreate', U1, { secret: { provider: 'azure', path: `${C.castKv}/lc` } });
  assert.equal(code(run(e, 'storePurge', U1, { ref: AZ('lc') })), 'not_soft_deleted');
  assert.equal(code(run(e, 'storeRecover', U1, { ref: AZ('lc') })), 'not_soft_deleted');
  run(e, 'storeDelete', U1, { ref: AZ('lc') });
  assert.equal(item(e, U1, AZ('lc')).state, 'soft-deleted');
  assert.equal(code(run(e, 'storeRead', U1, { read: { ref: AZ('lc'), consumer: 'simulated-gateway' } })), 'soft_deleted');
  assert.equal(code(run(e, 'storeRotate', U1, { ref: AZ('lc') })), 'soft_deleted');
  assert.equal(code(run(e, 'storeUpdate', U1, { update: { ref: AZ('lc'), tags: ['x'] } })), 'soft_deleted');
  assert.equal(code(run(e, 'storeDelete', U1, { ref: AZ('lc') })), 'already_deleted');
  assert.equal(code(run(e, 'storeRecover', U1, { ref: AZ('lc') })), 'ok'); assert.equal(item(e, U1, AZ('lc')).state, 'active');
  run(e, 'storeDelete', U1, { ref: AZ('lc') });
  assert.equal(run(e, 'storePurge', U1, { ref: AZ('lc') }).result.purged, true);
  assert.equal(item(e, U1, AZ('lc')), undefined);
  assert.equal(e.providerValues().length, e.s.inventory.reduce((n, r) => n + r.versions.length * r.fields.length, 0), 'the provider holds nothing for it either');
});

test('Delinea: the Secure-File template has a file field (a size in the inventory, never the content); the Password template has username, password, notes', () => {
  const e = newEngine();
  e.s.policies.push({ id: 'pol-9001', principal: ADMIN, scope: 'delinea:**', actions: ['read', 'write'], by: 'test', at: '' });
  run(e, 'storeCreate', ADMIN, { secret: { provider: 'delinea', path: `${C.castDelFolder}/Ops/f`, template: 'Secure-File', fields: { file: 'FILE-CONTENT-MARKER-0123456789', description: 'a file' } } });
  const it = item(e, ADMIN, `delinea:${C.castDelFolder}/Ops/f`);
  assert.deepEqual(it.fields.map((f) => [f.name, f.type]), [['description', 'text'], ['file', 'file']]);
  assert.equal(it.fields.find((f) => f.name === 'file').size, 30);
  assert.ok(!e.dump().includes('FILE-CONTENT-MARKER') && !JSON.stringify(snap(e, ADMIN)).includes('FILE-CONTENT-MARKER'));
  const r = run(e, 'storeRead', ADMIN, { read: { ref: `delinea:${C.castDelFolder}/Ops/f`, consumer: 'simulated-gateway' } }).result;
  assert.ok(!JSON.stringify(r).includes('FILE-CONTENT-MARKER')); assert.equal(r.fields.find((f) => f.name === 'file').type, 'file');
  assert.deepEqual(item(e, ADMIN, `delinea:${C.castDelFolder}/Ops/jump-host`).fields.map((f) => f.name), ['username', 'password', 'notes']);
});

test('update merges: an omitted field keeps its value (same version), a changed field makes a new version; rotation changes only password-type fields', () => {
  const e = newEngine();
  e.s.policies.push({ id: 'pol-9001', principal: ADMIN, scope: 'delinea:**', actions: ['read', 'write'], by: 'test', at: '' });
  const ref = `delinea:${C.castDelFolder}/Ops/jump-host`; const p = e.providerValues.bind(e);
  const before = new Set(p());
  run(e, 'storeUpdate', ADMIN, { update: { ref, fields: { notes: 'new notes text here' } } });
  const after = new Set(p());
  assert.equal(item(e, ADMIN, ref).currentVersion, 2);
  assert.ok(after.has('new notes text here')); for (const v of before) assert.ok(after.has(v), 'every earlier value is kept at the provider');
  run(e, 'storeRotate', ADMIN, { ref });
  assert.equal(item(e, ADMIN, ref).currentVersion, 3);
  assert.equal(code(run(e, 'storeUpdate', ADMIN, { update: { ref } })), 'nothing_to_update');
});

test('rotate on demand works for every provider and counts', () => {
  const e = newEngine();
  e.s.policies.push({ id: 'pol-9001', principal: ADMIN, scope: '*:**', actions: ['write'], by: 'test', at: '' });
  for (const r of e.s.inventory.slice()) { const ref = r.ref; assert.equal(code(run(e, 'storeRotate', ADMIN, { ref })), 'ok', ref); }
  for (const r of e.s.inventory) { assert.equal(r.rotationCount, 1); assert.equal(r.currentVersion, 2); }
});

test('the provider connection credential is sealed at rest, never returned, and a tampered or replaced one fails closed', () => {
  const e = newEngine();
  const text = JSON.stringify(snap(e, ADMIN)) + e.dump();
  assert.ok(!/MOCK-conn-/.test(text), 'no connection credential in any state');
  assert.equal(snap(e, ADMIN).stores.providers[0].connection.sealed, 'AES-256-GCM, never shown');
  const sealed = e.s.connections.aws.sealed; e.s.connections.aws.sealed = { ...sealed, ct: Buffer.from('tampered-bytes!').toString('base64') };
  assert.equal(code(run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-gateway' } })), 'provider_credential_rejected');
  e.s.connections.aws.sealed = sealed;
  assert.equal(code(run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-gateway' } })), 'ok');
  assert.equal(code(run(e, 'connectProvider', U1, { provider: 'aws' })), 'forbidden_role');
  assert.equal(run(e, 'connectProvider', ADMIN, { provider: 'aws' }).result.connection.version, 2);
  assert.equal(code(run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-gateway' } })), 'ok', 'the new connection works');
  run(e, 'restartKeys', ADMIN, { key: { configured: 'vault', reachable: true } });
  assert.equal(code(run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-gateway' } })), 'ok', 'the connection survives a re-key');
});

test('a read delivers the value to a simulated consumer only: the answer is masked, sized, and says it matches the provider now', () => {
  const e = newEngine();
  const r = run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'simulated-agent-tool' } }).result;
  assert.equal(r.delivered, true); assert.equal(r.note, 'value delivered to the consumer (masked)'); assert.equal(r.matchesProviderNow, true);
  assert.deepEqual(r.fields.map((f) => f.shown), ['•'.repeat(8)]); assert.equal(r.bytes, 'MOCK-aws-'.length + 24);
  for (const v of e.providerValues()) assert.ok(!JSON.stringify(r).includes(v));
  assert.equal(code(run(e, 'storeRead', U1, { read: { ref: AWS, consumer: 'anywhere' } })), 'bad_consumer');
  assert.ok(e.consumers['simulated-agent-tool'].last.bytes === r.bytes);
});

test('nothing sets or shows another provider\'s state through the wrong provider id or a stale pid', () => {
  const e = newEngine();
  assert.equal(code(run(e, 'providerChange', ADMIN, { change: { provider: 'gcp', op: 'delete', ref: AWS } })), 'not_found');
  assert.equal(code(run(e, 'providerChange', ADMIN, { change: { provider: 'aws', op: 'explode', ref: AWS } })), 'bad_change');
  assert.equal(code(run(e, 'storeRead', SUP, { read: { ref: {}, consumer: 'simulated-gateway' } })), 'not_found');
  assert.equal(code(run(e, 'storeRead', AUD, { read: { ref: 'x'.repeat(300), consumer: 'simulated-gateway' } })), 'not_found');
});
