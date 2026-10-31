// Five in-process MOCK secret managers with REAL state: versions, soft-delete and purge (Azure only, as the deck says), rotation counters, the
// hierarchy each one keeps (GCP org/folder/project, Delinea folders and templates, CyberArk safes, Azure vaults, AWS name prefixes), and file fields
// (Delinea). Nothing here is a real provider: the call shapes are illustrations on .example hosts and are never sent.
// A provider holds the VALUES. The Privilege side (engine inventory) never does: it asks a provider for metadata, or fetches a value live at the
// moment of an authorized read and hands it to a simulated consumer.
import { createHmac } from 'node:crypto';
import { refuse } from './errors.js';

export const PROVIDER_IDS = ['aws', 'gcp', 'azure', 'delinea', 'cyberark'];
export const PROVIDERS = {
  aws: { id: 'aws', name: 'AWS Secrets Manager', structure: 'name prefixes (the console shows them as folders)', softDelete: false, purge: false, fileFields: false, segments: [1, 8] },
  gcp: { id: 'gcp', name: 'GCP Secret Manager', structure: 'organisation, folder, project', softDelete: false, purge: false, fileFields: false, segments: [4, 4] },
  azure: { id: 'azure', name: 'Azure Key Vault', structure: 'vaults', softDelete: true, purge: true, fileFields: false, segments: [2, 2] },
  delinea: { id: 'delinea', name: 'Delinea Secret Server', structure: 'folders and secret templates', softDelete: false, purge: false, fileFields: true, segments: [2, 8] },
  cyberark: { id: 'cyberark', name: 'CyberArk PAM', structure: 'safes', softDelete: false, purge: false, fileFields: false, segments: [2, 2] },
};
export const DELINEA_TEMPLATES = {
  Password: [{ name: 'username', type: 'text' }, { name: 'password', type: 'password' }, { name: 'notes', type: 'text' }],
  'Secure-File': [{ name: 'description', type: 'text' }, { name: 'file', type: 'file' }],
};
const SIMPLE = [{ name: 'value', type: 'password' }];
const CYBERARK = [{ name: 'userName', type: 'text' }, { name: 'secret', type: 'password' }];
export const SEGMENT = /^[A-Za-z0-9][A-Za-z0-9._-]{0,47}$/;
export const FIELD_MAX_BYTES = 4096;
export const PATH_MAX = 120;
const VERSIONS_KEPT = 10;
const bytes = (s) => Buffer.byteLength(String(s), 'utf8');
export const mockValue = (rand, label) => `MOCK-${label}-${rand(12).toString('hex')}`;

// The illustrated call each provider's live fetch would make (never sent). The provider credential is never shown.
export function callShape(provider, path, op = 'read') {
  const last = path.split('/').pop(); const first = path.split('/')[0];
  const verb = { read: 'GET', create: 'POST', update: 'PUT', delete: 'DELETE', rotate: 'POST', recover: 'POST', purge: 'DELETE' }[op] || 'GET';
  const urls = {
    aws: [`POST`, 'https://secretsmanager.eu-west-1.example/', `X-Amz-Target: secretsmanager.${{ read: 'GetSecretValue', create: 'CreateSecret', update: 'PutSecretValue', delete: 'DeleteSecret', rotate: 'RotateSecret', recover: 'RestoreSecret', purge: 'DeleteSecret' }[op]}`],
    gcp: [verb, `https://secretmanager.example/v1/projects/${path.split('/')[2] || 'project'}/secrets/${last}${op === 'read' ? '/versions/latest:access' : ''}`, ''],
    azure: [verb, `https://${first}.vault.example/secrets/${last}${op === 'purge' ? '/purge' : ''}`, ''],
    delinea: [verb, `https://secretserver.example/api/v1/secrets/${op === 'create' ? '' : last}`, ''],
    cyberark: [verb, `https://pvwa.example/PasswordVault/API/Accounts/${last}${op === 'read' ? '/Password/Retrieve' : ''}`, ''],
  }[provider];
  return { method: urls[0], url: urls[1], ...(urls[2] ? { note: urls[2] } : {}) };
}

export class MockProvider {
  constructor(id, { rand, pidSeq }) {
    this.id = id; this.cfg = PROVIDERS[id]; this.rand = rand; this.pidSeq = pidSeq;
    this.nodes = new Map(); // path -> kind (structure the provider keeps; AWS derives its prefixes)
    this.secrets = new Map(); // pid -> record (VALUES live here, on the provider's side)
    this.credTag = null; // HMAC of the connection credential this provider accepts
    this.tagKey = rand(32);
  }

  tagOf(credential) { return createHmac('sha256', this.tagKey).update(String(credential)).digest('hex'); }
  acceptCredential(credential) { this.credTag = this.tagOf(credential); }
  authenticate(credential) { return this.credTag !== null && typeof credential === 'string' && this.tagOf(credential) === this.credTag; }

  addNode(path, kind) { this.nodes.set(path, kind); }
  layout(template) {
    if (this.id === 'delinea') return Object.hasOwn(DELINEA_TEMPLATES, template) ? DELINEA_TEMPLATES[template] : null;
    return this.id === 'cyberark' ? CYBERARK : SIMPLE;
  }

  // null when the path can be created, else a fixed reason code. Parent containers must already exist (no implicit creation).
  pathProblem(path) {
    if (typeof path !== 'string' || path.length === 0 || path.length > PATH_MAX) return 'bad_path';
    const segs = path.split('/');
    const [lo, hi] = this.cfg.segments;
    if (segs.length < lo || segs.length > hi || !segs.every((s) => SEGMENT.test(s))) return 'bad_path';
    if (this.id === 'gcp' && !this.nodes.has(segs.slice(0, 3).join('/'))) return 'parent_not_found';
    if (this.id === 'azure' && !this.nodes.has(segs[0])) return 'parent_not_found';
    if (this.id === 'cyberark' && !this.nodes.has(segs[0])) return 'parent_not_found';
    if (this.id === 'delinea' && !this.nodes.has(segs.slice(0, -1).join('/'))) return 'parent_not_found';
    if ([...this.secrets.values()].some((s) => s.path === path)) return 'already_exists';
    return null;
  }

  fieldsFrom(template, given, existing = null) {
    const defs = this.layout(template);
    const out = {};
    for (const d of defs) {
      const has = given && Object.hasOwn(given, d.name);
      let v = has ? given[d.name] : undefined;
      if (v === undefined) { out[d.name] = existing ? existing[d.name] : d.type === 'text' ? { type: d.type, value: `mock-${this.rand(3).toString('hex')}` } : { type: d.type, value: mockValue(this.rand, d.type === 'file' ? 'file' : this.id) }; continue; }
      if (typeof v !== 'string' || v.length === 0 || bytes(v) > FIELD_MAX_BYTES) throw refuse('bad_field_value', 'a field value must be a non-empty string of at most 4096 bytes');
      out[d.name] = { type: d.type, value: v };
    }
    if (given) for (const k of Object.keys(given)) if (!defs.some((d) => d.name === k)) throw refuse('unknown_field', 'the secret carries a field this template does not have');
    return out;
  }

  create({ path, template, tags, given, now }) {
    const pid = `${this.id}-${String(++this.pidSeq.n).padStart(4, '0')}`;
    const rec = { pid, path, template: template || null, tags: [...tags], versions: [{ v: 1, at: now, fields: this.fieldsFrom(template, given) }], state: 'active', deletedAt: null, rotationCount: 0 };
    this.secrets.set(pid, rec);
    this.touchNodes(path);
    return pid;
  }
  touchNodes() { /* AWS prefixes are derived from the paths; the other providers keep explicit containers */ }

  current(pid) { const r = this.secrets.get(pid); return r ? r.versions[r.versions.length - 1].fields : null; }
  read(pid) { const r = this.secrets.get(pid); return r && r.state === 'active' ? this.current(pid) : null; }

  pushVersion(rec, fields, now) {
    rec.versions.push({ v: rec.versions[rec.versions.length - 1].v + 1, at: now, fields });
    if (rec.versions.length > VERSIONS_KEPT) rec.versions.shift();
  }
  update(pid, { given, tags, now }) {
    const r = this.secrets.get(pid);
    if (given) this.pushVersion(r, this.fieldsFrom(r.template, given, this.current(pid)), now);
    if (tags) r.tags = [...tags];
  }
  rotate(pid, now) {
    const r = this.secrets.get(pid); const cur = this.current(pid);
    const next = {};
    for (const [k, f] of Object.entries(cur)) next[k] = f.type === 'password' ? { type: 'password', value: mockValue(this.rand, this.id) } : f;
    this.pushVersion(r, next, now); r.rotationCount += 1;
  }
  remove(pid, now) {
    const r = this.secrets.get(pid);
    if (this.cfg.softDelete) { r.state = 'soft-deleted'; r.deletedAt = now; return 'soft'; }
    this.secrets.delete(pid); return 'hard';
  }
  recover(pid) { const r = this.secrets.get(pid); r.state = 'active'; r.deletedAt = null; }
  purge(pid) { this.secrets.delete(pid); }
  rename(pid, newPath) { this.secrets.get(pid).path = newPath; }

  // Metadata only: the only thing the Privilege inventory ever receives from a provider.
  list() {
    return [...this.secrets.values()].map((r) => ({
      pid: r.pid, path: r.path, template: r.template, tags: [...r.tags], state: r.state, rotationCount: r.rotationCount,
      versions: r.versions.map((v) => ({ v: v.v, at: v.at })), currentVersion: r.versions[r.versions.length - 1].v,
      fields: Object.entries(this.current(r.pid)).map(([name, f]) => ({ name, type: f.type, size: bytes(f.value) })),
    }));
  }
  structure() {
    if (this.id === 'aws') {
      const prefixes = new Set();
      for (const r of this.secrets.values()) { const s = r.path.split('/'); for (let i = 1; i < s.length; i++) prefixes.add(s.slice(0, i).join('/')); }
      return [...prefixes].sort().map((p) => ({ path: p, kind: 'prefix' }));
    }
    return [...this.nodes.entries()].map(([path, kind]) => ({ path, kind })).sort((a, b) => a.path.localeCompare(b.path));
  }
  // Every value this provider holds, for the no-copy proof only (never returned by any API).
  allValues() {
    const out = [];
    for (const r of this.secrets.values()) for (const v of r.versions) for (const f of Object.values(v.fields)) out.push(f.value);
    return out;
  }
}

// The seeded estate, with names from the cast. Values are lab-labelled MOCK values made at construction.
export function seedProviders(cast, rand) {
  const pidSeq = { n: 0 };
  const P = Object.fromEntries(PROVIDER_IDS.map((id) => [id, new MockProvider(id, { rand, pidSeq })]));
  const now = 0;
  const add = (id, path, template, tags) => P[id].create({ path, template, tags, given: null, now });
  const c = cast;
  P.gcp.addNode(c.castOrg, 'organisation');
  for (const [f, p] of [[c.castFolder, c.castProject], [c.castFolder2, c.castProject2]]) { P.gcp.addNode(`${c.castOrg}/${f}`, 'folder'); P.gcp.addNode(`${c.castOrg}/${f}/${p}`, 'project'); }
  for (const v of [c.castKv, c.castKv2]) P.azure.addNode(v, 'vault');
  P.delinea.addNode(c.castDelFolder, 'folder'); P.delinea.addNode(`${c.castDelFolder}/${c.castDelSub}`, 'folder'); P.delinea.addNode(`${c.castDelFolder}/Ops`, 'folder');
  for (const s of [c.castSafe, c.castSafe2]) P.cyberark.addNode(s, 'safe');

  add('aws', `${c.castAwsPrefix}/db-admin`, null, ['prod', 'database']);
  add('aws', `${c.castAwsPrefix}/signing-key`, null, ['prod']);
  add('aws', `${c.castAwsPrefix2}/scoring-token`, null, ['prod']);
  add('gcp', `${c.castOrg}/${c.castFolder}/${c.castProject}/db-password`, null, ['prod', 'database']);
  add('gcp', `${c.castOrg}/${c.castFolder}/${c.castProject}/service-token`, null, ['prod']);
  add('gcp', `${c.castOrg}/${c.castFolder2}/${c.castProject2}/model-key`, null, ['prod']);
  add('azure', `${c.castKv}/db-connection`, null, ['prod', 'database']);
  add('azure', `${c.castKv}/storage-key`, null, ['prod']);
  add('azure', `${c.castKv2}/batch-token`, null, ['prod']);
  add('delinea', `${c.castDelFolder}/${c.castDelSub}/db-admin`, 'Password', ['prod', 'database']);
  add('delinea', `${c.castDelFolder}/${c.castDelSub}/tls-bundle`, 'Secure-File', ['prod', 'tls']);
  add('delinea', `${c.castDelFolder}/Ops/jump-host`, 'Password', ['ops']);
  add('cyberark', `${c.castSafe}/db-admin`, null, ['prod', 'database']);
  add('cyberark', `${c.castSafe}/batch-svc`, null, ['prod']);
  add('cyberark', `${c.castSafe2}/etl-svc`, null, ['prod']);
  return { providers: P, pidSeq };
}
