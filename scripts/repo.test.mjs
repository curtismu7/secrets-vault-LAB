import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

test('the files the standalone rules ask for are present', () => {
  for (const f of ['README.md', 'CLAUDE.md', 'LICENSE', 'Dockerfile', 'docker-compose.yml', '.github/workflows/ci.yml', 'docs/talk-track.md', 'docs/safety.md', 'docs/content-pack.schema.json', 'scripts/build-mock-table.mjs', 'docs/shelf-entry.json', 'customer.config.example.json', 'content-pack.json', 'scripts/doctor.mjs', 'scripts/reset.mjs', 'web/src/styles/standalone-ui.css', 'LICENSE', '.gitignore']) {
    assert.ok(fs.existsSync(path.join(root, f)), f);
  }
});

test('the shelf entry is valid and portable: relative composeFile, loopback url, health path, catalog id D108', () => {
  const e = JSON.parse(read('docs/shelf-entry.json')).demos[0];
  assert.equal(e.id, 'secrets-vault-lab');
  assert.equal(e.kind, 'Demo');
  assert.equal(e.healthPath, '/api/health');
  assert.match(e.url, /^http:\/\/localhost:74[5-9]\d$/);
  assert.equal(e.catalogId, 'D108', 'catalog id planned in PROPOSED-CATALOG-ROWS-PRIVILEGE-DECK-2026-10-31.md');
  assert.equal(e.composeFile, 'secrets-vault-LAB/docker-compose.yml');
  assert.ok(!path.isAbsolute(e.composeFile), 'composeFile must be relative or a placeholder');
  assert.ok(!/\/Users\//.test(JSON.stringify(e)), 'no absolute home path');
});

test('customer.config.json is git-ignored, and its example only sets the three cast values', () => {
  assert.match(read('.gitignore'), /^customer\.config\.json$/m);
  assert.deepEqual(Object.keys(JSON.parse(read('customer.config.example.json')).cast).sort(), ['brand', 'host', 'user']);
});

test('no shipped text names a real customer, company or tenant', () => {
  const skip = new Set(['node_modules', 'dist', '.git', 'package-lock.json']);
  const hits = [];
  const walk = (dir) => {
    for (const name of fs.readdirSync(dir)) {
      if (skip.has(name)) continue;
      const p = path.join(dir, name);
      if (fs.statSync(p).isDirectory()) walk(p);
      // server/test/corpus holds the shared masker's random probe fragments (copied unchanged); a four-letter run there is chance, not a name
      else if (!p.includes(path.join('server', 'test', 'corpus')) && !['repo.test.mjs', 'story.test.js', 'content-pack.test.mjs'].some((n) => p.endsWith(n))) {
        const t = fs.readFileSync(p, 'utf8').toLowerCase();
        for (const w of ['united airlines', 'mileageplus', 'datapower', 'optum', 'unitedhealth', 'uhg', 'member benefit', 'personal-agent']) if (t.includes(w)) hits.push(`${path.relative(root, p)}: ${w}`);
      }
    }
  };
  walk(root);
  assert.deepEqual(hits, []);
});

test('the CI workflow is GitHub-hosted, Node 26 only, and carries the forbidden-strings and gitleaks jobs', () => {
  const ci = read('.github/workflows/ci.yml');
  assert.match(ci, /runs-on: ubuntu-latest/);
  assert.ok(!/self-hosted/.test(ci));
  const versions = [...ci.matchAll(/node-version: (\S+)/g)].map((m) => m[1]);
  assert.ok(versions.length >= 3 && versions.every((v) => v === '26'), versions.join());
  assert.match(ci, /forbidden-strings:/);
  assert.match(ci, /gitleaks/);
  assert.match(ci, /PORT=7459 npm run doctor/);
});

test('package.json requires Node 26 and the Dockerfile uses a Node 26 base', () => {
  assert.equal(JSON.parse(read('package.json')).engines.node, '>=26');
  assert.ok((read('Dockerfile').match(/^FROM node:26-alpine/gm) || []).length === 2);
});

test('README follows the README standard: title ends in LAB, plain Tier and Repo lines, the port text, a run-from-a-clone section; no internal names', () => {
  const r = read('README.md');
  assert.match(r.split('\n')[0], /^# .* LAB$/);
  assert.match(r, /^Tier: Demo$/m);
  assert.match(r, /^Repo: https:\/\/github\.com\/curtismu7\/secrets-vault-LAB$/m);
  for (const h of ['Run from a clone', 'Settings file', 'What to do if the port is taken', 'Mock and live modes', 'Health, doctor and reset', 'Docker', 'Tests', 'Troubleshooting', 'Ownership', 'What is simulated']) assert.match(r, new RegExp(`^## .*${h}`, 'mi'), h);
  assert.match(r, /lsof -iTCP:7450 -sTCP:LISTEN -n -P/);
  assert.match(r, /PORT=<other port> npm start/);
  assert.ok(!/ping-devops|cmuir|curtismu/i.test(r.replace(/^Repo: https:\/\/github\.com\/curtismu7\/[A-Za-z0-9-]+-LAB$/m, "")));
  assert.ok(!/\bdoor\b/i.test(r));
});

test('docs never use the word "door"', () => {
  for (const f of ['README.md', 'CLAUDE.md', 'docs/talk-track.md', 'docs/safety.md']) assert.ok(!/\bdoor\b/i.test(read(f)), f);
});

test('the lab ships no k8s manifests (deferred by the owner, 2026-10-31)', () => {
  assert.ok(!fs.existsSync(path.join(root, 'k8s')));
});

test('README sections follow the standard order (Troubleshooting, Ownership, Not done) and list the known detection limits and the input limits; conformance is said to be run by hand', () => {
  const r = read('README.md');
  for (const limit of ['10080', '65536', '500 entries', '40 hops', '4096 bytes', '2000 audit entries']) assert.ok(r.includes(limit), `the README states the limit: ${limit}`);
  const at = (h) => r.indexOf(`\n## ${h}`);
  const order = ['What is simulated', 'Run from a clone', 'Settings file', 'Ports, and what to do', 'Mock and live modes', 'Health, doctor and reset', 'Docker', 'Tests', 'Troubleshooting', 'Ownership', 'Not done'].map(at);
  assert.ok(order.every((i) => i > 0), order.join());
  assert.deepEqual([...order].sort((a, b) => a - b), order, 'sections are in order');
  assert.match(r, /### Known limits of the model/);
  assert.match(r, /lab-invented/i);
  assert.match(r, /run by hand/);
  assert.match(r, /util\.parseEnv/);
});

test('app CSS follows the CSS standard: tokens only, no dark-mode media query, no forced priority, no italics, breakpoints 600 and 900 only, no purple', () => {
  const css = read('web/src/app.css');
  assert.ok(!/#[0-9a-fA-F]{3,8}\b|\brgba?\(|\bhsla?\(/.test(css), 'no colour literal');
  assert.ok(!/prefers-color-scheme/.test(css)); assert.ok(!/!important/.test(css)); assert.ok(!/font-style:\s*italic/.test(css));
  const widths = [...css.matchAll(/@media \((?:max|min)-width: (\d+)px\)/g)].map((m) => m[1]);
  assert.ok(widths.length > 0 && widths.every((w) => w === '600' || w === '900'), widths.join());
  assert.ok(!/purple|violet|magenta|indigo/i.test(css + read('web/src/styles/standalone-ui.css').replace(/\/\*[\s\S]*?\*\//g, '').replace(/--[a-z-]+:[^;]*;/g, '')));
  const main = read('web/src/main.jsx');
  assert.ok(main.indexOf('standalone-ui.css') < main.indexOf('app.css'), 'the shared stylesheet loads before the app stylesheet');
  assert.ok(!/style=\{\{/.test(['App.jsx', 'components/VaultTab.jsx', 'components/InjectionTab.jsx', 'components/StoresTab.jsx', 'components/GovernanceTab.jsx', 'components/KeyPanel.jsx', 'components/ClockBar.jsx'].map((f) => read(`web/src/${f}`)).join('\n')), 'no style attributes outside diagram positions');
});

test('no bare MODE, and a password input is only ever a write-only field: its value is never rendered back into the page text', () => {
  for (const f of ['App.jsx', 'components/VaultTab.jsx', 'components/InjectionTab.jsx', 'components/StoresTab.jsx', 'components/GovernanceTab.jsx', 'components/KeyPanel.jsx']) assert.ok(!/process\.env\.MODE/.test(read(`web/src/${f}`)), f);
  assert.ok(!/dangerouslySetInnerHTML|innerHTML/.test(['App.jsx', 'components/VaultTab.jsx', 'components/InjectionTab.jsx', 'components/StoresTab.jsx', 'components/GovernanceTab.jsx'].map((f) => read(`web/src/${f}`)).join('\n')));
  assert.ok(!/localStorage\.setItem\([^)]*(secret|token|password|credential)/i.test(read('web/src/components/VaultTab.jsx')), 'a typed secret is never put in browser storage');
});

test('the README states how the lab differs from the deck: nothing returns a value, the caller names no owner', () => {
  const r = read('README.md');
  assert.match(r, /no API ever returns a stored value/i); assert.match(r, /no administrator override/i); assert.match(r, /UNVERIFIED on our tenant/);
});
