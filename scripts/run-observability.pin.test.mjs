// Rule 27: the vendored shared/run-observability files match web/src/run-observability/run-observability.sha256 byte for byte.
// They come from curtismu7/AI-DEMO-Standalone shared/run-observability: change them there, re-pin, re-vendor; never edit them here.
// This lab reads no logs (Real is a hop to the Privilege gateway, shown as `response` rows), so it vendors the core only: no server/src/runObservabilityReaders.js.
import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkPin } from './run-observability-checkPin.mjs';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const read = (p) => fs.readFileSync(path.join(root, p), 'utf8');

test('every vendored run-observability file matches its pin, and the core is present', () => {
  assert.deepEqual(checkPin(root), []);
});

test('an edited vendored byte, a missing pin and an unpinned file are each caught', () => {
  const copy = fs.mkdtempSync(path.join(os.tmpdir(), 'svl-pin-'));
  try {
    for (const p of ['web/src/run-observability', 'server/src/runObservability.js']) fs.cpSync(path.join(root, p), path.join(copy, p), { recursive: true });
    assert.deepEqual(checkPin(copy), [], 'an untouched copy is fine');
    const css = path.join(copy, 'web/src/run-observability/run-observability.css');
    fs.appendFileSync(css, ' ');
    assert.ok(checkPin(copy).length > 0, 'one added byte');
    fs.writeFileSync(css, fs.readFileSync(path.join(root, 'web/src/run-observability/run-observability.css')));
    fs.writeFileSync(path.join(copy, 'web/src/run-observability/extra.js'), 'export {};\n');
    assert.ok(checkPin(copy).some((m) => /extra\.js/.test(m)), 'a file beside them that the pin does not name');
    fs.rmSync(path.join(copy, 'web/src/run-observability/extra.js'));
    fs.rmSync(path.join(copy, 'web/src/run-observability/run-observability.sha256'));
    assert.ok(checkPin(copy).length > 0, 'no pin file');
  } finally { fs.rmSync(copy, { recursive: true, force: true }); }
});

test('this lab reads no logs: no readers file, no server file names a reader or a RUN_OBS_ setting (comments included), and the core has no imports', () => {
  assert.ok(!fs.existsSync(path.join(root, 'server/src/runObservabilityReaders.js')));
  const core = read('server/src/runObservability.js');
  assert.ok(!/^\s*import\s/m.test(core), 'the core has no imports');
  assert.ok(!/ElasticsearchReader|DockerLogReader|readersFromEnv|\bfetch\s*\(|node:http|node:fs/.test(core), 'the core names no reader, no network and no file access, not even in a comment');
  // the core's own "no log reader is configured" message names the setting a lab WITH readers would set: it is the one place, and it is vendored
  for (const f of fs.readdirSync(path.join(root, 'server/src')).filter((n) => n.endsWith('.js') && n !== 'runObservability.js')) {
    assert.ok(!/RUN_OBS_|runObservabilityReaders|ElasticsearchReader|DockerLogReader|readersFromEnv/.test(read(`server/src/${f}`)), `${f} names a log reader`);
  }
});

test('compose, the example settings and the Dockerfile never mount the Docker socket and carry no run-observability setting (nothing reads one)', () => {
  for (const f of ['docker-compose.yml', '.env.example', 'Dockerfile']) {
    assert.ok(!/docker\.sock/.test(read(f)), `${f}: no Docker socket`);
    assert.ok(!/RUN_OBS_/.test(read(f)), `${f}: no reader settings`);
  }
});
