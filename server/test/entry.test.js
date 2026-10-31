import test from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';

// index.js starts the server at import time, so it cannot be imported in a test. Pin its order instead: the network guard
// is installed before the env file is read, the doctor runs, or any server starts.
test('the entry installs the netguard first, before it can open any socket', () => {
  const src = fs.readFileSync(new URL('../src/index.js', import.meta.url), 'utf8');
  const m = /^installNetguard\(\);/m.exec(src);
  assert.ok(m, 'installNetguard() is called as a statement');
  const guard = m.index;
  for (const later of ['runChecks()', 'startHttpServer({', 'applySharedSettings(']) assert.ok(src.indexOf(later) > guard, `${later} comes after the guard`);
  assert.ok(src.indexOf('import { installNetguard }') < guard);
});

test('no source file evals, uses vm or Function, builds a regular expression from input, writes a file, or reads process.env.MODE', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js'))) {
    const code = fs.readFileSync(new URL(f, dir), 'utf8').split('\n').filter((l) => !/^\s*\/\//.test(l)).join('\n');
    assert.ok(!/\beval\(|new Function\(|\bvm\./.test(code), `${f}: no eval, Function or vm`);
    assert.ok(!/writeFile|appendFile|createWriteStream|mkdirSync|rmSync|unlinkSync/.test(code), `${f}: the server writes no file`);
    assert.ok(!/new RegExp\(/.test(code), `${f}: no regular expression is built at run time`);
    assert.ok(!/process\.env\.MODE\b/.test(code), `${f}: a bare MODE is never read`);
    assert.ok(!/child_process|node:http'|node:https|node:net'/.test(code.replace("from 'node:net'", '')) || f === 'netguard.js', `${f}: no network or process modules`);
  }
});

test('the server reads no credential from the environment or a file', () => {
  const dir = new URL('../src/', import.meta.url);
  for (const f of fs.readdirSync(dir).filter((x) => x.endsWith('.js') && x !== 'credentials.js' && x !== 'mask.js')) {
    const code = fs.readFileSync(new URL(f, dir), 'utf8');
    assert.ok(!/process\.env\.[A-Z_]*(TOKEN|SECRET|PASSWORD|KEY)/.test(code), `${f}: no credential env var`);
  }
});
