import test from 'node:test';
import assert from 'node:assert/strict';
import { createApp, startHttpServer } from '../server/src/app.js';
import { createHealth } from '../server/src/health.js';
import { createWorkspaces } from '../server/src/workspaces.js';
import { DEFAULT_CAST } from '../server/src/cast.js';
import { reset } from './reset.mjs';

test('the reset script clears the default workspace (every vertical) and refuses a non-loopback host', async () => {
  const workspaces = createWorkspaces();
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health, workspaces }) });
  try {
    const base = url.replace(/\/$/, '');
    const e = workspaces.engine('default', 'finance', DEFAULT_CAST); workspaces.engine('other', 'finance', DEFAULT_CAST);
    e.advance({ minutes: 30 });
    assert.deepEqual(await reset(base), { reset: 'ok', workspace: 'default' });
    assert.equal(workspaces.peek('default', 'finance'), null);
    assert.ok(workspaces.peek('other', 'finance'), 'another workspace is untouched');
    await assert.rejects(reset('http://example.invalid:7450'), /loopback only/);
  } finally { health.stop(); await new Promise((r) => server.close(r)); }
});
