// Preflight: the same checks GET /api/health reports from, plus whether the port is free, plus one real run of the engine through the HTTP API
// (a sealed entry, a gateway call, an isolation check) on a throwaway port. Prints only pass/fail lines, never a setting's value. Exit 1 on failure.
import net from 'node:net';
import path from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const load = (p) => import(pathToFileURL(path.join(root, p)));
const { installNetguard } = await load('server/src/netguard.js');
installNetguard();
const { applySharedSettings } = await load('server/src/settings.js');
applySharedSettings();

const { runChecks } = await load('server/src/doctor.js');
let failed = 0;
const report = (level, name, detail) => { if (level === 'fail') failed++; console.log(`${level.toUpperCase().padEnd(4)}  ${name}: ${detail}`); };
for (const c of await runChecks()) report(c.level, c.id, c.detail);

// A real cycle through the HTTP layer, in this process, on an ephemeral loopback port.
try {
  const { createApp, startHttpServer } = await load('server/src/app.js');
  const { createHealth } = await load('server/src/health.js');
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  const { server, url } = await startHttpServer({ port: 0, host: '127.0.0.1', app: createApp({ health }) });
  try {
    const base = url.replace(/\/$/, ''); const H = (actor) => ({ 'content-type': 'application/json', origin: base, 'x-workspace': 'doctor', 'x-lab-actor': actor });
    const post = async (p, actor, b) => (await fetch(base + p, { method: 'POST', headers: H(actor), body: JSON.stringify({ mode: 'live', vertical: 'finance', ...b }) })).json();
    const cast = (await (await fetch(`${base}/api/story?vertical=finance`)).json()).cast;
    const made = await post('/api/vault/entries', cast.castUser, { entry: { name: 'doctor', targetId: cast.castT1, shape: 'bearer', generate: true } });
    const id = made.result.entryId;
    const used = await post('/api/gateway/call', cast.castUser, { call: { targetId: cast.castT1, as: 'per-user', operation: 'read_summary' } });
    const other = await post(`/api/vault/entries/${id}/delete`, cast.castAdmin, {});
    const ok = made.ok === true && used.result?.backendView?.principal === cast.castUser && other.error === 'not_found' && used.state.proof.valuesFound === 0;
    report(ok ? 'pass' : 'fail', 'engine-cycle', ok ? 'a credential sealed in the user\'s vault, injected by the gateway so the backend logged that user, an administrator forced into their own empty vault (not found), and the no-copy search found nothing' : 'the vault, gateway and isolation cycle did not complete');
  } finally { health.stop(); await new Promise((res) => server.close(res)); }
} catch { report('fail', 'engine-cycle', 'the HTTP cycle could not run'); }

const port = Number(process.env.PORT) || 7450;
await new Promise((resolve) => {
  const s = net.createServer();
  s.once('error', (e) => { report('fail', 'port-free', `${port} is not free (${e.code}). Set PORT to a free port in 7450-7299`); resolve(); });
  s.listen(port, '127.0.0.1', () => s.close(() => { report('pass', 'port-free', `${port} is free`); resolve(); }));
});
process.exit(failed ? 1 : 0);
