// Shared by the echo sweeps: ONE value typed into every free-text field, key name, path segment, query, header and error-path input of every endpoint.
// Returns the text of every answer (status line, body, headers). Nothing here asserts; the callers search the texts.
import { C, U1, ADMIN, get, post, put, live, rawHttp } from './helpers.js';

export const AWS = `aws:${C.castAwsPrefix}/db-admin`;
export async function sweepAll(url, v, id) {
    const bodies = [
      [U1, 'POST', '/api/vault/entries', live({ entry: { name: v, targetId: v, shape: v, notes: v, headerName: v, secret: v } })],
      [U1, 'POST', '/api/vault/entries', live({ entry: { name: `n ${v}`, targetId: C.castT1, shape: 'bearer', notes: `see ${v} here`, secret: { token: v } } })],
      [U1, 'POST', '/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT3, shape: 'basic', secret: { username: v, password: v } } })],
      [U1, 'POST', '/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT4, shape: 'headers', secret: { headers: { [v]: v, 'X-Ok': v } } } })],
      [U1, 'POST', '/api/vault/entries', live({ entry: { name: 'x', targetId: C.castT1, shape: 'bearer', generate: true, [v]: v } })],
      [U1, 'PUT', `/api/vault/entries/${id}`, live({ entry: { name: v, notes: v, secret: { token: v }, [v]: v } })],
      [U1, 'PUT', `/api/vault/entries/${encodeURIComponent(v)}`, live({ entry: { notes: v } })],
      [U1, 'POST', `/api/vault/entries/${encodeURIComponent(v)}/delete`, live({})], [U1, 'POST', `/api/vault/entries/${encodeURIComponent(v)}/restore`, live({ [v]: v })],
      [U1, 'POST', '/api/gateway/call', live({ call: { targetId: v, as: v, entryId: v, operation: v, [v]: v } })],
      [U1, 'POST', '/api/gateway/call', live({ call: { targetId: C.castT1, as: 'per-user', entryId: id, operation: v } })],
      [ADMIN, 'POST', '/api/vault/keys', live({ key: { configured: v, reachable: v, [v]: v } })],
      [ADMIN, 'POST', '/api/targets', live({ target: { id: v, accepts: v, protocol: v, [v]: v } })],
      [ADMIN, 'POST', `/api/targets/${encodeURIComponent(v)}/remove`, live({})],
      [U1, 'POST', '/api/stores/secrets', live({ secret: { provider: v, path: v, template: v, tags: [v], fields: { [v]: v, value: v } } })],
      [ADMIN, 'POST', '/api/stores/secrets', live({ secret: { provider: 'aws', path: `prod/x/${v}`, tags: [v], fields: { value: v } } })],
      [ADMIN, 'POST', '/api/stores/secrets', live({ secret: { provider: 'aws', path: 'prod/echo/one', fields: { value: v } } })],
      [U1, 'POST', '/api/stores/read', live({ read: { ref: v, consumer: v, [v]: v } })], [U1, 'POST', '/api/stores/read', live({ read: { ref: AWS, consumer: v } })],
      [U1, 'POST', '/api/stores/update', live({ update: { ref: v, fields: { [v]: v }, tags: [v] } })], [ADMIN, 'POST', '/api/stores/update', live({ update: { ref: 'aws:prod/echo/one', fields: { value: v }, tags: [v] } })],
      [U1, 'POST', '/api/stores/rotate', live({ ref: v })], [U1, 'POST', '/api/stores/delete', live({ ref: v })], [U1, 'POST', '/api/stores/recover', live({ ref: v })], [U1, 'POST', '/api/stores/purge', live({ ref: v })],
      [ADMIN, 'POST', '/api/stores/connection', live({ provider: v })],
      [ADMIN, 'POST', '/api/stores/provider-change', live({ change: { provider: v, op: v, ref: v, newPath: v, path: v } })],
      [ADMIN, 'POST', '/api/stores/provider-change', live({ change: { provider: 'aws', op: 'create', path: v } })],
      [ADMIN, 'POST', '/api/stores/resync', live({ [v]: v })],
      [ADMIN, 'POST', '/api/policies', live({ grant: { principal: v, scope: v, actions: [v], [v]: v } })], [ADMIN, 'POST', `/api/policies/${encodeURIComponent(v)}/revoke`, live({})],
      [U1, 'POST', '/api/clock', live({ clock: { minutes: v, [v]: v } })],
      [U1, 'POST', '/api/reset', { [v]: v }],
    ];
    const gets = [`/api/state?mode=${encodeURIComponent(v)}`, `/api/state?mode=live&vertical=${encodeURIComponent(v)}&scenario=${encodeURIComponent(v)}`, `/api/state?mode=mock&scenario=${encodeURIComponent(v)}`, `/api/state?mode=live&${encodeURIComponent(v)}=${encodeURIComponent(v)}`, `/api/story?vertical=${encodeURIComponent(v)}`, `/api/diagram?name=${encodeURIComponent(v)}&vertical=${encodeURIComponent(v)}`, `/api/vault/entries/${encodeURIComponent(v)}`, `/api/vault/entries?owner=${encodeURIComponent(v)}`, `/api/stores/secrets?x=${encodeURIComponent(v)}`, `/api/${encodeURIComponent(v)}`, `/api/health?x=${encodeURIComponent(v)}`];
    const texts = [];
    for (const [who, m, p, b] of bodies) { const r = await (m === 'PUT' ? put : post)(url, p, b, who); texts.push(`${m} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
    for (const g of gets) { const r = await get(url, g, U1); texts.push(`GET ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`); }
    for (const hv of [v, `a ${v}`]) { const clean = hv.slice(0, 40).replace(/[^\x20-\x7e]/g, '?'); for (const h of [{ 'x-workspace': clean }, { 'x-lab-actor': clean }]) { const r = await get(url, '/api/state?mode=live', h['x-lab-actor'] ? clean : U1, h['x-workspace'] ? h : {}); texts.push(`H ${r.status} ${await r.text()}`); } }
    // wrong methods and unknown paths carrying the value, and the value in headers of a WRITE (workspace, traceparent, origin, actor)
    const e = encodeURIComponent(v);
    for (const [m, p] of [['POST', `/api/${e}`], ['DELETE', '/api/state'], ['PATCH', '/api/vault/entries'], ['POST', `/${e}`], ['GET', `/${e}`], ['GET', `/${e}.js`], ['POST', `/assets/${e}`], ['GET', `/api/vault/entries/${e}/delete`]]) {
      const r = await fetch(`${url}${p}`, { method: m, headers: { 'content-type': 'application/json', origin: url, 'x-lab-actor': U1 }, ...(m === 'GET' ? {} : { body: '{}' }) });
      texts.push(`${m} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`);
    }
    const clean = v.slice(0, 60).replace(/[^\x20-\x7e]/g, '?');
    for (const h of [{ 'x-workspace': clean }, { traceparent: clean }, { 'x-lab-actor': clean }]) {
      const r = await post(url, '/api/clock', live({ clock: { minutes: 1 } }), h['x-lab-actor'] ? clean : U1, h['x-lab-actor'] ? {} : h);
      texts.push(`W ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`);
    }
    // more headers on a read and a write: Origin, Accept, Content-Type charset, Authorization, Cookie, Referer, User-Agent, X-Forwarded-For, Host (node:http can set it)
    const ascii = v.slice(0, 80).replace(/[^\x21-\x7e]/g, '?');
    for (const h of [{ origin: ascii }, { accept: ascii }, { 'content-type': `application/json; charset=${ascii}` }, { authorization: `Bearer ${ascii}` }, { cookie: `sid=${ascii}` }, { referer: ascii }, { 'user-agent': ascii }, { 'x-forwarded-for': ascii }, { 'x-forwarded-host': ascii }]) {
      for (const m of ['GET', 'POST']) {
        const r = await fetch(`${url}${m === 'GET' ? '/api/state?mode=live' : '/api/clock'}`, { method: m, headers: { 'content-type': 'application/json', 'x-lab-actor': U1, ...(m === 'POST' ? { origin: url } : {}), ...h }, ...(m === 'POST' ? { body: JSON.stringify(live({ clock: { minutes: 1 } })) } : {}) });
        texts.push(`HDR ${m} ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`);
      }
    }
    { const u = new URL(url); const r = await rawHttp(`${url}/api/state?mode=live`, { headers: { host: ascii.replace(/[^A-Za-z0-9.:-]/g, '-') || 'x', 'x-lab-actor': U1 } }); texts.push(`HOST ${r.status} ${r.text} ${Object.values(r.headers).join(' ')} ${u.port}`); }
    // the mode, vertical and scenario fields themselves, on a write and a read
    for (const body of [{ mode: v, vertical: 'finance', clock: { minutes: 1 } }, { mode: 'live', vertical: v, clock: { minutes: 1 } }, { mode: 'mock', vertical: 'finance', clock: { minutes: 1 } }, { mode: ['live', v], clock: {} }, { mode: { [v]: v } }]) {
      const r = await post(url, '/api/clock', body, U1); texts.push(`MV ${r.status} ${await r.text()} ${[...r.headers.values()].join(' ')}`);
    }
    return texts;

}
