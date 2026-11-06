import { workspaceFetch } from "./workspace";

export async function getJson(url, opts = {}) {
  const r = await workspaceFetch(url, { method: "GET", ...opts });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// An answer that is not a JSON object (null, an array, text) is treated as an empty one: the page never trusts the shape of a body.
const objectBody = async (r) => { try { const j = await r.json(); return j !== null && typeof j === "object" && !Array.isArray(j) ? j : {}; } catch { return {}; } };

// POST or PUT JSON. Returns { ok, status, body }: a refusal (400, 403, 404, 409) is data (a code and a detail), not an exception.
export async function sendJson(method, url, payload, opts = {}) {
  const r = await workspaceFetch(url, { method, body: JSON.stringify(payload), ...opts });
  return { ok: r.ok, status: r.status, body: await objectBody(r) };
}
export const postJson = (url, payload) => sendJson("POST", url, payload);
export const putJson = (url, payload) => sendJson("PUT", url, payload);

// A read that is allowed to fail: used by the isolation check, which WANTS to see the 404 and the 400 (the browser logs them, the README says so).
export const probe = (url, as) => workspaceFetch(url, { method: "GET", as }).then(async (r) => ({ status: r.status, body: await objectBody(r) }));

export const resetWorkspace = () => workspaceFetch("/api/reset", { method: "POST", body: "{}" }).then((r) => r.ok);

// Rule 19: POST /api/mode {source:"mock"|"real"}. Returns { ok, status, body } (like sendJson): a refused
// switch comes back as data, never an exception.
export async function setMode(source) {
  const r = await workspaceFetch("/api/mode", { method: "POST", body: JSON.stringify({ source }) });
  return { ok: r.ok, status: r.status, body: await objectBody(r) };
}
