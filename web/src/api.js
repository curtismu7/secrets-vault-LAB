import { workspaceFetch } from "./workspace";

export async function getJson(url, opts = {}) {
  const r = await workspaceFetch(url, { method: "GET", ...opts });
  if (!r.ok) throw new Error(`HTTP ${r.status}`);
  return r.json();
}

// POST or PUT JSON. Returns { ok, status, body }: a refusal (400, 403, 404, 409) is data (a code and a detail), not an exception.
export async function sendJson(method, url, payload, opts = {}) {
  const r = await workspaceFetch(url, { method, body: JSON.stringify(payload), ...opts });
  let body = {};
  try { body = await r.json(); } catch { /* not JSON */ }
  return { ok: r.ok, status: r.status, body };
}
export const postJson = (url, payload) => sendJson("POST", url, payload);
export const putJson = (url, payload) => sendJson("PUT", url, payload);

// A read that is allowed to fail: used by the isolation check, which WANTS to see the 404 and the 400 (the browser logs them, the README says so).
export const probe = (url, as) => workspaceFetch(url, { method: "GET", as }).then(async (r) => { let body = {}; try { body = await r.json(); } catch { /* not JSON */ } return { status: r.status, body }; });

export const resetWorkspace = () => workspaceFetch("/api/reset", { method: "POST", body: "{}" }).then((r) => r.ok);
