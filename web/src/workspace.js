// Rule 13: each browser tab gets its own workspace id, kept in sessionStorage, and sends it as X-Workspace on every API call
// that touches server state. Storage can be blocked, so a failure falls back to a per-load id. The page also names WHO is acting (X-Lab-Actor):
// a lab stand-in for the verified token the real product would use.
const KEY = "svl.workspace";
let memo = null;
let actor = null;

// Tests only: forget the id held in memory so the next call picks a new one.
export const forgetWorkspace = () => { memo = null; actor = null; };
export const setActor = (id) => { actor = id; };

export function workspaceId() {
  if (memo) return memo;
  try { const saved = window.sessionStorage.getItem(KEY); if (saved && /^[a-z0-9-]{1,40}$/.test(saved)) return (memo = saved); } catch { /* blocked */ }
  const bytes = new Uint8Array(8);
  (window.crypto || { getRandomValues: (a) => a.map(() => Math.floor(Math.random() * 256)) }).getRandomValues(bytes);
  memo = `w-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
  try { window.sessionStorage.setItem(KEY, memo); } catch { /* blocked */ }
  return memo;
}

// `as` overrides the acting person for one call (the isolation check asks as each other role without switching the page).
export const workspaceFetch = (url, opts = {}) => {
  const { as, ...rest } = opts;
  const who = as || actor;
  return fetch(url, { ...rest, headers: { "content-type": "application/json", ...(rest.headers || {}), "x-workspace": workspaceId(), ...(who ? { "x-lab-actor": who } : {}) } });
};
