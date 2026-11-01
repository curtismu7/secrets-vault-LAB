// Rule 13: each browser tab gets its own workspace id, kept in sessionStorage, and sends it as X-Workspace on every API call
// that touches server state. Storage can be blocked, so a failure falls back to a per-load id. The page also names WHO is acting (X-Lab-Actor):
// a lab stand-in for the verified token the real product would use.
// The server refuses an id that looks like a credential (400 bad_workspace). A stored id that the server refuses must not brick the tab: the page makes a new
// one and repeats the call ONCE. Generated ids are "w-" plus 16 hex digits, so they always contain a letter and are never a run of 24 hex digits.
const KEY = "svl.workspace";
const SHAPE = /^[a-z0-9-]{1,40}$/;
const CREDENTIAL_LOOKING = /^(?:sk|pk|rk|pw|pwd|pass|passwd|password|tok|token|secret|apikey|bearer|ghp|gho|ghu|ghs|ghr|github|glpat|xox[abprs]|akia|asia|eyj|ya29)(?:-|$)|[0-9a-f]{24,}/;
const usable = (id) => typeof id === "string" && SHAPE.test(id) && /[a-z]/.test(id) && !CREDENTIAL_LOOKING.test(id);
let memo = null;
let actor = null;

// Tests only: forget the id held in memory so the next call picks a new one.
export const forgetWorkspace = () => { memo = null; actor = null; };
export const setActor = (id) => { actor = id; };

function makeId() {
  const bytes = new Uint8Array(8);
  (window.crypto || { getRandomValues: (a) => a.map(() => Math.floor(Math.random() * 256)) }).getRandomValues(bytes);
  return `w-${[...bytes].map((b) => b.toString(16).padStart(2, "0")).join("")}`;
}

export function workspaceId() {
  if (memo) return memo;
  try { const saved = window.sessionStorage.getItem(KEY); if (usable(saved)) return (memo = saved); } catch { /* blocked */ }
  memo = makeId();
  try { window.sessionStorage.setItem(KEY, memo); } catch { /* blocked */ }
  return memo;
}

// A new id replaces the current one (memory and storage).
export function regenerateWorkspace() {
  memo = makeId();
  try { window.sessionStorage.setItem(KEY, memo); } catch { /* blocked */ }
  return memo;
}

// `as` overrides the acting person for one call (the isolation check asks as each other role without switching the page).
export const workspaceFetch = async (url, opts = {}) => {
  const { as, ...rest } = opts;
  const who = as || actor;
  const send = () => fetch(url, { ...rest, headers: { "content-type": "application/json", ...(rest.headers || {}), "x-workspace": workspaceId(), ...(who ? { "x-lab-actor": who } : {}) } });
  const sent = workspaceId();
  const r = await send();
  if (r.status !== 400) return r;
  let refused = false;
  try { refused = (await r.clone().json())?.error === "bad_workspace"; } catch { /* not JSON */ }
  if (!refused) return r;
  // Regenerate only if no other call already did (two calls in flight must end up on the same new id), then repeat once.
  if (workspaceId() === sent) regenerateWorkspace();
  return send();
};
