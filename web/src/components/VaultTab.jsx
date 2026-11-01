import { useEffect, useMemo, useRef, useState } from "react";
import { ClaimTag, SourceTag, StatusTag } from "./Bits";
import KeyPanel from "./KeyPanel";
import { probe } from "../api";
import { left, t } from "../fmt";
import { visible } from "../safeText";

const SHAPE_LABEL = { bearer: "Bearer token", "api-key": "API key", basic: "Username and password (HTTP Basic)", headers: "Custom header pairs" };
const mockValue = () => { const a = new Uint8Array(12); window.crypto.getRandomValues(a); return `MOCK-lab-${[...a].map((b) => b.toString(16).padStart(2, "0")).join("")}`; };

// The secret fields for a shape. Inputs are password fields: a typed value goes to the server once, is sealed, and is never shown again.
function SecretFields({ shape, v, set, disabled, prefix }) {
  const f = (name, label, type = "password") => (
    <label key={name}>{label}
      <input type={type} autoComplete="off" value={v[name] || ""} disabled={disabled} onChange={(e) => set({ ...v, [name]: e.target.value })} data-testid={`${prefix}-${name}`} />
    </label>
  );
  if (shape === "bearer") return f("token", "Token");
  if (shape === "api-key") return f("key", "API key");
  if (shape === "basic") return <>{f("username", "User name", "text")}{f("password", "Password")}</>;
  return (
    <>
      {[0, 1].map((i) => (
        <div className="filters" key={i}>
          <label>Header name {i + 1}<input value={v[`hn${i}`] || ""} disabled={disabled} onChange={(e) => set({ ...v, [`hn${i}`]: e.target.value })} data-testid={`${prefix}-hn${i}`} /></label>
          <label>Header value {i + 1}<input type="password" autoComplete="off" value={v[`hv${i}`] || ""} disabled={disabled} onChange={(e) => set({ ...v, [`hv${i}`]: e.target.value })} data-testid={`${prefix}-hv${i}`} /></label>
        </div>
      ))}
    </>
  );
}
// The `secret` object the API takes, from the form values (only the fields that were filled in: omitted means "keep" when editing).
export function secretFrom(shape, v) {
  const keep = (o) => Object.fromEntries(Object.entries(o).filter(([, x]) => x !== undefined && x !== ""));
  if (shape === "bearer") return keep({ token: v.token });
  if (shape === "api-key") return keep({ key: v.key });
  if (shape === "basic") return keep({ username: v.username, password: v.password });
  const headers = {};
  for (const i of [0, 1]) if (v[`hn${i}`] && v[`hv${i}`]) headers[v[`hn${i}`]] = v[`hv${i}`];
  return Object.keys(headers).length ? { headers } : {};
}

function CreateForm({ state, lab }) {
  const [name, setName] = useState("Ledger bearer");
  const [target, setTarget] = useState(state.targets[0]?.id || "");
  const [generate, setGenerate] = useState(true);
  const [v, setV] = useState({});
  const [notes, setNotes] = useState("");
  const [msg, setMsg] = useState(null);
  const last = useRef(0);
  useEffect(() => { if (!state.targets.some((x) => x.id === target)) setTarget(state.targets[0]?.id || ""); }, [state.targets, target]);
  const tg = state.targets.find((x) => x.id === target);
  const shape = tg?.accepts || "bearer";
  const off = lab.readOnly || lab.busy || !tg;
  const submit = async () => {
    // a second click within 1.5 s of the last submit is a double click, not a second entry
    const now = Date.now(); if (now - last.current < 1500) return; last.current = now;
    const entry = { name, targetId: target, shape, ...(notes ? { notes } : {}), ...(generate ? { generate: true } : { secret: secretFrom(shape, v) }) };
    const r = await lab.act("POST", "/api/vault/entries", { entry });
    setMsg(r.ok ? { ok: true, text: `Stored ${r.body.result.entryId} in your vault: ${r.body.result.entry.secret.bytes} bytes, sealed, shown only as present and masked.` } : { ok: false, text: `Refused: ${r.body.error || r.status}${r.body.detail ? ` (${r.body.detail})` : ""}` });
    if (r.ok) setV({});
  };
  return (
    <section className="panel" data-testid="create-entry">
      <h2 className="panel__title">Store a credential in your vault <SourceTag source="deck" /></h2>
      <div className="filters">
        <label>Name<input value={name} disabled={off} onChange={(e) => setName(e.target.value)} data-testid="ce-name" /></label>
        <label>Target system
          <select value={target} disabled={off} onChange={(e) => setTarget(e.target.value)} data-testid="ce-target">{state.targets.map((x) => <option key={x.id} value={x.id}>{x.id} ({x.accepts})</option>)}</select>
        </label>
      </div>
      <p className="muted" data-testid="ce-shape">Shape: {SHAPE_LABEL[shape]} (what this target accepts)</p>
      <label className="check"><input type="checkbox" checked={generate} disabled={off} onChange={(e) => setGenerate(e.target.checked)} data-testid="ce-generate" /> Generate a lab MOCK credential for me (recommended)</label>
      {!generate && <><SecretFields shape={shape} v={v} set={setV} disabled={off} prefix="ce" />
        <p className="muted">Type lab mock values only. The value is sealed at once, never returned and never shown again. <button type="button" disabled={off} onClick={() => setV(shape === "basic" ? { username: "mock-user", password: mockValue() } : shape === "headers" ? { hn0: "X-Partner-Id", hv0: mockValue(), hn1: "X-Partner-Key", hv1: mockValue() } : { [shape === "bearer" ? "token" : "key"]: mockValue() })} data-testid="ce-fill">Fill with a mock value</button></p></>}
      <label>Notes (metadata; credential-shaped text is masked)<input value={notes} disabled={off} onChange={(e) => setNotes(e.target.value)} data-testid="ce-notes" /></label>
      <div className="seg"><button type="button" className="primary" disabled={off} onClick={submit} data-testid="ce-submit">Store in my vault</button></div>
      {msg && <p className={msg.ok ? "" : "field-error"} role={msg.ok ? "status" : "alert"} data-testid="create-message">{visible(msg.text)}</p>}
    </section>
  );
}

function EditPanel({ entry, state, lab }) {
  const [name, setName] = useState(entry.name);
  const [notes, setNotes] = useState(entry.notes);
  const [v, setV] = useState({});
  const [msg, setMsg] = useState(null);
  useEffect(() => { setName(entry.name); setNotes(entry.notes); setV({}); }, [entry.id, entry.updatedAt]); // eslint-disable-line react-hooks/exhaustive-deps
  const off = lab.readOnly || lab.busy || entry.status !== "active";
  const save = async () => {
    const secret = secretFrom(entry.shape, v);
    const patch = { name, notes, ...(Object.keys(secret).length ? { secret } : {}) };
    const r = await lab.act("PUT", `/api/vault/entries/${entry.id}`, { entry: patch });
    setMsg(r.ok ? { ok: true, text: r.body.result.secretChanged ? `Saved. The secret was replaced (now version ${r.body.result.entry.secret.version}, a fresh nonce).` : `Saved. The secret was omitted, so the stored value was kept (still version ${r.body.result.entry.secret.version}, same sealed bytes).` } : { ok: false, text: `Refused: ${r.body.error || r.status}${r.body.detail ? ` (${r.body.detail})` : ""}` });
    if (r.ok) setV({});
  };
  return (
    <section className="panel" data-testid="edit-entry">
      <h2 className="panel__title">Edit {entry.id}: merge, never replace <SourceTag source="deck" /></h2>
      <div className="filters">
        <label>Name<input value={name} disabled={off} onChange={(e) => setName(e.target.value)} data-testid="ed-name" /></label>
        <label>Notes<input value={notes} disabled={off} onChange={(e) => setNotes(e.target.value)} data-testid="ed-notes" /></label>
      </div>
      <p className="muted">Leave the secret fields BLANK to keep the stored value. A field you fill in replaces only that field.</p>
      <SecretFields shape={entry.shape} v={v} set={setV} disabled={off} prefix="ed" />
      <div className="seg"><button type="button" className="primary" disabled={off} onClick={save} data-testid="ed-save">Save changes</button></div>
      {entry.status !== "active" && <p className="muted">A staged entry cannot be edited: restore it first.</p>}
      {msg && <p className={msg.ok ? "" : "field-error"} role={msg.ok ? "status" : "alert"} data-testid="edit-message">{visible(msg.text)}</p>}
      <span className="sr-only">{state.actor.id}</span>
    </section>
  );
}

// Every other person asks for this entry. The server forces each one into their own vault: not found, and an owner parameter is refused.
function Isolation({ state, lab, entryId }) {
  const [rows, setRows] = useState(null);
  const [running, setRunning] = useState(false);
  const others = state.roster.filter((p) => p.id !== state.actor.id);
  const run = async () => {
    setRunning(true);
    const out = [];
    for (const p of others) {
      const direct = await probe(`/api/vault/entries/${entryId}`, p.id);
      const named = await probe(`/api/vault/entries/${entryId}?owner=${encodeURIComponent(state.actor.id)}`, p.id);
      const list = await probe("/api/vault/entries", p.id);
      out.push({ ...p, direct: `${direct.status} ${direct.body.error || "ok"}`, named: `${named.status} ${named.body.error || "ok"}`, list: `${list.body.entries ? list.body.entries.length : "-"} entries (their own)` });
    }
    setRows(out); setRunning(false);
  };
  const off = lab.readOnly || !entryId || running;
  return (
    <section className="panel" data-testid="isolation">
      <h2 className="panel__title">No administrator override <SourceTag source="deck" /></h2>
      <p className="muted">Each other person, in turn, asks for your entry by its id, then names you as the owner, then lists their vault. Every operation is forced to the caller's own vault, whatever the role. The browser logs the deliberate 404 and 400 answers as console messages.</p>
      <div className="seg"><button type="button" disabled={off} onClick={run} data-testid="isolation-run">Try every other role</button></div>
      {!entryId && <p className="muted">Store an entry first.</p>}
      {rows && (
        <div className="scroll"><table className="tbl tbl--wide" data-testid="isolation-table">
          <caption>As each other person: your entry {entryId}</caption>
          <thead><tr><th>Who</th><th>Role</th><th>Ask for the entry</th><th>Name you as owner</th><th>List their vault</th></tr></thead>
          <tbody>{rows.map((r) => <tr key={r.id} data-testid={`iso-${r.id}`}><td>{r.id}</td><td>{r.role}</td><td>{r.direct}</td><td>{r.named}</td><td>{r.list}</td></tr>)}</tbody>
        </table></div>
      )}
    </section>
  );
}

export default function VaultTab({ story, lab }) {
  const state = lab.state;
  const [sel, setSel] = useState(null);
  const entries = state.vault.entries;
  const selected = useMemo(() => entries.find((e) => e.id === sel) || entries[0] || null, [entries, sel]);
  const off = lab.readOnly || lab.busy;
  const stage = (e) => lab.act("POST", `/api/vault/entries/${e.id}/${e.status === "active" ? "delete" : "restore"}`, {});
  return (
    <div className="stack">
      <section className="panel" data-testid="vault-intro">
        <h2 className="panel__title">User Vault: {state.actor.id}'s own vault <ClaimTag /></h2>
        <p className="lesson">{story.claims.find((c) => c.id === "self-service").claim}</p>
        <p className="muted">{lab.readOnly ? `Mock tables are recorded as ${state.actor.id}. Switch to Live to act as anyone on the roster.` : `Acting as ${state.actor.id} (${state.actor.role}). The lab has no sign-in: you choose who acts, so you can try the wrong person. The real product takes the caller from the verified token.`}</p>
        <p data-testid="vault-count">{state.vault.count} of {state.limits.entriesPerUser} entries ({state.vault.staged} staged for deletion, still counted until purged). A credential is at most {state.limits.credentialBytes.toLocaleString("en-US")} bytes (64 KB).</p>
      </section>
      <div className="scroll"><table className="tbl tbl--wide" data-testid="entries-table">
        <caption>Entries (metadata only: a value is never returned)</caption>
        <thead><tr><th>Id</th><th>Name</th><th>Target</th><th>Shape</th><th>Status</th><th>Secret</th><th>Actions</th></tr></thead>
        <tbody>
          {entries.length === 0 && <tr><td colSpan={7} className="muted">No entries yet.</td></tr>}
          {entries.map((e) => (
            <tr key={e.id} data-testid={`entry-${e.id}`} aria-selected={selected?.id === e.id}>
              <td>{e.id}</td><td>{visible(e.name)}{e.notes ? <span className="muted"> · {visible(e.notes)}</span> : null}</td><td>{e.targetId}</td><td>{e.shape}{e.headerNames ? ` (${e.headerNames.join(", ")})` : e.headerName ? ` (${e.headerName})` : ""}</td>
              <td><StatusTag status={e.status} />{e.status === "staged-delete" && <div className="muted" data-testid={`purge-${e.id}`}>purges {t(e.purgeAt)} (in {left(e.purgesInMin)})</div>}</td>
              <td data-testid={`secret-${e.id}`}>present · {e.secret.bytes} bytes · v{e.secret.version} · {e.secret.masked} · nonce {e.secret.nonce}</td>
              <td>
                <button type="button" onClick={() => setSel(e.id)} data-testid={`select-${e.id}`}>Edit</button>{" "}
                <button type="button" disabled={off} onClick={() => stage(e)} data-testid={`${e.status === "active" ? "delete" : "restore"}-${e.id}`}>{e.status === "active" ? "Delete (stage)" : "Restore"}</button>
              </td>
            </tr>
          ))}
        </tbody>
      </table></div>
      <div className="cols">
        <CreateForm state={state} lab={lab} />
        {selected && <EditPanel key={selected.id} entry={selected} state={state} lab={lab} />}
      </div>
      <Isolation state={state} lab={lab} entryId={selected?.id || ""} />
      <KeyPanel state={state} lab={lab} />
    </div>
  );
}
