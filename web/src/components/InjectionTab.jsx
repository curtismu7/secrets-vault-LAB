import { useEffect, useState } from "react";
import { ClaimTag, SourceTag } from "./Bits";
import { t } from "../fmt";
import { visible } from "../safeText";

const SHAPE_EXAMPLE = { bearer: "Authorization: Bearer ••••••••", "api-key": "X-Api-Key: ••••••••", basic: "Authorization: Basic ••••••••", headers: "X-Partner-Id: ••••••••, X-Partner-Key: ••••••••" };

function View({ title, testId, children, tone }) {
  return <section className="panel" data-state={tone} data-testid={testId}><h3 className="panel__sub">{title}</h3>{children}</section>;
}

export default function InjectionTab({ story, lab }) {
  const state = lab.state;
  const targets = state.targets;
  const [target, setTarget] = useState(targets[0]?.id || "");
  const [entryId, setEntryId] = useState("");
  const [op, setOp] = useState("read_summary");
  const [call, setCall] = useState(null); // the last call's three views
  const [tid, setTid] = useState({ id: "", accepts: "bearer", protocol: "mcp" });
  const [msg, setMsg] = useState("");
  useEffect(() => { if (!targets.some((x) => x.id === target)) setTarget(targets[0]?.id || ""); }, [targets, target]);
  const mine = state.vault.entries.filter((e) => e.targetId === target && e.status === "active");
  useEffect(() => { if (!mine.some((e) => e.id === entryId)) setEntryId(mine[0]?.id || ""); }, [mine, entryId]); // eslint-disable-line react-hooks/exhaustive-deps
  const off = lab.readOnly || lab.busy;
  const tg = targets.find((x) => x.id === target);
  const go = async (as) => {
    const r = await lab.act("POST", "/api/gateway/call", { call: { targetId: target, as, operation: op, ...(as === "per-user" && entryId ? { entryId } : {}) } });
    setCall(r.ok ? { ok: true, as, ...r.body.result } : { ok: false, as, error: r.body.error || r.status, detail: r.body.detail });
  };
  // One sample entry for each of the four shapes, with generated lab mock credentials.
  const seed = async () => {
    let made = 0;
    for (const x of targets.slice(0, 4)) { if (state.vault.entries.some((e) => e.targetId === x.id && e.status === "active")) continue; const r = await lab.act("POST", "/api/vault/entries", { entry: { name: `${x.accepts} for ${x.id}`.slice(0, 60), targetId: x.id, shape: x.accepts, generate: true } }); if (r.ok) made += 1; }
    setMsg(`Created ${made} sample entries with generated lab mock credentials.`);
  };
  const admin = state.actor.role === "admin";
  return (
    <div className="stack">
      <section className="panel" data-testid="injection-intro">
        <h2 className="panel__title">Used at request time <ClaimTag /></h2>
        <p className="lesson">{story.claims.find((c) => c.id === "request-time").claim}</p>
        <p className="muted">{story.claims.find((c) => c.id === "modes").claim}</p>
        <div className="cols">{story.shapes.map((s) => <div key={s.id} className="panel" data-testid={`shape-${s.id}`}><strong>{s.id}</strong><p className="muted">{s.text}</p><code>{SHAPE_EXAMPLE[s.id]}</code></div>)}</div>
      </section>
      <section className="panel" data-testid="call-form">
        <h2 className="panel__title">An agent asks a backend for something <SourceTag source="invented" /></h2>
        <div className="filters">
          <label>Target system
            <select value={target} disabled={off} onChange={(e) => setTarget(e.target.value)} data-testid="inj-target">{targets.map((x) => <option key={x.id} value={x.id}>{x.id} ({x.protocol}, accepts {x.accepts})</option>)}</select>
          </label>
          <label>Your entry for it
            <select value={entryId} disabled={off || mine.length === 0} onChange={(e) => setEntryId(e.target.value)} data-testid="inj-entry">{mine.length === 0 ? <option value="">none: store one on the User Vault tab</option> : mine.map((e) => <option key={e.id} value={e.id}>{e.id} {visible(e.name)}</option>)}</select>
          </label>
          <label>Operation
            <select value={op} disabled={off} onChange={(e) => setOp(e.target.value)} data-testid="inj-op">{(tg?.operations || []).map((o) => <option key={o}>{o}</option>)}</select>
          </label>
        </div>
        <div className="seg">
          <button type="button" className="primary" disabled={off || !tg} onClick={() => go("per-user")} data-testid="inj-call-peruser">Call with my own vault credential</button>
          <button type="button" disabled={off || !tg} onClick={() => go("shared")} data-testid="inj-call-shared">Call with the shared service account (for contrast)</button>
          <button type="button" disabled={off} onClick={seed} data-testid="inj-seed">Create a sample entry for every target</button>
        </div>
        {msg && <p role="status" data-testid="inj-message">{msg}</p>}
        <p className="muted">"Per-user" is the application setting the deck describes. "Shared" shows the same call as one service account everyone uses, for contrast. With no entry for the target the per-user call is refused: it never falls back to the shared account.</p>
      </section>
      {call && !call.ok && <p className="field-error" role="alert" data-testid="call-refused">Refused ({call.error}): {visible(call.detail || "")}</p>}
      {call && call.ok && (
        <div className="cols" data-testid="call-views">
          <View title="1. What the agent sees" testId="view-agent">
            <p>Asked for <code>{call.agentView.asked}</code>. Holds a credential: <strong>{call.agentView.holdsCredential ? "yes" : "no"}</strong>.</p>
            <p>It sees: {call.agentView.sees} (<code>status {call.agentView.answer.status}</code>). Agent-side view of the credential: <code>••••••••</code> (it never receives one).</p>
          </View>
          <View title="2. What the gateway injects" testId="view-gateway">
            <p>Looked in: {call.gatewayView.lookedIn}.</p>
            <ul className="plain">{call.gatewayView.injected.map((i) => <li key={i.header}><code>{i.header}: {i.shown}</code> ({i.bytes} bytes, masked)</li>)}</ul>
          </View>
          <View title="3. What the backend logged" testId="view-backend" tone={call.backendView.principal ? "ok" : "bad"}>
            <p>Principal who actually acted: <strong data-testid="backend-principal">{call.backendView.principal || "nobody (rejected)"}</strong>.</p>
            <p><code>{call.backendView.logLine}</code></p>
            <p>{call.agentView.answer.status === 200 ? "Served." : visible(call.backendView.outcome)}</p>
          </View>
        </div>
      )}
      <div className="cols">
        <div className="scroll"><table className="tbl" data-testid="backend-log">
          <caption>The backend's own log (who it thinks acted; the last 20 of at most 300)</caption>
          <thead><tr><th>#</th><th>Time</th><th>Target</th><th>Operation</th><th>Principal</th><th>Status</th></tr></thead>
          <tbody>{state.backendLog.length === 0 && <tr><td colSpan={6} className="muted">No calls yet.</td></tr>}{state.backendLog.map((b) => <tr key={b.n}><td>{b.n}</td><td>{t(b.at)}</td><td>{b.target}</td><td>{b.operation}</td><td data-testid="log-principal">{b.principal || "unknown"}</td><td>{b.status}</td></tr>)}</tbody>
        </table></div>
        <div className="scroll"><table className="tbl" data-testid="gateway-log">
          <caption>The gateway's log (it knows the caller, even when the backend does not)</caption>
          <thead><tr><th>#</th><th>Caller</th><th>Target</th><th>Mode</th><th>Entry</th><th>Status</th></tr></thead>
          <tbody>{state.gatewayLog.length === 0 && <tr><td colSpan={6} className="muted">No calls yet.</td></tr>}{state.gatewayLog.map((g) => <tr key={g.n}><td>{g.n}</td><td>{g.actor}</td><td>{g.targetId}</td><td>{g.as}</td><td>{g.entryId || "-"}</td><td>{g.status}</td></tr>)}</tbody>
        </table></div>
      </div>
      <section className="panel" data-testid="targets">
        <h2 className="panel__title">Target systems (the application list) <SourceTag source="deck" /></h2>
        <p className="muted">Removing a target is an administrator action. The entries that pointed at it are then cleaned up automatically, deleted outright, and the administrator never reads them.</p>
        <div className="scroll"><table className="tbl">
          <thead><tr><th>Id</th><th>Host</th><th>Protocol</th><th>Accepts</th><th>Your entries</th><th /></tr></thead>
          <tbody>{targets.map((x) => <tr key={x.id} data-testid={`target-${x.id}`}><td>{x.id}</td><td>{x.host}</td><td>{x.protocol}</td><td>{x.accepts}</td><td>{state.vault.entries.filter((e) => e.targetId === x.id).length}</td>
            <td><button type="button" disabled={off || !admin} onClick={() => lab.act("POST", `/api/targets/${x.id}/remove`, {})} data-testid={`remove-${x.id}`}>Remove target</button></td></tr>)}</tbody>
        </table></div>
        <div className="filters">
          <label>New target id<input value={tid.id} disabled={off || !admin} onChange={(e) => setTid({ ...tid, id: e.target.value })} data-testid="nt-id" /></label>
          <label>Accepts<select value={tid.accepts} disabled={off || !admin} onChange={(e) => setTid({ ...tid, accepts: e.target.value })} data-testid="nt-accepts">{story.shapes.map((s) => <option key={s.id}>{s.id}</option>)}</select></label>
          <label>Protocol<select value={tid.protocol} disabled={off || !admin} onChange={(e) => setTid({ ...tid, protocol: e.target.value })} data-testid="nt-protocol"><option>mcp</option><option>a2a</option></select></label>
          <button type="button" disabled={off || !admin || !tid.id} onClick={() => lab.act("POST", "/api/targets", { target: tid })} data-testid="nt-add">Add target</button>
        </div>
        {!admin && !lab.readOnly && <p className="muted">Act as the administrator ({state.roster.find((p) => p.role === "admin")?.id}) to add or remove a target.</p>}
      </section>
    </div>
  );
}
