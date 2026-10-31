import { useState } from "react";
import { ClaimTag, SourceTag, StatusTag } from "./Bits";
import { t } from "../fmt";
import { visible } from "../safeText";

function Proof({ proof, lab }) {
  if (proof.skipped) return <section className="panel" data-state="warn" data-testid="proof"><h3 className="panel__sub">No-copy proof: skipped on this write</h3><p>{proof.reason}</p><button type="button" onClick={lab.reload} data-testid="proof-run">Run the proof now</button></section>;
  return (
    <section className="panel" data-state={proof.valuesFound === 0 && proof.selfTest.detected ? "ok" : "bad"} data-testid="proof">
      <h3 className="panel__sub">No-copy proof, computed now <SourceTag source="invented" /></h3>
      <p>Searched <strong data-testid="proof-bytes">{proof.bytesScanned.toLocaleString("en-US")}</strong> bytes in <strong>{proof.areas.length}</strong> areas for <strong data-testid="proof-checked">{proof.valuesChecked}</strong> values the providers, the connections and the vaults hold (plain, base64 and hex). Found in anything Privilege keeps: <strong data-testid="proof-found">{proof.valuesFound}</strong>.</p>
      <p data-testid="proof-selftest">Self-test: {proof.selfTest.detected ? "a planted copy WAS found" : "the planted copy was NOT found, so the search proves nothing"} ({proof.selfTest.howTested}). {proof.skippedShort} value(s) shorter than {proof.minBytes} bytes are skipped (a short string appears in ordinary words).</p>
      <div className="scroll"><table className="tbl" data-testid="proof-areas"><thead><tr><th>Area searched</th><th>Bytes</th></tr></thead><tbody>{proof.areas.map((a) => <tr key={a.name}><td>{a.name}</td><td>{a.bytes.toLocaleString("en-US")}</td></tr>)}</tbody></table></div>
      <p className="muted">This is a search, not a guarantee: it finds a value stored in the clear or as base64 or hex, and nothing cleverer. The provider's own store is outside it, by design.</p>
      <button type="button" onClick={lab.reload} data-testid="proof-run">Run the proof again</button>
    </section>
  );
}

export default function GovernanceTab({ story, lab }) {
  const state = lab.state; const g = state.governance;
  const [grant, setGrant] = useState({ principal: state.roster[0].id, scope: "aws:**", read: true, write: false });
  const [filter, setFilter] = useState("all");
  const [msg, setMsg] = useState(null);
  const admin = g.canEditPolicy; const off = lab.readOnly || lab.busy || !admin;
  const audit = g.audit.filter((a) => filter === "all" || (filter === "denied" ? a.outcome === "denied" : a.domain === filter));
  const add = async () => { const actions = [grant.read && "read", grant.write && "write"].filter(Boolean); const r = await lab.act("POST", "/api/policies", { grant: { principal: grant.principal, scope: grant.scope, actions } }); setMsg(r.ok ? { ok: true, text: `Granted ${actions.join(" and ")} on ${visible(grant.scope)}.` } : { ok: false, text: `Refused: ${r.body.error || r.status}` }); };
  return (
    <div className="stack">
      <section className="panel"><h2 className="panel__title">Governed access <ClaimTag /></h2><p className="lesson">{story.claims.find((c) => c.id === "governed").claim}</p></section>
      <div className="scroll"><table className="tbl tbl--wide" data-testid="policy-table">
        <caption>Grants {admin ? "(all)" : `(yours: ${g.policies.length} of ${g.policiesTotal})`}. Default deny.</caption>
        <thead><tr><th>Id</th><th>Who</th><th>Scope</th><th>Read</th><th>Write</th><th /></tr></thead>
        <tbody>{g.policies.map((p) => <tr key={p.id} data-testid={`grant-${p.id}`}><td>{p.id}</td><td>{p.principal}</td><td><code>{p.scope}</code></td><td>{p.actions.includes("read") ? "yes" : "no"}</td><td>{p.actions.includes("write") ? "yes" : "no"}</td><td><button type="button" disabled={off} onClick={() => lab.act("POST", `/api/policies/${p.id}/revoke`, {})} data-testid={`revoke-${p.id}`}>Revoke</button></td></tr>)}</tbody>
      </table></div>
      <section className="panel" data-testid="grant-form">
        <h3 className="panel__sub">Add a grant <SourceTag source="invented" /></h3>
        <div className="filters">
          <label>Who<select value={grant.principal} disabled={off} onChange={(e) => setGrant({ ...grant, principal: e.target.value })} data-testid="gr-principal">{state.roster.map((p) => <option key={p.id} value={p.id}>{p.id} ({p.role})</option>)}</select></label>
          <label>Scope (provider:path, * one segment, ** the rest)<input value={grant.scope} disabled={off} onChange={(e) => setGrant({ ...grant, scope: e.target.value })} data-testid="gr-scope" /></label>
          <label className="check"><input type="checkbox" checked={grant.read} disabled={off} onChange={(e) => setGrant({ ...grant, read: e.target.checked })} data-testid="gr-read" /> read</label>
          <label className="check"><input type="checkbox" checked={grant.write} disabled={off} onChange={(e) => setGrant({ ...grant, write: e.target.checked })} data-testid="gr-write" /> write</label>
          <button type="button" className="primary" disabled={off} onClick={add} data-testid="gr-add">Grant</button>
        </div>
        <p className="muted">{admin ? "Read and write are separate: granting write does not let someone read the value." : `Only the administrator edits grants. Act as ${state.roster.find((p) => p.role === "admin")?.id} to add one.`}</p>
        {msg && <p className={msg.ok ? "" : "field-error"} role={msg.ok ? "status" : "alert"} data-testid="grant-message">{msg.text}</p>}
      </section>
      <Proof proof={state.proof} lab={lab} />
      <section className="panel" data-testid="reports">
        <h3 className="panel__sub">Nightly re-sync reports <SourceTag source="invented" /></h3>
        {g.reports.length === 0 ? <p className="muted">None yet. Change something at a provider (Secret Stores), then move the lab clock across 02:00, or press Re-sync now.</p> : g.reports.map((r) => (
          <div key={r.id} data-testid={`report-${r.id}`}>
            <p><strong>{r.id}</strong> ({r.kind}, {t(r.at)} UTC): {r.itemsTotal} change(s); values found in the inventory afterwards: {r.valuesFoundInInventoryAfter}.</p>
            <ul className="plain">{r.items.map((i, n) => <li key={n}><StatusTag status={i.change === "deleted" ? "deleted" : "active"} /> {i.change} <code>{i.ref}</code>{i.from ? <> (was <code>{i.from}</code>; grants lost {i.grantsLost}, gained {i.grantsGained})</> : null}{i.what ? ` (${i.what.join(", ")})` : ""}</li>)}</ul>
            {r.skippedFull > 0 && <p className="field-error" role="alert">{r.skippedFull} new secret(s) could not be added: the inventory is full.</p>}
          </div>
        ))}
      </section>
      <section className="panel" data-testid="audit">
        <h3 className="panel__sub">Audit trail ({g.canSeeAllAudit ? "everyone's, metadata only" : "your own events"}; {g.auditTotal} in all)</h3>
        <label className="inline">Show <select value={filter} onChange={(e) => setFilter(e.target.value)} data-testid="audit-filter"><option value="all">everything</option><option value="denied">denied only</option><option value="store">secret stores</option><option value="vault">vault</option><option value="policy">grants</option><option value="provider">provider-side changes</option></select></label>
        <div className="scroll"><table className="tbl tbl--wide" data-testid="audit-table">
          <thead><tr><th>Id</th><th>Time</th><th>Who</th><th>Action</th><th>Resource</th><th>Outcome</th><th>Why</th></tr></thead>
          <tbody>{audit.length === 0 && <tr><td colSpan={7} className="muted">Nothing yet.</td></tr>}{audit.map((a) => <tr key={a.id}><td>{a.id}</td><td>{t(a.at)}</td><td>{a.actor} ({a.role})</td><td>{a.action}</td><td>{visible(a.resource)}</td><td><StatusTag status={a.outcome} /></td><td>{a.code || ""}</td></tr>)}</tbody>
        </table></div>
      </section>
    </div>
  );
}
