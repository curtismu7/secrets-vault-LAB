import { useRef } from "react";
import { visible } from "../safeText";

// Raw JSON or text, rendered as text only (never markup). Control and bidi characters are shown as visible escapes.
export function Json({ value, label, testId }) {
  return <pre className="json" tabIndex={0} aria-label={label} data-testid={testId}>{visible(typeof value === "string" ? value : JSON.stringify(value, null, 2))}</pre>;
}

// Every product claim carries this tag. It is on every tab, and in presenter mode too.
export function ClaimTag({ label }) {
  return <span className="tag" data-state="warn" data-testid="claim-tag">{label || "Ping release claim, UNVERIFIED on our tenant"}</span>;
}

// Where a field comes from: the deck, the lab's reading of it, or the lab's own invention.
const SRC = { deck: ["deck claim", "ok"], swagger: ["console swagger name (schema only)", "ok"], reading: ["lab reading", "warn"], invented: ["lab-invented", "none"] };
export function SourceTag({ source }) {
  const [text, state] = SRC[source] || [source, "none"];
  return <span className="tag" data-state={state} data-testid="source-tag">{text}</span>;
}

// status words with a state, so meaning never rests on colour alone
const GOOD = new Set(["active", "allowed", "present", "ok", "delivered"]);
const BAD = new Set(["denied", "staged-delete", "soft-deleted", "deleted", "rejected"]);
export const StatusTag = ({ status }) => <span className="tag" data-state={GOOD.has(status) ? "ok" : BAD.has(status) ? "bad" : "warn"} data-testid="status">{status}</span>;

export function Hops({ hops, traceId, truncated }) {
  return (
    <details className="hops" data-testid="hops">
      <summary>Raw hops with traceparent{traceId ? ` (trace ${traceId.slice(0, 8)}...)` : ""} ({hops.length})</summary>
      {truncated && <p className="muted">Only the first hops are shown.</p>}
      {hops.map((h) => (
        <div key={h.n}>
          <h4 className="hops__title">{h.n}. {h.label}</h4>
          <Json value={h.request} label={`hop ${h.n} request`} />
          <Json value={h.response} label={`hop ${h.n} response`} />
        </div>
      ))}
    </details>
  );
}

// The per-field source table, so every claim is tagged swagger name, lab reading or lab-invented.
export function FieldSources({ fields }) {
  return (
    <details data-testid="field-sources">
      <summary>Where each field comes from ({fields.length})</summary>
      <div className="scroll"><table className="tbl tbl--wide">
        <thead><tr><th>Field</th><th>Source</th><th>Note</th></tr></thead>
        <tbody>{fields.map((f) => <tr key={f.field}><td><code>{f.field}</code></td><td><SourceTag source={f.source} /></td><td>{visible(f.note)}</td></tr>)}</tbody>
      </table></div>
    </details>
  );
}

// Stale-response guard: run() returns a function that says whether a newer request has started since.
export function useSeq() {
  const seq = useRef(0);
  return () => { const mine = ++seq.current; return () => mine === seq.current; };
}
