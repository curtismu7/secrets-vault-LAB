// Rule 27: the shared run-observability panel for this lab, with the lab's own states around it.
// Mock: the recorded scenario's record (the events the engine wrote when the table was generated).
// Real: what the lab received on the page's own gateway check (the card above), asked for by that check's run id. A check that never reached the gateway
// made no run, so the panel says so and never shows an older record. Nothing is re-read on a timer: this lab reads no logs, so a re-read could find nothing new.
import { useEffect, useState } from "react";
import RunObservability from "../run-observability/RunObservability.jsx";

// Where this lab's run leaves logs and where they can stream (the README says the same).
export const LOG_STREAMS = [
  { product: "Secrets Vault LAB (this lab's container)", lives: "its stdout. In Live, one line per decision the engine makes (the grant table's allow or refusal, the gateway's injection, the backend's log of who acted) and one per answer received from the Privilege gateway in Real: the caller's name, a step, a result and a run id, never a credential, a sealed value or a gateway address. Mock reads recorded tables and writes none", streams: "nowhere today: the family log collector's source list does not name this container, so it would need an entry first. The SIEM time would then be Docker's wall-clock time for the line; the lab clock stays inside the line as labtime" },
  { product: "Privilege agent gateway (Real)", lives: "its own log (a log volume for a local gateway; the SIEM index for the hosted one)", streams: "the Privilege SIEM export. This lab does not read it, so the Real record holds only what the lab received" },
];

const TITLE = "What each layer logged for this run";
const Note = ({ testId, role, children }) => (
  <div className="obs">
    <section className="ro" data-testid={testId} aria-label={TITLE}>
      <h2>{TITLE}</h2>
      <p className="ro-muted" role={role}>{children}</p>
    </section>
  </div>
);

const NOTE = {
  mock: "Times are the lab clock: it starts at 2026-11-02 09:00 UTC and moves only when the scenario moves it, so the steps of one scenario can share a time (their order is kept). These are recorded decisions of the lab's own engine, not read from any product log. Person is a name chosen in the header: the lab has no sign-in. Agent is a simulated agent tool: there is no OBO token. Privilege holds the lab's own grant table, not PingOne Privilege. Agent gateway is the lab's simulated gateway: it injects the caller's own credential, which is information, not a decision, and the value is never shown. Resource server is the simulated backend's own log of who acted. The lab's own audit trail (Governance) can hold a refused entry for a step the scenario list shows as refused (another person's vault entry, an unsupported store operation): this panel shows only the gateway calls and the grant table's decisions.",
  real: "Real is only the hop to the Privilege gateway: each row is a reply the lab received, not a log line. The vault, the grant table and the backend stay in the lab's own engine in Real too, so their decisions are on the Governance tab, not here. No person signs in for this call and there is no OBO token: the caller is an agent access key. The key and the gateway address are never part of a row.",
};

// null = a request is needed; otherwise what to show instead (nothing is fetched and no older record is shown).
function waiting(real, check, scenarioId) {
  if (real) {
    if (check.phase === "done") return check.runId ? null : { id: "ro-no-run", role: "alert", text: "The gateway check ran, but the lab did not keep a record of it (the server log says why)." };
    if (check.phase === "not-configured") return { id: "ro-no-run", text: `No gateway call was made, so there is no run to show. ${check.reason || "Real is not configured."}` };
    if (check.phase === "error") return { id: "ro-no-run", role: "alert", text: `The gateway check did not complete, so there is no run to show (and no older one is shown in its place). ${check.reason || ""}`.trim() };
    return { id: "ro-loading", text: "Collecting this run's logs…" };
  }
  return scenarioId ? null : { id: "ro-loading", text: "Collecting this run's logs…" };
}

export default function RunObs({ source, vertical, scenarioId, check }) {
  const real = source === "real";
  const wait = waiting(real, check || { phase: "checking" }, scenarioId);
  const key = real ? `real|${check?.runId}` : `mock|${vertical}|${scenarioId}`;
  const [answer, setAnswer] = useState(null); // { key, record, message }: the answer to the request for `key`
  const url = real ? `/api/run-observability?runId=${encodeURIComponent(check?.runId ?? "")}` : `/api/run-observability?vertical=${encodeURIComponent(vertical)}&scenario=${encodeURIComponent(scenarioId ?? "")}`;
  useEffect(() => {
    if (wait) return undefined;
    let live = true;
    const done = (a) => { if (live) setAnswer({ key, ...a }); };
    fetch(url, { headers: { accept: "application/json" } }).then(
      async (r) => {
        const body = await r.json().catch(() => null);
        if (!r.ok) return done({ record: { error: body?.error || `http_${r.status}`, message: body?.message || `The lab answered ${r.status}.` } });
        if (body && typeof body === "object" && "record" in body) return done({ record: body.record, message: body.message });
        return done({ record: { error: "bad_answer", message: "The lab's answer was not a run record." } });
      },
      (e) => done({ record: { error: "unreachable", message: `Could not reach the lab (${String(e?.message || e).slice(0, 120)}).` } }),
    );
    return () => { live = false; };
  }, [key, url, wait === null]); // eslint-disable-line react-hooks/exhaustive-deps -- a new run, scenario or mode asks again; nothing else does

  if (wait) return <Note testId={wait.id} role={wait.role}>{wait.text}</Note>;
  if (!answer || answer.key !== key) return <Note testId="ro-loading">Collecting this run's logs…</Note>; // never the previous record
  if (answer.record === null) return <Note testId="ro-no-run">{answer.message || "There is no run to show."}</Note>;
  return (
    <div className="obs">
      <RunObservability record={answer.record} source={source} streams={LOG_STREAMS} />
      <p className="ro-muted" data-testid="ro-lab-note">{NOTE[real ? "real" : "mock"]}</p>
    </div>
  );
}
