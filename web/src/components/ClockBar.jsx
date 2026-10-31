import { t } from "../fmt";

const MOVES = [["1 minute", 1], ["1 hour", 60], ["23 h 59 min", 1439], ["24 hours", 1440], ["7 days", 10080]];

// The lab clock: forward only. Purging after 24 hours and the nightly 02:00 re-sync are seen by moving it.
export default function ClockBar({ state, lab }) {
  const off = lab.readOnly || lab.busy;
  return (
    <section className="panel clock" data-testid="clock-bar" aria-label="Lab clock">
      <p className="clock__now">Lab clock (UTC): <strong data-testid="lab-clock">{t(state.clock)}</strong> <span className="tag" data-state="none">lab-invented</span></p>
      <div className="seg" role="group" aria-label="Move the lab clock forward">
        {MOVES.map(([label, m]) => <button key={m} type="button" disabled={off} onClick={() => lab.act("POST", "/api/clock", { clock: { minutes: m } })} data-testid={`clock-${m}`}>+{label}</button>)}
      </div>
      <p className="muted">{lab.readOnly ? "Mock tables are recorded: switch to Live to move the clock." : "The clock only moves forward. A staged deletion purges at exactly 24 hours; connected stores re-synchronise each time it crosses 02:00."}</p>
    </section>
  );
}
