import { visible } from "../safeText";

// Mock only: the scripted scenarios the tables were recorded from, with every step and its result.
export default function ScenarioBar({ lab, scenarioId, setScenarioId }) {
  if (!lab.scenario) return null;
  const sc = lab.scenario;
  return (
    <section className="panel" data-testid="scenarios" aria-label="Scripted scenarios">
      <h2 className="panel__title">Scripted scenarios (recorded as {sc.actor})</h2>
      <div className="seg" role="group" aria-label="Scenario">{lab.scenarios.map((s) => <button key={s.id} type="button" aria-pressed={sc.id === s.id} onClick={() => setScenarioId(s.id)} data-testid={`scn-${s.id}`}>{s.title}</button>)}</div>
      <p className="lesson">{sc.say}</p>
      <ol className="plain" data-testid="scenario-steps">{sc.steps.map((st, i) => <li key={i}><strong>{st.actor}</strong>: {visible(st.say)} <span className="tag" data-state={st.result.ok ? "ok" : "warn"}>{st.result.ok ? "done" : `refused: ${st.result.code}`}</span></li>)}</ol>
      <p className="muted">The tabs below show the end of this scenario. Switch to Live to act yourself.</p>
    </section>
  );
}
