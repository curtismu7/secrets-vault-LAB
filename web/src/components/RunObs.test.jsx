// The lab's own states around the shared panel: loading (never the previous record), empty, an alert for any answer that is not a record, the mode
// the record was made in, and no request when nothing changed. fetch is replaced by a script; the real route is exercised by the server tests and App.test.jsx.
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, render, screen, waitFor } from "@testing-library/react";
import RunObs from "./RunObs";
import { setJsonView } from "./JsonPane.jsx";
import { mockRecord, realRecord } from "../run-observability/fixtures";

const realFetch = globalThis.fetch;
let calls = [];
let answers = {};
const ok = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
beforeEach(() => {
  setJsonView("raw"); calls = []; answers = {};
  globalThis.fetch = vi.fn(async (url) => {
    calls.push(String(url));
    const a = answers[String(url)] ?? answers["*"];
    if (typeof a === "function") return a();
    if (a instanceof Error) throw a;
    return a ?? ok({ record: null, message: "no answer scripted" });
  });
});
afterEach(() => { cleanup(); globalThis.fetch = realFetch; });

const MOCK_URL = "/api/run-observability?vertical=finance&scenario=own-vault";
const gate = () => { let open; const p = new Promise((r) => { open = r; }); return { p, open }; };

describe("Mock", () => {
  it("shows the panel for the recorded scenario, says what the lanes hold, and asks once", async () => {
    answers[MOCK_URL] = ok({ record: mockRecord });
    const { rerender } = render(<RunObs source="mock" vertical="finance" scenarioId="own-vault" check={{ phase: "checking" }} />);
    expect(screen.getByTestId("ro-loading")).toHaveTextContent("Collecting this run's logs");
    await screen.findByTestId("run-observability");
    expect(screen.getByTestId("ro-basis")).toHaveTextContent(/Simulated/);
    expect(screen.getByTestId("ro-lab-note")).toHaveTextContent(/lab has no sign-in.*simulated agent tool.*lab's own grant table.*injects the caller's own credential.*information, not a decision/s);
    expect(screen.getByTestId("ro-lab-note")).toHaveTextContent(/audit trail \(Governance\) can hold a refused entry for a step the scenario list shows as refused.*only the gateway calls and the grant table's decisions/s);
    expect(screen.getByTestId("ro-streams")).toHaveTextContent(/Mock reads recorded tables and writes none/);
    expect(screen.queryByText(/Re-read/)).toBeNull();
    // a re-render with the same run (a poll, a state refresh) asks nothing new
    rerender(<RunObs source="mock" vertical="finance" scenarioId="own-vault" check={{ phase: "done", runId: "gw-1" }} />);
    await new Promise((r) => setTimeout(r, 30));
    expect(calls).toEqual([MOCK_URL]);
  });

  it("waits for the scenario instead of asking for none, and never shows the previous scenario while the next one loads", async () => {
    answers[MOCK_URL] = ok({ record: mockRecord });
    const second = gate();
    answers["/api/run-observability?vertical=finance&scenario=staged-delete"] = () => second.p.then(() => ok({ record: { ...mockRecord, runId: "table-finance-staged-delete" } }));
    const { rerender } = render(<RunObs source="mock" vertical="finance" scenarioId={undefined} check={{ phase: "checking" }} />);
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(calls).toEqual([]);
    rerender(<RunObs source="mock" vertical="finance" scenarioId="own-vault" check={{ phase: "checking" }} />);
    await screen.findByTestId("run-observability");
    rerender(<RunObs source="mock" vertical="finance" scenarioId="staged-delete" check={{ phase: "checking" }} />);
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    second.open();
    await screen.findByTestId("run-observability");
    expect(calls).toHaveLength(2);
  });

  it("a route answer that is not a record is an alert: an HTTP error, a body that is not JSON, an answer without a record, an unreachable lab", async () => {
    for (const [a, text] of [
      [ok({ error: "unknown_scenario", message: "there is no such scenario in this pack" }, 404), /there is no such scenario in this pack/],
      [{ ok: false, status: 502, json: async () => { throw new Error("html"); } }, /The lab answered 502/],
      [ok({ nothing: true }), /not a run record/],
      [new TypeError("fetch failed"), /Could not reach the lab \(fetch failed\)/],
    ]) {
      answers[MOCK_URL] = a;
      const { unmount } = render(<RunObs source="mock" vertical="finance" scenarioId="own-vault" check={{ phase: "checking" }} />);
      expect(await screen.findByRole("alert")).toHaveTextContent(text);
      expect(screen.queryByTestId("ro-table")).toBeNull();
      unmount();
    }
  });

  it("a record made in the other mode is refused on screen (the server's mode and the page's differ)", async () => {
    answers[MOCK_URL] = ok({ record: realRecord });
    render(<RunObs source="mock" vertical="finance" scenarioId="own-vault" check={{ phase: "checking" }} />);
    expect(await screen.findByTestId("ro-mismatch")).toHaveTextContent(/real mode but the page is in mock mode/);
  });
});

describe("Real", () => {
  it("waits for the page's gateway check: nothing is asked and nothing older is shown while it runs", async () => {
    render(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "checking" }} />);
    expect(screen.getByTestId("ro-loading")).toHaveTextContent("Collecting this run's logs");
    await new Promise((r) => setTimeout(r, 30));
    expect(calls).toEqual([]);
  });

  it("asks for THAT check's run, shows it as real, and shows loading (not the old record) when the next check has a new run id", async () => {
    answers["/api/run-observability?runId=gw-1"] = ok({ record: { ...realRecord, runId: "gw-1" } });
    const next = gate();
    answers["/api/run-observability?runId=gw-2"] = () => next.p.then(() => ok({ record: { ...realRecord, runId: "gw-2" } }));
    const { rerender } = render(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "done", runId: "gw-1" }} />);
    await screen.findByTestId("run-observability");
    expect(screen.getByTestId("ro-basis")).toHaveTextContent(/Real:/);
    expect(screen.getByTestId("ro-lab-note")).toHaveTextContent(/only the hop to the Privilege gateway.*not a log line.*vault, the grant table and the backend stay in the lab's own engine/s);
    rerender(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "checking" }} />);
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    rerender(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "done", runId: "gw-2" }} />);
    expect(screen.getByTestId("ro-loading")).toBeInTheDocument(); expect(screen.queryByTestId("run-observability")).toBeNull();
    next.open();
    await screen.findByTestId("run-observability");
    expect(calls).toEqual(["/api/run-observability?runId=gw-1", "/api/run-observability?runId=gw-2"]);
  });

  it("a check that never reached the gateway made no run: it says so, asks nothing, and shows no older record", async () => {
    answers["/api/run-observability?runId=gw-1"] = ok({ record: { ...realRecord, runId: "gw-1" } });
    const { rerender } = render(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "done", runId: "gw-1" }} />);
    await screen.findByTestId("run-observability");
    rerender(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "error", reason: "the lab answered 409" }} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/did not complete.*no older one is shown in its place.*409/s);
    expect(screen.queryByTestId("run-observability")).toBeNull();
    rerender(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "not-configured", reason: "Real needs the gateway settings." }} />);
    expect(screen.getByTestId("ro-no-run")).toHaveTextContent(/No gateway call was made.*Real needs the gateway settings/s);
    rerender(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "done", runId: null }} />);
    expect(screen.getByRole("alert")).toHaveTextContent(/did not keep a record/);
    expect(calls).toHaveLength(1);
  });

  it("a run the lab no longer keeps is a note, not a record", async () => {
    answers["/api/run-observability?runId=gw-9"] = ok({ record: null, message: "That gateway check is no longer kept (the lab keeps the last few)." });
    render(<RunObs source="real" vertical="finance" scenarioId={undefined} check={{ phase: "done", runId: "gw-9" }} />);
    expect(await screen.findByTestId("ro-no-run")).toHaveTextContent(/no longer kept/);
    await waitFor(() => expect(calls).toHaveLength(1));
  });
});
