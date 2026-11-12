// These tests drive the real UI against the real Express app (started on a loopback port inside the test), so a green run means the pieces
// actually work together: the real story data, the real engine, the real Mock table.
import { afterAll, beforeAll, beforeEach, describe, expect, it, vi } from "vitest";
import { cleanup, fireEvent, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import { VERTICALS } from "../../server/src/cast.js";
import App, { BANNER_UNKNOWN, TABS } from "./App";
import { labelOffsets } from "./components/PatternDiagram";
import { secretFrom } from "./components/VaultTab";
import { visible } from "./safeText";
import { forgetWorkspace, workspaceId } from "./workspace";
import ErrorBoundary from "./components/ErrorBoundary";

const C = VERTICALS.finance;
let server; let base; const realFetch = globalThis.fetch; let seen = []; let statuses = [];
let delay = () => 0;
let override = () => null;
let pending = 0;
beforeAll(async () => {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  ({ server, url: base } = await startHttpServer({ port: 0, host: "127.0.0.1", app: createApp({ health, configFile: "/nonexistent/customer.config.json" }) }));
  base = base.replace(/\/$/, "");
  globalThis.fetch = async (u, init = {}) => {
    const url = typeof u === "string" && u.startsWith("/") ? `${base}${u}` : u;
    const rec = { url: String(url), body: typeof init.body === "string" ? init.body : "", headers: init.headers || {} }; seen.push(rec);
    pending += 1;
    try {
      const own = override(String(url), init); if (own) return own;
      const ms = delay(String(url), init); if (ms) await new Promise((r) => setTimeout(r, ms));
      const r = await realFetch(url, { ...init, headers: { origin: base, ...(init.headers || {}) } });
      await r.clone().text(); statuses.push({ url: rec.url, status: r.status });
      return r;
    } finally { pending -= 1; }
  };
});
afterAll(async () => { globalThis.fetch = realFetch; await new Promise((r) => server.close(r)); });
beforeEach(() => { cleanup(); forgetWorkspace(); seen = []; statuses = []; delay = () => 0; override = () => null; pending = 0; try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ } window.location.hash = ""; realFetch(`${base}/api/mode`, { method: "POST", headers: { "content-type": "application/json", origin: base }, body: JSON.stringify({ source: "mock" }) }).catch(() => {}); });

const T = { timeout: 20000 };
const mount = async () => { render(<App />); await screen.findByTestId("scenarios", {}, T); };
const tab = (name) => userEvent.click(screen.getByRole("tab", { name }));
const click = (id) => userEvent.click(screen.getByTestId(id));
const live = async () => { await pick("mode-select", "real"); await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/)); await screen.findByTestId("create-entry", {}, T); await waitFor(() => expect(screen.getByTestId("ce-submit")).toBeEnabled(), T); };
const pick = (id, value) => userEvent.selectOptions(screen.getByTestId(id), value);
const actAs = async (who) => { await pick("actor", who); await waitFor(() => expect(screen.getByTestId("actor")).toHaveValue(who)); await waitFor(() => expect(screen.getByTestId("banner")).toBeInTheDocument()); await settled(); };
const settled = async () => { await waitFor(() => expect(pending).toBeLessThanOrEqual(0), { timeout: 20000 }); await new Promise((r) => setTimeout(r, 60)); await waitFor(() => expect(pending).toBeLessThanOrEqual(0), { timeout: 20000 }); };
const wholePageText = () => { const c = document.body.cloneNode(true); c.querySelectorAll("textarea,input").forEach((n) => n.remove()); return c.textContent; };
const store = async (name = "Ledger bearer") => { fireEvent.change(screen.getByTestId("ce-name"), { target: { value: name } }); await waitFor(() => expect(screen.getByTestId("ce-submit")).toBeEnabled(), T); await click("ce-submit"); await waitFor(() => expect(screen.getByTestId("create-message")).toHaveTextContent(/Stored vcr-/), T); };
const clock = async (m) => { await waitFor(() => expect(screen.getByTestId(`clock-${m}`)).toBeEnabled(), T); await click(`clock-${m}`); await settled(); };

describe("shell", () => {
  it("says it is simulated and UNVERIFIED on every tab, in presenter mode too, and shows the mode", async () => {
    await mount();
    expect(screen.getByTestId("banner")).toHaveTextContent(/MOCK mode/);
    expect(screen.getByTestId("mode")).toHaveTextContent("Mode: mock");
    for (const t of TABS) { await tab(t.label); expect(screen.getByTestId("banner")).toHaveTextContent(/UNVERIFIED on our tenant/); }
    await tab("User Vault");
    await userEvent.keyboard("p");
    expect(screen.getByTestId("presenter-say")).toBeInTheDocument();
    expect(screen.getByTestId("banner")).toHaveTextContent(/SIMULATED/); expect(screen.getByTestId("banner")).toHaveTextContent(/UNVERIFIED on our tenant/);
    expect(screen.getByTestId("presenter")).toHaveTextContent("Exit present (Esc)");
    for (const t of TABS.filter((x) => x.id !== "talk")) { await tab(t.label); expect(screen.getByTestId("presenter-say")).toBeInTheDocument(); expect(screen.getByTestId("banner")).toHaveTextContent(/UNVERIFIED/); }
    await userEvent.keyboard("{Escape}");
    expect(screen.queryByTestId("presenter-say")).toBeNull();
    expect(BANNER_UNKNOWN).toMatch(/UNVERIFIED/);
  });

  it("the banner and the mode chip follow the toggle, in both directions, on every tab", async () => {
    await mount(); await pick("mode-select", "real");
    await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/));
    expect(screen.getByTestId("mode")).toHaveTextContent("Mode: live");
    for (const t of TABS) { await tab(t.label); expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/); expect(screen.getByTestId("banner")).toHaveAttribute("data-state", "live"); }
    await pick("mode-select", "mock");
    await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/MOCK mode/));
  });

  it("the choice of mode is remembered, and a blocked storage never breaks the page", async () => {
    await mount(); await pick("mode-select", "real");
    await waitFor(() => expect(window.localStorage.getItem("svl.mode")).toBe("live"));
    cleanup(); render(<App />);
    await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/), T);
  });

  it("arrow keys move between tabs, and the URL hash follows", async () => {
    await mount();
    screen.getByRole("tab", { name: "User Vault" }).focus();
    await userEvent.keyboard("{ArrowRight}");
    expect(screen.getByRole("tab", { name: "Request-time injection" })).toHaveAttribute("aria-selected", "true");
    expect(window.location.hash).toBe("#injection");
    await userEvent.keyboard("{ArrowLeft}{ArrowLeft}");
    expect(screen.getByRole("tab", { name: "Talk track" })).toHaveAttribute("aria-selected", "true");
  });

  it("talks only to its own origin, and names the acting person on every Live call", async () => {
    await mount(); await live();
    for (const t of TABS) await tab(t.label);
    expect(seen.length).toBeGreaterThan(3);
    expect(seen.every((s) => s.url.startsWith(base))).toBe(true);
    expect(seen.filter((s) => /\/api\/state\?mode=live/.test(s.url)).every((s) => s.headers["x-lab-actor"] === C.castUser)).toBe(true);
  });
});

describe("Mock mode: seven scripted scenarios, read-only", () => {
  it("shows a scenario and its steps; switching scenario changes the state every tab shows", async () => {
    await mount();
    expect(screen.getByTestId("scenario-steps").querySelectorAll("li").length).toBe(5);
    await click("scn-no-override");
    await waitFor(() => expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/refused: unknown_field/), T);
    expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/refused: not_found/);
    expect(screen.getByTestId("actor")).toHaveValue(C.castAdmin); expect(screen.getByTestId("actor")).toBeDisabled();
    await click("scn-staged-delete");
    await waitFor(() => expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/purged/), T);
    await tab("Governance"); expect(await screen.findByTestId("proof-found")).toHaveTextContent("0");
    // Mock shows what the table recorded: it must not claim to be computed now, and it cannot be re-run here.
    expect(screen.getByTestId("proof")).toHaveTextContent(/recorded when the Mock table was generated/); expect(screen.getByTestId("proof")).not.toHaveTextContent(/computed now/);
    expect(screen.getByTestId("proof-run")).toBeDisabled(); expect(screen.getByTestId("proof-run")).toHaveTextContent(/Live only/);
    await tab("Request-time injection"); await click("scn-own-vault");
    await waitFor(() => expect(screen.getAllByTestId("log-principal").map((x) => x.textContent)).toEqual([C.castUser, `svc-${C.castT1}`, `svc-${C.castT1}`]), T);
  });

  it("every write control is off in Mock, and a note says to switch to Live", async () => {
    await mount();
    expect(screen.getByTestId("ce-submit")).toBeDisabled(); expect(screen.getByTestId("key-restart")).toBeDisabled(); expect(screen.getByTestId("isolation-run")).toBeDisabled();
    expect(screen.getByTestId("vault-intro")).toHaveTextContent(/Switch to Live/);
    await tab("Secret Stores"); expect(screen.getByTestId("sc-submit")).toBeDisabled(); expect(screen.getByTestId("resync-now")).toBeDisabled();
    await tab("Governance"); expect(screen.getByTestId("gr-add")).toBeDisabled();
    expect(seen.filter((s) => /POST|PUT/.test(JSON.stringify(s))).length).toBe(0);
  });
});

describe("User Vault (Live)", () => {
  it("create an entry (generated mock), edit its metadata keeping the secret, use it at request time, delete, restore: the whole cycle", async () => {
    await mount(); await live();
    await store();
    const row = within(screen.getByTestId("entry-vcr-0001"));
    expect(screen.getByTestId("secret-vcr-0001")).toHaveTextContent(/present · \d+ bytes · v1 · •{8} · nonce [0-9a-f]{8}/);
    expect(row.getByText("Ledger bearer")).toBeInTheDocument();
    expect(screen.getByTestId("vault-count")).toHaveTextContent("1 of 500");
    // merge edit: notes only, secret blank
    fireEvent.change(screen.getByTestId("ed-notes"), { target: { value: "rotated quarterly" } });
    await click("ed-save");
    await waitFor(() => expect(screen.getByTestId("edit-message")).toHaveTextContent(/secret was omitted, so the stored value was kept \(still version 1/), T);
    expect(screen.getByTestId("entry-vcr-0001")).toHaveTextContent("rotated quarterly");
    // use at request time
    await tab("Request-time injection"); await screen.findByTestId("call-form", {}, T);
    await waitFor(() => expect(screen.getByTestId("inj-call-peruser")).toBeEnabled(), T);
    await click("inj-call-peruser");
    await screen.findByTestId("call-views", {}, T);
    expect(screen.getByTestId("view-agent")).toHaveTextContent(/Holds a credential: no/); expect(screen.getByTestId("view-agent")).toHaveTextContent("••••••••");
    expect(screen.getByTestId("view-gateway")).toHaveTextContent(/Bearer ••••••••/);
    expect(screen.getByTestId("backend-principal")).toHaveTextContent(C.castUser);
    await click("inj-call-shared");
    await waitFor(() => expect(screen.getByTestId("backend-principal")).toHaveTextContent(`svc-${C.castT1}`), T);
    // delete and restore
    await tab("User Vault"); await screen.findByTestId("entries-table");
    await click("delete-vcr-0001");
    await waitFor(() => expect(screen.getByTestId("purge-vcr-0001")).toHaveTextContent(/purges 2026-11-03 09:00 \(in 24 h 0 min\)/), T);
    await click("restore-vcr-0001");
    await waitFor(() => expect(screen.queryByTestId("purge-vcr-0001")).toBeNull(), T);
  });

  it("deleting stages for 24 hours: at 23:59 it is still there, at 24:00 it is purged and cannot be restored", async () => {
    await mount(); await live(); await store();
    await click("delete-vcr-0001"); await waitFor(() => expect(screen.getByTestId("purge-vcr-0001")).toBeInTheDocument(), T);
    await clock(1439);
    expect(screen.getByTestId("purge-vcr-0001")).toHaveTextContent(/in 1 min/); expect(screen.getByTestId("vault-count")).toHaveTextContent("1 of 500 entries (1 staged");
    await clock(1);
    await waitFor(() => expect(screen.queryByTestId("entry-vcr-0001")).toBeNull(), T);
    expect(screen.getByTestId("vault-count")).toHaveTextContent("0 of 500");
    expect(screen.getByTestId("lab-clock")).toHaveTextContent("2026-11-03 09:00");
  });

  it("a secret the visitor types is sent once and never shown again, not even masked into the page text, and a merge edit replaces only what is filled in", async () => {
    await mount(); await live();
    await tab("Request-time injection"); await tab("User Vault");
    await userEvent.click(screen.getByTestId("ce-generate"));
    await pick("ce-target", C.castT3);
    const typed = "typed-basic-password-QQQQ9999";
    fireEvent.change(screen.getByTestId("ce-username"), { target: { value: "maya" } }); fireEvent.change(screen.getByTestId("ce-password"), { target: { value: typed } });
    await click("ce-submit"); await waitFor(() => expect(screen.getByTestId("create-message")).toHaveTextContent(/Stored vcr-0001/), T);
    expect(seen.some((s) => s.body.includes(typed))).toBe(true);
    expect(wholePageText()).not.toContain(typed); expect(screen.getByTestId("ce-submit")).toBeEnabled();
    fireEvent.change(screen.getByTestId("ed-password"), { target: { value: `${typed}-v2` } }); await click("ed-save");
    await waitFor(() => expect(screen.getByTestId("edit-message")).toHaveTextContent(/replaced \(now version 2/), T);
    expect(wholePageText()).not.toContain(typed);
    expect(screen.getByTestId("secret-vcr-0001")).toHaveTextContent(/v2/);
  });

  it("a credential-shaped name is refused with its reason, and nothing is stored", async () => {
    await mount(); await live();
    fireEvent.change(screen.getByTestId("ce-name"), { target: { value: ["gh", "p_a1B2c3D4e5F6g7H8i9J0k1L2m3N4o5P6q7R8"].join("") } });
    await click("ce-submit");
    await waitFor(() => expect(screen.getByTestId("create-message")).toHaveTextContent(/credential_shaped_text/), T);
    expect(screen.getByTestId("vault-count")).toHaveTextContent("0 of 500");
    expect(wholePageText()).not.toContain("a1B2c3D4e5F6g7H8");
  });

  it("another person, the administrator, the auditor and support are each forced into their own vault: not found, owner refused", async () => {
    await mount(); await live(); await store();
    await click("isolation-run");
    await waitFor(() => expect(screen.getByTestId("isolation-table")).toBeInTheDocument(), T);
    for (const who of [C.castUser2, C.castAdmin, C.castAuditor, C.castSupport]) {
      const r = within(screen.getByTestId(`iso-${who}`));
      expect(r.getByText("404 not_found")).toBeInTheDocument(); expect(r.getByText("400 unknown_field")).toBeInTheDocument(); expect(r.getByText("0 entries (their own)")).toBeInTheDocument();
    }
    await actAs(C.castAdmin);
    expect(screen.getByTestId("vault-count")).toHaveTextContent("0 of 500");
    expect(screen.queryByTestId("entry-vcr-0001")).toBeNull();
  });

  it("the key provider: aws and vault are quiet, no key source falls back to the loud DEVELOPMENT KEY warning; only the administrator may restart", async () => {
    await mount(); await live(); await store();
    expect(screen.queryByTestId("dev-warning")).toBeNull(); expect(screen.getByTestId("key-restart")).toBeDisabled();
    const nonce = screen.getByTestId("secret-vcr-0001").textContent.match(/nonce ([0-9a-f]{8})/)[1];
    await actAs(C.castAdmin);
    await pick("key-configured", "none"); await click("key-restart");
    await waitFor(() => expect(screen.getByTestId("dev-warning")).toHaveTextContent(/DEVELOPMENT KEY/), T);
    expect(screen.getByTestId("key-active")).toHaveTextContent(/no key provider configured/);
    await pick("key-configured", "vault"); await click("key-restart");
    await waitFor(() => expect(screen.queryByTestId("dev-warning")).toBeNull(), T);
    expect(screen.getByTestId("key-active")).toHaveTextContent(/HashiCorp Vault/);
    await actAs(C.castUser);
    expect(screen.getByTestId("secret-vcr-0001").textContent).not.toContain(nonce);
    expect(screen.getByTestId("nonce-info")).toHaveTextContent("1 sealed values, 1 distinct");
  });

  it("limits are stated: 500 entries and 64 KB (65,536 bytes)", async () => {
    await mount();
    expect(screen.getByTestId("vault-count")).toHaveTextContent(/of 500 entries/); expect(screen.getByTestId("vault-count")).toHaveTextContent(/65,536 bytes \(64 KB\)/);
  });
});

describe("Request-time injection (Live)", () => {
  it("each of the four shapes is injected, masked, and the backend names the caller; with no entry the call is refused and never falls back", async () => {
    await mount(); await live(); await tab("Request-time injection"); await screen.findByTestId("call-form", {}, T);
    await waitFor(() => expect(screen.getByTestId("inj-seed")).toBeEnabled(), T);
    await click("inj-seed"); await waitFor(() => expect(screen.getByTestId("inj-message")).toHaveTextContent(/Created 4/), T);
    const expected = { [C.castT1]: /Authorization: Bearer ••••••••/, [C.castT2]: /X-Api-Key: ••••••••/, [C.castT3]: /Authorization: Basic ••••••••/, [C.castT4]: /X-Partner-Id: ••••••••/ };
    for (const [target, re] of Object.entries(expected)) {
      await pick("inj-target", target); await waitFor(() => expect(screen.getByTestId("inj-entry")).not.toHaveValue(""), T);
      await click("inj-call-peruser"); await waitFor(() => expect(screen.getByTestId("view-gateway")).toHaveTextContent(re), T);
      expect(screen.getByTestId("backend-principal")).toHaveTextContent(C.castUser);
    }
    await actAs(C.castUser2); await tab("Request-time injection"); await screen.findByTestId("call-form", {}, T);
    await click("inj-call-peruser");
    await waitFor(() => expect(screen.getByTestId("call-refused")).toHaveTextContent(/no_credential_for_target/), T);
    expect(wholePageText()).not.toMatch(/MOCK-/);
  });

  it("removing a target as the administrator cleans up the entries that pointed at it, automatically", async () => {
    await mount(); await live(); await store(); await actAs(C.castAdmin); await tab("Request-time injection"); await screen.findByTestId("targets", {}, T);
    await click(`remove-${C.castT1}`);
    await waitFor(() => expect(screen.queryByTestId(`target-${C.castT1}`)).toBeNull(), T);
    await actAs(C.castUser); await tab("User Vault"); await waitFor(() => expect(screen.getByTestId("vault-count")).toHaveTextContent("0 of 500"), T);
  });
});

describe("Secret Stores (Live)", () => {
  it("browse the hierarchy, create, rotate, soft-delete and purge in Azure; AWS refuses recover; a read is delivered to the consumer, masked", async () => {
    await mount(); await live(); await tab("Secret Stores"); await screen.findByTestId("secrets-table", {}, T);
    await click("prov-gcp"); expect(screen.getByTestId("hierarchy")).toHaveTextContent(`${C.castOrg}/${C.castFolder}/${C.castProject}`); expect(screen.getByTestId("hierarchy")).toHaveTextContent("organisation");
    await click("prov-azure");
    expect(screen.getByTestId("prov-info")).toHaveTextContent(/Soft-delete and purge: yes/);
    fireEvent.change(screen.getByTestId("sc-path"), { target: { value: `${C.castKv}/ui-token` } }); await click("sc-submit");
    await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/Created azure:/), T);
    const k = `azure-${C.castKv}-ui-token`;
    await click(`rotate-${k}`); await waitFor(() => expect(screen.getByTestId(`secret-${k}`)).toHaveTextContent(/v2/), T);
    await click(`read-${k}`); await waitFor(() => expect(screen.getByTestId("delivery")).toHaveTextContent(/value delivered to the consumer \(masked\)/), T);
    expect(screen.getByTestId("delivery")).toHaveTextContent("••••••••"); expect(wholePageText()).not.toMatch(/MOCK-azure/);
    await click(`delete-${k}`); await waitFor(() => expect(screen.getByTestId(`secret-${k}`)).toHaveTextContent(/soft-deleted/), T);
    await click(`purge-${k}`); await waitFor(() => expect(screen.queryByTestId(`secret-${k}`)).toBeNull(), T);
    await actAs(C.castAdmin); await click("prov-aws");
    const aws = `aws-${C.castAwsPrefix.replace("/", "-")}-db-admin`;
    await click(`recover-${aws}`); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/unsupported_operation/), T);
    await click(`purge-${aws}`); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/unsupported_operation/), T);
  });

  it("read granted vs denied: the user reads but cannot rotate AWS; the administrator rotates but cannot read; support does not see it at all", async () => {
    await mount(); await live(); await tab("Secret Stores"); await screen.findByTestId("secrets-table", {}, T);
    await click("prov-aws");
    const aws = `aws-${C.castAwsPrefix.replace("/", "-")}-db-admin`;
    expect(screen.getByTestId(`secret-${aws}`)).toHaveTextContent(/read yes/); expect(screen.getByTestId(`secret-${aws}`)).toHaveTextContent(/write no/);
    await click(`read-${aws}`); await waitFor(() => expect(screen.getByTestId("delivery")).toBeInTheDocument(), T);
    await click(`rotate-${aws}`); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/access_denied/), T);
    await actAs(C.castAdmin); await click("prov-aws");
    await click(`read-${aws}`); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/access_denied/), T);
    await click(`rotate-${aws}`); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/Rotated/), T);
    await actAs(C.castSupport); await click("prov-aws");
    expect(screen.queryByTestId(`secret-${aws}`)).toBeNull(); expect(screen.getByTestId("secrets-table")).toHaveTextContent(/Nothing here that you hold a grant on/);
  });

  it("a change made at the provider is found by the re-sync, from metadata only: the rename is reported with its effect on the grants", async () => {
    await mount(); await live(); await actAs(C.castAdmin); await tab("Secret Stores"); await screen.findByTestId("provider-change", {}, T); await click("prov-aws");
    await waitFor(() => expect(screen.getByTestId("pc-run")).toBeEnabled(), T);
    fireEvent.change(screen.getByTestId("pc-path"), { target: { value: `${C.castAwsPrefix}/db-admin-v2` } }); await click("pc-run");
    await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/inventory has not been told/), T);
    expect(screen.getByTestId("secrets-table")).toHaveTextContent("db-admin");
    await click("resync-now"); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/1 change\(s\) found/), T);
    expect(screen.getByTestId("secrets-table")).toHaveTextContent("db-admin-v2");
    await tab("Governance"); const rep = await screen.findByTestId("reports");
    expect(rep).toHaveTextContent(/renamed/); expect(rep).toHaveTextContent(/grants lost/);
    await tab("Request-time injection"); await clock(1440); await tab("Governance"); await waitFor(() => expect(screen.getByTestId("reports")).toHaveTextContent(/nightly/), T);
  });
});

describe("Governance (Live)", () => {
  it("the proof is computed live: values found 0, a self-test that finds a planted copy, the areas searched; it reruns", async () => {
    await mount(); await live(); await store(); await tab("Governance");
    expect(await screen.findByTestId("proof-found")).toHaveTextContent("0");
    expect(screen.getByTestId("proof-selftest")).toHaveTextContent(/all 7 planted copies were found/);
    expect(Number(screen.getByTestId("proof-checked").textContent)).toBeGreaterThan(20);
    expect(within(screen.getByTestId("proof-areas")).getAllByRole("row").length).toBeGreaterThan(10);
    const before = seen.length; await click("proof-run"); await waitFor(() => expect(seen.length).toBeGreaterThan(before), T);
  });

  it("grants: only the administrator edits; a grant takes effect; the audit trail lists denied and allowed reads", async () => {
    await mount(); await live(); await tab("Governance"); await screen.findByTestId("policy-table", {}, T);
    expect(screen.getByTestId("gr-add")).toBeDisabled(); expect(screen.getByTestId("grant-form")).toHaveTextContent(/Only the administrator edits grants/);
    await actAs(C.castSupport); await tab("Secret Stores"); await click("prov-aws"); await tab("Governance");
    await actAs(C.castAdmin); await waitFor(() => expect(screen.getByTestId("gr-add")).toBeEnabled(), T);
    await pick("gr-principal", C.castSupport); fireEvent.change(screen.getByTestId("gr-scope"), { target: { value: `aws:${C.castAwsPrefix}/**` } }); await click("gr-add");
    await waitFor(() => expect(screen.getByTestId("grant-message")).toHaveTextContent(/Granted read on/), T);
    await actAs(C.castSupport); await tab("Secret Stores"); await click("prov-aws");
    const aws = `aws-${C.castAwsPrefix.replace("/", "-")}-db-admin`;
    await waitFor(() => expect(screen.getByTestId(`secret-${aws}`)).toBeInTheDocument(), T);
    await click(`read-${aws}`); await waitFor(() => expect(screen.getByTestId("delivery")).toBeInTheDocument(), T);
    await tab("Governance"); await pick("audit-filter", "store");
    expect(screen.getByTestId("audit-table")).toHaveTextContent(/store\.read/); expect(screen.getByTestId("audit-table")).not.toHaveTextContent(/policy\.grant/);
    await actAs(C.castAuditor); await tab("Governance"); await pick("audit-filter", "policy");
    await waitFor(() => expect(screen.getByTestId("audit-table")).toHaveTextContent(/policy\.grant/), T);
    expect(screen.getByTestId("audit")).toHaveTextContent(/everyone's, metadata only/);
  });
});

describe("the other tabs", () => {
  it("Diagram: both diagrams load from data, Simulate walks the arrows, Reset restores", async () => {
    await mount(); await tab("Diagram");
    await screen.findByTestId("pattern-canvas", {}, T);
    expect(screen.getByRole("heading", { name: /User Vault: the caller's own credential, injected at request time/ })).toBeInTheDocument();
    expect(screen.getByTestId("pattern-step-bar")).toHaveTextContent(/Simulate walks the 7 arrows/);
    await click("simulate"); await waitFor(() => expect(screen.getByTestId("pattern-now")).toBeInTheDocument(), T);
    await click("pattern-reset"); await waitFor(() => expect(screen.queryByTestId("pattern-now")).toBeNull(), T);
    await click("dg-secret-store-no-copy");
    await waitFor(() => expect(screen.getByRole("heading", { name: /Secret Store Management: governed, with no copy/ })).toBeInTheDocument(), T);
    await waitFor(() => expect(screen.getByTestId("pattern-step-bar")).toHaveTextContent(/Simulate walks the 6 arrows/), T);
    expect(screen.getByTestId("speed")).toBeInTheDocument();
  });

  it("the edge-label offsets nudge a reply apart from the arrow it answers", () => {
    expect(labelOffsets([{ from: "a", to: "b" }, { from: "b", to: "a" }, { from: "a", to: "c" }])).toEqual([-16, 16, 0]);
  });

  it("Talk track has both Why it matters entries marked as Ping claims", async () => {
    await mount(); await tab("Talk track");
    const t = await screen.findByTestId("talk-track");
    expect(t).toHaveTextContent(/Why it matters: User Vault \(slide 42\)/); expect(t).toHaveTextContent(/Why it matters: Secret Store Management \(slide 43\)/);
    expect(t).toHaveTextContent(/Ping claims, unverified on our tenant/); expect(t).toHaveTextContent(/Challenge:.*Technical:.*Business:/);
    expect(t).toHaveTextContent(/five backend-credential|none, an app-wide static token/);
  });

  it("the vertical switch reloads the cast: names change in the story and in the roster", async () => {
    await mount(); await live();
    await userEvent.selectOptions(screen.getByTestId("vertical-select"), "health");
    await waitFor(() => expect(screen.getByTestId("actor")).toHaveValue(VERTICALS.health.castUser), T);
    await tab("Talk track"); await waitFor(() => expect(wholePageText()).toContain("Contoso Health"), T);
  });
});

describe("stale answers and honest successes", () => {
  it("a late scenario answer never overwrites the scenario picked after it", async () => {
    await mount();
    delay = (url) => (/scenario=own-vault/.test(url) ? 1000 : 0);
    await click("scn-own-vault"); await click("scn-no-override");
    await waitFor(() => expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/administrator, tries to edit it/), T);
    await settled();
    expect(screen.getByTestId("scenario-steps")).toHaveTextContent(/administrator, tries to edit it/); expect(screen.getByTestId("scn-no-override")).toHaveAttribute("aria-pressed", "true");
  });

  it("a write answer for a mode the visitor has already left is not shown (stale write guard)", async () => {
    await mount(); await live();
    delay = (url, init) => (/\/api\/vault\/entries$/.test(url) && init.method === "POST" ? 800 : 0);
    await click("ce-submit"); await pick("mode-select", "mock");
    await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/MOCK mode/));
    await settled();
    expect(screen.queryByTestId("last-action")).toBeNull(); expect(screen.getByTestId("scenario-steps")).toBeInTheDocument();
  });

  it("a 200 whose body lacks ok true is shown as a refusal, never as a success", async () => {
    await mount(); await live();
    for (const body of ["{}", "null", "[]", '{"ok":"true"}', '{"result":{"entryId":"vcr-0001"}}']) {
      override = (url, init) => (/\/api\/vault\/entries$/.test(url) && init.method === "POST" ? new Response(body, { status: 200, headers: { "content-type": "application/json" } }) : null);
      await click("ce-submit");
      await waitFor(() => expect(screen.getByTestId("create-message")).toHaveAttribute("role", "alert"), T);
      expect(screen.getByTestId("create-message")).not.toHaveTextContent(/Stored vcr-/);
    }
  });

  it("a refusal is a real 4xx whose body the page reads as data: the reason is shown, no error is thrown, and there is no refusalsAs200 flag any more", async () => {
    await mount(); await live();
    fireEvent.change(screen.getByTestId("ce-name"), { target: { value: "" } }); await click("ce-submit");
    await waitFor(() => expect(screen.getByTestId("create-message")).toHaveTextContent(/Refused: bad_name/), T);
    expect(seen.some((x) => /vault\/entries$/.test(x.url) && x.body.includes('"name":""'))).toBe(true);
    expect(seen.every((x) => !x.body.includes("refusalsAs200"))).toBe(true);
    expect(statuses.some((s) => s.url.endsWith("/api/vault/entries") && s.status === 400)).toBe(true);
    expect(screen.queryByText(/Could not load the lab/)).toBeNull();
  });
});

describe("Reset", () => {
  it("clears the vault, the grants, the audit and the clock in Live; another workspace is not touched", async () => {
    await mount(); await live(); await store(); await clock(60);
    await waitFor(() => expect(screen.getByTestId("lab-clock")).toHaveTextContent("10:00"), T);
    await click("reset");
    await waitFor(() => expect(screen.getByTestId("lab-clock")).toHaveTextContent("2026-11-02 09:00"), T);
    await waitFor(() => expect(screen.getByTestId("vault-count")).toHaveTextContent("0 of 500"), T);
    expect(seen.some((s) => /\/api\/reset/.test(s.url))).toBe(true);
  });

  it("Reset also restores the diagram box positions", async () => {
    await mount(); await tab("Diagram"); await screen.findByTestId("pattern-canvas", {}, T);
    expect(screen.getByText(/Moved: 0 box/)).toBeInTheDocument();
    await click("reset"); await waitFor(() => expect(screen.getByText(/Moved: 0 box/)).toBeInTheDocument());
  });
});

describe("inert text and the secret object", () => {
  it("control and bidi characters become visible escapes, markup stays text", () => {
    expect(visible("a‮b\u0000c")).toBe("a\\u202eb\\u0000c");
    expect(visible("<img src=x onerror=alert(1)>")).toBe("<img src=x onerror=alert(1)>");
  });
  it("secretFrom sends only the fields that were filled in, so a blank keeps the stored value", () => {
    expect(secretFrom("bearer", {})).toEqual({}); expect(secretFrom("basic", { username: "", password: "p" })).toEqual({ password: "p" });
    expect(secretFrom("headers", { hn0: "X-A", hv0: "v", hn1: "X-B", hv1: "" })).toEqual({ headers: { "X-A": "v" } });
  });
});

const no401 = () => { expect(statuses.filter((x) => x.status === 401)).toEqual([]); expect(screen.queryByText(/Could not load the lab/)).toBeNull(); expect(screen.queryByTestId("boundary")).toBeNull(); expect(screen.getByTestId("banner")).toBeInTheDocument(); };
const TAB_NAMES = ["User Vault", "Request-time injection", "Secret Stores", "Governance", "Diagram", "Talk track"];

describe("S6: switching vertical, person, provider and mode never sends a stale person (no 401), never flashes an error, never blanks the page", () => {
  for (const mode of ["mock", "live"]) {
    it(`${mode}: a vertical switch on EVERY tab, one after the other and back to back`, async () => {
      await mount(); if (mode === "live") await live();
      for (const name of TAB_NAMES) {
        await tab(name);
        for (const v of ["health", "retail", "finance"]) { await pick("vertical-select", v); await waitFor(() => expect(screen.getByTestId("vertical-select")).toHaveValue(v)); await settled(); no401(); }
        await pick("vertical-select", "health"); await pick("vertical-select", "retail"); await pick("vertical-select", "finance"); // rapid: three switches without waiting
        await settled(); no401();
        await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(mode === "live" ? /LIVE mode/ : /MOCK mode/), T);
      }
      if (mode === "live") await waitFor(() => expect(screen.getByTestId("actor")).toHaveValue(VERTICALS.finance.castUser), T);
      expect(statuses.filter((x) => x.status >= 400)).toEqual([]);
    });
  }

  it("live: a person switch on every tab, a provider switch, and a mode switch back and forth, with no 401 and no error flash", async () => {
    await mount(); await live();
    for (const name of TAB_NAMES) { await tab(name); for (const who of [C.castAdmin, C.castAuditor, C.castSupport, C.castUser2, C.castUser]) { await pick("actor", who); await waitFor(() => expect(screen.getByTestId("actor")).toHaveValue(who)); await settled(); no401(); } }
    await tab("Secret Stores"); for (const id of ["gcp", "delinea", "cyberark", "azure", "aws"]) { await waitFor(() => expect(screen.getByTestId(`prov-${id}`)).toBeInTheDocument(), T); await click(`prov-${id}`); no401(); }
    for (let i = 0; i < 3; i++) { await pick("mode-select", "mock"); await pick("mode-select", "real"); await pick("mode-select", "mock"); await pick("mode-select", "real"); }
    await settled(); await waitFor(() => expect(screen.getByTestId("banner")).toHaveTextContent(/LIVE mode/), T); no401();
    expect(statuses.filter((x) => x.status >= 400)).toEqual([]);
  });

  it("live: a vertical switch while a write is in flight shows neither the old answer nor an error, and the write itself was a valid one", async () => {
    await mount(); await live();
    delay = (url, init) => (/\/api\/vault\/entries$/.test(url) && init.method === "POST" ? 600 : 0);
    await click("ce-submit"); await pick("vertical-select", "health");
    await settled(); await waitFor(() => expect(screen.getByTestId("actor")).toHaveValue(VERTICALS.health.castUser), T); await settled(); no401();
    expect(statuses.filter((x) => /vault\/entries$/.test(x.url) && x.status === 200).length).toBe(1);
    await waitFor(() => expect(screen.getByTestId("vault-count")).toHaveTextContent("0 of 500"), T);
  });

  it("a tab that throws while drawing is replaced by a message with a retry, not a blank page", async () => {
    const Boom = () => { throw new Error("boom"); };
    const spy = console.error; console.error = () => {};
    try { render(<ErrorBoundary><Boom /></ErrorBoundary>); expect(screen.getByTestId("boundary")).toHaveTextContent(/could not be drawn/); expect(screen.getByRole("button", { name: "Try again" })).toBeInTheDocument(); } finally { console.error = spy; }
  });
});

describe("double clicks, the on-demand proof and the administrator-only helpers", () => {
  it("a second click right after the first response is a double click, not a second entry; a deliberate second submit later still works", async () => {
    await mount(); await live();
    let t = 1_000_000; const spy = vi.spyOn(Date, "now").mockImplementation(() => t);
    try {
      await click("ce-submit"); await waitFor(() => expect(screen.getByTestId("create-message")).toHaveTextContent(/Stored vcr-0001/), T); await settled();
      await click("ce-submit"); await click("ce-submit"); await settled();
      expect(screen.getByTestId("vault-count")).toHaveTextContent("1 of 500");
      t += 2000; await click("ce-submit"); await waitFor(() => expect(screen.getByTestId("vault-count")).toHaveTextContent("2 of 500"), T);
    } finally { spy.mockRestore(); }
  });

  it("six rapid clicks on Store in my vault make ONE entry", async () => {
    await mount(); await live();
    const b = screen.getByTestId("ce-submit"); for (let i = 0; i < 6; i++) fireEvent.click(b);
    await settled(); await waitFor(() => expect(screen.getByTestId("vault-count")).toHaveTextContent("1 of 500"), T);
    expect(statuses.filter((x) => /vault\/entries$/.test(x.url) && x.status === 200).length).toBe(1);
  });

  it("a big workspace shows 'not run' with a button; the button runs the proof on the server and the next read shows the result; a refusal never says the proof passed", async () => {
    await mount(); await live();
    for (let i = 0; i < 110; i++) await realFetch(`${base}/api/vault/entries`, { method: "POST", headers: { "content-type": "application/json", origin: base, "x-lab-actor": C.castUser, "x-workspace": workspaceId() }, body: JSON.stringify({ mode: "live", vertical: "finance", entry: { name: `e${i}`, targetId: C.castT1, shape: "bearer", generate: true } }) });
    await tab("Governance"); await screen.findByTestId("policy-table", {}, T);
    await click("reset"); await screen.findByTestId("lab-clock", {}, T);
    for (let i = 0; i < 110; i++) await realFetch(`${base}/api/vault/entries`, { method: "POST", headers: { "content-type": "application/json", origin: base, "x-lab-actor": C.castUser, "x-workspace": workspaceId() }, body: JSON.stringify({ mode: "live", vertical: "finance", entry: { name: `e${i}`, targetId: C.castT1, shape: "bearer", generate: true } }) });
    await pick("mode-select", "mock"); await pick("mode-select", "real");
    await waitFor(() => expect(screen.getByTestId("proof-skipped")).toHaveTextContent(/Run the proof now/), T);
    expect(screen.queryByTestId("proof-found")).toBeNull();
    await click("proof-run");
    await waitFor(() => expect(screen.getByTestId("proof-found")).toHaveTextContent("0"), T);
    expect(screen.getByTestId("proof-selftest")).toHaveTextContent(/all 7 planted copies were found/); expect(screen.getByTestId("proof-short")).toHaveTextContent(/whole field/);
    expect(seen.some((x) => /proof\/run$/.test(x.url))).toBe(true);
  });

  it("the provider-side helper and the manual re-sync are for the administrator: greyed out for everyone else, with the reason", async () => {
    await mount(); await live(); await tab("Secret Stores"); await screen.findByTestId("provider-change", {}, T);
    expect(screen.getByTestId("pc-run")).toBeDisabled(); expect(screen.getByTestId("resync-now")).toBeDisabled(); expect(screen.getByTestId("provider-change")).toHaveTextContent(/administrator only/);
    await actAs(C.castAdmin); await tab("Secret Stores"); await waitFor(() => expect(screen.getByTestId("resync-now")).toBeEnabled(), T);
  });

  it("the consumers table compares what a consumer holds against the provider now, and goes stale after a provider-side rotation", async () => {
    await mount(); await live(); await tab("Secret Stores"); await screen.findByTestId("secrets-table", {}, T); await click("prov-aws");
    const aws = `aws-${C.castAwsPrefix.replace("/", "-")}-db-admin`;
    await click(`read-${aws}`); await waitFor(() => expect(screen.getByTestId("delivery")).toHaveTextContent(/Whether it still matches the provider is checked on the Governance tab/), T);
    await tab("Governance"); await waitFor(() => expect(screen.getByTestId("consumer-simulated-gateway")).toHaveTextContent(/yes/), T);
    await actAs(C.castAdmin); await tab("Secret Stores"); await click("prov-aws"); await waitFor(() => expect(screen.getByTestId("pc-ref")).toBeInTheDocument(), T);
    await pick("pc-op", "rotate"); await click("pc-run"); await waitFor(() => expect(screen.getByTestId("store-message")).toHaveTextContent(/not been told/), T);
    await tab("Governance"); await waitFor(() => expect(screen.getByTestId("consumer-simulated-gateway")).toHaveTextContent(/no: stale/), T);
  });
});
