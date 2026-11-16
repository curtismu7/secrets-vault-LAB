// The header shows this lab's own Verified / In progress mark, read from the same /api/shelf call the Shelf link makes (through the lab-proxy that
// call reaches the shelf, whose payload lists every demo with its mark). The lab's own /api/shelf has no demos, so there is no mark then.
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { cleanup, render, screen, within } from "@testing-library/react";
import { createApp, startHttpServer } from "../../server/src/app.js";
import { createHealth } from "../../server/src/health.js";
import App from "./App.jsx";

let server; let base; const realFetch = globalThis.fetch;
beforeAll(async () => {
  const health = createHealth({ runChecks: async () => [], intervalMs: 3_600_000 });
  ({ server, url: base } = await startHttpServer({ port: 0, host: "127.0.0.1", app: createApp({ health, configFile: "/nonexistent/customer.config.json" }) }));
  base = base.replace(/\/$/, "");
});
afterAll(async () => { globalThis.fetch = realFetch; await new Promise((r) => server.close(r)); });
beforeEach(() => { cleanup(); try { window.localStorage.clear(); window.sessionStorage.clear(); } catch { /* ignore */ } window.location.hash = ""; });

// Every call goes to the real Express app, except /api/shelf, which answers the given payload (the shelf's view).
function withShelf(payload) {
  globalThis.fetch = async (u, init = {}) => {
    if (u === "/api/shelf") return new Response(JSON.stringify(payload), { status: 200, headers: { "content-type": "application/json" } });
    const url = typeof u === "string" && u.startsWith("/") ? `${base}${u}` : u;
    return realFetch(url, { ...init, headers: { origin: base, ...(init.headers || {}) } });
  };
  return () => { globalThis.fetch = realFetch; };
}
const mark = (status, label, extra = {}) => ({ status, label, note: "", updatedAt: "2026-11-15", source: "shipped", ...extra });
const MINE = "secrets-vault-lab";

describe("verification mark in the header", () => {
  it("shows this lab's own mark beside the Shelf link, and no other lab's", async () => {
    const restore = withShelf({ shelfUrl: "http://shelf.example", demos: [{ id: "other-lab", verification: mark("in-progress", "In progress") }, { id: MINE, verification: mark("verified", "Verified", { note: "Both modes run on the mock" }) }] });
    try {
      render(<App />);
      const bar = within(await screen.findByTestId("top-menu"));
      expect(await bar.findByText("Verified")).toBeInTheDocument();
      expect(bar.getByRole("link", { name: "Shelf" })).toBeInTheDocument();
      expect(bar.queryByText("In progress")).toBeNull();
      expect(document.querySelectorAll(".verify")).toHaveLength(1);
      expect(bar.getByText("Verified").closest(".verify")).toHaveAttribute("title", expect.stringContaining("Both modes run on the mock"));
    } finally { restore(); }
  });

  it("shows nothing when the lab is opened on its own port (its /api/shelf has no demos) or the shelf has no mark for it", async () => {
    for (const payload of [{ shelfUrl: "http://shelf.example" }, { shelfUrl: "http://shelf.example", demos: [{ id: MINE, verification: null }, { id: "other-lab", verification: mark("verified", "Verified") }] }]) {
      const restore = withShelf(payload);
      try {
        const { unmount } = render(<App />);
        const bar = within(await screen.findByTestId("top-menu"));
        expect(await bar.findByRole("link", { name: "Shelf" })).toBeInTheDocument(); // the shelf answered, and still no badge
        expect(document.querySelector(".verify")).toBeNull();
        unmount();
      } finally { restore(); }
    }
  });

  it("is wired in App.jsx exactly once, with this lab's shelf id (remove the line and this fails)", () => {
    const src = fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "App.jsx"), "utf8");
    expect(src.match(/<VerifyMark\b/g)).toHaveLength(1);
    expect(src).toContain(`<VerifyMark id="${MINE}" />`);
    const entry = JSON.parse(fs.readFileSync(path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "docs", "shelf-entry.json"), "utf8"));
    expect(entry.demos.map((d) => d.id)).toContain(MINE);
  });
});
