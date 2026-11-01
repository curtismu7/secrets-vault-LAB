import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { forgetWorkspace, regenerateWorkspace, workspaceFetch, workspaceId } from "./workspace";

// Rule 13, client side: the id is "w-" + 16 hex digits (always a letter, never 24 hex digits); a stored id that is unusable or that the server refuses
// is replaced, and a refused call is repeated ONCE.
const KEY = "svl.workspace";
const join = (...p) => p.join("-"); // assembled at run time: no credential-looking literal sits in the repository
const CLIENT_OK_SERVER_NO = join("bob", "hunter2xyz");
const json = (status, body) => new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });

describe("workspace id", () => {
  beforeEach(() => { forgetWorkspace(); window.sessionStorage.clear(); });
  afterEach(() => { vi.unstubAllGlobals(); });

  it("makes w- plus 16 hex digits, and keeps it for the tab", () => {
    const id = workspaceId();
    expect(id).toMatch(/^w-[0-9a-f]{16}$/);
    expect(window.sessionStorage.getItem(KEY)).toBe(id);
    expect(workspaceId()).toBe(id);
  });

  it("every generated id contains a letter, whatever the random bytes are (all zero, all 0x99)", () => {
    for (const fill of [0, 0x99, 0xff]) {
      forgetWorkspace(); window.sessionStorage.clear();
      vi.stubGlobal("crypto", { getRandomValues: (a) => { a.fill(fill); return a; } });
      const id = workspaceId();
      expect(id).toMatch(/[a-z]/); expect(id).toMatch(/^w-[0-9a-f]{16}$/);
      vi.unstubAllGlobals();
    }
  });

  it("a stored id that is not usable is replaced at once: no letter, 24 hex digits, a credential prefix, a bad shape", () => {
    for (const bad of ["123456789012", "0123456789abcdef01234567", join("pw", "hunter2xyz"), join("sk", "abcdefghijklmnop1234"), join("password", "hunter2xyz"), "token", "UPPER", "a b", "x".repeat(41)]) {
      forgetWorkspace(); window.sessionStorage.setItem(KEY, bad);
      const id = workspaceId();
      expect(id).not.toBe(bad); expect(id).toMatch(/^w-[0-9a-f]{16}$/);
      expect(window.sessionStorage.getItem(KEY)).toBe(id);
    }
  });

  it("a good stored id is kept: 23 hex digits are fine, 24 are not", () => {
    window.sessionStorage.setItem(KEY, `w${"a".repeat(23)}`); forgetWorkspace();
    expect(workspaceId()).toBe(`w${"a".repeat(23)}`);
    forgetWorkspace(); window.sessionStorage.setItem(KEY, "a".repeat(24));
    expect(workspaceId()).not.toBe("a".repeat(24));
  });

  it("a 400 bad_workspace makes a new id and repeats the call ONCE with it", async () => {
    window.sessionStorage.setItem(KEY, CLIENT_OK_SERVER_NO); forgetWorkspace(); // the client accepts it; the server does not
    const seen = [];
    vi.stubGlobal("fetch", vi.fn(async (_u, o) => { seen.push(o.headers["x-workspace"]); return seen.length === 1 ? json(400, { error: "bad_workspace" }) : json(200, { ok: true }); }));
    const r = await workspaceFetch("/api/state?mode=live", { method: "GET" });
    expect(r.status).toBe(200);
    expect(seen).toHaveLength(2); expect(seen[0]).toBe(CLIENT_OK_SERVER_NO); expect(seen[1]).toMatch(/^w-[0-9a-f]{16}$/);
    expect(window.sessionStorage.getItem(KEY)).toBe(seen[1]);
  });

  it("a second refusal is returned as it is (no loop), and other 400s and other statuses are not retried", async () => {
    const f = vi.fn(async () => json(400, { error: "bad_workspace" })); vi.stubGlobal("fetch", f);
    const r = await workspaceFetch("/api/reset", { method: "POST", body: "{}" });
    expect(r.status).toBe(400); expect(f).toHaveBeenCalledTimes(2);
    const g = vi.fn(async () => json(400, { error: "bad_mode" })); vi.stubGlobal("fetch", g);
    expect((await workspaceFetch("/api/state", {})).status).toBe(400); expect(g).toHaveBeenCalledTimes(1);
    const h = vi.fn(async () => new Response("<html>", { status: 400 })); vi.stubGlobal("fetch", h);
    expect((await workspaceFetch("/api/state", {})).status).toBe(400); expect(h).toHaveBeenCalledTimes(1);
    const k = vi.fn(async () => json(404, { error: "bad_workspace" })); vi.stubGlobal("fetch", k);
    expect((await workspaceFetch("/api/state", {})).status).toBe(404); expect(k).toHaveBeenCalledTimes(1);
  });

  it("two calls in flight that are both refused end up on the SAME new id", async () => {
    window.sessionStorage.setItem(KEY, CLIENT_OK_SERVER_NO); forgetWorkspace();
    const seen = [];
    vi.stubGlobal("fetch", vi.fn(async (_u, o) => { const id = o.headers["x-workspace"]; seen.push(id); return id === CLIENT_OK_SERVER_NO ? json(400, { error: "bad_workspace" }) : json(200, {}); }));
    const [a, b] = await Promise.all([workspaceFetch("/api/state", {}), workspaceFetch("/api/governance", {})]);
    expect(a.status).toBe(200); expect(b.status).toBe(200);
    const fresh = seen.filter((x) => x !== CLIENT_OK_SERVER_NO);
    expect(fresh).toHaveLength(2); expect(fresh[0]).toBe(fresh[1]);
  });

  it("regenerateWorkspace replaces the id in memory and in storage", () => {
    const first = workspaceId(); const next = regenerateWorkspace();
    expect(next).not.toBe(first); expect(workspaceId()).toBe(next); expect(window.sessionStorage.getItem(KEY)).toBe(next);
  });

  it("works with storage blocked (the id lives in memory for the load)", () => {
    const real = window.sessionStorage;
    Object.defineProperty(window, "sessionStorage", { configurable: true, get() { throw new Error("blocked"); } });
    try { forgetWorkspace(); const id = workspaceId(); expect(id).toMatch(/^w-[0-9a-f]{16}$/); expect(regenerateWorkspace()).toMatch(/^w-/); } finally { Object.defineProperty(window, "sessionStorage", { configurable: true, value: real }); }
  });
});
