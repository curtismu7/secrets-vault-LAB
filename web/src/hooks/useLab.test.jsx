import { describe, it, expect, vi } from "vitest";
import { renderHook, act, waitFor } from "@testing-library/react";

vi.mock("../api", () => ({ getJson: vi.fn(), sendJson: vi.fn() }));
import { getJson } from "../api";
import useLab from "./useLab";

describe("useLab: a late answer for a context the page has left is dropped", () => {
  it("a Live state answer for the previous vertical is not shown after the vertical changes, even while the new vertical has no person yet", async () => {
    let resolveOld;
    getJson.mockImplementationOnce(() => new Promise((res) => { resolveOld = res; }));
    const { result, rerender } = renderHook((p) => useLab(p), { initialProps: { mode: "live", vertical: "finance", scenario: "", actor: "maya.chen" } });
    expect(getJson).toHaveBeenCalledTimes(1);
    // the vertical changes; the new vertical's cast is not loaded yet, so there is no person and no new request
    rerender({ mode: "live", vertical: "health", scenario: "", actor: "" });
    await act(async () => { resolveOld({ mode: "live", vertical: "finance", state: { roster: [{ id: "maya.chen" }] } }); await Promise.resolve(); });
    await waitFor(() => expect(getJson).toHaveBeenCalledTimes(1));
    expect(result.current.data).toBeNull();
    expect(result.current.state).toBeNull();
  });
});
