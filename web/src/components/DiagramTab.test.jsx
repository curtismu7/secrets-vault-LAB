import { describe, it, expect, vi } from "vitest";
import { render, screen, waitFor } from "@testing-library/react";

vi.mock("../api", () => ({ getJson: vi.fn() }));
vi.mock("./PatternDiagram", () => ({ default: ({ pattern }) => <div data-testid="pattern">{pattern.id}</div> }));
import { getJson } from "../api";
import DiagramTab from "./DiagramTab";

describe("DiagramTab: a failed load shows its error beside the picker and clears when the vertical changes", () => {
  it("keeps the picker visible on an error, and a later successful load removes the error", async () => {
    getJson.mockRejectedValueOnce(new Error("HTTP 500"));
    const { rerender } = render(<DiagramTab vertical="finance" resetSignal={0} />);
    expect(await screen.findByRole("alert")).toHaveTextContent(/HTTP 500/);
    expect(screen.getByTestId("dg-secret-store-no-copy")).toBeInTheDocument();
    getJson.mockResolvedValueOnce({ id: "vault-request-time" });
    rerender(<DiagramTab vertical="health" resetSignal={0} />);
    await waitFor(() => expect(screen.getByTestId("pattern")).toHaveTextContent("vault-request-time"));
    expect(screen.queryByRole("alert")).toBeNull();
  });
});
