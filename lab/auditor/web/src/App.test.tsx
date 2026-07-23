import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { mockFetchImplementation } from "@/test/fixtures";

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders the Overview page at the root route", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
  });

  it("renders sidebar navigation for all four screens", () => {
    render(<App />);
    expect(screen.getByRole("link", { name: /overview/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /devices/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /evidence/i })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: /verdicts/i })).toBeInTheDocument();
  });

  it("renders a 404 page for an unknown route", async () => {
    window.history.pushState({}, "", "/this-route-does-not-exist");
    render(<App />);
    expect(await screen.findByText(/page not found/i)).toBeInTheDocument();
    window.history.pushState({}, "", "/");
  });
});
