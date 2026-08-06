import { render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";
import App from "./App";
import { mockFetchImplementation } from "@/test/fixtures";

describe("App", () => {
  beforeEach(() => {
    vi.stubGlobal("fetch", vi.fn((url: string) => mockFetchImplementation(url)));
  });

  it("renders the new Home page at the root route", async () => {
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Raqib" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: /start a manual run/i })).toBeInTheDocument();
  });

  it("renders the Overview dashboard at /overview, one slot below Home", async () => {
    window.history.pushState({}, "", "/overview");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Overview" })).toBeInTheDocument();
    window.history.pushState({}, "", "/");
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

  it("redirects the old /run-scan route to Devices, rather than 404ing", async () => {
    // Run Scan's functionality is now split across the Fingerprinting and
    // SA-IOT Compliance pipeline pages - anyone with the old URL bookmarked
    // should land somewhere real, not a dead link.
    window.history.pushState({}, "", "/run-scan");
    render(<App />);
    expect(await screen.findByRole("heading", { name: "Devices" })).toBeInTheDocument();
    window.history.pushState({}, "", "/");
  });

  it("renders the sidebar grouped and ordered as the guided pipeline", () => {
    render(<App />);
    const linkNames = screen.getAllByRole("link").map((link) => link.textContent);
    // Pipeline order must read top to bottom exactly as lib/pipeline.ts's
    // PIPELINE_PHASES - Discovery sits just above it (pre-registration, no
    // per-device status of its own). Post-Quantum Readiness sits before
    // Remediation (informational readiness check ahead of acting on
    // findings), not after it.
    const pipelineOrder = [
      "Discovery", "Devices", "Fingerprinting", "SA-IOT Compliance",
      "NCA Compliance", "Vulnerability Intelligence", "Risk Assessment",
      "Post-Quantum Readiness", "Remediation", "Executive Summary",
    ];
    const indices = pipelineOrder.map((name) => linkNames.indexOf(name));
    expect(indices).toEqual([...indices].sort((a, b) => a - b));
    expect(indices.every((i) => i !== -1)).toBe(true);
  });
});
