import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { describe, expect, it } from "vitest";
import { Shell } from "./Shell";

describe("Shell phase color scoping", () => {
  // Every button/link/checkbox on a pipeline page styles itself off
  // var(--color-brand) directly (PhaseRunnerCard, ScanJobCard,
  // DeviceCohortPicker, etc.) - for a KAUSTify page to read as one
  // consistent color rather than a mix of "phase-colored accent bar +
  // globally-teal buttons", Shell must re-declare --color-brand on <main>
  // to the page's own phase color, not just pass `phase` through to
  // TopBar's accent bar.
  it("does not set a local --color-brand override when no phase is given", () => {
    render(
      <MemoryRouter>
        <Shell title="Overview">
          <p>content</p>
        </Shell>
      </MemoryRouter>,
    );
    const main = screen.getByText("content").closest("main") as HTMLElement;
    expect(main.style.getPropertyValue("--color-brand")).toBe("");
  });

  it("re-declares --color-brand as the page's own phase color on <main>", () => {
    render(
      <MemoryRouter>
        <Shell title="NCA Compliance" phase="compliance">
          <p>content</p>
        </Shell>
      </MemoryRouter>,
    );
    const main = screen.getByText("content").closest("main") as HTMLElement;
    expect(main.style.getPropertyValue("--color-brand")).toBe("var(--color-phase-compliance)");
  });

  it("uses a different phase's color for a different page", () => {
    render(
      <MemoryRouter>
        <Shell title="Remediation" phase="solution">
          <p>content</p>
        </Shell>
      </MemoryRouter>,
    );
    const main = screen.getByText("content").closest("main") as HTMLElement;
    expect(main.style.getPropertyValue("--color-brand")).toBe("var(--color-phase-solution)");
  });
});
