import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { PhaseStatusBadge } from "./PhaseStatusBadge";

const PHASE = { id: "fingerprinting" as const, label: "Fingerprinting" };

describe("PhaseStatusBadge", () => {
  it("shows the phase label either way - status is never color alone", () => {
    const { rerender } = render(<PhaseStatusBadge phase={PHASE} reached={true} />);
    expect(screen.getByText("Fingerprinting")).toBeInTheDocument();

    rerender(<PhaseStatusBadge phase={PHASE} reached={false} />);
    expect(screen.getByText("Fingerprinting")).toBeInTheDocument();
  });

  it("renders a distinct icon for reached vs not-reached", () => {
    const { container, rerender } = render(<PhaseStatusBadge phase={PHASE} reached={true} />);
    const reachedIconClass = container.querySelector("svg")?.getAttribute("class");

    rerender(<PhaseStatusBadge phase={PHASE} reached={false} />);
    const notReachedIconClass = container.querySelector("svg")?.getAttribute("class");

    expect(reachedIconClass).not.toEqual(notReachedIconClass);
  });
});
