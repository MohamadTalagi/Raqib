import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it } from "vitest";
import {
  SeverityBadge,
  StatusBadge,
  ConfidenceLabel,
  BLOCKING_EXPLANATION,
  BlockingBadge,
  NCAReadinessBadge,
} from "./severity-badge";

describe("SeverityBadge", () => {
  it("renders the severity label", () => {
    render(<SeverityBadge severity="critical" />);
    expect(screen.getByText("critical")).toBeInTheDocument();
  });
});

describe("StatusBadge", () => {
  it("renders each verdict status", () => {
    render(<StatusBadge status="FAIL" />);
    expect(screen.getByText("FAIL")).toBeInTheDocument();
  });
});

describe("ConfidenceLabel", () => {
  it("renders the confidence level", () => {
    render(<ConfidenceLabel confidence="high" />);
    expect(screen.getByText("high")).toBeInTheDocument();
  });
});

describe("NCAReadinessBadge", () => {
  it("renders the classification label and icon at the default (md) size", () => {
    render(<NCAReadinessBadge classification="passed" />);
    const badge = screen.getByText("Passed").closest("span");
    expect(badge).toHaveClass("text-sm");
  });

  it("renders at a smaller size matching NCAStatusBadge's dimensions when size='sm'", () => {
    render(<NCAReadinessBadge classification="failed" size="sm" />);
    const badge = screen.getByText("Failed").closest("span");
    expect(badge).toHaveClass("text-xs");
    expect(badge).not.toHaveClass("text-sm");
  });

  it("renders every classification without throwing", () => {
    const { rerender } = render(<NCAReadinessBadge classification="passed" />);
    expect(screen.getByText("Passed")).toBeInTheDocument();
    rerender(<NCAReadinessBadge classification="partially_passed" />);
    expect(screen.getByText("Partially Passed")).toBeInTheDocument();
    rerender(<NCAReadinessBadge classification="failed" />);
    expect(screen.getByText("Failed")).toBeInTheDocument();
  });
});

describe("BlockingBadge", () => {
  it("renders the blocking label", () => {
    render(<BlockingBadge />);
    expect(screen.getByText("blocking")).toBeInTheDocument();
  });

  it("explains itself via a tooltip instead of a native title attribute", async () => {
    const user = userEvent.setup();
    render(<BlockingBadge />);

    const badge = screen.getByText("blocking").closest("span");
    expect(badge).not.toHaveAttribute("title");

    await user.hover(screen.getByText("blocking"));
    expect(await screen.findByRole("tooltip")).toHaveTextContent(BLOCKING_EXPLANATION);
  });
});
