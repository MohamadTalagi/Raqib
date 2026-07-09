import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SeverityBadge, StatusBadge, ConfidenceLabel } from "./severity-badge";

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
