import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { DomainSummaryGrid } from "./DomainSummaryGrid";
import type { NCADomainCounts } from "@/lib/types";

const COUNTS: NCADomainCounts = { pass: 3, partial: 1, fail: 2, not_tested: 4, review_required: 5 };

describe("DomainSummaryGrid", () => {
  it("renders a card per domain with all five status counts", () => {
    render(<DomainSummaryGrid domains={[["Cybersecurity Defense", COUNTS]]} />);

    expect(screen.getByText("Cybersecurity Defense")).toBeInTheDocument();
    expect(screen.getByText("3 pass")).toBeInTheDocument();
    expect(screen.getByText("1 partial")).toBeInTheDocument();
    expect(screen.getByText("2 fail")).toBeInTheDocument();
    expect(screen.getByText("4 not tested")).toBeInTheDocument();
    expect(screen.getByText("5 review")).toBeInTheDocument();
  });

  it("renders one card per entry, in the order given", () => {
    render(
      <DomainSummaryGrid
        domains={[
          ["Cybersecurity Governance", COUNTS],
          ["Cybersecurity Defense", COUNTS],
        ]}
      />,
    );
    expect(screen.getByText("Cybersecurity Governance")).toBeInTheDocument();
    expect(screen.getByText("Cybersecurity Defense")).toBeInTheDocument();
  });

  it("renders nothing when given no domains", () => {
    const { container } = render(<DomainSummaryGrid domains={[]} />);
    expect(container.querySelector(".rounded-md")).not.toBeInTheDocument();
  });
});
