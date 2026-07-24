import { render, screen } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { OrganizationalCompliancePage } from "./OrganizationalCompliancePage";
import { api } from "@/lib/api";
import type { NCAOrganizationalCompliance } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

const ORG: NCAOrganizationalCompliance = {
  organizational_scope_id: "default",
  overall_status: "partial",
  score: 40,
  domain_summary: {
    "Cybersecurity Governance": { pass: 2, partial: 1, fail: 0, not_tested: 6, review_required: 0 },
    "Cybersecurity Defense": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
    "Cybersecurity Resilience": { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 },
    "Third-Party and Cloud Computing Cybersecurity": { pass: 0, partial: 0, fail: 0, not_tested: 11, review_required: 0 },
  },
  readiness: {
    classification: "failed",
    score: 40,
    reasons: ["Score 40% is below the failing threshold of 50%."],
    blocking_control_ids: [],
    critical_failure_control_ids: [],
    not_tested_control_ids: [],
    review_required_control_ids: [],
    pass_threshold: 85,
    partial_threshold: 50,
  },
  controls: [
    {
      control: {
        id: "NCA-CGIoT-1_2024-1-1-1",
        framework: "NCA-CGIoT",
        framework_version: "1:2024",
        domain_id: "1",
        domain_name: "Cybersecurity Governance",
        subdomain_id: "1-1",
        subdomain_name: "Cybersecurity Strategy",
        guideline_id: "1-1-1",
        canonical_requirement: "Establish a cybersecurity strategy.",
        implementation_summary: "Have a strategy document.",
        source_page: "17",
        scope_type: "organization",
        assessment_type: "manual",
        required: true,
        severity: "medium",
        blocking: false,
        evidence_requirements: [],
        remediation_guidance: "",
        enabled: true,
      },
      assessment: null,
    },
  ],
};

function renderPage() {
  return render(
    <MemoryRouter>
      <OrganizationalCompliancePage />
    </MemoryRouter>,
  );
}

describe("OrganizationalCompliancePage", () => {
  it("shows the overall organizational status and score", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    renderPage();

    expect(await screen.findByText("Partial")).toBeInTheDocument();
    expect(screen.getByText("40% informational score")).toBeInTheDocument();
  });

  it("lists organizational controls as not-assessed when no assessment exists yet", async () => {
    vi.spyOn(api, "ncaOrganization").mockResolvedValue(ORG);
    renderPage();

    expect(await screen.findByText("Have a strategy document.")).toBeInTheDocument();
    expect(screen.getByText("Not Assessed")).toBeInTheDocument();
  });

  it("renders an error state when organizational data fails to load", async () => {
    vi.spyOn(api, "ncaOrganization").mockRejectedValue(new Error("could not load organization"));
    renderPage();

    expect(await screen.findByText(/could not load organization/i)).toBeInTheDocument();
  });
});
