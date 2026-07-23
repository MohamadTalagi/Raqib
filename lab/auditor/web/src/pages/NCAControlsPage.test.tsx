import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { MemoryRouter } from "react-router-dom";
import { afterEach, describe, expect, it, vi } from "vitest";
import { NCAControlsPage } from "./NCAControlsPage";
import { api } from "@/lib/api";
import type { NCAControl } from "@/lib/types";

afterEach(() => vi.restoreAllMocks());

function makeControl(overrides: Partial<NCAControl>): NCAControl {
  return {
    id: "NCA-CGIoT-1_2024-2-2-2",
    framework: "NCA-CGIoT",
    framework_version: "1:2024",
    domain_id: "2",
    domain_name: "Cybersecurity Defense",
    subdomain_id: "2-2",
    subdomain_name: "Access and Permission Restriction",
    guideline_id: "2-2-2",
    canonical_requirement: "Do not use default or hard-coded passwords.",
    implementation_summary: "No default creds.",
    source_page: "17",
    scope_type: "device",
    assessment_type: "automated",
    required: true,
    severity: "high",
    evidence_requirements: [],
    remediation_guidance: "",
    enabled: true,
    ...overrides,
  };
}

const CONTROLS: NCAControl[] = [
  makeControl({ id: "c1", guideline_id: "2-2-2", implementation_summary: "No default creds.", scope_type: "device" }),
  makeControl({
    id: "c2",
    guideline_id: "1-1-1",
    implementation_summary: "Board-approved security policy.",
    domain_name: "Cybersecurity Governance",
    scope_type: "organization",
    severity: "medium",
  }),
];

function renderPage() {
  return render(
    <MemoryRouter>
      <NCAControlsPage />
    </MemoryRouter>,
  );
}

describe("NCAControlsPage", () => {
  it("lists every control from the catalog", async () => {
    vi.spyOn(api, "ncaControls").mockResolvedValue(CONTROLS);
    renderPage();

    expect(await screen.findByText("No default creds.")).toBeInTheDocument();
    expect(screen.getByText("Board-approved security policy.")).toBeInTheDocument();
    expect(screen.getByText("2 of 2")).toBeInTheDocument();
  });

  it("filters by domain", async () => {
    vi.spyOn(api, "ncaControls").mockResolvedValue(CONTROLS);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("No default creds.");
    await user.selectOptions(screen.getByLabelText(/filter by domain/i), "Cybersecurity Governance");

    expect(screen.queryByText("No default creds.")).not.toBeInTheDocument();
    expect(screen.getByText("Board-approved security policy.")).toBeInTheDocument();
    expect(screen.getByText("1 of 2")).toBeInTheDocument();
  });

  it("filters by scope", async () => {
    vi.spyOn(api, "ncaControls").mockResolvedValue(CONTROLS);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("No default creds.");
    await user.selectOptions(screen.getByLabelText(/filter by scope/i), "organization");

    expect(screen.queryByText("No default creds.")).not.toBeInTheDocument();
    expect(screen.getByText("Board-approved security policy.")).toBeInTheDocument();
  });

  it("links each control to its detail page", async () => {
    vi.spyOn(api, "ncaControls").mockResolvedValue(CONTROLS);
    renderPage();

    const link = await screen.findByRole("link", { name: /no default creds/i });
    expect(link).toHaveAttribute("href", "/nca-compliance/controls/c1");
  });

  it("shows an empty state when no controls match the filters", async () => {
    vi.spyOn(api, "ncaControls").mockResolvedValue(CONTROLS);
    const user = userEvent.setup();
    renderPage();

    await screen.findByText("No default creds.");
    await user.selectOptions(screen.getByLabelText(/filter by scope/i), "supplier");

    expect(screen.getByText(/no controls match the current filters/i)).toBeInTheDocument();
  });
});
