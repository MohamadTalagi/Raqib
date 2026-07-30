import { render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { VulnFreshnessNote } from "./VulnFreshnessNote";
import { api } from "@/lib/api";
import { vulnIntelStatusFixture } from "@/test/fixtures";

afterEach(() => vi.restoreAllMocks());

describe("VulnFreshnessNote", () => {
  it("shows the DB build date once status loads", async () => {
    vi.spyOn(api, "vulnIntelStatus").mockResolvedValue(vulnIntelStatusFixture);
    render(<VulnFreshnessNote />);
    expect(await screen.findByText(vulnIntelStatusFixture.vuln_db_built_at!)).toBeInTheDocument();
  });

  it("says freshness is unknown when no evidence has ever used Grype", async () => {
    vi.spyOn(api, "vulnIntelStatus").mockResolvedValue({
      known: false, vuln_db_built_at: null, vuln_db_checksum: null,
      observed_at: null, observed_from_evidence_id: null, observed_from_device_id: null,
    });
    render(<VulnFreshnessNote />);
    expect(await screen.findByText(/freshness unknown/i)).toBeInTheDocument();
  });

  it("renders nothing while loading or on error, rather than a layout flash", () => {
    vi.spyOn(api, "vulnIntelStatus").mockReturnValue(new Promise(() => {})); // never resolves
    const { container } = render(<VulnFreshnessNote />);
    expect(container).toBeEmptyDOMElement();
  });
});
