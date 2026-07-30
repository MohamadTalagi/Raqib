import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { VulnAdvisoryPanel } from "./VulnAdvisoryPanel";
import type { VulnPackageAdvisory } from "@/lib/types";

const OPENSSL: VulnPackageAdvisory = {
  name: "openssl",
  version: "1.0.1e",
  outdated: true,
  eol: null,
  latest_known_version: null,
  official_patch_available: true,
  patched_version: "1.0.1g",
  kev_listed_count: 1,
  cves: [
    { id: "CVE-2014-0160", cvss: 7.5, summary: "Heartbleed", kev_listed: true, kev_date_added: "2022-05-04" },
    { id: "CVE-2016-6304", cvss: 5.9, summary: "OOB write", kev_listed: false, kev_date_added: null },
  ],
  notes: [],
};

describe("VulnAdvisoryPanel", () => {
  it("shows an empty state when there are no packages", () => {
    render(<VulnAdvisoryPanel packages={[]} />);
    expect(screen.getByText(/no packages were listed/i)).toBeInTheDocument();
  });

  it("shows each package's name, version, outdated status, and patched version", () => {
    render(<VulnAdvisoryPanel packages={[OPENSSL]} />);
    expect(screen.getByText("openssl@1.0.1e")).toBeInTheDocument();
    expect(screen.getByText(/outdated/i)).toBeInTheDocument();
    expect(screen.getByText(/patched in 1.0.1g/)).toBeInTheDocument();
  });

  it("shows a KEV badge only when the package has at least one KEV-listed CVE", () => {
    render(<VulnAdvisoryPanel packages={[OPENSSL]} />);
    expect(screen.getByText("KEV")).toBeInTheDocument();
  });

  it("does not show a KEV badge for a package with zero KEV-listed CVEs", () => {
    const clean: VulnPackageAdvisory = { ...OPENSSL, kev_listed_count: 0, cves: [] };
    render(<VulnAdvisoryPanel packages={[clean]} />);
    expect(screen.queryByText("KEV")).not.toBeInTheDocument();
  });

  it("lists each CVE with its id and CVSS score", () => {
    render(<VulnAdvisoryPanel packages={[OPENSSL]} />);
    expect(screen.getByText("CVE-2014-0160")).toBeInTheDocument();
    expect(screen.getByText("CVSS 7.5")).toBeInTheDocument();
    expect(screen.getByText("CVE-2016-6304")).toBeInTheDocument();
  });

  it("caps the visible CVE list and shows a '+N more' indicator", () => {
    const manyOpenssl: VulnPackageAdvisory = {
      ...OPENSSL,
      cves: Array.from({ length: 8 }, (_, i) => ({
        id: `CVE-2020-000${i}`,
        cvss: 5.0,
        summary: "synthetic",
        kev_listed: false,
        kev_date_added: null,
      })),
    };
    render(<VulnAdvisoryPanel packages={[manyOpenssl]} />);
    expect(screen.getByText("+3 more")).toBeInTheDocument();
  });

  it("explains when a package was not cross-referenced against KEV (kev_listed_count is null)", () => {
    const staticTableOnly: VulnPackageAdvisory = { ...OPENSSL, kev_listed_count: null };
    render(<VulnAdvisoryPanel packages={[staticTableOnly]} />);
    expect(screen.getByText(/not cross-referenced against cisa kev/i)).toBeInTheDocument();
  });
});
