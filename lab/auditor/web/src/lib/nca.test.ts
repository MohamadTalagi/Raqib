import { describe, expect, it } from "vitest";
import { applicableDomains } from "./nca";
import type { NCADomainSummary } from "./types";

describe("applicableDomains", () => {
  it("excludes a domain with zero controls across every status", () => {
    const domains: NCADomainSummary = {
      "Cybersecurity Governance": { pass: 0, partial: 0, fail: 0, not_tested: 0 },
      "Cybersecurity Defense": { pass: 3, partial: 0, fail: 1, not_tested: 2 },
    };
    expect(applicableDomains(domains).map(([name]) => name)).toEqual(["Cybersecurity Defense"]);
  });

  it("keeps a domain whose only nonzero count is not_tested", () => {
    // Distinguishes "no device-scope guideline exists in this domain at
    // all" (total 0, excluded) from "guidelines exist but nobody has
    // assessed them yet" (not_tested > 0, kept).
    const domains: NCADomainSummary = {
      "Cybersecurity Resilience": { pass: 0, partial: 0, fail: 0, not_tested: 5 },
    };
    expect(applicableDomains(domains)).toHaveLength(1);
  });

  it("returns an empty list when every domain is all-zero", () => {
    const domains: NCADomainSummary = {
      "Cybersecurity Governance": { pass: 0, partial: 0, fail: 0, not_tested: 0 },
    };
    expect(applicableDomains(domains)).toEqual([]);
  });
});
