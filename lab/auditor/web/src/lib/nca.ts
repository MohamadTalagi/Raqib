import type { NCADomainCounts, NCADomainSummary } from "./types";

/**
 * Excludes domains with zero controls of any status from a per-device (or
 * fleet-wide-per-device) domain summary. Governance and the mobile/supplier/
 * cloud group are organization-scope only (see OrganizationalCompliancePage,
 * and finding_mappings.py's own docstring server-side) - a device genuinely
 * has no device-scope guideline in those domains at all, so an all-zero
 * entry here means "not applicable to a per-device view", not "not yet
 * tested" (which would show as a non-zero not_tested count instead).
 *
 * Do NOT apply this to the organizational compliance page's domain summary
 * - those same domains are exactly the ones that DO apply there.
 */
export function applicableDomains(domains: NCADomainSummary): Array<[string, NCADomainCounts]> {
  return Object.entries(domains).filter(
    ([, counts]) =>
      counts.pass + counts.partial + counts.fail + counts.not_tested + counts.review_required > 0,
  );
}
