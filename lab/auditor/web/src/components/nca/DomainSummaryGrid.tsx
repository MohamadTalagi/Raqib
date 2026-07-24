import type { NCADomainCounts } from "@/lib/types";

interface DomainSummaryGridProps {
  domains: Array<[string, NCADomainCounts]>;
}

/**
 * Per-domain pass/partial/fail/not_tested/review_required counts, one card
 * per domain - extracted from three near-verbatim copies (NCACompliancePage,
 * OrganizationalCompliancePage, DeviceDetailPage's Compliance tab) so the
 * five statuses shown here can't drift out of sync with a sibling
 * visualization (e.g. NCADomainBarChart) the way three separate copies did.
 * Filtering (e.g. lib/nca.ts's applicableDomains()) and empty-state handling
 * stay with each caller - callers differ on whether/how they filter, this
 * component just renders whatever domain entries it's given.
 */
export function DomainSummaryGrid({ domains }: DomainSummaryGridProps) {
  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
      {domains.map(([domainName, counts]) => (
        <div key={domainName} className="rounded-md border border-[var(--color-border)] p-4">
          <p className="text-xs font-medium text-[var(--color-text-secondary)]">{domainName}</p>
          <div className="mt-2 flex flex-wrap gap-3 text-xs">
            <span className="text-[var(--color-pass)]">{counts.pass} pass</span>
            <span className="text-[var(--color-medium)]">{counts.partial} partial</span>
            <span className="text-[var(--color-critical)]">{counts.fail} fail</span>
            <span className="text-[var(--color-text-muted)]">{counts.not_tested} not tested</span>
            <span className="text-[var(--color-brand)]">{counts.review_required} review</span>
          </div>
        </div>
      ))}
    </div>
  );
}
