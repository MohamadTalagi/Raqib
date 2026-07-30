import { AlertTriangle } from "lucide-react";
import { KevBadge } from "@/components/ui/severity-badge";
import type { VulnPackageAdvisory } from "@/lib/types";

const CVES_SHOWN_PER_PACKAGE = 5;

interface VulnAdvisoryPanelProps {
  packages: VulnPackageAdvisory[];
}

/**
 * Real per-package CVE/KEV/CVSS data from the worker's Grype + CISA-KEV
 * -backed TEST-FW-MANIFEST scan (see lab/auditor/api/vuln_routes.py) - not
 * a summary count, the actual advisory list, since an auditor needs to see
 * which specific CVEs a package carries, not just how many. CVEs within a
 * package already arrive KEV-listed-first (scan_tests.py's sort order), so
 * capping the visible list to the top few never hides a KEV-listed finding
 * behind a longer, lower-priority CVE.
 */
export function VulnAdvisoryPanel({ packages }: VulnAdvisoryPanelProps) {
  if (packages.length === 0) {
    return (
      <p className="text-xs text-[var(--color-text-muted)]">
        No packages were listed in this firmware's manifest.
      </p>
    );
  }

  return (
    <div className="space-y-3">
      {packages.map((pkg) => (
        <div
          key={`${pkg.name}-${pkg.version}`}
          className="rounded-md border border-[var(--color-border)] p-3"
        >
          <div className="flex flex-wrap items-center gap-2">
            <span className="font-mono text-sm text-[var(--color-text)]">
              {pkg.name}@{pkg.version}
            </span>
            {pkg.outdated === true ? (
              <span className="rounded-full bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] px-2 py-0.5 text-xs font-medium text-[var(--color-medium)]">
                outdated{pkg.patched_version ? ` · patched in ${pkg.patched_version}` : ""}
              </span>
            ) : pkg.outdated === false ? (
              <span className="rounded-full bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] px-2 py-0.5 text-xs font-medium text-[var(--color-pass)]">
                current
              </span>
            ) : null}
            {pkg.kev_listed_count ? <KevBadge size="xs" /> : null}
            <span className="ml-auto font-mono-tabular text-xs text-[var(--color-text-muted)]">
              {pkg.cves.length} CVE{pkg.cves.length === 1 ? "" : "s"}
            </span>
          </div>

          {pkg.cves.length > 0 && (
            <ul className="mt-2 space-y-1.5">
              {pkg.cves.slice(0, CVES_SHOWN_PER_PACKAGE).map((cve) => (
                <li key={cve.id} className="flex items-start gap-2 text-xs">
                  {cve.kev_listed ? (
                    <AlertTriangle
                      className="mt-0.5 h-3 w-3 shrink-0 text-[var(--color-critical)]"
                      aria-label="CISA KEV-listed"
                    />
                  ) : (
                    <span className="mt-0.5 h-3 w-3 shrink-0" />
                  )}
                  <span className="font-mono text-[var(--color-text-secondary)]">{cve.id}</span>
                  {cve.cvss !== null && (
                    <span className="font-mono-tabular shrink-0 text-[var(--color-text-muted)]">
                      CVSS {cve.cvss}
                    </span>
                  )}
                  <span className="min-w-0 flex-1 truncate text-[var(--color-text-muted)]">{cve.summary}</span>
                </li>
              ))}
              {pkg.cves.length > CVES_SHOWN_PER_PACKAGE && (
                <li className="pl-5 text-xs text-[var(--color-text-muted)]">
                  +{pkg.cves.length - CVES_SHOWN_PER_PACKAGE} more
                </li>
              )}
            </ul>
          )}

          {pkg.kev_listed_count === null && (
            <p className="mt-2 text-xs text-[var(--color-text-muted)]">
              Not cross-referenced against CISA KEV - this package matched only the small static
              reference table, not Grype's local vulnerability database.
            </p>
          )}
        </div>
      ))}
    </div>
  );
}
