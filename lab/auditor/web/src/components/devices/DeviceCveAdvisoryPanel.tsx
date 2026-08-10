import { AlertTriangle } from "lucide-react";
import { KevBadge } from "@/components/ui/severity-badge";
import { cn } from "@/lib/utils";
import type { VulnDeviceCVE, VulnDeviceIdentity, VulnFirmwareCurrency } from "@/lib/types";

const CVES_SHOWN = 8;

/**
 * Four distinct outcomes, four distinct colours. `affected_no_fix` is amber
 * rather than red: it is a real finding, but unlike `outdated` there is no
 * action the operator can take by updating, so it should not read as the same
 * kind of alarm.
 */
const CURRENCY_STYLES: Record<VulnFirmwareCurrency["status"], string> = {
  outdated: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)]",
  affected_no_fix: "bg-[color-mix(in_oklab,var(--color-high)_16%,transparent)] text-[var(--color-high)]",
  current: "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)]",
  unknown: "bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] text-[var(--color-text-muted)]",
};

const CURRENCY_LABEL: Record<VulnFirmwareCurrency["status"], string> = {
  outdated: "outdated",
  affected_no_fix: "affected · no fix published",
  current: "current",
  unknown: "currency unknown",
};

const VERSION_STATUS_LABEL: Record<VulnDeviceCVE["version_status"], string> = {
  affected: "affected",
  not_affected: "not affected",
  affected_no_fix: "no fix",
  unknown: "",
};

interface DeviceCveAdvisoryPanelProps {
  identity: VulnDeviceIdentity | null;
  cves: VulnDeviceCVE[];
  /** The collector's own deterministic notes - never model-generated. */
  notes?: string[];
  firmwareCurrency?: VulnFirmwareCurrency | null;
}

/**
 * Real device-level CVE data from the worker's NVD-backed
 * TEST-DEVICE-CVE-LOOKUP collector - matched by the device's vendor/model CPE
 * with no firmware image involved at all.
 *
 * Sibling to VulnAdvisoryPanel, deliberately flat rather than grouped: there
 * is one product here, not a package list, so per-package grouping would add
 * a level of nesting with exactly one child. CVEs arrive KEV-listed-first
 * (nvd_lookup.py's sort order), so capping the visible list never hides a
 * KEV-listed finding behind a lower-priority one.
 *
 * The unmatched-CPE case renders as its own explicit state. That matters: "we
 * found no CVEs" and "we could not look this product up" are different facts,
 * and showing the second as the first would be the overclaim this project
 * forbids everywhere else.
 */
export function DeviceCveAdvisoryPanel({
  identity,
  cves,
  notes,
  firmwareCurrency,
}: DeviceCveAdvisoryPanelProps) {
  const kevCount = cves.filter((cve) => cve.kev_listed).length;

  return (
    <div className="space-y-3">
      {firmwareCurrency && (
        <div className="space-y-1">
          <span
            className={cn(
              "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
              CURRENCY_STYLES[firmwareCurrency.status],
            )}
          >
            Firmware {CURRENCY_LABEL[firmwareCurrency.status]}
          </span>
          <p className="text-xs text-[var(--color-text-muted)]">{firmwareCurrency.reason}</p>
        </div>
      )}

      {identity && (
        <div className="flex flex-wrap items-center gap-2 text-xs">
          <span className="font-mono text-[var(--color-text)]">
            {identity.vendor ?? "Unknown vendor"} {identity.model ?? ""}
          </span>
          {identity.firmware_version && (
            <span className="text-[var(--color-text-muted)]">fw {identity.firmware_version}</span>
          )}
          {identity.cpe_matched ? (
            <span
              className="rounded-full bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] px-2 py-0.5 font-medium text-[var(--color-pass)]"
              title={identity.cpe ?? undefined}
            >
              CPE matched
            </span>
          ) : (
            <span className="rounded-full bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] px-2 py-0.5 font-medium text-[var(--color-text-muted)]">
              no CPE mapping
            </span>
          )}
          {kevCount > 0 && <KevBadge size="xs" />}
          <span className="ml-auto font-mono-tabular text-[var(--color-text-muted)]">
            {cves.length} CVE{cves.length === 1 ? "" : "s"}
          </span>
        </div>
      )}

      {cves.length > 0 && (
        <ul className="space-y-1.5">
          {cves.slice(0, CVES_SHOWN).map((cve) => (
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
              {/* Only ever shown when the comparison actually resolved. An
                  unresolved CVE gets no tag at all rather than a neutral
                  placeholder that could be misread as a verdict. */}
              {cve.version_status !== "unknown" && (
                <span
                  className={cn(
                    "shrink-0 rounded px-1.5 text-[10px] font-medium uppercase",
                    cve.version_status === "affected"
                      ? "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)]"
                      : cve.version_status === "affected_no_fix"
                        ? "bg-[color-mix(in_oklab,var(--color-high)_16%,transparent)] text-[var(--color-high)]"
                        : "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)]",
                  )}
                  title={cve.advisory_source ? `source: ${cve.advisory_source}` : undefined}
                >
                  {VERSION_STATUS_LABEL[cve.version_status]}
                  {cve.fixed_version ? ` · fixed ${cve.fixed_version}` : ""}
                </span>
              )}
              <span className="min-w-0 flex-1 truncate text-[var(--color-text-muted)]">{cve.summary}</span>
            </li>
          ))}
          {cves.length > CVES_SHOWN && (
            <li className="pl-5 text-xs text-[var(--color-text-muted)]">
              +{cves.length - CVES_SHOWN} more
            </li>
          )}
        </ul>
      )}

      {notes?.map((note) => (
        <p key={note} className="text-xs text-[var(--color-text-muted)]">
          {note}
        </p>
      ))}
    </div>
  );
}
