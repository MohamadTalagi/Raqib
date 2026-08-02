import { useState } from "react";
import { Link } from "react-router-dom";
import { ChevronDown, FileDown, Printer, HardDrive, Gauge, ShieldAlert, Wrench } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { StatTile } from "@/components/ui/stat-tile";
import {
  AiGeneratedBadge,
  BlockingBadge,
  NCAStatusBadge,
  RiskCategoryBadge,
  StatusBadge,
} from "@/components/ui/severity-badge";
import { PqcReadinessPanel } from "@/components/pipeline/PqcReadinessPanel";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type {
  ExecutiveSummaryDevice,
  NCAStatus,
  PqcCriterionCounts,
  RemediationPriority,
} from "@/lib/types";

const PQC_CRITERION_LABEL: Record<"tls_key_exchange" | "certificate_signature" | "firmware_crypto", string> = {
  tls_key_exchange: "TLS key exchange (KEM)",
  certificate_signature: "Certificate signature algorithm",
  firmware_crypto: "Firmware crypto library currency",
};

function PqcCriterionCountsRow({ label, counts }: { label: string; counts: PqcCriterionCounts }) {
  return (
    <tr className="border-t border-[var(--color-border)] text-sm">
      <td className="py-2 pr-4 text-[var(--color-text)]">{label}</td>
      <td className="py-2 pr-4 text-[var(--color-pass)]">{counts.pass}</td>
      <td className="py-2 pr-4 text-[var(--color-critical)]">{counts.fail}</td>
      <td className="py-2 pr-4 text-[var(--color-inconclusive)]">{counts.unknown}</td>
      <td className="py-2 text-[var(--color-text-muted)]">{counts.not_applicable}</td>
    </tr>
  );
}

const PRIORITY_LABEL: Record<RemediationPriority, string> = {
  immediate: "Immediate",
  short_term: "Short-term",
  long_term: "Long-term",
};

function DeviceDetailPanel({ device }: { device: ExecutiveSummaryDevice }) {
  return (
    <div className="space-y-4">
      <div>
        <p className="mb-1.5 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
          Compliance gaps
        </p>
        {device.sa_iot_gaps.length === 0 && device.nca_gaps.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)]">No compliance gaps recorded for this device.</p>
        ) : (
          <ul className="space-y-1.5">
            {device.sa_iot_gaps.map((g) => (
              <li key={`sa-${g.control_id}`} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="rounded-md bg-[var(--color-surface-hover)] px-1.5 py-0.5 text-[10px] font-medium uppercase text-[var(--color-text-secondary)]">
                  SA-IOT
                </span>
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{g.control_id}</span>
                <StatusBadge status={g.status} />
                <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">{g.reason}</span>
              </li>
            ))}
            {device.nca_gaps.map((g) => (
              <li key={`nca-${g.control_id}`} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="rounded-md bg-[var(--color-surface-hover)] px-1.5 py-0.5 text-[10px] font-medium uppercase text-[var(--color-text-secondary)]">
                  NCA
                </span>
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{g.guideline_id}</span>
                <NCAStatusBadge status={g.status as NCAStatus} />
                {g.blocking && <BlockingBadge size="xs" />}
                <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                  {g.canonical_requirement}
                </span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <p className="mb-1.5 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
          Evidence and tools
        </p>
        {device.evidence.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)]">No evidence recorded for this device.</p>
        ) : (
          <ul className="space-y-1.5">
            {device.evidence.map((e) => (
              <li key={e.evidence_id} className="flex flex-wrap items-center gap-2 text-sm">
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{e.evidence_id}</span>
                <span className="font-mono text-xs text-[var(--color-text-muted)]">{e.test_id}</span>
                <span className="rounded-md bg-[var(--color-surface-hover)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-secondary)]">
                  {e.tool} {e.tool_version}
                </span>
                <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">{e.finding}</span>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <p className="mb-1.5 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
          Remediation
        </p>
        {device.remediation.length === 0 ? (
          <p className="text-xs text-[var(--color-text-muted)]">No remediation blueprints generated yet.</p>
        ) : (
          <ul className="space-y-2">
            {device.remediation.map((r) => (
              <li key={r.id} className="rounded-md border border-[var(--color-border)] p-2.5 text-sm">
                <div className="flex flex-wrap items-center gap-2">
                  <span className="font-mono text-xs text-[var(--color-text-muted)]">{r.control_id}</span>
                  <span className="text-xs font-semibold uppercase text-[var(--color-text-secondary)]">
                    {PRIORITY_LABEL[r.priority]}
                  </span>
                  {!r.reviewed && <AiGeneratedBadge size="xs" />}
                  {r.reviewed && (
                    <span className="text-xs text-[var(--color-pass)]">Reviewed by {r.reviewed_by}</span>
                  )}
                </div>
                <p className="mt-1 text-[var(--color-text-secondary)]">{r.root_cause}</p>
              </li>
            ))}
          </ul>
        )}
      </div>

      <div>
        <p className="mb-1.5 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
          Post-quantum readiness <span className="normal-case text-[var(--color-text-muted)]">(informational only)</span>
        </p>
        <PqcReadinessPanel readiness={device.pqc_readiness} />
      </div>

      <Link
        to={`/devices/${device.device_id}`}
        className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--color-brand)] hover:underline"
      >
        View device
      </Link>
    </div>
  );
}

/**
 * The last analytical stage of the pipeline (IoTGuard Stage 08): aggregates
 * every device's real risk score, compliance gaps, evidence/tools, and
 * AI-assisted (human-reviewed) remediation into one fleet-wide view. No
 * AI-generated narrative text anywhere on this page or its exports - every
 * figure is a real, already-computed value, matching the same rule every
 * other report in this app already follows.
 */
export function ExecutiveSummaryPage() {
  const summary = useFetch(api.executiveSummary, []);
  const [expanded, setExpanded] = useState<string | null>(null);

  const data = summary.data;

  return (
    <Shell
      title="Executive Summary"
      subtitle="Fleet-wide security posture: risk, compliance, evidence, and remediation in one view"
    >
      {summary.error ? (
        <ErrorState message={summary.error} />
      ) : summary.loading || !data ? (
        <div className="space-y-4">
          <Skeleton className="h-28" />
          <Skeleton className="h-96" />
        </div>
      ) : (
        <div className="space-y-6">
          <div className="flex justify-end gap-2">
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            >
              <Printer className="h-4 w-4" /> Print / Save as PDF
            </button>
            <a
              href={api.executiveSummaryReportPdfUrl()}
              className="inline-flex items-center gap-1.5 rounded-md bg-[var(--color-brand)] px-3 py-1.5 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
            >
              <FileDown className="h-4 w-4" /> Download PDF
            </a>
            <a
              href={api.executiveSummaryReportHtmlUrl()}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            >
              HTML
            </a>
          </div>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            <StatTile label="Devices" value={data.fleet_summary.total_devices} icon={HardDrive} accent="neutral" />
            <StatTile
              label="Average risk score"
              value={data.fleet_summary.average_risk_score ?? "n/a"}
              icon={Gauge}
              accent="brand"
            />
            <StatTile
              label="Compliance gaps"
              value={data.fleet_summary.total_compliance_gaps}
              icon={ShieldAlert}
              accent="critical"
            />
            <StatTile
              label="Remediation coverage"
              value={
                data.fleet_summary.remediation_coverage_pct !== null
                  ? `${data.fleet_summary.remediation_coverage_pct}%`
                  : "n/a"
              }
              icon={Wrench}
              accent="neutral"
              hint={`${data.fleet_summary.remediation_generated} generated, ${data.fleet_summary.remediation_reviewed} reviewed`}
            />
          </div>

          <Card>
            <CardHeader>
              <CardTitle>Priority recommendations</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              {data.priority_recommendations.length === 0 ? (
                <EmptyState message="No unreviewed immediate-priority remediation right now." />
              ) : (
                <ul className="divide-y divide-[var(--color-border)]">
                  {data.priority_recommendations.map((r) => (
                    <li key={r.id} className="flex flex-wrap items-center gap-2 py-2 text-sm">
                      <Link
                        to={`/devices/${r.device_id}`}
                        className="font-medium text-[var(--color-text)] hover:text-[var(--color-brand)] hover:underline"
                      >
                        {r.device_display_name}
                      </Link>
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{r.control_id}</span>
                      <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                        {r.root_cause}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Most significant compliance gaps</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              {data.significant_compliance_gaps.length === 0 ? (
                <EmptyState message="No blocking NCA controls are currently failing." />
              ) : (
                <ul className="divide-y divide-[var(--color-border)]">
                  {data.significant_compliance_gaps.map((g) => (
                    <li key={`${g.device_id}-${g.control_id}`} className="flex flex-wrap items-center gap-2 py-2 text-sm">
                      <Link
                        to={`/devices/${g.device_id}`}
                        className="font-medium text-[var(--color-text)] hover:text-[var(--color-brand)] hover:underline"
                      >
                        {g.device_display_name}
                      </Link>
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{g.guideline_id}</span>
                      <BlockingBadge size="xs" />
                      <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">
                        {g.canonical_requirement}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Post-Quantum Readiness (informational)</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <p className="mb-3 text-xs text-[var(--color-text-muted)]">
                3 named technical criteria grounded in real NIST standards (FIPS 203 ML-KEM, FIPS 204 ML-DSA, FIPS
                205 SLH-DSA) - no enforceable IoT post-quantum regulation exists yet, so this is not a compliance
                framework. Never affects the risk scores or compliance gaps above.
              </p>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="text-left text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase">
                      <th className="pb-2 pr-4">Criterion</th>
                      <th className="pb-2 pr-4">Pass</th>
                      <th className="pb-2 pr-4">Fail</th>
                      <th className="pb-2 pr-4">Unknown</th>
                      <th className="pb-2">Not applicable</th>
                    </tr>
                  </thead>
                  <tbody>
                    <PqcCriterionCountsRow
                      label={PQC_CRITERION_LABEL.tls_key_exchange}
                      counts={data.post_quantum_readiness.tls_key_exchange}
                    />
                    <PqcCriterionCountsRow
                      label={PQC_CRITERION_LABEL.certificate_signature}
                      counts={data.post_quantum_readiness.certificate_signature}
                    />
                    <PqcCriterionCountsRow
                      label={PQC_CRITERION_LABEL.firmware_crypto}
                      counts={data.post_quantum_readiness.firmware_crypto}
                    />
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Devices, ranked by risk (highest first)</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              {data.devices.length === 0 ? (
                <EmptyState message="No devices registered yet." />
              ) : (
                <div className="space-y-3">
                  {data.devices.map((device) => {
                    const isOpen = expanded === device.device_id;
                    return (
                      <Card key={device.device_id} className="overflow-hidden py-0">
                        <button
                          type="button"
                          onClick={() => setExpanded(isOpen ? null : device.device_id)}
                          className="flex w-full cursor-pointer items-center gap-4 px-5 py-3.5 text-left transition-colors hover:bg-[var(--color-surface-hover)]"
                        >
                          <span className="font-mono-tabular w-8 shrink-0 text-sm text-[var(--color-text-muted)]">
                            #{device.priority_rank}
                          </span>
                          <span className="min-w-0 flex-1 truncate text-sm text-[var(--color-text)]">
                            {device.display_name}
                          </span>
                          <span className="font-mono text-xs text-[var(--color-text-muted)]">{device.device_id}</span>
                          <span className="font-mono-tabular shrink-0 text-sm text-[var(--color-text-secondary)]">
                            {device.risk_score}
                          </span>
                          <RiskCategoryBadge category={device.risk_category} size="sm" />
                          <ChevronDown
                            className={cn(
                              "h-4 w-4 shrink-0 text-[var(--color-text-muted)] transition-transform",
                              isOpen && "rotate-180",
                            )}
                          />
                        </button>
                        {isOpen && (
                          <div className="border-t border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4">
                            <DeviceDetailPanel device={device} />
                          </div>
                        )}
                      </Card>
                    );
                  })}
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </Shell>
  );
}
