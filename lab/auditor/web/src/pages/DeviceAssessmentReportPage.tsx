import { Link, useParams } from "react-router-dom";
import { ArrowLeft, FileDown, Printer } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import {
  NCAReadinessBadge,
  NCAStatusBadge,
  RiskCategoryBadge,
  SeverityBadge,
  StatusBadge,
} from "@/components/ui/severity-badge";
import { VulnAdvisoryPanel } from "@/components/devices/VulnAdvisoryPanel";
import { VulnFreshnessNote } from "@/components/devices/VulnFreshnessNote";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { RISK_FACTOR_LABELS, formatRiskRawValue } from "@/lib/risk";
import { RISK_FACTOR_KEYS, type VerdictStatus, type Severity } from "@/lib/types";

function isVerdictStatus(v: string): v is VerdictStatus {
  return ["PASS", "FAIL", "PARTIAL", "INCONCLUSIVE", "NOT_APPLICABLE"].includes(v);
}
function isSeverity(v: string): v is Severity {
  return ["low", "medium", "high", "critical"].includes(v);
}

interface FieldProps {
  label: string;
  value: string | null | undefined;
}
function Field({ label, value }: FieldProps) {
  return (
    <div>
      <p className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">{label}</p>
      <p className="mt-0.5 text-sm text-[var(--color-text)]">
        {value ? value : <span className="text-[var(--color-text-muted)]">Not recorded</span>}
      </p>
    </div>
  );
}

/**
 * A single consolidated assessment for one registered device: everything on
 * record for it - profile + inventory the user entered, services, firmware,
 * NCA compliance readiness, verdicts per control, and the evidence behind
 * them - in one reviewable, printable page. Downloads (PDF/HTML/JSON) reuse
 * the existing server-rendered report endpoints.
 */
export function DeviceAssessmentReportPage() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const detail = useFetch(() => api.device(deviceId ?? ""), [deviceId]);
  const nca = useFetch(() => api.ncaDevice(deviceId ?? ""), [deviceId]);
  const vulnSummary = useFetch(() => api.vulnIntelDevice(deviceId ?? ""), [deviceId]);
  const riskDetail = useFetch(() => api.riskDevice(deviceId ?? ""), [deviceId]);
  const reportHistory = useFetch(() => api.reportHistory(deviceId ?? ""), [deviceId]);

  if (detail.error) {
    return (
      <Shell title="Assessment" subtitle={deviceId}>
        <ErrorState message={detail.error} />
      </Shell>
    );
  }

  if (detail.loading || !detail.data) {
    return (
      <Shell title="Assessment" subtitle={deviceId}>
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-64" />
        </div>
      </Shell>
    );
  }

  const { device, services, evidence, verdicts, compliance } = detail.data;
  const generatedAt = new Date().toISOString().replace("T", " ").slice(0, 19) + " UTC";

  return (
    <Shell title={`Assessment: ${device.display_name}`} subtitle={`${device.device_id} · consolidated device assessment`}>
      <div className="space-y-6">
        {/* Actions (hidden when printing) */}
        <div className="flex flex-wrap items-center gap-3 print:hidden">
          <Link
            to={`/devices/${device.device_id}`}
            className="inline-flex items-center gap-1 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-text)]"
          >
            <ArrowLeft className="h-3.5 w-3.5" /> Back to device
          </Link>
          <div className="ml-auto flex flex-wrap gap-2">
            <button
              type="button"
              onClick={() => window.print()}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            >
              <Printer className="h-4 w-4" /> Print / Save as PDF
            </button>
            <a
              href={api.deviceReportUrl(device.device_id)}
              className="inline-flex items-center gap-1.5 rounded-md bg-[var(--color-brand)] px-3 py-1.5 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
            >
              <FileDown className="h-4 w-4" /> Download PDF
            </a>
            <a
              href={api.deviceReportHtmlUrl(device.device_id)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            >
              HTML
            </a>
            <a
              href={api.deviceReportJsonUrl(device.device_id)}
              className="inline-flex items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-sm text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)]"
            >
              JSON
            </a>
          </div>
        </div>

        <p className="text-xs text-[var(--color-text-muted)]">Generated {generatedAt}</p>

        {/* Report history - an append-only log of past exports, not a cache
            of what any of them said (report content is always assembled
            fresh; see report_records in init.sql). */}
        {reportHistory.data && reportHistory.data.length > 0 && (
          <Card className="print:hidden">
            <CardHeader>
              <CardTitle>Report history</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <ul className="flex flex-wrap gap-x-4 gap-y-1 text-xs text-[var(--color-text-muted)]">
                {reportHistory.data.slice(0, 8).map((r) => (
                  <li key={r.id} className="font-mono">
                    {r.format.toUpperCase()} · {r.generated_at}
                  </li>
                ))}
              </ul>
            </CardContent>
          </Card>
        )}

        {/* Device profile + inventory */}
        <Card>
          <CardHeader>
            <CardTitle>Device profile</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 pt-2 sm:grid-cols-3">
            <Field label="Device ID" value={device.device_id} />
            <Field label="Display name" value={device.display_name} />
            <Field label="Host" value={device.host} />
            <Field label="Type / tier" value={device.tier} />
            <Field label="Vendor" value={device.vendor} />
            <Field label="Model" value={device.model} />
            <Field label="Location" value={device.location} />
            <Field label="Owner" value={device.owner} />
            <Field label="Source" value={device.source} />
            <div className="col-span-2 sm:col-span-3">
              <Field label="Description" value={device.description} />
            </div>
            <div className="col-span-2 sm:col-span-3">
              <Field label="Notes" value={device.notes} />
            </div>
          </CardContent>
        </Card>

        {/* Services */}
        <Card>
          <CardHeader>
            <CardTitle>Exposed services ({services.length})</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {services.length === 0 ? (
              <EmptyState message="No services registered." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {services.map((s) => (
                  <li key={s.id} className="flex flex-wrap items-center gap-3 py-2 text-sm">
                    <span className="font-mono text-xs text-[var(--color-text)]">{s.service_type}</span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">
                      port {s.port}
                      {s.published_port ? ` → ${s.published_port}` : ""}
                    </span>
                    {!s.enabled && (
                      <span className="rounded bg-[var(--color-surface-hover)] px-1.5 py-0.5 text-[10px] text-[var(--color-text-muted)]">
                        disabled
                      </span>
                    )}
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Firmware */}
        <Card>
          <CardHeader>
            <CardTitle>Firmware</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 pt-2 sm:grid-cols-3">
            {device.firmware_filename ? (
              <>
                <Field label="Filename" value={device.firmware_filename} />
                <Field label="Uploaded" value={device.firmware_uploaded_at} />
                <Field label="SHA-256" value={device.firmware_sha256 ? `${device.firmware_sha256.slice(0, 24)}…` : null} />
              </>
            ) : (
              <p className="col-span-2 text-sm text-[var(--color-text-muted)] sm:col-span-3">
                No firmware uploaded for this device.
              </p>
            )}
          </CardContent>
        </Card>

        {/* Vulnerability intelligence */}
        <Card>
          <CardHeader>
            <CardTitle>
              Vulnerability intelligence
              {vulnSummary.data?.has_data ? ` (${vulnSummary.data.total_cves} CVEs)` : ""}
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-2">
            {vulnSummary.loading ? (
              <Skeleton className="h-24" />
            ) : !vulnSummary.data?.has_data ? (
              <p className="text-sm text-[var(--color-text-muted)]">
                No firmware manifest scan (TEST-FW-MANIFEST) has been recorded for this device.
              </p>
            ) : (
              <>
                <VulnAdvisoryPanel packages={vulnSummary.data.packages} />
                <VulnFreshnessNote />
              </>
            )}
          </CardContent>
        </Card>

        {/* Risk assessment */}
        <Card>
          <CardHeader className="flex-row items-center justify-between">
            <CardTitle>Risk assessment</CardTitle>
            {riskDetail.data?.known && riskDetail.data.risk_category && (
              <div className="flex items-center gap-2">
                <span className="font-mono-tabular text-sm text-[var(--color-text-secondary)]">
                  {riskDetail.data.risk_score}/100
                </span>
                <RiskCategoryBadge category={riskDetail.data.risk_category} size="sm" />
              </div>
            )}
          </CardHeader>
          <CardContent className="space-y-3 pt-2">
            {riskDetail.loading ? (
              <Skeleton className="h-40" />
            ) : !riskDetail.data?.known || !riskDetail.data.breakdown ? (
              <p className="text-sm text-[var(--color-text-muted)]">
                Risk score unavailable for this device.
              </p>
            ) : (
              <ul className="divide-y divide-[var(--color-border)] text-sm">
                {RISK_FACTOR_KEYS.map((key) => {
                  const factor = riskDetail.data!.breakdown![key];
                  return (
                    <li key={key} className="flex items-center justify-between gap-4 py-2">
                      <div className="min-w-0">
                        <p className="text-[var(--color-text)]">{RISK_FACTOR_LABELS[key]}</p>
                        <p className="font-mono text-xs text-[var(--color-text-muted)]">
                          raw: {formatRiskRawValue(factor.raw_value)} · weight{" "}
                          {Math.round(factor.weight * 100)}%
                        </p>
                      </div>
                      <span className="font-mono-tabular shrink-0 text-[var(--color-text)]">
                        +{factor.contribution.toFixed(1)}
                      </span>
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* NCA compliance readiness */}
        <Card>
          <CardHeader>
            <CardTitle>NCA CGIoT-1:2024 compliance</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-2">
            <div className="flex flex-wrap items-center gap-4">
              <div>
                <p className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                  Automated scan coverage
                </p>
                <p className="mt-0.5 text-sm text-[var(--color-text)]">
                  {compliance.passing_controls}/{compliance.tested_controls} controls passing
                  {compliance.percentage !== null ? ` (${compliance.percentage}%)` : ""}
                </p>
              </div>
              {nca.data && (
                <>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                      Readiness
                    </span>
                    <NCAReadinessBadge classification={nca.data.readiness.classification} size="sm" />
                  </div>
                  <div className="flex items-center gap-2">
                    <span className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                      Status
                    </span>
                    <NCAStatusBadge status={nca.data.overall_status} />
                  </div>
                </>
              )}
            </div>
            {nca.data && nca.data.readiness.reasons.length > 0 && (
              <ul className="list-disc space-y-0.5 pl-4 text-xs text-[var(--color-text-secondary)]">
                {nca.data.readiness.reasons.map((r, i) => (
                  <li key={i}>{r}</li>
                ))}
              </ul>
            )}
            <p className="text-[11px] text-[var(--color-text-muted)]">
              This alignment summary is not an NCA certification. See the assessment workspace for per-control detail.
            </p>
          </CardContent>
        </Card>

        {/* Verdicts */}
        <Card>
          <CardHeader>
            <CardTitle>Control verdicts ({verdicts.length})</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {verdicts.length === 0 ? (
              <EmptyState message="No verdicts recorded for this device." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {verdicts.map((v) => (
                  <li key={v.verdict_id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    {isVerdictStatus(v.status) ? (
                      <StatusBadge status={v.status} />
                    ) : (
                      <span className="font-mono text-xs">{v.status}</span>
                    )}
                    {isSeverity(v.severity) ? (
                      <SeverityBadge severity={v.severity} />
                    ) : (
                      <span className="font-mono text-xs">{v.severity}</span>
                    )}
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.control_id}</span>
                    <span className="min-w-0 flex-1 text-[var(--color-text-secondary)]">{v.reason}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        {/* Evidence */}
        <Card>
          <CardHeader>
            <CardTitle>Evidence collected ({evidence.length})</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {evidence.length === 0 ? (
              <EmptyState message="No evidence collected for this device." />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-muted)] uppercase">
                      <th className="py-2 pr-4">Evidence</th>
                      <th className="py-2 pr-4">Test</th>
                      <th className="py-2 pr-4">Finding</th>
                      <th className="py-2 pr-4">Confidence</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[var(--color-border)]">
                    {evidence.map((e) => (
                      <tr key={e.evidence_id}>
                        <td className="py-2 pr-4 font-mono text-xs text-[var(--color-text-muted)]">{e.evidence_id}</td>
                        <td className="py-2 pr-4 font-mono text-xs text-[var(--color-text-muted)]">{e.test_id}</td>
                        <td className="py-2 pr-4 text-[var(--color-text-secondary)]">{e.finding}</td>
                        <td className="py-2 pr-4 text-xs text-[var(--color-text-secondary)]">{e.confidence}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
