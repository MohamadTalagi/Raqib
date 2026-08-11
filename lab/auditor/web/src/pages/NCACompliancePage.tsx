import { useMemo, useState } from "react";
import { Link } from "react-router-dom";
import {
  ArrowUpRight,
  ClipboardCheck,
  Download,
  FileSpreadsheet,
  FileText,
  Gauge,
  HardDrive,
  Loader2,
  RefreshCw,
  ShieldAlert,
  Sparkles,
} from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { StatTile } from "@/components/ui/stat-tile";
import { NCAReadinessBadge, NCAStatusBadge } from "@/components/ui/severity-badge";
import { Tabs } from "@/components/ui/tabs";
import { Tooltip } from "@/components/ui/tooltip";
import { ComplianceGauge } from "@/components/charts/ComplianceGauge";
import { NCADomainBarChart } from "@/components/charts/NCADomainBarChart";
import { DomainSummaryGrid } from "@/components/nca/DomainSummaryGrid";
import { DeviceCohortPicker } from "@/components/pipeline/DeviceCohortPicker";
import { PhaseRunnerCard } from "@/components/pipeline/PhaseRunnerCard";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { applicableDomains } from "@/lib/nca";
import { useToast } from "@/lib/useToast";
import type { NCADeviceComplianceRow, NCAStatus } from "@/lib/types";

// review_required never actually appears as an overall_status (device_overall_status folds it
// into "partial" - see policies/nca/evaluator.py) but NCAStatus is shared with per-control
// assessment.status, so this Record must still cover it for TS exhaustiveness.
const ATTENTION_ORDER: Record<NCAStatus, number> = { fail: 0, partial: 1, not_tested: 2, review_required: 2, pass: 3 };

type StatusFilter = NCAStatus | "all";

const STATUS_TABS: Array<{ value: StatusFilter; label: string }> = [
  { value: "all", label: "All" },
  { value: "pass", label: "Passed" },
  { value: "partial", label: "Partially Compliant" },
  { value: "fail", label: "Failed" },
  { value: "not_tested", label: "Not Assessed" },
];

function matchesStatus(row: NCADeviceComplianceRow, status: StatusFilter): boolean {
  return status === "all" || row.overall_status === status;
}

export function NCACompliancePage() {
  const { showToast } = useToast();
  const [refreshKey, setRefreshKey] = useState(0);
  const summary = useFetch(api.ncaSummary, [refreshKey]);
  const coverage = useFetch(api.ncaCoverage, [refreshKey]);
  const domains = useFetch(api.ncaDomains, [refreshKey]);
  const devices = useFetch(api.ncaDevices, [refreshKey]);
  const [recomputing, setRecomputing] = useState(false);

  // The collector runner needs the full device records (services, firmware
  // state) that PhaseRunnerCard works from - ncaDevices only carries
  // compliance rollups.
  const allDevices = useFetch(api.devices, []);
  const scanTests = useFetch(api.scanTests, []);
  const [collectorCohort, setCollectorCohort] = useState<Set<string>>(new Set());
  const registeredDevices = useMemo(
    () => (allDevices.data ?? []).filter((device) => device.registered),
    [allDevices.data],
  );
  const complianceTests = useMemo(
    () => (scanTests.data ?? []).filter((test) => test.pipeline_phase === "nca_compliance"),
    [scanTests.data],
  );

  const [statusFilter, setStatusFilter] = useState<StatusFilter>("all");
  const [tierFilter, setTierFilter] = useState<string>("all");
  const [vendorFilter, setVendorFilter] = useState<string>("all");
  const [selected, setSelected] = useState<Set<string>>(new Set());

  function handleAssessSelected() {
    // No single workspace spans multiple devices - each selected device's
    // existing per-device assessment workspace opens in its own tab, in
    // turn, rather than building a new bulk-assessment page.
    for (const deviceId of selected) {
      window.open(`/nca-compliance/devices/${encodeURIComponent(deviceId)}`, "_blank", "noopener,noreferrer");
    }
  }

  async function handleRecompute() {
    setRecomputing(true);
    try {
      const result = await api.recomputeNcaAssessments();
      showToast(
        result.created === 0
          ? "No new automated findings to surface — every mapped (control, device) pair already has an assessment."
          : `${result.created} new not-tested assessment(s) surfaced from automated evidence — review and record a real finding for each.`,
        "success",
      );
      setRefreshKey((k) => k + 1);
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : "Could not recompute NCA mappings.", "error");
    } finally {
      setRecomputing(false);
    }
  }

  const vendors = useMemo(() => {
    const set = new Set((devices.data ?? []).map((d) => d.vendor).filter((v): v is string => Boolean(v)));
    return Array.from(set).sort();
  }, [devices.data]);

  const filteredDevices = useMemo(() => {
    return (devices.data ?? []).filter(
      (row) =>
        matchesStatus(row, statusFilter) &&
        (tierFilter === "all" || row.tier === tierFilter) &&
        (vendorFilter === "all" || row.vendor === vendorFilter),
    );
  }, [devices.data, statusFilter, tierFilter, vendorFilter]);

  const statusCounts = useMemo(() => {
    const counts: Record<NCAStatus, number> = { pass: 0, partial: 0, fail: 0, not_tested: 0, review_required: 0 };
    for (const row of devices.data ?? []) {
      counts[row.overall_status] += 1;
    }
    return counts;
  }, [devices.data]);

  // Governance and the mobile/supplier/cloud group are organization-scope
  // only (see OrganizationalCompliancePage) - a device has no device-scope
  // guideline in those domains at all, so they show up here as an all-zero
  // entry rather than a real, if untested, one. Excluded from this
  // per-device breakdown for that reason; kept on the organizational page,
  // where those same domains are exactly the ones that DO apply.
  const deviceApplicableDomains = useMemo(
    () => (domains.data ? applicableDomains(domains.data) : []),
    [domains.data],
  );

  const devicesNeedingAttention = useMemo(() => {
    return [...(devices.data ?? [])]
      .filter((row) => row.overall_status !== "pass")
      .sort((a, b) => {
        const byStatus = ATTENTION_ORDER[a.overall_status] - ATTENTION_ORDER[b.overall_status];
        if (byStatus !== 0) return byStatus;
        return (a.score ?? 0) - (b.score ?? 0);
      })
      .slice(0, 6);
  }, [devices.data]);

  const loading = summary.loading || domains.loading || devices.loading;
  const error = summary.error ?? domains.error ?? devices.error;

  return (
    <Shell
      title="NCA Compliance"
      subtitle="Alignment with NCA CGIoT-1:2024 guidance across registered devices"
      phase="compliance"
    >
      {error ? (
        <ErrorState message={error} />
      ) : (
        <div className="space-y-6">
          <Card className="border-[var(--color-brand)]/30 bg-[color-mix(in_oklab,var(--color-brand)_6%,var(--color-surface))]">
            <CardContent className="pt-5 text-sm leading-relaxed text-[var(--color-text-secondary)]">
              {loading || !summary.data ? (
                <Skeleton className="h-12" />
              ) : (
                <>
                  <p className="font-medium text-[var(--color-text)]">{summary.data.product_label}</p>
                  <p className="mt-1">{summary.data.disclaimer}</p>
                  <div className="mt-3 flex flex-wrap items-center gap-4">
                    <Link
                      to="/nca-compliance/organization"
                      className="inline-flex items-center gap-1 text-[var(--color-brand)] hover:underline"
                    >
                      View organizational compliance <ArrowUpRight className="h-3.5 w-3.5" />
                    </Link>
                    <Link
                      to="/nca-compliance/controls"
                      className="inline-flex items-center gap-1 text-[var(--color-brand)] hover:underline"
                    >
                      Browse all {summary.data.total_controls} controls <ArrowUpRight className="h-3.5 w-3.5" />
                    </Link>
                    <Tooltip
                      content="Scans relevant evidence for controls with no assessment yet and surfaces them as not-tested — a human still records the actual finding."
                      className="ml-auto"
                    >
                      <button
                        type="button"
                        onClick={handleRecompute}
                        disabled={recomputing}
                        className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)] disabled:cursor-not-allowed disabled:opacity-50"
                      >
                        {recomputing ? (
                          <Loader2 className="h-3.5 w-3.5 animate-spin" />
                        ) : (
                          <RefreshCw className="h-3.5 w-3.5" />
                        )}
                        Recompute from evidence
                      </button>
                    </Tooltip>
                  </div>
                </>
              )}
            </CardContent>
          </Card>

          <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4">
            {loading || !summary.data ? (
              <>
                <Skeleton className="h-28" />
                <Skeleton className="h-28" />
                <Skeleton className="h-28" />
                <Skeleton className="h-28" />
              </>
            ) : (
              <>
                <StatTile
                  label="Devices assessed"
                  value={summary.data.total_devices}
                  icon={HardDrive}
                  accent="neutral"
                />
                <StatTile
                  label="Failing devices"
                  value={statusCounts.fail}
                  icon={ShieldAlert}
                  accent="critical"
                />
                <StatTile
                  label="Controls in catalog"
                  value={summary.data.total_controls}
                  icon={ClipboardCheck}
                  accent="neutral"
                  hint={`${summary.data.framework} ${summary.data.framework_version}`}
                />
                <StatTile
                  label="Guided or automated"
                  value={coverage.data ? `${coverage.data.guided_or_automated_count}/${coverage.data.total_guidelines}` : "…"}
                  icon={Sparkles}
                  accent="neutral"
                  hint="collector or checklist support"
                />
              </>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-1">
              <CardHeader>
                <CardTitle>NCA Control Pass Rate</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center gap-3 pb-6">
                {loading || !summary.data ? (
                  <Skeleton className="h-40 w-40 rounded-full" />
                ) : summary.data.overall_pass_percentage === null ? (
                  <div className="flex h-40 w-40 items-center justify-center rounded-full border border-[var(--color-border)]">
                    <Gauge className="h-8 w-8 text-[var(--color-text-muted)]" />
                  </div>
                ) : (
                  <ComplianceGauge score={summary.data.overall_pass_percentage} sourceLabel="NCA CONTROLS" />
                )}
                <p className="text-center text-xs text-[var(--color-text-muted)]">
                  Informational only, never the strict per-control status
                </p>
              </CardContent>
            </Card>

            <Card className="xl:col-span-2">
              <CardHeader>
                <CardTitle>Domain summary</CardTitle>
              </CardHeader>
              <CardContent className="pt-2">
                {loading || !domains.data ? (
                  <Skeleton className="h-64" />
                ) : deviceApplicableDomains.length === 0 ? (
                  <EmptyState message="No device-scope controls loaded." />
                ) : (
                  <NCADomainBarChart domains={Object.fromEntries(deviceApplicableDomains)} />
                )}
              </CardContent>
            </Card>
          </div>

          {!loading && deviceApplicableDomains.length > 0 ? (
            <DomainSummaryGrid domains={deviceApplicableDomains} />
          ) : null}

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-2">
              <CardHeader>
                <CardTitle>Devices needing attention</CardTitle>
              </CardHeader>
              <CardContent className="pt-2">
                {loading || !devices.data ? (
                  <Skeleton className="h-40" />
                ) : devicesNeedingAttention.length === 0 ? (
                  <p className="py-6 text-center text-sm text-[var(--color-text-muted)]">
                    No device currently fails or is only partially compliant.
                  </p>
                ) : (
                  <ul className="divide-y divide-[var(--color-border)]">
                    {devicesNeedingAttention.map((row) => (
                      <li key={row.device_id} className="flex items-center gap-4 py-2.5 text-sm">
                        <Link
                          to={`/devices/${row.device_id}`}
                          className="min-w-0 flex-1 truncate font-medium text-[var(--color-text)] hover:text-[var(--color-brand)] hover:underline"
                        >
                          {row.display_name}
                        </Link>
                        <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                          {row.score === null ? "—" : `${row.score}%`}
                        </span>
                        <NCAStatusBadge status={row.overall_status} />
                      </li>
                    ))}
                  </ul>
                )}
              </CardContent>
            </Card>

            <Card className="xl:col-span-1">
              <CardHeader>
                <CardTitle>Reports</CardTitle>
              </CardHeader>
              <CardContent className="pt-2">
                <p className="mb-3 text-xs text-[var(--color-text-muted)]">
                  Export the current NCA CGIoT-1:2024 compliance state.
                </p>
                <div className="grid grid-cols-1 gap-2 sm:grid-cols-2">
                  <a
                    href={api.ncaDeviceReportCsvUrl()}
                    download
                    className="flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  >
                    <FileSpreadsheet className="h-4 w-4 shrink-0" />
                    Devices (CSV)
                  </a>
                  <a
                    href={api.ncaControlsReportCsvUrl()}
                    download
                    className="flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  >
                    <FileSpreadsheet className="h-4 w-4 shrink-0" />
                    Controls (CSV)
                  </a>
                  <a
                    href={api.ncaEvidenceReportCsvUrl()}
                    download
                    className="flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  >
                    <FileSpreadsheet className="h-4 w-4 shrink-0" />
                    Evidence (CSV)
                  </a>
                  <a
                    href={api.ncaExecutiveReportPdfUrl()}
                    download
                    className="flex items-center gap-2 rounded-md border border-[var(--color-border)] px-3 py-2 text-sm text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)] hover:text-[var(--color-text)]"
                  >
                    <FileText className="h-4 w-4 shrink-0" />
                    Executive summary (PDF)
                  </a>
                </div>
                <p className="mt-3 flex items-center gap-1.5 text-[11px] text-[var(--color-text-muted)]">
                  <Download className="h-3 w-3" />
                  Downloads reflect live data as of the moment you open them.
                </p>
              </CardContent>
            </Card>
          </div>

          {/* Collector runner, rehomed here when the SA-IOT Compliance stage
              was retired. These are the same 18 device-scope collectors that
              stage ran; they were always the evidence behind this page's own
              finding mappings and auto-suggestions, so they belong here rather
              than behind a separate stage. Without this section they would be
              reachable only through a Fully Automated Run. */}
          {!loading && (registeredDevices?.length ?? 0) > 0 && complianceTests.length > 0 && (
            <Card>
              <CardHeader className="flex-col items-start gap-2">
                <CardTitle>Collect compliance evidence</CardTitle>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Run the device-scope collectors that feed this framework's automated findings -
                  default credentials, TLS, MQTT, logging, tamper status and the firmware checks.
                  Record each finding, then assess the affected guidelines below.
                </p>
              </CardHeader>
              <CardContent className="space-y-4 pt-2">
                <DeviceCohortPicker
                  devices={registeredDevices ?? []}
                  selected={collectorCohort}
                  onChange={setCollectorCohort}
                />
                {(registeredDevices ?? [])
                  .filter((device) => collectorCohort.has(device.device_id))
                  .map((device) => (
                    <PhaseRunnerCard
                      key={device.device_id}
                      device={device}
                      tests={complianceTests.filter((test) =>
                        test.applicable_service_types.length === 0
                          ? Boolean(device.firmware_sha256)
                          : device.services.some(
                              (service) =>
                                service.enabled &&
                                test.applicable_service_types.includes(service.service_type),
                            ),
                      )}
                      emptyHint={
                        <p className="text-xs text-[var(--color-text-muted)]">
                          No compliance collector applies to this device's registered services.
                        </p>
                      }
                    />
                  ))}
              </CardContent>
            </Card>
          )}

          {!loading && (devices.data?.length ?? 0) > 0 && (
            <Card>
              <CardHeader className="flex-col items-start gap-2">
                <CardTitle>Assess a cohort</CardTitle>
                <p className="text-xs text-[var(--color-text-secondary)]">
                  Select one, some, or all devices to open their assessment workspace, in turn.
                </p>
              </CardHeader>
              <CardContent className="space-y-3 pt-2">
                <DeviceCohortPicker devices={devices.data ?? []} selected={selected} onChange={setSelected} />
                <button
                  type="button"
                  onClick={handleAssessSelected}
                  disabled={selected.size === 0}
                  className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <ClipboardCheck className="h-4 w-4" />
                  Assess selected ({selected.size})
                </button>
              </CardContent>
            </Card>
          )}

          <Card>
            <CardHeader className="flex-col items-start gap-3">
              <CardTitle>Device compliance</CardTitle>
              <Tabs
                items={STATUS_TABS.map((tab) => ({
                  value: tab.value,
                  label: tab.label,
                  count: tab.value === "all" ? devices.data?.length ?? 0 : statusCounts[tab.value as NCAStatus],
                }))}
                value={statusFilter}
                onChange={(v) => setStatusFilter(v as StatusFilter)}
              />
              <div className="flex flex-wrap gap-3">
                <select
                  aria-label="Filter by device type"
                  value={tierFilter}
                  onChange={(e) => setTierFilter(e.target.value)}
                  className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text-secondary)]"
                >
                  <option value="all">All device types</option>
                  <option value="insecure">Insecure</option>
                  <option value="partial">Partial</option>
                  <option value="hardened">Hardened</option>
                  <option value="unknown">Unknown</option>
                </select>
                <select
                  aria-label="Filter by manufacturer"
                  value={vendorFilter}
                  onChange={(e) => setVendorFilter(e.target.value)}
                  className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text-secondary)]"
                >
                  <option value="all">All manufacturers</option>
                  {vendors.map((vendor) => (
                    <option key={vendor} value={vendor}>
                      {vendor}
                    </option>
                  ))}
                </select>
              </div>
            </CardHeader>
            <CardContent className="pt-2">
              {loading || !devices.data ? (
                <div className="space-y-2">
                  <Skeleton className="h-12" />
                  <Skeleton className="h-12" />
                  <Skeleton className="h-12" />
                </div>
              ) : filteredDevices.length === 0 ? (
                <EmptyState message="No devices match the current filters." />
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[var(--color-border)] text-left text-xs text-[var(--color-text-muted)] uppercase">
                        <th className="py-2 pr-4">Device</th>
                        <th className="py-2 pr-4">Type</th>
                        <th className="py-2 pr-4">Manufacturer</th>
                        <th className="py-2 pr-4">Status</th>
                        <th className="py-2 pr-4">Readiness</th>
                        <th className="py-2 pr-4 text-right">Assess</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[var(--color-border)]">
                      {filteredDevices.map((row) => (
                        <tr key={row.device_id}>
                          <td className="py-2.5 pr-4">
                            <Link
                              to={`/devices/${row.device_id}`}
                              className="inline-flex items-center gap-1 font-medium text-[var(--color-text)] hover:text-[var(--color-brand)] hover:underline"
                            >
                              {row.display_name}
                              <ArrowUpRight className="h-3 w-3" />
                            </Link>
                            <div className="font-mono text-xs text-[var(--color-text-muted)]">{row.device_id}</div>
                          </td>
                          <td className="py-2.5 pr-4 text-[var(--color-text-secondary)]">{row.tier}</td>
                          <td className="py-2.5 pr-4 text-[var(--color-text-secondary)]">
                            {row.vendor ?? <span className="text-[var(--color-text-muted)]">unknown</span>}
                          </td>
                          <td className="py-2.5 pr-4">
                            <NCAStatusBadge status={row.overall_status} />
                          </td>
                          <td className="py-2.5 pr-4">
                            <div className="flex items-center gap-2">
                              <NCAReadinessBadge classification={row.readiness_classification} size="sm" />
                              <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                                {row.score === null ? "—" : `${row.score}%`}
                              </span>
                            </div>
                          </td>
                          <td className="py-2.5 pr-4 text-right">
                            <Link
                              to={`/nca-compliance/devices/${encodeURIComponent(row.device_id)}`}
                              className="inline-flex items-center gap-1 rounded-md bg-[var(--color-brand)] px-2.5 py-1 text-xs font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
                            >
                              <ClipboardCheck className="h-3.5 w-3.5" />
                              Assess
                            </Link>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </Shell>
  );
}
