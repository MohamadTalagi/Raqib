import { useMemo } from "react";
import { Bug, FileSearch, Flame, Gavel, HardDrive, ShieldAlert } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ui/state";
import { StatTile } from "@/components/ui/stat-tile";
import {
  StatusBadge,
  SeverityBadge,
  ComplianceBadge,
  KevBadge,
  RiskCategoryBadge,
} from "@/components/ui/severity-badge";
import { VulnFreshnessNote } from "@/components/devices/VulnFreshnessNote";
import { Link } from "react-router-dom";
import { VerdictDonut } from "@/components/charts/VerdictDonut";
import { DeviceActivityBar } from "@/components/charts/DeviceActivityBar";
import { ComplianceGauge } from "@/components/charts/ComplianceGauge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import type { ControlRecord, VerdictRecord } from "@/lib/types";

function controlTitle(controls: ControlRecord[] | null, controlId: string): string {
  return controls?.find((c) => c.control_id === controlId)?.title ?? controlId;
}

const SEVERITY_WEIGHT: Record<VerdictRecord["severity"], number> = {
  critical: 4,
  high: 3,
  medium: 2,
  low: 1,
};

export function OverviewPage() {
  const summary = useFetch(api.summary, []);
  const devices = useFetch(api.devices, []);
  const verdicts = useFetch(api.verdicts, []);
  const controls = useFetch(api.controls, []);
  const vulnFleet = useFetch(api.vulnIntelFleetSummary, []);
  const riskDevices = useFetch(api.riskDevices, []);

  // GET /risk/devices already returns worst-first (see risk_routes.py) -
  // just take the top 5 for this summary card.
  const topRiskDevices = useMemo(
    () => (riskDevices.data?.devices ?? []).slice(0, 5),
    [riskDevices.data],
  );

  const complianceScore = useMemo(() => {
    const s = summary.data;
    if (!s) return null;
    const decided = s.verdicts_by_status.PASS + s.verdicts_by_status.FAIL + s.verdicts_by_status.PARTIAL;
    if (decided === 0) return 0;
    const weighted = s.verdicts_by_status.PASS + s.verdicts_by_status.PARTIAL * 0.5;
    return Math.round((weighted / decided) * 100);
  }, [summary.data]);

  const deviceCompliance = useMemo(() => {
    const rows = summary.data?.device_compliance ?? [];
    // Only devices with at least one assessed control have a meaningful
    // percentage to rank - devices with zero coverage are surfaced
    // separately rather than sorted in among real scores.
    return [...rows]
      .filter((d) => d.percentage !== null)
      .sort((a, b) => (a.percentage ?? 0) - (b.percentage ?? 0));
  }, [summary.data]);

  const topFailures = useMemo(() => {
    if (!verdicts.data) return [];
    return [...verdicts.data]
      .filter((v) => v.status === "FAIL")
      .sort((a, b) => SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity])
      .slice(0, 5);
  }, [verdicts.data]);

  const loading = summary.loading || devices.loading;
  const error = summary.error ?? devices.error;

  return (
    <Shell title="Overview" subtitle="Live posture across the simulated IoT lab">
      {error ? (
        <ErrorState message={error} />
      ) : (
        <div className="space-y-6">
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
                  label="Evidence collected"
                  value={summary.data.total_evidence}
                  icon={FileSearch}
                  accent="brand"
                  hint="manual + automated tests"
                />
                <StatTile
                  label="Verdicts issued"
                  value={summary.data.total_verdicts}
                  icon={Gavel}
                  accent="neutral"
                  hint="NCA CGIoT-1:2024 controls"
                />
                <StatTile
                  label="Devices monitored"
                  value={devices.data?.length ?? 0}
                  icon={HardDrive}
                  accent="neutral"
                  hint="cameras + brokers"
                />
                <StatTile
                  label="Failing verdicts"
                  value={summary.data.verdicts_by_status.FAIL}
                  icon={ShieldAlert}
                  accent="critical"
                  hint="require remediation"
                />
              </>
            )}
          </div>

          <div className="grid grid-cols-1 gap-4 xl:grid-cols-3">
            <Card className="xl:col-span-1">
              <CardHeader>
                <CardTitle>Verdict Pass Rate</CardTitle>
              </CardHeader>
              <CardContent className="flex flex-col items-center gap-3 pb-6">
                {complianceScore === null ? (
                  <Skeleton className="h-40 w-40 rounded-full" />
                ) : (
                  <ComplianceGauge score={complianceScore} sourceLabel="SA-IOT VERDICTS" />
                )}
                <p className="text-center text-xs text-[var(--color-text-muted)]">
                  PASS + ½·PARTIAL over decided verdicts
                </p>
              </CardContent>
            </Card>

            <Card className="xl:col-span-1">
              <CardHeader>
                <CardTitle>Verdict breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                {summary.loading || !summary.data ? (
                  <Skeleton className="h-56" />
                ) : (
                  <>
                    <VerdictDonut counts={summary.data.verdicts_by_status} />
                    <div className="mt-2 grid grid-cols-2 gap-2 text-xs">
                      {(
                        [
                          ["PASS", "var(--color-pass)"],
                          ["FAIL", "var(--color-critical)"],
                          ["PARTIAL", "var(--color-medium)"],
                          ["INCONCLUSIVE", "var(--color-inconclusive)"],
                        ] as const
                      ).map(([status, color]) => (
                        <div key={status} className="flex items-center gap-1.5 text-[var(--color-text-secondary)]">
                          <span className="h-2 w-2 rounded-full" style={{ backgroundColor: color }} />
                          {status}
                          <span className="ml-auto font-mono-tabular text-[var(--color-text)]">
                            {summary.data!.verdicts_by_status[status]}
                          </span>
                        </div>
                      ))}
                    </div>
                  </>
                )}
              </CardContent>
            </Card>

            <Card className="xl:col-span-1">
              <CardHeader>
                <CardTitle>Activity by device</CardTitle>
              </CardHeader>
              <CardContent>
                {devices.loading || !devices.data ? (
                  <Skeleton className="h-64" />
                ) : (
                  <DeviceActivityBar devices={devices.data} />
                )}
              </CardContent>
            </Card>
          </div>

          <Card>
            <CardHeader>
              <CardTitle>NCA CGIoT-1:2024 compliance by device</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              <p className="mb-3 text-xs text-[var(--color-text-muted)]">
                Percentage of this device's assessed controls (out of the 5 this lab automates)
                that currently PASS. Devices with no assessed controls yet aren't scored.
              </p>
              {summary.loading || !summary.data ? (
                <Skeleton className="h-32" />
              ) : deviceCompliance.length === 0 ? (
                <p className="py-6 text-center text-sm text-[var(--color-text-muted)]">
                  No device has an assessed NCA control yet.
                </p>
              ) : (
                <ul className="divide-y divide-[var(--color-border)]">
                  {deviceCompliance.map((d) => (
                    <li key={d.device_id} className="flex items-center gap-4 py-2.5 text-sm">
                      <Link
                        to={`/devices/${d.device_id}`}
                        className="min-w-0 flex-1 truncate font-mono text-[var(--color-text)] hover:underline"
                      >
                        {d.device_id}
                      </Link>
                      <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                        {d.passing_controls}/{d.tested_controls} passing
                      </span>
                      <ComplianceBadge percentage={d.percentage} />
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex-col items-start gap-1">
              <CardTitle className="flex items-center gap-2">
                <Bug className="h-4 w-4 text-[var(--color-text-muted)]" />
                Vulnerability intelligence by device
              </CardTitle>
              <p className="text-xs text-[var(--color-text-muted)]">
                Real CVE data from each device's most recent firmware manifest scan (Grype's
                local vulnerability database, cross-referenced against CISA's Known Exploited
                Vulnerabilities catalog). Devices with no firmware scan aren't listed.
              </p>
            </CardHeader>
            <CardContent className="space-y-3 pt-2">
              {vulnFleet.loading || !vulnFleet.data ? (
                <Skeleton className="h-32" />
              ) : vulnFleet.data.devices.length === 0 ? (
                <p className="py-6 text-center text-sm text-[var(--color-text-muted)]">
                  No device has a firmware manifest scan yet.
                </p>
              ) : (
                <>
                  <ul className="divide-y divide-[var(--color-border)]">
                    {vulnFleet.data.devices.map((d) => (
                      <li key={d.device_id} className="flex items-center gap-4 py-2.5 text-sm">
                        <Link
                          to={`/devices/${d.device_id}`}
                          className="min-w-0 flex-1 truncate font-mono text-[var(--color-text)] hover:underline"
                        >
                          {d.device_id}
                        </Link>
                        <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                          {d.total_cves} CVE{d.total_cves === 1 ? "" : "s"}
                          {d.highest_cvss !== null ? ` · highest CVSS ${d.highest_cvss}` : ""}
                        </span>
                        {d.kev_listed_cves > 0 ? (
                          <KevBadge size="xs" />
                        ) : (
                          <span className="w-[52px]" aria-hidden="true" />
                        )}
                      </li>
                    ))}
                  </ul>
                  <VulnFreshnessNote />
                </>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex-col items-start gap-1">
              <CardTitle className="flex items-center gap-2">
                <Flame className="h-4 w-4 text-[var(--color-text-muted)]" />
                Org-wide risk priority
              </CardTitle>
              <p className="text-xs text-[var(--color-text-muted)]">
                Combines NCA compliance, CVE/CVSS, exploit availability, device criticality,
                internet exposure, violations, and insecure services into one score per
                device.{" "}
                <Link to="/risk" className="text-[var(--color-brand)] hover:underline">
                  See the full breakdown
                </Link>
                .
              </p>
            </CardHeader>
            <CardContent className="pt-2">
              {riskDevices.loading || !riskDevices.data ? (
                <Skeleton className="h-32" />
              ) : topRiskDevices.length === 0 ? (
                <p className="py-6 text-center text-sm text-[var(--color-text-muted)]">
                  No devices registered yet.
                </p>
              ) : (
                <ul className="divide-y divide-[var(--color-border)]">
                  {topRiskDevices.map((d) => (
                    <li key={d.device_id} className="flex items-center gap-4 py-2.5 text-sm">
                      <span className="font-mono-tabular w-6 text-xs text-[var(--color-text-muted)]">
                        #{d.priority_rank}
                      </span>
                      <Link
                        to={`/devices/${d.device_id}`}
                        className="min-w-0 flex-1 truncate font-mono text-[var(--color-text)] hover:underline"
                      >
                        {d.device_id}
                      </Link>
                      <span className="font-mono-tabular text-xs text-[var(--color-text-muted)]">
                        {d.risk_score}
                      </span>
                      <RiskCategoryBadge category={d.risk_category} size="sm" />
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle>Highest-priority failures</CardTitle>
            </CardHeader>
            <CardContent className="pt-2">
              {verdicts.loading || controls.loading ? (
                <Skeleton className="h-40" />
              ) : topFailures.length === 0 ? (
                <p className="py-6 text-center text-sm text-[var(--color-text-muted)]">
                  No failing verdicts recorded — every mapped control currently passes.
                </p>
              ) : (
                <ul className="divide-y divide-[var(--color-border)]">
                  {topFailures.map((v) => (
                    <li key={v.verdict_id} className="flex items-center gap-4 py-3">
                      <SeverityBadge severity={v.severity} />
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-[var(--color-text)]">
                          {controlTitle(controls.data, v.control_id)}
                        </p>
                        <p className="truncate font-mono text-xs text-[var(--color-text-muted)]">
                          {v.control_id} · {v.device_id}
                        </p>
                      </div>
                      <StatusBadge status={v.status} />
                    </li>
                  ))}
                </ul>
              )}
            </CardContent>
          </Card>
        </div>
      )}
    </Shell>
  );
}
