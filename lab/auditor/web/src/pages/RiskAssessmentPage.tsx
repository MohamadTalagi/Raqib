import { useState } from "react";
import { ChevronDown, ArrowRight } from "lucide-react";
import { Link } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { RiskCategoryBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { RISK_FACTOR_KEYS } from "@/lib/types";
import { RISK_FACTOR_LABELS, formatRiskRawValue } from "@/lib/risk";

/**
 * One factor's share of the final score, drawn to scale against that
 * factor's own maximum possible contribution (weight * 100) - so a 5%-
 * weighted factor maxed out and a 25%-weighted factor maxed out both show a
 * full bar, making "this factor is as bad as it can get" legible at a
 * glance regardless of how much weight it carries.
 */
function RiskFactorBar({ contribution, weight }: { contribution: number; weight: number }) {
  const maxContribution = weight * 100;
  const pct = maxContribution > 0 ? Math.min(100, (contribution / maxContribution) * 100) : 0;
  return (
    <div className="mt-1 h-1.5 w-full overflow-hidden rounded-full bg-[var(--color-surface-hover)]">
      <div className="h-full rounded-full bg-[var(--color-brand)]" style={{ width: `${pct}%` }} />
    </div>
  );
}

function DeviceBreakdownPanel({ deviceId }: { deviceId: string }) {
  const detail = useFetch(() => api.riskDevice(deviceId), [deviceId]);

  if (detail.loading || !detail.data?.breakdown) {
    return <Skeleton className="h-48" />;
  }

  const { breakdown } = detail.data;
  return (
    <div className="space-y-4">
      {RISK_FACTOR_KEYS.map((key) => {
        const factor = breakdown[key];
        return (
          <div key={key} className="grid grid-cols-[1fr_auto] items-start gap-4 text-sm">
            <div className="min-w-0">
              <p className="text-[var(--color-text)]">{RISK_FACTOR_LABELS[key]}</p>
              <p className="font-mono text-xs text-[var(--color-text-muted)]">
                raw: {formatRiskRawValue(factor.raw_value)} · weight {Math.round(factor.weight * 100)}%
              </p>
              <RiskFactorBar contribution={factor.contribution} weight={factor.weight} />
            </div>
            <span className="font-mono-tabular shrink-0 text-[var(--color-text)]">
              +{factor.contribution.toFixed(1)}
            </span>
          </div>
        );
      })}
      <Link
        to={`/devices/${deviceId}`}
        className="inline-flex items-center gap-1.5 text-xs font-medium text-[var(--color-brand)] hover:underline"
      >
        View device
        <ArrowRight className="h-3.5 w-3.5" />
      </Link>
    </div>
  );
}

/**
 * The org-wide priority ranking (IoTGuard Stage 06): every registered
 * device, worst-first, from lab/auditor/api/risk_routes.py's live-computed
 * scores. Each row expands in place (matches VerdictsPage's own expand-on-
 * click convention) to the full 7-factor breakdown, so the number is never
 * a black box - an auditor can see exactly why a device scored what it did.
 */
export function RiskAssessmentPage() {
  const devices = useFetch(api.riskDevices, []);
  const [expanded, setExpanded] = useState<string | null>(null);

  return (
    <Shell
      title="Risk Assessment"
      subtitle="Org-wide priority ranking, combining SA-IOT verdicts, NCA CGIoT-1:2024 compliance, and Vulnerability Intelligence (CVE/CVSS/CISA-KEV) with device context"
    >
      {devices.error ? (
        <ErrorState message={devices.error} />
      ) : devices.loading || !devices.data ? (
        <Skeleton className="h-96" />
      ) : devices.data.devices.length === 0 ? (
        <EmptyState message="No devices registered yet." />
      ) : (
        <div className="space-y-3">
          {devices.data.devices.map((d) => {
            const isOpen = expanded === d.device_id;
            return (
              <Card key={d.device_id} className="overflow-hidden py-0">
                <button
                  type="button"
                  onClick={() => setExpanded(isOpen ? null : d.device_id)}
                  className="flex w-full cursor-pointer items-center gap-4 px-5 py-3.5 text-left transition-colors hover:bg-[var(--color-surface-hover)]"
                >
                  <span className="font-mono-tabular w-8 shrink-0 text-sm text-[var(--color-text-muted)]">
                    #{d.priority_rank}
                  </span>
                  <span className="min-w-0 flex-1 truncate font-mono text-sm text-[var(--color-text)]">
                    {d.device_id}
                  </span>
                  <span className="font-mono-tabular shrink-0 text-sm text-[var(--color-text-secondary)]">
                    {d.risk_score}
                  </span>
                  <RiskCategoryBadge category={d.risk_category} size="sm" />
                  <ChevronDown
                    className={cn(
                      "h-4 w-4 shrink-0 text-[var(--color-text-muted)] transition-transform",
                      isOpen && "rotate-180",
                    )}
                  />
                </button>
                {isOpen && (
                  <div className="border-t border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4">
                    <DeviceBreakdownPanel deviceId={d.device_id} />
                  </div>
                )}
              </Card>
            );
          })}
        </div>
      )}
    </Shell>
  );
}
