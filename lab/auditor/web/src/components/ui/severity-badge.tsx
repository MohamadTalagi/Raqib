import { cn } from "@/lib/utils";
import type { Severity, VerdictStatus, Confidence } from "@/lib/types";

const SEVERITY_STYLES: Record<Severity, string> = {
  critical: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-critical)_35%,transparent)]",
  high: "bg-[color-mix(in_oklab,var(--color-high)_16%,transparent)] text-[var(--color-high)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-high)_35%,transparent)]",
  medium: "bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] text-[var(--color-medium)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-medium)_35%,transparent)]",
  low: "bg-[color-mix(in_oklab,var(--color-low)_16%,transparent)] text-[var(--color-low)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-low)_35%,transparent)]",
};

export function SeverityBadge({ severity }: { severity: Severity }) {
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium uppercase tracking-wide",
        SEVERITY_STYLES[severity],
      )}
    >
      <span className="h-1.5 w-1.5 rounded-full bg-current" />
      {severity}
    </span>
  );
}

const STATUS_STYLES: Record<VerdictStatus, string> = {
  PASS: "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-pass)_35%,transparent)]",
  FAIL: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-critical)_35%,transparent)]",
  PARTIAL: "bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] text-[var(--color-medium)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-medium)_35%,transparent)]",
  INCONCLUSIVE: "bg-[color-mix(in_oklab,var(--color-inconclusive)_16%,transparent)] text-[var(--color-inconclusive)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-inconclusive)_35%,transparent)]",
};

export function StatusBadge({ status }: { status: VerdictStatus }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide",
        STATUS_STYLES[status],
      )}
    >
      {status}
    </span>
  );
}

const CONFIDENCE_STYLES: Record<Confidence, string> = {
  high: "text-[var(--color-pass)]",
  medium: "text-[var(--color-medium)]",
  low: "text-[var(--color-text-muted)]",
};

export function ConfidenceLabel({ confidence }: { confidence: Confidence }) {
  return (
    <span className={cn("font-mono text-xs uppercase tracking-wide", CONFIDENCE_STYLES[confidence])}>
      {confidence}
    </span>
  );
}

function complianceStyle(percentage: number | null): string {
  if (percentage === null) return STATUS_STYLES.INCONCLUSIVE;
  if (percentage >= 80) return STATUS_STYLES.PASS;
  if (percentage >= 50) return STATUS_STYLES.PARTIAL;
  return STATUS_STYLES.FAIL;
}

/** A percentage-based compliance pill, shared by the device detail page and the Overview fleet breakdown. */
export function ComplianceBadge({ percentage }: { percentage: number | null }) {
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md px-2 py-0.5 font-mono text-xs font-semibold tracking-wide",
        complianceStyle(percentage),
      )}
    >
      {percentage === null ? "NOT ASSESSED" : `${percentage}%`}
    </span>
  );
}
