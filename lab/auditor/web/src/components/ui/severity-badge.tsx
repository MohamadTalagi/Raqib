import { CheckCircle2, AlertTriangle, XCircle, CircleDashed, Eye } from "lucide-react";
import { cn } from "@/lib/utils";
import type { Severity, VerdictStatus, Confidence, NCAStatus, NCAReadinessClassification } from "@/lib/types";

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
  NOT_APPLICABLE: "bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] text-[var(--color-text-muted)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-text-muted)_35%,transparent)]",
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

const NCA_STATUS_STYLES: Record<NCAStatus, string> = {
  pass: "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-pass)_35%,transparent)]",
  fail: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-critical)_35%,transparent)]",
  partial: "bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] text-[var(--color-medium)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-medium)_35%,transparent)]",
  not_tested: "bg-[color-mix(in_oklab,var(--color-inconclusive)_16%,transparent)] text-[var(--color-inconclusive)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-inconclusive)_35%,transparent)]",
  review_required: "bg-[color-mix(in_oklab,var(--color-brand)_16%,transparent)] text-[var(--color-brand)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-brand)_35%,transparent)]",
};

const NCA_STATUS_ICON: Record<NCAStatus, typeof CheckCircle2> = {
  pass: CheckCircle2,
  fail: XCircle,
  partial: AlertTriangle,
  not_tested: CircleDashed,
  review_required: Eye,
};

const NCA_STATUS_LABEL: Record<NCAStatus, string> = {
  pass: "Pass",
  fail: "Fail",
  partial: "Partial",
  not_tested: "Not Assessed",
  review_required: "Review Required",
};

const READINESS_STYLES: Record<NCAReadinessClassification, string> = {
  passed: "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-pass)_35%,transparent)]",
  partially_passed: "bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] text-[var(--color-medium)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-medium)_35%,transparent)]",
  failed: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-critical)_35%,transparent)]",
};

const READINESS_ICON: Record<NCAReadinessClassification, typeof CheckCircle2> = {
  passed: CheckCircle2,
  partially_passed: AlertTriangle,
  failed: XCircle,
};

const READINESS_LABEL: Record<NCAReadinessClassification, string> = {
  passed: "Passed",
  partially_passed: "Partially Passed",
  failed: "Failed",
};

/**
 * The Passed/Partially Passed/Failed compliance-readiness verdict (icon +
 * text, same colorblind/greyscale-safe rule as NCAStatusBadge) - distinct
 * from NCAStatusBadge, which renders a single control's status rather than
 * the whole-scope classification.
 */
export function NCAReadinessBadge({ classification }: { classification: NCAReadinessClassification }) {
  const Icon = READINESS_ICON[classification];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2.5 py-1 text-sm font-semibold tracking-wide",
        READINESS_STYLES[classification],
      )}
    >
      <Icon className="h-4 w-4" strokeWidth={2} />
      {READINESS_LABEL[classification]}
    </span>
  );
}

/**
 * Icon + text always together, never color alone - the compliance brief is
 * explicit that a colourblind reader or a greyscale printout must still be
 * able to tell PASS from FAIL from the badge itself.
 */
export function NCAStatusBadge({ status }: { status: NCAStatus }) {
  const Icon = NCA_STATUS_ICON[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide",
        NCA_STATUS_STYLES[status],
      )}
    >
      <Icon className="h-3.5 w-3.5" strokeWidth={2} />
      {NCA_STATUS_LABEL[status]}
    </span>
  );
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
