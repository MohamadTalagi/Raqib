import { CheckCircle2, AlertTriangle, XCircle, CircleDashed, Eye, Ban, ShieldAlert, ShieldCheck, AlertOctagon, Loader2, Bot, Sparkles, ScanSearch } from "lucide-react";
import { cn } from "@/lib/utils";
import { Tooltip } from "@/components/ui/tooltip";
import type { Severity, VerdictStatus, Confidence, NCAStatus, NCAReadinessClassification, RiskCategory, AssessmentStatus, PqcCriterionStatus } from "@/lib/types";

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

const READINESS_SIZE_STYLES: Record<"sm" | "md", string> = {
  md: "gap-1.5 px-2.5 py-1 text-sm",
  sm: "gap-1.5 px-2 py-0.5 text-xs",
};

const READINESS_ICON_SIZE: Record<"sm" | "md", string> = {
  md: "h-4 w-4",
  sm: "h-3.5 w-3.5",
};

/**
 * The Passed/Partially Passed/Failed compliance-readiness verdict (icon +
 * text, same colorblind/greyscale-safe rule as NCAStatusBadge) - distinct
 * from NCAStatusBadge, which renders a single control's status rather than
 * the whole-scope classification. `size="md"` (default) is the hero-badge
 * treatment used on device/organization compliance headers; `size="sm"`
 * matches NCAStatusBadge's own dimensions exactly, for dense table rows
 * where the two badges sit side by side and must read as the same visual
 * weight rather than one dwarfing the other.
 */
export function NCAReadinessBadge({
  classification,
  size = "md",
}: {
  classification: NCAReadinessClassification;
  size?: "sm" | "md";
}) {
  const Icon = READINESS_ICON[classification];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md font-semibold tracking-wide",
        READINESS_SIZE_STYLES[size],
        READINESS_STYLES[classification],
      )}
    >
      <Icon className={READINESS_ICON_SIZE[size]} strokeWidth={2} />
      {READINESS_LABEL[classification]}
    </span>
  );
}

const RISK_CATEGORY_ICON: Record<RiskCategory, typeof CheckCircle2> = {
  low: ShieldCheck,
  medium: AlertTriangle,
  high: AlertTriangle,
  critical: AlertOctagon,
};

const RISK_CATEGORY_LABEL: Record<RiskCategory, string> = {
  low: "Low",
  medium: "Medium",
  high: "High",
  critical: "Critical",
};

/**
 * The Dynamic Risk Assessment engine's (policies/risk/risk_engine.py)
 * low/medium/high/critical category - icon + text, same colorblind/
 * greyscale-safe rule as every other classification badge here. Reuses
 * SEVERITY_STYLES since risk categories and control severities share the
 * same 4-tier color vocabulary, even though they're semantically distinct
 * axes (a device's risk score, not a control's assigned severity).
 */
export function RiskCategoryBadge({
  category,
  size = "md",
}: {
  category: RiskCategory;
  size?: "sm" | "md";
}) {
  const Icon = RISK_CATEGORY_ICON[category];
  return (
    <span
      className={cn(
        "inline-flex items-center rounded-md font-semibold tracking-wide",
        READINESS_SIZE_STYLES[size],
        SEVERITY_STYLES[category],
      )}
    >
      <Icon className={READINESS_ICON_SIZE[size]} strokeWidth={2} />
      {RISK_CATEGORY_LABEL[category]}
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

export const BLOCKING_EXPLANATION =
  "A failure of this control alone forces the overall readiness classification to Failed, regardless of score.";

const BLOCKING_SIZE_STYLES: Record<"xs" | "sm", string> = {
  xs: "gap-1 px-1.5 py-0.5 text-[10px]",
  sm: "gap-1 px-2 py-0.5 text-xs",
};

const BLOCKING_ICON_SIZE: Record<"xs" | "sm", string> = {
  xs: "h-3 w-3",
  sm: "h-3.5 w-3.5",
};

/**
 * Marks a control whose failure alone forces a Failed readiness
 * classification (see policies/nca/build_catalog.py's BLOCKING_GUIDELINES) -
 * the single most consequential piece of information in the compliance
 * flow, so it always carries its own explanation rather than relying on a
 * native `title` attribute (this app has no other tooltip anywhere, so this
 * was previously the least discoverable explanation in the UI).
 */
export function BlockingBadge({ size = "sm" }: { size?: "xs" | "sm" }) {
  return (
    <Tooltip content={BLOCKING_EXPLANATION}>
      <span
        tabIndex={0}
        className={cn(
          "inline-flex items-center rounded-md font-mono font-medium uppercase tracking-wide",
          "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)]",
          BLOCKING_SIZE_STYLES[size],
        )}
      >
        <Ban className={BLOCKING_ICON_SIZE[size]} strokeWidth={2} />
        blocking
      </span>
    </Tooltip>
  );
}

export const KEV_EXPLANATION =
  "This CVE is on CISA's Known Exploited Vulnerabilities catalog - confirmed exploitation in the wild, not just a theoretical CVSS score.";

/** Marks a CVE that's on CISA's real KEV catalog (see vuln_routes.py / policies/catalog's Grype+CISA-KEV integration) - a stronger, more concrete signal than CVSS alone, so it carries its own explanation the same way BlockingBadge does. */
export function KevBadge({ size = "sm" }: { size?: "xs" | "sm" }) {
  return (
    <Tooltip content={KEV_EXPLANATION}>
      <span
        tabIndex={0}
        className={cn(
          "inline-flex items-center rounded-md font-mono font-medium uppercase tracking-wide",
          "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)]",
          BLOCKING_SIZE_STYLES[size],
        )}
      >
        <ShieldAlert className={BLOCKING_ICON_SIZE[size]} strokeWidth={2} />
        KEV
      </span>
    </Tooltip>
  );
}

export const AUTO_RECORDED_EXPLANATION =
  "Recorded by Fully Automated Run with zero human review - the same attestation_confirmed flag a real sign-off " +
  "carries, but no person has actually read this evidence yet. Use \"Review & confirm\" to do that.";

/**
 * Marks a compliance_assessments row with auto_recorded=true - structurally
 * distinguishes "the system recorded this and satisfied the attestation
 * constraint" from a real human sign-off, so the audit trail never lies
 * about whether a person actually looked at it (see
 * automated_run_runner.py's module docstring). Always carries its own
 * explanation, same as BlockingBadge/KevBadge, since this is the one badge
 * in the app whose entire point is "don't trust this at face value yet."
 */
export function AutoRecordedBadge({ size = "sm" }: { size?: "xs" | "sm" }) {
  return (
    <Tooltip content={AUTO_RECORDED_EXPLANATION}>
      <span
        tabIndex={0}
        className={cn(
          "inline-flex items-center rounded-md font-mono font-medium uppercase tracking-wide",
          "bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] text-[var(--color-medium)]",
          BLOCKING_SIZE_STYLES[size],
        )}
      >
        <Bot className={BLOCKING_ICON_SIZE[size]} strokeWidth={2} />
        auto-recorded
      </span>
    </Tooltip>
  );
}

export const AUTO_DETECTED_IDENTITY_EXPLANATION =
  "Vendor, model and firmware version were read automatically from this device's own unauthenticated " +
  "/api/device/info endpoint (TEST-DEVICE-ID) - they are what the device claims about itself, not values " +
  "an auditor verified. Editing any of them marks this inventory record manual.";

/**
 * Marks a devices row with identity_source='auto_detected' - the same
 * "don't trust this at face value yet" role AutoRecordedBadge plays for
 * auto-recorded NCA assessments, for self-reported device identity. The
 * distinction is real: SA-IOT-001's own `limitations` field says this check
 * "does not verify the values are accurate", and a device is free to lie
 * about its own vendor/model/firmware.
 */
export function AutoDetectedIdentityBadge({ size = "xs" }: { size?: "xs" | "sm" }) {
  return (
    <Tooltip content={AUTO_DETECTED_IDENTITY_EXPLANATION}>
      <span
        tabIndex={0}
        className={cn(
          "inline-flex items-center rounded-md font-mono font-medium uppercase tracking-wide",
          "bg-[color-mix(in_oklab,var(--color-low)_16%,transparent)] text-[var(--color-low)]",
          BLOCKING_SIZE_STYLES[size],
        )}
      >
        <ScanSearch className={BLOCKING_ICON_SIZE[size]} strokeWidth={2} />
        auto-detected
      </span>
    </Tooltip>
  );
}

export const AI_GENERATED_EXPLANATION =
  "Generated by an LLM (AI-Assisted Remediation, Raqib Stage 07) from this finding's own details - " +
  "never invents the finding itself, only explains and expands on one already determined by deterministic " +
  "scanning/policy evaluation. Not yet reviewed by a human - confirm before relying on it.";

/**
 * Marks a remediation_blueprints row before a human has reviewed it -
 * same "don't trust this at face value yet" role AutoRecordedBadge plays
 * for auto-recorded NCA assessments, for AI-generated remediation content
 * instead of a system-recorded compliance verdict.
 */
export function AiGeneratedBadge({ size = "sm" }: { size?: "xs" | "sm" }) {
  return (
    <Tooltip content={AI_GENERATED_EXPLANATION}>
      <span
        tabIndex={0}
        className={cn(
          "inline-flex items-center rounded-md font-mono font-medium uppercase tracking-wide",
          "bg-[color-mix(in_oklab,var(--color-brand)_16%,transparent)] text-[var(--color-brand)]",
          BLOCKING_SIZE_STYLES[size],
        )}
      >
        <Sparkles className={BLOCKING_ICON_SIZE[size]} strokeWidth={2} />
        ai-generated
      </span>
    </Tooltip>
  );
}

const ASSESSMENT_STATUS_STYLES: Record<AssessmentStatus, string> = {
  queued: "bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] text-[var(--color-text-muted)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-text-muted)_35%,transparent)]",
  running: "bg-[color-mix(in_oklab,var(--color-low)_16%,transparent)] text-[var(--color-low)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-low)_35%,transparent)]",
  partially_completed: "bg-[color-mix(in_oklab,var(--color-medium)_16%,transparent)] text-[var(--color-medium)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-medium)_35%,transparent)]",
  completed: "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-pass)_35%,transparent)]",
  failed: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-critical)_35%,transparent)]",
  cancelled: "bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] text-[var(--color-text-muted)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-text-muted)_35%,transparent)]",
};

const ASSESSMENT_STATUS_ICON: Record<AssessmentStatus, typeof CheckCircle2> = {
  queued: CircleDashed,
  running: Loader2,
  partially_completed: AlertTriangle,
  completed: CheckCircle2,
  failed: XCircle,
  cancelled: Ban,
};

const ASSESSMENT_STATUS_LABEL: Record<AssessmentStatus, string> = {
  queued: "Queued",
  running: "Running",
  partially_completed: "Partially completed",
  completed: "Completed",
  failed: "Failed",
  cancelled: "Cancelled",
};

/** The Assessment entity's aggregate status (policies/engine/assessment_status.py) - shared by Run Scan's in-flight indicator and the device detail page's assessment history. */
export function AssessmentStatusBadge({ status }: { status: AssessmentStatus }) {
  const Icon = ASSESSMENT_STATUS_ICON[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide",
        ASSESSMENT_STATUS_STYLES[status],
      )}
    >
      <Icon className={cn("h-3.5 w-3.5", status === "running" && "animate-spin")} strokeWidth={2} />
      {ASSESSMENT_STATUS_LABEL[status]}
    </span>
  );
}

const PQC_CRITERION_STYLES: Record<PqcCriterionStatus, string> = {
  pass: "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-pass)_35%,transparent)]",
  fail: "bg-[color-mix(in_oklab,var(--color-critical)_16%,transparent)] text-[var(--color-critical)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-critical)_35%,transparent)]",
  unknown: "bg-[color-mix(in_oklab,var(--color-inconclusive)_16%,transparent)] text-[var(--color-inconclusive)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-inconclusive)_35%,transparent)]",
  not_applicable: "bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] text-[var(--color-text-muted)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-text-muted)_35%,transparent)]",
};

const PQC_CRITERION_ICON: Record<PqcCriterionStatus, typeof CheckCircle2> = {
  pass: CheckCircle2,
  fail: XCircle,
  unknown: CircleDashed,
  not_applicable: Ban,
};

const PQC_CRITERION_LABEL: Record<PqcCriterionStatus, string> = {
  pass: "Ready",
  fail: "Not Ready",
  unknown: "Unknown",
  not_applicable: "Not Applicable",
};

/** Pass/Fail/Unknown/Not Applicable for one Post-Quantum Readiness criterion
 * - "unknown" (never a guessed pass or fail) covers a probe that couldn't
 * reach the device or a firmware library this project hasn't verified a
 * PQC threshold for. See pqc_routes.py. */
export function PqcCriterionBadge({ status }: { status: PqcCriterionStatus }) {
  const Icon = PQC_CRITERION_ICON[status];
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-semibold tracking-wide",
        PQC_CRITERION_STYLES[status],
      )}
    >
      <Icon className="h-3.5 w-3.5" />
      {PQC_CRITERION_LABEL[status]}
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
