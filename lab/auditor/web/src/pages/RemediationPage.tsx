import { useEffect, useMemo, useRef, useState } from "react";
import { Link } from "react-router-dom";
import { CheckCircle2, Loader2, Sparkles } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { AiGeneratedBadge } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import type { RemediationBlueprint, RemediationFindingType } from "@/lib/types";

// A small pause between "Generate all missing" calls, comfortably under
// Gemini's free-tier rate limit (see docs/remediation.md) - the point is to
// never burn quota unexpectedly, not to be fast.
const BULK_GENERATE_DELAY_MS = 4000;

const PRIORITY_STYLE: Record<RemediationBlueprint["priority"], string> = {
  immediate: "text-[var(--color-critical)]",
  short_term: "text-[var(--color-medium)]",
  long_term: "text-[var(--color-text-muted)]",
};

const PRIORITY_LABEL: Record<RemediationBlueprint["priority"], string> = {
  immediate: "Immediate",
  short_term: "Short-term",
  long_term: "Long-term",
};

interface RemediationFinding {
  findingType: RemediationFindingType;
  findingId: string;
  deviceId: string | null;
  controlId: string;
  status: string;
  existingRemediation: string | null;
  reasonOrFinding: string;
}

function delay(ms: number): Promise<void> {
  return new Promise((resolve) => window.setTimeout(resolve, ms));
}

export function RemediationPage() {
  const { showToast } = useToast();
  const [refreshKey, setRefreshKey] = useState(0);
  const verdicts = useFetch(api.verdicts, [refreshKey]);
  const ncaAssessments = useFetch(api.ncaAssessments, [refreshKey]);
  const blueprints = useFetch(api.allRemediationBlueprints, [refreshKey]);

  const [reviewerName, setReviewerName] = useState("");
  const [generating, setGenerating] = useState<Set<string>>(new Set());
  const [bulkGenerating, setBulkGenerating] = useState(false);
  const [rowError, setRowError] = useState<Record<string, string>>({});

  const mountedRef = useRef(true);
  useEffect(() => {
    mountedRef.current = true;
    return () => {
      mountedRef.current = false;
    };
  }, []);

  const findings = useMemo<RemediationFinding[]>(() => {
    const saIot: RemediationFinding[] = (verdicts.data ?? [])
      .filter((v) => v.status === "FAIL" || v.status === "PARTIAL")
      .map((v) => ({
        findingType: "sa_iot_verdict" as const,
        findingId: v.verdict_id,
        deviceId: v.device_id,
        controlId: v.control_id,
        status: v.status,
        existingRemediation: v.remediation,
        reasonOrFinding: v.reason,
      }));
    const nca: RemediationFinding[] = (ncaAssessments.data ?? [])
      .filter((a) => a.status === "fail" || a.status === "partial")
      .map((a) => ({
        findingType: "nca_assessment" as const,
        findingId: a.id,
        deviceId: a.device_id,
        controlId: a.control_id,
        status: a.status,
        existingRemediation: a.remediation,
        reasonOrFinding: a.finding ?? "",
      }));
    return [...saIot, ...nca];
  }, [verdicts.data, ncaAssessments.data]);

  const blueprintByFinding = useMemo(() => {
    const map = new Map<string, RemediationBlueprint>();
    for (const b of blueprints.data ?? []) {
      map.set(`${b.finding_type}:${b.finding_id}`, b);
    }
    return map;
  }, [blueprints.data]);

  const findingsWithoutBlueprint = useMemo(
    () => findings.filter((f) => !blueprintByFinding.has(`${f.findingType}:${f.findingId}`)),
    [findings, blueprintByFinding],
  );

  async function handleGenerate(finding: RemediationFinding) {
    const key = `${finding.findingType}:${finding.findingId}`;
    setGenerating((prev) => new Set(prev).add(key));
    setRowError((prev) => ({ ...prev, [key]: "" }));
    try {
      await api.generateRemediation(finding.findingType, finding.findingId);
      if (mountedRef.current) setRefreshKey((k) => k + 1);
    } catch (err) {
      if (mountedRef.current) {
        setRowError((prev) => ({
          ...prev,
          [key]: err instanceof ApiError ? err.message : "Could not generate remediation.",
        }));
      }
    } finally {
      if (mountedRef.current) {
        setGenerating((prev) => {
          const next = new Set(prev);
          next.delete(key);
          return next;
        });
      }
    }
  }

  async function handleGenerateAllMissing() {
    setBulkGenerating(true);
    for (const finding of findingsWithoutBlueprint) {
      if (!mountedRef.current) return;
      await handleGenerate(finding);
      if (!mountedRef.current) return;
      await delay(BULK_GENERATE_DELAY_MS);
    }
    if (mountedRef.current) setBulkGenerating(false);
  }

  async function handleReview(blueprintId: string) {
    if (!reviewerName.trim()) return;
    try {
      await api.reviewRemediationBlueprint(blueprintId, reviewerName.trim());
      showToast("Blueprint marked reviewed.", "success");
      setRefreshKey((k) => k + 1);
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : "Could not mark this blueprint reviewed.", "error");
    }
  }

  const loading = verdicts.loading || ncaAssessments.loading || blueprints.loading;
  const error = verdicts.error ?? ncaAssessments.error ?? blueprints.error;

  return (
    <Shell
      title="Remediation"
      subtitle="AI-assisted remediation guidance per finding (Raqib Stage 07)"
      phase="solution"
    >
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 pt-5">
            <label htmlFor="remediation-reviewer-name" className="text-xs text-[var(--color-text-muted)]">
              Your name, to mark generated blueprints reviewed:
            </label>
            <input
              id="remediation-reviewer-name"
              value={reviewerName}
              onChange={(e) => setReviewerName(e.target.value)}
              className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2 py-1 text-xs text-[var(--color-text)]"
            />
            <button
              type="button"
              onClick={handleGenerateAllMissing}
              disabled={bulkGenerating || findingsWithoutBlueprint.length === 0}
              className="ml-auto inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
            >
              {bulkGenerating ? <Loader2 className="h-4 w-4 animate-spin" /> : <Sparkles className="h-4 w-4" />}
              Generate all missing ({findingsWithoutBlueprint.length})
            </button>
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Currently failing or partial findings ({findings.length})</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {error ? (
              <ErrorState message={error} />
            ) : loading ? (
              <div className="space-y-2">
                <Skeleton className="h-24" />
                <Skeleton className="h-24" />
              </div>
            ) : findings.length === 0 ? (
              <EmptyState message="No failing or partial findings right now - nothing to remediate." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {findings.map((finding) => {
                  const key = `${finding.findingType}:${finding.findingId}`;
                  const blueprint = blueprintByFinding.get(key);
                  const isGenerating = generating.has(key);
                  return (
                    <li key={key} className="space-y-2 py-4 text-sm">
                      <div className="flex flex-wrap items-center gap-2">
                        {finding.deviceId ? (
                          <Link
                            to={`/devices/${finding.deviceId}`}
                            className="font-medium text-[var(--color-text)] hover:text-[var(--color-brand)] hover:underline"
                          >
                            {finding.deviceId}
                          </Link>
                        ) : (
                          <span className="text-[var(--color-text-muted)]">organization-wide</span>
                        )}
                        <span className="font-mono text-xs text-[var(--color-text-muted)]">{finding.controlId}</span>
                        <span className="rounded-md bg-[var(--color-surface-hover)] px-1.5 py-0.5 text-[10px] font-medium tracking-wide text-[var(--color-text-secondary)] uppercase">
                          {finding.findingType === "sa_iot_verdict" ? "SA-IOT" : "NCA"}
                        </span>
                        {!blueprint && (
                          <button
                            type="button"
                            onClick={() => handleGenerate(finding)}
                            disabled={isGenerating}
                            className="ml-auto inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)] disabled:opacity-50"
                          >
                            {isGenerating ? (
                              <Loader2 className="h-3.5 w-3.5 animate-spin" />
                            ) : (
                              <Sparkles className="h-3.5 w-3.5" />
                            )}
                            Generate AI remediation
                          </button>
                        )}
                      </div>

                      {finding.existingRemediation && (
                        <p className="text-[var(--color-text-secondary)]">{finding.existingRemediation}</p>
                      )}

                      {rowError[key] && <p className="text-xs text-[var(--color-critical)]">{rowError[key]}</p>}

                      {blueprint && (
                        <div className="space-y-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] p-3">
                          <div className="flex flex-wrap items-center gap-2">
                            {!blueprint.reviewed && <AiGeneratedBadge size="xs" />}
                            <span className={`text-xs font-semibold tracking-wide uppercase ${PRIORITY_STYLE[blueprint.priority]}`}>
                              {PRIORITY_LABEL[blueprint.priority]}
                            </span>
                            {blueprint.estimated_effort && (
                              <span className="text-xs text-[var(--color-text-muted)]">
                                Effort: {blueprint.estimated_effort}
                              </span>
                            )}
                            {blueprint.reviewed ? (
                              <span className="ml-auto inline-flex items-center gap-1 text-xs text-[var(--color-pass)]">
                                <CheckCircle2 className="h-3.5 w-3.5" />
                                Reviewed by {blueprint.reviewed_by}
                              </span>
                            ) : (
                              <button
                                type="button"
                                onClick={() => handleReview(blueprint.id)}
                                disabled={!reviewerName.trim()}
                                className="ml-auto inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-border-strong)] hover:text-[var(--color-text)] disabled:cursor-not-allowed disabled:opacity-40"
                                title={!reviewerName.trim() ? "Enter your name above first" : undefined}
                              >
                                <CheckCircle2 className="h-3.5 w-3.5" />
                                Mark reviewed
                              </button>
                            )}
                          </div>
                          <p className="text-[var(--color-text)]">{blueprint.root_cause}</p>
                          <ol className="list-decimal space-y-1 pl-4 text-[var(--color-text-secondary)]">
                            {blueprint.remediation_steps.map((step, i) => (
                              <li key={i}>{step}</li>
                            ))}
                          </ol>
                          {blueprint.caveats && (
                            <p className="text-xs text-[var(--color-text-muted)]">Caveat: {blueprint.caveats}</p>
                          )}
                        </div>
                      )}
                    </li>
                  );
                })}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
