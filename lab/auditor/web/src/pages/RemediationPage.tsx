import { Construction } from "lucide-react";
import { Link } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";

/**
 * Reserves this pipeline phase's sidebar slot without inventing generated
 * content - the real AI-remediation engine (model choice, prompting, a
 * human-review gate matching this project's "AI-assisted, not AI-decided"
 * rule) is a separate, larger piece of work with its own future plan. In
 * the meantime this shows exactly what that engine will eventually build
 * from: every currently-failing SA-IOT control's own static remediation
 * text, already recorded on the verdict - never anything AI-generated.
 */
export function RemediationPage() {
  const verdicts = useFetch(api.verdicts, []);
  const failing = (verdicts.data ?? []).filter((v) => v.status === "FAIL");

  return (
    <Shell
      title="Remediation"
      subtitle="AI-assisted remediation guidance per finding - not yet available"
    >
      <div className="space-y-6">
        <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--color-border)] py-16 text-center">
          <Construction className="h-8 w-8 text-[var(--color-text-muted)]" strokeWidth={1.75} />
          <div>
            <p className="text-sm font-medium text-[var(--color-text)]">Not built yet</p>
            <p className="mx-auto mt-1 max-w-md text-xs text-[var(--color-text-muted)]">
              A real AI-generated remediation blueprint per finding lands here in a later phase, with a
              human-review gate before anything is treated as guidance. Below is a preview of what it will
              build from today: each currently-failing control's own static remediation text.
            </p>
          </div>
        </div>

        <Card>
          <CardContent className="pt-5">
            <p className="mb-3 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
              Currently failing controls ({failing.length})
            </p>
            {verdicts.error ? (
              <ErrorState message={verdicts.error} />
            ) : verdicts.loading ? (
              <div className="space-y-2">
                <Skeleton className="h-16" />
                <Skeleton className="h-16" />
              </div>
            ) : failing.length === 0 ? (
              <EmptyState message="No failing verdicts right now - nothing to remediate." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {failing.map((v) => (
                  <li key={v.verdict_id} className="py-3 text-sm">
                    <div className="flex flex-wrap items-center gap-2">
                      <Link
                        to={`/devices/${v.device_id}`}
                        className="font-medium text-[var(--color-text)] hover:text-[var(--color-brand)] hover:underline"
                      >
                        {v.device_id}
                      </Link>
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.control_id}</span>
                    </div>
                    <p className="mt-1 text-[var(--color-text-secondary)]">{v.remediation}</p>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
