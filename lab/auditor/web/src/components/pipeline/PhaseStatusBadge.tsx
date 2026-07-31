import { CheckCircle2, CircleDashed } from "lucide-react";
import { cn } from "@/lib/utils";
import type { PipelinePhaseDef } from "@/lib/pipeline";

/**
 * "Reached" / "not yet" for a single pipeline phase - icon + text always
 * together, matching this app's existing rule that a status is never color
 * alone (severity-badge.tsx's StatusBadge/NCAStatusBadge hold the same
 * rule). Reused across Devices and every phase page rather than a bespoke
 * indicator on each.
 */
export function PhaseStatusBadge({ phase, reached }: { phase: PipelinePhaseDef; reached: boolean }) {
  const Icon = reached ? CheckCircle2 : CircleDashed;
  return (
    <span
      className={cn(
        "inline-flex items-center gap-1.5 rounded-md px-2 py-0.5 text-xs font-medium tracking-wide",
        reached
          ? "bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)] text-[var(--color-pass)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-pass)_35%,transparent)]"
          : "bg-[color-mix(in_oklab,var(--color-text-muted)_16%,transparent)] text-[var(--color-text-muted)] ring-1 ring-inset ring-[color-mix(in_oklab,var(--color-text-muted)_35%,transparent)]",
      )}
    >
      <Icon className="h-3.5 w-3.5" strokeWidth={2} />
      {phase.label}
    </span>
  );
}
