import { Construction } from "lucide-react";
import { Shell } from "@/components/layout/Shell";

interface ComingSoonPageProps {
  title: string;
  phaseLabel: string;
  description: string;
}

/**
 * A placeholder for a pipeline page whose route/sidebar entry exists (so the
 * guided pipeline reads as complete end to end) but whose real page hasn't
 * been built yet in this phased rollout - see ui-overhaul.txt's delivery
 * order. Each one gets replaced by its real page in its own later phase.
 */
export function ComingSoonPage({ title, phaseLabel, description }: ComingSoonPageProps) {
  return (
    <Shell title={title} subtitle={phaseLabel}>
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--color-border)] py-20 text-center">
        <Construction className="h-8 w-8 text-[var(--color-text-muted)]" strokeWidth={1.75} />
        <div>
          <p className="text-sm font-medium text-[var(--color-text)]">Not built yet</p>
          <p className="mx-auto mt-1 max-w-md text-xs text-[var(--color-text-muted)]">{description}</p>
        </div>
      </div>
    </Shell>
  );
}
