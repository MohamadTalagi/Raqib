import { Link } from "react-router-dom";
import { Compass } from "lucide-react";
import { Shell } from "@/components/layout/Shell";

export function NotFoundPage() {
  return (
    <Shell title="Page not found" subtitle="404">
      <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--color-border)] py-20 text-center">
        <Compass className="h-8 w-8 text-[var(--color-text-muted)]" strokeWidth={1.75} />
        <div>
          <p className="text-sm font-medium text-[var(--color-text)]">This page doesn't exist</p>
          <p className="mt-1 text-xs text-[var(--color-text-muted)]">
            Check the URL, or head back to the Overview.
          </p>
        </div>
        <Link
          to="/"
          className="mt-2 inline-flex items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)]"
        >
          Back to Overview
        </Link>
      </div>
    </Shell>
  );
}
