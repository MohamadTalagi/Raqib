import type { LucideIcon } from "lucide-react";
import { cn } from "@/lib/utils";

interface StatTileProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  accent?: "brand" | "pass" | "critical" | "neutral";
  hint?: string;
}

const ACCENT_STYLES: Record<NonNullable<StatTileProps["accent"]>, string> = {
  brand: "text-[var(--color-brand)] bg-[color-mix(in_oklab,var(--color-brand)_14%,transparent)]",
  pass: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_14%,transparent)]",
  critical: "text-[var(--color-critical)] bg-[color-mix(in_oklab,var(--color-critical)_14%,transparent)]",
  neutral: "text-[var(--color-text-secondary)] bg-[var(--color-surface-hover)]",
};

export function StatTile({ label, value, icon: Icon, accent = "neutral", hint }: StatTileProps) {
  return (
    <div className="rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] p-5">
      <div className="flex items-start justify-between">
        <p className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">{label}</p>
        <div className={cn("flex h-8 w-8 items-center justify-center rounded-md", ACCENT_STYLES[accent])}>
          <Icon className="h-4 w-4" strokeWidth={2} />
        </div>
      </div>
      <p className="font-mono-tabular mt-3 text-3xl font-semibold text-[var(--color-text)]">{value}</p>
      {hint ? <p className="mt-1 text-xs text-[var(--color-text-muted)]">{hint}</p> : null}
    </div>
  );
}
