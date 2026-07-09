import { Activity } from "lucide-react";

interface TopBarProps {
  title: string;
  subtitle?: string;
}

export function TopBar({ title, subtitle }: TopBarProps) {
  return (
    <header className="sticky top-0 z-10 flex h-16 items-center justify-between border-b border-[var(--color-border)] bg-[var(--color-bg)]/85 px-8 backdrop-blur">
      <div>
        <h1 className="text-lg font-semibold tracking-tight text-[var(--color-text)]">{title}</h1>
        {subtitle ? <p className="text-xs text-[var(--color-text-muted)]">{subtitle}</p> : null}
      </div>
      <div className="flex items-center gap-2 rounded-full border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-1.5">
        <Activity className="h-3.5 w-3.5 text-[var(--color-pass)]" strokeWidth={2.5} />
        <span className="font-mono text-xs text-[var(--color-text-secondary)]">lab: live</span>
      </div>
    </header>
  );
}
