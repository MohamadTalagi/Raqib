import { AlertTriangle, Inbox } from "lucide-react";

export function ErrorState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] py-16 text-center">
      <AlertTriangle className="h-8 w-8 text-[var(--color-critical)]" strokeWidth={1.75} />
      <div>
        <p className="text-sm font-medium text-[var(--color-text)]">Couldn't load data</p>
        <p className="mt-1 font-mono text-xs text-[var(--color-text-muted)]">{message}</p>
      </div>
    </div>
  );
}

export function EmptyState({ message }: { message: string }) {
  return (
    <div className="flex flex-col items-center gap-3 rounded-lg border border-dashed border-[var(--color-border)] py-16 text-center">
      <Inbox className="h-8 w-8 text-[var(--color-text-muted)]" strokeWidth={1.75} />
      <p className="text-sm text-[var(--color-text-muted)]">{message}</p>
    </div>
  );
}
