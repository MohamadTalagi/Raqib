import { useMemo, useState } from "react";
import { ChevronDown, Search } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { ConfidenceLabel } from "@/components/ui/severity-badge";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";

export function EvidencePage() {
  const evidence = useFetch(api.evidence, []);
  const [query, setQuery] = useState("");
  const [expanded, setExpanded] = useState<string | null>(null);

  const filtered = useMemo(() => {
    if (!evidence.data) return [];
    const q = query.trim().toLowerCase();
    if (!q) return evidence.data;
    return evidence.data.filter((e) =>
      [e.evidence_id, e.device_id, e.tool, e.test_id, e.finding].some((field) =>
        field.toLowerCase().includes(q),
      ),
    );
  }, [evidence.data, query]);

  return (
    <Shell title="Evidence" subtitle="Raw findings normalized into structured records">
      <div className="mb-4 flex items-center gap-2 rounded-lg border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2">
        <Search className="h-4 w-4 text-[var(--color-text-muted)]" />
        <input
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search by device, tool, test, or finding…"
          className="w-full bg-transparent text-sm text-[var(--color-text)] placeholder:text-[var(--color-text-muted)] focus:outline-none"
        />
      </div>

      {evidence.error ? (
        <ErrorState message={evidence.error} />
      ) : evidence.loading || !evidence.data ? (
        <Skeleton className="h-96" />
      ) : filtered.length === 0 ? (
        <EmptyState message="No evidence records match your search." />
      ) : (
        <Card className="overflow-hidden py-0">
          <div className="grid grid-cols-[1.1fr_1fr_0.9fr_2fr_0.7fr_28px] gap-4 border-b border-[var(--color-border)] px-5 py-3 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
            <span>Evidence</span>
            <span>Device / Test</span>
            <span>Tool</span>
            <span>Finding</span>
            <span>Confidence</span>
            <span />
          </div>
          <div className="divide-y divide-[var(--color-border)]">
            {filtered.map((e) => {
              const isOpen = expanded === e.evidence_id;
              return (
                <div key={e.evidence_id}>
                  <button
                    type="button"
                    onClick={() => setExpanded(isOpen ? null : e.evidence_id)}
                    className="grid w-full cursor-pointer grid-cols-[1.1fr_1fr_0.9fr_2fr_0.7fr_28px] items-center gap-4 px-5 py-3 text-left text-sm transition-colors hover:bg-[var(--color-surface-hover)]"
                  >
                    <span className="truncate font-mono text-xs text-[var(--color-text-secondary)]">
                      {e.evidence_id}
                    </span>
                    <span className="min-w-0">
                      <span className="block truncate text-[var(--color-text)]">{e.device_id}</span>
                      <span className="block truncate font-mono text-[11px] text-[var(--color-text-muted)]">
                        {e.test_id}
                      </span>
                    </span>
                    <span className="truncate text-[var(--color-text-secondary)]">
                      {e.tool} <span className="text-[var(--color-text-muted)]">{e.tool_version}</span>
                    </span>
                    <span className="truncate text-[var(--color-text)]">{e.finding}</span>
                    <ConfidenceLabel confidence={e.confidence} />
                    <ChevronDown
                      className={cn(
                        "h-4 w-4 text-[var(--color-text-muted)] transition-transform",
                        isOpen && "rotate-180",
                      )}
                    />
                  </button>
                  {isOpen && (
                    <div className="space-y-3 border-t border-[var(--color-border)] bg-[var(--color-surface-raised)] px-5 py-4">
                      <div>
                        <p className="mb-1 text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                          Command
                        </p>
                        <code className="block overflow-x-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-[var(--color-text)]">
                          {e.command}
                        </code>
                      </div>
                      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
                        <div>
                          <p className="mb-1 text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                            Observations
                          </p>
                          <pre className="overflow-x-auto rounded-md bg-black/30 px-3 py-2 font-mono text-xs text-[var(--color-text-secondary)]">
                            {JSON.stringify(e.observations, null, 2)}
                          </pre>
                        </div>
                        <div className="space-y-2 text-xs">
                          <p>
                            <span className="text-[var(--color-text-muted)]">Timestamp: </span>
                            <span className="font-mono text-[var(--color-text-secondary)]">{e.timestamp}</span>
                          </p>
                          <p>
                            <span className="text-[var(--color-text-muted)]">SHA-256: </span>
                            <span className="font-mono text-[var(--color-text-secondary)]">
                              {e.sha256.slice(0, 16)}…
                            </span>
                          </p>
                          <p>
                            <span className="text-[var(--color-text-muted)]">Raw output: </span>
                            <a
                              href={api.rawArtefactUrl(e.raw_output_path)}
                              target="_blank"
                              rel="noreferrer"
                              className="font-mono break-all text-[var(--color-brand)] hover:underline"
                            >
                              {e.raw_output_path}
                            </a>
                          </p>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}
          </div>
        </Card>
      )}
    </Shell>
  );
}
