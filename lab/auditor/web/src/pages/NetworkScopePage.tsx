import { useEffect, useState } from "react";
import type { FormEvent } from "react";
import { Loader2, Plus, Radar, RotateCcw, ShieldAlert, XCircle } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState } from "@/components/ui/state";
import { useNetworkScan } from "@/components/devices/NetworkDiscoveryPanel";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { useToast } from "@/lib/useToast";
import { cn } from "@/lib/utils";
import type { InterfaceDetectObservations, NetworkScope } from "@/lib/types";

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

function scopeBadge(scope: NetworkScope): { label: string; className: string } {
  if (scope.kind === "lab_preset") {
    return {
      label: "Built-in lab preset",
      className: "text-[var(--color-brand)] bg-[color-mix(in_oklab,var(--color-brand)_16%,transparent)]",
    };
  }
  if (scope.source === "detected") {
    return {
      label: "Detected",
      className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_16%,transparent)]",
    };
  }
  return {
    label: "Custom",
    className: "text-[var(--color-text-secondary)] bg-[var(--color-surface-hover)]",
  };
}

function ScopeBadge({ scope }: { scope: NetworkScope }) {
  const { label, className } = scopeBadge(scope);
  return (
    <span className={cn("inline-flex items-center rounded-md px-2 py-0.5 text-xs font-semibold", className)}>
      {label}
    </span>
  );
}

/** Every registered device's host must fall inside one of these ranges to
 * validate (device_validation.ALLOWED_NETWORKS) and Network Discovery only
 * ever sweeps these ranges (scan_tests.ACTIVE_SCOPES) - this list *is* the
 * platform's scan-target security boundary, not just a display convenience. */
function AddScopeForm({ onCreated }: { onCreated: () => void }) {
  const { showToast } = useToast();
  const [label, setLabel] = useState("");
  const [cidr, setCidr] = useState("");
  const [addedBy, setAddedBy] = useState("");
  const [reason, setReason] = useState("");
  const [error, setError] = useState<{ field?: string; message: string } | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function fieldError(name: string) {
    if (error?.field !== name) return null;
    return <p className="mt-1 text-xs text-[var(--color-critical)]">{error.message}</p>;
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setSubmitting(true);
    try {
      await api.createNetworkScope({
        label: label.trim(),
        cidr: cidr.trim(),
        added_by: addedBy.trim(),
        reason: reason.trim() || undefined,
      });
      showToast(`Added network scope ${cidr.trim()}.`, "success");
      setLabel("");
      setCidr("");
      setReason("");
      onCreated();
    } catch (caught) {
      if (caught instanceof ApiError) {
        setError({ field: caught.field, message: caught.message });
      } else {
        setError({ message: "Could not add this scope." });
      }
    } finally {
      setSubmitting(false);
    }
  }

  return (
    <form onSubmit={handleSubmit} className="grid gap-4 sm:grid-cols-2">
      <div>
        <label className={LABEL_CLASS} htmlFor="scope-label">Label</label>
        <input
          id="scope-label"
          className={INPUT_CLASS}
          value={label}
          onChange={(e) => setLabel(e.target.value)}
          placeholder="Building 2 IoT VLAN"
          required
        />
        {fieldError("label")}
      </div>
      <div>
        <label className={LABEL_CLASS} htmlFor="scope-cidr">Subnet (CIDR)</label>
        <input
          id="scope-cidr"
          className={cn(INPUT_CLASS, "font-mono")}
          value={cidr}
          onChange={(e) => setCidr(e.target.value)}
          placeholder="10.4.0.0/24"
          required
        />
        {fieldError("cidr")}
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          Must be a private range (RFC1918 or link-local), /16 or narrower.
        </p>
      </div>
      <div>
        <label className={LABEL_CLASS} htmlFor="scope-added-by">Added by</label>
        <input
          id="scope-added-by"
          className={INPUT_CLASS}
          value={addedBy}
          onChange={(e) => setAddedBy(e.target.value)}
          placeholder="Your name"
          required
        />
        {fieldError("added_by")}
      </div>
      <div>
        <label className={LABEL_CLASS} htmlFor="scope-reason">Reason (optional)</label>
        <input
          id="scope-reason"
          className={INPUT_CLASS}
          value={reason}
          onChange={(e) => setReason(e.target.value)}
          placeholder="New building added to the fleet"
        />
      </div>
      {error && !error.field && <p className="text-sm text-[var(--color-critical)] sm:col-span-2">{error.message}</p>}
      <div className="sm:col-span-2">
        <button
          type="submit"
          disabled={submitting}
          className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-50"
        >
          {submitting ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
          Add scope
        </button>
      </div>
    </form>
  );
}

function DetectPanel({ onAdded }: { onAdded: () => void }) {
  const { showToast } = useToast();
  const [scanId, setScanId] = useState<number | null>(null);
  const [scan] = useNetworkScan(scanId);
  const [launching, setLaunching] = useState(false);
  const [launchError, setLaunchError] = useState<string | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [addedBy, setAddedBy] = useState("");
  const [adding, setAdding] = useState(false);

  const inFlight = scan !== null && (scan.status === "pending" || scan.status === "running");
  const observations =
    scan?.status === "completed" ? (scan.observations as InterfaceDetectObservations | null) : null;

  // Every candidate starts pre-checked once a detection completes - the
  // user reviews and can deselect, rather than having to opt in to each one.
  useEffect(() => {
    if (observations) {
      setSelected(new Set(observations.candidates.map((c) => c.cidr)));
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [scan?.id, scan?.status]);

  async function handleDetect() {
    setLaunchError(null);
    setLaunching(true);
    setSelected(new Set());
    try {
      const created = await api.createNetworkScan("interface_detect");
      setScanId(created.id);
    } catch (err) {
      setLaunchError(err instanceof ApiError ? err.message : "Could not start detection.");
    } finally {
      setLaunching(false);
    }
  }

  function toggle(cidr: string, checked: boolean) {
    setSelected((prev) => {
      const next = new Set(prev);
      if (checked) next.add(cidr);
      else next.delete(cidr);
      return next;
    });
  }

  async function handleAddSelected() {
    if (!observations || !addedBy.trim()) return;
    setAdding(true);
    const candidates = observations.candidates.filter((c) => selected.has(c.cidr));
    const results = await Promise.allSettled(
      candidates.map((c) =>
        api.createNetworkScope({
          label: `Detected: ${c.interface} (${c.cidr})`,
          cidr: c.cidr,
          added_by: addedBy.trim(),
          source: "detected",
        }),
      ),
    );
    const failed = results.filter((r) => r.status === "rejected").length;
    if (failed > 0) {
      showToast(`${candidates.length - failed} of ${candidates.length} detected scope(s) added.`, "error");
    } else {
      showToast(`Added ${candidates.length} detected scope(s).`, "success");
    }
    setAdding(false);
    setScanId(null);
    setSelected(new Set());
    onAdded();
  }

  return (
    <div className="space-y-4">
      <p className="text-xs text-[var(--color-text-secondary)]">
        Inspects the auditor-worker container's own network interfaces and suggests which one(s)
        likely sit on your IoT network — excluding whichever interface reaches this platform's own
        backend. Nothing is added until you review and confirm below.
      </p>
      <button
        type="button"
        onClick={handleDetect}
        disabled={launching || inFlight}
        className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)] disabled:cursor-not-allowed disabled:opacity-50"
      >
        {launching || inFlight ? <Loader2 className="h-4 w-4 animate-spin" /> : <Radar className="h-4 w-4" />}
        {inFlight ? "Detecting…" : "Detect automatically"}
      </button>
      {launchError && <p className="text-sm text-[var(--color-critical)]">{launchError}</p>}
      {scan?.status === "failed" && (
        <p className="text-sm text-[var(--color-critical)]">{scan.error ?? "Detection failed."}</p>
      )}
      {observations && (
        <div className="space-y-3 rounded-md border border-[var(--color-border)] p-4">
          {observations.error && <p className="text-sm text-[var(--color-critical)]">{observations.error}</p>}
          {observations.excluded_backend_subnet && (
            <p className="text-xs text-[var(--color-text-muted)]">
              Excluded <span className="font-mono">{observations.excluded_backend_subnet}</span> — this
              platform's own backend network.
            </p>
          )}
          {observations.candidates.length === 0 ? (
            <p className="text-sm text-[var(--color-text-muted)]">No other candidate subnets found.</p>
          ) : (
            <>
              {observations.candidates.map((candidate) => (
                <label key={candidate.cidr} className="flex cursor-pointer items-center gap-2 text-sm">
                  <input
                    type="checkbox"
                    checked={selected.has(candidate.cidr)}
                    onChange={(e) => toggle(candidate.cidr, e.target.checked)}
                    className="h-4 w-4 accent-[var(--color-brand)]"
                  />
                  <span className="font-mono text-[var(--color-text)]">{candidate.cidr}</span>
                  <span className="text-xs text-[var(--color-text-muted)]">({candidate.interface})</span>
                </label>
              ))}
              <div className="flex flex-wrap items-end gap-3 pt-2">
                <div>
                  <label className={LABEL_CLASS} htmlFor="detect-added-by">Added by</label>
                  <input
                    id="detect-added-by"
                    className={INPUT_CLASS}
                    value={addedBy}
                    onChange={(e) => setAddedBy(e.target.value)}
                    placeholder="Your name"
                  />
                </div>
                <button
                  type="button"
                  onClick={handleAddSelected}
                  disabled={adding || selected.size === 0 || !addedBy.trim()}
                  className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-50"
                >
                  {adding ? <Loader2 className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
                  Add selected ({selected.size})
                </button>
              </div>
            </>
          )}
        </div>
      )}
    </div>
  );
}

interface DeactivateState {
  scope: NetworkScope;
  affectedCount: number | null;
}

export function NetworkScopePage() {
  const { showToast } = useToast();
  const [refreshKey, setRefreshKey] = useState(0);
  const scopes = useFetch(() => api.listNetworkScopes(), [refreshKey]);
  const [deactivating, setDeactivating] = useState<DeactivateState | null>(null);
  const [actor, setActor] = useState("");
  const [deactivateReason, setDeactivateReason] = useState("");
  const [pending, setPending] = useState(false);

  function refresh() {
    setRefreshKey((k) => k + 1);
  }

  async function openDeactivate(scope: NetworkScope) {
    setActor("");
    setDeactivateReason("");
    setDeactivating({ scope, affectedCount: null });
    try {
      const impact = await api.networkScopeDeactivationImpact(scope.id);
      setDeactivating({ scope, affectedCount: impact.affected_device_count });
    } catch {
      setDeactivating({ scope, affectedCount: null });
    }
  }

  async function confirmDeactivate() {
    if (!deactivating || !actor.trim()) return;
    setPending(true);
    try {
      await api.deactivateNetworkScope(deactivating.scope.id, {
        actor: actor.trim(),
        reason: deactivateReason.trim() || undefined,
      });
      showToast(`Deactivated ${deactivating.scope.cidr}.`, "success");
      setDeactivating(null);
      refresh();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : "Could not deactivate this scope.", "error");
    } finally {
      setPending(false);
    }
  }

  async function handleReactivate(scope: NetworkScope) {
    try {
      await api.reactivateNetworkScope(scope.id);
      showToast(`Reactivated ${scope.cidr}.`, "success");
      refresh();
    } catch (err) {
      showToast(err instanceof ApiError ? err.message : "Could not reactivate this scope.", "error");
    }
  }

  return (
    <Shell
      title="Network Scope"
      subtitle="Which subnet(s) contain your IoT devices — the only ranges any scan is allowed to reach"
    >
      <div className="space-y-6">
        <Card>
          <CardContent className="flex items-start gap-3 pt-5">
            <ShieldAlert className="mt-0.5 h-5 w-5 shrink-0 text-[var(--color-medium)]" />
            <p className="text-sm text-[var(--color-text-secondary)]">
              This allowlist is the security boundary every scan in this platform passes through —
              Discovery, Fingerprinting, device-scope compliance checks, and Vulnerability
              Intelligence can only ever reach a host inside one of the ranges below. Registering a
              device or running a scan against anything outside them is rejected.
            </p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-col items-start gap-1">
            <CardTitle>Configured scopes</CardTitle>
            <CardDescription>Active scopes are swept and legal targets; inactive ones are kept, not deleted.</CardDescription>
          </CardHeader>
          <CardContent className="pt-0">
            {scopes.error ? (
              <ErrorState message={scopes.error} />
            ) : scopes.loading || !scopes.data ? (
              <Skeleton className="h-40" />
            ) : (
              <div className="divide-y divide-[var(--color-border)]">
                {scopes.data.map((scope) => (
                  <div key={scope.id} className="flex flex-wrap items-center gap-3 py-3">
                    <div className="min-w-0 flex-1">
                      <div className="flex items-center gap-2">
                        <span className="font-mono text-sm text-[var(--color-text)]">{scope.cidr}</span>
                        <ScopeBadge scope={scope} />
                        {!scope.is_active && <XCircle className="h-4 w-4 text-[var(--color-text-muted)]" />}
                      </div>
                      <p className="mt-0.5 text-xs text-[var(--color-text-muted)]">
                        {scope.label} · added by {scope.added_by}
                        {!scope.is_active && scope.deactivated_by && (
                          <> · deactivated by {scope.deactivated_by}</>
                        )}
                      </p>
                    </div>
                    {scope.is_active ? (
                      <button
                        type="button"
                        onClick={() => openDeactivate(scope)}
                        className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)]"
                      >
                        Deactivate
                      </button>
                    ) : (
                      <button
                        type="button"
                        onClick={() => handleReactivate(scope)}
                        className="inline-flex cursor-pointer items-center gap-1.5 rounded-md border border-[var(--color-border)] px-3 py-1.5 text-xs font-medium text-[var(--color-text-secondary)] transition-colors hover:bg-[var(--color-surface-hover)]"
                      >
                        <RotateCcw className="h-3.5 w-3.5" />
                        Reactivate
                      </button>
                    )}
                  </div>
                ))}
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-col items-start gap-1">
            <CardTitle>Detect automatically</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <DetectPanel onAdded={refresh} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex-col items-start gap-1">
            <CardTitle>Add a subnet</CardTitle>
          </CardHeader>
          <CardContent className="pt-0">
            <AddScopeForm onCreated={refresh} />
          </CardContent>
        </Card>
      </div>

      <ConfirmDialog
        open={deactivating !== null}
        title={`Deactivate ${deactivating?.scope.cidr ?? ""}?`}
        confirmLabel="Deactivate"
        pending={pending}
        confirmDisabled={!actor.trim()}
        onCancel={() => setDeactivating(null)}
        onConfirm={confirmDeactivate}
        description={
          <div className="space-y-3">
            <p>
              {deactivating?.affectedCount === null
                ? "Checking how many registered devices this affects…"
                : `${deactivating?.affectedCount} registered device(s) currently use this range. `}
              {deactivating && deactivating.affectedCount !== null && deactivating.affectedCount > 0 && (
                <>Any future scan against them will be rejected until this scope is reactivated.</>
              )}
            </p>
            <div>
              <label className={LABEL_CLASS} htmlFor="deactivate-actor">Your name</label>
              <input
                id="deactivate-actor"
                className={INPUT_CLASS}
                value={actor}
                onChange={(e) => setActor(e.target.value)}
                placeholder="Required"
              />
            </div>
            <div>
              <label className={LABEL_CLASS} htmlFor="deactivate-reason">Reason (optional)</label>
              <input
                id="deactivate-reason"
                className={INPUT_CLASS}
                value={deactivateReason}
                onChange={(e) => setDeactivateReason(e.target.value)}
              />
            </div>
          </div>
        }
      />
    </Shell>
  );
}
