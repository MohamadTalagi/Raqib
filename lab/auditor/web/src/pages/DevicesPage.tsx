import { useState } from "react";
import { Link } from "react-router-dom";
import { Plus, X, CheckCircle2, CircleDashed, ArrowUpRight, HardDrive } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { RegisterDeviceForm } from "@/components/devices/RegisterDeviceForm";
import { getTierBadge } from "@/lib/deviceTier";
import { serviceIcon } from "@/lib/serviceIcons";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Device, VerdictRecord } from "@/lib/types";

function verdictCounts(deviceVerdicts: VerdictRecord[]) {
  return {
    pass: deviceVerdicts.filter((v) => v.status === "PASS").length,
    fail: deviceVerdicts.filter((v) => v.status === "FAIL").length,
  };
}

interface DeviceCardProps {
  device: Device;
  failCount: number;
  onRegisterClick: () => void;
}

// The card body is shared between the registered (whole-card-is-a-link) and
// unregistered (plain, non-navigating) presentations below so the two stay
// visually identical apart from the affordance that differs between them.
function DeviceCardBody({ device, failCount, onRegisterClick }: DeviceCardProps) {
  const tier = getTierBadge(device.tier);
  const TierIcon = tier.icon;
  const Icon = device.services[0] ? serviceIcon(device.services[0].service_type) : HardDrive;

  return (
    <CardContent className="pt-5">
      <div className="flex items-start justify-between">
        <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[var(--color-surface-hover)]">
          <Icon className="h-5 w-5 text-[var(--color-text-secondary)]" strokeWidth={1.75} />
        </div>
        <span
          className={cn("inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium", tier.className)}
        >
          <TierIcon className="h-3 w-3" />
          {tier.label}
        </span>
      </div>
      <div className="mt-3 flex items-center justify-between gap-2">
        <span className="inline-flex items-center gap-0.5 font-mono text-xs text-[var(--color-text-muted)]">
          {device.device_id}
          {device.registered && <ArrowUpRight className="h-3 w-3" />}
        </span>
        <span
          className={cn(
            "inline-flex items-center gap-1 text-[10px] font-medium tracking-wide uppercase",
            device.registered ? "text-[var(--color-pass)]" : "text-[var(--color-text-muted)]",
          )}
        >
          {device.registered ? <CheckCircle2 className="h-3 w-3" /> : <CircleDashed className="h-3 w-3" />}
          {device.registered ? "Registered" : "Unregistered"}
        </span>
      </div>
      <p className="mt-0.5 text-sm font-medium text-[var(--color-text)]">{device.display_name}</p>
      <p className="mt-1.5 text-xs leading-relaxed text-[var(--color-text-secondary)]">{device.description}</p>
      <div className="mt-4 flex items-center gap-4 border-t border-[var(--color-border)] pt-3 text-xs">
        <span className="text-[var(--color-text-muted)]">
          Evidence <span className="font-mono-tabular text-[var(--color-text)]">{device.evidence_count}</span>
        </span>
        <span className="text-[var(--color-text-muted)]">
          Verdicts <span className="font-mono-tabular text-[var(--color-text)]">{device.verdict_count}</span>
        </span>
        <span className="ml-auto flex items-center gap-3">
          {failCount > 0 && <span className="font-mono-tabular text-[var(--color-critical)]">{failCount} fail</span>}
          {!device.registered && (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation();
                onRegisterClick();
              }}
              className="font-medium text-[var(--color-brand)] hover:underline"
            >
              Register
            </button>
          )}
        </span>
      </div>
    </CardContent>
  );
}

function DeviceCard({ device, failCount, onRegisterClick }: DeviceCardProps) {
  const body = <DeviceCardBody device={device} failCount={failCount} onRegisterClick={onRegisterClick} />;

  // Registered devices have a real detail page: make the whole card the
  // link target (not just the small device-id text) so it reads as
  // interactive. Unregistered devices have no `devices` row, so
  // GET /devices/{id} 404s — the card must NOT navigate there; its only
  // affordance is the Register button (handled in DeviceCardBody).
  if (device.registered) {
    return (
      <Link to={`/devices/${device.device_id}`} className="block">
        <Card className="transition-colors hover:border-[var(--color-border-strong)]">{body}</Card>
      </Link>
    );
  }

  return <Card className="opacity-60">{body}</Card>;
}

export function DevicesPage() {
  const [refreshKey, setRefreshKey] = useState(0);
  const devices = useFetch(api.devices, [refreshKey]);
  const verdicts = useFetch(api.verdicts, []);
  const [showForm, setShowForm] = useState(false);
  const [prefillDeviceId, setPrefillDeviceId] = useState<string | null>(null);

  const loading = devices.loading || verdicts.loading;
  const error = devices.error ?? verdicts.error;

  function openForm(deviceId?: string) {
    setPrefillDeviceId(deviceId ?? null);
    setShowForm(true);
  }

  function closeForm() {
    setShowForm(false);
    setPrefillDeviceId(null);
  }

  function handleRegistered() {
    closeForm();
    setRefreshKey((key) => key + 1);
  }

  return (
    <Shell title="Devices" subtitle="Simulated IoT device profiles in the lab">
      <div className="mb-4 flex items-center justify-end">
        <button
          type="button"
          onClick={() => (showForm ? closeForm() : openForm())}
          className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
        >
          {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
          {showForm ? "Cancel" : "Register device"}
        </button>
      </div>

      {showForm && (
        <Card className="mb-6">
          <CardContent className="pt-5">
            <RegisterDeviceForm
              key={prefillDeviceId ?? "new"}
              initialDeviceId={prefillDeviceId ?? undefined}
              onRegistered={handleRegistered}
              onCancel={closeForm}
            />
          </CardContent>
        </Card>
      )}

      {error ? (
        <ErrorState message={error} />
      ) : loading || !devices.data ? (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          <Skeleton className="h-44" />
          <Skeleton className="h-44" />
          <Skeleton className="h-44" />
        </div>
      ) : devices.data.length === 0 ? (
        <EmptyState message="No devices have generated evidence yet." />
      ) : (
        <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
          {devices.data.map((device) => {
            const counts = verdictCounts((verdicts.data ?? []).filter((v) => v.device_id === device.device_id));

            return (
              <DeviceCard
                key={device.device_id}
                device={device}
                failCount={counts.fail}
                onRegisterClick={() => openForm(device.device_id)}
              />
            );
          })}
        </div>
      )}
    </Shell>
  );
}
