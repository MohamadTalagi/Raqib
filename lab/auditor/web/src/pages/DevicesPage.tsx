import { useMemo, useState } from "react";
import { Link, useNavigate } from "react-router-dom";
import { Plus, X, CheckCircle2, CircleDashed, ArrowUpRight, HardDrive, ArrowRight, Zap } from "lucide-react";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { RegisterDeviceForm } from "@/components/devices/RegisterDeviceForm";
import type { DeviceRegistrationPrefill } from "@/components/devices/NetworkDiscoveryPanel";
import { DeviceCohortPicker } from "@/components/pipeline/DeviceCohortPicker";
import { PhaseStatusBadge } from "@/components/pipeline/PhaseStatusBadge";
import { AutomatedRunDialog } from "@/components/pipeline/AutomatedRunDialog";
import { serviceIcon } from "@/lib/serviceIcons";
import { useFetch } from "@/lib/useFetch";
import { api } from "@/lib/api";
import { cn } from "@/lib/utils";
import { devicePipelineStatus, furthestReachedPhase, type DevicePipelineData, type PipelinePhaseDef } from "@/lib/pipeline";
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
  furthestPhase?: PipelinePhaseDef | null;
}

// The card body is shared between the registered (whole-card-is-a-link) and
// unregistered (plain, non-navigating) presentations below so the two stay
// visually identical apart from the affordance that differs between them.
function DeviceCardBody({ device, failCount, onRegisterClick, furthestPhase }: DeviceCardProps) {
  const Icon = device.services[0] ? serviceIcon(device.services[0].service_type) : HardDrive;

  return (
    <CardContent className="pt-5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex h-10 w-10 items-center justify-center rounded-md bg-[var(--color-surface-hover)]">
          <Icon className="h-5 w-5 text-[var(--color-text-secondary)]" strokeWidth={1.75} />
        </div>
        {furthestPhase && <PhaseStatusBadge phase={furthestPhase} reached />}
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

function DeviceCard({ device, failCount, onRegisterClick, furthestPhase }: DeviceCardProps) {
  const body = (
    <DeviceCardBody
      device={device}
      failCount={failCount}
      onRegisterClick={onRegisterClick}
      furthestPhase={furthestPhase}
    />
  );

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
  const navigate = useNavigate();
  const [refreshKey, setRefreshKey] = useState(0);
  const devices = useFetch(api.devices, [refreshKey]);
  const verdicts = useFetch(api.verdicts, []);
  const evidence = useFetch(api.evidence, []);
  const scanTests = useFetch(api.scanTests, []);
  const ncaDevices = useFetch(api.ncaDevices, []);
  const vulnFleet = useFetch(api.vulnIntelFleetSummary, []);
  const riskDevices = useFetch(api.riskDevices, []);
  const [showForm, setShowForm] = useState(false);
  const [prefill, setPrefill] = useState<DeviceRegistrationPrefill | null>(null);
  const [selected, setSelected] = useState<Set<string>>(new Set());
  const [showAutomatedRunDialog, setShowAutomatedRunDialog] = useState(false);

  const loading = devices.loading || verdicts.loading;
  const error = devices.error ?? verdicts.error;

  // Every input here is already fetched fleet-wide for other reasons above -
  // no per-device request needed just to compute a phase badge. A device
  // absent from a fleet endpoint (nca/vuln/risk) simply hasn't reached that
  // phase yet, same as devicePipelineStatus's own "not reached" default.
  const furthestPhaseByDevice = useMemo(() => {
    const result = new Map<string, PipelinePhaseDef | null>();
    for (const device of devices.data ?? []) {
      const ncaRow = (ncaDevices.data ?? []).find((d) => d.device_id === device.device_id);
      // devicePipelineStatus only ever reads .overall_status/.has_data/.known
      // off these three - the fleet-wide endpoints above already carry that
      // much per device without a per-device fetch, so the rest of each
      // full detail shape is deliberately not reconstructed here.
      const data = {
        evidenceTestIds: (evidence.data ?? [])
          .filter((e) => e.device_id === device.device_id)
          .map((e) => e.test_id),
        // NOT_APPLICABLE means "this control doesn't apply to this device's
        // registered services," not "a real assessment happened" - the
        // fleet-wide recompute synthesizes these for every device regardless
        // of whether any test ever ran against it. Excluding it here matches
        // nca_compliance's own "not_tested" exclusion just below.
        hasSaIotVerdict: (verdicts.data ?? []).some(
          (v) => v.device_id === device.device_id && v.status !== "NOT_APPLICABLE",
        ),
        scanTests: scanTests.data ?? [],
        nca: ncaRow ? { overall_status: ncaRow.overall_status } : null,
        vuln: (vulnFleet.data?.devices ?? []).some((d) => d.device_id === device.device_id)
          ? { has_data: true }
          : null,
        risk: (riskDevices.data?.devices ?? []).some((d) => d.device_id === device.device_id)
          ? { known: true }
          : null,
      } as unknown as DevicePipelineData;
      result.set(device.device_id, furthestReachedPhase(devicePipelineStatus(data)));
    }
    return result;
  }, [devices.data, evidence.data, verdicts.data, scanTests.data, ncaDevices.data, vulnFleet.data, riskDevices.data]);

  const registeredDevices = useMemo(() => (devices.data ?? []).filter((d) => d.registered), [devices.data]);

  function openForm(deviceId?: string) {
    setPrefill(deviceId ? { device_id: deviceId, display_name: "", host: "", services: [] } : null);
    setShowForm(true);
  }

  function closeForm() {
    setShowForm(false);
    setPrefill(null);
  }

  function handleRegistered() {
    closeForm();
    setRefreshKey((key) => key + 1);
  }

  function advanceToFingerprinting() {
    navigate("/fingerprinting", { state: { deviceIds: Array.from(selected) } });
  }

  return (
    <Shell title="Devices" subtitle="Simulated IoT device profiles in the lab">
      <div className="mb-4 flex items-center justify-between gap-2">
        <Link
          to="/discovery"
          className="inline-flex items-center gap-1.5 text-xs text-[var(--color-text-muted)] hover:text-[var(--color-brand)] hover:underline"
        >
          Looking for devices to register? Try Discovery →
        </Link>
        <div className="flex items-center gap-2">
          <button
            type="button"
            onClick={() => setShowAutomatedRunDialog(true)}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] px-4 py-2 text-sm font-semibold text-[var(--color-text)] transition-colors hover:bg-[var(--color-surface-hover)]"
          >
            <Zap className="h-4 w-4" />
            Fully Automated Run
          </button>
          <button
            type="button"
            onClick={() => (showForm ? closeForm() : openForm())}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
          >
            {showForm ? <X className="h-4 w-4" /> : <Plus className="h-4 w-4" />}
            {showForm ? "Cancel" : "Register device"}
          </button>
        </div>
      </div>

      <AutomatedRunDialog
        open={showAutomatedRunDialog}
        onCancel={() => setShowAutomatedRunDialog(false)}
        onStarted={(run) => {
          setShowAutomatedRunDialog(false);
          navigate(`/automated-run/${run.id}`);
        }}
      />

      {showForm && (
        <Card className="mb-6">
          <CardContent className="pt-5">
            <RegisterDeviceForm
              key={prefill?.device_id ?? "new"}
              initialDeviceId={prefill?.device_id}
              initialDisplayName={prefill?.display_name}
              initialHost={prefill?.host}
              initialServices={prefill?.services}
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
        <>
          <div className="grid grid-cols-1 gap-4 md:grid-cols-2 xl:grid-cols-3">
            {devices.data.map((device) => {
              const counts = verdictCounts((verdicts.data ?? []).filter((v) => v.device_id === device.device_id));

              return (
                <DeviceCard
                  key={device.device_id}
                  device={device}
                  failCount={counts.fail}
                  onRegisterClick={() => openForm(device.device_id)}
                  furthestPhase={furthestPhaseByDevice.get(device.device_id)}
                />
              );
            })}
          </div>

          {registeredDevices.length > 0 && (
            <Card className="mt-6">
              <CardContent className="space-y-3 pt-5">
                <div>
                  <h2 className="text-sm font-semibold text-[var(--color-text)]">Advance down the pipeline</h2>
                  <p className="mt-0.5 text-xs text-[var(--color-text-secondary)]">
                    Select one, some, or all registered devices to carry forward into Fingerprinting.
                  </p>
                </div>
                <DeviceCohortPicker devices={registeredDevices} selected={selected} onChange={setSelected} />
                <button
                  type="button"
                  onClick={advanceToFingerprinting}
                  disabled={selected.size === 0}
                  className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90 disabled:cursor-not-allowed disabled:opacity-40"
                >
                  Advance to Fingerprinting ({selected.size})
                  <ArrowRight className="h-4 w-4" />
                </button>
              </CardContent>
            </Card>
          )}
        </>
      )}
    </Shell>
  );
}
