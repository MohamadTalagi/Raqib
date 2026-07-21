import type { LucideIcon } from "lucide-react";
import { FileDown, HelpCircle, ShieldAlert, ShieldCheck, ShieldQuestion, Trash2, Upload } from "lucide-react";
import { useEffect, useState } from "react";
import { useNavigate, useParams } from "react-router-dom";
import { Shell } from "@/components/layout/Shell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Skeleton } from "@/components/ui/skeleton";
import { ErrorState, EmptyState } from "@/components/ui/state";
import { ComplianceBadge, ConfidenceLabel, SeverityBadge, StatusBadge } from "@/components/ui/severity-badge";
import { ConfirmDialog } from "@/components/ui/confirm-dialog";
import { useFetch } from "@/lib/useFetch";
import { api, ApiError } from "@/lib/api";
import { cn } from "@/lib/utils";
import type { Confidence, DeviceTier, Severity, VerdictStatus } from "@/lib/types";

interface TierMeta {
  label: string;
  icon: LucideIcon;
  className: string;
}

const TIER_META: Record<DeviceTier, TierMeta> = {
  insecure: {
    label: "Insecure",
    icon: ShieldAlert,
    className: "text-[var(--color-critical)] bg-[color-mix(in_oklab,var(--color-critical)_14%,transparent)]",
  },
  partial: {
    label: "Partial",
    icon: ShieldQuestion,
    className: "text-[var(--color-medium)] bg-[color-mix(in_oklab,var(--color-medium)_14%,transparent)]",
  },
  hardened: {
    label: "Hardened",
    icon: ShieldCheck,
    className: "text-[var(--color-pass)] bg-[color-mix(in_oklab,var(--color-pass)_14%,transparent)]",
  },
  unknown: {
    label: "Unknown",
    icon: HelpCircle,
    className: "text-[var(--color-text-muted)] bg-[var(--color-surface-hover)]",
  },
};

const VERDICT_STATUSES: readonly VerdictStatus[] = ["PASS", "FAIL", "PARTIAL", "INCONCLUSIVE"];
const SEVERITIES: readonly Severity[] = ["low", "medium", "high", "critical"];
const CONFIDENCES: readonly Confidence[] = ["high", "medium", "low"];

function isVerdictStatus(value: string): value is VerdictStatus {
  return (VERDICT_STATUSES as readonly string[]).includes(value);
}

function isSeverity(value: string): value is Severity {
  return (SEVERITIES as readonly string[]).includes(value);
}

function isConfidence(value: string): value is Confidence {
  return (CONFIDENCES as readonly string[]).includes(value);
}

interface MetaFieldProps {
  label: string;
  value: string | null;
}

function MetaField({ label, value }: MetaFieldProps) {
  return (
    <div>
      <p className="text-[10px] font-medium tracking-wide text-[var(--color-text-muted)] uppercase">{label}</p>
      <p className="mt-1 text-sm text-[var(--color-text)]">
        {value ?? <span className="text-[var(--color-text-muted)]">Not recorded</span>}
      </p>
    </div>
  );
}

function deregisterErrorMessage(caught: unknown): string {
  if (caught instanceof ApiError || caught instanceof Error) {
    return caught.message;
  }
  return "Could not deregister the device.";
}

function firmwareErrorMessage(caught: unknown): string {
  if (caught instanceof ApiError || caught instanceof Error) {
    return caught.message;
  }
  return "Could not update firmware for this device.";
}

interface FirmwareState {
  firmware_filename: string | null;
  firmware_sha256: string | null;
  firmware_uploaded_at: string | null;
}

export function DeviceDetailPage() {
  const { deviceId } = useParams<{ deviceId: string }>();
  const navigate = useNavigate();
  const detail = useFetch(() => api.device(deviceId ?? ""), [deviceId]);
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [deregistering, setDeregistering] = useState(false);
  const [deregisterError, setDeregisterError] = useState<string | null>(null);
  const [firmwareOverride, setFirmwareOverride] = useState<FirmwareState | null>(null);
  const [pendingFirmwareFile, setPendingFirmwareFile] = useState<File | null>(null);
  const [firmwareBusy, setFirmwareBusy] = useState(false);
  const [firmwareError, setFirmwareError] = useState<string | null>(null);

  // A device switch (navigating from one detail page to another without a
  // full remount) must not carry over the previous device's upload state.
  useEffect(() => {
    setFirmwareOverride(null);
    setPendingFirmwareFile(null);
    setFirmwareBusy(false);
    setFirmwareError(null);
  }, [deviceId]);

  async function handleUploadFirmware() {
    if (!deviceId || !pendingFirmwareFile) return;
    setFirmwareBusy(true);
    setFirmwareError(null);
    try {
      const result = await api.uploadFirmware(deviceId, pendingFirmwareFile);
      setFirmwareOverride({
        firmware_filename: result.firmware_filename,
        firmware_sha256: result.firmware_sha256,
        firmware_uploaded_at: result.firmware_uploaded_at,
      });
      setPendingFirmwareFile(null);
    } catch (caught) {
      setFirmwareError(firmwareErrorMessage(caught));
    } finally {
      setFirmwareBusy(false);
    }
  }

  async function handleRemoveFirmware() {
    if (!deviceId) return;
    setFirmwareBusy(true);
    setFirmwareError(null);
    try {
      await api.deleteFirmware(deviceId);
      setFirmwareOverride({ firmware_filename: null, firmware_sha256: null, firmware_uploaded_at: null });
    } catch (caught) {
      setFirmwareError(firmwareErrorMessage(caught));
    } finally {
      setFirmwareBusy(false);
    }
  }

  async function handleConfirmDeregister() {
    if (!deviceId) return;
    setDeregistering(true);
    setDeregisterError(null);
    try {
      await api.deleteDevice(deviceId);
      navigate("/devices");
    } catch (caught) {
      setDeregisterError(deregisterErrorMessage(caught));
      setDeregistering(false);
      setConfirmOpen(false);
    }
  }

  if (detail.error) {
    return (
      <Shell title="Device" subtitle={deviceId}>
        <ErrorState message={detail.error} />
      </Shell>
    );
  }

  if (detail.loading || !detail.data) {
    return (
      <Shell title="Device">
        <div className="space-y-4">
          <Skeleton className="h-24" />
          <Skeleton className="h-40" />
          <Skeleton className="h-40" />
        </div>
      </Shell>
    );
  }

  const { device, evidence, verdicts, scan_jobs, compliance } = detail.data;
  const tier = TIER_META[device.tier];
  const TierIcon = tier.icon;
  const firmware: FirmwareState = firmwareOverride ?? device;

  return (
    <Shell title={device.display_name} subtitle={device.description}>
      <div className="space-y-6">
        <Card>
          <CardContent className="flex flex-wrap items-center gap-3 pt-5">
            <span
              className={cn(
                "inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-xs font-medium",
                tier.className,
              )}
            >
              <TierIcon className="h-3 w-3" />
              {tier.label}
            </span>
            <span
              className="flex items-center gap-1.5"
              title={`${compliance.tested_controls} of the NCA ${compliance.framework} controls this lab automates have been assessed for this device; ${compliance.passing_controls} pass.`}
            >
              <span className="text-xs text-[var(--color-text-muted)]">{compliance.framework}:</span>
              <ComplianceBadge percentage={compliance.percentage} />
            </span>
            <span className="font-mono text-xs text-[var(--color-text-secondary)]">
              {device.host ?? <span className="text-[var(--color-text-muted)]">No host configured</span>}
            </span>
            <span className="ml-auto text-xs text-[var(--color-text-muted)]">
              Source: {device.source ?? "unknown"}
            </span>
            <a
              href={api.deviceReportUrl(device.device_id)}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity hover:opacity-90"
            >
              <FileDown className="h-4 w-4" />
              Download report
            </a>
            <button
              type="button"
              onClick={() => setConfirmOpen(true)}
              className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-critical)] hover:text-[var(--color-critical)]"
            >
              <Trash2 className="h-4 w-4" />
              Deregister
            </button>
            {deregisterError && (
              <p className="w-full text-xs text-[var(--color-critical)]">{deregisterError}</p>
            )}
          </CardContent>
        </Card>

        <ConfirmDialog
          open={confirmOpen}
          title="Deregister this device?"
          description={
            <>
              This removes <span className="font-mono text-[var(--color-text)]">{device.device_id}</span> and its
              registered services from the inventory. Evidence and verdicts already recorded are kept — they are
              immutable audit records and are not deleted. The device will reappear in the device list as
              unregistered, and re-registering it with the same ID will reattach its full history.
            </>
          }
          confirmLabel="Deregister device"
          pending={deregistering}
          onConfirm={handleConfirmDeregister}
          onCancel={() => setConfirmOpen(false)}
        />

        <Card>
          <CardHeader>
            <CardTitle>Inventory</CardTitle>
          </CardHeader>
          <CardContent className="grid grid-cols-2 gap-4 pt-2 sm:grid-cols-3">
            <MetaField label="Vendor" value={device.vendor} />
            <MetaField label="Model" value={device.model} />
            <MetaField label="Location" value={device.location} />
            <MetaField label="Owner" value={device.owner} />
            <MetaField label="Notes" value={device.notes} />
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Firmware</CardTitle>
          </CardHeader>
          <CardContent className="space-y-3 pt-2">
            {firmware.firmware_filename ? (
              <>
                <div className="grid grid-cols-2 gap-4 sm:grid-cols-3">
                  <MetaField label="Filename" value={firmware.firmware_filename} />
                  <MetaField label="Uploaded" value={firmware.firmware_uploaded_at} />
                </div>
                <p className="text-xs">
                  <span className="text-[var(--color-text-muted)]">SHA-256: </span>
                  <span className="font-mono text-[var(--color-text-secondary)]">
                    {firmware.firmware_sha256?.slice(0, 16)}…
                  </span>
                </p>
                <button
                  type="button"
                  onClick={handleRemoveFirmware}
                  disabled={firmwareBusy}
                  className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] px-4 py-2 text-sm font-medium text-[var(--color-text-secondary)] transition-colors hover:border-[var(--color-critical)] hover:text-[var(--color-critical)] disabled:cursor-not-allowed disabled:opacity-50"
                >
                  <Trash2 className="h-4 w-4" />
                  Remove firmware
                </button>
              </>
            ) : (
              <div className="flex flex-wrap items-center gap-3">
                <input
                  type="file"
                  aria-label="Firmware archive"
                  accept=".tar.gz,.tgz"
                  onChange={(e) => setPendingFirmwareFile(e.target.files?.[0] ?? null)}
                  className="text-sm text-[var(--color-text-secondary)]"
                />
                <button
                  type="button"
                  onClick={handleUploadFirmware}
                  disabled={!pendingFirmwareFile || firmwareBusy}
                  className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] disabled:cursor-not-allowed disabled:opacity-40"
                >
                  <Upload className="h-4 w-4" />
                  Upload firmware
                </button>
              </div>
            )}
            {firmwareError && <p className="text-xs text-[var(--color-critical)]">{firmwareError}</p>}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Evidence</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {evidence.length === 0 ? (
              <EmptyState message="No evidence recorded for this device." />
            ) : (
              <div className="overflow-hidden rounded-md border border-[var(--color-border)]">
                <div className="grid grid-cols-[1fr_1fr_2fr_0.7fr_1.1fr] gap-4 border-b border-[var(--color-border)] px-4 py-2 text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                  <span>Evidence</span>
                  <span>Test / Tool</span>
                  <span>Finding</span>
                  <span>Confidence</span>
                  <span>Timestamp</span>
                </div>
                <div className="divide-y divide-[var(--color-border)]">
                  {evidence.map((e) => (
                    <div
                      key={e.evidence_id}
                      className="grid grid-cols-[1fr_1fr_2fr_0.7fr_1.1fr] items-center gap-4 px-4 py-2.5 text-sm"
                    >
                      <span className="truncate font-mono text-xs text-[var(--color-text-secondary)]">
                        {e.evidence_id}
                      </span>
                      <span className="min-w-0">
                        <span className="block truncate font-mono text-[11px] text-[var(--color-text-muted)]">
                          {e.test_id}
                        </span>
                        <span className="block truncate text-[var(--color-text-secondary)]">{e.tool}</span>
                      </span>
                      <span className="truncate text-[var(--color-text)]">{e.finding}</span>
                      {isConfidence(e.confidence) ? (
                        <ConfidenceLabel confidence={e.confidence} />
                      ) : (
                        <span className="font-mono text-xs text-[var(--color-text-muted)]">{e.confidence}</span>
                      )}
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{e.timestamp}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Verdicts</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {verdicts.length === 0 ? (
              <EmptyState message="No verdicts recorded for this device." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {verdicts.map((v) => (
                  <li key={v.verdict_id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    {isVerdictStatus(v.status) ? (
                      <StatusBadge status={v.status} />
                    ) : (
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.status}</span>
                    )}
                    {isSeverity(v.severity) ? (
                      <SeverityBadge severity={v.severity} />
                    ) : (
                      <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.severity}</span>
                    )}
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.control_id}</span>
                    <span className="min-w-0 flex-1 truncate text-[var(--color-text-secondary)]">{v.reason}</span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{v.timestamp}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>

        <Card>
          <CardHeader>
            <CardTitle>Scan history</CardTitle>
          </CardHeader>
          <CardContent className="pt-2">
            {scan_jobs.length === 0 ? (
              <EmptyState message="No scans have been run against this device yet." />
            ) : (
              <ul className="divide-y divide-[var(--color-border)]">
                {scan_jobs.map((job) => (
                  <li key={job.id} className="flex flex-wrap items-center gap-3 py-2.5 text-sm">
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">#{job.id}</span>
                    <span className="min-w-0 flex-1 truncate font-mono text-xs text-[var(--color-text-secondary)]">
                      {job.test_id}
                    </span>
                    <span className="text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase">
                      {job.status}
                    </span>
                    <span className="font-mono text-xs text-[var(--color-text-muted)]">{job.created_at}</span>
                  </li>
                ))}
              </ul>
            )}
          </CardContent>
        </Card>
      </div>
    </Shell>
  );
}
