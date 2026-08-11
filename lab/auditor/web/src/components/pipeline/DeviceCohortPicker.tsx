import { EmptyState } from "@/components/ui/state";

// Only device_id/display_name are ever read here - a Pick, not the full
// Device shape, so this can be reused with narrower per-page row types
// (e.g. NCACompliancePage's NCADeviceComplianceRow) without adapting them.
interface CohortDevice {
  device_id: string;
  display_name: string;
}

interface DeviceCohortPickerProps {
  devices: CohortDevice[];
  selected: Set<string>;
  onChange: (selected: Set<string>) => void;
}

/**
 * The one "select 1/some/all" device-cohort control, shared by every
 * pipeline page (Devices, Fingerprinting, NCA Compliance, Vulnerability
 * Intelligence, NCA Compliance) instead of a bespoke checkbox list on each -
 * see ui-overhaul.txt. Selecting a device here never mutates it or triggers
 * anything on its own; the calling page decides what "advance" means for
 * its own phase.
 */
export function DeviceCohortPicker({ devices, selected, onChange }: DeviceCohortPickerProps) {
  if (devices.length === 0) {
    return <EmptyState message="No devices registered yet." />;
  }

  const allSelected = devices.every((d) => selected.has(d.device_id));

  function toggleAll(checked: boolean) {
    onChange(checked ? new Set(devices.map((d) => d.device_id)) : new Set());
  }

  function toggleOne(deviceId: string, checked: boolean) {
    const next = new Set(selected);
    if (checked) {
      next.add(deviceId);
    } else {
      next.delete(deviceId);
    }
    onChange(next);
  }

  return (
    <div className="overflow-hidden rounded-md border border-[var(--color-border)]">
      <label className="flex cursor-pointer items-center gap-2 border-b border-[var(--color-border)] px-3 py-2 text-xs font-semibold tracking-wide text-[var(--color-text-muted)] uppercase hover:bg-[var(--color-surface-hover)]">
        <input
          type="checkbox"
          checked={allSelected}
          onChange={(e) => toggleAll(e.target.checked)}
          className="h-4 w-4 accent-[var(--color-brand)]"
        />
        Select all ({devices.length})
      </label>
      <div className="divide-y divide-[var(--color-border)]">
        {devices.map((device) => (
          <label
            key={device.device_id}
            className="flex cursor-pointer items-center gap-3 px-3 py-2 text-sm text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
          >
            <input
              type="checkbox"
              checked={selected.has(device.device_id)}
              onChange={(e) => toggleOne(device.device_id, e.target.checked)}
              className="h-4 w-4 accent-[var(--color-brand)]"
            />
            <span className="min-w-0 flex-1 truncate">{device.display_name}</span>
            <span className="font-mono text-xs text-[var(--color-text-muted)]">{device.device_id}</span>
          </label>
        ))}
      </div>
    </div>
  );
}
