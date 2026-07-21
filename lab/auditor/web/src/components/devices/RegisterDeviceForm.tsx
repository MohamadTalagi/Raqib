import { useState } from "react";
import type { FormEvent } from "react";
import { Plus, Trash2 } from "lucide-react";
import { api, ApiError, type CreateDevicePayload } from "@/lib/api";
import type { DeviceMutationResult, DeviceTier, ServiceType } from "@/lib/types";

const SERVICE_TYPES: ServiceType[] = ["http", "https", "mqtt", "mqtts", "telnet", "ssh"];
const TIERS: DeviceTier[] = ["insecure", "partial", "hardened", "unknown"];

interface ServiceRow {
  service_type: ServiceType;
  port: string;
  published_port: string;
}

const EMPTY_SERVICE: ServiceRow = { service_type: "http", port: "80", published_port: "" };

// Quick-picks keep the services repeater from being tedious for the common cases.
const QUICK_PICKS: Record<string, ServiceRow[]> = {
  "Smart camera (HTTP)": [{ service_type: "http", port: "80", published_port: "" }],
  "Smart camera (HTTPS)": [{ service_type: "https", port: "443", published_port: "" }],
  "MQTT broker": [{ service_type: "mqtt", port: "1883", published_port: "" }],
  "MQTT broker (TLS)": [{ service_type: "mqtts", port: "8883", published_port: "" }],
};

interface FormFields {
  device_id: string;
  display_name: string;
  description: string;
  tier: DeviceTier;
  host: string;
  vendor: string;
  model: string;
  location: string;
  owner: string;
  notes: string;
}

const EMPTY_FIELDS: FormFields = {
  device_id: "",
  display_name: "",
  description: "",
  tier: "unknown",
  host: "",
  vendor: "",
  model: "",
  location: "",
  owner: "",
  notes: "",
};

interface FormError {
  field?: string;
  message: string;
}

// Every `field` value the backend's validation can send in a 400 response —
// see validate_device_id/validate_host/validate_port/validate_service_type
// and the tier/display_name/services checks in
// lab/auditor/api/device_validation.py and _validate_device_payload in
// lab/auditor/api/main.py. Each of these has a dedicated inline renderer
// below (fieldError() for the top-level fields, serviceFieldError() for the
// three service-row fields, which the backend reports without a row index).
// Keep this set in sync with the backend: any field NOT in this set falls
// through to the banner instead of vanishing, so a backend field added later
// still surfaces its message even before a matching inline renderer exists.
const KNOWN_ERROR_FIELDS = new Set<string>([
  "device_id",
  "display_name",
  "host",
  "tier",
  "services",
  "service_type",
  "port",
  "published_port",
]);

interface RegisterDeviceFormProps {
  onRegistered: (device: DeviceMutationResult) => void;
  onCancel: () => void;
  /**
   * Pre-fills the device ID field — used when the form is opened from an
   * unregistered device card, where the ID is already known from evidence
   * and must match exactly for that evidence to attach to the new record.
   */
  initialDeviceId?: string;
}

const INPUT_CLASS =
  "mt-1 w-full rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-3 py-2 text-sm text-[var(--color-text)] focus:border-[var(--color-brand)] focus:outline-none";
const LABEL_CLASS = "text-xs font-medium tracking-wide text-[var(--color-text-muted)] uppercase";

export function RegisterDeviceForm({ onRegistered, onCancel, initialDeviceId }: RegisterDeviceFormProps) {
  const [fields, setFields] = useState<FormFields>({
    ...EMPTY_FIELDS,
    device_id: initialDeviceId ?? EMPTY_FIELDS.device_id,
  });
  const [services, setServices] = useState<ServiceRow[]>([{ ...EMPTY_SERVICE }]);
  const [firmwareFile, setFirmwareFile] = useState<File | null>(null);
  const [firmwareWarning, setFirmwareWarning] = useState<string | null>(null);
  // Set only when the device registered successfully but the firmware
  // upload failed - the form stays open on the warning instead of closing
  // immediately, so the message is actually seen before the parent unmounts
  // this component (its onRegistered closes the form right away).
  const [registeredDevice, setRegisteredDevice] = useState<DeviceMutationResult | null>(null);
  const [error, setError] = useState<FormError | null>(null);
  const [submitting, setSubmitting] = useState(false);

  function setField<K extends keyof FormFields>(name: K, value: FormFields[K]) {
    setFields((current) => ({ ...current, [name]: value }));
  }

  function updateService(index: number, patch: Partial<ServiceRow>) {
    setServices((current) => current.map((row, i) => (i === index ? { ...row, ...patch } : row)));
  }

  function removeService(index: number) {
    setServices((current) => current.filter((_, i) => i !== index));
  }

  function addService() {
    setServices((current) => [...current, { ...EMPTY_SERVICE }]);
  }

  function applyQuickPick(rows: ServiceRow[]) {
    setServices(rows.map((row) => ({ ...row })));
  }

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setError(null);
    setFirmwareWarning(null);
    setSubmitting(true);

    const payload: CreateDevicePayload = {
      device_id: fields.device_id,
      display_name: fields.display_name,
      description: fields.description || undefined,
      tier: fields.tier,
      host: fields.host,
      vendor: fields.vendor || null,
      model: fields.model || null,
      location: fields.location || null,
      owner: fields.owner || null,
      notes: fields.notes || null,
      services: services.map((row) => ({
        service_type: row.service_type,
        port: Number(row.port),
        published_port: row.published_port ? Number(row.published_port) : null,
      })),
    };

    try {
      const device = await api.createDevice(payload);
      // A failed firmware upload here must not look like a failed
      // registration - the device already exists at this point - so it gets
      // its own distinct, non-blocking warning rather than reusing `error`.
      if (firmwareFile) {
        try {
          const withFirmware = await api.uploadFirmware(device.device_id, firmwareFile);
          onRegistered(withFirmware);
        } catch (firmwareErr) {
          const message =
            firmwareErr instanceof ApiError
              ? firmwareErr.message
              : "Device registered, but the firmware upload failed.";
          setFirmwareWarning(message);
          setRegisteredDevice(device);
        }
      } else {
        onRegistered(device);
      }
    } catch (caught) {
      if (caught instanceof ApiError) {
        setError({ field: caught.field, message: caught.message });
      } else {
        const message = caught instanceof Error ? caught.message : "Could not register the device.";
        setError({ message });
      }
    } finally {
      setSubmitting(false);
    }
  }

  function fieldError(name: string) {
    if (error?.field !== name) return null;
    return <p className="mt-1 text-xs text-[var(--color-critical)]">{error.message}</p>;
  }

  // service_type/port/published_port errors come back from the backend as a
  // bare field name with no row index (see device_validation.py), so we
  // can't know which service row was at fault. Render the message once
  // against the repeater as a whole rather than inventing an indexing
  // convention the backend doesn't send.
  function serviceFieldError() {
    if (!error?.field || !["service_type", "port", "published_port"].includes(error.field)) {
      return null;
    }
    return <p className="mt-1 text-xs text-[var(--color-critical)]">{error.message}</p>;
  }

  return (
    <form onSubmit={handleSubmit} className="space-y-6">
      <div className="grid gap-4 sm:grid-cols-2">
        <div>
          <label className={LABEL_CLASS} htmlFor="register-device-id">
            Device ID
          </label>
          <input
            id="register-device-id"
            aria-label="Device ID"
            value={fields.device_id}
            onChange={(e) => setField("device_id", e.target.value)}
            className={`${INPUT_CLASS} font-mono`}
            required
          />
          {fieldError("device_id")}
        </div>
        <div>
          <label className={LABEL_CLASS} htmlFor="register-display-name">
            Display name
          </label>
          <input
            id="register-display-name"
            aria-label="Display name"
            value={fields.display_name}
            onChange={(e) => setField("display_name", e.target.value)}
            className={INPUT_CLASS}
            required
          />
          {fieldError("display_name")}
        </div>
        <div>
          <label className={LABEL_CLASS} htmlFor="register-host">
            Host (container name or 172.30.0.x)
          </label>
          <input
            id="register-host"
            aria-label="Host"
            value={fields.host}
            onChange={(e) => setField("host", e.target.value)}
            className={`${INPUT_CLASS} font-mono`}
            required
          />
          {fieldError("host")}
        </div>
        <div>
          <label className={LABEL_CLASS} htmlFor="register-tier">
            Security tier
          </label>
          <select
            id="register-tier"
            aria-label="Security tier"
            value={fields.tier}
            onChange={(e) => setField("tier", e.target.value as DeviceTier)}
            className={INPUT_CLASS}
          >
            {TIERS.map((tier) => (
              <option key={tier} value={tier}>
                {tier}
              </option>
            ))}
          </select>
          {fieldError("tier")}
        </div>
      </div>

      <div>
        <label className={LABEL_CLASS} htmlFor="register-description">
          Description
        </label>
        <textarea
          id="register-description"
          aria-label="Description"
          value={fields.description}
          onChange={(e) => setField("description", e.target.value)}
          rows={2}
          className={INPUT_CLASS}
        />
      </div>

      <div className="grid gap-4 sm:grid-cols-2">
        {(["vendor", "model", "location", "owner"] as const).map((name) => (
          <div key={name}>
            <label className={`${LABEL_CLASS} capitalize`} htmlFor={`register-${name}`}>
              {name}
            </label>
            <input
              id={`register-${name}`}
              aria-label={name}
              value={fields[name]}
              onChange={(e) => setField(name, e.target.value)}
              className={INPUT_CLASS}
            />
          </div>
        ))}
      </div>

      <div>
        <label className={LABEL_CLASS} htmlFor="register-notes">
          Notes
        </label>
        <textarea
          id="register-notes"
          aria-label="Notes"
          value={fields.notes}
          onChange={(e) => setField("notes", e.target.value)}
          rows={2}
          className={INPUT_CLASS}
        />
      </div>

      <div>
        <div className="mb-2 flex flex-wrap items-center gap-2">
          <span className={LABEL_CLASS}>Services</span>
          {Object.keys(QUICK_PICKS).map((label) => (
            <button
              key={label}
              type="button"
              onClick={() => applyQuickPick(QUICK_PICKS[label])}
              className="rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1 text-xs font-medium text-[var(--color-text-secondary)] hover:border-[var(--color-brand)] hover:text-[var(--color-brand)]"
            >
              {label}
            </button>
          ))}
        </div>

        <div className="space-y-2">
          {services.map((row, index) => (
            <div key={index} className="flex flex-wrap items-end gap-3">
              <div>
                <label className="text-xs text-[var(--color-text-muted)]" htmlFor={`service-type-${index}`}>
                  Service type
                </label>
                <select
                  id={`service-type-${index}`}
                  aria-label="Service type"
                  value={row.service_type}
                  onChange={(e) => updateService(index, { service_type: e.target.value as ServiceType })}
                  className="mt-1 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 text-sm text-[var(--color-text)]"
                >
                  {SERVICE_TYPES.map((type) => (
                    <option key={type} value={type}>
                      {type}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="text-xs text-[var(--color-text-muted)]" htmlFor={`service-port-${index}`}>
                  Port
                </label>
                <input
                  id={`service-port-${index}`}
                  aria-label={`Port ${index + 1}`}
                  value={row.port}
                  onChange={(e) => updateService(index, { port: e.target.value })}
                  className="mt-1 w-24 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 font-mono text-sm text-[var(--color-text)]"
                />
              </div>
              <div>
                <label className="text-xs text-[var(--color-text-muted)]" htmlFor={`service-published-port-${index}`}>
                  Published port
                </label>
                <input
                  id={`service-published-port-${index}`}
                  aria-label={`Published port ${index + 1}`}
                  value={row.published_port}
                  onChange={(e) => updateService(index, { published_port: e.target.value })}
                  className="mt-1 w-32 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-2.5 py-1.5 font-mono text-sm text-[var(--color-text)]"
                />
              </div>
              <button
                type="button"
                aria-label="Remove service"
                onClick={() => removeService(index)}
                className="rounded-md border border-[var(--color-border)] p-2 text-[var(--color-text-muted)] hover:border-[var(--color-critical)] hover:text-[var(--color-critical)]"
              >
                <Trash2 className="h-4 w-4" />
              </button>
            </div>
          ))}
        </div>

        <button
          type="button"
          onClick={addService}
          className="mt-2 inline-flex items-center gap-1 text-sm text-[var(--color-brand)] hover:opacity-80"
        >
          <Plus className="h-3.5 w-3.5" /> Add service
        </button>
        {fieldError("services")}
        {serviceFieldError()}
      </div>

      <div>
        <label className={LABEL_CLASS} htmlFor="register-firmware">
          Firmware archive (optional)
        </label>
        <input
          id="register-firmware"
          aria-label="Firmware archive"
          type="file"
          accept=".tar.gz,.tgz"
          onChange={(e) => setFirmwareFile(e.target.files?.[0] ?? null)}
          className={`${INPUT_CLASS} cursor-pointer file:mr-3 file:cursor-pointer file:rounded-md file:border-0 file:bg-[var(--color-surface-hover)] file:px-3 file:py-1.5 file:text-sm file:text-[var(--color-text)]`}
        />
        <p className="mt-1 text-xs text-[var(--color-text-muted)]">
          A .tar.gz archive enables automated firmware analysis for this device from the Run Scan page.
        </p>
      </div>

      {error && !KNOWN_ERROR_FIELDS.has(error.field ?? "") && (
        <p className="text-sm text-[var(--color-critical)]">{error.message}</p>
      )}

      {registeredDevice ? (
        <div className="space-y-3 rounded-md border border-[var(--color-medium)] bg-[var(--color-surface)] p-3">
          <p className="text-sm text-[var(--color-medium)]">
            Device registered as <span className="font-mono">{registeredDevice.device_id}</span>, but the
            firmware upload failed: {firmwareWarning}. You can upload it later from the device's detail page.
          </p>
          <button
            type="button"
            onClick={() => onRegistered(registeredDevice)}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)]"
          >
            Continue
          </button>
        </div>
      ) : (
        <div className="flex gap-2">
          <button
            type="submit"
            disabled={submitting}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md bg-[var(--color-brand)] px-4 py-2 text-sm font-semibold text-[var(--color-brand-foreground)] transition-opacity disabled:cursor-not-allowed disabled:opacity-40"
          >
            {submitting ? "Registering…" : "Register device"}
          </button>
          <button
            type="button"
            onClick={onCancel}
            className="inline-flex cursor-pointer items-center gap-2 rounded-md border border-[var(--color-border)] bg-[var(--color-surface)] px-4 py-2 text-sm font-medium text-[var(--color-text)] hover:bg-[var(--color-surface-hover)]"
          >
            Cancel
          </button>
        </div>
      )}
    </form>
  );
}
