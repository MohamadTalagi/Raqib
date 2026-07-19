import type {
  ControlRecord,
  ControlVerdictRollup,
  Device,
  DeviceDetail,
  DeviceSummary,
  EvidenceRecord,
  RecomputeVerdictsResult,
  ScanJob,
  ScanTestSpec,
  Summary,
  VerdictRecord,
} from "./types";

function resolveApiBaseUrl(): string {
  const configured = import.meta.env.VITE_API_URL as string | undefined;
  if (configured) {
    return configured;
  }
  // No build-time override: derive from whatever host the page was loaded
  // from (localhost, a LAN IP, or a Tailscale address) instead of hardcoding
  // localhost, which only ever resolves to the client's own machine.
  return `${window.location.protocol}//${window.location.hostname}:8000`;
}

const API_BASE_URL: string = resolveApiBaseUrl();

export class ApiError extends Error {
  readonly status: number;
  readonly field?: string;

  constructor(message: string, status: number, field?: string) {
    super(message);
    this.name = "ApiError";
    this.status = status;
    this.field = field;
  }
}

/**
 * Builds an ApiError from a failed response, preferring the API's
 * `{"field": ..., "detail": ...}` body shape (used by device-registration
 * validation errors) so callers can highlight the offending form field.
 * Falls back to the generic `${path} failed with ${status}` message for
 * responses that don't carry that shape.
 */
async function apiErrorFrom(path: string, response: Response): Promise<ApiError> {
  let body: unknown;
  try {
    body = await response.json();
  } catch {
    body = undefined;
  }

  if (
    typeof body === "object" &&
    body !== null &&
    "detail" in body &&
    typeof (body as { detail: unknown }).detail === "string"
  ) {
    const detail = (body as { detail: string }).detail;
    const field =
      "field" in body && typeof (body as { field: unknown }).field === "string"
        ? (body as { field: string }).field
        : undefined;
    return new ApiError(detail, response.status, field);
  }

  return new ApiError(`${path} failed with ${response.status}`, response.status);
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    throw await apiErrorFrom(path, response);
  }
  return (await response.json()) as T;
}

async function postJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw await apiErrorFrom(path, response);
  }
  return (await response.json()) as T;
}

async function patchJson<T>(path: string, body: unknown): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!response.ok) {
    throw await apiErrorFrom(path, response);
  }
  return (await response.json()) as T;
}

async function deleteRequest(path: string): Promise<void> {
  const response = await fetch(`${API_BASE_URL}${path}`, { method: "DELETE" });
  if (!response.ok) {
    throw await apiErrorFrom(path, response);
  }
  if (response.status === 204) {
    return;
  }
  // Non-204 success bodies aren't expected from DELETE in this API, but
  // drain the body defensively rather than leaving it unread.
  await response.json().catch(() => undefined);
}

export interface DeviceServicePayload {
  service_type: string;
  port: number;
  published_port: number | null;
}

export interface CreateDevicePayload {
  device_id: string;
  display_name: string;
  description?: string;
  tier: string;
  host: string;
  vendor?: string | null;
  model?: string | null;
  location?: string | null;
  owner?: string | null;
  notes?: string | null;
  services: DeviceServicePayload[];
}

export type UpdateDevicePayload = Partial<CreateDevicePayload>;

export const api = {
  summary: (): Promise<Summary> => getJson<Summary>("/summary"),
  devices: (): Promise<DeviceSummary[]> => getJson<DeviceSummary[]>("/devices"),
  evidence: (): Promise<EvidenceRecord[]> => getJson<EvidenceRecord[]>("/evidence"),
  verdicts: (): Promise<VerdictRecord[]> => getJson<VerdictRecord[]>("/verdicts"),
  controls: (): Promise<ControlRecord[]> => getJson<ControlRecord[]>("/controls"),

  scanTests: (): Promise<ScanTestSpec[]> => getJson<ScanTestSpec[]>("/scan-tests"),
  createScanJob: (device_id: string, test_id: string): Promise<ScanJob> =>
    postJson<ScanJob>("/scan-jobs", { device_id, test_id }),
  getScanJob: (id: number): Promise<ScanJob> => getJson<ScanJob>(`/scan-jobs/${id}`),
  recordScanJob: (id: number, finding: string, confidence: string): Promise<EvidenceRecord> =>
    postJson<EvidenceRecord>(`/scan-jobs/${id}/record`, { finding, confidence }),
  recomputeVerdicts: (): Promise<RecomputeVerdictsResult> =>
    postJson<RecomputeVerdictsResult>("/verdicts/recompute", {}),

  device: (deviceId: string): Promise<DeviceDetail> =>
    getJson<DeviceDetail>(`/devices/${deviceId}`),
  createDevice: (payload: CreateDevicePayload): Promise<Device> =>
    postJson<Device>("/devices", payload),
  updateDevice: (deviceId: string, patch: UpdateDevicePayload): Promise<Device> =>
    patchJson<Device>(`/devices/${deviceId}`, patch),
  deleteDevice: (deviceId: string): Promise<void> => deleteRequest(`/devices/${deviceId}`),
  controlVerdicts: (controlId: string): Promise<ControlVerdictRollup> =>
    getJson<ControlVerdictRollup>(`/controls/${controlId}/verdicts`),
};
