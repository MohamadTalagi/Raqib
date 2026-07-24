import type {
  Assessment,
  ControlRecord,
  ControlVerdictRollup,
  CreateAssessmentResult,
  CreateNCAAssessmentPayload,
  CreateNCAExceptionPayload,
  OverrideNCAAssessmentPayload,
  Device,
  DeviceDetail,
  DeviceMutationResult,
  EvidenceRecord,
  NetworkScan,
  NCAAssessment,
  NCAControl,
  NCAControlDetail,
  NCADeviceComplianceRow,
  NCADeviceDetail,
  NCADomainSummary,
  NCAException,
  NCAOrganizationalCompliance,
  NCAStatus,
  NCASummary,
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
  devices: (): Promise<Device[]> => getJson<Device[]>("/devices"),
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

  createAssessment: (deviceId: string, testIds: string[]): Promise<CreateAssessmentResult> =>
    postJson<CreateAssessmentResult>("/assessments", { device_id: deviceId, test_ids: testIds }),
  getAssessment: (assessmentId: string): Promise<Assessment> =>
    getJson<Assessment>(`/assessments/${encodeURIComponent(assessmentId)}`),
  cancelAssessment: (assessmentId: string): Promise<Assessment> =>
    postJson<Assessment>(`/assessments/${encodeURIComponent(assessmentId)}/cancel`, {}),

  device: (deviceId: string): Promise<DeviceDetail> =>
    getJson<DeviceDetail>(`/devices/${encodeURIComponent(deviceId)}`),
  createDevice: (payload: CreateDevicePayload): Promise<DeviceMutationResult> =>
    postJson<DeviceMutationResult>("/devices", payload),
  updateDevice: (deviceId: string, patch: UpdateDevicePayload): Promise<DeviceMutationResult> =>
    patchJson<DeviceMutationResult>(`/devices/${encodeURIComponent(deviceId)}`, patch),
  deleteDevice: (deviceId: string): Promise<void> =>
    deleteRequest(`/devices/${encodeURIComponent(deviceId)}`),
  uploadFirmware: async (deviceId: string, file: File): Promise<DeviceMutationResult> => {
    const body = new FormData();
    body.append("firmware", file);
    const response = await fetch(
      `${API_BASE_URL}/devices/${encodeURIComponent(deviceId)}/firmware`,
      { method: "POST", body },
    );
    if (!response.ok) {
      throw await apiErrorFrom("/firmware", response);
    }
    return (await response.json()) as DeviceMutationResult;
  },
  deleteFirmware: (deviceId: string): Promise<void> =>
    deleteRequest(`/devices/${encodeURIComponent(deviceId)}/firmware`),
  controlVerdicts: (controlId: string): Promise<ControlVerdictRollup> =>
    getJson<ControlVerdictRollup>(`/controls/${encodeURIComponent(controlId)}/verdicts`),

  // -- Network discovery (discovery-first device onboarding) --------------

  createNetworkScan: (): Promise<NetworkScan> => postJson<NetworkScan>("/network-scans", {}),
  getNetworkScan: (id: number): Promise<NetworkScan> => getJson<NetworkScan>(`/network-scans/${id}`),

  // Returns a URL rather than fetching: the browser must perform the download
  // itself so the server's Content-Disposition filename is honoured. Fetching
  // would yield a blob we'd then have to name ourselves.
  deviceReportUrl: (deviceId: string): string =>
    `${API_BASE_URL}/devices/${encodeURIComponent(deviceId)}/report.pdf`,
  deviceReportHtmlUrl: (deviceId: string): string =>
    `${API_BASE_URL}/devices/${encodeURIComponent(deviceId)}/report.html`,
  deviceReportJsonUrl: (deviceId: string): string =>
    `${API_BASE_URL}/devices/${encodeURIComponent(deviceId)}/report.json`,

  // Points directly at document-store's raw output file, served statically
  // by auditor-api - lets the UI's "view raw artefact" link open the exact
  // file the evidence's sha256 was computed from.
  rawArtefactUrl: (rawOutputPath: string): string => `${API_BASE_URL}/${rawOutputPath}`,

  // -- NCA CGIoT-1:2024 compliance module --------------------------------

  ncaSummary: (): Promise<NCASummary> => getJson<NCASummary>("/nca/summary"),
  ncaDomains: (): Promise<NCADomainSummary> => getJson<NCADomainSummary>("/nca/domains"),
  ncaControls: (filters?: { domainId?: string; scopeType?: string }): Promise<NCAControl[]> => {
    const params = new URLSearchParams();
    if (filters?.domainId) params.set("domain_id", filters.domainId);
    if (filters?.scopeType) params.set("scope_type", filters.scopeType);
    const query = params.toString();
    return getJson<NCAControl[]>(`/nca/controls${query ? `?${query}` : ""}`);
  },
  ncaControl: (controlId: string): Promise<NCAControlDetail> =>
    getJson<NCAControlDetail>(`/nca/controls/${encodeURIComponent(controlId)}`),
  ncaDevices: (status?: NCAStatus): Promise<NCADeviceComplianceRow[]> =>
    getJson<NCADeviceComplianceRow[]>(`/nca/devices${status ? `?status=${status}` : ""}`),
  ncaDevice: (deviceId: string): Promise<NCADeviceDetail> =>
    getJson<NCADeviceDetail>(`/nca/devices/${encodeURIComponent(deviceId)}`),
  ncaOrganization: (): Promise<NCAOrganizationalCompliance> =>
    getJson<NCAOrganizationalCompliance>("/nca/organization"),

  createNcaAssessment: (payload: CreateNCAAssessmentPayload): Promise<NCAAssessment> =>
    postJson<NCAAssessment>("/nca/assessments", payload),
  recomputeNcaAssessments: (): Promise<{ created: number; assessment_ids: string[] }> =>
    postJson("/nca/assessments/recompute", {}),
  retestNcaAssessment: (
    assessmentId: string,
    payload: Partial<CreateNCAAssessmentPayload>,
  ): Promise<NCAAssessment> =>
    postJson<NCAAssessment>(`/nca/assessments/${encodeURIComponent(assessmentId)}/retest`, payload),
  overrideNcaAssessment: (
    assessmentId: string,
    payload: OverrideNCAAssessmentPayload,
  ): Promise<NCAAssessment & { original_status: NCAStatus; override_justification: string }> =>
    postJson(`/nca/assessments/${encodeURIComponent(assessmentId)}/override`, payload),

  ncaExceptions: (filters?: { status?: string; controlId?: string; deviceId?: string }): Promise<NCAException[]> => {
    const params = new URLSearchParams();
    if (filters?.status) params.set("status", filters.status);
    if (filters?.controlId) params.set("control_id", filters.controlId);
    if (filters?.deviceId) params.set("device_id", filters.deviceId);
    const query = params.toString();
    return getJson<NCAException[]>(`/nca/exceptions${query ? `?${query}` : ""}`);
  },
  createNcaException: (payload: CreateNCAExceptionPayload): Promise<NCAException> =>
    postJson<NCAException>("/nca/exceptions", payload),
  approveNcaException: (exceptionId: string, approvedBy: string): Promise<NCAException> =>
    postJson<NCAException>(`/nca/exceptions/${encodeURIComponent(exceptionId)}/approve`, {
      approved_by: approvedBy,
    }),
  rejectNcaException: (exceptionId: string, rejectedBy: string): Promise<NCAException> =>
    postJson<NCAException>(`/nca/exceptions/${encodeURIComponent(exceptionId)}/reject`, {
      rejected_by: rejectedBy,
    }),

  ncaDeviceReportCsvUrl: (): string => `${API_BASE_URL}/nca/reports/devices.csv`,
  ncaControlsReportCsvUrl: (): string => `${API_BASE_URL}/nca/reports/controls.csv`,
  ncaEvidenceReportCsvUrl: (): string => `${API_BASE_URL}/nca/reports/evidence.csv`,
  ncaExecutiveReportPdfUrl: (): string => `${API_BASE_URL}/nca/reports/executive.pdf`,
};
