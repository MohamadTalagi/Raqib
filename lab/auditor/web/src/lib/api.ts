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
  NCAChecklist,
  NCAComplianceEvidence,
  NCACoverage,
  NCAControl,
  NCAControlDetail,
  NCADeviceComplianceRow,
  NCADeviceDetail,
  NCADeviceSuggestions,
  NCADomainSummary,
  NCAException,
  NCAOrganizationalCompliance,
  NCAStatus,
  NCASummary,
  RecomputeVerdictsResult,
  ReportRecord,
  ScanJob,
  ScanTestSpec,
  Severity,
  Summary,
  VerdictRecord,
  VulnDeviceSummary,
  VulnFleetSummary,
  VulnIntelStatus,
  DeviceRiskDetail,
  RiskCriticality,
  RiskDevicesResponse,
  RiskExposure,
  RiskFleetSummary,
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

// criticality/exposure are never accepted at POST /devices time (the API
// computes a sensible default there - see main.py's create_device) - only
// PATCH /devices/{id} can set them, so they're additive to Update's payload
// rather than part of CreateDevicePayload itself.
export type UpdateDevicePayload = Partial<CreateDevicePayload> & {
  criticality?: RiskCriticality;
  exposure?: RiskExposure;
};

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
  recordScanJob: (
    id: number,
    finding: string,
    confidence: string,
    confidenceReason?: string,
  ): Promise<EvidenceRecord> =>
    postJson<EvidenceRecord>(`/scan-jobs/${id}/record`, {
      finding,
      confidence,
      ...(confidenceReason ? { confidence_reason: confidenceReason } : {}),
    }),
  recomputeVerdicts: (): Promise<RecomputeVerdictsResult> =>
    postJson<RecomputeVerdictsResult>("/verdicts/recompute", {}),

  createAssessment: (deviceId: string, testIds: string[]): Promise<CreateAssessmentResult> =>
    postJson<CreateAssessmentResult>("/assessments", { device_id: deviceId, test_ids: testIds }),
  getAssessment: (assessmentId: string): Promise<Assessment> =>
    getJson<Assessment>(`/assessments/${encodeURIComponent(assessmentId)}`),
  cancelAssessment: (assessmentId: string): Promise<Assessment> =>
    postJson<Assessment>(`/assessments/${encodeURIComponent(assessmentId)}/cancel`, {}),
  listAssessments: (deviceId: string): Promise<Assessment[]> =>
    getJson<Assessment[]>(`/assessments?device_id=${encodeURIComponent(deviceId)}`),

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
  assessControlVerdict: (deviceId: string, controlId: string, severity?: Severity): Promise<VerdictRecord> =>
    postJson<VerdictRecord>(
      `/devices/${encodeURIComponent(deviceId)}/controls/${encodeURIComponent(controlId)}/assess`,
      severity ? { severity } : {},
    ),

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
  reportHistory: (deviceId: string): Promise<ReportRecord[]> =>
    getJson<ReportRecord[]>(`/devices/${encodeURIComponent(deviceId)}/report-history`),

  // Points directly at document-store's raw output file, served statically
  // by auditor-api - lets the UI's "view raw artefact" link open the exact
  // file the evidence's sha256 was computed from.
  rawArtefactUrl: (rawOutputPath: string): string => `${API_BASE_URL}/${rawOutputPath}`,

  // -- NCA CGIoT-1:2024 compliance module --------------------------------

  ncaSummary: (): Promise<NCASummary> => getJson<NCASummary>("/nca/summary"),
  ncaCoverage: (): Promise<NCACoverage> => getJson<NCACoverage>("/nca/coverage"),
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
  /** 404 (thrown as ApiError) is the expected, common case here - most
   * controls have no guided checklist authored yet. Callers should catch
   * and fall back to the plain assessment dialog, not treat it as an error. */
  ncaControlChecklist: (controlId: string): Promise<NCAChecklist> =>
    getJson<NCAChecklist>(`/nca/controls/${encodeURIComponent(controlId)}/checklist`),
  evaluateNcaChecklist: (
    controlId: string,
    answers: Record<string, unknown>,
  ): Promise<{ control_id: string; suggested_status: NCAStatus | null }> =>
    postJson(`/nca/controls/${encodeURIComponent(controlId)}/checklist/evaluate`, { answers }),
  /** For genuinely new organizational evidence (policy documents, training
   * records, supplier contracts) - see nca_routes.py's own docstring on
   * this endpoint. collected_by/assessment_id are query params on the
   * backend (no Form() annotation there), not multipart fields - the file
   * itself is the only multipart body part. */
  uploadNcaComplianceDocument: async (
    file: File,
    collectedBy: string,
    assessmentId?: string | null,
  ): Promise<NCAComplianceEvidence> => {
    const body = new FormData();
    body.append("file", file);
    const params = new URLSearchParams({ collected_by: collectedBy });
    if (assessmentId) params.set("assessment_id", assessmentId);
    const response = await fetch(`${API_BASE_URL}/nca/evidence/upload?${params.toString()}`, {
      method: "POST",
      body,
    });
    if (!response.ok) {
      throw await apiErrorFrom("/nca/evidence/upload", response);
    }
    return (await response.json()) as NCAComplianceEvidence;
  },
  ncaDevices: (status?: NCAStatus): Promise<NCADeviceComplianceRow[]> =>
    getJson<NCADeviceComplianceRow[]>(`/nca/devices${status ? `?status=${status}` : ""}`),
  ncaDevice: (deviceId: string): Promise<NCADeviceDetail> =>
    getJson<NCADeviceDetail>(`/nca/devices/${encodeURIComponent(deviceId)}`),
  ncaDeviceSuggestions: (deviceId: string): Promise<NCADeviceSuggestions> =>
    getJson<NCADeviceSuggestions>(`/nca/devices/${encodeURIComponent(deviceId)}/suggestions`),
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

  // -- Vulnerability intelligence (IoTGuard Stage 05) ---------------------

  vulnIntelStatus: (): Promise<VulnIntelStatus> => getJson<VulnIntelStatus>("/vuln-intel/status"),
  vulnIntelFleetSummary: (): Promise<VulnFleetSummary> =>
    getJson<VulnFleetSummary>("/vuln-intel/fleet-summary"),
  vulnIntelDevice: (deviceId: string): Promise<VulnDeviceSummary> =>
    getJson<VulnDeviceSummary>(`/vuln-intel/devices/${encodeURIComponent(deviceId)}`),

  // -- Dynamic Risk Assessment (IoTGuard Stage 06) -------------------------

  riskDevices: (): Promise<RiskDevicesResponse> => getJson<RiskDevicesResponse>("/risk/devices"),
  riskDevice: (deviceId: string): Promise<DeviceRiskDetail> =>
    getJson<DeviceRiskDetail>(`/risk/devices/${encodeURIComponent(deviceId)}`),
  riskFleetSummary: (): Promise<RiskFleetSummary> => getJson<RiskFleetSummary>("/risk/fleet-summary"),
};
