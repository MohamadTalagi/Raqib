import type {
  ControlRecord,
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

  constructor(message: string, status: number) {
    super(message);
    this.name = "ApiError";
    this.status = status;
  }
}

async function getJson<T>(path: string): Promise<T> {
  const response = await fetch(`${API_BASE_URL}${path}`);
  if (!response.ok) {
    throw new ApiError(`${path} failed with ${response.status}`, response.status);
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
    throw new ApiError(`${path} failed with ${response.status}`, response.status);
  }
  return (await response.json()) as T;
}

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
};
