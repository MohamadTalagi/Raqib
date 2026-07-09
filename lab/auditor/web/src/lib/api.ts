import type {
  ControlRecord,
  DeviceSummary,
  EvidenceRecord,
  Summary,
  VerdictRecord,
} from "./types";

const API_BASE_URL: string =
  (import.meta.env.VITE_API_URL as string | undefined) ?? "http://localhost:8000";

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

export const api = {
  summary: (): Promise<Summary> => getJson<Summary>("/summary"),
  devices: (): Promise<DeviceSummary[]> => getJson<DeviceSummary[]>("/devices"),
  evidence: (): Promise<EvidenceRecord[]> => getJson<EvidenceRecord[]>("/evidence"),
  verdicts: (): Promise<VerdictRecord[]> => getJson<VerdictRecord[]>("/verdicts"),
  controls: (): Promise<ControlRecord[]> => getJson<ControlRecord[]>("/controls"),
};
