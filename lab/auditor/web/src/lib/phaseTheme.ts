/**
 * Splits the guided pipeline into 4 color-coded groups — a KAUSTify color
 * scheme design choice (see index.css's `:root[data-color-scheme="kaustify"]`
 * block), not a permanent restructuring of the app. Under the Default color
 * scheme, every group resolves to the same single brand accent (today's
 * look, unchanged); under KAUSTify, each group gets one of KAUST's own 4
 * brand colors. Grouped by pipeline phase, not by sidebar position:
 * Discovery (finding/registering/identifying devices), Compliance (SA-IOT +
 * NCA), Intelligence (vulnerability/risk/PQC signal), Solution (acting on
 * findings). Keyed by route path rather than lib/pipeline.ts's
 * `PipelinePhaseId` since that type only covers the 6 phases with a
 * per-device status badge — this covers all 10 pipeline nav pages,
 * including Discovery, Remediation, PQC Readiness, and Executive Summary,
 * which have no per-device status of their own.
 */
export type PipelinePhaseGroup = "discovery" | "compliance" | "intelligence" | "solution";

export const PHASE_GROUP_LABEL: Record<PipelinePhaseGroup, string> = {
  discovery: "Discovery",
  compliance: "Compliance",
  intelligence: "Intelligence",
  solution: "Solution",
};

/** CSS var() reference for each group — resolves to the KAUSTify hex under
 * that color scheme, or the single brand color under Default. */
export const PHASE_GROUP_VAR: Record<PipelinePhaseGroup, string> = {
  discovery: "var(--color-phase-discovery)",
  compliance: "var(--color-phase-compliance)",
  intelligence: "var(--color-phase-intelligence)",
  solution: "var(--color-phase-solution)",
};

/** Keyed by the exact route path each pipeline page registers in App.tsx/
 * Sidebar.tsx's NAV_GROUPS. */
export const PIPELINE_ROUTE_PHASE_GROUP: Record<string, PipelinePhaseGroup> = {
  "/discovery": "discovery",
  "/devices": "discovery",
  "/fingerprinting": "discovery",
  "/nca-compliance": "compliance",
  "/vulnerability-intelligence": "intelligence",
  "/risk": "intelligence",
  "/pqc-readiness": "intelligence",
  "/remediation": "solution",
  "/executive-summary": "solution",
};
