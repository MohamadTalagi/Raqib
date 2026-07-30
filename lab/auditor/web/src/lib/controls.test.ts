import { describe, expect, it } from "vitest";
import { scanAssessableControls } from "./controls";
import type { ControlRecord, ScanTestSpec } from "@/lib/types";

function control(id: string, testIds: string[]): ControlRecord {
  return {
    control_id: id,
    title: id,
    saudi_source: [],
    applicability: { device_type: [] },
    required_evidence: testIds.map((t) => ({ test_id: t })),
    automated_test_ids: testIds,
    severity: "high",
    conditions: {},
    remediation: "",
  };
}

function test(id: string): ScanTestSpec {
  return { test_id: id, label: id, category: "network-and-protocol", applicable_service_types: [] };
}

const CATALOG = [test("TEST-NET-PORTSCAN"), test("TEST-AUTH-DEFAULT-CREDS")];

describe("scanAssessableControls", () => {
  it("excludes controls whose only test has no collector in the catalog", () => {
    const controls = [
      control("SA-IOT-003", ["TEST-NET-PORTSCAN"]),
      control("SA-IOT-001", ["TEST-DEVICE-ID"]), // no catalog entry -> manual only
    ];
    const result = scanAssessableControls(controls, CATALOG).map((c) => c.control_id);
    expect(result).toEqual(["SA-IOT-003"]);
  });

  it("keeps a control if any of its tests has a collector", () => {
    const controls = [control("SA-IOT-X", ["TEST-DEVICE-ID", "TEST-AUTH-DEFAULT-CREDS"])];
    expect(scanAssessableControls(controls, CATALOG)).toHaveLength(1);
  });

  it("returns all controls unchanged when the catalog is empty (not-yet-loaded)", () => {
    const controls = [control("SA-IOT-001", ["TEST-DEVICE-ID"])];
    expect(scanAssessableControls(controls, [])).toEqual(controls);
  });
});
