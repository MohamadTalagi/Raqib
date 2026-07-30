import type { ControlRecord, ScanTestSpec } from "@/lib/types";

/**
 * The controls that can actually be assessed from a scan: at least one of
 * their required/automated tests has a real collector in the scan catalog.
 *
 * A control whose only required test has no collector (e.g. SA-IOT-001's
 * TEST-DEVICE-ID, which has no SCAN_CATALOG entry) is manual-assessment-only -
 * there is no scan that can ever produce evidence for it, so offering it in a
 * "assess from evidence" picker only leads to a dead-end error. Those are
 * filtered out here.
 *
 * If the catalog isn't available yet (`tests` empty), returns the controls
 * unchanged rather than hiding everything - a missing catalog should degrade
 * to the previous behaviour, not an empty picker.
 */
export function scanAssessableControls(controls: ControlRecord[], tests: ScanTestSpec[]): ControlRecord[] {
  if (tests.length === 0) return controls;
  const catalog = new Set(tests.map((t) => t.test_id));
  return controls.filter((control) => {
    const testIds = [...control.automated_test_ids, ...control.required_evidence.map((r) => r.test_id)];
    return testIds.some((id) => catalog.has(id));
  });
}
