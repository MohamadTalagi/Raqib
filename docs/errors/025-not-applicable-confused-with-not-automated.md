# ERR-025 — NOT_APPLICABLE wrongly assigned to a control with no automated collector

- **Date:** 2026-07-22
- **Component:** policy-engine (`policies/engine/policy_engine.py::is_control_applicable`)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (session implementing the Week 1 gap-analysis closure)

## What happened

`NOT_APPLICABLE` support was added to the verdict engine so a control whose
required tests can never apply to a device's registered services (e.g.
SA-IOT-004/MQTT against an HTTP-only device) gets a real verdict instead of
staying silently unassessed. The first live run of `POST /verdicts/recompute`
against the real dev database marked **every single device** `NOT_APPLICABLE`
for `SA-IOT-001` (device identification) — including devices that plainly do
expose an HTTP service SA-IOT-001 should be testable against.

## Exact error / symptom

```
SA-IOT-001 device-insecure NOT_APPLICABLE False
SA-IOT-001 device-partial NOT_APPLICABLE False
SA-IOT-001 device-hardened NOT_APPLICABLE False
SA-IOT-001 mqtt-broker-insecure NOT_APPLICABLE False
SA-IOT-001 mqtt-broker-secure NOT_APPLICABLE False
SA-IOT-001 telnet-sim NOT_APPLICABLE False
```

No exception was raised — this was a silent logic bug, only caught by
manually inspecting the real recompute output rather than trusting the
`created: 18` count alone.

## Root cause

`is_control_applicable()` checks whether any of a control's
`required_evidence[].test_id` values are applicable (via
`policies/catalog/scan_tests.py::is_applicable()`) to any of a device's
registered services. `SA-IOT-001` requires `TEST-DEVICE-ID` — which has
**no entry in `SCAN_CATALOG` at all** (it was never wired into the live Run
Scan automation; it predates that work). `is_applicable()` correctly returns
`False` for any target when the test_id isn't in the catalog, so every
device failed the "is this test applicable to any service" check — which
the code then read as "this control doesn't apply here," when the honest
answer is "nobody has automated this control's evidence collection yet."
Those are different facts, and conflating them wrongly turns "not yet
automated" into a false negative that a real report would consider settled
and NCA CGIoT-1:2024 §2-1-1-mapped compliance would incorrectly treat as
resolved (a device with no visible evidence of device identification would
misleadingly appear compliant-by-exemption rather than simply unassessed).

## The fix

`is_control_applicable()` now short-circuits to `True` (meaning: do **not**
treat the control as inapplicable) whenever any of its required test_ids
isn't in `SCAN_CATALOG` at all:

```python
if any(test_id not in SCAN_CATALOG for test_id in test_ids):
    return True
```

Only once every required test_id genuinely exists in the catalog does the
function fall through to the real applicability-by-service-type check.

## How to prevent it next time

Added `test_is_control_applicable_true_when_the_required_test_has_no_automated_collector`
(`policies/engine/test_policy_engine.py`) and an integration-level regression
(`test_recompute_leaves_a_control_with_no_automated_collector_unassessed`,
`lab/auditor/api/test_verdicts_recompute.py`) asserting SA-IOT-001 stays
unassessed rather than `NOT_APPLICABLE`. The unit tests for
`is_control_applicable()` written *before* this bug was found only ever used
`SA-IOT-004`/`SA-IOT-005` (both of which DO have a real `SCAN_CATALOG`
entry) — the "required test has no collector at all" case was never
exercised until the live end-to-end recompute run against real data. Same
lesson as [ERR-024]: real data caught what hand-picked synthetic fixtures
didn't.

## References

Caught the same way as ERR-024 — inspecting the real `POST
/verdicts/recompute` response against the live dev database, not just
trusting a green unit-test run.
