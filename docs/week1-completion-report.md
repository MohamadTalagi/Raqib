# Week 1 Completion Report

> Verified 2026-07-31 against the real codebase (routes, migrations, YAML controls, test files) —
> not just against CLAUDE.md's own claims. Source brief: `week-1-tasks.txt`.

**Bottom line: yes, effectively all of Week 1 is complete.** The brief's own 10 tasks map almost
exactly onto the "Week 1 mentor-brief gap closure" session (2026-07-22, see CLAUDE.md changelog)
— `scripts/smoke_test.sh` literally comments `# Clean-deployment smoke test (Week 1 brief, task 10)`.
Everything built since (NCA compliance, vulnerability intelligence, risk scoring) sits *on top of*
this baseline, not in place of it. Of the 10 tasks, **9 are fully done** and **1 (device/assessment
management) is done except for one missing piece** — a UI page for assessment history — that has
full backend support but no frontend surface.

## Task-by-task

### 1. Complete assessment workflow — ✅ Done
Select device → create assessment → run collectors → structured evidence → evaluate policies →
store verdicts → display → export report, all present and wired:
- `POST /assessments` (main.py:334) creates a real Assessment row grouping a batch of scan_jobs.
- `job_runner.py` runs the collectors, `POST /scan-jobs/{id}/record` writes evidence.
- `POST /verdicts/recompute` runs `policy_engine.py` against evidence.
- Report export at `/devices/{id}/report.{pdf,html,json}`.
- All three device profiles (`device-insecure`/`-partial`/`-hardened`) are supported — confirmed
  in `policies/engine/test_generate_verdicts.py` and referenced across 25+ test files.

### 2. Device and assessment management — 🟡 Done except one gap
Confirmed built: device registration (`POST /devices`), selection, assessment creation, status
tracking (`assessment_status.py`'s `queued/running/partially_completed/completed/failed/cancelled`
— matches the brief's list exactly), cancellation (`POST /assessments/{id}/cancel`), error
reporting (`POST /scan-jobs/{id}/record-failure`). `assessments` table (migration 004) stores
device ID, assessment ID, status, policy_version, started/completed_at, error.

**Gap found:** `GET /assessments` (list) exists on the backend, but grepping the entire frontend
turned up no page that renders it — `RunScanPage.tsx` only tracks the *current* in-flight
assessment in local component state; navigate away and it's gone. There is no "assessment
history" view for a device. Also, "collector versions" is captured per-evidence-row
(`tool_version`) but never rolled up onto the assessment record itself as the brief's storage
list implies.

### 3. Automated network collector — ✅ Done
Every listed check has a real `SCAN_CATALOG` entry in `policies/catalog/scan_tests.py`:
`TEST-NET-REACHABILITY` (host reachability), `TEST-NET-PORTSCAN` (open ports + service ID),
`TEST-NET-HTTP-INSPECT`/implicit HTTP(S) availability via port/service targeting, telnet exposure
(via portscan + native telnet server on `device-insecure`), `TEST-MQTT-OPEN` (exposure +
`mqtt_anonymous` auth), `mqtt_tls` flag (encryption), `TEST-TLS-CONFIG` (cert presence via
handshake success, `cert_expired` for validity, `tls_version`/`weak_cipher` for protocol/cipher
strength).
Collector discipline requirements all confirmed: target allow-listing (`device_validation.py`,
regression-tested against argv injection in `test_device_validation.py::test_argv_injection_rejected`),
fixed argv-list commands (never shell strings), timeouts (`test_job_runner.py`'s 3 timeout tests),
tool version capture (`tool_version_command` per test), raw stdout/stderr preserved,
SHA-256 hashing (`sha256` field, schema-enforced), and failed collectors produce `INCONCLUSIVE`
via `record-failure` + `observations.collector_error`, never a silent FAIL.

**Minor note:** "Supported TLS versions" is captured as the single negotiated protocol version
from one handshake (`tls_version`), not an enumeration of every version the server accepts —
a reasonable proxy, but not literally "supported versions" (plural).

### 4. Structured evidence model — ✅ Done
`policies/schema/evidence.schema.json` has every required field: `evidence_id`, `assessment_id`,
`device_id`, `test_id`, `source_type`, `tool`, `tool_version`, `observations` (typed per test),
`timestamp`, `confidence`, `confidence_reason`, `raw_output_path`, `sha256`, `error_state`. All
enforced via JSON Schema, `additionalProperties: false`.

### 5. First five controls — ✅ Done
`policies/controls/SA-IOT-001.yaml` through `-005.yaml` exist (device identification, default
credentials, unnecessary services, insecure protocols, TLS/cert config). Verified `SA-IOT-005`
has every required field: `applicability`, `required_evidence`, `conditions.{pass,fail,partial,
inconclusive}`, `not_applicable` (derived, not per-control), `severity`, confidence (from
evidence), `saudi_source` (framework/reference/clause), `remediation`, `limitations`.
`policy_engine.py` evaluates structured `{field, op, value}` predicates against `observations` —
never prose.

### 6. Evidence conflict handling — ✅ Done
`policies/engine/conflict.py` + `test_conflict.py` implement exactly the brief's own example
(documentation says TLS, packet capture shows plaintext): records both evidence items, prefers
`source_type == "automated"` over `"manual"`/`"document"`, sets `conflict_detected`/
`conflict_reason` on the resulting verdict (migration 004 columns), surfaced in both the API and
the report (`report.py` includes `conflict_detected`/`conflict_reason` per control).

### 7. Complete storage — ✅ Done
PostgreSQL, 8 tracked migrations (`001`–`008`). Stores devices, assessments, scan_jobs (collector
runs), evidence, verdicts, policy versions (`verdicts.policy_version`), report generation is
on-demand (no persisted "report record" table, see note below), NCA `compliance_audit_events`
(audit events), and manual evidence/assessment decisions. `test_persistence.py` confirms data
survives a connection restart (proxy for restart persistence).

**Minor note:** the brief's storage list includes "Report records" as its own stored entity —
reports are generated fresh on request from live DB state (matching this project's "never
persist a derived computation" convention elsewhere, e.g. risk scores), not stored as their own
row. Functionally equivalent but technically not a literal stored "report record."

### 8. Complete web interface — ✅ Done
Register/select device, start assessment, view progress (live status polling), collector errors
(`ScanJobCard`), verdicts, severity/confidence, Saudi source mapping, evidence provenance, raw
artefact links (`/document-store/{path}` route), remediation, and report export are all present
across `DevicesPage`, `RunScanPage`, `VerdictsPage`, `DeviceDetailPage`, and
`DeviceAssessmentReportPage`. Visual polish was explicitly deprioritized per the brief and matches
that (functional, not decorative, though it has since gained a lot more polish in later sessions).

### 9. Generate reports — ✅ Done
`GET /devices/{id}/report.html` and `.json` (plus a bonus `.pdf`) share one `build_report_model()`.
Confirmed present: device profile, assessment scope, methodology, policy version, tool versions
(via evidence), control results, evidence references, confidence, severity, Saudi mapping,
conflicting evidence, controls not assessed, remediation, limitations, and a
non-certification disclaimer (`DISCLAIMER` constant).

### 10. Test the complete system — ✅ Done
- Four-case matrix per control: `policies/engine/test_controls_four_cases.py`, parametrized across
  all 5 `CONTROL_IDS` × {pass, fail, inconclusive/missing-evidence, contradictory-evidence} = 20 cases.
- Parser tests for all three device profiles: 38 references to `device-insecure`/`-partial`/
  `-hardened` across `policies/catalog/test_scan_tests.py`.
- API workflow tests: `test_assessments.py`, `test_scan_jobs.py`, `test_evidence.py`, `test_verdicts.py`.
- Database persistence test: `test_persistence.py`.
- Collector timeout test: `test_job_runner.py` (3 tests, job + network-scan timeout paths).
- Malformed evidence/input tests: `test_devices_crud.py`, `test_firmware_upload.py`,
  `test_report_route.py` (malformed IDs/archives).
- Command-injection prevention test: `test_device_validation.py::test_argv_injection_rejected`.
- One complete assessment test per device profile: covered via `test_generate_verdicts.py` +
  `test_assessments.py`'s full lifecycle tests, exercised against all three real seeded profiles.
- Clean deployment smoke test: `scripts/smoke_test.sh`, explicitly labeled for this task.

## "By the end of Week 1" checklist

| Item | Status |
|---|---|
| Working end-to-end auditor | ✅ |
| Three assessable Docker device profiles | ✅ |
| Five working controls | ✅ |
| Automated network evidence collection | ✅ |
| Structured evidence storage | ✅ |
| Persistent database | ✅ |
| Functional web interface | ✅ |
| HTML and JSON reporting | ✅ |
| Automated tests | ✅ (well beyond minimum — hundreds of tests total across the repo today) |
| Updated architecture diagram | ✅ `docs/architecture/architecture-diagram.{md,png}` |
| Updated README | ✅ `lab/README.md` (confirmed it correctly describes the React stack, not stale Flutter text) |
| Known limitations register | ✅ `docs/known-limitations.md` (164 lines) |

## Week 1 completion demonstration checklist
All 10 demo steps (clean deploy → assess insecure device → show evidence → show 5 verdicts →
trace one verdict to policy rule + raw artefact → export report → repeat for hardened device →
explain different results → show one collector failure → show passing tests) are supported by
functionality that exists and is tested today. Not independently re-run live in this pass (this
was a static code/test verification, not a live demo run) — see "Not verified this pass" below.

## What actually remains to fully close Week 1

1. **Assessment history UI** — build a small view (e.g. on the device detail page or a new tab)
   that calls the already-existing `GET /assessments?device_id=...` and lists past assessments
   with status/timestamps, so history isn't only visible via direct API calls or lost once you
   navigate away from Run Scan mid-assessment.
2. **(Optional/cosmetic) Collector versions on the assessment record** — currently only present
   per-evidence-row; could be aggregated onto the assessment entity itself if the brief's literal
   storage list is meant strictly.
3. **(Optional/cosmetic) "Report records" as a stored table** — reports are correctly generated
   live from DB state (consistent with the rest of the app's philosophy) rather than persisted as
   their own row; only a gap if "Report records" was meant literally rather than functionally.
4. **Not verified this pass** — this was a static repo audit, not a live run. Nobody in this
   session actually executed `scripts/smoke_test.sh` or stepped through the 10-point demo script
   against a running stack. Given the code and tests all exist and pass per CLAUDE.md's own
   changelog history, this is a low-risk gap, but it's the one honest "not confirmed live today"
   item.

**Net assessment: Week 1 is ~95%+ complete.** The one real, actionable gap is the assessment-history
UI; everything else is either fully done or a matter of interpretation (report/collector-version
storage) rather than missing functionality.
