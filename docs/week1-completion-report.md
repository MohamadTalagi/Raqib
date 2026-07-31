# Week 1 Completion Report

> Verified 2026-07-31 against the real codebase (routes, migrations, YAML controls, test files) —
> not just against CLAUDE.md's own claims. Source brief: `week-1-tasks.txt`.
>
> **Update, same day:** all 4 gaps this report originally found ("What actually remains" below)
> have since been closed, planned and implemented gap-by-gap with a commit per gap. See CLAUDE.md
> §0's "All 4 remaining Week 1 gaps closed" entry for the full breakdown and live-verification
> detail. The "What actually remains" section below is kept as the historical record of what this
> audit originally found, with each item's resolution noted inline.

**Bottom line: yes, all of Week 1 is complete.** The brief's own 10 tasks map almost
exactly onto the "Week 1 mentor-brief gap closure" session (2026-07-22, see CLAUDE.md changelog)
— `scripts/smoke_test.sh` literally comments `# Clean-deployment smoke test (Week 1 brief, task 10)`.
Everything built since (NCA compliance, vulnerability intelligence, risk scoring) sits *on top of*
this baseline, not in place of it. All 10 tasks are now fully done — the 4 narrow gaps this audit
originally found (assessment history UI, TLS version enumeration, collector versions, and
confidence_reason/report_records) were all closed the same day; see the update note above.

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

### 2. Device and assessment management — ✅ Done
Confirmed built: device registration (`POST /devices`), selection, assessment creation, status
tracking (`assessment_status.py`'s `queued/running/partially_completed/completed/failed/cancelled`
— matches the brief's list exactly), cancellation (`POST /assessments/{id}/cancel`), error
reporting (`POST /scan-jobs/{id}/record-failure`). `assessments` table (migration 004) stores
device ID, assessment ID, status, policy_version, started/completed_at, error.

**Originally found, closed same day:** `GET /assessments` (list) existed on the backend, but
nothing in the frontend rendered it — `RunScanPage.tsx` only tracked the *current* in-flight
assessment in local component state, lost on navigation. New "Assessment history" card on
`DeviceDetailPage` closes this. "Collector versions" — originally only per-evidence-row — is now
also derived live and returned on the assessment record itself (`_collector_versions_for_assessment()`).

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

**Closed same day:** "Supported TLS versions" was originally captured as only the single negotiated
protocol version from one handshake. `tls_cert_check.py` now forces a handshake at each of
TLSv1/1.1/1.2/1.3 and reports a real per-version `accepted`/`rejected`/`untestable` result
(`observations.protocol_probe`/`supported_tls_versions`), confirmed live against a real HTTPS device.

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
PostgreSQL, 9 tracked migrations (`001`–`009`). Stores devices, assessments, scan_jobs (collector
runs), evidence, verdicts, policy versions (`verdicts.policy_version`), report generation events
(`report_records`, added same day — an audit trail, not a content snapshot), NCA `compliance_audit_events`
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
- One complete assessment test per device profile: `test_generate_verdicts.py` — originally only
  `device-insecure`/`device-hardened` had a dedicated full evidence-to-verdict test; a later,
  more precise pass (the published report artifact) caught that `device-partial` didn't, closed
  same day with `test_generate_verdicts_produces_a_mixed_result_for_device_partial` (a real
  3-PASS/2-FAIL mix against the real controls).
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

## What actually remains to fully close Week 1 — all closed same day

1. **Assessment history UI** — ✅ **Closed.** New "Assessment history" card on `DeviceDetailPage`
   calling `GET /assessments?device_id=...`, expanding in place to its collector jobs.
2. **Collector versions on the assessment record** — ✅ **Closed.** Derived live from the
   assessment's child `scan_jobs` (`_collector_versions_for_assessment()`), not a new stored
   column — matches this codebase's existing rule for every other rollup.
3. **"Report records" as a stored table** — ✅ **Closed.** New `report_records` table (migration
   009), an append-only generation-event log analogous to `compliance_audit_events`, plus
   `GET /devices/{id}/report-history`. Report *content* is still always computed live, by design.
4. **Not verified live in the original pass** — ✅ Closed differently than expected: rather than
   running the static 10-point demo script, this session's actual live verification work (rebuilding/
   redeploying all 3 images, running real assessments through the real worker, hitting real
   endpoints) directly exercised the equivalent real workflow multiple times over, for both the
   assessment-history feature and all 4 gap-closure changes.

Two further narrow items were found and closed *while implementing the above*, not in the original
audit: `TEST-TLS-CONFIG`'s "Supported TLS versions" now genuinely enumerates per-version support
(3-state accepted/rejected/untestable, never conflated) instead of reporting only the one
default-negotiated protocol; and `confidence_reason` now auto-fills on both automated
evidence-recording paths instead of staying null.

**Net assessment: Week 1 is now fully complete against every task and sub-requirement this audit
checked.** See CLAUDE.md §0 for the complete gap-by-gap breakdown and live-verification detail.
