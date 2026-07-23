# Week 1 Mentor Task — Gap Analysis

**Source:** `Week 1 (4).docx` (mentor task brief, provided 2026-07-22)
**Method:** Every line item below was checked against the actual code, schema, and
test files in this repo (not against changelog narrative alone) — file/function
references are given so each finding can be re-verified directly.

**Legend:** ✅ Done · ⚠️ Partial · ❌ Missing

---

## 1. Complete the assessment workflow

> Select device → create assessment → run collectors → generate structured evidence
> → evaluate policies → store verdicts → display results → export report

⚠️ **Partial.** The end-to-end flow exists and works, but there is no first-class
**Assessment** entity the way the brief describes it (one ID that groups a whole
run of collectors against a device, with its own lifecycle). What exists instead:

- Select device ✅ — `DevicesPage`/`RegisterDeviceForm`.
- Run collectors ✅ — one `scan_jobs` row **per individual test**, launched from
  `RunScanPage.tsx` → `POST /scan-jobs` → polled and executed by
  `lab/auditor/worker/job_runner.py`. There is no parent object that groups "all
  five controls' worth of collectors for device X, run together" into one unit.
- Generate structured evidence ✅ — `parse_observations` functions in
  `policies/catalog/scan_tests.py`, recorded via `POST /scan-jobs/{id}/record`.
- Evaluate policies ✅ — `policies/engine/policy_engine.py`'s `evaluate()`.
- Store verdicts ✅ — `verdicts` table, `POST /verdicts` / `POST /verdicts/recompute`.
- Display results ✅ — `EvidencePage`, `VerdictsPage`, `DeviceDetailPage`.
- Export report ✅ — PDF only (see §9 below for format gap).

All three device profiles (insecure/partial/hardened) are supported ✅.

**Gap:** introduce an `assessments` table/concept that groups a batch of
`scan_jobs` + their resulting verdicts under one ID with its own status, per §2.

## 2. Complete device and assessment management

| Item | Status | Evidence |
|---|---|---|
| Device registration and selection | ✅ | `POST /devices`, `RegisterDeviceForm.tsx` |
| Assessment creation | ⚠️ | Only per-test `scan_jobs` creation exists (`POST /scan-jobs`); no "create one assessment covering N controls" endpoint |
| Assessment status tracking | ⚠️ | `scan_jobs.status` exists but only per single test, not aggregated |
| Assessment history | ✅ (per test) | Device detail page "Scan history" card, `scan_jobs` table |
| Error reporting | ✅ | `scan_jobs.error` column, surfaced in `job_runner.py`'s failure paths |
| Assessment cancellation or timeout handling | ⚠️ | Timeout ✅ (`job_runner.py:30`, `COMMAND_TIMEOUT_SECONDS = 30`, tested in `test_job_runner.py::test_process_job_marks_failed_on_timeout`). **Cancellation ❌** — no `DELETE`/cancel endpoint or UI control for an in-flight job |
| Required assessment statuses | ⚠️ | Actual `scan_jobs` statuses: `pending, running, awaiting_finding, recorded, failed` — does not match the brief's vocabulary (`Queued, Running, Partially completed, Completed, Failed, Cancelled`), and there is no aggregate status across multiple tests |

**Store — brief's required fields vs. what's actually persisted:**

| Field | Status | Notes |
|---|---|---|
| Device ID | ✅ | `scan_jobs.device_id` |
| Assessment ID | ❌ | No such entity exists |
| Start and completion time | ✅ | `scan_jobs.created_at`/`updated_at` |
| Policy version | ❌ | Control YAMLs have no version field; no verdict/evidence row records which control-file revision produced it |
| Collector versions | ✅ | `evidence.tool_version` / `scan_jobs.tool_version`, captured live via each test's `tool_version_command` |
| Assessment status | ⚠️ | Only per-job, not aggregate |
| Errors | ✅ | `scan_jobs.error` |
| Evidence references | ✅ | `scan_jobs.evidence_id` |
| Verdict references | ❌ | Verdicts link back to evidence (`evidence_ids`), not to the job/assessment that produced them |

## 3. Build the automated network collector

| Test | Status | Evidence |
|---|---|---|
| Host reachability | ❌ | No standalone reachability/ping check — implied only by a successful port scan |
| Open TCP ports | ✅ | `TEST-NET-PORTSCAN`, `_parse_nmap_observations` |
| Service identification | ✅ | `nmap -sV`, `services` list in observations |
| HTTP availability | ✅ | Multiple HTTP-targeted tests (`TEST-HTTP-HEADERS`, `TEST-NET-HTTP-INSPECT`, etc.) |
| HTTPS availability | ✅ | Same tests target `service_type=https` devices |
| Telnet exposure | ✅ | `open_ports contains 23` (SA-IOT-003 condition) |
| MQTT exposure | ✅ | `TEST-MQTT-OPEN` |
| MQTT authentication | ✅ | `observations.mqtt_anonymous` |
| MQTT encryption | ✅ | `observations.mqtt_tls` (keyed on `service_type == "mqtts"`) |
| TLS certificate presence | ⚠️ | Implied by `TEST-TLS-CONFIG` running at all; no explicit "is there a cert" boolean |
| TLS certificate validity | ❌ | Only key strength (`weak_cipher`) and protocol version are checked — no expiry/hostname/chain validity check |
| Supported TLS versions | ✅ | `observations.tls_version`, deprecated-version check |

**Collector requirements:**

| Requirement | Status | Evidence |
|---|---|---|
| Target allow-listing | ✅ | `lab/auditor/api/device_validation.py`, re-validated independently in `job_runner.py:resolve_target` |
| Fixed commands | ✅ | Every `build_command` returns an argv list; `subprocess.run(..., shell=False)` implicitly (no `shell=True` anywhere) |
| Apply timeouts | ✅ | `job_runner.py:30`, `COMMAND_TIMEOUT_SECONDS = 30` |
| Capture tool versions | ✅ | `_tool_version()` in `job_runner.py` |
| Preserve stdout and stderr | ⚠️ | Captured but **concatenated** into one `raw_output` string (`job_runner.py:90`) — not preserved as distinguishable separate streams |
| Store raw artefacts | ✅ | `evidence.raw_output_path`, files under `document-store/raw/` |
| Hash raw artefacts (SHA-256) | ✅ | `evidence.sha256` |
| Handle collector failures correctly ("failed collector → Inconclusive, not Fail") | ❌ | A failed job (timeout/exception/invalid target) is marked `scan_jobs.status = 'failed'` with an error message, but **no evidence or verdict is ever created for it** — the control simply stays unassessed rather than getting an explicit `INCONCLUSIVE` verdict. This does satisfy "not automatically Fail," but does not satisfy "produce Inconclusive." |

## 4. Finalise the structured evidence model

Actual `evidence` table columns: `evidence_id, device_id, test_id, tool, tool_version, command, timestamp, finding, observations, raw_output_path, confidence, sha256`.

| Brief's required field | Status | Notes |
|---|---|---|
| Evidence ID | ✅ | `evidence_id` |
| Assessment ID | ❌ | No Assessment entity exists (see §1/§2) |
| Device ID | ✅ | |
| Test ID | ✅ | |
| Source type | ❌ | No field distinguishing e.g. automated/manual/document source |
| Tool | ✅ | |
| Tool version | ✅ | |
| Typed observed value | ⚠️ | `observations` is a JSONB object, free-form per test rather than a single typed value with a fixed schema |
| Timestamp | ✅ | |
| Confidence | ✅ | enum `high`/`medium`/`low` |
| Confidence reason | ❌ | No separate field — only the free-text `finding` |
| Raw artefact path | ✅ | `raw_output_path` |
| Raw artefact hash | ✅ | `sha256` |
| Error state | ❌ | Errors live on `scan_jobs.error`, never carried onto an evidence row (a failed job produces no evidence row at all — see §3) |

## 5. Complete the first five controls

The 5 controls exist (`policies/controls/SA-IOT-001..005.yaml`): device identification,
default credentials, open/unnecessary services, insecure protocols, TLS/certificate
configuration — matching the brief's list ✅.

| Required control capability | Status | Evidence |
|---|---|---|
| Applicability | ✅ | `applicability.device_type` per control |
| Required evidence | ✅ | `required_evidence` list |
| Pass | ✅ | evaluated in `policy_engine.py::evaluate()` |
| Fail | ✅ | same |
| Partial | ⚠️ | field exists in every control's `conditions.partial`, but is `null` in at least `SA-IOT-002.yaml` — not every control actually defines a PARTIAL path |
| Inconclusive | ⚠️ | Only reachable as the loop's **default fallback** when nothing else matches (`policy_engine.py:53`) — the YAML `inconclusive: {when: ...}` condition itself is dead code, since `_condition_matches()` unconditionally returns `False` whenever a condition dict contains a `"when"` key (`policy_engine.py:31-33`). Confidence-gated inconclusive logic described in the YAML is never actually executed. |
| Not Applicable | ❌ | `evaluate()`'s status loop only iterates `("fail", "partial", "pass")` — `NOT_APPLICABLE` is not a reachable outcome anywhere in the engine |
| Severity | ✅ | `severity` field per control |
| Confidence | ⚠️ | Confidence lives on the evidence record, not factored into the verdict logic (see Inconclusive note above) |
| Saudi source mapping | ✅ | `saudi_source: [{framework, reference, clause}]` |
| Remediation | ✅ | `remediation` field |
| Limitations | ❌ | No `limitations` field on any control YAML |

"The policy engine must evaluate structured values, not prose" ✅ — confirmed;
`_condition_matches` only ever compares typed JSON values via `OPS`, never parses text.

## 6. Add evidence conflict handling

❌ **Missing entirely.** No code anywhere in the repo references evidence conflict
detection, resolution, or preference rules (`grep -r "conflict"` across all `.py`
files returns only unrelated SQL `ON CONFLICT` clauses in seed scripts). There is no
mechanism to record two contradictory evidence items for the same control, prefer
direct technical observation over documentation, flag the conflict, or explain the
resulting verdict.

## 7. Complete storage

| Item | Status | Evidence |
|---|---|---|
| PostgreSQL | ✅ | `lab/auditor/db/init.sql`, used throughout |
| Devices | ✅ | `devices`/`device_services` tables |
| Assessments | ❌ | No such table |
| Collector runs | ⚠️ | `scan_jobs` covers this for single tests, no batch/assessment grouping |
| Evidence metadata | ✅ | `evidence` table |
| Verdicts | ✅ | `verdicts` table |
| Policy versions | ❌ | Not tracked anywhere (see §2) |
| Report records | ❌ | Reports are generated on demand (`GET /devices/{id}/report.pdf`) and never persisted as their own row/record |
| Audit events | ✅ (NCA module only) | `compliance_audit_events` table exists for the new NCA compliance module (§8 below), but the original `SA-IOT-*` verdict pipeline has no audit trail — a verdict/evidence row is immutable but nothing records *who* triggered a recompute or *when* |
| Manual evidence decisions | ⚠️ | A human types the `finding`+`confidence` when recording evidence (`POST /scan-jobs/{id}/record`), but there's no separate "manual override decision" record distinct from an automated one |

"The system must retain previous assessments after restart" ✅ by construction —
Postgres data is on a named Docker volume (`auditor-db-data`) — but there is **no
dedicated test proving this** (see §10).

## 8. Complete the web interface

| Requirement | Status | Evidence |
|---|---|---|
| Select or register a device | ✅ | `DevicesPage`, `RegisterDeviceForm` |
| Start an assessment | ✅ (per test, not batched) | `RunScanPage` |
| View progress | ✅ | `ScanJobCard` polls `scan_jobs.status` |
| View collector errors | ✅ | `ScanJobCard` surfaces `error` |
| View verdicts | ✅ | `VerdictsPage`, `DeviceDetailPage` |
| View severity and confidence | ✅ | `SeverityBadge`, `ConfidenceLabel` |
| View Saudi source mapping | ✅ | `ControlDetailPage` |
| View evidence provenance | ✅ | Evidence card shows tool/command/hash |
| Open raw artefact references | ⚠️ | `raw_output_path` is displayed as text but there is no link/download control to actually open the referenced file from the UI |
| View remediation | ✅ | `ControlDetailPage`, PDF report |
| Export the report | ✅ (PDF only) | `api.deviceReportUrl()` |

Note: this session also shipped an entire separate **NCA CGIoT-1:2024 Alignment**
dashboard (device compliance table, domain breakdown, org compliance, control
detail, audit trail) — beyond what Week 1 asked for, but built on a **different**
data model (`compliance_*` tables) than the one this brief describes, so it doesn't
close the gaps listed above.

## 9. Generate reports

| Format | Status |
|---|---|
| HTML report | ❌ Not implemented — only PDF (`report.py` → WeasyPrint) and the NCA module's PDF/CSV/JSON exports exist. No `/report.html` route anywhere. |
| JSON report | ❌ Not implemented for the `SA-IOT-*` device assessment report. (The NCA module has `GET /nca/reports/controls.json`, but that's a controls catalog export, not a per-device assessment report.) |

**Required report contents**, checked against the existing PDF (`report.py` /
`templates/device_report.html`):

| Content | Status |
|---|---|
| Device profile | ✅ |
| Assessment scope | ⚠️ services list shown; no explicit "scope statement" |
| Assessment methodology | ❌ Not described anywhere in the report |
| Policy version | ❌ Not tracked (see §2) |
| Tool versions | ✅ (in the evidence provenance table) |
| Control results | ✅ |
| Evidence references | ✅ |
| Confidence | ✅ (evidence table) |
| Severity | ✅ |
| Saudi mapping | ✅ |
| Conflicting evidence | ❌ (feature doesn't exist — see §6) |
| Controls not assessed | ❌ Not explicitly listed; only controls that have a verdict appear at all |
| Remediation | ✅ |
| Limitations | ❌ |
| Disclaimer ("not official certification") | ✅ for the NCA module (`policies/nca/compliance_text.py`) — ❌ for the original per-device PDF report, which has no such disclaimer text |

## 10. Test the complete system

| Requirement | Status | Evidence |
|---|---|---|
| Four tests per control (pass/fail/inconclusive/contradictory) | ❌ | Only `SA-IOT-003` has a dedicated real-control regression test (`test_policy_engine.py::test_sa_iot_003_real_control_reproduces_historical_verdicts_via_open_ports`); no systematic 4-case matrix across all 5 controls, and **no contradictory-evidence case exists anywhere** (§6) |
| Parser tests for all three device profiles | ✅ | `policies/catalog/test_scan_tests.py` (65 tests) exercises the parsers extensively |
| API workflow tests | ✅ | `lab/auditor/api/test_*.py` (~140 tests across devices/evidence/verdicts/scan-jobs/controls) |
| Database persistence test | ❌ | No test that writes data, restarts/reconnects, and asserts it survived |
| Collector timeout test | ✅ | `test_job_runner.py::test_process_job_marks_failed_on_timeout` |
| Malformed evidence test | ✅ | `test_evidence.py::test_post_evidence_rejects_invalid_payload` |
| Command-injection prevention test | ✅ | `test_device_validation.py::test_argv_injection_rejected` |
| One complete assessment test per device profile | ⚠️ | Individual scan-job/evidence/verdict flows are tested per test type, but no single test drives "register device X → run all 5 controls → get 5 verdicts" end-to-end per profile |
| Clean deployment smoke test | ❌ | No automated test brings up the full Docker Compose stack from nothing and asserts it's healthy (this has only ever been done manually, per CLAUDE.md's changelog) |

---

## "By the end of Week 1" checklist

| Deliverable | Status |
|---|---|
| A working end-to-end auditor | ✅ (per-test workflow, not a unified "Assessment") |
| Three assessable Docker device profiles | ✅ |
| Five working controls | ✅ (with the Inconclusive/Not-Applicable/Limitations gaps noted in §5) |
| Automated network evidence collection | ✅ (with the reachability/cert-validity gaps noted in §3) |
| Structured evidence storage | ⚠️ (missing Assessment ID, source type, confidence reason, error state — §4) |
| Persistent database | ✅ (no explicit restart test — §10) |
| Functional web interface | ✅ |
| HTML and JSON reporting | ❌ (PDF only — §9) |
| Automated tests | ⚠️ (strong coverage on parsers/API/validation; weak on the specific per-control and system-level cases §10 lists) |
| Updated architecture diagram | ✅ (`docs/architecture/architecture-diagram.md`/`.png`, from Day 1 — not verified as updated for everything built since) |
| Updated README | ⚠️ (`lab/README.md` is accurate for Docker bring-up but documents none of the application features built since Day 1) |
| Known limitations register | ❌ (limitations are scattered across CLAUDE.md changelog prose and `docs/nca-compliance.md`; no single consolidated register) |

## Week 1 completion demonstration checklist

| Demonstration step | Can it be shown today? |
|---|---|
| Start the full platform on a clean deployment | ✅ `docker compose up -d` |
| Assess the insecure device | ✅ via Run Scan, one test at a time |
| Show collected evidence | ✅ Evidence page |
| Show five verdicts | ✅ Verdicts page (once all 5 controls' tests are run + recorded + recomputed) |
| Trace one verdict back to its policy rule and raw artefact | ✅ Control detail page + evidence provenance |
| Export the report | ✅ PDF only, not HTML/JSON |
| Repeat the assessment for the hardened device | ✅ |
| Explain the different results | ✅ |
| Show handling of one collector failure | ⚠️ can show a job going to `status=failed` with an error message, but **not** an INCONCLUSIVE verdict resulting from it, since none is ever generated |
| Show passing tests | ✅ |

---

## Summary — what's most worth prioritizing next

1. **Introduce a real `assessments` entity** grouping a batch of `scan_jobs` under
   one ID with an aggregate status, and add `assessment_id` to `evidence`/`verdicts`.
2. **Make a failed collector produce an INCONCLUSIVE verdict**, not silence — this
   is explicitly called out twice in the brief (§3 and the demo checklist) and is
   currently the single clearest functional gap.
3. **Evidence conflict handling** (§6) — entirely unbuilt.
4. **NOT_APPLICABLE as a real verdict outcome**, and make the `partial`/`inconclusive`
   YAML conditions actually reachable (the `"when"` key currently short-circuits to
   `False` unconditionally in `policy_engine.py`).
5. **HTML + JSON report formats**, plus policy-version tracking so a report can state
   which control revision produced each verdict.
6. **Assessment cancellation**, and a consolidated known-limitations register.
