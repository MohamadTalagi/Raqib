# NCA CGIoT-1:2024 Compliance Module

## Alignment, not certification

> This module reflects an assessment of **alignment** with NCA CGIoT-1:2024 guidance.
> It is **not an NCA certification**, and CGIoT-1:2024 is guidance rather than a
> certifiable standard: a device or network scan alone cannot establish organizational
> compliance, since governance controls such as policy approval, personnel training,
> independent audits, and supplier or cloud contract compliance are not observable from
> a scan and are tracked here as separate manual assessments. Industrial IoT deployments
> may require a separate OTCC assessment. Cryptographic controls and cloud-hosted
> components may require additional mapping against the NCS and CCC control sets, which
> this module does not perform.

This exact text is defined once, in `policies/nca/compliance_text.py`, and is repeated
verbatim by every surface that shows compliance results: the `/nca/summary` API
response, every CSV/JSON/PDF export, and the "NCA Compliance" dashboard page. The
product is labelled **"NCA CGIoT-1:2024 Alignment"** everywhere — never "NCA certified."

## Feature overview

This module is a parallel, richer system that sits alongside the project's original
5-control `SA-IOT-*` policy-as-code pilot (`policies/controls/*.yaml`,
`policies/engine/policy_engine.py`, the `evidence`/`verdicts` tables, `ControlsPage`,
`VerdictsPage`) — that pilot, and the Run Scan job-queue feature built on top of it, are
**untouched**. The NCA module instead covers the real, versioned, 81-guideline
CGIoT-1:2024 catalog (4 domains, 27 subdomains) with a proper compliance data model:
device-scope and organization-scope assessments, evidence with retention/expiry,
exceptions with mandatory expiry, and an append-only audit trail.

## Data model

Six new tables (`lab/auditor/db/init.sql` for fresh installs,
`lab/auditor/db/migrations/003-nca-compliance.sql` for existing volumes — same
idempotent-migration pattern as `002-devices-firmware-columns.sql`):

- **`compliance_controls`** — the 81-guideline catalog. `id` is
  `NCA-CGIoT-1_2024-<guideline_id>` (see `policies/nca/build_catalog.control_id()`).
  `scope_type`/`assessment_type`/`required`/`severity` are **IoTGuard's own
  methodology**, authored in `policies/nca/build_catalog.py`'s classification tables —
  never presented as NCA's own classification, and documented as such in that file's
  docstring.
- **`compliance_finding_mappings`** — the configurable evidence→control mapping table
  (see "Finding-to-control mapping" below).
- **`compliance_assessments`** — append-only. Re-assessing a control **never**
  `UPDATE`s the prior row; it inserts a new row and sets the old row's
  `superseded_by` to the new row's id, with a `compliance_audit_events` row recording
  the before/after/actor/reason. The original result is preserved forever.
- **`compliance_evidence`** — for automated findings, `linked_evidence_id` points at
  the **existing** `evidence` table (no re-hashing, no duplication). Only genuinely new
  organizational evidence (policy documents, training records, supplier contracts) gets
  its own file under `document-store/compliance/`, referenced by path + SHA-256 — same
  convention as the existing firmware upload.
- **`compliance_exceptions`** — `expires_at` is `NOT NULL`: every exception must have an
  expiry, no exceptions (pun intended).
- **`compliance_audit_events`** — generic before/after/actor/reason log, keyed by
  entity_type + entity_id.
- **`compliance_control_checklists`** (migration `011`) — one row per guideline
  with an authored guided checklist: `questions` (ordered JSONB) and
  `suggestion_rule` (JSONB, evaluated by `policies/nca/checklists.py`). See
  "Guided checklists" below.
- **`compliance_assessments.attested_role` / `attestation_confirmed` /
  `attestation_statement`** (migrations `011`/`012`) — the formal sign-off
  required on every real verdict; see "Formal sign-off" below.

## Migration instructions

Fresh install: `init.sql` already includes the NCA tables. Existing volume:

```
docker exec kaust-iot-lab-auditor-database-1 psql -U auditor -d auditor \
  -f /path/to/lab/auditor/db/migrations/003-nca-compliance.sql
```

An existing volume also needs migrations `011-nca-checklists-and-attestation.sql`,
`012-nca-attestation-not-required-for-not-tested.sql`, and
`013-automated-runs.sql` (the `automated_runs` table + `compliance_assessments.auto_recorded`)
applied the same way.

Then seed the catalog, finding mappings, and checklists (idempotent, safe to re-run):

```
python -m policies.nca.build_catalog        # regenerates catalog_1_2024.json (only needed after editing the source markdown)
python -m policies.nca.seed_catalog         # upserts the 81 guidelines into compliance_controls
python -m policies.nca.seed_finding_mappings  # upserts the ~28 evidence→control mappings
python -m policies.nca.seed_checklists      # upserts the 60 guided checklists
```

All scripts read `DATABASE_URL` from the environment, matching every other
`seed_*.py` script's convention. **Note**: `nca_routes.py` itself (unlike
`policies/`, which is bind-mounted) is baked into the `auditor-api` image at
build time — after editing it, `docker compose build auditor-api` is required,
not just a container restart (see "Known limitations").

## Status-calculation rules — one centralized evaluator

**`policies/nca/evaluator.py`** is the *only* place status/score/domain-counts are
computed. The API (`lab/auditor/api/nca_routes.py`) assembles rows and calls these pure
functions; the frontend only ever renders the numbers/strings they return. Do not
duplicate this logic anywhere else.

- **`effective_status(row)`** — a `pass` whose linked evidence has expired rolls down
  to `partial`. FAIL/PARTIAL/NOT_TESTED are never changed by evidence expiry.
- **`is_effectively_applicable(row)`** — `not_applicable` controls and controls with an
  approved, unexpired exception are both excluded from the denominator.
- **`device_overall_status(rows)`** — exact precedence: **FAIL** if any applicable
  required control fails; else **PARTIAL** if any is partial/not_tested/expired-evidence
  (but not *every* control is not_tested); else **PASS** only if every applicable
  required control passes with current evidence; a device where **every** applicable
  required control is still `not_tested` (nothing has ever been assessed) reads as its
  own **NOT_TESTED** ("Not Assessed") outcome rather than PARTIAL.
- **`device_score(rows)`** — `passed / total * 100` over applicable+required controls,
  rounded. `None` (never 0%) when the denominator is empty or nothing has been assessed
  yet. **Purely informational — never overrides the strict status.**
- **`domain_summary(rows)`** — PASS/PARTIAL/FAIL/NOT_TESTED counts across all
  effectively-applicable controls (required and optional), grouped into the 4 domain
  buckets (Governance/Defense/Resilience/Third-Party & Cloud).

All of this is exhaustively unit tested in `policies/nca/test_evaluator.py` — every
status transition and aggregation edge case named in the brief, plus the regression
case above (all-`not_tested` rows must read NOT_TESTED, not PARTIAL).

## Finding-to-control mapping

**`policies/nca/finding_mappings.py`** matches a piece of automated scan evidence to
the control(s) it's relevant to, reusing `policy_engine.py`'s existing
`{field, op, value}` predicate (exported as the public `condition_matches`) — one
predicate vocabulary, not two. Mappings live in the `compliance_finding_mappings`
table (seeded from `policies/nca/seed_finding_mappings.py`'s `MAPPINGS` list) and are
edited by changing that list and re-running the seed script — never hardcoded in the
API or UI.

A match only ever *suggests* a control link — `POST /nca/assessments/recompute` uses it
to create a `not_tested` placeholder assessment pointing at the relevant evidence, never
a PASS/FAIL verdict. A human still has to open the assessment and record the actual
finding/status, same "AI-assisted, not AI-decided" principle the rest of the project
follows for the `SA-IOT-*` evidence/verdict pipeline.

**No mapping ever targets domain 1 (governance) or the mobile/supplier/cloud guideline
groups** — a network or device scan cannot demonstrate policy approval, personnel
training, audit outcomes, or supplier/cloud contract compliance. Those stay
manual-assessment-only, enforced by `test_finding_mappings.py`'s own regression test.

## Guided checklists (automated suggestion for the 60 non-device guidelines)

The 60 organizational/mobile/supplier/cloud guidelines above can never get an
automated finding mapping — no scan proves a policy was approved or staff were
trained. **`policies/nca/checklists.py`** gives them the same "system
suggests, human signs" shape anyway, via a different mechanism: a small fixed
checklist per guideline (`compliance_control_checklists`, seeded from
`policies/nca/seed_checklists.py`), evaluated with a deterministic
`suggestion_rule` that reuses the exact same `condition_matches` predicate
`finding_mappings.py` already uses against scan evidence — one evaluation
vocabulary in the codebase for "does this data satisfy this rule," whether the
data came from a scan or from an auditor's own answers.

- `GET /nca/controls/{id}/checklist` — the questions, or `404` if none has
  been authored yet for that guideline (an expected, common state — not every
  guideline needs to launch with one; see the coverage note below).
- `POST /nca/controls/{id}/checklist/evaluate` — `{"answers": {...}}` in, a
  suggested status out. Read-only, exactly like
  `GET /nca/devices/{id}/suggestions` — never writes anything.
- The dashboard's `ChecklistAssessmentPanel` renders the questions, calls
  `evaluate` live as the auditor answers them, lets them attach the real
  underlying document as evidence (`POST /nca/evidence/upload`, previously
  built but never wired to any UI until this), and hands the result to
  `RecordAssessmentDialog` exactly like a device's automated suggestion does —
  same component, same sign-off step, one flow either way.

**Coverage today**: all 60 non-device guidelines have an authored checklist
(`GET /nca/coverage` reports this live — `guided_or_automated_count` combines
checklist-backed org-scope guidelines with automated/hybrid-classified
device-scope ones). 3 reusable question templates
(`_define_approve_implement`, `_periodic_review`, `_practice_with_evidence`)
match this framework's own recurring phrasing patterns; every question's
subject text is still drawn from that specific guideline's real canonical
requirement, never invented.

## Formal sign-off (attestation)

Every assessment now requires an explicit certification, not just a name.
`compliance_assessments` gained `attested_role`, `attestation_confirmed`
(`CHECK`'d `true` for any real verdict — see migrations 011/012), and
`attestation_statement` (the exact fixed copy shown at signing time, stored
verbatim so a later dispute sees what was actually agreed to, not today's UI
copy). `RecordAssessmentDialog`'s "Confirm & Sign" section — role + a
required "I have reviewed the evidence/reasons above and certify this
finding" checkbox — is the one place this whole module is actually enforced,
applying uniformly whether the assessment came from a device suggestion, a
checklist suggestion, or a fully manual page with neither.

**The one exception**: a `not_tested` placeholder (the row
`POST /nca/assessments/recompute` inserts, `assessed_by = 'system:recompute'`)
is exempt — it's the system's own "nothing has been asserted yet" marker, not
a human verdict, so there's nothing to attest to. Still no real
authentication (see below) — this is a stronger attestation step layered on
the existing free-text reviewer-identity convention, not a login system.

## Fully Automated Run (`auto_recorded`)

A single dashboard action (`AutomatedRunDialog` on Overview/Devices →
`POST /automation/runs`) drives the *entire* pipeline — Discovery through NCA
sign-off — with zero further clicks, for the whole fleet or an explicit
device scope. It deliberately goes further than the manual flow's "a human
always signs" rule: it auto-*records* NCA assessments too, not just
auto-suggests them.

That's reconciled with the attestation rule above by a new
`compliance_assessments.auto_recorded BOOLEAN NOT NULL DEFAULT false`
column (migration 013), set `true` only by `automated_run_runner.py`
(`lab/auditor/worker/`) and never by the dashboard's own
`RecordAssessmentDialog`. An auto-recorded row still satisfies the same
`attestation_confirmed = true` CHECK constraint every real verdict does —
`attested_role: "system:automated-run"`, `assessed_by: "Fully Automated
Run"`, and a fixed `attestation_statement` disclosing that no human
reviewed it — so the audit trail is honest about *what* confirmed it
without ever bypassing the constraint.

**What the run actually does, in order** (`automated_run_runner.py`, a new
poll loop registered in `job_runner.py`'s main loop): Discovery scan → guess
and register any new `iot_device`/`uncertain` host (mirrors
`NetworkDiscoveryPanel.tsx`'s own prefill logic, reimplemented in Python) →
every applicable Fingerprinting/SA-IOT-Compliance test per device, each
job's already-deterministic `suggested_finding`/`suggested_confidence`
auto-submitted with zero human review → `POST /verdicts/recompute` →
Vulnerability Intelligence for any device that already has firmware
uploaded (never invented) → `POST /nca/assessments/recompute` +
`GET /nca/devices/{id}/suggestions` per device, each suggestion
auto-recorded with `auto_recorded: true`. **Never automated, by design**:
the ~60 organizational/mobile/supplier/cloud guidelines (they need a
human's guided-checklist answers — nothing in scan evidence tells the
system whether a policy was approved) and Vulnerability Intelligence for a
device with no firmware. Both are stated up front in the confirmation
dialog before the run starts.

Architecturally the runner is not a new execution path: every stage calls
the exact same auditor-api endpoints a human clicking through the UI
would, so it inherits every existing security boundary
(`device_validation`, the scan-test whitelist, the finding-mapping table)
with no new bypass surface. Scan-job/network-scan *execution* reuses
`job_runner.py`'s own `process_job()`/`process_network_scan()` directly —
creating a row via the API and waiting for the next `poll_once()`/
`poll_network_scans_once()` iteration to pick it up would deadlock against
itself, since `poll_automated_runs_once()` runs inside the same
single-threaded loop, after those two have already run for that iteration.

**A real bug this uncovered live, not by unit tests alone**: the first
version handed `process_job()` the raw `POST /scan-jobs` response as the
job's target — but that endpoint deliberately never returns
`host`/`service_type`/`port` (`scan_jobs` is a pure audit row by design;
only `GET /scan-jobs?status=pending`'s list endpoint resolves the live
target via a join against `device_services`, the same one
`job_runner.py`'s own `poll_once()` reads from). A live whole-fleet run
failed 114 of 115 scan jobs with `"invalid target: host is required"`
before this was caught and fixed to re-fetch from the pending list by job
id first.

Every auto-recorded assessment carries an **"Auto-recorded — not yet
reviewed"** badge (`AutoRecordedBadge`) wherever it appears in
`DeviceAssessmentPage`'s control list, with its own filter tab, and a
**"Review & confirm"** action that opens the same `RecordAssessmentDialog`
retest flow a manual retest already uses — a human reads the pre-filled
finding/evidence and does a real Confirm & Sign, which supersedes the
auto-recorded row with a new one (`auto_recorded: false`) via the existing
append-only mechanism. The original auto-recorded row is never deleted —
both stay visible in the control's audit trail.

## Evidence handling

- Automated findings: `compliance_evidence.linked_evidence_id` references the existing
  `evidence` table's row (already has `sha256`/`raw_output_path`/`tool`/`tool_version`)
  — no re-hashing, no second copy of the raw output.
- New organizational documents: uploaded via `POST /nca/evidence/upload`, capped at 20MB
  (same chunked-read-with-cap defense as firmware upload, in the shared
  `lab/auditor/api/upload_utils.py`), stored under `document-store/compliance/`,
  referenced by path + SHA-256 — never as a database blob.
- `retention_expires_at` on a `compliance_evidence` row: once passed, any assessment
  whose evidence has expired has its PASS rolled down to PARTIAL by the evaluator (see
  above) — expired evidence is a UI warning, not silently ignored.

## Manual assessment workflow (reviewer identity, not real authentication)

**This application has no login/session/user system anywhere.** Rather than build one
just for this module, every write that represents a judgment call requires a free-text
**reviewer identity** recorded directly on the row:

- `compliance_assessments.assessed_by` — `NOT NULL`. Required on every
  `POST /nca/assessments` and `POST /nca/assessments/{id}/retest` call (`400` with
  `{"field": "assessed_by", ...}` if missing).
- `compliance_exceptions.requested_by` — `NOT NULL` on creation.
- Approving/rejecting an exception requires `approved_by` / `rejected_by` in the
  request body (`422` if missing — `POST /nca/exceptions/{id}/approve` with no
  `approved_by` is exactly the case `test_nca_routes.py` checks for).

This is **not authentication** — anyone can type any name. It is a deliberate, explicit
limitation (see below), not something silently glossed over. It satisfies the brief's
"require reason+approver for manual overrides" and "require expiry for exceptions"
rules without inventing a login system this project has never had.

## Dashboard UI (record/retest assessments, exceptions, the full catalog)

Every write endpoint below has a real dashboard UI wired to it — this was **not** true
originally: `POST /nca/assessments`, `/retest`, `/exceptions`, `/exceptions/{id}/approve`,
`/exceptions/{id}/reject`, and `/assessments/recompute` all existed and were fully tested
at the API layer, but nothing in `lab/auditor/web/` ever called them. The only way to
populate `compliance_assessments` was `policies/nca/seed_demo_assessments.py` (a one-off
script), and the 60+ organization-scope guidelines (governance, mobile, supplier, cloud)
had **no path to ever being assessed at all** through the product. Closed as follows:

- **`components/nca/RecordAssessmentDialog.tsx`** — the single write path for both a
  brand-new assessment and a retest (retest pre-fills every field from the prior
  assessment and posts to `/retest` instead of a plain create). Adapts to the control's
  own `scope_type`: a device picker for device-scope controls, a fixed "default"
  organizational scope with no picker for governance/mobile/supplier/cloud ones — the
  user is never given a choice that would be wrong for the control they're looking at.
  Wired into `NCAControlDetailPage` (a "Record assessment" button, and a "Retest" button
  on the current, non-superseded assessment), and reachable with the device
  pre-selected via `?device_id=` from `DeviceDetailPage`'s Compliance tab and from
  `OrganizationalCompliancePage`'s controls list (both gained an "Assess"/"Retest" link
  per control row).
- **`components/nca/RequestExceptionDialog.tsx`** — same scope-adaptive pattern, for
  `POST /nca/exceptions`. `NCAControlDetailPage` also gained a full **Exceptions** card:
  the list for that control, and — for any `pending` one — inline Approve/Reject buttons
  gated behind typing a reviewer name first (the same "reviewer identity, not real auth"
  convention as everywhere else in this module).
- **`pages/NCAControlsPage.tsx`** (`/nca-compliance/controls`) — the full 81-guideline
  catalog, browsable and filterable by domain/scope, was previously **only** reachable
  one control at a time via a device's or the organizational page's own controls list
  (which only shows controls already relevant to that scope) — there was no way to see
  the whole catalog, or to find an organization-scope control to assess it for the first
  time, without already knowing its ID.
- **A "Recompute from evidence" button on `NCACompliancePage`** — `POST
  /assessments/recompute` (matches scan evidence against `compliance_finding_mappings`
  and creates `not_tested` placeholder assessments pointing at the relevant evidence,
  same idempotent insert-if-missing pattern as `/verdicts/recompute`) existed since this
  module was built but had no UI trigger anywhere; a human still has to open each
  placeholder and record the real finding — this button only ever surfaces what needs
  review, never decides a status.

**Verified live against the real dev stack**, not just unit-tested: recorded a real
`pass` assessment on a real governance control (`1-1-1`, "Cybersecurity Strategy" —
previously unassessable through the product at all), retested it (confirmed the prior
assessment flips to `superseded` and the audit trail shows the `assessment_retested`
event), requested and approved a real exception, and clicked "Recompute from evidence"
and confirmed it surfaced real not-tested placeholders from real scan evidence already
in the database.

## Compliance readiness classification (Passed / Partially Passed / Failed)

Additive alongside `device_overall_status`/`device_score` above, which the existing
dashboard keeps using unchanged: **`overall_classification(rows)`** in
`policies/nca/evaluator.py` computes a single Passed/Partially Passed/Failed verdict
per device or organizational scope, returned as `readiness` on
`GET /nca/devices/{id}` and `GET /nca/organization` (and a `readiness_classification`
summary field on each `GET /nca/devices` row). Exact rules, thresholds configurable
(`pass_threshold=85`, `partial_threshold=50` by default):

- **Failed** — a control flagged `blocking=true` failed, **or** no applicable required
  control has ever produced a result, **or** score < `partial_threshold`.
- **Partially Passed** — score is in the `partial_threshold`–`pass_threshold` band; **or**
  score ≥ `pass_threshold` but a critical-severity control failed; **or** a mandatory
  control is still `NOT_TESTED`; **or** a mandatory control is `REVIEW_REQUIRED`.
- **Passed** — score ≥ `pass_threshold`, no critical-severity failure, no blocking
  condition, no mandatory control left `NOT_TESTED`/`REVIEW_REQUIRED`.

Deliberately does not rely on the percentage alone, per the brief's own "do not rely
only on the percentage" requirement — a blocking condition or critical failure
overrides a high score. The response includes `reasons` (plain-language, e.g. "Score
40% is below the failing threshold of 50%.") and the exact `*_control_ids` that drove
the result, so the UI never has to re-derive an explanation. Rendered as a new
**`NCAReadinessBadge`** (icon+text, same colorblind/greyscale-safe rule as
`NCAStatusBadge`) on `DeviceDetailPage`'s Compliance tab, `OrganizationalCompliancePage`,
and a new "Readiness" column on `NCACompliancePage`'s device table.

**Blocking controls** are a new `compliance_controls.blocking` boolean — like
`scope_type`/`severity`, this is **IoTGuard's own judgment call**, authored in
`policies/nca/build_catalog.py`'s `BLOCKING_GUIDELINES` set, not NCA's own
classification (real CGIoT-1:2024 guideline text is organizational/high-level and
doesn't contain literal technical trigger phrases like "Telnet" or "default
password" — confirmed by searching the live catalog text before deciding this had
to be authored, the same way `HIGH_SEVERITY_GUIDELINES` already is). Deliberately
small, limited to guidelines with a concrete, well-known device weakness at stake
that matches the project's own worked examples: `2-2-2` (default/hard-coded
credentials), `2-4-3` (sensitive data transmitted without encryption), `2-15-2`
(unnecessary/insecure exposed services, e.g. Telnet). Shown as a "blocking condition"
badge on the control detail page and the controls catalog.

**`review_required`** is a new, sixth status alongside pass/partial/fail/not_tested —
distinct from `not_tested`: an assessment *was* recorded, but something about it
(most commonly conflicting evidence, mirroring `policies/engine/conflict.py`'s
SA-IOT-* precedent) means a human needs to look at it again before it counts as a
real pass or fail. It rolls into the existing `device_overall_status`'s PARTIAL
bucket but is tracked as its own thing by `overall_classification`, since a
Passed verdict must not be reachable while any mandatory control is still awaiting
review. Selectable in `RecordAssessmentDialog`'s status dropdown and the new
`OverrideAssessmentDialog`'s.

## Auditor override

**`POST /nca/assessments/{id}/override`** lets an authorized auditor override a
previously-recorded (automated or manual) result — required fields: `status`,
`justification` (mandatory written reason), `overridden_by` (auditor identity), and
an optional `original_status` the API rejects with `400` if it no longer matches the
assessment's real current status (stale-read protection: the assessment may have
changed since the auditor loaded it). Like retest, this **never mutates the original
row** — it inserts a new, superseding assessment via the same
supersede-and-audit-trail mechanism `_insert_assessment` already uses, with
`event_type="assessment_overridden"` and a `reason` combining the auditor's identity
and justification, so both the original result and the override remain permanently
visible in the control's audit trail. The response includes `original_status` and
`override_justification` for the UI to display immediately without a second fetch.
Wired into `NCAControlDetailPage` as an "Override" button next to "Retest" on each
current assessment, opening `components/nca/OverrideAssessmentDialog.tsx`.

## Reports

`GET /nca/reports/devices.csv`, `/controls.csv`, `/controls.json`, `/evidence.csv`,
`/executive.pdf` (WeasyPrint, same `FontConfiguration` pattern — passed to **both**
`CSS()` and `write_pdf()` — as the existing per-device PDF report, see
`lab/auditor/api/nca_report.py`). Every export includes the framework/version, the
alignment-not-certification disclaimer, and — for the executive PDF — device
compliance, domain breakdown, failed/partial controls, and approved exceptions.

## How to add a new framework version

1. Update `docs/reference/CGIoT-1_2024.md` (or add a new transcription file) with the
   new version's text.
2. Bump `FRAMEWORK_VERSION` in `policies/nca/build_catalog.py`, or parameterize it if
   multiple versions must coexist — `compliance_controls` is keyed on
   `UNIQUE(framework, framework_version, guideline_id)`, so old and new versions can be
   queried side-by-side without conflict.
3. Regenerate the catalog JSON (`python -m policies.nca.build_catalog`) and review the
   diff by hand before committing — this is a human-reviewed artifact, not something
   trusted blindly.
4. Re-run `seed_catalog.py` against the target database.

## Known limitations

- **Reviewer identity is not real authentication.** See above.
- **`source_page` is a page *range*, not an exact page**, for guidelines that share a
  transcription page-marker block with others — the source transcription doesn't have
  finer precision, and this module does not fabricate it.
- **`scope_type`/`assessment_type`/`required`/`severity` are IoTGuard's own
  methodology**, not NCA's own classification — documented in
  `policies/nca/build_catalog.py`'s module docstring and repeated here so it isn't lost.
- **Single fixed organizational scope** (`"default"`) — not multi-tenant. A future
  multi-organization deployment would need `organizational_scope_id` to vary.
- **The fleet-level device compliance table filters by status, device type, and
  manufacturer only** — severity, firmware version, assessment date, and evidence
  state are per-*control* properties, not per-*device* ones, and are filterable on
  each device's own Compliance tab and the control detail page rather than the
  fleet table (a device can simultaneously have controls at every severity/evidence
  state, so a device-level filter on those fields wouldn't cleanly select anything).
- **5 device-scope guidelines have neither a collector nor a checklist**
  (`2-9-2` vulnerability-management process, `2-14-2` application allowlisting,
  `2-15-3` end-of-life/disposal, `3-1-1`/`3-1-2` fail-safe capability) —
  `GET /nca/coverage` reports this honestly (76/81 today, not 81/81). Each is a
  real process or hardware-access requirement no realistic network/device scan
  can verify in this lab; the guided-checklist mechanism *could* extend to
  them (checklists aren't inherently org-scope-only), just hasn't yet — a
  natural next increment, not an architectural gap.
- **A checklist's `suggestion_rule` is authored per-guideline, not
  auto-derived from its canonical text** — the 3 reusable templates in
  `seed_checklists.py` cover this framework's own recurring phrasing well, but
  a genuinely novel guideline shape would need a 4th template or a one-off
  rule, same as any rule-based system.
- **`lab/auditor/api/*.py` (main.py, nca_routes.py, ...) is baked into the
  `auditor-api` image at build time** — unlike `policies/`, which is
  bind-mounted read-only into both `auditor-api` and `auditor-worker`, so
  editing `policies/catalog/scan_tests.py` only needs a container *restart*
  to take effect, but editing `nca_routes.py` needs a full
  `docker compose build auditor-api` (confirmed the hard way: the checklist
  endpoints returned a plain routing 404 after a restart alone, until the
  image was actually rebuilt).
- **A Fully Automated Run's cancellation is cooperative, not preemptive** —
  same documented limitation as `POST /assessments/{id}/cancel`: the run's
  status is checked between stages/devices, but a scan already dispatched to
  `process_job()` (a blocking `subprocess.run`) is left to finish rather than
  killed mid-execution.
- **A Fully Automated Run can never assess the ~60 organizational/mobile/
  supplier/cloud guidelines or run Vulnerability Intelligence on a device
  with no firmware uploaded** — by design, not an oversight; see "Fully
  Automated Run" above. An auto-recorded assessment's finding text is the
  same fixed, deterministic template a human sees pre-filled in
  `RecordAssessmentDialog` — never model-generated.
