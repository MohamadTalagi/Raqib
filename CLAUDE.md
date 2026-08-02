# CLAUDE.md — KAUST IoT Security Project

> **This file is the single source of truth for the project.** It MUST be updated every time
> something meaningful changes: a new component is built, a decision is made, a tool is chosen,
> a task is completed, or a milestone is reached. Treat it as a living document.
>
> **Last updated:** 2026-08-03
> **Maintained by:** Team of 4 · KAUST Academy — Cybersecurity Specialization
> **Timeline:** 3-week project · Tooling: Claude Opus 4.8

---

## 0. Current Status — RESUME HERE 👈

**Phase:** **Post-Quantum Readiness — a bonus pipeline stage beyond IoTGuard's
original 10, sitting between AI Remediation and the AI Executive Summary —
COMPLETE** (2026-08-03). The owner's idea, raised first as an exploratory
question ("it does not affect risk scoring, it just checks whether the IoT
system is post-quantum ready or not"), then turned into a full implementation
request with one explicit instruction: "if anything is unclear please ask,
don't hallucinate." Two clarifying questions were asked and answered up front:
(1) remediation tips are **static, deterministic text**, not AI-generated,
matching this project's dominant convention; (2) the new collector **is
included in the Fully Automated Run**, unlike AI Remediation (which stays
manual-only) — the owner's own choice, more aggressive than this session's
default recommendation. Full detail, design decisions, and the real bug this
caught live: `docs/pqc-readiness.md`.
- **3 named technical criteria** grounded in real NIST standards (FIPS 203
  ML-KEM, FIPS 204 ML-DSA, FIPS 205 SLH-DSA), not a fabricated regulation - no
  enforceable IoT post-quantum regulation exists yet, stated honestly
  everywhere this surfaces: TLS Key Exchange (KEM), Certificate Signature
  Algorithm, Firmware Crypto Library Currency. Every criterion resolves to
  `pass`/`fail`/`unknown`/`not_applicable` - `unknown` is a real, honest state
  (a probe that couldn't reach the device, or a firmware crypto library this
  project hasn't verified a threshold for), never a guessed pass or fail.
- **Verified live against the real `auditor-worker` image (OpenSSL 3.5.6)
  before designing anything**: `openssl list -tls1_3 -tls-groups` shows
  exactly 3 real hybrid PQC groups (`X25519MLKEM768`, `SecP256r1MLKEM768`,
  `SecP384r1MLKEM1024`); this lab's own `device-hardened`/`device-partial`
  already negotiate a real hybrid PQC key exchange, a genuine surprise worth
  confirming rather than assuming "everything will fail" - while their
  certificates stay classical RSA, honestly reflecting the real world (PQC
  key-exchange rollout is ahead of PQC certificate/PKI rollout industry-wide).
- **New `policies/catalog/pqc_crypto_reference.py`** (OpenSSL-only,
  version-gated lookup + fixed tip text) and
  **`lab/auditor/worker/scan_scripts/pqc_readiness_check.py`** (mirrors
  `tls_cert_check.py`'s two-handshake shape). Two new `SCAN_CATALOG` entries
  (`TEST-PQC-TLS-HANDSHAKE`, `TEST-PQC-FIRMWARE-CRYPTO`) and a new
  `PIPELINE_PHASE_PQC_READINESS`. New read-only
  `lab/auditor/api/pqc_routes.py` (`GET /pqc-readiness/devices(/{id})`,
  `/fleet-summary`) - computed live from `evidence` rows on every request,
  same architecture as `vuln_routes.py`/`risk_routes.py`, no new table, no new
  verdict/assessment concept.
- **A real bug caught by the first live scan, not by unit tests alone**: the
  original PQC group list included a 4th name, `X448MLKEM1024`, invented by
  analogy with the other 3 pairings without checking OpenSSL's actual
  supported list first - that group doesn't exist in OpenSSL's real
  hybrid-group registry (ML-KEM-1024 only pairs with SecP384r1, not X448),
  and passing it made `-groups` reject its *entire* argument outright, so
  every TLS-capable device reported `connection_error` instead of a real
  result. Fixed by removing it from both the collector script and
  `scan_tests.py`'s classification set; re-verified live that
  `device-hardened` now correctly negotiates `X25519MLKEM768` (KEM pass) with
  a classical certificate signature (fail).
- **Wired into the Fully Automated Run**: a new `pqc_readiness` stage between
  `vulnerability_intelligence` and `nca_compliance` in
  `automated_run_runner.py`, with its own `summary["pqc_devices_scanned"]`
  counter; `AutomatedRunDialog.tsx` discloses it up front,
  `AutomatedRunProgressPage.tsx` shows a live stat tile. A real scoped run
  against `device-hardened` confirmed `pqc_devices_scanned: 1` live.
- **`executive_summary.py`** gained a `post_quantum_readiness` fleet-wide
  section (via a new shared `fleet_summary_from_devices()` helper, refactored
  out of the route so the two can never disagree) and a per-device
  `pqc_readiness` breakdown - deliberately kept separate from
  `risk_score`/`fleet_summary`'s existing fields, never blended into the
  compliance-gap counts. The PDF/HTML template and `ExecutiveSummaryPage.tsx`
  both got a matching new section, confirmed live to render the real
  post-fix data (1 pass / 1 fail on TLS key exchange, matching the API
  exactly) via curl and a real browser (Claude-in-Chrome).
- **New `/pqc-readiness` dashboard page** (`PostQuantumReadinessPage.tsx`),
  inserted in the sidebar's Pipeline group between Remediation and Executive
  Summary as requested - same `DeviceCohortPicker` +
  `PhaseRunnerCard`-wrapping pattern `VulnerabilityIntelligencePage.tsx`
  already established (`DevicePqcReadinessCard.tsx`), plus a shared
  `PqcReadinessPanel` reused on both this page and the Executive Summary's
  per-device panel so the two can never render differently. New
  `PqcCriterionBadge` (`severity-badge.tsx`) for the 4-state status set.
- **Verified live end to end**: real collector runs against `device-hardened`
  (TLS service present) and `device-insecure` (no TLS service, correctly
  rejected/`not_applicable`); a real Fully Automated Run; the fleet-summary
  and executive-summary endpoints agreeing byte-for-byte; the live HTML
  export rendering the real evidence row and fleet table; and both the
  Executive Summary page and the new `/pqc-readiness` route confirmed live in
  a real browser.
- **Regression**: 387 `policies` (+17) + 310 `lab/auditor/api` (3
  pre-existing WeasyPrint failures, unrelated) + 113 `lab/auditor/worker`
  (in-container, 0 failures) + 307 frontend tests (+22) passing, `tsc -b`/
  `oxlint` clean. `auditor-api`/`auditor-web` rebuilt and redeployed
  (baked-in code changed); `auditor-worker` restarted twice - once for the
  initial wiring, once more after the live-caught group-name fix
  (bind-mounted, no rebuild needed).
- **Docs**: new `docs/pqc-readiness.md`, this entry, and a new changelog row.

Before that: **AI Executive Summary (IoTGuard Stage 08) — the final analytical
pipeline stage — COMPLETE** (2026-08-02). The owner asked whether Remediation
was wired into the Fully Automated Run (confirmed: no, deliberately - it
stays on-demand only, never part of that pipeline's own documented
boundary), then asked to plan the last pipeline stage: every device listed
and ranked by risk score (highest first), the remediation for each device,
the evidence pointing to each vulnerability and what tool found it, all
summarized clearly. Per `docs/reference/IoTGuard.md`, that's Stage 08 - AI
Executive Summary, depending on Stages 4-7 (compliance, vulnerabilities,
risk, remediation), all already built. **Confirmed with the owner up
front**: stays a fully deterministic rollup, no genuinely AI-generated
narrative text - every other report in this app already carries the same
rule ("a generated summary paragraph would contradict the report's own
determinism claim"), and a document aimed at non-technical stakeholders is
exactly where a hallucinated claim would do the most damage. The "AI" in
the stage's name is satisfied by aggregating the already-AI-generated,
human-reviewed Remediation blueprints from Stage 07, not by generating new
prose.
- **New `lab/auditor/api/executive_summary.py`** - pure aggregation,
  nothing reimplemented: reuses `risk_routes._compute_risk_for_device()`
  for ranking (same worst-first sort `GET /risk/devices` already does),
  `report.build_report_model()` once per device (SA-IOT gaps, evidence+
  tools, vulnerability summary - called wholesale, not reimplemented),
  `nca_routes._evaluator_rows_for_scope()` +
  `policies/nca/evaluator.py`'s `effective_status()`/`_applicable_required()`
  for NCA gaps (so this view can never disagree with a device's own
  readiness classification), and a direct query against
  `remediation_blueprints` (already has a denormalized `device_id` column
  from Stage 07 - no new join needed). Fleet-wide rollup adds priority
  recommendations (unreviewed immediate-priority remediation, worst-device-
  first) and significant compliance gaps (blocking NCA controls currently
  failing, fleet-wide).
- **New `lab/auditor/api/executive_summary_routes.py`**:
  `GET /executive-summary` (live JSON model), `GET /executive-summary/
  report.pdf` / `/report.html` (same Jinja2/WeasyPrint `font_config`
  pattern as `report.py`/`nca_report.py`). Read-only, like `risk_routes.py`
  - nothing is cached or persisted. Not logged to `report_records` (that
  table's `device_id` column is scoped to a single device by design - a
  documented scope cut, not a silent gap).
- **New `ExecutiveSummaryPage.tsx`** (`/executive-summary`), the final entry
  in the Sidebar's Pipeline group: fleet-wide stat tiles, priority-
  recommendations and significant-compliance-gaps cards, and every device
  ranked by risk score highest-first, expand-in-place (same convention
  `RiskAssessmentPage` already uses) to show compliance gaps, evidence+
  tools, and remediation blueprints (reusing the `AiGeneratedBadge` built
  for Stage 07). PDF/HTML export buttons matching
  `DeviceAssessmentReportPage`'s own convention.
- **Verified live end to end**: loaded against the real stack - 11 real
  devices correctly ranked by risk (`device-insecure` #1 at 84/Critical
  down to `telnet-sim` #11 at 38/Medium), real priority recommendations
  and blocking compliance gaps rendered fleet-wide, and
  `device-insecure`'s expanded panel showed its real compliance gaps, its
  real evidence/tool list, and both of its real remediation blueprints
  exactly as previously recorded (one "Reviewed by Lead Auditor," the
  other still carrying the "AI-generated" badge). Both the PDF export (a
  genuine 139KB `%PDF-1.7` file) and the HTML export were downloaded and
  confirmed against the live stack.
- **Regression**: 370 `policies` + 300 `lab/auditor/api` (3 pre-existing
  WeasyPrint gaps, unrelated - the new PDF-rendering test joins the same
  known Windows-host gap every other PDF test in this suite already has)
  + 78 `lab/auditor/worker` + 299 frontend tests all passing, `tsc -b`/
  `oxlint` clean. `auditor-api`/`auditor-web` rebuilt and redeployed.
- **Docs**: new `docs/executive-summary.md`, this entry.

Before that: **AI-Assisted Remediation (IoTGuard Stage 07) built out via
Google Gemini's free tier — COMPLETE** (2026-08-02). The owner asked how to
add AI-assisted remediation "worthwhile and cheap" - no money to spend.
Chose Gemini specifically because its free tier needs no billing/card
attached at all (unlike this project's own build-time tooling, Claude
Opus 4.8, which is a paid API); planned via plan mode, one real scoping
question confirmed with the owner up front: cover **both** SA-IOT verdicts
*and* NCA CGIoT-1:2024 assessments in v1, not just the SA-IOT pilot the old
stub already showed, since NCA's `remediation_guidance` is hardcoded `""`
for every one of its 81 guidelines in `policies/nca/build_catalog.py` — a
real, bigger gap than SA-IOT's one-line static remediation.
- **`RemediationPage.tsx` rebuilt** from its long-standing "Not built yet"
  stub: every currently failing/partial finding (SA-IOT verdict or NCA
  assessment, tagged accordingly) gets a "Generate AI remediation" button;
  the resulting structured blueprint (root cause, numbered steps, priority,
  effort, caveats) renders behind a new `AiGeneratedBadge` (modeled on the
  Fully Automated Run feature's own `AutoRecordedBadge`) until a human
  types their name and clicks "Mark reviewed." A page-level "Generate all
  missing" button paces itself 4s apart, safely under the free tier's rate
  limit.
- **New `lab/auditor/api/remediation_engine.py`** — pure, unit-testable
  (same shape as `risk_engine.py`): builds the Gemini prompt, calls its
  REST `generateContent` endpoint via plain `httpx.post` (no SDK, no new
  dependency - `httpx` was already installed), and validates the
  structured-JSON response. **Never raises** - a missing key, rate limit,
  or malformed response all return `None`, so the caller reports an honest
  failure instead of fabricating a blueprint, matching
  `cisa_kev.fetch_and_cache_kev_feed()`'s own convention for a failed
  external call. The prompt is explicit that the finding itself is already
  decided by deterministic code and must never be second-guessed or
  expanded with invented facts - a prompt instruction, not a hard
  guarantee, which is exactly why every blueprint still needs a human
  review before being treated as authoritative.
- **New `remediation_blueprints` table** (migration `014`) - append-only,
  same supersede pattern as `compliance_assessments`: a re-generate for a
  finding supersedes the prior blueprint rather than overwriting it. Never
  mutates `verdicts.remediation`/`compliance_assessments.remediation` -
  purely additive display, so neither existing append-only table needed
  any change. New flat `GET /nca/assessments` (fleet-wide, filterable by
  status - the NCA equivalent of the already-existing `GET /verdicts`) so
  the Remediation page can list every failing NCA finding in one call.
- **A real bug caught by the first live call, not by planning alone**: the
  originally planned default model, `gemini-2.0-flash`, returned `429
  RESOURCE_EXHAUSTED` with `limit: 0` the instant a real key went live -
  Google had reduced that model's free-tier allocation to zero for new
  keys by the time this was built (its knowledge of "current" free-tier
  models was stale). Queried Gemini's own live `ListModels` endpoint,
  confirmed `gemini-3.5-flash-lite` has real free quota and correctly
  honors structured JSON output, and switched the pinned default
  everywhere (`GEMINI_MODEL` env var, so this can change again without a
  code change if Google deprecates it too).
- **Verified live end to end**: a real SA-IOT verdict (`SA-IOT-002`,
  default credentials) and a real NCA assessment
  (`NCA-CGIoT-1_2024-1-1-1`, organizational scope) both generated real,
  sensible blueprints through the actual browser; the review flow
  correctly cleared the AI-generated badge and showed the reviewer's name;
  a regenerate correctly superseded the prior blueprint while both stayed
  visible in the append-only history; the "Generate all missing" counter
  decremented correctly as blueprints were generated one at a time.
- **Key handling**: the owner generated a free Gemini API key via Google AI
  Studio: a first key was accidentally pasted into chat and treated as
  compromised (never used, instructed to revoke and regenerate); the real
  key lives only in the gitignored `lab/.env` (`GEMINI_API_KEY`),
  interpolated into `docker-compose.yml`'s `auditor-api` environment via
  `${GEMINI_API_KEY}` so the literal value never touches a tracked file.
- **Regression**: 370 `policies` + 289 `lab/auditor/api` (2 pre-existing
  WeasyPrint gaps, unrelated) + 78 `lab/auditor/worker` + 294 frontend
  tests (+3 net: 3 new suites replacing the old stub's 3) all passing,
  `tsc -b`/`oxlint` clean. `auditor-api`/`auditor-web` rebuilt (baked-in
  code changed).
- **Docs**: new `docs/remediation.md` (architecture, prompt design, the
  live model-availability correction, known limitations), this entry.

Before that: **"Fully Automated Run" — one dashboard action drives Discovery
through NCA sign-off end to end with zero further clicks — COMPLETE**
(2026-08-02). The owner's own framing: "to ensure actual end users don't
find this overwhelming or difficult," automate everything from network
scanning to device cataloguing to fingerprinting all the way until scoring.
Planned via plan mode with 3 clarifying decisions, each more aggressive than
this session's own default recommendation, all confirmed with the owner up
front: (1) the run **auto-records** NCA assessments, not just
auto-suggests them — going further than the guided-workflow phase's own "a
human always signs" rule; (2) scan evidence **auto-submits** its
already-deterministic suggested finding with zero human review; (3) scope
is **the entire fleet, including a fresh Discovery sweep**, not just
already-registered devices.
- **Reconciling full automation with the attestation rule from the phase
  below**: a new `compliance_assessments.auto_recorded BOOLEAN NOT NULL
  DEFAULT false` column (migration `013`, alongside a new `automated_runs`
  table) is set `true` only by the new orchestrator, never by
  `RecordAssessmentDialog`'s human path. An auto-recorded row still
  satisfies the same `attestation_confirmed = true` CHECK every real
  verdict does (`attested_role: "system:automated-run"`, `assessed_by:
  "Fully Automated Run"`, a fixed disclosure statement) — honest about
  *what* confirmed it, never bypassing the constraint.
- **New `lab/auditor/worker/automated_run_runner.py`**, a new poll loop
  registered in `job_runner.py`'s main loop: Discovery scan → guess and
  register any new `iot_device`/`uncertain` host (mirrors
  `NetworkDiscoveryPanel.tsx`'s own prefill logic, reimplemented in Python)
  → every applicable Fingerprinting/SA-IOT-Compliance test per device with
  its suggested finding auto-submitted → `POST /verdicts/recompute` →
  Vulnerability Intelligence for any device that already has firmware
  uploaded (never invented) → NCA recompute + per-device suggestions, each
  auto-recorded. **Never automated, stated up front in the confirmation
  dialog**: the ~60 organizational/mobile/supplier/cloud guidelines (need a
  human's checklist answers) and Vulnerability Intelligence for a
  firmware-less device. Architecturally not a new execution path — every
  stage calls the exact same auditor-api endpoints a human clicking through
  the UI would, inheriting every existing security boundary with no new
  bypass surface; scan-job/network-scan *execution* reuses `job_runner.py`'s
  own `process_job()`/`process_network_scan()` directly rather than
  creating a row and waiting for the next poll iteration (which would
  deadlock against itself, single-threaded loop).
- **New `lab/auditor/api/automation_routes.py`**: `POST/GET /automation/runs`,
  `GET /automation/runs/{id}`, `PATCH /automation/runs/{id}` (progress
  reporting, only ever called by the runner), `POST /automation/runs/{id}/cancel`
  (cooperative, not preemptive — same documented limitation as
  `POST /assessments/{id}/cancel`).
- **Frontend**: `AutomatedRunDialog` (states exactly what will run and what
  won't, before anything starts — the same "confirm before fleet-wide side
  effects" pattern this project always uses for consequential actions),
  entry buttons on Overview and Devices, and `AutomatedRunProgressPage`
  (`/automated-run/:id`, polls live stage/summary counts, cancel button,
  review links once complete). New `AutoRecordedBadge` marks any
  `auto_recorded: true` row in the NCA per-device workspace, with its own
  filter tab and a **"Review & confirm"** action that reopens
  `RecordAssessmentDialog`'s existing retest flow — a human reads the
  pre-filled finding and does a real Confirm & Sign, superseding the
  auto-recorded row (append-only; the original is never deleted).
- **A real bug caught by the first live run, not by unit tests alone**: the
  first version handed `process_job()` the raw `POST /scan-jobs` response as
  the job's target, but that endpoint deliberately never returns
  `host`/`service_type`/`port` (`scan_jobs` is a pure audit row by design —
  only `GET /scan-jobs?status=pending`'s list endpoint resolves the live
  target via a join, the same one `job_runner.py`'s own `poll_once()` reads
  from). A live whole-fleet run failed 114 of 115 scan jobs with `"invalid
  target: host is required"` before this was caught and fixed to re-fetch
  from the pending list by job id first. 2 new regression tests lock this
  down.
- **Verified live end to end, twice**: a first whole-fleet run (via a real
  browser, Claude-in-Chrome) surfaced the bug above; after the fix, a
  second scoped run against `device-insecure` recorded 13/13 evidence (was
  1/115), computed 2 new verdicts, ran Vulnerability Intelligence once, and
  auto-recorded 9 real NCA assessments — confirmed live in the browser
  (`AUTO-RECORDED` badges, correct filter counts), then a real human
  "Review & confirm" was carried out on one control through the actual UI
  and confirmed via the API that the new human-signed row
  (`auto_recorded: false`) correctly superseded the auto-recorded one while
  both stayed visible in the append-only audit trail.
- **Regression**: 370 `policies` + 266 `lab/auditor/api` (2 pre-existing
  WeasyPrint gaps, unrelated) + 78 `lab/auditor/worker` (2 pre-existing
  yara-import gaps on this host, unrelated) + 291 frontend tests (+9,
  including a real fix: the new "Auto-recorded" filter tab's text collided
  with an existing test's loose `/record/i` button query) all passing,
  `tsc -b`/`oxlint` clean. `auditor-api`/`auditor-web` rebuilt (baked-in
  code changed), `auditor-worker` restarted (bind-mounted, no rebuild
  needed) and confirmed live serving the new poll loop.
- **Docs**: this entry, plus a new "Fully Automated Run" section and two
  new "Known limitations" bullets in `docs/nca-compliance.md`.

Before that: **NCA Compliance made "guided end to end" — every one of the 81
CGIoT-1:2024 guidelines now reaches an auditor as a suggested status +
evidence to review, with a mandatory formal sign-off before anything is
recorded — COMPLETE** (2026-08-02). The owner asked, after reviewing how NCA
Compliance actually worked, "wouldn't it make sense to automate all NCA
Compliance sections and then have the auditor manually read them and sign
them under his name instead of only doing some?" — this phase is that,
executed as a 9-phase plan (approved via plan mode) after 3 clarifying
decisions with the owner: (1) for the 60 guidelines no scan can ever verify
(governance/HR/training/supplier/cloud), "automate" means a **structured
attestation workflow** (guided checklist + real document upload), never an
invented verdict; (2) sign-off gets a **formal attestation step** (role +
explicit certify checkbox), still no real login — a full auth rebuild stays
a separate, previously-deferred track; (3) **new device-scope collectors**
get built wherever a real technical check exists, raising automated coverage
as far as honestly possible.
- **Phase 0 (prerequisite, found live)**: `policies/nca/build_catalog.py`'s
  `DEVICE_TESTABLE_GUIDELINES` was missing `2-6-2`/`2-6-3`/`2-7-2` even
  though real finding mappings and device evidence already targeted them
  (added last session) — they silently fell through to `scope_type =
  "organization"`, and `GET /nca/devices/{id}` only ever lists
  `scope_type = "device"` controls, so their real computed suggestions were
  **orphaned**: reachable via `/suggestions` but with no "Record" button
  anywhere to act on them. Fixed by reclassifying all 3, and caught 5 more
  guidelines (`2-4-2`, `2-4-6`, `2-9-1`, `2-13-2`, `2-15-1`) still marked
  `"manual"` even though real collectors already existed for them from
  earlier sessions — this table had simply never been revisited as
  collectors were added. New regression test locks the invariant down:
  every mapped `control_id` must resolve to `device`/`mobile` scope.
- **New guided-checklist mechanism** (`policies/nca/checklists.py`,
  `compliance_control_checklists` table, migration `011`) for the 60
  guidelines a scan can never verify: a small fixed set of questions per
  guideline, evaluated by a deterministic `suggestion_rule` reusing
  `policy_engine.py`'s own `{field, op, value}` predicate — one evaluation
  vocabulary in the codebase, not a second DSL. New
  `GET/POST /nca/controls/{id}/checklist(/evaluate)` endpoints; new
  `ChecklistAssessmentPanel.tsx` renders the questions, live-evaluates a
  suggestion, and finally wires up `POST /nca/evidence/upload` (built in an
  earlier session, never once called from any UI until now) so an auditor
  can attach the real underlying policy/contract document as evidence.
  **All 60 non-device guidelines now have a real, authored checklist**
  (`policies/nca/seed_checklists.py`) — 27 governance, 21 remaining domain-2
  organizational, 1 mobile, 6 supplier, 5 cloud — built from 3 reusable
  templates matching this framework's own recurring phrasing patterns
  (`_define_approve_implement`, `_periodic_review`, `_practice_with_evidence`),
  every question's subject text drawn from that guideline's own real
  canonical text, never invented. 11 new structural tests lock down full
  coverage and that every rule can actually reach pass/partial/fail.
- **Formal sign-off on every assessment, not just checklist-driven ones**:
  `compliance_assessments` gained `attested_role`/`attestation_confirmed`
  (`CHECK`'d true for any real verdict)/`attestation_statement` (the exact
  fixed certify text, stored verbatim). `RecordAssessmentDialog` gained a
  "Confirm & Sign" section — role + a required "I have reviewed the
  evidence/reasons above and certify this finding" checkbox — Save stays
  disabled until both are filled, applying uniformly whether the flow
  started from a device auto-verdict suggestion, a checklist suggestion, or
  a fully manual assessment. **One exception, found live**: `recompute`'s
  own system-generated `not_tested` placeholder (`assessed_by =
  'system:recompute'`) has nothing to attest to — a first-pass unconditional
  `CHECK` briefly broke that path, fixed one migration later (`012`) once
  caught.
- **3 new device-scope collectors** raising real automated coverage:
  `TEST-TLS-CLIENT-AUTH` (2-4-5, detects whether a TLS handshake ever
  requests a client certificate), `TEST-SECURITY-LOG-ENDPOINT` (2-11-1) and
  `TEST-MONITORING-ENDPOINT` (2-11-2, both chained conventional-path curl
  probes). A 4th planned collector (2-4-6, secure update transport) was
  dropped after investigation found no real update endpoint exists in this
  lab to probe — documented as a deliberate boundary, not silently skipped.
- **New `GET /nca/coverage`** (computed live, never cached): how many of the
  81 guidelines have automated-or-hybrid device-scope signal or an authored
  checklist today — **76/81**, with the 5 remaining gap guidelines named
  explicitly (`2-9-2`, `2-14-2`, `2-15-3`, `3-1-1`, `3-1-2` — a process,
  OS-level, or hardware-access requirement each) — surfaced as a stat tile
  on the NCA Compliance dashboard and a summary line on
  `OrganizationalCompliancePage`, so partial rollout stays honestly visible
  rather than overclaimed.
- **`OrganizationalCompliancePage` rebuilt into a guided workspace in
  place** (not a separate route like `DeviceAssessmentPage` — there's only
  one organizational scope, so a dedicated URL per-scope doesn't apply the
  same way): a progress bar, Unassessed/Failing filter tabs, and per-control
  "Assess"/"Retest" now opens the guided checklist inline before handing off
  to `RecordAssessmentDialog`, instead of navigating away.
- **Two real deployment incidents hit and resolved live** while verifying
  this: (1) a mid-recovery `docker compose up -d auditor-api` partial
  failure left `auditor-database` with **zero network attachments** at the
  Docker level, and a follow-up recovery attempt dropped the
  `docker-compose.dev.yml` overlay flag, silently unpublishing port 8000 —
  both fixed with a clean `down`/`up` cycle, data intact throughout, no
  purge needed (a stale container/network state issue, not the deeper
  embedded-DNS corruption from `docs/errors/032`). (2) Discovered
  `lab/auditor/api/*.py` (unlike `policies/`, which is bind-mounted) is
  baked into the `auditor-api` image at build time — the new checklist
  endpoints returned a plain routing 404 after a restart alone, until the
  image was actually rebuilt. Both now documented in
  `docs/nca-compliance.md`'s "Known limitations" and `lab/README.md`.
- **Verified live end to end at every phase, not just at the end**: the
  Phase 0 fix confirmed live (2-6-2/2-6-3 now appear in a device's own
  workspace); all 3 new collectors run for real against real devices,
  including both positive cases (`device-smartlock`'s real
  `/api/access-log`, `device-insecure`'s real `/health`) and the honest
  negative case (no device in this lab does mutual TLS); a real signed
  `partial` assessment recorded on `1-1-1` via the API, confirming the
  organizational rollup updated and `attestation_confirmed` was stored.
  Regression: 370 `policies` tests (+31 this phase), 253 `lab/auditor/api`
  tests (2 pre-existing WeasyPrint failures, unrelated), 282 frontend tests
  (+9), `tsc -b --force`/`oxlint` clean throughout every phase.
- **Also fixed `lab/README.md`'s previously-flagged first-time-setup gap**
  while touching this doc: the NCA catalog seed steps are now documented
  as needed after any fresh volume/purge, not just silently assumed.

Before that: **5 new non-camera IoT device fixtures added for protocol/domain
variety, fully wired into the scan/policy/NCA pipeline and live-verified end
to end — COMPLETE** (2026-08-02). Every device in the lab until now was a
posture variant of the same `smart-camera` app (HTTP/HTTPS + MQTT + Telnet) —
the owner asked for real variety to stress-test assumptions baked in from
camera-only testing. Planned via plan mode (grounded in a real gap found
before designing anything: `policies/nca/seed_finding_mappings.py`'s 20
mappings only ever touched NCA subdomains 2-2/2-4/2-7/2-9/2-14/2-15 — **2-13
Physical Security and 2-6 Data and Information Protection had zero
device-scope evidence at all**, despite being real, already-seeded
CGIoT-1:2024 controls) and confirmed with the owner up front: 5 device
*types*, one posture each (breadth over depth — the camera trio already
proves posture-depth), reusing nmap's own NSE scripts for Modbus/RTSP over
hand-rolled protocol clients where practical.
- **The 5 devices** (`lab/devices/`, each a small FastAPI app mirroring
  `smart-camera`'s file layout — `app/config.py`/`main.py`/Dockerfile/
  `entrypoint.sh`/`profiles/insecure.env`/`tests/`): **`smart-lock`**
  (`device-smartlock`, HTTP REST `/lock`/`/unlock`/`/api/access-log`, default
  PIN `0000` never forced to rotate, unauthenticated unlock, a
  `tamper_detection_wired: false` status field that's always false —
  deliberately never wired to anything real); **`plc-gateway`**
  (`device-plc-gateway`, a real Modbus TCP server on 502 via `pymodbus`
  simulating a temperature/valve sensor gateway, no auth at all since the
  protocol itself has none); **`router-gateway`** (`device-router-gw`, HTTP
  admin with the same default-creds pattern as the camera + a hand-rolled
  UPnP/SSDP responder on 1900/udp answering any M-SEARCH unauthenticated, and
  a `/api/portmap` endpoint that accepts arbitrary port-forward rules from
  any caller — the real UPnP IGD exposure class); **`nvr`** (`device-nvr`, HTTP
  admin + a hand-rolled RTSP responder on 554 answering OPTIONS/DESCRIBE/PLAY
  with zero authentication, `/api/clips` listing indefinitely-retained
  recordings with `retention_policy: "none"`); **`smart-speaker`**
  (`device-speaker`, HTTP + a hand-rolled mDNS responder on 5353/udp
  answering any datagram with a plaintext TXT record disclosing
  `voice_log_encrypted: false`, `/api/voice-log` storing raw transcripts
  unencrypted forever). The UPnP and mDNS responders are small, deterministic
  raw-socket services (background thread off FastAPI's startup event, same
  pattern `smart-camera/app/telnet_server.py` already established) — a real
  design correction made mid-build: the plan's original assumption that nmap
  ships a per-host UPnP NSE script was wrong (nmap's own UPnP script is
  broadcast-class, scoped to a whole subnet, not one target), caught before
  writing the worker collector, not after.
- **New worker collectors** (`policies/catalog/scan_tests.py`): `TEST-MODBUS-PROBE`
  and `TEST-RTSP-PROBE` reuse nmap's real `modbus-discover`/`rtsp-methods` NSE
  scripts; `TEST-UPNP-PROBE`/`TEST-MDNS-PROBE` are new small raw-UDP Python
  probes (`lab/auditor/worker/scan_scripts/upnp_probe.py`/`mdns_probe.py`),
  the same raw-protocol-probe technique this project already used to
  diagnose the Docker embedded DNS resolver (`docs/errors/032`). A 5th test,
  not in the original 4-test plan, was added once actually wiring up the
  finding mappings surfaced a real gap: the smart lock's `tamper_detection_wired`
  field had no collector at all, so `TEST-PHYSICAL-TAMPER-STATUS` (a plain
  curl against `/api/status`) was added to give NCA 2-13-2 real evidence to
  point at, rather than skip that domain's coverage silently. New
  `MODBUS_SERVICE_TYPES`/`RTSP_SERVICE_TYPES`/`UPNP_SERVICE_TYPES`/
  `MDNS_SERVICE_TYPES` and 4 new `SERVICE_TYPES` entries mirrored across
  `lab/auditor/api/device_validation.py` (the actual scan-target security
  boundary), `lab/auditor/web/src/lib/types.ts`'s `ServiceType` union, and
  `RegisterDeviceForm.tsx`'s picker. `IOT_SIGNATURE_PORTS` gained 502/554
  (both TCP, so a TCP-only Discovery sweep detects them) with 1900/5353
  deliberately **not** added — both are UDP-only protocols a TCP-only nmap
  sweep can never see as "open" regardless of what's in the port list; both
  affected devices already expose HTTP on port 80 too, so they still
  classify correctly via that signature, documented in-code rather than
  silently worked around.
- **New migration `010-device-services-new-service-types.sql`** (+ `init.sql`
  updated for fresh volumes) — widens `device_services.service_type`'s
  Postgres CHECK constraint to match the widened Python `SERVICE_TYPES`
  tuple. **A real bug caught live, not by unit tests**: registering
  `device-plc-gateway` 500'd with `psycopg.errors.CheckViolation` the moment
  live verification tried it — the DB-level CHECK constraint is a second
  place the same enum lives, missed on the first pass since nothing in the
  Python layer would ever catch a mismatch between the two.
- **8 new `compliance_finding_mappings`** (`policies/nca/seed_finding_mappings.py`,
  20 → 28) tying the new collectors' real observation fields into 2-13-2,
  2-6-2, 2-6-3 (new ground), and reusing 2-15-2/2-4-3 where a device's flaw
  is the same underlying issue as the camera's (default creds, unencrypted
  protocol). Live-verified this is exactly the closure the whole effort was
  for: `GET /nca/devices/{id}/suggestions` now returns real auto-suggested
  FAIL verdicts on 2-13-2 for `device-smartlock` and on 2-6-2/2-6-3 for both
  `device-nvr` and `device-speaker` — the first device-scope evidence either
  NCA subdomain has ever had in this project.
- **Two more real bugs caught live during verification, both fixed on the
  spot with regression tests**: (1) `nmap -sV` genuinely hangs against both
  the Modbus and RTSP fixtures' minimal custom protocol servers, which (like
  many real embedded devices) never respond to a probe they don't recognize
  rather than rejecting it, so nmap's generic version-detection probes wait
  out their full timeout - fixed by dropping `-sV` (the NSE scripts alone
  already identify the service and run in under a second) and adding
  `--script-timeout 10s` as a safety bound, confirmed live on both. (2)
  `_parse_rtsp_probe_observations`'s regex assumed `rtsp-methods` prints on
  two lines (matching `modbus-discover`'s own shape); nmap actually prints it
  on one line (`|_rtsp-methods: OPTIONS, DESCRIBE, ...`), confirmed by
  reading the real command output - the **unit test's own fixture had copied
  the same wrong two-line assumption**, so it passed against fabricated data
  that didn't match reality until this live pass caught it. Both fixes
  verified live afterward: `device-plc-gateway`'s Modbus port now honestly
  reports "open but the discovery script returned no data" (a real, if
  unhelpful, outcome - the pymodbus fixture apparently doesn't answer
  whatever slave-id/function-code `modbus-discover` tries, itself a realistic
  Modbus behavior), and `device-nvr`'s RTSP methods now parse correctly
  (`OPTIONS, DESCRIBE, SETUP, PLAY, PAUSE, TEARDOWN`, `unauthenticated_stream_access: true`).
- **Verified live end to end against a freshly-rebuilt 16-container stack**
  (all 11 original + these 5 new): registered all 5 real devices via the
  API, ran every new collector against its real device, recorded real
  evidence (`EV-2026-08-02-0004` through `-0012`), recomputed NCA
  assessments, and confirmed real auto-suggestions on the target controls
  for all 5. Re-ran `TEST-NET-DISCOVERY`'s real subnet sweep and confirmed
  all 5 new hosts classify as `iot_device` (including via the HTTP-port-80
  fallback for the two UDP-only fixtures, exactly as designed) - `device-nvr`
  and `device-plc-gateway` correctly show their extra TCP ports (554, 502)
  open in the same sweep now that those are in `IOT_SIGNATURE_PORTS`.
  Regression: 337 `policies` tests passing (was ~309, +28 new), 241
  `lab/auditor/api` tests passing (2 pre-existing WeasyPrint failures,
  unrelated), 30 new per-device app tests (8+3+7+7+5) passing on the host
  venv, `tsc -b --force`/`oxlint` clean (same 5 pre-existing warnings — one
  real gap caught here too: `lib/serviceIcons.ts`'s `Record<ServiceType,
  LucideIcon>` doesn't tolerate a partial mapping, so `tsc` correctly failed
  until icons were added for all 4 new types), full Vitest suite still
  271/271. Not yet committed to git.

Before that: **Dashboard overhaul (guided pipeline) — all 13 planned phases COMPLETE
and fully live-verified end to end, 3 real bugs found and fixed in that verification
pass** (2026-08-01). The overhaul itself (Discovery → Devices → Fingerprinting →
SA-IOT Compliance → NCA Compliance → Vulnerability Intelligence → Risk Assessment →
Remediation, sidebar ordered top-to-bottom as the pipeline, cohort-select-and-advance
at every step) was designed and built in a prior session ending 2026-07-31, but that
session's own Phase 13 (final regression + live verification) was interrupted mid-way
by a real Docker networking failure serious enough that the user rebooted the whole
machine — this session picked up from a detailed handoff document
(`handoff.txt`, now deleted per its own closing instruction once folded in here) and
finished exactly the one thing that document said was still missing: a real, live,
browser-driven proof that the new pipeline actually works against live data end to
end, not just against mocks.
- **Design recap** (already fully implemented before this session, only now written
  up here for the first time): the user rejected the old flat 13-item sidebar as
  undiscoverable and asked for a step-by-step guided pipeline where "after device
  discovery you get the ability to either specify all device or some of the devices
  to advance down the pipeline" — the "best of both worlds" between a wizard and this
  project's existing real-permanent-pages architecture. Explicitly rejected cramming
  compliance+risk into one page ("dont make any one page too complicated"), and
  caught a real scope gap during design ("Where is CVE compliance? ... Risk
  Assessment is a whole other thing" — promoted Vulnerability Intelligence, IoTGuard
  Stage 05, out of Device Detail's Firmware card into its own full pipeline phase).
  A device's furthest-reached pipeline phase (`lib/pipeline.ts::devicePipelineStatus()`/
  `furthestReachedPhase()`) is, per this project's standing "never persist a derived
  value" rule, computed live every render from real evidence/verdict/NCA/vuln/risk
  data — no stored "current phase" column anywhere, so re-scanning a device makes
  every page "catch up" automatically. New `pipeline_phase` field on every
  `SCAN_CATALOG` entry (`policies/catalog/scan_tests.py`) drives which tests appear
  on which phase page. New shared `components/pipeline/` modules
  (`DeviceCohortPicker`, `PhaseStatusBadge`, `ScanJobCard`/`useScanJob` extracted
  from the old Run Scan page, `PhaseRunnerCard`, `DeviceVulnerabilityCard`) so
  Fingerprinting/SA-IOT/Vuln-Intel never hand-roll their own "run a test, watch it,
  record a finding" flow. Old `RunScanPage`/`ComingSoonPage` deleted outright once
  every call site had a real replacement page. Full per-phase file list and the
  13-commit history (`1c30969`..`a0104ca`, each prefixed "dashboard overhaul: ") are
  preserved in `ui-overhaul.txt` (the user's own pasted copy of the approved plan,
  committed at `591d674`) rather than repeated here.
- **What this session actually did, in order:** confirmed Docker Desktop was healthy
  post-reboot but the lab stack wasn't running yet; brought it up with the dev
  overlay; re-ran the exact same DNS check the prior session had left failing
  (`getent hosts auditor-database` from inside `auditor-api`) and found the bug had
  survived the full reboot. A deeper live diagnosis this session (raw UDP DNS
  queries sent directly to `127.0.0.11:53`, bypassing `getent`) found something more
  precise than "DNS is dead": the resolver was alive and answering, but with
  **inconsistent per-name behavior** on `internal-network` only (`auditor-database`
  got a clean fast NXDOMAIN, `auditor-api`/`auditor-worker`/`auditor-web` got total
  silence/timeout) — ruling out a host firewall/VPN block (checked, neither present)
  or a stale Windows virtual adapter (checked, only the one expected `vEthernet
  (WSL)`) and pointing at corrupted internal state inside the Docker Desktop engine
  itself. User ran Docker Desktop's Troubleshoot → Clean/Purge data (confirmed first
  via `docker ps -a`/`images`/`volume ls` that every object on the machine belonged
  to this project, current or a stale prior naming iteration, so nothing unrelated
  was at risk) — DNS resolved correctly on the very first `up -d` afterward. Full
  writeup: `docs/errors/032`.
- **A purge wipes named volumes too, which surfaced two more one-time-setup gaps**,
  neither specific to this session's own DNS bug: `lab/README.md`'s documented
  "first-time setup" (cert-init + the mosquitto secure-broker password file) had to
  be re-run against the fresh volumes before `mqtt-broker-secure` would even start;
  and the NCA compliance catalog (81 guidelines + ~20 finding mappings) turned out to
  be seeded **imperatively**, not via `init.sql`/migrations at all
  (`python -m policies.nca.seed_catalog` / `seed_finding_mappings`, run inside
  `auditor-api` since `auditor-worker` has no `psycopg` installed) — the NCA
  Compliance page silently showed "0 controls in catalog" with no error until this
  was run. Neither step is currently mentioned anywhere as needed after a fresh
  Postgres volume specifically (only as "once per clone"); worth a README fix, noted
  but not done this session since it's documentation-only and non-blocking.
- **Full live walk, all real data, nothing mocked**: ran a real Discovery network
  scan (found all 9 real lab hosts, correctly classified), used the bulk-select
  "Register selected (3)" flow for the first time ever against a real backend
  (confirmed a `ConfirmDialog` listing real suggested device ids/IPs, then all 3
  flipped to "Already registered" inline with no page reload) — this flow had only
  ever been unit-tested against mocks before. Advanced the new cohort to
  Fingerprinting via route state, ran a real `nmap -sV -p-` against `device-insecure`
  (172.30.0.5, real telnet/http ports), recorded real findings twice (a genuine
  double-launch, both real jobs, both recorded — not a mistake to hide, evidence is
  append-only). Confirmed the Devices page's furthest-phase badge picked up the new
  evidence live with zero manual refresh. Ran a real 10-credential-pair chained
  `curl` default-credentials test on SA-IOT Compliance (`admin:admin` genuinely
  accepted), recorded the finding, clicked "Recompute verdicts" and got back real
  `SA-IOT-002`/`SA-IOT-003` FAIL verdicts from the actual policy engine. Generated
  real firmware (`generate_firmware.py`, real OpenSSL 1.0.1e / BusyBox 1.19.4),
  uploaded it through the Vulnerability Intelligence page's own upload control (no
  longer on Device Detail, per this overhaul's Phase 9), ran `TEST-FW-MANIFEST`, and
  got back real Grype-scanned CVE data — 77 CVEs for openssl (exactly matching this
  project's own historical expected count from when Grype was first wired in), 24
  for busybox, Heartbleed correctly flagged CISA-KEV-listed. Selected `device-insecure`
  on NCA Compliance's new "Assess a cohort" card and clicked "Assess selected" —
  confirmed a real new browser tab opened to that device's own assessment workspace
  (`window.open`, literally unverifiable via curl, needed a real browser context),
  recorded a real assessment on the auto-suggested-FAIL blocking control `2-15-2`,
  watched the device's readiness flip to `Failed`. Confirmed Risk Assessment's
  7-factor breakdown for `device-insecure` sums to exactly its displayed score (82,
  Critical) from real compliance/CVSS/KEV/criticality/exposure/violation/
  insecure-service inputs. Confirmed Remediation's stub correctly shows only real,
  already-recorded static remediation text for 2 real currently-failing controls,
  with a clear "Not built yet" banner — never fake/previewed AI content.
- **Three real bugs found by this live pass, not by the existing unit tests** (all
  now fixed with regression tests, all three genuinely couldn't have been caught by
  mocked fixtures alone since each depended on how a *real* backend response shapes
  up for a device that exists but has no meaningful history yet):
  1. **`devicePipelineStatus()`'s `risk_assessment` factor was trivially true the
     instant a device was registered.** `GET /risk/devices/{id}`'s `known` flag
     means "this device_id exists in the table," not "an assessment happened" —
     `risk_engine.py` always computes a defensible worst-case score even with zero
     evidence, by design (a never-assessed device must never look safe). Every
     freshly-registered device showed "Risk Assessment" — the *last* pipeline
     phase — as its furthest-reached phase with 0 evidence and 0 verdicts. Fixed in
     `lib/pipeline.ts` to require real signal from an earlier phase too
     (`hasSaIotVerdict || hasNcaAssessment || hasVulnData`) — **deliberately
     excluding fingerprinting**, confirmed by reading `risk_routes.py`'s actual 7
     inputs that none of them derive from `TEST-NET-PORTSCAN`-class evidence at
     all (only from SA-IOT verdicts, NCA assessments, vuln-intel evidence, and
     registration-time `device_services`), so a device with only fingerprinting
     evidence produces the identical risk score to one with none. 3 new
     `pipeline.test.ts` cases lock down both the general rule and the
     fingerprinting-specific exclusion.
  2. **`DevicesPage.tsx`'s `hasSaIotVerdict` counted a `NOT_APPLICABLE` verdict as
     "SA-IOT Compliance reached."** The fleet-wide `POST /verdicts/recompute`
     synthesizes a `NOT_APPLICABLE` placeholder for every device/control
     combination it can evaluate from registered services alone, regardless of
     whether any test ever ran against that device — caught live when running
     recompute for `device-insecure` also silently gave `device-hardened`/
     `device-partial` (0 evidence each) a `NOT_APPLICABLE` verdict, which then
     satisfied the old check and jumped their badges straight to the end of the
     pipeline. Fixed to exclude `NOT_APPLICABLE`, matching the exact same
     principle `nca_compliance`'s own `overall_status !== "not_tested"` check
     already used one line below it. New `DevicesPage.test.tsx` case.
  3. **`SAIOTCompliancePage.tsx` never refetched verdicts after "Recompute
     verdicts" succeeded** — `useFetch(api.verdicts, [])` only ever fetched once
     on mount; the recompute handler called the endpoint and showed a success
     toast, but the page's own "Current verdicts: 0 pass · 0 fail" counter stayed
     frozen at its stale mount-time value even though `GET /verdicts` (confirmed
     via direct curl) already had the real new rows. Fixed with the same
     `refreshKey`-bumped-into-`useFetch`-deps pattern every other mutating page in
     this codebase already uses (`DeviceDetailPage`, `DevicesPage`,
     `DiscoveryPage`, `NCACompliancePage`, ...) — this page was simply missing it.
     New regression test mocks two different `api.verdicts` responses across the
     recompute call and asserts the displayed count actually changes.
- **Verified**: `tsc -b --force` clean, `oxlint` clean (same 5 pre-existing
  warnings), full Vitest suite green at 271/271 (was 266 before this session's 5 new
  regression tests, +1 net after one fixture-collision test was rewritten as an
  isolated per-test mock instead of a shared-fixture addition once it broke an
  unrelated `VerdictsPage` test). Backend untouched this session (all 3 fixes were
  frontend-only) — `policies`/`lab/auditor/api` suites not re-run since nothing
  there changed. Rebuilt and redeployed `auditor-web` three times, once per fix,
  each confirmed live in a real browser via Claude-in-Chrome before moving to the
  next — not batched, so each fix was independently proven against real data before
  trusting the next one. `docs/errors/032` written up for the Docker DNS saga.
  `handoff.txt` deleted per its own closing instruction now that this write-up
  exists.

Before that: **All 4 remaining Week 1 gaps closed — COMPLETE** (2026-07-31). The
task-by-task audit artifact (below) had found 10/10 brief tasks implemented but
flagged 4 narrow gaps at file/line precision. Planned via plan mode (full plan
preserved in the session; every design decision investigated live before being
written down, not assumed) and closed one gap per commit:
- **Gap 1 (test-only)**: `test_generate_verdicts_produces_a_mixed_result_for_device_partial`
  (`policies/engine/test_generate_verdicts.py`) - `device-insecure`/`device-hardened`
  already had a full evidence-to-verdict test against the real 5 controls;
  `device-partial` didn't, closing "one complete assessment test per device profile"
  to 3/3. Real 3-PASS/2-FAIL mix, not a rubber-stamp all-one-way result.
- **Gap 2**: `tls_cert_check.py` now forces a handshake at each of
  TLSv1/1.1/1.2/1.3 and classifies each into `accepted`/`rejected`/`untestable` -
  never conflated to two states. Confirmed live against the real worker image
  before designing this that a real, distinct failure mode exists: this host's
  own OpenSSL 3.5.6 refuses to even offer TLSv1/1.1 client-side (`no protocols
  available`), which is a toolchain limit, not a server signal - an untestable
  version is never reported as unsupported. New
  `observations.protocol_probe`/`supported_tls_versions`/
  `deprecated_tls_versions_supported`, purely additive (existing
  `tls_version`/`weak_cipher`/`cert_expired` untouched, so `SA-IOT-005`'s
  pass/fail condition needed no change). Deliberately **not** folded into that
  condition - `policy_engine.py` only supports single-predicate conditions, and
  extending its grammar is bigger scope than this gap (a collector completeness
  fix, not a controls-engine redesign). `TEST-TLS-CONFIG`'s timeout bumped to 90s.
- **Gap 3**: `collector_versions` on an assessment - derived **live** from the
  assessment's own child `scan_jobs` (`_collector_versions_for_assessment()`,
  a plain `SELECT DISTINCT`), not a new stored column, matching this codebase's
  existing rule for every other rollup (risk score, compliance %, NCA domain
  summary): compute from the current source of truth on read, never a value
  that can drift out of sync. Wired into `GET /assessments/{id}` and
  `POST /assessments`; shown in `DeviceDetailPage`'s assessment-history expand
  panel next to Started/Completed.
- **Gap 4**: two fields the schema/brief named but the automated path never
  populated. `confidence_reason` now auto-fills with a fixed, deterministic
  template (never model-generated) on both `record_scan_job_evidence` and
  `record_scan_job_failure` when the auditor doesn't supply one - `RunScanPage`
  gained an optional "Why this confidence level?" input, `DeviceDetailPage`
  surfaces it as a tooltip. New `report_records` table (migration 009 +
  `init.sql`) is an append-only log of *that* a report was generated - directly
  analogous to the existing `compliance_audit_events` table, never a snapshot
  of report *content* (which stays always-live-computed, same rule as risk/
  compliance scores). Confirmed live via grep before designing this that the 3
  report URLs are only ever plain `<a href>` links, never fetched from JS, so
  this only logs a real human export. New `GET /devices/{id}/report-history` +
  a small "Report history" list on `DeviceAssessmentReportPage`.
- **A real, unrelated bug caught and fixed along the way**: `test_assessments.py`'s
  `client` fixture didn't isolate `DOCUMENT_STORE_DIR` to `tmp_path` the way its
  sibling `test_scan_jobs.py` already does - running it against this real dev
  environment silently overwrote a real evidence file's raw output on disk
  twice during this session (`EV-2026-07-31-0002.txt`, restored from git both
  times). Fixed to match the sibling file's convention.
- **A real, unrelated tooling gap caught and fixed**: `tsc --noEmit` alone had
  been silently checking **nothing** all session (`tsconfig.json`'s root config
  is `{"files": [], "references": [...]}` - project references need `tsc -b` to
  actually run). Switched to `npx tsc -b --force`, the same command this
  project's own `npm run build` script uses, which immediately caught 2 real
  type errors in test fixtures missing the newly-required `confidence_reason`
  field. Fixed. Every future frontend verification in this project should use
  `tsc -b`, not bare `tsc --noEmit`.
- **Verified**: `pytest` across `policies/` (297 passed) and `lab/auditor/api`
  (236 passed, only the 2 pre-existing WeasyPrint gaps failing, unrelated) all
  green; frontend `tsc -b` clean, `oxlint` clean (same 5 pre-existing warnings),
  full Vitest suite green except the one already-known pre-existing
  `RunScanPage.test.tsx` timing flake. Migration 009 applied to the live dev
  Postgres; `auditor-api`/`auditor-worker`/`auditor-web` rebuilt and redeployed.
  **Verified live end to end, all 4 gaps at once**: ran `cert-init` to generate
  real TLS certs (never generated in this dev environment before) and brought
  up `device-hardened` for the first time this session; created a real
  assessment running `TEST-TLS-CONFIG` against its real HTTPS service and
  confirmed the real live response showed `protocol_probe: {"TLSv1": null,
  "TLSv1.1": null, "TLSv1.2": true, "TLSv1.3": true}` (TLSv1/1.1 genuinely
  untestable on this host, not guessed) and real `collector_versions:
  [{"tool": "openssl", "tool_version": "OpenSSL 3.5.6..."}]` on the same
  assessment response; recorded a finding with no explicit confidence_reason
  and confirmed the real auto-filled template came back; hit the real
  report.html/.json endpoints and confirmed `GET .../report-history` returned
  both real generation events. `docs/week1-completion-report.md` and the
  published report artifact's "not yet implemented" list are both now closed.

Before that: **Assessment history UI added to the device detail page — COMPLETE**
(2026-07-31). Prompted by a fresh audit of the mentor's original Week 1 brief
(`week-1-tasks.txt`, the owner added this file to the repo root this session) against
the real codebase — every one of its 10 tasks was verified file-by-file (routes,
migrations, control YAMLs, test files, not just re-reading old changelog claims), and
9 of 10 were already fully done from the 2026-07-22 "Week 1 mentor-brief gap closure"
session and everything built since. The one real, actionable gap found: task 2's
"Assessment history" requirement had full backend support (`GET /assessments?device_id=`
already existed and was already tested) but **no frontend ever called it** — Run Scan
only tracks the single in-flight assessment in local component state, which is lost
the moment you navigate away. Full findings written up in
`docs/week1-completion-report.md`.
- **New "Assessment history" card on `DeviceDetailPage`** — lists every past Assessment
  for the device (worst/newest-first, via the existing list endpoint), each row
  showing its status, policy version, and timestamp; clicking a row expands it in
  place (same `expanded === id` convention `VerdictsPage` already uses) to show its
  child collector jobs, fetched lazily via the existing `GET /assessments/{id}` only
  on first expand and cached in component state so re-expanding never refetches.
- **New shared `AssessmentStatusBadge`** (`severity-badge.tsx`) — the
  queued/running/partially_completed/completed/failed/cancelled status, icon+text
  like every other status badge in this file. Extracted from `RunScanPage`'s own
  local `ASSESSMENT_STATUS_COPY` (now deleted) so the same status never renders two
  different ways across the two pages that show it — the exact "same signal shown
  inconsistently" class of bug this project has fixed several times before (see the
  2026-07-24 dashboard-consistency-pass entry below).
- **`Assessment.jobs` is now correctly optional** in the frontend's own type
  (`types.ts`) — it was typed as always-present, which was simply false for the list
  endpoint's response shape (only `POST /assessments` and `GET /assessments/{id}`
  return `jobs`); `CreateAssessmentResult` narrows it back to required, since that
  endpoint always populates it.
- No backend changes at all — `GET /assessments?device_id=` already existed, already
  filtered correctly, and was already covered by `test_assessments.py`.
- **Verified**: `tsc --noEmit` clean; `oxlint` clean (same 5 pre-existing warnings,
  nothing new); full Vitest suite green except the one already-known pre-existing
  `RunScanPage.test.tsx` timing flake (confirmed independent of this change by
  reproducing it identically on the unmodified code via `git stash`); 3 new
  `DeviceDetailPage` tests (empty state, list rendering, expand-to-fetch-and-cache).
  Rebuilt and redeployed `auditor-web` live; confirmed the new bundle is served
  (content strings present) and drove a real assessment through the real API/worker
  end to end to prove the card against live data, not just mocks: created
  `ASMT-2026-07-31-0001` on `device-insecure` (`TEST-NET-REACHABILITY` +
  `TEST-HTTP-HEADERS`), let the real worker run both collectors, recorded both
  findings, and confirmed the assessment reached `completed` with two real evidence
  rows (`EV-2026-07-31-0001/0002`) - kept, real data, per this project's standing
  convention for verification artifacts created in the dev DB. Claude-in-Chrome
  wasn't connected this session, so this was a curl/API-level live check, not a
  browser screenshot. A full task-by-task re-audit of `week-1-tasks.txt` against
  the codebase (file/line citations throughout, four narrow non-blocking gaps
  found and documented) was written up as a report artifact this same session.

Before that: **Dynamic Risk Assessment (IoTGuard Stage 06) built out fully — COMPLETE**
(2026-07-31). Stage 06 was entirely unbuilt going in — confirmed by a repo-wide grep
before starting: zero hits for risk-scoring code anywhere. Orchestrated as a 7-phase
plan (full write-up in `docs/risk-assessment.md`), agreed with the owner up front on
four decisions that the codebase genuinely couldn't answer on its own: (1) device
criticality/internet exposure — neither existed in the data model, added as
**auditor-set fields with a computed default**, always editable; (2) the risk score's
compliance input uses the **NCA CGIoT-1:2024 score** (the fuller, 81-guideline
framework), not the smaller SA-IOT-\* pilot; (3) violation count combines **both**
compliance engines' failures; (4) UI scope is a **dedicated Risk Assessment page**
(`/risk`), not just summary cards, so a score is never a black box.
- **`policies/risk/risk_engine.py`** — one pure, centralized, unit-tested function
  (`compute_device_risk()`) combining 7 normalized 0–100 "risk contribution" factors
  (compliance, CVSS, CISA-KEV exploit availability, device criticality, internet
  exposure, violation count, insecure-service count) into a weighted score + Low/
  Medium/High/Critical category, matching every other scoring engine's architecture
  in this codebase (`policy_engine.py`, `policies/nca/evaluator.py`,
  `vuln_routes.py`). Every weight/threshold/point-value is a named, tunable
  constant. A never-assessed device scores **maximum** risk on the compliance
  factor, never a neutral/guessed value — absence of proof of compliance is not
  proof of safety, same honesty rule `device_score()` already applies.
- **New `devices.criticality`/`devices.exposure` columns** (migration
  `008-device-risk-fields.sql`), editable via the existing `PATCH /devices/{id}`
  (now finally has a real caller — confirmed via a fresh grep this session that the
  `updateDevice` API client function existed on both ends since an earlier session
  but was never once invoked from any UI). `criticality` defaults `'high'` only for
  a device with an enabled MQTT/MQTTS service, else `'medium'`; `exposure` always
  defaults `'internal_only'` — deliberately **not** inferred from a service's
  `published_port`, since in this lab that reflects host-dev-convenience port
  mapping, not real internet reachability, and claiming `internet_facing` from that
  signal alone would overclaim.
- **New read-only `lab/auditor/api/risk_routes.py`**: `GET /risk/devices` (every
  device, computed live, sorted worst-first — this sorted list *is* the org-wide
  priority ranking), `GET /risk/devices/{id}` (full per-factor breakdown), `GET
  /risk/fleet-summary`. Assembles its 7 inputs entirely by reusing existing
  functions (`nca_routes._evaluator_rows_for_scope` → `device_score()`,
  `vuln_routes._manifest_packages`/`_summarize_packages`, a dedup'd verdicts/
  assessments query) — never reimplements a compliance score or a CVE lookup. Like
  `device_score()` and `vuln_routes._summarize_packages()`, the risk score is
  **never cached or persisted** — computed fresh from current data on every
  request.
- **Dashboard**: new `/risk` page (org-wide priority table, each row expanding in
  place to the full breakdown — matches `VerdictsPage`'s own expand-on-click
  convention), a new `RiskCategoryBadge` component, an Overview "Org-wide risk
  priority" card, a risk badge on the device detail page header, and a new "Risk
  profile" card there letting an auditor set criticality/exposure directly.
- **Report integration**: `report.py`'s `build_report_model()` imports
  `risk_routes.py`'s own computation (never reimplements it) into a new numbered
  section on the PDF/HTML report and a matching card on
  `DeviceAssessmentReportPage`.
- **Verified**: 373 backend (`policies`/`lab/auditor/worker`) + 228
  `lab/auditor/api` (2 pre-existing WeasyPrint gaps, unrelated) + 227 frontend
  tests (1 confirmed pre-existing timing-flake in `RunScanPage.test.tsx`,
  unrelated) all passing; `tsc`/`oxlint` clean (same 5 pre-existing warnings,
  nothing new). Rebuilt and redeployed `auditor-api`+`auditor-web`; confirmed
  **live end to end**: real `/risk/devices/{id}` breakdown for `device-insecure`
  hand-verified against the formula (25 + 0 + 0 + 7.5 + 4 + 0 + 2.5 = risk score 39,
  medium), the live PDF/HTML report and the deployed JS bundle both carry the new
  section/page, and `/risk` resolves via the SPA route.
- **Not done this pass** (documented, not silently skipped — full detail in
  `docs/risk-assessment.md`'s "Known limitations"): the score is self-reported for
  2 of its 7 inputs (criticality/exposure accuracy depends on the auditor keeping
  them current); no feedback loop into compliance verdicts, by design; violation
  count can double-count an issue that fails both compliance engines, by design; no
  historical trend (a natural fit for Stage 10 - Continuous Monitoring, still
  unbuilt).

Before that: **Vulnerability Intelligence (IoTGuard Stage 05) built out fully — COMPLETE**
(2026-07-30/31). Stage 05 was previously a 6-entry hardcoded Python dict
(`policies/catalog/vuln_reference.py`) covering only the two packages this lab's own
synthetic firmware fixtures ship — honest about being an "auditor-aid," not
deployment-ready coverage. Orchestrated as an 8-phase plan (full write-up in
`docs/vulnerability-intelligence.md`), agreed with the owner up front on two decisions:
a **hybrid sourcing model** (scan-time lookups stay 100% local/offline, a separate
scheduled process refreshes the local snapshot — preserving this project's "evidence
must be reproducible" rule) and **package/component-level scope only** (device-level
vendor/model CPE matching deferred). A live spike then found something that changed
the shape of the whole plan for the better: the worker image already installs **Grype
and Syft** (named in the original Day-2 brief) but neither was ever actually invoked —
Grype's own local, versioned, offline-refreshable vulnerability database *is* the
hybrid model this task called for, already built. Wired Grype in instead of hand-rolling
an NVD API client and new Postgres tables.
- **Grype wired into `TEST-FW-MANIFEST`**: new `sbom.py` translates a firmware
  manifest's package list into a CycloneDX SBOM Grype can scan (a small
  hand-verified `CPE_OVERRIDES` table covers components where Grype's default
  purl-synthesis under-matches, confirmed live); `firmware_check.py` runs
  `grype sbom:... --add-cpes-if-none` and summarizes the match JSON;
  `scan_tests.py` merges Grype's result with the static table with a clear
  priority (Grype → static table → honest "no data"), fixing a real gap found
  while writing this: a package Grype genuinely checked and found clean must
  say so, not fall through to a "not checked" message. Real coverage jump,
  confirmed live: openssl 1.0.1e went from 2 known CVEs (static table) to 77
  (Grype); busybox 1.19.4 from 0 to 24.
- **Grype's local DB persists and auto-refreshes**: a new `grype-db-data` Docker
  volume + a low-frequency staleness check in `job_runner.py`'s existing poll
  loop (`maybe_refresh_grype_db`). **Caught a real bug live**: the first version
  compared Grype's own "Built" field (when Anchore published their upstream
  snapshot) against wall-clock time, which is *always* stale by real-world
  standards and would have re-attempted an update every single check forever —
  fixed by tracking refresh success via a local sentinel file instead, confirmed
  live across multiple real restarts spanning 20+ minutes that the throttle now
  holds correctly.
- **CISA KEV cross-reference**: new `cisa_kev.py` fetches and caches CISA's real
  published KEV feed (1656 entries, confirmed live); every Grype-resolved CVE
  gets tagged `kev_listed`/`kev_date_added`, sorted first within its package's
  CVE list. Confirmed live that CVE-2014-0160 (Heartbleed) is genuinely
  KEV-listed. **Caught and repaired a real, unrelated incident during this same
  live pass**: Grype's local DB had been corrupted (likely from a container
  restart interrupting a write during the same day's earlier Docker-networking
  recovery) — the existing three-tier fallback handled it exactly as designed
  (silent fallback to the static table, no crash, no fabricated data) until the
  DB was manually repaired.
- **New read-only API surface** (`lab/auditor/api/vuln_routes.py`): `GET
  /vuln-intel/status` (which DB snapshot the most recent scan used, sourced from
  evidence since the API has no access to the worker's filesystem),
  `/vuln-intel/fleet-summary` (worst-first by device), `/vuln-intel/devices/{id}`
  (one device's full advisory list). Set up this session's first host-side
  Python test environment (`.venv` + the `C:\work` junction, same pattern
  documented in the 2026-07-21 entry below) since `lab/auditor/api`'s test suite
  needs a real ephemeral Postgres the worker container's minimal image doesn't
  support.
- **Dashboard UI** (previously nothing rendered this data at all — confirmed no
  existing component ever read `outdated`/`eol`/`cves` from a package advisory):
  a new `KevBadge` (`components/ui/severity-badge.tsx`, same tooltip-explained
  pattern as `BlockingBadge`); `VulnAdvisoryPanel` (the real per-package CVE
  list, KEV-listed sorted first, capped with a "+N more" indicator) and
  `VulnFreshnessNote` (since this data is snapshot-based, unlike the rest of
  this app's evidence); wired into Overview (a new "Vulnerability intelligence
  by device" card), the device detail page's Firmware card, the consolidated
  `DeviceAssessmentReportPage`, and the server-rendered PDF/HTML report
  (`report.py` imports `vuln_routes.py`'s own rollup function rather than
  reimplementing it, so the report and dashboard can never disagree).
- **Verified**: 333 backend (`policies`/`lab/auditor/worker`) + 9 new
  `test_vuln_routes.py` + 3 new report tests + 214 frontend tests (35 files, was
  193) all passing; `tsc`/`oxlint` clean (same 5 pre-existing warnings, nothing
  new). One real test bug caught and fixed: a `DeviceDetailPage` test asserted
  synchronously on `VulnFreshnessNote`'s content, which fetches independently of
  the page's own data load — a genuine race (reproduced consistently in
  isolation), fixed by awaiting it properly and confirmed clean across 5 repeat
  runs. Rebuilt and redeployed `auditor-api`+`auditor-web`; confirmed **live end
  to end through the real production pipeline**, not just against a test
  database: registered a throwaway device, uploaded real firmware, ran a real
  `TEST-FW-MANIFEST` scan job, recorded the resulting evidence, and confirmed
  `/vuln-intel/status`, `/vuln-intel/fleet-summary`, the live PDF/HTML report,
  and the deployed JS bundle all served the real Grype+KEV data end to end
  (101 CVEs, 1 KEV-listed) — then cleaned up every throwaway artifact
  afterward, including one incidental discovery: host-side pytest runs that
  exercise evidence-recording endpoints write real raw-output files into the
  real `document-store/raw/` directory (via the `/work` → `C:\work` junction),
  even though the database side is fully isolated to an ephemeral test
  Postgres — noted in `docs/vulnerability-intelligence.md` for future sessions.
- **Not done this pass** (documented, not silently skipped — full detail in
  `docs/vulnerability-intelligence.md`'s "Known limitations"): device-level
  vendor/model CPE matching (deferred per the up-front scoping decision);
  `TEST-NET-HTTP-INSPECT` isn't Grype-backed (stayed on the small static table —
  wiring it in would have required breaking the pure-parser convention every
  other collector in `scan_tests.py` holds); EPSS scores (absent from the pinned
  Grype version); any verdict-logic change (a KEV-listed finding doesn't
  auto-flip a verdict, matching this project's "tool-assisted, not
  tool-decided" rule); DB corruption is only caught by the natural refresh
  cycle, not actively detected.

Before that: **Five owner-requested features — all COMPLETE** (2026-07-30),
worked as a loop. (1) **Default-creds scan label** cleaned up — dropped the
misleading "(admin/admin)" suffix from `TEST-AUTH-DEFAULT-CREDS`'s label (the
scan actually tries 10 pairs); scan still tries admin:admin. (2) **Verdicts
page filters** — added severity and device dropdowns alongside the existing
status tabs (status-tab counts now reflect the severity+device selection);
`VerdictsPage.tsx`. (3) **Per-control verdict assessment on the device page** —
new `POST /devices/{id}/controls/{control_id}/assess` (deterministic policy
engine over the device's real evidence, always records a fresh verdict; 400
with the required test ids when applicable-but-no-evidence, NOT_APPLICABLE
when the control can't apply); a control-picker + "Assess verdict" panel in
the device detail Verdicts card. **The severity is the auditor's choice** —
the endpoint accepts an optional `{"severity": low|medium|high|critical}`
(a risk judgement about this device's context, not something the evidence
decides); the panel has a severity dropdown that defaults to the control's
catalogued severity. The pass/fail *status* stays evidence-computed. (4) **Consolidated per-device assessment
report** — new `DeviceAssessmentReportPage.tsx` (`/devices/:id/assessment`)
compiling profile+inventory, services, firmware, NCA readiness, verdicts, and
evidence into one printable page with PDF/HTML/JSON download (reuses the
existing `report.*` endpoints) + a "View assessment" entry point on the device
page. (5) **Web-based scan console** — new `ScanConsolePage.tsx`
(`/scan-console`, sidebar under Assessment): a terminal-style runner that is
**deliberately not a shell** — it only understands `scan`/`list`/`help`/`clear`
and its sole action is `createScanJob(device, test)`, which auditor-api
re-validates against the fixed `SCAN_CATALOG` whitelist before the worker runs
an argv-list command; unknown input is rejected client-side too, so the
security boundary is unchanged.
- **Verified**: `tsc`/`oxlint` clean; new backend suite (6 assess-endpoint
  tests) + 14 verdict tests + 91 `policies/catalog` + 50 API regression tests
  pass; 45 frontend tests across the 5 touched/new page suites pass (incl. a
  console test asserting an unknown command never calls the API, and
  verdict-filter/assess/assessment-report coverage). Rebuilt/redeployed
  `auditor-api`+`auditor-web`; confirmed live: the label is now "Default
  credentials", the assess endpoint computed a real SA-IOT-002 FAIL from real
  evidence, and `/devices/:id/assessment`, `/scan-console`, `/verdicts` all
  serve with the new UI strings in the bundle. Browser-based visual check not
  performed (Claude-in-Chrome not connected). One valid verdict
  (`VD-2026-07-30-0001`, SA-IOT-002 FAIL) was created in the live DB during
  assess verification — real, correct data, kept (verdicts are append-only by
  design).

Before that: **Firmware upload now accepts `.zip` (not just `.tar.gz`) end to
end — COMPLETE** (2026-07-27). The owner reported "I cannot upload a
firmware"; first pass broadened the file picker's `accept` filter
(`docs/errors/030` — Windows greys out compound-extension `.tar.gz` files),
but the real blocker was that their archive was a `.zip` (what Windows'
right-click "Compress" produces) and the whole firmware pipeline hardcoded
`tarfile` (`docs/errors/031`). Added native zip support: new
`lab/auditor/worker/firmware/archive_reader.py` (`open_archive()` detects
gzip vs zip by **magic bytes**, yields a uniform member interface with bounded
reads, preserving the existing zip-bomb caps); `scan_firmware.py` and
`scan_scripts/firmware_check.py` refactored to iterate it instead of calling
`tarfile` directly; the API accepts `.zip`, validates by magic bytes (tar
**or** zip, rejecting unsafe member paths in both), and stores under a
format-neutral `{device_id}.archive` name (original filename kept only for
display); both firmware `<input accept>` filters + helper text updated.
**Verified**: 27 worker firmware tests (tar+zip parametrized) pass in the
container, 13 API firmware-upload tests + 22 scan-job tests pass, 6
`archive_reader` unit tests pass on the host, `tsc` clean, touched frontend
tests green; rebuilt/redeployed api+web+worker and confirmed **live end to
end** — uploaded a real `.zip`, ran `TEST-FW-MANIFEST`, and the worker read
the zip, parsed `manifest.json`, and produced real OpenSSL 1.0.1e
Heartbleed/CCS CVE observations.

Before that: **NCA Compliance reorganized into an auditor-usable assessment
workspace, with auto-verdict suggestions — COMPLETE** (2026-07-27). The owner
asked to "improve and modify the NCA Compliance section and make it like a
real assessment and organized so any auditor can use it." A scoping question
settled the direction: **reorganize the existing (already feature-rich)
module** for a clearer auditor flow — not a rebuild — and **auto-verdict where
possible** (mapped automated evidence pre-fills a suggested verdict the
auditor confirms in one click). The real gap found on inspection: assessing
was *scattered* — the per-device control checklist existed (device detail →
Compliance tab), but every "Assess" link navigated **away** to a control
page, so an auditor bounced back and forth and lost their place; there was no
single workpaper.
- **New per-device assessment workspace** (`pages/DeviceAssessmentPage.tsx`,
  route `/nca-compliance/devices/:deviceId`) — the workpaper. Device header +
  overall status + readiness badge + a **progress bar** (X of N controls
  assessed, where a `not_tested` placeholder still counts as *not* assessed),
  every applicable device-scope control **grouped by domain**, and an inline
  **Record/Retest button per row that opens `RecordAssessmentDialog` in place**
  (no navigation — the auditor works straight down the list). Filter tabs:
  All / Unassessed / Failing / Has suggestion, each with a live count.
- **Auto-verdict** (`GET /nca/devices/{id}/suggestions`, new endpoint in
  `nca_routes.py`): for each device-scope control that this device's real
  automated scan evidence maps to, a suggested status. Rows show a
  "suggests FAIL" chip; clicking Record pre-fills the dialog's status,
  evidence ids, and test method (a new `suggestion` prop on
  `RecordAssessmentDialog`, shown behind a "Suggested from automated
  evidence" banner) — the auditor still confirms or overrides and records the
  finding. **Verdict polarity is honest**: every existing finding mapping
  fires precisely on an *insecure* condition, so a match cleanly implies a
  suggested `fail`; the 3 mappings that only surface "relevant evidence for
  manual review" (update-script/manifest present, banner discloses framework)
  suggest `review_required` instead. Absence of a matching mapping is **never**
  reported as a pass (a test may simply not have run) — the project's
  "AI-assisted, not AI-decided" rule, preserved.
- **`verdict_hint` column** on `compliance_finding_mappings` (migration
  `007-nca-finding-mapping-verdict-hint.sql`, added to `init.sql` for fresh
  volumes, seeded in `seed_finding_mappings.py`) makes that polarity explicit
  and **configurable in the same table** rather than hardcoded in the API.
  A new `map_evidence_to_mappings()` in `policies/nca/finding_mappings.py`
  returns the full matched mappings (not just control_ids), with the existing
  `map_evidence_to_controls()` kept as a thin wrapper so there's exactly one
  evidence-matching path.
- **Entry points wired in** (the reorg): the NCA Compliance device table
  gained a prominent **"Assess"** button per row into the workspace, and the
  device detail Compliance tab gained an **"Open assessment workspace"**
  button. Nothing removed — the control-detail and org pages still work
  exactly as before.
- **Verified**: `tsc --noEmit` clean; `oxlint` clean (no new warnings — the
  new page's two initial exhaustive-deps hints were fixed by memoizing
  `controls`/`suggestions`); 6 new backend suggestions tests +
  finding-mapping/evaluator suites green (37/38 NCA API tests pass — the 1
  failure is the pre-existing WeasyPrint/libgobject native-library gap on this
  Windows host, unrelated; 82/82 `policies/nca`); 15 new/updated frontend
  tests green (6 `DeviceAssessmentPage` + 2 new `RecordAssessmentDialog`
  suggestion cases). Full frontend suite showed 10 failures under the host's
  parallel-runner load — all confirmed **flakes**, not regressions, by
  re-running the touched + failing files with `--no-file-parallelism` (64/64
  pass in isolation). Applied migration 007 to the live DB, rebuilt and
  redeployed `auditor-api`/`auditor-web`; confirmed the live suggestions
  endpoint returns real auto-verdict data for `device-insecure` (Telnet-open →
  2-15-2, default-creds/api-key → 2-2-2, etc., each with real evidence ids),
  the SPA route resolves, and the new UI strings are in the served bundle.
  Browser-based visual verification was **not** performed (Claude-in-Chrome
  not connected this session) — noted rather than claimed.

Before that: **Network Map topology made collision-proof at any device count —
COMPLETE** (2026-07-26). The owner flagged that the Network Map's node layout
(built the same day, see the phase below) needed to guarantee "each device
should have its own space without conflict" as more devices get registered,
not just look fine for the current 6-device fleet. The original `scatter()`
placed each node via up to 40 attempts of deterministic-hashed jitter within
a **fixed-size** zone, rejecting a candidate spot only if it landed within
`MIN_DIST` of an already-placed node — a real, if unlikely-in-practice,
failure mode: once enough nodes are packed into that fixed area, all 40
attempts can land too close to something, and the code fell back to using
that too-close position anyway, visually overlapping two nodes.
- **`components/network/NetworkGraph.tsx`'s `scatter()` replaced with
  `gridPlacement()`** — deterministically tiles each zone's width into a
  grid sized to give every id its own cell (`cols` chosen from the zone's
  fixed width and a `CELL_SIZE` floor; `rows = ceil(count / cols)`, so the
  grid always has enough cells for however many ids it's given), then
  jitters each id within its own cell, bounded well inside the cell's
  margins so adjacent cells' jitter ranges can never overlap. This is a
  structural guarantee (like the existing MST-based edge algorithm it sits
  alongside, kept unchanged), not a tuning knob — verified with a standalone
  script across device counts from 1 to 150 that minimum pairwise node
  distance never drops meaningfully as the fleet grows (stays ≈100+ units
  throughout, vs. the old algorithm's unbounded worst case of ~0).
- **The canvas grows to fit, instead of cramming more nodes into a fixed
  box**: `VIEW_H` is now computed per render from whichever zone needs more
  grid rows (`Math.max(auditGrid.rows, backendGrid.rows)`), and the
  container's aspect ratio is set via an inline `style={{ aspectRatio }}`
  matching that computed height instead of the previous fixed
  `aspect-square sm:aspect-[16/10] xl:aspect-[16/9]` Tailwind breakpoints —
  otherwise a taller SVG viewBox squeezed into a fixed-aspect-ratio box would
  just visually squash the new rows rather than actually showing them with
  room to breathe. For the current real 6-device/4-infra fleet this
  computes to the exact same 560-unit height as before — verified by hand,
  so there's no visual regression for the fleet size the page ships with
  today; the growth path only engages once there are enough nodes to need it.
- **Verified**: `tsc --noEmit` and `oxlint` clean (same 2 pre-existing
  `only-export-components` warnings as before, nothing new); full Vitest
  suite green (no test files exist for this feature, per the original
  handoff document's explicit, stated gap); rebuilt and redeployed
  `auditor-web`, confirmed via a content-hash/size diff against the previous
  build that the new bundle was actually served (browser-based visual
  verification wasn't possible — Claude-in-Chrome still not connected this
  session).

Before that: **Network Map page added — COMPLETE** (2026-07-26). The owner supplied
a self-contained handoff document (`HANDOFF-NETWORK-MAP-FEATURE.md`, delivered via
Telegram from a separate session/laptop where the feature had already been
designed and iterated on three times, on a branch never merged/pushed) and asked
to execute it verbatim in this clone. Verified the handoff's every claimed
precondition against this repo's real files before writing anything (`Device`/
`DeviceTier`/`VerdictRecord`/`ServiceType` shapes, `api.devices`/`api.verdicts`,
`useFetch`, `serviceIcon`, `Shell`, `ErrorState`/`EmptyState`, `Skeleton`,
`StatTile`, `Card`/`CardHeader`/`CardTitle`/`CardContent`, the `NAV_GROUPS` sidebar
structure, the `App.tsx` route list, `index.css`'s `@layer utilities` block) —
everything matched exactly, so the spec's exact code was used unmodified rather
than adapted.
- **New `/network-map` page** — a live topology view of the real lab, not a
  decorative diagram: two zone boxes (`AUDIT NETWORK`/`BACKEND`) mirroring
  `lab/docker-compose.yml`'s actual two Docker networks (`audit-network`, where
  every device plus `auditor-worker`/`traffic-capture` sit, and `internal-network`,
  `internal: true`/no route out, where `auditor-api`/`auditor-database` sit),
  with `auditor-worker` as the one explicit cross-zone bridge edge — the only
  service with a leg in both networks.
- **`components/network/NetworkGraph.tsx`** (new) — deliberately **not**
  hub-and-spoke. The handoff document's own history explains why: a first
  attempt (every device wired to one central "Gateway" node) was rejected by the
  owner outright ("the design actually bad, it is not like a network, like a
  star"), and a second attempt that kept the same shape but added jitter/curves
  to disguise it still read as a star, since the problem was structural (one
  node touching every other node), not cosmetic. The shipped version scatters
  each zone's nodes semi-randomly (deterministic hash-based jitter, stable across
  re-renders) and connects them with a **Minimum Spanning Tree** (Prim's
  algorithm) computed per zone, which structurally guarantees no node can have
  universally high degree — not a tuning knob, an inherent property of the
  algorithm. Clicking a device or infra node dims every non-adjacent edge and
  swaps the side panel between fleet overview / device detail (posture, host,
  evidence/verdict counts including live FAIL counts from `/verdicts`, exposed
  services) / infra detail.
- **`components/ui/card.tsx`** gained a small, additive `CardDescription` export
  (the one existing piece of shared infrastructure the feature needed that
  wasn't already there) — every other file the feature depends on already
  existed with a matching shape, confirmed by reading each one before writing
  any new code, not assumed from the handoff doc's own table.
- Route (`/network-map`), sidebar entry (Monitoring group, right after
  "Devices"), and the `animate-network-dash` scrolling-dash keyframe (nested into
  `index.css`'s existing `@layer utilities` block, respecting
  `prefers-reduced-motion`) added exactly as specified.
- **No new automated tests** — an explicit, stated gap in the handoff document
  itself ("a known gap, not an oversight to silently fix by inventing test
  content beyond what's asked"), respected as-is rather than overridden with
  this project's usual per-page test convention, since the document's author
  had already made and documented that call.
- **Verified**: every Step 1 precondition confirmed against real files first;
  `tsc --noEmit` clean; `oxlint` clean (2 new `only-export-components` warnings
  in `NetworkGraph.tsx` for exporting `TIER_LABEL`/`INFRA_NODES` alongside the
  component - the same pre-existing, already-tolerated warning class this
  codebase already has in `useToast.tsx`/`NetworkDiscoveryPanel.tsx`, not a new
  problem); full Vitest suite green (2 unrelated pre-existing environment flakes
  - `RunScanPage.test.tsx`'s known timing-dependent test and a
  `RecordAssessmentDialog.test.tsx` worker-pool timeout under this host's
  parallel-runner load - both confirmed passing 100% in isolation, and neither
  touches anything this feature added, since it has no test files of its own).
  Rebuilt and redeployed `auditor-web` live; confirmed via curl that the
  deployed bundle contains the new page's strings, `GET /network-map` resolves
  via the SPA fallback, and the live `/devices` endpoint returns the real
  6-device fleet the graph renders against. Browser-based visual verification
  (zone boxes, click-to-inspect, dimming) was **not** performed this session -
  the Claude-in-Chrome extension was not connected - noted here rather than
  claimed.

Before that: **NCA Compliance dashboard + overall UI/UX consistency pass — COMPLETE**
(2026-07-24). The owner asked to "improve the dashboard of the NCA Compliance
and the overall UI/UX." A fresh audit (not a repeat of the 2026-07-22
"Dashboard UX/UI improvement pass" below, which already shipped the NCA
dashboard's gauge/chart/attention-panel/reports and the site-wide toast/404/
responsive-sidebar baseline) found a different, newer class of problem: UI
elements added incrementally across several sessions (the readiness
classification, the `blocking` flag, `review_required`, the legacy per-device
compliance chip, the org-scope page) now showed **the same underlying
information inconsistently across pages** — two different-looking
"compliance %" gauges that read as the same metric, badges of mismatched
size for the same signal, a chart silently dropping a status category its
own sibling view still counted, and identical domain-summary markup
copy-pasted three times (exactly how the chart/card mismatch went
unnoticed). Fixed as a scoped, incremental pass — dark theme + amber accent
unchanged, the two legitimately-different compliance formulas (SA-IOT-*
verdict math vs. NCA CGIoT-1:2024 control math) deliberately **not** merged,
only made visually distinguishable:
- **`components/nca/DomainSummaryGrid.tsx`** (new) — the domain-summary count
  grid extracted from 3 near-verbatim copies (`NCACompliancePage.tsx`,
  `OrganizationalCompliancePage.tsx`, `DeviceDetailPage.tsx`'s Compliance
  tab), so all 5 statuses (including `review_required`) can no longer drift
  out of sync between pages the way they had.
- **`NCADomainBarChart.tsx`** now plots `review_required` as a 5th stacked
  segment (`CHART_COLORS.low`, not `.brand`/`.medium` — confirmed those two
  are byte-identical hex values, which would have visually fused it into the
  `partial` segment).
- **`ComplianceGauge.tsx`** gained an optional `sourceLabel` prop and both
  gauge cards were renamed to be self-explanatory ("Verdict Pass Rate" on
  Overview vs. "NCA Control Pass Rate" on NCA Compliance) instead of relying
  on a small caption to differentiate two identical-looking gauges measuring
  different things.
- **`severity-badge.tsx`**: `NCAReadinessBadge` gained a `size` prop (`sm`
  now matches `NCAStatusBadge`'s own dimensions exactly, used in
  `NCACompliancePage.tsx`'s device table so Readiness no longer visually
  dwarfs Status in the same row — Score is now folded inline into that same
  cell instead of a separate column); new `BlockingBadge` component
  (replacing two near-duplicate inline chips) explains itself via the new
  `Tooltip` primitive instead of a native `title` attribute, and now appears
  on `DeviceDetailPage.tsx`'s and `OrganizationalCompliancePage.tsx`'s
  per-control rows too — the `blocking` signal previously only reached
  `NCAControlsPage.tsx`/`NCAControlDetailPage.tsx`, not the device/org views
  where a Failed readiness's *cause* actually needs to be visible.
- **`components/ui/tooltip.tsx`** (new) — this app's first tooltip
  component; every prior non-trivial explanation relied on a native `title`.
  Built with both a visible border and a shadow (not border alone), since
  `--color-surface-raised` and `--color-surface` are the identical `#ffffff`
  in the light theme.
- **`DeviceDetailPage.tsx`**'s header previously showed a legacy
  `ComplianceBadge` (the older SA-IOT-*-verdict-based metric, labeled with
  the dynamic `compliance.framework` string, which happens to read
  "NCA-CGIoT") on *every* tab, including the Compliance tab, sitting directly
  above the real NCA readiness card. Now hidden on the Compliance tab and
  relabeled from `{compliance.framework}:` to static "Automated scan
  coverage" text, explained via `Tooltip` as a separate, older metric.
- **`VerdictsPage.tsx`** migrated its hand-rolled status-filter pill row to
  the shared `Tabs` primitive (now shows per-status counts, matching the
  pattern `NCACompliancePage.tsx`/`DeviceDetailPage.tsx` already used for
  the identical UX goal).
- **`OrganizationalCompliancePage.tsx`** finally has a real sidebar nav entry
  (`Sidebar.tsx`'s Compliance group) — previously reachable only via an
  inline text link inside `NCACompliancePage.tsx`'s disclaimer banner.
- **Not done this pass** (deferred, documented rather than silently
  skipped): a device-table/attention-panel blocking indicator on
  `NCACompliancePage.tsx` itself needs a small backend addition
  (`GET /nca/devices` only returns `readiness_classification`, not the
  `blocking_control_ids` `overall_classification()` already computes) — out
  of scope for a frontend-only pass; wider adoption of
  `--color-surface-raised` on every `Card` (cosmetic-only); merging the two
  compliance formulas (deliberately out of scope — they measure different
  things).
- **Verified**: `tsc --noEmit` clean, `oxlint` clean (no new warnings), full
  Vitest suite green (2 unrelated pre-existing environment flakes confirmed
  independent of this work by re-running in isolation — `RunScanPage.test.tsx`'s
  known timing-dependent test, and a `severity-badge.test.tsx` worker-pool
  timeout under this host's parallel-runner load, both 100% green alone).
  Rebuilt and redeployed `auditor-web` live; confirmed the deployed JS bundle
  contains every new UI string and confirmed live `/nca/controls` data has
  real `blocking: true` rows for the new badges to render against.

Before that: **NCA compliance-assessment robustness pass — COMPLETE** (2026-07-24).
The owner asked (as a senior full-stack/IoT-security/compliance-architect brief) to
inspect the existing project and add a "robust automated compliance-assessment
feature" — not a rebuild: an earlier, much larger scope-conflicting prompt asking
for a full Next.js/Prisma/BullMQ greenfield rebuild was surfaced back to the owner
via a clarifying question (it contradicted this same file's already-documented
"deferred, do not start" decision on a production rebuild) and the owner replied
with this smaller, correctly-scoped one instead. Inspection found the module (see
the phase below) already had the full data model, a centralized evaluator, and a
now-real dashboard UI — genuinely missing were the specific mechanics the brief
named: an explicit Passed/Partially-Passed/Failed **readiness classification** that
doesn't rely on percentage alone, a **blocking-condition** concept, a real
**`REVIEW_REQUIRED`** status, and an **auditor-override** workflow with mandatory
justification. All four added additively — every existing endpoint, UI flow, and
field keeps working unchanged.
- **`overall_classification()`** (`policies/nca/evaluator.py`) — Passed (score
  ≥85%, no critical failure, no blocking condition, no mandatory control
  `NOT_TESTED`/`REVIEW_REQUIRED`) / Partially Passed (50-84.99%, or a high score
  offset by a critical failure/untested/review-required mandatory control) /
  Failed (below 50%, or a blocking control failed, or nothing has ever been
  assessed) — thresholds configurable, reuses `device_score()`/`has_blocking_failure()`
  rather than duplicating the math, and sits alongside (never replacing)
  `device_overall_status()`/`device_score()`, which the existing dashboard keeps
  using exactly as before. Returned as `readiness` on `GET /nca/devices/{id}` and
  `/nca/organization`, and `readiness_classification` on each `GET /nca/devices` row.
- **`blocking`** — a new `compliance_controls` column, authored the same way
  `severity`/`scope_type` already are (`policies/nca/build_catalog.py`'s
  `BLOCKING_GUIDELINES` set — real NCA guideline text has no literal technical
  trigger phrases, confirmed by searching the live catalog before deciding this had
  to be IoTGuard's own judgment call, not NCA's). Limited to 3 guidelines matching
  the brief's own worked examples: `2-2-2` (default/hard-coded credentials),
  `2-4-3` (unencrypted sensitive data), `2-15-2` (unnecessary/insecure exposed
  services, e.g. Telnet). A failure here forces `readiness` to Failed regardless
  of score.
- **`review_required`** — a real sixth assessment status (DB CHECK constraint +
  evaluator + `_validate_assessment_payload`), distinct from `not_tested`: an
  assessment *was* recorded but needs a human to look again (e.g. conflicting
  evidence, mirroring `policies/engine/conflict.py`'s existing precedent). Rolls
  into the existing PARTIAL bucket for `device_overall_status` but blocks a Passed
  readiness classification on its own.
- **`POST /nca/assessments/{id}/override`** — mandatory `justification` +
  `overridden_by`, optional `original_status` (rejected with 400 if stale — the
  assessment changed since the auditor loaded it). Never mutates the original row:
  inserts a new superseding assessment through the same audit-trail mechanism
  `retest` already uses, so the original result and the override both stay
  permanently visible in the control's audit trail. New
  `components/nca/OverrideAssessmentDialog.tsx` + an "Override" button next to
  "Retest" on `NCAControlDetailPage`.
- **Migration**: `lab/auditor/db/migrations/006-nca-blocking-and-review-required.sql`
  (idempotent — `blocking BOOLEAN DEFAULT false` column, `review_required` added to
  the status CHECK constraint).
- **Tests**: 21 new `policies/nca/test_evaluator.py` cases (blocking failure
  detection, all 9 named classification scenarios from the brief — high score +
  critical failure, blocking condition at high score, all-not-applicable, nothing
  ever tested, configurable thresholds, etc.) + 15 new `lab/auditor/api/test_nca_routes.py`
  cases (readiness wiring, `review_required` accepted/rejected, override
  success/missing-justification/missing-identity/404/stale-original-status) + 5 new
  frontend `OverrideAssessmentDialog.test.tsx` cases. 82 `policies/nca` + 205
  `lab/auditor/api` (only the 2 pre-existing WeasyPrint-native-library gaps on this
  Windows host fail, unrelated) + 158 frontend tests passing (full-suite frontend
  runs occasionally show unrelated timeout flakiness under this host's parallel
  test-runner load — confirmed by re-running the same files in isolation and with
  `--no-file-parallelism`, both 100% green; not a regression from this work).
- **Not done this pass** (documented rather than silently skipped, since the
  brief's scope was large): per-scope configurable pass/partial thresholds stored
  in the DB (currently function parameters with sensible defaults, not yet a
  per-framework-version DB setting); a dedicated assessment-snapshot table capturing
  control definitions/weights at assessment time (the append-only
  `compliance_assessments` + never-mutated `compliance_controls` history already
  gives every past assessment's control text as of when the guideline itself last
  changed, but a literal weights/thresholds snapshot column doesn't exist yet);
  rate limiting and RBAC (this application has no login system anywhere, a
  pre-existing, explicitly documented limitation this pass didn't change). Full
  detail in `docs/nca-compliance.md`'s new "Compliance readiness classification"
  and "Auditor override" sections.

Before that: **NCA Compliance module made real, not a prototype — COMPLETE**
(2026-07-23). The owner's own words: "make it real, not just prototype...
if you automate it, go for it." A full audit of the existing module (built
earlier this project, 6 tables, 81 real guidelines, a centralized evaluator,
~25 API endpoints, all already unit- and API-tested) found the actual gap
was **entirely on the frontend**: every write endpoint that lets a human
record a real compliance judgment existed and worked, but nothing in
`lab/auditor/web/` ever called them. `grep`-confirmed zero UI usages of
`createNcaAssessment`, `retestNcaAssessment`, `createNcaException`,
`approveNcaException`, `rejectNcaException`, `recomputeNcaAssessments`, or
even `ncaControls` (the full-catalog list). In practice this meant: the
only way `compliance_assessments` ever got a row was a one-off seed script
(`seed_demo_assessments.py`), and the 60+ organization-scope guidelines
(governance, mobile, supplier, cloud domains) had **no path to ever being
assessed at all** through the actual product — a compliance tool that can't
record a compliance judgment isn't real, it's a read-only viewer for
script-seeded data. Closed with pure frontend work (zero backend/schema
changes needed — every endpoint, type, and validation rule was already
correct):

- **`components/nca/RecordAssessmentDialog.tsx`** — the one write path for
  both a new assessment and a retest, adapting to the control's own
  `scope_type` (device picker vs. the fixed "default" organizational scope,
  never letting the user pick wrong). Wired into `NCAControlDetailPage`
  ("Record assessment" + a "Retest" button per current assessment),
  reachable with the device pre-selected via a new `?device_id=` query
  param from `DeviceDetailPage`'s Compliance tab and
  `OrganizationalCompliancePage`'s controls list (both gained an
  "Assess"/"Retest" link per control row).
- **`components/nca/RequestExceptionDialog.tsx`** + a new **Exceptions**
  card on `NCAControlDetailPage` — request an exception, and approve/reject
  any pending one inline (gated behind typing a reviewer name first, same
  "reviewer identity, not real auth" convention this whole module already
  established).
- **`pages/NCAControlsPage.tsx`** (`/nca-compliance/controls`, new nav
  entry) — the full 81-guideline catalog, browsable and filterable by
  domain/scope, previously only reachable one control at a time through a
  device's or the org page's own (scope-limited) controls list.
- **A "Recompute from evidence" button on `NCACompliancePage`** —
  `POST /assessments/recompute` (matches real scan evidence against
  `compliance_finding_mappings`, creates `not_tested` placeholders, human
  still records the real finding — never an auto-decided verdict) existed
  since this module was built but had no UI trigger anywhere.

**Verified live against the real dev stack**, not just unit-tested (27 new
frontend tests cover the logic, but the live pass is what actually proves
"real"): recorded a genuine `pass` assessment on a real governance control
(`1-1-1`, "Cybersecurity Strategy" — previously unassessable through the
product at all, screenshotted), retested it and confirmed the prior
assessment flipped to `superseded` with a real `assessment_retested` audit
event, requested and approved a real exception end to end, and clicked
"Recompute from evidence" and watched it surface 4 real not-tested
placeholders from real scan evidence already sitting in the database
(screenshotted: "4 new not-tested assessment(s) surfaced from automated
evidence"). The smoke-test rows created during that live pass were deleted
afterward via direct SQL (the module has no delete endpoint by design — an
append-only audit trail — so this was the only way to keep the dev DB's
demo data meaningful); the 4 real recompute-surfaced placeholders were kept,
since those reflect genuine product state, not test pollution.

152 frontend tests passing (was 125; +27: `RecordAssessmentDialog` (8),
`RequestExceptionDialog` (5), `NCAControlsPage` (5), `NCAControlDetailPage`
(+6), `NCACompliancePage` (+3)), `tsc` clean. No backend changes at all —
every endpoint this UI calls already existed, was already validated, and
was already covered by `test_nca_routes.py`.

Before that: **Network discovery fully separated from Run Scan — COMPLETE**
(2026-07-23). Closed the last piece of overlap between the two network-
discovery entry points built earlier the same day: Run Scan's "4. Network
Discovery" section still required selecting a device from the dropdown
before it would even appear, even though the scan itself never used that
device's host/port at all (it always swept the whole subnet). Removed that
section entirely from `RunScanPage.tsx` (and the `"network-discovery"`
special case in `testsInSection`/the "any tests selected" check that
existed only to support it) — the standalone "Discover devices" panel on
the Devices page (`POST /network-scans`, no device required at all) is now
the only real entry point. Added a pointer note under Run Scan's device
selector linking to it, so the capability doesn't just quietly disappear.
`TEST-NET-DISCOVERY` itself, its `SCAN_CATALOG` entry, and the backend
per-device dispatch path (`is_network_discovery_test()` in `job_runner.py`/
`main.py`) are all untouched — `process_network_scan()` still reads the
catalog entry directly by key for the standalone flow, and the per-device
path stays reachable via a direct `POST /scan-jobs` call if anything needs
it, just no longer surfaced in this page's UI.

1 test removed (asserted the now-deleted section), 2 added (one confirming
the section is genuinely gone, one confirming the pointer link works) —
125 frontend tests passing (was 124), `tsc` clean. No backend changes.

Before that: **Discovery panel persistence + a gentler, more accurate scan —
COMPLETE** (2026-07-23). Two refinements to the discovery-first onboarding
feature built earlier the same day, both owner-requested: (1) registering
one discovered host no longer hides the discovery panel or discards its
scan results — `DevicesPage.tsx`'s `openForm`/`openFormWithPrefill` no
longer force `showDiscovery` closed, so the panel and a completed scan's
host list stay visible alongside the registration form. Since
`NetworkDiscoveryPanel` stays mounted, its scan state survives, and each
freshly-registered host flips from "Register" to "Already registered"
inline the moment `handleRegistered()` refreshes the device list — the
whole point being "register several discovered hosts from one scan," not
"rescan before every registration." (2) The scan itself is now explicitly
tuned for an IoT environment where real devices can have weak network
stacks: `-T4` (Aggressive) → `-T3` (Normal - nmap's own docs say `-T4`
assumes "a reasonably fast and reliable network," not a safe assumption for
constrained gear), added `--max-rate 50` (hard packet-rate ceiling) and
`--version-intensity 2` (lighter service-fingerprint probes — the
classifier only needs the port number). Verified live this costs no real
time in this lab (~25s either way, since a /24 sweep is dominated by the
mostly-silent discovery phase, not per-host probe aggressiveness) - but
raised this test's own timeout to 90s anyway (via a new per-test
`timeout_seconds` override in `SCAN_CATALOG`, read by both
`job_runner.py`'s `process_job` and `process_network_scan`; every other
test keeps the 30s default) purely for headroom, since a real network
won't always be this fast.

**A real, unrelated accuracy bug turned up during that same live-tuning
pass** (`docs/errors/029`): `--open` (present since this test was first
built) doesn't just hide closed/filtered port rows — it silently omits a
live host's *entire* report if none of the 6 signature ports are open, so
a real non-IoT appliance on the VLAN (the subnet gateway, an infra
container) never appeared in the output at all, making the `"unknown"`
classification unreachable from genuine scan output despite being unit-
tested. Fixed by dropping `--open` entirely (the parser already only counts
literal "open" port lines, so closed/filtered rows are correctly ignored
with no parser change needed). Re-verified live: the gateway and two
infrastructure containers now correctly appear and classify as `"unknown"`
— a real, accurate demonstration of "another network appliance sharing the
VLAN" that isn't just the `telnet-sim` `"uncertain"` case.

Backend: 2 new `policies/catalog` tests (verifying the gentler command
shape and the longer timeout) + 2 new `job_runner` tests (verifying the
per-test timeout actually reaches `subprocess.run`) — 84 and 17 tests in
those files respectively, all passing. Frontend: 124 tests passing (was
123; +1 `DevicesPage` test for the panel-stays-open-while-registering
behavior), `tsc` clean.

Before that: **Discovery-first device onboarding — COMPLETE** (2026-07-23).
Follow-up to the Network Discovery scan built earlier the same day: the
owner clarified the actual goal wasn't a scan test to run against an
already-registered device, but a real replacement for manual device
registration — "use network discovery to search for devices in its
environment instead of register them manually." Built as a new, small
subsystem deliberately decoupled from the existing `scan_jobs`/device
machinery (which requires a device to already exist before anything can run
against it): a new `network_scans` table with **no** `device_id` column at
all, `POST /network-scans` (auditor-api only ever inserts a pending row,
same "never executes anything itself" boundary as scan_jobs), and a second
poll loop in `job_runner.py` (`poll_network_scans_once()`/
`process_network_scan()`) that reuses `TEST-NET-DISCOVERY`'s own
`build_command`/`parse_observations` pure functions from
`policies/catalog/scan_tests.py` rather than duplicating the classifier.
The Devices page gained a "Discover devices" toggle
(`components/devices/NetworkDiscoveryPanel.tsx`) — click "Scan network,"
see every live host with its `iot_device`/`uncertain`/`unknown`
classification and rationale, and click **Register** on any one of them to
open the existing `RegisterDeviceForm` pre-filled (device id and display
name guessed from this lab's own `kaust-iot-lab-<name>-<index>` container
naming convention, host set to the discovered IP, services derived from
open ports via a small port→service-type map) instead of typing every field
in from scratch. `RegisterDeviceForm` gained `initialDisplayName`/
`initialHost`/`initialServices` props alongside the pre-existing
`initialDeviceId` to support this. No new tool was needed — the already-
built, already-verified `nmap` invocation and classifier from the earlier
Network Discovery work were reused as-is.

**Verified for real against the live lab**, not just unit-tested: triggered
a real scan through the actual browser UI, watched it classify all 6 real
containers correctly, clicked Register on a real discovered host and
confirmed the form opened pre-filled with the right device id/host/services,
and confirmed the "Already registered" state for hosts that already have a
real `devices` row. **Caught one real bug this way** (`docs/errors/028`):
the "Already registered" check compared a discovered host's IP against
registered devices' `host` field, but every one of this lab's seeded devices
registers with its **container name** as `host`, never an IP — so every
already-registered device wrongly still showed a "Register" button. Fixed
by also matching on the container name guessed from the discovered
hostname (the same guess `RegisterDeviceForm`'s prefill already computes),
with regression tests for both matching paths.

Backend: 8 new `lab/auditor/api` network-scan tests + 3 new `job_runner`
tests, all passing (162 total `lab/auditor/api`, was 154). Frontend: 123
tests passing (was 114; +6 `NetworkDiscoveryPanel` + 1 `RegisterDeviceForm`
prefill + 1 `DevicesPage` toggle, one further regression added after the
live-caught bug above), `tsc` clean.

Before that: **NCA domain-summary cleanup + a new Network Discovery scan —
COMPLETE** (2026-07-23). Two owner requests handled together: (1) the
per-device NCA domain breakdown (NCA Compliance page + the device detail
page's Compliance tab) no longer shows Governance or the Third-Party/
Cloud domain group, since neither has a single device-scope guideline
mapped to it at all (confirmed live: both were a real `0/0/0/0` across
every status, not just untested) — a device-scope view showing them was
misleading, not merely incomplete. This isn't a hardcoded name-based
removal: a new shared helper, `lib/nca.ts::applicableDomains()`, excludes
any domain whose pass+partial+fail+not_tested total is exactly zero,
so Cybersecurity Resilience (which does have real assessed/not_tested
controls today) correctly stays visible, and would only disappear on its
own if it ever became genuinely empty too — exactly the "if Resilience
isn't applicable either, drop it" instruction, expressed as a standing
rule rather than a one-off edit. The **organizational** compliance page is
deliberately untouched, since Governance and the mobile/supplier/cloud
group are precisely the domains that *do* apply there (device scans can't
demonstrate policy approval, training, or contract compliance — those stay
manual, organization-scope assessments).

(2) A new **Network Discovery** scan (`TEST-NET-DISCOVERY`, a 4th Run Scan
section) sweeps the whole `audit-network` subnet (172.30.0.0/24) with one
`nmap -sV -p 22,23,80,443,1883,8883 --open -T4` invocation — restricted to
a small, fixed signature-port set rather than a full `/24` port sweep, so it
finishes reliably inside `job_runner.py`'s 30s timeout — and classifies
every live host as `iot_device` (a management-UI or MQTT-protocol port is
open — high confidence), `uncertain` (only Telnet/SSH is open — a real
signal for "some other network appliance may be sharing this VLAN," since
those protocols are common to switches/legacy servers too, not just IoT),
or `unknown` (none of the signature ports responded). Deliberately does
**not** use MAC-vendor/OUI lookup or OS/TTL fingerprinting, and says so in
its own output notes: this scan runs inside a Docker bridge network where
every container shares the host kernel and uses a virtual MAC, so neither
technique would actually distinguish device types here — overclaiming
either would have violated the "keep the classification honest" ask.
Wired through the same `applicable_service_types=()` / "no live host:port
needed" path firmware tests already established (`is_network_discovery_test()`
mirrors `is_firmware_test()` in `scan_tests.py`, `job_runner.py`, and
`main.py`'s `_create_scan_job`), so it needs only a registered device to
exist (any device — the scan itself ignores which one), not an enabled
service. **Verified for real against the live lab**, not just unit-tested:
found all 6 real containers, correctly classified the 3 smart cameras and
both MQTT brokers as `iot_device` via their management-UI/MQTT ports, and
correctly classified `telnet-sim` as only `uncertain` rather than
confidently IoT — the concrete "the VLAN may contain another network
appliance, distinguish it" scenario the owner asked for, reproduced with
real containers rather than a synthetic example. Recorded as real evidence,
`EV-2026-07-23-0001` (exported to `document-store/evidence/` per the usual
convention).

**One real bug caught by that live run, not by unit tests alone**
(`docs/errors/026`): the port-table parser used `\s+` instead of `[ \t]+`,
so a port with no version text (`23/tcp open  telnet?` alone) let the
optional version group's leading `\s+` absorb the newline and swallow the
*next* port's entire line as its own "version" — `device-insecure` (which
genuinely exposes Telnet with no version immediately followed by HTTP with
one) came back `uncertain` with `open_ports: [23]` instead of `iot_device`
with `[23, 80]`. `_parse_nmap_observations` (`TEST-NET-PORTSCAN`) already
avoided this exact trap; the new function just didn't match it. Fixed and
added a regression test using exactly that no-version-then-versioned shape.
**A second, unrelated but also real incident** (`docs/errors/027`): an ad
hoc `docker run` file-bind-mount (to run `test_job_runner.py` outside the
full Compose stack) left a 0-byte file on the host at
`lab/auditor/worker/device_validation.py` — a path that must never be a
real file, since the real module is baked into the worker image from
`lab/auditor/api/device_validation.py` and reached via `PYTHONPATH=/work`,
never bind-mounted at that path. That empty file silently shadowed the real
one the moment the directory got bind-mounted into the live
`auditor-worker` container, crash-looping it. Deleted the stray file,
confirmed the real container recovers, and added the path to `.gitignore`
so this fails loudly (an import error, easy to spot) rather than quietly
persisting into a commit again.

Backend: 82 `policies/catalog` scan-test tests (was 79) + 24
`lab/auditor/api` scan-job tests (was 22) + 14 `job_runner` tests (was 13)
passing. Frontend: 114 tests passing (was 108), `tsc` clean. Verified live
against the real rebuilt `auditor-web`/`auditor-worker`/`auditor-api`
images.

Before that: **Dashboard UX/UI improvement pass — COMPLETE** (2026-07-22). The
owner asked for three things in one go: "further improve the UX/UI," "add a
dashboard in NCA Compliance section or something better and usable," and
"make overall improvement and modification to the overall web interface and
make it ready to go." Planned via plan mode (findings grounded in the actual
code, not general impressions) and executed in four parts, all against
`lab/auditor/web/`:
1. **NCA Compliance page rebuilt as an actual dashboard**, not a stat-tile
   list. New `components/charts/NCADomainBarChart.tsx` (a stacked bar chart,
   one bar per CGIoT-1:2024 domain, pass/partial/fail/not_tested segments —
   same recharts + `CHART_COLORS` convention as the existing
   `DeviceActivityBar`); the plain "Overall pass rate" stat tile became a
   real `ComplianceGauge` (already existed, already used on Overview); a new
   "Devices needing attention" panel (worst-first: fail > partial >
   not_tested, mirroring Overview's "Highest-priority failures" list); and a
   new "Reports" card wiring up the 4 CSV/PDF export endpoints
   (`ncaDeviceReportCsvUrl`/`ncaControlsReportCsvUrl`/`ncaEvidenceReportCsvUrl`/
   `ncaExecutiveReportPdfUrl`) that existed in `api.ts` since an earlier
   session but were never linked from any page. The old per-domain count
   cards and the filterable device compliance table both stayed, moved below
   the new visual section rather than removed.
2. **`VerdictsPage.tsx` correctness fixes**: `NOT_APPLICABLE` was missing from
   the `FILTERS` array (added to the backend/types in the Week 1 gap-closure
   work above but never wired into this page's filter bar), and
   `conflict_detected`/`conflict_reason`/`policy_version` — all real fields
   added in that same earlier work — were never surfaced anywhere in the UI.
   Added a small "Conflict" badge on the collapsed row header plus the full
   conflict reason and policy version inside the expanded panel.
3. **Production-readiness baseline the dashboard never had**: a real
   `NotFoundPage.tsx` + catch-all `<Route path="*">` (previously an unknown
   URL just rendered nothing); a class-based `ErrorBoundary.tsx` wrapping
   `<Routes>` in `App.tsx` so an unexpected render error shows a recoverable
   "reload the page" screen instead of a blank one; and a responsive
   collapsible sidebar — `Sidebar.tsx` now takes `open`/`onClose` props and
   slides off-canvas below the `lg` breakpoint behind a hamburger button
   (`Menu` icon, new in `TopBar.tsx`) with a click-to-close backdrop,
   `Shell.tsx` now owns the open/close state and its content padding changed
   from unconditional `pl-60` to `lg:pl-60`. Also grouped the sidebar's 8 flat
   nav items into three labeled sections (Monitoring / Assessment /
   Compliance) since the flat list had grown cluttered.
4. **A consistent toast notification system**, replacing several different
   ad hoc inline success/error paragraphs with one pattern: `components/ui/toast.tsx`
   (presentational stack, bottom-right, auto-dismissing, dismissible) +
   `lib/useToast.tsx` (context/provider + `useToast()` hook), mounted once in
   `App.tsx` inside the new `ErrorBoundary`. Wired into `RegisterDeviceForm`
   (success toast; the existing per-field inline validation errors were
   deliberately left untouched — that pattern is correct UX and predates this
   pass), Run Scan's recompute-verdicts result and each `ScanJobCard`'s
   "evidence recorded" outcome (replacing an inline paragraph that could only
   ever show the *last* action's result), and `DeviceDetailPage`'s firmware
   upload/remove and deregister outcomes (replacing per-action inline error
   paragraphs with toasts for both success and failure, since these are
   one-shot action outcomes, not form-field validation).

**Verified for real, not just unit-tested**: the Claude-in-Chrome browser
extension was unavailable again this session (checked, not connected), so
live verification used a headless Playwright script (already an established
pattern in this project's history) driven against the actual rebuilt
`auditor-web` Docker image and the real dev stack — confirmed the NCA
dashboard renders live gauge/chart/attention-panel/report-link data matching
the real `/nca/domains` API response byte-for-byte, confirmed the sidebar
correctly collapses off-canvas at a 480px viewport and opens via the
hamburger with a backdrop, confirmed a bad route renders the real 404 page,
confirmed a real device registration produces a real toast that appears and
auto-dismisses (screenshotted), and confirmed the Verdicts page's
`NOT_APPLICABLE` filter and expanded "Policy version" field both work
against real live verdict rows already in the dev database (the conflict
badge itself has no live data to show today — no real conflicting evidence
pair currently exists in this dev DB — so that path is unit-tested only,
not live-confirmed). 108 frontend tests passing (was 96 before this pass;
+12: NCA dashboard reports/attention-panel tests, Verdicts NOT_APPLICABLE +
conflict/policy-version tests, a 404-route test, ErrorBoundary tests, and
`useToast` tests), `tsc --noEmit` clean. Not committed to git yet.

Before that: **Week 1 mentor-brief gap closure — COMPLETE** (2026-07-22). The owner
asked for a gap analysis of the mentor's "Week 1" task brief
(`docs/week1-gap-analysis.md`, written the same day) against the real
`SA-IOT-*` assessment pipeline, then asked to close every ❌/⚠️ item found.
Additive throughout — the existing evidence/verdict/scan_jobs flow and the
NCA compliance module below are both untouched in behavior, only extended.
Highlights:
- **A real `assessments` entity**: `POST /assessments` (device_id + test_ids[])
  groups a batch of `scan_jobs` under one id with an aggregate status computed
  by one pure function (`policies/engine/assessment_status.py` —
  `queued`/`running`/`partially_completed`/`completed`/`failed`/`cancelled`),
  never hand-set beyond queued/cancelled. `POST /assessments/{id}/cancel`
  fails not-yet-started jobs and marks the assessment terminal (an already
  `running` job is left to finish — no process-group tracking to kill it
  safely, documented as a limitation, not silently promised). Run Scan's
  existing "Run selected" batch launch now creates a real Assessment instead
  of N unlinked jobs, with a status bar and Cancel button; the existing
  per-job card UI is unchanged.
- **A failed collector now produces `INCONCLUSIVE`, never silence or FAIL.**
  `job_runner.py`'s timeout/exception paths call a new
  `POST /scan-jobs/{id}/record-failure`, which deterministically writes
  evidence flagged `observations.collector_error` — `policy_engine.py`'s
  `evaluate()` checks that flag before any condition matching and always
  scores it `INCONCLUSIVE`.
- **`NOT_APPLICABLE` is now a real, reachable verdict status** — derived from
  the *existing* `is_applicable()`/`applicable_service_types` machinery
  (never the unused `applicability.device_type` YAML field, which
  corresponds to no column `devices` actually has), synthesized at
  `/verdicts/recompute` time for a registered device whose services never
  match a control's required tests. The previously dead `"when":
  "evidence_missing_or_low_confidence"` YAML mechanism is now real code too
  (a `WHEN_HANDLERS` dispatch), not just a fallback default.
- **Evidence conflict detection** (`policies/engine/conflict.py`) — the
  mentor's own example (documentation says MQTT uses TLS, a packet capture
  shows plaintext): evidence for the same (device, control) pair is now
  evaluated together, `source_type == "automated"` wins over
  `"manual"`/`"document"` on disagreement, and the resulting verdict carries
  `conflict_detected`/`conflict_reason` plus every evidence id considered
  (not just the winner).
- **Two real bugs caught live**, not by unit tests alone (both now have
  regression tests + `docs/errors/024`/`025`): conflict detection crashed on
  a real list-valued observation field (`open_ports`) since a plain `set()`
  can't hold unhashable values; and `is_control_applicable()` initially
  marked *every* device `NOT_APPLICABLE` for SA-IOT-001 because its required
  test has no automated collector at all — conflating "not yet automated"
  with "doesn't apply."
- **New collectors**: `TEST-NET-REACHABILITY` (plain TCP connect probe) and
  real TLS certificate expiry (`TEST-TLS-CONFIG` now also reports
  `cert_expired`, via a second `openssl s_client -showcerts` handshake fed
  into `openssl x509 -noout -dates` — confirmed live that `-brief` suppresses
  the certificate PEM even with `-showcerts` together, so this needs two
  separate handshakes, not one).
- **Evidence/verdict schema additions**: `source_type`, `confidence_reason`,
  `error_state`, `assessment_id` on evidence; `policy_version`,
  `conflict_detected`, `conflict_reason`, `assessment_id` on verdicts — all
  optional (not required) in `evidence.schema.json`/`verdict.schema.json` so
  every existing caller keeps validating unchanged. Every control YAML
  gained `version` and a real `limitations` string.
- **Reports**: `GET /devices/{id}/report.html` and `.json` alongside the
  existing `.pdf`, all three sharing one `build_report_model()` now extended
  with `methodology`, `disclaimer`, `assessment_scope`, and
  `controls_not_assessed`. A new `GET /document-store/{path}` route (path-
  traversal-safe) actually serves raw evidence artefacts so the dashboard's
  "view raw artefact" link opens a real file instead of just printing a path
  as text.
- **Tests**: a systematic pass/fail/inconclusive/contradictory-evidence
  matrix across all 5 real `SA-IOT-*` controls (20 parametrized cases,
  `policies/engine/test_controls_four_cases.py`), a database-persistence
  test (write via one connection, read via a fresh one), and
  `scripts/smoke_test.sh` — a real clean-deployment smoke test, verified live
  end to end against the actual stack. 149 backend `lab/auditor/api` tests +
  148 `policies/*` tests + 96 frontend tests passing (only the 2 pre-existing
  WeasyPrint-native-library gaps on this Windows dev shell still fail,
  unrelated to this work).
- **Docs**: `docs/known-limitations.md` (consolidated register),
  `lab/README.md` updated to cover every application feature (was still
  describing the dashboard as Flutter Web from Day 1), and a note added to
  `docs/architecture/architecture-diagram.md` confirming the topology is
  unchanged (this work added application logic inside existing containers,
  no new container/network).

Before that: **NCA CGIoT-1:2024 Compliance Module — COMPLETE** (2026-07-22). A full,
production-quality compliance module built as a parallel system alongside the
original 5-control `SA-IOT-*` policy-as-code pilot (which is untouched — Run Scan,
`ControlsPage`, `VerdictsPage`, the `evidence`/`verdicts` tables all still work exactly
as before). Covers all 81 real CGIoT-1:2024 guidelines across all 4 domains, with
device-scope and organizational-scope assessments, an append-only audit trail,
exceptions with mandatory expiry, and a "NCA CGIoT-1:2024 Alignment" dashboard page
that is careful never to claim NCA certification. Full detail in
`docs/nca-compliance.md`. Highlights:
- **Catalog**: `policies/nca/build_catalog.py` deterministically parses the
  already-verified `docs/reference/CGIoT-1_2024.md` transcription into 81 guideline
  entries + 11 Manufacturer Principles — canonical wording copied verbatim, never
  invented; IoTGuard's own scope/assessment-type/severity classification kept
  clearly separate from NCA's own text.
- **Data model**: 6 new Postgres tables (`compliance_controls`,
  `compliance_finding_mappings`, `compliance_assessments`, `compliance_evidence`,
  `compliance_exceptions`, `compliance_audit_events`) via `init.sql` +
  `migrations/003-nca-compliance.sql`. Assessments are append-only (re-assessment
  supersedes the prior row, never overwrites it) with a full before/after audit
  trail. Automated evidence reuses the existing `evidence` table by reference
  (`linked_evidence_id`) rather than duplicating it.
- **Evaluator**: one centralized, pure-function module
  (`policies/nca/evaluator.py`, 45 unit tests) computes every status/score/domain-count
  — the API and UI only ever render its output, never recompute it. Hit and fixed a
  real bug here during integration: a never-assessed device's rows are a *full* list
  where every status defaults to `not_tested` (not an empty list), which the first
  version of `device_overall_status` mis-classified as PARTIAL instead of "Not
  Assessed" — caught by hitting the live API with a freshly-seeded, unassessed device.
- **Finding-to-control mapping**: `policies/nca/finding_mappings.py`, a configurable
  ~20-entry table (not hardcoded in the API/UI) reusing `policy_engine.py`'s existing
  `{field, op, value}` predicate. Deliberately has **zero** mappings into domain 1
  (governance) or the mobile/supplier/cloud groups — a scan cannot demonstrate policy
  approval, training, audits, or contract compliance, so those stay
  manual-assessment-only, enforced by its own regression test. Hit and fixed a real
  bug: a mapping's `not_equals` rule matched evidence that never even carried the
  relevant observation key at all (`None != []` is spuriously `True`), so the mapper
  now requires the field to actually be present before evaluating any rule.
- **API**: `lab/auditor/api/nca_routes.py`, a new `APIRouter` (~25 endpoints:
  summary/domains/controls/devices/assessments/exceptions/organization/reports)
  mounted into the existing app — same `get_connection()`/`ValidationError`→400
  conventions as the rest of the API. Reviewer identity (free-text name + reason),
  not real authentication — this app has no login system anywhere, and this is
  documented as a deliberate, explicit limitation rather than glossed over.
- **Frontend**: new "NCA Compliance" nav entry + page (header/disclaimer, summary
  tiles, 4-domain breakdown, status-tabbed/filterable device table), a control detail
  page, an organizational compliance page, and a new Compliance tab on the existing
  device detail page — all built from the existing `Shell`/`Card`/`Skeleton` component
  vocabulary, plus one genuinely new shared primitive (`ui/tabs.tsx`, needed twice).
  Status is always icon+text (`NCAStatusBadge`), never color alone. 92 frontend tests
  passing (was 77).
- **Demo seed**: `policies/nca/seed_demo_assessments.py` (manual, not wired into any
  entrypoint) builds the 3 required real scenarios against the real lab devices,
  linking real committed Day-2 evidence rows — verified live against the dev DB:
  `device-hardened` → PASS/100%, `device-partial` → PARTIAL/89% (one genuinely partial
  weak-TLS-cert control, one left NOT_TESTED for physical tamper protection), `device-insecure`
  → FAIL/0% (5 concrete failures, each linked to real evidence).
- **Verified live**: full regression run (133 backend tests across `policies/nca`,
  `policies/catalog`, and the full `lab/auditor/api` suite — only the 2 pre-existing
  WeasyPrint-native-library gaps on this Windows dev shell fail, unrelated to this
  work; 92 frontend tests; `tsc --noEmit` clean), plus real end-to-end verification
  against the live `auditor-api`/`auditor-database` containers: seeded the real
  catalog + mappings + demo assessments, hit every `/nca/*` endpoint including the
  create/retest/audit-trail/exception-422 flows, and confirmed the executive PDF
  renders real data. Browser-based visual verification of the new dashboard pages
  was **not** performed this session (the Claude-in-Chrome extension was not
  connected) — noted here rather than claimed.

Before that: **Three more owner-requested dashboard refinements — all COMPLETE**,
same day (2026-07-21): (1) removed the security-tier concept from the UI
entirely — the tier badge/pill ("Insecure"/"Partial"/"Hardened"/"Unknown") is
gone from the Devices list, the device detail page, and Device Console, and
the "Security tier" `<select>` is gone from device registration (every new
device now registers with `tier: "unknown"`, matching the backend's own
default for an omitted tier — the `tier` column/data model itself is
untouched, this is a UI-only removal, deliberately not a schema migration
that would also touch the PDF report and `device_validation.py`);
`lib/deviceTier.ts` (the shared badge-styling module) is deleted outright now
that nothing imports it. (2) Removed the service-registration quick-pick
buttons ("Smart camera (HTTP)", "Smart camera (HTTPS)", "MQTT broker", "MQTT
broker (TLS)") from `RegisterDeviceForm.tsx` — the services repeater itself
is untouched, just the shortcut buttons that pre-filled it. (3) "Run
selected" on the Run Scan page is now disabled for the whole time a
previously-launched scan is `pending`/`running` (not just during the
synchronous launch click) — each `ScanJobCard` reports its polled status up
to the page via a new `onStatusChange` callback, seeded immediately from the
`POST /scan-jobs` response so there's no gap between launch and the first
poll, with an inline "a scan is already running" hint explaining why the
button is greyed out. **Verified for real in a browser**: registered-device
cards and the device detail page show no tier badge, the registration form's
Services section has no quick-pick row, and clicking "Run selected" against
a real device visibly disables the button with the hint text until the real
nmap job reaches `awaiting_finding`. 77 frontend tests passing (was 71).

Before that: **Four owner-requested refinements to Run Scan and the dashboard —
all COMPLETE**, same day (2026-07-21): (1) dropped the boolean `telnet_open`
observation field (`policies/catalog/scan_tests.py`), migrating
`SA-IOT-003`'s condition to `observations.open_ports contains/not_contains 23`
instead (a new `not_contains` op added to `policy_engine.py`) — reproduces
the exact same PASS/FAIL against the real committed Day-2 evidence that used
to carry both fields; (2) `TEST-AUTH-DEFAULT-CREDS` now tries the 10 most
commonly documented IoT default credential pairs (admin:admin, root:root,
root:toor, guest:guest, etc. — the same pairs published in security research
like Mirai's credential list), chained into one `curl --next` invocation,
reporting which pair(s) worked rather than only ever checking admin:admin;
(3) generalized `TEST-NET-HTTP-INSPECT`'s framework-disclosure check from a
single hardcoded `"uvicorn"` substring match to "any non-empty Server header
discloses something," so it stays meaningful for whatever product is
registered, not just this lab's own camera app; (4) added a light theme
toggle (Sun/Moon button in `TopBar.tsx`, persisted to `localStorage`, applied
pre-paint via an inline script in `index.html` so there's no flash of the
wrong theme) — a full light CSS-variable palette in `index.css` means every
`var(--color-*)` reference across the whole app repaints correctly in either
theme with zero component changes needed. **Verified for real against the
live stack**: ran a real nmap scan (confirmed no `telnet_open` key, real
per-port `services` list, correct FAIL from the new `open_ports`-based
condition), ran the real 10-credential login chain against `device-insecure`
(only `admin:admin` — its actual seed credential — came back as working),
and toggled the theme in a real browser session (persisted across a
navigation). 72 `policies/catalog` + 9 `policy_engine` + 31 `job_runner`
backend tests and 71 frontend tests passing.

Also same day: **added a per-device/fleet NCA CGIoT-1:2024 compliance
percentage**, after the owner uploaded the actual CGIoT-1:2024 PDF to the
repo root for reference (already fully transcribed in
`docs/reference/CGIoT-1_2024.md` from the same source — nothing new to
transcribe, so this became "build the missing feature that uses it," not
"digest a new document"). `GET /devices/{id}` gained a `compliance` object
and `GET /summary` gained a `device_compliance` breakdown, both computed by
a new shared `_compliance_from_verdict_rows()` helper: percentage = passing
/ **tested** controls (owner's explicit choice — an unassessed control is
reported as missing coverage, never assumed pass or fail), keeping only the
most recent verdict per control_id since a control can be re-tested and
otherwise double-count. Shown on the device detail page (a `ComplianceBadge`
next to the tier badge) and a new "NCA CGIoT-1:2024 compliance by device"
card on Overview, worst-first, linking to each device. **Verified for real**:
hit the live `/summary` and `/devices/device-insecure` endpoints and got back
real numbers matching the actual committed verdict history (device-insecure
0% — its 2 tested controls are SA-IOT-002 FAIL and the latest SA-IOT-003
verdict, FAIL; device-hardened 100%); confirmed in a real browser that the
Overview breakdown sorts worst-first and links to each device. One test
needed a real host-side fix, not a shrug: the API test suite's 21
`/work/...`-hardcoded-path failures from previous sessions turned out to be
genuinely fixable rather than an accepted gap — a `C:\work` → `policies`
directory junction on the build machine (host-local, not part of the repo)
resolves them, so all 3 dropped to 1 real remaining failure (WeasyPrint's
`libgobject` native library isn't installed on this Windows host - unrelated
to this session's changes).

Before that: **Removed the device detail page's Services section, and enriched
every scan test's JSON observations with auditor-facing detail — both
COMPLETE**, same day (2026-07-21). The dashboard's per-device Services card
(protocol/internal port/published port list) is gone entirely — services
still exist in the data model (device registration, scan-test service-type
matching) but are no longer surfaced as their own UI section. Separately,
every one of the 15 `parse_observations` functions in
`policies/catalog/scan_tests.py` now returns a `notes: [str]` array of
deterministic, rule-based auditor guidance (e.g. what a missing security
header actually exposes, why anonymous MQTT access matters), and
`TEST-FW-MANIFEST`'s package list is enriched via a new
`policies/catalog/vuln_reference.py` local lookup — each package gets
`outdated`, `eol`, `latest_known_version`, `official_patch_available`,
`patched_version`, and `cves` (each with a real CVE ID, CVSS score, and a
fact-checked summary). This is a small, deliberately non-comprehensive local
table (offline, deterministic, no live NVD/CVE API call — same rule as Day-2/
Day-3 evidence), populated only with CVEs verified as real and accurately
described (e.g. OpenSSL 1.0.1e → Heartbleed CVE-2014-0160 + CCS Injection
CVE-2014-0224); a (component, version) pair not in the table returns an
honest "no local reference data" result rather than a fabricated one.
`TEST-NET-PORTSCAN` also now parses nmap's per-port SERVICE/VERSION columns
into a `services` list (best-effort — nmap's free-form version strings don't
reliably map to the small vuln-reference table, so they're surfaced for the
auditor to check by hand rather than auto-matched). `TEST-NET-HTTP-INSPECT`
attempts a `name/version` split of the `Server` banner and runs it through
the same lookup. **Verified for real, not just unit-tested:** built the
`device-insecure` firmware fixture via `generate_firmware.py` (real
OpenSSL 1.0.1e / BusyBox 1.19.4, the exact versions this reference table
covers), uploaded it through the live device detail page, ran
`TEST-FW-MANIFEST` through the real API/worker, and confirmed the returned
evidence-candidate JSON carried the real Heartbleed/CCS Injection CVE data
end to end — not a mock. 70 `policies/catalog` scan-test tests + 7 new
`vuln_reference` tests + 31 `job_runner` tests passing; 64 frontend tests
passing (one updated for the Services removal). See the two new 2026-07-21
changelog entries below for full detail.

Before that: **Device firmware upload (end-to-end) + a native telnet server on
`device-insecure` — both COMPLETE**, merged directly to `main` 2026-07-21 (no
worktree, same day as the Run Scan restructuring below). `POST`/`DELETE
/devices/{id}/firmware` let the device detail page upload or remove a
`.tar.gz`/`.tgz` firmware archive; the "Run Scan" page's Simulated Firmware
Analysis section (previously fully static/disabled — see the correction
below) now live-enables its 7 checkboxes once a device has firmware
uploaded, running the real Day-2 firmware tests
(`TEST-FW-VERSION` … `TEST-FW-UPDATESCRIPT`) via `job_runner.py`'s
`is_firmware_test()` dispatch, which skips live-target validation entirely
since firmware tests are keyed on `device_id` alone, not host/port/service.
Verified for real: uploaded a throwaway `.tar.gz` through the actual device
detail page in a browser against the live stack, watched `GET /scan-tests` →
`POST /scan-jobs` → `job_runner.py` run `firmware_check.py` against the real
uploaded archive and return real parsed observations, then removed the
firmware and confirmed the section goes back to disabled. See the two new
2026-07-21 changelog entries below for full detail.

Before that: **Run Scan restructured into 3 assessment sections COMPLETE** — merged
directly to `main` 2026-07-21 (no worktree; scoped small enough to do inline). The
dashboard's "Run Scan" test picker now mirrors the Day-2 manual assessment brief
exactly: Web and Authentication Assessment (5 live tests), Network and Protocol
Assessment (5 live tests), and Simulated Firmware Analysis (initially shipped here
as a static, disabled 7-item section pending the firmware-upload feature above —
made live later the same day, not left "out of this job runner's scope" as this
entry originally said before that feature existed). Checkboxes let a user run one
test (e.g. just "Default credentials") or select-all a section. See the 2026-07-21
changelog entry below for the full detail, including three test_ids
(`TEST-ADMIN-UNAUTH`, `TEST-MQTT-OPEN`, `TEST-TLS-CONFIG`) that turned out to
already be wired into NCA controls SA-IOT-004/005 — automating them changes real
verdict outcomes the first time someone records evidence through the new UI, which
is intended.

Before that: **Per-device PDF compliance report COMPLETE** (`worktree-pdf-report`,
6 tasks + carried follow-up fixes) — merged to `main` 2026-07-20, deployed and
verified on the physical PC. Before that, the **device registration & visibility
feature** (14 tasks) was merged 2026-07-19. Before both: **Phases 0-8 functionally COMPLETE**, and the `auditor-web` dashboard has
been **rebuilt from scratch in React + Tailwind v4 + Vite**, replacing Flutter Web
entirely, after the owner rejected the Flutter redesign as "AI slop" (see §8 for the
full story — kept in `docs/NEXT-SESSION-HANDOFF.md` as a historical record of the
root-cause analysis, now resolved). Branch `worktree-phase-6-8-implementation` was
**merged into `main` on 2026-07-19** (fast-forward to `fa73983`, 48 commits, 111 files)
— `main` is now the single live branch again.

**2026-07-09 — dashboard rebuilt in React (resolved the "AI slop" complaint):**
Replaced `lab/auditor/web/` (Flutter) wholesale with a Vite + React + TypeScript +
Tailwind v4 app. Design direction: dark near-black theme, single amber brand accent,
severity-coded status colors, real bundled Inter + JetBrains Mono fonts (via
`@fontsource`, so no repeat of the "referenced but never bundled" font bug), recharts
for the compliance gauge / verdict donut / device activity bar, lucide-react icons
throughout (no emojis). Fetches live from `auditor-api` (`/summary`, `/devices`,
`/evidence`, `/verdicts`, `/controls`). Verified by seeding the real 12
evidence + 8 verdict records from `document-store/` into a locally built
`auditor-database` + `auditor-api`, then visually confirming all 4 screens
(Overview, Devices, Evidence, Verdicts) with Playwright screenshots against both the
Vite dev server and the actual built Docker/nginx image — not just `flutter
analyze`/`tsc` this time. 14 Vitest + React Testing Library tests pass (7 files),
exceeding the old Flutter suite's 11. Two small errors hit and logged
(`docs/errors/018`-`019`).

**Plans:**
- `docs/superpowers/plans/2026-07-07-preliminary-iot-lab-phases-0-5.md` — 31 tasks,
  Phases 0-5, all complete.
- `docs/superpowers/plans/2026-07-08-phases-6-8-platform-completion.md` — 20 tasks,
  Phases 6-8 (auditor-api, auditor-database, auditor-web, traffic-capture), all
  complete and PC-verified. Acceptance doc: `docs/architecture/phases-6-8-acceptance.md`.

**Acceptance verification:** `docs/architecture/phases-0-5-acceptance.md` — full Day-1/Day-2/Day-3 acceptance criteria checked off with evidence, all independently re-verified against the real committed files (not just implementer claims). Headline results:
- Day 1: full lab (6 services + auditor-worker, 2 networks) built and demonstrated working on the physical PC.
- Day 2: 12 real manual-assessment evidence entries collected (exceeds required ≥8), all schema-valid.
- Day 3: 5 NCA controls (SA-IOT-001..005) mapped to real CGIoT-1:2024 sources; verdict engine run for real against the Day-2 evidence — 4 controls (not just the required ≥2) show correct PASS+FAIL pairs across different device configs.
- 45+ tests passing across the whole codebase (schema, policy engine, controls, firmware, evidence recording, smart-camera device, auditor-api, auditor-web widget tests).
- 17 errors hit and logged (`docs/errors/001`-`017`), each with root cause + fix + prevention.

**Already done (2026-07-07/08/09):**
- Approved design spec → `docs/superpowers/specs/2026-07-07-preliminary-iot-security-lab-design.md`
- Private git repo → `https://github.com/OSAMAxALHARBI/kaust-iot-security-lab` (branch `main`)
- Working **ssh-mcp** connection to the 32 GB build PC → host `OSRA-PC2025-V2`, user `osama`, Tailscale `100.99.182.30`, key auth. Tools appear as `mcp__ssh-mcp__*`. Remote shell is **Windows PowerShell 5.1** (no `&&` — use `;`; stderr from git gets wrongly wrapped as a PowerShell error even on success — check actual result, don't trust the error alone).
- **PC has read-write repo access**: dedicated ed25519 deploy key generated on the PC (`C:\Users\osama\.ssh\kaust_iot_deploy_key`), registered on GitHub as a **read-write** deploy key ("OSRA-PC2025-V2 (build PC, read-write)" — upgraded 2026-07-07 from an initial read-only key, so the PC could commit+push Day-2 evidence files generated on it per the Phase 0-5 plan's Task 26), SSH host alias `github.com-kaust-iot` added to `C:\Users\osama\.ssh\config`. Repo cloned to `C:\Users\osama\Projects\kaust-iot-security-lab`. (gh CLI is NOT installed on the PC — GCM/HTTPS auth doesn't work non-interactively over ssh-mcp, so use this SSH deploy-key path for any future PC git auth needs.)
- **Implementation happened in git worktrees**: `.claude/worktrees/phase-0-5-implementation` (branch `worktree-phase-0-5-implementation`, merged) and `.claude/worktrees/phase-6-8-implementation` (branch `worktree-phase-6-8-implementation`, not yet merged), both via subagent-driven-development (fresh implementer + reviewer subagent per task).
- Full stack (all 11 containers, including `auditor-api`/`auditor-database`/`auditor-web`/`traffic-capture`) deployed and manually verified working on the physical PC, including a live CORS bug fix caught by the owner opening a real browser.

**Next steps, in order:**
1. Nothing blocking. `EV-2026-07-21-0001`'s finding text ("Cleartext GET /
   HTTP/1.1 visible in the capture; plaintext HTTP confirmed.") was reviewed
   against the live DB row this session and is an accurate, well-formed
   finding, not placeholder text from verification — kept as-is, exported to
   `document-store/evidence/EV-2026-07-21-0001.json` per the `8eb469a`
   precedent (evidence recorded through the live UI lives only in Postgres
   otherwise, and a fresh clone needs it to reproduce 14 evidence records).
2. The two "orphaned files" this item used to track
   (`document-store/raw/EV-2026-07-08-0001.txt`/`0002.txt`) were already
   deleted per the 2026-07-20 changelog entry below — confirmed gone from a
   fresh listing of `document-store/raw/` (starts at `EV-...-0013`) while
   fixing this list's staleness this session.

> **Deferred, do not start:** a "production-ready" rebuild of the platform. The owner
> explicitly scoped this as a later track (2026-07-19) — finish the current feature
> work on the existing 11-container lab first.

> Also read the recalled memory notes (project-overview, ssh-pc-connection, error-log-convention).
> Full history is in §8 changelog; decisions in §9 and the spec's decisions log.

---

## 1. What We Are Building

**Project name:** IoTGuard — *AI-Assisted IoT Security Compliance & Risk Assessment Platform (NCA-Aligned)*

A plug-and-play **IoT Security Posture Management (IoT-SPM)** solution for organizations in Saudi Arabia. It:

1. Discovers IoT devices on a network
2. Fingerprints them (vendor, model, firmware, services, ports)
3. Evaluates compliance against **Saudi NCA** controls (CGIoT-1:2024)
4. Enriches findings with vulnerability intelligence (CVE/NVD/CISA KEV)
5. Computes a dynamic risk score
6. Generates AI-powered remediation blueprints and executive summaries
7. Presents everything on a security dashboard with continuous monitoring

Unlike a plain compliance auditor, it runs the **full workflow from discovery → actionable remediation**.

**We produce two deliverables:**
- **A working project** (usually a web app / platform — the auditor + dashboard)
- **A research output** (documentation, findings, policy-as-code, methodology) built up alongside the code

---

## 2. Two Governing Documents

| Doc | What it is | Where |
|---|---|---|
| **IoTGuard vision** | The 10-stage platform pipeline (the "what to build") | `docs/reference/IoTGuard.md` |
| **CGIoT-1:2024** | The Saudi NCA IoT cybersecurity guidelines — 4 domains, 27 subdomains, 81 guidelines. The compliance controls we map devices against. | `docs/reference/CGIoT-1_2024.md` |

The **preliminary tasks** (our immediate 3-day sprint) come from `First_Task/Pre-liminary Tasks.pdf` and are summarized in Section 4 below.

---

## 3. The IoTGuard 10-Stage Pipeline (target architecture)

| # | Stage | Core tech |
|---|---|---|
| 01 | Platform Deployment & Initialization | Docker, Docker Compose, FastAPI, Flutter Web, PostgreSQL, Nginx |
| 02 | Network Discovery | Nmap, python-nmap, Scapy, ARP, SSDP, mDNS |
| 03 | Device Fingerprinting | Nmap service detection, banner grabbing, SNMP, ONVIF, MAC vendor DB |
| 04 | NCA Compliance Assessment | Python rule engine, YAML/JSON rules, CGIoT-1:2024 |
| 05 | Vulnerability Intelligence | NVD, CVE, CVSS, CISA KEV, EPSS (optional) |
| 06 | Dynamic Risk Assessment | Python risk scoring, Pandas (optional) |
| 07 | AI Security Blueprint & Remediation | LLM, prompt engineering, RAG (optional) |
| 08 | AI Executive Summary | LLM, prompt templates |
| 09 | Security Dashboard | Flutter Web, REST API, FastAPI, fl_chart |
| 10 | Continuous Monitoring & Historical Analysis | PostgreSQL, APScheduler/Celery, background tasks |

Full detail per stage: `docs/reference/IoTGuard.md`.

---

## 4. Current Focus — Preliminary 3-Day Training Sprint

Source: `First_Task/Pre-liminary Tasks.pdf`. This builds the **safe simulated lab** and the **evidence → policy → verdict** core that the full platform later automates.

### Task 0 — Docker simulated laboratory (3 device profiles)

Three logical smart-camera profiles, same app configured differently via Compose profiles / env vars / mounted config:

- **Device A — Insecure:** HTTP mgmt UI, default creds, Telnet, unencrypted MQTT, hard-coded API key, outdated component, weak/missing logging, privacy doc missing retention info.
- **Device B — Partially hardened:** Telnet removed, default password changed, HTTPS with *weak* cert, MQTT still unencrypted, some logging, unsigned update process, incomplete privacy docs.
- **Device C — Hardened:** HTTPS only, strong creds, MQTT over TLS, no unnecessary services, signed firmware, security logging, updated components, complete vendor docs, retention/deletion evidence.

### Required lab architecture (Docker Compose services)

`auditor-web`, `auditor-api`, `auditor-worker`, `auditor-database`, `device-insecure`, `device-partial`, `device-hardened`, `mqtt-broker-insecure`, `mqtt-broker-secure`, `traffic-capture`, `document-store`.
Optional: vuln DB mirror, mock update server, reverse proxy, log collector, test CA.

**Networks (≥2):** `audit-network` (auditor → devices) and `internal-network` (backend, isolated from devices).
Must document: container names, IP ranges, exposed ports, trust boundaries, data flows, what is reachable, what stays isolated.

### Day 1 — Docker IoT lab + network-security basics
- Intentionally insecure Flask/FastAPI smart-camera service: login page, device-info endpoint, config endpoint, firmware-version endpoint, default user/pass, plain HTTP, ≥1 admin endpoint.
- Network services: Telnet-like, MQTT broker, HTTP, optional SSH — reachable **only inside** the lab.
- Docker infra: Dockerfiles, Compose, audit + internal networks, volumes, env config, health checks.
- Threat & evidence model: architecture diagram, trust-boundary diagram, STRIDE-style threat model, initial JSON evidence schema.
- **Day-1 output:** working Compose env, ≥1 simulated device, ≥3 exposed services, network diagram, threat model, device inventory, README (start/stop).
- **Acceptance:** reach device web UI, connect to MQTT, detect ≥3 open ports, view simulated metadata.

### Day 2 — Manual cybersecurity assessment (collect evidence before automating)
- Web/auth: default creds, anonymous access, weak sessions, missing security headers, unprotected admin endpoints.
- Network/protocol: Nmap service detection, HTTP inspection, MQTT testing, TLS testing, packet capture.
- Simulated firmware analysis: build archive (version file, config, hard-coded password, API key, cert/key, manifest, update script); analyze with `file`, `strings`, `grep`, YARA, Syft, Grype.
- Evidence normalisation record fields: Evidence ID, Device ID, Tool, Tool version, Command, Timestamp, Finding, Raw output location, Confidence, Hash of evidence file.
- **Day-2 output:** ≥8 manual findings (default creds, exposed insecure service, unencrypted protocol, hard-coded secret, outdated package, weak/missing TLS, missing logging, missing privacy/update evidence).
- **Acceptance:** each finding shows raw output → structured evidence → security interpretation → suggested remediation.

### Day 3 — Saudi policy mapping + policy-as-code
- Map first 5 controls (device identification, default credentials, unnecessary services, insecure protocols, TLS/secure comms) to Saudi sources (CGIoT-1:2024).
- Test-to-control mapping: which Docker service creates evidence, which command/tool tests it, Pass/Fail/Inconclusive results.
- YAML control schema fields: Control ID, Title, Saudi source mapping, Applicability, Required evidence, Automated test IDs, Pass/Fail/Partial/Inconclusive conditions, Severity, Remediation.
- Minimal policy engine (Python): load 1 YAML control → read 1 evidence JSON → apply verdict logic → output verdict JSON.
- **Day-3 output:** working demo — simulated device → network test → evidence JSON → YAML policy → verdict JSON.
- **Acceptance:** ≥2 controls produce correct Pass and Fail verdicts across different simulated configs.

---

## 5. Repository Layout

```
Kaust IoT Project/
├── CLAUDE.md                      # ← this file (living project charter)
├── First_Task/
│   └── Pre-liminary Tasks.pdf     # mentor-provided task brief
├── docs/
│   ├── reference/
│   │   ├── IoTGuard.md            # platform vision (10 stages)
│   │   └── CGIoT-1_2024.md        # Saudi NCA IoT guidelines
│   ├── architecture/              # diagrams, threat models, network design
│   └── errors/                    # one MD file per error we hit + how we fixed it
│       ├── README.md              # error-log convention
│       └── ERROR_TEMPLATE.md      # copy this for each new error
└── (code folders added as we build: lab/, auditor/, policies/, ...)
```

---

## 6. Error & Solution Log — MANDATORY convention

> **Every error we face while building gets its own Markdown file** in `docs/errors/`.
> This is a hard rule from the project owner — these logs feed our research report later.

- One file per distinct error: `docs/errors/NNN-short-slug.md` (e.g. `001-docker-compose-port-conflict.md`).
- Copy `docs/errors/ERROR_TEMPLATE.md` and fill it in.
- Record: what happened, exact error text, root cause, the fix, and prevention.
- Add a one-line entry to the index in `docs/errors/README.md`.
- Do this even for "small" errors — the research value is in the pattern of problems.

---

## 7. Working Agreements

- **Update this file** whenever a component is built, a decision is made, or a milestone is hit (Section 8 changelog).
- **Log every error** as its own file (Section 6).
- Keep the simulated-vulnerable lab **isolated inside Docker** — never expose insecure services to the host/internet.
- Prefer many small, cohesive files over few large ones.
- This is authorized, self-contained security training — all "insecure" devices are intentional and sandboxed.

---

## 8. Changelog

| Date | Change |
|---|---|
| 2026-08-03 | **Post-Quantum Readiness — a bonus pipeline stage between AI Remediation and the AI Executive Summary** — see §0 and `docs/pqc-readiness.md` for the full breakdown. Owner's idea, raised first as an exploratory question, then a full implementation request with an explicit "ask, don't hallucinate" instruction - honored by verifying every technical claim live against the real `auditor-worker` OpenSSL 3.5.6 image before designing anything. 3 named technical criteria (TLS Key Exchange, Certificate Signature Algorithm, Firmware Crypto Library Currency) grounded in real NIST FIPS 203/204/205 standards, not a fabricated regulation - explicitly informational only, never touches `risk_engine.py` or any compliance verdict. New `pqc_crypto_reference.py` (static tips, per the owner's own choice over AI-generated ones) + `pqc_readiness_check.py` (mirrors `tls_cert_check.py`'s two-handshake shape) + read-only `pqc_routes.py` (computed live from evidence, no new table). Wired into the Fully Automated Run (the owner's own choice, more aggressive than the default recommendation) via a new `pqc_readiness` stage in `automated_run_runner.py`. New `/pqc-readiness` dashboard page in the sidebar's Pipeline group at the requested position, plus a new fleet-wide + per-device section on the AI Executive Summary. **A real bug caught by the first live scan, not by unit tests alone**: the original PQC group list included an invented, non-existent OpenSSL group name (`X448MLKEM1024`), which made `-groups` reject its entire argument and made every TLS-capable device report `connection_error` - fixed by removing it once `openssl list -tls1_3 -tls-groups`'s real output was checked, then re-verified live that `device-hardened` correctly negotiates a real hybrid PQC key exchange (pass) with a classical certificate signature (fail), a real scoped Fully Automated Run reported `pqc_devices_scanned: 1`, and both the Executive Summary page and the new route rendered the real post-fix data live in a browser. 387 `policies` (+17) + 310 `lab/auditor/api` (3 pre-existing WeasyPrint failures) + 113 `lab/auditor/worker` (in-container) + 307 frontend tests (+22) passing, `tsc -b`/`oxlint` clean. |
| 2026-08-02 | **AI Executive Summary (IoTGuard Stage 08) — the final analytical pipeline stage** — see §0 for the full breakdown. Owner asked to plan the last pipeline stage after confirming Remediation is deliberately not wired into the Fully Automated Run. Matches Stage 08's own definition in `docs/reference/IoTGuard.md`: overall posture, highest-risk devices, most significant compliance gaps, priority recommendations - depending on Stages 4-7, all already built. Confirmed with the owner up front: stays a fully deterministic rollup, no AI-generated narrative text, matching every other report in this app's own "never generate a summary paragraph" rule - the "AI" in the name is satisfied by aggregating Stage 07's already-AI-generated, human-reviewed remediation content. New `executive_summary.py` reuses `risk_routes._compute_risk_for_device()` (ranking), `report.build_report_model()` (per-device SA-IOT gaps/evidence+tools/vulnerabilities, called once per device), `nca_routes._evaluator_rows_for_scope()` (NCA gaps), and a direct query against `remediation_blueprints` (already has a denormalized `device_id` column) - nothing reimplemented. New `executive_summary_routes.py` (`GET /executive-summary`, PDF/HTML export). New `ExecutiveSummaryPage.tsx` (`/executive-summary`, last Pipeline sidebar entry): fleet stat tiles, priority-recommendations and significant-compliance-gaps cards, devices ranked by risk highest-first with expand-in-place detail (compliance gaps, evidence+tools, remediation). Verified live end to end: 11 real devices correctly ranked, a device's expanded panel showed its real gaps/evidence/remediation exactly as previously recorded (one blueprint "Reviewed by Lead Auditor," one still "AI-generated"), both PDF (genuine 139KB file) and HTML exports downloaded and confirmed. 370 `policies` + 300 `lab/auditor/api` (3 pre-existing WeasyPrint gaps) + 78 `lab/auditor/worker` + 299 frontend tests passing, `tsc -b`/`oxlint` clean. |
| 2026-08-02 | **AI-Assisted Remediation (IoTGuard Stage 07) via Google Gemini's free tier** — see §0 for the full breakdown. Owner wanted this cheap - Gemini's free tier needs no billing attached at all. Scope confirmed with the owner up front: both SA-IOT verdicts and NCA CGIoT-1:2024 assessments, not just the SA-IOT pilot the old "Not built yet" stub showed, since NCA's `remediation_guidance` is hardcoded empty for every one of its 81 guidelines. New `remediation_engine.py` (pure, builds the Gemini prompt, calls its REST endpoint via plain `httpx.post` - no SDK, no new dependency, `httpx` was already installed - never raises, a failed/malformed call returns `None` so the caller reports an honest failure rather than fabricating a blueprint) + `remediation_routes.py` (generate/list/review, append-only `remediation_blueprints` table, migration 014, same supersede pattern as `compliance_assessments` - never mutates the existing `verdicts.remediation`/`compliance_assessments.remediation` fields). New flat `GET /nca/assessments` (fleet-wide, the NCA equivalent of `GET /verdicts`). Rebuilt `RemediationPage.tsx`: every failing/partial finding gets a "Generate AI remediation" button, the structured blueprint (root cause/steps/priority/effort/caveats) renders behind a new `AiGeneratedBadge` until a human marks it reviewed - a prompt instruction (not a hard guarantee) forbids the model from inventing facts beyond the given finding, which is exactly why the human-review gate exists. A real bug caught by the first live call: the planned default model, `gemini-2.0-flash`, returned 429 "limit: 0" the moment a real key went live (Google had zeroed its free-tier allocation for new keys since - stale model-availability knowledge) - queried Gemini's own ListModels endpoint live and switched the pinned default to `gemini-3.5-flash-lite`, confirmed real quota and correct structured-output support. Verified live end to end: real blueprints generated for both finding types through the browser, review/regenerate-supersede both confirmed correct. 370 `policies` + 289 `lab/auditor/api` (2 pre-existing WeasyPrint gaps) + 78 `lab/auditor/worker` + 294 frontend tests passing, `tsc -b`/`oxlint` clean. |
| 2026-08-02 | **"Fully Automated Run" — one dashboard action drives Discovery through NCA sign-off end to end, zero further clicks** — see §0 for the full breakdown. Owner's framing: automate everything from network scanning to fingerprinting to scoring so end users aren't overwhelmed. Goes further than the guided-workflow phase's own "a human always signs" rule by design (3 clarifying decisions, all confirmed with the owner, each more aggressive than the default recommendation): auto-*records* NCA assessments (not just suggests), auto-submits scan evidence with zero review, and scopes to the whole fleet including a fresh Discovery sweep. New `compliance_assessments.auto_recorded` flag (migration 013) reconciles this with the attestation CHECK constraint - an auto-recorded row still satisfies `attestation_confirmed=true` but is structurally distinguishable from a real human sign-off. New `automated_run_runner.py` (a new `job_runner.py` poll loop) drives every stage through auditor-api's existing endpoints only - no new bypass of device_validation/the scan-test whitelist/the finding-mapping table; scan-job/network-scan execution reuses `process_job()`/`process_network_scan()` directly rather than creating a row and waiting for the next poll iteration, which would deadlock against itself. New `automation_routes.py` (`POST/GET/PATCH /automation/runs`, cancel). New frontend: `AutomatedRunDialog` (states exactly what will run/what won't before starting), `AutomatedRunProgressPage`, `AutoRecordedBadge` + filter tab + "Review & confirm" action reopening the existing retest flow to let a human supersede an auto-recorded row with a real signed one. A real bug caught by the first live whole-fleet run (not unit tests): the runner passed POST /scan-jobs' response straight to `process_job()`, but that endpoint deliberately never returns host/service_type/port (scan_jobs is a pure audit row - only the list endpoint resolves it via a join) - 114 of 115 scan jobs failed with "invalid target: host is required" before being caught and fixed. Re-verified live end to end after the fix: a scoped run recorded 13/13 evidence, auto-recorded 9 real NCA assessments, and a real human "Review & confirm" through the browser correctly superseded one while preserving the full append-only audit trail. 370 `policies` + 266 `lab/auditor/api` (2 pre-existing WeasyPrint gaps) + 78 `lab/auditor/worker` (2 pre-existing yara gaps) + 291 frontend tests passing, `tsc -b`/`oxlint` clean. |
| 2026-08-02 | **Made NCA Compliance guided end to end — all 81 CGIoT-1:2024 guidelines now suggest a status + evidence for the auditor to review and formally sign** — see §0 for the full breakdown. Owner asked to automate every NCA section and gate recording behind an explicit sign-off, executed as a 9-phase approved plan. Phase 0 fixed a real orphaned-suggestion bug (2-6-2/2-6-3/2-7-2 misclassified as organization-scope, plus 5 more guidelines still marked "manual" despite real collectors existing). New `policies/nca/checklists.py` + `compliance_control_checklists` table give all 60 non-device guidelines a real guided checklist (`seed_checklists.py`, 3 reusable templates, every question drawn from real canonical text) evaluated with the same `condition_matches` predicate scan-evidence mappings already use. Every assessment now requires a formal "Confirm & Sign" step (`attested_role`/`attestation_confirmed`/`attestation_statement`, `CHECK`'d server-side) except the system's own `not_tested` placeholder. 3 new device-scope collectors (TLS client-auth, security-log endpoint, monitoring endpoint) raised real coverage to 76/81, honestly reported via a new live `GET /nca/coverage`. `OrganizationalCompliancePage` rebuilt in place into a guided workspace. Hit and fixed 2 real deployment incidents live (a container losing its network attachment mid-recovery, and discovering `lab/auditor/api/*.py` needs an image rebuild, not just a restart, to pick up changes — unlike bind-mounted `policies/`). 370 `policies` (+31) + 253 `lab/auditor/api` (2 pre-existing WeasyPrint gaps) + 282 frontend tests passing, `tsc -b`/`oxlint` clean, verified live at every phase against the running stack. |
| 2026-08-02 | **Added 5 non-camera IoT device fixtures (smart lock, industrial Modbus gateway, router/gateway with UPnP, NVR with RTSP, smart speaker with mDNS) for real protocol/domain variety, fully live-verified** — see §0 for the full breakdown. Grounded in a real, confirmed gap: NCA subdomains 2-13 (Physical Security) and 2-6 (Data Protection) had zero device-scope finding mappings despite being real seeded CGIoT-1:2024 controls. Each device is a small FastAPI app mirroring `smart-camera`'s layout; new worker collectors reuse nmap's real `modbus-discover`/`rtsp-methods` NSE scripts plus two new hand-rolled raw-UDP probes (`upnp_probe.py`/`mdns_probe.py`) for protocols nmap has no per-host script for — a real correction made mid-build after discovering nmap's UPnP script is broadcast-only, not per-host. 8 new NCA finding mappings close the 2-13-2/2-6-2/2-6-3 gap with real evidence. Found and fixed 4 real bugs during live verification (not caught by unit tests alone): a missing DB-level CHECK constraint update (`device_services_service_type_check`, new migration 010) that 500'd on first real registration; `nmap -sV` hanging against both custom protocol servers' non-standard probe responses (fixed by dropping `-sV` and adding `--script-timeout 10s`); an RTSP-methods regex whose own unit-test fixture had copied a wrong two-line output assumption, caught only by reading nmap's actual single-line output live; and `serviceIcons.ts`'s exhaustive `Record<ServiceType, LucideIcon>` correctly failing `tsc` until icons were added for all 4 new types. Verified live end to end against a rebuilt 16-container stack: all 5 devices registered, every new collector run for real with real evidence recorded, NCA recompute producing real auto-suggested FAILs on the target controls for all 5, and a real `TEST-NET-DISCOVERY` sweep classifying all 5 as `iot_device` (including the two UDP-only fixtures via their HTTP-port fallback, exactly as designed). 337 `policies` (+28) + 241 `lab/auditor/api` (2 pre-existing WeasyPrint gaps) + 30 new per-device tests + 271 frontend tests passing, `tsc -b`/`oxlint` clean. |
| 2026-08-01 | **Dashboard overhaul (guided pipeline) — all 13 phases live-verified end to end, 3 real bugs found and fixed** — see §0 for the full breakdown. The 13-phase guided-pipeline overhaul itself was built in the prior session but never written up here since that session's final live-verification step was interrupted by a Docker Desktop networking failure serious enough to require a full OS reboot (`docker_networking_saga` preserved in the now-deleted `handoff.txt`). This session resumed after the reboot, found the DNS bug had survived it too, diagnosed it further via raw UDP queries to `127.0.0.11:53` (inconsistent per-name resolver behavior on `internal-network` only — not a compose config or host-firewall issue), and the user ran Docker Desktop's Troubleshoot → Clean/Purge data, which fixed it (`docs/errors/032`). Re-ran the lab's documented first-time setup (cert-init, mqtt secure-broker password) plus a previously-undocumented one — the NCA catalog's 81 guidelines/~20 finding mappings are seeded imperatively (`policies.nca.seed_catalog`/`seed_finding_mappings`), not via `init.sql`, and needed re-running against the purge-wiped volume. Then drove the entire pipeline live through a real browser (Claude-in-Chrome): Discovery's bulk-register flow (never exercised against a real backend before) registered 3 real devices from a real network scan; Fingerprinting ran a real `nmap` scan and recorded real evidence; SA-IOT Compliance ran a real 10-credential-pair default-creds test and recomputed real FAIL verdicts; Vulnerability Intelligence uploaded real generated firmware and got back real Grype-scanned CVE/KEV data (77 openssl CVEs, matching this project's own historical count); NCA Compliance's cohort "Assess selected" opened a real new browser tab and recorded a real blocking-control failure; Risk Assessment's 7-factor breakdown summed exactly to its displayed score; Remediation's stub correctly showed only real static remediation text. Found and fixed 3 real bugs this live pass exposed that mocked tests couldn't have caught: `risk_assessment` was trivially "reached" the instant any device was registered (`risk.known` means "device exists," not "assessed" — fixed to require real upstream SA-IOT/NCA/vuln signal, deliberately excluding fingerprinting since risk's own inputs never derive from it); `hasSaIotVerdict` counted a `NOT_APPLICABLE` placeholder verdict (created fleet-wide by any recompute) as "compliance reached" for devices that were never actually tested; and `SAIOTCompliancePage` never refetched verdicts after "Recompute verdicts" succeeded, leaving its own counts stale. All three fixed with regression tests (271/271 frontend passing, was 266), `tsc -b`/`oxlint` clean, `auditor-web` rebuilt/redeployed and re-verified live after each fix. |
| 2026-07-31 | **Closed all 4 remaining Week 1 gaps found by the task-by-task audit** — see §0 for the full breakdown. (1) A real complete-assessment test for the partially-hardened profile, mixed 3-PASS/2-FAIL against the real controls. (2) `TEST-TLS-CONFIG` now forces a handshake at each of TLSv1/1.1/1.2/1.3 and reports a real 3-state (`accepted`/`rejected`/`untestable`) per-version enumeration instead of one default-negotiated value — confirmed live that this host's own OpenSSL genuinely can't offer TLSv1/1.1, a distinct honest state from a real server rejection. (3) `collector_versions` on an assessment, derived live from its child scan_jobs (never a new stored column, matching every other rollup in this codebase). (4) `confidence_reason` now auto-fills with a fixed template on both automated evidence-recording paths; new `report_records` audit-trail table + `GET /devices/{id}/report-history`, directly analogous to `compliance_audit_events`. Also fixed two real, unrelated bugs caught along the way: `test_assessments.py` was silently overwriting real evidence files on disk (fixed to isolate `DOCUMENT_STORE_DIR` like its sibling test file already does), and `tsc --noEmit` had been checking nothing all session because this project's root `tsconfig.json` needs `-b` to actually run its project references — `tsc -b --force` immediately caught 2 real errors, now fixed. 297 `policies` + 236 `lab/auditor/api` (2 pre-existing WeasyPrint gaps) + 236 frontend tests passing, `tsc -b`/`oxlint` clean. Migration 009 applied live; all 3 changed images rebuilt/redeployed; verified live end to end for all 4 gaps at once against a real `device-hardened` HTTPS service (brought up for the first time this session via `cert-init`). |
| 2026-07-31 | **Added the assessment history UI to the device detail page, closing the last real gap from a full Week 1 brief re-audit** — see §0 for the full breakdown and `docs/week1-completion-report.md` for the complete task-by-task verification against `week-1-tasks.txt`. 9 of the brief's 10 tasks were already done; the one real gap was that `GET /assessments?device_id=` had no UI caller at all. New "Assessment history" card lists every past Assessment for a device with status/policy version/timestamp, expanding in place to lazily fetch and cache its child collector jobs. New shared `AssessmentStatusBadge` (`severity-badge.tsx`) replaces `RunScanPage`'s own local status-label mapping, so the same Assessment status renders identically on both pages. No backend changes — the endpoint already existed and was already tested. `tsc`/`oxlint` clean, 3 new frontend tests, full suite green except the already-known pre-existing `RunScanPage.test.tsx` timing flake (reproduced identically on the unmodified code, confirmed unrelated). Not yet rebuilt/redeployed to the live images. |
| 2026-07-31 | **Built out Dynamic Risk Assessment (IoTGuard Stage 06) fully** — see §0 for the complete breakdown and `docs/risk-assessment.md` for the full architecture writeup. New `policies/risk/risk_engine.py` (one pure, unit-tested `compute_device_risk()` combining compliance/CVSS/CISA-KEV-exploit-availability/device-criticality/internet-exposure/violation-count/insecure-service-count into a weighted 0-100 score + Low/Medium/High/Critical category, matching the architecture of every other scoring engine in this codebase); new `devices.criticality`/`devices.exposure` columns (migration 008) with computed defaults, editable via the pre-existing but previously-never-called `PATCH /devices/{id}`; new read-only `risk_routes.py` (`GET /risk/devices` worst-first = the org-wide priority ranking, `/risk/devices/{id}` full breakdown, `/risk/fleet-summary`), reusing NCA/vuln-intel functions rather than reimplementing them, never cached; a new dedicated `/risk` dashboard page plus an Overview card and a device-detail badge/edit panel; and a matching section on both the PDF/HTML report and the consolidated device assessment page. 373 backend + 228 API + 227 frontend tests passing (was 373/226/226 respectively before this session's API-suite additions), `tsc`/`oxlint` clean. Verified live end to end: `device-insecure`'s real `/risk/devices/{id}` breakdown hand-checked against the formula (score 39, medium), confirmed in the live report, the deployed dashboard bundle, and the `/risk` route. |
| 2026-07-30/31 | **Built out Vulnerability Intelligence (IoTGuard Stage 05) fully** — see §0 for the complete breakdown and `docs/vulnerability-intelligence.md` for the full architecture writeup. Replaced the 6-entry hardcoded `vuln_reference.py` fallback table with real coverage by wiring in Grype (already installed in the worker image, never invoked) via a hybrid model: scan-time lookups stay 100% local, a scheduled `job_runner.py` check refreshes Grype's local DB and a new CISA KEV cache out of band. New `sbom.py` (manifest → CycloneDX), `cisa_kev.py` (KEV feed fetch/cache), a new read-only `vuln_routes.py` API surface, and dashboard UI (`VulnAdvisoryPanel`/`VulnFreshnessNote`/`KevBadge`) across Overview, the device detail page, the consolidated assessment report, and the PDF/HTML report. Real coverage jump confirmed live: openssl 1.0.1e went from 2 CVEs to 77, busybox 1.19.4 from 0 to 24, with real CISA KEV cross-referencing (Heartbleed confirmed genuinely KEV-listed). Caught and fixed two real bugs live (a staleness-check design flaw that would have re-triggered a DB update on every check forever, and a frontend test race condition) and caught-and-repaired one real, unrelated incident (a corrupted Grype DB from an earlier container restart, handled gracefully by the existing three-tier fallback with zero bad data reaching evidence). 333 backend + 214 frontend tests passing (was 290/193), `tsc`/`oxlint` clean. Verified live end to end through the real production pipeline (register → upload firmware → scan → evidence → dashboard/report), not just against test databases. |
| 2026-07-30 | **Hide non-scannable controls from the assess pickers** — the "This control has no automated collector…" dead-end message appeared because manual-only controls (e.g. SA-IOT-001, whose only test `TEST-DEVICE-ID` has no `SCAN_CATALOG` entry) were still listed in the assess control dropdowns. New `lib/controls.ts::scanAssessableControls()` filters the pickers (device detail assess panel + `AssessVerdictDialog`) to controls with at least one catalogued collector, so the dead-end can't be selected; falls back to all controls if the catalog hasn't loaded. Backend 400 kept as a concise defensive guard (verbose NCA-workspace text trimmed). 3 helper unit tests; verified live SA-IOT-001 is excluded. |
| 2026-07-30 | **Assess-verdict follow-ups** — (a) fixed a misleading error: assessing a control whose required test has no automated collector (e.g. SA-IOT-001 → TEST-DEVICE-ID, which has no `SCAN_CATALOG` entry) told the user to "run TEST-DEVICE-ID first" — impossible through the product. The 400 now distinguishes runnable required tests (names them) from manual-only controls ("This control has no automated collector … assess it manually …"). (b) Added an **"Assess verdict"** button + `AssessVerdictDialog` on the Verdicts page (pick device + control + optional severity → `POST .../assess`; backend 400s shown inline), so a new verdict can be assessed without opening a device page. 1 new backend test (manual-only message) + 2 new frontend tests; `tsc`/`oxlint` clean; rebuilt/redeployed and verified live. |
| 2026-07-30 | **Five owner-requested features, worked as a loop** — see §0. (1) Dropped "(admin/admin)" from the `TEST-AUTH-DEFAULT-CREDS` label (still tries 10 pairs). (2) Verdicts page gained severity + device filters beside the status tabs. (3) New `POST /devices/{id}/controls/{control_id}/assess` (deterministic per-(device,control) verdict from evidence) + an "Assess verdict" control-picker on the device Verdicts card. (4) New consolidated `DeviceAssessmentReportPage` (`/devices/:id/assessment`) compiling profile/inventory/services/firmware/NCA-readiness/verdicts/evidence into one printable page with PDF/HTML/JSON download. (5) New `ScanConsolePage` (`/scan-console`) — a terminal-style runner for whitelisted catalog scans only (`scan`/`list`/`help`/`clear`; sole action is `createScanJob`, server re-validated against the whitelist — not a shell). `tsc`/`oxlint` clean; 6 new assess-endpoint tests + 45 frontend tests across 5 touched/new suites + verdict/catalog/API regression suites pass; rebuilt/redeployed `auditor-api`+`auditor-web` and verified each live. |
| 2026-07-27 | **Firmware upload now accepts `.zip`, not just `.tar.gz`, end to end** — see §0 and `docs/errors/030`/`031`. Owner reported "I cannot upload a firmware"; the picker's `accept=".tar.gz,.tgz"` greyed out files on Windows (030), but the real cause was that the pipeline only handled gzip tarballs and their file was a `.zip` (031). Added a shared `archive_reader.py` (`open_archive()` detects gzip vs zip by magic bytes, uniform member interface, bounded reads preserving the zip-bomb caps); refactored `scan_firmware.py` + `firmware_check.py` off direct `tarfile` use; API accepts+validates `.zip` (magic bytes, unsafe-path check for both formats) and stores under a format-neutral `{device_id}.archive` name; frontend `accept` + helper text updated. 27 worker (tar+zip) + 13 API upload + 6 archive_reader + 22 scan-job tests pass, `tsc` clean; rebuilt/redeployed and verified live: a real `.zip` upload → `TEST-FW-MANIFEST` → worker parsed the zip's manifest and produced real OpenSSL Heartbleed/CCS CVE observations. |
| 2026-07-27 | **Reorganized NCA Compliance into an auditor-usable assessment workspace with auto-verdict suggestions** — see §0 for the full breakdown. Owner asked to make the section "like a real assessment, organized so any auditor can use it"; a scoping question chose *reorganize the existing module* (not rebuild) + *auto-verdict where possible*. The gap: assessing was scattered — the per-device checklist existed but every "Assess" link navigated away, so there was no single workpaper. New per-device workspace (`DeviceAssessmentPage.tsx`, `/nca-compliance/devices/:deviceId`): progress bar, controls grouped by domain, inline Record/Retest opening the dialog in place, filter tabs. New `GET /nca/devices/{id}/suggestions` endpoint pre-fills a suggested verdict from mapped automated evidence (honest polarity — a mapping match implies FAIL since every mapping fires on an insecure condition; 3 informational mappings suggest review_required; absence never implies pass). New `verdict_hint` column on `compliance_finding_mappings` (migration 007 + init.sql + seed) makes that configurable, not hardcoded; new `map_evidence_to_mappings()` returns full matched mappings with `map_evidence_to_controls()` kept as a thin wrapper. `RecordAssessmentDialog` gained a `suggestion` prop (banner + pre-fill; ignored on retest). Entry points added to the NCA device table ("Assess") and device Compliance tab ("Open assessment workspace"); nothing removed. `tsc`/`oxlint` clean, 6 new backend + 15 new/updated frontend tests green (full frontend suite's 10 failures confirmed as host parallel-runner flakes — 64/64 pass in isolation; 1 NCA API failure is the pre-existing WeasyPrint gap). Applied migration 007 to the live DB, rebuilt/redeployed `auditor-api`/`auditor-web`, confirmed the live endpoint returns real auto-verdict data and the new page is served. |
| 2026-07-26 | **Made the Network Map's node layout collision-proof at any device count** — see §0 for the full breakdown. The original `scatter()` (built the same day) placed nodes via rejection-sampled random jitter within a fixed-size zone, which had a real failure mode once enough nodes were packed in: after 40 failed attempts it placed the node anyway, overlapping another. Replaced with `gridPlacement()` — a deterministic grid sized to give every id its own cell, growing rows (and the canvas height, via a computed inline `aspectRatio` replacing the old fixed Tailwind aspect classes) to fit however many nodes there are, rather than cramming more into the same space. Verified with a standalone script that minimum pairwise node distance stays ≈100+ units from 1 to 150 devices, vs. the old algorithm's unbounded worst case. No visual change for the current 6-device fleet (computes to the identical height). `tsc`/`oxlint` clean, full Vitest suite green, rebuilt and redeployed `auditor-web` (confirmed via a bundle hash/size diff that the new build was actually served). |
| 2026-07-26 | **Added the Network Map page (`/network-map`)** — see §0 for the full breakdown. Executed from a self-contained handoff document delivered via Telegram from a separate session where the feature had already been designed, iterated on three times, and finalized on an unmerged branch. Every Step 1 precondition (shared types/components the feature depends on) was verified against this repo's real files before writing anything — all matched exactly, so the spec's code was used unmodified. New `components/network/NetworkGraph.tsx` renders the real two-Docker-network topology (`audit-network`/`internal-network` from `lab/docker-compose.yml`, `auditor-worker` as the one cross-zone bridge) using deterministic scatter + a per-zone Minimum Spanning Tree (Prim's algorithm) rather than a hub-and-spoke layout — the MST approach is a structural guarantee against the star-shaped layout the owner explicitly rejected twice in the design history this document preserved. New `pages/NetworkMapPage.tsx`, one small additive `CardDescription` export on `card.tsx`, a new route, a new sidebar entry, and a CSS dash-flow animation. No new tests (an explicit, stated gap in the handoff document itself, respected as-is). `tsc`/`oxlint` clean, full Vitest suite green (2 unrelated pre-existing environment flakes, confirmed independent in isolation), rebuilt and redeployed `auditor-web`, confirmed live via curl (bundle strings, SPA route, real 6-device fleet data) since the Claude-in-Chrome extension wasn't connected for a visual check. |
| 2026-07-24 | **NCA Compliance dashboard + overall UI/UX consistency pass** — see §0 for the full breakdown. Fixed the same compliance information being shown inconsistently across pages: extracted a shared `DomainSummaryGrid` component (was copy-pasted 3x, which is how a status category went missing from `NCADomainBarChart` unnoticed); gave the two legitimately-different compliance gauges (SA-IOT-* verdicts vs. NCA controls) self-explanatory titles instead of relying on a small caption; added a `size` prop to `NCAReadinessBadge` so it stops visually dwarfing `NCAStatusBadge` in the same table row; added a new `BlockingBadge` (explained via a new `Tooltip` primitive, this app's first) and propagated it to device/org control-list rows, not just the controls catalog; hid the legacy per-device `ComplianceBadge` chip on the Compliance tab where it previously sat confusingly above the real NCA readiness card; migrated `VerdictsPage`'s hand-rolled filter pills to the shared `Tabs` primitive; added `OrganizationalCompliancePage` to the sidebar nav (previously only reachable via an inline link). Frontend-only, no backend changes. `tsc`/`oxlint` clean, full Vitest suite green, rebuilt and redeployed `auditor-web`. |
| 2026-07-24 | **NCA compliance-assessment robustness pass** — see §0 for the full breakdown. Added a Passed/Partially Passed/Failed readiness classification (`overall_classification()` in `policies/nca/evaluator.py`, additive alongside the existing `device_overall_status`/`device_score`) that explicitly does not rely on percentage alone; a new `compliance_controls.blocking` flag (IoTGuard's own judgment call, authored the same way `severity` already is, limited to 3 guidelines — default credentials, unencrypted sensitive data, unnecessary exposed services) that forces Failed regardless of score; a real sixth `review_required` assessment status distinct from `not_tested`; and `POST /nca/assessments/{id}/override` (mandatory justification + auditor identity, never mutates the original row, same supersede-and-audit-trail mechanism as retest). New migration `006-nca-blocking-and-review-required.sql`. 82 `policies/nca` + 205 `lab/auditor/api` (2 pre-existing WeasyPrint gaps, unrelated) + 158 frontend tests passing. |
| 2026-07-23 | **Made the NCA Compliance module real** — see §0 for the full breakdown. Every write endpoint (record/retest an assessment, request/approve/reject an exception, recompute from evidence) already existed and was already tested at the API layer, but had zero UI wired to it - the module was a read-only viewer for script-seeded data, and 60+ organization-scope guidelines had no path to ever being assessed through the product at all. Added `RecordAssessmentDialog`/`RequestExceptionDialog` (scope-adaptive: device picker vs. fixed organizational scope), an Exceptions card + Record/Retest actions on `NCAControlDetailPage` and per-control-row links from the device Compliance tab and organizational page, a new full-catalog `NCAControlsPage` (all 81, filterable), and a "Recompute from evidence" button. Zero backend changes - purely frontend. Verified live: recorded a real assessment on a previously-unassessable governance control, retested it, approved a real exception, and confirmed recompute surfaced real not-tested placeholders from real evidence. 152 frontend tests passing (was 125), `tsc` clean. |
| 2026-07-23 | **Removed Run Scan's "Network Discovery" section** — see §0 for the full breakdown. It required selecting a device before it would even appear, despite the scan itself never using that device's host/port (it always swept the whole subnet) - a leftover overlap with the standalone "Discover devices" panel on the Devices page, which is now the only real entry point (no device selection needed). Added a pointer link from Run Scan to it. Backend catalog/dispatch untouched. 125 frontend tests passing (was 124), `tsc` clean. |
| 2026-07-23 | **Discovery panel persistence + a gentler, more accurate scan** — see §0 for the full breakdown. Registering a discovered host no longer hides the discovery panel or discards its scan results, so multiple hosts from one scan can be registered without rescanning; each one flips to "Already registered" inline as soon as the device list refreshes. The scan command itself is now deliberately gentle for an IoT environment (`-T3` instead of `-T4`, `--max-rate 50`, `--version-intensity 2`) with a per-test 90s timeout override (`SCAN_CATALOG`'s new `timeout_seconds` key, read by `job_runner.py`) since the gentler settings trade a little more time for going easier on constrained devices - verified live this costs no real time in this lab. One real, unrelated accuracy bug caught during that same live-tuning pass (`docs/errors/029`): `--open` was silently omitting every live host with no signature port open (the subnet gateway, infra containers), making the `"unknown"` classification unreachable from real output despite being unit-tested - fixed by dropping `--open`, re-verified live that those hosts now correctly appear and classify as `"unknown"`. 4 new backend tests, 1 new frontend test (124 total), `tsc` clean. |
| 2026-07-23 | **Discovery-first device onboarding** — see §0 for the full breakdown. A new `network_scans` table (no `device_id` at all - deliberately decoupled from the existing per-device `scan_jobs` machinery) + `POST /network-scans` + a second `job_runner.py` poll loop reusing `TEST-NET-DISCOVERY`'s own command/parser. The Devices page gained a "Discover devices" panel: scan the subnet, see every live host classified, click Register to open the existing form pre-filled (device id/name guessed from this lab's container-naming convention, host = the discovered IP, services derived from open ports) instead of typing every field by hand. One real bug caught live (`docs/errors/028`): "Already registered" matched only by IP, missing every real lab device (which registers with a container name as `host`, not an IP) - fixed to match on either. 8 new `lab/auditor/api` + 3 new `job_runner` backend tests (162 total API tests); 123 frontend tests passing (was 114), `tsc` clean. |
| 2026-07-23 | **NCA per-device domain-summary cleanup + a new Network Discovery scan** — see §0 for the full breakdown. Governance and the Third-Party/Cloud domain group no longer show in the per-device NCA domain breakdown (a real, general `applicableDomains()` zero-total filter, not a hardcoded name removal, so Resilience stays visible today and would only disappear on its own if it too became genuinely empty). New `TEST-NET-DISCOVERY` sweeps the whole audit-network subnet and classifies each live host as `iot_device`/`uncertain`/`unknown` from its open-port signature, honestly declining to use MAC-vendor/OS fingerprinting inside this Docker bridge network. Verified live against the real lab: correctly classified all 5 real IoT devices/brokers as `iot_device` and `telnet-sim` as only `uncertain` - the "distinguish another appliance on the VLAN" scenario, with real containers. One real regex bug caught by that live run (`docs/errors/026`, a `\s+`-swallows-the-next-port-line bug) and one unrelated Docker-tooling incident (`docs/errors/027`, a stray empty `device_validation.py` that crash-looped the live worker) - both fixed, both logged. 82 `policies/catalog` + 24 `lab/auditor/api` scan-job + 14 `job_runner` backend tests passing; 114 frontend tests passing (was 108), `tsc` clean. |
| 2026-07-22 | **Dashboard UX/UI improvement pass** — see §0 for the full breakdown. NCA Compliance page rebuilt as a real dashboard (new stacked `NCADomainBarChart`, a `ComplianceGauge` in place of a plain stat tile, a worst-first "Devices needing attention" panel, and a "Reports" card finally linking the 4 CSV/PDF export endpoints that existed in `api.ts` but were never wired into any page); `VerdictsPage.tsx` gained the missing `NOT_APPLICABLE` filter plus conflict/policy-version display for fields that existed in the schema but were invisible in the UI; production-readiness baseline added (`NotFoundPage` + catch-all route, a class `ErrorBoundary` wrapping `<Routes>`, a responsive collapsible sidebar with a hamburger toggle and grouped nav sections); and a consistent toast notification system (`components/ui/toast.tsx` + `lib/useToast.tsx`) replacing several different ad hoc inline success/error paragraphs across `RegisterDeviceForm`, Run Scan, and the device detail page. Verified live via a headless Playwright script against the rebuilt `auditor-web` image and the real dev stack (screenshots of the new dashboard, the mobile sidebar collapse/expand, the 404 page, and a real toast appearing and auto-dismissing after a live device registration) since the Claude-in-Chrome extension was unavailable again this session. 108 frontend tests passing (was 96), `tsc` clean. |
| 2026-07-22 | **Closed every gap `docs/week1-gap-analysis.md` found in the mentor's Week 1 brief** — see §0 for the full breakdown. A real `assessments` entity (groups a `scan_jobs` batch under one id + aggregate status, cancellable); a failed collector now produces `INCONCLUSIVE` (never silence or FAIL) via a new `record-failure` endpoint; `NOT_APPLICABLE` is a real, reachable verdict status derived from existing service-applicability logic; the previously-dead `"when"` YAML mechanism is real code now; evidence conflict detection (`policies/engine/conflict.py`) implements the brief's own documentation-vs-packet-capture example, preferring automated evidence; new `TEST-NET-REACHABILITY` collector and real TLS certificate expiry checking; `source_type`/`policy_version`/`conflict_detected`/`assessment_id` added to evidence/verdicts (all optional, zero breakage to existing callers); HTML/JSON report formats alongside the existing PDF, all three sharing one extended `build_report_model()`; a new path-traversal-safe `/document-store/{path}` route so raw artefacts are actually openable from the UI. Two real bugs caught live against the actual dev database (not by unit tests alone, both logged as `docs/errors/024`/`025` and now regression-tested): conflict detection crashed on a real list-valued observation field, and every device was wrongly marked NOT_APPLICABLE for SA-IOT-001 because its required test has no automated collector at all. Added a systematic 20-case pass/fail/inconclusive/contradictory-evidence matrix across all 5 real controls, a database-persistence test, and `scripts/smoke_test.sh` (verified live against the real stack). New `docs/known-limitations.md`; `lab/README.md` brought current (was still describing the dashboard as Flutter Web). 149 backend `lab/auditor/api` + 148 `policies/*` + 96 frontend tests passing (only the 2 pre-existing WeasyPrint-native-library gaps on this Windows host still fail, unrelated). |
| 2026-07-22 | **Built the full NCA CGIoT-1:2024 compliance module** — see §0 for the complete breakdown (catalog generation, 6-table data model, centralized evaluator, configurable finding-mapping layer, ~25-endpoint API router, 3 new dashboard pages + a Compliance tab on the device detail page, demo seed script). Additive alongside the existing `SA-IOT-*` policy pilot, which is untouched. Two real bugs caught during integration (not by unit tests alone): the evaluator initially misclassified a never-assessed device as PARTIAL instead of "Not Assessed" (caught by hitting the live API against a freshly seeded device with zero assessments), and the finding-mapping layer initially let a `not_equals` rule spuriously match evidence that never carried the relevant observation key at all (`None != []`). Both fixed with regression tests. 133 backend tests + 92 frontend tests passing; `docs/nca-compliance.md` has the full writeup including known limitations (reviewer-identity ≠ real auth, page-range source citations, IoTGuard's own scope/severity classification kept distinct from NCA's text, single fixed organizational scope). |
| 2026-07-07 | Project initialized. Copied reference docs (IoTGuard vision, CGIoT-1:2024) into `docs/reference/`. Read and summarized mentor's preliminary 3-day sprint tasks. Created CLAUDE.md charter, error-log convention, and folder scaffolding. |
| 2026-07-07 | **Stack decisions** (see §9): all-Python spine, FastAPI for device + auditor API; sprint needs **no frontend**; LLM stages use the **Claude API (Opus 4.8)**; run the lab in **WSL2**. Adopted the "AI-assisted, not AI-decided" principle — evidence and verdicts are deterministic Python, never LLM output. |
| 2026-07-07 | Ran a full **brainstorming** pass (Superpowers) on the mentor's 3-day sprint. Decisions: standalone project · full 11-container architecture (Option A) · `auditor-web` = thin Flutter/Dart built last · manual-then-automated assessment · hybrid real/simulated services · target machine = the 32 GB PC · single deliverer. Design approved section-by-section and written to `docs/superpowers/specs/2026-07-07-preliminary-iot-security-lab-design.md`. Created `setup/ssh-mcp/` scripts to remote-control the PC over Tailscale. Next: user reviews spec → set up ssh-mcp + switch Opus→Sonnet → implementation plan. |
| 2026-07-07 | **Spec approved. Git initialized** (commits `d94853e`, `71343b3`). **ssh-mcp connection to the 32 GB PC is working** (host OSRA-PC2025-V2, user `osama`, Tailscale 100.99.182.30, key auth) — verified `hostname`/`whoami` over SSH; MCP registered at user scope. Hit + fixed + logged the Windows `spawn npx ENOENT` bug (**ERR-001**; use `cmd /c npx`). **Boundary reached:** restart Claude Code + switch Opus→Sonnet to load `mcp__ssh-mcp__*`, then write the implementation plan and build on the PC. Open decision: build directly on the PC vs. author-on-laptop + git-sync + run-via-ssh-mcp. |
| 2026-07-07 | **Model switched to Sonnet 5, `mcp__ssh-mcp__*` tools confirmed loaded** (`hostname`/`whoami` succeeded over SSH). **Decided Workflow B** (author on laptop → push → PC pulls + runs via ssh-mcp). Set up **read-only repo access on the PC**: generated a dedicated ed25519 deploy key on the PC, registered it read-only on GitHub via local `gh` CLI, added SSH host alias `github.com-kaust-iot`, cloned the repo to `C:\Users\osama\Projects\kaust-iot-security-lab`. (HTTPS + Git Credential Manager doesn't work here — no TTY/browser over non-interactive ssh-mcp, and PC has no `gh` CLI — so SSH deploy key is the pattern going forward.) Confirmed the PC has **Docker Desktop 29.x + Compose v5 with the WSL2 backend already running** — `docker`/`docker compose` work directly from the ssh-mcp PowerShell session, no need to shell into WSL. **Wrote the full Phases 0-5 implementation plan** (31 tasks, TDD throughout for all pure-Python pieces) via the writing-plans skill → `docs/superpowers/plans/2026-07-07-preliminary-iot-lab-phases-0-5.md`. Next: execute Phase 0 (Task 1 onward). |
| 2026-07-08 | **Phases 0-5 fully implemented, reviewed, and PC-verified — all 31 tasks complete.** Executed via subagent-driven-development in the `phase-0-5-implementation` worktree: fresh implementer subagent + independent reviewer subagent per task, with PC-side Docker/Compose verification over ssh-mcp wherever the lab itself was touched. Phase 0 (contracts), Phase 1 (lab core: 3 device profiles, telnet-sim, 2 MQTT brokers, cert-init, auditor-worker, 2-network topology), Phase 2 (TLS profiles hardening), Phase 3 (Day-1 diagrams/threat model/inventory/README), Phase 4 (Day-2 manual assessment: 12 real evidence entries collected on the PC across nmap/curl/openssl/mosquitto/YARA/Syft/Grype, all schema-valid), and Phase 5 (Day-3 policy-as-code: deterministic policy engine with no `eval`/`exec`, 5 NCA controls mapped to real CGIoT-1:2024 sources, verdict-generation CLI run for real producing 4 controls with correct PASS+FAIL pairs — double the required ≥2). 11 errors hit and logged (`docs/errors/001`-`011`). Final acceptance doc written and independently fact-checked twice (`docs/architecture/phases-0-5-acceptance.md`) — first draft had a wrong test count and some fabricated NCA references, caught by controller cross-checking against the real committed files, then corrected and re-verified line-by-line. **Total: 45 tests passing.** Next: merge the worktree, then plan Phases 6-8. |
| 2026-07-08/09 | **Phases 6-8 implemented and PC-verified — all 20 tasks complete** in the `phase-6-8-implementation` worktree via subagent-driven-development: `auditor-api` (FastAPI, full CRUD, CORS), `auditor-database` (Postgres schema + indexes), `auditor-web` (Flutter dashboard, 4 screens), `traffic-capture` (tcpdump on audit-network), all wired into the 11-container compose stack. Hit and fixed 6 more errors (`docs/errors/012`-`017`), including two genuine infra findings: Docker Desktop's host port-forwarding proxy silently fails to bind ports for containers whose only network is `internal: true` (fixed via a dev-only compose overlay, ERR-017), and a live CORS bug the owner caught by opening a real browser (curl-based verification never exercises CORS). Full stack deployed and smoke-tested on the PC. **Then did a "full UI redesign" pass on `auditor-web` (commit `d84d21f`) that the owner rejected as "AI slop"** — root cause: custom fonts (`Inter`/`JetBrains Mono`) were referenced in `theme.dart` but never bundled in `pubspec.yaml`, no design-approval step ran before implementation, and the result was never visually verified (same blind spot as the CORS bug: checks passed, nobody looked at a real browser). Wrote `docs/NEXT-SESSION-HANDOFF.md` with the concrete root causes and fix plan for the next session. Branch pushed but not yet merged — final whole-branch review and UI redo both still outstanding. |
| 2026-07-09 | **`auditor-web` rebuilt from scratch in React, resolving the "AI slop" complaint.** Owner decided to abandon Flutter Web for the dashboard entirely and switch to React + Tailwind + shadcn-style components. Deleted `lab/auditor/web/`'s Flutter app wholesale (Dockerfile, `lib/`, `test/`, `pubspec.yaml`, `web/`) and scaffolded a Vite + React 19 + TypeScript app in its place: Tailwind v4 (`@tailwindcss/vite`), `@fontsource/inter` + `@fontsource/jetbrains-mono` actually bundled (not just referenced — the exact bug that sank the Flutter attempt), recharts for the compliance gauge/verdict donut/device bar chart, lucide-react icons, react-router for the 4 screens (Overview/Devices/Evidence/Verdicts). Design: dark near-black theme with a single amber brand accent and severity-coded status colors (critical/high/medium/low + PASS/FAIL/PARTIAL/INCONCLUSIVE), monospace accents for control/evidence IDs and raw commands — deliberately avoiding the generic "dark mode + rounded cards + one teal accent" Material look called out in the handoff doc. Verified for real this time: built `auditor-database` + `auditor-api` locally, seeded the actual 12 evidence + 8 verdict records from `document-store/` through the live API, then used Playwright to screenshot all 4 screens against both the Vite dev server and the final built Docker/nginx image (`docker run` on a scratch port, since the shared dev machine already had 8080 bound — ERR-019) — confirmed real fonts render, live data flows through, zero console errors. Added a from-scratch Vitest + React Testing Library suite (14 tests / 7 files, beating the old Flutter suite's 11) since the whole app was replaced. Hit two small errors (`docs/errors/018`-`019`). New Dockerfile is a standard Node-build → nginx multi-stage (replacing the `cirruslabs/flutter` build stage), with an `nginx.conf` adding SPA fallback routing. Deployed to the physical build PC same-day (`git pull` + `docker compose build auditor-web` + `--force-recreate`, using the existing `docker-compose.dev.yml` overlay for host port 8080) and confirmed serving the new build (`curl`'d title tag matches). Still outstanding: the owner's live sign-off in a real browser, then the final whole-branch review and merge to `main`. |
| 2026-07-12 | **Added a live "Run Scan" feature to the dashboard** — a real button that triggers an actual whitelisted test against a live device, not just the CLI/terminal workflow. Built as a job-queue architecture rather than direct execution from the web layer (`auditor-api` never runs a command itself — it only manages `scan_jobs` rows; `auditor-worker`'s new `job_runner.py` polls for pending jobs and is the sole executor, re-validating device/test against a fixed whitelist in `policies/catalog/scan_tests.py` before running anything, commands built as argv lists, never a shell string). The dashboard preserves the project's evidence principle end to end: raw output and observations are captured automatically, but a human still has to type the "finding" text before evidence gets recorded — same requirement as `record_evidence.py`, just through a form. Added an idempotent `POST /verdicts/recompute` (existing `generate_verdicts.py` would duplicate-key-crash on a second run; this one checks each verdict's `evidence_ids` first, safe to click repeatedly). Verified for real: a live nmap scan and a live rejected-login curl against real containers, driven through the actual React UI via Playwright, evidence + verdict visible afterward on the existing pages — not just mocked tests (though there are 74 of those too, all passing). Hit and logged `docs/errors/021`: adding a table to `init.sql` doesn't reach an already-initialized Postgres volume — had to apply the migration by hand on both the local dev DB and the PC's real one. |
| 2026-07-12 | **Added a "Device Console" page to the dashboard** — one card per device (`device-insecure`, `device-partial`, `device-hardened`), each with a button per service the brief requires (login page, login with default creds, device info, config, firmware version, admin reset, privacy doc, health), 24 buttons total. Every click is a real browser `fetch` straight to the device container (no backend proxy) via a new `lab/auditor/web/src/lib/consoleDevices.ts`, deriving each device's base URL from `window.location.hostname` at runtime (same pattern as ERR-020's `api.ts` fix) so the page works identically on localhost, LAN, or Tailscale. Added CORS middleware to the device app itself (`lab/devices/smart-camera/app/main.py`) since browser calls now cross the `:8080 → :8081/8082/8083` origin boundary — 1 new device test (22/22 passing). The two HTTPS devices' self-signed lab certs need a one-time manual "trust" click in a real browser; the UI surfaces this directly as an inline hint instead of failing silently. Verified for real on the physical PC over Tailscale: curl'd CORS headers on all 3 devices, then drove the page itself with Playwright at `http://100.99.182.30:8080/console` — clicked "Device info" on `device-insecure` and got back a live 200 response with real device data (`vendor: AcmeCam`, `firmware_version: 1.0.0-old`) fetched directly from the container. **Follow-up same day:** "Login page" and "Privacy doc" are HTML pages meant to be viewed, not just fetched — clicking them now also opens the real page in a new tab (`window.open`) alongside the existing fetch-result panel, via a new `viewable` flag on `ConsoleEndpoint`. Verified live on the PC with Playwright: clicking "Login page" on `device-insecure` opened a second browser tab showing the real rendered login form at `http://100.99.182.30:8081/`. |
| 2026-07-10 | **Each simulated device now has a minimal `/dashboard` UI, and all three postures are reachable from a browser.** Previously the smart-camera app only had a bare login form plus raw JSON endpoints, and only `device-insecure` was published to the host (via the dev overlay) — `device-partial`/`device-hardened` had no way to be viewed directly. Added `GET /dashboard` (`lab/devices/smart-camera/app/main.py`): shows device info, config (the hardcoded API key rendered in red when exposed — the vulnerability made visible), and a live "Trigger admin reset" button wired to the existing `/api/admin/reset` endpoint, demonstrating the exact posture difference interactively (instant reset with no auth on `device-insecure`; HTTP 401 on `device-hardened`, since the browser sends no `Authorization` header). Added a real `transport` config field mirroring `entrypoint.sh`'s `TRANSPORT` env var rather than guessing it. Left `POST /login`'s response untouched, since it's referenced byte-for-byte by committed Day-2 evidence (`EV-2026-07-08-0015`)'s raw output and hash. Published `device-partial` (`8082→443`) and `device-hardened` (`8083→443`) in `docker-compose.dev.yml` alongside the existing `device-insecure` (`8081→80`). 4 new tests (21/21 passing). Verified for real: built and ran all three device images, confirmed each dashboard renders, confirmed the admin-reset auth difference actually works, confirmed the weak/strong self-signed certs correctly trigger a browser TLS warning (expected — lab test CA, not a public one) — then deployed to the build PC and re-verified all three respond over Tailscale. |
| 2026-07-20 | **Added the missing Deregister action to the device detail page.** `DELETE /devices/{id}` and `api.deleteDevice()` both already existed, but **no UI ever called them** — the owner found this by trying to test the delete/re-add flow. Worth recording as a process gap: six task reviews and a whole-branch review all missed it, because reviews check for defects in code that changed and none of them asks whether a button the plan implied was ever built. Labelled **Deregister**, not Delete, because the action is an inventory operation and not a records one: it drops the `devices` row and cascades to `device_services` only, while evidence and verdicts survive untouched (they carry no FK to `devices` and are immutable audit records). The confirmation dialog states that explicitly rather than leaving the user to guess, since wording it as "Delete" would either scare people away from a safe action or wrongly imply it cleaned up findings. Verified live on the PC: deleting a device with 1 evidence and 1 verdict left both rows intact, `/summary` unchanged at 13/8/4/4, and the device reappeared as an orphan card still showing its counts; re-registering with the same `device_id` reattached the full history, which is why the orphan card's Register button pre-fills the ID — evidence joins on the device_id **string**, so a typo yields a fresh empty device while the orphan keeps the findings. New `confirm-dialog.tsx` primitive handles Escape, backdrop and initial focus but has no full Tab focus trap; noted for a future upgrade. |
| 2026-07-20 | **Added a per-device PDF compliance report, and closed every carried follow-up from the previous branch's review.** `GET /devices/{id}/report.pdf` renders server-side via WeasyPrint from a Jinja2 template plus a paged-media stylesheet: device profile, exposed services, compliance summary, findings with each control's clause text and the exact condition that produced the verdict, and a full evidence provenance table (tool, version, command, timestamp, confidence, SHA-256). Deliberately a **light** document rather than the dashboard's dark theme, status always rendered as a word so it survives greyscale printing, and **IoTGuard branding with an NCA citation rather than the NCA emblem** — the report states pass/fail verdicts and must not imply the regulator issued it. No LLM-generated narrative anywhere: every string is a fixed label, a database value, or YAML text copied verbatim, because a generated summary would contradict the report's own determinism claim. **The defining bug of this branch:** WeasyPrint silently ignores every `@font-face` rule and falls back to DejaVu Sans unless a `FontConfiguration()` is threaded through *both* `CSS()` and `write_pdf()` — and the fallback is invisible, since DejaVu covers `§`, `—` and hex and has distinct weights. The first implementer rendered a PDF, looked at it, and reported the fonts verified; review disproved it via `pdffonts`. The fix ships with a detector that inflates the PDF's compressed object streams (a raw byte search false-negatives even on correct embedding) plus a negative-control test that omits `font_config` and asserts the fallback reappears, so the detector cannot rot into a vacuous pass. Also fixed, all carried from the device-registration review: scan commands now use the resolved port (a device on HTTP:8080 was probed on 80 and produced evidence attributed to the wrong service — default-port commands kept byte-identical so committed evidence stays consistent); `post_scan_job` **and** `GET /scan-jobs` both resolve a device's service by matching the test's `applicable_service_types` instead of `LIMIT 1` (the first fix alone only moved the failure from creation time to execution time); PATCH now validates `display_name` like POST; the seeder can repair missing service rows (its `ON CONFLICT` was unreachable dead code, so the docstring's idempotency promise was false); `device_validation.py` is baked into the worker image instead of arriving by single-file bind mount; `encodeURIComponent` on four API paths; and device cards are now wholly clickable with unregistered cards no longer linking to a detail page that 404s. Two orphaned 9-byte scratch files were deleted from the PC rather than committed — they were referenced by no evidence record, and committing them would have put junk into the audit trail dressed as evidence. Final whole-branch review returned no blocking issues; three cheap findings were fixed before merge (a path-traversal guard in `_load_control` matching the one its module neighbour already used, font-embedding assertions against the real relative-URL stylesheet rather than only a synthetic one, and `white-space: pre-wrap` so a command's whitespace reaches the PDF byte-identical). |
| 2026-07-19 | **Devices became first-class database records, and the dashboard gained device registration, per-device detail, and NCA Controls screens.** Executed as a 14-task plan via subagent-driven-development (fresh implementer + independent reviewer per task) on `worktree-device-registration`. Backend: new `devices` + `device_services` tables; full device CRUD; a standalone `device_validation.py` that replaced the old hardcoded `allowed_devices` whitelist as the scan security boundary (targets restricted to container names or `172.30.0.0/24`, infrastructure hostnames denied, argv-injection blocked by requiring an alphanumeric leading character, IPs parsed with `ipaddress` so octal forms like `0172.030.0.1` cannot bypass the range check); `auditor-worker` re-validates the same values read back out of the database before building any command, treating the DB as untrusted input; scan tests re-keyed from device names to `applicable_service_types`; a per-control verdict rollup endpoint. Frontend: registration form with field-level API error rendering, per-device detail page, NCA Controls list + detail, and the deletion of `deviceMeta.ts` / `consoleDevices.ts` so device identity now comes from the API alone. **Review caught real defects the plan itself introduced**, including a port scan narrowed to a single known port (destroying the discovery purpose that evidences SA-IOT-003 — owner chose to restore full-range `-p-`), validation errors that rendered nowhere for three field names, a control-detail page that hung forever on an unknown ID because the backend returns 200-with-empty-data rather than 404, and a `Device` type that lied about three of the four endpoints returning it. **PC verification:** migration + seed applied to the live database with `GET /summary` byte-identical before and after (13 evidence / 8 verdicts / 4 PASS / 4 FAIL — note 13, not the plan's stale 12), all 11 containers healthy, and every new screen driven in a real browser over Tailscale including a live rejection of host `10.0.0.5` rendered under the Host input. Also fixed `telnet-sim`'s long-standing unhealthy status: BusyBox `nc` has no `-z` flag **and** `localhost` resolves to IPv6 while the service binds IPv4 — ERR-005 had diagnosed the same IPv6 issue in 2026-07 but its fix only landed in the Dockerfile `HEALTHCHECK`, which the Compose `healthcheck:` block overrides (`docs/errors/022`). |
| 2026-07-19 | **Merged `worktree-phase-6-8-implementation` into `main`** — fast-forward to `fa73983`, 48 commits, 111 files, +9,266/-147. `main` had zero commits the branch lacked, so no conflicts and no merge commit. This also resolved a documentation trap: `main`'s CLAUDE.md had been stale since 2026-07-08 (still claiming Phases 6-8 were merely "planned") while the branch's copy was fully current — the fix was merging, not rewriting. **Lab restored on the build PC:** Docker Desktop was found not running (all 11 containers `Exited (255)` from an engine restart, not a crash — images intact); started the engine and `docker compose up -d` brought all 11 back, 9 reporting healthy. **Known issue:** `telnet-sim` is `Up (unhealthy)` — healthcheck fails with exit 1 and empty output on a 4-run streak; the container itself is running, so this looks like a broken healthcheck command rather than a dead service. Not yet diagnosed. Also noted: 3 uncommitted evidence files on the PC in `document-store/raw/`. Owner scoped the "production-ready rebuild" as a **deferred** later track — current work continues on the existing 11-container lab. |
| 2026-07-21 | **Restructured the "Run Scan" test picker into the 3 Day-2 assessment sections, and automated 3 tests the controls layer had been waiting on since Day 3.** Owner asked for Web and Authentication / Network and Protocol / Simulated Firmware Analysis as exactly 3 sections with per-test checkboxes (run one test, or select-all a section) — matching CLAUDE.md §4's Day-2 brief wording verbatim. Section 3 (firmware) ships here as static and disabled, pending a firmware-upload feature (see the same-day changelog entry below for how it went live within hours of this one). Sections 1 and 2 got 7 new live `SCAN_CATALOG` entries in `policies/catalog/scan_tests.py` (`TEST-AUTH-ANON-ACCESS`, `TEST-AUTH-SESSION`, `TEST-ADMIN-UNAUTH`, `TEST-NET-HTTP-INSPECT`, `TEST-MQTT-OPEN`, `TEST-TLS-CONFIG`, `TEST-NET-PKTCAPTURE`) alongside a new `category` field on all 10 (also exposed by `GET /scan-tests`). **Discovered mid-design, not assumed:** `TEST-ADMIN-UNAUTH`/`TEST-MQTT-OPEN`/`TEST-TLS-CONFIG` were not new — `policies/controls/SA-IOT-004.yaml`/`SA-IOT-005.yaml` already declared them as `automated_test_ids` with real evidence behind them (`EV-2026-07-08-0017/0019/0020`) from `lab/auditor/worker/tests/run_catalog.md`'s manual runbook; wiring them into the live catalog automates a Day-3 gap rather than inventing anything, and it means recording evidence through the new UI for these three will genuinely change SA-IOT-004/005's verdicts. The TLS test turned out simpler than planned: plain `openssl s_client -brief` (no cert mount needed) already prints `certificate key too weak` for the lab's 1024-bit cert and omits it for the 2048-bit one — confirmed against the real committed raw output before writing the parser, not assumed. MQTT testing needed no schema change either, once it was confirmed the two MQTT brokers are seeded as their own top-level devices (`mqtt-broker-insecure`/`-secure`), not sub-services of the camera devices. Packet capture (`lab/auditor/worker/scan_scripts/packet_capture.py`, new) needed real new infra — `tcpdump` added to the worker Dockerfile and `cap_add: [NET_ADMIN, NET_RAW]` added to `auditor-worker` in `docker-compose.yml`, mirroring the existing `traffic-capture` service — because the worker has to capture its own request/response traffic (a Docker bridge won't let a third party see another pair's unicast traffic). **Hit and fixed one real bug live on the PC** (`docs/errors/023`): tcpdump's "listening on" readiness banner doesn't guarantee the capture ring buffer is actually attached on this Docker Desktop/WSL2 host — a single fetch right after the banner captured 0 packets non-deterministically; fixed by firing the GET up to 3 times with a short gap inside the same capture window (5/5 trials clean afterward). Frontend (`RunScanPage.tsx`): replaced the old single-test dropdown with grouped checkboxes, a "select all" per section, and a "Run selected (N)" batch launcher using `Promise.allSettled` with per-test-id error tracking; extracted the per-job result/finding UI into a `ScanJobCard` component so each launched job gets its own polling hook instance instead of calling a hook in a loop. **Verified for real, not just unit-tested:** all 10 live tests run through the actual API/worker against the real seeded devices and both real MQTT brokers, output/observations inspected by hand for each (TLS correctly told the weak cert from the strong one, MQTT correctly showed anonymous-accepted vs. rejected, packet capture correctly showed plaintext-visible on HTTP vs. not on HTTPS); then the same flow re-verified by driving the actual React UI with a real browser (select-all, batch-launch 3 tests, independent job cards, record evidence) end to end. 47 backend + 59 frontend tests passing. One real evidence record, `EV-2026-07-21-0001`, was created on `device-insecure` during this live verification — see §0 next-steps for a note on it. |
| 2026-07-21 | **Added device firmware upload and wired it end-to-end into Run Scan's Simulated Firmware Analysis section — same day as the restructuring above.** Backend: `POST`/`DELETE /devices/{id}/firmware` (`lab/auditor/api/main.py`) accept a `.tar.gz`/`.tgz` archive, cap the upload at 20MB by counting bytes read rather than trusting the client's `Content-Length` header, open it with `tarfile` to reject any member path containing `..` or a leading `/` (defense in depth — `firmware_check.py` only ever reads member bytes in memory, never `extractall()`s, but a future maintainer might not know that), store it under `document-store/firmware/{device_id}.tar.gz`, and hash it into new `devices.firmware_filename`/`firmware_sha256`/`firmware_uploaded_at` columns (`lab/auditor/db/migrations/002-devices-firmware-columns.sql`, following the `init.sql`-doesn't-reach-an-existing-volume pattern from `docs/errors/021`). A new `firmware` test category (7 `SCAN_CATALOG` entries, `TEST-FW-VERSION` through `TEST-FW-UPDATESCRIPT`, matching the exact 7 items the Day-2 brief lists) has `applicable_service_types: ()` — firmware tests are keyed on `device_id` alone, not a live host/port, so `is_firmware_test()` (`policies/catalog/scan_tests.py`) makes both `post_scan_job` and `job_runner.py`'s `resolve_target`/`is_applicable` skip live-target validation entirely rather than failing it on empty input; `lab/auditor/worker/scan_scripts/firmware_check.py` (new, 9 tests) dispatches per check name rather than forcing all 7 through one shape — 3 (secrets/apikey/certkey) reuse the pre-existing offline `scan_firmware.scan_archive()` YARA scanner instead of duplicating it, the other 4 are structural (member-name lookup, JSON parse, shebang sniff). Reusing `scan_archive()` on a now-arbitrary user upload (previously it only ever saw synthetic Day-2 fixtures) meant it needed zip-bomb hardening: a per-member size cap plus a running total-bytes budget that stops opening further members once exceeded, since a tar header's declared size is attacker-controlled and can understate real decompressed size. The registration form (`RegisterDeviceForm.tsx`) also gained an optional firmware-upload field so a device can be registered with firmware in one step; a failed upload there doesn't fail the registration (the device already exists by that point) — it shows a distinct non-blocking warning and lets the device be uploaded to later from its detail page. `seed_devices.py` now seeds `device-insecure` with a `telnet` service entry too, matching the telnet server this same day's other change turns on for it. Frontend: `RunScanPage.tsx`'s firmware section (previously fully static, see the correction above) now renders live, checkable tests once `selectedDevice.firmware_sha256` is set, using the same `TestCheckbox`/select-all pattern as sections 1-2 — the one structural difference is that firmware tests can't come from `testsForDevice`'s service-type intersection (empty `applicable_service_types` would never match), so `testsInSection("firmware")` special-cases them; when no firmware is uploaded the section stays disabled with a link to the device detail page instead of the old "run manually" hint, which described a path this feature has now superseded. `DeviceDetailPage.tsx` gained a Firmware card (upload control / filename+hash+remove) — the `Upload` icon import and `api.ts`'s `uploadFirmware`/`deleteFirmware` methods had already been added in an earlier, interrupted pass at this feature and were sitting unused (`tsc` was failing on this before this session: 2 unused-import errors plus 13 `Device`/`DeviceBase` test fixtures across 4 files missing the new required `firmware_*` fields — all fixed here). **Verified for real, not just unit-tested:** built and uploaded a throwaway `.tar.gz` through the actual device detail page in a real browser against the live stack, watched the Run Scan page's firmware checkboxes go from disabled to live, ran `TEST-FW-VERSION` for real (`job_runner.py` executed `firmware_check.py` against the real uploaded file and returned real — if unsurprising, since the throwaway archive didn't contain a real version file — parsed observations), then removed the firmware and confirmed the section reverted to disabled. 64 frontend tests passing (was 59; +5 for the new firmware upload/delete/error-path coverage). |
| 2026-07-21 | **Added a native telnet server to `device-insecure`, replacing that profile's dependence on the separate `telnet-sim` container.** `lab/devices/smart-camera/app/telnet_server.py` (new, from scratch) binds port 23 in a daemon thread started from the app's own `startup` event, sends a `"{vendor} {model} Telnet Management Console\r\nlogin: "` banner on connect, and is gated by a new `telnet_enabled` setting (`app/config.py`) that defaults off and is turned on only by `profiles/insecure.env`'s `TELNET_ENABLED=true` — `device-partial`/`device-hardened` never enable it, matching the lab's posture design (Telnet is the insecure profile's vulnerability, not a shared service). Dockerfile now `EXPOSE`s `23` alongside `80 443`. This is deliberately separate from the standalone `telnet-sim` container, which stays as-is (it's had recurring healthcheck flakiness — `docs/errors/005`, `022` — but that's a healthcheck bug, not a reason to remove the service it's simulating). **Verified for real**: connected from inside `auditor-worker`'s container to `device-insecure:23` and got back the real banner byte-for-byte. 23 device tests passing (1 new test for the banner). |
| 2026-07-21 | **Removed the Services section from the device detail page.** The card listing each service's protocol/internal port/published port (`DeviceDetailPage.tsx`) is gone; the underlying `device_services` data and API responses are untouched (still needed for device registration and scan-test service-type matching), it's just no longer rendered as its own section. Removed the now-unused `serviceIcon` import and `services` destructuring alongside it. One test updated (a `/8081/` port assertion that depended on the removed card). |
| 2026-07-21 | **Enriched every scan test's JSON observations with auditor-facing detail: notes, and for firmware packages, real vulnerability data.** All 15 `parse_observations` functions in `policies/catalog/scan_tests.py` now return a `notes: [str]` array — deterministic, rule-based guidance (e.g. what a missing `Content-Security-Policy` header actually exposes, why unauthenticated MQTT matters), never LLM-generated, consistent with this project's determinism rule. New `policies/catalog/vuln_reference.py`: a small, explicitly non-comprehensive local lookup (`lookup_component(name, version)`, offline, no live NVD/CVE/CISA-KEV call) that `TEST-FW-MANIFEST` now runs against every package in a device's firmware manifest, replacing the bare `{name, version}` dicts with `outdated`, `eol`, `latest_known_version`, `official_patch_available`, `patched_version`, and `cves` (each a real CVE ID + CVSS + fact-checked summary — not fabricated). Only 6 (component, version) pairs are populated, matching exactly what `generate_firmware.py`'s synthetic fixtures ship (e.g. OpenSSL 1.0.1e → CVE-2014-0160 "Heartbleed" + CVE-2014-0224 "CCS Injection", both real and independently verified before being written down); anything not in the table returns an honest "no local reference data" result rather than a guessed one — the explicit design goal was never to assert something unverified. `TEST-NET-PORTSCAN` also now parses nmap's SERVICE/VERSION columns into a `services` list per open port (best-effort only — nmap's free-form version text doesn't reliably key into the small reference table, so it's surfaced for manual cross-check rather than auto-matched), and `TEST-NET-HTTP-INSPECT` attempts a `name/version` split of the `Server` banner through the same lookup. No control YAML depends on any of the fields this touched (`SA-IOT-002` through `-005` key on `default_creds`/`telnet_open`/`mqtt_tls`/`weak_cipher`, all left untouched here — `telnet_open` itself was removed in a later same-day change below, which migrated `SA-IOT-003` off it) and the evidence schema's `observations` field was already a schema-less `object`, so nothing downstream needed to change. **Verified for real, not just unit-tested:** built the `device-insecure` firmware fixture via `generate_firmware.py` (real OpenSSL 1.0.1e / BusyBox 1.19.4 — the exact versions this reference table covers), uploaded it through the live device detail page, ran `TEST-FW-MANIFEST` through the real API/worker (`POST /scan-jobs` → `job_runner.py` → `firmware_check.py`), and confirmed the real returned JSON carried the real Heartbleed/CCS Injection CVE data end to end. 70 `policies/catalog` scan-test tests (was 60) + 7 new `vuln_reference` tests + 31 `job_runner` tests (2 updated for the new observation shape) passing. |
| 2026-07-21 | **Three owner-requested refinements to how Run Scan tests observe and report.** (1) Dropped the boolean `observations.telnet_open` field from `TEST-NET-PORTSCAN` (the `open_ports` list plus a still-present `services`/`notes` breakdown says the same thing without a special-cased field) — `SA-IOT-003` was the only control depending on it, migrated to `field: observations.open_ports, op: contains/not_contains, value: 23` instead, which required adding a `not_contains` op to `policy_engine.py`'s `OPS` table. Verified this reproduces the exact same historical PASS/FAIL against the real committed evidence that used to carry both fields (`EV-2026-07-08-0013/0014`, which already had `open_ports` alongside `telnet_open`). (2) `TEST-AUTH-DEFAULT-CREDS` no longer only tries `admin:admin` - it chains the 10 most commonly documented IoT default credential pairs (admin:admin/password/1234/12345, root:root/toor/admin, a blank admin password, user:user, guest:guest — the same pairs widely published in IoT security research, e.g. Mirai's credential list) into one `curl --next` invocation (still a single argv list, never a shell string), reporting `credentials_tried`, `working_credentials`, and a `default_creds` boolean for `SA-IOT-002` to keep keying on. (3) Generalized `TEST-NET-HTTP-INSPECT`'s `banner_discloses_framework` check from a hardcoded `"uvicorn" in banner` (this lab's own smart-camera app) to "any non-empty Server header discloses something" — meaningful for whatever product gets registered, not just this one. **Verified for real against the live stack**: ran a real nmap scan (raw output confirmed no `telnet_open` key, real per-port `services` list including the native telnet server from an earlier session showing up as `telnet?`), and ran the real 10-credential chain against `device-insecure` (`curl --next` × 9, only `admin:admin` — its actual seed credential — came back accepted). 72 `policies/catalog` + 9 `policy_engine` tests passing. |
| 2026-07-21 | **Added a per-device and fleet-wide NCA CGIoT-1:2024 compliance percentage**, after the owner uploaded the actual CGIoT-1:2024 PDF to the repo root — already fully transcribed in `docs/reference/CGIoT-1_2024.md` from the identical source PDF, so this was "build the missing feature," not "digest a new document." `GET /devices/{id}` gained a `compliance` object and `GET /summary` gained a `device_compliance` breakdown, both from one new `_compliance_from_verdict_rows()` helper: percentage = passing / **tested** controls (the owner's explicit choice over "percent of all 5 mapped controls," so an unassessed control shows as missing coverage rather than being assumed a fail), keeping only the most recent verdict per `control_id` since a control can be re-tested and would otherwise double-count (confirmed against the real data: `SA-IOT-003` already carries 2 historical verdicts for `device-insecure`). Frontend: a new `ComplianceBadge` (color-scaled: ≥80% pass-green, ≥50% amber, below red, `null` "not assessed" gray) on the device detail page (originally placed next to the tier badge - that badge was removed the same day in a later change below, and the compliance badge stayed put on its own), and a new "NCA CGIoT-1:2024 compliance by device" card on Overview, sorted worst-first and linking to each device — distinct from and additional to the pre-existing fleet-wide "Compliance score" gauge (which already existed, uses a different PASS+½·PARTIAL formula across raw verdict counts without per-control dedup; both now coexist, clearly separately labeled). **Verified for real**: hit the live `/summary` and `/devices/device-insecure` endpoints and got back real numbers matching the actual verdict history (device-insecure 0%, device-hardened 100%), then confirmed the Overview breakdown's sort order and device links in a real browser. Also fixed a real, reusable local-environment gap while verifying this: 21 of the API test suite's tests were failing on this Windows host purely because `main.py` hardcodes `/work/...` absolute paths for schema/controls files that only resolve inside the Docker containers - a `C:\work` → `policies` directory junction (host-local, not part of the repo) resolves the same way Windows resolves `Path("/work/...")`, dropping host-side API test failures from 21 to 1 (WeasyPrint's `libgobject` native library isn't installed on Windows - unrelated, pre-existing, and out of scope here). 5 new/updated `test_devices_summary.py` tests passing; 104 of 105 API tests passing overall (was 81/102 before the junction). |
| 2026-07-21 | **Added a light theme toggle to the dashboard**, which had been dark-only since the 2026-07-09 React rebuild. A Sun/Moon button in `TopBar.tsx` calls a new `useTheme.ts` hook that toggles a `data-theme="light"` attribute on `<html>` and persists the choice to `localStorage`; a small inline script in `index.html` applies the stored preference before React hydrates, so there's no flash of the wrong theme on load. `index.css` gained a full light-mode override block (`:root[data-theme="light"] { --color-bg: ...; }` etc., same custom-property names as the existing dark `@theme` block) — every `var(--color-*)` reference across the whole app repaints correctly with zero component changes required. **Verified for real in a browser**: toggled to light, confirmed the Overview gauges/charts, stat tiles, and the new compliance badges all keep readable contrast, confirmed the choice survives a client-side navigation to the device detail page, then toggled back. 4 new `TopBar.test.tsx` tests passing. |
| 2026-07-21 | **Removed the security-tier UI and service-registration quick-picks; Run Scan now blocks launching a second scan while one is in flight.** The tier badge/pill is gone from `DevicesPage.tsx`, `DeviceDetailPage.tsx`, and `DeviceConsolePage.tsx`, and the "Security tier" `<select>` is gone from `RegisterDeviceForm.tsx` (every new device now registers `tier: "unknown"`, the backend's own default for an omitted tier) — deliberately UI-only, not a schema migration: the `tier` column, `device_validation.py`, and the PDF report (a different deliverable, not mentioned in this ask) are untouched. `lib/deviceTier.ts`, the shared tier-badge-styling module, is deleted outright now that nothing imports it. Also removed from `RegisterDeviceForm.tsx`: the "Smart camera (HTTP)"/"Smart camera (HTTPS)"/"MQTT broker"/"MQTT broker (TLS)" quick-pick buttons that pre-filled the services repeater - the repeater itself is untouched. Separately, `RunScanPage.tsx`'s "Run selected" button is now disabled for the *entire* time a previously-launched job is `pending`/`running`, not just during the synchronous launch click: each `ScanJobCard` reports its polled status up via a new `onStatusChange` callback into a `jobStatuses` map on the page, seeded immediately from the `POST /scan-jobs` response itself (not just the first poll) so there's no gap where a second launch could slip through; an inline "a scan is already running" hint explains why the button is greyed out. **Verified for real in a browser**: registered device cards and the device detail page show no tier badge, the registration form's Services section has no quick-pick row, and clicking "Run selected" against the real `device-insecure` container visibly disabled the button until the real nmap job (job #65) reached `awaiting_finding`, at which point it re-enabled. 77 frontend tests passing (was 71). |

---

## 9. Stack Decisions

- **Model:** Opus 4.8 used across the board — as the build assistant, and as the platform LLM for Stages 7–8. Resolves the LLM-provider question → **Claude API**.
- **Determinism rule (important for research):** evidence collection (Day 2) and verdict logic (Day 3) are **deterministic Python** — reproducible from `(tool, version, command, timestamp, hash)`. LLMs assist/explain but never decide a Pass/Fail. Framed as "AI-assisted, not AI-decided."
- **Backend:** FastAPI for both the simulated device and `auditor-api` (Flask dropped — no second framework).
- **Sprint frontend:** none required — the 3-day acceptance tests are endpoint/MQTT/port/JSON based. Dashboard (Flutter Web per vision, or React/HTMX) is deferred to the full platform.
- **Environment:** WSL2 on Windows (best compatibility for nmap/Scapy/tcpdump/Docker networking).
- **Sprint core (5 things only):** FastAPI · PostgreSQL · nmap/python-nmap · PyYAML · firmware CLI tools (file/strings/grep/YARA/Syft/Grype).

### Still open
- [ ] Team fluent in Flutter/Dart or React? (No — as of 2026-07-07.) Flips the *platform* dashboard choice later; irrelevant to the sprint.
- [ ] Frontend stack for the final platform deliverable (revisit after the sprint).
