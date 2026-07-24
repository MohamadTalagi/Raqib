# CLAUDE.md — KAUST IoT Security Project

> **This file is the single source of truth for the project.** It MUST be updated every time
> something meaningful changes: a new component is built, a decision is made, a tool is chosen,
> a task is completed, or a milestone is reached. Treat it as a living document.
>
> **Last updated:** 2026-07-24
> **Maintained by:** Team of 4 · KAUST Academy — Cybersecurity Specialization
> **Timeline:** 3-week project · Tooling: Claude Opus 4.8

---

## 0. Current Status — RESUME HERE 👈

**Phase:** **NCA Compliance dashboard + overall UI/UX consistency pass — COMPLETE**
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
