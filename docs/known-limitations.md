# Known Limitations Register

A single consolidated place for limitations that were previously scattered
across `CLAUDE.md` changelog prose and code comments. Written per the Week 1
brief's explicit request for a "known limitations register." This is the
`SA-IOT-*` assessment pipeline's own register — the separate NCA CGIoT-1:2024
compliance module (`policies/nca/`) has its own limitations section in
`docs/nca-compliance.md`.

## Assessment cancellation

`POST /assessments/{id}/cancel` only prevents **not-yet-started** (`pending`)
child jobs from running; a job already `running` is left to finish rather than
killed mid-execution. Killing an in-flight `subprocess.run` safely would need
process-group tracking `lab/auditor/worker/job_runner.py` doesn't have today.
This is standard "cancel" semantics for already-dispatched work, not a bug,
but it means a cancelled assessment can still show one more job transition to
`recorded`/`failed` after the cancel call returns.

## Collector stdout/stderr

`job_runner.py` concatenates a collector's stdout and stderr into one
`raw_output` string (`raw_output = (result.stdout or "") + (result.stderr or "")`)
rather than preserving them as two distinguishable streams. The content is
fully preserved; only which stream a given line came from is lost.

## Per-control coverage gaps

Each of the 5 `SA-IOT-*` controls' YAML now carries a `limitations` field
describing exactly what it does and doesn't check (surfaced in every report
format). In summary:

- **SA-IOT-001** (device identification): only checks that a device-info
  endpoint discloses vendor/model/firmware — doesn't verify the values are
  accurate. `TEST-DEVICE-ID` has no automated collector wired into
  `SCAN_CATALOG` at all yet, so this control is never automatically
  evaluated in practice; it stays unassessed (not `NOT_APPLICABLE` — see
  below) until a real collector is built for it.
- **SA-IOT-002** (default credentials): only tries 10 commonly documented
  default pairs against an HTTP(S) login form — no brute force, no
  SSH/Telnet/MQTT credential checking.
- **SA-IOT-003** (unnecessary services): only the Telnet-specific
  pass/fail condition is automated; a full port scan runs and records every
  open port, but other unnecessary services need manual review of the same
  output.
- **SA-IOT-004** (insecure protocols): only evaluates MQTT, not any other
  protocol a device might use.
- **SA-IOT-005** (TLS configuration): checks key strength and protocol
  version only — not certificate expiry, hostname/CN matching, or full
  chain-of-trust validation (a separate, real `cert_expired` field was added
  to `TEST-TLS-CONFIG`'s observations for expiry specifically, but SA-IOT-005
  doesn't currently key its verdict on it).

## NOT_APPLICABLE vs. "not yet automated"

`policies/engine/policy_engine.py::is_control_applicable()` deliberately
treats a required test_id with **no entry in `SCAN_CATALOG` at all** as
"possibly applicable" (never `NOT_APPLICABLE`) — an absent collector tells us
nothing about whether a control genuinely doesn't apply to a device's
registered services, only that nobody has automated it yet. `NOT_APPLICABLE`
is reserved for controls whose required test_ids **do** exist in
`SCAN_CATALOG` but whose `applicable_service_types` never match any of the
device's registered services (e.g. SA-IOT-004/MQTT against an HTTP-only
device). Getting this distinction wrong was caught live against the real
dev database during this session — see `docs/errors/025-not-applicable-confused-with-not-automated.md`.

## Evidence conflict detection

`policies/engine/conflict.py::detect_conflict()` only detects disagreement on
the specific field(s) a control's own `pass`/`fail` conditions key on — two
evidence rows that disagree on an unrelated observation field are not
flagged as conflicting. When a real conflict is found, the row with
`source_type == "automated"` always wins over `"manual"`/`"document"` rows;
among multiple automated rows (or no automated row at all), the most recent
timestamp wins. There's no separate manual "which one is right" override —
conflict resolution is always automatic once evidence is recorded.

## Reviewer identity is not authentication

This entire application has no login, session, or user/role concept
anywhere. Nothing in the Week 1 `SA-IOT-*` pipeline requires a reviewer name
(that requirement applies to the separate NCA module's manual
assessments/exceptions — see `docs/nca-compliance.md`).

## Report formats

- The HTML report (`GET /devices/{id}/report.html`) inlines the same
  stylesheet the PDF uses, but its `@font-face` `url()`s stay relative and
  won't resolve from an API route path — the browser falls back to a system
  font. Cosmetic only; every value in the document is identical real data.
- Policy version tracking (`compliance_assessments.policy_version` /
  `verdicts.policy_version`) is recorded per assessment/verdict at the time
  it's created, taken from the control YAML's own `version:` field. There is
  no mechanism yet to diff two policy versions against each other or show
  what changed between them.

## Clean-deployment smoke test

`scripts/smoke_test.sh` brings the stack up and polls Docker health checks
plus a few HTTP endpoints; it does not (by default) tear down and remove
volumes first, since that would destroy real seeded data. Pass `--fresh` for
a true from-nothing deployment test — but never against a stack whose data
you want to keep.
