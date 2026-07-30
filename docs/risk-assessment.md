# Dynamic Risk Assessment (IoTGuard Stage 06)

## What this closes

Stage 06 of the IoTGuard vision (`docs/reference/IoTGuard.md`) calls for combining
compliance score, CVSS, exploit availability, device criticality, internet exposure,
violation count, and insecure-service count into one risk score, category, and
org-wide priority ranking. Before this work it was entirely unbuilt — confirmed by a
repo-wide grep for risk-scoring code before starting: zero hits.

## Design decisions (agreed with the project owner before implementation)

1. **Device criticality and internet exposure** — neither existed anywhere in the
   data model. Added as **auditor-set fields with a sensible computed default**
   (`devices.criticality`/`devices.exposure`) — always editable, never blocked
   pending manual entry.
2. **Compliance-score input** — this project runs two parallel, deliberately-unmerged
   compliance engines (the original 5-control SA-IOT-\* pilot and the full 81-guideline
   NCA CGIoT-1:2024 module). The risk score uses the **NCA score**
   (`policies/nca/evaluator.device_score()`) — the fuller, currently-maintained
   framework.
3. **Violation count** — **both engines combined**: SA-IOT-\* `FAIL` verdicts + NCA
   `fail`-status assessments. A real violation in either framework should count
   toward risk, even if the same underlying issue is counted from two angles.
4. **UI scope** — a **dedicated Risk Assessment page** (`/risk`), not just summary
   cards — the point of a risk score is that an auditor can see exactly why a device
   scored what it did, not just a number.

## Architecture

One pure, centralized, unit-tested function (`policies/risk/risk_engine.py`'s
`compute_device_risk()`) computes the score from 7 inputs — matching every other
scoring engine in this codebase (`policy_engine.py`, `policies/nca/evaluator.py`,
`vuln_routes.py`'s summarization). Every API/UI surface only ever renders its output,
never recomputes it. **Nothing is cached or persisted** — like `device_score()` and
`vuln_routes._summarize_packages()`, the risk score is computed fresh from current
data on every request, since every input already lives somewhere real.

**Explicit non-goal**: the risk score never feeds back into or auto-flips a
compliance verdict, matching this project's "tool-assisted, not tool-decided" rule.
It's a new, independent, informational rollup.

### The 7 factors

| Factor | Source | Normalization (0-100, higher = riskier) | Weight |
|---|---|---|---|
| Compliance | `policies.nca.evaluator.device_score()` | `100 - score`; never-assessed (`None`) → **100** | 25% |
| CVSS | Highest CVSS across the device's firmware CVEs (`vuln_routes._summarize_packages`) | `cvss * 10`; no CVE data → 0 | 20% |
| Exploit availability | Any CISA KEV-listed CVE | binary: 100 if any, else 0 | 20% |
| Device criticality | `devices.criticality` | `{low: 25, medium: 50, high: 75, critical: 100}` | 15% |
| Internet exposure | `devices.exposure` | `{none: 0, internal_only: 40, internet_facing: 100}` | 10% |
| Violation count | SA-IOT `FAIL` verdicts + NCA `fail` assessments (deduped to the most recent per control) | `min(100, count * 20)` | 5% |
| Insecure-service count | Enabled `http`/`mqtt`/`telnet` services | `min(100, count * 25)` | 5% |

**Risk score** = weighted sum, rounded, 0–100. **Risk category**: 0–24 Low, 25–49
Medium, 50–74 High, 75–100 Critical. All weights/thresholds/point-values are named,
tunable module-level constants in `risk_engine.py` — never hardcoded inline.

The **never-assessed-compliance-is-maximum-risk** rule deserves emphasis: absence of
proof of compliance is not proof of safety. A device nobody has ever assessed scores
the same compliance-factor risk as one that failed every control — never the same as
a device that's actually been checked and found clean.

### Why criticality/exposure default the way they do

`devices.criticality` defaults to `'high'` only if the device registers with an
enabled `mqtt`/`mqtts` service (a broker is a central dependency many other devices
lean on) — otherwise `'medium'`, a neutral baseline, **never** guessed down to
`'low'` since nothing in registration data supports that inference.

`devices.exposure` **always** defaults to `'internal_only'` — deliberately not
inferred from a service's `published_port`. In this lab, a published port reflects
host-machine dev-convenience mapping (so a browser on the host can reach a
container), not real internet reachability. Claiming `'internet_facing'` from that
signal alone would be a stronger, more alarming claim than the data supports.
`'internet_facing'` is something only an auditor should assert, via the existing
`PATCH /devices/{id}` (surfaced as the device detail page's "Risk profile" card).

## API surface (`lab/auditor/api/risk_routes.py`)

Read-only, mirrors `nca_routes.py`/`vuln_routes.py`'s separate-`APIRouter` pattern:

- `GET /risk/devices` — every device, computed live, sorted worst-first (descending
  risk score). This sorted list **is** the org-wide priority ranking; rank position
  is implicit in list order.
- `GET /risk/devices/{device_id}` — one device's full score, category, and the
  complete per-factor breakdown (raw value, normalized contribution, weight, weighted
  contribution) — this is what makes the score fully auditable rather than a black
  box.
- `GET /risk/fleet-summary` — count by category + fleet-wide average, for the
  Overview page's tile.

No write endpoints. A device's risk score is entirely derived from data recorded
elsewhere (NCA assessments, SA-IOT verdicts, vulnerability-intel evidence,
`device_services`) plus the two auditor-set fields, which already have their own
write path via the existing `PATCH /devices/{id}`.

## Dashboard

- **`/risk`** (Risk Assessment page, new sidebar entry under Assessment) — the full
  org-wide priority-ranked table, each row expanding in place (matches
  `VerdictsPage`'s own expand-on-click convention) to the complete 7-factor
  breakdown.
- **Overview** — an "Org-wide risk priority" card, worst-first, linking to `/risk`.
- **Device detail page** — a risk category badge near the header, linking to `/risk`;
  a "Risk profile" card lets an auditor set criticality/exposure directly (the first
  real caller of the pre-existing but previously-unused `PATCH /devices/{id}`
  frontend client function).
- **Device assessment report** (`DeviceAssessmentReportPage` + the server-rendered
  PDF/HTML report) — a matching risk section. `report.py`'s `build_report_model()`
  imports `risk_routes.py`'s own `_compute_risk_for_device()` rather than
  reimplementing it, so the report and the dashboard can never disagree.

## Known limitations

- **Self-reported inputs.** Criticality and exposure accuracy depends entirely on the
  auditor keeping them current — the engine has no way to verify either.
- **No feedback loop into compliance verdicts, by design.** A critical risk score
  never auto-fails a control or blocks a Passed readiness classification.
- **Violation count can double-count the same underlying issue** if it fails a
  control in both frameworks (e.g. default credentials failing both an SA-IOT and an
  NCA control) — a deliberate choice (Q3 in the design decisions above): a risk score
  is about real-world exposure, not compliance bookkeeping, so double-coverage is
  acceptable signal.
- **Package/component-level CVE data only** (inherited from Stage 05's own scope) —
  a device with no firmware manifest scan contributes 0 to the CVSS factor and `false`
  to exploit availability, which is an honest "no data" result, not a claim the
  device has no vulnerabilities.
- **No historical trend** — each score is a point-in-time snapshot; Stage 10
  (Continuous Monitoring, not yet built) would be the natural place to track how a
  device's risk score changes over time.
