# AI Executive Summary (IoTGuard Stage 08)

## What this closes

The last analytical stage of the IoTGuard pipeline. Per
`docs/reference/IoTGuard.md`: "Summarize the overall security posture of
the organization for both technical and non-technical stakeholders,"
depending on Stages 4-7 (compliance, vulnerabilities, risk, remediation) -
all of which were already built. This stage aggregates them into one view:
every device ranked by risk score (highest first), that device's
compliance gaps, the evidence and tools that found each one, and the
AI-assisted (human-reviewed) remediation recorded for it.

## Deliberately no AI-generated narrative text

Confirmed with the project owner before building this. Every other report
in this app already carries the same rule in its own docstring — `report.py`:
"a generated summary paragraph would contradict the report's own
determinism claim." A document aimed at non-technical stakeholders is
exactly where a hallucinated claim would do the most damage, and this
project's standing principle is "AI-assisted, not AI-decided" throughout.

The "AI" in this stage's name is satisfied by **aggregating** the
already-AI-generated, human-reviewed Remediation blueprints from Stage 07 -
not by generating new prose here. Every sentence on the page and in both
exports is a template filled with a real, already-computed value.

## Architecture: pure aggregation, nothing reimplemented

`lab/auditor/api/executive_summary.py` reuses, rather than reimplements,
every input:

- **Risk ranking**: `risk_routes._compute_risk_for_device()`, the exact
  same per-device score `GET /risk/devices` already computes and sorts
  worst-first with `priority_rank` assigned.
- **SA-IOT compliance gaps + evidence/tools + vulnerability summary**:
  `report.build_report_model(conn, device_id)` - called once per device,
  reused wholesale. Its `controls` list is filtered here to `FAIL`/
  `PARTIAL` only for the "gaps" view; its `evidence` list (tool, tool
  version, command, finding, confidence, sha256) is exactly "the evidence
  that points to the vulnerability and what tool found it."
- **NCA compliance gaps**: `nca_routes._evaluator_rows_for_scope()` +
  `policies/nca/evaluator.py`'s `effective_status()`/`_applicable_required()`
  - the same rules that already decide a device's NCA readiness
  classification, so this view can never disagree with it.
- **Remediation per device**: a direct query against
  `remediation_blueprints WHERE device_id = %s AND superseded_by IS NULL`
  - that table already carries a denormalized `device_id` column from
  Stage 07, so no new join was needed.
- **Fleet-wide rollup**: risk category breakdown, SA-IOT + NCA gap counts,
  remediation generated/reviewed/coverage-percent, a **priority
  recommendations** list (every `priority: immediate` blueprint not yet
  `reviewed`, worst-risk-device-first), and a **significant compliance
  gaps** list (any `blocking` NCA control currently failing, fleet-wide).

Nothing is cached or persisted - like every other rollup in this app
(`device_score()`, risk scores, NCA domain summaries), it's computed fresh
from current data on every request, so it can never drift out of sync with
the rest of the dashboard.

## API surface (`lab/auditor/api/executive_summary_routes.py`)

- `GET /executive-summary` - the live JSON model, for the dashboard page.
- `GET /executive-summary/report.pdf` / `/report.html` - server-rendered
  exports, same Jinja2/WeasyPrint pattern (`font_config` passed to both
  `CSS()` and `write_pdf()`) as `report.py`/`nca_report.py`.

No write endpoints - like `risk_routes.py`, this is entirely read-only,
derived from data recorded elsewhere.

## Dashboard

`ExecutiveSummaryPage.tsx` (`/executive-summary`), the last entry in the
Sidebar's Pipeline group:

- Fleet-wide stat tiles (devices, average risk, compliance gaps,
  remediation coverage).
- **Priority recommendations** card and **most significant compliance
  gaps** card, both fleet-wide.
- **Devices ranked by risk, highest first** - expand-in-place (same
  convention `RiskAssessmentPage` already uses) to show that device's
  compliance gaps (SA-IOT + NCA together), evidence + tools, and
  remediation blueprints (reusing the `AiGeneratedBadge` built for Stage 07).
- PDF/HTML export buttons, matching `DeviceAssessmentReportPage`'s own
  Print/Download/HTML convention.

## Verified live

Loaded against the real stack: 11 real devices correctly ranked by risk
(`device-insecure` #1 at 84/Critical down to `telnet-sim` #11 at 38/Medium),
real priority recommendations and blocking compliance gaps rendered fleet-
wide, and `device-insecure`'s expanded panel showed its real compliance
gaps, its real (long) evidence/tool list, and both of its real remediation
blueprints exactly as previously recorded - one marked "Reviewed by Lead
Auditor," the other still carrying the "AI-generated" badge. Both the PDF
export (a genuine 139KB `%PDF-1.7` file) and the HTML export (inlined
stylesheet, real device names) were downloaded and confirmed against the
live stack.

## Known limitations

- No AI-generated narrative text, by explicit decision - see above.
- Fleet-wide report generation isn't logged to `report_records` (that
  table's `device_id` column is scoped to a single device by design) - a
  deliberate, documented scope cut, not a silent gap. A future increment
  could widen that column to nullable if fleet-report audit logging is
  ever needed.
- Nothing here is cached - a very large fleet would pay the full
  recomputation cost (one `build_report_model()` call per device, plus the
  NCA/remediation queries) on every page load or export. Not a concern at
  this lab's scale (11-16 devices).
