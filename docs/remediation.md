# AI-Assisted Remediation (IoTGuard Stage 07)

## What this closes

`RemediationPage.tsx` was a deliberate stub since the dashboard-overhaul
session: it listed every currently-failing SA-IOT verdict and showed only
that verdict's already-recorded static one-line `remediation` string, with a
"Not built yet" banner. This closes that gap: every currently failing or
partial finding — both the 5-control SA-IOT pilot and the 81-guideline NCA
CGIoT-1:2024 framework — can now get a real, structured, LLM-generated
remediation blueprint (root cause, numbered steps, priority, effort
estimate, caveats), reviewed by a human before it's treated as authoritative.

NCA compliance had a real, bigger gap than SA-IOT: `policies/nca/
build_catalog.py` hardcodes `remediation_guidance: ""` for every one of the
81 guidelines — this feature is the first time any of them get real
remediation content at all, not just SA-IOT's.

## Why Google Gemini

The owner wanted this cheap, not free-in-name-only. Gemini's API can be used
with a real, no-credit-card-attached free tier (a key from
[aistudio.google.com](https://aistudio.google.com), no billing enabled).
**A real correction made during implementation, not assumed from
documentation**: the originally planned default model, `gemini-2.0-flash`,
returned `429 RESOURCE_EXHAUSTED` with `limit: 0` the moment a real key went
live — Google had reduced its free-tier allocation to zero for new keys in
favor of newer models by the time this was built. A live query against
Gemini's own `ListModels` endpoint found `gemini-3.5-flash-lite` genuinely
has free quota and correctly honors structured JSON output — that's the
pinned default now (`GEMINI_MODEL` env var, overridable). **Model
availability and free-tier allocation change over time on Google's side** —
if this stops working again, query `GET https://generativelanguage.
googleapis.com/v1beta/models?key=$GEMINI_API_KEY` for whatever's currently
free, rather than assuming a name from any prior documentation (including
this one).

## Architecture

Lives in `auditor-api`, not `auditor-worker`. The worker's job-queue model
(`scan_jobs`/`network_scans`/`automated_runs`) exists for local subprocess
execution needing `device_validation`'s security boundary (nmap/curl/
openssl against a live device). An LLM call is a synchronous network
request to an external HTTPS API with no such boundary — the closer
existing precedent is WeasyPrint PDF rendering, which already happens
synchronously inside `auditor-api` itself. A human clicks "Generate," waits
a couple of seconds, gets a result.

**No new dependency added.** `httpx` was already in `lab/auditor/api/
requirements.txt` (FastAPI's own test client pulls it in) but nothing
called out with it before this. Gemini's REST `generateContent` endpoint is
called directly via `httpx.post(...)` — the same "plain HTTP call, no SDK"
convention `scan_scripts/cisa_kev.py` already established for an external
API in this codebase. Structured output (`generationConfig.
responseMimeType: "application/json"` + `responseSchema`) keeps the response
shape fixed even though content varies call to call.

- **`lab/auditor/api/remediation_engine.py`** — pure, unit-testable without
  a real network call (same shape as `policies/risk/risk_engine.py`):
  `build_prompt(finding)` assembles the fixed instruction + finding fields;
  `call_gemini(prompt_body)` makes the one HTTP call and validates the
  response shape; `generate_remediation_blueprint(finding)` glues them
  together. **Never raises** — a missing API key, a rate limit, a network
  failure, or a malformed/incomplete response all return `None`, the same
  "never crash the caller, report failure honestly" convention
  `cisa_kev.fetch_and_cache_kev_feed()` already uses.
- **`lab/auditor/api/remediation_routes.py`** — owns everything database-
  facing: loading the real `verdicts` or `compliance_assessments` row a
  finding refers to, assembling the normalized `finding` dict the engine
  expects (control text, why it failed, device context), and persisting
  the result.
- **`remediation_blueprints` table** (migration `014`) — append-only,
  exactly like `compliance_assessments`: a re-`generate` for the same
  finding supersedes the prior blueprint rather than overwriting it, so a
  prior AI response is never silently lost. `finding_type`/`finding_id` are
  deliberately polymorphic (no FK) since a finding is either a
  `verdicts.verdict_id` or a `compliance_assessments.id` — two different
  tables, so a single real foreign key can't span both.
- **`GET /nca/assessments`** (new, in `nca_routes.py`) — a flat, fleet-wide
  list of the latest non-superseded assessment per `(control_id, scope)`,
  optionally filtered by status. Every other NCA read endpoint before this
  was scoped to one device, one control, or the single organizational
  scope; nothing listed "every failing assessment across the whole fleet"
  in one call. This is the NCA equivalent of the already-existing flat
  `GET /verdicts`, generically useful beyond just this feature.

## The prompt, and the honesty boundary

The prompt is explicit that the finding is already decided by deterministic
code and must not be questioned, second-guessed, or expanded with invented
facts:

> "The finding below has ALREADY been determined by deterministic scanning
> and policy evaluation - it is a fact, not something for you to question,
> second-guess, or restate as uncertain. Do not invent additional
> vulnerabilities, CVEs, or facts beyond what is given below."

The model's only job is to explain root cause and produce concrete
remediation steps, priority, and effort for the one finding it's given.

**This is a prompt instruction, not a hard technical guarantee** — the same
honesty this project applies to every LLM-adjacent claim ("AI-assisted, not
AI-decided"). That's exactly why every generated blueprint carries a
human-review gate before it's ever treated as authoritative: `reviewed`/
`reviewed_by`/`reviewed_at` (free-text reviewer identity, same convention as
`compliance_exceptions` — this app has no login system to build real auth
for). A generated blueprint is purely additive display: it never mutates
`verdicts.remediation` or `compliance_assessments.remediation`, so neither
of those append-only tables needed any change at all.

## API surface (`lab/auditor/api/remediation_routes.py`)

- `POST /remediation/generate` — body `{finding_type, finding_id}`. 404s if
  the finding doesn't exist, 400s if it isn't actually failing/partial
  (nothing to remediate), 502s (never fabricates) if Gemini didn't return a
  usable response. On success, inserts a new blueprint row, superseding any
  prior one for the same finding.
- `GET /remediation/blueprints?finding_type=&finding_id=&latest_only=` —
  list. Called with no filters at all (as `RemediationPage.tsx` does) it
  returns every current (non-superseded) blueprint across every finding in
  one call, avoiding an N+1 fetch per row.
- `POST /remediation/blueprints/{id}/review` — body `{reviewed_by}`, `422`
  if missing.

## Dashboard

`RemediationPage.tsx` (`/remediation`) lists every currently failing or
partial finding — SA-IOT verdicts and NCA assessments together, tagged
`SA-IOT`/`NCA` — each showing its existing static remediation text (if any)
plus a "Generate AI remediation" button. Once generated, the structured
blueprint renders behind a new `AiGeneratedBadge` (visually modeled on the
existing `AutoRecordedBadge` from the Fully Automated Run feature - "don't
trust this at face value yet") until a human types their name and clicks
"Mark reviewed," which clears the badge and shows who reviewed it.

A page-level "Generate all missing" button loops the same per-finding call
sequentially with a **4-second pause between requests**, safely under
Gemini's free-tier rate limit, continuing past individual failures rather
than aborting the batch.

## Verified live

Both finding types generated for real against the live stack: a SA-IOT
verdict (`SA-IOT-002`, default credentials) and an NCA assessment
(`NCA-CGIoT-1_2024-1-1-1`, organizational scope, `device_id: null` handled
correctly). Confirmed live: the review flow correctly clears the
"AI-generated" badge and shows the reviewer's name; a regenerate correctly
supersedes the prior blueprint while both stay visible via
`latest_only=false`; the "Generate all missing" counter decrements
correctly as blueprints are generated one at a time.

## Known limitations

- **Free-tier Gemini has a real, finite rate limit.** The bulk "Generate
  all missing" button paces itself (4s between calls), but a very large
  fleet could still need multiple clicks across multiple free-tier windows.
  Not a concern at this lab's current scale (dozens of findings, not
  thousands).
- **The "never invent facts" guarantee is a prompt instruction, not a hard
  technical constraint** — see "The prompt, and the honesty boundary"
  above. The human-review gate exists precisely because of this.
- **Reviewer identity is free-text, not real authentication** — same
  pre-existing, already-documented limitation as the rest of this app
  (NCA exceptions, NCA assessment attestation, automated-run "review &
  confirm").
- **Gemini model names and free-tier availability are not stable over
  time** — see "Why Google Gemini" above. `GEMINI_MODEL` is an env var
  specifically so this can be changed without a code change if Google
  deprecates the pinned default again.
- **No feedback loop into compliance verdicts or scores** — a generated (or
  even reviewed) blueprint never changes a verdict's status, a device's
  risk score, or NCA readiness. It's remediation guidance only, matching
  this project's "tool-assisted, not tool-decided" rule everywhere else.
