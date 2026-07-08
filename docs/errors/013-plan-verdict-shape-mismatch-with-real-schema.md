# ERR-013 — Plan's verdict test fixtures used dict-shaped `matched`/`saudi_source`, contradicting the real committed schema and `evaluate()`'s actual contract

- **Date:** 2026-07-08
- **Component:** docs/superpowers/plans/2026-07-08-phases-6-8-platform-completion.md (Tasks 4, 6, 8)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 4 implementer caught it; controller diagnosed and fixed)

## What happened
While writing the Phases 6-8 plan, Task 4's `VALID_VERDICT` test fixture (and Task 6's `VERDICT_FAIL`/`VERDICT_PASS`,
and Task 8's `generate_verdicts.py` rewrite) used **object-shaped** values for `matched` (e.g.
`{"default_creds": True}`) and `saudi_source` (e.g. `{"framework": "CGIoT-1:2024", "reference": "2-2-2"}`).
Task 4's implementer, before writing any code, empirically validated this fixture against the already-committed
`policies/schema/verdict.schema.json` (from Phase 0-5) and found it fails: that schema requires `matched` to be
a `string` enum (`pass`/`fail`/`partial`/`inconclusive`) and `saudi_source` to be a plain `string`. The
implementer correctly stopped and reported BLOCKED rather than guessing or unilaterally widening scope to
rewrite the schema file.

## Exact error / symptom
```
jsonschema.exceptions.ValidationError: {'framework': 'CGIoT-1:2024', 'reference': '2-2-2'} is not of type 'string'
```
(raised when validating the plan's own `VALID_VERDICT` fixture against the real, already-committed
`policies/schema/verdict.schema.json`)

## Environment
- Component: `lab/auditor/api/test_verdicts.py` (not yet written at the time of the block — the implementer
  ran the schema check standalone before writing code)
- Relevant files: `policies/schema/verdict.schema.json`, `policies/engine/policy_engine.py`,
  `policies/controls/SA-IOT-002.yaml`, `document-store/verdicts/*.json` (real Phase 0-5 data)

## Root cause
When authoring the Phases 6-8 plan, the controller designed Task 8's `generate_verdicts.py` rewrite from a
guessed interface — assuming `policy_engine.py`'s `evaluate(control, evidence)` returns a *partial* result
(`{"status": ..., "matched": ..., "reason": ...}`) that the caller then assembles into a full verdict dict
(adding `verdict_id`, `evidence_ids`, raw `saudi_source`, etc.). The controller did not re-read the actual,
already-approved `policy_engine.py` from Phase 0-5's Task 28 before designing this. In reality,
`evaluate(control, evidence, verdict_id=None) -> dict` already returns the **complete** verdict — it formats
`saudi_source` into a string internally (`f"{control['saudi_source'][0]['framework']} §{...}"`, using only the
first entry of the control's `saudi_source` *list*) and sets `matched` to the lowercase status string, not an
object. The plan's Task 4/6 test fixtures were then written by pattern-matching what "seemed natural" for
`matched`/`saudi_source` (structured objects, since the fields *sound* structured) rather than checking what
the real, already-committed schema and real historical `document-store/verdicts/*.json` files actually contain
— both of which use plain strings for both fields, and both of which predate this plan.

## The fix
Corrected the plan's Task 4 `VALID_VERDICT`, Task 6 `VERDICT_FAIL`/`VERDICT_PASS`, and Task 8's
`generate_verdicts.py` + inline test YAML control:
- `matched`: object → lowercase status string (`"fail"`, `"pass"`)
- `saudi_source`: object → formatted string (`"CGIoT-1:2024 §2-2-2"`)
- Task 8's `generate_verdicts()` no longer reassembles verdict fields manually — it computes only the
  `verdict_id` and calls `evaluate(control, evidence, verdict_id=verdict_id)`, using its return value directly
  as the complete verdict to `POST`.
- Task 8's `required_evidence` handling fixed from `evidence["test_id"] not in control["required_evidence"]`
  (wrong — `required_evidence` is a list of `{"test_id": ...}` dicts, not plain strings) to
  `evidence["test_id"] not in {req["test_id"] for req in control["required_evidence"]}`.
- Both locations now carry an explicit note directing the task's implementer to read the real
  `policy_engine.py` before writing code, rather than trusting the plan's summary alone.

No code had been written or committed yet when this was caught — the implementer correctly stopped at the
design-verification step, before touching any files.

## How to prevent it next time
When a new plan's tasks build on top of an existing, already-approved module (here, `policy_engine.py` from a
prior phase), re-read that module's actual source in full while writing the new plan's task text — don't
infer its contract from its name, its test file, or a natural-seeming assumption about how its return value
"should" look. This is the same class of mistake as [ERR-008] (plan's own test code contradicted its stated
file paths) — a plan author asserting a contract without checking it against the real file. The fact that a
downstream implementer independently validated the fixture against the real schema *before* writing code is
exactly the kind of check that catches this early — worth calling out as a good practice, not just logging the
mistake it caught.

## References
None external — diagnosed directly by the Task 4 implementer's schema check, confirmed by the controller
reading `policies/engine/policy_engine.py`, `policies/controls/SA-IOT-002.yaml`, and a real committed
`document-store/verdicts/*.json` file.
