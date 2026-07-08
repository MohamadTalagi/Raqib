# ERR-014 — `record_evidence.py`'s sequence numbering would collide on every repeated invocation after moving to API-based writes

- **Date:** 2026-07-08
- **Component:** lab/auditor/worker/tests/record_evidence.py (Task 7 of the Phases 6-8 plan)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 7 implementer identified it; controller fixed it)

## What happened
Task 7 moved `record_evidence.py` from writing evidence JSON directly to `document-store/evidence/` to
`POST`ing it to `auditor-api` instead (Phase 6's whole point). The implementer correctly identified, tested
honestly, and flagged in their report that `_next_sequence()` was left unchanged — it still counted
`EV-{date}-*.json` files in the local `document-store/evidence/` directory to compute the next sequence
number. Since that directory is no longer written to at all (evidence now lives only in the database via the
API), its file count never advances. Every invocation of `record_evidence.py` on the same calendar day would
therefore compute the *same* sequence number as the previous one, producing a duplicate `evidence_id` and
causing the second `POST /evidence` call to fail (the database's `evidence_id` primary key would reject the
duplicate insert).

## Exact error / symptom
Not yet triggered in production — caught via code review before the first real duplicate-collision failure
happened. The implementer's own test (`test_sequence_reflects_existing_evidence_dir_contents`, since renamed)
explicitly demonstrated the formula only worked if something *else* pre-populated the local directory, which
nothing does in real operation anymore.

## Environment
- Component: `lab/auditor/worker/tests/record_evidence.py`, `lab/auditor/worker/tests/test_record_evidence.py`

## Root cause
A partial refactor: Task 7's brief (and the implementer following it) correctly replaced the *evidence write*
with an API `POST`, but the *sequence-number read* was left pointing at the same now-stale local directory.
The two were coupled (both depended on `document-store/evidence/` reflecting real state) but only one side of
the coupling was updated.

## The fix
Changed `_next_sequence(evidence_dir: Path, date_str: str)` to `_next_sequence(api_url: str, date_str: str)`,
querying `GET /evidence` and counting records whose `evidence_id` already starts with `EV-{date_str}-`:
```python
def _next_sequence(api_url: str, date_str: str) -> int:
    response = requests.get(f"{api_url}/evidence", timeout=10)
    response.raise_for_status()
    prefix = f"EV-{date_str}-"
    existing = [e for e in response.json() if e["evidence_id"].startswith(prefix)]
    return len(existing) + 1
```
`record_evidence()` now computes `api_url` once, up front, and reuses it for both the sequence-number lookup
and the final `POST`. Updated all four tests in `test_record_evidence.py` to mock `requests.get` (returning a
controllable list of "existing evidence") in addition to the existing `requests.post` mock — every test that
calls `record_evidence()` now needs both, since `_next_sequence()` makes a real HTTP call as of this fix.

## How to prevent it next time
When a plan/task replaces one half of a read-then-write pattern (here: write moved to API, but the "how many
already exist" read stayed pointed at the old location), explicitly re-derive every value that used to depend
on the old write path, not just the write itself. This is the same class of gap that caused [ERR-010] and
[ERR-013] in this project — a design change in one place silently invalidating an assumption baked into a
different, not-obviously-related piece of code. The implementer's own honest test naming
(`test_sequence_reflects_existing_evidence_dir_contents`, explaining exactly why the formula no longer
naturally advances) was the signal that caught this before it shipped — a good practice worth repeating:
if a test's own docstring/comment has to explain why a real-world guarantee no longer holds, that's a strong
signal the code needs fixing, not just the test.

## References
None external — diagnosed directly by the Task 7 implementer's own report and confirmed by the controller
reading the committed code.
