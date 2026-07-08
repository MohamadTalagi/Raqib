# ERR-008 — Plan's own test code contradicted its stated file paths (`auditor.worker` vs `lab/auditor/worker`)

- **Date:** 2026-07-08
- **Component:** docs/superpowers/plans/2026-07-07-preliminary-iot-lab-phases-0-5.md (Tasks 23-26)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 23 task-reviewer + controller follow-up)

## What happened
Task 23's brief said to create `lab/auditor/worker/tests/record_evidence.py`, but the test code in
that same brief imported it as `from auditor.worker.tests.record_evidence import record_evidence` —
missing the `lab.` prefix. The implementer, executing the brief in good faith, resolved the
contradiction by placing the files at repo-root `auditor/worker/tests/` instead (matching the
executable import, not the stated path) — which also happened to make a second, related bug
(`DOCUMENT_STORE`'s parent-directory climbing) work by accident, since it shifted the file one
directory level shallower than the plan intended.

## Exact error / symptom
No runtime error — the implementer's tests passed. The task reviewer caught the discrepancy by
reading the brief's Files section (`lab/auditor/worker/...`) against its own test code's import
statement (`auditor.worker...`, no `lab.`), and treated it as a Critical spec-compliance finding.

## Environment
- Component: pure planning-document bug, not a runtime environment issue
- Relevant files: the plan file's Tasks 23-26 code blocks (record_evidence.py, generate_firmware.py,
  scan_firmware.py test imports); `lab/auditor/worker/tests/record_evidence.py`

## Root cause
When drafting the plan, the `lab/` prefix was used consistently in File Structure listings and
`touch`/`git add` commands, but was dropped from the Python `from ... import ...` statements
themselves — an authoring inconsistency, not a design decision. A second, compounding bug: the
`DOCUMENT_STORE = Path(__file__).resolve().parents[3] / "document-store"` line assumed one fewer
directory level than `lab/auditor/worker/tests/record_evidence.py` actually has above the repo root
(`tests/ → worker/ → auditor/ → lab/ → repo-root` is 4 hops, not 3), so it would have resolved to
`lab/document-store` (nonexistent) instead of the real `document-store/` at the repo root — this bug
was masked by the implementer's shallower (repo-root `auditor/`) placement, which happened to make
`parents[3]` land in the right place by coincidence.

## The fix
Fixed both issues directly in the plan document (not yet re-applied to the already-committed
Task 23 files at the time of writing — see Task 23's fix-and-re-review cycle for that):
```python
- from auditor.worker.tests.record_evidence import record_evidence
+ from lab.auditor.worker.tests.record_evidence import record_evidence
...
- DOCUMENT_STORE = Path(__file__).resolve().parents[3] / "document-store"
+ DOCUMENT_STORE = Path(__file__).resolve().parents[4] / "document-store"
```
Also fixed the same missing-`lab.`-prefix pattern in Tasks 24-26's firmware generator/scanner test
imports (`from auditor.worker.firmware...` → `from lab.auditor.worker.firmware...`), found via a
repo-wide grep once the first instance was caught.

## How to prevent it next time
When a plan specifies both a file's location (in a "Files:" section or directory tree) and that
file's own import statements or path-climbing logic, double check the two agree — an inconsistency
between "where a file lives" and "what the file's own code assumes about where it lives" often
doesn't surface as a test failure (a subagent implementer will frequently resolve the contradiction
silently in favor of whichever path makes the immediate test pass, rather than flagging the
contradiction), so it has to be caught by grep/review, not by trusting a green test run.

## References
None external — found via task-reviewer subagent's diff review, confirmed via grep in this session.
