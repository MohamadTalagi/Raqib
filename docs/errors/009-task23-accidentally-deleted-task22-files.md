# ERR-009 — Task 23's implementer accidentally deleted Task 22's already-committed files

- **Date:** 2026-07-08
- **Component:** subagent-driven-development process (Task 23 implementer)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 23 re-review + controller follow-up)

## What happened
Task 23's original commit (`c00c485`, "feat(worker): add evidence recorder CLI with schema
validation") deleted `lab/auditor/worker/Dockerfile` and `lab/auditor/worker/requirements.txt` —
files that Task 22 had added and committed one commit earlier (`1d6e399`), already reviewed,
approved, and verified working on the physical build PC. Neither the first task-reviewer pass nor
the second (re-review, after fixing the file-location bug from ERR-008) caught this: the first
review didn't mention it at all; the second review's ⚠️ item noted the deletions appeared in the
diff but concluded (incorrectly) that they were "accidentally created in the initial commit that
were cleaned up in the fix" — assuming the deleted files were duplicates of something the same task
had wrongly created, rather than checking whether they were a different, unrelated, already-approved
task's real files.

## Exact error / symptom
`git log --diff-filter=D --oneline -- lab/auditor/worker/Dockerfile lab/auditor/worker/requirements.txt`
pointed to `c00c485` as the deleting commit. At HEAD, `lab/auditor/worker/` contained only
`__init__.py`, `__pycache__/`, and `tests/` — no `Dockerfile`, no `requirements.txt` — which would
have broken Task 22's `docker compose build auditor-worker` on the next PC rebuild, despite Task 22
having been separately approved and verified.

## Environment
- Not an environment/tooling bug — a subagent implementer error during Task 23's original work,
  likely caused by a broad file-staging or cleanup command (e.g. an overly broad `rm`/`git add -A`)
  while setting up the (at-the-time-correct, per the plan's own bug — see ERR-008) repo-root
  `auditor/` directory structure, which swept up a deletion of the unrelated, correctly-placed
  `lab/auditor/worker/` files from the immediately-preceding task.

## Root cause
Two things compounded:
1. ERR-008 (the plan's own path inconsistency) put the implementer in an unusual position —
   creating a *new* `auditor/` tree at the repo root, one level removed from where Task 22's files
   already lived nested under `lab/`. Directory-level operations (bulk moves, cleanup, or staging)
   during that setup evidently touched files outside the intended scope.
2. Neither task review caught it. The first review didn't check the diff for unrelated deletions at
   all. The second review noticed the deletion lines in the diff but rationalized them away as
   "accidentally created... cleaned up" without verifying against git history whether those files
   belonged to a different, prior, already-approved task.

## The fix
```bash
git checkout 1d6e399 -- lab/auditor/worker/Dockerfile lab/auditor/worker/requirements.txt
git commit -m "fix: restore lab/auditor/worker/Dockerfile and requirements.txt"
```
Restored both files verbatim from Task 22's original commit.

## How to prevent it next time
When a task reviewer sees a deletion in a diff that isn't explicitly called for by the task brief,
don't assume it's an artifact of the current task's own mistake — check `git log --diff-filter=D`
(or equivalent) to see which commit and which task the deleted file actually belonged to before
concluding it's safe. As the controller, when a reviewer flags an unexplained deletion as a ⚠️ item
even with a plausible-sounding rationalization, verify it directly (`ls`, `git show HEAD:<path>`)
rather than trusting the reviewer's read of the diff — this is exactly the kind of cross-task,
git-history-dependent check a single-diff-scoped reviewer isn't positioned to get right, and the
controller holds the context (which task owns which file) that the reviewer doesn't.

## References
None external — diagnosed directly via `git log --diff-filter=D` and `git show` in this session.
