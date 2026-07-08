# ERR-012 — `psycopg[binary]==3.2.3` has no available wheel on PyPI

- **Date:** 2026-07-08
- **Component:** lab/auditor/api (auditor-api's requirements.txt, Task 2 of the Phases 6-8 plan)
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 2 implementer + controller-side verification)

## What happened
The Phases 6-8 plan specified `psycopg[binary]==3.2.3` in `lab/auditor/api/requirements.txt`. Task 2's
implementer found this exact version+extra combination doesn't resolve on PyPI, and worked around it locally
by dropping the `[binary]` extra (`psycopg==3.2.3` instead). That workaround only fixes the *install* step —
it silently introduces a *runtime* problem: pure `psycopg` (without `[binary]` or `[c]`) needs the `libpq`
shared library installed on the host/container to actually open a database connection, and the `auditor-api`
Dockerfile (`python:3.12-slim`, from Task 2's own brief) never installs `libpq5`. Task 3's tests are the
first ones that actually call `psycopg.connect(...)` against a real Postgres — this would have failed inside
the container the first time Task 3 ran, not at Task 2's health-check-only test (which never touches the
database).

## Exact error / symptom
```
ERROR: Could not find a version that satisfies the requirement psycopg-binary==3.2.3; implementation_name != "pypy" and extra == "binary" (from psycopg[binary])
ERROR: No matching distribution found for psycopg-binary==3.2.3; ...
```

## Environment
- OS / shell: Windows, laptop worktree venv (`pip install`)
- Tool + version: pip (via python 3.14 venv), psycopg 3.2.3
- Relevant files: `lab/auditor/api/requirements.txt`

## Root cause
`psycopg-binary` (the wheel package backing `psycopg[binary]`) simply doesn't publish a build for version
3.2.3 — the earliest available `psycopg-binary` release at the time of checking was 3.2.10. The base
`psycopg` metapackage itself does have a 3.2.3 release, so `pip install psycopg==3.2.3` (no extra) succeeds,
which is why the implementer's local health-check test passed — it never actually connects to a database, so
the missing `libpq` runtime dependency stayed invisible until this check.

## The fix
Bumped the pin to a version where `psycopg[binary]` actually resolves:
```diff
-psycopg==3.2.3
+psycopg[binary]==3.2.10
```
Verified directly: `pip install "psycopg[binary]==3.2.10"` downloads both `psycopg-3.2.10` and a real
platform wheel (`psycopg_binary-3.2.10-...whl`), with no system `libpq` install required in the container.

## How to prevent it next time
When a plan pins a specific patch version for a package with a compiled/binary variant, verify the *exact*
pinned version actually has a binary wheel available before treating "pip install succeeded" as confirmation
— a metapackage installing successfully without its binary extra can mask a runtime-only dependency (like
`libpq`) that won't surface until the code path that needs it (a real DB connection) is actually exercised,
which may be a later task than the one that pinned the version. See also [ERR-002] (a similar "the base
package name resolves but the specific pin/build users actually need doesn't" pattern with `pydantic-core`).

## References
None external — diagnosed directly via `pip install` output in this session.
