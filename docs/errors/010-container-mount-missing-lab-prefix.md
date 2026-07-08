# ERR-010 — `auditor-worker`'s volume mount didn't include the `lab/` segment, breaking `lab.`-prefixed imports

- **Date:** 2026-07-08
- **Component:** lab/docker-compose.yml (auditor-worker service, Task 22), Tasks 23-26 test code
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 25 controller-side verification)

## What happened
Task 25's implementer noted that `yara-python` can't be built on this Windows/Python-3.14 laptop (no
prebuilt wheel exists for any version — confirmed directly, unlike ERR-002's pydantic-core issue
which a version bump fixed), so they verified their tests by running them inside the `auditor-worker`
container instead, where `yara-python` installs fine via its own Linux wheel. When the controller
tried to reproduce that verification independently, `python -m pytest auditor/worker/firmware/test_scan_firmware.py`
failed with `ModuleNotFoundError: No module named 'lab'` — the test file's `from
lab.auditor.worker.firmware.generate_firmware import ...` (added by ERR-008's fix) has no `lab`
directory to resolve against inside the container.

## Exact error / symptom
```
ImportError while importing test module '/work/auditor/worker/firmware/test_scan_firmware.py'.
/work/lab/auditor/worker/firmware/test_scan_firmware.py:1: in <module>
    ???
E   ModuleNotFoundError: No module named 'lab'
```

## Environment
- OS / shell: `auditor-worker` container (python:3.12-slim), Docker Compose bind mounts
- Relevant files: `lab/docker-compose.yml` (auditor-worker's `volumes:` section)

## Root cause
Task 22's compose service mounted `./auditor/worker:/work/auditor/worker` — dropping the `lab/`
segment that exists on the host. That's fine for shell invocations like `python
auditor/worker/tests/record_evidence.py` run from `/work` (no import statement involved, just a
script path), but ERR-008's fix made every *test file*'s own Python code import via `from
lab.auditor.worker... import ...` to match the **laptop-side** layout (where pytest runs from the
repo root and `lab/` genuinely is the parent directory). Inside the container, `/work/policies` and
`/work/document-store` DO mirror the repo-root layout (mounted from `../policies` and
`../document-store`), but `/work/auditor/worker` did not — it was missing the `lab/` layer that the
other two mounts implicitly have. This meant the *exact same* Python source file behaved correctly
when run one way (laptop, `pytest` from repo root) and incorrectly the other way (container, `python`
from `/work`) — a mount-vs-import mismatch that only surfaces when someone actually tries the second
path, which nothing prior to Task 25 had done (Tasks 23-24's tests never needed the container, since
they don't depend on yara-python).

## The fix
```yaml
# lab/docker-compose.yml, auditor-worker service
- - ./auditor/worker:/work/auditor/worker
+ - ./auditor/worker:/work/lab/auditor/worker
```
This makes `/work` mirror the repo root exactly: `/work/policies`, `/work/document-store`,
`/work/lab/auditor/worker` — so `from lab.auditor.worker... import ...` resolves identically whether
pytest runs locally from the repo root or inside this container from `/work`. Updated every
`python auditor/worker/...` invocation in Task 26's runbook (and the two firmware-output path
references, and the `.gitignore` entry) to `python lab/auditor/worker/...` to match.

## How to prevent it next time
When a plan (or any design) has the same logical code running in two different execution contexts
(here: laptop pytest vs. in-container pytest) that are expected to share identical import paths,
verify the *mount/filesystem layout*, not just the *import statement*, matches in both contexts.
A test suite that only ever gets exercised in one of the two contexts (as Tasks 23-24 were,
laptop-only) won't catch a mismatch that only manifests in the other — this is exactly the kind of
gap that surfaces only when a later task (here, Task 25, which genuinely needs the container) tries
the previously-unexercised path.

## References
None external — diagnosed directly via `docker compose exec ... pytest` output in this session.
