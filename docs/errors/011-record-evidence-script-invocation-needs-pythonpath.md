# ERR-011 — `record_evidence.py` fails with `ModuleNotFoundError` when run as a plain script (needs `PYTHONPATH`)

- **Date:** 2026-07-08
- **Component:** lab/docker-compose.yml (auditor-worker), lab/auditor/worker/tests/record_evidence.py invocation
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 26 controller-side evidence collection)

## What happened
Running Task 26's runbook — `python lab/auditor/worker/tests/record_evidence.py --device ... --test-id
TEST-NET-PORTSCAN ...` from `/work` inside the `auditor-worker` container — failed immediately on the
very first evidence-recording call.

## Exact error / symptom
```
Traceback (most recent call last):
  File "/work/lab/auditor/worker/tests/record_evidence.py", line 7, in <module>
    from policies.schema.validate import validate_evidence
ModuleNotFoundError: No module named 'policies'
```

## Environment
- Container: `auditor-worker` (python:3.12-slim), `/work` as workdir, `policies/` bind-mounted at
  `/work/policies`
- Relevant files: `lab/auditor/worker/tests/record_evidence.py`, `lab/docker-compose.yml`

## Root cause
Python's `sys.path` insertion rule differs by invocation style:
- `python -m pytest ...` and `python -c "..."` both insert the **current working directory** at
  `sys.path[0]`.
- `python /path/to/script.py` instead inserts **the directory containing that script** —
  `/work/lab/auditor/worker/tests/`, not `/work`.

Tasks 23-25's verification all used `python -m pytest`, so this never surfaced. Task 26's runbook is
the first thing to invoke `record_evidence.py` the way it's actually meant to be used in practice —
as a standalone CLI script, `python lab/auditor/worker/tests/record_evidence.py --device ...` — and
that invocation style doesn't get `/work` on `sys.path`, so the script's own `from
policies.schema.validate import validate_evidence` fails.

## The fix
Added an explicit `PYTHONPATH=/work` environment variable to the `auditor-worker` service in
`lab/docker-compose.yml`:
```yaml
  auditor-worker:
    build: ./auditor/worker
    environment:
      - PYTHONPATH=/work
```
This makes `/work` importable regardless of how Python is invoked inside the container — script,
`-m`, or `-c` — fixing this uniformly rather than special-casing each call site.

## How to prevent it next time
When a Python script under a nested package (`lab/auditor/worker/tests/record_evidence.py`) imports
from a sibling top-level package (`policies/`), don't assume `python -m pytest`-style verification
during development covers every way the script will actually be invoked later. A CLI tool meant to be
run directly (`python path/to/script.py ...`, as documented in its own runbook) needs either an
explicit `PYTHONPATH`, a `sys.path.insert()` at the top of the script, or a wrapper entry point —
pytest's cwd-insertion behavior is not a reliable substitute for verifying the tool's real, documented
invocation.

## References
None external — diagnosed directly via the traceback in this session.
