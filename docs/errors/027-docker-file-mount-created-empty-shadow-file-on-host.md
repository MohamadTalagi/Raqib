# ERR-027 — A Docker file-bind-mount test run created an empty file on the host that shadowed a real one

- **Date:** 2026-07-23
- **Component:** auditor-worker / device_validation.py
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (session work)

## What happened

To run `test_job_runner.py` outside the full Docker Compose stack, a
throwaway container was started with:

```
docker run --rm -v "$(pwd):/work" \
  -v "$(pwd)/lab/auditor/worker:/app" \
  -v "$(pwd)/lab/auditor/api/device_validation.py:/app/device_validation.py" \
  -w /app -e PYTHONPATH=/work:/app python:3.13-slim ...
```

This mounts `lab/auditor/worker` as `/app`, then separately bind-mounts one
file (`api/device_validation.py`) onto a path *inside* that already-mounted
directory. Sometime during this, an empty (0-byte) file appeared on the real
host filesystem at `lab/auditor/worker/device_validation.py` — a path that
had never existed there before (confirmed via `git log`: zero prior commits
touched it). This file is not supposed to exist there at all:
`lab/docker-compose.yml`'s real `auditor-worker` service sets
`PYTHONPATH=/work` and bind-mounts `./auditor/worker:/work/lab/auditor/worker`
(a *different* path from where the Dockerfile `COPY`s the real
`device_validation.py`, which lands at `/work/device_validation.py`) —
Python's import resolution finds the script's own directory first, so an
empty file sitting in `lab/auditor/worker/` on the host silently shadows the
correct image-baked module the moment that directory gets bind-mounted into
the real `auditor-worker` container.

The live `auditor-worker` container crash-looped as a result:

## Exact error / symptom

```
Traceback (most recent call last):
  File "/work/lab/auditor/worker/job_runner.py", line 20, in <module>
    from device_validation import (
ImportError: cannot import name 'ValidationError' from 'device_validation' (/work/lab/auditor/worker/device_validation.py)
```

A separate local commit (made by tooling outside this session, not via any
`git commit` run here) subsequently picked up the empty file via a broad
`git add`, so it also ended up briefly committed to the repository.

## Environment

- Docker Desktop on Windows, Git Bash (MSYS) shell — this project has hit
  Docker-volume-path mangling under MSYS before (see `docs/errors/003`), and
  file-vs-directory bind-mount interaction is a known rough edge on this
  platform.
- Relevant files: `lab/auditor/worker/device_validation.py` (should never
  exist as a real file — see `lab/auditor/worker/Dockerfile`'s own comment:
  "single source of truth still lives at auditor/api/device_validation.py"),
  `lab/docker-compose.yml` (`auditor-worker` service).

## Root cause

Bind-mounting a single file onto a path inside an already directory-mounted
target, on this Docker Desktop/Windows setup, can materialize an empty file
back on the *host* source path instead of cleanly layering the mount —
compounded by the fact that nothing (no `.gitignore` entry, no test) treats
`lab/auditor/worker/device_validation.py` as a forbidden path, even though
the whole point of the Dockerfile's `COPY api/device_validation.py .` +
`PYTHONPATH=/work` design is that this exact filename must never exist
inside the bind-mounted `lab/auditor/worker/` directory.

## The fix

Deleted the stray host-side file entirely (not repopulated with a copy —
that would just recreate the duplication the Dockerfile comment already
warns against) and restarted the real `auditor-worker` container, which
then resolved `device_validation` correctly via `/work/device_validation.py`
(the image-baked copy) again. Re-ran the network-discovery scan this file
had been blocking to confirm the fix.

## How to prevent it next time

Don't file-bind-mount a single module onto a path inside an already
directory-bind-mounted target for ad hoc test runs on this platform;
mounting the *directory* containing the real file at a distinct path (or
copying it in at container start) avoids the host-side side effect
entirely. More durably: `lab/auditor/worker/device_validation.py` is a path
that must never be a real tracked or on-disk file — worth adding to
`.gitignore` explicitly so a repeat of this (from any tool, not just this
one) fails loudly (import error, easy to spot) rather than silently
persisting into a commit.

## References

- `docs/errors/003-docker-credstore-fails-over-ssh.md` — an earlier
  Docker-on-this-host rough edge, different mechanism, same platform.
- `lab/auditor/worker/Dockerfile` — the comment explaining why
  `device_validation.py` is baked in rather than bind-mounted.
