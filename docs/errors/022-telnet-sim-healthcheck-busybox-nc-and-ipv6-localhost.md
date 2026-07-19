# ERR-022 — `telnet-sim` reports `Up (unhealthy)` for days despite the service working correctly

- **Date:** 2026-07-19
- **Component:** lab/docker-compose.yml (telnet-sim service)
- **Severity:** low
- **Status:** resolved
- **Author:** Claude (Task 14 cleanup)

## What happened
`telnet-sim` had been showing `Up (unhealthy)` in `docker compose ps` for days on the build PC,
even though the telnet banner service itself was working correctly and reachable. The
`lab/docker-compose.yml` healthcheck for the service was:

```yaml
    healthcheck:
      test: ["CMD", "nc", "-z", "localhost", "23"]
```

This is the same shape of problem [ERR-005](005-busybox-nc-localhost-ipv6-healthcheck.md) already
diagnosed once, on 2026-07-08 — and ERR-005's fix (`nc -z 127.0.0.1 23`) was applied, but only to
`lab/telnet-sim/Dockerfile`'s `HEALTHCHECK` directive. A Compose-file `healthcheck:` block takes
precedence over (fully overrides) a Dockerfile's `HEALTHCHECK`, and `lab/docker-compose.yml`'s own
`healthcheck:` block for `telnet-sim` was never updated — it still shipped the original, broken
`localhost`-based test. So the Dockerfile-level fix from ERR-005 was silently inert for anyone
running the service via `docker compose up`, which is the only way this lab is ever run.

## Exact error / symptom
Running the exact healthcheck command inside the live container reproduced the failure directly:

```
nc -h
# nc: unrecognized option: h
# Usage: nc [OPTIONS] HOST PORT

nc -z localhost 23; echo exit=$?
# (empty output)
# exit=1
```

`docker compose ps` showed a permanent failing streak (4/4 consecutive failed health probes,
never recovering) and reported `Up (unhealthy)` continuously, matching this exact output shape —
exit code 1, no stdout/stderr, no transient recovery.

Meanwhile the service itself was confirmed healthy two independent ways inside the same container:
- `python3 -c "import socket; socket.create_connection(('127.0.0.1', 23), timeout=2)"` succeeded
  ("port 23 OPEN").
- `nc -w 2 127.0.0.1 23 < /dev/null` exited **0**.

## Environment
- OS / shell: Docker Desktop, `python:3.12-alpine` container (BusyBox v1.37.0), Windows build PC
- Tool + version: BusyBox `nc` bundled in `python:3.12-alpine` — does not implement `-z`
  (`nc -h` itself errors with `unrecognized option: h`, confirming this is a stripped-down
  BusyBox `nc` build, not GNU netcat or a fuller BusyBox build)
- Relevant files: `lab/docker-compose.yml` (telnet-sim `healthcheck:` block),
  `lab/telnet-sim/Dockerfile`, `lab/telnet-sim/banner_server.py`

## Root cause
Two compounding faults, both verified by running commands inside the live container:

1. **BusyBox `nc` in this image build has no `-z` flag.** `nc -z localhost 23` exits 1 with
   empty output unconditionally — it fails identically whether port 23 is open or closed, because
   `-z` (scan-only, no data) is not a recognized option at all in this BusyBox build. This alone
   explains the permanent failing streak: the healthcheck could never pass, regardless of the
   server's real state.
2. **`localhost` resolves to IPv6 inside the container.** `getent hosts localhost` returns `::1`.
   `banner_server.py` binds `0.0.0.0` (IPv4 only), so nothing listens on the IPv6 loopback — a
   correct `nc` invocation against `localhost` would still fail to connect. This is the same
   IPv6/`localhost` mechanism identified in ERR-005, still present here as a second, independent
   failure mode layered on top of the missing `-z` flag.

The service itself was never broken. Only the healthcheck definition was — and specifically the
copy of it in `lab/docker-compose.yml`, since that overrides the Dockerfile's `HEALTHCHECK` and
is the one actually in effect for every `docker compose up` run.

## The fix
```yaml
  telnet-sim:
    healthcheck:
-     test: ["CMD", "nc", "-z", "localhost", "23"]
+     test: ["CMD-SHELL", "nc -w 2 127.0.0.1 23 < /dev/null"]
      interval: 10s
      timeout: 3s
      retries: 3
```

`CMD-SHELL` (not `CMD`) is required because of the `< /dev/null` redirect — under `CMD`, the
command array is exec'd directly with no shell to interpret the redirect, so `nc` would instead
hold the connection open (reading from an inherited stdin that never closes) until `-w 2` times
out, rather than exiting immediately once the TCP connect succeeds. `127.0.0.1` is used instead
of `localhost` to bypass the IPv6-resolution issue entirely, and `-w 2` bounds the connect
timeout without depending on `-z`.

`interval`, `timeout`, and `retries` were left unchanged. No other service in
`lab/docker-compose.yml` was modified.

## How to prevent it next time
- Never assume a healthcheck is correct because it was written — verify it actually reports
  `healthy` at least once against the real running container before considering a healthcheck
  fix, or the original implementation, complete.
- Assume BusyBox coreutils (not GNU) in any Alpine-based image, and confirm flag support
  (`nc -h`, or check the actual exit behavior) rather than porting a flag from a GNU-flavored
  example.
- Prefer the literal loopback address `127.0.0.1` over the hostname `localhost` in container
  healthchecks — `/etc/hosts` inside a container commonly resolves `localhost` to both `::1` and
  `127.0.0.1`, and a service bound IPv4-only will fail a healthcheck that happens to pick the
  IPv6 entry.
- When a Dockerfile defines `HEALTHCHECK` and the same service also has a `healthcheck:` block in
  a Compose file, remember the Compose-file block wins outright — it does not merge with or layer
  on top of the Dockerfile's directive. A fix applied only at the Dockerfile level (as in
  [ERR-005](005-busybox-nc-localhost-ipv6-healthcheck.md)) will silently not take effect under
  `docker compose up` if the Compose file's own `healthcheck:` block still has the old test. Keep
  both in sync, or better, define the check in only one place.

## References
[ERR-005](005-busybox-nc-localhost-ipv6-healthcheck.md) — the original diagnosis of the BusyBox
`nc`/IPv6-`localhost` failure mode, whose fix was applied at the Dockerfile level only and did not
propagate to the Compose-file healthcheck override that actually governs `docker compose up`.
