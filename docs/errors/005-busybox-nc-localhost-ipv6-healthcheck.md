# ERR-005 — BusyBox `nc -z localhost <port>` healthcheck fails for an IPv4-only-bound server

- **Date:** 2026-07-08
- **Component:** lab/telnet-sim
- **Severity:** low
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 11 controller-side integration verification)

## What happened
After bringing up `device-insecure`, `telnet-sim`, and `mqtt-broker-insecure` via `docker compose up`
(Task 11), `docker compose ps` showed `telnet-sim` as `unhealthy` while the other two services were
`healthy` — even though the container was actually reachable and working (a raw TCP connect from a
separate container succeeded fine in Task 8's own smoke test).

## Exact error / symptom
```
kaust-iot-lab-telnet-sim-1   kaust-iot-lab-telnet-sim   "python banner_serve…"   telnet-sim   Up About a minute (unhealthy)   23/tcp
```
Manually running the exact healthcheck command inside the container:
```
docker exec kaust-iot-lab-telnet-sim-1 sh -c 'nc -z localhost 23; echo EXITCODE=$?'
# EXITCODE=1
docker exec kaust-iot-lab-telnet-sim-1 sh -c 'nc -zv 127.0.0.1 23; echo EXITCODE=$?'
# 127.0.0.1 (127.0.0.1:23) open
# EXITCODE=0
```

## Environment
- OS / shell: Docker Desktop 29.1.3, `python:3.12-alpine` (BusyBox v1.37.0) container
- Tool + version: BusyBox `nc` (not GNU netcat)
- Relevant files: `lab/telnet-sim/Dockerfile`, `lab/telnet-sim/banner_server.py`

## Root cause
`/etc/hosts` inside the container resolves `localhost` to both `127.0.0.1` and `::1` (IPv4 and
IPv6). BusyBox `nc` tries the resolved addresses but does not fall back to a second address family
the way e.g. Python's `urllib` does — it picked the IPv6 loopback (`::1`) and gave up. But
`banner_server.py` calls `server.bind(("0.0.0.0", 23))`, which binds only the IPv4 wildcard address,
so nothing is listening on `::1`. Connecting to the explicit `127.0.0.1` address skips DNS/`/etc/hosts`
resolution entirely and hits the actual listening socket.

Note this only affects services whose Dockerfile HEALTHCHECK uses BusyBox `nc` against a Python
server bound IPv4-only. The Mosquitto broker healthchecks in this same plan use the identical `nc -z
localhost <port>` pattern but are unaffected, because Eclipse Mosquitto's default listener binds both
IPv4 and IPv6 by default.

## The fix
```dockerfile
- HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD nc -z localhost 23 || exit 1
+ HEALTHCHECK --interval=10s --timeout=3s --retries=3 CMD nc -z 127.0.0.1 23 || exit 1
```
Rebuilt and confirmed `docker compose ps` reports `telnet-sim` as `healthy`.

## How to prevent it next time
When writing a Dockerfile HEALTHCHECK with BusyBox `nc` (or any netcat variant without multi-address
fallback) against a server that binds a specific address family, use the literal loopback IP
(`127.0.0.1`) instead of the `localhost` hostname — it avoids depending on `/etc/hosts` resolution
order and the healthcheck tool's fallback behavior (or lack of it) entirely.

## References
None external — diagnosed directly via `docker exec`/`docker inspect` output in this session.
