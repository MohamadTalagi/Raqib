# ERR-019 — Host port 8080 already bound by an unrelated process on the dev machine

- **Date:** 2026-07-09
- **Component:** lab/auditor/web (Docker verification)
- **Severity:** low
- **Status:** resolved
- **Author:** Claude Code session

## What happened
After rebuilding `auditor-web` as a React (nginx-served) container, ran
`docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d auditor-web`
on the laptop (a shared dev machine, not the dedicated build PC) to visually verify
the new dashboard before deploying. The container failed to start.

## Exact error / symptom
```
Error response from daemon: ports are not available: exposing port TCP 0.0.0.0:8080
-> 127.0.0.1:0: listen tcp 0.0.0.0:8080: bind: Only one usage of each socket address
(protocol/network address/port) is normally permitted.
```
`netstat -ano | grep ":8080"` showed an unrelated host process (PID 5340, nothing to
do with this project) already `LISTENING` on 8080.

## Environment
- OS / shell: Windows 11, Git Bash
- Tool + version: Docker Desktop 29.5.3, Compose v5.1.4
- Relevant files: `lab/docker-compose.yml` (auditor-web `ports: 8080:80`)

## Root cause
The laptop used for this session runs other long-lived local tools that already
occupy port 8080. This is specific to the shared laptop, not the project's dedicated
build PC (`OSRA-PC2025-V2`), where 8080 is free per prior sessions.

## The fix
Verified the built image without touching the shared compose port mapping: ran the
already-built image standalone, attached to the same Compose-managed network, on a
free host port instead —

```
docker run --rm -d --name auditor-web-verify \
  --network kaust-iot-lab_internal-network \
  -p 18080:80 kaust-iot-lab-auditor-web
curl -s -o /dev/null -w "%{http_code}\n" http://localhost:18080/
```

This avoided editing `docker-compose.yml`'s committed port mapping just to work
around a local, machine-specific conflict.

## How to prevent it next time
When verifying a container locally on a shared/multi-purpose dev machine, check
`netstat -ano | grep ":<port>"` (or `docker ps` for existing project containers)
before assuming a compose `up` failure is caused by the container itself. Don't
"fix" a local port conflict by changing a port mapping meant for the deployment
target — run the image standalone on a scratch port instead.

## References
Related: [ERR-017](017-internal-network-blocks-docker-desktop-port-forwarding.md)
(the `internal-network` port-forwarding issue this dev overlay works around).
