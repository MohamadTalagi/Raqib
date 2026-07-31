# ERR-032 — Docker Desktop's embedded DNS corrupted on internal-network, survived a full OS reboot, fixed only by a full Docker Desktop data purge

- **Date:** 2026-08-01
- **Component:** docker-compose / Docker Desktop (Windows, WSL2 backend)
- **Severity:** blocker
- **Status:** resolved
- **Author:** Claude (live verification session, resuming from `handoff.txt`)

## What happened
Picking up mid-session from a handoff written just before the user rebooted their
machine to fix a Docker networking bug: `auditor-api` (single-homed on
`internal-network`) could not resolve `auditor-database` by hostname, so every
API call touching the database returned HTTP 500. The previous session had
already ruled out a config problem and escalated through container restart,
network disconnect/reconnect, full `docker compose down`/`up` (recreating both
containers and networks from scratch), a `wsl --shutdown`, and a full Docker
Desktop application restart — none fixed it. The user then rebooted the whole
machine. This session resumed after that reboot to find the identical bug still
present.

## Exact error / symptom
```
File "/app/db.py", line 8, in get_connection
    return psycopg.connect(database_url)
psycopg.OperationalError: [Errno -2] Name or service not known
```
`MSYS_NO_PATHCONV=1 docker compose exec auditor-api getent hosts auditor-database`
returned nothing, exit code 2. `curl http://localhost:8000/devices` returned
`Internal Server Error` / HTTP 500.

A closer live diagnosis this session (raw UDP DNS queries sent straight to
`127.0.0.11:53` from inside `auditor-api`, bypassing `getent`/glibc resolver
plumbing) found something more precise than "DNS is dead": the embedded
resolver was alive and answering, but with **inconsistent per-name behavior**
— querying `auditor-database` (a real, currently-attached container) returned
a clean, fast `NXDOMAIN`; querying `auditor-api`/`auditor-worker`/`auditor-web`
(also real, attached containers) never returned a response at all (raw socket
timeout, no packet back). This ruled out "resolver process not listening" and
"host DNS/firewall/VPN blocking UDP:53" (neither explains per-name
inconsistency from the same query, same socket, same resolver) and pointed at
corrupted internal state inside the Docker Desktop engine's own DNS backend.

## Environment
- OS: Windows 11 Home, Docker Desktop with WSL2 backend, `docker` server
  version 28.3.3.
- Compose project: `kaust-iot-lab` (`lab/docker-compose.yml` +
  `lab/docker-compose.dev.yml` overlay).
- Affected network: `kaust-iot-lab_internal-network` (bridge, `internal: true`
  in the base compose file, overridden to `false` by the dev overlay).
  Sibling network `kaust-iot-lab_audit-network` (bridge, never `internal:
  true`) had completely normal DNS the whole time — same driver, same IPAM
  shape, different outcome.

## Root cause
Corrupted internal DNS-record state inside the Docker Desktop engine/VM
itself, specific to this one network. Not reproducible from any compose-file
difference (both networks' `docker network inspect` output was identical
apart from subnet), not a stale Windows virtual network adapter (`Get-NetAdapter`
showed only the one expected `vEthernet (WSL (Hyper-V firewall))`), not a VPN
or third-party firewall (`Get-Process` showed no VPN client; Windows Defender
Firewall was the only active filter, and a per-name-inconsistent symptom isn't
explained by a blanket UDP:53 block anyway). The bug persisted across
container recreation, network recreation, WSL restart, Docker Desktop app
restart, and a full OS reboot — none of which reset the Docker Desktop engine's
own on-disk state, which is exactly what a full Docker Desktop data purge does.

## The fix
Docker Desktop → Troubleshoot (bug icon in the main window's top toolbar, not
under Settings in the version installed here) → **Clean / Purge data**. This
wipes the entire Docker Desktop engine state (all containers, images,
networks, volumes — every project on the machine, not just this one); before
running it, confirmed via `docker ps -a`/`docker images`/`docker volume ls`
that everything present belonged to this project (current `kaust-iot-lab-*`
plus a stale `iot-security-lab-*` naming iteration from an earlier session),
so nothing unrelated was at risk. After the purge:
```
cd lab
docker compose -f docker-compose.yml -f docker-compose.dev.yml build
docker compose -f docker-compose.yml -f docker-compose.dev.yml up -d
MSYS_NO_PATHCONV=1 docker compose exec auditor-api getent hosts auditor-database
# -> 172.31.0.2   auditor-database  (real IP, real hostname line)
```
DNS resolved correctly on the very first `up -d` after the purge, no further
special handling needed.

Two things needed re-running exactly once, since the purge also wiped the
named volumes any prior session had (fixed only by rebuilding images/wiping
volumes, so not a fresh finding, but worth recording since it cost real time
during this recovery):
- `docker compose --profile init run --rm cert-init` (TLS certs) +
  `docker run --rm -v kaust-iot-lab_mqtt-secure-passwd:/mosquitto/config
  eclipse-mosquitto:2 mosquitto_passwd -c -b /mosquitto/config/passwd
  labworker "LabWork3r-Secr3t!"` + a `chmod 644` on that same file — all three
  documented in `lab/README.md`'s "First-time setup (once per clone)" section,
  which a from-scratch volume needs even on a machine that already has the
  images built.
- The NCA compliance catalog (81 guidelines) and its ~20 finding-mapping rows
  are **not** part of `init.sql`/migrations at all — they're seeded
  imperatively via `python -m policies.nca.seed_catalog` and `python -m
  policies.nca.seed_finding_mappings` (see `docs/nca-compliance.md`), which
  had never been run against this freshly-recreated database. `auditor-worker`
  has no `psycopg` installed (it talks to `auditor-api` over HTTP, never
  touches Postgres directly) so these have to run inside `auditor-api`
  instead, with `DATABASE_URL`/`PYTHONPATH` passed explicitly:
  ```
  docker compose exec -e DATABASE_URL="postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor" \
    -e PYTHONPATH="/work" auditor-api python3 -m policies.nca.seed_catalog
  docker compose exec -e DATABASE_URL="postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor" \
    -e PYTHONPATH="/work" auditor-api python3 -m policies.nca.seed_finding_mappings
  ```

## How to prevent it next time
This is a Docker Desktop engine bug, not something the project's compose files
or code can prevent outright — but the diagnostic path is now on record:
before escalating straight to a destructive purge, send a raw DNS query
(UDP socket, not `getent`) to `127.0.0.11:53` for a few different real
container names on the affected network and compare response/timeout per
name. A consistent, per-name-specific split (some names answer fast, others
hang forever) is a strong signal this is Docker Desktop engine-side
corruption, not a compose config or host-network problem — skip re-testing
`down`/`up`, WSL restart, or app restart (all already ruled out once, see
`handoff.txt`'s full diagnostic trail from the prior session) and go straight
to Troubleshoot → Clean/Purge data.

Separately: this repo's fresh-clone bootstrap (`lab/README.md`) does not
mention the NCA catalog seed step at all, only the cert/mqtt-password step —
worth adding, since a rebuilt or freshly-purged environment silently shows
"0 controls in catalog" with no error, easy to miss without deliberately
checking the NCA Compliance page.

## References
- `handoff.txt` (deleted after this session folded its content into
  `CLAUDE.md` — see the same-day changelog entry) had the full pre-reboot
  diagnostic trail this session built on.
- `docs/nca-compliance.md` documents the seed script invocations.
