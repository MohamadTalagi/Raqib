# ERR-017 — `internal: true` Docker network silently blocks Docker Desktop's host port-forwarding proxy

- **Date:** 2026-07-08
- **Component:** lab/docker-compose.dev.yml (Task 17's dev overlay)
- **Severity:** high
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, controller-side, Task 20 full-stack verification)

## What happened
During Task 20's full-stack verification (after resolving [016](016-disk-space-exhaustion-corrupts-docker-containerd.md)'s
disk-space/containerd corruption and confirming Docker Desktop itself was healthy again), `auditor-api`
(published at `:8000`) and `auditor-web` (published at `:8080`) were still completely unreachable from the
host — `docker port` showed no actual binding despite `docker-compose.dev.yml` correctly declaring
`ports: ["8000:8000"]` / the base compose file's `8080:80` mapping for `auditor-web`, and despite
`docker compose config`'s resolved output showing the correct `published:` values. Meanwhile
`device-insecure` (`:8081`) and `mqtt-broker-insecure` (`:18830`), published by the exact same
`docker-compose.dev.yml` mechanism, worked correctly.

## Exact error / symptom
```
docker port kaust-iot-lab-auditor-api-1
# (no output — empty)

curl.exe -s -o NUL -w "%{http_code}" http://localhost:8000/health
# 000  (connection failed entirely)
```
```
docker inspect kaust-iot-lab-auditor-api-1 --format "{{json .NetworkSettings.Ports}}"
# {"8000/tcp":[]}          <- empty, no actual binding
docker inspect kaust-iot-lab-auditor-api-1 --format "{{json .HostConfig.PortBindings}}"
# {"8000/tcp":[{"HostIp":"","HostPort":"8000"}]}   <- binding IS configured, just never took effect
```

## Environment
- OS: Windows 11, Docker Desktop with WSL2 backend
- Relevant files: `lab/docker-compose.yml` (defines `internal-network` with `internal: true`),
  `lab/docker-compose.dev.yml` (the dev-only port-publishing overlay from Task 17)

## Root cause
`auditor-api` and `auditor-web` are both connected only to `internal-network`, which is deliberately marked
`internal: true` in the base compose file — the whole point of that flag is that the trusted backend segment
has no route to anything outside itself, matching the project's threat model (`auditor-worker` is meant to be
the *only* bridge between the untrusted device segment and the trusted backend).

On Docker Desktop for Windows/Mac, host-published ports are not implemented via plain Linux iptables DNAT the
way they are on native Linux Docker — they go through Docker Desktop's own host-side forwarding proxy, which
has to route into the Docker network stack running inside the WSL2 VM. A network flagged `internal: true` is
specifically isolated from *all* external routing as a hard guarantee — and that isolation apparently extends
to blocking Docker Desktop's own forwarding proxy from reaching containers whose only network is internal,
even though the container's own `HostConfig.PortBindings` correctly records the intended mapping. The
publish configuration is accepted and stored, it just silently never takes effect.

This was confirmed as the actual cause (not a leftover of the disk-space corruption) by a direct A/B test:
`device-insecure`/`mqtt-broker-insecure` (both on `audit-network`, which is a normal, non-internal network)
had their dev-only published ports working correctly at the exact same moment `auditor-api`/`auditor-web`
(both on `internal-network` only) did not.

## The fix
`lab/docker-compose.dev.yml` now overrides `internal-network`'s `internal` flag to `false`, in the dev overlay
only — never in the base `docker-compose.yml`, which keeps the production/default security posture
(`internal-network` genuinely isolated, no accidental host exposure) fully intact when the lab is run without
the dev overlay:
```yaml
networks:
  internal-network:
    internal: false
```
This is consistent with `docker-compose.dev.yml`'s own documented purpose (its header comment already says
"Overlay for local development only — exposes device ports to localhost"): relaxing the same network's
isolation for the same reason it already relaxes individual container port exposure.

Verified directly: after this change, `docker port kaust-iot-lab-auditor-api-1` correctly showed
`8000/tcp -> 0.0.0.0:8000`, and both `http://localhost:8000/health` and `http://localhost:8080` returned
`200` from the host.

## How to prevent it next time
When a service that needs host-published ports for local development lives on a network marked
`internal: true` for legitimate production security reasons, don't assume `ports:` declarations alone are
sufficient — verify the actual binding (`docker port`, not just `docker compose config`'s resolved YAML)
before concluding a compose file is correct. The compose config validates and resolves the *intent* correctly;
whether Docker Desktop's specific implementation can *honor* that intent for an internal-only container is a
separate question that only shows up at runtime. This is a Docker Desktop (Windows/Mac) implementation detail,
not something `docker compose config` or `docker compose up`'s own logging will warn about.

## References
None external — diagnosed directly via a controlled A/B comparison between `internal-network`-only and
`audit-network` containers' actual `docker port` output in this session.
