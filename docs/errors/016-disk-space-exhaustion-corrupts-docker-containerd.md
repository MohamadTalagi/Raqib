# ERR-016 — PC disk space exhaustion corrupted Docker Desktop's containerd storage and port-forwarding proxy during Task 20's final verification

- **Date:** 2026-07-08
- **Component:** build PC (OSRA-PC2025-V2) — Docker Desktop infrastructure, not project code
- **Severity:** high (blocking, though ultimately resolved without data loss)
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, controller-side, Task 20 full-stack verification)

## What happened
While transferring the `ghcr.io/cirruslabs/flutter:stable` Docker image directly to the PC via `scp` (to
bypass an extremely slow public-internet `docker pull`, see context below), `docker load` failed with a
containerd `input/output error`. Investigation found the PC's `C:` drive had only ~2.5GB free out of 1862GB
total — the load attempt (needing headroom for a ~7GB uncompressed image) had run the drive to exhaustion
mid-write, corrupting containerd's blob store. After that, even basic commands like `docker images` and
`docker system df` failed with the same I/O error, and `docker ps`/`docker load` were unusable.

## Exact error / symptom
```
failed to ingest "blobs/sha256/28bb4f253b703cce1e21ef11b5e626f19ce7d34c5d1b465372488e28b0298e6e": failed to copy: failed to send write: write /var/lib/desktop-containerd/daemon/io.containerd.content.v1.content/ingest/.../data: input/output error
```
```
Error response from daemon: rpc error: code = Unknown desc = blob sha256:0c530cfd08ac28a497e8ccd6365b2e1ca87f7fc3676b3175235d0e301da25d17 expected at /var/lib/desktop-containerd/daemon/io.containerd.content.v1.content/blobs/sha256/0c530cfd08ac28a497e8ccd6365b2e1ca87f7fc3676b3175235d0e301da25d17: open ...: input/output error
```

## Environment
- OS: Windows 11, Docker Desktop with WSL2 backend
- Host: build PC (shared/long-lived machine, also hosts many unrelated Docker images from other projects —
  `docker images` at the time listed dozens of unrelated images: wazuh, n8n, supabase, portainer, MobSF, etc.)

## Root cause
The PC's `C:` drive had accumulated years of Docker images/build cache across many unrelated projects, leaving
almost no headroom. Attempting to load a large (~2.2GB compressed, ~7GB uncompressed) image with essentially
zero free space caused containerd's write operations to fail partway through, leaving its content-addressed
blob store in an inconsistent state — subsequent reads of blobs that were mid-write when the disk filled
returned I/O errors even for blobs unrelated to the failed load, because the whole containerd daemon's storage
layer was affected, not just the one image being loaded.

Recovery required two independent fixes for two independent Docker Desktop subsystems that both got into a
bad state from the same root cause:
1. **containerd/WSL2 VM corruption** — fixed by `wsl --shutdown`, which forces Docker Desktop's Linux VM to
   fully restart and rebuild its containerd state cleanly.
2. **Host port-forwarding proxy** — after (1), `docker ps`/`docker images` worked again, but containers with
   published ports (`auditor-api:8000`, `auditor-web:8080`) had `NetworkSettings.Ports` come back empty
   despite correct `HostConfig.PortBindings`, meaning the actual host-to-container port forwarding silently
   never took effect. This needed a full Docker Desktop process kill + relaunch (not just `wsl --shutdown`)
   to recover — Docker Desktop on Windows runs the WSL2 VM/containerd and the Windows-side port-forwarding
   proxy as separate subsystems that can each independently wedge.

Even after both restarts, `auditor-api`/`auditor-web` still didn't get reachable published ports — that
turned out to be a **separate, unrelated, genuine bug** (their placement on an `internal: true` Docker network
blocking the port-forwarding proxy entirely), logged separately as [017](017-internal-network-blocks-docker-desktop-port-forwarding.md).
Don't conflate the two — this entry is specifically about the disk-space-triggered corruption; 017 is a real
architectural gap in the dev compose overlay that would have surfaced eventually regardless of the disk
incident.

## The fix
1. User manually freed ~50GB of disk space on the PC (this was the load-bearing fix — without headroom,
   nothing else would have worked).
2. `wsl --shutdown` to recover containerd's corrupted blob store; verified via `docker images` succeeding.
3. Full Docker Desktop process restart (`Stop-Process` on all `docker`-named processes, then relaunch
   `Docker Desktop.exe`) to recover the host port-forwarding proxy; verified via `docker port` on a
   known-working container (`device-insecure`, correctly bound at that point) before concluding the proxy
   itself was healthy again.
4. Retried the `scp` transfer (source file still existed locally from the failed first attempt, no need to
   re-`docker save`) and `docker load` — succeeded once there was adequate disk space.

## How to prevent it next time
- Check free disk space *before* transferring or loading a large image, not after a failure — a simple
  `Get-CimInstance -ClassName Win32_LogicalDisk -Filter "DeviceID='C:'"` check would have caught this in
  seconds and avoided the entire corruption-and-recovery detour.
- On shared, long-lived build machines accumulating images across many unrelated projects, periodic
  `docker system prune` (or at minimum `docker image prune`) keeps headroom available. This PC's `docker
  images` output showed dozens of images from entirely unrelated projects (n8n, wazuh, supabase, MobSF,
  portainer, various MCP servers) that were never cleaned up.
- When diagnosing Docker Desktop issues on Windows, remember it is not a single monolithic daemon — the
  WSL2 VM/containerd and the host-side port-forwarding proxy are separate subsystems, and `wsl --shutdown`
  alone does not necessarily fix a wedged proxy. If `docker ps` works but published ports don't forward,
  suspect the proxy specifically and try a full Docker Desktop process restart before assuming the fix
  didn't work at all.

## References
None external — diagnosed directly via containerd's own error text and iterative recovery-step verification
in this session.
