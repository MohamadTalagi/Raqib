# Error & Solution Log

Every error we hit while building this project gets its **own Markdown file** here. These logs
feed our research report later, so we capture them even when the error is small.

## How to add an entry

1. Copy `ERROR_TEMPLATE.md` to a new file named `NNN-short-slug.md`
   (increment `NNN`, use a short kebab-case slug — e.g. `001-docker-compose-port-conflict.md`).
2. Fill in every section.
3. Add a one-line row to the index table below.

## Index

| ID | Title | Component | Date | Status |
|----|-------|-----------|------|--------|
| [001](001-npx-enoent-windows-mcp.md) | `spawn npx ENOENT` on Windows MCP launch | ssh-mcp / MCP servers | 2026-07-07 | resolved |
| [002](002-pydantic-core-no-py314-wheel.md) | `pydantic-core` has no Python 3.14 wheel, source build fails (no MSVC linker) | lab/devices/smart-camera | 2026-07-08 | resolved |
| [003](003-docker-credstore-fails-over-ssh.md) | Docker `credsStore: desktop` fails over non-interactive SSH session | build PC / Docker Desktop | 2026-07-08 | resolved |
| [004](004-docker-buildx-attestation-manifest-already-exists.md) | `docker build` succeeds but reports "image already exists" (buildx attestation manifest) | build PC / Docker Desktop | 2026-07-08 | resolved |
| [005](005-busybox-nc-localhost-ipv6-healthcheck.md) | BusyBox `nc -z localhost <port>` healthcheck fails for an IPv4-only-bound server | lab/telnet-sim | 2026-07-08 | resolved |
