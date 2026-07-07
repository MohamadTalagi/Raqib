# ERR-003 — Docker `credsStore: desktop` fails over non-interactive SSH session

- **Date:** 2026-07-08
- **Component:** build PC (OSRA-PC2025-V2) / Docker Desktop config
- **Severity:** medium
- **Status:** resolved
- **Author:** Claude (subagent-driven-development, Task 7 controller-side PC verification)

## What happened
Running `docker build` on the build PC over the ssh-mcp (non-interactive SSH) session failed
immediately while loading the base image metadata (`python:3.12-slim`), before any actual pull
happened.

## Exact error / symptom
```
#2 ERROR: error getting credentials - err: exit status 1, out: `A specified logon session does not exist. It may already have been terminated.`
------
 > [internal] load metadata for docker.io/library/python:3.12-slim:
------
ERROR: failed to build: failed to solve: error getting credentials - err: exit status 1, out: `A specified logon session does not exist. It may already have been terminated.`
```

## Environment
- OS / shell: Windows 11, Docker Desktop 29.1.3 (WSL2 backend), Compose v5.0.0-desktop.1
- Tool + version: `docker build` invoked over an ssh-mcp (Windows OpenSSH) non-interactive session
- Relevant files: `C:\Users\osama\.docker\config.json`

## Root cause
Docker Desktop's default `config.json` sets `"credsStore": "desktop"`, which shells out to
`docker-credential-desktop.exe`. That helper talks to Docker Desktop's credential vault, which is
tied to the interactive Windows logon/desktop session. An SSH exec session has no such interactive
session, so the credential helper fails outright — even for a fully anonymous, public-image pull
that needs no credentials at all.

## The fix
Backed up `config.json` and removed the `credsStore` key entirely, so the Docker CLI does plain
anonymous registry calls without invoking any credential helper:
```powershell
Copy-Item $env:USERPROFILE\.docker\config.json $env:USERPROFILE\.docker\config.json.bak
$config = Get-Content $env:USERPROFILE\.docker\config.json -Raw | ConvertFrom-Json
$config.PSObject.Properties.Remove('credsStore')
$config | ConvertTo-Json -Depth 10 | Set-Content $env:USERPROFILE\.docker\config.json
```
Confirmed the subsequent `docker build` progressed past the metadata-load step.

## How to prevent it next time
For any Docker automation that must run over a headless/non-interactive session on Windows with
Docker Desktop, check `~/.docker/config.json` for a `credsStore` up front if only public images are
needed — it's a common blocker that looks like a network/registry problem but is actually a
credential-helper/session issue. If private registry auth is ever needed from this PC over SSH,
revisit this (a config-file-based credential store, not `desktop`, would be needed instead of
reverting to `desktop`).

## References
None external — diagnosed directly via `docker build` output in this session.
