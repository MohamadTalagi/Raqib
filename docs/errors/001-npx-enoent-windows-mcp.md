# ERR-001 — `spawn npx ENOENT` when starting an npx-based MCP on Windows

- **Date:** 2026-07-07
- **Component:** ssh-mcp setup / Claude Code MCP servers (also affects the existing `ssh-pi` MCP)
- **Severity:** high (blocks any npx-launched MCP from starting)
- **Status:** resolved
- **Author:** osama

## What happened
While setting up remote control of the home PC, we probed the already-configured `ssh-pi` MCP. Its
health check failed and blocked the tool. The same launch mechanism (`npx`) is what our new
tufantunc/`ssh-mcp` would use, so this would have broken our setup too.

## Exact error / symptom
```
PreToolUse:mcp__ssh-pi__ssh_list_servers hook error: [MCPHealthCheck] ssh-pi is unavailable
(spawn npx ENOENT). Blocking ssh_list_servers so Claude can fall back to non-MCP tools.
```

## Environment
- OS / shell: Windows 11 Home, PowerShell 5.1
- Node: v24.14.0 — `node.exe` at `C:\Program Files\nodejs\`
- npm/npx: 11.9.0 — `npx.ps1` / `npx.cmd` at `C:\Program Files\nodejs\` (NO bare `npx.exe`)
- Relevant files: `setup/ssh-mcp/laptop-setup.ps1`, `setup/ssh-mcp/README.md`

## Root cause
Node **is** installed and `npx` works in an interactive shell — but on Windows `npx` is a `.cmd`/`.ps1`
script, not an `.exe`. When an MCP is configured with `command: "npx"`, Node's `child_process.spawn`
(no shell) searches for an executable literally named `npx`, finds none (there's no `npx.exe`), and
throws `ENOENT`. So the MCP process never launches. This is a general Windows problem for **any**
npx-launched MCP, not specific to `ssh-pi`.

## The fix
Launch through `cmd`, which resolves `npx.cmd` correctly. Register the MCP with `cmd /c npx …`
instead of bare `npx …`:

```powershell
# BAD (Windows): spawn npx ENOENT
claude mcp add --scope user --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=... --user=... --key=...

# GOOD (Windows):
claude mcp add --scope user --transport stdio ssh-mcp -- cmd /c npx -y ssh-mcp -- --host=... --user=... --key=...
```

`setup/ssh-mcp/laptop-setup.ps1` and the README were updated to use `cmd /c npx`.

## How to prevent it next time
- On Windows, always launch npx-based MCP servers via `cmd /c npx` (or point `command` at the full
  path to `npx.cmd`). Never use bare `npx` in an MCP `command` field on Windows.
- The existing **`ssh-pi`** MCP has the same defect and is currently unavailable because of it. Fix
  its config the same way (edit its `command` from `npx` to `cmd` with args `/c npx …`, typically in
  `~/.claude.json`) to restore the Pi workflow.

## References
- Node.js Windows `spawn` + `.cmd` resolution behavior (bare command name has no `.exe`).
