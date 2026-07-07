# ssh-mcp setup — control the home PC from the laptop over Tailscale

Goal: let Claude Code on the **laptop** run commands on the **home Windows 11 PC** (32 GB RAM,
Tailscale IP `100.99.182.30`) through the `ssh-mcp` server (https://github.com/tufantunc/ssh-mcp).

**Security posture:** SSH is restricted to the Tailscale network only (never the public internet),
key authentication is preferred, and **no password is stored in any file**.

> ⚠️ Run this at the **execution boundary** — right when you switch Opus → Sonnet. Adding an MCP
> requires restarting Claude Code, so bundle it with that restart. Do it *after* the design spec is
> written (the spec is on disk, so a restart loses nothing).

---

## Files

| File | Runs on | As admin? | Purpose |
|---|---|---|---|
| `pc-1-enable-openssh.ps1` | **home PC** | yes (elevated) | Install/enable OpenSSH Server, make PowerShell the default SSH shell, lock the firewall to Tailscale only |
| `pc-2-install-authorized-key.ps1` | **home PC** | yes (elevated) | Install your laptop's public key into the correct `authorized_keys` with correct ACLs |
| `laptop-setup.ps1` | **laptop** | no | Generate an SSH key, print the public key, and register `ssh-mcp` in Claude Code at **user scope** |

Get the two `pc-*.ps1` files onto the PC however is easiest (Tailscale file send, OneDrive, USB).

---

## Order of operations

1. **On the PC** (elevated PowerShell):
   ```powershell
   ./pc-1-enable-openssh.ps1
   ```
   Note the **username** it prints at the end — you'll need it on the laptop. (I won't assume it.)

2. **On the laptop** (normal PowerShell), using that username:
   ```powershell
   ./laptop-setup.ps1 -PcUser <THE_PC_USERNAME>
   ```
   It generates `~/.ssh/id_ed25519` (if missing), prints your **public key**, and registers the MCP.
   Copy the printed public key.

3. **On the PC** (elevated PowerShell), paste the public key:
   ```powershell
   ./pc-2-install-authorized-key.ps1 -PublicKey "ssh-ed25519 AAAA... your-comment"
   ```

4. **On the laptop**, verify SSH works with the key:
   ```powershell
   ssh -i $env:USERPROFILE\.ssh\id_ed25519 <THE_PC_USERNAME>@100.99.182.30 hostname
   ```

5. **Restart Claude Code**, then ask it to run a safe test through the MCP:
   `hostname`, `whoami`, or `Get-ComputerInfo | Select-Object CsName, WindowsProductName`.

---

## Password fallback (temporary, optional)

If key auth isn't working yet, you can register with a password instead. **Type it yourself** — do
NOT paste it into any file in this repo. It lands only in your user-scope MCP config, never in the project:

```powershell
claude mcp add --scope user --transport stdio ssh-mcp -- cmd /c npx -y ssh-mcp -- --host=100.99.182.30 --user=<USER> --password=<TYPE_IT_HERE>
```

> **Windows note:** launch via `cmd /c npx`, not bare `npx`. On Windows, `npx` is `npx.cmd`, and
> Node's `spawn` can't resolve a bare `npx` — you get `spawn npx ENOENT` and the MCP never starts.
> See `docs/errors/001-npx-enoent-windows-mcp.md`. (Your existing `ssh-pi` MCP has this same bug.)

Switch to key auth as soon as you can, then remove the password entry (`claude mcp remove ssh-mcp`
and re-run `laptop-setup.ps1`).

## Remote shell note
`pc-1` sets the default SSH shell to **PowerShell**, so commands the MCP runs on the PC are
PowerShell by default (matches the Windows target).
