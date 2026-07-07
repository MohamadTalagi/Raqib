<#
  Run this ON THE LAPTOP (normal PowerShell — no admin needed).
  1) Generates an ed25519 SSH key if you don't have one.
  2) Prints your PUBLIC key (paste it into pc-2-install-authorized-key.ps1 on the PC).
  3) Registers ssh-mcp in Claude Code at USER scope, using key auth (no password in any file).

  Usage:
    ./laptop-setup.ps1 -PcUser <THE_PC_USERNAME>
  The username is printed at the end of pc-1-enable-openssh.ps1. This script does NOT assume it.
#>
param(
    [Parameter(Mandatory)] [string] $PcUser,
    [string] $PcIp   = '100.99.182.30',
    [string] $KeyPath = "$env:USERPROFILE\.ssh\id_ed25519"
)
$ErrorActionPreference = 'Stop'

# 1. Generate key if missing (empty passphrase for unattended MCP use)
if (-not (Test-Path $KeyPath)) {
    Write-Host "Generating SSH key at $KeyPath ..." -ForegroundColor Cyan
    $sshDir = Split-Path $KeyPath -Parent
    if (-not (Test-Path $sshDir)) { New-Item -ItemType Directory -Path $sshDir | Out-Null }
    # If this line errors on quoting, run manually: ssh-keygen -t ed25519 -f "$KeyPath"
    ssh-keygen -t ed25519 -f $KeyPath -N '""'
} else {
    Write-Host "Key already exists at $KeyPath" -ForegroundColor Green
}

# 2. Show the public key to install on the PC
Write-Host ''
Write-Host '=== YOUR PUBLIC KEY — paste into pc-2-install-authorized-key.ps1 on the PC ===' -ForegroundColor Yellow
Get-Content "$KeyPath.pub"
Write-Host '============================================================================' -ForegroundColor Yellow
Write-Host ''
Write-Host "After installing it, verify:  ssh -i `"$KeyPath`" $PcUser@$PcIp hostname" -ForegroundColor Cyan
Write-Host ''

# 3. Register ssh-mcp at USER scope (forward slashes so the path parses cleanly)
$keyFwd = $KeyPath -replace '\\','/'
Write-Host 'Registering ssh-mcp in Claude Code (user scope)...' -ForegroundColor Cyan
claude mcp add --scope user --transport stdio ssh-mcp -- npx -y ssh-mcp -- --host=$PcIp --user=$PcUser --key=$keyFwd

Write-Host ''
Write-Host 'Registered. Now RESTART Claude Code, then test the MCP with: hostname / whoami' -ForegroundColor Green
