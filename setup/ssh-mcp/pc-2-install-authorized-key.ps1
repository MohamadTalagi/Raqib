#Requires -RunAsAdministrator
<#
  Run this ON THE HOME PC (Windows 11) in an ELEVATED PowerShell.
  Installs the laptop's PUBLIC key into the correct authorized_keys file with the
  strict ACLs that Windows OpenSSH requires. Handles admin vs standard accounts.

  Usage:
    ./pc-2-install-authorized-key.ps1 -PublicKey "ssh-ed25519 AAAA... comment"
#>
param(
    [Parameter(Mandatory)] [string] $PublicKey
)
$ErrorActionPreference = 'Stop'

$isAdminUser = ([Security.Principal.WindowsPrincipal] `
    [Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole(
    [Security.Principal.WindowsBuiltInRole]::Administrator)

if ($isAdminUser) {
    # OpenSSH on Windows requires admin users' keys to live here, NOT in ~/.ssh
    $akFile = Join-Path $env:ProgramData 'ssh\administrators_authorized_keys'
    Write-Host "Administrator account -> $akFile"
} else {
    $akDir = Join-Path $env:USERPROFILE '.ssh'
    if (-not (Test-Path $akDir)) { New-Item -ItemType Directory -Path $akDir | Out-Null }
    $akFile = Join-Path $akDir 'authorized_keys'
    Write-Host "Standard account -> $akFile"
}

if (-not (Test-Path $akFile)) { New-Item -ItemType File -Path $akFile | Out-Null }

$existing = Get-Content $akFile -ErrorAction SilentlyContinue
if ($existing -contains $PublicKey.Trim()) {
    Write-Host 'Key already present.' -ForegroundColor Green
} else {
    Add-Content -Path $akFile -Value $PublicKey.Trim()
    Write-Host 'Key added.' -ForegroundColor Green
}

# Fix ACLs — OpenSSH refuses keys on files that are too permissive
if ($isAdminUser) {
    icacls $akFile /inheritance:r | Out-Null
    icacls $akFile /grant 'Administrators:F' | Out-Null
    icacls $akFile /grant 'SYSTEM:F' | Out-Null
    Write-Host 'ACLs restricted to Administrators + SYSTEM.'
}

Restart-Service sshd
Write-Host 'sshd restarted. You can now test key auth from the laptop.' -ForegroundColor Green
