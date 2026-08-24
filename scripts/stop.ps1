<#
.SYNOPSIS
  Raqib / IoTGuard - stop the lab.

.DESCRIPTION
  Without -Wipe: stops and removes the containers but keeps every Docker
  volume, so devices, evidence and verdicts survive the restart.
  With -Wipe: also deletes the volumes - a true from-scratch reset that
  destroys the auditor database.

.EXAMPLE
  .\scripts\stop.ps1
  .\scripts\stop.ps1 -Wipe
#>
param(
    [switch]$Wipe
)

# NOTE: deliberately NOT 'Stop'. docker writes its progress lines to stderr,
# which Windows PowerShell 5.1 would turn into terminating NativeCommandErrors.
# Exit codes are checked explicitly instead.
$ErrorActionPreference = 'Continue'

$RepoRoot = Split-Path -Parent $PSScriptRoot
$ComposeArgs = @('compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')

docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Write-Host "Docker daemon is not running - nothing to stop."
    exit 0
}

Set-Location (Join-Path $RepoRoot 'lab')

if ($Wipe) {
    Write-Host "==> WARNING: this deletes the lab's Docker volumes." -ForegroundColor Yellow
    Write-Host "    The auditor database (devices, evidence, verdicts) will be lost."
    $confirm = Read-Host "    Type 'wipe' to confirm"
    if ($confirm -ne 'wipe') {
        Write-Host "Aborted - nothing was removed."
        exit 1
    }
    Write-Host "==> Stopping and removing containers + volumes" -ForegroundColor Cyan
    docker @ComposeArgs down -v --remove-orphans
    $code = $LASTEXITCODE
    Write-Host "==> Done. The next start.ps1 will redo first-time setup and reseed."
} else {
    Write-Host "==> Stopping and removing containers (data volumes are preserved)" -ForegroundColor Cyan
    docker @ComposeArgs down --remove-orphans
    $code = $LASTEXITCODE
    Write-Host "==> Done. Restart with: .\scripts\start.ps1"
}

exit $code
