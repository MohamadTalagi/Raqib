<#
.SYNOPSIS
  Raqib / IoTGuard - one-command start.

.DESCRIPTION
  Idempotent: safe on a fresh clone, on an already-running stack, or after a
  Docker volume purge. First-time setup steps run only when actually missing.

.EXAMPLE
  .\scripts\start.ps1
  .\scripts\start.ps1 -Build      # force a rebuild of the custom images
  .\scripts\start.ps1 -NoSeed     # skip database seeding
#>
param(
    [switch]$Build,
    [switch]$NoSeed
)

# NOTE: deliberately NOT 'Stop'. docker and docker compose write their progress
# lines to stderr, which Windows PowerShell 5.1 would turn into terminating
# NativeCommandErrors. Exit codes are checked explicitly instead.
$ErrorActionPreference = 'Continue'

$RepoRoot     = Split-Path -Parent $PSScriptRoot
$LabDir       = Join-Path $RepoRoot 'lab'
$Project      = 'kaust-iot-lab'
$PasswdVolume = "${Project}_mqtt-secure-passwd"
$ComposeArgs  = @('compose', '-f', 'docker-compose.yml', '-f', 'docker-compose.dev.yml')

function Say($msg) { Write-Host ""; Write-Host "==> $msg" -ForegroundColor Cyan }

function Fail($msg) {
    Write-Host "ERROR: $msg" -ForegroundColor Red
    exit 1
}

# --- 0. Docker must be running -----------------------------------------------
docker info 2>&1 | Out-Null
if ($LASTEXITCODE -ne 0) {
    Fail "cannot talk to the Docker daemon. Start Docker Desktop, wait for 'Engine running', then retry."
}

Set-Location $LabDir

# --- 1. lab/.env --------------------------------------------------------------
if (-not (Test-Path '.env')) {
    Say "Creating lab/.env from .env.example"
    Copy-Item '.env.example' '.env'
    Write-Host "    (optional) add your GEMINI_API_KEY to lab\.env for AI remediation"
} else {
    Write-Host "==> lab/.env already present"
}

# --- 2. TLS certificates ------------------------------------------------------
if ((Test-Path 'certs\ca.crt') -and (Test-Path 'certs\strong.crt') -and (Test-Path 'certs\weak.crt') -and (Test-Path 'certs\mqtt-server.crt')) {
    Write-Host "==> TLS certificates already generated"
} else {
    Say "Generating lab TLS certificates"
    docker @ComposeArgs --profile init run --rm cert-init
    if ($LASTEXITCODE -ne 0) { Fail "certificate generation failed." }
}

# --- 3. Secure MQTT password file --------------------------------------------
docker run --rm -v "${PasswdVolume}:/mosquitto/config" alpine test -f /mosquitto/config/passwd 2>&1 | Out-Null
if ($LASTEXITCODE -eq 0) {
    Write-Host "==> MQTT password file already present"
} else {
    Say "Creating the secure MQTT broker password file"
    docker run --rm -v "${PasswdVolume}:/mosquitto/config" eclipse-mosquitto:2 mosquitto_passwd -c -b /mosquitto/config/passwd labworker "LabWork3r-Secr3t!"
    docker run --rm -v "${PasswdVolume}:/mosquitto/config" alpine chmod 644 /mosquitto/config/passwd
    if ($LASTEXITCODE -ne 0) { Fail "could not create the MQTT password file." }
}

# --- 4. Bring the stack up ----------------------------------------------------
Say "Starting the stack (first build takes several minutes)"
if ($Build) {
    docker @ComposeArgs up -d --build
} else {
    docker @ComposeArgs up -d
}
if ($LASTEXITCODE -ne 0) { Fail "'docker compose up' failed - see the output above." }

# --- 5. Wait for the API ------------------------------------------------------
Say "Waiting for auditor-api to become healthy"
$ready = $false
foreach ($i in 1..60) {
    try {
        Invoke-WebRequest -Uri 'http://localhost:8000/health' -TimeoutSec 3 -UseBasicParsing | Out-Null
        $ready = $true
        Write-Host "    API is up."
        break
    } catch {
        Start-Sleep -Seconds 3
    }
}
if (-not $ready) {
    Fail "auditor-api did not come up within 3 minutes. Check: docker compose logs auditor-api"
}

# --- 6. Seed the database (idempotent) ---------------------------------------
if (-not $NoSeed) {
    Say "Seeding the database (idempotent - safe to repeat)"
    docker @ComposeArgs exec -T -e PYTHONPATH=/work -e DATABASE_URL=postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor auditor-api python -m policies.engine.seed_devices
    docker @ComposeArgs exec -T auditor-api python -m policies.nca.seed_catalog
    docker @ComposeArgs exec -T auditor-api python -m policies.nca.seed_finding_mappings
    docker @ComposeArgs exec -T auditor-api python -m policies.nca.seed_checklists
    if ($LASTEXITCODE -ne 0) { Write-Host "WARNING: a seeding step reported an error - check the output above." -ForegroundColor Yellow }
}

# --- 7. Report ----------------------------------------------------------------
Say "Container status"
docker @ComposeArgs ps --format "table {{.Service}}`t{{.Status}}"

Write-Host @"

==> Ready.

  Dashboard    http://localhost:8080
  API summary  http://localhost:8000/summary

  Simulated devices (self-signed certs on the HTTPS ones):
    device-insecure     http://localhost:8081/
    device-partial      https://localhost:8082/
    device-hardened     https://localhost:8083/
    device-smartlock    http://localhost:8084/
    device-plc-gateway  http://localhost:8085/health   (no page at /)
    device-router-gw    http://localhost:8086/
    device-nvr          http://localhost:8087/
    device-speaker      http://localhost:8088/health   (no page at /)

  Stop with: .\scripts\stop.ps1
"@ -ForegroundColor Green
