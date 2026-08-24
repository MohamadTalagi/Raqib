#!/usr/bin/env bash
# Raqib / IoTGuard - one-command start.
#
# Idempotent: safe to run on a fresh clone, on an existing stack, or after a
# Docker volume purge. It performs the first-time setup steps only when they
# are actually missing.
#
# Usage:
#   scripts/start.sh              # start (build only what's missing)
#   scripts/start.sh --build      # force a rebuild of the custom images
#   scripts/start.sh --no-seed    # skip database seeding
set -euo pipefail

# Git Bash on Windows rewrites container-side paths like /work into
# C:/Program Files/Git/work. Disable that for every docker call below.
export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LAB_DIR="$REPO_ROOT/lab"
COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml)
PROJECT=kaust-iot-lab
PASSWD_VOLUME="${PROJECT}_mqtt-secure-passwd"

BUILD_FLAG=""
DO_SEED=1
for arg in "$@"; do
  case "$arg" in
    --build)   BUILD_FLAG="--build" ;;
    --no-seed) DO_SEED=0 ;;
    -h|--help) sed -n '2,12p' "$0"; exit 0 ;;
    *) echo "Unknown option: $arg" >&2; exit 2 ;;
  esac
done

say() { echo; echo "==> $*"; }

# --- 0. Docker must be running -----------------------------------------------
if ! docker info >/dev/null 2>&1; then
  echo "ERROR: cannot talk to the Docker daemon." >&2
  echo "       Start Docker Desktop and wait for 'Engine running', then retry." >&2
  exit 1
fi

cd "$LAB_DIR"

# --- 1. lab/.env --------------------------------------------------------------
if [[ ! -f .env ]]; then
  say "Creating lab/.env from .env.example"
  cp .env.example .env
  echo "    (optional) add your GEMINI_API_KEY to lab/.env for AI remediation"
else
  echo "==> lab/.env already present"
fi

# --- 2. TLS certificates ------------------------------------------------------
if [[ -f certs/ca.crt && -f certs/strong.crt && -f certs/weak.crt && -f certs/mqtt-server.crt ]]; then
  echo "==> TLS certificates already generated"
else
  say "Generating lab TLS certificates"
  "${COMPOSE[@]}" --profile init run --rm cert-init
fi

# --- 3. Secure MQTT password file --------------------------------------------
if docker run --rm -v "${PASSWD_VOLUME}:/mosquitto/config" alpine \
     test -f /mosquitto/config/passwd 2>/dev/null; then
  echo "==> MQTT password file already present"
else
  say "Creating the secure MQTT broker password file"
  docker run --rm -v "${PASSWD_VOLUME}:/mosquitto/config" eclipse-mosquitto:2 \
    mosquitto_passwd -c -b /mosquitto/config/passwd labworker "LabWork3r-Secr3t!"
  docker run --rm -v "${PASSWD_VOLUME}:/mosquitto/config" alpine \
    chmod 644 /mosquitto/config/passwd
fi

# --- 4. Bring the stack up ----------------------------------------------------
say "Starting the stack (first build takes several minutes)"
"${COMPOSE[@]}" up -d $BUILD_FLAG

# --- 5. Wait for the API ------------------------------------------------------
say "Waiting for auditor-api to become healthy"
for i in $(seq 1 60); do
  if curl -sf http://localhost:8000/health >/dev/null 2>&1; then
    echo "    API is up."
    break
  fi
  if [[ $i -eq 60 ]]; then
    echo "ERROR: auditor-api did not come up within 3 minutes." >&2
    echo "       Check: docker compose logs auditor-api" >&2
    exit 1
  fi
  sleep 3
done

# --- 6. Seed the database (idempotent) ---------------------------------------
if [[ $DO_SEED -eq 1 ]]; then
  say "Seeding the database (idempotent - safe to repeat)"
  "${COMPOSE[@]}" exec -T \
    -e PYTHONPATH=/work \
    -e DATABASE_URL=postgresql://auditor:auditor-lab-pw@auditor-database:5432/auditor \
    auditor-api python -m policies.engine.seed_devices
  "${COMPOSE[@]}" exec -T auditor-api python -m policies.nca.seed_catalog
  "${COMPOSE[@]}" exec -T auditor-api python -m policies.nca.seed_finding_mappings
  "${COMPOSE[@]}" exec -T auditor-api python -m policies.nca.seed_checklists
fi

# --- 7. Report ----------------------------------------------------------------
say "Container status"
"${COMPOSE[@]}" ps --format "table {{.Service}}\t{{.Status}}"

cat <<'EOF'

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

  Stop with: scripts/stop.sh
EOF
