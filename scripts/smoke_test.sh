#!/usr/bin/env bash
# Clean-deployment smoke test (Week 1 brief, task 10).
#
# Brings the full lab stack up and asserts every service that exposes a
# health check actually reports healthy, then hits each HTTP-reachable
# service's own health/root endpoint from the host. Fails (non-zero exit)
# the moment anything doesn't come up clean.
#
# Usage:
#   scripts/smoke_test.sh          # up the existing stack (safe, no data loss)
#   scripts/smoke_test.sh --fresh  # ALSO removes containers/volumes first -
#                                  # a true from-nothing deployment, but this
#                                  # destroys the auditor database's data.
#                                  # Never run --fresh against a stack you
#                                  # care about the data in.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE_DIR="$REPO_ROOT/lab"
COMPOSE="docker compose -f docker-compose.yml -f docker-compose.dev.yml"

cd "$COMPOSE_DIR"

if [[ "${1:-}" == "--fresh" ]]; then
  echo "==> --fresh: tearing down containers AND volumes first (data will be lost)"
  $COMPOSE down -v
fi

echo "==> Bringing the stack up"
$COMPOSE up -d --build

HEALTHCHECKED_SERVICES=(
  auditor-database auditor-api device-insecure device-partial device-hardened
  mqtt-broker-insecure mqtt-broker-secure telnet-sim
)

echo "==> Waiting for health checks (up to 90s)"
deadline=$((SECONDS + 90))
while true; do
  all_healthy=true
  for service in "${HEALTHCHECKED_SERVICES[@]}"; do
    container="kaust-iot-lab-${service}-1"
    status="$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")"
    if [[ "$status" != "healthy" ]]; then
      all_healthy=false
    fi
  done
  if $all_healthy; then
    break
  fi
  if [[ $SECONDS -ge $deadline ]]; then
    echo "FAILED: not every service became healthy within 90s"
    for service in "${HEALTHCHECKED_SERVICES[@]}"; do
      container="kaust-iot-lab-${service}-1"
      status="$(docker inspect --format '{{.State.Health.Status}}' "$container" 2>/dev/null || echo "missing")"
      echo "  $service: $status"
    done
    exit 1
  fi
  sleep 3
done
echo "    all health-checked services report healthy"

echo "==> Checking auditor-api HTTP health"
curl -sf http://localhost:8000/health | grep -q '"status":"ok"'
echo "    auditor-api: ok"

echo "==> Checking auditor-web serves the dashboard"
curl -sf http://localhost:8080/ | grep -qi "<title>"
echo "    auditor-web: ok"

echo "==> Checking device-insecure's HTTP endpoint"
curl -sf http://localhost:8081/health >/dev/null
echo "    device-insecure: ok"

echo "==> Smoke test passed."
