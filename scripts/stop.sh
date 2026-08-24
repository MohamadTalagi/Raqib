#!/usr/bin/env bash
# Raqib / IoTGuard - stop the lab.
#
# Usage:
#   scripts/stop.sh            # stop and remove containers, KEEP all data
#   scripts/stop.sh --wipe     # also delete volumes (database, certs, MQTT
#                              # password) - a true from-scratch reset.
#                              # Destroys every device, evidence record and
#                              # verdict in the auditor database.
set -euo pipefail

export MSYS_NO_PATHCONV=1
export MSYS2_ARG_CONV_EXCL='*'

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT/lab"

COMPOSE=(docker compose -f docker-compose.yml -f docker-compose.dev.yml)

if ! docker info >/dev/null 2>&1; then
  echo "Docker daemon is not running - nothing to stop."
  exit 0
fi

case "${1:-}" in
  --wipe)
    echo "==> WARNING: this deletes the lab's Docker volumes."
    echo "    The auditor database (devices, evidence, verdicts) will be lost."
    read -r -p "    Type 'wipe' to confirm: " confirm
    if [[ "$confirm" != "wipe" ]]; then
      echo "Aborted - nothing was removed."
      exit 1
    fi
    echo "==> Stopping and removing containers + volumes"
    "${COMPOSE[@]}" down -v --remove-orphans
    echo "==> Done. Next scripts/start.sh will redo first-time setup and reseed."
    ;;
  ""|--keep)
    echo "==> Stopping and removing containers (data volumes are preserved)"
    "${COMPOSE[@]}" down --remove-orphans
    echo "==> Done. Restart with: scripts/start.sh"
    ;;
  -h|--help)
    sed -n '2,10p' "$0"
    ;;
  *)
    echo "Unknown option: $1" >&2
    exit 2
    ;;
esac
