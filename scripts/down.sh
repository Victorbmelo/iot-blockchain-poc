#!/usr/bin/env bash
# Stop all Audit Layer services.

set -euo pipefail

PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-$HOME/fabric-samples}"

if docker compose -f "$PROJECT_ROOT/docker-compose.yml" ps --quiet 2>/dev/null | grep -q .; then
    echo "Stopping Docker Compose services"
    docker compose -f "$PROJECT_ROOT/docker-compose.yml" down -v
fi

if [ -d "$FABRIC_SAMPLES_DIR/test-network" ]; then
    echo "Stopping Fabric test-network"
    cd "$FABRIC_SAMPLES_DIR/test-network"
    ./network.sh down 2>/dev/null || true
fi

pkill -f "uvicorn app.main:app" 2>/dev/null || true

echo "All services stopped"
