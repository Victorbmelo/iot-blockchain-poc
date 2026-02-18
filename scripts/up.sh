#!/usr/bin/env bash
# Start the Audit Layer application stack.
#
# Modes:
#   --stub    Gateway with in-memory ledger (default - no Docker, no Fabric)
#   --docker  Gateway + MinIO via Docker Compose, in-memory stub
#   --fabric  Gateway + MinIO via Docker Compose, connected to real Fabric network
#
# For --fabric: start the Fabric network first:
#   make fabric-up
#   make fabric-deploy

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MODE="${1:---stub}"
NETWORK_DIR="$PROJECT_ROOT/fabric/network"

case "$MODE" in
    --stub)
        echo "Starting gateway in stub mode (in-memory ledger)"
        cd "$PROJECT_ROOT/gateway"
        FABRIC_STUB_MODE=true \
        RESULTS_DIR="$PROJECT_ROOT/results" \
        uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
        ;;

    --docker)
        echo "Starting application stack via Docker Compose (stub mode)"
        cd "$PROJECT_ROOT"
        FABRIC_STUB_MODE=true docker compose up --build -d
        echo "Gateway : http://localhost:8080"
        echo "API docs: http://localhost:8080/docs"
        echo "MinIO   : http://localhost:9001  (minioadmin / minioadmin)"
        ;;

    --fabric)
        # Verify Fabric network is running
        if ! docker ps --format '{{.Names}}' | grep -q "peer0.org1.audit.local"; then
            echo "Fabric network is not running."
            echo "Start it first: make fabric-up && make fabric-deploy"
            exit 1
        fi

        echo "Starting application stack connected to Fabric network"
        cd "$PROJECT_ROOT"

        # Export TLS cert path for gateway container volume mount
        ORG1_TLS_CA="$NETWORK_DIR/crypto-material/peerOrganizations/org1.audit.local/peers/peer0.org1.audit.local/tls/ca.crt"
        if [ ! -f "$ORG1_TLS_CA" ]; then
            echo "Fabric crypto material not found. Run: make fabric-up"
            exit 1
        fi

        FABRIC_STUB_MODE=false docker compose up --build -d
        echo "Gateway : http://localhost:8080 (connected to Fabric)"
        echo "API docs: http://localhost:8080/docs"
        echo "MinIO   : http://localhost:9001"
        echo "CouchDB0: http://localhost:5984/_utils"
        echo "CouchDB1: http://localhost:6984/_utils"
        ;;

    *)
        echo "Usage: $0 [--stub | --docker | --fabric]"
        exit 1
        ;;
esac
