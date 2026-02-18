#!/usr/bin/env bash
# Start the Audit Layer stack.
#
# Modes:
#   --stub    Start only the gateway with an in-memory ledger (default, no Docker required)
#   --docker  Start the gateway and MinIO via Docker Compose
#   --fabric  Start the Hyperledger Fabric test-network, deploy chaincode, and start the gateway
#
# Prerequisites for --fabric:
#   fabric-samples installed at $FABRIC_SAMPLES_DIR (default: ~/fabric-samples)
#   Run: curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
MODE="${1:---stub}"
FABRIC_SAMPLES_DIR="${FABRIC_SAMPLES_DIR:-$HOME/fabric-samples}"
CHANNEL="mychannel"
CHAINCODE_NAME="auditcc"

case "$MODE" in
    --stub)
        echo "Starting gateway in stub mode (in-memory ledger)"
        cd "$PROJECT_ROOT/gateway"
        FABRIC_STUB_MODE=true uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
        ;;

    --docker)
        echo "Starting via Docker Compose"
        cd "$PROJECT_ROOT"
        docker compose up --build -d
        echo "Gateway : http://localhost:8080"
        echo "Docs    : http://localhost:8080/docs"
        echo "MinIO   : http://localhost:9001  (minioadmin / minioadmin)"
        ;;

    --fabric)
        if [ ! -d "$FABRIC_SAMPLES_DIR" ]; then
            echo "fabric-samples not found at $FABRIC_SAMPLES_DIR"
            echo "Install with: curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7"
            exit 1
        fi

        NETWORK_DIR="$FABRIC_SAMPLES_DIR/test-network"
        CHAINCODE_SRC="$PROJECT_ROOT/fabric/chaincode/auditcc"

        echo "[1/4] Stopping previous network"
        cd "$NETWORK_DIR"
        ./network.sh down 2>/dev/null || true

        echo "[2/4] Starting network with CouchDB"
        ./network.sh up createChannel -ca -c "$CHANNEL" -s couchdb

        echo "[3/4] Deploying chaincode"
        ./network.sh deployCC \
            -ccn "$CHAINCODE_NAME" \
            -ccp "$CHAINCODE_SRC" \
            -ccl go \
            -ccv 1.0 \
            -ccs 1 \
            -c "$CHANNEL"

        echo "[4/4] Starting gateway"
        cd "$PROJECT_ROOT/gateway"

        export FABRIC_PEER_ENDPOINT="localhost:7051"
        export FABRIC_CHANNEL="$CHANNEL"
        export FABRIC_CHAINCODE="$CHAINCODE_NAME"
        export FABRIC_PEER_TLS_CERT="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/peers/peer0.org1.example.com/tls/ca.crt"
        export FABRIC_GATEWAY_CERT="$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/signcerts/cert.pem"
        export FABRIC_GATEWAY_KEY
        FABRIC_GATEWAY_KEY="$(ls "$NETWORK_DIR/organizations/peerOrganizations/org1.example.com/users/Admin@org1.example.com/msp/keystore/"*_sk 2>/dev/null | head -1)"
        export FABRIC_STUB_MODE=false

        uvicorn app.main:app --host 0.0.0.0 --port 8080 --reload
        ;;

    *)
        echo "Usage: $0 [--stub | --docker | --fabric]"
        exit 1
        ;;
esac
