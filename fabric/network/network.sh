#!/usr/bin/env bash
# Fabric network lifecycle script for the Audit Layer prototype.
#
# Commands:
#   up       Generate crypto material, create channel, start all containers
#   deploy   Package, install, approve, and commit the auditcc chaincode
#   down     Stop containers, remove volumes and generated artifacts
#   reset    down + up (full clean restart)
#
# Prerequisites:
#   - Docker and Docker Compose v2
#   - Fabric binaries (peer, orderer, configtxgen, cryptogen) on PATH
#     Install: curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
#             Then: export PATH=$PATH:$HOME/fabric-samples/bin
#
# Usage:
#   bash fabric/network/network.sh up
#   bash fabric/network/network.sh deploy
#   bash fabric/network/network.sh down

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
NETWORK_DIR="$SCRIPT_DIR"
FABRIC_DIR="$(dirname "$SCRIPT_DIR")"
CONFIG_DIR="$FABRIC_DIR/config"
CHAINCODE_DIR="$FABRIC_DIR/chaincode/auditcc"

CHANNEL_NAME="audit-channel"
CHAINCODE_NAME="auditcc"
CHAINCODE_VERSION="1.0"
CHAINCODE_SEQUENCE=1

ORDERER_ADDRESS="localhost:7050"
ORDERER_TLS_CA="$NETWORK_DIR/crypto-material/ordererOrganizations/orderer.audit.local/orderers/orderer0.orderer.audit.local/tls/ca.crt"

ORG1_PEER="localhost:7051"
ORG1_TLS_CA="$NETWORK_DIR/crypto-material/peerOrganizations/org1.audit.local/peers/peer0.org1.audit.local/tls/ca.crt"
ORG1_MSP="$NETWORK_DIR/crypto-material/peerOrganizations/org1.audit.local/users/Admin@org1.audit.local/msp"

ORG2_PEER="localhost:9051"
ORG2_TLS_CA="$NETWORK_DIR/crypto-material/peerOrganizations/org2.audit.local/peers/peer0.org2.audit.local/tls/ca.crt"
ORG2_MSP="$NETWORK_DIR/crypto-material/peerOrganizations/org2.audit.local/users/Admin@org2.audit.local/msp"

check_prereqs() {
    for cmd in peer configtxgen cryptogen docker; do
        if ! command -v "$cmd" &> /dev/null; then
            echo "Missing required tool: $cmd"
            echo "Install Fabric binaries: curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7"
            exit 1
        fi
    done
}

generate_crypto() {
    echo "[1/4] Generating crypto material"
    mkdir -p "$NETWORK_DIR/crypto-material"
    cryptogen generate \
        --config="$CONFIG_DIR/crypto-config.yaml" \
        --output="$NETWORK_DIR/crypto-material"
}

generate_channel_artifacts() {
    echo "[2/4] Generating channel artifacts"
    mkdir -p "$NETWORK_DIR/channel-artifacts"

    export FABRIC_CFG_PATH="$CONFIG_DIR"

    configtxgen \
        -profile AuditGenesis \
        -channelID system-channel \
        -outputBlock "$NETWORK_DIR/channel-artifacts/genesis.block"

    configtxgen \
        -profile AuditChannel \
        -outputCreateChannelTx "$NETWORK_DIR/channel-artifacts/${CHANNEL_NAME}.tx" \
        -channelID "$CHANNEL_NAME"

    configtxgen \
        -profile AuditChannel \
        -outputAnchorPeersUpdate "$NETWORK_DIR/channel-artifacts/Org1MSPanchors.tx" \
        -channelID "$CHANNEL_NAME" \
        -asOrg AuditGatewayMSP

    configtxgen \
        -profile AuditChannel \
        -outputAnchorPeersUpdate "$NETWORK_DIR/channel-artifacts/Org2MSPanchors.tx" \
        -channelID "$CHANNEL_NAME" \
        -asOrg InspectorMSP
}

start_containers() {
    echo "[3/4] Starting Docker containers"
    cd "$NETWORK_DIR"
    docker compose -f docker-compose-fabric.yml up -d
    echo "Waiting for peers to be ready..."
    sleep 10
}

create_channel() {
    echo "[4/4] Creating channel and joining peers"
    export FABRIC_CFG_PATH="$CONFIG_DIR"

    peer channel create \
        -o "$ORDERER_ADDRESS" \
        -c "$CHANNEL_NAME" \
        -f "$NETWORK_DIR/channel-artifacts/${CHANNEL_NAME}.tx" \
        --tls \
        --cafile "$ORDERER_TLS_CA" \
        --outputBlock "$NETWORK_DIR/channel-artifacts/${CHANNEL_NAME}.block"

    # Join Org1 peer
    CORE_PEER_LOCALMSPID=AuditGatewayMSP \
    CORE_PEER_ADDRESS=$ORG1_PEER \
    CORE_PEER_MSPCONFIGPATH=$ORG1_MSP \
    CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_TLS_CA \
    peer channel join \
        -b "$NETWORK_DIR/channel-artifacts/${CHANNEL_NAME}.block"

    # Join Org2 peer
    CORE_PEER_LOCALMSPID=InspectorMSP \
    CORE_PEER_ADDRESS=$ORG2_PEER \
    CORE_PEER_MSPCONFIGPATH=$ORG2_MSP \
    CORE_PEER_TLS_ROOTCERT_FILE=$ORG2_TLS_CA \
    peer channel join \
        -b "$NETWORK_DIR/channel-artifacts/${CHANNEL_NAME}.block"

    echo "Channel $CHANNEL_NAME created. Both peers joined."
}

deploy_chaincode() {
    export FABRIC_CFG_PATH="$CONFIG_DIR"

    echo "[1/5] Packaging chaincode"
    peer lifecycle chaincode package auditcc.tar.gz \
        --path "$CHAINCODE_DIR" \
        --lang golang \
        --label "${CHAINCODE_NAME}_${CHAINCODE_VERSION}"

    echo "[2/5] Installing on Org1 peer"
    CORE_PEER_LOCALMSPID=AuditGatewayMSP \
    CORE_PEER_ADDRESS=$ORG1_PEER \
    CORE_PEER_MSPCONFIGPATH=$ORG1_MSP \
    CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_TLS_CA \
    peer lifecycle chaincode install auditcc.tar.gz

    echo "[3/5] Installing on Org2 peer"
    CORE_PEER_LOCALMSPID=InspectorMSP \
    CORE_PEER_ADDRESS=$ORG2_PEER \
    CORE_PEER_MSPCONFIGPATH=$ORG2_MSP \
    CORE_PEER_TLS_ROOTCERT_FILE=$ORG2_TLS_CA \
    peer lifecycle chaincode install auditcc.tar.gz

    # Get package ID from install output
    PACKAGE_ID=$(CORE_PEER_LOCALMSPID=AuditGatewayMSP \
        CORE_PEER_ADDRESS=$ORG1_PEER \
        CORE_PEER_MSPCONFIGPATH=$ORG1_MSP \
        CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_TLS_CA \
        peer lifecycle chaincode queryinstalled 2>&1 | grep "${CHAINCODE_NAME}_${CHAINCODE_VERSION}" | awk '{print $3}' | tr -d ',')

    echo "[4/5] Approving chaincode definition (both orgs)"
    for MSP_ID in AuditGatewayMSP InspectorMSP; do
        if [ "$MSP_ID" = "AuditGatewayMSP" ]; then
            PEER_ADDR=$ORG1_PEER; MSP_PATH=$ORG1_MSP; TLS_CA=$ORG1_TLS_CA
        else
            PEER_ADDR=$ORG2_PEER; MSP_PATH=$ORG2_MSP; TLS_CA=$ORG2_TLS_CA
        fi

        CORE_PEER_LOCALMSPID=$MSP_ID \
        CORE_PEER_ADDRESS=$PEER_ADDR \
        CORE_PEER_MSPCONFIGPATH=$MSP_PATH \
        CORE_PEER_TLS_ROOTCERT_FILE=$TLS_CA \
        peer lifecycle chaincode approveformyorg \
            -o "$ORDERER_ADDRESS" \
            --channelID "$CHANNEL_NAME" \
            --name "$CHAINCODE_NAME" \
            --version "$CHAINCODE_VERSION" \
            --package-id "$PACKAGE_ID" \
            --sequence "$CHAINCODE_SEQUENCE" \
            --tls \
            --cafile "$ORDERER_TLS_CA"
    done

    echo "[5/5] Committing chaincode definition"
    CORE_PEER_LOCALMSPID=AuditGatewayMSP \
    CORE_PEER_ADDRESS=$ORG1_PEER \
    CORE_PEER_MSPCONFIGPATH=$ORG1_MSP \
    CORE_PEER_TLS_ROOTCERT_FILE=$ORG1_TLS_CA \
    peer lifecycle chaincode commit \
        -o "$ORDERER_ADDRESS" \
        --channelID "$CHANNEL_NAME" \
        --name "$CHAINCODE_NAME" \
        --version "$CHAINCODE_VERSION" \
        --sequence "$CHAINCODE_SEQUENCE" \
        --tls \
        --cafile "$ORDERER_TLS_CA" \
        --peerAddresses "$ORG1_PEER" \
        --tlsRootCertFiles "$ORG1_TLS_CA" \
        --peerAddresses "$ORG2_PEER" \
        --tlsRootCertFiles "$ORG2_TLS_CA"

    echo "Chaincode $CHAINCODE_NAME committed to channel $CHANNEL_NAME"
    rm -f auditcc.tar.gz
}

network_up() {
    check_prereqs
    generate_crypto
    generate_channel_artifacts
    start_containers
    create_channel
    echo ""
    echo "Fabric network is up."
    echo "  Channel  : $CHANNEL_NAME"
    echo "  Org1 peer: $ORG1_PEER (AuditGatewayMSP)"
    echo "  Org2 peer: $ORG2_PEER (InspectorMSP)"
    echo "  CouchDB0 : http://localhost:5984/_utils"
    echo "  CouchDB1 : http://localhost:6984/_utils"
    echo ""
    echo "Next: bash fabric/network/network.sh deploy"
}

network_down() {
    cd "$NETWORK_DIR"
    docker compose -f docker-compose-fabric.yml down -v 2>/dev/null || true
    rm -rf crypto-material channel-artifacts
    echo "Network stopped and cleaned."
}

case "${1:-}" in
    up)     network_up ;;
    deploy) deploy_chaincode ;;
    down)   network_down ;;
    reset)  network_down; network_up ;;
    *)
        echo "Usage: $0 {up|deploy|down|reset}"
        exit 1
        ;;
esac
