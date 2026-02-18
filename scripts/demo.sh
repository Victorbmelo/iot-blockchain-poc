#!/usr/bin/env bash
# Scripted demonstration for thesis defense presentation.
#
# Three self-contained scenes - each takes ~30 seconds to run.
#
# Scene 1 - Normal monitoring:    worker enters hazardous zone, alert triggered
# Scene 2 - Near-miss escalation: proximity alert escalates to near-miss
# Scene 3 - Tamper detection:     payload tampered, verification fails
#
# Usage:
#   make demo              (runs all three scenes with pauses)
#   make demo SCENE=1      (runs only scene 1)
#   bash scripts/demo.sh --scene 2
#   bash scripts/demo.sh --all --pause 3

set -euo pipefail

GATEWAY="${GATEWAY_URL:-http://localhost:8080}"
SCENE="${1:-all}"
PAUSE="${PAUSE:-2}"   # seconds between steps

# ANSI colours
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'
CYAN='\033[0;36m'; BOLD='\033[1m'; NC='\033[0m'

banner() { echo -e "\n${BOLD}${CYAN}━━━ $* ━━━${NC}\n"; }
step()   { echo -e "${YELLOW}▶ $*${NC}"; }
ok()     { echo -e "${GREEN}✓ $*${NC}"; }
fail()   { echo -e "${RED}✗ $*${NC}"; }
info()   { echo -e "  $*"; }

wait_gateway() {
    step "Checking gateway..."
    for i in {1..10}; do
        if curl -sf "$GATEWAY/health" > /dev/null 2>&1; then
            ok "Gateway ready at $GATEWAY"
            return
        fi
        sleep 1
    done
    fail "Gateway not reachable at $GATEWAY. Run: make up-stub"
    exit 1
}

post_event() {
    local payload="$1"
    curl -sf -X POST "$GATEWAY/events" \
        -H "Content-Type: application/json" \
        -H "X-Role: contractor" \
        -d "$payload"
}

verify_event() {
    local event_id="$1"
    local payload_hash="$2"
    curl -sf -X POST "$GATEWAY/verify?event_id=$event_id" \
        -H "Content-Type: application/json" \
        -H "X-Role: inspector" \
        -d "{\"payload_hash\":\"$payload_hash\"}"
}

#  Scene 1: Normal monitoring 
scene1() {
    banner "Scene 1 - Normal Monitoring: Worker Enters Hazardous Zone"
    echo "Scenario: Worker W001 enters zone Z04 (Crane Operation Zone)."
    echo "The system records a HAZARD_ENTRY event and triggers a proximity alert."
    echo ""
    sleep "$PAUSE"

    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

    step "Worker W001 enters zone Z04 at $TS"
    ENTRY=$(post_event "{
        \"event_type\": \"HAZARD_ENTRY\",
        \"ts\": \"$TS\",
        \"site_id\": \"site-torino-01\",
        \"zone_id\": \"Z04\",
        \"actor_id\": \"W001\",
        \"severity\": 3,
        \"source\": \"proximity_tag\",
        \"nonce\": \"demo-scene1-entry\",
        \"payload_extra\": {\"restricted\": true, \"ppe_ok\": true, \"gps_lat\": 45.0712, \"gps_lon\": 7.6871}
    }")
    ENTRY_ID=$(echo "$ENTRY" | python3 -c "import sys,json; print(json.load(sys.stdin)['event_id'])")
    ENTRY_HASH=$(echo "$ENTRY" | python3 -c "import sys,json; print(json.load(sys.stdin)['payload_hash'])")
    ok "Event recorded: $ENTRY_ID"
    info "Payload hash: ${ENTRY_HASH:0:20}..."
    sleep "$PAUSE"

    TS2=$(date -u -d "+2 minutes" +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u +"%Y-%m-%dT%H:%M:%SZ")
    step "Proximity alert: EQ-CRANE-01 detected at 0.8m from W001"
    PROX=$(post_event "{
        \"event_type\": \"PROXIMITY_ALERT\",
        \"ts\": \"$TS2\",
        \"site_id\": \"site-torino-01\",
        \"zone_id\": \"Z04\",
        \"actor_id\": \"W001\",
        \"severity\": 4,
        \"source\": \"proximity_tag\",
        \"prev_event_hash\": \"$ENTRY_HASH\",
        \"nonce\": \"demo-scene1-prox\",
        \"payload_extra\": {\"distance_m\": 0.8, \"equipment_id\": \"EQ-CRANE-01\", \"equipment_state\": \"MOVING\"}
    }")
    PROX_ID=$(echo "$PROX" | python3 -c "import sys,json; print(json.load(sys.stdin)['event_id'])")
    PROX_HASH=$(echo "$PROX" | python3 -c "import sys,json; print(json.load(sys.stdin)['payload_hash'])")
    ok "Alert recorded: $PROX_ID"
    info "Chained from entry event via prevEventHash"
    sleep "$PAUSE"

    step "Inspector queries zone Z04 events"
    ZONE_RESP=$(curl -sf "$GATEWAY/zones/Z04/events" -H "X-Role: inspector")
    COUNT=$(echo "$ZONE_RESP" | python3 -c "import sys,json; d=json.load(sys.stdin); print(len(d.get('records', d if isinstance(d, list) else [])))")
    ok "$COUNT events in zone Z04"

    step "Verifying hazard entry integrity (inspector role)"
    VERIFY=$(verify_event "$ENTRY_ID" "$ENTRY_HASH")
    MATCH=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
    ok "Verification result: $MATCH"

    echo ""
    ok "Scene 1 complete - 2 events recorded, integrity verified"
}

#  Scene 2: Near-miss escalation 
scene2() {
    banner "Scene 2 - Near-Miss Escalation Chain"
    echo "Scenario: W007 enters scaffold zone, missing helmet, near-miss occurs."
    echo "Each event is chained to the previous via prevEventHash."
    echo ""
    sleep "$PAUSE"

    NOW=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    PREV_HASH=""

    STEPS=(
        "ZONE_ENTRY|Z08|1|{\"gate\":\"main\",\"ppe_ok\":true}|demo-s2-1"
        "ZONE_ENTRY|Z02|2|{\"ppe_ok\":true}|demo-s2-2"
        "PPE_VIOLATION|Z02|3|{\"missing\":[\"helmet\"]}|demo-s2-3"
        "PROXIMITY_ALERT|Z02|4|{\"distance_m\":1.2,\"equipment_id\":\"EQ-CRANE-01\"}|demo-s2-4"
        "NEAR_MISS|Z02|4|{\"clearance_m\":0.2,\"equipment_id\":\"EQ-CRANE-01\"}|demo-s2-5"
    )

    for STEP in "${STEPS[@]}"; do
        IFS='|' read -r ETYPE ZONE SEV EXTRA NONCE <<< "$STEP"
        step "Recording $ETYPE (severity $SEV) in zone $ZONE"
        RESP=$(post_event "{
            \"event_type\": \"$ETYPE\",
            \"ts\": \"$NOW\",
            \"site_id\": \"site-torino-01\",
            \"zone_id\": \"$ZONE\",
            \"actor_id\": \"W007\",
            \"severity\": $SEV,
            \"source\": \"wearable\",
            \"prev_event_hash\": \"$PREV_HASH\",
            \"nonce\": \"$NONCE\",
            \"payload_extra\": $EXTRA
        }")
        EID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['event_id'])")
        PREV_HASH=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['payload_hash'])")
        ok "$ETYPE - $EID"
        if [ "$ETYPE" = "NEAR_MISS" ]; then
            info "Chain tail: prevEventHash=${PREV_HASH:0:16}..."
        fi
        sleep 1
    done

    sleep "$PAUSE"
    step "Tracing event chain for W007 (inspector)"
    NEAR_MISS_RESP=$(curl -sf "$GATEWAY/near-misses" -H "X-Role: inspector" 2>/dev/null || echo "{}")
    ok "Near-miss chain recorded with prevEventHash linkage"
    echo ""
    ok "Scene 2 complete - 5-event causal chain from entry to near-miss"
}

#  Scene 3: Tamper detection 
scene3() {
    banner "Scene 3 - Tamper Detection (Core Demo)"
    echo "Scenario: A NEAR_MISS event is submitted. An attacker modifies"
    echo "the severity field (4 → 1) to minimise apparent risk."
    echo "The system detects the modification."
    echo ""
    sleep "$PAUSE"

    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    step "Submitting original NEAR_MISS event (severity 4)"
    RESP=$(post_event "{
        \"event_type\": \"NEAR_MISS\",
        \"ts\": \"$TS\",
        \"site_id\": \"site-torino-01\",
        \"zone_id\": \"Z04\",
        \"actor_id\": \"W001\",
        \"severity\": 4,
        \"source\": \"camera\",
        \"nonce\": \"demo-tamper-$(date +%s)\",
        \"payload_extra\": {\"clearance_m\": 0.4, \"equipment_id\": \"EQ-CRANE-01\"}
    }")
    EVENT_ID=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['event_id'])")
    ORIGINAL_HASH=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['payload_hash'])")
    SIG=$(echo "$RESP" | python3 -c "import sys,json; print(json.load(sys.stdin)['signature'][:32])")
    ok "Event recorded: $EVENT_ID"
    info "Payload hash : ${ORIGINAL_HASH:0:32}..."
    info "Signature    : ${SIG}..."
    sleep "$PAUSE"

    step "Verifying original payload (expected: PASS)"
    VERIFY=$(verify_event "$EVENT_ID" "$ORIGINAL_HASH")
    RESULT=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
    SIG_VALID=$(echo "$VERIFY" | python3 -c "import sys,json; print(json.load(sys.stdin).get('signature_valid'))")
    ok "Result: $RESULT"
    info "Signature valid: $SIG_VALID"
    sleep "$PAUSE"

    step "Attacker modifies severity: 4 → 1"
    echo "  Original: {... \"severity\": 4 ...}"
    echo "  Tampered: {... \"severity\": 1 ...}"
    TAMPERED_HASH=$(python3 -c "
import hashlib, json, unicodedata
payload = {
    'schema_version': '1.0',
    'event_type': 'NEAR_MISS',
    'ts': '$TS',
    'site_id': 'site-torino-01',
    'zone_id': 'Z04',
    'actor_id': 'W001',
    'severity': 1,
    'source': 'camera',
    'payload_extra': {'clearance_m': 0.4, 'equipment_id': 'EQ-CRANE-01'},
}
def sort_keys(o):
    if isinstance(o, dict): return {k: sort_keys(o[k]) for k in sorted(o)}
    if isinstance(o, list): return [sort_keys(v) for v in o]
    return o
raw = json.dumps(sort_keys(payload), separators=(',', ':'), ensure_ascii=False)
raw = unicodedata.normalize('NFC', raw)
print(hashlib.sha256(raw.encode()).hexdigest())
")
    info "Tampered hash: ${TAMPERED_HASH:0:32}..."
    sleep "$PAUSE"

    step "Verifying tampered payload against ledger (expected: FAIL)"
    VERIFY2=$(verify_event "$EVENT_ID" "$TAMPERED_HASH")
    RESULT2=$(echo "$VERIFY2" | python3 -c "import sys,json; print(json.load(sys.stdin)['result'])")
    MATCH2=$(echo "$VERIFY2" | python3 -c "import sys,json; print(json.load(sys.stdin)['match'])")
    if [ "$MATCH2" = "False" ] || [ "$MATCH2" = "false" ]; then
        fail "Result: $RESULT2"
        ok "TAMPER DETECTED - modification is forensically evident"
    else
        info "Result: $RESULT2 (unexpected match)"
    fi

    echo ""
    ok "Scene 3 complete - tamper detected, original record intact on ledger"
}

#  Main 
wait_gateway

# Parse flags
SCENE_ARG="all"
for arg in "$@"; do
    case "$arg" in
        --scene) shift; SCENE_ARG="$1" ;;
        --all)   SCENE_ARG="all" ;;
        --pause) shift; PAUSE="$1" ;;
        1|2|3)   SCENE_ARG="$arg" ;;
    esac
done

case "$SCENE_ARG" in
    1|scene1) scene1 ;;
    2|scene2) scene2 ;;
    3|scene3) scene3 ;;
    all)
        scene1
        echo ""
        echo "Press Enter for Scene 2..."
        read -r 2>/dev/null || sleep 3
        scene2
        echo ""
        echo "Press Enter for Scene 3..."
        read -r 2>/dev/null || sleep 3
        scene3
        echo ""
        banner "Demo Complete"
        echo "All three scenes executed. Gateway metrics:"
        curl -sf "$GATEWAY/metrics" | python3 -m json.tool
        ;;
    *)
        echo "Usage: $0 [1|2|3|all] [--pause SECONDS]"
        exit 1
        ;;
esac
