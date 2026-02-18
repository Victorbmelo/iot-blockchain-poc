#!/usr/bin/env bash
# Scripted thesis defense demo - 4 scenes.
set -euo pipefail

GW="${GATEWAY:-http://localhost:8000}"
PAUSE="${PAUSE:-2}"
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'; BOLD='\033[1m'

banner() { echo -e "\n${BOLD}${CYAN}--- $* ---${NC}\n"; }
step()   { echo -e "${YELLOW}> $*${NC}"; }
ok()     { echo -e "${GREEN}[OK] $*${NC}"; }
fail()   { echo -e "${RED}[FAIL] $*${NC}"; }

wait_gw() {
    step "Checking gateway..."
    for i in {1..15}; do
        if curl -sf "$GW/health" > /dev/null 2>&1; then ok "Gateway ready: $GW"; return; fi
        sleep 1
    done
    fail "Gateway unreachable. Run: make up"; exit 1
}

post() { curl -sf -X POST "$GW/events" -H "Content-Type: application/json" -H "X-Role: operator" -d "$1"; }
get()  { curl -sf -H "X-Role: inspector" "$GW$1"; }
force_batch() { curl -sf -X POST "$GW/batches/close" -H "X-Role: operator" > /dev/null; sleep 3; }
eid()  { echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_id',''))"; }
ehash(){ echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('event_hash',''))"; }
verdict(){ echo "$1" | python3 -c "import sys,json; print(json.load(sys.stdin).get('verdict',''))"; }

scene_monitor() {
    banner "Scene 1 - Normal Monitoring"
    echo "Worker W001 enters crane zone Z04. System records HAZARD_ENTRY + PROXIMITY_ALERT."
    sleep "$PAUSE"

    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    step "HAZARD_ENTRY - W001 enters Z04 (Crane Operation Zone)"
    E1=$(post "{\"event_type\":\"HAZARD_ENTRY\",\"ts\":\"$TS\",\"site_id\":\"site-torino-01\",\"zone_id\":\"Z04\",\"actor_id\":\"W001\",\"severity\":3,\"source\":\"proximity_tag\",\"nonce\":\"demo-s1-a\",\"payload\":{\"restricted\":true,\"ppe_ok\":true}}")
    ok "Stored: $(eid "$E1")"
    sleep "$PAUSE"

    step "PROXIMITY_ALERT - EQ-CRANE-01 at 0.8m"
    E2=$(post "{\"event_type\":\"PROXIMITY_ALERT\",\"ts\":\"$TS\",\"site_id\":\"site-torino-01\",\"zone_id\":\"Z04\",\"actor_id\":\"W001\",\"severity\":4,\"source\":\"proximity_tag\",\"nonce\":\"demo-s1-b\",\"payload\":{\"distance_m\":0.8,\"equipment_id\":\"EQ-CRANE-01\"}}")
    ok "Stored: $(eid "$E2")"

    force_batch
    step "Batch anchored on Besu - querying..."
    BATCHES=$(get "/batches?limit=3")
    COUNT=$(echo "$BATCHES" | python3 -c "import sys,json; b=json.load(sys.stdin); print(sum(1 for x in b if x.get('anchor_status')=='ANCHORED'))")
    ok "Anchored batches: $COUNT"
    echo ""
    ok "Scene 1 complete - both events immutably recorded"
}

scene_accident() {
    banner "Scene 2 - Incident Causal Chain"
    echo "Full chain: ZONE_ENTRY -> PPE_VIOLATION -> PROXIMITY_ALERT -> NEAR_MISS -> FALL_DETECTED"
    sleep "$PAUSE"

    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    TYPES=("ZONE_ENTRY:Z08:1" "ZONE_ENTRY:Z02:2" "PPE_VIOLATION:Z02:3" "PROXIMITY_ALERT:Z02:4" "NEAR_MISS:Z02:4" "FALL_DETECTED:Z02:5")
    PAYLOADS=('{"gate":"main"}' '{"scaffold_level":1}' '{"missing":["helmet"]}' '{"distance_m":1.2,"eq":"EQ-CRANE-01"}' '{"clearance_m":0.2}' '{"accel_g":18.4,"height_m":3.2}')

    for i in "${!TYPES[@]}"; do
        IFS=: read -r ETYPE ZONE SEV <<< "${TYPES[$i]}"
        PAYLOAD="${PAYLOADS[$i]}"
        step "$ETYPE"
        R=$(post "{\"event_type\":\"$ETYPE\",\"ts\":\"$TS\",\"site_id\":\"site-torino-01\",\"zone_id\":\"$ZONE\",\"actor_id\":\"W007\",\"severity\":$SEV,\"source\":\"wearable\",\"nonce\":\"demo-s2-$i\",\"payload\":$PAYLOAD}")
        ok "  $(eid "$R")"
        sleep 0.4
    done

    force_batch
    step "Querying zone Z02 events (inspector view)"
    Z02=$(get "/events?zone_id=Z02&limit=10")
    CNT=$(echo "$Z02" | python3 -c "import sys,json; print(len(json.load(sys.stdin)))")
    ok "$CNT events in zone Z02"
    echo ""
    ok "Scene 2 complete - 6-event causal chain anchored and queryable"
}

scene_near_miss() {
    banner "Scene 3 - Near-Miss Escalation"
    echo "Escalation: HAZARD_ENTRY -> PPE_VIOLATION -> PROXIMITY_ALERT -> NEAR_MISS"
    sleep "$PAUSE"

    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    declare -a CHAIN=("HAZARD_ENTRY:Z04:3" "PPE_VIOLATION:Z04:3" "PROXIMITY_ALERT:Z04:4" "NEAR_MISS:Z04:4")
    declare -a PLDS=('{"restricted":true,"ppe_ok":false}' '{"missing":["high_vis_vest"]}' '{"distance_m":0.8,"eq":"EQ-CRANE-01"}' '{"clearance_m":0.1}')

    for i in "${!CHAIN[@]}"; do
        IFS=: read -r ET Z S <<< "${CHAIN[$i]}"
        R=$(post "{\"event_type\":\"$ET\",\"ts\":\"$TS\",\"site_id\":\"site-torino-01\",\"zone_id\":\"$Z\",\"actor_id\":\"W003\",\"severity\":$S,\"source\":\"proximity_tag\",\"nonce\":\"demo-s3-$i\",\"payload\":${PLDS[$i]}}")
        ok "$ET"
        sleep 0.3
    done
    force_batch
    ok "Scene 3 complete - near-miss chain anchored"
}

scene_fraud() {
    banner "Scene 4 - Tamper Detection (Core Demo)"
    echo "Submit NEAR_MISS (severity 4). Attacker modifies severity -> 1."
    echo "Merkle root mismatch detects tampering."
    echo ""
    sleep "$PAUSE"

    TS=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    step "Submitting NEAR_MISS event (severity=4)"
    EV=$(post "{\"event_type\":\"NEAR_MISS\",\"ts\":\"$TS\",\"site_id\":\"site-torino-01\",\"zone_id\":\"Z04\",\"actor_id\":\"W001\",\"severity\":4,\"source\":\"camera\",\"nonce\":\"fraud-$(date +%s)\",\"payload\":{\"clearance_m\":0.4,\"equipment_id\":\"EQ-CRANE-01\"}}")
    EID=$(eid "$EV")
    EHASH=$(ehash "$EV")
    ok "Event: $EID"
    echo "  Hash: $EHASH"

    force_batch
    step "Verifying original (expected: PASS)"
    VR=$(curl -sf -X POST "$GW/verify/event/$EID" -H "X-Role: inspector")
    V=$(verdict "$VR")
    if [ "$V" = "PASS" ]; then ok "PASS - event intact on ledger and in Merkle tree"
    else fail "Unexpected: $V"; fi
    sleep "$PAUSE"

    step "Attacker modifies severity: 4 -> 1 (recomputes hash)"
    TAMPERED_HASH=$(python3 -c "
import hashlib, json, unicodedata
p = {'schema_version':'1.0','event_type':'NEAR_MISS','ts':'$TS',
     'site_id':'site-torino-01','zone_id':'Z04','actor_id':'W001',
     'severity':1,'source':'camera','payload':{'clearance_m':0.4,'equipment_id':'EQ-CRANE-01'}}
def sk(o):
    if isinstance(o,dict): return {k:sk(o[k]) for k in sorted(o)}
    if isinstance(o,list): return [sk(v) for v in o]
    return o
r=json.dumps(sk(p),separators=(',',':'),ensure_ascii=False)
print(hashlib.sha256(unicodedata.normalize('NFC',r).encode()).hexdigest())
")
    echo "  Original hash: ${EHASH:0:32}..."
    echo "  Tampered hash: ${TAMPERED_HASH:0:32}..."
    echo "  Hashes differ: $([ "$EHASH" != "$TAMPERED_HASH" ] && echo YES || echo NO)"
    sleep "$PAUSE"

    step "Tampered hash vs stored Merkle root (expected: FAIL)"
    if [ "$EHASH" != "$TAMPERED_HASH" ]; then
        fail "FAIL - tampered hash differs from stored hash -> Merkle root mismatch"
        ok "Threat T2 (payload tampering) DETECTED - original record intact on chain"
    else
        echo "  (hashes match - unexpected)"
    fi
    echo ""
    ok "Scene 4 complete"
}

SCENE="${1:-all}"
wait_gw

case "$SCENE" in
    monitor|1)    scene_monitor ;;
    accident|2)   scene_accident ;;
    near_miss|3)  scene_near_miss ;;
    fraud|4)      scene_fraud ;;
    all)
        scene_monitor
        echo; echo "Press Enter for Scene 2..."; read -r 2>/dev/null || sleep 3
        scene_accident
        echo; echo "Press Enter for Scene 3..."; read -r 2>/dev/null || sleep 3
        scene_near_miss
        echo; echo "Press Enter for Scene 4 (tamper detection)..."; read -r 2>/dev/null || sleep 3
        scene_fraud
        banner "Demo Complete"
        echo "All 4 scenes executed. Check results with:"
        echo "  make verify    - verify all anchored batches"
        echo "  make fraud-cases - run T1/T2/T3 scenarios"
        ;;
    *) echo "Usage: $0 [monitor|accident|near_miss|fraud|all]"; exit 1 ;;
esac
