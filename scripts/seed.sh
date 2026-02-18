#!/usr/bin/env bash
# Seed the ledger with all demonstration scenarios.

set -euo pipefail

GATEWAY="${GATEWAY_URL:-http://localhost:8080}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM="$PROJECT_ROOT/simulator/generate_events.py"

echo "Seeding audit ledger at $GATEWAY"

echo "Waiting for gateway..."
for i in {1..15}; do
    if curl -sf "$GATEWAY/health" > /dev/null 2>&1; then
        echo "Gateway ready"
        break
    fi
    sleep 2
done

echo ""
echo "[1/3] Accident scenario (causal chain for UC2 demo)"
python3 "$SIM" --scenario accident --gateway "$GATEWAY"

echo ""
echo "[2/3] Near-miss escalation scenario"
python3 "$SIM" --scenario near_miss --gateway "$GATEWAY"

echo ""
echo "[3/3] Normal operational events (200)"
python3 "$SIM" --scenario normal --count 200 --gateway "$GATEWAY"

echo ""
echo "Exporting audit report..."
mkdir -p "$PROJECT_ROOT/results"
curl -sf "$GATEWAY/audit/report?filter_type=zone_id&filter_value=Z04" \
    | python3 -m json.tool > "$PROJECT_ROOT/results/audit_report_Z04.json"
echo "Report saved to results/audit_report_Z04.json"

echo ""
echo "Seeding complete. Try:"
echo "  curl $GATEWAY/stats"
echo "  curl '$GATEWAY/zones/Z04/events'"
echo "  make sim-fraud"
echo "  make dashboard"
