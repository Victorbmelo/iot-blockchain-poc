#!/usr/bin/env bash
# Seed the ledger with demo data for presentation purposes.

set -euo pipefail

GATEWAY="${GATEWAY_URL:-http://localhost:8080}"
PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIM="$PROJECT_ROOT/simulator/generate_events.py"

echo "Seeding audit ledger at $GATEWAY"

echo "Waiting for gateway to be ready..."
for i in {1..15}; do
    if curl -sf "$GATEWAY/health" > /dev/null 2>&1; then
        echo "Gateway is up"
        break
    fi
    sleep 2
done

echo ""
echo "[1/3] Loading incident day scenario"
python3 "$SIM" --scenario "$PROJECT_ROOT/simulator/scenarios/incident_day.json" --gateway "$GATEWAY"

echo ""
echo "[2/3] Generating 500 random operational events"
python3 "$SIM" --count 500 --gateway "$GATEWAY"

echo ""
echo "[3/3] Exporting audit report"
mkdir -p "$PROJECT_ROOT/results"
curl -sf "$GATEWAY/audit/report" | python3 -m json.tool > "$PROJECT_ROOT/results/audit_report.json"
echo "Report saved to results/audit_report.json"

echo ""
echo "Seeding complete."
echo "Try:"
echo "  curl $GATEWAY/stats"
echo "  curl '$GATEWAY/events?zone_id=Z04'"
echo "  python3 scripts/verify_integrity.py --report results/audit_report.json"
