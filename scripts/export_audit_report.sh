#!/usr/bin/env bash
# Export a filtered audit report to a JSON file in results/.
#
# Usage:
#   ./scripts/export_audit_report.sh              # all events
#   ./scripts/export_audit_report.sh --zone Z04
#   ./scripts/export_audit_report.sh --actor W001
#   ./scripts/export_audit_report.sh --type NEAR_MISS
#   ./scripts/export_audit_report.sh --severity critical
#   ./scripts/export_audit_report.sh --start 2024-11-15T00:00:00Z --end 2024-11-15T23:59:59Z

set -euo pipefail

GATEWAY="${GATEWAY_URL:-http://localhost:8080}"
OUTPUT_DIR="results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
QUERY_PARAMS=""
LABEL="all"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --zone)     QUERY_PARAMS="zone_id=$2";     LABEL="zone_$2";    shift 2 ;;
        --actor)    QUERY_PARAMS="actor_id=$2";    LABEL="actor_$2";   shift 2 ;;
        --type)     QUERY_PARAMS="event_type=$2";  LABEL="type_$2";    shift 2 ;;
        --severity) QUERY_PARAMS="severity=$2";    LABEL="sev_$2";     shift 2 ;;
        --start)    START="$2"; shift 2 ;;
        --end)      END="$2";   shift 2 ;;
        *) echo "Unknown argument: $1"; exit 1 ;;
    esac
done

if [[ -n "${START:-}" && -n "${END:-}" ]]; then
    QUERY_PARAMS="start_ts=${START}&end_ts=${END}"
    LABEL="timerange"
fi

URL="$GATEWAY/audit/report${QUERY_PARAMS:+?$QUERY_PARAMS}"
OUTPUT="$OUTPUT_DIR/audit_report_${LABEL}_${TIMESTAMP}.json"

mkdir -p "$OUTPUT_DIR"
echo "Fetching: $URL"
curl -sf "$URL" | python3 -m json.tool > "$OUTPUT"

EVENT_COUNT=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(d.get('event_count', 0))")
PKG_HASH=$(python3 -c "import json; d=json.load(open('$OUTPUT')); print(d.get('package_hash','N/A')[:24])")

echo "File        : $OUTPUT"
echo "Events      : $EVENT_COUNT"
echo "Package hash: $PKG_HASH"
echo ""
echo "To verify integrity:"
echo "  python3 scripts/verify_integrity.py --report $OUTPUT --gateway $GATEWAY"
