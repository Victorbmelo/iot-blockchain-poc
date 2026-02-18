#!/usr/bin/env python3
"""
Standalone integrity verification tool.

Verifies one event by ID, or batch-verifies all events in an exported audit report.

Usage:
    python verify_integrity.py --event-id evt-abc123 --payload-file payload.json
    python verify_integrity.py --event-id evt-abc123 --payload-json '{"event_type":"NEAR_MISS",...}'
    python verify_integrity.py --report results/audit_report.json
"""

import argparse
import hashlib
import json
import sys

import requests


def compute_hash(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def verify_single(gateway_url: str, event_id: str, payload_json: str) -> dict:
    response = requests.post(
        f"{gateway_url}/events/{event_id}/verify",
        json={"payload_json": payload_json},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def batch_verify(gateway_url: str, report_path: str) -> bool:
    with open(report_path) as f:
        report = json.load(f)

    events = report.get("events", [])
    print(f"\nBatch Integrity Verification")
    print(f"Report : {report_path}")
    print(f"Events : {len(events)}")
    print(f"Generated: {report.get('generated_at', 'unknown')}\n")

    passed = 0
    failed = 0

    canonical_keys = ["event_type", "ts_event", "site_id", "zone_id",
                      "actor_id", "severity", "source", "payload_extra"]

    for event in events:
        canonical = {k: event[k] for k in canonical_keys if event.get(k) is not None}
        payload_json = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        event_id = event.get("event_id", "")

        try:
            result = verify_single(gateway_url, event_id, payload_json)
            if result["match"]:
                print(f"  PASS  {event_id[:28]:30s}  hash={result['stored_hash'][:14]}")
                passed += 1
            else:
                print(f"  FAIL  {event_id[:28]:30s}  {result['result'][:50]}")
                failed += 1
        except Exception as exc:
            print(f"  ERROR {event_id[:28]:30s}  {exc}")
            failed += 1

    print(f"\nPASS: {passed}  FAIL: {failed}  TOTAL: {len(events)}")

    if failed == 0:
        print("All events verified — audit chain intact.")
    else:
        print(f"{failed} event(s) failed integrity check — tampering suspected.")

    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="Audit Layer Integrity Verifier")
    parser.add_argument("--gateway", default="http://localhost:8080")
    parser.add_argument("--event-id", help="Single event ID to verify")
    parser.add_argument("--payload-file", help="Path to payload JSON file")
    parser.add_argument("--payload-json", help="Inline payload JSON string")
    parser.add_argument("--report", help="Audit report JSON for batch verification")
    args = parser.parse_args()

    if args.report:
        ok = batch_verify(args.gateway, args.report)
        sys.exit(0 if ok else 1)

    if not args.event_id:
        parser.error("--event-id is required for single-event verification")

    if args.payload_file:
        with open(args.payload_file) as f:
            payload_json = f.read().strip()
    elif args.payload_json:
        payload_json = args.payload_json
    else:
        parser.error("provide --payload-file or --payload-json")

    result = verify_single(args.gateway, args.event_id, payload_json)
    print(f"Event    : {result['event_id']}")
    print(f"Result   : {result['result']}")
    print(f"Stored   : {result['stored_hash']}")
    print(f"Computed : {result['computed_hash']}")
    print(f"Match    : {'PASS' if result['match'] else 'FAIL'}")
    sys.exit(0 if result["match"] else 1)


if __name__ == "__main__":
    main()
