#!/usr/bin/env python3
"""
Standalone integrity verification tool.

Verifies one event by ID and payload hash, or batch-verifies all events
in an exported audit report.

Usage:
    python verify_integrity.py --event-id evt-abc --payload-hash <sha256hex>
    python verify_integrity.py --report results/audit_report.json
"""
import argparse
import hashlib
import json
import sys

import requests


def verify_single(gateway_url: str, event_id: str, payload_hash: str) -> dict:
    response = requests.post(
        f"{gateway_url}/verify",
        params={"event_id": event_id},
        json={"payload_hash": payload_hash},
        timeout=10,
    )
    response.raise_for_status()
    return response.json()


def batch_verify(gateway_url: str, report_path: str) -> bool:
    with open(report_path) as f:
        report = json.load(f)

    events = report.get("events", [])
    print(f"Batch Integrity Verification")
    print(f"Report    : {report_path}")
    print(f"Events    : {len(events)}")
    print(f"Generated : {report.get('generatedAt', 'unknown')}\n")

    canonical_keys = [
        "schema_version", "event_type", "ts", "site_id",
        "zone_id", "actor_id", "severity", "source", "payload_extra",
    ]
    # Map from camelCase (on-chain) to snake_case (canonical payload)
    field_map = {
        "schemaVersion": "schema_version",
        "eventType": "event_type",
        "actorId": "actor_id",
        "siteId": "site_id",
        "zoneId": "zone_id",
        "payloadExtra": "payload_extra",
    }

    passed, failed = 0, 0
    for event in events:
        # Normalise field names from on-chain camelCase to canonical snake_case
        normalised = {}
        for k, v in event.items():
            snake = field_map.get(k, k)
            normalised[snake] = v

        canonical = {k: normalised[k] for k in canonical_keys if normalised.get(k) is not None}
        payload_hash = hashlib.sha256(
            json.dumps(dict(sorted(canonical.items())), separators=(",", ":"), ensure_ascii=False).encode()
        ).hexdigest()

        event_id = event.get("eventId", "")
        try:
            result = verify_single(gateway_url, event_id, payload_hash)
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
        print("All events verified - audit chain intact.")
    else:
        print(f"{failed} event(s) failed - tampering suspected.")
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="Audit Layer Integrity Verifier")
    parser.add_argument("--gateway", default="http://localhost:8080")
    parser.add_argument("--event-id")
    parser.add_argument("--payload-hash", help="SHA-256 hex of the canonical payload")
    parser.add_argument("--report", help="Audit report JSON for batch verification")
    args = parser.parse_args()

    if args.report:
        ok = batch_verify(args.gateway, args.report)
        sys.exit(0 if ok else 1)

    if not args.event_id or not args.payload_hash:
        parser.error("provide --event-id and --payload-hash, or --report for batch mode")

    result = verify_single(args.gateway, args.event_id, args.payload_hash)
    print(f"Event         : {result['event_id']}")
    print(f"Result        : {result['result']}")
    print(f"Stored hash   : {result['stored_hash']}")
    print(f"Submitted hash: {result['submitted_hash']}")
    print(f"Sig valid     : {result.get('signature_valid')}")
    print(f"Match         : {'PASS' if result['match'] else 'FAIL'}")
    sys.exit(0 if result["match"] else 1)


if __name__ == "__main__":
    main()
