#!/usr/bin/env python3
"""
IoT safety event simulator for the construction site audit layer.

Generates realistic safety events and submits them to the Audit Gateway API.

Usage:
    python generate_events.py                          # 500 events, default gateway
    python generate_events.py --count 1000
    python generate_events.py --dry-run --count 20
    python generate_events.py --scenario scenarios/incident_day.json
    python generate_events.py --tamper-demo
    python generate_events.py --export
"""

import argparse
import json
import random
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

GATEWAY_URL = "http://localhost:8080"
DEFAULT_COUNT = 500
SITE_ID = "site-torino-01"

ZONES = {
    "Z01": {"name": "Foundation Pit", "risk": "high"},
    "Z02": {"name": "Scaffolding Area", "risk": "high"},
    "Z03": {"name": "Material Storage", "risk": "medium"},
    "Z04": {"name": "Crane Operation Zone", "risk": "critical"},
    "Z05": {"name": "Workers Rest Area", "risk": "low"},
    "Z06": {"name": "Electrical Room", "risk": "high"},
    "Z07": {"name": "Concrete Pour Area", "risk": "medium"},
    "Z08": {"name": "Perimeter Gate", "risk": "low"},
}

WORKERS = [f"W{str(i).zfill(3)}" for i in range(1, 26)]
EQUIPMENT = ["EQ-CRANE-01", "EQ-EXCAVATOR-01", "EQ-FORKLIFT-02", "EQ-PUMP-01"]
ACTORS = WORKERS + EQUIPMENT

EVENT_TYPES = {
    "ZONE_ENTRY": {"weight": 35, "severity": {"low": 0.5, "medium": 0.4, "high": 0.1}},
    "ZONE_EXIT": {"weight": 30, "severity": {"low": 0.7, "medium": 0.3}},
    "PROXIMITY_ALERT": {"weight": 12, "severity": {"medium": 0.5, "high": 0.5}},
    "NEAR_MISS": {"weight": 5, "severity": {"high": 0.6, "critical": 0.4}},
    "PPE_VIOLATION": {"weight": 8, "severity": {"medium": 0.6, "high": 0.4}},
    "EQUIPMENT_FAULT": {"weight": 4, "severity": {"high": 0.7, "critical": 0.3}},
    "FALL_DETECTED": {"weight": 2, "severity": {"critical": 1.0}},
    "INTRUSION": {"weight": 2, "severity": {"high": 0.8, "critical": 0.2}},
    "GAS_ALERT": {"weight": 1, "severity": {"critical": 1.0}},
    "MANUAL_ALERT": {"weight": 1, "severity": {"medium": 0.4, "high": 0.6}},
}

SOURCES = ["wearable", "camera", "gateway", "simulator"]
SOURCE_WEIGHTS = [40, 30, 15, 15]


def weighted_pick(options: dict) -> str:
    keys = list(options.keys())
    weights = [v["weight"] if isinstance(v, dict) else v for v in options.values()]
    return random.choices(keys, weights=weights, k=1)[0]


def pick_severity(event_type: str) -> str:
    dist = EVENT_TYPES[event_type]["severity"]
    return random.choices(list(dist.keys()), weights=list(dist.values()), k=1)[0]


def build_event(base_ts: Optional[datetime] = None) -> dict:
    if base_ts is None:
        base_ts = datetime.now(timezone.utc)

    ts_event = (base_ts + timedelta(seconds=random.randint(0, 3600))).isoformat(timespec="seconds")
    event_type = weighted_pick(EVENT_TYPES)
    zone_id = random.choice(list(ZONES.keys()))

    return {
        "event_type": event_type,
        "ts_event": ts_event,
        "site_id": SITE_ID,
        "zone_id": zone_id,
        "actor_id": random.choice(ACTORS),
        "severity": pick_severity(event_type),
        "source": random.choices(SOURCES, weights=SOURCE_WEIGHTS, k=1)[0],
        "evidence_uri": "",
        "prev_event_hash": "",
        "payload_extra": {
            "gps_lat": round(45.0703 + random.uniform(-0.005, 0.005), 6),
            "gps_lon": round(7.6869 + random.uniform(-0.005, 0.005), 6),
            "sensor_value": round(random.uniform(0.1, 100.0), 2),
            "battery_pct": random.randint(10, 100),
            "zone_name": ZONES[zone_id]["name"],
        },
    }


def submit(gateway_url: str, event: dict, session: requests.Session) -> dict:
    response = session.post(f"{gateway_url}/events", json=event, timeout=10)
    response.raise_for_status()
    return response.json()


def print_result(event: dict, response: dict):
    print(
        f"  {response['event_id'][:22]} "
        f"type={event['event_type']:18s} "
        f"actor={event['actor_id']:8s} "
        f"zone={event['zone_id']} "
        f"severity={event['severity']:8s} "
        f"hash={response['payload_hash'][:12]}"
    )


def run_tamper_demo(gateway_url: str):
    """Submit one event, then show that a tampered payload fails verification."""
    print("\nTamper Detection Demo")
    print("Demonstrates that any modification to a recorded payload is detected.\n")

    session = requests.Session()

    event = build_event()
    event.update({"event_type": "NEAR_MISS", "actor_id": "W001", "zone_id": "Z04", "severity": "high"})

    print(f"[1] Submitting event: type={event['event_type']} actor={event['actor_id']} zone={event['zone_id']}")
    response = submit(gateway_url, event, session)
    event_id = response["event_id"]
    print(f"    event_id : {event_id}")
    print(f"    tx_id    : {response['tx_id']}")
    print(f"    hash     : {response['payload_hash']}")

    canonical_keys = ["event_type", "ts_event", "site_id", "zone_id", "actor_id", "severity", "source", "payload_extra"]
    canonical_payload = {k: event[k] for k in canonical_keys if event.get(k) is not None}
    original_json = json.dumps(canonical_payload, sort_keys=True, separators=(",", ":"))

    print(f"\n[2] Original payload (first 80 chars): {original_json[:80]}")

    print(f"\n[3] Verifying original payload (expected: PASS)")
    result = session.post(f"{gateway_url}/events/{event_id}/verify", json={"payload_json": original_json}).json()
    print(f"    Result: {result['result']}")

    tampered = dict(canonical_payload)
    tampered["severity"] = "low"
    tampered_json = json.dumps(tampered, sort_keys=True, separators=(",", ":"))

    print(f"\n[4] Tampering payload: changing severity 'high' -> 'low'")

    print(f"\n[5] Verifying tampered payload (expected: FAIL)")
    result2 = session.post(f"{gateway_url}/events/{event_id}/verify", json={"payload_json": tampered_json}).json()
    print(f"    Result      : {result2['result']}")
    print(f"    stored_hash : {result2['stored_hash'][:32]}")
    print(f"    computed    : {result2['computed_hash'][:32]}")

    print("\nDemo complete.")
    print("The ledger hash does not match the tampered payload — tampering detected.")


def load_scenario(path: str, gateway_url: str, session: requests.Session):
    with open(path) as f:
        scenario = json.load(f)

    print(f"Loading scenario: {scenario.get('name', path)}")
    print(f"Description: {scenario.get('description', '')}")
    events = scenario.get("events", [])
    print(f"Events to submit: {len(events)}\n")

    for i, event in enumerate(events, 1):
        try:
            response = submit(gateway_url, event, session)
            print_result(event, response)
        except Exception as exc:
            print(f"  Event {i} failed: {exc}")


def export_report(gateway_url: str, output_path: str = "results/audit_report.json"):
    response = requests.get(f"{gateway_url}/audit/report", timeout=30)
    response.raise_for_status()
    report = response.json()

    Path(output_path).parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        json.dump(report, f, indent=2, ensure_ascii=False)

    print(f"\nAudit report saved: {output_path}")
    print(f"Events: {report['event_count']}  Package hash: {report.get('package_hash', 'N/A')[:24]}")


def main():
    parser = argparse.ArgumentParser(description="IoT Safety Event Simulator")
    parser.add_argument("--count", type=int, default=DEFAULT_COUNT)
    parser.add_argument("--gateway", default=GATEWAY_URL)
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--tamper-demo", action="store_true")
    parser.add_argument("--scenario", help="Path to a scenario JSON file")
    parser.add_argument("--export", action="store_true", help="Export audit report after seeding")
    parser.add_argument("--delay", type=float, default=0.0, help="Delay in seconds between submissions")
    parser.add_argument("--start-date", default=None, help="Base date for events (ISO-8601)")
    args = parser.parse_args()

    print(f"Audit Layer Simulator  |  gateway={args.gateway}  |  site={SITE_ID}")

    if args.tamper_demo:
        run_tamper_demo(args.gateway)
        return

    session = requests.Session()

    if args.scenario:
        load_scenario(args.scenario, args.gateway, session)
        if args.export:
            export_report(args.gateway)
        return

    base_ts = (
        datetime.fromisoformat(args.start_date).replace(tzinfo=timezone.utc)
        if args.start_date
        else datetime.now(timezone.utc) - timedelta(days=7)
    )
    interval = timedelta(days=7) / max(args.count, 1)

    print(f"Generating {args.count} events from {base_ts.date()}\n")

    submitted = 0
    failed = 0

    for i in range(args.count):
        event = build_event(base_ts=base_ts + interval * i)

        if args.dry_run:
            print(json.dumps(event, indent=2))
            continue

        try:
            response = submit(args.gateway, event, session)
            print_result(event, response)
            submitted += 1
        except Exception as exc:
            print(f"  Event {i + 1} failed: {exc}")
            failed += 1

        if args.delay:
            time.sleep(args.delay)

    if not args.dry_run:
        print(f"\nSubmitted: {submitted}  Failed: {failed}")

    if args.export:
        export_report(args.gateway)


if __name__ == "__main__":
    main()
