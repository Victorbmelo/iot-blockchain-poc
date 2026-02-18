#!/usr/bin/env python3
"""
IoT safety event simulator for the construction site audit layer.

Generates realistic safety events across five scenarios and submits them
to the Audit Gateway API. Includes built-in metrics export.

Scenarios:
  normal         -- Routine monitoring: entries, exits, minor alerts
  near_miss      -- Escalating hazard events with proximity alerts
  accident       -- Full incident chain: PPE violation -> near-miss -> fall
  fraud          -- Tampers a submitted payload to demonstrate detection
  replay         -- Submits the same event twice to demonstrate idempotency

Usage:
    python generate_events.py --scenario normal --count 200
    python generate_events.py --scenario accident
    python generate_events.py --scenario fraud
    python generate_events.py --scenario replay
    python generate_events.py --rate 10 --duration 60
"""
import argparse
import hashlib
import json
import random
import secrets
import sys
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

GATEWAY_URL = "http://localhost:8080"
SCHEMA_VERSION = "1.0"
SITE_ID = "site-torino-01"

ZONES = {
    "Z01": "Foundation Pit",
    "Z02": "Scaffolding Area",
    "Z03": "Material Storage",
    "Z04": "Crane Operation Zone",
    "Z05": "Workers Rest Area",
    "Z06": "Electrical Room",
    "Z07": "Concrete Pour Area",
    "Z08": "Perimeter Gate",
}

WORKERS = [f"W{str(i).zfill(3)}" for i in range(1, 26)]
EQUIPMENT = ["EQ-CRANE-01", "EQ-EXCAVATOR-01", "EQ-FORKLIFT-02"]
ACTORS = WORKERS + EQUIPMENT

EVENT_WEIGHTS = {
    "ZONE_ENTRY": 30,
    "ZONE_EXIT": 25,
    "PROXIMITY_ALERT": 12,
    "NEAR_MISS": 5,
    "PPE_VIOLATION": 10,
    "EQUIPMENT_FAULT": 4,
    "FALL_DETECTED": 2,
    "INTRUSION": 2,
    "GAS_ALERT": 1,
    "HAZARD_ENTRY": 9,
}

SEVERITY_BY_TYPE = {
    "ZONE_ENTRY": [1, 2],
    "ZONE_EXIT": [0, 1],
    "PROXIMITY_ALERT": [3, 4],
    "NEAR_MISS": [4, 5],
    "PPE_VIOLATION": [2, 3],
    "EQUIPMENT_FAULT": [3, 4],
    "FALL_DETECTED": [5],
    "INTRUSION": [3, 4],
    "GAS_ALERT": [5],
    "HAZARD_ENTRY": [2, 3],
    "MANUAL_ALERT": [3, 4],
}

SOURCES = ["wearable", "camera", "proximity_tag", "gateway"]
SOURCE_WEIGHTS = [40, 30, 20, 10]


def pick_event_type() -> str:
    types = list(EVENT_WEIGHTS.keys())
    weights = list(EVENT_WEIGHTS.values())
    return random.choices(types, weights=weights, k=1)[0]


def pick_severity(event_type: str) -> int:
    options = SEVERITY_BY_TYPE.get(event_type, [2, 3])
    return random.choice(options)


def build_event(
    event_type: Optional[str] = None,
    actor_id: Optional[str] = None,
    zone_id: Optional[str] = None,
    severity: Optional[int] = None,
    base_ts: Optional[datetime] = None,
    payload_extra: Optional[dict] = None,
) -> dict:
    ts = (base_ts or datetime.now(timezone.utc)).isoformat(timespec="seconds")
    event_type = event_type or pick_event_type()
    zone_id = zone_id or random.choice(list(ZONES.keys()))

    return {
        "event_type": event_type,
        "ts": ts,
        "site_id": SITE_ID,
        "zone_id": zone_id,
        "actor_id": actor_id or random.choice(ACTORS),
        "severity": severity if severity is not None else pick_severity(event_type),
        "source": random.choices(SOURCES, weights=SOURCE_WEIGHTS, k=1)[0],
        "evidence_ref": "",
        "prev_event_hash": "",
        "nonce": secrets.token_hex(8),
        "payload_extra": payload_extra or {
            "gps_lat": round(45.0703 + random.uniform(-0.005, 0.005), 6),
            "gps_lon": round(7.6869 + random.uniform(-0.005, 0.005), 6),
            "sensor_value": round(random.uniform(0.1, 100.0), 2),
            "battery_pct": random.randint(15, 100),
        },
    }


def submit(session: requests.Session, gateway: str, event: dict) -> dict:
    resp = session.post(f"{gateway}/events", json=event, timeout=10)
    resp.raise_for_status()
    return resp.json()


def print_result(event: dict, response: dict):
    print(
        f"  {response['event_id'][:22]}"
        f"  type={event['event_type']:18s}"
        f"  actor={event['actor_id']:8s}"
        f"  zone={event['zone_id']}"
        f"  sev={event['severity']}"
        f"  hash={response['payload_hash'][:10]}"
    )


# --- Scenarios ---

def run_normal(gateway: str, count: int, base_ts: Optional[datetime] = None):
    """Routine monitoring: random events spread over a time window."""
    print(f"Scenario: normal  count={count}")
    session = requests.Session()
    base = base_ts or datetime.now(timezone.utc) - timedelta(days=7)
    interval = timedelta(days=7) / max(count, 1)
    ok, fail = 0, 0
    for i in range(count):
        ev = build_event(base_ts=base + interval * i)
        try:
            resp = submit(session, gateway, ev)
            print_result(ev, resp)
            ok += 1
        except Exception as exc:
            print(f"  FAIL event {i+1}: {exc}")
            fail += 1
    print(f"\nSubmitted: {ok}  Failed: {fail}")


def run_near_miss(gateway: str):
    """Escalating hazard chain: entry -> proximity -> near-miss."""
    print("Scenario: near_miss")
    session = requests.Session()
    now = datetime.now(timezone.utc)
    actor, zone = "W001", "Z04"

    sequence = [
        ("ZONE_ENTRY", 1, {"ppe_ok": True}),
        ("HAZARD_ENTRY", 3, {"restricted_zone": True}),
        ("PROXIMITY_ALERT", 4, {"distance_m": 1.8, "equipment": "EQ-CRANE-01"}),
        ("NEAR_MISS", 4, {"clearance_m": 0.4, "equipment": "EQ-CRANE-01"}),
    ]

    prev_hash = ""
    for i, (etype, sev, extra) in enumerate(sequence):
        ts = (now + timedelta(minutes=i * 5)).isoformat(timespec="seconds")
        ev = build_event(event_type=etype, actor_id=actor, zone_id=zone,
                         severity=sev, base_ts=now + timedelta(minutes=i * 5),
                         payload_extra=extra)
        ev["prev_event_hash"] = prev_hash
        ev["ts"] = ts
        try:
            resp = submit(session, gateway, ev)
            print_result(ev, resp)
            prev_hash = resp["payload_hash"]
        except Exception as exc:
            print(f"  FAIL: {exc}")


def run_accident(gateway: str):
    """Full incident chain: normal ops -> PPE violation -> near-miss -> fall."""
    print("Scenario: accident")
    session = requests.Session()
    now = datetime.now(timezone.utc)
    actor, zone = "W007", "Z02"

    sequence = [
        ("ZONE_ENTRY", "Z08", 1, {"gate": "main"}),
        ("ZONE_ENTRY", zone, 2, {"ppe_ok": True}),
        ("PPE_VIOLATION", zone, 3, {"missing": ["helmet"]}),
        ("PROXIMITY_ALERT", zone, 4, {"distance_m": 1.2}),
        ("NEAR_MISS", zone, 4, {"clearance_m": 0.2}),
        ("FALL_DETECTED", zone, 5, {"accel_g": 18.4, "height_m": 3.2, "impact": True}),
        ("MANUAL_ALERT", zone, 5, {"text": "Worker fell from scaffolding level 2"}),
    ]

    prev_hash = ""
    for i, (etype, zid, sev, extra) in enumerate(sequence):
        ts = (now + timedelta(minutes=i * 3)).isoformat(timespec="seconds")
        ev = build_event(event_type=etype, actor_id=actor, zone_id=zid,
                         severity=sev, payload_extra=extra)
        ev["ts"] = ts
        ev["prev_event_hash"] = prev_hash
        try:
            resp = submit(session, gateway, ev)
            print_result(ev, resp)
            prev_hash = resp["payload_hash"]
        except Exception as exc:
            print(f"  FAIL: {exc}")


def run_fraud(gateway: str):
    """Submit an event, tamper with the payload off-chain, then verify -> FAIL."""
    print("Scenario: fraud (tamper detection demo)")
    session = requests.Session()

    ev = build_event(event_type="NEAR_MISS", actor_id="W001",
                     zone_id="Z04", severity=4,
                     payload_extra={"clearance_m": 0.4})
    print("  Submitting original event...")
    resp = submit(session, gateway, ev)
    event_id = resp["event_id"]
    original_hash = resp["payload_hash"]
    print(f"  event_id     : {event_id}")
    print(f"  payload_hash : {original_hash}")
    print(f"  signature    : {resp['signature'][:32]}...")

    print("\n  Verifying original (expected: PASS)")
    vresp = session.post(
        f"{gateway}/verify?event_id={event_id}",
        json={"payload_hash": original_hash},
    ).json()
    print(f"  Result: {vresp['result']}")

    print("\n  Tampering: changing severity 4 -> 1")
    canonical_keys = ["schema_version", "event_type", "ts", "site_id",
                      "zone_id", "actor_id", "severity", "source", "payload_extra"]
    canonical = {k: ev.get(k) for k in canonical_keys if ev.get(k) is not None}
    canonical["schema_version"] = SCHEMA_VERSION
    canonical["severity"] = 1
    tampered_str = json.dumps(dict(sorted(canonical.items())), separators=(",", ":"))
    tampered_hash = hashlib.sha256(tampered_str.encode()).hexdigest()

    print("\n  Verifying tampered payload (expected: FAIL)")
    vresp2 = session.post(
        f"{gateway}/verify?event_id={event_id}",
        json={"payload_hash": tampered_hash},
    ).json()
    print(f"  Result      : {vresp2['result']}")
    print(f"  stored_hash : {vresp2['stored_hash'][:32]}")
    print(f"  submitted   : {vresp2['submitted_hash'][:32]}")
    print(f"  sig_valid   : {vresp2.get('signature_valid')}")
    print("\nFraud scenario complete — tamper detected.")


def run_replay(gateway: str):
    """Submit the same event twice to demonstrate idempotency protection."""
    print("Scenario: replay attack")
    session = requests.Session()

    ev = build_event(event_type="ZONE_ENTRY", actor_id="W003", zone_id="Z04", severity=1)
    nonce = ev["nonce"]

    print("  Submitting event (attempt 1)...")
    resp1 = submit(session, gateway, ev)
    print(f"  Accepted: {resp1['event_id']}")

    print("  Re-submitting identical event with same nonce (attempt 2)...")
    try:
        resp2 = submit(session, gateway, ev)
        print(f"  Unexpected acceptance: {resp2['event_id']}")
    except requests.HTTPError as exc:
        print(f"  Rejected (expected): {exc.response.status_code} — {exc.response.text[:80]}")

    print("\nReplay scenario complete — duplicate rejected by idempotency check.")


def run_rate_based(gateway: str, rate: float, duration: int):
    """Submit events at a controlled rate for throughput measurement."""
    print(f"Rate-based simulation: {rate} events/s for {duration}s")
    session = requests.Session()
    interval = 1.0 / rate
    end = time.monotonic() + duration
    ok, fail = 0, 0
    while time.monotonic() < end:
        ev = build_event()
        t0 = time.monotonic()
        try:
            submit(session, gateway, ev)
            ok += 1
        except Exception:
            fail += 1
        elapsed = time.monotonic() - t0
        remaining = interval - elapsed
        if remaining > 0:
            time.sleep(remaining)
    print(f"\nSubmitted: {ok}  Failed: {fail}")

    stats = requests.get(f"{gateway}/metrics", timeout=5).json()
    print(f"Avg latency : {stats.get('avg_latency_ms')} ms")
    print(f"P95 latency : {stats.get('p95_latency_ms')} ms")
    print(f"Throughput  : {stats.get('throughput_tps')} tx/s")


def main():
    parser = argparse.ArgumentParser(description="IoT Safety Event Simulator")
    parser.add_argument("--gateway", default=GATEWAY_URL)
    parser.add_argument("--scenario", default="normal",
                        choices=["normal", "near_miss", "accident", "fraud", "replay", "all"])
    parser.add_argument("--count", type=int, default=200)
    parser.add_argument("--rate", type=float, default=0.0,
                        help="Events per second (overrides --scenario for throughput testing)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration in seconds for rate-based simulation")
    parser.add_argument("--export", action="store_true",
                        help="Export metrics CSV after simulation")
    args = parser.parse_args()

    print(f"Simulator  |  gateway={args.gateway}  |  site={SITE_ID}\n")

    if args.rate > 0:
        run_rate_based(args.gateway, args.rate, args.duration)
    elif args.scenario == "all":
        run_normal(args.gateway, args.count)
        run_near_miss(args.gateway)
        run_accident(args.gateway)
        run_fraud(args.gateway)
        run_replay(args.gateway)
    elif args.scenario == "normal":
        run_normal(args.gateway, args.count)
    elif args.scenario == "near_miss":
        run_near_miss(args.gateway)
    elif args.scenario == "accident":
        run_accident(args.gateway)
    elif args.scenario == "fraud":
        run_fraud(args.gateway)
    elif args.scenario == "replay":
        run_replay(args.gateway)

    if args.export:
        resp = requests.post(f"{args.gateway}/metrics/export", timeout=5)
        if resp.ok:
            print(f"\nMetrics exported to: {resp.json().get('exported_to')}")


if __name__ == "__main__":
    main()
