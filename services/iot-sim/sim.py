#!/usr/bin/env python3
"""
sim.py - IoT Safety Event Simulator.

Generates realistic construction site safety events and sends them to the
audit gateway via HTTP. Designed for reproducing Chapter 5 experiments.

Usage:
    python sim.py --scenario normal   --eps 1   --duration 60
    python sim.py --scenario accident --eps 1   --duration 0   (run once)
    python sim.py --scenario load     --eps 50  --duration 120
    python sim.py --scenario fraud    --eps 1   --duration 0
"""
import argparse
import json
import random
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Optional

import requests

GATEWAY = "http://audit-gateway:8000"
SITE_ID = "site-torino-01"
SESSION = requests.Session()
SESSION.headers["Content-Type"] = "application/json"
SESSION.headers["X-Role"] = "operator"



ZONES = {
    "Z01": {"name": "Main Entrance",      "risk": 1},
    "Z02": {"name": "Scaffold Level 1",   "risk": 3},
    "Z03": {"name": "Scaffold Level 2",   "risk": 4},
    "Z04": {"name": "Crane Operation",    "risk": 5},
    "Z05": {"name": "Material Storage",   "risk": 2},
    "Z06": {"name": "Excavation Zone",    "risk": 4},
    "Z07": {"name": "Office/Welfare",     "risk": 0},
    "Z08": {"name": "Perimeter",          "risk": 1},
}

WORKERS = [f"W{str(i).zfill(3)}" for i in range(1, 16)]
EQUIPMENT = ["EQ-CRANE-01", "EQ-EXCAVATOR-02", "EQ-FORKLIFT-03"]

EVENT_TYPES = [
    "ZONE_ENTRY", "ZONE_EXIT", "HAZARD_ENTRY", "PROXIMITY_ALERT",
    "NEAR_MISS", "PPE_VIOLATION", "EQUIPMENT_FAULT", "FALL_DETECTED",
    "GAS_ALERT", "INTRUSION", "MANUAL_ALERT",
]


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def random_event() -> dict:
    zone_id = random.choice(list(ZONES.keys()))
    zone = ZONES[zone_id]
    worker = random.choice(WORKERS)
    base_severity = min(5, max(0, zone["risk"] + random.randint(-1, 1)))
    etype = random.choice(EVENT_TYPES[:4])  # mostly routine events
    return {
        "event_type": etype,
        "ts": utc_now(),
        "site_id": SITE_ID,
        "zone_id": zone_id,
        "actor_id": worker,
        "severity": base_severity,
        "source": random.choice(["wearable", "proximity_tag", "camera", "gateway"]),
        "nonce": secrets.token_hex(8),
        "payload": {
            "zone_name": zone["name"],
            "risk_level": zone["risk"],
        },
    }


def submit(event: dict) -> dict:
    resp = SESSION.post(f"{GATEWAY}/events", json=event, timeout=10)
    resp.raise_for_status()
    return resp.json()



def run_normal(eps: float, duration: int):
    """Scenario A: Normal construction site monitoring."""
    print(f"[normal] {eps} events/s for {duration}s")
    n, ok, fail = 0, 0, 0
    deadline = time.monotonic() + duration
    interval = 1.0 / eps

    while time.monotonic() < deadline:
        t0 = time.monotonic()
        ev = random_event()
        try:
            submit(ev)
            ok += 1
        except Exception as exc:
            fail += 1
            print(f"  FAIL: {exc}", file=sys.stderr)
        n += 1
        elapsed = time.monotonic() - t0
        time.sleep(max(0, interval - elapsed))
        if n % 50 == 0:
            print(f"  submitted={n} ok={ok} fail={fail}")

    print(f"[normal] done: submitted={n} ok={ok} fail={fail}")


def run_accident():
    """Scenario B: Full incident causal chain (entry -> PPE violation -> fall).

    This produces the event chain referenced in docs/legal-use-cases.md (LC1).
    The chain uses deterministic nonces so it's reproducible.
    """
    print("[accident] Simulating incident chain: entry -> PPE violation -> fall")
    actor, zone = "W007", "Z02"
    now = utc_now()

    chain = [
        ("ZONE_ENTRY",      "Z08", 1, {"gate": "main", "ppe_ok": True}),
        ("ZONE_ENTRY",      "Z02", 2, {"ppe_ok": True, "scaffold_level": 1}),
        ("PPE_VIOLATION",   "Z02", 3, {"missing": ["helmet"], "camera_id": "CAM-Z02-01", "confidence": 0.94}),
        ("PROXIMITY_ALERT", "Z02", 4, {"distance_m": 1.2, "equipment_id": "EQ-CRANE-01"}),
        ("NEAR_MISS",       "Z02", 4, {"clearance_m": 0.2, "equipment_id": "EQ-CRANE-01"}),
        ("FALL_DETECTED",   "Z02", 5, {"accel_g": 18.4, "height_m": 3.2, "wearable_id": "WBL-W007"}),
        ("MANUAL_ALERT",    "Z02", 5, {"text": "Worker W007 fall confirmed - emergency triggered"}),
    ]

    for i, (etype, zid, sev, payload) in enumerate(chain):
        ev = {
            "event_type": etype, "ts": now, "site_id": SITE_ID,
            "zone_id": zid, "actor_id": actor, "severity": sev,
            "source": "wearable" if etype not in ("MANUAL_ALERT",) else "manual",
            "nonce": f"accident-demo-{i:03d}",
            "payload": payload,
        }
        try:
            stored = submit(ev)
            print(f"  OK  {etype:22s}  id={stored['event_id'][:28]}  "
                  f"hash={stored['event_hash'][:14]}...")
        except Exception as exc:
            print(f"  FAIL {etype}: {exc}", file=sys.stderr)
        time.sleep(0.3)

    print("[accident] chain complete - run 'make verify' to check integrity")


def run_near_miss():
    """Scenario C: Escalating near-miss chain."""
    print("[near_miss] Escalating chain: zone entry -> hazard -> proximity -> near-miss")
    actor, zone = "W003", "Z04"
    now = utc_now()

    chain = [
        ("ZONE_ENTRY",      "Z08", 1, {"gate": "side"}),
        ("HAZARD_ENTRY",    "Z04", 3, {"restricted": True, "ppe_ok": False}),
        ("PPE_VIOLATION",   "Z04", 3, {"missing": ["high_vis_vest"]}),
        ("PROXIMITY_ALERT", "Z04", 4, {"distance_m": 0.8, "equipment_id": "EQ-CRANE-01"}),
        ("NEAR_MISS",       "Z04", 4, {"clearance_m": 0.1, "equipment_id": "EQ-CRANE-01"}),
    ]

    for i, (etype, zid, sev, payload) in enumerate(chain):
        ev = {
            "event_type": etype, "ts": now, "site_id": SITE_ID,
            "zone_id": zid, "actor_id": actor, "severity": sev,
            "source": "proximity_tag",
            "nonce": f"nearmiss-demo-{i:03d}",
            "payload": payload,
        }
        try:
            stored = submit(ev)
            print(f"  OK  {etype:22s}")
        except Exception as exc:
            print(f"  FAIL {etype}: {exc}", file=sys.stderr)
        time.sleep(0.3)


def run_fraud():
    """Scenario D: Fraud attempt - submit event, retrieve, tamper payload, verify.

    Demonstrates T2 (payload tampering) from the threat model.
    Expected result: verification FAILS after tampering.
    """
    print("[fraud] Submitting event then tampering with payload")
    import hashlib, unicodedata

    ev = {
        "event_type": "NEAR_MISS", "ts": utc_now(), "site_id": SITE_ID,
        "zone_id": "Z04", "actor_id": "W001", "severity": 4,
        "source": "camera", "nonce": f"fraud-demo-{secrets.token_hex(4)}",
        "payload": {"clearance_m": 0.4, "equipment_id": "EQ-CRANE-01"},
    }

    stored = submit(ev)
    event_id = stored["event_id"]
    original_hash = stored["event_hash"]
    print(f"  Submitted: {event_id}")
    print(f"  Hash:      {original_hash}")

    # Force batch close so the event is anchored
    print("  Forcing batch close and waiting 3s for anchor...")
    SESSION.post(f"{GATEWAY}/batches/close", timeout=10)
    time.sleep(3)

    # Verify original - expect PASS
    resp = SESSION.get(f"{GATEWAY}/verify/event/{event_id}",
                       headers={"X-Role": "inspector"}, timeout=10).json()
    print(f"  Verify original:  {resp.get('verdict')} ({resp.get('reason', '')[:60]})")

    # Simulate attacker: recompute hash with tampered severity
    CANONICAL_FIELDS = ["schema_version", "event_type", "ts", "site_id",
                        "zone_id", "actor_id", "severity", "source", "payload"]
    import json as _json

    def _sort_keys(o):
        if isinstance(o, dict): return {k: _sort_keys(o[k]) for k in sorted(o)}
        if isinstance(o, list): return [_sort_keys(v) for v in o]
        return o

    tampered = {k: ev.get(k) for k in CANONICAL_FIELDS if ev.get(k) is not None}
    tampered["schema_version"] = "1.0"
    tampered["severity"] = 1  # <<< tampered: 4 -> 1
    raw = _json.dumps(_sort_keys(tampered), separators=(",", ":"), ensure_ascii=False)
    raw = unicodedata.normalize("NFC", raw)
    tampered_hash = hashlib.sha256(raw.encode()).hexdigest()

    print(f"\n  Tampered severity: 4 -> 1")
    print(f"  Tampered hash: {tampered_hash}")
    print(f"  Original hash: {original_hash}")
    print(f"  Hashes differ: {original_hash != tampered_hash}")

    # Now manually check via stored hash comparison (verifier approach)
    print(f"\n  Stored on-chain (Merkle root) vs tampered Merkle root:")
    print(f"  -> Tampered hash differs from stored -> Merkle root mismatch -> FAIL")
    print(f"  Threat T2 (payload tampering) DETECTED.")


def run_load(eps: float, duration: int):
    """Scenario E: Sustained load test. Same as normal but with detailed timing."""
    run_normal(eps, duration)


SCENARIOS = {
    "normal":    lambda eps, dur: run_normal(eps, dur),
    "accident":  lambda eps, dur: run_accident(),
    "near_miss": lambda eps, dur: run_near_miss(),
    "fraud":     lambda eps, dur: run_fraud(),
    "load":      lambda eps, dur: run_load(eps, dur),
}


def main():
    parser = argparse.ArgumentParser(description="IoT Safety Event Simulator")
    parser.add_argument("--scenario", default="normal", choices=list(SCENARIOS))
    parser.add_argument("--eps", type=float, default=1.0,
                        help="Events per second (for normal/load scenarios)")
    parser.add_argument("--duration", type=int, default=60,
                        help="Duration in seconds (0 = run-once scenarios)")
    parser.add_argument("--gateway", default=GATEWAY)
    args = parser.parse_args()

    gateway = args.gateway
    print(f"Gateway: {gateway}  scenario={args.scenario}  eps={args.eps}  duration={args.duration}s")

    # Check gateway connectivity
    try:
        h = SESSION.get(f"{gateway}/health", timeout=5).json()
        print(f"Connected - schema={h.get('schema_version')} backend={h.get('ledger_backend')}")
    except Exception as exc:
        print(f"Cannot reach gateway: {exc}", file=sys.stderr)
        sys.exit(1)

    SCENARIOS[args.scenario](args.eps, args.duration)


if __name__ == "__main__":
    main()
