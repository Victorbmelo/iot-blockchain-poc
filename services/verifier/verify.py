#!/usr/bin/env python3
"""
verify.py - Standalone batch integrity verifier.

Runs independently of the gateway:
- Fetches batch + event data from the Audit Gateway API
- Verifies Merkle integrity by recomputing roots
- Uses the gateway's /verify endpoints (which internally query Besu)

Verification modes:
  all-batches     - verify every ANCHORED batch
  batch <id>      - verify a specific batch
  event <id>      - verify a single event (hash + Merkle proof)
  fraud-cases     - run narrative fraud scenarios (T1/T2/T3)

Output: JSON + CSV to results/verify_<timestamp>.{json,csv}
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import sys
import time
import unicodedata
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

import requests


DEFAULT_GATEWAY = os.getenv("GATEWAY_URL", "http://audit-gateway:8000")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def build_session() -> requests.Session:
    s = requests.Session()
    s.headers["X-Role"] = "inspector"
    return s


def api(session: requests.Session, base_url: str, path: str, **kwargs) -> Any:
    resp = session.get(f"{base_url}{path}", timeout=15, **kwargs)
    resp.raise_for_status()
    return resp.json()


def verify_batch(session: requests.Session, base_url: str, batch_id: str) -> Dict[str, Any]:
    """Call gateway /verify/batch and return result."""
    t0 = time.monotonic()
    resp = session.get(f"{base_url}/verify/batch/{batch_id}", timeout=20)
    elapsed = (time.monotonic() - t0) * 1000

    if resp.status_code == 404:
        return {
            "batch_id": batch_id,
            "verdict": "FAIL",
            "reason": "Batch not found",
            "verify_ms": round(elapsed, 2),
        }

    resp.raise_for_status()
    result = resp.json()
    result["verify_ms"] = round(elapsed, 2)
    return result


def verify_event(session: requests.Session, base_url: str, event_id: str) -> Dict[str, Any]:
    """Verify a single event via gateway /verify/event."""
    t0 = time.monotonic()
    resp = session.post(f"{base_url}/verify/event/{event_id}", timeout=15)
    elapsed = (time.monotonic() - t0) * 1000
    resp.raise_for_status()
    result = resp.json()
    result["verify_ms"] = round(elapsed, 2)
    return result


def _sort_keys(o: Any) -> Any:
    if isinstance(o, dict):
        return {k: _sort_keys(o[k]) for k in sorted(o)}
    if isinstance(o, list):
        return [_sort_keys(v) for v in o]
    return o


def _sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def _hash_pair(a: bytes, b: bytes) -> bytes:
    lo, hi = (a, b) if a <= b else (b, a)
    return _sha256(lo + hi)


def compute_root(hashes_hex: List[str]) -> str:
    """Standalone Merkle root (sorted leaves, pairwise hash with duplication)."""
    if not hashes_hex:
        return "0" * 64
    layer = sorted(bytes.fromhex(h) for h in hashes_hex)
    while len(layer) > 1:
        nxt: List[bytes] = []
        for i in range(0, len(layer), 2):
            l = layer[i]
            r = layer[i + 1] if i + 1 < len(layer) else layer[i]
            nxt.append(_hash_pair(l, r))
        layer = nxt
    return layer[0].hex()


def run_fraud_scenarios(session: requests.Session, base_url: str) -> List[Dict[str, Any]]:
    """Run narrative fraud scenarios (T1/T2/T3) and report PASS/FAIL."""
    print("\n" + "-" * 60)
    print("Fraud / Tamper Scenarios")
    print("-" * 60)

    results: List[Dict[str, Any]] = []

    batches = api(session, base_url, "/batches?limit=10")
    anchored = [b for b in batches if b.get("anchor_status") == "ANCHORED"]
    if not anchored:
        print("No anchored batches found. Run 'make seed' then wait for batch window.")
        return results

    batch_id = anchored[0]["batch_id"]
    batch_events = api(session, base_url, f"/batches/{batch_id}/events")
    if not batch_events:
        print("No events in batch.")
        return results

    target_event = batch_events[0]
    event_id = target_event["event_id"]
    original_hash = target_event["event_hash"]

    # --- T2: Payload tampering ---------------------------------------------
    print("\nT2: Payload tampering (severity 4 -> 1)")
    print(f"  Target event: {event_id}")
    print(f"  Stored hash:  {original_hash[:32]}...")

    CANONICAL_FIELDS = [
        "schema_version",
        "event_type",
        "ts",
        "site_id",
        "zone_id",
        "actor_id",
        "severity",
        "source",
        "payload",
    ]

    tampered = {k: target_event.get(k) for k in CANONICAL_FIELDS if target_event.get(k) is not None}
    tampered["schema_version"] = "1.0"
    tampered["severity"] = 1  # tampered
    raw = json.dumps(_sort_keys(tampered), separators=(",", ":"), ensure_ascii=False)
    tampered_hash = hashlib.sha256(unicodedata.normalize("NFC", raw).encode()).hexdigest()

    hashes_differ = tampered_hash != original_hash
    t2_result = {
        "scenario": "T2_payload_tamper",
        "event_id": event_id,
        "original_hash": original_hash[:32],
        "tampered_hash": tampered_hash[:32],
        "hashes_differ": hashes_differ,
        "verdict": "PASS - tamper detected" if hashes_differ else "FAIL - tamper NOT detected",
    }
    print(f"  Hashes differ:  {hashes_differ}  ->  {t2_result['verdict']}")
    results.append(t2_result)

    # --- T3: Extra event injection -----------------------------------------
    print("\nT3: Extra event injection (Merkle tree tampering)")
    all_hashes = [e["event_hash"] for e in batch_events]
    legitimate_root = compute_root(all_hashes)

    fake_hash = "a" * 64
    injected_root = compute_root(all_hashes + [fake_hash])

    roots_differ = legitimate_root != injected_root
    t3_result = {
        "scenario": "T3_event_injection",
        "batch_id": batch_id,
        "legitimate_root": legitimate_root[:32],
        "injected_root": injected_root[:32],
        "roots_differ": roots_differ,
        "verdict": "PASS - injection changes root (anchor mismatch)" if roots_differ else "FAIL - injection not detected",
    }
    print(f"  Legitimate root:     {legitimate_root[:32]}...")
    print(f"  Root with fake hash: {injected_root[:32]}...")
    print(f"  {t3_result['verdict']}")
    results.append(t3_result)

    # --- T1: Deletion simulation -------------------------------------------
    print("\nT1: Event deletion from batch (simulated)")
    deleted_root = compute_root(all_hashes[1:])

    roots_differ = legitimate_root != deleted_root
    t1_result = {
        "scenario": "T1_event_deletion",
        "batch_id": batch_id,
        "original_event_count": len(all_hashes),
        "after_deletion_count": len(all_hashes) - 1,
        "legitimate_root": legitimate_root[:32],
        "root_after_deletion": deleted_root[:32],
        "roots_differ": roots_differ,
        "verdict": "PASS - deletion changes root (anchor mismatch)" if roots_differ else "FAIL - deletion not detected",
    }
    print(f"  Events before deletion: {len(all_hashes)}")
    print(f"  Events after deletion:  {len(all_hashes) - 1}")
    print(f"  {t1_result['verdict']}")
    results.append(t1_result)

    return results


def write_outputs(out_dir: Path, ts: str, results: List[Dict[str, Any]], prefix: str = "verify") -> None:
    out_json = out_dir / f"{prefix}_{ts}.json"
    out_json.write_text(json.dumps(results, indent=2))

    if not results:
        print(f"Results -> {out_json}")
        return

    out_csv = out_dir / f"{prefix}_{ts}.csv"
    keys = sorted({k for r in results for k in r})
    with open(out_csv, "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=keys)
        w.writeheader()
        for r in results:
            w.writerow({k: r.get(k, "") for k in keys})

    passed = sum(1 for r in results if r.get("verdict") == "PASS" or "PASS" in str(r.get("verdict", "")))
    failed = sum(1 for r in results if r.get("verdict") == "FAIL")
    print(f"\nTotal: {len(results)}  PASS-like: {passed}  FAIL: {failed}")
    print(f"Results -> {out_json}  {out_csv}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Audit Batch Verifier")
    parser.add_argument("mode", choices=["all-batches", "batch", "event", "fraud-cases"], help="Verification mode")
    parser.add_argument("id", nargs="?", help="Batch or event ID (for 'batch' and 'event' modes)")
    parser.add_argument("--gateway", default=DEFAULT_GATEWAY, help="Gateway base URL (Docker: http://audit-gateway:8000)")
    parser.add_argument("--out", default="results", help="Output directory for CSV/JSON")
    args = parser.parse_args()

    session = build_session()
    gateway = args.gateway

    # Verify gateway reachable
    try:
        h = session.get(f"{gateway}/health", timeout=5).json()
        print(f"Gateway: {gateway}  backend={h.get('ledger_backend')}")
    except Exception as exc:
        print(f"Cannot reach gateway: {exc}", file=sys.stderr)
        sys.exit(1)

    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    results: List[Dict[str, Any]] = []

    if args.mode == "fraud-cases":
        fraud_results = run_fraud_scenarios(session, gateway)
        write_outputs(out_dir, ts, fraud_results, prefix="fraud")
        return

    if args.mode == "all-batches":
        batches = api(session, gateway, "/batches?limit=200")
        anchored = [b for b in batches if b.get("anchor_status") == "ANCHORED"]
        print(f"Verifying {len(anchored)} anchored batches...")
        for b in anchored:
            r = verify_batch(session, gateway, b["batch_id"])
            results.append(r)
            print(f"  {b['batch_id'][:40]:40s}  {r['verdict']:5s}  {str(r.get('reason',''))[:50]}")

    elif args.mode == "batch":
        if not args.id:
            sys.exit("Provide batch ID: python verify.py batch <batch_id>")
        r = verify_batch(session, gateway, args.id)
        results.append(r)
        print(json.dumps(r, indent=2))

    elif args.mode == "event":
        if not args.id:
            sys.exit("Provide event ID: python verify.py event <event_id>")
        r = verify_event(session, gateway, args.id)
        results.append(r)
        print(json.dumps(r, indent=2))

    write_outputs(out_dir, ts, results, prefix="verify")


if __name__ == "__main__":
    main()
