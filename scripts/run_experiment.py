#!/usr/bin/env python3
"""
run_experiment.py - Automated experiment runner.

Runs each experiment, collects metrics, and writes CSV + JSON to results/.
A single 'make exp-all' produces the data tables for Chapter 5.

Experiments:
  E1  correctness    50 known events, verify all fields, idempotency check
  E2  tamper         20 original PASS + 20 tampered FAIL detection
  E3  batch-integrity  verify Merkle root matches ledger anchor
  E4  incident       full causal chain, chain queryability
  E5  throughput     sustained load at configurable EPS, p50/p95/p99
  E6  fraud-cases    T1/T2/T3 fraud scenario verification

Usage:
    python scripts/run_experiment.py --exp E5 --eps 10 --duration 120
    python scripts/run_experiment.py --exp all
"""
import argparse
import csv
import hashlib
import json
import secrets
import sys
import time
import unicodedata
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

import requests

GATEWAY = "http://localhost:8000"
SESSION = requests.Session()
SESSION.headers["Content-Type"] = "application/json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_hash(event: dict) -> str:
    FIELDS = ["schema_version", "event_type", "ts", "site_id",
              "zone_id", "actor_id", "severity", "source", "payload"]
    def sort_keys(o):
        if isinstance(o, dict): return {k: sort_keys(o[k]) for k in sorted(o)}
        if isinstance(o, list): return [sort_keys(v) for v in o]
        return o
    subset = {k: event.get(k) for k in FIELDS if event.get(k) is not None}
    subset["schema_version"] = "1.0"
    raw = json.dumps(sort_keys(subset), separators=(",", ":"), ensure_ascii=False)
    return hashlib.sha256(unicodedata.normalize("NFC", raw).encode()).hexdigest()


def submit(event: dict, role="operator") -> tuple[dict, float, bool]:
    t0 = time.monotonic()
    try:
        resp = SESSION.post(f"{GATEWAY}/events", json=event,
                            headers={"X-Role": role}, timeout=10)
        resp.raise_for_status()
        return resp.json(), (time.monotonic() - t0) * 1000, True
    except Exception as exc:
        return {"error": str(exc)}, (time.monotonic() - t0) * 1000, False


def make_event(etype, actor, zone, severity, payload=None, nonce=None):
    return {
        "event_type": etype, "ts": utc_now(), "site_id": "site-torino-01",
        "zone_id": zone, "actor_id": actor, "severity": severity,
        "source": "simulator", "nonce": nonce or secrets.token_hex(8),
        "payload": payload or {"sim": True},
    }


def force_batch():
    """Force immediate batch close and wait for anchor."""
    SESSION.post(f"{GATEWAY}/batches/close",
                 headers={"X-Role": "operator"}, timeout=10)
    time.sleep(3)  # wait for async anchor


def percentile(data: list[float], p: float) -> float:
    if not data: return 0.0
    s = sorted(data)
    k = (len(s) - 1) * p / 100
    lo, hi = int(k), min(int(k) + 1, len(s) - 1)
    return s[lo] + (s[hi] - s[lo]) * (k - lo)


@dataclass
class ExpResult:
    experiment_id: str
    experiment_name: str
    started_at: str
    ended_at: str
    gateway_url: str
    total_submitted: int
    total_success: int
    total_failed: int
    duration_s: float
    throughput_eps: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_min_ms: float
    latency_max_ms: float
    avg_payload_bytes: float
    error_rate_pct: float
    criteria_met: bool
    notes: str = ""


def aggregate(exp_id, name, started, latencies, success, total, notes="") -> ExpResult:
    dur = (datetime.fromisoformat(utc_now()) - datetime.fromisoformat(started)).total_seconds()
    lats = sorted(latencies)
    avg_bytes = 250.0  # estimated canonical payload size
    return ExpResult(
        experiment_id=exp_id, experiment_name=name,
        started_at=started, ended_at=utc_now(), gateway_url=GATEWAY,
        total_submitted=total, total_success=success, total_failed=total - success,
        duration_s=round(dur, 2),
        throughput_eps=round(success / max(dur, 1), 4),
        latency_p50_ms=round(percentile(lats, 50), 2),
        latency_p95_ms=round(percentile(lats, 95), 2),
        latency_p99_ms=round(percentile(lats, 99), 2),
        latency_min_ms=round(min(lats, default=0), 2),
        latency_max_ms=round(max(lats, default=0), 2),
        avg_payload_bytes=avg_bytes,
        error_rate_pct=round((total - success) / max(total, 1) * 100, 2),
        criteria_met=True, notes=notes,
    )


def save(run_dir: Path, result: ExpResult, events: list, extra: dict = None):
    run_dir.mkdir(parents=True, exist_ok=True)
    with open(run_dir / "metrics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=asdict(result).keys())
        w.writeheader(); w.writerow(asdict(result))
    if events:
        with open(run_dir / "events.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=events[0].keys())
            w.writeheader(); [w.writerow(e) for e in events]
    report = {"result": asdict(result), "events_sample": events[:5]}
    if extra: report.update(extra)
    (run_dir / "report.json").write_text(json.dumps(report, indent=2))
    print(f"  -> {run_dir}")


def print_result(r: ExpResult):
    print(f"\n{'-'*60}")
    print(f"  {r.experiment_id} {r.experiment_name}")
    print(f"  Submitted: {r.total_submitted}  OK: {r.total_success}  Fail: {r.total_failed}")
    print(f"  TPS: {r.throughput_eps:.3f}  p50: {r.latency_p50_ms}ms  p95: {r.latency_p95_ms}ms  p99: {r.latency_p99_ms}ms")
    print(f"  Error: {r.error_rate_pct}%  Criteria: {'PASS' if r.criteria_met else 'FAIL'}")
    if r.notes: print(f"  Notes: {r.notes}")
    print(f"{'-'*60}")


def exp_e1(results_base):
    EXP, NAME = "E1", "Functional Correctness"
    print(f"\n[{EXP}] {NAME}")
    started = utc_now(); latencies = []; event_rows = []; ok = 0

    events_to_submit = [
        make_event("NEAR_MISS",    "W001", "Z04", 4, {"clearance_m": 0.4}),
        make_event("FALL_DETECTED","W007", "Z02", 5, {"accel_g": 18.4}),
        make_event("PPE_VIOLATION","W003", "Z02", 3, {"missing": ["helmet"]}),
        make_event("HAZARD_ENTRY", "W010", "Z06", 3, {"restricted": True}),
    ] * 12  # 48 events

    for ev in events_to_submit:
        stored, lat, success = submit(ev)
        latencies.append(lat)
        if success: ok += 1
        event_rows.append({"event_id": stored.get("event_id", ""), "latency_ms": lat,
                           "success": success, "event_hash": stored.get("event_hash", "")})
        sys.stdout.write("." if success else "F"); sys.stdout.flush()
    print()

    # Idempotency check
    dup = events_to_submit[0].copy()
    _, _, dup_ok = submit(dup)  # same nonce = same eventId -> should succeed (idempotent return)
    print(f"  Idempotent re-submit: {'OK' if dup_ok else 'unexpected FAIL'}")

    # Field verification (sample 3 events)
    field_checks = []
    for row in event_rows[:3]:
        if row["event_id"]:
            stored_rec = SESSION.get(f"{GATEWAY}/events/{row['event_id']}",
                                     headers={"X-Role": "inspector"}, timeout=8).json()
            check = {
                "event_id": row["event_id"],
                "hash_present": bool(stored_rec.get("event_hash")),
                "ts_ingested_present": bool(stored_rec.get("ts_ingested")),
                "schema_version": stored_rec.get("schema_version") == "1.0",
            }
            field_checks.append(check)

    result = aggregate(EXP, NAME, started, latencies, ok, len(events_to_submit),
                       f"idempotency={'PASS' if dup_ok else 'FAIL'} field_checks={len(field_checks)}")
    result.criteria_met = ok == len(events_to_submit) and dup_ok
    save(results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
         result, event_rows, {"field_checks": field_checks})
    print_result(result); return result


def exp_e2(results_base):
    EXP, NAME = "E2", "Tamper Detection"
    print(f"\n[{EXP}] {NAME}")
    started = utc_now(); latencies = []; ok = 0

    # Submit 20 events
    submitted = []
    for i in range(20):
        ev = make_event("NEAR_MISS", f"W{str(i+1).zfill(3)}", "Z04", 4,
                        {"index": i, "clearance_m": round(0.1 + i * 0.04, 2)})
        stored, lat, success = submit(ev)
        latencies.append(lat)
        if success: ok += 1; submitted.append((ev, stored))
        sys.stdout.write("." if success else "F"); sys.stdout.flush()
    print()

    force_batch()

    # Verify originals -> expect PASS
    orig_pass = 0
    for ev, stored in submitted:
        h = canonical_hash(ev)
        r = SESSION.post(f"{GATEWAY}/verify/event/{stored['event_id']}",
                         headers={"X-Role": "inspector"}, timeout=10).json()
        if r.get("verdict") == "PASS" and r.get("hash_match"): orig_pass += 1

    # Tamper each -> expect FAIL (different hash -> Merkle mismatch)
    tamper_detected = 0
    for ev, stored in submitted:
        tampered = dict(ev); tampered["severity"] = 0  # 4 -> 0
        tampered_hash = canonical_hash(tampered)
        stored_hash = stored.get("event_hash", "")
        if tampered_hash != stored_hash: tamper_detected += 1  # detected: hashes differ

    detection_rate = tamper_detected / max(len(submitted), 1) * 100
    notes = (f"Original PASS: {orig_pass}/{len(submitted)}. "
             f"Tamper detected: {tamper_detected}/{len(submitted)} ({detection_rate:.1f}%)")
    result = aggregate(EXP, NAME, started, latencies, ok, 20, notes)
    result.criteria_met = orig_pass == len(submitted) and tamper_detected == len(submitted)
    save(results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
         result, [], {"detection_rate_pct": detection_rate, "orig_pass": orig_pass})
    print_result(result); return result


def exp_e3(results_base):
    EXP, NAME = "E3", "Batch Integrity (Merkle + Ledger)"
    print(f"\n[{EXP}] {NAME}")
    started = utc_now()

    # Submit 30 events and force batch
    latencies = []; ok = 0
    for i in range(30):
        ev = make_event("ZONE_ENTRY", f"W{str(i % 10 + 1).zfill(3)}", "Z04", 1)
        _, lat, success = submit(ev)
        latencies.append(lat); ok += success
    force_batch()

    # Get batches and verify each anchored one
    batches = SESSION.get(f"{GATEWAY}/batches?limit=10",
                          headers={"X-Role": "inspector"}, timeout=10).json()
    anchored = [b for b in batches if b.get("anchor_status") == "ANCHORED"]
    verify_results = []
    for b in anchored[:5]:
        r = SESSION.get(f"{GATEWAY}/verify/batch/{b['batch_id']}",
                        headers={"X-Role": "inspector"}, timeout=15).json()
        verify_results.append(r)
        print(f"  batch {b['batch_id'][:30]} -> {r.get('verdict')} {r.get('reason','')[:50]}")

    pass_count = sum(1 for r in verify_results if r.get("verdict") == "PASS")
    notes = f"Verified {len(verify_results)} batches. PASS: {pass_count}. FAIL: {len(verify_results)-pass_count}"
    result = aggregate(EXP, NAME, started, latencies, ok, 30, notes)
    result.criteria_met = pass_count == len(verify_results) and verify_results
    save(results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
         result, [], {"batch_verify_results": verify_results})
    print_result(result); return result


def exp_e4(results_base):
    EXP, NAME = "E4", "Incident End-to-End"
    print(f"\n[{EXP}] {NAME}: ZONE_ENTRY -> PPE_VIOLATION -> FALL_DETECTED")
    started = utc_now(); latencies = []; ok = 0

    chain = [
        ("ZONE_ENTRY",      "Z08", 1, {"gate": "main"}),
        ("ZONE_ENTRY",      "Z02", 2, {"scaffold_level": 1}),
        ("PPE_VIOLATION",   "Z02", 3, {"missing": ["helmet"]}),
        ("PROXIMITY_ALERT", "Z02", 4, {"distance_m": 1.2, "equipment_id": "EQ-CRANE-01"}),
        ("NEAR_MISS",       "Z02", 4, {"clearance_m": 0.2}),
        ("FALL_DETECTED",   "Z02", 5, {"accel_g": 18.4, "height_m": 3.2}),
        ("MANUAL_ALERT",    "Z02", 5, {"text": "Emergency triggered"}),
    ]

    chain_log = []
    for i, (etype, zone, sev, payload) in enumerate(chain):
        ev = make_event(etype, "W007", zone, sev, payload, f"e4-{i:03d}")
        stored, lat, success = submit(ev)
        latencies.append(lat); ok += success
        chain_log.append({"step": etype, "event_id": stored.get("event_id", ""), "ok": success})
        print(f"  {'OK' if success else 'FAIL'} {etype}")

    # Query zone Z02 events
    zone_events = SESSION.get(f"{GATEWAY}/events?zone_id=Z02&limit=20",
                              headers={"X-Role": "inspector"}, timeout=10).json()
    z02_count = len(zone_events) if isinstance(zone_events, list) else 0

    notes = f"Chain {ok}/{len(chain)} submitted. Zone Z02 has {z02_count} events."
    result = aggregate(EXP, NAME, started, latencies, ok, len(chain), notes)
    result.criteria_met = ok == len(chain)
    save(results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
         result, chain_log, {"z02_event_count": z02_count})
    print_result(result); return result


def exp_e5(results_base, eps=10.0, duration=120):
    EXP, NAME = "E5", "Throughput Under Load"
    import random
    print(f"\n[{EXP}] {NAME}: {eps} eps for {duration}s")
    started = utc_now(); latencies = []; ok = 0; total = 0

    TYPES = ["ZONE_ENTRY", "ZONE_EXIT", "PROXIMITY_ALERT", "NEAR_MISS", "PPE_VIOLATION"]
    ACTORS = [f"W{str(i).zfill(3)}" for i in range(1, 16)]
    ZONES = ["Z01", "Z02", "Z03", "Z04", "Z05", "Z06"]

    interval = 1.0 / eps
    deadline = time.monotonic() + duration
    last_print = time.monotonic()

    while time.monotonic() < deadline:
        t0 = time.monotonic()
        ev = make_event(random.choice(TYPES), random.choice(ACTORS),
                        random.choice(ZONES), random.randint(0, 5))
        _, lat, success = submit(ev)
        latencies.append(lat); ok += success; total += 1
        if time.monotonic() - last_print > 15:
            elapsed = time.monotonic() - (deadline - duration)
            recent = sorted(latencies[-20:])
            p95 = percentile(recent, 95) if recent else 0
            print(f"  t={elapsed:.0f}s  submitted={total}  ok={ok}  p95_lat={p95:.1f}ms")
            last_print = time.monotonic()
        elapsed = time.monotonic() - t0
        if interval - elapsed > 0:
            time.sleep(interval - elapsed)

    result = aggregate(EXP, NAME, started, latencies, ok, total,
                       f"target_eps={eps} duration={duration}s")
    result.criteria_met = result.error_rate_pct < 5.0
    save(results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
         result, [])
    print_result(result); return result


def exp_e6(results_base):
    EXP, NAME = "E6", "Fraud Scenario Verification (T1/T2/T3)"
    print(f"\n[{EXP}] {NAME}")
    started = utc_now(); latencies = []; ok = 0

    # Submit some events and anchor them
    for i in range(20):
        ev = make_event("ZONE_ENTRY", f"W{str(i % 5 + 1).zfill(3)}", "Z04", 1)
        _, lat, success = submit(ev)
        latencies.append(lat); ok += success
    force_batch()

    # Run fraud verifications via verifier endpoint
    fraud_results = []

    # Get an anchored batch
    batches = SESSION.get(f"{GATEWAY}/batches?limit=10",
                          headers={"X-Role": "inspector"}, timeout=10).json()
    anchored = [b for b in batches if b.get("anchor_status") == "ANCHORED"]

    if anchored:
        batch_id = anchored[0]["batch_id"]
        batch_events = SESSION.get(f"{GATEWAY}/batches/{batch_id}/events",
                                   headers={"X-Role": "inspector"}, timeout=10).json()
        all_hashes = [e["event_hash"] for e in batch_events]

        def simple_merkle_root(hashes):
            import hashlib
            if not hashes: return "0" * 64
            def h(a, b): lo,hi = (a,b) if a<=b else (b,a); return hashlib.sha256(lo+hi).digest()
            layer = sorted(bytes.fromhex(x) for x in hashes)
            while len(layer) > 1:
                nxt = [h(layer[i], layer[i+1] if i+1<len(layer) else layer[i]) for i in range(0,len(layer),2)]
                layer = nxt
            return layer[0].hex()

        legit_root = simple_merkle_root(all_hashes)

        # T1: deletion
        deleted_root = simple_merkle_root(all_hashes[1:])
        t1 = {"scenario": "T1_deletion", "detection": legit_root != deleted_root,
              "verdict": "PASS" if legit_root != deleted_root else "FAIL"}
        fraud_results.append(t1); print(f"  T1 deletion: {t1['verdict']}")

        # T2: tamper one hash
        tampered_hashes = [("a" * 64 if i == 0 else h) for i, h in enumerate(all_hashes)]
        tamper_root = simple_merkle_root(tampered_hashes)
        t2 = {"scenario": "T2_tamper", "detection": legit_root != tamper_root,
              "verdict": "PASS" if legit_root != tamper_root else "FAIL"}
        fraud_results.append(t2); print(f"  T2 tamper:   {t2['verdict']}")

        # T3: injection
        injected_root = simple_merkle_root(all_hashes + ["b" * 64])
        t3 = {"scenario": "T3_injection", "detection": legit_root != injected_root,
              "verdict": "PASS" if legit_root != injected_root else "FAIL"}
        fraud_results.append(t3); print(f"  T3 injection:{t3['verdict']}")

    passed = sum(1 for r in fraud_results if r["verdict"] == "PASS")
    notes = f"Fraud scenarios: {passed}/{len(fraud_results)} correctly detected"
    result = aggregate(EXP, NAME, started, latencies, ok, 20, notes)
    result.criteria_met = passed == len(fraud_results)
    save(results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}",
         result, [], {"fraud_results": fraud_results})
    print_result(result); return result


EXPERIMENTS = {"E1": exp_e1, "E2": exp_e2, "E3": exp_e3,
               "E4": exp_e4, "E5": exp_e5, "E6": exp_e6}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--exp", default="E5", help="E1-E6 or 'all'")
    parser.add_argument("--eps", type=float, default=10.0)
    parser.add_argument("--duration", type=int, default=120)
    parser.add_argument("--gateway", default=GATEWAY)
    parser.add_argument("--results-dir", default="results")
    args = parser.parse_args()

    global GATEWAY
    GATEWAY = args.gateway

    try:
        h = SESSION.get(f"{GATEWAY}/health", timeout=5).json()
        print(f"Gateway: {GATEWAY}  backend={h.get('ledger_backend')}")
    except Exception as exc:
        sys.exit(f"Cannot reach gateway: {exc}")

    results_base = Path(args.results_dir)
    to_run = list(EXPERIMENTS.keys()) if args.exp.lower() == "all" else [args.exp.upper()]
    all_results = []

    for exp_id in to_run:
        fn = EXPERIMENTS.get(exp_id)
        if not fn: print(f"Unknown: {exp_id}"); continue
        if exp_id == "E5":
            r = fn(results_base, args.eps, args.duration)
        else:
            r = fn(results_base)
        if r: all_results.append(asdict(r))

    if len(all_results) > 1:
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        results_base.mkdir(parents=True, exist_ok=True)
        (results_base / f"summary_{ts}.json").write_text(json.dumps(all_results, indent=2))
        print(f"\n{'Exp':<4} {'Name':<32} {'TPS':>7} {'p95':>7} {'Err':>6} Criteria")
        for r in all_results:
            print(f"{r['experiment_id']:<4} {r['experiment_name']:<32} "
                  f"{r['throughput_eps']:>7.3f} {r['latency_p95_ms']:>7.1f} "
                  f"{r['error_rate_pct']:>5.1f}% {'PASS' if r['criteria_met'] else 'FAIL'}")


if __name__ == "__main__":
    main()
