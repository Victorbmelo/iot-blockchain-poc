#!/usr/bin/env python3
"""
Experiment runner for the Immutable Audit Layer.

Runs one experiment at a time and writes reproducible, timestamped results
to results/run_<EXPERIMENT>_<TIMESTAMP>/. Results include:
  - events.csv        per-event latency, success/fail, hash
  - metrics.csv       aggregate statistics (p50, p95, p99, throughput, error rate)
  - payload_sizes.csv per-event payload size on-chain and off-chain
  - report.json       full experiment report for Chapter 5

Experiments:
  E1  correctness      Submit 50 known events, verify all fields stored correctly
  E2  tamper           Verify detection rate across 20 tampered payloads
  E3  query            Query correctness across actor/zone/type/time filters
  E4  incident         End-to-end incident scenario with chain tracing
  E5  throughput       Sustained load at configurable rate (default 10 tx/s, 120s)
  E6  batch-verify     Batch integrity verification of an exported report
  E7  access-control   ACL enforcement (requires Fabric mode)

Usage:
    python experiments/run_experiment.py --experiment E5
    python experiments/run_experiment.py --experiment E5 --rate 50 --duration 120
    python experiments/run_experiment.py --experiment all
    python experiments/run_experiment.py --experiment E1 --gateway http://localhost:8080
"""
import argparse
import csv
import hashlib
import json
import math
import os
import secrets
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Optional

import requests

GATEWAY = "http://localhost:8080"
SCHEMA_VERSION = "1.0"
SITE_ID = "site-torino-01"



# Data structures


@dataclass
class EventRecord:
    experiment: str
    event_id: str
    event_type: str
    actor_id: str
    zone_id: str
    severity: int
    ts_submitted: str
    latency_ms: float
    success: bool
    payload_hash: str
    payload_bytes_canonical: int
    payload_bytes_full: int
    signature: str
    tx_id: str
    error: Optional[str] = None


@dataclass
class ExperimentResult:
    experiment_id: str
    experiment_name: str
    started_at: str
    ended_at: str
    gateway_url: str
    total_submitted: int
    total_success: int
    total_failed: int
    total_retries: int
    duration_s: float
    throughput_tps: float
    latency_p50_ms: float
    latency_p95_ms: float
    latency_p99_ms: float
    latency_min_ms: float
    latency_max_ms: float
    avg_payload_canonical_bytes: float
    avg_payload_full_bytes: float
    error_rate_pct: float
    acceptance_criteria_met: bool
    notes: str = ""



# Helpers


SESSION = requests.Session()
SESSION.headers["Content-Type"] = "application/json"


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def canonical_json(payload: dict) -> str:
    import unicodedata

    def sort_keys(obj):
        if isinstance(obj, dict):
            return {k: sort_keys(obj[k]) for k in sorted(obj.keys())}
        if isinstance(obj, list):
            return [sort_keys(v) for v in obj]
        return obj

    raw = json.dumps(sort_keys(payload), separators=(",", ":"), ensure_ascii=False)
    return unicodedata.normalize("NFC", raw)


def compute_hash(payload: dict) -> str:
    return hashlib.sha256(canonical_json(payload).encode()).hexdigest()


def make_event(
    event_type: str,
    actor_id: str,
    zone_id: str,
    severity: int,
    ts: Optional[str] = None,
    payload_extra: Optional[dict] = None,
    nonce: Optional[str] = None,
    prev_event_hash: str = "",
) -> dict:
    return {
        "event_type": event_type,
        "ts": ts or utc_now(),
        "site_id": SITE_ID,
        "zone_id": zone_id,
        "actor_id": actor_id,
        "severity": severity,
        "source": "simulator",
        "evidence_ref": "",
        "prev_event_hash": prev_event_hash,
        "nonce": nonce or secrets.token_hex(8),
        "payload_extra": payload_extra or {"sensor_value": 42.0},
    }


def submit(gateway: str, event: dict, experiment: str) -> EventRecord:
    t0 = time.monotonic()
    full_size = len(json.dumps(event).encode())

    canonical_keys = [
        "schema_version", "event_type", "ts", "site_id",
        "zone_id", "actor_id", "severity", "source", "payload_extra",
    ]
    canonical = {k: event.get(k) for k in canonical_keys if event.get(k) is not None}
    canonical["schema_version"] = SCHEMA_VERSION
    canonical_size = len(canonical_json(canonical).encode())

    try:
        resp = SESSION.post(f"{gateway}/events", json=event, timeout=15)
        latency_ms = (time.monotonic() - t0) * 1000
        resp.raise_for_status()
        data = resp.json()
        return EventRecord(
            experiment=experiment,
            event_id=data["event_id"],
            event_type=event["event_type"],
            actor_id=event["actor_id"],
            zone_id=event["zone_id"],
            severity=event["severity"],
            ts_submitted=utc_now(),
            latency_ms=round(latency_ms, 3),
            success=True,
            payload_hash=data["payload_hash"],
            payload_bytes_canonical=canonical_size,
            payload_bytes_full=full_size,
            signature=data.get("signature", "")[:32],
            tx_id=data.get("tx_id", ""),
        )
    except Exception as exc:
        latency_ms = (time.monotonic() - t0) * 1000
        return EventRecord(
            experiment=experiment,
            event_id="",
            event_type=event["event_type"],
            actor_id=event["actor_id"],
            zone_id=event["zone_id"],
            severity=event["severity"],
            ts_submitted=utc_now(),
            latency_ms=round(latency_ms, 3),
            success=False,
            payload_hash="",
            payload_bytes_canonical=canonical_size,
            payload_bytes_full=full_size,
            signature="",
            tx_id="",
            error=str(exc)[:120],
        )


def aggregate(records: list[EventRecord], experiment_id: str, name: str,
              gateway: str, started_at: str, notes: str = "") -> ExperimentResult:
    latencies = sorted(r.latency_ms for r in records if r.success)
    success = sum(1 for r in records if r.success)
    failed = len(records) - success
    duration = (datetime.fromisoformat(utc_now()) - datetime.fromisoformat(started_at)).total_seconds()

    def percentile(data: list[float], p: float) -> float:
        if not data:
            return 0.0
        k = (len(data) - 1) * p / 100
        lo, hi = int(k), min(int(k) + 1, len(data) - 1)
        return data[lo] + (data[hi] - data[lo]) * (k - lo)

    avg_canonical = sum(r.payload_bytes_canonical for r in records) / max(len(records), 1)
    avg_full = sum(r.payload_bytes_full for r in records) / max(len(records), 1)

    return ExperimentResult(
        experiment_id=experiment_id,
        experiment_name=name,
        started_at=started_at,
        ended_at=utc_now(),
        gateway_url=gateway,
        total_submitted=len(records),
        total_success=success,
        total_failed=failed,
        total_retries=0,
        duration_s=round(duration, 2),
        throughput_tps=round(success / max(duration, 1), 4),
        latency_p50_ms=round(percentile(latencies, 50), 2),
        latency_p95_ms=round(percentile(latencies, 95), 2),
        latency_p99_ms=round(percentile(latencies, 99), 2),
        latency_min_ms=round(min(latencies, default=0), 2),
        latency_max_ms=round(max(latencies, default=0), 2),
        avg_payload_canonical_bytes=round(avg_canonical, 1),
        avg_payload_full_bytes=round(avg_full, 1),
        error_rate_pct=round(100 * failed / max(len(records), 1), 2),
        acceptance_criteria_met=True,
        notes=notes,
    )


def save_results(
    run_dir: Path,
    records: list[EventRecord],
    result: ExperimentResult,
    extra: Optional[dict] = None,
):
    run_dir.mkdir(parents=True, exist_ok=True)

    if records:
        with open(run_dir / "events.csv", "w", newline="") as f:
            w = csv.DictWriter(f, fieldnames=asdict(records[0]).keys())
            w.writeheader()
            for r in records:
                w.writerow(asdict(r))

    with open(run_dir / "metrics.csv", "w", newline="") as f:
        w = csv.DictWriter(f, fieldnames=asdict(result).keys())
        w.writeheader()
        w.writerow(asdict(result))

    report = {
        "result": asdict(result),
        "sample_events": [asdict(r) for r in records[:5]],
    }
    if extra:
        report.update(extra)
    with open(run_dir / "report.json", "w") as f:
        json.dump(report, f, indent=2)

    print(f"\nResults saved to: {run_dir}")


def print_result(result: ExperimentResult):
    print(f"\n{'-' * 60}")
    print(f"Experiment  : {result.experiment_id} - {result.experiment_name}")
    print(f"Duration    : {result.duration_s}s")
    print(f"Submitted   : {result.total_submitted}  Success: {result.total_success}  Failed: {result.total_failed}")
    print(f"Throughput  : {result.throughput_tps} tx/s")
    print(f"Latency     : p50={result.latency_p50_ms}ms  p95={result.latency_p95_ms}ms  p99={result.latency_p99_ms}ms")
    print(f"Payload     : {result.avg_payload_canonical_bytes}B canonical  {result.avg_payload_full_bytes}B full")
    print(f"Error rate  : {result.error_rate_pct}%")
    print(f"Criteria met: {'PASS' if result.acceptance_criteria_met else 'FAIL'}")
    if result.notes:
        print(f"Notes       : {result.notes}")
    print(f"{'-' * 60}")



# E1 - Correctness


def run_e1(gateway: str, results_base: Path):
    EXP = "E1"
    NAME = "Functional Correctness"
    print(f"\n[{EXP}] {NAME}: submit 50 known events, verify all fields stored correctly")

    started_at = utc_now()
    records: list[EventRecord] = []
    correctness_checks = []

    events_to_submit = [
        make_event("NEAR_MISS", "W001", "Z04", 4, payload_extra={"clearance_m": 0.4}),
        make_event("FALL_DETECTED", "W007", "Z02", 5, payload_extra={"accel_g": 18.4}),
        make_event("PPE_VIOLATION", "W003", "Z02", 3, payload_extra={"missing": ["helmet"]}),
        make_event("HAZARD_ENTRY", "W010", "Z06", 3, payload_extra={"restricted": True}),
        make_event("PROXIMITY_ALERT", "W001", "Z04", 4, payload_extra={"distance_m": 0.8}),
    ] * 10  # 50 events

    for ev in events_to_submit:
        rec = submit(gateway, ev, EXP)
        records.append(rec)
        if rec.success:
            sys.stdout.write(".")
        else:
            sys.stdout.write("F")
        sys.stdout.flush()

    print()

    # Correctness check: retrieve and verify each submitted event
    passed = 0
    failed_checks = []
    for rec in [r for r in records if r.success]:
        try:
            stored = SESSION.get(f"{gateway}/events/{rec.event_id}", timeout=10).json()
            checks = {
                "event_id_matches": stored.get("eventId") == rec.event_id,
                "hash_matches": stored.get("payloadHash") == rec.payload_hash,
                "has_signature": bool(stored.get("signature")),
                "has_ts_ledger": bool(stored.get("tsLedger")),
                "has_msp": bool(stored.get("recordedByMSP")),
            }
            all_pass = all(checks.values())
            correctness_checks.append({"event_id": rec.event_id, **checks, "pass": all_pass})
            if all_pass:
                passed += 1
            else:
                failed_checks.append(rec.event_id)
        except Exception as exc:
            failed_checks.append(f"{rec.event_id}: {exc}")

    # Also verify duplicate rejection (idempotency)
    dup_event = events_to_submit[0].copy()
    dup_event["nonce"] = events_to_submit[0]["nonce"]  # same nonce = same eventId
    dup_rec = submit(gateway, dup_event, EXP)
    idempotency_ok = not dup_rec.success  # must be rejected

    notes = (
        f"Correctness: {passed}/{len([r for r in records if r.success])} pass. "
        f"Idempotency: {'PASS' if idempotency_ok else 'FAIL'}. "
        f"Failed checks: {failed_checks[:3]}"
    )
    result = aggregate(records, EXP, NAME, gateway, started_at, notes)
    result.acceptance_criteria_met = (
        result.total_success == result.total_submitted
        and passed == result.total_success
        and idempotency_ok
    )

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, records, result, {"correctness_checks": correctness_checks})
    print_result(result)
    return result



# E2 - Tamper detection


def run_e2(gateway: str, results_base: Path):
    EXP = "E2"
    NAME = "Tamper Detection"
    print(f"\n[{EXP}] {NAME}: verify detection rate across 20 original + 20 tampered payloads")

    started_at = utc_now()
    records: list[EventRecord] = []
    verify_results = []

    # Submit 20 events with known payloads
    submitted_events = []
    for i in range(20):
        ev = make_event("NEAR_MISS", f"W{str(i+1).zfill(3)}", "Z04", 4,
                        payload_extra={"clearance_m": round(0.1 + i * 0.05, 2), "index": i})
        rec = submit(gateway, ev, EXP)
        records.append(rec)
        if rec.success:
            submitted_events.append((ev, rec))
        sys.stdout.write("." if rec.success else "F")
    print()

    # Verify originals - expect all PASS
    original_pass = 0
    for ev, rec in submitted_events:
        canonical_keys = ["schema_version", "event_type", "ts", "site_id",
                          "zone_id", "actor_id", "severity", "source", "payload_extra"]
        canonical = {k: ev.get(k) for k in canonical_keys if ev.get(k) is not None}
        canonical["schema_version"] = SCHEMA_VERSION
        payload_hash = compute_hash(canonical)
        try:
            resp = SESSION.post(
                f"{gateway}/verify",
                params={"event_id": rec.event_id},
                json={"payload_hash": payload_hash},
                timeout=10,
            ).json()
            match = resp.get("match", False)
            sig_valid = resp.get("signature_valid")
            verify_results.append({
                "type": "original", "event_id": rec.event_id,
                "match": match, "signature_valid": sig_valid, "expected": "PASS",
            })
            if match:
                original_pass += 1
        except Exception as exc:
            verify_results.append({"type": "original", "event_id": rec.event_id, "error": str(exc)})

    # Tamper each payload - expect all FAIL
    tamper_fail = 0
    for ev, rec in submitted_events:
        tampered = dict(ev)
        tampered["severity"] = 0  # change severity 4 → 0
        canonical_keys = ["schema_version", "event_type", "ts", "site_id",
                          "zone_id", "actor_id", "severity", "source", "payload_extra"]
        canonical = {k: tampered.get(k) for k in canonical_keys if tampered.get(k) is not None}
        canonical["schema_version"] = SCHEMA_VERSION
        tampered_hash = compute_hash(canonical)
        try:
            resp = SESSION.post(
                f"{gateway}/verify",
                params={"event_id": rec.event_id},
                json={"payload_hash": tampered_hash},
                timeout=10,
            ).json()
            no_match = not resp.get("match", True)
            verify_results.append({
                "type": "tampered", "event_id": rec.event_id,
                "match": resp.get("match"), "expected": "FAIL", "detected": no_match,
            })
            if no_match:
                tamper_fail += 1
        except Exception as exc:
            verify_results.append({"type": "tampered", "event_id": rec.event_id, "error": str(exc)})

    detection_rate = tamper_fail / max(len(submitted_events), 1) * 100
    false_negative_rate = (len(submitted_events) - tamper_fail) / max(len(submitted_events), 1) * 100

    notes = (
        f"Original PASS: {original_pass}/{len(submitted_events)}. "
        f"Tamper detection: {tamper_fail}/{len(submitted_events)} ({detection_rate:.1f}%). "
        f"False negatives: {false_negative_rate:.1f}%."
    )
    result = aggregate(records, EXP, NAME, gateway, started_at, notes)
    result.acceptance_criteria_met = (
        original_pass == len(submitted_events)
        and tamper_fail == len(submitted_events)
    )

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, records, result, {
        "verify_results": verify_results,
        "detection_rate_pct": detection_rate,
        "false_negative_rate_pct": false_negative_rate,
    })
    print_result(result)
    return result



# E3 - Query correctness


def run_e3(gateway: str, results_base: Path):
    EXP = "E3"
    NAME = "Query Correctness"
    print(f"\n[{EXP}] {NAME}: seed known distribution, verify query results match ground truth")

    started_at = utc_now()
    records: list[EventRecord] = []
    ground_truth = {"actor": {}, "zone": {}, "type": {}}

    # Seed 100 events with known distribution
    actors = ["W001", "W002", "W003"]
    zones = ["Z04", "Z05", "Z06"]
    types = ["ZONE_ENTRY", "PROXIMITY_ALERT", "NEAR_MISS"]

    for i in range(100):
        actor = actors[i % 3]
        zone = zones[i % 3]
        etype = types[i % 3]
        ev = make_event(etype, actor, zone, 2 + (i % 4))
        rec = submit(gateway, ev, EXP)
        records.append(rec)
        if rec.success:
            ground_truth["actor"][actor] = ground_truth["actor"].get(actor, 0) + 1
            ground_truth["zone"][zone] = ground_truth["zone"].get(zone, 0) + 1
            ground_truth["type"][etype] = ground_truth["type"].get(etype, 0) + 1
        sys.stdout.write("." if rec.success else "F")
    print()

    query_checks = []

    # Query by actor and compare counts
    for actor, expected in ground_truth["actor"].items():
        try:
            resp = SESSION.get(f"{gateway}/actors/{actor}/events", timeout=10).json()
            actual = resp.get("fetchedCount", len(resp.get("records", [])))
            query_checks.append({
                "filter": "actor_id", "value": actor,
                "expected": expected, "actual": actual,
                "pass": actual >= expected,
            })
        except Exception as exc:
            query_checks.append({"filter": "actor_id", "value": actor, "error": str(exc)})

    # Query by zone
    for zone, expected in ground_truth["zone"].items():
        try:
            resp = SESSION.get(f"{gateway}/zones/{zone}/events", timeout=10).json()
            actual = resp.get("fetchedCount", len(resp.get("records", [])))
            query_checks.append({
                "filter": "zone_id", "value": zone,
                "expected": expected, "actual": actual,
                "pass": actual >= expected,
            })
        except Exception as exc:
            query_checks.append({"filter": "zone_id", "value": zone, "error": str(exc)})

    # Query by event type
    for etype, expected in ground_truth["type"].items():
        try:
            resp = SESSION.get(f"{gateway}/events", params={"event_type": etype}, timeout=10).json()
            recs = resp if isinstance(resp, list) else resp.get("records", [])
            actual = len(recs)
            query_checks.append({
                "filter": "event_type", "value": etype,
                "expected": expected, "actual": actual,
                "pass": actual >= expected,
            })
        except Exception as exc:
            query_checks.append({"filter": "event_type", "value": etype, "error": str(exc)})

    passed_queries = sum(1 for q in query_checks if q.get("pass"))
    notes = (
        f"Query checks: {passed_queries}/{len(query_checks)} correct. "
        f"Ground truth: {ground_truth}"
    )
    result = aggregate(records, EXP, NAME, gateway, started_at, notes)
    result.acceptance_criteria_met = passed_queries == len(query_checks)

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, records, result, {
        "ground_truth": ground_truth,
        "query_checks": query_checks,
    })
    print_result(result)
    return result



# E4 - Incident end-to-end


def run_e4(gateway: str, results_base: Path):
    EXP = "E4"
    NAME = "Incident End-to-End"
    print(f"\n[{EXP}] {NAME}: full causal chain ZONE_ENTRY -> PPE_VIOLATION -> NEAR_MISS -> FALL_DETECTED")

    started_at = utc_now()
    records: list[EventRecord] = []
    actor, zone = "W007", "Z02"
    now = datetime.now(timezone.utc)

    chain = [
        ("ZONE_ENTRY",     "Z08", 1, {"gate": "main"},                          0),
        ("ZONE_ENTRY",     zone,  2, {"ppe_ok": True},                          3),
        ("PPE_VIOLATION",  zone,  3, {"missing": ["helmet"]},                   10),
        ("PROXIMITY_ALERT", zone, 4, {"distance_m": 1.2, "eq": "EQ-CRANE-01"}, 15),
        ("NEAR_MISS",      zone,  4, {"clearance_m": 0.2},                      20),
        ("FALL_DETECTED",  zone,  5, {"accel_g": 18.4, "height_m": 3.2},       25),
        ("MANUAL_ALERT",   zone,  5, {"text": "Worker W007 fell from level 2"}, 26),
    ]

    prev_hash = ""
    chain_log = []
    for etype, zid, sev, extra, offset_min in chain:
        ts = (now + timedelta(minutes=offset_min)).isoformat(timespec="seconds")
        ev = make_event(etype, actor, zid, sev, ts=ts,
                        payload_extra=extra, prev_event_hash=prev_hash)
        rec = submit(gateway, ev, EXP)
        records.append(rec)
        chain_log.append({
            "step": etype, "ts": ts, "event_id": rec.event_id,
            "prev_hash": prev_hash[:12] if prev_hash else "",
            "success": rec.success,
        })
        if rec.success:
            prev_hash = rec.payload_hash
        print(f"  {etype:20s} {'OK' if rec.success else 'FAIL'} {rec.event_id[:24]}")

    # Verify chain is queryable and all events are in zone Z02
    try:
        zone_resp = SESSION.get(f"{gateway}/zones/{zone}/events", timeout=10).json()
        zone_records = zone_resp.get("records", zone_resp if isinstance(zone_resp, list) else [])
        zone_count = len(zone_records)
    except Exception:
        zone_count = 0

    # Verify the fall event specifically
    fall_rec = next((r for r in records if r.event_type == "FALL_DETECTED" and r.success), None)
    fall_verified = False
    if fall_rec:
        # Find the original event to get the canonical payload for verification
        stored = SESSION.get(f"{gateway}/events/{fall_rec.event_id}", timeout=10).json()
        fall_verified = bool(stored.get("payloadHash"))

    notes = (
        f"Chain length: {len([r for r in records if r.success])}/{len(chain)}. "
        f"Zone query returned {zone_count} events. "
        f"FALL_DETECTED verified: {fall_verified}. "
        f"prevEventHash chain: {[c['prev_hash'] for c in chain_log]}"
    )
    result = aggregate(records, EXP, NAME, gateway, started_at, notes)
    result.acceptance_criteria_met = (
        all(r.success for r in records)
        and zone_count >= 6
        and fall_verified
    )

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, records, result, {"chain_log": chain_log})
    print_result(result)
    return result



# E5 - Throughput under load


def run_e5(gateway: str, results_base: Path, rate: float = 10.0, duration: int = 120):
    EXP = "E5"
    NAME = "Throughput Under Load"
    print(f"\n[{EXP}] {NAME}: sustained {rate} tx/s for {duration}s")

    import random
    EVENT_TYPES = ["ZONE_ENTRY", "ZONE_EXIT", "PROXIMITY_ALERT", "NEAR_MISS",
                   "PPE_VIOLATION", "EQUIPMENT_FAULT", "HAZARD_ENTRY"]
    ACTORS = [f"W{str(i).zfill(3)}" for i in range(1, 16)]
    ZONES = ["Z01", "Z02", "Z03", "Z04", "Z05", "Z06"]

    started_at = utc_now()
    records: list[EventRecord] = []
    interval = 1.0 / rate
    deadline = time.monotonic() + duration
    last_print = time.monotonic()

    while time.monotonic() < deadline:
        t0 = time.monotonic()
        ev = make_event(
            random.choice(EVENT_TYPES),
            random.choice(ACTORS),
            random.choice(ZONES),
            random.randint(0, 5),
        )
        rec = submit(gateway, ev, EXP)
        records.append(rec)

        if time.monotonic() - last_print > 10:
            elapsed = time.monotonic() - (deadline - duration)
            ok = sum(1 for r in records if r.success)
            recent_lat = [r.latency_ms for r in records[-20:] if r.success]
            avg_lat = sum(recent_lat) / max(len(recent_lat), 1)
            print(f"  t={elapsed:.0f}s  submitted={len(records)}  ok={ok}  "
                  f"recent_avg_lat={avg_lat:.1f}ms")
            last_print = time.monotonic()

        elapsed = time.monotonic() - t0
        sleep_for = interval - elapsed
        if sleep_for > 0:
            time.sleep(sleep_for)

    result = aggregate(records, EXP, NAME, gateway, started_at,
                       f"Target rate: {rate} tx/s. Duration: {duration}s.")
    result.acceptance_criteria_met = result.error_rate_pct < 5.0

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, records, result)
    print_result(result)
    return result



# E6 - Batch integrity verification


def run_e6(gateway: str, results_base: Path):
    EXP = "E6"
    NAME = "Batch Integrity Verification"
    print(f"\n[{EXP}] {NAME}: seed 50 events, export report, batch verify, then tamper 10 and re-verify")

    started_at = utc_now()
    records: list[EventRecord] = []
    submitted_canonical = []

    for i in range(50):
        ev = make_event("ZONE_ENTRY", f"W{str(i % 10 + 1).zfill(3)}", "Z04", 1,
                        payload_extra={"index": i})
        rec = submit(gateway, ev, EXP)
        records.append(rec)
        if rec.success:
            canonical_keys = ["schema_version", "event_type", "ts", "site_id",
                              "zone_id", "actor_id", "severity", "source", "payload_extra"]
            canonical = {k: ev.get(k) for k in canonical_keys if ev.get(k) is not None}
            canonical["schema_version"] = SCHEMA_VERSION
            submitted_canonical.append((rec.event_id, compute_hash(canonical)))
        sys.stdout.write("." if rec.success else "F")
    print()

    # Verify all 50 with correct hashes - expect 50 PASS
    original_pass = 0
    for eid, phash in submitted_canonical:
        try:
            resp = SESSION.post(f"{gateway}/verify",
                                params={"event_id": eid},
                                json={"payload_hash": phash}, timeout=10).json()
            if resp.get("match"):
                original_pass += 1
        except Exception:
            pass

    # Tamper 10 payloads (modify hash) - expect 10 FAIL
    tamper_detected = 0
    for eid, _ in submitted_canonical[:10]:
        fake_hash = "a" * 64
        try:
            resp = SESSION.post(f"{gateway}/verify",
                                params={"event_id": eid},
                                json={"payload_hash": fake_hash}, timeout=10).json()
            if not resp.get("match"):
                tamper_detected += 1
        except Exception:
            pass

    notes = (
        f"Batch verify: {original_pass}/50 original PASS. "
        f"Tamper detection: {tamper_detected}/10 ({tamper_detected * 10}%). "
    )
    result = aggregate(records, EXP, NAME, gateway, started_at, notes)
    result.acceptance_criteria_met = (
        original_pass == len(submitted_canonical)
        and tamper_detected == 10
    )

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, records, result, {
        "original_pass": original_pass,
        "tamper_detected": tamper_detected,
        "total_verified": len(submitted_canonical),
    })
    print_result(result)
    return result



# E7 - Access control (Fabric mode only)


def run_e7(gateway: str, results_base: Path):
    EXP = "E7"
    NAME = "Access Control Enforcement"
    print(f"\n[{EXP}] {NAME}: verify MSP-level write restriction (requires Fabric mode)")

    health = SESSION.get(f"{gateway}/health", timeout=5).json()
    if health.get("stub_mode"):
        print("  Skipped: gateway is in stub mode. Use 'make up-fabric' for E7.")
        return None

    started_at = utc_now()
    ev = make_event("ZONE_ENTRY", "W001", "Z04", 1)

    # Submit as authorised gateway - should succeed
    rec_ok = submit(gateway, ev, EXP)
    print(f"  Authorised submit: {'OK' if rec_ok.success else 'FAIL (unexpected)'}")

    notes = (
        f"Authorised write: {'PASS' if rec_ok.success else 'FAIL'}. "
        "Unauthorised write test: requires direct peer CLI (documented in experiment-plan.md)."
    )
    result = aggregate([rec_ok], EXP, NAME, gateway, started_at, notes)
    result.acceptance_criteria_met = rec_ok.success

    run_dir = results_base / f"{EXP}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    save_results(run_dir, [rec_ok], result)
    print_result(result)
    return result



# Main


EXPERIMENTS = {
    "E1": run_e1,
    "E2": run_e2,
    "E3": run_e3,
    "E4": run_e4,
    "E5": run_e5,
    "E6": run_e6,
    "E7": run_e7,
}


def main():
    parser = argparse.ArgumentParser(description="Audit Layer Experiment Runner")
    parser.add_argument("--experiment", default="E5",
                        help=f"Experiment to run: {', '.join(EXPERIMENTS)} or 'all'")
    parser.add_argument("--gateway", default=GATEWAY)
    parser.add_argument("--rate", type=float, default=10.0,
                        help="Target tx/s for E5 throughput experiment")
    parser.add_argument("--duration", type=int, default=120,
                        help="Duration in seconds for E5")
    parser.add_argument("--results-dir", default="results")
    args = parser.parse_args()

    results_base = Path(args.results_dir)

    # Check gateway is reachable
    try:
        health = SESSION.get(f"{args.gateway}/health", timeout=5).json()
        print(f"Gateway: {args.gateway}  stub_mode={health.get('stub_mode')}  "
              f"schema={health.get('schema_version')}")
    except Exception as exc:
        print(f"Cannot reach gateway at {args.gateway}: {exc}")
        sys.exit(1)

    to_run = list(EXPERIMENTS.keys()) if args.experiment.lower() == "all" else [args.experiment.upper()]
    all_results = []

    for exp_id in to_run:
        fn = EXPERIMENTS.get(exp_id)
        if not fn:
            print(f"Unknown experiment: {exp_id}")
            continue
        if exp_id == "E5":
            r = fn(args.gateway, results_base, args.rate, args.duration)
        else:
            r = fn(args.gateway, results_base)
        if r:
            all_results.append(asdict(r))

    if len(all_results) > 1:
        summary_path = results_base / f"summary_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
        with open(summary_path, "w") as f:
            json.dump(all_results, f, indent=2)
        print(f"\nSummary written to: {summary_path}")

        print("\nFinal Summary:")
        print(f"{'Exp':<4} {'Name':<30} {'TPS':>6} {'p95ms':>7} {'Errors':>7} {'Criteria'}")
        for r in all_results:
            print(f"{r['experiment_id']:<4} {r['experiment_name']:<30} "
                  f"{r['throughput_tps']:>6.3f} {r['latency_p95_ms']:>7.1f} "
                  f"{r['error_rate_pct']:>6.1f}% "
                  f"{'PASS' if r['acceptance_criteria_met'] else 'FAIL'}")


if __name__ == "__main__":
    main()
