# Experiment Plan

**Thesis:** Immutable Audit Layer for IoT Safety Data in Construction Sites  
**Institution:** Politecnico di Torino

## Overview

The experiments validate the prototype against the functional requirements (RF1–RF6) and non-functional requirements (RNF1–RNF6). The focus is on correctness, integrity, and auditability. No throughput benchmark is claimed.

## E1 - Functional Correctness: Event Registration

**Requirements covered:** RF1, RF2

**Goal:** Verify that events are stored with a correctly validated schema and correctly computed hash.

**Procedure:**
1. Submit 10 events with known payloads via `POST /events`.
2. For each event, retrieve it via `GET /events/{event_id}` and confirm all fields match.
3. Recompute the expected hash locally and compare against the stored hash.
4. Attempt to submit the same event twice (same deterministic ID) and confirm rejection.

**Acceptance criteria:**
- 10/10 events stored with correct field values.
- 10/10 hashes match the locally computed value.
- Duplicate submission returns an error.

## E2 - Integrity Verification: PASS/FAIL Detection

**Requirements covered:** RF5

**Goal:** Verify that hash verification correctly distinguishes original payloads from tampered ones.

**Procedure:**
1. Submit 20 events with known payloads and record the canonical JSON for each.
2. Verify all 20 events with their original payloads - expect PASS for all.
3. Modify a field in 10 of the payloads (e.g., change `severity: "high"` to `"low"`).
4. Verify the 10 modified payloads - expect FAIL for all.

**Expected results:**

| Scenario | Expected |
|----------|----------|
| Original payload | PASS |
| severity changed | FAIL |
| actor_id changed | FAIL |
| ts_event changed | FAIL |
| Extra field added | FAIL |

**Acceptance criteria:**
- 20/20 original payloads: PASS.
- 10/10 tampered payloads: FAIL (zero false negatives).

## E3 - Query Correctness

**Requirements covered:** RF3

**Goal:** Verify that queries return complete and correct results.

**Procedure:**
1. Seed the ledger with 500 synthetic events with a known distribution (workers, zones, event types, timestamps).
2. Run the following queries and compare returned counts against the known ground truth:
   - `GET /events?actor_id=W001`
   - `GET /events?zone_id=Z04`
   - `GET /events?event_type=NEAR_MISS`
   - `GET /events?severity=critical`
   - Time range query for a 1-hour window

**Metric:** Query correctness = (correct results / expected results) × 100%

**Acceptance criteria:** 100% correctness for all queries.

## E4 - Incident Scenario End-to-End

**Requirements covered:** UC2 (post-incident audit)

**Goal:** Validate the complete post-incident audit workflow from event submission to forensic report.

**Procedure:**
1. Load `simulator/scenarios/incident_day.json` (11 pre-defined events including a FALL_DETECTED).
2. Query all events for zone Z04 in the incident time window.
3. Export an audit report via `GET /audit/report?zone_id=Z04`.
4. Run batch integrity verification via `verify_integrity.py --report`.
5. Generate an audit package via `GET /audit/package?filter_type=zone_id&filter_value=Z04`.
6. Document the reconstructed event timeline: ZONE_ENTRY -> PROXIMITY_ALERT -> NEAR_MISS -> FALL_DETECTED.

**Acceptance criteria:**
- All 11 events correctly loaded and retrievable.
- Complete incident timeline reconstructable from the ledger.
- All integrity verifications pass.
- Audit report exportable as self-contained JSON.

## E5 - Non-Repudiation: Tamper Evidence (Key Demo)

**Requirements covered:** UC3 (dispute resolution)

**Goal:** Demonstrate that any modification to a recorded event is detectable.

**How to run:**

```bash
make demo-tamper
```

**Manual steps:**
1. Submit event E with `severity="high"`. Record `event_id` and `payload_hash`.
2. Store the canonical payload as `original.json`.
3. Modify `original.json` - change `severity` to `"low"`.
4. Call `POST /events/{event_id}/verify` with `original.json` - expect PASS.
5. Call `POST /events/{event_id}/verify` with the modified payload - expect FAIL.
6. Call `GET /events/{event_id}/history` - confirm only one write transaction exists.

**Expected output:**

```
[3] Verifying original payload (expected: PASS)
    Result: PASS

[5] Verifying tampered payload (expected: FAIL)
    Result: FAIL: stored=e3b0c44298fc1c14 computed=ba7816bf8f01cfea
    stored_hash : e3b0c44298fc1c149afbf4c8996fb924...
    computed    : ba7816bf8f01cfea414140de5dae2268...
```

## E6 - Batch Audit Report Integrity

**Requirements covered:** RF4

**Goal:** Verify that a complete exported audit report maintains integrity.

**Procedure:**
1. Seed 200 events and export an audit report.
2. Run `make verify-report` - expect 200 PASS results.
3. Manually modify 5 events in the exported JSON.
4. Re-run the verifier - expect 5 FAIL results and 195 PASS results.

**Metric:** Tamper detection rate = (correctly identified tampered events / total tampered) × 100%

**Acceptance criteria:** 100% detection rate.

## E7 - Access Control Validation

**Requirements covered:** RF6

**Note:** This experiment requires Fabric mode (`make up-fabric`).

**Procedure:**
1. Attempt to submit an event using an Org2 identity (read-only role).
2. Confirm that the chaincode returns an endorsement policy failure.
3. Submit the same event using the Org1 identity (Audit Gateway) - confirm success.

In stub mode this experiment is out of scope and documented as a limitation.

## Results Summary

| Experiment | Requirements | Metric | Target |
|------------|-------------|--------|--------|
| E1 | RF1, RF2 | Storage correctness | 100% |
| E2 | RF5 | Tamper detection | 100% |
| E3 | RF3 | Query correctness | 100% |
| E4 | UC2 | End-to-end audit | All steps pass |
| E5 | UC3 | Non-repudiation demo | PASS/FAIL as expected |
| E6 | RF4 | Batch verification | 100% detection |
| E7 | RF6 | Access control | Write blocked for Org2 |

## How to Run All Experiments

```bash
# Start gateway
make up-stub

# Seed data (E3, E4)
make seed

# Tamper demo (E5)
make demo-tamper

# Incident scenario (E4)
make demo-incident

# Export and batch verify (E6)
make export-report
make verify-report
```

## Limitations

- Event data is simulated and not from real construction site sensors.
- Throughput at scale is not benchmarked.
- Stub mode does not test real Fabric consensus or endorsement policy.
- Off-chain MinIO integration is partial - `evidence_uri` is optional in the prototype.
