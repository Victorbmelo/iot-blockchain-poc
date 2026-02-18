# Legal and Forensic Use Cases

## Purpose

This document describes how the audit layer is used by different stakeholders in real legal and investigative contexts. It is intended to answer the question: "How does an auditor, insurer, or lawyer actually use this system?"

The system's primary value is not real-time monitoring - it is post-incident accountability. This document makes that value concrete.

## Stakeholder Roles

| Stakeholder | Role in the System | Access Level |
|---|---|---|
| Safety Manager (Contractor) | Operates the IoT platform; triggers Gateway submissions | Write + Read |
| Site Inspector (Regulator) | Verifies that safety rules were followed | Read + Export |
| Insurance Adjuster | Validates incident timeline for claim processing | Read + Export |
| Legal Counsel | Requests audit packages for litigation | Read + Export |
| Forensic Investigator | Performs independent integrity verification | Read + Verify |

## Use Case LC1 - Post-Incident Investigation (Inspector)

**Context:** A worker falls from scaffolding at 10:45 on 15 November 2024. The contractor claims the zone had no prior alerts that day. The site inspector needs to determine whether the contractor knew of hazardous conditions before the fall.

**Step 1 - Reconstruct the event timeline**

The inspector queries all events in zone Z02 (Scaffolding Area) for the day of the incident:

```bash
curl "http://gateway/events?zone_id=Z02&start_ts=2024-11-15T00:00:00Z&end_ts=2024-11-15T23:59:59Z"
```

The ledger returns a chronological record showing:
- 07:00 - ZONE_ENTRY, actor W007, source: wearable
- 07:30 - PPE_VIOLATION, actor W005, helmet missing, source: camera
- 10:45 - FALL_DETECTED, actor W007, accelerometer: 18.4g, source: wearable
- 10:45 - MANUAL_ALERT, actor W010, "W007 fell from level 2"

**Step 2 - Export a signed audit package**

```bash
curl "http://gateway/audit/report?zone_id=Z02" > incident_report_Z02.json
```

The report includes:
- All events matching the filter
- The `payload_hash` of each event
- The `tx_id` of each Fabric transaction
- The `recorded_by` MSP identity for each record
- A `package_hash` covering the entire bundle

**Step 3 - Verify report integrity**

The inspector can independently verify that the report has not been modified since export:

```bash
python3 verify_integrity.py --report incident_report_Z02.json
```

Expected output: all events PASS. If the contractor modified the exported JSON before handing it over, at least one event will FAIL.

**Step 4 - Present findings**

The inspector presents the audit package as evidence that:
1. A PPE violation was recorded at 07:30, 3 hours before the fall.
2. The contractor's IoT platform detected and logged the violation (source: camera, recorded_by: Org1MSP).
3. The record has not been modified since it was submitted to the ledger (hash verification passes).
4. The Fabric transaction ID can be independently cross-referenced against the blockchain explorer.

**Outcome:** The ledger provides a tamper-evident timeline that contradicts the contractor's claim of no prior alerts.

## Use Case LC2 - Insurance Claim Validation (Adjuster)

**Context:** The contractor files an insurance claim for worker W007's fall. The insurer needs to determine:
- Whether the incident actually occurred at the claimed time
- Whether the contractor took reasonable precautions
- Whether any negligence contributed to the incident

**Step 1 - Retrieve the worker's full event history**

```bash
curl "http://gateway/events?actor_id=W007"
```

The insurer sees the complete record of W007's movements and alerts across all zones and dates. This establishes context: how often was W007 in high-risk zones, and were there prior proximity alerts?

**Step 2 - Retrieve the zone history for Z02**

```bash
curl "http://gateway/audit/package?filter_type=zone_id&filter_value=Z02"
```

The audit package shows all events for the zone across all dates. The insurer can identify patterns: was Z02 consistently generating PPE violations? Were prior near-misses recorded?

**Step 3 - Verify that the FALL_DETECTED event is authentic**

The insurer independently re-derives the expected payload hash:

```python
import hashlib, json

payload = {
    "event_type": "FALL_DETECTED",
    "ts_event": "2024-11-15T10:45:00+00:00",
    "site_id": "site-torino-01",
    "zone_id": "Z02",
    "actor_id": "W007",
    "severity": "critical",
    "source": "wearable",
    "payload_extra": {
        "accelerometer_g": 18.4,
        "height_m": 3.2,
        "impact_detected": True,
        "emergency_triggered": True
    }
}
canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
print(hashlib.sha256(canonical.encode()).hexdigest())
```

The computed hash must match the `payload_hash` stored on the ledger. If it does, the insurer has independent cryptographic confirmation that the wearable sensor reported these exact values at the claimed time.

**Step 4 - Assess contractor compliance**

The insurer reviews the PPE_VIOLATION event (07:30, same zone, same day) and determines that the contractor was aware of a PPE non-compliance 3 hours before the fall and did not remove the worker from the zone. This affects the liability assessment.

**Outcome:** The ledger provides the insurer with an independently verifiable, tamper-evident record of both the incident and the prior conditions - without relying on the contractor to provide honest records.

## Use Case LC3 - Dispute Resolution (Legal Counsel)

**Context:** The contractor's legal counsel disputes the validity of the audit log, claiming the records were fabricated by the site inspector after the fact.

**Claim by contractor's counsel:** "The event records were inserted into the system retrospectively to implicate our client."

**Rebuttal using the audit layer:**

**Step 1 - Show the Fabric transaction timestamp**

Each on-chain record contains a `tx_id`. The corresponding Fabric block contains a cryptographically signed timestamp set by the ordering service at the time of transaction commit. This timestamp cannot be retroactively altered without rewriting the entire blockchain from that block forward, which requires collusion of all ordering nodes.

The inspector presents: "The FALL_DETECTED event has transaction ID `abc123`. This transaction is recorded in block 47 of the `mychannel` ledger. Block 47 was committed at 10:45:01 on 15 November 2024, as shown by the block header timestamp signed by the RAFT ordering service."

**Step 2 - Show the write history**

```bash
curl "http://gateway/events/evt-abc123/history"
```

The Fabric history API returns the complete write history for the event key. If only one write transaction exists (the original submission), this refutes the claim that the record was inserted later - an after-the-fact insertion would require a second write, which is rejected by the chaincode's idempotency check.

**Step 3 - Show the source chain of custody**

The `recorded_by` field identifies the submitting MSP as `Org1MSP` (the Audit Gateway operated by the safety manager). The `source` field identifies the originating sensor as `wearable`. The `evidence_uri` points to the raw sensor log stored in MinIO, whose hash also matches the on-chain `payload_hash`.

The chain of custody is: physical wearable sensor → IoT platform → Audit Gateway (Org1MSP) → Fabric ledger (endorsed by Org1 and Org2) → immutable block.

**Step 4 - Demonstrate that retroactive insertion is technically impossible**

If the inspector had inserted the event after the fact, the contractor's Org2 peer would have had to endorse the transaction. The endorsement policy requires signatures from both Org1 and Org2. The contractor cannot claim the record was fabricated unilaterally by the inspector - their own organisation's peer endorsed it.

**Outcome:** The multi-party endorsement policy provides non-repudiation. Neither party can unilaterally claim the records are fabricated, because both parties' organisations signed every transaction.

## Use Case LC4 - Regulatory Compliance Audit (External Regulator)

**Context:** The national workplace safety authority (INAIL in Italy) is auditing the construction site's compliance with EU OSH Directive 89/391/EEC and ISO 45001. They request evidence that safety incidents were recorded, reported, and acted upon.

**Step 1 - Export the full site audit report**

```bash
curl "http://gateway/audit/report" > site_audit_full.json
```

**Step 2 - Filter by near-miss and fall events**

```bash
curl "http://gateway/events?event_type=NEAR_MISS"
curl "http://gateway/events?event_type=FALL_DETECTED"
```

**Step 3 - Verify completeness and integrity**

The regulator runs the batch verifier against the exported report:

```bash
python3 verify_integrity.py --report site_audit_full.json
```

**Step 4 - Cross-reference with incident reports**

The regulator compares the on-chain event log against the contractor's paper incident reports. Discrepancies (events on the ledger with no corresponding paper report) indicate unreported incidents.

**Outcome:** The audit layer provides the regulator with an independent, tamper-evident log that the contractor cannot modify retroactively, satisfying the record-keeping requirements of ISO 45001 clause 10.2.

## Formal Chain of Custody

For the audit package to be admissible as forensic evidence, it must satisfy the chain of custody requirements: origin, integrity, and continuity must be demonstrable.

| Requirement | How the system satisfies it |
|---|---|
| **Origin** - who created the record | `recorded_by` (MSP identity) + `source` (sensor type) |
| **Integrity** - record was not altered | SHA-256 payload hash verified against ledger |
| **Continuity** - record was in custody since creation | Fabric block timestamp + write history (single write) |
| **Authenticity** - record reflects real events | Multi-org endorsement + sensor provenance chain |

These four properties correspond to the standard legal requirements for digital forensic evidence under ISO/IEC 27037 (Guidelines for Identification, Collection, Acquisition, and Preservation of Digital Evidence).
