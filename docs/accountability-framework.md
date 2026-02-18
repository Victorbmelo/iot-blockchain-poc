# Multi-Stakeholder Accountability Framework

## Purpose

This document describes how the audit layer functions as a multi-stakeholder accountability framework, not merely as a data logging system. It defines the governance model, the roles of each participant, the verification protocol, and the properties that make the system suitable for legal and regulatory contexts.

## Framework Overview

The audit layer implements what can be formally described as a **Distributed Accountability Protocol (DAP)** for construction site safety events. The protocol has three properties:

1. **Completeness:** Every safety event that passes through an authorised gateway is permanently recorded.
2. **Integrity:** No recorded event can be modified after the fact without detection by any participant.
3. **Verifiability:** Any authorised participant can independently verify any record without relying on another participant's assertion.

These three properties together enable accountability: the ability to demonstrate, to a sceptical third party, that a specific event occurred, at a specific time, as recorded by a specific source.

## Governance Model

### Network Participants

The Fabric network in this prototype includes two organisations. In a real deployment, the recommended participant set is:

| Organisation | Role | Ledger Permissions | Rationale |
|---|---|---|---|
| Main Contractor | Operates the IoT platform and Gateway | Write + Read | Responsible party; must be able to submit events |
| Safety Regulator / Inspector | Independent oversight authority | Read + Endorse | Provides independent endorsement; cannot be dismissed by contractor |
| Insurance Provider | Financial risk carrier | Read | Has financial incentive to maintain honest records |
| Project Owner / Client | Contracting authority | Read | Ultimate accountability recipient |

### Endorsement Policy

The endorsement policy is the governance rule that determines which combination of organisations must sign a transaction before it is committed to the ledger.

For this system, the recommended policy is:

```
OutOf(2, "Org1MSP", "Org2MSP", "Org3MSP")
```

This means any two of the three organisations must endorse each write. This provides:
- Resistance to a single compromised organisation
- Operational continuity if one organisation is temporarily unavailable
- Mutual non-repudiation across the network

In the prototype, a simpler `AND("Org1MSP", "Org2MSP")` policy is used for clarity.

### Who Controls What

| Action | Who can do it | Who cannot do it |
|---|---|---|
| Submit a new event | Audit Gateway (Org1) | Any unauthenticated party |
| Read any event | Any enrolled organisation | External parties |
| Modify an existing event | **Nobody** | Including the submitter |
| Delete an event | **Nobody** | Including network admins |
| Export an audit report | Any enrolled organisation | - |
| Verify integrity | Any party with the original payload | - |

The "nobody" rows are not a policy decision - they are a technical property of the Fabric ledger. There is no administrative command that rewrites committed blocks.

## Verification Protocol

The verification protocol defines the steps a third party must follow to independently confirm the authenticity and integrity of an audit record. This protocol is designed to be executable without trusting any single participant.

### Step 1 - Retrieve the on-chain record

Query the ledger for the event by ID. This can be done through any organisation's peer node - the record will be identical regardless of which peer is queried, because all peers hold the same ledger state.

```bash
curl "http://gateway/events/{event_id}"
```

Record the following fields: `payload_hash`, `tx_id`, `ts_ingest`, `recorded_by`.

### Step 2 - Obtain the original payload

Request the original payload from the off-chain evidence store (MinIO), or from the submitting organisation's records, or from the IoT platform's own logs. The source of the original payload does not matter - what matters is that any authentic copy will produce the same hash.

### Step 3 - Recompute the hash independently

Using any SHA-256 implementation and the canonical JSON serialisation rule (keys sorted alphabetically, no extra whitespace):

```python
import hashlib, json

canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
computed_hash = hashlib.sha256(canonical.encode()).hexdigest()
```

### Step 4 - Compare hashes

If `computed_hash == stored payload_hash`, the payload is authentic and unmodified.

If they differ, the payload has been modified since submission. The stored hash on the ledger is the authoritative value - it was committed by the endorsing organisations at submission time.

### Step 5 - Verify the transaction timestamp

The `tx_id` can be looked up in the Fabric block explorer to confirm the block timestamp, the endorsing organisations, and the block position. This provides independent confirmation of when the event was recorded.

### Step 6 - Check write history

```bash
curl "http://gateway/events/{event_id}/history"
```

A legitimate record will have exactly one write entry. Multiple write entries indicate attempted modifications (which the chaincode rejects, but the attempt is still visible in history).

## Accountability Matrix

The following matrix maps each accountability claim to its technical basis in the system:

| Claim | Technical Basis | Verifiable By |
|---|---|---|
| "This event occurred at time T" | `ts_ingest` in ledger record, set by chaincode at commit time | Any Fabric participant |
| "This event was recorded by organisation X" | `recorded_by` (MSP ID) in ledger record | Any Fabric participant |
| "This event's data has not been modified" | `payload_hash` matches SHA-256 of original payload | Any party with original payload |
| "This event was not inserted after the fact" | Single write in Fabric history; block timestamp predates dispute | Any Fabric participant |
| "Organisation X cannot deny submitting this event" | Org X's MSP cert signed the endorsement transaction | Any party with PKI access |
| "Organisation Y cannot claim they did not endorse this event" | Org Y's peer endorsed the transaction; signature is in the block | Any Fabric participant |
| "The audit report was not modified after export" | `package_hash` of the report matches SHA-256 of its contents | Any party re-computing the hash |

## Properties Formally Stated

**Immutability:** For any event record R committed to the ledger at time T, the state of R at any time T' > T is identical to its state at T, or any modification is detectable by any participant.

**Non-repudiation:** For any event record R endorsed by organisation X, it is computationally infeasible for X to deny having endorsed R, because X's signature is embedded in the committed block.

**Multi-party accountability:** For any event record R, at least N organisations (where N is defined by the endorsement policy) have collectively attested to its existence and content. No single organisation's denial can invalidate this attestation.

**Independent verifiability:** For any event record R, any party in possession of the original payload can verify R's integrity without requesting assistance from the submitting organisation or any other participant.

## Distinction from a Logging System

A logging system records events. This framework provides accountability for events. The distinction is:

- A log records what happened.
- An accountability framework provides cryptographic evidence, attributable to identifiable parties, that can be presented to a third party who was not present and does not trust any single witness.

The accountability framework adds three things that a log does not have:
1. **Attribution:** Each record is tied to an organisational identity, not just a username.
2. **Multi-witness attestation:** Multiple independent organisations attest to each record.
3. **Independent verifiability:** Any party can verify the record without trusting the record-keeper.

These are the properties that make the system relevant in legal, regulatory, and insurance contexts.
