# Threat Model

## Purpose

This document defines the threat model for the Immutable Audit Layer. It identifies who the adversaries are, what assets are being protected, what concrete threats are addressed, and what is explicitly out of scope. A clear threat model is a prerequisite for any security claim made in this thesis.

## Assets

The following assets require protection:

| Asset | Description | Value |
|---|---|---|
| Safety event record | The on-chain record of a safety incident | Primary — basis of legal accountability |
| Payload integrity | The guarantee that a stored payload was not modified after submission | Primary — required for non-repudiation |
| Submission timestamp | The time at which an event was recorded by the ledger | High — determines legal timeline |
| Submitter identity | The MSP identity of the organisation that submitted a record | High — required for attribution |
| Audit report | The exported bundle of events used in investigation | High — forensic evidence |

## Trust Boundaries

The system operates across three distinct trust zones:

**Zone 1 — Trusted at submission time**  
The Audit Gateway and the IoT platform feeding it. Within this zone, events are assumed to arrive with correct metadata. The ledger cannot verify whether the sensor data itself is accurate — only that what was submitted was not later modified.

**Zone 2 — Mutually distrusted**  
The organisations participating in the Fabric network (contractor, inspector, insurer). No single organisation is trusted by the others. The ledger is the shared source of truth precisely because it requires multi-party endorsement.

**Zone 3 — Untrusted**  
External parties with no Fabric identity: attackers, unauthenticated API clients, and anyone attempting to query without a valid certificate.

## Adversary Model

### Adversary A1 — Malicious Contractor (Insider)

**Who:** The main contractor whose worker caused an incident. They have write access to the IoT platform and possibly to the Audit Gateway.

**Motivation:** Avoid legal liability by modifying, deleting, or backdating event records after an incident.

**Capabilities:**
- Full administrative access to the IoT monitoring platform
- Ability to modify the IoT database before the event reaches the ledger
- Ability to tamper with off-chain evidence files (MinIO)
- No direct access to the Fabric ledger after the Gateway MSP cert is issued

**What they can do:**
- Modify off-chain payload files after submission
- Attempt to re-submit a modified event with the same ID (replay with altered data)
- Attempt to delete or overwrite on-chain records

**What the system prevents:**
- Re-submission of a modified event with the same ID is rejected (idempotency check)
- On-chain records cannot be deleted or overwritten — Fabric is append-only
- Off-chain payload tampering is detected by `VerifyIntegrity` (hash mismatch)

**Residual risk:** If the contractor tampers with the IoT platform *before* the Gateway submits the event, the ledger records a false event. Mitigation: deployment requires the Gateway to be operated by a neutral party (e.g., the insurer or a third-party auditor), not the contractor.

### Adversary A2 — Malicious Platform Administrator

**Who:** An IT administrator who controls the server running the Audit Gateway or the IoT platform database.

**Motivation:** Suppress evidence of negligence or receive a bribe from the contractor.

**Capabilities:**
- Root access to the Gateway server
- Ability to modify the off-chain evidence store (MinIO)
- Access to Gateway private keys (if key management is poor)

**What they can do:**
- Modify or delete off-chain payload files
- Attempt to forge a new on-chain record (requires valid MSP cert)

**What the system prevents:**
- Off-chain modification is detected by hash verification
- On-chain records cannot be retroactively altered, even with the Gateway private key
- The Fabric endorsement policy requires signatures from multiple organisations — a single compromised Gateway key is insufficient to alter existing records

**Residual risk:** A compromised Gateway key could submit new fraudulent events. Mitigation: Gateway certificate rotation and anomaly detection on submission patterns (out of scope for prototype).

### Adversary A3 — Colluding Organisations

**Who:** Two or more Fabric network participants (e.g., contractor + insurer) acting together.

**Motivation:** Jointly suppress or alter evidence to avoid liability.

**Capabilities:**
- Control over their respective peer nodes
- Ability to attempt to fork the channel state

**What the system prevents:**
- Fabric's RAFT-based ordering service requires a majority of orderer nodes to agree on each block. A minority coalition cannot rewrite history.
- The more independent organisations added to the network, the higher the collusion threshold.

**Residual risk:** If all organisations collude, the ledger can be forked. This is an inherent property of all permissioned blockchains and is addressed by the trust model assumption: at least one organisation has an incentive to preserve the correct record (e.g., the insurer).

### Adversary A4 — External Attacker

**Who:** An external party with no Fabric identity, attempting to read or write records.

**Capabilities:**
- Network-level access to the Gateway API
- Ability to send crafted HTTP requests

**What the system prevents:**
- The Gateway API validates all input schemas (Pydantic). Malformed requests are rejected with 422.
- In production, the Gateway API is not exposed to the public internet — it sits behind the organisation's network perimeter.
- Fabric peer communication requires mutual TLS authentication.

## Concrete Threat Scenarios

| ID | Threat | Affected Asset | Attack Vector | System Response |
|---|---|---|---|---|
| T1 | Contractor modifies severity of a near-miss from "high" to "low" | Payload integrity | Off-chain file edit | Hash mismatch on next VerifyIntegrity call |
| T2 | Platform admin deletes a FALL_DETECTED event from the IoT database | Event record | Database delete | Event remains on ledger; deletion only affects raw IoT data, not the audit record |
| T3 | Contractor re-submits a backdated event to overwrite an existing record | Submission timestamp | POST /events with same event_id | Idempotency check — chaincode rejects duplicate IDs |
| T4 | Gateway admin forges a new event claiming a worker was in a safe zone at time of incident | Submitter identity | Direct Fabric submit with valid cert | RecordedBy field identifies the submitting MSP; anomaly requires cert compromise, which is auditable via PKI logs |
| T5 | Attacker replays an old valid event to inflate hazard count | Event record | POST /events with copied payload | Deterministic event_id derived from (site, actor, ts_event, type) — same event produces same ID, rejected as duplicate |
| T6 | Insurer modifies the exported audit_report.json before presenting it in court | Audit report | File edit | Package hash of the report computed at export time; independent re-export from ledger produces the same hash |

## What the System Does Not Protect Against

The following threats are explicitly out of scope for this prototype:

- **Sensor spoofing:** If the physical sensor sends false data (e.g., a worker bypasses a wearable), the ledger faithfully records the false event. The system cannot validate ground truth.
- **Gateway key compromise before first use:** If an attacker obtains the Gateway private key before deployment, they could submit fraudulent events. Mitigated by HSM-backed key storage in production.
- **Network-level attacks:** DDoS, BGP hijacking, and similar network-layer threats are out of scope. The system assumes a protected network perimeter.
- **Social engineering:** Convincing a legitimate operator to submit a false event is a human process vulnerability, not a system vulnerability.
- **Timestamp accuracy:** The system records `ts_ingest` at the moment the chaincode executes. If the peer node's clock is wrong, the timestamp is wrong. Mitigated by NTP synchronisation of all peer nodes.

## Why This Threat Model Matters for the Thesis

The central claim of this thesis is that the audit layer provides stronger guarantees than a conventional append-only database. The threat model makes this claim precise:

A conventional database with an append-only flag controlled by a single administrator (A2) can be bypassed by that administrator. A Fabric ledger with multiple endorsing organisations cannot be unilaterally modified by any single participant — including the administrator who deployed it.

This is the concrete security property that justifies the use of a permissioned blockchain over a simpler append-only store. See `docs/design-rationale.md` for the formal comparison.
