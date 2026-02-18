# Architecture

## System Purpose

The audit layer is designed as a **multi-stakeholder accountability framework**, not a monitoring system. Its goal is to provide tamper-evident records of safety events that are credible to all parties - including the party operating the IoT infrastructure - without requiring any party to trust a single administrator.

This distinction drives every architectural decision. See `docs/accountability-framework.md` for the formal framework description and `docs/design-rationale.md` for the justification of Hyperledger Fabric over simpler alternatives.

## Component Overview

```
Construction Site

  Wearables           Cameras           IoT Gateway / SCADA
  (BLE/Zigbee)        (RTSP/AI)         (existing platform)
       |                  |                    |
       +------------------+--------------------+
                          |
                   Events (HTTP / MQTT)
                          |
                          v
             Audit Gateway (Python / FastAPI)
             - Validate event schema (Pydantic)
             - Generate deterministic event_id
             - Compute SHA-256(canonical_payload)
             - Submit transaction via Fabric Gateway SDK
             - Optionally store full payload off-chain (MinIO)

             REST API endpoints:
               POST /events
               GET  /events
               GET  /events/{id}
               GET  /events/{id}/history
               POST /events/{id}/verify
               GET  /audit/report
               GET  /audit/package
                          |
                   gRPC + mutual TLS
                          |
                          v
         Hyperledger Fabric 2.5 - Permissioned Ledger

           Org1 (Contractor)    Org2 (Inspector/Insurer)
             peer0                peer0
             CouchDB              CouchDB

           Orderer (RAFT consensus)

           Channel: mychannel
           Chaincode: auditcc (Go)
           Endorsement policy: AND(Org1MSP, Org2MSP)
                          |
                          v
         Off-chain Evidence Store (MinIO / S3)
         - Full event JSON payloads
         - Camera screenshots / video clips
         - Sensor time-series data
         Ledger stores: payload_hash + evidence_uri only
```

## Design Constraints

The architecture is shaped by three non-negotiable constraints:

**Low coupling:** The system must be attachable to any existing IoT safety platform without requiring that platform to be redesigned. The Gateway accepts a simple HTTP POST - the IoT platform does not need to know about Fabric.

**No single point of trust:** No organisation controls the ledger unilaterally. The endorsement policy requires signatures from multiple independent organisations on every write transaction. This is the property that distinguishes the system from a conventional append-only database.

**Independent verifiability:** Any party in possession of the original payload can verify any record without contacting the submitter. This is required for the records to be useful in legal and regulatory contexts.

## Data Model

### On-Chain Record (SafetyEvent)

| Field | Type | Purpose |
|---|---|---|
| `event_id` | string | Deterministic SHA-256 digest of (site, actor, ts_event, type) |
| `event_type` | enum | Classification of the safety event |
| `ts_event` | ISO-8601 | Timestamp of the physical event (from IoT platform) |
| `ts_ingest` | ISO-8601 | Timestamp set by the chaincode at commit time |
| `site_id` | string | Construction site identifier |
| `zone_id` | string | Zone within the site |
| `actor_id` | string | Worker or equipment identifier |
| `severity` | enum | low / medium / high / critical |
| `source` | enum | wearable / camera / gateway / simulator / manual |
| `payload_hash` | SHA-256 hex | Hash of the canonical JSON payload |
| `evidence_uri` | string | Pointer to off-chain full payload (MinIO URI) |
| `prev_event_hash` | string | Optional hash of previous event for actor chaining |
| `tx_id` | string | Fabric transaction ID |
| `recorded_by` | string | MSP ID of the submitting organisation |

The on-chain record does not store the full payload. It stores the hash and enough metadata to query, filter, and attribute the event. This keeps the ledger lean while ensuring any tampering of off-chain data is detectable.

### Canonical Payload (Off-Chain, Subject to Hashing)

```json
{
  "event_type": "NEAR_MISS",
  "ts_event": "2024-11-15T09:17:45+00:00",
  "site_id": "site-torino-01",
  "zone_id": "Z04",
  "actor_id": "W001",
  "severity": "high",
  "source": "camera",
  "payload_extra": {
    "clearance_m": 0.4,
    "equipment_id": "EQ-CRANE-01"
  }
}
```

Fields are serialised with sorted keys and no whitespace to ensure the hash is deterministic regardless of field insertion order.

## Data Flows

### Event Registration

```
IoT Platform
  POST /events {event_type, ts_event, actor_id, zone_id, ...}

Audit Gateway
  1. Validate schema
  2. Generate event_id = "evt-" + SHA256(site:actor:ts:type)[0:32]
  3. Build canonical_payload (fixed field set, sorted keys)
  4. payload_hash = SHA256(JSON(canonical_payload))
  5. [optional] Upload full payload to MinIO -> evidence_uri
  6. Submit RegisterEvent(event_id, ..., payload_hash, evidence_uri)

Chaincode (auditcc)
  1. Check event_id not already in state (idempotency)
  2. Read caller MSP ID
  3. Write SafetyEvent to ledger state
  4. Emit SafetyEventRecorded chaincode event

Fabric Ordering Service
  1. Order transaction into a block
  2. Set block timestamp (independent of submitter)
  3. Distribute block to all peers

Result: immutable record with multi-org endorsement and independent timestamp
```

### Integrity Verification

```
Auditor
  POST /events/{event_id}/verify
  Body: {payload_json: "<canonical JSON string>"}

Audit Gateway
  1. Compute computed_hash = SHA256(payload_json)
  2. Retrieve stored_hash from ledger via QueryEvent

Chaincode (on-chain path, alternative)
  1. GetState(event_id) -> stored_hash
  2. SHA256(payload_json) == stored_hash -> "PASS" or "FAIL: ..."

Result: PASS if payload matches; FAIL with both hashes if tampered
```

## Chaincode Functions

| Function | Transaction Type | Description |
|---|---|---|
| `RegisterEvent` | Submit | Record a new safety event; rejects duplicates |
| `QueryEvent` | Evaluate | Retrieve a single event by ID |
| `QueryByWorker` | Evaluate | CouchDB rich query by actor_id |
| `QueryByZone` | Evaluate | CouchDB rich query by zone_id |
| `QueryByEventType` | Evaluate | CouchDB rich query by event_type |
| `QueryBySeverity` | Evaluate | CouchDB rich query by severity |
| `QueryByTimeRange` | Evaluate | CouchDB range query by ts_event |
| `QueryByZoneAndTime` | Evaluate | Combined zone and time filter |
| `VerifyIntegrity` | Evaluate | Hash comparison executed on-chain |
| `GetAuditPackage` | Evaluate | Bundle with package hash for chain-of-custody |
| `GetHistory` | Evaluate | Full Fabric write history for a key |

## Access Control

| Role | Organisation | Write | Read | Verify | Export |
|---|---|:---:|:---:|:---:|:---:|
| Audit Gateway | Org1 | yes | yes | yes | yes |
| Safety Manager | Org1 | no | yes | yes | yes |
| Site Inspector | Org2 | no | yes | yes | yes |
| Insurance Adjuster | Org2 | no | yes | yes | yes |

Write access is enforced by the Fabric endorsement policy - a write transaction that does not carry valid signatures from the required MSPs will not be committed. Read access is enforced at the Gateway API layer in this prototype.

## Why CouchDB

The Fabric state database must support rich queries (filtering by actor, zone, time range) for the audit use cases. LevelDB, the default Fabric state database, supports only key-range queries. CouchDB is required for JSON field queries. All query-heavy chaincode functions depend on CouchDB being configured when the network is started.

## Related Documents

- `docs/accountability-framework.md` - Formal framework description, verification protocol, accountability matrix
- `docs/threat-model.md` - Adversary definitions, concrete threat scenarios, residual risks
- `docs/design-rationale.md` - Formal comparison with append-only database; justification for blockchain
- `docs/legal-use-cases.md` - Concrete forensic and legal scenarios with step-by-step procedures
- `docs/experiment-plan.md` - Validation experiments with acceptance criteria
- `docs/api-spec.md` - REST API reference
