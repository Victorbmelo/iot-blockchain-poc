# Architecture

## Overview

The system adds an immutable audit layer on top of existing construction site safety monitoring platforms. It does not replace sensors or central IoT platforms — it augments them with a permissioned blockchain that guarantees:

- **Immutability**: written records cannot be silently modified
- **Non-repudiation**: each record carries the MSP identity of the submitting organisation
- **Verifiability**: any authorised stakeholder can re-verify a payload hash
- **Auditability**: full query and export capabilities for forensic investigation

## Component Diagram

```
Construction Site

  Wearables (BLE/Zigbee)   Cameras (RTSP/AI)   IoT Gateway / SCADA
          |                       |                     |
          +-------------------+---+---------------------+
                              | Events (HTTP / MQTT)
                              v
  Audit Gateway (Python / FastAPI)
    1. Validate event schema (Pydantic)
    2. Generate deterministic event_id
    3. Compute SHA-256(canonical_payload)
    4. Submit transaction via Fabric Gateway SDK
    5. Store full payload off-chain (MinIO)

    REST API:
      POST /events
      GET  /events
      GET  /audit/report
      POST /events/{id}/verify
      GET  /audit/package

                              | gRPC
                              v
  Hyperledger Fabric — Permissioned Ledger

    Org1 (Contractor)   Org2 (Inspector)   Orderer (RAFT)
      peer0               peer0              orderer0
      CouchDB             CouchDB

    Channel: mychannel
    Chaincode: auditcc (Go)

                              |
                              v
  Off-chain Evidence Store (MinIO / S3)
    Full event JSON payloads
    Camera screenshots / video clips
    Sensor time-series data

    Ledger stores: payload_hash + evidence_uri only
```

## Data Flow: Event Registration

```
IoT Platform
  POST /events {event_type, ts_event, actor_id, zone_id, ...}
  |
Audit Gateway
  validate schema (Pydantic)
  event_id = SHA256(site + actor + ts + type)[0:32]
  canonical_payload = {event_type, ts_event, site_id, zone_id, actor_id, severity, source}
  payload_hash = SHA256(JSON.canonical(canonical_payload))
  [optional] upload full payload to MinIO -> evidence_uri
  submit RegisterEvent(event_id, ..., payload_hash, evidence_uri)
  |
Chaincode (auditcc)
  check event_id does not already exist (idempotency)
  write {event_id, event_type, ts_event, ts_ingest, site_id, zone_id,
         actor_id, severity, source, payload_hash, evidence_uri,
         prev_event_hash, tx_id, recorded_by(MSP)}
  PutState(event_id, record)
  |
Ledger (immutable)
```

## Data Flow: Integrity Verification

```
Auditor
  POST /events/{event_id}/verify {payload_json: "..."}
  |
Audit Gateway
  computed_hash = SHA256(payload_json)
  call VerifyIntegrity(event_id, payload_json) on chaincode
  |
Chaincode
  stored_hash = GetState(event_id).payload_hash
  if SHA256(payload_json) == stored_hash -> "PASS"
  else -> "FAIL: stored=... computed=..."
  |
Auditor receives PASS or FAIL with both hashes for comparison
```

## Access Control Model

| Role             | Org     | Write | Read | Export |
|------------------|---------|:-----:|:----:|:------:|
| Audit Gateway    | Org1    | yes   | yes  | yes    |
| Safety Manager   | Org1    | no    | yes  | yes    |
| Site Inspector   | Org2    | no    | yes  | yes    |
| Insurance Auditor| Org2    | no    | yes  | yes    |

Access control is enforced at the gateway API level in this prototype. Chaincode-level ABAC (attribute-based access control) is documented as a future extension.

## Design Decisions

**Hyperledger Fabric over public blockchains**

Fabric is permissioned, meaning only authorised organisations participate. There are no transaction fees, throughput is higher than public chains, and data can be scoped to specific channels for privacy. Rich CouchDB queries allow the complex filtering needed for forensic audit.

**Off-chain payload + on-chain hash**

Large payloads (video, sensor time-series) would bloat the ledger and make it impractical. Only the hash needs to be immutable — the ledger guarantees hash integrity, and any modification to the off-chain payload is detected by re-computing the hash.

**Canonical JSON hashing (SHA-256)**

JSON fields are sorted alphabetically and serialised without extra whitespace before hashing. This ensures the hash is deterministic regardless of the order in which fields appear in the original payload. Any auditor can verify the hash using standard tooling.

## Threat Model

| Threat | Mitigation |
|--------|-----------|
| Attacker modifies event record | Hash stored on ledger; modification detected on next verify call |
| Attacker deletes event | Fabric ledger is append-only; deletes are not supported |
| Attacker replays old event | Deterministic event_id; idempotency check rejects duplicates |
| Gateway submits false events | MSP identity recorded with each event; auditable per organisation |
| Collusion of all organisations | Requires all endorsing orgs to collude; mitigated by adding more orgs |
| Off-chain evidence tampered | payload_hash comparison detects any modification |
| Timestamp manipulation | ts_ingest is set by the chaincode at submission time, not by the client |
