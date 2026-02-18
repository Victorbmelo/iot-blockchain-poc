# Data Model

## Overview

The data model separates what goes on-chain (minimal, immutable, hashable) from what stays off-chain (full sensor payload, evidence files). This separation is a deliberate design choice: the Fabric ledger is not an event store — it is a tamper-evident witness registry.

## Entities

### Worker (off-chain, IoT platform)

Represents a construction site worker. Only a pseudonymised ID appears on-chain.

| Field | Type | Description |
|---|---|---|
| `worker_id` | string | Pseudonymised ID (e.g. W001). Never contains PII |
| `role` | enum | WORKER, SUPERVISOR, INSPECTOR, EQUIPMENT_OPERATOR |
| `site_id` | string | Site assignment |
| `ppe_profile` | object | Required PPE for this worker's role (off-chain only) |

The mapping from `worker_id` to real identity is stored in the HR system, not on the ledger. This satisfies GDPR pseudonymisation requirements (Art. 4(5)).

### Zone (off-chain, IoT platform)

A named area within the construction site with an associated risk level.

| Field | Type | Description |
|---|---|---|
| `zone_id` | string | Short code (e.g. Z04) |
| `name` | string | Human-readable name (e.g. "Crane Operation Zone") |
| `risk_level` | enum | LOW, MEDIUM, HIGH, CRITICAL |
| `geofence` | GeoJSON | Polygon defining the zone boundary |
| `restricted` | bool | Whether PPE and access authorisation are required |

### SafetyEvent (on-chain + off-chain)

The core entity. The on-chain record contains metadata and the hash. The full payload is stored off-chain.

#### On-Chain Fields (Ledger — immutable after commit)

| Field | Type | Size | Description |
|---|---|---|---|
| `schemaVersion` | string | 3 B | Schema version for forward compatibility |
| `eventId` | string | 38 B | `"evt-"` + SHA-256(schemaVersion:actor:ts:type:zone:nonce)[0:32] |
| `eventType` | enum | ≤20 B | See EventType table below |
| `actorId` | string | ≤16 B | Pseudonymised worker or equipment ID |
| `siteId` | string | ≤32 B | Site identifier |
| `zoneId` | string | ≤8 B | Zone identifier |
| `ts` | ISO-8601 | 25 B | Timestamp at event source (IoT platform clock) |
| `tsLedger` | ISO-8601 | 25 B | Timestamp at chaincode execution (orderer clock) |
| `severity` | int (0–5) | 1 B | 0=informational, 5=critical |
| `source` | enum | ≤16 B | Originating sensor type |
| `payloadHash` | SHA-256 hex | 64 B | Hash of canonical off-chain payload |
| `evidenceRef` | URI | ≤256 B | MinIO/IPFS URI of the full payload (empty if not uploaded) |
| `prevEventHash` | SHA-256 hex | 64 B | payloadHash of previous event in actor chain (empty if first) |
| `signature` | base64 DER | ~96 B | ECDSA-P256 signature of payloadHash by the gateway |
| `signerId` | string | ≤32 B | Gateway identifier that signed this event |
| `signerCertFingerprint` | hex | 16 B | First 16 bytes of SHA-256 of gateway public key |
| `recordedByMSP` | string | ≤32 B | Fabric MSP ID of the submitting organisation |
| `txId` | string | 64 B | Fabric transaction ID |

Typical on-chain record size: ~700 B per event.

#### Off-Chain Fields (MinIO — hashed, not immutable)

| Field | Type | Description |
|---|---|---|
| `schema_version` | string | Must match on-chain schemaVersion |
| `event_type` | string | Must match on-chain eventType |
| `ts` | ISO-8601 | Must match on-chain ts |
| `site_id` | string | Must match on-chain siteId |
| `zone_id` | string | Must match on-chain zoneId |
| `actor_id` | string | Must match on-chain actorId |
| `severity` | int | Must match on-chain severity |
| `source` | string | Must match on-chain source |
| `payload_extra` | object | Sensor-specific data (see examples below) |

The SHA-256 of the canonical JSON serialisation of these fields (sorted keys, no whitespace) must equal `payloadHash` on-chain. Any modification to any field — including `payload_extra` — will cause verification to fail.

### EvidenceRecord (off-chain, MinIO)

Full evidence bundle associated with an event. Not always present (depends on sensor capability).

| Field | Type | Description |
|---|---|---|
| `event_id` | string | Links to the on-chain SafetyEvent |
| `media_type` | enum | IMAGE, VIDEO, SENSOR_LOG, TELEMETRY |
| `uri` | string | MinIO object URI (stored in on-chain evidenceRef) |
| `content_hash` | SHA-256 | Hash of the raw media file |
| `captured_at` | ISO-8601 | Timestamp of media capture |
| `device_id` | string | Camera or sensor hardware ID |

## Event Types

| EventType | Severity Range | Typical Source | Description |
|---|---|---|---|
| `ZONE_ENTRY` | 0–2 | wearable, proximity_tag | Worker entered a monitored zone |
| `ZONE_EXIT` | 0–1 | wearable, proximity_tag | Worker exited a monitored zone |
| `HAZARD_ENTRY` | 2–4 | wearable, camera | Worker entered a restricted hazard zone |
| `PROXIMITY_ALERT` | 3–4 | proximity_tag, wearable | Worker within unsafe distance of equipment |
| `NEAR_MISS` | 4–5 | camera, wearable | Automated detection of near-miss incident |
| `PPE_VIOLATION` | 2–4 | camera | Missing or incorrect PPE detected |
| `EQUIPMENT_FAULT` | 3–5 | gateway | Equipment sensor fault or safety threshold breach |
| `FALL_DETECTED` | 5 | wearable | High-g impact detected by accelerometer |
| `GAS_ALERT` | 5 | gateway | Gas sensor above threshold |
| `INTRUSION` | 3–5 | camera, proximity_tag | Unauthorised entry into restricted zone |
| `MANUAL_ALERT` | 3–5 | manual | Manually submitted alert by supervisor |

## Severity Scale

| Level | Label | Meaning | Typical Response |
|---|---|---|---|
| 0 | Informational | Normal operation event | Log only |
| 1 | Low | Minor deviation, no immediate risk | Log, optional review |
| 2 | Medium | Non-compliance noted | Supervisor notification |
| 3 | Elevated | Hazardous condition | Immediate supervisor action |
| 4 | High | Serious hazard or near-miss | Zone alert, work stop |
| 5 | Critical | Injury, imminent danger, or system fault | Emergency response |

## On-Chain vs Off-Chain Separation

```
POST /events (full payload)
        |
        v
Audit Gateway
        |
        +--- canonical_payload (subset) ---> SHA-256 --> payloadHash (on-chain)
        |
        +--- full payload + payload_extra --> MinIO --> evidenceRef (on-chain URI)
        |
        +--- payloadHash ---> ECDSA sign --> signature (on-chain)
        |
        v
Fabric Ledger
  Records: eventId, eventType, actorId, siteId, zoneId, ts, tsLedger,
           severity, source, payloadHash, evidenceRef, prevEventHash,
           signature, signerId, signerCertFingerprint, recordedByMSP, txId
```

What the ledger guarantees:
- The `payloadHash` stored on-chain has not changed since commit
- The `tsLedger` was set by the chaincode at commit time, not by the submitter
- The `recordedByMSP` identity submitted this transaction
- The `signature` was produced by the gateway with key fingerprint `signerCertFingerprint`

What the ledger does not guarantee:
- That the off-chain payload in MinIO has not been modified (but any modification is detectable via hash comparison)
- That the sensor data itself was accurate (sensor spoofing is out of scope)
- That the `ts` field reflects the true event time (it comes from the IoT platform clock)

## Payload Extra — Examples by Event Type

### FALL_DETECTED
```json
{
  "accelerometer_g": 18.4,
  "height_m": 3.2,
  "impact_detected": true,
  "emergency_triggered": true,
  "wearable_id": "WBL-07-042"
}
```

### PROXIMITY_ALERT
```json
{
  "distance_m": 0.8,
  "equipment_id": "EQ-CRANE-01",
  "equipment_state": "MOVING",
  "tag_id": "TAG-005"
}
```

### PPE_VIOLATION
```json
{
  "missing_ppe": ["helmet", "high_vis_vest"],
  "camera_id": "CAM-Z02-01",
  "confidence": 0.94
}
```

### ZONE_ENTRY / HAZARD_ENTRY
```json
{
  "gps_lat": 45.0712,
  "gps_lon": 7.6871,
  "access_authorised": false,
  "ppe_verified": false
}
```

## Composite Key Indexes (On-Chain)

Three composite key indexes are maintained in CouchDB state to support efficient range queries without full-table scans:

| Index | Key Format | Query Use Case |
|---|---|---|
| Actor-time index | `actor~ts~eventId` / `actorId:ts:eventId` | Full history of a specific worker |
| Zone-time index | `zone~ts~eventId` / `zoneId:ts:eventId` | All events in a zone during an incident window |
| Type-time index | `type~ts~eventId` / `eventType:ts:eventId` | All NEAR_MISS or FALL_DETECTED events in a period |

These indexes enable O(log n) range scans rather than O(n) full ledger scans, which is significant when the ledger contains tens of thousands of events.

## Storage Estimates

| Component | Per Event | 10,000 Events |
|---|---|---|
| Ledger state (on-chain) | ~700 B | ~7 MB |
| Ledger history (all versions) | ~700 B | ~7 MB |
| CouchDB indexes | ~200 B | ~2 MB |
| MinIO payload (off-chain) | ~2–10 KB | ~20–100 MB |
| MinIO evidence media | 0–10 MB | 0–100 GB |

The ledger footprint is deliberately small. The Fabric ledger is not designed for large binary payloads — only the tamper-evident metadata and hashes reside there.
