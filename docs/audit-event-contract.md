# Audit Event Contract

## Purpose

This document is the formal specification of the *auditable event* unit and the *audit package* in the Immutable Audit Layer. It is the single source of truth for:

- Chaincode data structures (`SafetyEvent`, `AuditPackage`)
- Gateway validation rules (`RegisterEventRequest`)
- Canonical hashing inputs
- Chapter 4 (Implementation) data model tables
- Chapter 5 (Evaluation) storage cost measurements

---

## 1. The Auditable Event

An *auditable event* is the smallest unit of safety-relevant activity that the system records. Once committed to the Fabric ledger it cannot be modified, deleted, or reordered.

### 1.1 On-Chain Fields

These fields are stored on the Fabric ledger. The ledger is the tamper-evident witness.

| # | Field | Type | Max Size | Required | Description |
|---|---|---|---|---|---|
| 1 | `schemaVersion` | string | 3 B | Yes | Schema version for forward compatibility. Current: `"1.0"` |
| 2 | `eventId` | string | 38 B | Yes | Deterministic ID: `"evt-" + SHA256(schema:actor:ts:type:zone:nonce)[0:32]` |
| 3 | `eventType` | enum | 20 B | Yes | See EventType table (§1.4) |
| 4 | `actorId` | string | 16 B | Yes | Pseudonymised worker or equipment ID. No PII. |
| 5 | `siteId` | string | 32 B | Yes | Construction site identifier |
| 6 | `zoneId` | string | 8 B | Yes | Zone within site (e.g. `Z04`) |
| 7 | `ts` | ISO-8601 | 25 B | Yes | Event timestamp at IoT source (UTC) |
| 8 | `tsLedger` | ISO-8601 | 25 B | Yes | Block commit timestamp set by chaincode. Cannot be forged by submitter. |
| 9 | `severity` | int 0–5 | 1 B | Yes | 0 = informational, 5 = critical (see §1.5) |
| 10 | `source` | enum | 16 B | Yes | Originating sensor type (see §1.6) |
| 11 | `payloadHash` | hex string | 64 B | Yes | SHA-256 of canonical off-chain payload |
| 12 | `evidenceRef` | URI | 256 B | No | MinIO/IPFS URI of full sensor payload |
| 13 | `prevEventHash` | hex string | 64 B | No | `payloadHash` of previous event in actor chain. Empty for first event. |
| 14 | `signature` | base64 DER | ~128 B | Yes | ECDSA-P256 signature of `payloadHash` by gateway |
| 15 | `signerId` | string | 32 B | Yes | Gateway instance that signed this event |
| 16 | `signerCertFingerprint` | hex | 16 B | Yes | SHA-256[:16] of gateway public key |
| 17 | `recordedByMSP` | string | 32 B | Yes | Fabric MSP ID of the submitting organisation |
| 18 | `txId` | string | 64 B | Yes | Fabric transaction ID |

**Typical on-chain record size: ~700 B**

### 1.2 Off-Chain Fields (Canonical Payload - Hashed)

These fields are stored off-chain (MinIO) and their SHA-256 hash appears as `payloadHash` on the ledger. Any modification to any field changes the hash and is detected on verification.

Canonicalisation rules:
- Keys sorted alphabetically (recursive)
- No extra whitespace: `separators=(",", ":")`
- Unicode normalised to NFC
- Encoding: UTF-8

| Field | Type | Included in canonical hash |
|---|---|---|
| `schema_version` | string | Yes |
| `event_type` | string | Yes |
| `ts` | ISO-8601 | Yes |
| `site_id` | string | Yes |
| `zone_id` | string | Yes |
| `actor_id` | string | Yes |
| `severity` | int | Yes |
| `source` | string | Yes |
| `payload_extra` | object | Yes |
| `evidence_ref` | URI | No - may be set asynchronously after submission |
| `prev_event_hash` | string | No - stored separately on-chain |
| `nonce` | string | No - consumed in eventId generation only |

**Why `evidence_ref` is excluded from the hash**: the URI for off-chain evidence may not be known at submission time (e.g. the upload to MinIO happens asynchronously). Excluding it allows the hash to be computed and signed before the upload completes, while the URI is still stored on-chain for retrieval.

### 1.3 Event ID Generation

```
eventId = "evt-" + SHA256(schemaVersion + ":" + actorId + ":" + ts + ":" + eventType + ":" + zoneId + ":" + nonce)[0:32]
```

Properties:
- **Deterministic**: same inputs always produce the same ID
- **Idempotent**: retry with the same nonce produces the same ID, which the chaincode rejects as a duplicate without error
- **Collision-resistant**: different events produce different IDs with overwhelming probability
- **Nonce-isolated**: a new nonce generates a new ID even if all other fields are identical (supports planned re-submissions)

### 1.4 Event Types

| EventType | Severity Range | Typical Source | Description |
|---|---|---|---|
| `ZONE_ENTRY` | 0–2 | wearable, proximity_tag | Worker entered a monitored zone |
| `ZONE_EXIT` | 0–1 | wearable, proximity_tag | Worker exited a monitored zone |
| `HAZARD_ENTRY` | 2–4 | wearable, camera | Worker entered a restricted hazard zone |
| `PROXIMITY_ALERT` | 3–4 | proximity_tag, wearable | Worker within unsafe distance of equipment |
| `NEAR_MISS` | 4–5 | camera, wearable | Automated near-miss detection |
| `PPE_VIOLATION` | 2–4 | camera | Missing or non-compliant PPE |
| `EQUIPMENT_FAULT` | 3–5 | gateway | Equipment sensor fault or threshold breach |
| `FALL_DETECTED` | 5 | wearable | High-g impact (accelerometer) |
| `GAS_ALERT` | 5 | gateway | Gas concentration above threshold |
| `INTRUSION` | 3–5 | camera, proximity_tag | Unauthorised entry |
| `MANUAL_ALERT` | 3–5 | manual | Manually submitted supervisor alert |

### 1.5 Severity Scale

| Level | Label | Response |
|---|---|---|
| 0 | Informational | Log only |
| 1 | Low | Optional review |
| 2 | Medium | Supervisor notification |
| 3 | Elevated | Immediate supervisor action |
| 4 | High | Zone alert, work stop |
| 5 | Critical | Emergency response |

### 1.6 Source Types

| Source | Description |
|---|---|
| `wearable` | Body-worn sensor (helmet, vest, wristband) |
| `camera` | Fixed or PTZ camera with computer vision |
| `proximity_tag` | RFID/UWB proximity sensor on equipment |
| `gateway` | Environmental sensor (gas, temperature) connected to IoT hub |
| `simulator` | Synthetic event from the test simulator |
| `manual` | Manually entered by a supervisor |

---

## 2. The Audit Package

An *audit package* is a tamper-evident bundle of events produced by the chaincode in response to an audit query. It is the output unit used in post-incident investigations, insurance claims, and regulatory audits.

### 2.1 Fields

| Field | Type | Description |
|---|---|---|
| `generatedAt` | ISO-8601 | Timestamp of package generation on the chaincode |
| `filter` | string | Human-readable filter description (e.g. `zone_id=Z04 from=... to=...`) |
| `eventCount` | int | Number of events included |
| `events` | SafetyEvent[] | Full on-chain records (not the off-chain payloads) |
| `packageHash` | hex string | SHA-256 of the canonical JSON of all included events |

### 2.2 Package Hash

```
packageHash = SHA256(canonical_json(events))
```

The `packageHash` is computed by the chaincode at the time of package generation. Any verifier can:
1. Receive the package (via API, email, file)
2. Recompute `SHA256(canonical_json(package.events))`
3. Compare with `packageHash`

If they match, the package has not been modified since it was generated by the chaincode.

### 2.3 Package Usage by Role

| Role | Can Request | Purpose |
|---|---|---|
| inspector | Yes | Post-incident reconstruction, regulatory submission |
| insurer | No - requests via inspector | Insurance claim validation |
| contractor | No | Cannot self-audit (conflict of interest) |
| safety_manager | No | Operational access only |

---

## 3. Integrity Verification Protocol

Any party can verify the integrity of a safety event independently - without trusting the gateway, the contractor, or the inspector - by following this protocol:

### Step 1: Obtain the payload

Retrieve the original payload from the off-chain store (MinIO URI from `evidenceRef`), or from the IoT platform's own logs.

### Step 2: Canonicalise

```python
canonical = {k: payload[k] for k in CANONICAL_FIELDS if payload.get(k) is not None}
canonical_str = json.dumps(sorted_keys(canonical), separators=(",", ":"), ensure_ascii=False)
canonical_str = unicodedata.normalize("NFC", canonical_str)
```

Where `CANONICAL_FIELDS = [schema_version, event_type, ts, site_id, zone_id, actor_id, severity, source, payload_extra]`.

### Step 3: Hash

```python
submitted_hash = hashlib.sha256(canonical_str.encode("utf-8")).hexdigest()
```

### Step 4: Compare

```
GET /verify?event_id=<id>
Body: { "payload_hash": "<submitted_hash>" }

Response: { "result": "PASS" | "FAIL", "match": true | false, "signature_valid": true | false }
```

Or directly against the chaincode:

```
peer chaincode query -n auditcc -C audit-channel -c '{"Args":["VerifyEvent","<id>","<hash>"]}'
```

### Step 5: Validate signature

```python
from cryptography.hazmat.primitives.asymmetric import ec
public_key.verify(base64.b64decode(event.signature), event.payloadHash.encode(), ec.ECDSA(hashes.SHA256()))
```

The public key is available at `GET /pubkey` - fetch it once and store locally.

### Step 6: Check write history

```
peer chaincode query -n auditcc -C audit-channel -c '{"Args":["GetHistory","<id>"]}'
```

A legitimate record returns exactly one history entry. Two or more entries would indicate a modification attempt (blocked by Fabric at the protocol level, but visible here as forensic evidence).

---

## 4. Mapping to Thesis Chapters

| This document section | Thesis location |
|---|---|
| §1.1 On-Chain Fields table | Chapter 4.3 - Data Model |
| §1.2 Off-Chain Fields + canonicalisation | Chapter 4.4 - Hashing and Integrity |
| §1.3 Event ID generation | Chapter 4.4 - Idempotency |
| §2.1 Audit Package fields | Chapter 4.5 - Audit Package |
| §3 Verification protocol | Chapter 5 - Evaluation (E2, E6 experiments) |
| §1.4 Event types | Appendix A |
