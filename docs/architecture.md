# Architecture

## System Boundary

This system is an **audit layer**, not a monitoring system.

| In scope | Out of scope |
|---|---|
| Tamper-evident event recording | Real-time alerting |
| Post-incident verification | Safety dashboards |
| Causal chain reconstruction | Sensor data processing |
| Integrity evidence for investigators | Worker performance tracking |

The distinction is deliberate: the system minimises complexity and avoids competing with existing safety management platforms. It adds a single property those platforms lack - post-hoc tamper detectability by independent parties.

---

## Components

### iot-sim (Python)

Synthetic event generator. Simulates a construction site with:
- 20 workers (W001-W020)
- 8 zones (Z01-Z08) with configurable risk levels
- 3 equipment units (EQ-CRANE-01, EQ-EXCAVATOR-02, EQ-LIFT-03)
- 11 event types at configurable rates

In a production deployment, this is replaced by the real IoT platform (MQTT broker, edge gateway, existing safety wearables).

### audit-gateway (FastAPI, Python)

The single entry point for event submission. Responsibilities:
1. Schema validation (EventIngest contract)
2. Canonical hashing: `event_hash = SHA256(canonical_json(fixed_fields))`
3. Persistence to Postgres
4. Batch accumulation in memory
5. On each time window: compute Merkle root -> anchor on ledger
6. Access control (role-based, X-Role header in prototype)
7. Access log for all read/verify operations

### postgres

Operational event store. Holds:
- `events` - one row per safety event including `event_hash`
- `batches` - one row per time window, `merkle_root`, `anchor_status`

Postgres is trusted by the gateway but untrusted by the verifier - the verifier treats it as potentially adversarial (recomputes all hashes from scratch).

### besu (Hyperledger Besu, CLIQUE PoA)

Permissioned blockchain. Runs the `AuditAnchor.sol` contract. Stores only:
```
batchId -> (merkleRoot, metaHash, timestamp, anchoredBy)
```
Write-once: the contract rejects duplicate `batchId` values. The gateway account must be in the `authorisedGateways` mapping.

Why Besu over Fabric: Besu starts in a single Docker container with no certificate management. The contract interface is four functions. This reduces setup friction to zero on WSL2. The ledger adapter interface (`adapter.py`) is identical for both - switching to Fabric requires implementing `FabricAdapter`, not changing any other component.

### verifier (Python)

Stateless integrity checker. For each batch:
1. Reads all events for `batch_id` from Postgres
2. Recomputes `event_hash` for each event from stored field values
3. Rebuilds the Merkle tree from recomputed hashes
4. Fetches the anchored root from Besu via `getAnchor(batchId)`
5. Compares: `recomputed_root == anchored_root` -> PASS/FAIL

The verifier does not trust Postgres. It treats stored `event_hash` values as untrusted caches and recomputes from raw fields.

---

## Data Flow

### Event submission (happy path)

```
IoT sensor
  | POST /events {event_id, ts, actor_id, site_id, zone_id,
  |               event_type, severity, source, payload}
  v
Gateway: validate schema
  | event is valid
  v
Gateway: compute payload_hash = SHA256(canonical(payload))
  |
  v
Gateway: compute event_hash = SHA256(canonical({
           schema_version, event_id, ts, actor_id, site_id,
           zone_id, event_type, severity, source, payload_hash}))
  |
  v
Postgres: INSERT INTO events (event_id, ..., event_hash)
  |
  v
BatchEngine: append to in-memory pending list
  | [background, every window_seconds]
  v
BatchEngine: close window
  leaf_hashes = [e.event_hash for e in pending]
  merkle_root = MerkleTree(leaf_hashes).root()
  meta_hash   = SHA256(canonical({batch_id, site_id, window, count}))
  |
  v
Besu: AuditAnchor.storeBatchRoot(batch_id, merkle_root, meta_hash, count, site_id)
  | tx confirmed
  v
Postgres: UPDATE batches SET anchor_status='ANCHORED', ledger_tx_id=tx_hash
```

### Batch verification (post-incident)

```
Inspector calls: POST /verify?batch_id=<id>
  |
  v
Gateway queries Postgres: SELECT * FROM events WHERE batch_id = ?
  |
  v
Gateway recomputes:
  for each event:
    recomputed_hash = SHA256(canonical({fixed_fields}))
    if recomputed_hash != stored event_hash:
      tampered.append(event_id)
  recomputed_root = MerkleTree([recomputed_hashes]).root()
  |
  v
Gateway queries Besu: AuditAnchor.getAnchor(batch_id)
  -> anchored_root
  |
  v
if recomputed_root == anchored_root and not tampered:
  return PASS
else:
  return FAIL + tampered event IDs + hash mismatch details
```

---

## Role-Based Access Control

| Role | Submit | Read Events | Verify | Access Log |
|---|---|---|---|---|
| `operator` | [OK] | - | - | - |
| `safety_manager` | - | [OK] | - | - |
| `inspector` | - | [OK] | [OK] | [OK] |
| `insurer` | - | [OK] | [OK] | - |

All read/verify operations are logged in the access log (`GET /access-log`) with role, timestamp, path, and client IP. This addresses the governance requirement: a permissioned blockchain without access logging is just a private network.

In production: replace the `X-Role` header with JWT claims (bearer token from an identity provider) or mTLS client certificate attributes mapped to roles.

---

## Batching: Design Rationale

Writing one blockchain transaction per event at 10-100 events/s would cost:
- 10 events/s x 5s anchor latency = 50 concurrent pending transactions
- Gas cost scales linearly with events
- Throughput limited by ledger commit latency (~100-2000ms per tx)

With 5-second batching:
- Maximum 2 blockchain transactions per 10 seconds regardless of event rate
- Each transaction covers N events (N = eps x window_seconds)
- Integrity is preserved: every event is a leaf in the Merkle tree anchored by that transaction
- A single tampered event in a batch of 1000 is detectable

The Merkle proof (`services/audit-gateway/app/merkle.py`) allows proving a single event's inclusion without revealing the full batch - relevant if some events are sensitive.

---

## Ledger Adapter Interface

```python
class LedgerAdapter(ABC):
    async def anchor(batch_id, merkle_root, meta_hash, event_count, site_id) -> dict
    async def get_anchor(batch_id) -> Optional[dict]
    async def health() -> dict
```

Three implementations:
- `StubAdapter` - in-memory dict (tests, local dev without Docker)
- `BesuAdapter` - Hyperledger Besu via Web3.py
- `FabricAdapter` - placeholder (not implemented)

Switching from Besu to Fabric: implement `FabricAdapter`, set `LEDGER_MODE=fabric`.
No other code changes required.
