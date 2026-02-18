# Threat Model

## Scope

This threat model covers the Immutable Audit Layer prototype for construction site safety data. Each threat is defined with a concrete attack vector, the system component that mitigates it, and how to verify the mitigation holds.

Out of scope: sensor spoofing (hardware-level attack), key compromise before deployment, network-layer denial-of-service.

---

## Actors

| Actor | Role | Trust Level | Controls |
|---|---|---|---|
| **Contractor** | Main contractor; operates the IoT platform and gateway | Untrusted post-incident | IoT platform, gateway process, network |
| **Safety Inspector** | Regulatory body representative | Trusted | Org2 peer, their own queries |
| **Insurer** | Insurance adjuster | Trusted (read-only) | Audit package received from inspector |
| **Regulator** | External authority | Trusted (read-only) | Independent peer (optional) |

---

## Threats and Mitigations

### T1: Malicious deletion of a safety event

**Threat**: After an incident, the contractor deletes the FALL_DETECTED or NEAR_MISS event that would establish liability.

**Attack vector**: Direct database access (conventional log system), or social engineering of the platform administrator.

**Mitigation**: Hyperledger Fabric uses an append-only ledger. Once a transaction is committed, it cannot be deleted - at the protocol level, not just the application level. Even the orderer cannot remove blocks retroactively.

**Implementation reference**:
- `fabric/network/docker-compose-fabric.yml` - ledger stored in peer volume, not in gateway
- Chaincode `RegisterEvent()` - only writes, never deletes
- `GetHistory()` chaincode function - returns full write history; zero delete entries is verifiable

**Verification command**:
```bash
# Verify no delete entries in history
curl http://localhost:8080/events/<event_id>/history
# Expected: array with isDelete=false for all entries
```

**Residual risk**: If all peer nodes are compromised simultaneously (requires collusion of both organisations) and the ledger files are directly modified. Mitigated in production by independent infrastructure for each org.

---

### T2: Payload tampering after submission

**Threat**: The contractor modifies the payload of a submitted event to reduce severity (e.g. FALL_DETECTED severity 5 → severity 1) or change the event type.

**Attack vector**: Modify the off-chain payload in MinIO, or forge a new payload with a modified field.

**Mitigation**: The SHA-256 hash of the canonical payload is stored on-chain as `payloadHash`. Any modification to any field in the payload produces a different hash, which is detected immediately on verification.

**Implementation reference**:
- `gateway/app/hashing.py` - `canonical_json()` + `compute_payload_hash()`
- `gateway/app/main.py` - hash computed before submission, never after
- `fabric/chaincode/auditcc/auditcc.go` - `VerifyEvent()` function
- `gateway/app/main.py` - `/verify` endpoint

**Verification command**:
```bash
# Submit event, then verify with tampered hash
make sim-fraud
# Expected output: FAIL: stored=... submitted=...
```

**Residual risk**: If the attacker can also modify the on-chain `payloadHash` - requires compromising both Org1 and Org2 endorsement simultaneously.

---

### T3: Event reordering or timeline manipulation

**Threat**: The contractor reorders events to make a PPE_VIOLATION appear to happen after a FALL_DETECTED (reversing the causal chain), or inserts a fabricated event at an earlier timestamp.

**Attack vector**: Modifying `ts` field of a submitted event, or submitting a backdated event with a forged timestamp.

**Mitigations**:
1. `tsLedger` - set by the chaincode at block commit time, not by the submitter. An attacker can forge `ts` (the source timestamp) but cannot forge `tsLedger`.
2. `prevEventHash` - each event references the `payloadHash` of the previous event in the actor chain. Reordering breaks the chain, which `TraceChain` detects.
3. Fabric transaction ordering - the RAFT orderer assigns a global ordering to all transactions; this ordering cannot be retroactively changed.

**Implementation reference**:
- `auditcc.go` - `TsLedger: time.Now().UTC().Format(time.RFC3339)` (line in `RegisterEvent`)
- `auditcc.go` - `TraceChain()` function
- `simulator/generate_events.py` - `run_accident()` sets `prev_event_hash` for each link

**Verification command**:
```bash
make sim-accident
# Then query the chain for actor W007
curl http://localhost:8080/events/<fall_event_id>/chain
# Expected: chain links with ChainValid=true for each step
```

**Residual risk**: `ts` forgery is not detected (it comes from the IoT platform clock). Investigators must use `tsLedger` as the authoritative timestamp. The gap between `ts` and `tsLedger` is measurable and logged.

---

### T4: Insider with write permission submitting false events

**Threat**: An authorised gateway operator submits fabricated safety events (e.g. recording a PPE_VIOLATION for a worker who was not on site) to create false evidence against a worker.

**Attack vector**: Calling `POST /events` with forged `actorId` and plausible sensor data.

**Mitigation** (partial):
1. `recordedByMSP` - the submitting organisation's MSP ID is recorded on every event. False events are traceable to the submitting organisation.
2. `signerId` + `signerCertFingerprint` - the specific gateway instance is identified on every event.
3. Endorsement policy - `AND(AuditGatewayMSP, InspectorMSP)` means the inspector peer co-endorses every write transaction. A false event would also carry the inspector's endorsement.
4. Physical corroboration - `payload_extra` includes GPS coordinates and sensor values that can be cross-checked with physical records.

**Implementation reference**:
- `auditcc.go` - `RecordedByMSP: mspID` in `RegisterEvent`
- `fabric/config/configtx.yaml` - endorsement policy definition
- `gateway/app/signing.py` - `signerCertFingerprint` binds signature to specific gateway key

**Residual risk**: This threat is partially mitigated. The system cannot prevent a determined insider from submitting false events if they have valid credentials. It provides a complete audit trail that makes such fabrication attributable and detectable by cross-referencing with physical evidence.

---

### T5: Replay attack (re-submitting an old event)

**Threat**: An attacker replays an old legitimate event (e.g. a ZONE_ENTRY) to inflate incident counts or create confusion in the audit timeline.

**Attack vector**: Capture a valid submission and re-POST it to the gateway.

**Mitigation**: The `eventId` is deterministic: `SHA256(schema:actor:ts:type:zone:nonce)`. Resubmitting the same request produces the same `eventId`, which the chaincode rejects with an idempotency error.

**Implementation reference**:
- `gateway/app/hashing.py` - `generate_event_id()`
- `auditcc.go` - `existing, err := ctx.GetStub().GetState(eventID); if existing != nil { return error }`

**Verification command**:
```bash
make sim-replay
# Expected: second submission rejected with "already exists (idempotency check)"
```

**Residual risk**: An attacker can submit a new event with the same content but a different nonce, which produces a different `eventId` and is accepted. The audit trail will show two events with identical content, which is detectable by investigators.

---

### T6: Single-organisation ledger control (centralisation attack)

**Threat**: Because the contractor controls the gateway (Org1), they could attempt to unilaterally modify the ledger state.

**Attack vector**: Restart the Org1 peer with a modified ledger database, or submit transactions without Org2 endorsement.

**Mitigation**: The Fabric endorsement policy is `AND(AuditGatewayMSP, InspectorMSP)`. Transactions without both organisations' endorsements are rejected by the ordering service. Neither organisation can unilaterally write to the channel.

**Implementation reference**:
- `fabric/config/configtx.yaml` - `LifecycleEndorsement: MAJORITY Endorsement` and `Endorsement: MAJORITY Endorsement`
- The chaincode commit step in `fabric/network/network.sh` - `--peerAddresses` includes both peers

**Residual risk**: If both organisations collude, they can modify the ledger. Mitigated in production by adding a third independent observer peer (e.g. regulator) and requiring `OutOf(2, Org1, Org2, Org3)`.

---

## Summary: Threat vs. Mitigation Matrix

| Threat | Attack Vector | Primary Mitigation | Verified By |
|---|---|---|---|
| T1 Delete event | Direct DB access | Append-only ledger | `GetHistory` - zero delete entries |
| T2 Tamper payload | Modify off-chain file | SHA-256 canonical hash | `VerifyEvent` returns FAIL |
| T3 Reorder events | Forge `ts`, backdated event | `tsLedger` + `prevEventHash` chain | `TraceChain` - ChainValid flags |
| T4 Insider false event | POST with forged actorId | `recordedByMSP` + dual endorsement | Attribution trail |
| T5 Replay attack | Re-POST old request | Deterministic `eventId` + idempotency | Second POST rejected |
| T6 Single-org control | Unilateral ledger write | `AND(Org1, Org2)` endorsement policy | Transaction rejected without dual sig |

---

## Implementation Verification Commands

All mitigations can be verified without Fabric running (stub mode covers T2, T5):

```bash
make up-stub
make sim-fraud    # verifies T2: tamper detection
make sim-replay   # verifies T5: replay rejection

# For T1, T3, T6 - requires full Fabric mode:
make fabric-up
make fabric-deploy
make up-fabric
make seed
# Then check GetHistory, TraceChain, and attempt unauthorised write via CLI
```
