# Immutable Audit Layer for IoT Safety Data in Construction Sites

Laurea Magistrale — Politecnico di Torino

## What This System Is

A multi-stakeholder accountability framework for construction site safety events, built on Hyperledger Fabric 2.5. It augments existing IoT safety platforms with a permissioned ledger that neither the contractor nor the inspector can alter unilaterally — because both organisations' cryptographic signatures are required on every write transaction.

The system is not a monitoring platform. Its value is post-incident: providing tamper-evident records that are credible to all parties (contractor, inspector, insurer, regulator) without requiring any party to trust a single administrator.

**Key question the system answers:** "Can this safety record have been modified after the incident?"  
**Answer the ledger provides:** No — here is cryptographic proof, endorsed by both organisations.

See `docs/design-rationale.md` for the formal comparison with append-only databases and digital signatures.

## Documentation

| Document | Contents |
|---|---|
| `docs/architecture.md` | Component diagram, data flows, chaincode functions |
| `docs/data-model.md` | Entity schema, on-chain vs off-chain fields, storage estimates |
| `docs/accountability-framework.md` | Governance model, verification protocol, accountability matrix |
| `docs/threat-model.md` | Adversaries (A1–A4), concrete threats (T1–T6), residual risks |
| `docs/design-rationale.md` | Why blockchain over append-only DB + digital signatures |
| `docs/legal-use-cases.md` | Step-by-step scenarios for inspector, insurer, legal counsel |
| `docs/experiment-plan.md` | Validation experiments with acceptance criteria |
| `docs/api-spec.md` | REST API reference |

## Architecture

```
IoT Platform / Simulators
        |  POST /events
        v
  Audit Gateway (FastAPI, Python)
  validate -> canonical hash -> ECDSA sign -> submit
        |  gRPC + mutual TLS
        v
  Hyperledger Fabric 2.5
  ┌─────────────────────────────────┐
  │  Channel: audit-channel         │
  │  Chaincode: auditcc (Go)        │
  │  Endorsement: AND(Org1, Org2)   │
  │                                 │
  │  Org1 peer + CouchDB (:5984)    │  ← AuditGatewayMSP (writer)
  │  Org2 peer + CouchDB (:6984)    │  ← InspectorMSP (endorser)
  │  Orderer (RAFT single node)     │
  └─────────────────────────────────┘
        |
        v
  MinIO (off-chain evidence store)
  Full payloads, sensor logs, video evidence
  Ledger stores: payloadHash + evidenceRef only
```

## Prerequisites

| Tool | Version | Purpose |
|---|---|---|
| Docker + Compose v2 | 24+ | All containers |
| Python | 3.11+ | Gateway, simulator, dashboard |
| Go | 1.21+ | Compiling chaincode (Fabric mode only) |
| Fabric binaries | 2.5.0 | peer, configtxgen, cryptogen (Fabric mode only) |

**Install Fabric binaries (required for Fabric mode only):**
```bash
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
export PATH=$PATH:$HOME/fabric-samples/bin
```

## Quick Start — Three Modes

### Mode 1: Stub (no Docker, no Fabric — fastest for development)

In-memory ledger. All application logic works. No blockchain, no consensus.

```bash
make install-dev
make up-stub
```

In a second terminal:
```bash
make seed              # accident + near-miss + 200 normal events
make sim-fraud         # tamper detection demo
make dashboard         # Streamlit UI at http://localhost:8501
```

### Mode 2: Docker Compose (gateway + MinIO, still stub ledger)

```bash
make up-docker
make seed
make sim-fraud
```

### Mode 3: Full Hyperledger Fabric (production-equivalent)

Start the permissioned blockchain network (2 orgs, 1 orderer, 2 peers, 2 CouchDB):

```bash
make fabric-up         # generate crypto material + start containers
make fabric-deploy     # package, install, approve, commit chaincode
make up-fabric         # start gateway connected to Fabric
make seed
make sim-fraud
make sim-rate          # throughput experiment (E7)
make export-report
make verify-report
```

**Ports in Fabric mode:**

| Service | Port | Notes |
|---|---|---|
| Audit Gateway | 8080 | REST API |
| Org1 peer | 7051 | AuditGatewayMSP |
| Org2 peer | 9051 | InspectorMSP |
| Orderer | 7050 | RAFT ordering service |
| CouchDB (Org1) | 5984 | `http://localhost:5984/_utils` |
| CouchDB (Org2) | 6984 | `http://localhost:6984/_utils` |
| MinIO | 9001 | `http://localhost:9001` |

## Simulation Scenarios

| Command | What it demonstrates |
|---|---|
| `make sim-normal` | Routine monitoring — 200 random events |
| `make sim-accident` | Causal chain: ZONE_ENTRY → PPE_VIOLATION → NEAR_MISS → FALL_DETECTED |
| `make sim-near-miss` | Escalating hazard: HAZARD_ENTRY → PROXIMITY_ALERT → NEAR_MISS |
| `make sim-fraud` | Tamper detection: submit event → alter severity → verify → FAIL |
| `make sim-replay` | Idempotency: submit same event twice → second rejected |
| `make sim-rate` | 10 tx/s for 60s → metrics CSV for Chapter 5 |

## REST API Summary

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Status, mode, schema version, signer ID |
| `/pubkey` | GET | Gateway ECDSA public key for independent signature verification |
| `/stats` | GET | Event counts grouped by type, severity, zone |
| `/metrics` | GET | Latency P50/P95/P99, throughput (tx/s), error rate |
| `/metrics/export` | POST | Write results/run_*/events.csv + metrics.csv |
| `/events` | POST | Submit event — validate, hash, sign, record on ledger |
| `/events/{id}` | GET | Retrieve a single on-chain event record |
| `/events/{id}/history` | GET | Fabric write history (1 entry = no tampering) |
| `/events/{id}/chain` | GET | Trace prevEventHash chain, detect broken links |
| `/actors/{id}/events` | GET | Paginated actor history with time range filter |
| `/zones/{id}/events` | GET | Paginated zone history with time range filter |
| `/near-misses` | GET | All NEAR_MISS events (paginated) |
| `/verify` | POST | Compare payload hash against ledger + validate signature |
| `/audit/report` | GET | Tamper-evident audit package with package hash |

## Project Structure

```
audit-layer/
├── README.md
├── Makefile
├── docker-compose.yml           -- app stack (gateway + MinIO)
├── docs/
│   ├── data-model.md            -- entity schema, on-chain vs off-chain
│   ├── architecture.md
│   ├── accountability-framework.md
│   ├── threat-model.md
│   ├── design-rationale.md
│   ├── legal-use-cases.md
│   ├── experiment-plan.md
│   └── api-spec.md
├── fabric/
│   ├── config/
│   │   ├── crypto-config.yaml   -- MSP and CA definitions
│   │   └── configtx.yaml        -- channel, genesis block, endorsement policy
│   ├── network/
│   │   ├── docker-compose-fabric.yml  -- CA, orderer, 2 peers, 2 CouchDB, CLI
│   │   └── network.sh           -- one-command: up / deploy / down / reset
│   └── chaincode/
│       └── auditcc/
│           ├── auditcc.go       -- composite keys, ACL, pagination, TraceChain
│           └── go.mod
├── gateway/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              -- all endpoints + metrics instrumentation
│       ├── schemas.py           -- SafetyEvent schema v1.0, Pydantic models
│       ├── fabric_client.py     -- Fabric Gateway SDK wrapper + in-memory stub
│       ├── hashing.py           -- canonical JSON + SHA-256 hashing
│       ├── signing.py           -- ECDSA-P256 signing + verification
│       └── metrics.py           -- latency/throughput collection + CSV export
├── dashboard/
│   ├── app.py                   -- Streamlit: timeline, verify, metrics, tamper demo
│   └── requirements.txt
├── simulator/
│   ├── generate_events.py       -- 5 scenarios + rate-based throughput simulation
│   └── scenarios/
│       └── incident_day.json
├── tests/
│   ├── test_hashing.py          -- canonical JSON, hash consistency, event ID
│   └── test_signing.py          -- ECDSA round-trip, tamper detection
├── scripts/
│   ├── up.sh                    -- start app stack (stub/docker/fabric)
│   ├── down.sh
│   ├── seed.sh
│   ├── export_audit_report.sh
│   └── verify_integrity.py
└── results/
    └── run_YYYYMMDD_HHMM/
        ├── events.csv
        └── metrics.csv
```

## Security Properties

| Property | Mechanism |
|---|---|
| Immutability | Fabric append-only ledger; chaincode idempotency check rejects overwrites |
| Non-repudiation | ECDSA-P256 signature on every event + `AND(Org1, Org2)` endorsement on every block |
| Integrity verification | SHA-256 canonical JSON — any party recomputes and compares |
| Identity attribution | `recordedByMSP` + `signerId` + `signerCertFingerprint` on every record |
| Idempotency / replay protection | `eventId = SHA256(schema:actor:ts:type:zone:nonce)` — retry-safe |
| Chain integrity | `prevEventHash` links events per actor; `TraceChain` detects broken links |
| Pseudonymisation | `actorId` is a pseudonym; PII kept out of ledger (GDPR Art. 4(5)) |
| Write access control | `writerMSPs` in chaincode; non-writers receive access denied error |

## Answering the Key Banca Question

> "Why not use an append-only database with digital signatures?"

The entity that controls a database — even an "append-only" one — can bypass application-layer constraints via direct database access, backup restoration, or administrative override. In the construction site context, the main contractor (who controls the IoT infrastructure) is the primary accountability subject after an incident.

A Fabric ledger with `AND(AuditGatewayMSP, InspectorMSP)` endorsement cannot be modified by either organisation acting alone. The proof is architectural, not procedural.

Full formal argument: `docs/design-rationale.md`

## Limitations

- Events are simulated, not from real IoT sensors (documented in `docs/experiment-plan.md`)
- Stub mode does not exercise Fabric consensus or endorsement policy — use `make fabric-up` for real validation
- Chaincode-level ABAC (attribute-based access control) is MSP-level only in this prototype
- MinIO `evidenceRef` is optional — the hash verification path is fully implemented

## References

- Hyperledger Fabric 2.5: https://hyperledger-fabric.readthedocs.io
- Fabric Gateway SDK: https://hyperledger.github.io/fabric-gateway
- ISO 45001:2018 — Occupational health and safety management systems
- ISO/IEC 27037 — Digital evidence identification and preservation
- EU OSH Directive 89/391/EEC
- FastAPI: https://fastapi.tiangolo.com
- Streamlit: https://streamlit.io
