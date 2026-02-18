# Immutable Audit Layer for IoT Safety Data in Construction Sites

Laurea Magistrale — Politecnico di Torino

## What This System Is

This is a multi-stakeholder accountability framework for construction site safety events. Its purpose is to provide tamper-evident records that are credible to all parties — including the party operating the IoT infrastructure.

The system addresses a specific gap: safety event logs controlled by the main contractor can be modified or suppressed after an incident, making them legally unreliable for insurance claims, regulatory investigations, and litigation. A permissioned blockchain with multi-party endorsement removes that gap. Neither the contractor nor the inspector can unilaterally alter the record, because both parties' cryptographic signatures are required on every write transaction.

See `docs/design-rationale.md` for the formal comparison with append-only databases. See `docs/accountability-framework.md` for the governance model and verification protocol.

## Documentation

| Document | Contents |
|---|---|
| `docs/architecture.md` | Component diagram, data model, data flows, chaincode functions |
| `docs/accountability-framework.md` | Governance model, verification protocol, accountability matrix |
| `docs/threat-model.md` | Adversary definitions, concrete threat scenarios (T1–T6), residual risks |
| `docs/design-rationale.md` | Why blockchain; formal comparison with append-only DB + digital signatures |
| `docs/legal-use-cases.md` | Step-by-step forensic/legal scenarios for inspector, insurer, legal counsel |
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
  Endorsement: AND(Org1MSP, Org2MSP)
  Chaincode: auditcc (Go)
  State DB: CouchDB (composite key indexes)
        |
        v
  MinIO (off-chain evidence store)
  Ledger stores: payloadHash + evidenceRef only
```

## Key Security Properties

| Property | Mechanism |
|---|---|
| Immutability | Fabric append-only ledger; PutState rejects overwrites via idempotency check |
| Non-repudiation | ECDSA signature on every event; multi-org endorsement on every block |
| Integrity verification | SHA-256 canonical JSON hash; any party can independently recompute |
| Identity attribution | `recordedByMSP` + `signerId` + `signerCertFingerprint` on every record |
| Idempotency | `eventId = SHA256(schemaVersion:actor:ts:type:zone:nonce)` — retry-safe |
| Chain integrity | `prevEventHash` links events per actor; `TraceChain` detects broken links |
| Pseudonymisation | `actorId` is a pseudonym; PII kept off-chain |

## Prerequisites

- Docker and Docker Compose v2+
- Python 3.11+ with pip
- Go 1.21+ (only for Fabric deployment mode)
- WSL2 (Windows) or Linux / macOS

For full Fabric mode:
```bash
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

## Quick Start

### Stub mode (no Docker, no Fabric)

```bash
make install-dev
make up-stub          # gateway at http://localhost:8080

# In a second terminal:
make seed             # load accident + near-miss + 200 normal events
make sim-fraud        # tamper detection demo
make dashboard        # open Streamlit UI
```

### Docker Compose

```bash
docker compose up --build
streamlit run dashboard/app.py
```

### Full Fabric

```bash
make up-fabric
make seed
make sim-fraud
```

## Simulation Scenarios

| Command | Scenario | Demonstrates |
|---|---|---|
| `make sim-normal` | 200 random events over 7 days | Normal monitoring (UC1) |
| `make sim-accident` | Entry -> PPE violation -> near-miss -> fall | Incident timeline (UC2) |
| `make sim-near-miss` | Entry -> hazard -> proximity -> near-miss | Escalating chain |
| `make sim-fraud` | Submit event, tamper severity, verify -> FAIL | Tamper detection (UC3) |
| `make sim-replay` | Submit same event twice | Idempotency protection |
| `make sim-rate` | 10 tx/s for 60s | Throughput measurement (E7) |

## REST API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Status, stub mode, schema version, signer ID |
| `/pubkey` | GET | Gateway public key PEM for signature verification |
| `/stats` | GET | Event counts by type, severity, zone |
| `/metrics` | GET | Latency (avg, P95, P99), throughput, error rate |
| `/metrics/export` | POST | Write metrics.csv + events.csv to results/ |
| `/events` | POST | Submit event — validate, hash, sign, record |
| `/events/{id}` | GET | Retrieve single event |
| `/events/{id}/history` | GET | Fabric write history (1 entry = no tampering) |
| `/events/{id}/chain` | GET | Trace prevEventHash chain backward |
| `/actors/{id}/events` | GET | Paginated actor event history |
| `/zones/{id}/events` | GET | Paginated zone event history |
| `/near-misses` | GET | All NEAR_MISS events (paginated) |
| `/verify` | POST | Verify payload hash + validate signature |
| `/audit/report` | GET | Tamper-evident audit package (hash + events) |

## Project Structure

```
audit-layer/
├── README.md
├── Makefile
├── docker-compose.yml
├── docs/
│   ├── architecture.md
│   ├── accountability-framework.md
│   ├── threat-model.md
│   ├── design-rationale.md
│   ├── legal-use-cases.md
│   ├── experiment-plan.md
│   └── api-spec.md
├── fabric/
│   └── chaincode/
│       └── auditcc/
│           ├── auditcc.go       -- composite keys, ACL, pagination, TraceChain
│           └── go.mod
├── gateway/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py              -- all endpoints + metrics instrumentation
│       ├── schemas.py           -- SafetyEvent schema v1.0
│       ├── fabric_client.py     -- Fabric SDK wrapper + stub
│       ├── hashing.py           -- canonical JSON + SHA-256
│       ├── signing.py           -- ECDSA signing + verification
│       └── metrics.py           -- latency/throughput collection + CSV export
├── dashboard/
│   ├── app.py                   -- Streamlit UI: timeline, verify, metrics, tamper button
│   └── requirements.txt
├── simulator/
│   ├── generate_events.py       -- 5 scenarios: normal/near_miss/accident/fraud/replay
│   └── scenarios/
│       └── incident_day.json
├── tests/
│   ├── test_hashing.py
│   └── test_signing.py
├── scripts/
│   ├── up.sh / down.sh / seed.sh
│   ├── export_audit_report.sh
│   └── verify_integrity.py
└── results/                     -- auto-created by metrics export
    └── run_YYYYMMDD_HHMM/
        ├── events.csv
        └── metrics.csv
```

## Thesis Chapter Mapping

| Chapter | Topic | Primary Artefacts |
|---|---|---|
| 2 | Background | docs/design-rationale.md, docs/threat-model.md |
| 3 | System design | docs/architecture.md, docs/accountability-framework.md |
| 4 | Implementation | gateway/, fabric/chaincode/, simulator/, dashboard/ |
| 5 | Evaluation | docs/experiment-plan.md, docs/legal-use-cases.md, results/ |

## Answering the Banca's Key Question

> "Why not use an append-only database with digital signatures?"

Short answer: Because the entity that controls the database (the main contractor) is the primary accountability subject. A database with a single administrator can be modified by that administrator, regardless of append-only constraints at the application layer. A Fabric ledger with `AND(Org1MSP, Org2MSP)` endorsement cannot be modified by either organisation acting alone — including the one who deployed it.

Full answer with formal comparison: `docs/design-rationale.md`.

## Limitations

- Events are simulated, not from real IoT sensors
- Stub mode does not exercise Fabric consensus or endorsement policy
- Throughput not benchmarked against large-scale production workloads
- ABAC at chaincode level is documented but not fully implemented (MSP-level ACL is)
- MinIO integration uses optional `evidenceRef` — hash verification path is complete

## References

- Hyperledger Fabric 2.5: https://hyperledger-fabric.readthedocs.io
- Fabric Gateway SDK: https://hyperledger.github.io/fabric-gateway
- ISO 45001:2018 — Occupational health and safety management systems
- ISO/IEC 27037 — Digital evidence identification and preservation
- EU OSH Directive 89/391/EEC
- FastAPI: https://fastapi.tiangolo.com
- Streamlit: https://streamlit.io
