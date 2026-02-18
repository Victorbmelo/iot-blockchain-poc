# Immutable Audit Layer for IoT Safety Data in Construction Sites

Laurea Magistrale — Politecnico di Torino

## What This System Is

This prototype implements a **multi-stakeholder accountability framework** for construction site safety events. It is not a monitoring system — its purpose is to provide tamper-evident records that are credible to all parties involved in a safety incident, including the party operating the IoT infrastructure.

The system addresses a specific gap in existing safety platforms: event logs controlled by the main contractor can be modified or suppressed after an incident, making them legally unreliable for insurance claims, regulatory investigations, and litigation. This system removes that gap by recording events on a permissioned blockchain where no single organisation can unilaterally alter the record.

**Core properties:**
- A submitted event cannot be modified or deleted by any single party
- Any authorised stakeholder can independently verify any record without trusting the submitter
- The submitting organisation's identity is permanently attached to each record
- Multi-party endorsement means neither the contractor nor the inspector can claim the records were fabricated by the other

For the formal justification of why a permissioned blockchain is necessary rather than a simpler append-only database, see `docs/design-rationale.md`.

## Documentation Map

| Document | Contents |
|---|---|
| `docs/architecture.md` | Component diagram, data model, data flows, chaincode functions |
| `docs/accountability-framework.md` | Governance model, verification protocol, accountability matrix |
| `docs/threat-model.md` | Adversary definitions, concrete threat scenarios, residual risks |
| `docs/design-rationale.md` | Why blockchain; formal comparison with append-only DB + signatures |
| `docs/legal-use-cases.md` | Concrete forensic/legal scenarios for inspector, insurer, legal counsel |
| `docs/experiment-plan.md` | Validation experiments with acceptance criteria |
| `docs/api-spec.md` | REST API reference with curl examples |

## Architecture (Summary)

```
IoT Platform / Simulators
        |  HTTP POST /events
        v
  Audit Gateway (FastAPI, Python)
  validate -> hash -> submit
        |  gRPC + mutual TLS
        v
  Hyperledger Fabric 2.5
  Channel: mychannel
  Chaincode: auditcc (Go)
  Endorsement: AND(Org1MSP, Org2MSP)
  State DB: CouchDB
        |
        v
  MinIO (off-chain evidence store)
  Full payloads, sensor logs, video evidence
```

Every write transaction requires endorsement from both the contractor's peer (Org1) and the inspector's peer (Org2). Neither can unilaterally modify the ledger.

## Prerequisites

- Docker and Docker Compose v2+
- Python 3.11+
- Go 1.21+ (only for Fabric deployment mode)
- WSL2 (Windows) or Linux / macOS
- Hyperledger Fabric samples for full Fabric mode:

```bash
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

## Quick Start

### Stub Mode (no Docker, no Fabric — fastest)

Uses an in-memory ledger. Sufficient for demonstrating all application logic.

```bash
make install-dev
make up-stub
```

In a second terminal:

```bash
make seed          # seed with 500+ events including incident scenario
make demo-tamper   # tamper detection demo
make query-stats   # event counts by type, severity, zone
```

API docs: `http://localhost:8080/docs`

### Docker Compose

```bash
docker compose up --build
# Gateway: http://localhost:8080
# MinIO console: http://localhost:9001  (minioadmin / minioadmin)
```

### Full Hyperledger Fabric

```bash
make up-fabric
make seed
make demo-tamper
make export-report
make verify-report
```

## Demonstration Scenarios

### Tamper Detection (Key Demo)

Submits an event, then verifies that a modified version of the payload produces a hash mismatch:

```bash
make demo-tamper
```

Output:

```
[3] Verifying original payload (expected: PASS)
    Result: PASS

[5] Verifying tampered payload (expected: FAIL)
    Result: FAIL: stored=e3b0c44298fc1c14 computed=ba7816bf8f01cfea
```

This is the core of the non-repudiation demonstration. Any modification to a stored payload is detectable by any party holding the original data, without contacting the submitter.

### Post-Incident Timeline (UC2)

Loads a pre-built incident day scenario and reconstructs the event timeline:

```bash
make demo-incident

# Query the incident zone
curl "http://localhost:8080/events?zone_id=Z04"

# Export incident audit report
bash scripts/export_audit_report.sh --zone Z04
```

The incident day scenario (`simulator/scenarios/incident_day.json`) includes ZONE_ENTRY, PPE_VIOLATION, PROXIMITY_ALERT, NEAR_MISS, and FALL_DETECTED events, allowing a full causal chain to be reconstructed from the ledger.

See `docs/legal-use-cases.md` for the step-by-step procedure an inspector, insurer, or lawyer would follow using this output.

### Batch Integrity Verification

```bash
make export-report
make verify-report
```

Verifies every event in the exported report by recomputing its hash and comparing it against the ledger. Produces a PASS/FAIL result per event and a summary.

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
│           ├── auditcc.go
│           └── go.mod
├── gateway/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py
│       ├── schemas.py
│       ├── fabric_client.py
│       └── hashing.py
├── simulator/
│   ├── generate_events.py
│   └── scenarios/
│       └── incident_day.json
├── scripts/
│   ├── up.sh
│   ├── down.sh
│   ├── seed.sh
│   ├── export_audit_report.sh
│   └── verify_integrity.py
└── results/
    └── sample_report.json
```

## REST API

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/stats` | GET | Event counts by type, severity, zone |
| `/events` | POST | Submit a new safety event |
| `/events` | GET | Query events (actor, zone, type, severity, time range) |
| `/events/{id}` | GET | Retrieve a single event |
| `/events/{id}/history` | GET | Fabric write history — confirms single write |
| `/events/{id}/verify` | POST | Verify payload hash: returns PASS or FAIL |
| `/audit/report` | GET | Export full audit report as JSON |
| `/audit/package` | GET | Chaincode-level bundle with package hash |

## Mapping to Thesis Chapters

| Chapter | Topic | Primary Artefacts |
|---|---|---|
| Chapter 2 | Background: IoT safety, permissioned blockchain | docs/design-rationale.md, docs/threat-model.md |
| Chapter 3 | System design | docs/architecture.md, docs/accountability-framework.md |
| Chapter 4 | Implementation | gateway/, fabric/chaincode/, simulator/ |
| Chapter 5 | Experiments and validation | docs/experiment-plan.md, docs/legal-use-cases.md, results/ |

## Limitations

- Events are generated by the simulator, not by real IoT sensors.
- Stub mode does not exercise real Fabric consensus or endorsement policy.
- Throughput at scale is not benchmarked — performance analysis is out of scope.
- Chaincode-level attribute-based access control (ABAC) is documented but not implemented in this prototype.
- `evidence_uri` and MinIO integration are optional in the prototype; the hash verification path is fully implemented.

## References

- Hyperledger Fabric 2.5: https://hyperledger-fabric.readthedocs.io
- Fabric Gateway SDK: https://hyperledger.github.io/fabric-gateway
- ISO 45001:2018 — Occupational health and safety management systems
- ISO/IEC 27037 — Guidelines for digital evidence identification and preservation
- EU OSH Framework Directive 89/391/EEC
- FastAPI: https://fastapi.tiangolo.com
