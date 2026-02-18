# Immutable Audit Layer for IoT Safety Data in Construction Sites

Laurea Magistrale — Politecnico di Torino

## What This Project Is

This prototype implements an immutable audit layer that couples to existing IoT-based safety monitoring platforms in construction sites. It does not replace sensors or existing safety systems — it adds a tamper-evident, permissioned ledger that records safety event evidence in a way that:

- Cannot be silently modified after the fact (immutability via blockchain)
- Can be independently verified by multiple stakeholders (contractors, inspectors, insurers)
- Provides cryptographic proof of integrity (SHA-256 payload hashing)
- Supports forensic investigation after incidents (queryable audit trail)

The core technology is Hyperledger Fabric, a permissioned blockchain where only authorised organisations participate. Events are submitted via a REST gateway (FastAPI + Python) that validates, hashes, and records each safety event. Full payloads are stored off-chain (MinIO/S3), while only hashes and metadata go on-chain.

## Architecture

```
IoT Platform / Simulators
        |  POST /events
        v
  Audit Gateway (FastAPI, Python)
  validate -> hash -> submit
        |  gRPC (Fabric Gateway SDK)
        v
  Hyperledger Fabric 2.5
  Channel: mychannel
  Chaincode: auditcc (Go)
  State DB: CouchDB
        |
        v
  MinIO (off-chain evidence store)
  Full payloads, video clips, sensor logs
```

See [docs/architecture.md](docs/architecture.md) for the full component diagram, data flows, and threat model.

## Prerequisites

- Docker and Docker Compose v2+
- Python 3.11+
- Go 1.21+ (only needed for Fabric mode)
- WSL2 (Windows) or Linux / macOS
- Hyperledger Fabric samples (only for `--fabric` mode):

```bash
curl -sSL https://bit.ly/2ysbOFE | bash -s -- 2.5.0 1.5.7
```

## Quick Start

### Option A — Stub Mode (no Docker, no Fabric)

Fastest way to run. Uses an in-memory ledger for local development and testing.

```bash
make install-dev
make up-stub
# Gateway: http://localhost:8080
# API docs: http://localhost:8080/docs
```

In a second terminal:

```bash
make seed          # seed with 500+ events
make demo-tamper   # run tamper detection demo
make query-stats   # show ledger statistics
```

### Option B — Docker Compose

Runs the gateway and MinIO. Still uses the in-memory stub (no real Fabric).

```bash
docker compose up --build
# Gateway: http://localhost:8080
# MinIO console: http://localhost:9001  (minioadmin / minioadmin)
```

### Option C — Full Hyperledger Fabric

```bash
make up-fabric     # starts Fabric test-network, deploys chaincode, starts gateway
make seed
make demo-tamper
make export-report
make verify-report
```

## Use-Case Demos

### Normal Monitoring (UC1)

```bash
cd simulator
python3 generate_events.py --count 500 --gateway http://localhost:8080
```

Query the results:

```bash
curl "http://localhost:8080/events?zone_id=Z04"
curl "http://localhost:8080/events?severity=critical"
curl "http://localhost:8080/events?event_type=NEAR_MISS"
```

### Post-Incident Audit (UC2)

Load the pre-built incident day scenario — includes a FALL_DETECTED event and a complete timeline:

```bash
make demo-incident
bash scripts/export_audit_report.sh --zone Z04
```

### Tamper Detection (UC3)

The key demo for the thesis defence. Shows that any modification to a recorded payload is detected:

```bash
make demo-tamper
```

Expected output:

```
[3] Verifying original payload (expected: PASS)
    Result: PASS

[5] Verifying tampered payload (expected: FAIL)
    Result: FAIL: stored=e3b0c44298fc1c14 computed=ba7816bf8f01cfea
    stored_hash : e3b0c44298fc1c149afbf4c8996fb924...
    computed    : ba7816bf8f01cfea414140de5dae2268...
```

### Batch Integrity Verification

```bash
make export-report
make verify-report
```

## Project Structure

```
audit-layer/
├── README.md
├── Makefile
├── docker-compose.yml
├── docs/
│   ├── architecture.md       -- component diagram, data flows, threat model
│   ├── api-spec.md           -- REST API reference with curl examples
│   └── experiment-plan.md    -- Chapter 5 experiments with acceptance criteria
├── fabric/
│   └── chaincode/
│       └── auditcc/
│           ├── auditcc.go    -- Hyperledger Fabric chaincode (Go)
│           └── go.mod
├── gateway/
│   ├── Dockerfile
│   ├── requirements.txt
│   └── app/
│       ├── main.py           -- FastAPI application and all endpoints
│       ├── schemas.py        -- Pydantic request/response models
│       ├── fabric_client.py  -- Fabric Gateway SDK wrapper with stub fallback
│       └── hashing.py        -- SHA-256 canonical hashing utilities
├── simulator/
│   ├── generate_events.py    -- IoT event simulator and tamper demo
│   └── scenarios/
│       └── incident_day.json -- Pre-built incident scenario
├── scripts/
│   ├── up.sh                 -- Start services (stub / docker / fabric)
│   ├── down.sh               -- Stop services
│   ├── seed.sh               -- Seed ledger with demo data
│   ├── export_audit_report.sh
│   └── verify_integrity.py   -- CLI integrity verifier
└── results/
    └── sample_report.json
```

## REST API Summary

| Endpoint | Method | Description |
|---|---|---|
| `/health` | GET | Health check |
| `/stats` | GET | Event counts by type, severity, zone |
| `/events` | POST | Register a new safety event |
| `/events` | GET | Query events (actor, zone, type, severity, time range) |
| `/events/{id}` | GET | Retrieve a single event |
| `/events/{id}/history` | GET | Fabric write history (tamper evidence) |
| `/events/{id}/verify` | POST | Verify payload hash — returns PASS or FAIL |
| `/audit/report` | GET | Export audit report as JSON |
| `/audit/package` | GET | Chaincode-level bundle with package hash |

Full reference: [docs/api-spec.md](docs/api-spec.md) or `http://localhost:8080/docs`

## Chaincode Functions (auditcc)

| Function | Type | Description |
|---|---|---|
| `RegisterEvent` | Submit | Record a new safety event |
| `QueryEvent` | Evaluate | Retrieve event by ID |
| `QueryByWorker` | Evaluate | Filter by actor_id (CouchDB) |
| `QueryByZone` | Evaluate | Filter by zone_id (CouchDB) |
| `QueryByEventType` | Evaluate | Filter by event_type (CouchDB) |
| `QueryBySeverity` | Evaluate | Filter by severity (CouchDB) |
| `QueryByTimeRange` | Evaluate | Filter by time window (CouchDB) |
| `QueryByZoneAndTime` | Evaluate | Combined zone and time filter |
| `VerifyIntegrity` | Evaluate | Hash comparison on-chain |
| `GetAuditPackage` | Evaluate | Bundle with package hash for chain of custody |
| `GetHistory` | Evaluate | Fabric write history for a key |

## Mapping to Thesis Chapters

| Chapter | Content | Project Artefact |
|---|---|---|
| Chapter 2 | Background: IoT safety, blockchain, Fabric | docs/architecture.md |
| Chapter 3 | System design | docs/architecture.md, docs/api-spec.md |
| Chapter 4 | Prototype implementation | gateway/, fabric/chaincode/, simulator/ |
| Chapter 5 | Experiments and results | docs/experiment-plan.md, results/ |

## Limitations

- Events are simulated, not from real IoT sensors
- No throughput benchmark — performance at scale is not the focus of this prototype
- Stub mode does not test Fabric consensus or endorsement policy
- Chaincode-level ABAC is documented but not fully implemented
- MinIO integration is present in the architecture but evidence_uri is optional in the prototype

## References

- Hyperledger Fabric 2.5: https://hyperledger-fabric.readthedocs.io
- Fabric Gateway SDK: https://hyperledger.github.io/fabric-gateway
- FastAPI: https://fastapi.tiangolo.com
- ISO 45001:2018 — Occupational health and safety management systems
- EU OSH Framework Directive 89/391/EEC
